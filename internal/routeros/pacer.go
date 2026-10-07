package routeros

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// The pacer reads the router's cpu-load, the all-core average of the last
// full second: on an RB5009 it matched mikroscope's kernel series to within a
// point at a one-second lag (2026-10-07), and it changes once a second, so it
// is read at most that often.
const (
	pacerReadEvery    = time.Second
	pacerStartPause   = 200 * time.Millisecond
	pacerMaxPause     = 5 * time.Second
	pacerMinPause     = 50 * time.Millisecond
	pacerCalmMargin   = 10 // percentage points under the limit
	pacerBusyReadings = 2
	pacerBlockEntries = 100
	pacerStaleAfter   = 10 * time.Second
)

// PacerHooks report what a Pacer reads and does, for metrics. Any may be nil.
type PacerHooks struct {
	Load      func(load int)        // every reading of the router's cpu-load
	Throttled func(on bool)         // when slowing down starts and ends
	Waited    func(d time.Duration) // each wait, in a pause or in WaitCalm
}

// Pacer slows the bouncer's bulk work down while the router's CPU is busy.
// Before each block of work (Block, or Entry every pacerBlockEntries entries)
// it waits a pause: none at full speed; pacerStartPause once two readings in
// a row reached the limit; twice as long for each further busy reading, at
// most pacerMaxPause; half as long for each calm reading, back to full speed
// under pacerMinPause. While it slows down, per-entry work runs one entry at
// a time. A nil Pacer, and one with limit 0, never reads and never waits.
type Pacer struct {
	limit int
	read  func(context.Context) (int, error)
	now   func() time.Time
	sleep func(context.Context, time.Duration) error

	mu       sync.Mutex
	hooks    PacerHooks
	pause    time.Duration // 0: full speed
	busy     int           // busy readings in a row at full speed
	lastRead time.Time     // the last read, or attempt
	load     int           // the last reading
	loadOK   bool          // the last read succeeded
	entries  int           // Entry calls since the last Block they made
	since    time.Time     // when slowing down started
	waited   time.Duration // all the time spent waiting

	serial chan struct{} // one entry at a time while slowing down
}

// NewPacer returns a pacer that reads the router's cpu-load through read and
// slows down at limit percent; limit 0 turns it off.
func NewPacer(limit int, read func(context.Context) (int, error)) *Pacer {
	return &Pacer{
		limit:  limit,
		read:   read,
		now:    time.Now,
		sleep:  sleepContext,
		serial: make(chan struct{}, 1),
	}
}

// SetHooks sets the hooks that report what the pacer reads and does.
func (p *Pacer) SetHooks(h PacerHooks) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hooks = h
}

// Block waits before one block of bulk work, a script chunk or a lookup, as
// long as the router is busy: at most pacerMaxPause, shorter if the router
// calms down meanwhile. It returns ctx's error once ctx is done.
func (p *Pacer) Block(ctx context.Context) error {
	if !p.enabled() {
		return nil
	}
	p.observe(ctx)
	return p.wait(ctx, p.currentPause())
}

// Entry is Block for per-entry work: every pacerBlockEntries calls it waits as
// Block does, and while slowing down it lets one entry through at a time and
// waits that pause holding the turn, so a pause stops every entry, not only
// the one that waits it. The caller calls release once the entry is done,
// also after an error.
func (p *Pacer) Entry(ctx context.Context) (release func(), err error) {
	noop := func() {
		// Nothing to release: no turn was taken.
	}
	if !p.enabled() {
		return noop, nil
	}
	p.mu.Lock()
	p.entries++
	due := p.entries >= pacerBlockEntries
	if due {
		p.entries = 0
	}
	p.mu.Unlock()
	if p.currentPause() == 0 {
		if due {
			// The reading this wait makes can start slowing down; it has
			// waited the first pause already.
			if blockErr := p.Block(ctx); blockErr != nil {
				return noop, blockErr
			}
			due = false
		}
		if p.currentPause() == 0 {
			return noop, nil
		}
	}
	select {
	case p.serial <- struct{}{}:
	case <-ctx.Done():
		return noop, ctx.Err()
	}
	release = func() { <-p.serial }
	if due {
		if blockErr := p.Block(ctx); blockErr != nil {
			release()
			return noop, blockErr
		}
	}
	return release, nil
}

// WaitCalm waits while the router's CPU is at or above the limit, at most
// most: the start of a periodic pass, whose address-list read is one command
// that cannot be paced. It returns ctx's error once ctx is done.
func (p *Pacer) WaitCalm(ctx context.Context, most time.Duration) error {
	if !p.enabled() {
		return nil
	}
	var waited time.Duration
	defer func() { p.addWaited(waited) }()
	for {
		p.observe(ctx)
		p.mu.Lock()
		busy, load := p.loadOK && p.load >= p.limit, p.load
		p.mu.Unlock()
		switch {
		case !busy:
			return nil
		case waited >= most:
			log.Info().Int("cpu_load", load).Dur("waited", waited).Msg("router CPU still busy, reconciling anyway")
			return nil
		case waited == 0:
			log.Info().Int("cpu_load", load).Int("limit", p.limit).Msg("router CPU busy, delaying the reconciliation")
		}
		if err := p.sleep(ctx, pacerReadEvery); err != nil {
			return err
		}
		waited += pacerReadEvery
	}
}

// Rest ends the bulk work: a pacer slowing down goes back to full speed, and
// the next work starts afresh, with a reading of its own. Without it, a pass
// that ends slowed down would report it until the next pass.
func (p *Pacer) Rest() {
	if !p.enabled() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.busy = 0
	p.entries = 0
	p.lastRead = time.Time{}
	p.fullSpeedLocked(p.now(), msgRest)
}

// Waited returns all the time the pacer has spent waiting.
func (p *Pacer) Waited() time.Duration {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.waited
}

func (p *Pacer) enabled() bool {
	return p != nil && p.limit > 0 && p.read != nil
}

func (p *Pacer) currentPause() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pause
}

// calmBelow is the load under which a reading counts as calm: pacerCalmMargin
// points under the limit, or half the limit when that is smaller, so a low
// limit can still calm down.
func (p *Pacer) calmBelow() int {
	return p.limit - min(pacerCalmMargin, p.limit/2)
}

// observe reads the router's load if the last read is a second old or more,
// and moves the pacer on. It reads outside the lock: the others skip the read.
func (p *Pacer) observe(ctx context.Context) {
	now, due := p.claimRead()
	if !due {
		return
	}

	load, err := p.read(ctx)

	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		// No reading: nothing changes, and the work goes on.
		p.loadOK = false
		return
	}
	p.load, p.loadOK = load, true
	if p.hooks.Load != nil {
		p.hooks.Load(load)
	}
	switch {
	case load >= p.limit:
		p.busyLocked(load, now)
	case load < p.calmBelow():
		p.calmLocked(now)
	default:
		p.busy = 0
	}
}

// claimRead claims the read that is due a second after the last one, and
// returns the time it claimed it at. After pacerStaleAfter without a reading
// it starts afresh.
func (p *Pacer) claimRead() (now time.Time, due bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now = p.now()
	if !p.lastRead.IsZero() && now.Sub(p.lastRead) < pacerReadEvery {
		return now, false
	}
	if !p.lastRead.IsZero() && now.Sub(p.lastRead) > pacerStaleAfter {
		// No reading for a while: a read hung, or the last pass ended without
		// Rest. Start afresh; nothing read the CPU calm.
		p.busy = 0
		p.fullSpeedLocked(now, msgStale)
	}
	p.lastRead = now
	return now, true
}

// busyLocked moves the pacer on with a reading at or above the limit: twice
// the pause while slowing down, or the start of slowing down at the second
// busy reading in a row. The caller holds p.mu.
func (p *Pacer) busyLocked(load int, now time.Time) {
	if p.pause > 0 {
		p.pause = min(2*p.pause, pacerMaxPause)
		return
	}
	p.busy++
	if p.busy < pacerBusyReadings {
		return
	}
	p.busy = 0
	p.pause = pacerStartPause
	p.since = now
	log.Info().Int("cpu_load", load).Int("limit", p.limit).Msg("router CPU busy, slowing the bouncer down")
	if p.hooks.Throttled != nil {
		p.hooks.Throttled(true)
	}
}

// calmLocked moves the pacer on with a calm reading: half the pause, and full
// speed under pacerMinPause. The caller holds p.mu.
func (p *Pacer) calmLocked(now time.Time) {
	p.busy = 0
	if p.pause == 0 {
		return
	}
	p.pause /= 2
	if p.pause < pacerMinPause {
		p.fullSpeedLocked(now, msgCalm)
	}
}

// The ways slowing down ends.
const (
	msgCalm  = "router CPU calm again, back to full speed"
	msgRest  = "reconciliation over, back to full speed"
	msgStale = "no reading of the router CPU for a while, starting afresh at full speed"
)

// fullSpeedLocked ends slowing down, logging msg. The caller holds p.mu.
func (p *Pacer) fullSpeedLocked(now time.Time, msg string) {
	if p.pause == 0 {
		return
	}
	p.pause = 0
	log.Info().Int("limit", p.limit).Dur("slowed_for", now.Sub(p.since)).Msg(msg)
	if p.hooks.Throttled != nil {
		p.hooks.Throttled(false)
	}
}

// wait sleeps d in steps of a second at most, reading the router between
// them: a calmer router shortens what is left.
func (p *Pacer) wait(ctx context.Context, d time.Duration) error {
	var waited time.Duration
	defer func() { p.addWaited(waited) }()
	for d > 0 {
		step := min(d, pacerReadEvery)
		if err := p.sleep(ctx, step); err != nil {
			return err
		}
		waited += step
		d -= step
		if d > 0 {
			p.observe(ctx)
			d = min(d, p.currentPause())
		}
	}
	return nil
}

func (p *Pacer) addWaited(d time.Duration) {
	if d == 0 {
		return
	}
	p.mu.Lock()
	p.waited += d
	hook := p.hooks.Waited
	p.mu.Unlock()
	if hook != nil {
		hook(d)
	}
}

// sleepContext sleeps d, or until ctx is done.
func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
