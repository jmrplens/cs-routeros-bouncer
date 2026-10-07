package routeros

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCPU answers the pacer's reads from a script of loads; the last one
// repeats. err, when set, fails every read.
type fakeCPU struct {
	mu    sync.Mutex
	loads []int
	err   error
	reads int
}

func (f *fakeCPU) read(context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.err != nil {
		return 0, f.err
	}
	v := f.loads[0]
	if len(f.loads) > 1 {
		f.loads = f.loads[1:]
	}
	return v, nil
}

func (f *fakeCPU) set(loads ...int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loads = loads
}

func (f *fakeCPU) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

// testPacer is a Pacer on a fake clock: a sleep moves the clock, and slept
// records every sleep.
type testPacer struct {
	*Pacer
	mu    sync.Mutex
	clock time.Time
	slept []time.Duration
}

func newTestPacer(limit int, cpu *fakeCPU) *testPacer {
	tp := &testPacer{clock: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)}
	tp.Pacer = NewPacer(limit, cpu.read)
	tp.now = func() time.Time {
		tp.mu.Lock()
		defer tp.mu.Unlock()
		return tp.clock
	}
	tp.sleep = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		tp.mu.Lock()
		defer tp.mu.Unlock()
		tp.slept = append(tp.slept, d)
		tp.clock = tp.clock.Add(d)
		return nil
	}
	return tp
}

// throttledPacer returns a test pacer already slowing down with pause, whose
// last reading is fresh, so its next calls make none.
func throttledPacer(pause time.Duration) (*testPacer, *fakeCPU) {
	cpu := &fakeCPU{loads: []int{95}}
	tp := newTestPacer(80, cpu)
	tp.pause = pause
	tp.since = tp.now()
	tp.lastRead = tp.now()
	return tp, cpu
}

func (tp *testPacer) advance(d time.Duration) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.clock = tp.clock.Add(d)
}

func (tp *testPacer) sleeps() []time.Duration {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return append([]time.Duration(nil), tp.slept...)
}

func (tp *testPacer) sleptTotal() time.Duration {
	var total time.Duration
	for _, d := range tp.sleeps() {
		total += d
	}
	return total
}

func (tp *testPacer) resetSlept() {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.slept = nil
}

// raisePeak records n in peak if it is higher.
func raisePeak(peak *atomic.Int32, n int32) {
	for {
		p := peak.Load()
		if n <= p || peak.CompareAndSwap(p, n) {
			return
		}
	}
}

// blockEverySecond calls Block n times, a second of clock apart.
func (tp *testPacer) blockEverySecond(t *testing.T, n int) {
	t.Helper()
	for range n {
		if err := tp.Block(context.Background()); err != nil {
			t.Fatalf("Block: %v", err)
		}
		tp.advance(time.Second)
	}
}

// TestPacer_OneSpikeDoesNotSlowDown verifies that a single busy second, such
// as the router's own jobs every 30 s on an RB5009, slows nothing down: it
// takes two busy readings in a row.
func TestPacer_OneSpikeDoesNotSlowDown(t *testing.T) {
	cpu := &fakeCPU{loads: []int{95, 40, 95, 40}}
	tp := newTestPacer(80, cpu)

	tp.blockEverySecond(t, 4)

	if len(tp.sleeps()) != 0 || tp.currentPause() != 0 {
		t.Fatalf("expected full speed, slept %v, pause %v", tp.sleeps(), tp.currentPause())
	}
}

// TestPacer_TwoBusyReadingsSlowDown verifies that two busy readings in a row
// start slowing down with pacerStartPause, and say so once.
func TestPacer_TwoBusyReadingsSlowDown(t *testing.T) {
	cpu := &fakeCPU{loads: []int{95}}
	tp := newTestPacer(80, cpu)
	var events []bool
	tp.SetHooks(PacerHooks{Throttled: func(on bool) { events = append(events, on) }})

	tp.blockEverySecond(t, 2)

	if got := tp.sleptTotal(); got != pacerStartPause {
		t.Fatalf("expected one pause of %v, slept %v", pacerStartPause, tp.sleeps())
	}
	if len(events) != 1 || !events[0] {
		t.Fatalf("expected one start event, got %v", events)
	}
}

// TestPacer_PauseDoublesUpToMax verifies that each further busy reading
// doubles the pause, never past pacerMaxPause, and that no Block waits longer
// than that.
func TestPacer_PauseDoublesUpToMax(t *testing.T) {
	cpu := &fakeCPU{loads: []int{95}}
	tp := newTestPacer(80, cpu)

	var last time.Duration
	for i := range 12 {
		before := tp.sleptTotal()
		if err := tp.Block(context.Background()); err != nil {
			t.Fatal(err)
		}
		if waited := tp.sleptTotal() - before; waited > pacerMaxPause {
			t.Fatalf("Block %d waited %v, over %v", i, waited, pacerMaxPause)
		}
		last = tp.currentPause()
		if last > pacerMaxPause {
			t.Fatalf("pause %v after Block %d, over %v", last, i, pacerMaxPause)
		}
		tp.advance(time.Second)
	}
	if last != pacerMaxPause {
		t.Fatalf("expected the pause to reach %v, got %v", pacerMaxPause, last)
	}
}

// TestPacer_CalmReadingsHalveBackToFullSpeed verifies that calm readings halve
// the pause until it is back to full speed, with one start and one end event.
func TestPacer_CalmReadingsHalveBackToFullSpeed(t *testing.T) {
	cpu := &fakeCPU{loads: []int{95}}
	tp := newTestPacer(80, cpu)
	var events []bool
	tp.SetHooks(PacerHooks{Throttled: func(on bool) { events = append(events, on) }})
	tp.blockEverySecond(t, 6)
	if tp.currentPause() == 0 {
		t.Fatal("expected to be slowing down after six busy readings")
	}

	cpu.set(30)
	tp.blockEverySecond(t, 12)

	if tp.currentPause() != 0 {
		t.Fatalf("expected full speed after calm readings, pause %v", tp.currentPause())
	}
	if len(events) != 2 || !events[0] || events[1] {
		t.Fatalf("expected a start and an end event, got %v", events)
	}
}

// TestPacer_IntermediateReadingsHoldThePause verifies that a reading between
// the calm line and the limit neither grows nor shrinks the pause.
func TestPacer_IntermediateReadingsHoldThePause(t *testing.T) {
	tp, cpu := throttledPacer(400 * time.Millisecond)
	tp.advance(time.Second)
	cpu.set(75) // limit 80: calm below 70

	tp.blockEverySecond(t, 3)

	if got := tp.currentPause(); got != 400*time.Millisecond {
		t.Fatalf("expected the pause held at 400ms, got %v", got)
	}
}

// TestPacer_SmallLimitCanCalmDown verifies that a limit under twice the margin
// can still calm down: 10 points under a limit of 5 would never come, so half
// the limit counts.
func TestPacer_SmallLimitCanCalmDown(t *testing.T) {
	cpu := &fakeCPU{loads: []int{9}}
	tp := newTestPacer(5, cpu)
	tp.blockEverySecond(t, 2)
	if tp.currentPause() == 0 {
		t.Fatal("expected a load of 9 to slow a limit of 5 down")
	}

	cpu.set(2)
	tp.blockEverySecond(t, 6)

	if tp.currentPause() != 0 {
		t.Fatalf("expected a load of 2 to calm a limit of 5, pause %v", tp.currentPause())
	}
}

// TestPacer_EntryWaitsEveryBlockOfEntries verifies that per-entry work waits
// once every pacerBlockEntries entries, not before each one.
func TestPacer_EntryWaitsEveryBlockOfEntries(t *testing.T) {
	tp, _ := throttledPacer(400 * time.Millisecond)

	for range 2*pacerBlockEntries + 50 {
		release, err := tp.Entry(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		release()
	}

	if got := len(tp.sleeps()); got != 2 {
		t.Fatalf("expected a pause at entries %d and %d, got %v", pacerBlockEntries, 2*pacerBlockEntries, tp.sleeps())
	}
}

// TestPacer_EntryOneAtATimeWhileSlowing verifies that while slowing down only
// one caller holds an entry at a time.
func TestPacer_EntryOneAtATimeWhileSlowing(t *testing.T) {
	tp, _ := throttledPacer(400 * time.Millisecond)
	var cur, peak atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				release, err := tp.Entry(context.Background())
				if err != nil {
					t.Error(err)
					return
				}
				raisePeak(&peak, cur.Add(1))
				time.Sleep(time.Millisecond)
				cur.Add(-1)
				release()
			}
		})
	}
	wg.Wait()
	if got := peak.Load(); got != 1 {
		t.Fatalf("expected one entry at a time while slowing down, saw %d at once", got)
	}
}

// TestPacer_EntryFullSpeedRunsTogether verifies that at full speed entries do
// not wait for each other.
func TestPacer_EntryFullSpeedRunsTogether(t *testing.T) {
	tp := newTestPacer(80, &fakeCPU{loads: []int{10}})
	const n = 8
	held := make(chan struct{}, n)
	done := make(chan struct{})
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			release, err := tp.Entry(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			held <- struct{}{}
			<-done
			release()
		})
	}
	for i := range n {
		select {
		case <-held:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of %d entries held at once at full speed", i, n)
		}
	}
	close(done)
	wg.Wait()
}

// TestPacer_StaleStateStartsAfresh verifies that a pass after more than
// pacerStaleAfter without readings does not inherit the last one's pause.
func TestPacer_StaleStateStartsAfresh(t *testing.T) {
	tp, cpu := throttledPacer(2 * time.Second)
	tp.advance(pacerStaleAfter + time.Second)
	cpu.set(50)

	if err := tp.Block(context.Background()); err != nil {
		t.Fatal(err)
	}

	if tp.currentPause() != 0 || len(tp.sleeps()) != 0 {
		t.Fatalf("expected a fresh start, pause %v, slept %v", tp.currentPause(), tp.sleeps())
	}
}

// TestPacer_ReadErrorChangesNothing verifies that a failed read is no reading:
// no state change, no wait, and the work goes on.
func TestPacer_ReadErrorChangesNothing(t *testing.T) {
	cpu := &fakeCPU{loads: []int{95}, err: errors.New("i/o timeout")}
	tp := newTestPacer(80, cpu)

	tp.blockEverySecond(t, 3)
	if err := tp.WaitCalm(context.Background(), time.Minute); err != nil {
		t.Fatal(err)
	}

	if tp.currentPause() != 0 || len(tp.sleeps()) != 0 {
		t.Fatalf("expected no effect from failed reads, pause %v, slept %v", tp.currentPause(), tp.sleeps())
	}
}

// TestPacer_DisabledNeverReads verifies that limit 0 and a nil pacer never
// read and never wait.
func TestPacer_DisabledNeverReads(t *testing.T) {
	cpu := &fakeCPU{loads: []int{100}}
	tp := newTestPacer(0, cpu)
	ctx := context.Background()
	if err := tp.Block(ctx); err != nil {
		t.Fatal(err)
	}
	release, entryErr := tp.Entry(ctx)
	if entryErr != nil {
		t.Fatal(entryErr)
	}
	release()
	if err := tp.WaitCalm(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	if cpu.readCount() != 0 || len(tp.sleeps()) != 0 {
		t.Fatalf("limit 0 read %d times and slept %v", cpu.readCount(), tp.sleeps())
	}

	var nilPacer *Pacer
	nilPacer.SetHooks(PacerHooks{})
	if err := nilPacer.Block(ctx); err != nil {
		t.Fatal(err)
	}
	nilRelease, nilErr := nilPacer.Entry(ctx)
	if nilErr != nil {
		t.Fatal(nilErr)
	}
	nilRelease()
	if err := nilPacer.WaitCalm(ctx, time.Minute); err != nil || nilPacer.Waited() != 0 {
		t.Fatalf("nil pacer: %v, waited %v", err, nilPacer.Waited())
	}
}

// TestPacer_ContextEndsWaits verifies that a done context ends a pause, a
// WaitCalm and a wait for the entry slot at once.
func TestPacer_ContextEndsWaits(t *testing.T) {
	cpu := &fakeCPU{loads: []int{95}}
	p := NewPacer(80, cpu.read) // real sleeps

	p.pause, p.since, p.lastRead = pacerMaxPause, time.Now(), time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	if err := p.Block(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Block: expected context.Canceled, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("Block took %v after the cancel", time.Since(start))
	}

	p.lastRead = time.Time{} // the next call reads: busy
	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start = time.Now()
	if err := p.WaitCalm(ctx, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitCalm: expected context.Canceled, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("WaitCalm took %v after the cancel", time.Since(start))
	}

	p.serial <- struct{}{} // another caller holds the entry slot
	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	release, err := p.Entry(ctx)
	release()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Entry: expected context.Canceled, got %v", err)
	}
}

// TestPacer_WaitCalm verifies that WaitCalm returns once the router is calm,
// and after most if it stays busy, without an error.
func TestPacer_WaitCalm(t *testing.T) {
	cpu := &fakeCPU{loads: []int{95, 95, 50}}
	tp := newTestPacer(80, cpu)

	if err := tp.WaitCalm(context.Background(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if got := tp.sleptTotal(); got != 2*time.Second {
		t.Fatalf("expected to wait 2s for the calm reading, slept %v", tp.sleeps())
	}

	cpu.set(95)
	tp.advance(time.Second)
	tp.resetSlept()
	if err := tp.WaitCalm(context.Background(), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := tp.sleptTotal(); got != 3*time.Second {
		t.Fatalf("expected to give up after 3s, slept %v", tp.sleeps())
	}
	if got := tp.Waited(); got != 5*time.Second {
		t.Fatalf("expected 5s waited in all, got %v", got)
	}
}

// TestPacer_HooksReportReadingsAndWaits verifies the hooks the metrics use.
func TestPacer_HooksReportReadingsAndWaits(t *testing.T) {
	cpu := &fakeCPU{loads: []int{95}}
	tp := newTestPacer(80, cpu)
	var loads []int
	var waited time.Duration
	tp.SetHooks(PacerHooks{
		Load:   func(load int) { loads = append(loads, load) },
		Waited: func(d time.Duration) { waited += d },
	})

	tp.blockEverySecond(t, 2)

	if len(loads) != 2 || loads[0] != 95 {
		t.Fatalf("expected two readings of 95, got %v", loads)
	}
	if waited != pacerStartPause || tp.Waited() != pacerStartPause {
		t.Fatalf("expected %v waited, hook %v, Waited %v", pacerStartPause, waited, tp.Waited())
	}
}
