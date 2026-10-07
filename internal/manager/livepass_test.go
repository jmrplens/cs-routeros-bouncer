package manager

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
	"github.com/jmrplens/cs-routeros-bouncer/internal/crowdsec"
	"github.com/jmrplens/cs-routeros-bouncer/internal/metrics"
	ros "github.com/jmrplens/cs-routeros-bouncer/internal/routeros"
)

// decisionsCount reads crowdsec_bouncer_decisions_total for one label set.
func decisionsCount(t *testing.T, action, proto, origin string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "crowdsec_bouncer_decisions_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			labels := map[string]string{}
			for _, label := range metric.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}
			if labels["action"] == action && labels["proto"] == proto && labels["origin"] == origin {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func liveDecision(value, origin string) *crowdsec.Decision {
	return &crowdsec.Decision{Value: value, Proto: "ip", Origin: origin, Duration: time.Hour, Type: "ban"}
}

func ipv4Manager(mock *mockROS) *Manager {
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	return newTestManager(mock, cfg)
}

func removedIDs(mock *mockROS) []string {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	ids := make([]string, 0, len(mock.removeAddressCalls))
	for _, call := range mock.removeAddressCalls {
		ids = append(ids, call.ID)
	}
	return ids
}

func addedAddresses(mock *mockROS) []string {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	addrs := make([]string, 0, len(mock.addAddressCalls))
	for _, call := range mock.addAddressCalls {
		addrs = append(addrs, call.Address)
	}
	return addrs
}

// TestLiveBan_OutsideAPassNotesNothing verifies that with no pass running a
// live ban is applied as before and leaves no journal behind.
func TestLiveBan_OutsideAPassNotesNothing(t *testing.T) {
	mock := &mockROS{addAddressID: "*1"}
	mgr := ipv4Manager(mock)

	mgr.liveBan(liveDecision("203.0.113.1", "crowdsec"))

	if got := addedAddresses(mock); len(got) != 1 {
		t.Fatalf("expected the ban applied, got %v", got)
	}
	if mgr.passLive != nil {
		t.Fatal("expected no journal outside a pass")
	}
}

// TestReconcile_LeavesLiveAddressesToTheLivePath verifies that a pass neither
// removes an address banned live during it, though its snapshot no longer has
// it, nor adds one unbanned live, though its snapshot still has it.
func TestReconcile_LeavesLiveAddressesToTheLivePath(t *testing.T) {
	mock := &mockROS{
		addAddressID: "*x",
		listAddresses: []ros.AddressEntry{
			{ID: "*x", Address: "203.0.113.1", Comment: "crowdsec-bouncer|old"},
			{ID: "*z", Address: "203.0.113.3", Comment: "crowdsec-bouncer|stale"},
		},
	}
	mgr := ipv4Manager(mock)
	mgr.beginPass()
	mgr.liveBan(liveDecision("203.0.113.1", "crowdsec"))
	mgr.liveUnban(liveDecision("203.0.113.2", "crowdsec"))
	mgr.liveBan(liveDecision("203.0.113.5", "crowdsec"))

	snapshot := []*crowdsec.Decision{liveDecision("203.0.113.2", "crowdsec"), liveDecision("203.0.113.4", "crowdsec")}
	if _, err := mgr.reconcileProtocolAddresses(context.Background(), "ip", snapshot, time.Now()); err != nil {
		t.Fatal(err)
	}

	var bulk []string
	for _, call := range mock.bulkAddCalls {
		for _, e := range call.Entries {
			bulk = append(bulk, e.Address)
		}
	}
	if !slices.Equal(bulk, []string{"203.0.113.4"}) {
		t.Fatalf("expected the pass to add only 203.0.113.4, got %v", bulk)
	}
	if got := removedIDs(mock); !slices.Equal(got, []string{"*z"}) {
		t.Fatalf("expected the pass to remove only *z, got %v", got)
	}
	if ipv4, _ := metrics.GetActiveDecisionsByIPType(); ipv4 != 3 {
		t.Fatalf("expected 3 active IPv4 decisions (203.0.113.1, .4 and .5), got %d", ipv4)
	}
}

// TestReconcile_RefreshLeavesLiveCacheEntries verifies that the cache refresh
// at the start of a pass neither forgets an address banned live after the
// listing nor caches again one unbanned live after it, and that the pass adds
// a live ban that failed in transit, which settles whether it got there.
func TestReconcile_RefreshLeavesLiveCacheEntries(t *testing.T) {
	mock := &mockROS{
		addAddressID:  "*x",
		listAddresses: []ros.AddressEntry{{ID: "*y", Address: "203.0.113.2", Comment: "crowdsec-bouncer|old"}},
	}
	mgr := ipv4Manager(mock)
	mgr.addressCache["203.0.113.2"] = "*y"
	mgr.beginPass()
	mgr.liveBan(liveDecision("203.0.113.1", "crowdsec"))
	mgr.liveUnban(liveDecision("203.0.113.2", "crowdsec"))
	mock.addAddressErr = errors.New("connection reset")
	mgr.liveBan(liveDecision("203.0.113.3", "crowdsec")) // may have reached the router
	mock.addAddressErr = nil

	if _, err := mgr.reconcileProtocolAddresses(context.Background(), "ip", nil, time.Now()); err != nil {
		t.Fatal(err)
	}

	if _, cached := mgr.addressCache["203.0.113.1"]; !cached {
		t.Fatal("expected the live ban to stay cached")
	}
	if _, cached := mgr.addressCache["203.0.113.2"]; cached {
		t.Fatal("expected the live unban to stay uncached")
	}
	var bulk []string
	for _, call := range mock.bulkAddCalls {
		for _, e := range call.Entries {
			bulk = append(bulk, e.Address)
		}
	}
	if !slices.Equal(bulk, []string{"203.0.113.3"}) {
		t.Fatalf("expected the pass to add the failed live ban, got %v", bulk)
	}
	if got := removedIDs(mock); !slices.Equal(got, []string{"*y"}) {
		t.Fatalf("expected only the live unban's removal, got %v", got)
	}
}

// TestSettleLive brings each address a live decision touched during a pass to
// that decision's last word, counting a decision once.
func TestSettleLive(t *testing.T) {
	const addr = "203.0.113.10"

	t.Run("ban still cached: nothing", func(t *testing.T) {
		mock := &mockROS{addAddressID: "*1"}
		mgr := ipv4Manager(mock)
		mgr.beginPass()
		mgr.liveBan(liveDecision(addr, "settle-a"))

		mgr.settleLive()

		if got := addedAddresses(mock); len(got) != 1 {
			t.Fatalf("expected the live add only, got %v", got)
		}
		if mgr.passLive != nil {
			t.Fatal("expected the journal closed")
		}
	})

	t.Run("ban the pass removed, not counted live: added and counted", func(t *testing.T) {
		mock := &mockROS{addAddressID: "*2"}
		mgr := ipv4Manager(mock)
		mgr.addressCache[addr] = "*1"
		mgr.beginPass()
		mgr.liveBan(liveDecision(addr, "settle-b")) // cached: skipped, not counted
		mgr.forgetAddress(addr)                     // the pass removed it
		before := decisionsCount(t, "ban", "ipv4", "settle-b")

		mgr.settleLive()

		if got := addedAddresses(mock); !slices.Equal(got, []string{addr}) {
			t.Fatalf("expected the ban added again, got %v", got)
		}
		if got := decisionsCount(t, "ban", "ipv4", "settle-b") - before; got != 1 {
			t.Fatalf("expected the ban counted once, got %v", got)
		}
	})

	t.Run("ban counted live, then uncached: added, not counted again", func(t *testing.T) {
		mock := &mockROS{addAddressID: "*1"}
		mgr := ipv4Manager(mock)
		mgr.beginPass()
		mgr.liveBan(liveDecision(addr, "settle-c"))
		mgr.forgetAddress(addr) // the refresh dropped it
		before := decisionsCount(t, "ban", "ipv4", "settle-c")

		mgr.settleLive()

		if got := addedAddresses(mock); len(got) != 2 {
			t.Fatalf("expected the ban added again, got %v", got)
		}
		if got := decisionsCount(t, "ban", "ipv4", "settle-c") - before; got != 0 {
			t.Fatalf("expected no second count, got %v", got)
		}
	})

	t.Run("unban the pass added, not counted live: removed and counted", func(t *testing.T) {
		mock := &mockROS{}
		mgr := ipv4Manager(mock)
		mgr.beginPass()
		mgr.liveUnban(liveDecision(addr, "settle-d")) // unknown: skipped, not counted
		mgr.cacheAddress(addr, "*9")                  // the pass added it
		before := decisionsCount(t, "unban", "ipv4", "settle-d")

		mgr.settleLive()

		if got := removedIDs(mock); !slices.Equal(got, []string{"*9"}) {
			t.Fatalf("expected the entry removed, got %v", got)
		}
		if got := decisionsCount(t, "unban", "ipv4", "settle-d") - before; got != 1 {
			t.Fatalf("expected the unban counted once, got %v", got)
		}
	})

	t.Run("unban counted live, then cached again: removed, not counted again", func(t *testing.T) {
		mock := &mockROS{}
		mgr := ipv4Manager(mock)
		mgr.addressCache[addr] = "*1"
		mgr.beginPass()
		mgr.liveUnban(liveDecision(addr, "settle-e"))
		mgr.cacheAddress(addr, "*2") // the refresh cached it again
		before := decisionsCount(t, "unban", "ipv4", "settle-e")

		mgr.settleLive()

		if got := removedIDs(mock); !slices.Equal(got, []string{"*1", "*2"}) {
			t.Fatalf("expected the entry removed again, got %v", got)
		}
		if got := decisionsCount(t, "unban", "ipv4", "settle-e") - before; got != 0 {
			t.Fatalf("expected no second count, got %v", got)
		}
	})

	t.Run("unban unknown: nothing", func(t *testing.T) {
		mock := &mockROS{}
		mgr := ipv4Manager(mock)
		mgr.beginPass()
		mgr.liveUnban(liveDecision(addr, "settle-f"))

		mgr.settleLive()

		if got := removedIDs(mock); len(got) != 0 {
			t.Fatalf("expected no removal, got %v", got)
		}
	})

	t.Run("the last word wins", func(t *testing.T) {
		mock := &mockROS{addAddressID: "*1"}
		mgr := ipv4Manager(mock)
		mgr.beginPass()
		mgr.liveBan(liveDecision(addr, "settle-g"))
		mgr.liveUnban(liveDecision(addr, "settle-g"))
		mgr.cacheAddress(addr, "*1") // the pass added it after the unban

		mgr.settleLive()

		if got := removedIDs(mock); !slices.Equal(got, []string{"*1", "*1"}) {
			t.Fatalf("expected the unban to be the last word, got %v", got)
		}
	})
}

// TestSettleLive_FailedBanOwesReconcile verifies that a ban the settling could
// not make owes a reconcile, as a failed live ban does.
func TestSettleLive_FailedBanOwesReconcile(t *testing.T) {
	mock := &mockROS{addAddressID: "*1"}
	mgr := ipv4Manager(mock)
	mgr.addressCache["203.0.113.11"] = "*0"
	mgr.beginPass()
	mgr.liveBan(liveDecision("203.0.113.11", "crowdsec"))
	mgr.forgetAddress("203.0.113.11")
	mock.addAddressErr = errors.New("connection reset")

	if !mgr.settleLive() {
		t.Fatal("expected the failed ban to owe a reconcile")
	}
}

// TestSettleLive_RecountsActiveDecisions verifies that once a pass is settled
// the active-decision gauges show what the pass expected with each live
// decision's last word, whatever the live counting left them at.
func TestSettleLive_RecountsActiveDecisions(t *testing.T) {
	mock := &mockROS{
		addAddressID: "*c",
		listAddresses: []ros.AddressEntry{
			{ID: "*a", Address: "203.0.113.21", Comment: "crowdsec-bouncer|x"},
			{ID: "*b", Address: "203.0.113.22", Comment: "crowdsec-bouncer|x"},
		},
	}
	mgr := ipv4Manager(mock)
	mgr.beginPass()
	snapshot := []*crowdsec.Decision{liveDecision("203.0.113.21", "recount-cs"), liveDecision("203.0.113.22", "recount-capi")}
	if _, err := mgr.reconcileProtocolAddresses(context.Background(), "ip", snapshot, time.Now()); err != nil {
		t.Fatal(err)
	}
	mgr.liveBan(liveDecision("203.0.113.23", "recount-cs"))
	mgr.liveUnban(liveDecision("203.0.113.21", "recount-cs"))
	metrics.SetActiveDecisions("ipv4", 99)

	mgr.settleLive()

	if ipv4, _ := metrics.GetActiveDecisionsByIPType(); ipv4 != 2 {
		t.Fatalf("expected 2 active IPv4 decisions (.22 and .23), got %d", ipv4)
	}
	origins := metrics.GetActiveDecisionsByOrigin()
	if origins["recount-cs"] != 1 || origins["recount-capi"] != 1 {
		t.Fatalf("expected one decision per origin, got %v", origins)
	}
}

// blockingSnapshot returns a stream whose snapshot reports each request on
// asked and waits for release, or for the pass's context to end; ended
// counts the snapshots that returned.
func blockingSnapshot(decisions []*crowdsec.Decision) (stream *mockStream, asked, release chan struct{}, ended *atomic.Int32) {
	asked = make(chan struct{}, 8)
	release = make(chan struct{})
	ended = &atomic.Int32{}
	stream = &mockStream{ActiveDecisionsFunc: func(ctx context.Context) ([]*crowdsec.Decision, error) {
		defer ended.Add(1)
		asked <- struct{}{}
		select {
		case <-release:
			return decisions, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	return stream, asked, release, ended
}

func waitSignal(t *testing.T, name string, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

type loopChans struct {
	ban, del   chan *crowdsec.Decision
	err        chan error
	reconcileC chan time.Time
	rebootC    chan struct{}
}

func newLoopChans() loopChans {
	return loopChans{
		ban:        make(chan *crowdsec.Decision, 1),
		del:        make(chan *crowdsec.Decision, 1),
		err:        make(chan error, 1),
		reconcileC: make(chan time.Time, 1),
		rebootC:    make(chan struct{}, 1),
	}
}

func (c loopChans) run(ctx context.Context, mgr *Manager) chan error {
	result := make(chan error, 1)
	go func() {
		result <- mgr.processLiveDecisions(ctx, c.ban, c.del, c.err, c.reconcileC, c.rebootC, nil)
	}()
	return result
}

func ipv4Config() config.Config {
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	return cfg
}

// TestProcessLiveDecisions_LiveBanDuringPass verifies that a live ban reaches
// the router while a pass runs, not when it ends.
func TestProcessLiveDecisions_LiveBanDuringPass(t *testing.T) {
	mock := &mockROS{addAddressID: "*1"}
	stream, asked, release, _ := blockingSnapshot(nil)
	mgr := newTestManagerWithStream(mock, stream, ipv4Config())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newLoopChans()
	c.reconcileC <- time.Now()
	result := c.run(ctx, mgr)

	waitSignal(t, "the pass", asked)
	c.ban <- liveDecision("203.0.113.30", "crowdsec")
	waitForManagerCondition(t, "the live ban during the pass", func() bool { return len(addedAddresses(mock)) == 1 })
	close(release)
	cancel()
	if err := waitForManagerResult(t, result); err != nil {
		t.Fatal(err)
	}
}

// TestProcessLiveDecisions_LiveBanWhileWaitingForCalm verifies that a live ban
// reaches the router while a periodic pass waits for the router's CPU.
func TestProcessLiveDecisions_LiveBanWhileWaitingForCalm(t *testing.T) {
	mock := &mockROS{addAddressID: "*1"}
	mgr := newTestManagerWithStream(mock, &mockStream{}, ipv4Config())
	release := make(chan struct{})
	fp := &fakePacer{waitFunc: func(ctx context.Context) error {
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	mgr.pacer = fp
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newLoopChans()
	c.reconcileC <- time.Now()
	result := c.run(ctx, mgr)

	waitForManagerCondition(t, "the wait for calm", func() bool { return fp.waitCount() == 1 })
	c.ban <- liveDecision("203.0.113.31", "crowdsec")
	waitForManagerCondition(t, "the live ban during the wait", func() bool { return len(addedAddresses(mock)) == 1 })
	close(release)
	cancel()
	if err := waitForManagerResult(t, result); err != nil {
		t.Fatal(err)
	}
}

// TestProcessLiveDecisions_StreamErrorStopsTheRunningPass verifies that a
// stream error during a pass ends the pass and returns once it has ended.
func TestProcessLiveDecisions_StreamErrorStopsTheRunningPass(t *testing.T) {
	stream, asked, _, ended := blockingSnapshot(nil)
	mgr := newTestManagerWithStream(&mockROS{}, stream, ipv4Config())
	ctx := t.Context()
	c := newLoopChans()
	c.reconcileC <- time.Now()
	result := c.run(ctx, mgr)

	waitSignal(t, "the pass", asked)
	c.err <- errors.New("stream down")
	if err := waitForManagerResult(t, result); err == nil || !strings.Contains(err.Error(), "stream down") {
		t.Fatalf("expected the stream error, got %v", err)
	}
	if ended.Load() != 1 {
		t.Fatal("expected the pass ended before the loop returned")
	}
}

// TestProcessLiveDecisions_ShutdownWaitsForTheRunningPass verifies that the
// loop returns only once a running pass has ended, so Shutdown never runs
// beside it.
func TestProcessLiveDecisions_ShutdownWaitsForTheRunningPass(t *testing.T) {
	stream, asked, _, ended := blockingSnapshot(nil)
	mgr := newTestManagerWithStream(&mockROS{}, stream, ipv4Config())
	ctx, cancel := context.WithCancel(context.Background())
	c := newLoopChans()
	c.reconcileC <- time.Now()
	result := c.run(ctx, mgr)

	waitSignal(t, "the pass", asked)
	cancel()
	if err := waitForManagerResult(t, result); err != nil {
		t.Fatal(err)
	}
	if ended.Load() != 1 {
		t.Fatal("expected the pass ended before the loop returned")
	}
}

// TestProcessLiveDecisions_TickDuringPassRunsAfter verifies that a periodic
// tick that arrives during a pass runs one pass once it ends.
func TestProcessLiveDecisions_TickDuringPassRunsAfter(t *testing.T) {
	stream, asked, release, _ := blockingSnapshot(nil)
	mgr := newTestManagerWithStream(&mockROS{}, stream, ipv4Config())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newLoopChans()
	c.reconcileC <- time.Now()
	result := c.run(ctx, mgr)

	waitSignal(t, "the first pass", asked)
	c.reconcileC <- time.Now()
	select {
	case <-asked:
		t.Fatal("a second pass ran beside the first")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	waitSignal(t, "the owed pass", asked)
	cancel()
	if err := waitForManagerResult(t, result); err != nil {
		t.Fatal(err)
	}
}

// TestProcessLiveDecisions_RebootDuringPassRunsAfterWithoutWait verifies that
// a reboot during a pass runs one pass once it ends, without waiting for a
// calm router, also when a periodic tick was owed first.
func TestProcessLiveDecisions_RebootDuringPassRunsAfterWithoutWait(t *testing.T) {
	stream, asked, release, _ := blockingSnapshot(nil)
	mgr := newTestManagerWithStream(&mockROS{}, stream, ipv4Config())
	fp := &fakePacer{}
	mgr.pacer = fp
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newLoopChans()
	c.reconcileC <- time.Now()
	result := c.run(ctx, mgr)

	waitSignal(t, "the first pass", asked)
	c.reconcileC <- time.Now()
	waitForManagerCondition(t, "the tick taken", func() bool { return len(c.reconcileC) == 0 })
	c.rebootC <- struct{}{}
	waitForManagerCondition(t, "the reboot taken", func() bool { return len(c.rebootC) == 0 })
	close(release)
	waitSignal(t, "the pass after the reboot", asked)
	cancel()
	if err := waitForManagerResult(t, result); err != nil {
		t.Fatal(err)
	}
	if got := fp.waitCount(); got != 1 {
		t.Fatalf("expected only the periodic pass to wait for calm, got %d waits", got)
	}
}

// TestProcessLiveDecisions_PassLeavesLiveBanAlone verifies the journal is
// open while a pass runs: an address banned live while the pass fetched its
// snapshot is not removed by the pass, though the snapshot lacks it, and the
// journal is closed once the pass has ended.
func TestProcessLiveDecisions_PassLeavesLiveBanAlone(t *testing.T) {
	mock := &mockROS{
		addAddressID:  "*x",
		listAddresses: []ros.AddressEntry{{ID: "*x", Address: "203.0.113.32", Comment: "crowdsec-bouncer|old"}},
	}
	stream, asked, release, ended := blockingSnapshot(nil)
	mgr := newTestManagerWithStream(mock, stream, ipv4Config())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newLoopChans()
	c.reconcileC <- time.Now()
	result := c.run(ctx, mgr)

	waitSignal(t, "the pass", asked)
	c.ban <- liveDecision("203.0.113.32", "crowdsec")
	waitForManagerCondition(t, "the live ban", func() bool { return len(addedAddresses(mock)) == 1 })
	close(release)
	waitForManagerCondition(t, "the pass settled", func() bool {
		mgr.passMu.Lock()
		defer mgr.passMu.Unlock()
		return ended.Load() == 1 && mgr.passLive == nil
	})
	cancel()
	if err := waitForManagerResult(t, result); err != nil {
		t.Fatal(err)
	}
	if got := removedIDs(mock); len(got) != 0 {
		t.Fatalf("expected the live ban left alone, got removals %v", got)
	}
}

// TestStart_LiveBanDuringFirstPass verifies that live decisions are applied
// while the first reconciliation runs, not once it ends.
func TestStart_LiveBanDuringFirstPass(t *testing.T) {
	setTestInitialCollectionTimings(t, time.Millisecond, time.Millisecond)
	mock := &mockROS{
		addAddressID:  "*1",
		listAddresses: []ros.AddressEntry{{ID: "*s", Address: "203.0.113.40", Comment: "crowdsec-bouncer|stale"}},
	}
	sendLive := make(chan struct{})
	stream := &mockStream{RunFunc: func(ctx context.Context, banCh, _ chan<- *crowdsec.Decision) error {
		select {
		case <-sendLive:
			banCh <- liveDecision("203.0.113.41", "crowdsec")
		case <-ctx.Done():
		}
		<-ctx.Done()
		return nil
	}}
	mgr := newTestManagerWithStream(mock, stream, ipv4Config())
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	mgr.pacer = &fakePacer{entryFunc: func(ctx context.Context) error {
		entered <- struct{}{} // the first pass removes the stale entry
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- mgr.Start(ctx) }()

	waitSignal(t, "the first pass", entered)
	close(sendLive)
	waitForManagerCondition(t, "the live ban during the first pass", func() bool { return len(addedAddresses(mock)) == 1 })
	close(release)
	cancel()
	if err := waitForManagerResult(t, result); err != nil {
		t.Fatal(err)
	}
}

// TestProcessLiveDecisions_RetryDuringASuccessfulPassIsDropped verifies that a
// retry that fires during a pass that then succeeds runs no extra pass: the
// pass reconciled what the retry was for, as on the loop before passes ran
// beside it, where a successful pass cleared the retry.
func TestProcessLiveDecisions_RetryDuringASuccessfulPassIsDropped(t *testing.T) {
	stream, asked, release, ended := blockingSnapshot(nil)
	mgr := newTestManagerWithStream(&mockROS{}, stream, ipv4Config())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newLoopChans()
	c.reconcileC <- time.Now()
	retryC := make(chan time.Time, 1)
	result := make(chan error, 1)
	go func() {
		result <- mgr.processLiveDecisions(ctx, c.ban, c.del, c.err, c.reconcileC, c.rebootC, retryC)
	}()

	waitSignal(t, "the pass", asked)
	retryC <- time.Now()
	waitForManagerCondition(t, "the retry taken", func() bool { return len(retryC) == 0 })
	close(release)
	waitForManagerCondition(t, "the pass ended", func() bool { return ended.Load() == 1 })
	select {
	case <-asked:
		t.Fatal("expected no extra pass after a successful one")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if err := waitForManagerResult(t, result); err != nil {
		t.Fatal(err)
	}
}

// TestProcessLiveDecisions_RetryDuringAFailedPassWaitsItsTurn verifies that a
// retry that fires during a pass that then fails does not run at once on top
// of the retry the failure schedules, which would double the back-off.
func TestProcessLiveDecisions_RetryDuringAFailedPassWaitsItsTurn(t *testing.T) {
	prev := reconcileRetryInterval
	reconcileRetryInterval = time.Hour
	t.Cleanup(func() { reconcileRetryInterval = prev })

	asked := make(chan struct{}, 8)
	release := make(chan struct{})
	stream := &mockStream{ActiveDecisionsFunc: func(ctx context.Context) ([]*crowdsec.Decision, error) {
		asked <- struct{}{}
		select {
		case <-release:
			return nil, errors.New("LAPI not reachable")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	mgr := newTestManagerWithStream(&mockROS{}, stream, ipv4Config())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newLoopChans()
	c.reconcileC <- time.Now()
	retryC := make(chan time.Time, 1)
	result := make(chan error, 1)
	go func() {
		result <- mgr.processLiveDecisions(ctx, c.ban, c.del, c.err, c.reconcileC, c.rebootC, retryC)
	}()

	waitSignal(t, "the pass", asked)
	retryC <- time.Now()
	waitForManagerCondition(t, "the retry taken", func() bool { return len(retryC) == 0 })
	close(release)
	select {
	case <-asked:
		t.Fatal("expected the failed pass's retry to wait its turn")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if err := waitForManagerResult(t, result); err != nil {
		t.Fatal(err)
	}
}

// TestProcessLiveDecisions_RebootDuringAFailedPassStartsFromTheFirstWait
// verifies that the pass a reboot asks for during a pass that then fails still
// starts from the first wait: the router lost every dynamic entry.
func TestProcessLiveDecisions_RebootDuringAFailedPassStartsFromTheFirstWait(t *testing.T) {
	prev := reconcileRetryInterval
	reconcileRetryInterval = time.Hour
	t.Cleanup(func() { reconcileRetryInterval = prev })

	var mgr *Manager
	asked := make(chan time.Duration, 8)
	release := make(chan struct{})
	stream := &mockStream{ActiveDecisionsFunc: func(ctx context.Context) ([]*crowdsec.Decision, error) {
		asked <- mgr.retryDelay
		select {
		case <-release:
			return nil, errors.New("LAPI not reachable")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	mgr = newTestManagerWithStream(&mockROS{}, stream, ipv4Config())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newLoopChans()
	c.reconcileC <- time.Now()
	result := c.run(ctx, mgr)

	select {
	case <-asked:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the pass")
	}
	c.rebootC <- struct{}{}
	waitForManagerCondition(t, "the reboot taken", func() bool { return len(c.rebootC) == 0 })
	close(release)
	select {
	case delay := <-asked:
		if delay != 0 {
			t.Fatalf("expected the reboot's pass to start from the first wait, got a delay of %v", delay)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the reboot's pass")
	}
	cancel()
	if err := waitForManagerResult(t, result); err != nil {
		t.Fatal(err)
	}
}

// TestSettleLive_LeavesAloneWhatTheLivePathSettled verifies that a live ban
// the router refused, or a foreign entry holds, is not tried again once the
// pass ends: the answer would be the same, and for a foreign entry it costs a
// lookup that walks the whole list.
func TestSettleLive_LeavesAloneWhatTheLivePathSettled(t *testing.T) {
	for _, liveErr := range []error{ros.ErrForeignEntry, ros.ErrAddRefused} {
		mock := &mockROS{addAddressErr: liveErr}
		mgr := ipv4Manager(mock)
		mgr.beginPass()
		mgr.liveBan(liveDecision("203.0.113.50", "crowdsec"))

		mgr.settleLive()

		if got := addedAddresses(mock); len(got) != 1 {
			t.Fatalf("%v: expected the live add only, got %v", liveErr, got)
		}
	}
}

// TestProcessLiveDecisions_LiveUnbanDuringPass verifies that a live unban
// removes the entry while a pass runs, and that the pass, whose snapshot and
// listing still have it, neither adds it back nor counts on it.
func TestProcessLiveDecisions_LiveUnbanDuringPass(t *testing.T) {
	const addr = "203.0.113.60"
	mock := &mockROS{listAddresses: []ros.AddressEntry{{ID: "*u", Address: addr, Comment: "crowdsec-bouncer|old"}}}
	stream, asked, release, ended := blockingSnapshot([]*crowdsec.Decision{liveDecision(addr, "crowdsec")})
	mgr := newTestManagerWithStream(mock, stream, ipv4Config())
	mgr.addressCache[addr] = "*u"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newLoopChans()
	c.reconcileC <- time.Now()
	result := c.run(ctx, mgr)

	waitSignal(t, "the pass", asked)
	c.del <- liveDecision(addr, "crowdsec")
	waitForManagerCondition(t, "the live unban during the pass", func() bool { return len(removedIDs(mock)) == 1 })
	close(release)
	waitForManagerCondition(t, "the pass settled", func() bool {
		mgr.passMu.Lock()
		defer mgr.passMu.Unlock()
		return ended.Load() == 1 && mgr.passLive == nil
	})
	cancel()
	if err := waitForManagerResult(t, result); err != nil {
		t.Fatal(err)
	}
	if _, known := mgr.knownAddress(addr); known {
		t.Fatal("expected the unbanned address unknown after the pass")
	}
	if len(mock.bulkAddCalls) != 0 || len(removedIDs(mock)) != 1 {
		t.Fatalf("expected the pass to leave the address alone, got %d bulk adds and removals %v", len(mock.bulkAddCalls), removedIDs(mock))
	}
}

// TestReconcile_LeavesLiveIPv6AddressesToTheLivePath verifies that the journal
// matches an IPv6 address however the decision wrote it, and only on the
// IPv6 pass.
func TestReconcile_LeavesLiveIPv6AddressesToTheLivePath(t *testing.T) {
	listed := ros.NormalizeAddress("2001:db8::5", "ipv6")
	mock := &mockROS{
		addAddressID:  "*6",
		listAddresses: []ros.AddressEntry{{ID: "*6", Address: listed, Comment: "crowdsec-bouncer|old"}},
	}
	mgr := newTestManager(mock, baseConfig())
	mgr.beginPass()
	mgr.liveBan(&crowdsec.Decision{Value: "2001:DB8:0::5", Proto: "ipv6", Origin: "crowdsec", Duration: time.Hour})

	if live := mgr.liveFor("ip"); len(live) != 0 {
		t.Fatalf("expected no IPv6 record on the IPv4 pass, got %v", live)
	}
	if _, err := mgr.reconcileProtocolAddresses(context.Background(), "ipv6", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := removedIDs(mock); len(got) != 0 {
		t.Fatalf("expected the live IPv6 ban left alone, got removals %v", got)
	}
}

// TestReconcile_RepairsAStaleCachedLiveBan verifies that a live ban the cache
// answered, though the router had lost the entry (after a reboot, say), does
// not keep the pass from adding the address again: the live path wrote
// nothing, so the pass, whose listing lacks the address, adds it.
func TestReconcile_RepairsAStaleCachedLiveBan(t *testing.T) {
	const addr = "203.0.113.70"
	mock := &mockROS{}
	mgr := ipv4Manager(mock)
	mgr.addressCache[addr] = "*gone"
	mgr.beginPass()
	mgr.liveBan(liveDecision(addr, "crowdsec")) // cached: nothing written

	snapshot := []*crowdsec.Decision{liveDecision(addr, "crowdsec")}
	if _, err := mgr.reconcileProtocolAddresses(context.Background(), "ip", snapshot, time.Now()); err != nil {
		t.Fatal(err)
	}

	var bulk []string
	for _, call := range mock.bulkAddCalls {
		for _, e := range call.Entries {
			bulk = append(bulk, e.Address)
		}
	}
	if !slices.Equal(bulk, []string{addr}) {
		t.Fatalf("expected the pass to add the address the router lost, got %v", bulk)
	}
}

// TestReconcile_RemovesAListedUncachedLiveUnban verifies that a live unban
// the cache did not know of, for an address the router still holds, does not
// keep the pass from removing it: the live path removed nothing.
func TestReconcile_RemovesAListedUncachedLiveUnban(t *testing.T) {
	const addr = "203.0.113.71"
	mock := &mockROS{listAddresses: []ros.AddressEntry{{ID: "*l", Address: addr, Comment: "crowdsec-bouncer|old"}}}
	mgr := ipv4Manager(mock)
	mgr.beginPass()
	mgr.liveUnban(liveDecision(addr, "crowdsec")) // unknown: nothing removed

	snapshot := []*crowdsec.Decision{liveDecision(addr, "crowdsec")} // taken before the unban
	if _, err := mgr.reconcileProtocolAddresses(context.Background(), "ip", snapshot, time.Now()); err != nil {
		t.Fatal(err)
	}

	if got := removedIDs(mock); !slices.Equal(got, []string{"*l"}) {
		t.Fatalf("expected the pass to remove the unbanned address, got %v", got)
	}
}

// TestReconcile_LeavesARefusedLiveBanAlone verifies that the pass does not
// send again an add the router refused live during it: the answer would be
// the same, and a refused add fails the pass.
func TestReconcile_LeavesARefusedLiveBanAlone(t *testing.T) {
	const addr = "203.0.113.72"
	mock := &mockROS{addAddressErr: ros.ErrAddRefused}
	mgr := ipv4Manager(mock)
	mgr.beginPass()
	mgr.liveBan(liveDecision(addr, "crowdsec"))

	snapshot := []*crowdsec.Decision{liveDecision(addr, "crowdsec")}
	if _, err := mgr.reconcileProtocolAddresses(context.Background(), "ip", snapshot, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(mock.bulkAddCalls) != 0 {
		t.Fatalf("expected the refused address left alone, got %d bulk adds", len(mock.bulkAddCalls))
	}
}
