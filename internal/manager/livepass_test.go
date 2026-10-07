package manager

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

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
// listing nor caches again one unbanned live after it.
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
	if _, known := mgr.knownAddress("203.0.113.3"); !known {
		t.Fatal("expected the failed live ban to stay uncertain")
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
