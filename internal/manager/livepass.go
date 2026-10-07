package manager

import (
	"maps"
	"slices"

	"github.com/jmrplens/cs-routeros-bouncer/internal/crowdsec"
	"github.com/jmrplens/cs-routeros-bouncer/internal/metrics"
	rosClient "github.com/jmrplens/cs-routeros-bouncer/internal/routeros"
)

// Live decisions during a reconciliation pass.
//
// A pass works from a snapshot of the active decisions and a listing of the
// router, both taken at its start, and can run for minutes while the router's
// CPU is busy. The decision loop applies live bans and unbans meanwhile, and
// notes each in a journal (passLive) that lives as long as the pass:
//
//   - the pass leaves a noted address to the live path: it neither adds nor
//     removes it, its cache refresh does not touch it, and it expects what
//     the decision's last word says (reconcileDiff.leaveToLive);
//   - once the pass ends, settleLive brings each noted address to that last
//     word, since a decision noted after the pass planned can still meet the
//     pass's adds and removals, and sets the active-decision gauges from what
//     the pass expected and those last words.
//
// A decision is counted once: when it arrives, or, if it did nothing then,
// when settleLive applies it.

// liveDuringPass is the last live decision on one address while a
// reconciliation pass runs.
type liveDuringPass struct {
	d       *crowdsec.Decision
	ban     bool // a ban; false, an unban
	counted bool // its metrics were recorded when it arrived
}

// beginPass opens the journal of the pass about to run.
func (m *Manager) beginPass() {
	m.passMu.Lock()
	defer m.passMu.Unlock()
	m.passLive = make(map[string]*liveDuringPass)
	m.passDesired = make(map[string]map[string]*crowdsec.Decision)
}

// noteLive records d as the last live decision on its address, and returns
// the record; nil when no pass runs.
func (m *Manager) noteLive(d *crowdsec.Decision, ban bool) *liveDuringPass {
	if d == nil {
		return nil
	}
	m.passMu.Lock()
	defer m.passMu.Unlock()
	if m.passLive == nil {
		return nil
	}
	e := &liveDuringPass{d: d, ban: ban}
	m.passLive[rosClient.NormalizeAddress(d.Value, d.Proto)] = e
	return e
}

// markCounted records that e's metrics were recorded.
func (m *Manager) markCounted(e *liveDuringPass) {
	if e == nil {
		return
	}
	m.passMu.Lock()
	defer m.passMu.Unlock()
	e.counted = true
}

// liveBan is the decision loop's ban: noted for the running pass, if any,
// then applied as handleBan applies it.
func (m *Manager) liveBan(d *crowdsec.Decision) (reconcileOwed bool) {
	e := m.noteLive(d, true)
	added, reconcileOwed := m.ban(d, true)
	if added {
		m.markCounted(e)
	}
	return reconcileOwed
}

// liveUnban is the decision loop's unban: noted for the running pass, if any,
// then applied as handleUnban applies it.
func (m *Manager) liveUnban(d *crowdsec.Decision) {
	e := m.noteLive(d, false)
	if m.unban(d, true) {
		m.markCounted(e)
	}
}

// liveFor returns a copy of the journal's records for proto's addresses, nil
// when no pass runs.
func (m *Manager) liveFor(proto string) map[string]liveDuringPass {
	m.passMu.Lock()
	defer m.passMu.Unlock()
	if len(m.passLive) == 0 {
		return nil
	}
	live := make(map[string]liveDuringPass)
	for addr, e := range m.passLive {
		if e.d.Proto == proto {
			live[addr] = *e
		}
	}
	return live
}

// notePassDesired records what the running pass expects for proto.
func (m *Manager) notePassDesired(proto string, desired map[string]*crowdsec.Decision) {
	m.passMu.Lock()
	defer m.passMu.Unlock()
	if m.passDesired != nil {
		m.passDesired[proto] = desired
	}
}

// leaveToLive leaves the addresses of live decisions to the live path: the
// pass neither adds nor removes them, and expects what their last word says.
func (diff *reconcileDiff) leaveToLive(proto string, live map[string]liveDuringPass) {
	if len(live) == 0 {
		return
	}
	for addr, e := range live {
		if e.ban {
			diff.shouldExist[addr] = e.d
		} else {
			delete(diff.shouldExist, addr)
		}
	}
	diff.toAdd = slices.DeleteFunc(diff.toAdd, func(entry rosClient.BulkEntry) bool {
		_, noted := live[rosClient.NormalizeAddress(entry.Address, proto)]
		return noted
	})
	diff.toRemove = slices.DeleteFunc(diff.toRemove, func(entry rosClient.AddressEntry) bool {
		_, noted := live[entry.Address]
		return noted
	})
}

// settleLive closes the pass's journal and brings each address a live
// decision touched during the pass to that decision's last word, counting it
// only if it was not counted when it arrived. It then sets the
// active-decision gauges, and reports whether a ban it could not make owes a
// reconcile. It runs on the decision loop once the pass has ended.
func (m *Manager) settleLive() (reconcileOwed bool) {
	m.passMu.Lock()
	live, desired := m.passLive, m.passDesired
	m.passLive, m.passDesired = nil, nil
	m.passMu.Unlock()
	if len(live) == 0 {
		return false
	}
	for _, e := range live {
		if e.ban {
			_, owed := m.ban(e.d, !e.counted)
			reconcileOwed = reconcileOwed || owed
			continue
		}
		m.unban(e.d, !e.counted)
	}
	m.recountActive(live, desired)
	return reconcileOwed
}

// recountActive sets the active-decision gauges from what the pass expected
// for each protocol it read and the last word of each live decision: what the
// gauges would show had the decisions waited for the pass to end. Like
// reconcileAddresses, it replaces the per-origin gauge only when the pass read
// every list.
func (m *Manager) recountActive(live map[string]*liveDuringPass, desired map[string]map[string]*crowdsec.Decision) {
	origins := map[string]int64{}
	for proto, expected := range desired {
		merged := maps.Clone(expected)
		for addr, e := range live {
			if e.d.Proto != proto {
				continue
			}
			if e.ban {
				merged[addr] = e.d
			} else {
				delete(merged, addr)
			}
		}
		metrics.SetActiveDecisions(metricsProtoName(proto), len(merged))
		mergeOriginCounts(origins, originCounts(merged))
	}
	if len(desired) == len(m.enabledProtos()) {
		metrics.ReplaceActiveDecisionsByOrigin(origins)
		return
	}
	for origin, count := range origins {
		metrics.SetActiveDecisionsByOrigin(origin, count)
	}
}
