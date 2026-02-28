// Tests for the metrics package covering Prometheus metric recording,
// the HTTP health endpoint, the metrics server lifecycle, per-origin
// active decision tracking, dropped/processed counter delta logic,
// and per-ip_type LAPI delta metrics.
package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// resetOriginAndDropped clears the package-level per-origin and dropped
// counter state so tests run in isolation.
func resetOriginAndDropped() {
	originDecisionsMu.Lock()
	originDecisions = map[string]int64{}
	originDecisionsMu.Unlock()

	droppedCountersMu.Lock()
	droppedCounters = DroppedCounters{}
	lastSentCounters = DroppedCounters{}
	droppedCountersMu.Unlock()
}

// TestRecordDecision verifies that RecordDecision increments the
// crowdsec_bouncer_decisions_total counter with the correct labels.
func TestRecordDecision(t *testing.T) {
	RecordDecision("ban", "ip", "crowdsec")
	RecordDecision("ban", "ip", "crowdsec")

	expected := `
# HELP crowdsec_bouncer_decisions_total Total number of decisions processed.
# TYPE crowdsec_bouncer_decisions_total counter
crowdsec_bouncer_decisions_total{action="ban",origin="crowdsec",proto="ip"} 2
`
	if err := testutil.CollectAndCompare(decisionsTotal, strings.NewReader(expected),
		"crowdsec_bouncer_decisions_total"); err != nil {
		t.Errorf("unexpected metric result: %v", err)
	}
}

// TestRecordError verifies that RecordError increments the errors counter
// with the specified operation label.
func TestRecordError(t *testing.T) {
	RecordError("add_address")
	if got := testutil.ToFloat64(errorsTotal.WithLabelValues("add_address")); got != 1 {
		t.Errorf("expected error count 1, got %v", got)
	}
}

// TestSetActiveDecisions verifies that SetActiveDecisions correctly sets
// the gauge value for a given protocol, including normalizing "ip" to "ipv4".
func TestSetActiveDecisions(t *testing.T) {
	SetActiveDecisions("ip", 42)
	if got := testutil.ToFloat64(activeDecisions.WithLabelValues("ipv4")); got != 42 {
		t.Errorf("expected 42, got %v", got)
	}
}

// TestSetActiveDecisionsUpdatesAtomicCounters verifies that SetActiveDecisions
// updates both the Prometheus gauge and the internal atomic counters used by
// the LAPI metrics reporter.
func TestSetActiveDecisionsUpdatesAtomicCounters(t *testing.T) {
	SetActiveDecisions("ipv4", 100)
	SetActiveDecisions("ipv6", 50)

	total := GetTotalActiveDecisions()
	if total != 150 {
		t.Errorf("expected total 150 (100+50), got %d", total)
	}
}

// TestGetTotalActiveDecisionsZero verifies that GetTotalActiveDecisions
// returns 0 when no active decisions have been set.
func TestGetTotalActiveDecisionsZero(t *testing.T) {
	SetActiveDecisions("ipv4", 0)
	SetActiveDecisions("ipv6", 0)

	total := GetTotalActiveDecisions()
	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}
}

// TestGetTotalActiveDecisionsIPv4Only verifies the counter when only IPv4
// decisions are present.
func TestGetTotalActiveDecisionsIPv4Only(t *testing.T) {
	SetActiveDecisions("ipv4", 500)
	SetActiveDecisions("ipv6", 0)

	total := GetTotalActiveDecisions()
	if total != 500 {
		t.Errorf("expected total 500, got %d", total)
	}
}

// TestGetTotalActiveDecisionsIPv6Only verifies the counter when only IPv6
// decisions are present.
func TestGetTotalActiveDecisionsIPv6Only(t *testing.T) {
	SetActiveDecisions("ipv4", 0)
	SetActiveDecisions("ipv6", 200)

	total := GetTotalActiveDecisions()
	if total != 200 {
		t.Errorf("expected total 200, got %d", total)
	}
}

// TestSetActiveDecisionsOverwrite verifies that subsequent calls to
// SetActiveDecisions overwrite (not accumulate) the counter.
func TestSetActiveDecisionsOverwrite(t *testing.T) {
	SetActiveDecisions("ipv4", 100)
	SetActiveDecisions("ipv4", 200)

	// The gauge should show 200, not 300
	if got := testutil.ToFloat64(activeDecisions.WithLabelValues("ipv4")); got != 200 {
		t.Errorf("expected gauge 200 after overwrite, got %v", got)
	}

	SetActiveDecisions("ipv6", 0)
	total := GetTotalActiveDecisions()
	if total != 200 {
		t.Errorf("expected total 200 after overwrite, got %d", total)
	}
}

// TestSetConnected verifies that SetConnected updates the RouterOS
// connection gauge to 1 for connected and 0 for disconnected.
func TestSetConnected(t *testing.T) {
	SetConnected(true)
	if got := testutil.ToFloat64(routerosConnected); got != 1 {
		t.Errorf("expected 1 for connected, got %v", got)
	}
	SetConnected(false)
	if got := testutil.ToFloat64(routerosConnected); got != 0 {
		t.Errorf("expected 0 for disconnected, got %v", got)
	}
}

// TestObserveOperationDuration verifies that ObserveOperationDuration records
// a histogram observation for the given operation.
func TestObserveOperationDuration(t *testing.T) {
	ObserveOperationDuration("reconcile", 100*time.Millisecond)

	// Collect the histogram vec to verify at least one observation was recorded.
	count := testutil.CollectAndCount(operationDuration, "crowdsec_bouncer_operation_duration_seconds")
	if count == 0 {
		t.Error("expected non-zero histogram observation count")
	}
}

// TestRecordReconciliation verifies that RecordReconciliation adds the
// correct count to the reconciliation counter.
func TestRecordReconciliation(t *testing.T) {
	RecordReconciliation("added", 5)
	if got := testutil.ToFloat64(reconciliationTotal.WithLabelValues("added")); got != 5 {
		t.Errorf("expected 5, got %v", got)
	}
}

// TestSetInfo verifies that SetInfo sets the bouncer info gauge with version
// and identity labels.
func TestSetInfo(t *testing.T) {
	SetInfo("1.0.0", "myrouter")
	if got := testutil.ToFloat64(bouncerInfo.WithLabelValues("1.0.0", "myrouter")); got != 1 {
		t.Errorf("expected 1, got %v", got)
	}
}

// TestSetStartTime verifies that SetStartTime records a non-zero timestamp.
func TestSetStartTime(t *testing.T) {
	SetStartTime()
	if got := testutil.ToFloat64(startTimeSeconds); got == 0 {
		t.Error("expected non-zero start time")
	}
}

// TestHandleHealthEndpoint verifies that the /health endpoint returns the
// expected JSON structure with status, connection state, and version.
func TestHandleHealthEndpoint(t *testing.T) {
	srv := &Server{version: "test-v1"}
	srv.connected.Store(true)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	srv.handleHealth(w, req)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected status 'ok', got '%v'", body["status"])
	}
	if body["routeros_connected"] != true {
		t.Errorf("expected routeros_connected true, got %v", body["routeros_connected"])
	}
	if body["version"] != "test-v1" {
		t.Errorf("expected version 'test-v1', got '%v'", body["version"])
	}
}

// TestHandleHealthDisconnected verifies that the /health endpoint reports
// disconnected state correctly.
func TestHandleHealthDisconnected(t *testing.T) {
	srv := &Server{version: "v0"}
	srv.connected.Store(false)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.handleHealth(w, req)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["routeros_connected"] != false {
		t.Errorf("expected false, got %v", body["routeros_connected"])
	}
}

// TestSetConnectedServer verifies the Server.SetConnected method updates
// the atomic boolean used by the health endpoint.
func TestSetConnectedServer(t *testing.T) {
	srv := &Server{version: "test"}
	srv.SetConnected(true)
	if !srv.connected.Load() {
		t.Error("expected connected=true after SetConnected(true)")
	}
	srv.SetConnected(false)
	if srv.connected.Load() {
		t.Error("expected connected=false after SetConnected(false)")
	}
}

// TestNewServerCreatesInstance verifies that NewServer returns a valid Server
// with a configured HTTP server listening on the specified address and port.
func TestNewServerCreatesInstance(t *testing.T) {
	cfg := config.MetricsConfig{
		ListenAddr: "127.0.0.1",
		ListenPort: 0, // will use ephemeral
	}
	srv := NewServer(cfg, "v1.0.0")
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
	if srv.version != "v1.0.0" {
		t.Errorf("expected version v1.0.0, got %s", srv.version)
	}
	if srv.httpServer == nil {
		t.Fatal("expected non-nil http server")
	}
}

// TestServerStartAndShutdown verifies the full lifecycle of the metrics
// server: start, verify it responds, and shut down gracefully.
func TestServerStartAndShutdown(t *testing.T) {
	// Find a free port
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cfg := config.MetricsConfig{
		ListenAddr: "127.0.0.1",
		ListenPort: port,
	}
	srv := NewServer(cfg, "test")

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// doGet is a helper that performs a context-aware HTTP GET.
	doGet := func(url string, client *http.Client) *http.Response {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("NewRequest(%s) error: %v", url, err)
		}
		if client == nil {
			client = http.DefaultClient
		}
		resp, err := client.Do(req) //nolint:gosec // test-only code with localhost URLs
		if err != nil {
			t.Fatalf("GET %s failed: %v", url, err)
		}
		return resp
	}

	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	// Verify /health responds
	resp := doGet(base+"/health", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// Verify /metrics responds
	resp = doGet(base+"/metrics", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// Verify root redirects to /metrics
	noRedirect := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp = doGet(base+"/", noRedirect)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("expected 301, got %d", resp.StatusCode)
	}

	// Verify 404 for unknown paths
	resp = doGet(base+"/unknown", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() error: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-origin active decision tracking
// ─────────────────────────────────────────────────────────────────────────────

// TestSetActiveDecisionsByOrigin verifies storing and retrieving per-origin counts,
// including the Prometheus gauge vec.
func TestSetActiveDecisionsByOrigin(t *testing.T) {
	resetOriginAndDropped()

	SetActiveDecisionsByOrigin("crowdsec", 100)
	SetActiveDecisionsByOrigin("cscli", 5)
	SetActiveDecisionsByOrigin("CAPI", 2000)

	got := GetActiveDecisionsByOrigin()
	if got["crowdsec"] != 100 {
		t.Errorf("crowdsec: want 100, got %d", got["crowdsec"])
	}
	if got["cscli"] != 5 {
		t.Errorf("cscli: want 5, got %d", got["cscli"])
	}
	if got["CAPI"] != 2000 {
		t.Errorf("CAPI: want 2000, got %d", got["CAPI"])
	}

	// Verify Prometheus gauge vec reflects the same values.
	if v := testutil.ToFloat64(activeDecisionsByOrigin.WithLabelValues("crowdsec")); v != 100 {
		t.Errorf("prometheus gauge crowdsec: want 100, got %v", v)
	}
	if v := testutil.ToFloat64(activeDecisionsByOrigin.WithLabelValues("cscli")); v != 5 {
		t.Errorf("prometheus gauge cscli: want 5, got %v", v)
	}
	if v := testutil.ToFloat64(activeDecisionsByOrigin.WithLabelValues("CAPI")); v != 2000 {
		t.Errorf("prometheus gauge CAPI: want 2000, got %v", v)
	}
}

// TestSetActiveDecisionsByOriginZeroDeletes verifies that setting count to 0
// removes the origin entry and sets the Prometheus gauge to 0.
func TestSetActiveDecisionsByOriginZeroDeletes(t *testing.T) {
	resetOriginAndDropped()

	SetActiveDecisionsByOrigin("crowdsec", 50)
	SetActiveDecisionsByOrigin("crowdsec", 0)

	got := GetActiveDecisionsByOrigin()
	if _, exists := got["crowdsec"]; exists {
		t.Error("expected crowdsec to be deleted when count is 0")
	}

	if v := testutil.ToFloat64(activeDecisionsByOrigin.WithLabelValues("crowdsec")); v != 0 {
		t.Errorf("prometheus gauge should be 0 after deletion, got %v", v)
	}
}

// TestSetActiveDecisionsByOriginNegativeDeletes verifies that negative counts
// also remove the entry.
func TestSetActiveDecisionsByOriginNegativeDeletes(t *testing.T) {
	resetOriginAndDropped()

	SetActiveDecisionsByOrigin("test", 10)
	SetActiveDecisionsByOrigin("test", -1)

	got := GetActiveDecisionsByOrigin()
	if _, exists := got["test"]; exists {
		t.Error("expected entry to be deleted for negative count")
	}
}

// TestGetActiveDecisionsByOriginReturnsSnapshot verifies that the returned map
// is a copy that doesn't alias the internal state.
func TestGetActiveDecisionsByOriginReturnsSnapshot(t *testing.T) {
	resetOriginAndDropped()

	SetActiveDecisionsByOrigin("crowdsec", 42)

	snap := GetActiveDecisionsByOrigin()
	snap["crowdsec"] = 999 // mutate the snapshot

	got := GetActiveDecisionsByOrigin()
	if got["crowdsec"] != 42 {
		t.Errorf("internal state was mutated via snapshot: got %d", got["crowdsec"])
	}
}

// TestOriginDecisionsConcurrency exercises concurrent read/write to check
// for data races (run with -race).
func TestOriginDecisionsConcurrency(t *testing.T) {
	resetOriginAndDropped()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			SetActiveDecisionsByOrigin(fmt.Sprintf("origin-%d", n%5), int64(n))
		}(i)
		go func() {
			defer wg.Done()
			_ = GetActiveDecisionsByOrigin()
		}()
	}
	wg.Wait()
}

// TestOriginOverwriteRegression reproduces the bug where iterating over
// protocols (ipv4 then ipv6) would overwrite origin counts because
// SetActiveDecisionsByOrigin uses .Set(), not .Add(). The correct pattern
// is to accumulate counts across protocols before calling Set.
func TestOriginOverwriteRegression(t *testing.T) {
	resetOriginAndDropped()

	// Simulate reconciliation: accumulate counts across both protocols
	// before calling SetActiveDecisionsByOrigin (as the fix does).
	globalOriginCounts := map[string]int64{}

	// IPv4 decisions
	ipv4Origins := map[string]int64{"CAPI": 22000, "crowdsec": 1400}
	for origin, count := range ipv4Origins {
		globalOriginCounts[origin] += count
	}

	// IPv6 decisions — CAPI present in both, crowdsec only in ipv4
	ipv6Origins := map[string]int64{"CAPI": 570}
	for origin, count := range ipv6Origins {
		globalOriginCounts[origin] += count
	}

	// Set final accumulated counts
	for origin, count := range globalOriginCounts {
		SetActiveDecisionsByOrigin(origin, count)
	}

	// Verify combined totals
	got := GetActiveDecisionsByOrigin()
	if got["CAPI"] != 22570 {
		t.Errorf("CAPI: want 22570, got %d", got["CAPI"])
	}
	if got["crowdsec"] != 1400 {
		t.Errorf("crowdsec: want 1400, got %d", got["crowdsec"])
	}

	// Verify Prometheus gauges
	if v := testutil.ToFloat64(activeDecisionsByOrigin.WithLabelValues("CAPI")); v != 22570 {
		t.Errorf("prometheus CAPI gauge: want 22570, got %v", v)
	}
	if v := testutil.ToFloat64(activeDecisionsByOrigin.WithLabelValues("crowdsec")); v != 1400 {
		t.Errorf("prometheus crowdsec gauge: want 1400, got %v", v)
	}
}

// TestOriginOverwriteBrokenPattern demonstrates what the OLD buggy code
// did: calling SetActiveDecisionsByOrigin per-proto overwrites earlier
// values because Set replaces rather than adds.
func TestOriginOverwriteBrokenPattern(t *testing.T) {
	resetOriginAndDropped()

	// Simulate the OLD buggy pattern: set per-proto separately.
	// IPv4 pass
	SetActiveDecisionsByOrigin("CAPI", 22000)
	SetActiveDecisionsByOrigin("crowdsec", 1400)
	// IPv6 pass — this OVERWRITES the IPv4 CAPI value
	SetActiveDecisionsByOrigin("CAPI", 570)
	// crowdsec not present in ipv6 — no call means it keeps 1400

	got := GetActiveDecisionsByOrigin()
	// This shows the overwrite: CAPI lost 22000 and only has 570
	if got["CAPI"] != 570 {
		t.Errorf("CAPI (broken pattern): want 570 (overwritten), got %d", got["CAPI"])
	}
	// crowdsec was not overwritten because ipv6 didn't have it
	if got["crowdsec"] != 1400 {
		t.Errorf("crowdsec (broken pattern): want 1400, got %d", got["crowdsec"])
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Incremental active decision updates (streaming ban/unban)
// ─────────────────────────────────────────────────────────────────────────────

// TestIncrDecrActiveDecisions verifies that IncrActiveDecisions and
// DecrActiveDecisions correctly update both the gauge and atomic counters.
func TestIncrDecrActiveDecisions(t *testing.T) {
	// Start from a known baseline
	SetActiveDecisions("ipv4", 100)
	SetActiveDecisions("ipv6", 20)

	// Simulate streaming bans
	IncrActiveDecisions("ipv4")
	IncrActiveDecisions("ipv4")
	IncrActiveDecisions("ipv6")

	ipv4, ipv6 := GetActiveDecisionsByIPType()
	if ipv4 != 102 {
		t.Errorf("ipv4 after incr: want 102, got %d", ipv4)
	}
	if ipv6 != 21 {
		t.Errorf("ipv6 after incr: want 21, got %d", ipv6)
	}
	if v := testutil.ToFloat64(activeDecisions.WithLabelValues("ipv4")); v != 102 {
		t.Errorf("prometheus ipv4 gauge: want 102, got %v", v)
	}
	if v := testutil.ToFloat64(activeDecisions.WithLabelValues("ipv6")); v != 21 {
		t.Errorf("prometheus ipv6 gauge: want 21, got %v", v)
	}

	// Simulate streaming unbans
	DecrActiveDecisions("ipv4")
	DecrActiveDecisions("ipv6")

	ipv4, ipv6 = GetActiveDecisionsByIPType()
	if ipv4 != 101 {
		t.Errorf("ipv4 after decr: want 101, got %d", ipv4)
	}
	if ipv6 != 20 {
		t.Errorf("ipv6 after decr: want 20, got %d", ipv6)
	}
}

// TestIncrDecrActiveDecisionsByOrigin verifies streaming updates to
// per-origin tracking.
func TestIncrDecrActiveDecisionsByOrigin(t *testing.T) {
	resetOriginAndDropped()

	// Simulate reconciliation baseline
	SetActiveDecisionsByOrigin("CAPI", 1000)
	SetActiveDecisionsByOrigin("crowdsec", 50)

	// Streaming bans
	IncrActiveDecisionsByOrigin("CAPI")
	IncrActiveDecisionsByOrigin("CAPI")
	IncrActiveDecisionsByOrigin("crowdsec")
	IncrActiveDecisionsByOrigin("cscli") // new origin during streaming

	got := GetActiveDecisionsByOrigin()
	if got["CAPI"] != 1002 {
		t.Errorf("CAPI: want 1002, got %d", got["CAPI"])
	}
	if got["crowdsec"] != 51 {
		t.Errorf("crowdsec: want 51, got %d", got["crowdsec"])
	}
	if got["cscli"] != 1 {
		t.Errorf("cscli: want 1, got %d", got["cscli"])
	}

	// Streaming unbans
	DecrActiveDecisionsByOrigin("CAPI")
	DecrActiveDecisionsByOrigin("cscli") // drops to 0 → removed

	got = GetActiveDecisionsByOrigin()
	if got["CAPI"] != 1001 {
		t.Errorf("CAPI after decr: want 1001, got %d", got["CAPI"])
	}
	if _, exists := got["cscli"]; exists {
		t.Error("cscli should be removed when count reaches 0")
	}
	if v := testutil.ToFloat64(activeDecisionsByOrigin.WithLabelValues("cscli")); v != 0 {
		t.Errorf("prometheus cscli gauge should be 0, got %v", v)
	}
}

// TestIncrActiveDecisionsByOriginEmptyOrigin verifies that an empty origin
// string is normalized to "unknown".
func TestIncrActiveDecisionsByOriginEmptyOrigin(t *testing.T) {
	resetOriginAndDropped()

	IncrActiveDecisionsByOrigin("")
	IncrActiveDecisionsByOrigin("")

	got := GetActiveDecisionsByOrigin()
	if got["unknown"] != 2 {
		t.Errorf("unknown: want 2, got %d", got["unknown"])
	}
}

// TestDecrActiveDecisionsByOriginBelowZero verifies that decrementing below
// zero cleans up the entry rather than going negative.
func TestDecrActiveDecisionsByOriginBelowZero(t *testing.T) {
	resetOriginAndDropped()

	IncrActiveDecisionsByOrigin("test")
	DecrActiveDecisionsByOrigin("test")
	DecrActiveDecisionsByOrigin("test") // would go to -1

	got := GetActiveDecisionsByOrigin()
	if _, exists := got["test"]; exists {
		t.Error("entry should be deleted, not negative")
	}
	if v := testutil.ToFloat64(activeDecisionsByOrigin.WithLabelValues("test")); v != 0 {
		t.Errorf("prometheus gauge should be 0, got %v", v)
	}
}

// TestIncrDecrConcurrency exercises concurrent incr/decr to check for races.
func TestIncrDecrConcurrency(t *testing.T) {
	resetOriginAndDropped()
	SetActiveDecisions("ipv4", 0)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			IncrActiveDecisions("ipv4")
			IncrActiveDecisionsByOrigin("CAPI")
		}()
		go func() {
			defer wg.Done()
			DecrActiveDecisions("ipv4")
			DecrActiveDecisionsByOrigin("CAPI")
		}()
	}
	wg.Wait()
	// Just checking no race / panic — final values are nondeterministic
}

// TestDroppedCountersDelta verifies the basic delta calculation and
// Prometheus gauge values.
func TestDroppedCountersDelta(t *testing.T) {
	resetOriginAndDropped()

	SetDroppedCounters(1000, 50)

	// Verify Prometheus gauges are set.
	if v := testutil.ToFloat64(droppedBytesTotal); v != 1000 {
		t.Errorf("prometheus dropped bytes: want 1000, got %v", v)
	}
	if v := testutil.ToFloat64(droppedPacketsTotal); v != 50 {
		t.Errorf("prometheus dropped packets: want 50, got %v", v)
	}

	b, p := GetAndResetDroppedDeltas()
	if b != 1000 || p != 50 {
		t.Errorf("first delta: want (1000,50), got (%d,%d)", b, p)
	}

	// Second call with higher values → returns only the increase.
	SetDroppedCounters(1500, 80)

	if v := testutil.ToFloat64(droppedBytesTotal); v != 1500 {
		t.Errorf("prometheus dropped bytes after update: want 1500, got %v", v)
	}
	if v := testutil.ToFloat64(droppedPacketsTotal); v != 80 {
		t.Errorf("prometheus dropped packets after update: want 80, got %v", v)
	}

	b, p = GetAndResetDroppedDeltas()
	if b != 500 || p != 30 {
		t.Errorf("second delta: want (500,30), got (%d,%d)", b, p)
	}
}

// TestDroppedCountersNoDelta verifies that calling GetAndResetDroppedDeltas
// twice without setting new counters returns zero.
func TestDroppedCountersNoDelta(t *testing.T) {
	resetOriginAndDropped()

	SetDroppedCounters(100, 10)
	_, _ = GetAndResetDroppedDeltas()

	b, p := GetAndResetDroppedDeltas()
	if b != 0 || p != 0 {
		t.Errorf("want (0,0), got (%d,%d)", b, p)
	}
}

// TestDroppedCountersWrapAround verifies that if counters decrease (rule
// recreation), the full new value is reported instead of a negative delta.
func TestDroppedCountersWrapAround(t *testing.T) {
	resetOriginAndDropped()

	SetDroppedCounters(5000, 200)
	_, _ = GetAndResetDroppedDeltas()

	// Counter resets to a smaller value (rule was recreated).
	SetDroppedCounters(300, 10)
	b, p := GetAndResetDroppedDeltas()
	if b != 300 || p != 10 {
		t.Errorf("after wrap: want (300,10), got (%d,%d)", b, p)
	}
}

// TestDroppedCountersConcurrency exercises concurrent access (run with -race).
func TestDroppedCountersConcurrency(t *testing.T) {
	resetOriginAndDropped()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n uint64) {
			defer wg.Done()
			SetDroppedCounters(n*100, n*10)
		}(uint64(i))
		go func() {
			defer wg.Done()
			_, _ = GetAndResetDroppedDeltas()
		}()
	}
	wg.Wait()
}

// TestSetRouterOSSystemMetrics verifies CPU load and memory gauges.
func TestSetRouterOSSystemMetrics(t *testing.T) {
	SetRouterOSSystemMetrics(42, 500_000_000, 1_000_000_000)

	v := testutil.ToFloat64(routerosCPULoad)
	if v != 42 {
		t.Errorf("cpu_load = %v, want 42", v)
	}
	v = testutil.ToFloat64(routerosMemoryUsed)
	if v != 500_000_000 {
		t.Errorf("memory_used = %v, want 500000000", v)
	}
	v = testutil.ToFloat64(routerosMemoryTotal)
	if v != 1_000_000_000 {
		t.Errorf("memory_total = %v, want 1000000000", v)
	}
}

// TestSetRouterOSCPUTemperature verifies the temperature gauge.
func TestSetRouterOSCPUTemperature(t *testing.T) {
	SetRouterOSCPUTemperature(55.5)
	v := testutil.ToFloat64(routerosCPUTemperature)
	if v != 55.5 {
		t.Errorf("cpu_temp = %v, want 55.5", v)
	}
}

// TestSetRouterOSSystemMetricsConcurrency exercises concurrent access (run with -race).
func TestSetRouterOSSystemMetricsConcurrency(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n float64) {
			defer wg.Done()
			SetRouterOSSystemMetrics(n, uint64(n*1000), uint64(n*2000))
		}(float64(i))
		go func(n float64) {
			defer wg.Done()
			SetRouterOSCPUTemperature(n)
		}(float64(i))
	}
	wg.Wait()
}

// --- RouterOS uptime, info, and per-proto dropped counter tests ---

// TestSetRouterOSUptime verifies that SetRouterOSUptime correctly sets the
// uptime gauge and that subsequent calls overwrite the previous value.
func TestSetRouterOSUptime(t *testing.T) {
	SetRouterOSUptime(86400)
	v := testutil.ToFloat64(routerosUptimeSeconds)
	if v != 86400 {
		t.Errorf("uptime = %v, want 86400", v)
	}
	SetRouterOSUptime(12345.5)
	v = testutil.ToFloat64(routerosUptimeSeconds)
	if v != 12345.5 {
		t.Errorf("uptime = %v, want 12345.5", v)
	}
}

// TestSetRouterOSInfo verifies that SetRouterOSInfo registers the info gauge
// with version and board_name labels, and that a second call replaces the labels.
func TestSetRouterOSInfo(t *testing.T) {
	routerosInfo.Reset()
	SetRouterOSInfo("7.21.3 (stable)", "RB5009UG+S+")
	expected := `
# HELP crowdsec_bouncer_routeros_info RouterOS system information.
# TYPE crowdsec_bouncer_routeros_info gauge
crowdsec_bouncer_routeros_info{board_name="RB5009UG+S+",version="7.21.3 (stable)"} 1
`
	if err := testutil.CollectAndCompare(routerosInfo, strings.NewReader(expected),
		"crowdsec_bouncer_routeros_info"); err != nil {
		t.Errorf("unexpected: %v", err)
	}

	// Second call replaces labels (Reset + Set).
	SetRouterOSInfo("7.22", "hAP ax3")
	v := testutil.ToFloat64(routerosInfo.WithLabelValues("7.22", "hAP ax3"))
	if v != 1 {
		t.Errorf("expected 1, got %v", v)
	}
}

// TestSetDroppedCountersByProto verifies that per-protocol dropped bytes and
// packets gauges are set correctly for both IPv4 and IPv6.
func TestSetDroppedCountersByProto(t *testing.T) {
	SetDroppedCountersByProto(1000, 10, 500, 5)
	if v := testutil.ToFloat64(droppedBytesProto.WithLabelValues("ipv4")); v != 1000 {
		t.Errorf("ipv4 bytes = %v, want 1000", v)
	}
	if v := testutil.ToFloat64(droppedBytesProto.WithLabelValues("ipv6")); v != 500 {
		t.Errorf("ipv6 bytes = %v, want 500", v)
	}
	if v := testutil.ToFloat64(droppedPacketsProto.WithLabelValues("ipv4")); v != 10 {
		t.Errorf("ipv4 pkts = %v, want 10", v)
	}
	if v := testutil.ToFloat64(droppedPacketsProto.WithLabelValues("ipv6")); v != 5 {
		t.Errorf("ipv6 pkts = %v, want 5", v)
	}
}

// --- SetConfigInfo tests ---

// testConfigParams returns a fully populated ConfigParams for testing.
func testConfigParams() ConfigParams {
	return ConfigParams{
		CrowdSecAPIURL:           "http://localhost:8080/",
		CrowdSecUpdateFrequency:  "15s",
		CrowdSecOrigins:          []string{"crowdsec", "cscli", "CAPI"},
		CrowdSecScopes:           []string{"ip", "range"},
		CrowdSecDecisionTypes:    []string{"ban"},
		CrowdSecRetryInitConnect: true,
		CrowdSecTLS:              false,
		MikroTikAddress:          "192.168.0.1:8728",
		MikroTikTLS:              false,
		MikroTikPoolSize:         10,
		MikroTikConnTimeout:      "10s",
		MikroTikCmdTimeout:       "30s",
		FWIPv4Enabled:            true,
		FWIPv4List:               "crowdsec-banned",
		FWIPv6Enabled:            true,
		FWIPv6List:               "crowdsec6-banned",
		FWFilterEnabled:          true,
		FWFilterChains:           []string{"input"},
		FWRawEnabled:             true,
		FWRawChains:              []string{"prerouting"},
		FWDenyAction:             "drop",
		FWBlockOutput:            false,
		FWRulePlacement:          "top",
		FWCommentPrefix:          "crowdsec-bouncer",
		FWLog:                    false,
		LogLevel:                 "info",
		LogFormat:                "text",
		MetricsEnabled:           true,
		MetricsTrackProcessed:    true,
		MetricsListenAddr:        "0.0.0.0",
		MetricsListenPort:        2112,
		MetricsPollInterval:      "30s",
	}
}

// TestSetConfigInfoRegistersMetric verifies the config info metric emits
// one series per parameter (31 total), each with group/param/value labels.
func TestSetConfigInfoRegistersMetric(t *testing.T) {
	configInfo.Reset()

	p := testConfigParams()
	SetConfigInfo(p)

	count := testutil.CollectAndCount(configInfo)
	if count != 32 {
		t.Fatalf("expected 32 config_info series, got %d", count)
	}

	// Spot-check specific parameters
	checks := []struct {
		group, param, value string
	}{
		{"CrowdSec", "API URL", "http://localhost:8080/"},
		{"CrowdSec", "Origins", "crowdsec, cscli, CAPI"},
		{"MikroTik", "Connection Pool Size", "10"},
		{"Firewall", "Deny Action", "drop"},
		{"Logging", "Level", "info"},
		{"Metrics", "Listen Port", "2112"},
		{"Metrics", "Track Processed", "true"},
	}
	for _, c := range checks {
		v := testutil.ToFloat64(configInfo.WithLabelValues(c.group, c.param, c.value))
		if v != 1 {
			t.Errorf("config_info{group=%q,param=%q,value=%q} = %v, want 1", c.group, c.param, c.value, v)
		}
	}
}

// TestSetConfigInfoEmptySlices verifies behavior when slice fields are empty.
func TestSetConfigInfoEmptySlices(t *testing.T) {
	configInfo.Reset()

	p := testConfigParams()
	p.CrowdSecOrigins = nil
	p.CrowdSecScopes = []string{}
	p.FWFilterChains = nil
	p.FWRawChains = []string{}

	// Should not panic
	SetConfigInfo(p)

	// Empty slices produce empty string values
	v := testutil.ToFloat64(configInfo.WithLabelValues("CrowdSec", "Origins", ""))
	if v != 1 {
		t.Errorf("empty origins = %v, want 1", v)
	}
	v = testutil.ToFloat64(configInfo.WithLabelValues("Firewall", "Filter Chains", ""))
	if v != 1 {
		t.Errorf("empty filter chains = %v, want 1", v)
	}
}

// TestSetConfigInfoBoolConversion verifies that all boolean fields are
// correctly represented as "true" or "false" strings.
func TestSetConfigInfoBoolConversion(t *testing.T) {
	configInfo.Reset()

	// All booleans true
	p := testConfigParams()
	p.CrowdSecRetryInitConnect = true
	p.CrowdSecTLS = true
	p.MikroTikTLS = true
	p.FWIPv4Enabled = true
	p.FWIPv6Enabled = true
	p.FWFilterEnabled = true
	p.FWRawEnabled = true
	p.FWBlockOutput = true
	p.FWLog = true
	p.MetricsEnabled = true

	SetConfigInfo(p)

	boolParams := []struct {
		group, param string
	}{
		{"CrowdSec", "Retry Initial Connect"},
		{"CrowdSec", "TLS Enabled"},
		{"MikroTik", "TLS Enabled"},
		{"Firewall", "IPv4 Enabled"},
		{"Firewall", "IPv6 Enabled"},
		{"Firewall", "Filter Enabled"},
		{"Firewall", "Raw Enabled"},
		{"Firewall", "Block Output"},
		{"Firewall", "Logging Enabled"},
		{"Metrics", "Enabled"},
	}
	for _, bp := range boolParams {
		v := testutil.ToFloat64(configInfo.WithLabelValues(bp.group, bp.param, "true"))
		if v != 1 {
			t.Errorf("config_info{group=%q,param=%q,value=\"true\"} = %v, want 1", bp.group, bp.param, v)
		}
	}

	// Reset and test all false
	configInfo.Reset()
	p.CrowdSecRetryInitConnect = false
	p.CrowdSecTLS = false
	p.MikroTikTLS = false
	p.FWIPv4Enabled = false
	p.FWIPv6Enabled = false
	p.FWFilterEnabled = false
	p.FWRawEnabled = false
	p.FWBlockOutput = false
	p.FWLog = false
	p.MetricsEnabled = false

	SetConfigInfo(p)

	for _, bp := range boolParams {
		v := testutil.ToFloat64(configInfo.WithLabelValues(bp.group, bp.param, "false"))
		if v != 1 {
			t.Errorf("config_info{group=%q,param=%q,value=\"false\"} = %v, want 1", bp.group, bp.param, v)
		}
	}
}

// TestSetConfigInfoMultipleChains verifies comma-joined slice labels.
func TestSetConfigInfoMultipleChains(t *testing.T) {
	configInfo.Reset()

	p := testConfigParams()
	p.FWFilterChains = []string{"input", "forward"}
	p.FWRawChains = []string{"prerouting", "output"}
	p.CrowdSecOrigins = []string{"crowdsec", "cscli", "CAPI", "lists"}

	SetConfigInfo(p)

	checks := []struct {
		group, param, value string
	}{
		{"Firewall", "Filter Chains", "input, forward"},
		{"Firewall", "Raw Chains", "prerouting, output"},
		{"CrowdSec", "Origins", "crowdsec, cscli, CAPI, lists"},
	}
	for _, c := range checks {
		v := testutil.ToFloat64(configInfo.WithLabelValues(c.group, c.param, c.value))
		if v != 1 {
			t.Errorf("config_info{param=%q} value=%q not found", c.param, c.value)
		}
	}
}

// TestSetConfigInfoConcurrency exercises concurrent SetConfigInfo calls (run with -race).
func TestSetConfigInfoConcurrency(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			p := testConfigParams()
			p.MikroTikPoolSize = n
			p.LogLevel = fmt.Sprintf("level-%d", n)
			SetConfigInfo(p)
		}(i)
	}
	wg.Wait()
}

// --- computeDelta ---

// TestComputeDeltaNormal verifies that computeDelta returns the difference when
// current > last (normal counter increment).
func TestComputeDeltaNormal(t *testing.T) {
	if d := computeDelta(100, 50); d != 50 {
		t.Errorf("computeDelta(100, 50) = %d, want 50", d)
	}
}

// TestComputeDeltaZero verifies that computeDelta returns 0 when current equals
// last (no change).
func TestComputeDeltaZero(t *testing.T) {
	if d := computeDelta(50, 50); d != 0 {
		t.Errorf("computeDelta(50, 50) = %d, want 0", d)
	}
}

// TestComputeDeltaWrapAround verifies that computeDelta handles counter resets
// (current < last) by returning the full current value.
func TestComputeDeltaWrapAround(t *testing.T) {
	// When current < lastSent, counter was reset — return current as full delta.
	if d := computeDelta(30, 100); d != 30 {
		t.Errorf("computeDelta(30, 100) = %d, want 30 (reset case)", d)
	}
}

// TestComputeDeltaFromZero verifies that computeDelta returns 0 when both
// current and last are zero.
func TestComputeDeltaFromZero(t *testing.T) {
	if d := computeDelta(0, 0); d != 0 {
		t.Errorf("computeDelta(0, 0) = %d, want 0", d)
	}
}

// --- SetDroppedCountersByIPType / GetAndResetDroppedDeltasByIPType ---

// TestDroppedByIPTypeDelta verifies that SetDroppedByIPType computes the correct
// delta on first call and returns zero on a second call with the same values.
func TestDroppedByIPTypeDelta(t *testing.T) {
	// Reset state.
	droppedProtoState.mu.Lock()
	droppedProtoState.current = ProtoCounters{}
	droppedProtoState.lastSent = ProtoCounters{}
	droppedProtoState.mu.Unlock()

	SetDroppedCountersByIPType(100, 10, 200, 20)
	b4, p4, b6, p6 := GetAndResetDroppedDeltasByIPType()

	if b4 != 100 || p4 != 10 || b6 != 200 || p6 != 20 {
		t.Errorf("first delta = (%d,%d,%d,%d), want (100,10,200,20)", b4, p4, b6, p6)
	}

	// Second call with no changes → zero deltas.
	b4, p4, b6, p6 = GetAndResetDroppedDeltasByIPType()
	if b4 != 0 || p4 != 0 || b6 != 0 || p6 != 0 {
		t.Errorf("second delta (no change) = (%d,%d,%d,%d), want (0,0,0,0)", b4, p4, b6, p6)
	}
}

// TestDroppedByIPTypeIncrementalDeltas verifies that SetDroppedByIPType computes
// correct incremental deltas between successive counter updates.
func TestDroppedByIPTypeIncrementalDeltas(t *testing.T) {
	droppedProtoState.mu.Lock()
	droppedProtoState.current = ProtoCounters{}
	droppedProtoState.lastSent = ProtoCounters{}
	droppedProtoState.mu.Unlock()

	SetDroppedCountersByIPType(100, 10, 50, 5)
	GetAndResetDroppedDeltasByIPType() // baseline

	SetDroppedCountersByIPType(150, 15, 70, 8)
	b4, p4, b6, p6 := GetAndResetDroppedDeltasByIPType()
	if b4 != 50 || p4 != 5 || b6 != 20 || p6 != 3 {
		t.Errorf("incremental delta = (%d,%d,%d,%d), want (50,5,20,3)", b4, p4, b6, p6)
	}
}

// TestDroppedByIPTypeWrapAround verifies that SetDroppedByIPType correctly
// handles counter resets by returning the full new value instead of a negative.
func TestDroppedByIPTypeWrapAround(t *testing.T) {
	droppedProtoState.mu.Lock()
	droppedProtoState.current = ProtoCounters{}
	droppedProtoState.lastSent = ProtoCounters{}
	droppedProtoState.mu.Unlock()

	SetDroppedCountersByIPType(100, 10, 100, 10)
	GetAndResetDroppedDeltasByIPType() // baseline at 100

	// Counter resets to lower value.
	SetDroppedCountersByIPType(20, 2, 30, 3)
	b4, p4, b6, p6 := GetAndResetDroppedDeltasByIPType()
	if b4 != 20 || p4 != 2 || b6 != 30 || p6 != 3 {
		t.Errorf("wrap-around delta = (%d,%d,%d,%d), want (20,2,30,3)", b4, p4, b6, p6)
	}
}

// --- SetProcessedCounters / GetAndResetProcessedDeltas ---

// TestProcessedDelta verifies that SetProcessedCounters computes the correct
// delta on first and second calls for accepted, dropped, and forwarded counters.
func TestProcessedDelta(t *testing.T) {
	processedProtoState.mu.Lock()
	processedProtoState.current = ProtoCounters{}
	processedProtoState.lastSent = ProtoCounters{}
	processedProtoState.mu.Unlock()

	SetProcessedCounters(1000, 100, 2000, 200)
	b4, p4, b6, p6 := GetAndResetProcessedDeltas()

	if b4 != 1000 || p4 != 100 || b6 != 2000 || p6 != 200 {
		t.Errorf("first delta = (%d,%d,%d,%d), want (1000,100,2000,200)", b4, p4, b6, p6)
	}

	// No change → zero.
	b4, p4, b6, p6 = GetAndResetProcessedDeltas()
	if b4 != 0 || p4 != 0 || b6 != 0 || p6 != 0 {
		t.Errorf("second delta = (%d,%d,%d,%d), want zeros", b4, p4, b6, p6)
	}
}

// TestProcessedIncrementalDeltas verifies that SetProcessedCounters computes
// correct incremental deltas between successive counter updates.
func TestProcessedIncrementalDeltas(t *testing.T) {
	processedProtoState.mu.Lock()
	processedProtoState.current = ProtoCounters{}
	processedProtoState.lastSent = ProtoCounters{}
	processedProtoState.mu.Unlock()

	SetProcessedCounters(500, 50, 300, 30)
	GetAndResetProcessedDeltas() // baseline

	SetProcessedCounters(800, 80, 450, 45)
	b4, p4, b6, p6 := GetAndResetProcessedDeltas()
	if b4 != 300 || p4 != 30 || b6 != 150 || p6 != 15 {
		t.Errorf("delta = (%d,%d,%d,%d), want (300,30,150,15)", b4, p4, b6, p6)
	}
}

// TestProcessedWrapAround verifies that SetProcessedCounters correctly handles
// counter resets by returning the full new value instead of a negative delta.
func TestProcessedWrapAround(t *testing.T) {
	processedProtoState.mu.Lock()
	processedProtoState.current = ProtoCounters{}
	processedProtoState.lastSent = ProtoCounters{}
	processedProtoState.mu.Unlock()

	SetProcessedCounters(500, 50, 500, 50)
	GetAndResetProcessedDeltas() // baseline at 500

	SetProcessedCounters(10, 1, 20, 2)
	b4, p4, b6, p6 := GetAndResetProcessedDeltas()
	if b4 != 10 || p4 != 1 || b6 != 20 || p6 != 2 {
		t.Errorf("wrap-around = (%d,%d,%d,%d), want (10,1,20,2)", b4, p4, b6, p6)
	}
}

// --- SetProcessedCountersPrometheus ---

// TestSetProcessedCountersPrometheus verifies that SetProcessedCounters correctly
// publishes delta values to the Prometheus accepted, dropped, and forwarded gauges.
func TestSetProcessedCountersPrometheus(t *testing.T) {
	processedBytesTotal.Set(0)
	processedPacketsTotal.Set(0)
	processedBytesProto.Reset()
	processedPacketsProto.Reset()

	SetProcessedCountersPrometheus(1000, 100, 2000, 200)

	if v := testutil.ToFloat64(processedBytesTotal); v != 3000 {
		t.Errorf("processedBytesTotal = %v, want 3000", v)
	}
	if v := testutil.ToFloat64(processedPacketsTotal); v != 300 {
		t.Errorf("processedPacketsTotal = %v, want 300", v)
	}
	if v := testutil.ToFloat64(processedBytesProto.WithLabelValues("ipv4")); v != 1000 {
		t.Errorf("processedBytesProto{ipv4} = %v, want 1000", v)
	}
	if v := testutil.ToFloat64(processedBytesProto.WithLabelValues("ipv6")); v != 2000 {
		t.Errorf("processedBytesProto{ipv6} = %v, want 2000", v)
	}
	if v := testutil.ToFloat64(processedPacketsProto.WithLabelValues("ipv4")); v != 100 {
		t.Errorf("processedPacketsProto{ipv4} = %v, want 100", v)
	}
	if v := testutil.ToFloat64(processedPacketsProto.WithLabelValues("ipv6")); v != 200 {
		t.Errorf("processedPacketsProto{ipv6} = %v, want 200", v)
	}
}

// --- Concurrency ---

// TestDroppedByIPTypeConcurrency exercises concurrent SetDroppedByIPType calls
// to verify there are no data races (run with -race).
func TestDroppedByIPTypeConcurrency(t *testing.T) {
	droppedProtoState.mu.Lock()
	droppedProtoState.current = ProtoCounters{}
	droppedProtoState.lastSent = ProtoCounters{}
	droppedProtoState.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n uint64) {
			defer wg.Done()
			SetDroppedCountersByIPType(n*10, n, n*20, n*2)
		}(uint64(i))
		go func() {
			defer wg.Done()
			GetAndResetDroppedDeltasByIPType()
		}()
	}
	wg.Wait()
}

// TestProcessedConcurrency exercises concurrent SetProcessedCounters calls to
// verify there are no data races (run with -race).
func TestProcessedConcurrency(t *testing.T) {
	processedProtoState.mu.Lock()
	processedProtoState.current = ProtoCounters{}
	processedProtoState.lastSent = ProtoCounters{}
	processedProtoState.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n uint64) {
			defer wg.Done()
			SetProcessedCounters(n*100, n*10, n*200, n*20)
		}(uint64(i))
		go func() {
			defer wg.Done()
			GetAndResetProcessedDeltas()
		}()
	}
	wg.Wait()
}
