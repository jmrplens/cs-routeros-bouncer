// Tests for the metrics package covering Prometheus metric recording,
// the HTTP health endpoint, and the metrics server lifecycle.
package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

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
// the gauge value for a given protocol.
func TestSetActiveDecisions(t *testing.T) {
	SetActiveDecisions("ip", 42)
	if got := testutil.ToFloat64(activeDecisions.WithLabelValues("ip")); got != 42 {
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
