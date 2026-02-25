// Copyright (c) 2025 jmrplens
// SPDX-License-Identifier: MIT

package lapi

import (
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/jmrplens/cs-routeros-bouncer/internal/metrics"
)

// testProvider returns a Provider with no MetricsProvider (tests only call
// metricsUpdater, which doesn't need the SDK client).
func testProvider() *Provider {
	return &Provider{}
}

// callUpdater is a test helper that invokes metricsUpdater on the given
// provider and returns the resulting payload.
func callUpdater(p *Provider, interval time.Duration) *models.RemediationComponentsMetrics {
	payload := &models.RemediationComponentsMetrics{}
	p.metricsUpdater(payload, interval)
	return payload
}

// resetMetrics sets a known metrics state for test isolation.
func resetMetrics() {
	metrics.SetActiveDecisions("ipv4", 0)
	metrics.SetActiveDecisions("ipv6", 0)
	metrics.SetDroppedCounters(0, 0)
	metrics.SetDroppedCountersByIPType(0, 0, 0, 0)
	metrics.SetProcessedCounters(0, 0, 0, 0)
	// Reset deltas by reading them once.
	metrics.GetAndResetDroppedDeltas()
	metrics.GetAndResetDroppedDeltasByIPType()
	metrics.GetAndResetProcessedDeltas()
}

// TestMetricsUpdaterActiveDecisionsFallback verifies that when no per-origin
// data is available, the updater sends a single active_decisions total.
func TestMetricsUpdaterActiveDecisionsFallback(t *testing.T) {
	resetMetrics()
	metrics.SetActiveDecisions("ipv4", 100)
	metrics.SetActiveDecisions("ipv6", 50)

	p := testProvider()
	payload := callUpdater(p, 15*time.Minute)

	if len(payload.Metrics) != 1 {
		t.Fatalf("expected 1 DetailedMetrics, got %d", len(payload.Metrics))
	}

	dm := payload.Metrics[0]
	if dm.Meta == nil {
		t.Fatal("expected Meta to be set")
	}
	if dm.Meta.WindowSizeSeconds == nil || *dm.Meta.WindowSizeSeconds != 900 {
		t.Errorf("expected WindowSizeSeconds=900, got %v", dm.Meta.WindowSizeSeconds)
	}

	// Should have at least the fallback total item.
	found := false
	for _, item := range dm.Items {
		if item.Name != nil && *item.Name == "active_decisions" && item.Labels == nil {
			found = true
			if *item.Value != 150 {
				t.Errorf("expected total active_decisions=150, got %v", *item.Value)
			}
		}
	}
	if !found {
		t.Error("expected fallback active_decisions item without labels")
	}
}

// TestMetricsUpdaterPerOriginDecisions verifies per-origin breakdown when
// SetActiveDecisionsByOrigin has been called.
func TestMetricsUpdaterPerOriginDecisions(t *testing.T) {
	resetMetrics()
	metrics.SetActiveDecisions("ipv4", 80)
	metrics.SetActiveDecisions("ipv6", 20)
	metrics.SetActiveDecisionsByOrigin("crowdsec", 70)
	metrics.SetActiveDecisionsByOrigin("CAPI", 30)

	p := testProvider()
	payload := callUpdater(p, time.Minute)

	dm := payload.Metrics[0]
	originItems := map[string]float64{}
	ipTypeItems := map[string]float64{}
	for _, item := range dm.Items {
		if item.Name != nil && *item.Name == "active_decisions" {
			if v, ok := item.Labels["origin"]; ok {
				originItems[v] = *item.Value
			}
			if v, ok := item.Labels["ip_type"]; ok {
				ipTypeItems[v] = *item.Value
			}
		}
	}

	if originItems["crowdsec"] != 70 {
		t.Errorf("expected origin crowdsec=70, got %v", originItems["crowdsec"])
	}
	if originItems["CAPI"] != 30 {
		t.Errorf("expected origin CAPI=30, got %v", originItems["CAPI"])
	}
	if ipTypeItems["ipv4"] != 80 {
		t.Errorf("expected ip_type ipv4=80, got %v", ipTypeItems["ipv4"])
	}
	if ipTypeItems["ipv6"] != 20 {
		t.Errorf("expected ip_type ipv6=20, got %v", ipTypeItems["ipv6"])
	}

	// Cleanup origin state.
	metrics.SetActiveDecisionsByOrigin("crowdsec", 0)
	metrics.SetActiveDecisionsByOrigin("CAPI", 0)
}

// TestMetricsUpdaterDroppedCounters verifies that dropped metrics per ip_type
// are included when firewall counters have been set.
func TestMetricsUpdaterDroppedCounters(t *testing.T) {
	resetMetrics()
	metrics.SetDroppedCountersByIPType(4000, 80, 1000, 20)

	p := testProvider()
	payload := callUpdater(p, time.Minute)

	dm := payload.Metrics[0]
	// Collect dropped items keyed by "iptype:unit".
	dropped := map[string]float64{}
	for _, item := range dm.Items {
		if item.Name != nil && *item.Name == "dropped" {
			key := item.Labels["ip_type"] + ":" + *item.Unit
			dropped[key] = *item.Value
		}
	}

	if dropped["ipv4:byte"] != 4000 {
		t.Errorf("expected dropped ipv4 bytes=4000, got %v", dropped["ipv4:byte"])
	}
	if dropped["ipv4:packet"] != 80 {
		t.Errorf("expected dropped ipv4 packets=80, got %v", dropped["ipv4:packet"])
	}
	if dropped["ipv6:byte"] != 1000 {
		t.Errorf("expected dropped ipv6 bytes=1000, got %v", dropped["ipv6:byte"])
	}
	if dropped["ipv6:packet"] != 20 {
		t.Errorf("expected dropped ipv6 packets=20, got %v", dropped["ipv6:packet"])
	}
}

// TestMetricsUpdaterDroppedDelta verifies the delta behavior: after a push,
// only new counters since last push are reported.
func TestMetricsUpdaterDroppedDelta(t *testing.T) {
	resetMetrics()
	metrics.SetDroppedCountersByIPType(1000, 50, 0, 0)

	p := testProvider()
	// First push: gets full delta (1000-0=1000, 50-0=50).
	payload1 := callUpdater(p, time.Minute)
	dm1 := payload1.Metrics[0]
	var bytes1, pkts1 float64
	for _, item := range dm1.Items {
		if item.Name != nil && *item.Name == "dropped" && item.Labels["ip_type"] == "ipv4" {
			if *item.Unit == "byte" {
				bytes1 = *item.Value
			}
			if *item.Unit == "packet" {
				pkts1 = *item.Value
			}
		}
	}
	if bytes1 != 1000 || pkts1 != 50 {
		t.Errorf("first push: expected bytes=1000 pkts=50, got bytes=%v pkts=%v", bytes1, pkts1)
	}

	// Update counters to simulate more traffic.
	metrics.SetDroppedCountersByIPType(1500, 80, 0, 0)

	// Second push: delta should be 500 bytes, 30 pkts.
	payload2 := callUpdater(p, time.Minute)
	dm2 := payload2.Metrics[0]
	var bytes2, pkts2 float64
	for _, item := range dm2.Items {
		if item.Name != nil && *item.Name == "dropped" && item.Labels["ip_type"] == "ipv4" {
			if *item.Unit == "byte" {
				bytes2 = *item.Value
			}
			if *item.Unit == "packet" {
				pkts2 = *item.Value
			}
		}
	}
	if bytes2 != 500 || pkts2 != 30 {
		t.Errorf("second push: expected bytes=500 pkts=30, got bytes=%v pkts=%v", bytes2, pkts2)
	}
}

// TestMetricsUpdaterZeroDecisions verifies behavior with no active decisions.
func TestMetricsUpdaterZeroDecisions(t *testing.T) {
	resetMetrics()

	p := testProvider()
	payload := callUpdater(p, 5*time.Minute)

	if len(payload.Metrics) != 1 {
		t.Fatalf("expected 1 DetailedMetrics, got %d", len(payload.Metrics))
	}

	if *payload.Metrics[0].Meta.WindowSizeSeconds != 300 {
		t.Errorf("expected window=300s for 5m interval, got %v", *payload.Metrics[0].Meta.WindowSizeSeconds)
	}
}

// TestMetricsUpdaterTimestamp verifies that the UTC timestamp is set to a
// recent value (within the last 5 seconds).
func TestMetricsUpdaterTimestamp(t *testing.T) {
	resetMetrics()
	metrics.SetActiveDecisions("ipv4", 10)

	before := time.Now().UTC().Unix()
	p := testProvider()
	payload := callUpdater(p, time.Minute)
	after := time.Now().UTC().Unix()

	ts := *payload.Metrics[0].Meta.UtcNowTimestamp
	if ts < before || ts > after {
		t.Errorf("timestamp %d not in range [%d, %d]", ts, before, after)
	}
}

// TestMetricsUpdaterWindowSizeVariousIntervals verifies that the window size
// correctly maps from duration to seconds for various intervals.
func TestMetricsUpdaterWindowSizeVariousIntervals(t *testing.T) {
	resetMetrics()
	metrics.SetActiveDecisions("ipv4", 1)

	tests := []struct {
		interval time.Duration
		wantSec  int64
	}{
		{time.Minute, 60},
		{5 * time.Minute, 300},
		{15 * time.Minute, 900},
		{30 * time.Minute, 1800},
		{time.Hour, 3600},
	}

	p := testProvider()
	for _, tt := range tests {
		payload := callUpdater(p, tt.interval)

		got := *payload.Metrics[0].Meta.WindowSizeSeconds
		if got != tt.wantSec {
			t.Errorf("interval=%v: expected WindowSizeSeconds=%d, got %d",
				tt.interval, tt.wantSec, got)
		}
	}
}

// TestMetricsUpdaterAppends verifies that calling metricsUpdater multiple
// times appends to the payload (the MetricsProvider clears between sends).
func TestMetricsUpdaterAppends(t *testing.T) {
	resetMetrics()
	metrics.SetActiveDecisions("ipv4", 10)

	p := testProvider()
	payload := &models.RemediationComponentsMetrics{}
	p.metricsUpdater(payload, time.Minute)
	p.metricsUpdater(payload, time.Minute)

	if len(payload.Metrics) != 2 {
		t.Fatalf("expected 2 DetailedMetrics after 2 calls, got %d", len(payload.Metrics))
	}
}

// TestMetricsUpdaterCounterCollector verifies that a registered collector
// is called before building the metrics payload.
func TestMetricsUpdaterCounterCollector(t *testing.T) {
	resetMetrics()
	called := false

	p := testProvider()
	p.SetCounterCollector(func() {
		called = true
		metrics.SetDroppedCountersByIPType(999, 42, 0, 0)
	})

	payload := callUpdater(p, time.Minute)

	if !called {
		t.Fatal("expected counter collector to be called")
	}

	dm := payload.Metrics[0]
	found := false
	for _, item := range dm.Items {
		if item.Name != nil && *item.Name == "dropped" && *item.Unit == "byte" && item.Labels["ip_type"] == "ipv4" {
			found = true
			if *item.Value != 999 {
				t.Errorf("expected dropped bytes=999, got %v", *item.Value)
			}
		}
	}
	if !found {
		t.Error("expected dropped byte item from collector")
	}
}

// TestMetricItemHelper verifies the metricItem helper builds correct structs.
func TestMetricItemHelper(t *testing.T) {
	item := metricItem("test_metric", "count", 42.0, map[string]string{"origin": "cscli"})

	if *item.Name != "test_metric" {
		t.Errorf("expected name=test_metric, got %q", *item.Name)
	}
	if *item.Unit != "count" {
		t.Errorf("expected unit=count, got %q", *item.Unit)
	}
	if *item.Value != 42.0 {
		t.Errorf("expected value=42, got %v", *item.Value)
	}
	if item.Labels["origin"] != "cscli" {
		t.Errorf("expected label origin=cscli, got %v", item.Labels)
	}
}

// TestMetricItemNilLabels verifies metricItem with nil labels produces no
// Labels field.
func TestMetricItemNilLabels(t *testing.T) {
	item := metricItem("test", "ip", 1.0, nil)
	if item.Labels != nil {
		t.Errorf("expected nil labels, got %v", item.Labels)
	}
}

// TestBouncerTypeConstant verifies the bouncerType constant matches the
// expected bouncer name.
func TestBouncerTypeConstant(t *testing.T) {
	if bouncerType != "cs-routeros-bouncer" {
		t.Errorf("expected bouncerType='cs-routeros-bouncer', got %q", bouncerType)
	}
}

// ===========================================================================
// SetCounterCollector and metricsUpdater with collector tests
// ===========================================================================

// TestSetCounterCollector verifies the collector callback is stored.
func TestSetCounterCollector(t *testing.T) {
	p := testProvider()
	if p.collector != nil {
		t.Error("collector should be nil initially")
	}

	called := false
	p.SetCounterCollector(func() { called = true })

	if p.collector == nil {
		t.Fatal("collector should be set after SetCounterCollector")
	}

	// Invoke the updater — the collector should be called.
	resetMetrics()
	payload := &models.RemediationComponentsMetrics{}
	p.metricsUpdater(payload, time.Minute)

	if !called {
		t.Error("expected collector to be called during metricsUpdater")
	}
}

// TestMetricsUpdaterWithCollector verifies that the collector is invoked
// before metrics are gathered, allowing it to refresh counters.
func TestMetricsUpdaterWithCollector(t *testing.T) {
	p := testProvider()
	resetMetrics()

	// Collector sets dropped counters per ip_type.
	p.SetCounterCollector(func() {
		metrics.SetDroppedCountersByIPType(1000, 50, 0, 0)
	})

	// First call to get baseline deltas.
	_ = callUpdater(p, time.Minute)

	// Set new counters.
	p.SetCounterCollector(func() {
		metrics.SetDroppedCountersByIPType(2000, 100, 0, 0)
	})
	payload := callUpdater(p, time.Minute)

	// Should have dropped metrics from the delta.
	foundDropped := false
	for _, item := range payload.Metrics {
		for _, m := range item.Items {
			if m.Name != nil && *m.Name == "dropped" {
				foundDropped = true
			}
		}
	}
	if !foundDropped {
		t.Error("expected dropped metrics in payload when deltas are non-zero")
	}
}

// TestMetricsUpdaterNilCollector verifies the updater works without a
// registered collector.
func TestMetricsUpdaterNilCollector(t *testing.T) {
	p := testProvider()
	p.collector = nil
	resetMetrics()

	// Should not panic.
	payload := &models.RemediationComponentsMetrics{}
	p.metricsUpdater(payload, time.Minute)
}
