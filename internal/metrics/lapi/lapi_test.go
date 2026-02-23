// Copyright (c) 2025 jmrplens
// SPDX-License-Identifier: MIT

package lapi

import (
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/jmrplens/cs-routeros-bouncer/internal/metrics"
)

// TestMetricsUpdater verifies the metricsUpdater callback populates the
// metrics payload correctly with active_decisions.
func TestMetricsUpdater(t *testing.T) {
	// Set known active decisions
	metrics.SetActiveDecisions("ipv4", 100)
	metrics.SetActiveDecisions("ipv6", 50)

	payload := &models.RemediationComponentsMetrics{}
	interval := 15 * time.Minute

	metricsUpdater(payload, interval)

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

	if len(dm.Items) != 1 {
		t.Fatalf("expected 1 metric item, got %d", len(dm.Items))
	}

	item := dm.Items[0]
	if item.Name == nil || *item.Name != "active_decisions" {
		t.Errorf("expected name=active_decisions, got %v", item.Name)
	}
	if item.Unit == nil || *item.Unit != "ip" {
		t.Errorf("expected unit=ip, got %v", item.Unit)
	}
	if item.Value == nil || *item.Value != 150 {
		t.Errorf("expected value=150 (100+50), got %v", *item.Value)
	}
}

// TestMetricsUpdaterZeroDecisions verifies behavior with no active decisions.
func TestMetricsUpdaterZeroDecisions(t *testing.T) {
	metrics.SetActiveDecisions("ipv4", 0)
	metrics.SetActiveDecisions("ipv6", 0)

	payload := &models.RemediationComponentsMetrics{}
	metricsUpdater(payload, 5*time.Minute)

	if len(payload.Metrics) != 1 {
		t.Fatalf("expected 1 DetailedMetrics, got %d", len(payload.Metrics))
	}

	if *payload.Metrics[0].Items[0].Value != 0 {
		t.Errorf("expected value=0, got %v", *payload.Metrics[0].Items[0].Value)
	}

	if *payload.Metrics[0].Meta.WindowSizeSeconds != 300 {
		t.Errorf("expected window=300s for 5m interval, got %v", *payload.Metrics[0].Meta.WindowSizeSeconds)
	}
}

// TestMetricsUpdaterTimestamp verifies that the UTC timestamp is set to a
// recent value (within the last 5 seconds).
func TestMetricsUpdaterTimestamp(t *testing.T) {
	metrics.SetActiveDecisions("ipv4", 10)
	metrics.SetActiveDecisions("ipv6", 0)

	before := time.Now().UTC().Unix()
	payload := &models.RemediationComponentsMetrics{}
	metricsUpdater(payload, time.Minute)
	after := time.Now().UTC().Unix()

	ts := *payload.Metrics[0].Meta.UtcNowTimestamp
	if ts < before || ts > after {
		t.Errorf("timestamp %d not in range [%d, %d]", ts, before, after)
	}
}

// TestMetricsUpdaterWindowSizeVariousIntervals verifies that the window size
// correctly maps from duration to seconds for various intervals.
func TestMetricsUpdaterWindowSizeVariousIntervals(t *testing.T) {
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

	metrics.SetActiveDecisions("ipv4", 1)
	metrics.SetActiveDecisions("ipv6", 0)

	for _, tt := range tests {
		payload := &models.RemediationComponentsMetrics{}
		metricsUpdater(payload, tt.interval)

		got := *payload.Metrics[0].Meta.WindowSizeSeconds
		if got != tt.wantSec {
			t.Errorf("interval=%v: expected WindowSizeSeconds=%d, got %d",
				tt.interval, tt.wantSec, got)
		}
	}
}

// TestMetricsUpdaterLargeDecisionCount verifies correct reporting with a
// large number of active decisions.
func TestMetricsUpdaterLargeDecisionCount(t *testing.T) {
	metrics.SetActiveDecisions("ipv4", 25000)
	metrics.SetActiveDecisions("ipv6", 600)

	payload := &models.RemediationComponentsMetrics{}
	metricsUpdater(payload, 15*time.Minute)

	if *payload.Metrics[0].Items[0].Value != 25600 {
		t.Errorf("expected value=25600, got %v", *payload.Metrics[0].Items[0].Value)
	}
}

// TestMetricsUpdaterAppends verifies that calling metricsUpdater multiple
// times appends to the payload (the MetricsProvider clears between sends).
func TestMetricsUpdaterAppends(t *testing.T) {
	metrics.SetActiveDecisions("ipv4", 10)
	metrics.SetActiveDecisions("ipv6", 5)

	payload := &models.RemediationComponentsMetrics{}
	metricsUpdater(payload, time.Minute)
	metricsUpdater(payload, time.Minute)

	if len(payload.Metrics) != 2 {
		t.Fatalf("expected 2 DetailedMetrics after 2 calls, got %d", len(payload.Metrics))
	}
}

// TestMetricsUpdaterItemFields verifies the exact Name and Unit string
// values set in the metric item.
func TestMetricsUpdaterItemFields(t *testing.T) {
	metrics.SetActiveDecisions("ipv4", 1)
	metrics.SetActiveDecisions("ipv6", 0)

	payload := &models.RemediationComponentsMetrics{}
	metricsUpdater(payload, time.Minute)

	item := payload.Metrics[0].Items[0]

	if item.Name == nil {
		t.Fatal("Name must not be nil")
	}
	if *item.Name != "active_decisions" {
		t.Errorf("expected Name='active_decisions', got %q", *item.Name)
	}

	if item.Unit == nil {
		t.Fatal("Unit must not be nil")
	}
	if *item.Unit != "ip" {
		t.Errorf("expected Unit='ip', got %q", *item.Unit)
	}
}

// TestBouncerTypeConstant verifies the bouncerType constant matches the
// expected bouncer name.
func TestBouncerTypeConstant(t *testing.T) {
	if bouncerType != "cs-routeros-bouncer" {
		t.Errorf("expected bouncerType='cs-routeros-bouncer', got %q", bouncerType)
	}
}
