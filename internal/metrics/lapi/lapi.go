// Copyright (c) 2025 jmrplens
// SPDX-License-Identifier: MIT

// Package lapi provides CrowdSec LAPI usage metrics integration.
// It uses the go-cs-bouncer MetricsProvider to periodically report
// bouncer metrics to the CrowdSec LAPI /v1/usage-metrics endpoint.
//
// The provider sends five metric types per the CrowdSec bouncer spec:
//   - active_decisions: current count of active decisions (by origin + ip_type)
//   - dropped: bytes and packets blocked by drop/reject rules (delta, by ip_type)
//   - processed: total bytes and packets through all bouncer rules (delta, by ip_type)
//
// The metricsUpdater callback runs on each tick and gathers data from:
//   - metrics.GetActiveDecisionsByOrigin() for per-origin decision counts
//   - metrics.GetActiveDecisionsByIPType() for per-protocol decision counts
//   - metrics.GetAndResetDroppedDeltasByIPType() for per-ip_type firewall drop deltas
//   - metrics.GetAndResetProcessedDeltas() for per-ip_type processed deltas
//
// An optional CounterCollector can be registered by the manager to refresh
// firewall counters from MikroTik just before each LAPI push.
package lapi

import (
	"context"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"

	"github.com/jmrplens/cs-routeros-bouncer/internal/metrics"
)

const bouncerType = "cs-routeros-bouncer"

// CounterCollector is called before each metrics push to refresh firewall
// counters. The manager registers this to query MikroTik byte/packet stats.
type CounterCollector func()

// Provider wraps the go-cs-bouncer MetricsProvider for LAPI usage metrics.
type Provider struct {
	mp        *csbouncer.MetricsProvider
	logger    zerolog.Logger
	collector CounterCollector
}

// NewProvider creates a LAPI metrics provider that reports active decisions
// and dropped traffic to the CrowdSec LAPI at the given interval.
func NewProvider(client *apiclient.ApiClient, interval time.Duration, logrusLogger logrus.FieldLogger, logger zerolog.Logger) (*Provider, error) {
	p := &Provider{
		logger: logger,
	}

	updater := func(payload *models.RemediationComponentsMetrics, d time.Duration) {
		p.metricsUpdater(payload, d)
	}

	mp, err := csbouncer.NewMetricsProvider(client, bouncerType, updater, logrusLogger)
	if err != nil {
		return nil, err
	}

	mp.Interval = interval
	p.mp = mp

	return p, nil
}

// SetCounterCollector registers a callback that refreshes firewall counters
// before each metrics push. Typically called by the manager after startup.
func (p *Provider) SetCounterCollector(c CounterCollector) {
	p.collector = c
}

// Run starts the periodic metrics reporting. Blocks until ctx is canceled.
func (p *Provider) Run(ctx context.Context) error {
	p.logger.Info().
		Dur("interval", p.mp.Interval).
		Msg("starting LAPI usage metrics reporting")

	return p.mp.Run(ctx)
}

// metricsUpdater is the callback invoked by MetricsProvider on each tick.
// It populates the payload with active_decisions and dropped metrics.
func (p *Provider) metricsUpdater(payload *models.RemediationComponentsMetrics, interval time.Duration) {
	// Refresh firewall counters from MikroTik if a collector is registered.
	if p.collector != nil {
		p.collector()
	}

	now := time.Now().UTC().Unix()
	windowSec := int64(interval.Seconds())
	meta := &models.MetricsMeta{
		UtcNowTimestamp:   &now,
		WindowSizeSeconds: &windowSec,
	}

	var items []*models.MetricsDetailItem

	// --- active_decisions per origin ---
	byOrigin := metrics.GetActiveDecisionsByOrigin()
	for origin, count := range byOrigin {
		items = append(items, metricItem("active_decisions", "ip", float64(count), map[string]string{
			"origin": origin,
		}))
	}

	// --- active_decisions per ip_type ---
	ipv4, ipv6 := metrics.GetActiveDecisionsByIPType()
	if ipv4 > 0 {
		items = append(items, metricItem("active_decisions", "ip", float64(ipv4), map[string]string{
			"ip_type": "ipv4",
		}))
	}
	if ipv6 > 0 {
		items = append(items, metricItem("active_decisions", "ip", float64(ipv6), map[string]string{
			"ip_type": "ipv6",
		}))
	}

	// If no origin data yet, send total as fallback.
	if len(byOrigin) == 0 {
		total := float64(metrics.GetTotalActiveDecisions())
		items = append(items, metricItem("active_decisions", "ip", total, nil))
	}

	// --- dropped bytes/packets per ip_type (delta since last push) ---
	dv4b, dv4p, dv6b, dv6p := metrics.GetAndResetDroppedDeltasByIPType()
	if dv4b > 0 {
		items = append(items, metricItem("dropped", "byte", float64(dv4b), map[string]string{"ip_type": "ipv4"}))
	}
	if dv4p > 0 {
		items = append(items, metricItem("dropped", "packet", float64(dv4p), map[string]string{"ip_type": "ipv4"}))
	}
	if dv6b > 0 {
		items = append(items, metricItem("dropped", "byte", float64(dv6b), map[string]string{"ip_type": "ipv6"}))
	}
	if dv6p > 0 {
		items = append(items, metricItem("dropped", "packet", float64(dv6p), map[string]string{"ip_type": "ipv6"}))
	}

	// --- processed bytes/packets per ip_type (delta since last push) ---
	pv4b, pv4p, pv6b, pv6p := metrics.GetAndResetProcessedDeltas()
	if pv4b > 0 {
		items = append(items, metricItem("processed", "byte", float64(pv4b), map[string]string{"ip_type": "ipv4"}))
	}
	if pv4p > 0 {
		items = append(items, metricItem("processed", "packet", float64(pv4p), map[string]string{"ip_type": "ipv4"}))
	}
	if pv6b > 0 {
		items = append(items, metricItem("processed", "byte", float64(pv6b), map[string]string{"ip_type": "ipv6"}))
	}
	if pv6p > 0 {
		items = append(items, metricItem("processed", "packet", float64(pv6p), map[string]string{"ip_type": "ipv6"}))
	}

	payload.Metrics = append(payload.Metrics, &models.DetailedMetrics{
		Meta:  meta,
		Items: items,
	})
}

// metricItem builds a single MetricsDetailItem with optional labels.
func metricItem(name, unit string, value float64, labels map[string]string) *models.MetricsDetailItem {
	item := &models.MetricsDetailItem{
		Name:  &name,
		Unit:  &unit,
		Value: &value,
	}
	if len(labels) > 0 {
		item.Labels = labels
	}
	return item
}
