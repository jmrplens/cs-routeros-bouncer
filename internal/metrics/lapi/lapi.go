// Copyright (c) 2025 jmrplens
// SPDX-License-Identifier: MIT

// Package lapi provides CrowdSec LAPI usage metrics integration.
// It uses the go-cs-bouncer MetricsProvider to periodically report
// active decision counts and bouncer metadata to the CrowdSec LAPI
// /v1/usage-metrics endpoint.
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

// Provider wraps the go-cs-bouncer MetricsProvider for LAPI usage metrics.
type Provider struct {
	mp     *csbouncer.MetricsProvider
	logger zerolog.Logger
}

// NewProvider creates a LAPI metrics provider that reports active decisions
// to the CrowdSec LAPI at the given interval. If interval is 0, metrics are disabled.
func NewProvider(client *apiclient.ApiClient, interval time.Duration, logrusLogger logrus.FieldLogger, logger zerolog.Logger) (*Provider, error) {
	mp, err := csbouncer.NewMetricsProvider(client, bouncerType, metricsUpdater, logrusLogger)
	if err != nil {
		return nil, err
	}

	mp.Interval = interval

	return &Provider{
		mp:     mp,
		logger: logger,
	}, nil
}

// Run starts the periodic metrics reporting. Blocks until ctx is canceled.
func (p *Provider) Run(ctx context.Context) error {
	p.logger.Info().
		Dur("interval", p.mp.Interval).
		Msg("starting LAPI usage metrics reporting")

	return p.mp.Run(ctx)
}

// metricsUpdater is the callback invoked by MetricsProvider on each tick.
// It populates the payload with active decision counts.
func metricsUpdater(metricsPayload *models.RemediationComponentsMetrics, interval time.Duration) {
	now := time.Now().UTC().Unix()
	windowSec := int64(interval.Seconds())

	activeCount := float64(metrics.GetTotalActiveDecisions())

	name := "active_decisions"
	unit := "ip"

	metricsPayload.Metrics = append(metricsPayload.Metrics, &models.DetailedMetrics{
		Meta: &models.MetricsMeta{
			UtcNowTimestamp:   &now,
			WindowSizeSeconds: &windowSec,
		},
		Items: []*models.MetricsDetailItem{
			{
				Name:  &name,
				Unit:  &unit,
				Value: &activeCount,
			},
		},
	})
}
