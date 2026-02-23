package metrics

import (
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// activeDecisionCounts tracks the current active decision count per proto
// for reporting to CrowdSec LAPI usage metrics.
var activeDecisionCounts struct {
	ipv4 atomic.Int64
	ipv6 atomic.Int64
}

var (
	decisionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "crowdsec_bouncer_decisions_total",
		Help: "Total number of decisions processed.",
	}, []string{"action", "proto", "origin"})

	errorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "crowdsec_bouncer_errors_total",
		Help: "Total number of errors encountered.",
	}, []string{"operation"})

	activeDecisions = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "crowdsec_bouncer_active_decisions",
		Help: "Number of active decisions currently on the router.",
	}, []string{"proto"})

	routerosConnected = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "crowdsec_bouncer_routeros_connected",
		Help: "Whether the bouncer is connected to RouterOS (1=connected, 0=disconnected).",
	})

	operationDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "crowdsec_bouncer_operation_duration_seconds",
		Help:    "Duration of operations in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"operation"})

	reconciliationTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "crowdsec_bouncer_reconciliation_total",
		Help: "Total reconciliation actions performed.",
	}, []string{"action"})

	bouncerInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "crowdsec_bouncer_info",
		Help: "Information about the bouncer instance.",
	}, []string{"version", "routeros_identity"})

	startTimeSeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "crowdsec_bouncer_start_time_seconds",
		Help: "Unix timestamp of bouncer startup.",
	})
)

// RecordDecision increments the decisions counter.
func RecordDecision(action, proto, origin string) {
	decisionsTotal.WithLabelValues(action, proto, origin).Inc()
}

// RecordError increments the errors counter.
func RecordError(operation string) {
	errorsTotal.WithLabelValues(operation).Inc()
}

// SetActiveDecisions sets the gauge for active decisions and updates the atomic counter.
func SetActiveDecisions(proto string, count int) {
	activeDecisions.WithLabelValues(proto).Set(float64(count))
	if proto == "ipv4" {
		activeDecisionCounts.ipv4.Store(int64(count))
	} else {
		activeDecisionCounts.ipv6.Store(int64(count))
	}
}

// GetTotalActiveDecisions returns the total active decisions across all protocols.
func GetTotalActiveDecisions() int64 {
	return activeDecisionCounts.ipv4.Load() + activeDecisionCounts.ipv6.Load()
}

// SetConnected sets the RouterOS connection gauge.
func SetConnected(connected bool) {
	if connected {
		routerosConnected.Set(1)
	} else {
		routerosConnected.Set(0)
	}
}

// ObserveOperationDuration records the duration of an operation.
func ObserveOperationDuration(operation string, duration time.Duration) {
	operationDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// RecordReconciliation increments reconciliation counters.
func RecordReconciliation(action string, count int) {
	reconciliationTotal.WithLabelValues(action).Add(float64(count))
}

// SetInfo sets the info metric with version and identity labels.
func SetInfo(version, identity string) {
	bouncerInfo.WithLabelValues(version, identity).Set(1)
}

// SetStartTime records the startup timestamp.
func SetStartTime() {
	startTimeSeconds.SetToCurrentTime()
}
