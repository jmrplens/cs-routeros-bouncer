// Package metrics exposes Prometheus instrumentation and an HTTP health endpoint
// for the cs-routeros-bouncer.
//
// Key metrics are registered via promauto on the default Prometheus registry:
//   - crowdsec_bouncer_info: build version and RouterOS identity (GaugeVec)
//   - crowdsec_bouncer_start_time_seconds: process start time (Gauge)
//   - crowdsec_bouncer_routeros_connected: RouterOS connectivity (Gauge)
//   - crowdsec_bouncer_active_decisions: current banned IPs by protocol (GaugeVec)
//   - crowdsec_bouncer_decisions_total: cumulative ban/unban count (CounterVec)
//   - crowdsec_bouncer_errors_total: error count by operation (CounterVec)
//   - crowdsec_bouncer_operation_duration_seconds: latency histogram (HistogramVec)
//   - crowdsec_bouncer_last_operation_duration_seconds: most recent operation duration (GaugeVec)
//   - crowdsec_bouncer_reconciliation_total: reconciliation add/remove/unchanged (CounterVec)
//
// The HTTP server serves /metrics (Prometheus scrape) and /health (JSON liveness).
//
// Runtime code updates collectors through helper functions such as
// [SetConnected], [RecordDecision], [SetActiveDecisions], and
// [SetDroppedCounters]. Use [NewServer] to expose the HTTP endpoints.
package metrics
