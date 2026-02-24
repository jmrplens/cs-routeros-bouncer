package metrics

import (
	"fmt"
	"strings"
	"sync"
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

	droppedBytesTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "crowdsec_bouncer_dropped_bytes_total",
		Help: "Cumulative bytes dropped by firewall rules.",
	})

	droppedPacketsTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "crowdsec_bouncer_dropped_packets_total",
		Help: "Cumulative packets dropped by firewall rules.",
	})

	activeDecisionsByOrigin = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "crowdsec_bouncer_active_decisions_by_origin",
		Help: "Number of active decisions by CrowdSec origin.",
	}, []string{"origin"})

	routerosCPULoad = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "crowdsec_bouncer_routeros_cpu_load",
		Help: "RouterOS CPU load percentage (0-100).",
	})

	routerosMemoryUsed = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "crowdsec_bouncer_routeros_memory_used_bytes",
		Help: "RouterOS used memory in bytes.",
	})

	routerosMemoryTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "crowdsec_bouncer_routeros_memory_total_bytes",
		Help: "RouterOS total memory in bytes.",
	})

	routerosCPUTemperature = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "crowdsec_bouncer_routeros_cpu_temperature_celsius",
		Help: "RouterOS CPU temperature in degrees Celsius.",
	})

	configInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "crowdsec_bouncer_config_info",
		Help: "Bouncer configuration parameters (one series per parameter, value is always 1).",
	}, []string{"group", "param", "value"})
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

// IncrActiveDecisions increments the active decisions gauge and atomic counter.
func IncrActiveDecisions(proto string) {
	activeDecisions.WithLabelValues(proto).Inc()
	if proto == "ipv4" {
		activeDecisionCounts.ipv4.Add(1)
	} else {
		activeDecisionCounts.ipv6.Add(1)
	}
}

// DecrActiveDecisions decrements the active decisions gauge and atomic counter.
func DecrActiveDecisions(proto string) {
	activeDecisions.WithLabelValues(proto).Dec()
	if proto == "ipv4" {
		activeDecisionCounts.ipv4.Add(-1)
	} else {
		activeDecisionCounts.ipv6.Add(-1)
	}
}

// GetTotalActiveDecisions returns the total active decisions across all protocols.
func GetTotalActiveDecisions() int64 {
	return activeDecisionCounts.ipv4.Load() + activeDecisionCounts.ipv6.Load()
}

// GetActiveDecisionsByIPType returns the active decision count per IP protocol.
func GetActiveDecisionsByIPType() (ipv4, ipv6 int64) {
	return activeDecisionCounts.ipv4.Load(), activeDecisionCounts.ipv6.Load()
}

// --- Per-origin active decision tracking for LAPI ---

// originDecisionsMu protects originDecisions map.
var originDecisionsMu sync.RWMutex

// originDecisions tracks active decision counts per origin.
var originDecisions = map[string]int64{}

// SetActiveDecisionsByOrigin stores the active decision count for a given origin.
func SetActiveDecisionsByOrigin(origin string, count int64) {
	originDecisionsMu.Lock()
	defer originDecisionsMu.Unlock()
	if count <= 0 {
		delete(originDecisions, origin)
		activeDecisionsByOrigin.WithLabelValues(origin).Set(0)
	} else {
		originDecisions[origin] = count
		activeDecisionsByOrigin.WithLabelValues(origin).Set(float64(count))
	}
}

// GetActiveDecisionsByOrigin returns a snapshot of active decisions per origin.
func GetActiveDecisionsByOrigin() map[string]int64 {
	originDecisionsMu.RLock()
	defer originDecisionsMu.RUnlock()
	result := make(map[string]int64, len(originDecisions))
	for k, v := range originDecisions {
		result[k] = v
	}
	return result
}

// IncrActiveDecisionsByOrigin increments the active count for a given origin.
func IncrActiveDecisionsByOrigin(origin string) {
	if origin == "" {
		origin = "unknown"
	}
	originDecisionsMu.Lock()
	defer originDecisionsMu.Unlock()
	originDecisions[origin]++
	activeDecisionsByOrigin.WithLabelValues(origin).Set(float64(originDecisions[origin]))
}

// DecrActiveDecisionsByOrigin decrements the active count for a given origin.
func DecrActiveDecisionsByOrigin(origin string) {
	if origin == "" {
		origin = "unknown"
	}
	originDecisionsMu.Lock()
	defer originDecisionsMu.Unlock()
	originDecisions[origin]--
	if originDecisions[origin] <= 0 {
		delete(originDecisions, origin)
		activeDecisionsByOrigin.WithLabelValues(origin).Set(0)
	} else {
		activeDecisionsByOrigin.WithLabelValues(origin).Set(float64(originDecisions[origin]))
	}
}

// --- Firewall dropped counters for LAPI ---

// DroppedCounters holds cumulative byte/packet counters from the firewall.
type DroppedCounters struct {
	Bytes   uint64
	Packets uint64
}

var droppedCountersMu sync.Mutex
var droppedCounters DroppedCounters
var lastSentCounters DroppedCounters

// SetDroppedCounters updates the current firewall dropped counters (cumulative).
func SetDroppedCounters(bytes, packets uint64) {
	droppedCountersMu.Lock()
	defer droppedCountersMu.Unlock()
	droppedCounters = DroppedCounters{Bytes: bytes, Packets: packets}
	droppedBytesTotal.Set(float64(bytes))
	droppedPacketsTotal.Set(float64(packets))
}

// GetAndResetDroppedDeltas returns the delta since last call and resets the baseline.
// This implements the "decrement after send" approach from the CrowdSec spec.
func GetAndResetDroppedDeltas() (bytes, packets uint64) {
	droppedCountersMu.Lock()
	defer droppedCountersMu.Unlock()

	// Handle counter wrap-around or reset (rule recreation).
	if droppedCounters.Bytes >= lastSentCounters.Bytes {
		bytes = droppedCounters.Bytes - lastSentCounters.Bytes
	} else {
		bytes = droppedCounters.Bytes // counter was reset
	}

	if droppedCounters.Packets >= lastSentCounters.Packets {
		packets = droppedCounters.Packets - lastSentCounters.Packets
	} else {
		packets = droppedCounters.Packets
	}

	lastSentCounters = droppedCounters

	return bytes, packets
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

// SetRouterOSSystemMetrics updates the RouterOS system resource gauges.
func SetRouterOSSystemMetrics(cpuLoad float64, memUsed, memTotal uint64) {
	routerosCPULoad.Set(cpuLoad)
	routerosMemoryUsed.Set(float64(memUsed))
	routerosMemoryTotal.Set(float64(memTotal))
}

// SetRouterOSCPUTemperature updates the RouterOS CPU temperature gauge.
func SetRouterOSCPUTemperature(celsius float64) {
	routerosCPUTemperature.Set(celsius)
}

// ConfigParams holds non-sensitive configuration values for the info metric.
type ConfigParams struct {
	CrowdSecAPIURL           string
	CrowdSecUpdateFrequency  string
	CrowdSecOrigins          []string
	CrowdSecScopes           []string
	CrowdSecDecisionTypes    []string
	CrowdSecRetryInitConnect bool
	CrowdSecTLS              bool
	MikroTikAddress          string
	MikroTikTLS              bool
	MikroTikPoolSize         int
	MikroTikConnTimeout      string
	MikroTikCmdTimeout       string
	FWIPv4Enabled            bool
	FWIPv4List               string
	FWIPv6Enabled            bool
	FWIPv6List               string
	FWFilterEnabled          bool
	FWFilterChains           []string
	FWRawEnabled             bool
	FWRawChains              []string
	FWDenyAction             string
	FWBlockOutput            bool
	FWRulePlacement          string
	FWCommentPrefix          string
	FWLog                    bool
	LogLevel                 string
	LogFormat                string
	MetricsEnabled           bool
	MetricsListenAddr        string
	MetricsListenPort        int
	MetricsPollInterval      string
}

// SetConfigInfo exposes non-sensitive configuration as Prometheus info metrics.
// Each parameter is emitted as a separate series with group/param/value labels.
func SetConfigInfo(p ConfigParams) {
	b := func(v bool) string {
		if v {
			return "true"
		}
		return "false"
	}

	configInfo.Reset()

	params := []struct {
		group, param, value string
	}{
		{"CrowdSec", "API URL", p.CrowdSecAPIURL},
		{"CrowdSec", "Update Frequency", p.CrowdSecUpdateFrequency},
		{"CrowdSec", "Origins", strings.Join(p.CrowdSecOrigins, ", ")},
		{"CrowdSec", "Scopes", strings.Join(p.CrowdSecScopes, ", ")},
		{"CrowdSec", "Decision Types", strings.Join(p.CrowdSecDecisionTypes, ", ")},
		{"CrowdSec", "Retry Initial Connect", b(p.CrowdSecRetryInitConnect)},
		{"CrowdSec", "TLS Enabled", b(p.CrowdSecTLS)},
		{"MikroTik", "Address", p.MikroTikAddress},
		{"MikroTik", "TLS Enabled", b(p.MikroTikTLS)},
		{"MikroTik", "Connection Pool Size", fmt.Sprintf("%d", p.MikroTikPoolSize)},
		{"MikroTik", "Connection Timeout", p.MikroTikConnTimeout},
		{"MikroTik", "Command Timeout", p.MikroTikCmdTimeout},
		{"Firewall", "IPv4 Enabled", b(p.FWIPv4Enabled)},
		{"Firewall", "IPv4 Address List", p.FWIPv4List},
		{"Firewall", "IPv6 Enabled", b(p.FWIPv6Enabled)},
		{"Firewall", "IPv6 Address List", p.FWIPv6List},
		{"Firewall", "Filter Enabled", b(p.FWFilterEnabled)},
		{"Firewall", "Filter Chains", strings.Join(p.FWFilterChains, ", ")},
		{"Firewall", "Raw Enabled", b(p.FWRawEnabled)},
		{"Firewall", "Raw Chains", strings.Join(p.FWRawChains, ", ")},
		{"Firewall", "Deny Action", p.FWDenyAction},
		{"Firewall", "Block Output", b(p.FWBlockOutput)},
		{"Firewall", "Rule Placement", p.FWRulePlacement},
		{"Firewall", "Comment Prefix", p.FWCommentPrefix},
		{"Firewall", "Logging Enabled", b(p.FWLog)},
		{"Logging", "Level", p.LogLevel},
		{"Logging", "Format", p.LogFormat},
		{"Metrics", "Enabled", b(p.MetricsEnabled)},
		{"Metrics", "Listen Address", p.MetricsListenAddr},
		{"Metrics", "Listen Port", fmt.Sprintf("%d", p.MetricsListenPort)},
		{"Metrics", "RouterOS Poll Interval", p.MetricsPollInterval},
	}

	for _, e := range params {
		configInfo.WithLabelValues(e.group, e.param, e.value).Set(1)
	}
}
