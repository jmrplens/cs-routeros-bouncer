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

	routerosUptimeSeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "crowdsec_bouncer_routeros_uptime_seconds",
		Help: "RouterOS uptime in seconds.",
	})

	routerosInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "crowdsec_bouncer_routeros_info",
		Help: "RouterOS system information.",
	}, []string{"version", "board_name"})

	droppedBytesProto = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "crowdsec_bouncer_dropped_bytes_by_proto",
		Help: "Cumulative bytes dropped by firewall rules, by protocol.",
	}, []string{"proto"})

	droppedPacketsProto = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "crowdsec_bouncer_dropped_packets_by_proto",
		Help: "Cumulative packets dropped by firewall rules, by protocol.",
	}, []string{"proto"})

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

// normalizeProto normalizes CrowdSec scope values to consistent protocol labels.
// CrowdSec sends "Ip" or "ip" for IPv4 and "Ip6"/"ipv6" for IPv6.
func normalizeProto(proto string) string {
	switch proto {
	case "ip", "Ip":
		return "ipv4"
	case "ipv6", "Ip6":
		return "ipv6"
	default:
		return proto
	}
}

// SetActiveDecisions sets the gauge for active decisions and updates the atomic counter.
func SetActiveDecisions(proto string, count int) {
	proto = normalizeProto(proto)
	activeDecisions.WithLabelValues(proto).Set(float64(count))
	switch proto {
	case "ipv4":
		activeDecisionCounts.ipv4.Store(int64(count))
	case "ipv6":
		activeDecisionCounts.ipv6.Store(int64(count))
	}
}

// IncrActiveDecisions increments the active decisions gauge and atomic counter.
func IncrActiveDecisions(proto string) {
	proto = normalizeProto(proto)
	activeDecisions.WithLabelValues(proto).Inc()
	switch proto {
	case "ipv4":
		activeDecisionCounts.ipv4.Add(1)
	case "ipv6":
		activeDecisionCounts.ipv6.Add(1)
	}
}

// DecrActiveDecisions decrements the active decisions gauge and atomic counter.
func DecrActiveDecisions(proto string) {
	proto = normalizeProto(proto)
	activeDecisions.WithLabelValues(proto).Dec()
	switch proto {
	case "ipv4":
		activeDecisionCounts.ipv4.Add(-1)
	case "ipv6":
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

// ProtoCounters holds byte/packet counters per IP protocol.
type ProtoCounters struct {
	IPv4Bytes uint64
	IPv4Pkts  uint64
	IPv6Bytes uint64
	IPv6Pkts  uint64
}

var droppedCountersMu sync.Mutex
var droppedCounters DroppedCounters
var lastSentCounters DroppedCounters

// Per-ip_type dropped counters for LAPI (delta tracking).
var droppedProtoState struct {
	mu       sync.Mutex
	current  ProtoCounters
	lastSent ProtoCounters
}

// Per-ip_type processed counters for LAPI (delta tracking).
var processedProtoState struct {
	mu       sync.Mutex
	current  ProtoCounters
	lastSent ProtoCounters
}

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

// SetDroppedCountersByIPType updates the per-ip_type dropped counters (cumulative).
func SetDroppedCountersByIPType(ipv4Bytes, ipv4Pkts, ipv6Bytes, ipv6Pkts uint64) {
	droppedProtoState.mu.Lock()
	defer droppedProtoState.mu.Unlock()
	droppedProtoState.current = ProtoCounters{
		IPv4Bytes: ipv4Bytes,
		IPv4Pkts:  ipv4Pkts,
		IPv6Bytes: ipv6Bytes,
		IPv6Pkts:  ipv6Pkts,
	}
}

// computeDelta returns the delta handling wrap-around/reset.
func computeDelta(current, lastSent uint64) uint64 {
	if current >= lastSent {
		return current - lastSent
	}
	return current // counter was reset
}

// GetAndResetDroppedDeltasByIPType returns per-ip_type dropped deltas and resets baseline.
func GetAndResetDroppedDeltasByIPType() (ipv4Bytes, ipv4Pkts, ipv6Bytes, ipv6Pkts uint64) {
	droppedProtoState.mu.Lock()
	defer droppedProtoState.mu.Unlock()

	ipv4Bytes = computeDelta(droppedProtoState.current.IPv4Bytes, droppedProtoState.lastSent.IPv4Bytes)
	ipv4Pkts = computeDelta(droppedProtoState.current.IPv4Pkts, droppedProtoState.lastSent.IPv4Pkts)
	ipv6Bytes = computeDelta(droppedProtoState.current.IPv6Bytes, droppedProtoState.lastSent.IPv6Bytes)
	ipv6Pkts = computeDelta(droppedProtoState.current.IPv6Pkts, droppedProtoState.lastSent.IPv6Pkts)

	droppedProtoState.lastSent = droppedProtoState.current
	return
}

// SetProcessedCounters updates the per-ip_type processed counters (cumulative).
// Processed = total traffic through all bouncer rules (drop + whitelist + passthrough).
func SetProcessedCounters(ipv4Bytes, ipv4Pkts, ipv6Bytes, ipv6Pkts uint64) {
	processedProtoState.mu.Lock()
	defer processedProtoState.mu.Unlock()
	processedProtoState.current = ProtoCounters{
		IPv4Bytes: ipv4Bytes,
		IPv4Pkts:  ipv4Pkts,
		IPv6Bytes: ipv6Bytes,
		IPv6Pkts:  ipv6Pkts,
	}
}

// GetAndResetProcessedDeltas returns per-ip_type processed deltas and resets baseline.
func GetAndResetProcessedDeltas() (ipv4Bytes, ipv4Pkts, ipv6Bytes, ipv6Pkts uint64) {
	processedProtoState.mu.Lock()
	defer processedProtoState.mu.Unlock()

	ipv4Bytes = computeDelta(processedProtoState.current.IPv4Bytes, processedProtoState.lastSent.IPv4Bytes)
	ipv4Pkts = computeDelta(processedProtoState.current.IPv4Pkts, processedProtoState.lastSent.IPv4Pkts)
	ipv6Bytes = computeDelta(processedProtoState.current.IPv6Bytes, processedProtoState.lastSent.IPv6Bytes)
	ipv6Pkts = computeDelta(processedProtoState.current.IPv6Pkts, processedProtoState.lastSent.IPv6Pkts)

	processedProtoState.lastSent = processedProtoState.current
	return
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

// SetRouterOSUptime updates the RouterOS uptime gauge.
func SetRouterOSUptime(seconds float64) {
	routerosUptimeSeconds.Set(seconds)
}

// SetRouterOSInfo sets the RouterOS info metric with version and board labels.
func SetRouterOSInfo(version, boardName string) {
	routerosInfo.Reset()
	routerosInfo.WithLabelValues(version, boardName).Set(1)
}

// SetDroppedCountersByProto updates the per-protocol dropped counters.
func SetDroppedCountersByProto(ipv4Bytes, ipv4Pkts, ipv6Bytes, ipv6Pkts uint64) {
	droppedBytesProto.WithLabelValues("ipv4").Set(float64(ipv4Bytes))
	droppedBytesProto.WithLabelValues("ipv6").Set(float64(ipv6Bytes))
	droppedPacketsProto.WithLabelValues("ipv4").Set(float64(ipv4Pkts))
	droppedPacketsProto.WithLabelValues("ipv6").Set(float64(ipv6Pkts))
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
