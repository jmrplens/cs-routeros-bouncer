package manager

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
	"github.com/jmrplens/cs-routeros-bouncer/internal/crowdsec"
	"github.com/jmrplens/cs-routeros-bouncer/internal/metrics"
	"github.com/jmrplens/cs-routeros-bouncer/internal/metrics/lapi"
	rosClient "github.com/jmrplens/cs-routeros-bouncer/internal/routeros"
)

// Manager-level constants define RouterOS comment signatures and channel sizing.
const (
	// defaultCommentPrefix is the fallback prefix for MikroTik resources when
	// no custom comment_prefix is set in the configuration.
	defaultCommentPrefix = "crowdsec-bouncer"

	// ruleSignature is a fixed, non-configurable identifier embedded in every
	// comment created by the bouncer (firewall rules and address list entries).
	// It allows reliable cleanup after a crash regardless of the configured
	// comment_prefix, since searching for this signature always finds all
	// bouncer-created resources.
	ruleSignature = "@cs-routeros-bouncer"

	// channelBuffer is the buffer size for decision channels.
	channelBuffer = 256
)

// Connection retry settings (vars so tests can override).
var (
	connectRetryInterval             = 10 * time.Second
	connectRetryTimeout              = 3 * time.Minute
	initialDecisionCollectionTimeout = 10 * time.Second
	initialDecisionIdleTimeout       = 3 * time.Second
)

// Manager orchestrates the CrowdSec stream and MikroTik firewall operations.
type Manager struct {
	cfg     config.Config
	ros     RouterOSClient
	pool    *rosClient.Pool
	stream  CrowdSecStream
	logger  zerolog.Logger
	version string

	// Track created firewall rule IDs for cleanup
	ruleIDs map[string]string // comment -> .id
	ruleMu  sync.Mutex

	// addressCache tracks addresses known to be on the router (for fast-path unban).
	// Protected by cacheMu. Keys are normalized addresses (e.g., "1.2.3.4", "::1/128").
	addressCache map[string]struct{}
	cacheMu      sync.RWMutex
}

type firewallRuleRef struct {
	Comment string
	ID      string
}

// NewManager creates a new bouncer manager.
func NewManager(cfg config.Config, version string) *Manager {
	return &Manager{
		cfg:          cfg,
		ros:          rosClient.NewClient(cfg.MikroTik),
		stream:       crowdsec.NewStream(cfg.CrowdSec, version),
		logger:       log.With().Str("component", "manager").Logger(),
		version:      version,
		ruleIDs:      make(map[string]string),
		addressCache: make(map[string]struct{}),
	}
}

// commentPrefix returns the effective comment prefix from config,
// falling back to defaultCommentPrefix if not set.
func (m *Manager) commentPrefix() string {
	if m.cfg.Firewall.CommentPrefix != "" {
		return m.cfg.Firewall.CommentPrefix
	}
	return defaultCommentPrefix
}

// connectWithRetry attempts to connect to the MikroTik router, retrying every
// connectRetryInterval for up to connectRetryTimeout. If the context is
// canceled during the retry loop, it returns immediately.
func (m *Manager) connectWithRetry(ctx context.Context) error {
	maxAttempts := int(connectRetryTimeout/connectRetryInterval) + 1
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := m.ros.Connect(); err != nil {
			lastErr = err
			metrics.SetConnected(false)

			if attempt == maxAttempts {
				break
			}

			remaining := connectRetryTimeout - time.Duration(attempt)*connectRetryInterval
			m.logger.Warn().
				Err(err).
				Int("attempt", attempt).
				Int("max_attempts", maxAttempts).
				Dur("retry_in", connectRetryInterval).
				Dur("remaining", remaining).
				Msg("failed to connect to MikroTik, retrying...")

			timer := time.NewTimer(connectRetryInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return fmt.Errorf("connecting to MikroTik: context canceled during retry: %w", ctx.Err())
			case <-timer.C:
			}
			continue
		}

		if attempt > 1 {
			m.logger.Info().Int("attempt", attempt).Msg("successfully connected to MikroTik after retry")
		}
		metrics.SetConnected(true)
		return nil
	}

	return fmt.Errorf("connecting to MikroTik: exhausted %d attempts over %v: %w",
		maxAttempts, connectRetryTimeout, lastErr)
}

// Start initializes all components and begins processing decisions.
func (m *Manager) Start(ctx context.Context) error {
	metrics.SetStartTime()
	if err := m.connectWithRetry(ctx); err != nil {
		return err
	}
	m.configureConnectionPool()
	m.recordRouterIdentity()
	m.recordConfigInfo()

	m.cleanupStaleRules()
	if err := m.createFirewallRules(); err != nil {
		return fmt.Errorf("creating firewall rules: %w", err)
	}
	if err := m.stream.Init(); err != nil {
		return fmt.Errorf("initializing CrowdSec stream: %w", err)
	}

	m.startLAPIMetrics(ctx)
	m.startRouterOSMetrics(ctx)

	banCh, deleteCh, errCh := m.startCrowdSecStream(ctx)
	initialBans, initialDeletes, err := m.collectInitialDecisions(ctx, banCh, deleteCh, errCh)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil
	}

	m.logInitialDecisions(initialBans, initialDeletes)
	m.reconcileAddresses(ctx, m.filterInitialBans(initialBans, initialDeletes))

	reconcileC, stopReconcile := m.reconciliationChannel()
	defer stopReconcile()

	m.logger.Info().Msg("reconciliation complete, processing live decisions")
	return m.processLiveDecisions(ctx, banCh, deleteCh, errCh, reconcileC)
}

// configureConnectionPool creates the optional RouterOS connection pool used by bulk cleanup.
func (m *Manager) configureConnectionPool() {
	poolSize := m.cfg.MikroTik.PoolSize
	if maxSessions := m.ros.GetAPIMaxSessions(); maxSessions > 0 {
		limit := max(maxSessions-2, 1)
		if poolSize > limit {
			m.logger.Info().
				Int("configured", m.cfg.MikroTik.PoolSize).
				Int("max_sessions", maxSessions).
				Int("effective", limit).
				Msg("pool size capped by router API max-sessions")
			poolSize = limit
		}
	}
	m.pool = rosClient.NewPool(m.cfg.MikroTik, poolSize)
	if err := m.pool.Connect(); err != nil {
		m.logger.Warn().Err(err).Msg("could not create connection pool, falling back to single connection")
		m.pool = nil
	}
}

// recordRouterIdentity stores RouterOS identity labels for Prometheus metrics.
func (m *Manager) recordRouterIdentity() {
	identity, identityErr := m.ros.GetIdentity()
	if identityErr != nil {
		m.logger.Warn().Err(identityErr).Msg("could not retrieve RouterOS identity")
		metrics.SetInfo(m.version, "unknown")
	} else {
		m.logger.Info().Str("identity", identity).Msg("connected to RouterOS")
		metrics.SetInfo(m.version, identity)
	}
}

// recordConfigInfo publishes static runtime configuration labels to metrics.
func (m *Manager) recordConfigInfo() {
	metrics.SetConfigInfo(metrics.ConfigParams{
		CrowdSecAPIURL:           m.cfg.CrowdSec.APIURL,
		CrowdSecUpdateFrequency:  m.cfg.CrowdSec.UpdateFrequency.String(),
		CrowdSecOrigins:          m.cfg.CrowdSec.Origins,
		CrowdSecScopes:           m.cfg.CrowdSec.Scopes,
		CrowdSecDecisionTypes:    m.cfg.CrowdSec.SupportedDecisionTypes,
		CrowdSecRetryInitConnect: m.cfg.CrowdSec.RetryInitialConnect,
		CrowdSecTLS:              m.cfg.CrowdSec.CertPath != "",
		MikroTikAddress:          m.cfg.MikroTik.Address,
		MikroTikTLS:              m.cfg.MikroTik.TLS,
		MikroTikPoolSize:         m.cfg.MikroTik.PoolSize,
		MikroTikConnTimeout:      m.cfg.MikroTik.ConnectionTimeout.String(),
		MikroTikCmdTimeout:       m.cfg.MikroTik.CommandTimeout.String(),
		FWIPv4Enabled:            m.cfg.Firewall.IPv4.Enabled,
		FWIPv4List:               m.cfg.Firewall.IPv4.AddressList,
		FWIPv6Enabled:            m.cfg.Firewall.IPv6.Enabled,
		FWIPv6List:               m.cfg.Firewall.IPv6.AddressList,
		FWFilterEnabled:          m.cfg.Firewall.Filter.Enabled,
		FWFilterChains:           m.cfg.Firewall.Filter.Chains,
		FWRawEnabled:             m.cfg.Firewall.Raw.Enabled,
		FWRawChains:              m.cfg.Firewall.Raw.Chains,
		FWDenyAction:             m.cfg.Firewall.DenyAction,
		FWBlockOutput:            m.cfg.Firewall.BlockOutput.Enabled,
		FWRulePlacement:          m.cfg.Firewall.RulePlacement.String(),
		FWCommentPrefix:          m.cfg.Firewall.CommentPrefix,
		FWLog:                    m.cfg.Firewall.Log,
		LogLevel:                 m.cfg.Logging.Level,
		LogFormat:                m.cfg.Logging.Format,
		MetricsEnabled:           m.cfg.Metrics.Enabled,
		MetricsListenAddr:        m.cfg.Metrics.ListenAddr,
		MetricsListenPort:        m.cfg.Metrics.ListenPort,
		MetricsPollInterval:      m.cfg.Metrics.RouterOSPollInterval.String(),
		MetricsTrackProcessed:    m.cfg.Metrics.TrackProcessed,
	})
}

// startLAPIMetrics starts CrowdSec usage-metrics reporting when configured.
func (m *Manager) startLAPIMetrics(ctx context.Context) {
	if m.cfg.CrowdSec.LapiMetricsInterval <= 0 {
		m.logger.Info().Msg("LAPI usage metrics reporting disabled")
		return
	}

	apiClient := m.stream.APIClient()
	logrusAdapter := crowdsec.NewLogrusAdapter(m.logger)
	metricsLogger := log.With().Str("component", "lapi-metrics").Logger()
	lapiProvider, providerErr := lapi.NewProvider(apiClient, m.cfg.CrowdSec.LapiMetricsInterval, logrusAdapter, metricsLogger)
	if providerErr != nil {
		m.logger.Warn().Err(providerErr).Msg("failed to initialize LAPI metrics, continuing without metrics reporting")
		return
	}

	lapiProvider.SetCounterCollector(m.collectLAPIFirewallCounters)
	m.logger.Info().Dur("interval", m.cfg.CrowdSec.LapiMetricsInterval).Msg("LAPI usage metrics reporting enabled")
	go func() {
		if runErr := lapiProvider.Run(ctx); runErr != nil {
			m.logger.Warn().Err(runErr).Msg("LAPI metrics provider stopped")
		}
	}()
}

// collectLAPIFirewallCounters refreshes RouterOS byte/packet counters for LAPI deltas.
func (m *Manager) collectLAPIFirewallCounters() {
	fc, countersErr := m.ros.GetFirewallCounters(m.commentPrefix() + ":")
	if countersErr != nil {
		m.logger.Debug().Err(countersErr).Msg("failed to collect firewall counters for LAPI metrics")
		return
	}
	metrics.SetDroppedCounters(fc.DroppedBytes, fc.DroppedPkts)
	metrics.SetDroppedCountersByIPType(
		fc.DroppedIPv4Bytes, fc.DroppedIPv4Pkts,
		fc.DroppedIPv6Bytes, fc.DroppedIPv6Pkts,
	)
	if m.cfg.Metrics.TrackProcessed {
		metrics.SetProcessedCounters(
			fc.ProcessedIPv4Bytes, fc.ProcessedIPv4Pkts,
			fc.ProcessedIPv6Bytes, fc.ProcessedIPv6Pkts,
		)
	}
}

// startRouterOSMetrics starts periodic RouterOS system polling when metrics are enabled.
func (m *Manager) startRouterOSMetrics(ctx context.Context) {
	if m.cfg.Metrics.Enabled && m.cfg.Metrics.RouterOSPollInterval > 0 {
		interval := m.cfg.Metrics.RouterOSPollInterval
		m.logger.Info().Dur("interval", interval).Msg("RouterOS system metrics polling enabled")
		go m.collectSystemMetrics(ctx, interval)
	}
}

// startCrowdSecStream starts the CrowdSec stream and returns decision/error channels.
func (m *Manager) startCrowdSecStream(ctx context.Context) (banCh, deleteCh chan *crowdsec.Decision, errCh chan error) {
	banCh = make(chan *crowdsec.Decision, channelBuffer)
	deleteCh = make(chan *crowdsec.Decision, channelBuffer)
	errCh = make(chan error, 1)
	go func() {
		if streamErr := m.stream.Run(ctx, banCh, deleteCh); streamErr != nil {
			errCh <- streamErr
		}
	}()
	return banCh, deleteCh, errCh
}

// collectInitialDecisions drains the startup decision burst before reconciliation.
func (m *Manager) collectInitialDecisions(ctx context.Context, banCh, deleteCh <-chan *crowdsec.Decision, errCh <-chan error) ([]*crowdsec.Decision, map[string]struct{}, error) {
	m.logger.Info().Msg("bouncer started, collecting initial decisions for reconciliation")
	var initialBans []*crowdsec.Decision
	initialDeletes := make(map[string]struct{})
	idleTimeout := time.NewTimer(initialDecisionCollectionTimeout)
	defer idleTimeout.Stop()

	resetIdleTimer := func() {
		if !idleTimeout.Stop() {
			select {
			case <-idleTimeout.C:
			default:
			}
		}
		idleTimeout.Reset(initialDecisionIdleTimeout)
	}

collectLoop:
	for {
		select {
		case <-ctx.Done():
			return nil, nil, nil
		case streamErr := <-errCh:
			return nil, nil, fmt.Errorf("CrowdSec stream error: %w", streamErr)
		case d := <-banCh:
			initialBans = append(initialBans, d)
			resetIdleTimer()
		case d := <-deleteCh:
			if d != nil {
				addr := rosClient.NormalizeAddress(d.Value, d.Proto)
				initialDeletes[addr] = struct{}{}
			}
			resetIdleTimer()
		case <-idleTimeout.C:
			break collectLoop
		}
	}
	return initialBans, initialDeletes, nil
}

// logInitialDecisions records the startup reconciliation input sizes.
func (m *Manager) logInitialDecisions(initialBans []*crowdsec.Decision, initialDeletes map[string]struct{}) {
	m.logger.Info().
		Int("bans", len(initialBans)).
		Int("deletes", len(initialDeletes)).
		Msg("initial decisions collected, starting reconciliation")
}

// filterInitialBans removes startup bans that were superseded by startup deletions.
func (m *Manager) filterInitialBans(initialBans []*crowdsec.Decision, initialDeletes map[string]struct{}) []*crowdsec.Decision {
	filteredBans := make([]*crowdsec.Decision, 0, len(initialBans))
	skipped := 0
	for _, d := range initialBans {
		addr := rosClient.NormalizeAddress(d.Value, d.Proto)
		if _, deleted := initialDeletes[addr]; deleted {
			skipped++
			continue
		}
		filteredBans = append(filteredBans, d)
	}
	if skipped > 0 {
		m.logger.Info().Int("skipped", skipped).Msg("skipped decisions that were immediately deleted")
	}
	return filteredBans
}

// reconciliationChannel creates the optional periodic reconciliation ticker.
func (m *Manager) reconciliationChannel() (reconcileC <-chan time.Time, stop func()) {
	reconcileInterval := m.cfg.CrowdSec.ReconciliationInterval
	if reconcileInterval <= 0 {
		m.logger.Info().Msg("periodic reconciliation disabled")
		return nil, func() {
			// No ticker was created when reconciliation is disabled.
		}
	}
	reconcileTicker := time.NewTicker(reconcileInterval)
	m.logger.Info().Dur("interval", reconcileInterval).Msg("periodic reconciliation enabled")
	return reconcileTicker.C, reconcileTicker.Stop
}

// processLiveDecisions handles live ban/unban events, stream errors, and reconciliation ticks.
func (m *Manager) processLiveDecisions(ctx context.Context, banCh, deleteCh <-chan *crowdsec.Decision, errCh <-chan error, reconcileC <-chan time.Time) error {
	for {
		select {
		case <-ctx.Done():
			m.logger.Info().Msg("shutting down manager")
			return nil

		case streamErr := <-errCh:
			return fmt.Errorf("CrowdSec stream error: %w", streamErr)

		case d := <-banCh:
			m.handleBan(d)

		case d := <-deleteCh:
			m.handleUnban(d)

		case <-reconcileC:
			m.reconcileActiveDecisions(ctx)
		}
	}
}

// reconcileActiveDecisions fetches a fresh active-decision snapshot from
// CrowdSec and applies the normal address-list diff against RouterOS.
func (m *Manager) reconcileActiveDecisions(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	start := time.Now()
	decisions, err := m.stream.ActiveDecisions(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		m.logger.Error().Err(err).Msg("periodic reconciliation snapshot failed")
		metrics.RecordError("reconcile")
		return
	}

	m.logger.Info().Int("decisions", len(decisions)).Msg("periodic reconciliation snapshot fetched")
	m.reconcileAddresses(ctx, decisions)
	m.logger.Info().Dur("elapsed", time.Since(start)).Msg("periodic reconciliation complete")
}

// Shutdown removes all firewall rules created by this bouncer.
func (m *Manager) Shutdown() {
	m.logger.Info().Msg("cleaning up firewall rules")
	m.removeFirewallRules()
	if m.pool != nil {
		m.pool.Close()
	}
	m.ros.Close()
	metrics.SetConnected(false)
	m.logger.Info().Msg("shutdown complete")
}

// collectSystemMetrics periodically polls RouterOS for CPU, memory, and
// temperature metrics and updates the Prometheus gauges.
func (m *Manager) collectSystemMetrics(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Collect once immediately at startup.
	m.pollSystemMetrics()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.pollSystemMetrics()
		}
	}
}

// pollSystemMetrics executes the RouterOS system resource and health queries.
func (m *Manager) pollSystemMetrics() {
	sr, err := m.ros.GetSystemResources()
	if err != nil {
		m.logger.Debug().Err(err).Msg("failed to collect system resources")
	} else {
		used := sr.TotalMemory - sr.FreeMemory
		metrics.SetRouterOSSystemMetrics(float64(sr.CPULoad), used, sr.TotalMemory)

		if sr.Uptime != "" {
			metrics.SetRouterOSUptime(rosClient.ParseMikroTikUptime(sr.Uptime))
		}
		if sr.Version != "" || sr.BoardName != "" {
			metrics.SetRouterOSInfo(sr.Version, sr.BoardName)
		}
	}

	sh, err := m.ros.GetSystemHealth()
	if err != nil {
		m.logger.Debug().Err(err).Msg("failed to collect system health")
	} else if sh.CPUTemperature >= 0 {
		metrics.SetRouterOSCPUTemperature(sh.CPUTemperature)
	}

	// Collect firewall dropped counters for Prometheus (independent of LAPI).
	fc, err := m.ros.GetFirewallCounters(m.commentPrefix() + ":")
	if err != nil {
		m.logger.Debug().Err(err).Msg("failed to collect firewall counters")
	} else {
		// Prometheus "dropped" gauges use only drop/reject rule counters.
		metrics.SetDroppedCounters(fc.DroppedBytes, fc.DroppedPkts)
		metrics.SetDroppedCountersByProto(fc.DroppedIPv4Bytes, fc.DroppedIPv4Pkts, fc.DroppedIPv6Bytes, fc.DroppedIPv6Pkts)
		// Prometheus "processed" gauges from passthrough counting rules.
		if m.cfg.Metrics.TrackProcessed {
			metrics.SetProcessedCountersPrometheus(fc.ProcessedIPv4Bytes, fc.ProcessedIPv4Pkts, fc.ProcessedIPv6Bytes, fc.ProcessedIPv6Pkts)
		}
	}
}

// handleBan processes a new ban decision.
// Uses optimistic add: tries to add first, handles "already exists" by updating timeout.
// This avoids the expensive FindAddress call (which scans entire address list).
func (m *Manager) handleBan(d *crowdsec.Decision) {
	if d == nil {
		return
	}

	start := time.Now()

	// Check if the protocol is enabled
	if d.Proto == "ip" && !m.cfg.Firewall.IPv4.Enabled {
		return
	}
	if d.Proto == "ipv6" && !m.cfg.Firewall.IPv6.Enabled {
		return
	}

	metricsProto := "ipv4"
	if d.Proto == "ipv6" {
		metricsProto = "ipv6"
	}

	listName := m.getAddressListName(d.Proto)
	addr := rosClient.NormalizeAddress(d.Value, d.Proto)

	m.cacheMu.RLock()
	_, inCache := m.addressCache[addr]
	m.cacheMu.RUnlock()
	if inCache {
		// The cache is intentionally authoritative between reconciliation passes
		// to avoid repeating RouterOS writes for duplicate live decisions. If an
		// entry disappears from RouterOS between passes, reconcileAddresses will
		// purge the stale cache key and re-add it when the decision remains active.
		m.logger.Debug().
			Str("address", d.Value).
			Str("list", listName).
			Msg("address already in cache, skipping duplicate ban")
		return
	}

	timeout := ""
	if d.Duration > 0 {
		timeout = rosClient.DurationToMikroTik(d.Duration)
	}

	comment := buildAddressComment(m.commentPrefix(), d)

	// AddAddress handles duplicates internally: if the address already exists
	// on the router it finds the existing entry and updates its attributes,
	// returning the existing ID with nil error.
	_, err := m.ros.AddAddress(d.Proto, listName, d.Value, timeout, comment)
	if err != nil {
		m.logger.Error().Err(err).Str("address", d.Value).Str("list", listName).Msg("error adding address to MikroTik")
		metrics.RecordError("add")
		return
	}

	// Update address cache
	m.cacheMu.Lock()
	m.addressCache[addr] = struct{}{}
	m.cacheMu.Unlock()

	metrics.RecordDecision("ban", metricsProto, d.Origin)
	metrics.IncrActiveDecisions(metricsProto)
	metrics.IncrActiveDecisionsByOrigin(d.Origin)
	metrics.ObserveOperationDuration("add", time.Since(start))

	m.logger.Info().
		Str("address", d.Value).
		Str("list", listName).
		Str("timeout", timeout).
		Str("origin", d.Origin).
		Str("scenario", d.Scenario).
		Msg("banned address")
}

// handleUnban processes a decision deletion.
// Uses address cache to skip FindAddress for addresses not on the router.
func (m *Manager) handleUnban(d *crowdsec.Decision) {
	if d == nil {
		return
	}

	start := time.Now()

	// Check if the protocol is enabled
	if d.Proto == "ip" && !m.cfg.Firewall.IPv4.Enabled {
		return
	}
	if d.Proto == "ipv6" && !m.cfg.Firewall.IPv6.Enabled {
		return
	}

	metricsProto := "ipv4"
	if d.Proto == "ipv6" {
		metricsProto = "ipv6"
	}

	listName := m.getAddressListName(d.Proto)
	addr := rosClient.NormalizeAddress(d.Value, d.Proto)

	// Fast-path: check address cache — skip API call if address is not on router
	m.cacheMu.RLock()
	_, inCache := m.addressCache[addr]
	m.cacheMu.RUnlock()

	if !inCache {
		m.logger.Debug().
			Str("address", d.Value).
			Msg("address not in cache, skipping unban (already expired or never added)")
		return
	}

	// Find the address in MikroTik
	entry, err := m.ros.FindAddress(d.Proto, listName, d.Value)
	if errors.Is(err, rosClient.ErrNotFound) {
		// Remove from cache — it expired on MikroTik
		m.cacheMu.Lock()
		delete(m.addressCache, addr)
		m.cacheMu.Unlock()

		m.logger.Debug().
			Str("address", d.Value).
			Msg("address not found in MikroTik (already expired?)")
		return
	}
	if err != nil {
		m.logger.Error().Err(err).
			Str("address", d.Value).
			Msg("error finding address for unban")
		metrics.RecordError("find")
		return
	}
	if entry == nil {
		// Defensive guard for RouterOSClient implementations that violate the
		// FindAddress contract and return (nil, nil).
		m.cacheMu.Lock()
		delete(m.addressCache, addr)
		m.cacheMu.Unlock()

		m.logger.Debug().
			Str("address", d.Value).
			Msg("address not found in MikroTik (already expired?)")
		return
	}

	// Remove the address
	if removeErr := m.ros.RemoveAddress(d.Proto, entry.ID); removeErr != nil {
		m.logger.Error().Err(removeErr).
			Str("address", d.Value).
			Str("id", entry.ID).
			Msg("error removing address from MikroTik")
		metrics.RecordError("remove")
		return
	}

	// Remove from cache
	m.cacheMu.Lock()
	delete(m.addressCache, addr)
	m.cacheMu.Unlock()

	metrics.RecordDecision("unban", metricsProto, d.Origin)
	metrics.DecrActiveDecisions(metricsProto)
	metrics.DecrActiveDecisionsByOrigin(d.Origin)
	metrics.ObserveOperationDuration("remove", time.Since(start))

	m.logger.Info().
		Str("address", d.Value).
		Str("list", listName).
		Msg("unbanned address")
}

// resolveLogPrefix returns the effective log-prefix for a rule type.
// Per-type prefix takes precedence; falls back to global firewall.log_prefix.
func (m *Manager) resolveLogPrefix(ruleType string) string {
	switch ruleType {
	case "filter":
		if m.cfg.Firewall.Filter.LogPrefix != "" {
			return m.cfg.Firewall.Filter.LogPrefix
		}
	case "raw":
		if m.cfg.Firewall.Raw.LogPrefix != "" {
			return m.cfg.Firewall.Raw.LogPrefix
		}
	case "output":
		if m.cfg.Firewall.BlockOutput.LogPrefix != "" {
			return m.cfg.Firewall.BlockOutput.LogPrefix
		}
	}
	return m.cfg.Firewall.LogPrefix
}

// cleanupStaleRules removes firewall rules left from a previous run. It
// searches for the fixed ruleSignature embedded in every bouncer-created rule
// comment, which reliably identifies all bouncer rules regardless of the
// configured comment_prefix. Address-list entries are reconciled separately
// during startup and are not removed during shutdown. This handles:
//   - Crash recovery (Shutdown was not called)
//   - comment_prefix changes between restarts
//   - Any other orphaned bouncer resources
func (m *Manager) cleanupStaleRules() {
	modes := []string{"filter", "raw"}
	protos := m.enabledProtos()

	removed := 0
	for _, proto := range protos {
		for _, mode := range modes {
			rules, err := m.ros.ListFirewallRulesBySignature(proto, mode, ruleSignature)
			if err != nil {
				m.logger.Debug().Err(err).
					Str("proto", proto).Str("mode", mode).
					Msg("could not list firewall rules for cleanup")
				continue
			}
			for _, r := range rules {
				if removeErr := m.ros.RemoveFirewallRule(proto, mode, r.ID); removeErr != nil {
					m.logger.Warn().Err(removeErr).
						Str("comment", r.Comment).Str("id", r.ID).
						Msg("failed to remove stale firewall rule")
				} else {
					m.logger.Info().
						Str("comment", r.Comment).
						Msg("removed stale firewall rule from previous run")
					removed++
				}
			}
		}
	}
	if removed > 0 {
		m.logger.Info().Int("count", removed).Msg("stale bouncer resources cleanup complete")
	}
}

// createFirewallRules creates all necessary firewall rules in MikroTik.
func (m *Manager) createFirewallRules() error {
	m.logger.Info().Msg("creating firewall rules")

	for _, proto := range m.enabledProtos() {
		listName := m.getAddressListName(proto)
		if err := m.createFilterRules(proto, listName); err != nil {
			return err
		}
		if err := m.createRawRules(proto, listName); err != nil {
			return err
		}
	}

	m.logger.Info().
		Int("rules_created", len(m.ruleIDs)).
		Msg("firewall rules ready")

	return nil
}

// createFilterRules creates all configured filter-table rules for one protocol.
func (m *Manager) createFilterRules(proto, listName string) error {
	if !m.cfg.Firewall.Filter.Enabled {
		return nil
	}
	for _, chain := range m.cfg.Firewall.Filter.Chains {
		if err := m.createFilterChainRules(proto, listName, chain); err != nil {
			return err
		}
	}
	if m.cfg.Firewall.BlockOutput.Enabled {
		outRule := m.outputRule(proto, listName)
		return m.ensureFirewallBlock(proto, "filter", "output", []rosClient.FirewallRule{outRule})
	}
	return nil
}

// createFilterChainRules creates whitelist, deny, counting, and output filter rules for one chain.
func (m *Manager) createFilterChainRules(proto, listName, chain string) error {
	rules := make([]rosClient.FirewallRule, 0, 3)
	if whitelistRule, ok := m.inputWhitelistRule(proto, "filter", chain); ok {
		rules = append(rules, whitelistRule)
	}
	comment := buildRuleComment(m.commentPrefix(), "filter", chain, "input", proto)
	if countingRule, ok := m.processedCountingRule(proto, "filter", chain); ok {
		rules = append(rules, countingRule)
	}
	rules = append(rules, m.filterInputRule(listName, chain, comment))
	return m.ensureFirewallBlock(proto, "filter", chain, rules)
}

// createRawRules creates all configured raw-table rules for one protocol.
func (m *Manager) createRawRules(proto, listName string) error {
	if !m.cfg.Firewall.Raw.Enabled {
		return nil
	}
	for _, chain := range m.cfg.Firewall.Raw.Chains {
		if err := m.createRawChainRules(proto, listName, chain); err != nil {
			return err
		}
	}
	return nil
}

// createRawChainRules creates whitelist, deny, and counting raw rules for one chain.
func (m *Manager) createRawChainRules(proto, listName, chain string) error {
	rules := make([]rosClient.FirewallRule, 0, 3)
	if whitelistRule, ok := m.inputWhitelistRule(proto, "raw", chain); ok {
		rules = append(rules, whitelistRule)
	}
	comment := buildRuleComment(m.commentPrefix(), "raw", chain, "input", proto)
	rule := rosClient.FirewallRule{
		Chain:          chain,
		Action:         m.rawDenyAction(),
		SrcAddressList: listName,
		Comment:        comment,
		Log:            m.cfg.Firewall.Log,
		LogPrefix:      m.resolveLogPrefix("raw"),
	}
	m.applyInputRuleOptions(&rule)
	if countingRule, ok := m.processedCountingRule(proto, "raw", chain); ok {
		rules = append(rules, countingRule)
	}
	rules = append(rules, rule)
	return m.ensureFirewallBlock(proto, "raw", chain, rules)
}

func (m *Manager) inputWhitelistRule(proto, mode, chain string) (rosClient.FirewallRule, bool) {
	if m.cfg.Firewall.BlockInput.Whitelist == "" {
		return rosClient.FirewallRule{}, false
	}
	comment := buildRuleComment(m.commentPrefix(), mode, chain, "whitelist", proto)
	rule := rosClient.FirewallRule{
		Chain:          chain,
		Action:         "accept",
		SrcAddressList: m.cfg.Firewall.BlockInput.Whitelist,
		Comment:        comment,
		Log:            m.cfg.Firewall.Log,
		LogPrefix:      m.resolveLogPrefix(mode),
	}
	m.applyInputRuleOptions(&rule)
	if mode == "filter" && m.cfg.Firewall.Filter.ConnectionState != "" {
		rule.ConnectionState = m.cfg.Firewall.Filter.ConnectionState
	}
	return rule, true
}

// filterInputRule builds the filter-table rule that blocks inbound source addresses.
func (m *Manager) filterInputRule(listName, chain, comment string) rosClient.FirewallRule {
	rule := rosClient.FirewallRule{
		Chain:          chain,
		Action:         m.cfg.Firewall.DenyAction,
		SrcAddressList: listName,
		Comment:        comment,
		Log:            m.cfg.Firewall.Log,
		LogPrefix:      m.resolveLogPrefix("filter"),
	}
	if m.cfg.Firewall.Filter.ConnectionState != "" {
		rule.ConnectionState = m.cfg.Firewall.Filter.ConnectionState
	}
	m.applyRejectOptions(&rule)
	m.applyInputRuleOptions(&rule)
	return rule
}

// outputRule builds the optional filter-table rule that blocks outbound destinations.
func (m *Manager) outputRule(proto, listName string) rosClient.FirewallRule {
	rule := rosClient.FirewallRule{
		Chain:          "output",
		Action:         m.cfg.Firewall.DenyAction,
		DstAddressList: listName,
		Comment:        buildRuleComment(m.commentPrefix(), "filter", "output", "output", proto),
		Log:            m.cfg.Firewall.Log,
		LogPrefix:      m.resolveLogPrefix("output"),
	}
	m.applyRejectOptions(&rule)
	m.applyOutputPassthrough(&rule, proto)
	if m.cfg.Firewall.BlockOutput.Interface != "" {
		rule.OutInterface = m.cfg.Firewall.BlockOutput.Interface
	}
	if m.cfg.Firewall.BlockOutput.InterfaceList != "" {
		rule.OutInterfaceList = m.cfg.Firewall.BlockOutput.InterfaceList
	}
	return rule
}

// applyRejectOptions adds RouterOS reject-with settings when deny_action is reject.
func (m *Manager) applyRejectOptions(rule *rosClient.FirewallRule) {
	if m.cfg.Firewall.DenyAction == "reject" && m.cfg.Firewall.RejectWith != "" {
		rule.RejectWith = m.cfg.Firewall.RejectWith
	}
}

// applyOutputPassthrough adds negated source exceptions for output blocking rules.
func (m *Manager) applyOutputPassthrough(rule *rosClient.FirewallRule, proto string) {
	if proto == "ip" {
		setNegatedAddress(&rule.SrcAddressList, m.cfg.Firewall.BlockOutput.PassthroughV4List)
		if rule.SrcAddressList == "" {
			setNegatedAddress(&rule.SrcAddress, m.cfg.Firewall.BlockOutput.PassthroughV4)
		}
		return
	}
	setNegatedAddress(&rule.SrcAddressList, m.cfg.Firewall.BlockOutput.PassthroughV6List)
	if rule.SrcAddressList == "" {
		setNegatedAddress(&rule.SrcAddress, m.cfg.Firewall.BlockOutput.PassthroughV6)
	}
}

// setNegatedAddress writes a RouterOS negated address matcher when value is set.
func setNegatedAddress(target *string, value string) {
	if value != "" {
		*target = "!" + value
	}
}

// rawDenyAction maps reject to drop because RouterOS raw rules cannot reject.
func (m *Manager) rawDenyAction() string {
	if m.cfg.Firewall.DenyAction == "reject" {
		return "drop"
	}
	return m.cfg.Firewall.DenyAction
}

func (m *Manager) processedCountingRule(proto, mode, chain string) (rosClient.FirewallRule, bool) {
	if !m.cfg.Metrics.TrackProcessed {
		return rosClient.FirewallRule{}, false
	}
	comment := buildRuleComment(m.commentPrefix(), mode, chain, "counting", proto)
	rule := rosClient.FirewallRule{Chain: chain, Action: "passthrough", Comment: comment}
	m.applyInputRuleOptions(&rule)
	return rule, true
}

// applyInputRuleOptions sets inbound interface matchers on a firewall rule.
func (m *Manager) applyInputRuleOptions(rule *rosClient.FirewallRule) {
	if m.cfg.Firewall.BlockInput.Interface != "" {
		rule.InInterface = m.cfg.Firewall.BlockInput.Interface
	}
	if m.cfg.Firewall.BlockInput.InterfaceList != "" {
		rule.InInterfaceList = m.cfg.Firewall.BlockInput.InterfaceList
	}
}

func (m *Manager) ensureFirewallRuleRef(proto, mode string, rule rosClient.FirewallRule) (firewallRuleRef, error) {
	// Check if rule already exists
	existing, err := m.ros.FindFirewallRuleByComment(proto, mode, rule.Comment)
	if err != nil && !errors.Is(err, rosClient.ErrNotFound) {
		metrics.RecordError("firewall")
		return firewallRuleRef{}, fmt.Errorf("checking existing rule %q: %w", rule.Comment, err)
	}

	if err == nil && existing != nil {
		m.logger.Debug().
			Str("comment", rule.Comment).
			Str("id", existing.ID).
			Msg("firewall rule already exists")
		m.ruleMu.Lock()
		m.ruleIDs[rule.Comment] = existing.ID
		m.ruleMu.Unlock()
		return firewallRuleRef{Comment: rule.Comment, ID: existing.ID}, nil
	}

	id, err := m.ros.AddFirewallRule(proto, mode, rule)
	if err != nil {
		metrics.RecordError("firewall")
		return firewallRuleRef{}, fmt.Errorf("creating firewall rule %q: %w", rule.Comment, err)
	}

	m.ruleMu.Lock()
	m.ruleIDs[rule.Comment] = id
	m.ruleMu.Unlock()

	return firewallRuleRef{Comment: rule.Comment, ID: id}, nil
}

func (m *Manager) ensureFirewallBlock(proto, mode, chain string, rules []rosClient.FirewallRule) error {
	refs := make([]firewallRuleRef, 0, len(rules))
	for _, rule := range rules {
		ref, err := m.ensureFirewallRuleRef(proto, mode, rule)
		if err != nil {
			return err
		}
		refs = append(refs, ref)
	}
	m.placeFirewallBlock(proto, mode, chain, refs)
	return nil
}

func (m *Manager) placeFirewallBlock(proto, mode, chain string, refs []firewallRuleRef) {
	if len(refs) == 0 {
		return
	}
	placement := m.cfg.Firewall.RulePlacement.ForMode(mode)
	strategy := placement.Strategy
	if strategy == "" {
		strategy = config.RulePlacementTop
	}
	if strategy == config.RulePlacementBottom {
		return
	}

	candidates, err := m.placementCandidates(proto, mode)
	if err != nil {
		m.logger.Warn().Err(err).
			Str("proto", proto).
			Str("mode", mode).
			Str("chain", chain).
			Msg("could not list firewall rules for placement; block left at bottom")
		return
	}

	switch strategy {
	case config.RulePlacementTop:
		m.placeFirewallBlockAtPosition(proto, mode, refs, candidates, 0)
	case config.RulePlacementPosition:
		position := 0
		if placement.Position != nil {
			position = *placement.Position
		}
		m.placeFirewallBlockAtPosition(proto, mode, refs, candidates, position)
	case config.RulePlacementBeforeComment:
		m.placeFirewallBlockBeforeComment(proto, mode, refs, candidates, placement)
	case config.RulePlacementAfterComment:
		m.placeFirewallBlockAfterComment(proto, mode, refs, candidates, placement)
	}
}

func (m *Manager) placementCandidates(proto, mode string) ([]rosClient.RuleEntry, error) {
	rules, err := m.ros.ListFirewallRules(proto, mode, "")
	if err != nil {
		return nil, err
	}
	candidates := make([]rosClient.RuleEntry, 0, len(rules))
	for _, rule := range rules {
		if hasRuleSignature(rule.Comment) {
			continue
		}
		candidates = append(candidates, rule)
	}
	return candidates, nil
}

func (m *Manager) placeFirewallBlockAtPosition(proto, mode string, refs []firewallRuleRef, candidates []rosClient.RuleEntry, position int) {
	if position >= len(candidates) {
		m.logger.Debug().
			Str("proto", proto).
			Str("mode", mode).
			Int("position", position).
			Int("rules", len(candidates)).
			Msg("configured firewall rule position is beyond existing rules; block left at bottom")
		return
	}
	for i := position; i < len(candidates); i++ {
		target := candidates[i]
		if err := m.moveFirewallBlockBefore(proto, mode, refs, target.ID); err != nil {
			m.logger.Debug().Err(err).
				Str("proto", proto).
				Str("mode", mode).
				Int("position", i).
				Str("target", target.ID).
				Msg("cannot move firewall block before target, trying next position")
			continue
		}
		m.logger.Info().
			Str("proto", proto).
			Str("mode", mode).
			Int("position", i).
			Msg("firewall rule block positioned")
		return
	}
	m.logger.Warn().
		Str("proto", proto).
		Str("mode", mode).
		Int("position", position).
		Msg("could not move firewall rule block to requested position; block left at bottom")
}

func (m *Manager) placeFirewallBlockBeforeComment(
	proto, mode string,
	refs []firewallRuleRef,
	candidates []rosClient.RuleEntry,
	placement config.RulePlacementConfig,
) {
	index, ok := findPlacementComment(candidates, placement)
	if !ok {
		m.logger.Warn().
			Str("proto", proto).
			Str("mode", mode).
			Str("comment", placement.Comment).
			Msg("firewall rule placement anchor not found; using fallback")
		m.placeFirewallBlockFallback(proto, mode, refs, candidates, placement)
		return
	}
	if err := m.moveFirewallBlockBefore(proto, mode, refs, candidates[index].ID); err != nil {
		m.logger.Warn().Err(err).
			Str("proto", proto).
			Str("mode", mode).
			Str("comment", placement.Comment).
			Msg("could not move firewall rule block before anchor; using fallback")
		m.placeFirewallBlockFallback(proto, mode, refs, candidates, placement)
	}
}

func (m *Manager) placeFirewallBlockAfterComment(
	proto, mode string,
	refs []firewallRuleRef,
	candidates []rosClient.RuleEntry,
	placement config.RulePlacementConfig,
) {
	index, ok := findPlacementComment(candidates, placement)
	if !ok {
		m.logger.Warn().
			Str("proto", proto).
			Str("mode", mode).
			Str("comment", placement.Comment).
			Msg("firewall rule placement anchor not found; using fallback")
		m.placeFirewallBlockFallback(proto, mode, refs, candidates, placement)
		return
	}
	if index+1 >= len(candidates) {
		m.logger.Info().
			Str("proto", proto).
			Str("mode", mode).
			Str("comment", placement.Comment).
			Msg("firewall rule placement anchor is last rule; block left at bottom")
		return
	}
	if err := m.moveFirewallBlockBefore(proto, mode, refs, candidates[index+1].ID); err != nil {
		m.logger.Warn().Err(err).
			Str("proto", proto).
			Str("mode", mode).
			Str("comment", placement.Comment).
			Msg("could not move firewall rule block after anchor; using fallback")
		m.placeFirewallBlockFallback(proto, mode, refs, candidates, placement)
	}
}

func findPlacementComment(candidates []rosClient.RuleEntry, placement config.RulePlacementConfig) (int, bool) {
	matchMode := placement.CommentMatch
	if matchMode == "" {
		matchMode = config.RulePlacementMatchExact
	}
	for i, candidate := range candidates {
		switch matchMode {
		case config.RulePlacementMatchContains:
			if strings.Contains(candidate.Comment, placement.Comment) {
				return i, true
			}
		default:
			if candidate.Comment == placement.Comment {
				return i, true
			}
		}
	}
	return 0, false
}

func (m *Manager) placeFirewallBlockFallback(
	proto, mode string,
	refs []firewallRuleRef,
	candidates []rosClient.RuleEntry,
	placement config.RulePlacementConfig,
) {
	fallback := placement.Fallback
	if fallback == "" {
		fallback = config.RulePlacementTop
	}
	if fallback == config.RulePlacementBottom {
		return
	}
	m.placeFirewallBlockAtPosition(proto, mode, refs, candidates, 0)
}

// moveFirewallBlockBefore moves refs one by one using m.ros.MoveFirewallRule.
// If a move fails after earlier refs were moved before beforeID, the block may
// be partially reordered; callers can retry placement later to complete ordering.
func (m *Manager) moveFirewallBlockBefore(proto, mode string, refs []firewallRuleRef, beforeID string) error {
	for _, ref := range refs {
		if err := m.ros.MoveFirewallRule(proto, mode, ref.ID, beforeID); err != nil {
			return fmt.Errorf("moving firewall rule %q before %q: %w", ref.Comment, beforeID, err)
		}
	}
	return nil
}

// removeFirewallRules removes all firewall rules created by this bouncer.
func (m *Manager) removeFirewallRules() {
	m.ruleMu.Lock()
	defer m.ruleMu.Unlock()

	for comment, id := range m.ruleIDs {
		// Determine proto and mode from comment
		proto, mode := parseRuleComment(m.commentPrefix(), comment)
		if proto == "" || mode == "" {
			m.logger.Warn().Str("comment", comment).Msg("could not parse rule comment for cleanup")
			continue
		}

		if err := m.ros.RemoveFirewallRule(proto, mode, id); err != nil {
			m.logger.Error().Err(err).
				Str("comment", comment).
				Str("id", id).
				Msg("error removing firewall rule")
		} else {
			m.logger.Info().
				Str("comment", comment).
				Msg("removed firewall rule")
		}
	}

	m.ruleIDs = make(map[string]string)
}

// reconcileAddresses performs initial state reconciliation on startup.
// Compares CrowdSec active decisions with MikroTik address lists
// and adds/removes entries as needed.
// Uses script-based bulk add and parallel workers for maximum speed.
// reconcileAddresses synchronizes RouterOS address lists with the active CrowdSec decisions.
func (m *Manager) reconcileAddresses(ctx context.Context, decisions []*crowdsec.Decision) {
	if ctx.Err() != nil {
		return
	}
	m.logger.Info().Int("decisions", len(decisions)).Msg("reconciling addresses with MikroTik")

	start := time.Now()
	globalOriginCounts := map[string]int64{}

	for _, proto := range m.enabledProtos() {
		if ctx.Err() != nil {
			return
		}
		result, err := m.reconcileProtocolAddresses(proto, decisions, start)
		if err != nil {
			continue
		}
		mergeOriginCounts(globalOriginCounts, result.originCounts)
	}

	metrics.ObserveOperationDuration("reconcile", time.Since(start))
	for origin, count := range globalOriginCounts {
		metrics.SetActiveDecisionsByOrigin(origin, count)
	}
}

// reconcileDiff groups the desired, current, missing, and stale address state for one protocol.
type reconcileDiff struct {
	shouldExist map[string]*crowdsec.Decision
	currentMap  map[string]rosClient.AddressEntry
	toAdd       []rosClient.BulkEntry
	toRemove    []rosClient.AddressEntry
}

// reconcileResult carries per-protocol reconciliation data used after processing.
type reconcileResult struct {
	originCounts map[string]int64
}

// reconcileProtocolAddresses applies the address-list diff for one RouterOS protocol.
func (m *Manager) reconcileProtocolAddresses(proto string, decisions []*crowdsec.Decision, start time.Time) (reconcileResult, error) {
	listName := m.getAddressListName(proto)
	existing, err := m.ros.ListAddresses(proto, listName, m.commentPrefix())
	if err != nil {
		m.logger.Error().Err(err).Str("proto", proto).Msg("error listing current addresses")
		metrics.RecordError("find")
		return reconcileResult{}, err
	}

	diff := buildReconcileDiff(proto, decisions, existing, m.commentPrefix())
	m.refreshAddressCache(proto, diff.currentMap)
	metricsProto := metricsProtoName(proto)
	added := m.addMissingAddresses(proto, listName, metricsProto, diff.toAdd)
	removed := m.removeStaleAddresses(proto, metricsProto, diff.toRemove)
	m.recordReconciliationMetrics(metricsProto, len(diff.shouldExist), added, removed)

	m.logger.Info().
		Str("proto", proto).
		Int("existing", len(existing)).
		Int("expected", len(diff.shouldExist)).
		Int("added", added).
		Int("removed", removed).
		Dur("elapsed", time.Since(start)).
		Msg("address reconciliation complete")

	return reconcileResult{originCounts: originCounts(diff.shouldExist)}, nil
}

// buildReconcileDiff computes additions and removals from desired and current address state.
func buildReconcileDiff(proto string, decisions []*crowdsec.Decision, existing []rosClient.AddressEntry, commentPrefix string) reconcileDiff {
	shouldExist := desiredAddressMap(proto, decisions)
	currentMap := currentAddressMap(existing)
	return reconcileDiff{
		shouldExist: shouldExist,
		currentMap:  currentMap,
		toAdd:       missingAddressEntries(shouldExist, currentMap, commentPrefix),
		toRemove:    staleAddressEntries(shouldExist, currentMap),
	}
}

// desiredAddressMap indexes active decisions by normalized RouterOS address.
func desiredAddressMap(proto string, decisions []*crowdsec.Decision) map[string]*crowdsec.Decision {
	shouldExist := make(map[string]*crowdsec.Decision)
	for _, decision := range decisions {
		if decision.Proto != proto {
			continue
		}
		addr := rosClient.NormalizeAddress(decision.Value, proto)
		shouldExist[addr] = decision
	}
	return shouldExist
}

// currentAddressMap indexes RouterOS address-list entries by normalized address.
func currentAddressMap(existing []rosClient.AddressEntry) map[string]rosClient.AddressEntry {
	currentMap := make(map[string]rosClient.AddressEntry)
	for _, entry := range existing {
		currentMap[entry.Address] = entry
	}
	return currentMap
}

// missingAddressEntries builds RouterOS bulk-add entries for decisions not yet present.
func missingAddressEntries(shouldExist map[string]*crowdsec.Decision, currentMap map[string]rosClient.AddressEntry, commentPrefix string) []rosClient.BulkEntry {
	var toAdd []rosClient.BulkEntry
	for addr, decision := range shouldExist {
		if _, exists := currentMap[addr]; exists {
			continue
		}
		toAdd = append(toAdd, rosClient.BulkEntry{
			Address: decision.Value,
			Timeout: decisionTimeout(decision),
			Comment: buildAddressComment(commentPrefix, decision),
		})
	}
	return toAdd
}

// decisionTimeout converts CrowdSec duration to RouterOS timeout syntax.
func decisionTimeout(decision *crowdsec.Decision) string {
	if decision.Duration <= 0 {
		return ""
	}
	return rosClient.DurationToMikroTik(decision.Duration)
}

// staleAddressEntries returns RouterOS entries that no active decision still requires.
func staleAddressEntries(shouldExist map[string]*crowdsec.Decision, currentMap map[string]rosClient.AddressEntry) []rosClient.AddressEntry {
	var toRemove []rosClient.AddressEntry
	for addr, entry := range currentMap {
		if _, ok := shouldExist[addr]; !ok {
			toRemove = append(toRemove, entry)
		}
	}
	return toRemove
}

// refreshAddressCache replaces the cache contents for one protocol after reconciliation.
func (m *Manager) refreshAddressCache(proto string, currentMap map[string]rosClient.AddressEntry) {
	// Hold cacheMu through the full replacement for this protocol so concurrent
	// handleBan/handleUnban calls never observe a partially refreshed cache.
	// Large reconciliations may briefly block live handlers, but correctness wins
	// over lower-latency cache updates here.
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	for addr := range m.addressCache {
		if strings.Contains(addr, ":") != (proto == "ipv6") {
			continue
		}
		if _, exists := currentMap[addr]; !exists {
			delete(m.addressCache, addr)
		}
	}
	for addr := range currentMap {
		m.addressCache[addr] = struct{}{}
	}
}

// addMissingAddresses bulk-adds missing entries and records reconciliation metrics.
func (m *Manager) addMissingAddresses(proto, listName, metricsProto string, toAdd []rosClient.BulkEntry) int {
	if len(toAdd) == 0 {
		return 0
	}
	addStart := time.Now()
	added, addErr := m.ros.BulkAddAddresses(proto, listName, toAdd)
	if addErr != nil {
		m.logger.Warn().Err(addErr).Msg("some addresses failed to add during reconciliation")
	}
	m.addEntriesToCache(proto, toAdd)
	for range added {
		metrics.RecordDecision("ban", metricsProto, "reconcile")
	}
	metrics.ObserveOperationDuration("bulk_add", time.Since(addStart))
	m.logger.Info().Int("added", added).Dur("elapsed", time.Since(addStart)).Msg("bulk add complete")
	return added
}

// addEntriesToCache records newly added address-list entries in the fast-path cache.
func (m *Manager) addEntriesToCache(proto string, entries []rosClient.BulkEntry) {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	for _, entry := range entries {
		addr := rosClient.NormalizeAddress(entry.Address, proto)
		m.addressCache[addr] = struct{}{}
	}
}

// removeStaleAddresses removes obsolete RouterOS entries and records reconciliation metrics.
func (m *Manager) removeStaleAddresses(proto, metricsProto string, toRemove []rosClient.AddressEntry) int {
	if len(toRemove) == 0 {
		return 0
	}
	removeStart := time.Now()
	removed := m.removeAddresses(proto, toRemove)
	m.removeEntriesFromCache(toRemove)
	for range removed {
		metrics.RecordDecision("unban", metricsProto, "reconcile")
	}
	metrics.ObserveOperationDuration("bulk_remove", time.Since(removeStart))
	m.logger.Info().Int("removed", removed).Dur("elapsed", time.Since(removeStart)).Msg("bulk remove complete")
	return removed
}

// removeAddresses selects parallel or sequential removal depending on pool availability.
func (m *Manager) removeAddresses(proto string, entries []rosClient.AddressEntry) int {
	if m.pool != nil {
		return m.removeAddressesParallel(proto, entries)
	}
	return m.removeAddressesSequential(proto, entries)
}

// removeAddressesParallel removes address-list entries through the RouterOS connection pool.
func (m *Manager) removeAddressesParallel(proto string, entries []rosClient.AddressEntry) int {
	errs := rosClient.ParallelExec(m.pool, entries, func(c *rosClient.Client, entry rosClient.AddressEntry) error {
		return c.RemoveAddress(proto, entry.ID)
	})
	removed := len(entries) - len(errs)
	for _, err := range errs {
		if errors.Is(err, rosClient.ErrNotFound) {
			removed++
			continue
		}
		m.logger.Error().Err(err).Msg("reconcile: error removing address")
		metrics.RecordError("remove")
	}
	return removed
}

// removeAddressesSequential removes address-list entries through the primary RouterOS client.
func (m *Manager) removeAddressesSequential(proto string, entries []rosClient.AddressEntry) int {
	removed := 0
	for _, entry := range entries {
		removeErr := m.ros.RemoveAddress(proto, entry.ID)
		switch {
		case removeErr == nil:
			removed++
		case errors.Is(removeErr, rosClient.ErrNotFound):
			removed++
		default:
			m.logger.Error().Err(removeErr).Str("address", entry.Address).Msg("reconcile: error removing address")
			metrics.RecordError("remove")
		}
	}
	return removed
}

// removeEntriesFromCache deletes removed RouterOS entries from the fast-path cache.
func (m *Manager) removeEntriesFromCache(entries []rosClient.AddressEntry) {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	for _, entry := range entries {
		delete(m.addressCache, entry.Address)
	}
}

// recordReconciliationMetrics updates Prometheus gauges and counters for one protocol.
func (m *Manager) recordReconciliationMetrics(metricsProto string, expected, added, removed int) {
	unchanged := max(expected-added, 0)
	metrics.RecordReconciliation("added", added)
	metrics.RecordReconciliation("removed", removed)
	metrics.RecordReconciliation("unchanged", unchanged)
	metrics.SetActiveDecisions(metricsProto, expected)
}

// metricsProtoName converts RouterOS protocol names to metric label values.
func metricsProtoName(proto string) string {
	if proto == "ipv6" {
		return "ipv6"
	}
	return "ipv4"
}

// originCounts aggregates active decisions by CrowdSec origin label.
func originCounts(shouldExist map[string]*crowdsec.Decision) map[string]int64 {
	counts := map[string]int64{}
	for _, decision := range shouldExist {
		origin := decision.Origin
		if origin == "" {
			origin = "unknown"
		}
		counts[origin]++
	}
	return counts
}

// mergeOriginCounts accumulates source origin counts into target.
func mergeOriginCounts(target, source map[string]int64) {
	for origin, count := range source {
		target[origin] += count
	}
}

// enabledProtos returns the list of enabled protocol strings ("ip" and/or "ipv6").
func (m *Manager) enabledProtos() []string {
	var protos []string
	if m.cfg.Firewall.IPv4.Enabled {
		protos = append(protos, "ip")
	}
	if m.cfg.Firewall.IPv6.Enabled {
		protos = append(protos, "ipv6")
	}
	return protos
}

// getAddressListName returns the address list name for the given protocol.
func (m *Manager) getAddressListName(proto string) string {
	if proto == "ipv6" {
		return m.cfg.Firewall.IPv6.AddressList
	}
	return m.cfg.Firewall.IPv4.AddressList
}

// buildRuleComment creates a deterministic comment for a firewall rule.
// Format: <prefix>:<mode>-<chain>-<direction>-<proto> @cs-routeros-bouncer
// The fixed ruleSignature suffix allows reliable identification of all
// bouncer-created rules regardless of the configured prefix.
func buildRuleComment(prefix, mode, chain, direction, proto string) string {
	protoSuffix := "v4"
	if proto == "ipv6" {
		protoSuffix = "v6"
	}
	return fmt.Sprintf("%s:%s-%s-%s-%s %s", prefix, mode, chain, direction, protoSuffix, ruleSignature)
}

// parseRuleComment extracts proto and mode from a rule comment.
func parseRuleComment(prefix, comment string) (proto, mode string) {
	// Strip the signature suffix before parsing
	comment = strings.TrimSuffix(comment, " "+ruleSignature)

	// Format: <prefix>:<mode>-<chain>-<direction>-<proto>
	if !strings.HasPrefix(comment, prefix+":") {
		return "", ""
	}
	parts := strings.SplitN(comment[len(prefix)+1:], "-", 2)
	if len(parts) < 2 {
		return "", ""
	}
	mode = parts[0]

	if strings.HasSuffix(comment, "-v6") {
		proto = "ipv6"
	} else {
		proto = "ip"
	}

	return proto, mode
}

// hasRuleSignature checks whether a comment contains the bouncer's fixed
// signature, identifying it as a bouncer-created resource.
func hasRuleSignature(comment string) bool {
	return strings.Contains(comment, ruleSignature)
}

// buildAddressComment creates a comment for an address list entry.
// Format: <prefix>|origin|scenario|timestamp @cs-routeros-bouncer
func buildAddressComment(prefix string, d *crowdsec.Decision) string {
	parts := []string{prefix}
	if d.Origin != "" {
		parts = append(parts, d.Origin)
	}
	if d.Scenario != "" {
		parts = append(parts, d.Scenario)
	}
	parts = append(parts, time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	return strings.Join(parts, "|") + " " + ruleSignature
}
