package manager

import (
	"context"
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

// Start initializes all components and begins processing decisions.
func (m *Manager) Start(ctx context.Context) error {
	// Record startup metrics
	metrics.SetStartTime()

	// 1. Connect to MikroTik
	if err := m.ros.Connect(); err != nil {
		metrics.SetConnected(false)
		return fmt.Errorf("connecting to MikroTik: %w", err)
	}
	metrics.SetConnected(true)

	// 1b. Determine effective pool size (configured value capped by router limit)
	poolSize := m.cfg.MikroTik.PoolSize
	if maxSessions := m.ros.GetAPIMaxSessions(); maxSessions > 0 {
		// Reserve 1 session for the main client + external tools
		limit := maxSessions - 2
		if limit < 1 {
			limit = 1
		}
		if poolSize > limit {
			m.logger.Info().
				Int("configured", m.cfg.MikroTik.PoolSize).
				Int("max_sessions", maxSessions).
				Int("effective", limit).
				Msg("pool size capped by router API max-sessions")
			poolSize = limit
		}
	}

	// 1c. Connect the parallel pool for bulk operations
	m.pool = rosClient.NewPool(m.cfg.MikroTik, poolSize)
	if err := m.pool.Connect(); err != nil {
		m.logger.Warn().Err(err).Msg("could not create connection pool, falling back to single connection")
		m.pool = nil
	}

	identity, err := m.ros.GetIdentity()
	if err != nil {
		m.logger.Warn().Err(err).Msg("could not retrieve RouterOS identity")
		metrics.SetInfo(m.version, "unknown")
	} else {
		m.logger.Info().Str("identity", identity).Msg("connected to RouterOS")
		metrics.SetInfo(m.version, identity)
	}

	// 2. Expose non-sensitive configuration as Prometheus info metric
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
		FWRulePlacement:          m.cfg.Firewall.RulePlacement,
		FWCommentPrefix:          m.cfg.Firewall.CommentPrefix,
		FWLog:                    m.cfg.Firewall.Log,
		LogLevel:                 m.cfg.Logging.Level,
		LogFormat:                m.cfg.Logging.Format,
		MetricsEnabled:           m.cfg.Metrics.Enabled,
		MetricsListenAddr:        m.cfg.Metrics.ListenAddr,
		MetricsListenPort:        m.cfg.Metrics.ListenPort,
		MetricsPollInterval:      m.cfg.Metrics.RouterOSPollInterval.String(),
	})

	// 4. Clean up stale firewall rules from a previous run or prefix change
	m.cleanupStaleRules()

	// 5. Create firewall rules
	if err := m.createFirewallRules(); err != nil {
		return fmt.Errorf("creating firewall rules: %w", err)
	}

	// 6. Initialize CrowdSec stream
	if err := m.stream.Init(); err != nil {
		return fmt.Errorf("initializing CrowdSec stream: %w", err)
	}

	// 3b. Start LAPI usage metrics reporting (if enabled)
	if m.cfg.CrowdSec.LapiMetricsInterval > 0 {
		apiClient := m.stream.APIClient()
		logrusAdapter := crowdsec.NewLogrusAdapter(m.logger)

		metricsLogger := log.With().Str("component", "lapi-metrics").Logger()
		lapiProvider, err := lapi.NewProvider(apiClient, m.cfg.CrowdSec.LapiMetricsInterval, logrusAdapter, metricsLogger)
		if err != nil {
			m.logger.Warn().Err(err).Msg("failed to initialize LAPI metrics, continuing without metrics reporting")
		} else {
			// Register firewall counter collector so LAPI metrics include
			// dropped bytes/packets from MikroTik firewall rules.
			lapiProvider.SetCounterCollector(func() {
				fc, err := m.ros.GetFirewallCounters(m.commentPrefix() + ":")
				if err != nil {
					m.logger.Debug().Err(err).Msg("failed to collect firewall counters for LAPI metrics")
					return
				}
				// Dropped: only drop/reject rule counters.
				metrics.SetDroppedCounters(fc.DroppedBytes, fc.DroppedPkts)
				metrics.SetDroppedCountersByIPType(
					fc.DroppedIPv4Bytes, fc.DroppedIPv4Pkts,
					fc.DroppedIPv6Bytes, fc.DroppedIPv6Pkts,
				)
				// Processed: total traffic through all bouncer rules.
				metrics.SetProcessedCounters(
					fc.IPv4Bytes, fc.IPv4Pkts,
					fc.IPv6Bytes, fc.IPv6Pkts,
				)
			})

			m.logger.Info().Dur("interval", m.cfg.CrowdSec.LapiMetricsInterval).Msg("LAPI usage metrics reporting enabled")
			go func() {
				if err := lapiProvider.Run(ctx); err != nil {
					m.logger.Warn().Err(err).Msg("LAPI metrics provider stopped")
				}
			}()
		}
	} else {
		m.logger.Info().Msg("LAPI usage metrics reporting disabled")
	}

	// 3c. Start RouterOS system metrics collector (if enabled)
	if m.cfg.Metrics.Enabled && m.cfg.Metrics.RouterOSPollInterval > 0 {
		interval := m.cfg.Metrics.RouterOSPollInterval
		m.logger.Info().Dur("interval", interval).Msg("RouterOS system metrics polling enabled")
		go m.collectSystemMetrics(ctx, interval)
	}

	// 5. Start CrowdSec stream and collect initial batch for reconciliation
	banCh := make(chan *crowdsec.Decision, channelBuffer)
	deleteCh := make(chan *crowdsec.Decision, channelBuffer)

	errCh := make(chan error, 1)
	go func() {
		if err := m.stream.Run(ctx, banCh, deleteCh); err != nil {
			errCh <- err
		}
	}()

	m.logger.Info().Msg("bouncer started, collecting initial decisions for reconciliation")

	// Collect first-poll decisions (CrowdSec sends ALL active decisions on first poll).
	// We use a short idle timeout to detect when the initial batch is complete.
	// Both bans AND deletes are collected to avoid processing stale deletes after reconciliation.
	var initialBans []*crowdsec.Decision
	initialDeletes := make(map[string]struct{}) // addresses to skip (already expired)
	idleTimeout := time.NewTimer(10 * time.Second)
	defer idleTimeout.Stop()

	resetIdleTimer := func() {
		if !idleTimeout.Stop() {
			select {
			case <-idleTimeout.C:
			default:
			}
		}
		idleTimeout.Reset(3 * time.Second)
	}

collectLoop:
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			return fmt.Errorf("CrowdSec stream error: %w", err)
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

	m.logger.Info().
		Int("bans", len(initialBans)).
		Int("deletes", len(initialDeletes)).
		Msg("initial decisions collected, starting reconciliation")

	// 6. Reconcile: compare CrowdSec state with router state
	// Filter out bans that are immediately followed by deletes (expired decisions)
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

	m.reconcileAddresses(filteredBans)

	m.logger.Info().Msg("reconciliation complete, processing live decisions")

	// 7. Process live decision events (deltas)
	for {
		select {
		case <-ctx.Done():
			m.logger.Info().Msg("shutting down manager")
			return nil

		case err := <-errCh:
			return fmt.Errorf("CrowdSec stream error: %w", err)

		case d := <-banCh:
			m.handleBan(d)

		case d := <-deleteCh:
			m.handleUnban(d)
		}
	}
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

	timeout := ""
	if d.Duration > 0 {
		timeout = rosClient.DurationToMikroTik(d.Duration)
	}

	comment := buildAddressComment(m.commentPrefix(), d)

	// Optimistic add: try to add directly (fast ~20ms).
	// If the address already exists, RouterOS returns an error containing
	// "already have" — in that case, find and update the timeout.
	_, err := m.ros.AddAddress(d.Proto, listName, d.Value, timeout, comment)
	if err != nil {
		if strings.Contains(err.Error(), "already have") {
			// Address exists — update timeout if needed
			if timeout != "" {
				existing, findErr := m.ros.FindAddress(d.Proto, listName, d.Value)
				if findErr != nil {
					m.logger.Error().Err(findErr).Str("address", d.Value).Msg("error finding existing address for timeout update")
					metrics.RecordError("find")
					return
				}
				if existing != nil {
					if updErr := m.ros.UpdateAddressTimeout(d.Proto, existing.ID, timeout); updErr != nil {
						m.logger.Error().Err(updErr).Str("address", d.Value).Msg("error updating address timeout")
						metrics.RecordError("add")
					} else {
						m.logger.Debug().Str("address", d.Value).Str("timeout", timeout).Msg("updated existing address timeout")
					}
				}
			}
			return
		}
		m.logger.Error().Err(err).Str("address", d.Value).Str("list", listName).Msg("error adding address to MikroTik")
		metrics.RecordError("add")
		return
	}

	// Update address cache
	addr := rosClient.NormalizeAddress(d.Value, d.Proto)
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
	if err != nil {
		m.logger.Error().Err(err).
			Str("address", d.Value).
			Msg("error finding address for unban")
		metrics.RecordError("find")
		return
	}

	if entry == nil {
		// Remove from cache — it expired on MikroTik
		m.cacheMu.Lock()
		delete(m.addressCache, addr)
		m.cacheMu.Unlock()

		m.logger.Debug().
			Str("address", d.Value).
			Msg("address not found in MikroTik (already expired?)")
		return
	}

	// Remove the address
	if err := m.ros.RemoveAddress(d.Proto, entry.ID); err != nil {
		m.logger.Error().Err(err).
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

// cleanupStaleRules removes firewall rules and address list entries left
// from a previous run. It searches for the fixed ruleSignature embedded in
// every bouncer-created comment, which reliably identifies all bouncer
// resources regardless of the configured comment_prefix. This handles:
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
				if err := m.ros.RemoveFirewallRule(proto, mode, r.ID); err != nil {
					m.logger.Warn().Err(err).
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

	protos := m.enabledProtos()

	for _, proto := range protos {
		listName := m.getAddressListName(proto)

		// Filter rules
		if m.cfg.Firewall.Filter.Enabled {
			for _, chain := range m.cfg.Firewall.Filter.Chains {
				// Whitelist accept rule (before drop/reject rule)
				if m.cfg.Firewall.BlockInput.Whitelist != "" {
					wlComment := buildRuleComment(m.commentPrefix(), "filter", chain, "whitelist", proto)
					wlRule := rosClient.FirewallRule{
						Chain:          chain,
						Action:         "accept",
						SrcAddressList: m.cfg.Firewall.BlockInput.Whitelist,
						Comment:        wlComment,
						Log:            m.cfg.Firewall.Log,
						LogPrefix:      m.resolveLogPrefix("filter"),
					}
					m.applyInputRuleOptions(&wlRule)
					if m.cfg.Firewall.Filter.ConnectionState != "" {
						wlRule.ConnectionState = m.cfg.Firewall.Filter.ConnectionState
					}
					if err := m.ensureFirewallRule(proto, "filter", wlRule); err != nil {
						return err
					}
				}

				// Input rule (src-address-list = drop/reject)
				comment := buildRuleComment(m.commentPrefix(), "filter", chain, "input", proto)
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
				if m.cfg.Firewall.DenyAction == "reject" && m.cfg.Firewall.RejectWith != "" {
					rule.RejectWith = m.cfg.Firewall.RejectWith
				}
				m.applyInputRuleOptions(&rule)

				if err := m.ensureFirewallRule(proto, "filter", rule); err != nil {
					return err
				}

				// Output rule (dst-address-list) — only if block_output enabled
				if m.cfg.Firewall.BlockOutput.Enabled {
					outComment := buildRuleComment(m.commentPrefix(), "filter", "output", "output", proto)
					outRule := rosClient.FirewallRule{
						Chain:          "output",
						Action:         m.cfg.Firewall.DenyAction,
						DstAddressList: listName,
						Comment:        outComment,
						Log:            m.cfg.Firewall.Log,
						LogPrefix:      m.resolveLogPrefix("output"),
					}
					if m.cfg.Firewall.DenyAction == "reject" && m.cfg.Firewall.RejectWith != "" {
						outRule.RejectWith = m.cfg.Firewall.RejectWith
					}
					// Passthrough: list negation takes precedence over single IP
					if proto == "ip" {
						if m.cfg.Firewall.BlockOutput.PassthroughV4List != "" {
							outRule.SrcAddressList = "!" + m.cfg.Firewall.BlockOutput.PassthroughV4List
						} else if m.cfg.Firewall.BlockOutput.PassthroughV4 != "" {
							outRule.SrcAddress = "!" + m.cfg.Firewall.BlockOutput.PassthroughV4
						}
					} else {
						if m.cfg.Firewall.BlockOutput.PassthroughV6List != "" {
							outRule.SrcAddressList = "!" + m.cfg.Firewall.BlockOutput.PassthroughV6List
						} else if m.cfg.Firewall.BlockOutput.PassthroughV6 != "" {
							outRule.SrcAddress = "!" + m.cfg.Firewall.BlockOutput.PassthroughV6
						}
					}
					if m.cfg.Firewall.BlockOutput.Interface != "" {
						outRule.OutInterface = m.cfg.Firewall.BlockOutput.Interface
					}
					if m.cfg.Firewall.BlockOutput.InterfaceList != "" {
						outRule.OutInterfaceList = m.cfg.Firewall.BlockOutput.InterfaceList
					}
					if m.cfg.Firewall.RulePlacement == "top" {
						outRule.PlaceBefore = "0"
					}

					if err := m.ensureFirewallRule(proto, "filter", outRule); err != nil {
						return err
					}
				}
			}
		}

		// Raw rules
		if m.cfg.Firewall.Raw.Enabled {
			for _, chain := range m.cfg.Firewall.Raw.Chains {
				// Whitelist accept rule (before drop rule)
				if m.cfg.Firewall.BlockInput.Whitelist != "" {
					wlComment := buildRuleComment(m.commentPrefix(), "raw", chain, "whitelist", proto)
					wlRule := rosClient.FirewallRule{
						Chain:          chain,
						Action:         "accept",
						SrcAddressList: m.cfg.Firewall.BlockInput.Whitelist,
						Comment:        wlComment,
						Log:            m.cfg.Firewall.Log,
						LogPrefix:      m.resolveLogPrefix("raw"),
					}
					m.applyInputRuleOptions(&wlRule)
					if err := m.ensureFirewallRule(proto, "raw", wlRule); err != nil {
						return err
					}
				}

				comment := buildRuleComment(m.commentPrefix(), "raw", chain, "input", proto)

				// Raw table does NOT support action=reject or reject-with in RouterOS;
				// force "drop" regardless of the configured deny_action.
				rawAction := m.cfg.Firewall.DenyAction
				if rawAction == "reject" {
					rawAction = "drop"
				}

				rule := rosClient.FirewallRule{
					Chain:          chain,
					Action:         rawAction,
					SrcAddressList: listName,
					Comment:        comment,
					Log:            m.cfg.Firewall.Log,
					LogPrefix:      m.resolveLogPrefix("raw"),
				}
				// Raw does NOT support connection-state or reject-with
				m.applyInputRuleOptions(&rule)

				if err := m.ensureFirewallRule(proto, "raw", rule); err != nil {
					return err
				}
			}
		}
	}

	m.logger.Info().
		Int("rules_created", len(m.ruleIDs)).
		Msg("firewall rules ready")

	return nil
}

// applyInputRuleOptions sets InInterface, InInterfaceList and PlaceBefore on
// a firewall rule based on the current BlockInput and RulePlacement config.
func (m *Manager) applyInputRuleOptions(rule *rosClient.FirewallRule) {
	if m.cfg.Firewall.BlockInput.Interface != "" {
		rule.InInterface = m.cfg.Firewall.BlockInput.Interface
	}
	if m.cfg.Firewall.BlockInput.InterfaceList != "" {
		rule.InInterfaceList = m.cfg.Firewall.BlockInput.InterfaceList
	}
	if m.cfg.Firewall.RulePlacement == "top" {
		rule.PlaceBefore = "0"
	}
}

// ensureFirewallRule creates a firewall rule if it doesn't already exist.
func (m *Manager) ensureFirewallRule(proto, mode string, rule rosClient.FirewallRule) error {
	// Check if rule already exists
	existing, err := m.ros.FindFirewallRuleByComment(proto, mode, rule.Comment)
	if err != nil {
		metrics.RecordError("firewall")
		return fmt.Errorf("checking existing rule %q: %w", rule.Comment, err)
	}

	if existing != nil {
		m.logger.Debug().
			Str("comment", rule.Comment).
			Str("id", existing.ID).
			Msg("firewall rule already exists")
		m.ruleMu.Lock()
		m.ruleIDs[rule.Comment] = existing.ID
		m.ruleMu.Unlock()
		return nil
	}

	id, err := m.ros.AddFirewallRule(proto, mode, rule)
	if err != nil {
		metrics.RecordError("firewall")
		return fmt.Errorf("creating firewall rule %q: %w", rule.Comment, err)
	}

	m.ruleMu.Lock()
	m.ruleIDs[rule.Comment] = id
	m.ruleMu.Unlock()

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
func (m *Manager) reconcileAddresses(decisions []*crowdsec.Decision) {
	m.logger.Info().Int("decisions", len(decisions)).Msg("reconciling addresses with MikroTik")

	start := time.Now()

	// Accumulate per-origin counts across all protocols.
	globalOriginCounts := map[string]int64{}

	for _, proto := range m.enabledProtos() {
		listName := m.getAddressListName(proto)

		metricsProto := "ipv4"
		if proto == "ipv6" {
			metricsProto = "ipv6"
		}

		// Get current addresses in MikroTik
		existing, err := m.ros.ListAddresses(proto, listName, m.commentPrefix())
		if err != nil {
			m.logger.Error().Err(err).
				Str("proto", proto).
				Msg("error listing current addresses")
			metrics.RecordError("find")
			continue
		}

		// Build map of addresses that should exist
		shouldExist := make(map[string]*crowdsec.Decision)
		for _, d := range decisions {
			if d.Proto == proto {
				addr := rosClient.NormalizeAddress(d.Value, proto)
				shouldExist[addr] = d
			}
		}

		// Build map of addresses that currently exist
		currentMap := make(map[string]rosClient.AddressEntry)
		for _, e := range existing {
			currentMap[e.Address] = e
		}

		// Populate address cache with current router state
		m.cacheMu.Lock()
		for addr := range currentMap {
			m.addressCache[addr] = struct{}{}
		}
		m.cacheMu.Unlock()

		// Collect addresses to add
		var toAdd []rosClient.BulkEntry
		for addr, d := range shouldExist {
			if _, exists := currentMap[addr]; !exists {
				timeout := ""
				if d.Duration > 0 {
					timeout = rosClient.DurationToMikroTik(d.Duration)
				}
				toAdd = append(toAdd, rosClient.BulkEntry{
					Address: d.Value,
					Timeout: timeout,
					Comment: buildAddressComment(m.commentPrefix(), d),
				})
			}
		}

		// Collect addresses to remove
		var toRemove []rosClient.AddressEntry
		for addr, entry := range currentMap {
			if _, ok := shouldExist[addr]; !ok {
				toRemove = append(toRemove, entry)
			}
		}

		// === BULK ADD via script (fastest) ===
		added := 0
		if len(toAdd) > 0 {
			addStart := time.Now()

			n, addErr := m.ros.BulkAddAddresses(proto, listName, toAdd)
			if addErr != nil {
				m.logger.Warn().Err(addErr).Msg("some addresses failed to add during reconciliation")
			}
			added = n

			// Update cache with newly added addresses
			m.cacheMu.Lock()
			for _, e := range toAdd {
				addr := rosClient.NormalizeAddress(e.Address, proto)
				m.addressCache[addr] = struct{}{}
			}
			m.cacheMu.Unlock()

			for i := 0; i < added; i++ {
				metrics.RecordDecision("ban", metricsProto, "reconcile")
			}
			metrics.ObserveOperationDuration("bulk_add", time.Since(addStart))

			m.logger.Info().
				Int("added", added).
				Dur("elapsed", time.Since(addStart)).
				Msg("bulk add complete")
		}

		// === PARALLEL REMOVE via pool ===
		removed := 0
		if len(toRemove) > 0 {
			removeStart := time.Now()

			if m.pool != nil {
				// Use connection pool for parallel removes
				errs := rosClient.ParallelExec(m.pool, toRemove, func(c *rosClient.Client, entry rosClient.AddressEntry) error {
					return c.RemoveAddress(proto, entry.ID)
				})
				removed = len(toRemove) - len(errs)
				for _, e := range errs {
					if !strings.Contains(e.Error(), "no such item") {
						m.logger.Error().Err(e).Msg("reconcile: error removing address")
						metrics.RecordError("remove")
					} else {
						removed++ // expired items count as removed
					}
				}
			} else {
				// Fallback to sequential
				for _, entry := range toRemove {
					err := m.ros.RemoveAddress(proto, entry.ID)
					switch {
					case err == nil:
						removed++
					case strings.Contains(err.Error(), "no such item"):
						removed++ // expired items count as removed
					default:
						m.logger.Error().Err(err).Str("address", entry.Address).Msg("reconcile: error removing address")
						metrics.RecordError("remove")
					}
				}
			}

			// Update cache
			m.cacheMu.Lock()
			for _, entry := range toRemove {
				delete(m.addressCache, entry.Address)
			}
			m.cacheMu.Unlock()

			for i := 0; i < removed; i++ {
				metrics.RecordDecision("unban", metricsProto, "reconcile")
			}
			metrics.ObserveOperationDuration("bulk_remove", time.Since(removeStart))

			m.logger.Info().
				Int("removed", removed).
				Dur("elapsed", time.Since(removeStart)).
				Msg("bulk remove complete")
		}

		unchanged := len(shouldExist) - added
		if unchanged < 0 {
			unchanged = 0
		}

		metrics.RecordReconciliation("added", added)
		metrics.RecordReconciliation("removed", removed)
		metrics.RecordReconciliation("unchanged", unchanged)
		metrics.SetActiveDecisions(metricsProto, len(shouldExist))

		// Accumulate per-origin counts (set metrics after all protos).
		for _, d := range shouldExist {
			origin := d.Origin
			if origin == "" {
				origin = "unknown"
			}
			globalOriginCounts[origin]++
		}

		m.logger.Info().
			Str("proto", proto).
			Int("existing", len(existing)).
			Int("expected", len(shouldExist)).
			Int("added", added).
			Int("removed", removed).
			Dur("elapsed", time.Since(start)).
			Msg("address reconciliation complete")
	}

	metrics.ObserveOperationDuration("reconcile", time.Since(start))

	// Set per-origin metrics after all protos are processed.
	for origin, count := range globalOriginCounts {
		metrics.SetActiveDecisionsByOrigin(origin, count)
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
