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
	// commentPrefix is the prefix for all MikroTik resources managed by this bouncer.
	commentPrefix = "crowdsec-bouncer"

	// channelBuffer is the buffer size for decision channels.
	channelBuffer = 256
)

// Manager orchestrates the CrowdSec stream and MikroTik firewall operations.
type Manager struct {
	cfg     config.Config
	ros     *rosClient.Client
	stream  *crowdsec.Stream
	logger  zerolog.Logger
	version string

	// Track created firewall rule IDs for cleanup
	ruleIDs map[string]string // comment -> .id
	ruleMu  sync.Mutex
}

// NewManager creates a new bouncer manager.
func NewManager(cfg config.Config, version string) *Manager {
	return &Manager{
		cfg:     cfg,
		ros:     rosClient.NewClient(cfg.MikroTik),
		stream:  crowdsec.NewStream(cfg.CrowdSec, version),
		logger:  log.With().Str("component", "manager").Logger(),
		version: version,
		ruleIDs: make(map[string]string),
	}
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

	identity, err := m.ros.GetIdentity()
	if err != nil {
		m.logger.Warn().Err(err).Msg("could not retrieve RouterOS identity")
		metrics.SetInfo(m.version, "unknown")
	} else {
		m.logger.Info().Str("identity", identity).Msg("connected to RouterOS")
		metrics.SetInfo(m.version, identity)
	}

	// 2. Create firewall rules
	if err := m.createFirewallRules(); err != nil {
		return fmt.Errorf("creating firewall rules: %w", err)
	}

	// 3. Initialize CrowdSec stream
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

	// 4. Start CrowdSec stream and collect initial batch for reconciliation
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
	var initialBans []*crowdsec.Decision
	idleTimeout := time.NewTimer(10 * time.Second)
	defer idleTimeout.Stop()

collectLoop:
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			return fmt.Errorf("CrowdSec stream error: %w", err)
		case d := <-banCh:
			initialBans = append(initialBans, d)
			// Reset idle timer — more decisions coming
			if !idleTimeout.Stop() {
				select {
				case <-idleTimeout.C:
				default:
				}
			}
			idleTimeout.Reset(3 * time.Second)
		case <-idleTimeout.C:
			break collectLoop
		}
	}

	m.logger.Info().Int("decisions", len(initialBans)).Msg("initial decisions collected, starting reconciliation")

	// 5. Reconcile: compare CrowdSec state with router state
	m.reconcileAddresses(initialBans)

	m.logger.Info().Msg("reconciliation complete, processing live decisions")

	// 6. Process live decision events (deltas)
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
	m.ros.Close()
	metrics.SetConnected(false)
	m.logger.Info().Msg("shutdown complete")
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

	comment := buildAddressComment(d)

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

	metrics.RecordDecision("ban", metricsProto, d.Origin)
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

	metrics.RecordDecision("unban", metricsProto, d.Origin)
	metrics.ObserveOperationDuration("remove", time.Since(start))

	m.logger.Info().
		Str("address", d.Value).
		Str("list", listName).
		Msg("unbanned address")
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
				// Input rule (src-address-list)
				comment := buildRuleComment("filter", chain, "input", proto)
				rule := rosClient.FirewallRule{
					Chain:          chain,
					Action:         m.cfg.Firewall.DenyAction,
					SrcAddressList: listName,
					Comment:        comment,
					Log:            m.cfg.Firewall.Log,
					LogPrefix:      m.cfg.Firewall.LogPrefix,
				}
				if m.cfg.Firewall.RulePlacement == "top" {
					rule.PlaceBefore = "0"
				}

				if err := m.ensureFirewallRule(proto, "filter", rule); err != nil {
					return err
				}

				// Output rule (dst-address-list) — only if block_output enabled
				if m.cfg.Firewall.BlockOutput.Enabled {
					outComment := buildRuleComment("filter", "output", "output", proto)
					outRule := rosClient.FirewallRule{
						Chain:          "output",
						Action:         m.cfg.Firewall.DenyAction,
						DstAddressList: listName,
						Comment:        outComment,
						Log:            m.cfg.Firewall.Log,
						LogPrefix:      m.cfg.Firewall.LogPrefix,
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
				comment := buildRuleComment("raw", chain, "input", proto)
				rule := rosClient.FirewallRule{
					Chain:          chain,
					Action:         m.cfg.Firewall.DenyAction,
					SrcAddressList: listName,
					Comment:        comment,
					Log:            m.cfg.Firewall.Log,
					LogPrefix:      m.cfg.Firewall.LogPrefix,
				}
				if m.cfg.Firewall.RulePlacement == "top" {
					rule.PlaceBefore = "0"
				}

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
		proto, mode := parseRuleComment(comment)
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
func (m *Manager) reconcileAddresses(decisions []*crowdsec.Decision) {
	m.logger.Info().Int("decisions", len(decisions)).Msg("reconciling addresses with MikroTik")

	start := time.Now()

	for _, proto := range m.enabledProtos() {
		listName := m.getAddressListName(proto)

		metricsProto := "ipv4"
		if proto == "ipv6" {
			metricsProto = "ipv6"
		}

		// Get current addresses in MikroTik
		existing, err := m.ros.ListAddresses(proto, listName, commentPrefix)
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

		// Add missing addresses
		added := 0
		for addr, d := range shouldExist {
			if _, exists := currentMap[addr]; !exists {
				addStart := time.Now()
				timeout := ""
				if d.Duration > 0 {
					timeout = rosClient.DurationToMikroTik(d.Duration)
				}
				comment := buildAddressComment(d)
				if _, err := m.ros.AddAddress(proto, listName, d.Value, timeout, comment); err != nil {
					m.logger.Error().Err(err).Str("address", d.Value).Msg("reconcile: error adding address")
					metrics.RecordError("add")
				} else {
					added++
					metrics.RecordDecision("ban", metricsProto, d.Origin)
					metrics.ObserveOperationDuration("add", time.Since(addStart))
				}
			}
		}

		// Remove stale addresses
		removed := 0
		for addr, entry := range currentMap {
			if _, shouldExist := shouldExist[addr]; !shouldExist {
				removeStart := time.Now()
				if err := m.ros.RemoveAddress(proto, entry.ID); err != nil {
					// "no such item" means the address expired before we removed it — harmless
					if strings.Contains(err.Error(), "no such item") {
						m.logger.Debug().Str("address", addr).Msg("reconcile: address already expired")
					} else {
						m.logger.Error().Err(err).Str("address", addr).Msg("reconcile: error removing address")
						metrics.RecordError("remove")
					}
				} else {
					removed++
					metrics.RecordDecision("unban", metricsProto, "reconcile")
					metrics.ObserveOperationDuration("remove", time.Since(removeStart))
				}
			}
		}

		unchanged := len(shouldExist) - added
		if unchanged < 0 {
			unchanged = 0
		}

		metrics.RecordReconciliation("added", added)
		metrics.RecordReconciliation("removed", removed)
		metrics.RecordReconciliation("unchanged", unchanged)
		metrics.SetActiveDecisions(metricsProto, len(shouldExist))

		m.logger.Info().
			Str("proto", proto).
			Int("existing", len(existing)).
			Int("expected", len(shouldExist)).
			Int("added", added).
			Int("removed", removed).
			Msg("address reconciliation complete")
	}

	metrics.ObserveOperationDuration("reconcile", time.Since(start))
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
// Format: crowdsec-bouncer:<mode>-<chain>-<direction>-<proto>
func buildRuleComment(mode, chain, direction, proto string) string {
	protoSuffix := "v4"
	if proto == "ipv6" {
		protoSuffix = "v6"
	}
	return fmt.Sprintf("%s:%s-%s-%s-%s", commentPrefix, mode, chain, direction, protoSuffix)
}

// parseRuleComment extracts proto and mode from a rule comment.
func parseRuleComment(comment string) (proto, mode string) {
	// Format: crowdsec-bouncer:<mode>-<chain>-<direction>-<proto>
	if !strings.HasPrefix(comment, commentPrefix+":") {
		return "", ""
	}
	parts := strings.SplitN(comment[len(commentPrefix)+1:], "-", 2)
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

// buildAddressComment creates a comment for an address list entry.
func buildAddressComment(d *crowdsec.Decision) string {
	parts := []string{commentPrefix}
	if d.Origin != "" {
		parts = append(parts, d.Origin)
	}
	if d.Scenario != "" {
		parts = append(parts, d.Scenario)
	}
	parts = append(parts, time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	return strings.Join(parts, "|")
}
