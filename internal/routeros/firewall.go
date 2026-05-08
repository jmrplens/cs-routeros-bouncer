package routeros

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Firewall attribute names used by RouterOS API requests and responses.
const (
	fwAttrSrcAddress       = "src-address"
	fwAttrSrcAddressList   = "src-address-list"
	fwAttrDstAddressList   = "dst-address-list"
	fwAttrInInterface      = "in-interface"
	fwAttrInInterfaceList  = "in-interface-list"
	fwAttrOutInterface     = "out-interface"
	fwAttrOutInterfaceList = "out-interface-list"
	fwAttrConnectionState  = "connection-state"
	fwAttrRejectWith       = "reject-with"
)

// ruleProplist is the standard set of properties requested when querying firewall rules.
var ruleProplist = []string{
	".id", "chain", "action", fwAttrSrcAddress, fwAttrSrcAddressList, fwAttrDstAddressList,
	fwAttrInInterface, fwAttrInInterfaceList, fwAttrOutInterface, fwAttrOutInterfaceList,
	fwAttrConnectionState, fwAttrRejectWith, "comment",
}

// RuleEntry represents a MikroTik firewall rule.
type RuleEntry struct {
	ID               string
	Chain            string
	Action           string
	SrcAddress       string
	SrcAddressList   string
	DstAddressList   string
	InInterface      string
	InInterfaceList  string
	OutInterface     string
	OutInterfaceList string
	ConnectionState  string
	RejectWith       string
	Comment          string
}

// FirewallRule defines a firewall rule to be created.
type FirewallRule struct {
	Chain            string
	Action           string
	SrcAddress       string // negated with ! for passthrough
	SrcAddressList   string
	DstAddressList   string
	InInterface      string
	InInterfaceList  string
	OutInterface     string
	OutInterfaceList string
	Comment          string
	PlaceBefore      string // "0" for top of chain
	Log              bool
	LogPrefix        string
	ConnectionState  string // filter only: e.g. "new" or "new,invalid"
	RejectWith       string // only when action=reject
}

// firewallPath returns the full path for firewall operations.
// mode is "filter" or "raw".
func firewallPath(proto, mode string) string {
	return protoPrefix(proto) + "/firewall/" + mode
}

// AddFirewallRule creates a firewall rule at the specified path.
// Returns the MikroTik .id of the created rule.
//
// When PlaceBefore is "top", the rule is added and then moved to position 0
// using the RouterOS move command with internal IDs, which is more reliable
// than the numeric place-before parameter across different chain types.
func (c *Client) AddFirewallRule(proto, mode string, rule FirewallRule) (string, error) {
	path := firewallPath(proto, mode)
	attrs := firewallRuleAttrs(rule)

	log.Info().
		Str("proto", proto).
		Str("mode", mode).
		Str("chain", rule.Chain).
		Str("action", rule.Action).
		Str("comment", rule.Comment).
		Msg("creating firewall rule")

	wantTop := rule.PlaceBefore == "top" || rule.PlaceBefore == "0"
	wantBefore := !wantTop && rule.PlaceBefore != ""

	// Add the rule (appended to end by default)
	id, err := c.Add(path, attrs)
	if err != nil {
		return "", fmt.Errorf("add %s/%s rule: %w", proto, mode, err)
	}

	// Move before a specific target rule (e.g. counting rule before drop rule)
	if wantBefore {
		moveErr := c.moveRule(path, id, rule.PlaceBefore)
		if moveErr != nil {
			log.Warn().Err(moveErr).Str("id", id).Str("target", rule.PlaceBefore).
				Msg("could not move rule before target, left at current position")
		} else {
			log.Info().Str("id", id).Str("before", rule.PlaceBefore).
				Msg("firewall rule moved before target rule")
		}
		return id, nil
	}

	if !wantTop {
		return id, nil
	}
	return c.moveRuleToTop(path, id)
}

// firewallRuleAttrs converts a FirewallRule into RouterOS API attributes.
func firewallRuleAttrs(rule FirewallRule) map[string]string {
	attrs := map[string]string{
		"chain":   rule.Chain,
		"action":  rule.Action,
		"comment": rule.Comment,
	}
	setIfNotEmpty(attrs, fwAttrSrcAddress, rule.SrcAddress)
	setIfNotEmpty(attrs, fwAttrSrcAddressList, rule.SrcAddressList)
	setIfNotEmpty(attrs, fwAttrDstAddressList, rule.DstAddressList)
	setIfNotEmpty(attrs, fwAttrInInterface, rule.InInterface)
	setIfNotEmpty(attrs, fwAttrInInterfaceList, rule.InInterfaceList)
	setIfNotEmpty(attrs, fwAttrOutInterface, rule.OutInterface)
	setIfNotEmpty(attrs, fwAttrOutInterfaceList, rule.OutInterfaceList)
	setIfNotEmpty(attrs, fwAttrConnectionState, rule.ConnectionState)
	setIfNotEmpty(attrs, fwAttrRejectWith, rule.RejectWith)
	if rule.Log {
		attrs["log"] = "true"
		setIfNotEmpty(attrs, "log-prefix", rule.LogPrefix)
	}
	return attrs
}

// setIfNotEmpty includes a RouterOS API attribute only when it has a value.
func setIfNotEmpty(attrs map[string]string, key, value string) {
	if value != "" {
		attrs[key] = value
	}
}

// moveRuleToTop moves a newly created firewall rule ahead of user-editable rules.
func (c *Client) moveRuleToTop(path, id string) (string, error) {
	// Move the newly created rule to the top of the chain.
	// List all rules to find the current first rule's internal ID.
	allRules, listErr := c.Print(path, nil, []string{".id"})
	if listErr != nil || len(allRules) == 0 {
		log.Warn().Err(listErr).Msg("could not list rules to reorder, rule appended at end")
		return id, nil
	}

	firstID := allRules[0][".id"]
	if firstID == id {
		// Already at position 0
		log.Info().Str("id", id).Msg("firewall rule already at top")
		return id, nil
	}

	// Try each position starting from 0, skipping builtin/dynamic rules
	// that cannot be displaced.
	for i, r := range allRules {
		targetID := r[".id"]
		if targetID == id {
			// Reached our own rule — already as high as possible
			log.Info().Str("id", id).Int("position", i).Msg("firewall rule placed at highest available position")
			return id, nil
		}
		moveErr := c.moveRule(path, id, targetID)
		if moveErr == nil {
			if i == 0 {
				log.Info().Str("id", id).Msg("firewall rule moved to top")
			} else {
				log.Info().Str("id", id).Int("position", i).Msg("firewall rule moved to position (after builtin rules)")
			}
			return id, nil
		}
		log.Debug().Err(moveErr).Int("position", i).Msg("cannot move before this rule, trying next position")
	}

	log.Warn().Str("id", id).Msg("could not move rule to any higher position, left at current position")

	return id, nil
}

// moveRule moves a firewall rule (identified by ruleID) before another rule
// (identified by beforeID) using the RouterOS move command.
func (c *Client) moveRule(path, ruleID, beforeID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureConnected(); err != nil {
		return err
	}

	args := []string{path + "/move", "=numbers=" + ruleID, "=destination=" + beforeID}
	_, err := c.conn.RunArgs(args)
	return err
}

// RemoveFirewallRule removes a firewall rule by its .id.
func (c *Client) RemoveFirewallRule(proto, mode, id string) error {
	path := firewallPath(proto, mode)

	log.Info().
		Str("proto", proto).
		Str("mode", mode).
		Str("id", id).
		Msg("removing firewall rule")

	return c.Remove(path, id)
}

// ListFirewallRules lists all firewall rules matching a comment prefix.
func (c *Client) ListFirewallRules(proto, mode, commentPrefix string) ([]RuleEntry, error) {
	path := firewallPath(proto, mode)

	results, err := c.Print(path, nil, ruleProplist)
	if err != nil {
		return nil, fmt.Errorf("list %s/%s rules: %w", proto, mode, err)
	}

	var entries []RuleEntry
	for _, r := range results {
		comment := r["comment"]
		if commentPrefix != "" && !strings.HasPrefix(comment, commentPrefix) {
			continue
		}
		entries = append(entries, RuleEntry{
			ID:               r[".id"],
			Chain:            r["chain"],
			Action:           r["action"],
			SrcAddress:       r[fwAttrSrcAddress],
			SrcAddressList:   r[fwAttrSrcAddressList],
			DstAddressList:   r[fwAttrDstAddressList],
			InInterface:      r[fwAttrInInterface],
			InInterfaceList:  r[fwAttrInInterfaceList],
			OutInterface:     r[fwAttrOutInterface],
			OutInterfaceList: r[fwAttrOutInterfaceList],
			ConnectionState:  r[fwAttrConnectionState],
			RejectWith:       r[fwAttrRejectWith],
			Comment:          r["comment"],
		})
	}

	return entries, nil
}

// ListFirewallRulesBySignature lists all firewall rules whose comment
// contains the given signature substring. This is used for crash-recovery
// cleanup: the signature is a fixed, non-configurable identifier embedded
// in every comment, so it finds all bouncer rules regardless of prefix.
func (c *Client) ListFirewallRulesBySignature(proto, mode, signature string) ([]RuleEntry, error) {
	path := firewallPath(proto, mode)

	results, err := c.Print(path, nil, ruleProplist)
	if err != nil {
		return nil, fmt.Errorf("list %s/%s rules by signature: %w", proto, mode, err)
	}

	var entries []RuleEntry
	for _, r := range results {
		comment := r["comment"]
		if !strings.Contains(comment, signature) {
			continue
		}
		entries = append(entries, RuleEntry{
			ID:               r[".id"],
			Chain:            r["chain"],
			Action:           r["action"],
			SrcAddress:       r[fwAttrSrcAddress],
			SrcAddressList:   r[fwAttrSrcAddressList],
			DstAddressList:   r[fwAttrDstAddressList],
			InInterface:      r[fwAttrInInterface],
			InInterfaceList:  r[fwAttrInInterfaceList],
			OutInterface:     r[fwAttrOutInterface],
			OutInterfaceList: r[fwAttrOutInterfaceList],
			ConnectionState:  r[fwAttrConnectionState],
			RejectWith:       r[fwAttrRejectWith],
			Comment:          r["comment"],
		})
	}

	return entries, nil
}

// FindFirewallRuleByComment finds a firewall rule by its exact comment.
func (c *Client) FindFirewallRuleByComment(proto, mode, comment string) (*RuleEntry, error) {
	path := firewallPath(proto, mode)

	query := []string{"?comment=" + comment}

	result, err := c.Find(path, query, ruleProplist)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("find %s/%s rule by comment %q: %w", proto, mode, comment, err)
	}

	return &RuleEntry{
		ID:               result[".id"],
		Chain:            result["chain"],
		Action:           result["action"],
		SrcAddress:       result[fwAttrSrcAddress],
		SrcAddressList:   result[fwAttrSrcAddressList],
		DstAddressList:   result[fwAttrDstAddressList],
		InInterface:      result[fwAttrInInterface],
		InInterfaceList:  result[fwAttrInInterfaceList],
		OutInterface:     result[fwAttrOutInterface],
		OutInterfaceList: result[fwAttrOutInterfaceList],
		ConnectionState:  result[fwAttrConnectionState],
		RejectWith:       result[fwAttrRejectWith],
		Comment:          result["comment"],
	}, nil
}

// RuleCounters holds byte and packet counters for a single firewall rule.
type RuleCounters struct {
	Comment string
	Action  string
	Bytes   uint64
	Packets uint64
}

// FirewallCounters aggregates counters from all bouncer firewall rules.
type FirewallCounters struct {
	Rules []RuleCounters

	// Total counters across ALL bouncer rules.
	TotalBytes uint64
	TotalPkts  uint64
	IPv4Bytes  uint64
	IPv4Pkts   uint64
	IPv6Bytes  uint64
	IPv6Pkts   uint64

	// Dropped only: counters from drop/reject rules.
	DroppedBytes     uint64
	DroppedPkts      uint64
	DroppedIPv4Bytes uint64
	DroppedIPv4Pkts  uint64
	DroppedIPv6Bytes uint64
	DroppedIPv6Pkts  uint64

	// Processed: counters from passthrough counting rules.
	// These represent ALL traffic evaluated by the bouncer chains,
	// analogous to iptables JUMP counters used by firewall-bouncer.
	ProcessedIPv4Bytes uint64
	ProcessedIPv4Pkts  uint64
	ProcessedIPv6Bytes uint64
	ProcessedIPv6Pkts  uint64
}

// GetFirewallCounters queries byte/packet counters from all firewall rules
// matching the given comment prefix. It queries filter and raw rules across
// both IPv4 and IPv6 (depending on which protocols the rules cover).
func (c *Client) GetFirewallCounters(commentPrefix string) (*FirewallCounters, error) {
	fc := &FirewallCounters{}
	for _, q := range firewallCounterQueries() {
		results, err := c.Print(q.path, nil, []string{".id", "bytes", "packets", "comment", "action"})
		if err != nil {
			log.Debug().Err(err).Str("path", q.path).Msg("skipping counter query (path may not exist)")
			continue
		}
		fc.addRuleCounters(q.proto, commentPrefix, results, c.logger)
	}
	return fc, nil
}

// firewallCounterQuery describes one RouterOS firewall table to scan for counters.
type firewallCounterQuery struct {
	path  string
	proto string // "ipv4" or "ipv6" for aggregation
}

// firewallCounterQueries returns IPv4/IPv6 filter and raw tables used for aggregation.
func firewallCounterQueries() []firewallCounterQuery {
	return []firewallCounterQuery{
		{protoPrefix("ip") + "/firewall/filter", "ipv4"},
		{protoPrefix("ip") + "/firewall/raw", "ipv4"},
		{protoPrefix("ipv6") + "/firewall/filter", "ipv6"},
		{protoPrefix("ipv6") + "/firewall/raw", "ipv6"},
	}
}

// addRuleCounters folds RouterOS print results into rule and aggregate counters.
func (fc *FirewallCounters) addRuleCounters(proto, commentPrefix string, results []map[string]string, logger zerolog.Logger) {
	for _, result := range results {
		comment := result["comment"]
		if commentPrefix != "" && !strings.HasPrefix(comment, commentPrefix) {
			continue
		}
		bytes, _ := strconv.ParseUint(result["bytes"], 10, 64)
		packets, _ := strconv.ParseUint(result["packets"], 10, 64)
		action := firewallCounterAction(result["action"], comment, logger)

		fc.Rules = append(fc.Rules, RuleCounters{Comment: comment, Action: action, Bytes: bytes, Packets: packets})
		if action == "" {
			continue
		}
		fc.addTotalCounters(proto, bytes, packets)
		if action == "drop" || action == "reject" {
			fc.addDroppedCounters(proto, bytes, packets)
		}
		if action == "passthrough" {
			fc.addProcessedCounters(proto, bytes, packets)
		}
	}
}

// firewallCounterAction validates the action field before aggregate counter updates.
func firewallCounterAction(action, comment string, logger zerolog.Logger) string {
	if action != "" {
		return action
	}
	logger.Warn().Str("comment", comment).Msg("firewall rule has empty action, skipping aggregate counters")
	return ""
}

// addTotalCounters increments total and per-protocol traffic counters.
func (fc *FirewallCounters) addTotalCounters(proto string, bytes, packets uint64) {
	fc.TotalBytes += bytes
	fc.TotalPkts += packets
	if proto == "ipv4" {
		fc.IPv4Bytes += bytes
		fc.IPv4Pkts += packets
		return
	}
	fc.IPv6Bytes += bytes
	fc.IPv6Pkts += packets
}

// addDroppedCounters increments total and per-protocol dropped traffic counters.
func (fc *FirewallCounters) addDroppedCounters(proto string, bytes, packets uint64) {
	fc.DroppedBytes += bytes
	fc.DroppedPkts += packets
	if proto == "ipv4" {
		fc.DroppedIPv4Bytes += bytes
		fc.DroppedIPv4Pkts += packets
		return
	}
	fc.DroppedIPv6Bytes += bytes
	fc.DroppedIPv6Pkts += packets
}

// addProcessedCounters increments per-protocol processed traffic counters.
func (fc *FirewallCounters) addProcessedCounters(proto string, bytes, packets uint64) {
	if proto == "ipv4" {
		fc.ProcessedIPv4Bytes += bytes
		fc.ProcessedIPv4Pkts += packets
		return
	}
	fc.ProcessedIPv6Bytes += bytes
	fc.ProcessedIPv6Pkts += packets
}
