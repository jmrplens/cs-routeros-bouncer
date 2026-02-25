package routeros

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

// ruleProplist is the standard set of properties requested when querying firewall rules.
var ruleProplist = []string{
	".id", "chain", "action", "src-address", "src-address-list", "dst-address-list",
	"in-interface", "in-interface-list", "out-interface", "out-interface-list",
	"connection-state", "reject-with", "comment",
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

	attrs := map[string]string{
		"chain":   rule.Chain,
		"action":  rule.Action,
		"comment": rule.Comment,
	}

	if rule.SrcAddress != "" {
		attrs["src-address"] = rule.SrcAddress
	}
	if rule.SrcAddressList != "" {
		attrs["src-address-list"] = rule.SrcAddressList
	}
	if rule.DstAddressList != "" {
		attrs["dst-address-list"] = rule.DstAddressList
	}
	if rule.InInterface != "" {
		attrs["in-interface"] = rule.InInterface
	}
	if rule.InInterfaceList != "" {
		attrs["in-interface-list"] = rule.InInterfaceList
	}
	if rule.OutInterface != "" {
		attrs["out-interface"] = rule.OutInterface
	}
	if rule.OutInterfaceList != "" {
		attrs["out-interface-list"] = rule.OutInterfaceList
	}
	if rule.ConnectionState != "" {
		attrs["connection-state"] = rule.ConnectionState
	}
	if rule.RejectWith != "" {
		attrs["reject-with"] = rule.RejectWith
	}
	if rule.Log {
		attrs["log"] = "true"
		if rule.LogPrefix != "" {
			attrs["log-prefix"] = rule.LogPrefix
		}
	}

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
			SrcAddress:       r["src-address"],
			SrcAddressList:   r["src-address-list"],
			DstAddressList:   r["dst-address-list"],
			InInterface:      r["in-interface"],
			InInterfaceList:  r["in-interface-list"],
			OutInterface:     r["out-interface"],
			OutInterfaceList: r["out-interface-list"],
			ConnectionState:  r["connection-state"],
			RejectWith:       r["reject-with"],
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
			SrcAddress:       r["src-address"],
			SrcAddressList:   r["src-address-list"],
			DstAddressList:   r["dst-address-list"],
			InInterface:      r["in-interface"],
			InInterfaceList:  r["in-interface-list"],
			OutInterface:     r["out-interface"],
			OutInterfaceList: r["out-interface-list"],
			ConnectionState:  r["connection-state"],
			RejectWith:       r["reject-with"],
			Comment:          r["comment"],
		})
	}

	return entries, nil
}

// FindFirewallRuleByComment finds a firewall rule by its exact comment.
// Returns nil if not found.
func (c *Client) FindFirewallRuleByComment(proto, mode, comment string) (*RuleEntry, error) {
	path := firewallPath(proto, mode)

	query := []string{"?comment=" + comment}

	result, err := c.Find(path, query, ruleProplist)
	if err != nil {
		return nil, fmt.Errorf("find %s/%s rule by comment %q: %w", proto, mode, comment, err)
	}

	if result == nil {
		return nil, nil
	}

	return &RuleEntry{
		ID:               result[".id"],
		Chain:            result["chain"],
		Action:           result["action"],
		SrcAddress:       result["src-address"],
		SrcAddressList:   result["src-address-list"],
		DstAddressList:   result["dst-address-list"],
		InInterface:      result["in-interface"],
		InInterfaceList:  result["in-interface-list"],
		OutInterface:     result["out-interface"],
		OutInterfaceList: result["out-interface-list"],
		ConnectionState:  result["connection-state"],
		RejectWith:       result["reject-with"],
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

	type query struct {
		path  string
		proto string // "ipv4" or "ipv6" for aggregation
	}

	queries := []query{
		{protoPrefix("ip") + "/firewall/filter", "ipv4"},
		{protoPrefix("ip") + "/firewall/raw", "ipv4"},
		{protoPrefix("ipv6") + "/firewall/filter", "ipv6"},
		{protoPrefix("ipv6") + "/firewall/raw", "ipv6"},
	}

	proplist := []string{".id", "bytes", "packets", "comment", "action"}

	for _, q := range queries {
		results, err := c.Print(q.path, nil, proplist)
		if err != nil {
			log.Debug().Err(err).Str("path", q.path).Msg("skipping counter query (path may not exist)")
			continue
		}

		for _, r := range results {
			comment := r["comment"]
			if commentPrefix != "" && !strings.HasPrefix(comment, commentPrefix) {
				continue
			}

			bytes, _ := strconv.ParseUint(r["bytes"], 10, 64)
			packets, _ := strconv.ParseUint(r["packets"], 10, 64)
			action := r["action"]
			if action == "" {
				c.logger.Warn().
					Str("comment", comment).
					Msg("firewall rule has empty action, treating as drop")
				action = "drop"
			}

			fc.Rules = append(fc.Rules, RuleCounters{
				Comment: comment,
				Action:  action,
				Bytes:   bytes,
				Packets: packets,
			})

			// Total across all bouncer rules.
			fc.TotalBytes += bytes
			fc.TotalPkts += packets

			if q.proto == "ipv4" {
				fc.IPv4Bytes += bytes
				fc.IPv4Pkts += packets
			} else {
				fc.IPv6Bytes += bytes
				fc.IPv6Pkts += packets
			}

			// Dropped: only drop/reject rules.
			if action == "drop" || action == "reject" {
				fc.DroppedBytes += bytes
				fc.DroppedPkts += packets

				if q.proto == "ipv4" {
					fc.DroppedIPv4Bytes += bytes
					fc.DroppedIPv4Pkts += packets
				} else {
					fc.DroppedIPv6Bytes += bytes
					fc.DroppedIPv6Pkts += packets
				}
			}

			// Processed: passthrough counting rules measure total chain traffic.
			if action == "passthrough" {
				if q.proto == "ipv4" {
					fc.ProcessedIPv4Bytes += bytes
					fc.ProcessedIPv4Pkts += packets
				} else {
					fc.ProcessedIPv6Bytes += bytes
					fc.ProcessedIPv6Pkts += packets
				}
			}
		}
	}

	return fc, nil
}
