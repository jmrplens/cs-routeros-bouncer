package routeros

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
)

// RuleEntry represents a MikroTik firewall rule.
type RuleEntry struct {
	ID               string
	Chain            string
	Action           string
	SrcAddressList   string
	DstAddressList   string
	InInterface      string
	InInterfaceList  string
	OutInterface     string
	OutInterfaceList string
	Comment          string
}

// FirewallRule defines a firewall rule to be created.
type FirewallRule struct {
	Chain            string
	Action           string
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

	// Add the rule (appended to end by default)
	id, err := c.Add(path, attrs)
	if err != nil {
		return "", fmt.Errorf("add %s/%s rule: %w", proto, mode, err)
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

	// Move our rule before the first rule using internal IDs
	moveErr := c.moveRule(path, id, firstID)
	if moveErr != nil {
		// If first rule is builtin/dynamic, try moving before second rule
		if strings.Contains(moveErr.Error(), "builtin") && len(allRules) > 1 {
			secondID := allRules[1][".id"]
			moveErr = c.moveRule(path, id, secondID)
			if moveErr != nil {
				log.Warn().Err(moveErr).Msg("failed to move rule to position 1, left at current position")
			} else {
				log.Info().Str("id", id).Msg("firewall rule moved to position 1 (after builtin)")
			}
		} else {
			log.Warn().Err(moveErr).Msg("failed to move rule to top, left at current position")
		}
	} else {
		log.Info().Str("id", id).Msg("firewall rule moved to top")
	}

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

	proplist := []string{".id", "chain", "action", "src-address-list", "dst-address-list",
		"in-interface", "in-interface-list", "out-interface", "out-interface-list", "comment"}

	results, err := c.Print(path, nil, proplist)
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
			SrcAddressList:   r["src-address-list"],
			DstAddressList:   r["dst-address-list"],
			InInterface:      r["in-interface"],
			InInterfaceList:  r["in-interface-list"],
			OutInterface:     r["out-interface"],
			OutInterfaceList: r["out-interface-list"],
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
	proplist := []string{".id", "chain", "action", "src-address-list", "dst-address-list",
		"in-interface", "in-interface-list", "out-interface", "out-interface-list", "comment"}

	result, err := c.Find(path, query, proplist)
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
		SrcAddressList:   result["src-address-list"],
		DstAddressList:   result["dst-address-list"],
		InInterface:      result["in-interface"],
		InInterfaceList:  result["in-interface-list"],
		OutInterface:     result["out-interface"],
		OutInterfaceList: result["out-interface-list"],
		Comment:          result["comment"],
	}, nil
}
