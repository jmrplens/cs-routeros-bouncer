//go:build integration

package integration

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
	"github.com/jmrplens/cs-routeros-bouncer/internal/routeros"
)

// loadTestConfig loads MikroTik config from env vars or config/test.yaml.
func loadTestConfig(t *testing.T) config.MikroTikConfig {
	t.Helper()

	// Try environment variables first.
	addr := os.Getenv("ROUTEROS_ADDRESS")
	user := os.Getenv("ROUTEROS_USERNAME")
	pass := os.Getenv("ROUTEROS_PASSWORD")

	if addr != "" && user != "" && pass != "" {
		return config.MikroTikConfig{
			Address:           addr,
			Username:          user,
			Password:          pass,
			TLS:               os.Getenv("ROUTEROS_TLS") == "true",
			TLSInsecure:       os.Getenv("ROUTEROS_TLS_INSECURE") == "true",
			ConnectionTimeout: 10 * time.Second,
			CommandTimeout:    10 * time.Second,
		}
	}

	// Fall back to config file.
	cfg, err := config.Load("../../config/test.yaml")
	if err != nil {
		t.Skipf("skipping: no env vars and could not load config/test.yaml: %v", err)
	}
	return cfg.MikroTik
}

// integrationFirewallRule tracks RouterOS firewall rules created during a live test.
type integrationFirewallRule struct {
	table string
	proto string
	id    string
}

// TestRouterOSIntegration exercises live address-list and firewall operations.
func TestRouterOSIntegration(t *testing.T) {
	mikrotikCfg := loadTestConfig(t)
	client := createRouterSession(t, mikrotikCfg)

	listName := fmt.Sprintf("cs-test-%d", time.Now().UnixNano())
	comment := fmt.Sprintf("cs-integration-test-%d", time.Now().UnixNano())

	var rules []integrationFirewallRule
	t.Run("CreateFirewallRules", func(t *testing.T) {
		rules = setupFirewallRules(t, client, listName, comment)
	})

	var ipv4IDs []string
	t.Run("AddIPv4Addresses", func(t *testing.T) {
		ipv4IDs = addIntegrationAddresses(t, client, "ipv4", listName, comment, []string{"192.0.2.1", "192.0.2.2", "198.51.100.1"})
	})

	var ipv6IDs []string
	t.Run("AddIPv6Addresses", func(t *testing.T) {
		ipv6IDs = addIntegrationAddresses(t, client, "ipv6", listName, comment, []string{"2001:db8::1", "2001:db8::2"})
	})

	t.Run("VerifyAddressesExist", func(t *testing.T) {
		verifyAddressCount(t, client, "ipv4", listName, comment, 3)
		verifyAddressCount(t, client, "ipv6", listName, comment, 2)
	})

	t.Run("RemoveAddresses", func(t *testing.T) {
		removeIntegrationAddresses(t, client, "ipv4", ipv4IDs)
		removeIntegrationAddresses(t, client, "ipv6", ipv6IDs)
	})

	t.Run("VerifyAddressesRemoved", func(t *testing.T) {
		verifyAddressCount(t, client, "ipv4", listName, comment, 0)
		verifyAddressCount(t, client, "ipv6", listName, comment, 0)
	})

	t.Run("RemoveFirewallRules", func(t *testing.T) {
		cleanupFirewallRules(t, client, rules)
	})

	t.Run("VerifyFirewallRulesRemoved", func(t *testing.T) {
		verifyFirewallRulesRemoved(t, client, rules, comment)
	})
}

// createRouterSession opens a RouterOS client and registers cleanup for it.
func createRouterSession(t testing.TB, cfg config.MikroTikConfig) *routeros.Client {
	t.Helper()
	client := routeros.NewClient(cfg)
	if err := client.Connect(); err != nil {
		t.Fatalf("failed to connect to RouterOS: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// setupFirewallRules creates filter/raw IPv4 and IPv6 rules for the integration list.
func setupFirewallRules(t testing.TB, client *routeros.Client, listName, comment string) []integrationFirewallRule {
	t.Helper()
	rules := make([]integrationFirewallRule, 0, 4)
	for _, table := range []string{"filter", "raw"} {
		for _, proto := range []string{"ipv4", "ipv6"} {
			rule := routeros.FirewallRule{Chain: "forward", Action: "drop", SrcAddressList: listName, Comment: comment}
			start := time.Now()
			id, err := client.AddFirewallRule(proto, table, rule)
			if err != nil {
				t.Fatalf("failed to add %s/%s firewall rule: %v", proto, table, err)
			}
			t.Logf("added %s/%s firewall rule %s in %v", proto, table, id, time.Since(start))
			rules = append(rules, integrationFirewallRule{table: table, proto: proto, id: id})
		}
	}
	return rules
}

// cleanupFirewallRules removes the rules created by setupFirewallRules.
func cleanupFirewallRules(t testing.TB, client *routeros.Client, rules []integrationFirewallRule) {
	t.Helper()
	for _, rule := range rules {
		start := time.Now()
		if err := client.RemoveFirewallRule(rule.proto, rule.table, rule.id); err != nil {
			t.Fatalf("failed to remove %s/%s firewall rule %s: %v", rule.proto, rule.table, rule.id, err)
		}
		t.Logf("removed %s/%s rule %s in %v", rule.proto, rule.table, rule.id, time.Since(start))
	}
}

// addIntegrationAddresses adds test addresses and returns their RouterOS IDs.
func addIntegrationAddresses(t testing.TB, client *routeros.Client, proto, listName, comment string, addrs []string) []string {
	t.Helper()
	ids := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		start := time.Now()
		id, err := client.AddAddress(proto, listName, addr, "1h", comment)
		if err != nil {
			t.Fatalf("failed to add %s address %s: %v", proto, addr, err)
		}
		t.Logf("added %s %s (id=%s) in %v", proto, addr, id, time.Since(start))
		ids = append(ids, id)
	}
	return ids
}

// removeIntegrationAddresses removes RouterOS address-list entries by ID.
func removeIntegrationAddresses(t testing.TB, client *routeros.Client, proto string, ids []string) {
	t.Helper()
	for _, id := range ids {
		start := time.Now()
		if err := client.RemoveAddress(proto, id); err != nil {
			t.Fatalf("failed to remove %s address %s: %v", proto, id, err)
		}
		t.Logf("removed %s id=%s in %v", proto, id, time.Since(start))
	}
}

// verifyAddressCount checks that the integration list contains the expected entries.
func verifyAddressCount(t testing.TB, client *routeros.Client, proto, listName, comment string, want int) {
	t.Helper()
	start := time.Now()
	entries, err := client.ListAddresses(proto, listName, comment)
	if err != nil {
		t.Fatalf("failed to list %s addresses: %v", proto, err)
	}
	t.Logf("listed %d %s addresses in %v", len(entries), proto, time.Since(start))
	if len(entries) != want {
		t.Errorf("expected %d %s addresses, got %d", want, proto, len(entries))
	}
}

// verifyFirewallRulesRemoved ensures the integration firewall rules are no longer present.
func verifyFirewallRulesRemoved(t testing.TB, client *routeros.Client, rules []integrationFirewallRule, comment string) {
	t.Helper()
	for _, rule := range rules {
		entry, err := client.FindFirewallRuleByComment(rule.proto, rule.table, comment)
		if err == nil {
			t.Errorf("expected ErrNotFound for removed %s/%s firewall rule with comment %q, got nil error", rule.proto, rule.table, comment)
			continue
		}
		if !errors.Is(err, routeros.ErrNotFound) {
			t.Errorf("failed to verify %s/%s firewall rule removal: %v", rule.proto, rule.table, err)
		}
		if errors.Is(err, routeros.ErrNotFound) && entry != nil {
			t.Errorf("inconsistent %s/%s firewall rule removal result: ErrNotFound with non-nil entry id=%s", rule.proto, rule.table, entry.ID)
		}
	}
}
