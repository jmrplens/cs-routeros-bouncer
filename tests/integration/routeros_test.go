//go:build integration

package integration

import (
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

func TestRouterOSIntegration(t *testing.T) {
	mikrotikCfg := loadTestConfig(t)

	client := routeros.NewClient(mikrotikCfg)

	// --- Step a: Connect ---
	t.Run("Connect", func(t *testing.T) {
		if err := client.Connect(); err != nil {
			t.Fatalf("failed to connect to RouterOS: %v", err)
		}
		t.Cleanup(func() { client.Close() })
	})

	listName := fmt.Sprintf("cs-test-%d", time.Now().UnixNano())
	comment := fmt.Sprintf("cs-integration-test-%d", time.Now().UnixNano())

	// --- Step b: Create firewall rules ---
	type fwRule struct {
		table string
		proto string
		id    string
	}
	var rules []fwRule

	t.Run("CreateFirewallRules", func(t *testing.T) {
		for _, table := range []string{"filter", "raw"} {
			for _, proto := range []string{"ipv4", "ipv6"} {
				rule := routeros.FirewallRule{
					Chain:          "forward",
					Action:         "drop",
					SrcAddressList: listName,
					Comment:        comment,
				}
				start := time.Now()
				id, err := client.AddFirewallRule(proto, table, rule)
				elapsed := time.Since(start)
				if err != nil {
					t.Fatalf("failed to add %s/%s firewall rule: %v", proto, table, err)
				}
				t.Logf("added %s/%s firewall rule %s in %v", proto, table, id, elapsed)
				rules = append(rules, fwRule{table: table, proto: proto, id: id})
			}
		}
	})

	// --- Step c: Add IPv4 addresses ---
	var ipv4IDs []string
	t.Run("AddIPv4Addresses", func(t *testing.T) {
		addrs := []string{"192.0.2.1", "192.0.2.2", "198.51.100.1"}
		for _, addr := range addrs {
			start := time.Now()
			id, err := client.AddAddress("ipv4", listName, addr, "1h", comment)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("failed to add IPv4 address %s: %v", addr, err)
			}
			t.Logf("added IPv4 %s (id=%s) in %v", addr, id, elapsed)
			ipv4IDs = append(ipv4IDs, id)
		}
	})

	// --- Step d: Add IPv6 addresses ---
	var ipv6IDs []string
	t.Run("AddIPv6Addresses", func(t *testing.T) {
		addrs := []string{"2001:db8::1", "2001:db8::2"}
		for _, addr := range addrs {
			start := time.Now()
			id, err := client.AddAddress("ipv6", listName, addr, "1h", comment)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("failed to add IPv6 address %s: %v", addr, err)
			}
			t.Logf("added IPv6 %s (id=%s) in %v", addr, id, elapsed)
			ipv6IDs = append(ipv6IDs, id)
		}
	})

	// --- Step e: Verify addresses exist ---
	t.Run("VerifyAddressesExist", func(t *testing.T) {
		start := time.Now()
		entries, err := client.ListAddresses("ipv4", listName, comment)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("failed to list IPv4 addresses: %v", err)
		}
		t.Logf("listed %d IPv4 addresses in %v", len(entries), elapsed)
		if len(entries) != 3 {
			t.Errorf("expected 3 IPv4 addresses, got %d", len(entries))
		}

		start = time.Now()
		entries, err = client.ListAddresses("ipv6", listName, comment)
		elapsed = time.Since(start)
		if err != nil {
			t.Fatalf("failed to list IPv6 addresses: %v", err)
		}
		t.Logf("listed %d IPv6 addresses in %v", len(entries), elapsed)
		if len(entries) != 2 {
			t.Errorf("expected 2 IPv6 addresses, got %d", len(entries))
		}
	})

	// --- Step f: Remove individual addresses ---
	t.Run("RemoveAddresses", func(t *testing.T) {
		for _, id := range ipv4IDs {
			start := time.Now()
			if err := client.RemoveAddress("ipv4", id); err != nil {
				t.Fatalf("failed to remove IPv4 address %s: %v", id, err)
			}
			t.Logf("removed IPv4 id=%s in %v", id, time.Since(start))
		}
		for _, id := range ipv6IDs {
			start := time.Now()
			if err := client.RemoveAddress("ipv6", id); err != nil {
				t.Fatalf("failed to remove IPv6 address %s: %v", id, err)
			}
			t.Logf("removed IPv6 id=%s in %v", id, time.Since(start))
		}
	})

	// --- Step g: Verify removal ---
	t.Run("VerifyAddressesRemoved", func(t *testing.T) {
		entries, err := client.ListAddresses("ipv4", listName, comment)
		if err != nil {
			t.Fatalf("failed to list IPv4 addresses: %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("expected 0 IPv4 addresses after removal, got %d", len(entries))
		}

		entries, err = client.ListAddresses("ipv6", listName, comment)
		if err != nil {
			t.Fatalf("failed to list IPv6 addresses: %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("expected 0 IPv6 addresses after removal, got %d", len(entries))
		}
	})

	// --- Step h: Remove firewall rules ---
	t.Run("RemoveFirewallRules", func(t *testing.T) {
		for _, r := range rules {
			start := time.Now()
			if err := client.RemoveFirewallRule(r.proto, r.table, r.id); err != nil {
				t.Fatalf("failed to remove %s/%s firewall rule %s: %v", r.proto, r.table, r.id, err)
			}
			t.Logf("removed %s/%s rule %s in %v", r.proto, r.table, r.id, time.Since(start))
		}
	})

	// --- Step i: Verify rules removed ---
	t.Run("VerifyFirewallRulesRemoved", func(t *testing.T) {
		for _, r := range rules {
			entry, err := client.FindFirewallRuleByComment(r.proto, r.table, comment)
			if err == nil && entry != nil {
				t.Errorf("expected %s/%s firewall rule with comment %q to be removed, but found id=%s", r.proto, r.table, comment, entry.ID)
			}
		}
	})
}
