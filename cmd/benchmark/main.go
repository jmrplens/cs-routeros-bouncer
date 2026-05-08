// Command benchmark performs API-level performance measurements against a MikroTik router.
package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
	rosClient "github.com/jmrplens/cs-routeros-bouncer/internal/routeros"
)

const (
	benchmarkIPv4Address  = "198.51.100.1" // NOSONAR: RFC 5737 TEST-NET-2 benchmark address.
	benchmarkFindAddress  = "198.51.100.2" // NOSONAR: RFC 5737 TEST-NET-2 benchmark address.
	benchmarkIPv6Address  = "2001:db8::1/128"
	benchmarkIPv4List     = "crowdsec-banned"
	benchmarkIPv6List     = "crowdsec6-banned"
	benchmarkIPv4BatchMax = 254
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.Kitchen})
	cfg, err := loadConfig(configPath())
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	client := rosClient.NewClient(cfg.MikroTik)
	if connectErr := client.Connect(); connectErr != nil {
		log.Fatal().Err(connectErr).Msg("failed to connect")
	}
	defer client.Close()

	runBenchmarks(client)
}

func configPath() string {
	configPath := "config/test.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}
	return configPath
}

func loadConfig(configPath string) (config.Config, error) {
	viper.SetConfigFile(configPath)
	if err := viper.ReadInConfig(); err != nil {
		return config.Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return config.Config{}, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

func runBenchmarks(client *rosClient.Client) {
	identity, err := client.GetIdentity()
	if err != nil {
		log.Warn().Err(err).Msg("failed to read RouterOS identity")
		identity = "unknown"
	}
	fmt.Printf("Connected to: %s\n\n", identity)
	benchmarkSingleOperations(client)
	benchmarkFirewallRules(client)
	benchmarkBatchAdds(client)
	fmt.Println("=== BENCHMARK COMPLETE ===")
}

func benchmarkSingleOperations(client *rosClient.Client) {
	fmt.Println("=== SINGLE OPERATION BENCHMARKS (RouterOS API) ===")

	bench("Add single IPv4", func() error {
		_, err := client.AddAddress("ip", benchmarkIPv4List, benchmarkIPv4Address, "1m", "benchmark-test")
		return err
	})

	bench("Find IPv4 (1 entry)", func() error {
		_, err := client.FindAddress("ip", benchmarkIPv4List, benchmarkIPv4Address)
		return err
	})

	bench("List IPv4 (1 entry)", func() error {
		_, err := client.ListAddresses("ip", benchmarkIPv4List, "")
		return err
	})

	entry, findErr := client.FindAddress("ip", benchmarkIPv4List, benchmarkIPv4Address)
	if findErr != nil && !errors.Is(findErr, rosClient.ErrNotFound) {
		log.Warn().Err(findErr).Msg("failed to find IPv4 entry before removal benchmark")
	}
	if findErr == nil && entry != nil {
		bench("Remove IPv4 by .id", func() error {
			return client.RemoveAddress("ip", entry.ID)
		})
	}

	bench("Add single IPv6", func() error {
		_, err := client.AddAddress("ipv6", benchmarkIPv6List, benchmarkIPv6Address, "1m", "benchmark-test")
		return err
	})

	entry6, findErr := client.FindAddress("ipv6", benchmarkIPv6List, benchmarkIPv6Address)
	if findErr != nil && !errors.Is(findErr, rosClient.ErrNotFound) {
		log.Warn().Err(findErr).Msg("failed to find IPv6 entry before removal benchmark")
	}
	if findErr == nil && entry6 != nil {
		bench("Remove IPv6 by .id", func() error {
			return client.RemoveAddress("ipv6", entry6.ID)
		})
	}
}

func benchmarkFirewallRules(client *rosClient.Client) {
	fmt.Println()
	fmt.Println("=== FIREWALL RULE BENCHMARKS ===")

	benchmarkFirewallRule(client, "ip", "filter", "Create filter rule (v4)", "Remove filter rule (v4)", rosClient.FirewallRule{
		Chain: "input", Action: "drop",
		SrcAddressList: benchmarkIPv4List,
		Comment:        "benchmark-filter-v4",
		PlaceBefore:    "0",
	})

	bench("Find rule by comment", func() error {
		_, err := client.FindFirewallRuleByComment("ip", "filter", "benchmark-filter-v4")
		return err
	})

	benchmarkFirewallRule(client, "ip", "raw", "Create raw rule (v4)", "Remove raw rule (v4)", rosClient.FirewallRule{
		Chain: "prerouting", Action: "drop",
		SrcAddressList: benchmarkIPv4List,
		Comment:        "benchmark-raw-v4",
		PlaceBefore:    "0",
	})

	benchmarkFirewallRule(client, "ipv6", "filter", "Create filter rule (v6)", "Remove filter rule (v6)", rosClient.FirewallRule{
		Chain: "input", Action: "drop",
		SrcAddressList: benchmarkIPv6List,
		Comment:        "benchmark-filter-v6",
	})

	benchmarkFirewallRule(client, "ipv6", "raw", "Create raw rule (v6)", "Remove raw rule (v6)", rosClient.FirewallRule{
		Chain: "prerouting", Action: "drop",
		SrcAddressList: benchmarkIPv6List,
		Comment:        "benchmark-raw-v6",
	})
}

func benchmarkFirewallRule(client *rosClient.Client, proto, mode, createLabel, removeLabel string, rule rosClient.FirewallRule) {
	var ruleID string
	bench(createLabel, func() error {
		id, err := client.AddFirewallRule(proto, mode, rule)
		ruleID = id
		return err
	})
	if ruleID != "" {
		bench(removeLabel, func() error {
			return client.RemoveFirewallRule(proto, mode, ruleID)
		})
	}
}

func benchmarkBatchAdds(client *rosClient.Client) {
	fmt.Println()
	fmt.Println("=== BATCH ADD BENCHMARKS (sequential via API) ===")

	sizes := []int{10, 50, 100, 500}
	for _, n := range sizes {
		benchmarkBatchSize(client, n)
		fmt.Println()
	}
}

func benchmarkBatchSize(client *rosClient.Client, n int) {
	if n > benchmarkIPv4BatchMax {
		fmt.Printf("  %-35s %8s  (max unique TEST-NET-2 addresses=%d)\n", fmt.Sprintf("Add %d IPv4 (sequential)", n), "SKIPPED", benchmarkIPv4BatchMax)
		return
	}

	start := time.Now()
	failureCount := 0
	for i := 1; i <= n; i++ {
		addr := fmt.Sprintf("198.51.100.%d", i)
		if _, err := client.AddAddress("ip", benchmarkIPv4List, addr, "1m", "batch"); err != nil {
			failureCount++
		}
	}
	elapsed := time.Since(start)
	fmt.Printf("  %-35s %8s  (%s/ip, failures=%d)\n", fmt.Sprintf("Add %d IPv4 (sequential)", n), elapsed.Round(time.Millisecond), (elapsed / time.Duration(n)).Round(time.Millisecond), failureCount)

	listStart := time.Now()
	entries, listErr := client.ListAddresses("ip", benchmarkIPv4List, "")
	listElapsed := time.Since(listStart)
	fmt.Printf("  %-35s %8s  (entries=%d)\n", fmt.Sprintf("List %d entries", n), listElapsed.Round(time.Millisecond), len(entries))
	if listErr != nil {
		log.Warn().Err(listErr).Int("target", n).Str("list", benchmarkIPv4List).Msg("failed to list benchmark entries")
	}

	findStart := time.Now()
	_, findErr := client.FindAddress("ip", benchmarkIPv4List, benchmarkFindAddress)
	findElapsed := time.Since(findStart)
	fmt.Printf("  %-35s %8s\n", fmt.Sprintf("Find 1 in %d entries", n), findElapsed.Round(time.Millisecond))
	if findErr != nil && !errors.Is(findErr, rosClient.ErrNotFound) {
		log.Warn().Err(findErr).Int("target", n).Str("list", benchmarkIPv4List).Msg("failed to find benchmark address")
	}

	cleanStart := time.Now()
	cleanupFailures := 0
	var cleanupErr error
	for _, entry := range entries {
		if err := client.RemoveAddress("ip", entry.ID); err != nil {
			cleanupFailures++
			cleanupErr = err
		}
	}
	cleanElapsed := time.Since(cleanStart)
	perEntry := time.Duration(0)
	if len(entries) > 0 {
		perEntry = cleanElapsed / time.Duration(len(entries))
	}
	fmt.Printf("  %-35s %8s  (%s/ip)\n", fmt.Sprintf("Remove %d entries", len(entries)), cleanElapsed.Round(time.Millisecond), perEntry.Round(time.Millisecond))
	if cleanupFailures > 0 {
		log.Warn().Err(cleanupErr).Int("failures", cleanupFailures).Str("list", benchmarkIPv4List).Msg("failed to clean benchmark entries")
	}
}

func bench(label string, fn func() error) {
	start := time.Now()
	err := fn()
	elapsed := time.Since(start)
	status := "OK"
	if err != nil {
		status = fmt.Sprintf("ERR: %v", err)
	}
	fmt.Printf("  %-35s %8s  %s\n", label, elapsed.Round(time.Millisecond), status)
}
