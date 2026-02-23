// Command benchmark performs API-level performance measurements against a MikroTik router.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
	rosClient "github.com/jmrplens/cs-routeros-bouncer/internal/routeros"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.Kitchen})

	configPath := "config/test.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	viper.SetConfigFile(configPath)
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal().Err(err).Msg("failed to read config")
	}
	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatal().Err(err).Msg("failed to parse config")
	}

	client := rosClient.NewClient(cfg.MikroTik)
	if err := client.Connect(); err != nil {
		log.Fatal().Err(err).Msg("failed to connect")
	}
	defer client.Close()

	identity, _ := client.GetIdentity()
	fmt.Printf("Connected to: %s\n\n", identity)

	fmt.Println("=== SINGLE OPERATION BENCHMARKS (RouterOS API) ===")

	bench("Add single IPv4", func() error {
		_, err := client.AddAddress("ip", "crowdsec-banned", "198.51.100.1", "1m", "benchmark-test")
		return err
	})

	bench("Find IPv4 (1 entry)", func() error {
		_, err := client.FindAddress("ip", "crowdsec-banned", "198.51.100.1")
		return err
	})

	bench("List IPv4 (1 entry)", func() error {
		_, err := client.ListAddresses("ip", "crowdsec-banned", "")
		return err
	})

	entry, _ := client.FindAddress("ip", "crowdsec-banned", "198.51.100.1")
	if entry != nil {
		bench("Remove IPv4 by .id", func() error {
			return client.RemoveAddress("ip", entry.ID)
		})
	}

	bench("Add single IPv6", func() error {
		_, err := client.AddAddress("ipv6", "crowdsec6-banned", "2001:db8::1", "1m", "benchmark-test")
		return err
	})

	entry6, _ := client.FindAddress("ipv6", "crowdsec6-banned", "2001:db8::1/128")
	if entry6 != nil {
		bench("Remove IPv6 by .id", func() error {
			return client.RemoveAddress("ipv6", entry6.ID)
		})
	}

	fmt.Println()
	fmt.Println("=== FIREWALL RULE BENCHMARKS ===")

	var ruleID string
	bench("Create filter rule (v4)", func() error {
		id, err := client.AddFirewallRule("ip", "filter", rosClient.FirewallRule{
			Chain: "input", Action: "drop",
			SrcAddressList: "crowdsec-banned",
			Comment:        "benchmark-filter-v4",
			PlaceBefore:    "0",
		})
		ruleID = id
		return err
	})

	bench("Find rule by comment", func() error {
		_, err := client.FindFirewallRuleByComment("ip", "filter", "benchmark-filter-v4")
		return err
	})

	if ruleID != "" {
		bench("Remove filter rule (v4)", func() error {
			return client.RemoveFirewallRule("ip", "filter", ruleID)
		})
	}

	bench("Create raw rule (v4)", func() error {
		id, err := client.AddFirewallRule("ip", "raw", rosClient.FirewallRule{
			Chain: "prerouting", Action: "drop",
			SrcAddressList: "crowdsec-banned",
			Comment:        "benchmark-raw-v4",
			PlaceBefore:    "0",
		})
		ruleID = id
		return err
	})
	if ruleID != "" {
		bench("Remove raw rule (v4)", func() error {
			return client.RemoveFirewallRule("ip", "raw", ruleID)
		})
	}

	bench("Create filter rule (v6)", func() error {
		id, err := client.AddFirewallRule("ipv6", "filter", rosClient.FirewallRule{
			Chain: "input", Action: "drop",
			SrcAddressList: "crowdsec6-banned",
			Comment:        "benchmark-filter-v6",
		})
		ruleID = id
		return err
	})
	if ruleID != "" {
		bench("Remove filter rule (v6)", func() error {
			return client.RemoveFirewallRule("ipv6", "filter", ruleID)
		})
	}

	bench("Create raw rule (v6)", func() error {
		id, err := client.AddFirewallRule("ipv6", "raw", rosClient.FirewallRule{
			Chain: "prerouting", Action: "drop",
			SrcAddressList: "crowdsec6-banned",
			Comment:        "benchmark-raw-v6",
		})
		ruleID = id
		return err
	})
	if ruleID != "" {
		bench("Remove raw rule (v6)", func() error {
			return client.RemoveFirewallRule("ipv6", "raw", ruleID)
		})
	}

	fmt.Println()
	fmt.Println("=== BATCH ADD BENCHMARKS (sequential via API) ===")

	sizes := []int{10, 50, 100, 500}
	for _, n := range sizes {
		label := fmt.Sprintf("Add %d IPv4 (sequential)", n)
		start := time.Now()
		errors := 0
		for i := 1; i <= n; i++ {
			addr := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
			if _, err := client.AddAddress("ip", "crowdsec-banned", addr, "1m", "batch"); err != nil {
				errors++
			}
		}
		elapsed := time.Since(start)
		fmt.Printf("  %-35s %8s  (%s/ip, errors=%d)\n", label, elapsed.Round(time.Millisecond), (elapsed / time.Duration(n)).Round(time.Millisecond), errors)

		start2 := time.Now()
		entries, _ := client.ListAddresses("ip", "crowdsec-banned", "")
		fmt.Printf("  %-35s %8s  (entries=%d)\n", fmt.Sprintf("List %d entries", n), time.Since(start2).Round(time.Millisecond), len(entries))

		start3 := time.Now()
		_, _ = client.FindAddress("ip", "crowdsec-banned", "198.51.0.1")
		fmt.Printf("  %-35s %8s\n", fmt.Sprintf("Find 1 in %d entries", n), time.Since(start3).Round(time.Millisecond))

		cleanStart := time.Now()
		for _, e := range entries {
			_ = client.RemoveAddress("ip", e.ID)
		}
		fmt.Printf("  %-35s %8s  (%s/ip)\n", fmt.Sprintf("Remove %d entries", len(entries)), time.Since(cleanStart).Round(time.Millisecond), (time.Since(cleanStart) / time.Duration(len(entries))).Round(time.Millisecond))
		fmt.Println()
	}

	fmt.Println("=== BENCHMARK COMPLETE ===")
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
