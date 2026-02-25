// Tests for the config package covering loading, defaults, validation,
// and environment variable overrides.
package config

import (
	"strings"
	"testing"
	"time"
)

// setMinimalEnv sets the minimum required environment variables for a valid
// configuration to load without a YAML file.
func setMinimalEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CROWDSEC_BOUNCER_API_KEY", "test-key")
	t.Setenv("CROWDSEC_URL", "http://localhost:8080/")
	t.Setenv("MIKROTIK_HOST", "192.168.0.1:8728")
	t.Setenv("MIKROTIK_USER", "admin")
	t.Setenv("MIKROTIK_PASS", "password")
}

// TestLoadFromEnv verifies that configuration can be loaded entirely from
// environment variables when no YAML file is provided.
func TestLoadFromEnv(t *testing.T) {
	setMinimalEnv(t)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.CrowdSec.APIKey != "test-key" {
		t.Errorf("expected api_key 'test-key', got '%s'", cfg.CrowdSec.APIKey)
	}
	if cfg.MikroTik.Address != "192.168.0.1:8728" {
		t.Errorf("expected address '192.168.0.1:8728', got '%s'", cfg.MikroTik.Address)
	}
	if !cfg.Firewall.IPv4.Enabled {
		t.Error("expected ipv4 enabled by default")
	}
	if cfg.Firewall.IPv4.AddressList != "crowdsec-banned" {
		t.Errorf("expected address_list 'crowdsec-banned', got '%s'", cfg.Firewall.IPv4.AddressList)
	}
	if cfg.Firewall.DenyAction != "drop" {
		t.Errorf("expected deny_action 'drop', got '%s'", cfg.Firewall.DenyAction)
	}
}

// TestLoadDefaults verifies that all default values are correctly applied
// when loading a minimal configuration.
func TestLoadDefaults(t *testing.T) {
	setMinimalEnv(t)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// CrowdSec defaults
	if cfg.CrowdSec.UpdateFrequency.String() != "10s" {
		t.Errorf("expected update_frequency '10s', got '%s'", cfg.CrowdSec.UpdateFrequency)
	}
	if !cfg.CrowdSec.RetryInitialConnect {
		t.Error("expected retry_initial_connect true by default")
	}

	// MikroTik defaults
	if cfg.MikroTik.TLS {
		t.Error("expected tls false by default")
	}
	if cfg.MikroTik.ConnectionTimeout.String() != "10s" {
		t.Errorf("expected connection_timeout '10s', got '%s'", cfg.MikroTik.ConnectionTimeout)
	}
	if cfg.MikroTik.CommandTimeout.String() != "30s" {
		t.Errorf("expected command_timeout '30s', got '%s'", cfg.MikroTik.CommandTimeout)
	}

	// Firewall defaults
	if !cfg.Firewall.IPv6.Enabled {
		t.Error("expected ipv6 enabled by default")
	}
	if cfg.Firewall.IPv6.AddressList != "crowdsec6-banned" {
		t.Errorf("expected ipv6 address_list 'crowdsec6-banned', got '%s'", cfg.Firewall.IPv6.AddressList)
	}
	if !cfg.Firewall.Filter.Enabled {
		t.Error("expected filter enabled by default")
	}
	if !cfg.Firewall.Raw.Enabled {
		t.Error("expected raw enabled by default")
	}
	if cfg.Firewall.RulePlacement != "top" {
		t.Errorf("expected rule_placement 'top', got '%s'", cfg.Firewall.RulePlacement)
	}
	if cfg.Firewall.CommentPrefix != "crowdsec-bouncer" {
		t.Errorf("expected comment_prefix 'crowdsec-bouncer', got '%s'", cfg.Firewall.CommentPrefix)
	}
	if cfg.Firewall.Log {
		t.Error("expected log false by default")
	}
	if cfg.Firewall.BlockOutput.Enabled {
		t.Error("expected block_output disabled by default")
	}
	if cfg.Firewall.BlockInput.Interface != "" {
		t.Error("expected block_input.interface empty by default")
	}
	if cfg.Firewall.BlockInput.InterfaceList != "" {
		t.Error("expected block_input.interface_list empty by default")
	}

	// Logging defaults
	if cfg.Logging.Level != "info" {
		t.Errorf("expected log level 'info', got '%s'", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" {
		t.Errorf("expected log format 'text', got '%s'", cfg.Logging.Format)
	}

	// Metrics defaults
	if cfg.Metrics.Enabled {
		t.Error("expected metrics disabled by default")
	}
	if cfg.Metrics.ListenAddr != "0.0.0.0" {
		t.Errorf("expected metrics addr '0.0.0.0', got '%s'", cfg.Metrics.ListenAddr)
	}
	if cfg.Metrics.ListenPort != 2112 {
		t.Errorf("expected metrics port 2112, got %d", cfg.Metrics.ListenPort)
	}
	if !cfg.Metrics.TrackProcessed {
		t.Error("expected track_processed true by default")
	}
}

// TestMetricsTrackProcessedEnvOverride verifies that METRICS_TRACK_PROCESSED
// environment variable overrides the default value.
func TestMetricsTrackProcessedEnvOverride(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("METRICS_TRACK_PROCESSED", "false")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Metrics.TrackProcessed {
		t.Error("expected track_processed false when METRICS_TRACK_PROCESSED=false")
	}
}

// TestValidateMissingAPIKey verifies that validation fails when the CrowdSec
// API key is not provided.
func TestValidateMissingAPIKey(t *testing.T) {
	t.Setenv("CROWDSEC_URL", "http://localhost:8080/")
	t.Setenv("MIKROTIK_HOST", "192.168.0.1:8728")
	t.Setenv("MIKROTIK_USER", "admin")
	t.Setenv("MIKROTIK_PASS", "password")

	_, err := Load("")
	if err == nil {
		t.Fatal("expected error for missing api_key")
	}
}

// TestValidateMissingAPIURL verifies that validation fails when the CrowdSec
// API URL is empty.
func TestValidateMissingAPIURL(t *testing.T) {
	cfg := Config{
		CrowdSec: CrowdSecConfig{APIKey: "key", APIURL: ""},
		MikroTik: MikroTikConfig{Address: "1.2.3.4:8728", Username: "admin", Password: "pass", PoolSize: 4},
		Firewall: FirewallConfig{
			IPv4: ProtoConfig{Enabled: true}, IPv6: ProtoConfig{Enabled: true},
			Filter: FilterConfig{Enabled: true}, Raw: RawConfig{Enabled: true},
			DenyAction: "drop",
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing api_url")
	} else if !strings.Contains(err.Error(), "api_url") {
		t.Errorf("error should mention api_url: %v", err)
	}
}

// TestValidateMissingMikroTikAddress verifies that validation fails when
// the MikroTik router address is empty.
func TestValidateMissingMikroTikAddress(t *testing.T) {
	cfg := Config{
		CrowdSec: CrowdSecConfig{APIKey: "key", APIURL: "http://localhost:8080/"},
		MikroTik: MikroTikConfig{Address: "", Username: "admin", Password: "pass", PoolSize: 4},
		Firewall: FirewallConfig{
			IPv4: ProtoConfig{Enabled: true}, IPv6: ProtoConfig{Enabled: true},
			Filter: FilterConfig{Enabled: true}, Raw: RawConfig{Enabled: true},
			DenyAction: "drop",
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing mikrotik.address")
	} else if !strings.Contains(err.Error(), "mikrotik.address") {
		t.Errorf("error should mention mikrotik.address: %v", err)
	}
}

// TestValidateMissingMikroTikCredentials verifies that validation fails when
// either the MikroTik username or password is missing.
func TestValidateMissingMikroTikCredentials(t *testing.T) {
	cfg := Config{
		CrowdSec: CrowdSecConfig{APIKey: "key", APIURL: "http://localhost:8080/"},
		MikroTik: MikroTikConfig{Address: "1.2.3.4:8728", Username: "", Password: "pass", PoolSize: 4},
		Firewall: FirewallConfig{
			IPv4: ProtoConfig{Enabled: true}, IPv6: ProtoConfig{Enabled: true},
			Filter: FilterConfig{Enabled: true}, Raw: RawConfig{Enabled: true},
			DenyAction: "drop",
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing username")
	}

	cfg.MikroTik.Username = "admin"
	cfg.MikroTik.Password = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing password")
	}
}

// TestValidateInvalidDenyAction verifies that validation rejects unrecognized
// deny actions (only "drop" and "reject" are valid).
func TestValidateInvalidDenyAction(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("FIREWALL_DENY_ACTION", "invalid")

	_, err := Load("")
	if err == nil {
		t.Fatal("expected error for invalid deny_action")
	}
}

// TestValidateDenyActionReject verifies that "reject" is accepted as a valid
// deny action.
func TestValidateDenyActionReject(t *testing.T) {
	cfg := Config{
		CrowdSec: CrowdSecConfig{APIKey: "key", APIURL: "http://localhost:8080/"},
		MikroTik: MikroTikConfig{Address: "1.2.3.4:8728", Username: "admin", Password: "pass", PoolSize: 4},
		Firewall: FirewallConfig{
			IPv4: ProtoConfig{Enabled: true}, IPv6: ProtoConfig{Enabled: true},
			Filter: FilterConfig{Enabled: true}, Raw: RawConfig{Enabled: true},
			DenyAction: "reject",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("reject should be a valid deny_action: %v", err)
	}
}

// TestValidateBothIPDisabled verifies that validation fails when both IPv4
// and IPv6 are disabled, as the bouncer needs at least one protocol.
func TestValidateBothIPDisabled(t *testing.T) {
	cfg := Config{
		CrowdSec: CrowdSecConfig{APIKey: "key", APIURL: "http://localhost:8080/"},
		MikroTik: MikroTikConfig{Address: "1.2.3.4:8728", Username: "admin", Password: "pass", PoolSize: 4},
		Firewall: FirewallConfig{
			IPv4: ProtoConfig{Enabled: false}, IPv6: ProtoConfig{Enabled: false},
			Filter: FilterConfig{Enabled: true}, Raw: RawConfig{Enabled: true},
			DenyAction: "drop",
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when both IPv4 and IPv6 are disabled")
	} else if !strings.Contains(err.Error(), "ipv4") || !strings.Contains(err.Error(), "ipv6") {
		t.Errorf("error should mention ipv4/ipv6: %v", err)
	}
}

// TestValidateBothRuleTypesDisabled verifies that validation fails when both
// filter and raw rule types are disabled.
func TestValidateBothRuleTypesDisabled(t *testing.T) {
	cfg := Config{
		CrowdSec: CrowdSecConfig{APIKey: "key", APIURL: "http://localhost:8080/"},
		MikroTik: MikroTikConfig{Address: "1.2.3.4:8728", Username: "admin", Password: "pass", PoolSize: 4},
		Firewall: FirewallConfig{
			IPv4: ProtoConfig{Enabled: true}, IPv6: ProtoConfig{Enabled: true},
			Filter: FilterConfig{Enabled: false}, Raw: RawConfig{Enabled: false},
			DenyAction: "drop",
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when both filter and raw are disabled")
	} else if !strings.Contains(err.Error(), "filter") || !strings.Contains(err.Error(), "raw") {
		t.Errorf("error should mention filter/raw: %v", err)
	}
}

// TestValidateBlockOutputRequiresInterface verifies that enabling output
// blocking without specifying an interface or interface list triggers an error.
func TestValidateBlockOutputRequiresInterface(t *testing.T) {
	cfg := Config{
		CrowdSec: CrowdSecConfig{APIKey: "key", APIURL: "http://localhost:8080/"},
		MikroTik: MikroTikConfig{Address: "1.2.3.4:8728", Username: "admin", Password: "pass", PoolSize: 4},
		Firewall: FirewallConfig{
			IPv4: ProtoConfig{Enabled: true}, IPv6: ProtoConfig{Enabled: true},
			Filter: FilterConfig{Enabled: true}, Raw: RawConfig{Enabled: true},
			DenyAction:  "drop",
			BlockOutput: BlockOutputConfig{Enabled: true, Interface: "", InterfaceList: ""},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when block_output enabled without interface")
	} else if !strings.Contains(err.Error(), "block_output") {
		t.Errorf("error should mention block_output: %v", err)
	}
}

// TestValidateBlockOutputWithInterface verifies that output blocking passes
// validation when a specific interface is configured.
func TestValidateBlockOutputWithInterface(t *testing.T) {
	cfg := Config{
		CrowdSec: CrowdSecConfig{APIKey: "key", APIURL: "http://localhost:8080/"},
		MikroTik: MikroTikConfig{Address: "1.2.3.4:8728", Username: "admin", Password: "pass", PoolSize: 4},
		Firewall: FirewallConfig{
			IPv4: ProtoConfig{Enabled: true}, IPv6: ProtoConfig{Enabled: true},
			Filter: FilterConfig{Enabled: true}, Raw: RawConfig{Enabled: true},
			DenyAction:  "drop",
			BlockOutput: BlockOutputConfig{Enabled: true, Interface: "ether1"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("should pass with block_output interface set: %v", err)
	}
}

// TestValidateBlockOutputWithInterfaceList verifies that output blocking
// passes validation when an interface list is configured.
func TestValidateBlockOutputWithInterfaceList(t *testing.T) {
	cfg := Config{
		CrowdSec: CrowdSecConfig{APIKey: "key", APIURL: "http://localhost:8080/"},
		MikroTik: MikroTikConfig{Address: "1.2.3.4:8728", Username: "admin", Password: "pass", PoolSize: 4},
		Firewall: FirewallConfig{
			IPv4: ProtoConfig{Enabled: true}, IPv6: ProtoConfig{Enabled: true},
			Filter: FilterConfig{Enabled: true}, Raw: RawConfig{Enabled: true},
			DenyAction:  "drop",
			BlockOutput: BlockOutputConfig{Enabled: true, InterfaceList: "WAN"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("should pass with block_output interface_list set: %v", err)
	}
}

// TestValidateCompleteConfig verifies that a fully populated valid
// configuration passes validation.
func TestValidateCompleteConfig(t *testing.T) {
	cfg := Config{
		CrowdSec: CrowdSecConfig{APIKey: "key", APIURL: "http://localhost:8080/"},
		MikroTik: MikroTikConfig{Address: "1.2.3.4:8728", Username: "admin", Password: "pass", PoolSize: 4},
		Firewall: FirewallConfig{
			IPv4:          ProtoConfig{Enabled: true, AddressList: "crowdsec-banned"},
			IPv6:          ProtoConfig{Enabled: true, AddressList: "crowdsec6-banned"},
			Filter:        FilterConfig{Enabled: true, Chains: []string{"input"}},
			Raw:           RawConfig{Enabled: true, Chains: []string{"prerouting"}},
			DenyAction:    "drop",
			RulePlacement: "top",
			CommentPrefix: "crowdsec-bouncer",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("complete valid config should not error: %v", err)
	}
}

// TestOriginsFromEnv verifies that the CrowdSec origins list can be set
// via the CROWDSEC_ORIGINS environment variable (space-separated).
func TestOriginsFromEnv(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("CROWDSEC_ORIGINS", "crowdsec cscli")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.CrowdSec.Origins) != 2 {
		t.Fatalf("expected 2 origins, got %d", len(cfg.CrowdSec.Origins))
	}
	if cfg.CrowdSec.Origins[0] != "crowdsec" || cfg.CrowdSec.Origins[1] != "cscli" {
		t.Errorf("unexpected origins: %v", cfg.CrowdSec.Origins)
	}
}

// TestEnvOverrides verifies that environment variables correctly override
// default values for all configuration sections.
func TestEnvOverrides(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("FIREWALL_IPV4_ENABLED", "false")
	t.Setenv("FIREWALL_FILTER_ENABLED", "true")
	t.Setenv("FIREWALL_RAW_ENABLED", "true")
	t.Setenv("FIREWALL_IPV6_ADDRESS_LIST", "custom6-list")
	t.Setenv("FIREWALL_DENY_ACTION", "reject")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("LOG_FORMAT", "json")
	t.Setenv("METRICS_ENABLED", "true")
	t.Setenv("METRICS_PORT", "9090")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Firewall.IPv4.Enabled {
		t.Error("expected ipv4 disabled via env")
	}
	if cfg.Firewall.IPv6.AddressList != "custom6-list" {
		t.Errorf("expected custom6-list, got '%s'", cfg.Firewall.IPv6.AddressList)
	}
	if cfg.Firewall.DenyAction != "reject" {
		t.Errorf("expected deny_action 'reject', got '%s'", cfg.Firewall.DenyAction)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("expected log level 'debug', got '%s'", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("expected log format 'json', got '%s'", cfg.Logging.Format)
	}
	if !cfg.Metrics.Enabled {
		t.Error("expected metrics enabled via env")
	}
	if cfg.Metrics.ListenPort != 9090 {
		t.Errorf("expected metrics port 9090, got %d", cfg.Metrics.ListenPort)
	}
}

// TestLoadInvalidConfigFile verifies that loading a nonexistent YAML file
// returns an error.
func TestLoadInvalidConfigFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent config file")
	}
}

// TestValidateLogPrefixRequiresLog verifies that the log_prefix configuration
// value is only meaningful when firewall logging is enabled.
func TestValidateLogPrefixRequiresLog(t *testing.T) {
	cfg := Config{
		CrowdSec: CrowdSecConfig{APIKey: "key", APIURL: "http://localhost:8080/"},
		MikroTik: MikroTikConfig{Address: "1.2.3.4:8728", Username: "admin", Password: "pass", PoolSize: 4},
		Firewall: FirewallConfig{
			IPv4: ProtoConfig{Enabled: true}, IPv6: ProtoConfig{Enabled: true},
			Filter: FilterConfig{Enabled: true}, Raw: RawConfig{Enabled: true},
			DenyAction: "drop",
			Log:        true,
			LogPrefix:  "CS-DROP",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("log+prefix should be valid: %v", err)
	}
}

// TestValidateFilterOnlyEnabled verifies that having only filter rules
// enabled (raw disabled) passes validation.
func TestValidateFilterOnlyEnabled(t *testing.T) {
	cfg := Config{
		CrowdSec: CrowdSecConfig{APIKey: "key", APIURL: "http://localhost:8080/"},
		MikroTik: MikroTikConfig{Address: "1.2.3.4:8728", Username: "admin", Password: "pass", PoolSize: 4},
		Firewall: FirewallConfig{
			IPv4: ProtoConfig{Enabled: true}, IPv6: ProtoConfig{Enabled: true},
			Filter:     FilterConfig{Enabled: true},
			Raw:        RawConfig{Enabled: false},
			DenyAction: "drop",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("filter-only config should be valid: %v", err)
	}
}

// TestValidateIPv4OnlyEnabled verifies that having only IPv4 enabled
// (IPv6 disabled) passes validation.
func TestValidateIPv4OnlyEnabled(t *testing.T) {
	cfg := Config{
		CrowdSec: CrowdSecConfig{APIKey: "key", APIURL: "http://localhost:8080/"},
		MikroTik: MikroTikConfig{Address: "1.2.3.4:8728", Username: "admin", Password: "pass", PoolSize: 4},
		Firewall: FirewallConfig{
			IPv4: ProtoConfig{Enabled: true}, IPv6: ProtoConfig{Enabled: false},
			Filter:     FilterConfig{Enabled: true},
			Raw:        RawConfig{Enabled: true},
			DenyAction: "drop",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("ipv4-only config should be valid: %v", err)
	}
}

// TestLapiMetricsIntervalDefault verifies that the default value of
// LapiMetricsInterval is 15 minutes when not explicitly set.
func TestLapiMetricsIntervalDefault(t *testing.T) {
	setMinimalEnv(t)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "15m0s"
	if cfg.CrowdSec.LapiMetricsInterval.String() != want {
		t.Errorf("expected LapiMetricsInterval=%s, got %s",
			want, cfg.CrowdSec.LapiMetricsInterval)
	}
}

// TestLapiMetricsIntervalEnvOverride verifies that the CROWDSEC_LAPI_METRICS_INTERVAL
// environment variable correctly overrides the default.
func TestLapiMetricsIntervalEnvOverride(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("CROWDSEC_LAPI_METRICS_INTERVAL", "5m")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "5m0s"
	if cfg.CrowdSec.LapiMetricsInterval.String() != want {
		t.Errorf("expected LapiMetricsInterval=%s, got %s",
			want, cfg.CrowdSec.LapiMetricsInterval)
	}
}

// TestValidatePoolSizeBounds verifies that pool_size validation enforces
// the allowed range of 1 to 20.
func TestValidatePoolSizeBounds(t *testing.T) {
	base := Config{
		CrowdSec: CrowdSecConfig{APIKey: "key", APIURL: "http://localhost:8080/"},
		MikroTik: MikroTikConfig{Address: "1.2.3.4:8728", Username: "admin", Password: "pass"},
		Firewall: FirewallConfig{
			IPv4: ProtoConfig{Enabled: true}, IPv6: ProtoConfig{Enabled: true},
			Filter: FilterConfig{Enabled: true}, Raw: RawConfig{Enabled: true},
			DenyAction: "drop",
		},
	}

	// Zero should fail
	base.MikroTik.PoolSize = 0
	if err := base.Validate(); err == nil {
		t.Error("expected error for pool_size=0")
	}

	// Negative should fail
	base.MikroTik.PoolSize = -1
	if err := base.Validate(); err == nil {
		t.Error("expected error for pool_size=-1")
	}

	// Over 20 should fail
	base.MikroTik.PoolSize = 21
	if err := base.Validate(); err == nil {
		t.Error("expected error for pool_size=21")
	}

	// 1 should pass
	base.MikroTik.PoolSize = 1
	if err := base.Validate(); err != nil {
		t.Errorf("pool_size=1 should be valid: %v", err)
	}

	// 20 should pass
	base.MikroTik.PoolSize = 20
	if err := base.Validate(); err != nil {
		t.Errorf("pool_size=20 should be valid: %v", err)
	}

	// 4 (default) should pass
	base.MikroTik.PoolSize = 4
	if err := base.Validate(); err != nil {
		t.Errorf("pool_size=4 should be valid: %v", err)
	}
}

// TestPoolSizeDefault verifies that the default pool_size is 4 when loaded
// from environment variables without explicit override.
func TestPoolSizeDefault(t *testing.T) {
	setMinimalEnv(t)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.MikroTik.PoolSize != 4 {
		t.Errorf("expected default pool_size=4, got %d", cfg.MikroTik.PoolSize)
	}
}

// TestPoolSizeEnvOverride verifies that MIKROTIK_POOL_SIZE environment
// variable correctly overrides the default pool size.
func TestPoolSizeEnvOverride(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("MIKROTIK_POOL_SIZE", "8")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.MikroTik.PoolSize != 8 {
		t.Errorf("expected pool_size=8, got %d", cfg.MikroTik.PoolSize)
	}
}

// TestBlockInputInterfaceEnv verifies that FIREWALL_INPUT_INTERFACE and
// FIREWALL_INPUT_INTERFACE_LIST environment variables are correctly bound
// to the BlockInput configuration.
func TestBlockInputInterfaceEnv(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("FIREWALL_INPUT_INTERFACE", "ether1")
	t.Setenv("FIREWALL_INPUT_INTERFACE_LIST", "WAN")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Firewall.BlockInput.Interface != "ether1" {
		t.Errorf("expected block_input.interface='ether1', got '%s'", cfg.Firewall.BlockInput.Interface)
	}
	if cfg.Firewall.BlockInput.InterfaceList != "WAN" {
		t.Errorf("expected block_input.interface_list='WAN', got '%s'", cfg.Firewall.BlockInput.InterfaceList)
	}
}

// TestBlockInputEmptyIsValid verifies that leaving block_input empty (the
// default) passes validation — rules apply to all interfaces.
func TestBlockInputEmptyIsValid(t *testing.T) {
	cfg := &Config{
		MikroTik: MikroTikConfig{Address: "1.2.3.4:8728", Username: "u", Password: "p", PoolSize: 4},
		CrowdSec: CrowdSecConfig{APIURL: "http://localhost:8080/", APIKey: "k"},
		Firewall: FirewallConfig{
			IPv4:       ProtoConfig{Enabled: true},
			Filter:     FilterConfig{Enabled: true, Chains: []string{"input"}},
			DenyAction: "drop",
			BlockInput: BlockInputConfig{},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("empty block_input should be valid: %v", err)
	}
}

// ---------- New firewall feature validation tests ----------

func TestRejectWithRequiresRejectAction(t *testing.T) {
	cfg := validCfg()
	cfg.Firewall.DenyAction = "drop"
	cfg.Firewall.RejectWith = "tcp-reset"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error: reject_with requires deny_action=reject")
	}
}

func TestRejectWithValidValues(t *testing.T) {
	valid := []string{
		"icmp-network-unreachable", "icmp-host-unreachable", "icmp-port-unreachable",
		"icmp-protocol-unreachable", "icmp-network-prohibited", "icmp-host-prohibited",
		"icmp-admin-prohibited", "tcp-reset",
	}
	for _, v := range valid {
		cfg := validCfg()
		cfg.Firewall.DenyAction = "reject"
		cfg.Firewall.RejectWith = v
		if err := cfg.Validate(); err != nil {
			t.Errorf("reject_with=%q should be valid: %v", v, err)
		}
	}
}

func TestRejectWithInvalidValue(t *testing.T) {
	cfg := validCfg()
	cfg.Firewall.DenyAction = "reject"
	cfg.Firewall.RejectWith = "invalid-value"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid reject_with value")
	}
}

func TestConnectionStateValid(t *testing.T) {
	tests := []string{
		"new",
		"new,invalid",
		"established,related,new",
		"new, invalid",
		"  established , related , new  ",
	}
	for _, v := range tests {
		cfg := validCfg()
		cfg.Firewall.Filter.ConnectionState = v
		if err := cfg.Validate(); err != nil {
			t.Errorf("connection_state=%q should be valid: %v", v, err)
		}
	}
}

func TestConnectionStateInvalid(t *testing.T) {
	cfg := validCfg()
	cfg.Firewall.Filter.ConnectionState = "new,bogus"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid connection_state value")
	}
}

func TestRejectWithEmptyIsValid(t *testing.T) {
	cfg := validCfg()
	cfg.Firewall.DenyAction = "reject"
	cfg.Firewall.RejectWith = ""
	if err := cfg.Validate(); err != nil {
		t.Errorf("empty reject_with should be valid: %v", err)
	}
}

// validCfg returns a minimal valid Config for testing new features.
func validCfg() *Config {
	return &Config{
		MikroTik: MikroTikConfig{Address: "1.2.3.4:8728", Username: "u", Password: "p", PoolSize: 4},
		CrowdSec: CrowdSecConfig{APIURL: "http://localhost:8080/", APIKey: "k"},
		Firewall: FirewallConfig{
			IPv4:       ProtoConfig{Enabled: true},
			Filter:     FilterConfig{Enabled: true, Chains: []string{"input"}},
			DenyAction: "drop",
		},
	}
}

// TestRouterOSPollIntervalDefault verifies the default poll interval from Viper.
func TestRouterOSPollIntervalDefault(t *testing.T) {
	setMinimalEnv(t)
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Metrics.RouterOSPollInterval != 30*time.Second {
		t.Errorf("got %v, want 30s", cfg.Metrics.RouterOSPollInterval)
	}
}

// TestRouterOSPollIntervalZeroDisables verifies that 0 disables polling.
func TestRouterOSPollIntervalZeroDisables(t *testing.T) {
	cfg := validCfg()
	cfg.Metrics.RouterOSPollInterval = 0
	if err := cfg.Validate(); err != nil {
		t.Errorf("zero should be valid (disables polling): %v", err)
	}
}

// TestRouterOSPollIntervalNegative verifies that negative values are rejected.
func TestRouterOSPollIntervalNegative(t *testing.T) {
	cfg := validCfg()
	cfg.Metrics.RouterOSPollInterval = -1 * time.Second
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for negative poll interval")
	}
}
