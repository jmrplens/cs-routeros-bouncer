// Tests for the config package covering loading, defaults, validation,
// and environment variable overrides.
package config

import (
	"os"
	"path/filepath"
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

	tests := []struct {
		name string
		want any
		got  func() any
	}{
		{name: "CrowdSec update frequency", want: 10 * time.Second, got: func() any { return cfg.CrowdSec.UpdateFrequency }},
		{name: "CrowdSec reconciliation interval", want: 15 * time.Minute, got: func() any { return cfg.CrowdSec.ReconciliationInterval }},
		{name: "CrowdSec retry initial connect", want: true, got: func() any { return cfg.CrowdSec.RetryInitialConnect }},
		{name: "MikroTik TLS", want: false, got: func() any { return cfg.MikroTik.TLS }},
		{name: "MikroTik connection timeout", want: 10 * time.Second, got: func() any { return cfg.MikroTik.ConnectionTimeout }},
		{name: "MikroTik command timeout", want: 30 * time.Second, got: func() any { return cfg.MikroTik.CommandTimeout }},
		{name: "Firewall IPv6 enabled", want: true, got: func() any { return cfg.Firewall.IPv6.Enabled }},
		{name: "Firewall IPv6 address list", want: "crowdsec6-banned", got: func() any { return cfg.Firewall.IPv6.AddressList }},
		{name: "Firewall filter enabled", want: true, got: func() any { return cfg.Firewall.Filter.Enabled }},
		{name: "Firewall raw enabled", want: true, got: func() any { return cfg.Firewall.Raw.Enabled }},
		{name: "Firewall rule placement", want: "top", got: func() any { return cfg.Firewall.RulePlacement.String() }},
		{name: "Firewall comment prefix", want: "crowdsec-bouncer", got: func() any { return cfg.Firewall.CommentPrefix }},
		{name: "Firewall log", want: false, got: func() any { return cfg.Firewall.Log }},
		{name: "Firewall block output", want: false, got: func() any { return cfg.Firewall.BlockOutput.Enabled }},
		{name: "Firewall block input interface", want: "", got: func() any { return cfg.Firewall.BlockInput.Interface }},
		{name: "Firewall block input interface list", want: "", got: func() any { return cfg.Firewall.BlockInput.InterfaceList }},
		{name: "Logging level", want: "info", got: func() any { return cfg.Logging.Level }},
		{name: "Logging format", want: "text", got: func() any { return cfg.Logging.Format }},
		{name: "Metrics enabled", want: false, got: func() any { return cfg.Metrics.Enabled }},
		{name: "Metrics listen address", want: "0.0.0.0", got: func() any { return cfg.Metrics.ListenAddr }},
		{name: "Metrics listen port", want: 2112, got: func() any { return cfg.Metrics.ListenPort }},
		{name: "Metrics track processed", want: true, got: func() any { return cfg.Metrics.TrackProcessed }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.got(); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
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

// TestLoadExpandsEnvPlaceholders verifies ${VAR} expansion in YAML values.
func TestLoadExpandsEnvPlaceholders(t *testing.T) {
	t.Setenv("CROWDSEC_KEY_FROM_FILE", "expanded-key")
	t.Setenv("MIKROTIK_PASSWORD_FROM_FILE", "expanded-password")
	t.Setenv("CROWDSEC_ORIGIN", "expanded-origin")
	t.Setenv("CROWDSEC_BOUNCER_API_KEY", "")
	t.Setenv("CROWDSEC_ORIGINS", "")
	t.Setenv("CROWDSEC_URL", "http://localhost:8080/")
	t.Setenv("MIKROTIK_HOST", "192.168.0.1:8728")
	t.Setenv("MIKROTIK_USER", "admin")
	t.Setenv("MIKROTIK_PASS", "")

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(`crowdsec:
  api_key: "${CROWDSEC_KEY_FROM_FILE}"
  origins: ["${CROWDSEC_ORIGIN}"]
mikrotik:
  password: "${MIKROTIK_PASSWORD_FROM_FILE}"
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	if cfg.CrowdSec.APIKey != "expanded-key" {
		t.Fatalf("expected expanded CrowdSec key, got %q", cfg.CrowdSec.APIKey)
	}
	if cfg.MikroTik.Password != "expanded-password" {
		t.Fatalf("expected expanded MikroTik password, got %q", cfg.MikroTik.Password)
	}
	if len(cfg.CrowdSec.Origins) != 1 || cfg.CrowdSec.Origins[0] != "expanded-origin" {
		t.Fatalf("expected expanded origins, got %#v", cfg.CrowdSec.Origins)
	}
}

// TestLoadPreservesLiteralDollarValues verifies secrets are not shell-expanded.
func TestLoadPreservesLiteralDollarValues(t *testing.T) {
	t.Setenv("CROWDSEC_URL", "http://localhost:8080/")
	t.Setenv("MIKROTIK_HOST", "192.168.0.1:8728")
	t.Setenv("MIKROTIK_USER", "admin")
	t.Setenv("MIKROTIK_PASS", "pa$$from-env")
	t.Setenv("COMMENT_SUFFIX", "prod")
	t.Setenv("CROWDSEC_BOUNCER_API_KEY", "")
	t.Setenv("FIREWALL_COMMENT_PREFIX", "")

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(`crowdsec:
  api_key: "api$KEY-pa$$word"
firewall:
  comment_prefix: "cost$center-${COMMENT_SUFFIX}"
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	if cfg.CrowdSec.APIKey != "api$KEY-pa$$word" {
		t.Fatalf("expected literal CrowdSec key, got %q", cfg.CrowdSec.APIKey)
	}
	if cfg.MikroTik.Password != "pa$$from-env" {
		t.Fatalf("expected literal MikroTik password, got %q", cfg.MikroTik.Password)
	}
	if cfg.Firewall.CommentPrefix != "cost$center-prod" {
		t.Fatalf("expected braced placeholder only expansion, got %q", cfg.Firewall.CommentPrefix)
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
			RulePlacement: RulePlacementConfig{Strategy: RulePlacementTop},
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

// TestLoadStructuredRulePlacement verifies loading structured firewall rule
// placement from a file and its per-mode override.
func TestLoadStructuredRulePlacement(t *testing.T) {
	setMinimalEnv(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(`firewall:
  rule_placement:
    strategy: after_comment
    comment: "drop invalid"
    comment_match: contains
    fallback: bottom
    raw:
      strategy: position
      position: 2
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	placement := cfg.Firewall.RulePlacement
	if placement.Strategy != RulePlacementAfterComment {
		t.Fatalf("expected after_comment strategy, got %q", placement.Strategy)
	}
	if placement.Comment != "drop invalid" || placement.CommentMatch != RulePlacementMatchContains {
		t.Fatalf("unexpected comment placement: %#v", placement)
	}
	if placement.Fallback != RulePlacementBottom {
		t.Fatalf("expected bottom fallback, got %q", placement.Fallback)
	}
	raw := placement.ForMode("raw")
	if raw.Strategy != RulePlacementPosition || raw.Position == nil || *raw.Position != 2 {
		t.Fatalf("expected raw position override 2, got %#v", raw)
	}
}

// TestLoadProtocolRulePlacement verifies that IPv4 and IPv6 placement overrides
// can inherit global fields and override table-specific behavior independently.
func TestLoadProtocolRulePlacement(t *testing.T) {
	setMinimalEnv(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(`firewall:
  rule_placement:
    strategy: before_comment
    comment: "global anchor"
    fallback: bottom
  ipv4:
    rule_placement:
      comment: "ipv4 anchor"
  ipv6:
    rule_placement:
      strategy: bottom
      filter:
        strategy: after_comment
        comment: "ipv6 filter anchor"
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ipv4Filter := cfg.Firewall.RulePlacementFor("ip", "filter")
	if ipv4Filter.Strategy != RulePlacementBeforeComment || ipv4Filter.Comment != "ipv4 anchor" || ipv4Filter.Fallback != RulePlacementBottom {
		t.Fatalf("expected IPv4 filter to inherit global placement with IPv4 comment, got %#v", ipv4Filter)
	}
	ipv4Raw := cfg.Firewall.RulePlacementFor("ip", "raw")
	if ipv4Raw.Strategy != RulePlacementBeforeComment || ipv4Raw.Comment != "ipv4 anchor" || ipv4Raw.Fallback != RulePlacementBottom {
		t.Fatalf("expected IPv4 raw to inherit global placement with IPv4 comment, got %#v", ipv4Raw)
	}
	ipv6Raw := cfg.Firewall.RulePlacementFor("ipv6", "raw")
	if ipv6Raw.Strategy != RulePlacementBottom {
		t.Fatalf("expected IPv6 raw bottom override, got %#v", ipv6Raw)
	}
	ipv6Filter := cfg.Firewall.RulePlacementFor("ipv6", "filter")
	if ipv6Filter.Strategy != RulePlacementAfterComment || ipv6Filter.Comment != "ipv6 filter anchor" || ipv6Filter.Fallback != RulePlacementBottom {
		t.Fatalf("expected IPv6 filter table override to inherit fallback, got %#v", ipv6Filter)
	}
	if got := cfg.Firewall.RulePlacementString(); !strings.Contains(got, "ipv4=before_comment:ipv4 anchor") || !strings.Contains(got, "ipv6=bottom") || !strings.Contains(got, "ipv6.filter=after_comment:ipv6 filter anchor") {
		t.Fatalf("expected protocol placement summary, got %q", got)
	}
}

// TestLoadRulePlacementEnvFields verifies loading firewall rule placement from
// environment variables, including the structured strategy alias.
func TestLoadRulePlacementEnvFields(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("FIREWALL_RULE_PLACEMENT_STRATEGY", "position")
	t.Setenv("FIREWALL_RULE_PLACEMENT_POSITION", "3")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	placement := cfg.Firewall.RulePlacement
	if placement.Strategy != RulePlacementPosition || placement.Position == nil || *placement.Position != 3 {
		t.Fatalf("expected env position 3, got %#v", placement)
	}
}

// TestLoadRulePlacementLegacyEnv verifies the legacy FIREWALL_RULE_PLACEMENT
// strategy variable remains supported for existing deployments.
func TestLoadRulePlacementLegacyEnv(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("FIREWALL_RULE_PLACEMENT", "bottom")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Firewall.RulePlacement.Strategy != RulePlacementBottom {
		t.Fatalf("expected legacy env bottom placement, got %#v", cfg.Firewall.RulePlacement)
	}
}

// TestValidateRulePlacement verifies RulePlacementConfig validation paths for
// supported strategies, defaults, and invalid values.
func TestValidateRulePlacement(t *testing.T) {
	position := 4
	positionZero := 0
	tests := []struct {
		name      string
		placement RulePlacementConfig
		wantErr   string
	}{
		{name: "legacy top", placement: RulePlacementConfig{Strategy: RulePlacementTop}},
		{name: "position", placement: RulePlacementConfig{Strategy: RulePlacementPosition, Position: &position}},
		{name: "position zero", placement: RulePlacementConfig{Strategy: RulePlacementPosition, Position: &positionZero}},
		{name: "after comment", placement: RulePlacementConfig{Strategy: RulePlacementAfterComment, Comment: "drop invalid"}},
		{name: "invalid strategy", placement: RulePlacementConfig{Strategy: "middle"}, wantErr: "strategy"},
		{name: "missing comment", placement: RulePlacementConfig{Strategy: RulePlacementBeforeComment}, wantErr: "comment"},
		{name: "invalid comment", placement: RulePlacementConfig{Strategy: RulePlacementBeforeComment, Comment: "bad\ncomment"}, wantErr: "control characters"},
		{name: "invalid match", placement: RulePlacementConfig{Strategy: RulePlacementTop, CommentMatch: "regex"}, wantErr: "comment_match"},
		{name: "invalid fallback", placement: RulePlacementConfig{Strategy: RulePlacementAfterComment, Comment: "x", Fallback: "position"}, wantErr: "fallback"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validCfg()
			cfg.Firewall.RulePlacement = tt.placement
			err := cfg.Validate()
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

// TestValidateRulePlacementNegativePosition ensures negative positions are rejected.
func TestValidateRulePlacementNegativePosition(t *testing.T) {
	position := -1
	cfg := validCfg()
	cfg.Firewall.RulePlacement = RulePlacementConfig{Strategy: RulePlacementPosition, Position: &position}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "position") {
		t.Fatalf("expected position validation error, got %v", err)
	}
}

// TestRulePlacementHelpers verifies String, ForMode, mergeRulePlacement, and
// nil or empty default behavior.
func TestRulePlacementHelpers(t *testing.T) {
	position := 7
	placement := RulePlacementConfig{
		Strategy:     RulePlacementBeforeComment,
		Comment:      "anchor",
		CommentMatch: RulePlacementMatchContains,
		Position:     &position,
		Fallback:     RulePlacementBottom,
		Filter:       &RulePlacementConfig{Strategy: RulePlacementAfterComment, Comment: "filter-anchor"},
		Raw:          &RulePlacementConfig{Strategy: RulePlacementPosition, Position: &position},
	}

	if got := (*RulePlacementConfig)(nil).String(); got != RulePlacementTop {
		t.Fatalf("nil String should default to top, got %q", got)
	}
	if got := (*RulePlacementConfig)(nil).ForMode("filter"); got.Strategy != "" {
		t.Fatalf("nil ForMode should return zero value, got %#v", got)
	}
	if got := (*RulePlacementConfig)(nil).withoutTableOverrides(); got.Strategy != "" {
		t.Fatalf("nil withoutTableOverrides should return zero value, got %#v", got)
	}
	if got := (&RulePlacementConfig{}).String(); got != RulePlacementTop {
		t.Fatalf("empty String should default to top, got %q", got)
	}
	if got := placement.String(); !strings.Contains(got, "before_comment:anchor") || !strings.Contains(got, "filter=after_comment:filter-anchor") || !strings.Contains(got, "raw=position:7") {
		t.Fatalf("unexpected placement string: %q", got)
	}
	if got := placement.ForMode("unknown"); got.Filter != nil || got.Raw != nil || got.Strategy != RulePlacementBeforeComment {
		t.Fatalf("unknown mode should return global settings without overrides, got %#v", got)
	}
	if got := placement.ForMode("filter"); got.Strategy != RulePlacementAfterComment || got.Comment != "filter-anchor" || got.CommentMatch != RulePlacementMatchContains || got.Fallback != RulePlacementBottom {
		t.Fatalf("filter override should merge with global settings, got %#v", got)
	}
	if got := placement.ForMode("raw"); got.Strategy != RulePlacementPosition || got.Position == nil || *got.Position != position {
		t.Fatalf("raw override should keep configured position, got %#v", got)
	}

	merged := mergeRulePlacement(RulePlacementConfig{}, RulePlacementConfig{
		Strategy:     RulePlacementAfterComment,
		Comment:      "merged",
		CommentMatch: RulePlacementMatchContains,
		Position:     &position,
		Fallback:     RulePlacementBottom,
	})
	if merged.Strategy != RulePlacementAfterComment || merged.Comment != "merged" || merged.CommentMatch != RulePlacementMatchContains || merged.Position == nil || *merged.Position != position || merged.Fallback != RulePlacementBottom {
		t.Fatalf("unexpected merged placement: %#v", merged)
	}
}

// TestFirewallRulePlacementFor verifies effective precedence across global,
// table, protocol, and protocol-table placement overrides.
func TestFirewallRulePlacementFor(t *testing.T) {
	position := 4
	firewall := FirewallConfig{
		RulePlacement: RulePlacementConfig{
			Strategy: RulePlacementBeforeComment,
			Comment:  "global",
			Fallback: RulePlacementBottom,
			Raw:      &RulePlacementConfig{Strategy: RulePlacementTop},
		},
		IPv4: ProtoConfig{RulePlacement: &RulePlacementConfig{Comment: "ipv4"}},
		IPv6: ProtoConfig{RulePlacement: &RulePlacementConfig{
			Strategy: RulePlacementBottom,
			Filter:   &RulePlacementConfig{Strategy: RulePlacementPosition, Position: &position},
		}},
	}

	ipv4Filter := firewall.RulePlacementFor("ip", "filter")
	if ipv4Filter.Strategy != RulePlacementBeforeComment || ipv4Filter.Comment != "ipv4" || ipv4Filter.Fallback != RulePlacementBottom {
		t.Fatalf("unexpected IPv4 filter placement: %#v", ipv4Filter)
	}
	ipv4Raw := firewall.RulePlacementFor("ip", "raw")
	if ipv4Raw.Strategy != RulePlacementTop || ipv4Raw.Comment != "ipv4" || ipv4Raw.Fallback != RulePlacementBottom {
		t.Fatalf("unexpected IPv4 raw placement: %#v", ipv4Raw)
	}
	ipv6Raw := firewall.RulePlacementFor("ipv6", "raw")
	if ipv6Raw.Strategy != RulePlacementBottom || ipv6Raw.Comment != "global" {
		t.Fatalf("unexpected IPv6 raw placement: %#v", ipv6Raw)
	}
	ipv6Filter := firewall.RulePlacementFor("ipv6", "filter")
	if ipv6Filter.Strategy != RulePlacementPosition || ipv6Filter.Position == nil || *ipv6Filter.Position != position || ipv6Filter.Comment != "global" {
		t.Fatalf("unexpected IPv6 filter placement: %#v", ipv6Filter)
	}
}

// TestParseRulePlacementConfigVariants verifies parsing of strings, maps,
// nested overrides, and representative error cases.
func TestParseRulePlacementConfigVariants(t *testing.T) {
	position := 3
	tests := []struct {
		name  string
		input any
		check func(*testing.T, RulePlacementConfig)
	}{
		{name: "nil", input: nil, check: func(t *testing.T, got RulePlacementConfig) {
			t.Helper()
			if got.Strategy != "" {
				t.Fatalf("expected zero value, got %#v", got)
			}
		}},
		{name: "struct", input: RulePlacementConfig{Strategy: RulePlacementBottom}, check: func(t *testing.T, got RulePlacementConfig) {
			t.Helper()
			if got.Strategy != RulePlacementBottom {
				t.Fatalf("expected bottom, got %#v", got)
			}
		}},
		{name: "map any", input: map[any]any{"strategy": "position", "position": int64(position)}, check: func(t *testing.T, got RulePlacementConfig) {
			t.Helper()
			if got.Strategy != RulePlacementPosition || got.Position == nil || *got.Position != position {
				t.Fatalf("expected position %d, got %#v", position, got)
			}
		}},
		{name: "map string", input: map[string]any{"strategy": "after_comment", "comment": "anchor", "comment_match": "contains", "fallback": "bottom"}, check: func(t *testing.T, got RulePlacementConfig) {
			t.Helper()
			if got.Strategy != RulePlacementAfterComment || got.Comment != "anchor" || got.CommentMatch != RulePlacementMatchContains || got.Fallback != RulePlacementBottom {
				t.Fatalf("unexpected parsed map: %#v", got)
			}
		}},
		{name: "filter override", input: map[string]any{"filter": map[string]any{"strategy": "bottom"}}, check: func(t *testing.T, got RulePlacementConfig) {
			t.Helper()
			if got.Filter == nil || got.Filter.Strategy != RulePlacementBottom {
				t.Fatalf("expected filter bottom override, got %#v", got)
			}
		}},
		{name: "partial filter override inherits", input: map[string]any{"strategy": "before_comment", "comment": "global", "fallback": "bottom", "filter": map[string]any{"comment": "filter"}}, check: func(t *testing.T, got RulePlacementConfig) {
			t.Helper()
			if got.Filter == nil || got.Filter.Strategy != "" || got.Filter.Comment != "filter" {
				t.Fatalf("expected sparse filter override, got %#v", got)
			}
			filter := got.ForMode("filter")
			if filter.Strategy != RulePlacementBeforeComment || filter.Comment != "filter" || filter.Fallback != RulePlacementBottom {
				t.Fatalf("expected filter to inherit global fields, got %#v", filter)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRulePlacementConfig(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tt.check(t, got)
		})
	}

	errorInputs := []struct {
		name    string
		input   any
		wantErr string
	}{
		{name: "invalid type", input: []string{"top"}, wantErr: "firewall.rule_placement must be a string or object"},
		{name: "invalid position", input: map[string]any{"position": "not-int"}, wantErr: "firewall.rule_placement.position must be an integer"},
		{name: "fractional position", input: map[string]any{"position": float64(1.5)}, wantErr: "firewall.rule_placement.position must be an integer"},
		{name: "unknown key", input: map[string]any{"stategy": "top"}, wantErr: "firewall.rule_placement: unknown key \"stategy\""},
		{name: "invalid filter", input: map[string]any{"filter": []string{"bad"}}, wantErr: "firewall.rule_placement.filter must be a string or object"},
		{name: "invalid raw", input: map[string]any{"raw": []string{"bad"}}, wantErr: "firewall.rule_placement.raw must be a string or object"},
	}
	for _, tt := range errorInputs {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseRulePlacementConfig(tt.input); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

// TestRulePlacementPositionTypes verifies position type coercion and invalid
// integer representations.
func TestRulePlacementPositionTypes(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want int
	}{
		{name: "int", in: 1, want: 1},
		{name: "int64", in: int64(2), want: 2},
		{name: "float64", in: float64(3), want: 3},
		{name: "string", in: " 4 ", want: 4},
		{name: "default", in: uint(5), want: 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rulePlacementPosition(tt.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, got)
			}
		})
	}
	if _, err := rulePlacementPosition("bad"); err == nil {
		t.Fatal("expected string conversion error")
	}
	if _, err := rulePlacementPosition(float64(1.5)); err == nil {
		t.Fatal("expected fractional float conversion error")
	}
	if _, err := rulePlacementPosition([]string{"bad"}); err == nil {
		t.Fatal("expected default conversion error")
	}
}

func TestExpandRulePlacementEnvAndPlaceholders(t *testing.T) {
	t.Setenv("PLACEMENT_STRATEGY", "after_comment")
	t.Setenv("PLACEMENT_COMMENT", "drop invalid")
	t.Setenv("PLACEMENT_MATCH", "contains")
	t.Setenv("PLACEMENT_FALLBACK", "bottom")
	t.Setenv("FILTER_COMMENT", "filter anchor")
	t.Setenv("RAW_COMMENT", "raw anchor")
	placement := RulePlacementConfig{
		Strategy:     "${PLACEMENT_STRATEGY}",
		Comment:      "${PLACEMENT_COMMENT}",
		CommentMatch: "${PLACEMENT_MATCH}",
		Fallback:     "${PLACEMENT_FALLBACK}",
		Filter:       &RulePlacementConfig{Comment: "${FILTER_COMMENT}"},
		Raw:          &RulePlacementConfig{Comment: "${RAW_COMMENT}"},
	}
	if err := expandRulePlacementEnv(&placement); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if placement.Strategy != RulePlacementAfterComment || placement.Comment != "drop invalid" || placement.CommentMatch != RulePlacementMatchContains || placement.Fallback != RulePlacementBottom {
		t.Fatalf("unexpected expanded placement: %#v", placement)
	}
	if placement.Filter.Comment != "filter anchor" || placement.Raw.Comment != "raw anchor" {
		t.Fatalf("nested placeholders not expanded: %#v", placement)
	}

	t.Setenv("FIREWALL_RULE_PLACEMENT", "POSITION")
	t.Setenv("FIREWALL_RULE_PLACEMENT_COMMENT", "env anchor")
	t.Setenv("FIREWALL_RULE_PLACEMENT_COMMENT_MATCH", "CONTAINS")
	t.Setenv("FIREWALL_RULE_PLACEMENT_POSITION", "9")
	t.Setenv("FIREWALL_RULE_PLACEMENT_FALLBACK", "BOTTOM")
	if err := expandRulePlacementEnv(&placement); err != nil {
		t.Fatalf("unexpected env error: %v", err)
	}
	if placement.Strategy != RulePlacementPosition || placement.Comment != "env anchor" || placement.CommentMatch != RulePlacementMatchContains || placement.Position == nil || *placement.Position != 9 || placement.Fallback != RulePlacementBottom {
		t.Fatalf("env overrides not applied: %#v", placement)
	}
}

func TestExpandRulePlacementEnvInvalidPosition(t *testing.T) {
	t.Setenv("FIREWALL_RULE_PLACEMENT_POSITION", "bad")
	if err := expandRulePlacementEnv(&RulePlacementConfig{}); err == nil {
		t.Fatal("expected invalid env position error")
	}
}

// TestValidateRulePlacementNestedRawError verifies nested raw validation errors
// include the full field path.
func TestValidateRulePlacementNestedRawError(t *testing.T) {
	cfg := validCfg()
	cfg.Firewall.RulePlacement = RulePlacementConfig{Raw: &RulePlacementConfig{Strategy: "bad"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "firewall.rule_placement.raw.strategy") {
		t.Fatalf("expected nested raw validation error, got %v", err)
	}
}

// TestValidateRulePlacementNestedSuccessAndFilterError verifies valid nested
// placements pass and invalid filter overrides keep their field path.
func TestValidateRulePlacementNestedSuccessAndFilterError(t *testing.T) {
	cfg := validCfg()
	cfg.Firewall.RulePlacement = RulePlacementConfig{
		Filter: &RulePlacementConfig{Strategy: RulePlacementBottom},
		Raw:    &RulePlacementConfig{Strategy: RulePlacementTop},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected nested placement to validate, got %v", err)
	}

	cfg.Firewall.RulePlacement = RulePlacementConfig{Filter: &RulePlacementConfig{Strategy: "bad"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "firewall.rule_placement.filter.strategy") {
		t.Fatalf("expected nested filter validation error, got %v", err)
	}

	cfg = validCfg()
	cfg.Firewall.RulePlacement = RulePlacementConfig{Strategy: RulePlacementBeforeComment, Comment: "global"}
	cfg.Firewall.IPv4.RulePlacement = &RulePlacementConfig{Comment: "ipv4"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected IPv4 sparse placement override to validate, got %v", err)
	}

	cfg.Firewall.IPv4.RulePlacement = &RulePlacementConfig{Strategy: "bad"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "firewall.ipv4.rule_placement.strategy") {
		t.Fatalf("expected IPv4 placement validation error, got %v", err)
	}

	cfg = validCfg()
	cfg.Firewall.IPv6.RulePlacement = &RulePlacementConfig{Filter: &RulePlacementConfig{Strategy: RulePlacementBeforeComment}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "firewall.ipv6.rule_placement.filter.comment") {
		t.Fatalf("expected IPv6 filter placement validation error, got %v", err)
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

// TestReconciliationIntervalEnvOverride verifies the environment override for
// periodic reconciliation cadence.
func TestReconciliationIntervalEnvOverride(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("CROWDSEC_RECONCILIATION_INTERVAL", "5m")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.CrowdSec.ReconciliationInterval != 5*time.Minute {
		t.Errorf("expected reconciliation_interval 5m, got %s", cfg.CrowdSec.ReconciliationInterval)
	}
}

// TestValidateReconciliationIntervalZeroDisables verifies that 0 is accepted
// as the documented way to disable periodic reconciliation.
func TestValidateReconciliationIntervalZeroDisables(t *testing.T) {
	cfg := validCfg()
	cfg.CrowdSec.ReconciliationInterval = 0
	if err := cfg.Validate(); err != nil {
		t.Errorf("zero should be valid (disables reconciliation): %v", err)
	}
}

// TestValidateReconciliationIntervalMinimum verifies the minimum non-zero
// periodic reconciliation interval.
func TestValidateReconciliationIntervalMinimum(t *testing.T) {
	cfg := validCfg()
	cfg.CrowdSec.ReconciliationInterval = 30 * time.Second
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for reconciliation interval below 1m")
	} else if !strings.Contains(err.Error(), "reconciliation_interval") {
		t.Errorf("expected reconciliation_interval error, got %v", err)
	}

	cfg.CrowdSec.ReconciliationInterval = time.Minute
	if err := cfg.Validate(); err != nil {
		t.Errorf("1m should be valid: %v", err)
	}
}

// TestValidateReconciliationIntervalNegative verifies that negative intervals
// are rejected.
func TestValidateReconciliationIntervalNegative(t *testing.T) {
	cfg := validCfg()
	cfg.CrowdSec.ReconciliationInterval = -time.Second
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for negative reconciliation interval")
	} else if !strings.Contains(err.Error(), "reconciliation_interval") {
		t.Errorf("expected reconciliation_interval error, got %v", err)
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

// TestBlockInputInterfaceEnv verifies canonical FIREWALL_BLOCK_INPUT_* variables
// are bound to BlockInput configuration.
func TestBlockInputInterfaceEnv(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("FIREWALL_BLOCK_INPUT_INTERFACE", "ether1")
	t.Setenv("FIREWALL_BLOCK_INPUT_INTERFACE_LIST", "WAN")
	t.Setenv("FIREWALL_BLOCK_INPUT_WHITELIST", "trusted")

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
	if cfg.Firewall.BlockInput.Whitelist != "trusted" {
		t.Errorf("expected block_input.whitelist='trusted', got '%s'", cfg.Firewall.BlockInput.Whitelist)
	}
}

// TestBlockInputLegacyEnv verifies the previous FIREWALL_INPUT_* names remain
// supported for backward compatibility.
func TestBlockInputLegacyEnv(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("FIREWALL_INPUT_INTERFACE", "ether2")
	t.Setenv("FIREWALL_INPUT_INTERFACE_LIST", "LAN")
	t.Setenv("FIREWALL_INPUT_WHITELIST", "trusted-old")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Firewall.BlockInput.Interface != "ether2" || cfg.Firewall.BlockInput.InterfaceList != "LAN" || cfg.Firewall.BlockInput.Whitelist != "trusted-old" {
		t.Fatalf("legacy block input env not applied: %#v", cfg.Firewall.BlockInput)
	}
}

// TestBlockOutputEnv verifies canonical FIREWALL_BLOCK_OUTPUT_* variables are
// bound to BlockOutput configuration.
func TestBlockOutputEnv(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("FIREWALL_BLOCK_OUTPUT", "true")
	t.Setenv("FIREWALL_BLOCK_OUTPUT_INTERFACE", "ether1")
	t.Setenv("FIREWALL_BLOCK_OUTPUT_INTERFACE_LIST", "WAN")
	t.Setenv("FIREWALL_BLOCK_OUTPUT_LOG_PREFIX", "out")
	t.Setenv("FIREWALL_BLOCK_OUTPUT_PASSTHROUGH_V4", "10.0.0.5")
	t.Setenv("FIREWALL_BLOCK_OUTPUT_PASSTHROUGH_V4_LIST", "allow-v4")
	t.Setenv("FIREWALL_BLOCK_OUTPUT_PASSTHROUGH_V6", "2001:db8::5")
	t.Setenv("FIREWALL_BLOCK_OUTPUT_PASSTHROUGH_V6_LIST", "allow-v6")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := cfg.Firewall.BlockOutput
	if !output.Enabled || output.Interface != "ether1" || output.InterfaceList != "WAN" || output.LogPrefix != "out" ||
		output.PassthroughV4 != "10.0.0.5" || output.PassthroughV4List != "allow-v4" ||
		output.PassthroughV6 != "2001:db8::5" || output.PassthroughV6List != "allow-v6" {
		t.Fatalf("block output env not applied: %#v", output)
	}
}

// TestBlockOutputLegacyEnv verifies the previous FIREWALL_OUTPUT_* names remain
// supported for backward compatibility.
func TestBlockOutputLegacyEnv(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("FIREWALL_BLOCK_OUTPUT", "true")
	t.Setenv("FIREWALL_OUTPUT_INTERFACE", "ether2")
	t.Setenv("FIREWALL_OUTPUT_INTERFACE_LIST", "LAN")
	t.Setenv("FIREWALL_OUTPUT_LOG_PREFIX", "legacy-out")
	t.Setenv("FIREWALL_OUTPUT_PASSTHROUGH_V4", "10.0.0.6")
	t.Setenv("FIREWALL_OUTPUT_PASSTHROUGH_V4_LIST", "legacy-v4")
	t.Setenv("FIREWALL_OUTPUT_PASSTHROUGH_V6", "2001:db8::6")
	t.Setenv("FIREWALL_OUTPUT_PASSTHROUGH_V6_LIST", "legacy-v6")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := cfg.Firewall.BlockOutput
	if output.Interface != "ether2" || output.InterfaceList != "LAN" || output.LogPrefix != "legacy-out" ||
		output.PassthroughV4 != "10.0.0.6" || output.PassthroughV4List != "legacy-v4" ||
		output.PassthroughV6 != "2001:db8::6" || output.PassthroughV6List != "legacy-v6" {
		t.Fatalf("legacy block output env not applied: %#v", output)
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

// TestRejectWithRequiresRejectAction verifies that setting reject_with without
// deny_action=reject produces a validation error.
func TestRejectWithRequiresRejectAction(t *testing.T) {
	cfg := validCfg()
	cfg.Firewall.DenyAction = "drop"
	cfg.Firewall.RejectWith = "tcp-reset"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error: reject_with requires deny_action=reject")
	}
}

// TestRejectWithValidValues verifies that all supported ICMP reject types and
// tcp-reset are accepted by validation when deny_action is "reject".
func TestRejectWithValidValues(t *testing.T) {
	valid := []string{
		"icmp-network-unreachable", "icmp-host-unreachable", "icmp-port-unreachable",
		"icmp-protocol-unreachable", "icmp-network-prohibited", "icmp-host-prohibited",
		"icmp-admin-prohibited", "tcp-reset",
	}
	for _, v := range valid {
		t.Run(v, func(t *testing.T) {
			cfg := validCfg()
			cfg.Firewall.DenyAction = "reject"
			cfg.Firewall.RejectWith = v
			if err := cfg.Validate(); err != nil {
				t.Errorf("reject_with=%q should be valid: %v", v, err)
			}
		})
	}
}

// TestRejectWithInvalidValue verifies that an unrecognized reject_with value
// causes a validation error.
func TestRejectWithInvalidValue(t *testing.T) {
	cfg := validCfg()
	cfg.Firewall.DenyAction = "reject"
	cfg.Firewall.RejectWith = "invalid-value"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid reject_with value")
	}
}

// TestConnectionStateValid verifies that valid connection-state strings
// (including whitespace-padded variants) pass validation.
func TestConnectionStateValid(t *testing.T) {
	tests := []string{
		"new",
		"new,invalid",
		"established,related,new",
		"new, invalid",
		"  established , related , new  ",
	}
	for _, v := range tests {
		t.Run(v, func(t *testing.T) {
			cfg := validCfg()
			cfg.Firewall.Filter.ConnectionState = v
			if err := cfg.Validate(); err != nil {
				t.Errorf("connection_state=%q should be valid: %v", v, err)
			}
		})
	}
}

// TestConnectionStateInvalid verifies that a connection_state value containing
// an unrecognized token causes a validation error.
func TestConnectionStateInvalid(t *testing.T) {
	cfg := validCfg()
	cfg.Firewall.Filter.ConnectionState = "new,bogus"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid connection_state value")
	}
}

// TestRejectWithEmptyIsValid verifies that an empty reject_with string is
// accepted when deny_action is "reject" (RouterOS uses its default).
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
