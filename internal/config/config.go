package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Build info (set via ldflags)
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Config holds the complete bouncer configuration.
type Config struct {
	CrowdSec CrowdSecConfig `yaml:"crowdsec" mapstructure:"crowdsec"`
	MikroTik MikroTikConfig `yaml:"mikrotik" mapstructure:"mikrotik"`
	Firewall FirewallConfig `yaml:"firewall" mapstructure:"firewall"`
	Logging  LoggingConfig  `yaml:"logging" mapstructure:"logging"`
	Metrics  MetricsConfig  `yaml:"metrics" mapstructure:"metrics"`
}

// CrowdSecConfig holds CrowdSec LAPI connection settings.
type CrowdSecConfig struct {
	APIURL                 string        `yaml:"api_url" mapstructure:"api_url"`
	APIKey                 string        `yaml:"api_key" mapstructure:"api_key"`
	UpdateFrequency        time.Duration `yaml:"update_frequency" mapstructure:"update_frequency"`
	Origins                []string      `yaml:"origins" mapstructure:"origins"`
	Scopes                 []string      `yaml:"scopes" mapstructure:"scopes"`
	ScenariosContaining    []string      `yaml:"scenarios_containing" mapstructure:"scenarios_containing"`
	ScenariosNotContaining []string      `yaml:"scenarios_not_containing" mapstructure:"scenarios_not_containing"`
	SupportedDecisionTypes []string      `yaml:"supported_decisions_types" mapstructure:"supported_decisions_types"`
	InsecureSkipVerify     bool          `yaml:"insecure_skip_verify" mapstructure:"insecure_skip_verify"`
	CertPath               string        `yaml:"cert_path" mapstructure:"cert_path"`
	KeyPath                string        `yaml:"key_path" mapstructure:"key_path"`
	CACertPath             string        `yaml:"ca_cert_path" mapstructure:"ca_cert_path"`
	RetryInitialConnect    bool          `yaml:"retry_initial_connect" mapstructure:"retry_initial_connect"`
	LapiMetricsInterval    time.Duration `yaml:"lapi_metrics_interval" mapstructure:"lapi_metrics_interval"`
}

// MikroTikConfig holds RouterOS API connection settings.
type MikroTikConfig struct {
	Address           string        `yaml:"address" mapstructure:"address"`
	Username          string        `yaml:"username" mapstructure:"username"`
	Password          string        `yaml:"password" mapstructure:"password"`
	TLS               bool          `yaml:"tls" mapstructure:"tls"`
	TLSInsecure       bool          `yaml:"tls_insecure" mapstructure:"tls_insecure"`
	ConnectionTimeout time.Duration `yaml:"connection_timeout" mapstructure:"connection_timeout"`
	CommandTimeout    time.Duration `yaml:"command_timeout" mapstructure:"command_timeout"`
	PoolSize          int           `yaml:"pool_size" mapstructure:"pool_size"`
}

// FirewallConfig holds firewall rule management settings.
type FirewallConfig struct {
	IPv4          ProtoConfig       `yaml:"ipv4" mapstructure:"ipv4"`
	IPv6          ProtoConfig       `yaml:"ipv6" mapstructure:"ipv6"`
	Filter        FilterConfig      `yaml:"filter" mapstructure:"filter"`
	Raw           RawConfig         `yaml:"raw" mapstructure:"raw"`
	DenyAction    string            `yaml:"deny_action" mapstructure:"deny_action"`
	RejectWith    string            `yaml:"reject_with" mapstructure:"reject_with"`
	BlockInput    BlockInputConfig  `yaml:"block_input" mapstructure:"block_input"`
	BlockOutput   BlockOutputConfig `yaml:"block_output" mapstructure:"block_output"`
	RulePlacement string            `yaml:"rule_placement" mapstructure:"rule_placement"`
	CommentPrefix string            `yaml:"comment_prefix" mapstructure:"comment_prefix"`
	Log           bool              `yaml:"log" mapstructure:"log"`
	LogPrefix     string            `yaml:"log_prefix" mapstructure:"log_prefix"`
}

// ProtoConfig holds per-protocol (IPv4/IPv6) settings.
type ProtoConfig struct {
	Enabled     bool   `yaml:"enabled" mapstructure:"enabled"`
	AddressList string `yaml:"address_list" mapstructure:"address_list"`
}

// FilterConfig holds filter-specific rule settings.
type FilterConfig struct {
	Enabled         bool     `yaml:"enabled" mapstructure:"enabled"`
	Chains          []string `yaml:"chains" mapstructure:"chains"`
	LogPrefix       string   `yaml:"log_prefix" mapstructure:"log_prefix"`
	ConnectionState string   `yaml:"connection_state" mapstructure:"connection_state"`
}

// RawConfig holds raw-specific rule settings.
type RawConfig struct {
	Enabled   bool     `yaml:"enabled" mapstructure:"enabled"`
	Chains    []string `yaml:"chains" mapstructure:"chains"`
	LogPrefix string   `yaml:"log_prefix" mapstructure:"log_prefix"`
}

// BlockInputConfig holds input blocking interface settings.
// When both Interface and InterfaceList are empty, input rules apply to all interfaces.
type BlockInputConfig struct {
	Interface     string `yaml:"interface" mapstructure:"interface"`
	InterfaceList string `yaml:"interface_list" mapstructure:"interface_list"`
	Whitelist     string `yaml:"whitelist" mapstructure:"whitelist"`
}

// BlockOutputConfig holds output blocking settings.
type BlockOutputConfig struct {
	Enabled           bool   `yaml:"enabled" mapstructure:"enabled"`
	Interface         string `yaml:"interface" mapstructure:"interface"`
	InterfaceList     string `yaml:"interface_list" mapstructure:"interface_list"`
	LogPrefix         string `yaml:"log_prefix" mapstructure:"log_prefix"`
	PassthroughV4     string `yaml:"passthrough_v4" mapstructure:"passthrough_v4"`
	PassthroughV4List string `yaml:"passthrough_v4_list" mapstructure:"passthrough_v4_list"`
	PassthroughV6     string `yaml:"passthrough_v6" mapstructure:"passthrough_v6"`
	PassthroughV6List string `yaml:"passthrough_v6_list" mapstructure:"passthrough_v6_list"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level  string `yaml:"level" mapstructure:"level"`
	Format string `yaml:"format" mapstructure:"format"`
	File   string `yaml:"file" mapstructure:"file"`
}

// MetricsConfig holds Prometheus metrics settings.
type MetricsConfig struct {
	Enabled              bool          `yaml:"enabled" mapstructure:"enabled"`
	ListenAddr           string        `yaml:"listen_addr" mapstructure:"listen_addr"`
	ListenPort           int           `yaml:"listen_port" mapstructure:"listen_port"`
	RouterOSPollInterval time.Duration `yaml:"routeros_poll_interval" mapstructure:"routeros_poll_interval"`
	TrackProcessed       bool          `yaml:"track_processed" mapstructure:"track_processed"`
}

// Load reads configuration from a YAML file and environment variables.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("crowdsec.api_url", "http://localhost:8080/")
	v.SetDefault("crowdsec.update_frequency", "10s")
	v.SetDefault("crowdsec.scopes", []string{"ip", "range"})
	v.SetDefault("crowdsec.supported_decisions_types", []string{"ban"})
	v.SetDefault("crowdsec.retry_initial_connect", true)
	v.SetDefault("crowdsec.lapi_metrics_interval", "15m")

	v.SetDefault("mikrotik.tls", false)
	v.SetDefault("mikrotik.tls_insecure", false)
	v.SetDefault("mikrotik.connection_timeout", "10s")
	v.SetDefault("mikrotik.command_timeout", "30s")
	v.SetDefault("mikrotik.pool_size", 4)

	v.SetDefault("firewall.ipv4.enabled", true)
	v.SetDefault("firewall.ipv4.address_list", "crowdsec-banned")
	v.SetDefault("firewall.ipv6.enabled", true)
	v.SetDefault("firewall.ipv6.address_list", "crowdsec6-banned")
	v.SetDefault("firewall.filter.enabled", true)
	v.SetDefault("firewall.filter.chains", []string{"input"})
	v.SetDefault("firewall.raw.enabled", true)
	v.SetDefault("firewall.raw.chains", []string{"prerouting"})
	v.SetDefault("firewall.deny_action", "drop")
	v.SetDefault("firewall.reject_with", "")
	v.SetDefault("firewall.block_output.enabled", false)
	v.SetDefault("firewall.rule_placement", "top")
	v.SetDefault("firewall.comment_prefix", "crowdsec-bouncer")
	v.SetDefault("firewall.log", false)
	v.SetDefault("firewall.log_prefix", "crowdsec-bouncer")

	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "text")

	v.SetDefault("metrics.enabled", false)
	v.SetDefault("metrics.listen_addr", "0.0.0.0")
	v.SetDefault("metrics.listen_port", 2112)
	v.SetDefault("metrics.routeros_poll_interval", "30s")
	v.SetDefault("metrics.track_processed", true)

	// Environment variable bindings (flat names for Docker compatibility)
	envBindings := map[string]string{ //nolint:gosec // G101: environment variable names, not credentials
		// CrowdSec
		"crowdsec.api_url":                   "CROWDSEC_URL",
		"crowdsec.api_key":                   "CROWDSEC_BOUNCER_API_KEY",
		"crowdsec.update_frequency":          "CROWDSEC_UPDATE_FREQUENCY",
		"crowdsec.origins":                   "CROWDSEC_ORIGINS",
		"crowdsec.scopes":                    "CROWDSEC_SCOPES",
		"crowdsec.scenarios_containing":      "CROWDSEC_SCENARIOS_CONTAINING",
		"crowdsec.scenarios_not_containing":  "CROWDSEC_SCENARIOS_NOT_CONTAINING",
		"crowdsec.supported_decisions_types": "CROWDSEC_DECISIONS_TYPES",
		"crowdsec.insecure_skip_verify":      "CROWDSEC_INSECURE_SKIP_VERIFY",
		"crowdsec.cert_path":                 "CROWDSEC_CERT_PATH",
		"crowdsec.key_path":                  "CROWDSEC_KEY_PATH",
		"crowdsec.ca_cert_path":              "CROWDSEC_CA_CERT_PATH",
		"crowdsec.retry_initial_connect":     "CROWDSEC_RETRY_INITIAL_CONNECT",
		"crowdsec.lapi_metrics_interval":     "CROWDSEC_LAPI_METRICS_INTERVAL",
		// MikroTik
		"mikrotik.address":            "MIKROTIK_HOST",
		"mikrotik.username":           "MIKROTIK_USER",
		"mikrotik.password":           "MIKROTIK_PASS",
		"mikrotik.tls":                "MIKROTIK_TLS",
		"mikrotik.tls_insecure":       "MIKROTIK_TLS_INSECURE",
		"mikrotik.connection_timeout": "MIKROTIK_CONN_TIMEOUT",
		"mikrotik.command_timeout":    "MIKROTIK_CMD_TIMEOUT",
		"mikrotik.pool_size":          "MIKROTIK_POOL_SIZE",
		// Firewall
		"firewall.ipv4.enabled":                     "FIREWALL_IPV4_ENABLED",
		"firewall.ipv4.address_list":                "FIREWALL_IPV4_ADDRESS_LIST",
		"firewall.ipv6.enabled":                     "FIREWALL_IPV6_ENABLED",
		"firewall.ipv6.address_list":                "FIREWALL_IPV6_ADDRESS_LIST",
		"firewall.filter.enabled":                   "FIREWALL_FILTER_ENABLED",
		"firewall.filter.chains":                    "FIREWALL_FILTER_CHAINS",
		"firewall.raw.enabled":                      "FIREWALL_RAW_ENABLED",
		"firewall.raw.chains":                       "FIREWALL_RAW_CHAINS",
		"firewall.deny_action":                      "FIREWALL_DENY_ACTION",
		"firewall.reject_with":                      "FIREWALL_REJECT_WITH",
		"firewall.rule_placement":                   "FIREWALL_RULE_PLACEMENT",
		"firewall.comment_prefix":                   "FIREWALL_COMMENT_PREFIX",
		"firewall.log":                              "FIREWALL_LOG",
		"firewall.log_prefix":                       "FIREWALL_LOG_PREFIX",
		"firewall.filter.log_prefix":                "FIREWALL_FILTER_LOG_PREFIX",
		"firewall.filter.connection_state":          "FIREWALL_FILTER_CONNECTION_STATE",
		"firewall.raw.log_prefix":                   "FIREWALL_RAW_LOG_PREFIX",
		"firewall.block_input.interface":            "FIREWALL_INPUT_INTERFACE",
		"firewall.block_input.interface_list":       "FIREWALL_INPUT_INTERFACE_LIST",
		"firewall.block_input.whitelist":            "FIREWALL_INPUT_WHITELIST",
		"firewall.block_output.enabled":             "FIREWALL_BLOCK_OUTPUT",
		"firewall.block_output.interface":           "FIREWALL_OUTPUT_INTERFACE",
		"firewall.block_output.interface_list":      "FIREWALL_OUTPUT_INTERFACE_LIST",
		"firewall.block_output.log_prefix":          "FIREWALL_OUTPUT_LOG_PREFIX",
		"firewall.block_output.passthrough_v4":      "FIREWALL_OUTPUT_PASSTHROUGH_V4",
		"firewall.block_output.passthrough_v4_list": "FIREWALL_OUTPUT_PASSTHROUGH_V4_LIST",
		"firewall.block_output.passthrough_v6":      "FIREWALL_OUTPUT_PASSTHROUGH_V6",
		"firewall.block_output.passthrough_v6_list": "FIREWALL_OUTPUT_PASSTHROUGH_V6_LIST",
		// Logging
		"logging.level":  "LOG_LEVEL",
		"logging.format": "LOG_FORMAT",
		"logging.file":   "LOG_FILE",
		// Metrics
		"metrics.enabled":                "METRICS_ENABLED",
		"metrics.listen_addr":            "METRICS_ADDR",
		"metrics.listen_port":            "METRICS_PORT",
		"metrics.routeros_poll_interval": "METRICS_ROUTEROS_POLL_INTERVAL",
		"metrics.track_processed":        "METRICS_TRACK_PROCESSED",
	}

	for key, env := range envBindings {
		_ = v.BindEnv(key, env)
	}

	// Handle space-separated CROWDSEC_ORIGINS → []string
	if origins := os.Getenv("CROWDSEC_ORIGINS"); origins != "" {
		v.Set("crowdsec.origins", strings.Fields(origins))
	}

	// Load config file if provided
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("reading config file %s: %w", configPath, err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

// Validate checks that all required configuration fields are set.
func (c *Config) Validate() error {
	if c.CrowdSec.APIKey == "" {
		return fmt.Errorf("crowdsec.api_key is required")
	}
	if c.CrowdSec.APIURL == "" {
		return fmt.Errorf("crowdsec.api_url is required")
	}
	if c.MikroTik.Address == "" {
		return fmt.Errorf("mikrotik.address is required")
	}
	if c.MikroTik.Username == "" {
		return fmt.Errorf("mikrotik.username is required")
	}
	if c.MikroTik.Password == "" {
		return fmt.Errorf("mikrotik.password is required")
	}
	if c.MikroTik.PoolSize < 1 || c.MikroTik.PoolSize > 20 {
		return fmt.Errorf("mikrotik.pool_size must be between 1 and 20, got %d", c.MikroTik.PoolSize)
	}
	if !c.Firewall.IPv4.Enabled && !c.Firewall.IPv6.Enabled {
		return fmt.Errorf("at least one of firewall.ipv4 or firewall.ipv6 must be enabled")
	}
	if !c.Firewall.Filter.Enabled && !c.Firewall.Raw.Enabled {
		return fmt.Errorf("at least one of firewall.filter or firewall.raw must be enabled")
	}
	if c.Firewall.DenyAction != "drop" && c.Firewall.DenyAction != "reject" {
		return fmt.Errorf("firewall.deny_action must be 'drop' or 'reject', got '%s'", c.Firewall.DenyAction)
	}
	if c.Firewall.RejectWith != "" && c.Firewall.DenyAction != "reject" {
		return fmt.Errorf("firewall.reject_with requires deny_action='reject'")
	}
	if c.Firewall.RejectWith != "" {
		valid := map[string]bool{
			"icmp-network-unreachable":  true,
			"icmp-host-unreachable":     true,
			"icmp-port-unreachable":     true,
			"icmp-protocol-unreachable": true,
			"icmp-network-prohibited":   true,
			"icmp-host-prohibited":      true,
			"icmp-admin-prohibited":     true,
			"tcp-reset":                 true,
		}
		if !valid[c.Firewall.RejectWith] {
			return fmt.Errorf("firewall.reject_with invalid value '%s'", c.Firewall.RejectWith)
		}
	}
	if c.Firewall.Filter.ConnectionState != "" {
		valid := map[string]bool{
			"established": true, "related": true, "new": true,
			"invalid": true, "untracked": true,
		}
		for _, s := range strings.Split(c.Firewall.Filter.ConnectionState, ",") {
			if !valid[strings.TrimSpace(s)] {
				return fmt.Errorf("firewall.filter.connection_state invalid value '%s'", s)
			}
		}
	}
	if c.Firewall.BlockOutput.Enabled {
		if c.Firewall.BlockOutput.Interface == "" && c.Firewall.BlockOutput.InterfaceList == "" {
			return fmt.Errorf("firewall.block_output requires interface or interface_list when enabled")
		}
	}

	if c.Metrics.RouterOSPollInterval < 0 {
		return fmt.Errorf("metrics.routeros_poll_interval must be >= 0 (0 disables)")
	}

	return nil
}
