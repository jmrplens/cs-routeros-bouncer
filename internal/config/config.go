package config

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/viper"
)

// Build info (set via ldflags)
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

var bracedEnvPlaceholder = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

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
	APIURL          string        `yaml:"api_url" mapstructure:"api_url"`
	APIKey          string        `yaml:"api_key" mapstructure:"api_key"`
	UpdateFrequency time.Duration `yaml:"update_frequency" mapstructure:"update_frequency"`
	// ReconciliationInterval controls periodic full-state reconciliation.
	// A zero value disables the periodic pass; non-zero values must be >= 1m.
	ReconciliationInterval time.Duration `yaml:"reconciliation_interval" mapstructure:"reconciliation_interval"`
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
	IPv4          ProtoConfig         `yaml:"ipv4" mapstructure:"ipv4"`
	IPv6          ProtoConfig         `yaml:"ipv6" mapstructure:"ipv6"`
	Filter        FilterConfig        `yaml:"filter" mapstructure:"filter"`
	Raw           RawConfig           `yaml:"raw" mapstructure:"raw"`
	DenyAction    string              `yaml:"deny_action" mapstructure:"deny_action"`
	RejectWith    string              `yaml:"reject_with" mapstructure:"reject_with"`
	BlockInput    BlockInputConfig    `yaml:"block_input" mapstructure:"block_input"`
	BlockOutput   BlockOutputConfig   `yaml:"block_output" mapstructure:"block_output"`
	RulePlacement RulePlacementConfig `yaml:"rule_placement" mapstructure:"rule_placement"`
	CommentPrefix string              `yaml:"comment_prefix" mapstructure:"comment_prefix"`
	Log           bool                `yaml:"log" mapstructure:"log"`
	LogPrefix     string              `yaml:"log_prefix" mapstructure:"log_prefix"`
}

const (
	RulePlacementTop           = "top"
	RulePlacementBottom        = "bottom"
	RulePlacementBeforeComment = "before_comment"
	RulePlacementAfterComment  = "after_comment"
	RulePlacementPosition      = "position"

	RulePlacementMatchExact    = "exact"
	RulePlacementMatchContains = "contains"
)

// RulePlacementConfig controls where bouncer-managed RouterOS firewall rules
// are placed. It accepts both the legacy string form ("top"/"bottom") and a
// structured object with strategy-specific settings.
type RulePlacementConfig struct {
	Strategy     string               `yaml:"strategy" mapstructure:"strategy"`
	Comment      string               `yaml:"comment" mapstructure:"comment"`
	CommentMatch string               `yaml:"comment_match" mapstructure:"comment_match"`
	Position     *int                 `yaml:"position" mapstructure:"position"`
	Fallback     string               `yaml:"fallback" mapstructure:"fallback"`
	Filter       *RulePlacementConfig `yaml:"filter" mapstructure:"filter"`
	Raw          *RulePlacementConfig `yaml:"raw" mapstructure:"raw"`
}

// UnmarshalMapstructure lets Viper decode rule_placement from either a legacy
// scalar string or a structured map.
func (p *RulePlacementConfig) UnmarshalMapstructure(input any) error {
	parsed, err := parseRulePlacementConfig(input)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// ForMode returns the placement settings for one RouterOS firewall table,
// merging optional table-specific overrides with the global settings.
func (p *RulePlacementConfig) ForMode(mode string) RulePlacementConfig {
	if p == nil {
		return RulePlacementConfig{}
	}
	base := p.withoutTableOverrides()
	var override *RulePlacementConfig
	switch mode {
	case "filter":
		override = p.Filter
	case "raw":
		override = p.Raw
	}
	if override == nil {
		return base
	}
	return mergeRulePlacement(base, override.withoutTableOverrides())
}

// String returns a concise non-sensitive representation for logs and metrics.
func (p *RulePlacementConfig) String() string {
	if p == nil {
		return RulePlacementTop
	}
	base := p.withoutTableOverrides()
	summary := base.summary()
	if p.Filter != nil {
		filterPlacement := mergeRulePlacement(base, p.Filter.withoutTableOverrides())
		summary += ",filter=" + filterPlacement.summary()
	}
	if p.Raw != nil {
		rawPlacement := mergeRulePlacement(base, p.Raw.withoutTableOverrides())
		summary += ",raw=" + rawPlacement.summary()
	}
	return summary
}

func (p *RulePlacementConfig) summary() string {
	if p == nil {
		return RulePlacementTop
	}
	strategy := p.Strategy
	if strategy == "" {
		strategy = RulePlacementTop
	}
	summary := strategy
	switch strategy {
	case RulePlacementBeforeComment, RulePlacementAfterComment:
		if p.Comment != "" {
			summary += ":" + p.Comment
		}
	case RulePlacementPosition:
		position := 0
		if p.Position != nil {
			position = *p.Position
		}
		summary += ":" + strconv.Itoa(position)
	}
	return summary
}

func (p *RulePlacementConfig) withoutTableOverrides() RulePlacementConfig {
	if p == nil {
		return RulePlacementConfig{}
	}
	placement := *p
	placement.Filter = nil
	placement.Raw = nil
	return placement
}

func mergeRulePlacement(base, override RulePlacementConfig) RulePlacementConfig {
	if override.Strategy != "" {
		base.Strategy = override.Strategy
	}
	if override.Comment != "" {
		base.Comment = override.Comment
	}
	if override.CommentMatch != "" {
		base.CommentMatch = override.CommentMatch
	}
	if override.Position != nil {
		base.Position = override.Position
	}
	if override.Fallback != "" {
		base.Fallback = override.Fallback
	}
	return base
}

func defaultStructuredRulePlacement() RulePlacementConfig {
	return RulePlacementConfig{
		Strategy:     RulePlacementTop,
		CommentMatch: RulePlacementMatchExact,
		Fallback:     RulePlacementTop,
	}
}

func parseRulePlacementConfig(input any) (RulePlacementConfig, error) {
	return parseRulePlacementConfigAt("firewall.rule_placement", input, true)
}

func parseRulePlacementConfigAt(path string, input any, withDefaults bool) (RulePlacementConfig, error) {
	switch value := input.(type) {
	case nil:
		return RulePlacementConfig{}, nil
	case string:
		return rulePlacementFromString(value, withDefaults), nil
	case RulePlacementConfig:
		return value, nil
	case map[string]any:
		return rulePlacementFromMap(path, value, withDefaults)
	case map[any]any:
		converted := make(map[string]any, len(value))
		for key, item := range value {
			converted[fmt.Sprint(key)] = item
		}
		return rulePlacementFromMap(path, converted, withDefaults)
	default:
		return RulePlacementConfig{}, fmt.Errorf("%s must be a string or object, got %T", path, input)
	}
}

func rulePlacementFromString(value string, withDefaults bool) RulePlacementConfig {
	placement := RulePlacementConfig{}
	if withDefaults {
		placement = defaultStructuredRulePlacement()
	}
	placement.Strategy = strings.ToLower(strings.TrimSpace(value))
	return placement
}

func rulePlacementFromMap(path string, values map[string]any, withDefaults bool) (RulePlacementConfig, error) {
	placement := RulePlacementConfig{}
	if withDefaults {
		placement = defaultStructuredRulePlacement()
	}
	for key, value := range values {
		switch key {
		case "strategy":
			placement.Strategy = strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
		case "comment":
			placement.Comment = fmt.Sprint(value)
		case "comment_match":
			placement.CommentMatch = strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
		case "fallback":
			placement.Fallback = strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
		case "position":
			position, err := rulePlacementPosition(value)
			if err != nil {
				return RulePlacementConfig{}, err
			}
			placement.Position = &position
		case "filter":
			parsed, err := parseRulePlacementConfigAt(path+".filter", value, false)
			if err != nil {
				return RulePlacementConfig{}, err
			}
			placement.Filter = &parsed
		case "raw":
			parsed, err := parseRulePlacementConfigAt(path+".raw", value, false)
			if err != nil {
				return RulePlacementConfig{}, err
			}
			placement.Raw = &parsed
		default:
			return RulePlacementConfig{}, fmt.Errorf("%s: unknown key %q", path, key)
		}
	}
	return placement, nil
}

func rulePlacementPosition(value any) (int, error) {
	switch typed := value.(type) {
	case int:
		return typed, nil
	case int64:
		return int(typed), nil
	case float64:
		if typed != math.Trunc(typed) {
			return 0, fmt.Errorf("firewall.rule_placement.position must be an integer, got %v", typed)
		}
		return int(typed), nil
	case string:
		position, err := strconv.Atoi(strings.TrimSpace(typed))
		if err != nil {
			return 0, fmt.Errorf("firewall.rule_placement.position must be an integer: %w", err)
		}
		return position, nil
	default:
		position, err := strconv.Atoi(fmt.Sprint(value))
		if err != nil {
			return 0, fmt.Errorf("firewall.rule_placement.position must be an integer: %w", err)
		}
		return position, nil
	}
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
	v.SetDefault("crowdsec.reconciliation_interval", "15m")
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
		"crowdsec.reconciliation_interval":   "CROWDSEC_RECONCILIATION_INTERVAL",
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
		"firewall.ipv4.enabled":                 "FIREWALL_IPV4_ENABLED",
		"firewall.ipv4.address_list":            "FIREWALL_IPV4_ADDRESS_LIST",
		"firewall.ipv6.enabled":                 "FIREWALL_IPV6_ENABLED",
		"firewall.ipv6.address_list":            "FIREWALL_IPV6_ADDRESS_LIST",
		"firewall.filter.enabled":               "FIREWALL_FILTER_ENABLED",
		"firewall.filter.chains":                "FIREWALL_FILTER_CHAINS",
		"firewall.raw.enabled":                  "FIREWALL_RAW_ENABLED",
		"firewall.raw.chains":                   "FIREWALL_RAW_CHAINS",
		"firewall.deny_action":                  "FIREWALL_DENY_ACTION",
		"firewall.reject_with":                  "FIREWALL_REJECT_WITH",
		"firewall.rule_placement":               "FIREWALL_RULE_PLACEMENT",
		"firewall.rule_placement.comment":       "FIREWALL_RULE_PLACEMENT_COMMENT",
		"firewall.rule_placement.comment_match": "FIREWALL_RULE_PLACEMENT_COMMENT_MATCH",
		"firewall.rule_placement.position":      "FIREWALL_RULE_PLACEMENT_POSITION",
		"firewall.rule_placement.fallback":      "FIREWALL_RULE_PLACEMENT_FALLBACK",
		"firewall.comment_prefix":               "FIREWALL_COMMENT_PREFIX",
		"firewall.log":                          "FIREWALL_LOG",
		"firewall.log_prefix":                   "FIREWALL_LOG_PREFIX",
		"firewall.filter.log_prefix":            "FIREWALL_FILTER_LOG_PREFIX",
		"firewall.filter.connection_state":      "FIREWALL_FILTER_CONNECTION_STATE",
		"firewall.raw.log_prefix":               "FIREWALL_RAW_LOG_PREFIX",
		"firewall.block_output.enabled":         "FIREWALL_BLOCK_OUTPUT",
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
	bindEnvAliases(v, "firewall.rule_placement.strategy", "FIREWALL_RULE_PLACEMENT_STRATEGY")
	bindEnvAliases(v, "firewall.block_input.interface", "FIREWALL_BLOCK_INPUT_INTERFACE", "FIREWALL_INPUT_INTERFACE")
	bindEnvAliases(v, "firewall.block_input.interface_list", "FIREWALL_BLOCK_INPUT_INTERFACE_LIST", "FIREWALL_INPUT_INTERFACE_LIST")
	bindEnvAliases(v, "firewall.block_input.whitelist", "FIREWALL_BLOCK_INPUT_WHITELIST", "FIREWALL_INPUT_WHITELIST")
	bindEnvAliases(v, "firewall.block_output.interface", "FIREWALL_BLOCK_OUTPUT_INTERFACE", "FIREWALL_OUTPUT_INTERFACE")
	bindEnvAliases(v, "firewall.block_output.interface_list", "FIREWALL_BLOCK_OUTPUT_INTERFACE_LIST", "FIREWALL_OUTPUT_INTERFACE_LIST")
	bindEnvAliases(v, "firewall.block_output.log_prefix", "FIREWALL_BLOCK_OUTPUT_LOG_PREFIX", "FIREWALL_OUTPUT_LOG_PREFIX")
	bindEnvAliases(v, "firewall.block_output.passthrough_v4", "FIREWALL_BLOCK_OUTPUT_PASSTHROUGH_V4", "FIREWALL_OUTPUT_PASSTHROUGH_V4")
	bindEnvAliases(v, "firewall.block_output.passthrough_v4_list", "FIREWALL_BLOCK_OUTPUT_PASSTHROUGH_V4_LIST", "FIREWALL_OUTPUT_PASSTHROUGH_V4_LIST")
	bindEnvAliases(v, "firewall.block_output.passthrough_v6", "FIREWALL_BLOCK_OUTPUT_PASSTHROUGH_V6", "FIREWALL_OUTPUT_PASSTHROUGH_V6")
	bindEnvAliases(v, "firewall.block_output.passthrough_v6_list", "FIREWALL_BLOCK_OUTPUT_PASSTHROUGH_V6_LIST", "FIREWALL_OUTPUT_PASSTHROUGH_V6_LIST")

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
	if err := expandConfigEnv(&cfg); err != nil {
		return nil, fmt.Errorf("expanding config env: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

func bindEnvAliases(v *viper.Viper, key string, envNames ...string) {
	args := append([]string{key}, envNames...)
	_ = v.BindEnv(args...)
}

// expandConfigEnv resolves ${VAR} placeholders in string-based configuration
// values after Viper has merged YAML, defaults, and direct environment overrides.
func expandConfigEnv(cfg *Config) error {
	cfg.CrowdSec.APIURL = expandConfigValue(cfg.CrowdSec.APIURL, "CROWDSEC_URL")
	cfg.CrowdSec.APIKey = expandConfigValue(cfg.CrowdSec.APIKey, "CROWDSEC_BOUNCER_API_KEY")
	cfg.CrowdSec.CertPath = expandConfigValue(cfg.CrowdSec.CertPath, "CROWDSEC_CERT_PATH")
	cfg.CrowdSec.KeyPath = expandConfigValue(cfg.CrowdSec.KeyPath, "CROWDSEC_KEY_PATH")
	cfg.CrowdSec.CACertPath = expandConfigValue(cfg.CrowdSec.CACertPath, "CROWDSEC_CA_CERT_PATH")
	cfg.CrowdSec.Origins = expandEnvSlice(cfg.CrowdSec.Origins, "CROWDSEC_ORIGINS")
	cfg.CrowdSec.Scopes = expandEnvSlice(cfg.CrowdSec.Scopes, "CROWDSEC_SCOPES")
	cfg.CrowdSec.ScenariosContaining = expandEnvSlice(cfg.CrowdSec.ScenariosContaining, "CROWDSEC_SCENARIOS_CONTAINING")
	cfg.CrowdSec.ScenariosNotContaining = expandEnvSlice(cfg.CrowdSec.ScenariosNotContaining, "CROWDSEC_SCENARIOS_NOT_CONTAINING")
	cfg.CrowdSec.SupportedDecisionTypes = expandEnvSlice(cfg.CrowdSec.SupportedDecisionTypes, "CROWDSEC_DECISIONS_TYPES")

	cfg.MikroTik.Address = expandConfigValue(cfg.MikroTik.Address, "MIKROTIK_HOST")
	cfg.MikroTik.Username = expandConfigValue(cfg.MikroTik.Username, "MIKROTIK_USER")
	cfg.MikroTik.Password = expandConfigValue(cfg.MikroTik.Password, "MIKROTIK_PASS")

	cfg.Firewall.IPv4.AddressList = expandConfigValue(cfg.Firewall.IPv4.AddressList, "FIREWALL_IPV4_ADDRESS_LIST")
	cfg.Firewall.IPv6.AddressList = expandConfigValue(cfg.Firewall.IPv6.AddressList, "FIREWALL_IPV6_ADDRESS_LIST")
	cfg.Firewall.Filter.Chains = expandEnvSlice(cfg.Firewall.Filter.Chains, "FIREWALL_FILTER_CHAINS")
	cfg.Firewall.Filter.LogPrefix = expandConfigValue(cfg.Firewall.Filter.LogPrefix, "FIREWALL_FILTER_LOG_PREFIX")
	cfg.Firewall.Filter.ConnectionState = expandConfigValue(cfg.Firewall.Filter.ConnectionState, "FIREWALL_FILTER_CONNECTION_STATE")
	cfg.Firewall.Raw.Chains = expandEnvSlice(cfg.Firewall.Raw.Chains, "FIREWALL_RAW_CHAINS")
	cfg.Firewall.Raw.LogPrefix = expandConfigValue(cfg.Firewall.Raw.LogPrefix, "FIREWALL_RAW_LOG_PREFIX")
	cfg.Firewall.DenyAction = expandConfigValue(cfg.Firewall.DenyAction, "FIREWALL_DENY_ACTION")
	cfg.Firewall.RejectWith = expandConfigValue(cfg.Firewall.RejectWith, "FIREWALL_REJECT_WITH")
	cfg.Firewall.BlockInput.Interface = expandConfigValueAny(cfg.Firewall.BlockInput.Interface, "FIREWALL_BLOCK_INPUT_INTERFACE", "FIREWALL_INPUT_INTERFACE")
	cfg.Firewall.BlockInput.InterfaceList = expandConfigValueAny(cfg.Firewall.BlockInput.InterfaceList, "FIREWALL_BLOCK_INPUT_INTERFACE_LIST", "FIREWALL_INPUT_INTERFACE_LIST")
	cfg.Firewall.BlockInput.Whitelist = expandConfigValueAny(cfg.Firewall.BlockInput.Whitelist, "FIREWALL_BLOCK_INPUT_WHITELIST", "FIREWALL_INPUT_WHITELIST")
	cfg.Firewall.BlockOutput.Interface = expandConfigValueAny(cfg.Firewall.BlockOutput.Interface, "FIREWALL_BLOCK_OUTPUT_INTERFACE", "FIREWALL_OUTPUT_INTERFACE")
	cfg.Firewall.BlockOutput.InterfaceList = expandConfigValueAny(cfg.Firewall.BlockOutput.InterfaceList, "FIREWALL_BLOCK_OUTPUT_INTERFACE_LIST", "FIREWALL_OUTPUT_INTERFACE_LIST")
	cfg.Firewall.BlockOutput.LogPrefix = expandConfigValueAny(cfg.Firewall.BlockOutput.LogPrefix, "FIREWALL_BLOCK_OUTPUT_LOG_PREFIX", "FIREWALL_OUTPUT_LOG_PREFIX")
	cfg.Firewall.BlockOutput.PassthroughV4 = expandConfigValueAny(cfg.Firewall.BlockOutput.PassthroughV4, "FIREWALL_BLOCK_OUTPUT_PASSTHROUGH_V4", "FIREWALL_OUTPUT_PASSTHROUGH_V4")
	cfg.Firewall.BlockOutput.PassthroughV4List = expandConfigValueAny(cfg.Firewall.BlockOutput.PassthroughV4List, "FIREWALL_BLOCK_OUTPUT_PASSTHROUGH_V4_LIST", "FIREWALL_OUTPUT_PASSTHROUGH_V4_LIST")
	cfg.Firewall.BlockOutput.PassthroughV6 = expandConfigValueAny(cfg.Firewall.BlockOutput.PassthroughV6, "FIREWALL_BLOCK_OUTPUT_PASSTHROUGH_V6", "FIREWALL_OUTPUT_PASSTHROUGH_V6")
	cfg.Firewall.BlockOutput.PassthroughV6List = expandConfigValueAny(cfg.Firewall.BlockOutput.PassthroughV6List, "FIREWALL_BLOCK_OUTPUT_PASSTHROUGH_V6_LIST", "FIREWALL_OUTPUT_PASSTHROUGH_V6_LIST")
	if err := expandRulePlacementEnv(&cfg.Firewall.RulePlacement); err != nil {
		return err
	}
	cfg.Firewall.CommentPrefix = expandConfigValue(cfg.Firewall.CommentPrefix, "FIREWALL_COMMENT_PREFIX")
	cfg.Firewall.LogPrefix = expandConfigValue(cfg.Firewall.LogPrefix, "FIREWALL_LOG_PREFIX")

	cfg.Logging.Level = expandConfigValue(cfg.Logging.Level, "LOG_LEVEL")
	cfg.Logging.Format = expandConfigValue(cfg.Logging.Format, "LOG_FORMAT")
	cfg.Logging.File = expandConfigValue(cfg.Logging.File, "LOG_FILE")
	cfg.Metrics.ListenAddr = expandConfigValue(cfg.Metrics.ListenAddr, "METRICS_ADDR")
	return nil
}

func expandRulePlacementEnv(placement *RulePlacementConfig) error {
	expandRulePlacementPlaceholders(placement)
	if envHasValue("FIREWALL_RULE_PLACEMENT") {
		placement.Strategy = strings.ToLower(strings.TrimSpace(os.Getenv("FIREWALL_RULE_PLACEMENT")))
	}
	if envHasValue("FIREWALL_RULE_PLACEMENT_STRATEGY") {
		placement.Strategy = strings.ToLower(strings.TrimSpace(os.Getenv("FIREWALL_RULE_PLACEMENT_STRATEGY")))
	}
	if envHasValue("FIREWALL_RULE_PLACEMENT_COMMENT") {
		placement.Comment = os.Getenv("FIREWALL_RULE_PLACEMENT_COMMENT")
	}
	if envHasValue("FIREWALL_RULE_PLACEMENT_COMMENT_MATCH") {
		placement.CommentMatch = strings.ToLower(strings.TrimSpace(os.Getenv("FIREWALL_RULE_PLACEMENT_COMMENT_MATCH")))
	}
	if envHasValue("FIREWALL_RULE_PLACEMENT_POSITION") {
		position, err := strconv.Atoi(strings.TrimSpace(os.Getenv("FIREWALL_RULE_PLACEMENT_POSITION")))
		if err != nil {
			return fmt.Errorf("FIREWALL_RULE_PLACEMENT_POSITION must be an integer: %w", err)
		}
		placement.Position = &position
	}
	if envHasValue("FIREWALL_RULE_PLACEMENT_FALLBACK") {
		placement.Fallback = strings.ToLower(strings.TrimSpace(os.Getenv("FIREWALL_RULE_PLACEMENT_FALLBACK")))
	}
	return nil
}

func expandRulePlacementPlaceholders(placement *RulePlacementConfig) {
	placement.Strategy = strings.ToLower(strings.TrimSpace(expandBracedEnv(placement.Strategy)))
	placement.Comment = expandBracedEnv(placement.Comment)
	placement.CommentMatch = strings.ToLower(strings.TrimSpace(expandBracedEnv(placement.CommentMatch)))
	placement.Fallback = strings.ToLower(strings.TrimSpace(expandBracedEnv(placement.Fallback)))
	if placement.Filter != nil {
		expandRulePlacementPlaceholders(placement.Filter)
	}
	if placement.Raw != nil {
		expandRulePlacementPlaceholders(placement.Raw)
	}
}

func expandConfigValue(value, envName string) string {
	return expandConfigValueAny(value, envName)
}

func expandConfigValueAny(value string, envNames ...string) string {
	for _, envName := range envNames {
		if envName != "" && envHasValue(envName) {
			return value
		}
	}
	return expandBracedEnv(value)
}

func envHasValue(envName string) bool {
	value, ok := os.LookupEnv(envName)
	return ok && value != ""
}

// expandBracedEnv expands explicit ${VAR} placeholders while preserving bare
// dollar signs that commonly appear in secrets and RouterOS values.
func expandBracedEnv(value string) string {
	return bracedEnvPlaceholder.ReplaceAllStringFunc(value, func(match string) string {
		name := match[2 : len(match)-1]
		return os.Getenv(name)
	})
}

// expandEnvSlice applies expandBracedEnv to each item in a configuration slice.
func expandEnvSlice(values []string, envName string) []string {
	if envName != "" && envHasValue(envName) {
		return values
	}
	for i, value := range values {
		values[i] = expandBracedEnv(value)
	}
	return values
}

// Validate checks that all required configuration fields are set.
func (c *Config) Validate() error {
	if err := c.validateCrowdSec(); err != nil {
		return err
	}
	if err := c.validateMikroTik(); err != nil {
		return err
	}
	if err := c.validateFirewall(); err != nil {
		return err
	}
	return c.validateIntervals()
}

// validateCrowdSec checks the required LAPI URL and bouncer API key settings.
func (c *Config) validateCrowdSec() error {
	if c.CrowdSec.APIKey == "" {
		return errors.New("crowdsec.api_key is required")
	}
	if c.CrowdSec.APIURL == "" {
		return errors.New("crowdsec.api_url is required")
	}
	parsedAPIURL, err := url.ParseRequestURI(c.CrowdSec.APIURL)
	if err != nil {
		return fmt.Errorf("crowdsec.api_url is invalid: %w", err)
	}
	if parsedAPIURL.Scheme == "" || parsedAPIURL.Host == "" {
		return fmt.Errorf("crowdsec.api_url must include scheme and host, got %q", c.CrowdSec.APIURL)
	}
	return nil
}

// validateMikroTik checks RouterOS connection credentials and pool bounds.
func (c *Config) validateMikroTik() error {
	if c.MikroTik.Address == "" {
		return errors.New("mikrotik.address is required")
	}
	if c.MikroTik.Username == "" {
		return errors.New("mikrotik.username is required")
	}
	if c.MikroTik.Password == "" {
		return errors.New("mikrotik.password is required")
	}
	if c.MikroTik.PoolSize < 1 || c.MikroTik.PoolSize > 20 {
		return fmt.Errorf("mikrotik.pool_size must be between 1 and 20, got %d", c.MikroTik.PoolSize)
	}
	return nil
}

// validateFirewall checks protocol, table, action, and option compatibility.
func (c *Config) validateFirewall() error {
	if !c.Firewall.IPv4.Enabled && !c.Firewall.IPv6.Enabled {
		return errors.New("at least one of firewall.ipv4 or firewall.ipv6 must be enabled")
	}
	if !c.Firewall.Filter.Enabled && !c.Firewall.Raw.Enabled {
		return errors.New("at least one of firewall.filter or firewall.raw must be enabled")
	}
	if c.Firewall.DenyAction != "drop" && c.Firewall.DenyAction != "reject" {
		return fmt.Errorf("firewall.deny_action must be 'drop' or 'reject', got '%s'", c.Firewall.DenyAction)
	}
	if err := c.validateRejectOptions(); err != nil {
		return err
	}
	if err := c.validateFilterOptions(); err != nil {
		return err
	}
	if err := c.validateRulePlacement(); err != nil {
		return err
	}
	return c.validateBlockOutputOptions()
}

func (c *Config) validateRulePlacement() error {
	placement := c.Firewall.RulePlacement
	if err := validateRulePlacementConfig("firewall.rule_placement", placement.withoutTableOverrides()); err != nil {
		return err
	}
	if placement.Filter != nil {
		filterPlacement := placement.ForMode("filter")
		if err := validateRulePlacementConfig("firewall.rule_placement.filter", filterPlacement.withoutTableOverrides()); err != nil {
			return err
		}
	}
	if placement.Raw != nil {
		rawPlacement := placement.ForMode("raw")
		if err := validateRulePlacementConfig("firewall.rule_placement.raw", rawPlacement.withoutTableOverrides()); err != nil {
			return err
		}
	}
	return nil
}

func validateRulePlacementConfig(path string, placement RulePlacementConfig) error {
	strategy := placement.Strategy
	if strategy == "" {
		strategy = defaultStructuredRulePlacement().Strategy
	}
	validStrategies := map[string]bool{
		RulePlacementTop:           true,
		RulePlacementBottom:        true,
		RulePlacementBeforeComment: true,
		RulePlacementAfterComment:  true,
		RulePlacementPosition:      true,
	}
	if !validStrategies[strategy] {
		return fmt.Errorf("%s.strategy invalid value %q", path, placement.Strategy)
	}

	commentMatch := placement.CommentMatch
	if commentMatch == "" {
		commentMatch = RulePlacementMatchExact
	}
	if commentMatch != RulePlacementMatchExact && commentMatch != RulePlacementMatchContains {
		return fmt.Errorf("%s.comment_match invalid value %q", path, placement.CommentMatch)
	}

	if strategy == RulePlacementBeforeComment || strategy == RulePlacementAfterComment {
		if strings.TrimSpace(placement.Comment) == "" {
			return fmt.Errorf("%s.comment is required when strategy=%q", path, strategy)
		}
		if err := validateRouterOSComment(placement.Comment); err != nil {
			return fmt.Errorf("%s.comment invalid value %q: %w", path, placement.Comment, err)
		}
		fallback := placement.Fallback
		if fallback == "" {
			fallback = RulePlacementTop
		}
		if fallback != RulePlacementTop && fallback != RulePlacementBottom {
			return fmt.Errorf("%s.fallback must be %q or %q, got %q", path, RulePlacementTop, RulePlacementBottom, placement.Fallback)
		}
	}

	if placement.Position != nil && *placement.Position < 0 {
		return fmt.Errorf("%s.position must be >= 0, got %d", path, *placement.Position)
	}
	return nil
}

// validateRouterOSComment permits printable RouterOS comment text and rejects
// control characters that cannot be safely represented in rule comments.
func validateRouterOSComment(comment string) error {
	if strings.ContainsFunc(comment, unicode.IsControl) {
		return errors.New("control characters are not allowed")
	}
	return nil
}

// validateRejectOptions checks reject-only firewall options and allowed reject reasons.
func (c *Config) validateRejectOptions() error {
	if c.Firewall.RejectWith != "" && c.Firewall.DenyAction != "reject" {
		return errors.New("firewall.reject_with requires deny_action='reject'")
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
	return nil
}

// validateFilterOptions checks optional filter-table match settings.
func (c *Config) validateFilterOptions() error {
	if c.Firewall.Filter.ConnectionState != "" {
		valid := map[string]bool{
			"established": true, "related": true, "new": true,
			"invalid": true, "untracked": true,
		}
		for s := range strings.SplitSeq(c.Firewall.Filter.ConnectionState, ",") {
			if !valid[strings.TrimSpace(s)] {
				return fmt.Errorf("firewall.filter.connection_state invalid value '%s'", s)
			}
		}
	}
	return nil
}

// validateBlockOutputOptions ensures output blocking has a concrete interface target.
func (c *Config) validateBlockOutputOptions() error {
	if c.Firewall.BlockOutput.Enabled {
		if c.Firewall.BlockOutput.Interface == "" && c.Firewall.BlockOutput.InterfaceList == "" {
			return errors.New("firewall.block_output requires interface or interface_list when enabled")
		}
	}
	return nil
}

// validateIntervals enforces minimum values for periodic background work.
func (c *Config) validateIntervals() error {
	if c.CrowdSec.ReconciliationInterval < 0 {
		return errors.New("crowdsec.reconciliation_interval must be >= 0 (0 disables)")
	}
	if c.CrowdSec.ReconciliationInterval > 0 && c.CrowdSec.ReconciliationInterval < time.Minute {
		return errors.New("crowdsec.reconciliation_interval must be >= 1m (0 disables)")
	}

	if c.Metrics.RouterOSPollInterval < 0 {
		return errors.New("metrics.routeros_poll_interval must be >= 0 (0 disables)")
	}

	return nil
}
