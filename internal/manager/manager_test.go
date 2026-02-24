// Tests for the manager package covering helper functions, firewall rule
// comment generation/parsing, and Manager construction.
package manager

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
	"github.com/jmrplens/cs-routeros-bouncer/internal/crowdsec"
	ros "github.com/jmrplens/cs-routeros-bouncer/internal/routeros"
)

var errMock = errors.New("mock error")

// TestBuildRuleComment verifies that buildRuleComment produces the expected
// deterministic comment format with the fixed ruleSignature suffix.
func TestBuildRuleComment(t *testing.T) {
	tests := []struct {
		mode, chain, direction, proto string
		want                          string
	}{
		{"filter", "input", "input", "ip", "crowdsec-bouncer:filter-input-input-v4 @cs-routeros-bouncer"},
		{"filter", "input", "input", "ipv6", "crowdsec-bouncer:filter-input-input-v6 @cs-routeros-bouncer"},
		{"raw", "prerouting", "input", "ip", "crowdsec-bouncer:raw-prerouting-input-v4 @cs-routeros-bouncer"},
		{"raw", "prerouting", "input", "ipv6", "crowdsec-bouncer:raw-prerouting-input-v6 @cs-routeros-bouncer"},
		{"filter", "forward", "output", "ip", "crowdsec-bouncer:filter-forward-output-v4 @cs-routeros-bouncer"},
	}
	for _, tt := range tests {
		got := buildRuleComment(defaultCommentPrefix, tt.mode, tt.chain, tt.direction, tt.proto)
		if got != tt.want {
			t.Errorf("buildRuleComment(%q,%q,%q,%q) = %q, want %q",
				tt.mode, tt.chain, tt.direction, tt.proto, got, tt.want)
		}
	}
}

// TestParseRuleCommentValid verifies that parseRuleComment correctly extracts
// the protocol and mode from a well-formed rule comment.
func TestParseRuleCommentValid(t *testing.T) {
	tests := []struct {
		comment   string
		wantProto string
		wantMode  string
	}{
		{"crowdsec-bouncer:filter-input-input-v4 @cs-routeros-bouncer", "ip", "filter"},
		{"crowdsec-bouncer:raw-prerouting-input-v6 @cs-routeros-bouncer", "ipv6", "raw"},
		{"crowdsec-bouncer:filter-forward-output-v4 @cs-routeros-bouncer", "ip", "filter"},
	}
	for _, tt := range tests {
		proto, mode := parseRuleComment(defaultCommentPrefix, tt.comment)
		if proto != tt.wantProto || mode != tt.wantMode {
			t.Errorf("parseRuleComment(%q) = (%q, %q), want (%q, %q)",
				tt.comment, proto, mode, tt.wantProto, tt.wantMode)
		}
	}
}

// TestParseRuleCommentInvalid verifies that parseRuleComment returns empty
// strings for comments that do not follow the expected format.
func TestParseRuleCommentInvalid(t *testing.T) {
	tests := []string{
		"",
		"random-comment",
		"crowdsec-bouncer",
		"other-prefix:filter-input-input-v4",
	}
	for _, comment := range tests {
		proto, mode := parseRuleComment(defaultCommentPrefix, comment)
		if proto != "" || mode != "" {
			t.Errorf("parseRuleComment(%q) should return empty, got (%q, %q)", comment, proto, mode)
		}
	}
}

// TestBuildAddressComment verifies that buildAddressComment produces a
// pipe-separated comment containing the prefix, origin, scenario, and timestamp.
func TestBuildAddressComment(t *testing.T) {
	d := &crowdsec.Decision{
		Origin:   "crowdsec",
		Scenario: "ssh-bf",
	}
	comment := buildAddressComment(defaultCommentPrefix, d)

	if !strings.HasPrefix(comment, defaultCommentPrefix) {
		t.Errorf("comment should start with %q, got %q", defaultCommentPrefix, comment)
	}
	if !strings.Contains(comment, "crowdsec") {
		t.Error("comment should contain origin")
	}
	if !strings.Contains(comment, "ssh-bf") {
		t.Error("comment should contain scenario")
	}
	if !strings.Contains(comment, "T") || !strings.Contains(comment, "Z") {
		t.Error("comment should contain UTC timestamp")
	}
	if !hasRuleSignature(comment) {
		t.Error("comment should contain fixed signature")
	}
}

// TestBuildAddressCommentEmptyFields verifies that buildAddressComment
// handles decisions with empty origin and scenario gracefully.
func TestBuildAddressCommentEmptyFields(t *testing.T) {
	d := &crowdsec.Decision{
		Origin:   "",
		Scenario: "",
	}
	comment := buildAddressComment(defaultCommentPrefix, d)

	if !strings.HasPrefix(comment, defaultCommentPrefix) {
		t.Errorf("comment should start with %q, got %q", defaultCommentPrefix, comment)
	}
}

// TestBuildAddressCommentPartialFields verifies that buildAddressComment
// includes only present fields.
func TestBuildAddressCommentPartialFields(t *testing.T) {
	d := &crowdsec.Decision{
		Origin:   "cscli",
		Scenario: "",
	}
	comment := buildAddressComment(defaultCommentPrefix, d)
	if !strings.Contains(comment, "cscli") {
		t.Error("comment should contain origin 'cscli'")
	}
}

// TestEnabledProtosBoth verifies that enabledProtos returns both "ip" and
// "ipv6" when both protocol families are enabled.
func TestEnabledProtosBoth(t *testing.T) {
	m := &Manager{
		cfg: config.Config{
			Firewall: config.FirewallConfig{
				IPv4: config.ProtoConfig{Enabled: true},
				IPv6: config.ProtoConfig{Enabled: true},
			},
		},
	}
	protos := m.enabledProtos()
	if len(protos) != 2 {
		t.Fatalf("expected 2 protocols, got %d", len(protos))
	}
	if protos[0] != "ip" || protos[1] != "ipv6" {
		t.Errorf("expected [ip, ipv6], got %v", protos)
	}
}

// TestEnabledProtosIPv4Only verifies that enabledProtos returns only "ip"
// when IPv6 is disabled.
func TestEnabledProtosIPv4Only(t *testing.T) {
	m := &Manager{
		cfg: config.Config{
			Firewall: config.FirewallConfig{
				IPv4: config.ProtoConfig{Enabled: true},
				IPv6: config.ProtoConfig{Enabled: false},
			},
		},
	}
	protos := m.enabledProtos()
	if len(protos) != 1 || protos[0] != "ip" {
		t.Errorf("expected [ip], got %v", protos)
	}
}

// TestEnabledProtosIPv6Only verifies that enabledProtos returns only "ipv6"
// when IPv4 is disabled.
func TestEnabledProtosIPv6Only(t *testing.T) {
	m := &Manager{
		cfg: config.Config{
			Firewall: config.FirewallConfig{
				IPv4: config.ProtoConfig{Enabled: false},
				IPv6: config.ProtoConfig{Enabled: true},
			},
		},
	}
	protos := m.enabledProtos()
	if len(protos) != 1 || protos[0] != "ipv6" {
		t.Errorf("expected [ipv6], got %v", protos)
	}
}

// TestEnabledProtosNone verifies that enabledProtos returns an empty slice
// when both protocols are disabled.
func TestEnabledProtosNone(t *testing.T) {
	m := &Manager{
		cfg: config.Config{
			Firewall: config.FirewallConfig{
				IPv4: config.ProtoConfig{Enabled: false},
				IPv6: config.ProtoConfig{Enabled: false},
			},
		},
	}
	protos := m.enabledProtos()
	if len(protos) != 0 {
		t.Errorf("expected empty protos, got %v", protos)
	}
}

// TestGetAddressListNameIPv4 verifies that getAddressListName returns the
// IPv4 address list name for protocol "ip".
func TestGetAddressListNameIPv4(t *testing.T) {
	m := &Manager{
		cfg: config.Config{
			Firewall: config.FirewallConfig{
				IPv4: config.ProtoConfig{AddressList: "crowdsec-banned"},
				IPv6: config.ProtoConfig{AddressList: "crowdsec6-banned"},
			},
		},
	}
	if got := m.getAddressListName("ip"); got != "crowdsec-banned" {
		t.Errorf("expected 'crowdsec-banned', got '%s'", got)
	}
}

// TestGetAddressListNameIPv6 verifies that getAddressListName returns the
// IPv6 address list name for protocol "ipv6".
func TestGetAddressListNameIPv6(t *testing.T) {
	m := &Manager{
		cfg: config.Config{
			Firewall: config.FirewallConfig{
				IPv4: config.ProtoConfig{AddressList: "crowdsec-banned"},
				IPv6: config.ProtoConfig{AddressList: "crowdsec6-banned"},
			},
		},
	}
	if got := m.getAddressListName("ipv6"); got != "crowdsec6-banned" {
		t.Errorf("expected 'crowdsec6-banned', got '%s'", got)
	}
}

// TestGetAddressListNameDefault verifies that getAddressListName returns the
// IPv4 list for any unrecognized protocol string (fallback behavior).
func TestGetAddressListNameDefault(t *testing.T) {
	m := &Manager{
		cfg: config.Config{
			Firewall: config.FirewallConfig{
				IPv4: config.ProtoConfig{AddressList: "default-v4"},
				IPv6: config.ProtoConfig{AddressList: "default-v6"},
			},
		},
	}
	if got := m.getAddressListName("unknown"); got != "default-v4" {
		t.Errorf("expected fallback to IPv4 list 'default-v4', got '%s'", got)
	}
}

// TestNewManagerCreatesInstance verifies that NewManager returns a non-nil
// Manager with the correct version string.
func TestNewManagerCreatesInstance(t *testing.T) {
	cfg := config.Config{
		MikroTik: config.MikroTikConfig{
			Address:  "127.0.0.1:8728",
			Username: "admin",
			Password: "pass",
		},
	}
	m := NewManager(cfg, "test-version")
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.version != "test-version" {
		t.Errorf("expected version 'test-version', got '%s'", m.version)
	}
}

// TestBuildRuleCommentRoundTrip verifies that buildRuleComment and
// parseRuleComment are inverse operations for common inputs.
func TestBuildRuleCommentRoundTrip(t *testing.T) {
	tests := []struct {
		mode, chain, direction, proto string
		wantProto                     string
	}{
		{"filter", "input", "input", "ip", "ip"},
		{"raw", "prerouting", "input", "ipv6", "ipv6"},
	}
	for _, tt := range tests {
		comment := buildRuleComment(defaultCommentPrefix, tt.mode, tt.chain, tt.direction, tt.proto)
		gotProto, gotMode := parseRuleComment(defaultCommentPrefix, comment)
		if gotProto != tt.wantProto {
			t.Errorf("round-trip proto: got %q, want %q (comment: %q)", gotProto, tt.wantProto, comment)
		}
		if gotMode != tt.mode {
			t.Errorf("round-trip mode: got %q, want %q (comment: %q)", gotMode, tt.mode, comment)
		}
	}
}

// TestBuildAddressCommentTimestamp verifies that the timestamp in the address
// comment is in the expected UTC format and reasonably close to now.
func TestBuildAddressCommentTimestamp(t *testing.T) {
	d := &crowdsec.Decision{Origin: "test", Scenario: "test"}
	before := time.Now().UTC()
	comment := buildAddressComment(defaultCommentPrefix, d)
	after := time.Now().UTC()

	// Strip the signature suffix before splitting by |
	comment = strings.TrimSuffix(comment, " "+ruleSignature)
	parts := strings.Split(comment, "|")
	ts := parts[len(parts)-1]
	parsed, err := time.Parse("2006-01-02T15:04:05Z", ts)
	if err != nil {
		t.Fatalf("failed to parse timestamp %q: %v", ts, err)
	}
	if parsed.Before(before.Truncate(time.Second)) || parsed.After(after.Add(time.Second)) {
		t.Errorf("timestamp %v not in expected range [%v, %v]", parsed, before, after)
	}
}

// TestBuildRuleCommentCustomPrefix verifies that a custom prefix is correctly
// used in place of the default.
func TestBuildRuleCommentCustomPrefix(t *testing.T) {
	got := buildRuleComment("my-custom", "filter", "input", "input", "ip")
	want := "my-custom:filter-input-input-v4 @cs-routeros-bouncer"
	if got != want {
		t.Errorf("buildRuleComment with custom prefix = %q, want %q", got, want)
	}
}

// TestParseRuleCommentCustomPrefix verifies that parseRuleComment works with
// a non-default prefix.
func TestParseRuleCommentCustomPrefix(t *testing.T) {
	proto, mode := parseRuleComment("my-custom", "my-custom:raw-prerouting-input-v6 @cs-routeros-bouncer")
	if proto != "ipv6" || mode != "raw" {
		t.Errorf("parseRuleComment with custom prefix = (%q, %q), want (ipv6, raw)", proto, mode)
	}
}

// TestCommentPrefixMethod verifies the Manager.commentPrefix() method
// returns the configured value or falls back to default.
func TestCommentPrefixMethod(t *testing.T) {
	cfg := config.Config{}
	m := NewManager(cfg, "test")

	if got := m.commentPrefix(); got != defaultCommentPrefix {
		t.Errorf("empty config: got %q, want %q", got, defaultCommentPrefix)
	}

	cfg.Firewall.CommentPrefix = "my-prefix"
	m2 := NewManager(cfg, "test")
	if got := m2.commentPrefix(); got != "my-prefix" {
		t.Errorf("custom config: got %q, want %q", got, "my-prefix")
	}
}

// TestHasRuleSignature verifies that hasRuleSignature correctly detects
// the fixed bouncer signature in comment strings.
func TestHasRuleSignature(t *testing.T) {
	tests := []struct {
		comment string
		want    bool
	}{
		{"crowdsec-bouncer:filter-input-input-v4 @cs-routeros-bouncer", true},
		{"my-prefix:raw-prerouting-input-v6 @cs-routeros-bouncer", true},
		{"prefix|origin|scenario|ts @cs-routeros-bouncer", true},
		{"crowdsec-bouncer:filter-input-input-v4", false},
		{"random comment without signature", false},
		{"", false},
		{"@cs-routeros-bouncer", true},
	}
	for _, tt := range tests {
		if got := hasRuleSignature(tt.comment); got != tt.want {
			t.Errorf("hasRuleSignature(%q) = %v, want %v", tt.comment, got, tt.want)
		}
	}
}

// TestBuildRuleCommentContainsSignature verifies that every comment produced
// by buildRuleComment contains the fixed ruleSignature.
func TestBuildRuleCommentContainsSignature(t *testing.T) {
	comment := buildRuleComment("any-prefix", "filter", "input", "input", "ip")
	if !hasRuleSignature(comment) {
		t.Errorf("buildRuleComment output should contain signature, got %q", comment)
	}
}

// TestBuildAddressCommentContainsSignature verifies that every comment
// produced by buildAddressComment contains the fixed ruleSignature.
func TestBuildAddressCommentContainsSignature(t *testing.T) {
	d := &crowdsec.Decision{Origin: "test", Scenario: "test"}
	comment := buildAddressComment("any-prefix", d)
	if !hasRuleSignature(comment) {
		t.Errorf("buildAddressComment output should contain signature, got %q", comment)
	}
}

// TestPollSystemMetricsSuccess verifies that pollSystemMetrics calls
// the RouterOS client methods and doesn't panic on success.
func TestPollSystemMetricsSuccess(t *testing.T) {
	mock := &mockROS{}
	cfg := config.Config{
		Metrics: config.MetricsConfig{Enabled: true, RouterOSPollInterval: 30 * time.Second},
	}
	m := newTestManager(mock, cfg)
	// Should not panic or error.
	m.pollSystemMetrics()
}

// TestPollSystemMetricsResourcesError verifies that pollSystemMetrics
// handles errors from GetSystemResources gracefully.
func TestPollSystemMetricsResourcesError(t *testing.T) {
	mock := &mockROS{systemResourcesErr: errMock}
	cfg := config.Config{
		Metrics: config.MetricsConfig{Enabled: true, RouterOSPollInterval: 30 * time.Second},
	}
	m := newTestManager(mock, cfg)
	m.pollSystemMetrics() // should not panic
}

// TestPollSystemMetricsHealthError verifies that pollSystemMetrics
// handles errors from GetSystemHealth gracefully.
func TestPollSystemMetricsHealthError(t *testing.T) {
	mock := &mockROS{systemHealthErr: errMock}
	cfg := config.Config{
		Metrics: config.MetricsConfig{Enabled: true, RouterOSPollInterval: 30 * time.Second},
	}
	m := newTestManager(mock, cfg)
	m.pollSystemMetrics() // should not panic
}

// TestPollSystemMetricsTemperatureUnavailable verifies that a negative
// temperature value (-1) does not update the gauge.
func TestPollSystemMetricsTemperatureUnavailable(t *testing.T) {
	mock := &mockROS{
		systemHealth: &ros.SystemHealth{CPUTemperature: -1},
	}
	cfg := config.Config{
		Metrics: config.MetricsConfig{Enabled: true, RouterOSPollInterval: 30 * time.Second},
	}
	m := newTestManager(mock, cfg)
	m.pollSystemMetrics() // should not update temperature gauge
}
