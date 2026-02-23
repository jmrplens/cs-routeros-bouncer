// Tests for the manager package covering helper functions, firewall rule
// comment generation/parsing, and Manager construction.
package manager

import (
	"strings"
	"testing"
	"time"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
	"github.com/jmrplens/cs-routeros-bouncer/internal/crowdsec"
)

// TestBuildRuleComment verifies that buildRuleComment produces the expected
// deterministic comment format: crowdsec-bouncer:<mode>-<chain>-<direction>-<proto>.
func TestBuildRuleComment(t *testing.T) {
	tests := []struct {
		mode, chain, direction, proto string
		want                          string
	}{
		{"filter", "input", "input", "ip", "crowdsec-bouncer:filter-input-input-v4"},
		{"filter", "input", "input", "ipv6", "crowdsec-bouncer:filter-input-input-v6"},
		{"raw", "prerouting", "input", "ip", "crowdsec-bouncer:raw-prerouting-input-v4"},
		{"raw", "prerouting", "input", "ipv6", "crowdsec-bouncer:raw-prerouting-input-v6"},
		{"filter", "forward", "output", "ip", "crowdsec-bouncer:filter-forward-output-v4"},
	}
	for _, tt := range tests {
		got := buildRuleComment(tt.mode, tt.chain, tt.direction, tt.proto)
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
		{"crowdsec-bouncer:filter-input-input-v4", "ip", "filter"},
		{"crowdsec-bouncer:raw-prerouting-input-v6", "ipv6", "raw"},
		{"crowdsec-bouncer:filter-forward-output-v4", "ip", "filter"},
	}
	for _, tt := range tests {
		proto, mode := parseRuleComment(tt.comment)
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
		proto, mode := parseRuleComment(comment)
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
	comment := buildAddressComment(d)

	if !strings.HasPrefix(comment, commentPrefix) {
		t.Errorf("comment should start with %q, got %q", commentPrefix, comment)
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
}

// TestBuildAddressCommentEmptyFields verifies that buildAddressComment
// handles decisions with empty origin and scenario gracefully.
func TestBuildAddressCommentEmptyFields(t *testing.T) {
	d := &crowdsec.Decision{
		Origin:   "",
		Scenario: "",
	}
	comment := buildAddressComment(d)

	if !strings.HasPrefix(comment, commentPrefix) {
		t.Errorf("comment should start with %q, got %q", commentPrefix, comment)
	}
}

// TestBuildAddressCommentPartialFields verifies that buildAddressComment
// includes only present fields.
func TestBuildAddressCommentPartialFields(t *testing.T) {
	d := &crowdsec.Decision{
		Origin:   "cscli",
		Scenario: "",
	}
	comment := buildAddressComment(d)
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
		comment := buildRuleComment(tt.mode, tt.chain, tt.direction, tt.proto)
		gotProto, gotMode := parseRuleComment(comment)
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
	comment := buildAddressComment(d)
	after := time.Now().UTC()

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
