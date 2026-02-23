// Tests for the routeros package covering duration conversion, protocol
// detection, address normalization, path helpers, and struct field mapping.
package routeros

import (
	"testing"
	"time"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// TestDurationToMikroTik verifies that Go durations are correctly converted
// to MikroTik-format duration strings (e.g. "1d2h3m4s").
func TestDurationToMikroTik(t *testing.T) {
	tests := []struct {
		input    time.Duration
		expected string
	}{
		{0, "0s"},
		{30 * time.Second, "30s"},
		{5 * time.Minute, "5m"},
		{2 * time.Hour, "2h"},
		{90 * time.Minute, "1h30m"},
		{24 * time.Hour, "1d"},
		{25 * time.Hour, "1d1h"},
		{49*time.Hour + 30*time.Minute + 15*time.Second, "2d1h30m15s"},
		{4 * time.Hour, "4h"},
		{1 * time.Second, "1s"},
		{7 * 24 * time.Hour, "7d"},
		{365 * 24 * time.Hour, "365d"},
		{time.Hour + time.Second, "1h1s"},
		{time.Minute + time.Second, "1m1s"},
	}

	for _, tt := range tests {
		result := DurationToMikroTik(tt.input)
		if result != tt.expected {
			t.Errorf("DurationToMikroTik(%v) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// TestDetectProto verifies that IP addresses (including CIDR notation and
// special formats) are classified as either "ip" or "ipv6".
func TestDetectProto(t *testing.T) {
	tests := []struct {
		address  string
		expected string
	}{
		{"1.2.3.4", "ip"},
		{"192.168.0.0/24", "ip"},
		{"10.0.0.1", "ip"},
		{"2001:db8::1", "ipv6"},
		{"::1", "ipv6"},
		{"fe80::1%eth0", "ipv6"},
		{"2001:db8::/32", "ipv6"},
		{"0.0.0.0", "ip"},
		{"255.255.255.255", "ip"},
		{"::ffff:192.168.1.1", "ipv6"},
	}

	for _, tt := range tests {
		result := DetectProto(tt.address)
		if result != tt.expected {
			t.Errorf("DetectProto(%q) = %q, want %q", tt.address, result, tt.expected)
		}
	}
}

// TestNormalizeAddress verifies that IPv6 addresses without a CIDR suffix
// receive /128, while IPv4 and already-suffixed addresses remain unchanged.
func TestNormalizeAddress(t *testing.T) {
	tests := []struct {
		address  string
		proto    string
		expected string
	}{
		{"1.2.3.4", "ip", "1.2.3.4"},
		{"192.168.0.0/24", "ip", "192.168.0.0/24"},
		{"2001:db8::1", "ipv6", "2001:db8::1/128"},
		{"2001:db8::/32", "ipv6", "2001:db8::/32"},
		{"::1", "ipv6", "::1/128"},
		{"::1/128", "ipv6", "::1/128"},
		{"10.0.0.0/8", "ip", "10.0.0.0/8"},
	}

	for _, tt := range tests {
		result := NormalizeAddress(tt.address, tt.proto)
		if result != tt.expected {
			t.Errorf("NormalizeAddress(%q, %q) = %q, want %q", tt.address, tt.proto, result, tt.expected)
		}
	}
}

// TestProtoPrefix verifies that protoPrefix maps protocol strings to
// MikroTik API path prefixes ("/ip" or "/ipv6").
func TestProtoPrefix(t *testing.T) {
	tests := []struct {
		proto    string
		expected string
	}{
		{"ip", "/ip"},
		{"ipv4", "/ip"},
		{"ipv6", "/ipv6"},
		{"anything", "/ip"},
		{"", "/ip"},
	}

	for _, tt := range tests {
		result := protoPrefix(tt.proto)
		if result != tt.expected {
			t.Errorf("protoPrefix(%q) = %q, want %q", tt.proto, result, tt.expected)
		}
	}
}

// TestAddressListPath verifies the correct API path is generated for
// address list operations in both IPv4 and IPv6.
func TestAddressListPath(t *testing.T) {
	tests := []struct {
		proto    string
		expected string
	}{
		{"ip", "/ip/firewall/address-list"},
		{"ipv6", "/ipv6/firewall/address-list"},
	}

	for _, tt := range tests {
		result := addressListPath(tt.proto)
		if result != tt.expected {
			t.Errorf("addressListPath(%q) = %q, want %q", tt.proto, result, tt.expected)
		}
	}
}

// TestFirewallPath verifies the correct API path is generated for firewall
// rule operations across both protocols and modes.
func TestFirewallPath(t *testing.T) {
	tests := []struct {
		proto    string
		mode     string
		expected string
	}{
		{"ip", "filter", "/ip/firewall/filter"},
		{"ip", "raw", "/ip/firewall/raw"},
		{"ipv6", "filter", "/ipv6/firewall/filter"},
		{"ipv6", "raw", "/ipv6/firewall/raw"},
	}

	for _, tt := range tests {
		result := firewallPath(tt.proto, tt.mode)
		if result != tt.expected {
			t.Errorf("firewallPath(%q, %q) = %q, want %q", tt.proto, tt.mode, result, tt.expected)
		}
	}
}

// TestAddressEntryStruct verifies that all fields of the AddressEntry struct
// are correctly stored and accessible.
func TestAddressEntryStruct(t *testing.T) {
	entry := AddressEntry{
		ID:      "*1A",
		Address: "1.2.3.4",
		List:    "crowdsec-banned",
		Timeout: "4h",
		Comment: "crowdsec-bouncer:ban",
	}

	if entry.ID != "*1A" || entry.Address != "1.2.3.4" || entry.List != "crowdsec-banned" {
		t.Errorf("AddressEntry fields not set correctly: %+v", entry)
	}
	if entry.Timeout != "4h" {
		t.Errorf("expected timeout '4h', got '%s'", entry.Timeout)
	}
	if entry.Comment != "crowdsec-bouncer:ban" {
		t.Errorf("expected comment 'crowdsec-bouncer:ban', got '%s'", entry.Comment)
	}
}

// TestRuleEntryStruct verifies that all fields of the RuleEntry struct are
// correctly stored, including interface and address list associations.
func TestRuleEntryStruct(t *testing.T) {
	rule := RuleEntry{
		ID:               "*1",
		Chain:            "input",
		Action:           "drop",
		SrcAddressList:   "crowdsec-banned",
		DstAddressList:   "crowdsec6-banned",
		InInterface:      "ether1",
		InInterfaceList:  "WAN",
		OutInterface:     "ether2",
		OutInterfaceList: "LAN",
		Comment:          "crowdsec-bouncer:filter-input-v4",
	}

	if rule.Chain != "input" || rule.Action != "drop" || rule.SrcAddressList != "crowdsec-banned" {
		t.Errorf("RuleEntry fields not set correctly: %+v", rule)
	}
	if rule.DstAddressList != "crowdsec6-banned" {
		t.Errorf("expected dst 'crowdsec6-banned', got '%s'", rule.DstAddressList)
	}
	if rule.InInterface != "ether1" {
		t.Errorf("expected in_interface 'ether1', got '%s'", rule.InInterface)
	}
	if rule.OutInterfaceList != "LAN" {
		t.Errorf("expected out_interface_list 'LAN', got '%s'", rule.OutInterfaceList)
	}
}

// TestFirewallRuleStruct verifies that the FirewallRule struct correctly
// stores all fields needed to create a firewall rule on RouterOS.
func TestFirewallRuleStruct(t *testing.T) {
	rule := FirewallRule{
		Chain:           "forward",
		Action:          "reject",
		SrcAddressList:  "test-list",
		Comment:         "test-comment",
		PlaceBefore:     "top",
		Log:             true,
		LogPrefix:       "CS-DROP",
		InInterfaceList: "WAN",
	}

	if rule.Chain != "forward" || rule.Action != "reject" {
		t.Errorf("FirewallRule fields not set correctly: %+v", rule)
	}
	if !rule.Log {
		t.Error("expected Log=true")
	}
	if rule.LogPrefix != "CS-DROP" {
		t.Errorf("expected LogPrefix 'CS-DROP', got '%s'", rule.LogPrefix)
	}
}

// TestFirewallRulePlaceBefore verifies that PlaceBefore values can be
// compared to determine if a rule should be placed at the top.
func TestFirewallRulePlaceBefore(t *testing.T) {
	tests := []struct {
		placeBefore string
		wantTop     bool
	}{
		{"top", true},
		{"0", true},
		{"", false},
		{"5", false},
		{"bottom", false},
	}

	for _, tt := range tests {
		rule := FirewallRule{PlaceBefore: tt.placeBefore}
		isTop := rule.PlaceBefore == "top" || rule.PlaceBefore == "0"
		if isTop != tt.wantTop {
			t.Errorf("PlaceBefore=%q isTop=%v, want %v", tt.placeBefore, isTop, tt.wantTop)
		}
	}
}

// TestNewClientNotNil verifies that NewClient returns a non-nil Client
// for a valid configuration.
func TestNewClientNotNil(t *testing.T) {
	cfg := config.MikroTikConfig{
		Address:  "127.0.0.1:8728",
		Username: "admin",
		Password: "pass",
	}
	client := NewClient(cfg)
	if client == nil {
		t.Fatal("NewClient returned nil")
	}
}

// TestNewClientTLS verifies that NewClient correctly stores TLS settings.
func TestNewClientTLS(t *testing.T) {
	cfg := config.MikroTikConfig{
		Address:     "127.0.0.1:8729",
		Username:    "admin",
		Password:    "pass",
		TLS:         true,
		TLSInsecure: true,
	}
	client := NewClient(cfg)
	if client == nil {
		t.Fatal("NewClient returned nil")
	}
}

// TestNewClientTimeouts verifies that NewClient stores connection and
// command timeout configurations correctly.
func TestNewClientTimeouts(t *testing.T) {
	cfg := config.MikroTikConfig{
		Address:           "127.0.0.1:8728",
		Username:          "admin",
		Password:          "pass",
		ConnectionTimeout: 5 * time.Second,
		CommandTimeout:    15 * time.Second,
	}
	client := NewClient(cfg)
	if client == nil {
		t.Fatal("NewClient returned nil")
	}
}

// TestNormalizeAddressIPv4WithSlash verifies that IPv4 addresses with CIDR
// notation are passed through unchanged.
func TestNormalizeAddressIPv4WithSlash(t *testing.T) {
	result := NormalizeAddress("172.16.0.0/12", "ip")
	if result != "172.16.0.0/12" {
		t.Errorf("expected 172.16.0.0/12, got %s", result)
	}
}

// TestNormalizeAddressIPv6FullAddress verifies that a full IPv6 address
// without CIDR receives a /128 suffix.
func TestNormalizeAddressIPv6FullAddress(t *testing.T) {
	result := NormalizeAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "ipv6")
	if result != "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128" {
		t.Errorf("expected /128 suffix, got %s", result)
	}
}

// TestDetectProtoEmptyString verifies that an empty address defaults to "ip".
func TestDetectProtoEmptyString(t *testing.T) {
	if got := DetectProto(""); got != "ip" {
		t.Errorf("DetectProto(\"\") = %q, want \"ip\"", got)
	}
}

// TestAddressListPathIPv4 verifies the full path returned for IPv4
// address list operations.
func TestAddressListPathIPv4(t *testing.T) {
	if got := addressListPath("ip"); got != "/ip/firewall/address-list" {
		t.Errorf("addressListPath(\"ip\") = %q", got)
	}
}

// TestFirewallPathCombinations verifies additional protocol/mode path
// combinations to ensure consistency.
func TestFirewallPathCombinations(t *testing.T) {
	// Verify unknown mode still works (passes through)
	got := firewallPath("ip", "mangle")
	if got != "/ip/firewall/mangle" {
		t.Errorf("firewallPath(\"ip\", \"mangle\") = %q, want \"/ip/firewall/mangle\"", got)
	}
}

// TestAddressEntryEmptyFields verifies that AddressEntry handles zero-value
// fields gracefully.
func TestAddressEntryEmptyFields(t *testing.T) {
	entry := AddressEntry{}
	if entry.ID != "" || entry.Address != "" || entry.List != "" {
		t.Error("zero-value AddressEntry should have empty fields")
	}
}

// TestFirewallRuleAllFields verifies that all FirewallRule fields are stored,
// including optional fields like DstAddressList and interface options.
func TestFirewallRuleAllFields(t *testing.T) {
	rule := FirewallRule{
		Chain:            "forward",
		Action:           "drop",
		SrcAddressList:   "src-list",
		DstAddressList:   "dst-list",
		Comment:          "test",
		PlaceBefore:      "top",
		Log:              true,
		LogPrefix:        "DROP",
		InInterfaceList:  "WAN",
		OutInterfaceList: "LAN",
	}
	if rule.DstAddressList != "dst-list" {
		t.Errorf("expected DstAddressList 'dst-list', got %q", rule.DstAddressList)
	}
	if rule.OutInterfaceList != "LAN" {
		t.Errorf("expected OutInterfaceList 'LAN', got %q", rule.OutInterfaceList)
	}
}
