// Tests for the routeros package covering duration conversion, protocol
// detection, address normalization, path helpers, struct field mapping,
// bulk script generation, and firewall path construction.
package routeros

import (
	"fmt"
	"strings"
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
		SrcAddress:       "!10.0.0.5",
		SrcAddressList:   "crowdsec-banned",
		DstAddressList:   "crowdsec6-banned",
		InInterface:      "ether1",
		InInterfaceList:  "WAN",
		OutInterface:     "ether2",
		OutInterfaceList: "LAN",
		ConnectionState:  "new,invalid",
		RejectWith:       "tcp-reset",
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
	if rule.SrcAddress != "!10.0.0.5" {
		t.Errorf("expected src_address '!10.0.0.5', got '%s'", rule.SrcAddress)
	}
	if rule.ConnectionState != "new,invalid" {
		t.Errorf("expected connection_state 'new,invalid', got '%s'", rule.ConnectionState)
	}
	if rule.RejectWith != "tcp-reset" {
		t.Errorf("expected reject_with 'tcp-reset', got '%s'", rule.RejectWith)
	}
}

// TestFirewallRuleStruct verifies that the FirewallRule struct correctly
// stores all fields needed to create a firewall rule on RouterOS.
func TestFirewallRuleStruct(t *testing.T) {
	rule := FirewallRule{
		Chain:           "forward",
		Action:          "reject",
		SrcAddress:      "!192.168.1.100",
		SrcAddressList:  "test-list",
		Comment:         "test-comment",
		PlaceBefore:     "top",
		Log:             true,
		LogPrefix:       "CS-DROP",
		InInterfaceList: "WAN",
		ConnectionState: "new",
		RejectWith:      "icmp-admin-prohibited",
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
	if rule.SrcAddress != "!192.168.1.100" {
		t.Errorf("expected SrcAddress '!192.168.1.100', got '%s'", rule.SrcAddress)
	}
	if rule.ConnectionState != "new" {
		t.Errorf("expected ConnectionState 'new', got '%s'", rule.ConnectionState)
	}
	if rule.RejectWith != "icmp-admin-prohibited" {
		t.Errorf("expected RejectWith 'icmp-admin-prohibited', got '%s'", rule.RejectWith)
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
		Action:           "reject",
		SrcAddress:       "!10.0.0.5",
		SrcAddressList:   "src-list",
		DstAddressList:   "dst-list",
		Comment:          "test",
		PlaceBefore:      "top",
		Log:              true,
		LogPrefix:        "DROP",
		InInterfaceList:  "WAN",
		OutInterfaceList: "LAN",
		ConnectionState:  "new,invalid",
		RejectWith:       "tcp-reset",
	}
	if rule.DstAddressList != "dst-list" {
		t.Errorf("expected DstAddressList 'dst-list', got %q", rule.DstAddressList)
	}
	if rule.OutInterfaceList != "LAN" {
		t.Errorf("expected OutInterfaceList 'LAN', got %q", rule.OutInterfaceList)
	}
	if rule.SrcAddress != "!10.0.0.5" {
		t.Errorf("expected SrcAddress '!10.0.0.5', got %q", rule.SrcAddress)
	}
	if rule.ConnectionState != "new,invalid" {
		t.Errorf("expected ConnectionState 'new,invalid', got %q", rule.ConnectionState)
	}
	if rule.RejectWith != "tcp-reset" {
		t.Errorf("expected RejectWith 'tcp-reset', got %q", rule.RejectWith)
	}
}

// --- buildBulkAddScript tests ---

// TestBuildBulkAddScriptIPv4Single verifies script generation for a single IPv4 entry.
func TestBuildBulkAddScriptIPv4Single(t *testing.T) {
	entries := []BulkEntry{
		{Address: "1.2.3.4", Timeout: "4h", Comment: "cs|crowdsec|ssh-bf"},
	}
	script := buildBulkAddScript("ip", "crowdsec-banned", entries)

	if !strings.Contains(script, "/ip/firewall/address-list/add") {
		t.Error("expected /ip/ prefix for IPv4")
	}
	if !strings.Contains(script, `list="crowdsec-banned"`) {
		t.Error("expected list name in script")
	}
	if !strings.Contains(script, `address="1.2.3.4"`) {
		t.Error("expected address in script")
	}
	if !strings.Contains(script, `timeout="4h"`) {
		t.Error("expected timeout in script")
	}
	if !strings.Contains(script, `:local count 0`) {
		t.Error("expected counter initialization")
	}
	if !strings.Contains(script, `:put $count`) {
		t.Error("expected count output at end")
	}
}

// TestBuildBulkAddScriptIPv6 verifies script generation uses /ipv6/ prefix
// and normalizes addresses.
func TestBuildBulkAddScriptIPv6(t *testing.T) {
	entries := []BulkEntry{
		{Address: "2001:db8::1", Timeout: "1h", Comment: "test"},
	}
	script := buildBulkAddScript("ipv6", "crowdsec6-banned", entries)

	if !strings.Contains(script, "/ipv6/firewall/address-list/add") {
		t.Error("expected /ipv6/ prefix")
	}
	// IPv6 without CIDR should get /128 via NormalizeAddress
	if !strings.Contains(script, `address="2001:db8::1/128"`) {
		t.Errorf("expected normalized IPv6 address, got script:\n%s", script)
	}
}

// TestBuildBulkAddScriptNoTimeout verifies that entries without a timeout
// omit the timeout attribute in the script.
func TestBuildBulkAddScriptNoTimeout(t *testing.T) {
	entries := []BulkEntry{
		{Address: "10.0.0.1", Timeout: "", Comment: "permanent"},
	}
	script := buildBulkAddScript("ip", "blocked", entries)

	if strings.Contains(script, "timeout") {
		t.Error("expected no timeout attribute for empty timeout")
	}
}

// TestBuildBulkAddScriptMultipleEntries verifies correct script for multiple entries.
func TestBuildBulkAddScriptMultipleEntries(t *testing.T) {
	entries := []BulkEntry{
		{Address: "1.1.1.1", Timeout: "2h", Comment: "a"},
		{Address: "2.2.2.2", Timeout: "3h", Comment: "b"},
		{Address: "3.3.3.3", Timeout: "4h", Comment: "c"},
	}
	script := buildBulkAddScript("ip", "test-list", entries)

	// Should have 3 :do { blocks
	if count := strings.Count(script, ":do {"); count != 3 {
		t.Errorf("expected 3 :do blocks, got %d", count)
	}
	// Should have 3 on-error handlers
	if count := strings.Count(script, "} on-error={}"); count != 3 {
		t.Errorf("expected 3 on-error blocks, got %d", count)
	}
}

// TestBuildBulkAddScriptEmpty verifies empty entries produce a minimal script.
func TestBuildBulkAddScriptEmpty(t *testing.T) {
	script := buildBulkAddScript("ip", "test", nil)

	if !strings.Contains(script, ":local count 0") {
		t.Error("expected counter initialization")
	}
	if !strings.Contains(script, ":put $count") {
		t.Error("expected count output")
	}
	if strings.Contains(script, "address-list/add") {
		t.Error("expected no add commands for empty entries")
	}
}

// TestBuildBulkAddScriptEscaping verifies that quotes and backslashes in
// comments are properly escaped.
func TestBuildBulkAddScriptEscaping(t *testing.T) {
	entries := []BulkEntry{
		{Address: "1.2.3.4", Timeout: "1h", Comment: `has "quotes" and \ backslash`},
	}
	script := buildBulkAddScript("ip", "test", entries)

	if !strings.Contains(script, `\"quotes\"`) {
		t.Error("expected escaped quotes in script")
	}
	if !strings.Contains(script, `\\`) {
		t.Error("expected escaped backslash in script")
	}
}

// --- NewPool tests ---

// TestNewPoolCreatesInstance verifies NewPool returns a non-nil pool.
func TestNewPoolCreatesInstance(t *testing.T) {
	cfg := config.MikroTikConfig{
		Address:  "192.168.0.1:8728",
		Username: "admin",
		Password: "secret",
	}
	p := NewPool(cfg, 4)
	if p == nil {
		t.Fatal("NewPool returned nil")
	}
	if p.size != 4 {
		t.Errorf("expected pool size 4, got %d", p.size)
	}
}

// TestNewPoolMinimumSize verifies NewPool enforces minimum size of 1.
func TestNewPoolMinimumSize(t *testing.T) {
	cfg := config.MikroTikConfig{Address: "127.0.0.1:8728"}
	p := NewPool(cfg, 0)
	if p.size != 1 {
		t.Errorf("expected pool size 1 (minimum), got %d", p.size)
	}
	p2 := NewPool(cfg, -5)
	if p2.size != 1 {
		t.Errorf("expected pool size 1 for negative input, got %d", p2.size)
	}
}

// TestPoolSizeMethod verifies Pool.Size returns configured size.
func TestPoolSizeMethod(t *testing.T) {
	cfg := config.MikroTikConfig{Address: "127.0.0.1:8728"}
	p := NewPool(cfg, 8)
	if got := p.Size(); got != 8 {
		t.Errorf("expected Size() = 8, got %d", got)
	}
}

// --- BulkEntry struct tests ---

// TestBulkEntryStruct verifies BulkEntry field storage.
func TestBulkEntryStruct(t *testing.T) {
	e := BulkEntry{
		Address: "10.0.0.1",
		Timeout: "2h",
		Comment: "cs|test|scenario",
	}
	if e.Address != "10.0.0.1" {
		t.Errorf("expected Address '10.0.0.1', got %q", e.Address)
	}
	if e.Timeout != "2h" {
		t.Errorf("expected Timeout '2h', got %q", e.Timeout)
	}
}

// --- FirewallRule attribute building tests ---

// TestFirewallRuleWantTopDetection verifies PlaceBefore="top" and "0" both
// trigger top placement logic.
func TestFirewallRuleWantTopDetection(t *testing.T) {
	tests := []struct {
		placeBefore string
		wantTop     bool
	}{
		{"top", true},
		{"0", true},
		{"", false},
		{"1", false},
		{"end", false},
	}
	for _, tt := range tests {
		rule := FirewallRule{PlaceBefore: tt.placeBefore}
		got := rule.PlaceBefore == "top" || rule.PlaceBefore == "0"
		if got != tt.wantTop {
			t.Errorf("PlaceBefore=%q: wantTop=%v, got=%v", tt.placeBefore, tt.wantTop, got)
		}
	}
}

// TestFirewallRuleInInterfaceFields verifies that input interface fields
// are correctly stored on the FirewallRule struct.
func TestFirewallRuleInInterfaceFields(t *testing.T) {
	rule := FirewallRule{
		Chain:           "input",
		Action:          "drop",
		SrcAddressList:  "banned",
		InInterface:     "ether1",
		InInterfaceList: "WAN",
		Comment:         "test",
	}
	if rule.InInterface != "ether1" {
		t.Errorf("expected InInterface 'ether1', got %q", rule.InInterface)
	}
	if rule.InInterfaceList != "WAN" {
		t.Errorf("expected InInterfaceList 'WAN', got %q", rule.InInterfaceList)
	}
}

// --- DurationToMikroTik edge cases ---

// TestDurationToMikroTikSubSecond verifies sub-second durations are truncated to 0s.
func TestDurationToMikroTikSubSecond(t *testing.T) {
	result := DurationToMikroTik(500 * time.Millisecond)
	if result != "0s" {
		t.Errorf("expected 0s for sub-second duration, got %q", result)
	}
}

// TestDurationToMikroTikLarge verifies handling of very large durations.
func TestDurationToMikroTikLarge(t *testing.T) {
	// 1000 days
	result := DurationToMikroTik(1000 * 24 * time.Hour)
	if result != "1000d" {
		t.Errorf("expected '1000d', got %q", result)
	}
}

// TestParseMikroTikUptime verifies that ParseMikroTikUptime correctly converts
// RouterOS uptime strings (e.g., "1w2d3h4m5s") into total seconds using
// table-driven subtests for various combinations of time components.
func TestParseMikroTikUptime(t *testing.T) {
	tests := []struct {
		input string
		want  float64
	}{
		{"1w2d3h4m5s", 1*604800 + 2*86400 + 3*3600 + 4*60 + 5},
		{"5s", 5},
		{"10m30s", 630},
		{"2h", 7200},
		{"3d12h", 3*86400 + 12*3600},
		{"1w", 604800},
		{"", 0},
		{"0s", 0},
		{"1w0d0h0m1s", 604801},
	}
	for _, tt := range tests {
		got := ParseMikroTikUptime(tt.input)
		if got != tt.want {
			t.Errorf("ParseMikroTikUptime(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// --- Pool.Connect tests ---

// TestPoolConnect_Success verifies Connect populates the pool when all dials succeed.
func TestPoolConnect_Success(t *testing.T) {
	p := NewPool(config.MikroTikConfig{}, 2)
	p.newClient = func(_ config.MikroTikConfig) *Client {
		mc := newMockConn()
		return &Client{
			dialFunc: func(_ config.MikroTikConfig) (RouterConn, error) {
				return mc, nil
			},
		}
	}

	if err := p.Connect(); err != nil {
		t.Fatalf("Connect() returned unexpected error: %v", err)
	}
	if len(p.conns) != 2 {
		t.Errorf("expected 2 connections in pool, got %d", len(p.conns))
	}
}

// TestPoolConnect_Error verifies Connect returns an error when dialing fails.
func TestPoolConnect_Error(t *testing.T) {
	p := NewPool(config.MikroTikConfig{}, 1)
	p.newClient = func(_ config.MikroTikConfig) *Client {
		return &Client{
			dialFunc: func(_ config.MikroTikConfig) (RouterConn, error) {
				return nil, fmt.Errorf("dial refused")
			},
		}
	}

	err := p.Connect()
	if err == nil {
		t.Fatal("Connect() should have returned an error")
	}
	if !strings.Contains(err.Error(), "dial refused") {
		t.Errorf("expected error to contain 'dial refused', got: %v", err)
	}
}

// TestPoolConnect_PartialFailure verifies Connect returns an error when
// only some connections succeed (third of three fails).
func TestPoolConnect_PartialFailure(t *testing.T) {
	var callCount int
	p := NewPool(config.MikroTikConfig{}, 3)
	p.newClient = func(_ config.MikroTikConfig) *Client {
		idx := callCount
		callCount++
		return &Client{
			dialFunc: func(_ config.MikroTikConfig) (RouterConn, error) {
				if idx == 2 {
					return nil, fmt.Errorf("connection 2 failed")
				}
				return newMockConn(), nil
			},
		}
	}

	err := p.Connect()
	if err == nil {
		t.Fatal("Connect() should have returned an error on partial failure")
	}
	if !strings.Contains(err.Error(), "connection 2 failed") {
		t.Errorf("expected error about connection 2, got: %v", err)
	}
}
