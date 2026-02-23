package manager

import (
	"errors"
	"sync"
	"testing"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
	"github.com/jmrplens/cs-routeros-bouncer/internal/crowdsec"
	ros "github.com/jmrplens/cs-routeros-bouncer/internal/routeros"
	"github.com/rs/zerolog"
)

// ---------------------------------------------------------------------------
// Mock RouterOS client
// ---------------------------------------------------------------------------

type mockROS struct {
	mu sync.Mutex

	// Return values
	connectErr       error
	identityName     string
	identityErr      error
	maxSessions      int
	addAddressID     string
	addAddressErr    error
	findAddressEntry *ros.AddressEntry
	findAddressErr   error
	updateTimeoutErr error
	removeAddressErr error
	listAddresses    []ros.AddressEntry
	listAddressesErr error
	bulkAddCount     int
	bulkAddErr       error

	addRuleID     string
	addRuleErr    error
	removeRuleErr error
	findRuleEntry *ros.RuleEntry
	findRuleErr   error

	// Call tracking
	connectCalls       int
	closeCalls         int
	addAddressCalls    []addAddressCall
	findAddressCalls   []findAddressCall
	updateTimeoutCalls []updateTimeoutCall
	removeAddressCalls []string // ids
	listAddressesCalls int
	bulkAddCalls       []bulkAddCall
	addRuleCalls       []addRuleCall
	removeRuleCalls    []removeRuleCall
	findRuleCalls      []findRuleCall
}

type addAddressCall struct {
	Proto, List, Address, Timeout, Comment string
}
type findAddressCall struct {
	Proto, List, Address string
}
type updateTimeoutCall struct {
	Proto, ID, Timeout string
}
type bulkAddCall struct {
	Proto, List string
	Entries     []ros.BulkEntry
}
type addRuleCall struct {
	Proto, Mode string
	Rule        ros.FirewallRule
}
type removeRuleCall struct {
	Proto, Mode, ID string
}
type findRuleCall struct {
	Proto, Mode, Comment string
}

func (m *mockROS) Connect() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectCalls++
	return m.connectErr
}

func (m *mockROS) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalls++
}

func (m *mockROS) GetAPIMaxSessions() int { return m.maxSessions }

func (m *mockROS) GetIdentity() (string, error) {
	return m.identityName, m.identityErr
}

func (m *mockROS) AddAddress(proto, list, address, timeout, comment string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addAddressCalls = append(m.addAddressCalls, addAddressCall{proto, list, address, timeout, comment})
	return m.addAddressID, m.addAddressErr
}

func (m *mockROS) FindAddress(proto, list, address string) (*ros.AddressEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findAddressCalls = append(m.findAddressCalls, findAddressCall{proto, list, address})
	return m.findAddressEntry, m.findAddressErr
}

func (m *mockROS) UpdateAddressTimeout(proto, id, timeout string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateTimeoutCalls = append(m.updateTimeoutCalls, updateTimeoutCall{proto, id, timeout})
	return m.updateTimeoutErr
}

func (m *mockROS) RemoveAddress(proto, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeAddressCalls = append(m.removeAddressCalls, id)
	return m.removeAddressErr
}

func (m *mockROS) ListAddresses(proto, list, commentPrefix string) ([]ros.AddressEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listAddressesCalls++
	return m.listAddresses, m.listAddressesErr
}

func (m *mockROS) BulkAddAddresses(proto, list string, entries []ros.BulkEntry) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bulkAddCalls = append(m.bulkAddCalls, bulkAddCall{proto, list, entries})
	return m.bulkAddCount, m.bulkAddErr
}

func (m *mockROS) AddFirewallRule(proto, mode string, rule ros.FirewallRule) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addRuleCalls = append(m.addRuleCalls, addRuleCall{proto, mode, rule})
	return m.addRuleID, m.addRuleErr
}

func (m *mockROS) RemoveFirewallRule(proto, mode, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeRuleCalls = append(m.removeRuleCalls, removeRuleCall{proto, mode, id})
	return m.removeRuleErr
}

func (m *mockROS) FindFirewallRuleByComment(proto, mode, comment string) (*ros.RuleEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findRuleCalls = append(m.findRuleCalls, findRuleCall{proto, mode, comment})
	return m.findRuleEntry, m.findRuleErr
}

// ---------------------------------------------------------------------------
// Helper: create a Manager with mock
// ---------------------------------------------------------------------------

func newTestManager(mock *mockROS, cfg config.Config) *Manager {
	return &Manager{
		cfg:          cfg,
		ros:          mock,
		logger:       zerolog.Nop(),
		version:      "test",
		ruleIDs:      make(map[string]string),
		addressCache: make(map[string]struct{}),
	}
}

func baseConfig() config.Config {
	return config.Config{
		Firewall: config.FirewallConfig{
			DenyAction: "drop",
			IPv4: config.ProtoConfig{
				Enabled:     true,
				AddressList: "crowdsec-banned",
			},
			IPv6: config.ProtoConfig{
				Enabled:     true,
				AddressList: "crowdsec6-banned",
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Tests: handleBan
// ---------------------------------------------------------------------------

func TestHandleBan_NilDecision(t *testing.T) {
	mock := &mockROS{}
	mgr := newTestManager(mock, baseConfig())
	mgr.handleBan(nil)
	if len(mock.addAddressCalls) != 0 {
		t.Error("expected no AddAddress calls for nil decision")
	}
}

func TestHandleBan_DisabledProtoIPv4(t *testing.T) {
	mock := &mockROS{}
	cfg := baseConfig()
	cfg.Firewall.IPv4.Enabled = false
	mgr := newTestManager(mock, cfg)

	mgr.handleBan(&crowdsec.Decision{Proto: "ip", Value: "1.2.3.4"})
	if len(mock.addAddressCalls) != 0 {
		t.Error("expected no AddAddress calls when IPv4 disabled")
	}
}

func TestHandleBan_DisabledProtoIPv6(t *testing.T) {
	mock := &mockROS{}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	mgr.handleBan(&crowdsec.Decision{Proto: "ipv6", Value: "::1"})
	if len(mock.addAddressCalls) != 0 {
		t.Error("expected no AddAddress calls when IPv6 disabled")
	}
}

func TestHandleBan_Success(t *testing.T) {
	mock := &mockROS{addAddressID: "*1"}
	mgr := newTestManager(mock, baseConfig())

	mgr.handleBan(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1", Duration: 3600})

	if len(mock.addAddressCalls) != 1 {
		t.Fatalf("expected 1 AddAddress call, got %d", len(mock.addAddressCalls))
	}
	call := mock.addAddressCalls[0]
	if call.Proto != "ip" || call.Address != "10.0.0.1" || call.List != "crowdsec-banned" {
		t.Errorf("unexpected AddAddress args: %+v", call)
	}
	if call.Timeout == "" {
		t.Error("expected non-empty timeout for duration > 0")
	}

	// Should be in cache
	mgr.cacheMu.RLock()
	_, inCache := mgr.addressCache["10.0.0.1"]
	mgr.cacheMu.RUnlock()
	if !inCache {
		t.Error("expected address to be in cache after successful ban")
	}
}

func TestHandleBan_IPv6Success(t *testing.T) {
	mock := &mockROS{addAddressID: "*2"}
	mgr := newTestManager(mock, baseConfig())

	mgr.handleBan(&crowdsec.Decision{Proto: "ipv6", Value: "2001:db8::1"})

	if len(mock.addAddressCalls) != 1 {
		t.Fatalf("expected 1 AddAddress call, got %d", len(mock.addAddressCalls))
	}
	if mock.addAddressCalls[0].List != "crowdsec6-banned" {
		t.Errorf("expected ipv6 list, got %s", mock.addAddressCalls[0].List)
	}
}

func TestHandleBan_ZeroDurationNoTimeout(t *testing.T) {
	mock := &mockROS{addAddressID: "*1"}
	mgr := newTestManager(mock, baseConfig())

	mgr.handleBan(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1", Duration: 0})

	if len(mock.addAddressCalls) != 1 {
		t.Fatal("expected 1 call")
	}
	if mock.addAddressCalls[0].Timeout != "" {
		t.Errorf("expected empty timeout for duration 0, got %q", mock.addAddressCalls[0].Timeout)
	}
}

func TestHandleBan_AlreadyExists_UpdateTimeout(t *testing.T) {
	mock := &mockROS{
		addAddressErr:    errors.New("failure: already have such entry"),
		findAddressEntry: &ros.AddressEntry{ID: "*5", Address: "10.0.0.1"},
	}
	mgr := newTestManager(mock, baseConfig())

	mgr.handleBan(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1", Duration: 7200})

	if len(mock.findAddressCalls) != 1 {
		t.Fatalf("expected FindAddress call for already-existing, got %d", len(mock.findAddressCalls))
	}
	if len(mock.updateTimeoutCalls) != 1 {
		t.Fatalf("expected UpdateAddressTimeout call, got %d", len(mock.updateTimeoutCalls))
	}
	if mock.updateTimeoutCalls[0].ID != "*5" {
		t.Errorf("expected update on ID *5, got %s", mock.updateTimeoutCalls[0].ID)
	}
}

func TestHandleBan_AlreadyExists_ZeroDuration(t *testing.T) {
	mock := &mockROS{
		addAddressErr: errors.New("failure: already have such entry"),
	}
	mgr := newTestManager(mock, baseConfig())

	// Duration 0 → no timeout → should NOT try to find/update
	mgr.handleBan(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1", Duration: 0})

	if len(mock.findAddressCalls) != 0 {
		t.Error("should not call FindAddress when duration is 0 (no timeout to update)")
	}
}

func TestHandleBan_AddError(t *testing.T) {
	mock := &mockROS{addAddressErr: errors.New("connection refused")}
	mgr := newTestManager(mock, baseConfig())

	// Should not panic
	mgr.handleBan(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1"})

	// Should not be in cache
	mgr.cacheMu.RLock()
	_, inCache := mgr.addressCache["10.0.0.1"]
	mgr.cacheMu.RUnlock()
	if inCache {
		t.Error("address should NOT be in cache after add error")
	}
}

// ---------------------------------------------------------------------------
// Tests: handleUnban
// ---------------------------------------------------------------------------

func TestHandleUnban_NilDecision(t *testing.T) {
	mock := &mockROS{}
	mgr := newTestManager(mock, baseConfig())
	mgr.handleUnban(nil)
	if len(mock.findAddressCalls) != 0 {
		t.Error("expected no calls for nil decision")
	}
}

func TestHandleUnban_DisabledProto(t *testing.T) {
	mock := &mockROS{}
	cfg := baseConfig()
	cfg.Firewall.IPv4.Enabled = false
	mgr := newTestManager(mock, cfg)

	mgr.handleUnban(&crowdsec.Decision{Proto: "ip", Value: "1.2.3.4"})
	if len(mock.findAddressCalls) != 0 {
		t.Error("expected no calls when proto disabled")
	}
}

func TestHandleUnban_NotInCache(t *testing.T) {
	mock := &mockROS{}
	mgr := newTestManager(mock, baseConfig())

	// Address not in cache → should skip without API call
	mgr.handleUnban(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1"})

	if len(mock.findAddressCalls) != 0 {
		t.Error("expected no FindAddress call when address not in cache")
	}
}

func TestHandleUnban_InCache_FoundAndRemoved(t *testing.T) {
	mock := &mockROS{
		findAddressEntry: &ros.AddressEntry{ID: "*7", Address: "10.0.0.1"},
	}
	mgr := newTestManager(mock, baseConfig())

	// Pre-populate cache
	mgr.addressCache["10.0.0.1"] = struct{}{}

	mgr.handleUnban(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1"})

	if len(mock.removeAddressCalls) != 1 {
		t.Fatalf("expected 1 RemoveAddress call, got %d", len(mock.removeAddressCalls))
	}
	if mock.removeAddressCalls[0] != "*7" {
		t.Errorf("expected remove ID *7, got %s", mock.removeAddressCalls[0])
	}

	// Should be removed from cache
	mgr.cacheMu.RLock()
	_, inCache := mgr.addressCache["10.0.0.1"]
	mgr.cacheMu.RUnlock()
	if inCache {
		t.Error("address should be removed from cache after unban")
	}
}

func TestHandleUnban_InCache_NotFoundOnRouter(t *testing.T) {
	mock := &mockROS{findAddressEntry: nil}
	mgr := newTestManager(mock, baseConfig())
	mgr.addressCache["10.0.0.1"] = struct{}{}

	mgr.handleUnban(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1"})

	if len(mock.removeAddressCalls) != 0 {
		t.Error("should not call RemoveAddress when entry not found on router")
	}

	// Should be removed from cache (expired on router)
	mgr.cacheMu.RLock()
	_, inCache := mgr.addressCache["10.0.0.1"]
	mgr.cacheMu.RUnlock()
	if inCache {
		t.Error("address should be removed from cache when not found on router")
	}
}

func TestHandleUnban_FindError(t *testing.T) {
	mock := &mockROS{findAddressErr: errors.New("timeout")}
	mgr := newTestManager(mock, baseConfig())
	mgr.addressCache["10.0.0.1"] = struct{}{}

	mgr.handleUnban(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1"})

	if len(mock.removeAddressCalls) != 0 {
		t.Error("should not try remove after find error")
	}
	// Cache should still contain the entry (we don't know if it's on router)
	mgr.cacheMu.RLock()
	_, inCache := mgr.addressCache["10.0.0.1"]
	mgr.cacheMu.RUnlock()
	if !inCache {
		t.Error("cache entry should be preserved on find error")
	}
}

func TestHandleUnban_RemoveError(t *testing.T) {
	mock := &mockROS{
		findAddressEntry: &ros.AddressEntry{ID: "*7", Address: "10.0.0.1"},
		removeAddressErr: errors.New("connection reset"),
	}
	mgr := newTestManager(mock, baseConfig())
	mgr.addressCache["10.0.0.1"] = struct{}{}

	mgr.handleUnban(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1"})

	// Cache should still contain the entry (remove failed)
	mgr.cacheMu.RLock()
	_, inCache := mgr.addressCache["10.0.0.1"]
	mgr.cacheMu.RUnlock()
	if !inCache {
		t.Error("cache entry should be preserved on remove error")
	}
}

// ---------------------------------------------------------------------------
// Tests: ensureFirewallRule
// ---------------------------------------------------------------------------

func TestEnsureFirewallRule_AlreadyExists(t *testing.T) {
	mock := &mockROS{
		findRuleEntry: &ros.RuleEntry{ID: "*A1", Comment: "crowdsec-bouncer:filter-input-input-v4"},
	}
	mgr := newTestManager(mock, baseConfig())

	rule := ros.FirewallRule{Comment: "crowdsec-bouncer:filter-input-input-v4"}
	if err := mgr.ensureFirewallRule("ip", "filter", rule); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.addRuleCalls) != 0 {
		t.Error("should not call AddFirewallRule when rule already exists")
	}

	mgr.ruleMu.Lock()
	id := mgr.ruleIDs["crowdsec-bouncer:filter-input-input-v4"]
	mgr.ruleMu.Unlock()
	if id != "*A1" {
		t.Errorf("expected ruleID *A1, got %s", id)
	}
}

func TestEnsureFirewallRule_Creates(t *testing.T) {
	mock := &mockROS{
		findRuleEntry: nil,
		addRuleID:     "*B2",
	}
	mgr := newTestManager(mock, baseConfig())

	rule := ros.FirewallRule{
		Chain:          "input",
		Action:         "drop",
		SrcAddressList: "crowdsec-banned",
		Comment:        "crowdsec-bouncer:filter-input-input-v4",
	}
	if err := mgr.ensureFirewallRule("ip", "filter", rule); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.addRuleCalls) != 1 {
		t.Fatalf("expected 1 AddFirewallRule call, got %d", len(mock.addRuleCalls))
	}
	if mock.addRuleCalls[0].Rule.Chain != "input" {
		t.Errorf("unexpected chain: %s", mock.addRuleCalls[0].Rule.Chain)
	}

	mgr.ruleMu.Lock()
	id := mgr.ruleIDs[rule.Comment]
	mgr.ruleMu.Unlock()
	if id != "*B2" {
		t.Errorf("expected ruleID *B2, got %s", id)
	}
}

func TestEnsureFirewallRule_FindError(t *testing.T) {
	mock := &mockROS{findRuleErr: errors.New("timeout")}
	mgr := newTestManager(mock, baseConfig())

	rule := ros.FirewallRule{Comment: "test-comment"}
	err := mgr.ensureFirewallRule("ip", "filter", rule)
	if err == nil {
		t.Fatal("expected error from FindFirewallRuleByComment failure")
	}
}

func TestEnsureFirewallRule_AddError(t *testing.T) {
	mock := &mockROS{addRuleErr: errors.New("out of memory")}
	mgr := newTestManager(mock, baseConfig())

	rule := ros.FirewallRule{Comment: "test-comment"}
	err := mgr.ensureFirewallRule("ip", "filter", rule)
	if err == nil {
		t.Fatal("expected error from AddFirewallRule failure")
	}
}

// ---------------------------------------------------------------------------
// Tests: createFirewallRules
// ---------------------------------------------------------------------------

func TestCreateFirewallRules_FilterOnly(t *testing.T) {
	mock := &mockROS{addRuleID: "*R1"}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// IPv4 input + IPv6 input = 2 rules (no output)
	if len(mock.addRuleCalls) != 2 {
		t.Errorf("expected 2 rule creations (ipv4+ipv6 input), got %d", len(mock.addRuleCalls))
	}
}

func TestCreateFirewallRules_FilterWithOutput(t *testing.T) {
	mock := &mockROS{addRuleID: "*R1"}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	cfg.Firewall.BlockOutput.Enabled = true
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// IPv4 input + IPv4 output + IPv6 input + IPv6 output = 4
	if len(mock.addRuleCalls) != 4 {
		t.Errorf("expected 4 rule creations, got %d", len(mock.addRuleCalls))
	}
}

func TestCreateFirewallRules_RawOnly(t *testing.T) {
	mock := &mockROS{addRuleID: "*R1"}
	cfg := baseConfig()
	cfg.Firewall.Raw.Enabled = true
	cfg.Firewall.Raw.Chains = []string{"prerouting"}
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// IPv4 prerouting + IPv6 prerouting = 2
	if len(mock.addRuleCalls) != 2 {
		t.Errorf("expected 2 rule creations, got %d", len(mock.addRuleCalls))
	}
}

func TestCreateFirewallRules_WithInterface(t *testing.T) {
	mock := &mockROS{addRuleID: "*R1"}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	cfg.Firewall.BlockInput.Interface = "ether1"
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, call := range mock.addRuleCalls {
		if call.Rule.InInterface != "ether1" {
			t.Errorf("expected in-interface ether1, got %q", call.Rule.InInterface)
		}
	}
}

func TestCreateFirewallRules_WithInterfaceList(t *testing.T) {
	mock := &mockROS{addRuleID: "*R1"}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	cfg.Firewall.BlockInput.InterfaceList = "WAN"
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, call := range mock.addRuleCalls {
		if call.Rule.InInterfaceList != "WAN" {
			t.Errorf("expected in-interface-list WAN, got %q", call.Rule.InInterfaceList)
		}
	}
}

func TestCreateFirewallRules_TopPlacement(t *testing.T) {
	mock := &mockROS{addRuleID: "*R1"}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	cfg.Firewall.RulePlacement = "top"
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, call := range mock.addRuleCalls {
		if call.Rule.PlaceBefore != "0" {
			t.Errorf("expected PlaceBefore=0 for top placement, got %q", call.Rule.PlaceBefore)
		}
	}
}

func TestCreateFirewallRules_NoneEnabled(t *testing.T) {
	mock := &mockROS{}
	cfg := baseConfig()
	// filter and raw both disabled (default)
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.addRuleCalls) != 0 {
		t.Errorf("expected 0 rule creations when nothing enabled, got %d", len(mock.addRuleCalls))
	}
}

func TestCreateFirewallRules_OutputInterfaceSettings(t *testing.T) {
	mock := &mockROS{addRuleID: "*R1"}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	cfg.Firewall.BlockOutput.Enabled = true
	cfg.Firewall.BlockOutput.Interface = "ether2"
	cfg.Firewall.BlockOutput.InterfaceList = "LAN"
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Find output rules
	for _, call := range mock.addRuleCalls {
		if call.Rule.Chain == "output" {
			if call.Rule.OutInterface != "ether2" {
				t.Errorf("expected out-interface ether2, got %q", call.Rule.OutInterface)
			}
			if call.Rule.OutInterfaceList != "LAN" {
				t.Errorf("expected out-interface-list LAN, got %q", call.Rule.OutInterfaceList)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: removeFirewallRules
// ---------------------------------------------------------------------------

func TestRemoveFirewallRules(t *testing.T) {
	mock := &mockROS{}
	mgr := newTestManager(mock, baseConfig())

	// Pre-populate ruleIDs
	mgr.ruleIDs["crowdsec-bouncer:filter-input-input-v4"] = "*A1"
	mgr.ruleIDs["crowdsec-bouncer:raw-prerouting-input-v4"] = "*A2"

	mgr.removeFirewallRules()

	if len(mock.removeRuleCalls) != 2 {
		t.Fatalf("expected 2 RemoveFirewallRule calls, got %d", len(mock.removeRuleCalls))
	}

	if len(mgr.ruleIDs) != 0 {
		t.Errorf("expected ruleIDs to be cleared, got %d entries", len(mgr.ruleIDs))
	}
}

func TestRemoveFirewallRules_ErrorContinues(t *testing.T) {
	mock := &mockROS{removeRuleErr: errors.New("not found")}
	mgr := newTestManager(mock, baseConfig())
	mgr.ruleIDs["crowdsec-bouncer:filter-input-input-v4"] = "*A1"
	mgr.ruleIDs["crowdsec-bouncer:raw-prerouting-input-v6"] = "*A2"

	// Should not panic even on errors
	mgr.removeFirewallRules()

	if len(mock.removeRuleCalls) != 2 {
		t.Errorf("expected 2 remove attempts despite errors, got %d", len(mock.removeRuleCalls))
	}
}

// ---------------------------------------------------------------------------
// Tests: reconcileAddresses
// ---------------------------------------------------------------------------

func TestReconcileAddresses_Empty(t *testing.T) {
	mock := &mockROS{listAddresses: []ros.AddressEntry{}}
	mgr := newTestManager(mock, baseConfig())

	mgr.reconcileAddresses(nil)

	if len(mock.bulkAddCalls) != 0 {
		t.Error("expected no bulk add calls for nil decisions")
	}
}

func TestReconcileAddresses_AddOnly(t *testing.T) {
	mock := &mockROS{
		listAddresses: []ros.AddressEntry{},
		bulkAddCount:  2,
	}
	mgr := newTestManager(mock, baseConfig())

	decisions := []*crowdsec.Decision{
		{Proto: "ip", Value: "10.0.0.1", Duration: 3600, Origin: "cscli"},
		{Proto: "ip", Value: "10.0.0.2", Duration: 3600, Origin: "cscli"},
	}

	mgr.reconcileAddresses(decisions)

	if len(mock.bulkAddCalls) != 1 {
		t.Fatalf("expected 1 BulkAddAddresses call for IPv4, got %d", len(mock.bulkAddCalls))
	}
	if len(mock.bulkAddCalls[0].Entries) != 2 {
		t.Errorf("expected 2 entries to add, got %d", len(mock.bulkAddCalls[0].Entries))
	}
}

func TestReconcileAddresses_RemoveOnly(t *testing.T) {
	mock := &mockROS{
		listAddresses: []ros.AddressEntry{
			{ID: "*1", Address: "10.0.0.99", Comment: "crowdsec-bouncer|old"},
		},
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false // Test only IPv4 for simplicity
	mgr := newTestManager(mock, cfg)

	// No decisions → the existing entry should be removed
	mgr.reconcileAddresses([]*crowdsec.Decision{})

	if len(mock.removeAddressCalls) != 1 {
		t.Fatalf("expected 1 RemoveAddress call, got %d", len(mock.removeAddressCalls))
	}
	if mock.removeAddressCalls[0] != "*1" {
		t.Errorf("expected remove ID *1, got %s", mock.removeAddressCalls[0])
	}
}

func TestReconcileAddresses_ListError(t *testing.T) {
	mock := &mockROS{listAddressesErr: errors.New("connection reset")}
	mgr := newTestManager(mock, baseConfig())

	// Should not panic on list error
	mgr.reconcileAddresses([]*crowdsec.Decision{
		{Proto: "ip", Value: "10.0.0.1"},
	})

	if len(mock.bulkAddCalls) != 0 {
		t.Error("should not attempt bulk add after list error")
	}
}

func TestReconcileAddresses_MixedAddRemove(t *testing.T) {
	mock := &mockROS{
		listAddresses: []ros.AddressEntry{
			{ID: "*1", Address: "10.0.0.1", Comment: "crowdsec-bouncer|keep"},
			{ID: "*2", Address: "10.0.0.99", Comment: "crowdsec-bouncer|stale"},
		},
		bulkAddCount: 1,
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false // Test only IPv4 for simplicity
	mgr := newTestManager(mock, cfg)

	decisions := []*crowdsec.Decision{
		{Proto: "ip", Value: "10.0.0.1", Origin: "cscli"}, // Already exists
		{Proto: "ip", Value: "10.0.0.2", Origin: "cscli"}, // New → add
	}

	mgr.reconcileAddresses(decisions)

	// Should add 10.0.0.2 and remove 10.0.0.99
	if len(mock.bulkAddCalls) != 1 {
		t.Fatalf("expected 1 BulkAdd call, got %d", len(mock.bulkAddCalls))
	}
	if len(mock.bulkAddCalls[0].Entries) != 1 {
		t.Errorf("expected 1 entry to add (10.0.0.2), got %d", len(mock.bulkAddCalls[0].Entries))
	}
	if len(mock.removeAddressCalls) != 1 {
		t.Fatalf("expected 1 RemoveAddress call (10.0.0.99), got %d", len(mock.removeAddressCalls))
	}
}

// ---------------------------------------------------------------------------
// Tests: getAddressListName
// ---------------------------------------------------------------------------

func TestGetAddressListName(t *testing.T) {
	mgr := newTestManager(&mockROS{}, baseConfig())

	if got := mgr.getAddressListName("ip"); got != "crowdsec-banned" {
		t.Errorf("expected crowdsec-banned for ip, got %s", got)
	}
	if got := mgr.getAddressListName("ipv6"); got != "crowdsec6-banned" {
		t.Errorf("expected crowdsec6-banned for ipv6, got %s", got)
	}
}
