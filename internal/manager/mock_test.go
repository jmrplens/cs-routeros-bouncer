// Tests for the manager package covering the core orchestration methods that
// interact with the RouterOS client. These tests use a mock implementation of
// the RouterOSClient interface (defined in routeros_iface.go) to verify
// ban/unban logic, firewall rule lifecycle, and address reconciliation
// without needing a real MikroTik router.
//
// Test structure:
//   - mockROS:       configurable mock implementing RouterOSClient
//   - newTestManager: creates a Manager wired to the mock
//   - baseConfig:    returns a minimal valid config for most tests
//
// Covered methods (Manager):
//   - handleBan          — optimistic-add with "already exists" fallback
//   - handleUnban        — cache-aware find-and-remove
//   - ensureFirewallRule — idempotent create-if-not-exists
//   - createFirewallRules— multi-proto, multi-chain rule creation
//   - removeFirewallRules— best-effort cleanup with error tolerance
//   - reconcileAddresses — diff-based bulk add/remove on startup
//   - getAddressListName — proto→list mapping
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

// mockROS is a test double for RouterOSClient that records every call and
// returns pre-configured values. All methods are guarded by a mutex so the
// mock is safe for concurrent use (e.g. reconcileAddresses iterates protos
// sequentially but could be extended to parallel in the future).
type mockROS struct {
	mu sync.Mutex

	// Return values — set these before calling the method under test.
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

	// Call tracking — inspected in assertions after calling the method under test.
	connectCalls       int
	closeCalls         int
	identityCalls      int
	addAddressCalls    []addAddressCall
	findAddressCalls   []findAddressCall
	updateTimeoutCalls []updateTimeoutCall
	removeAddressCalls []removeAddressCall
	listAddressesCalls int
	bulkAddCalls       []bulkAddCall
	addRuleCalls       []addRuleCall
	removeRuleCalls    []removeRuleCall
	findRuleCalls      []findRuleCall
}

// addAddressCall captures the arguments to a single AddAddress invocation.
type addAddressCall struct {
	Proto, List, Address, Timeout, Comment string
}

// findAddressCall captures the arguments to a single FindAddress invocation.
type findAddressCall struct {
	Proto, List, Address string
}

// updateTimeoutCall captures the arguments to a single UpdateAddressTimeout invocation.
type updateTimeoutCall struct {
	Proto, ID, Timeout string
}

// removeAddressCall captures the arguments to a single RemoveAddress invocation,
// including the proto so tests can verify the correct address family was used.
type removeAddressCall struct {
	Proto, ID string
}

// bulkAddCall captures the arguments to a single BulkAddAddresses invocation.
type bulkAddCall struct {
	Proto, List string
	Entries     []ros.BulkEntry
}

// addRuleCall captures the arguments to a single AddFirewallRule invocation.
type addRuleCall struct {
	Proto, Mode string
	Rule        ros.FirewallRule
}

// removeRuleCall captures the arguments to a single RemoveFirewallRule invocation.
type removeRuleCall struct {
	Proto, Mode, ID string
}

// findRuleCall captures the arguments to a single FindFirewallRuleByComment invocation.
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
	m.mu.Lock()
	defer m.mu.Unlock()
	m.identityCalls++
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
	m.removeAddressCalls = append(m.removeAddressCalls, removeAddressCall{proto, id})
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
// Helpers
// ---------------------------------------------------------------------------

// newTestManager creates a Manager wired to the given mock with a no-op logger,
// empty caches, and the provided config. This bypasses NewManager (which creates
// a real Client and Stream) so the test has full control.
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

// baseConfig returns a minimal config with both IPv4 and IPv6 enabled,
// the "drop" deny action (required by config validation), and sensible
// address list names. Callers can override individual fields as needed.
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

// ===========================================================================
// handleBan tests
// ===========================================================================

// TestHandleBan_NilDecision verifies that a nil decision is silently ignored
// without any RouterOS API calls.
func TestHandleBan_NilDecision(t *testing.T) {
	mock := &mockROS{}
	mgr := newTestManager(mock, baseConfig())
	mgr.handleBan(nil)
	if len(mock.addAddressCalls) != 0 {
		t.Error("expected no AddAddress calls for nil decision")
	}
}

// TestHandleBan_DisabledProtoIPv4 verifies that an IPv4 ban is skipped when
// the IPv4 protocol family is disabled in configuration.
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

// TestHandleBan_DisabledProtoIPv6 verifies that an IPv6 ban is skipped when
// the IPv6 protocol family is disabled in configuration.
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

// TestHandleBan_Success verifies the happy path: a new address is added to
// the correct list, a non-empty timeout is set for Duration > 0, and the
// address is recorded in the internal cache.
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

	// Address must be present in the local cache after a successful add.
	mgr.cacheMu.RLock()
	_, inCache := mgr.addressCache["10.0.0.1"]
	mgr.cacheMu.RUnlock()
	if !inCache {
		t.Error("expected address to be in cache after successful ban")
	}
}

// TestHandleBan_IPv6Success verifies that an IPv6 decision is routed to the
// correct IPv6 address list.
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

// TestHandleBan_ZeroDurationNoTimeout verifies that a duration of 0 (permanent
// ban) results in an empty timeout string, meaning the address never expires.
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

// TestHandleBan_AlreadyExists_UpdateTimeout verifies the "already have" fallback:
// when AddAddress fails because the entry already exists and the decision has
// a non-zero duration, the manager finds the existing entry and updates its timeout.
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

// TestHandleBan_AlreadyExists_ZeroDuration verifies that when an address
// already exists and the decision has duration 0 (permanent), the manager
// does NOT attempt to find/update it — the existing permanent entry is fine.
func TestHandleBan_AlreadyExists_ZeroDuration(t *testing.T) {
	mock := &mockROS{
		addAddressErr: errors.New("failure: already have such entry"),
	}
	mgr := newTestManager(mock, baseConfig())

	mgr.handleBan(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1", Duration: 0})

	if len(mock.findAddressCalls) != 0 {
		t.Error("should not call FindAddress when duration is 0 (no timeout to update)")
	}
}

// TestHandleBan_AlreadyExists_FindReturnsNil verifies that when AddAddress
// returns "already have" but FindAddress returns nil (entry disappeared between
// the two calls, e.g. expired), the manager does not panic or crash.
func TestHandleBan_AlreadyExists_FindReturnsNil(t *testing.T) {
	mock := &mockROS{
		addAddressErr:    errors.New("failure: already have such entry"),
		findAddressEntry: nil, // disappeared between add and find
	}
	mgr := newTestManager(mock, baseConfig())

	mgr.handleBan(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1", Duration: 3600})

	// FindAddress was called but returned nil → no UpdateAddressTimeout
	if len(mock.findAddressCalls) != 1 {
		t.Fatalf("expected 1 FindAddress call, got %d", len(mock.findAddressCalls))
	}
	if len(mock.updateTimeoutCalls) != 0 {
		t.Error("should not call UpdateAddressTimeout when FindAddress returns nil")
	}
}

// TestHandleBan_AddError verifies that a non-"already have" AddAddress error
// is handled gracefully (no panic) and the address is NOT added to the cache.
func TestHandleBan_AddError(t *testing.T) {
	mock := &mockROS{addAddressErr: errors.New("connection refused")}
	mgr := newTestManager(mock, baseConfig())

	mgr.handleBan(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1"})

	mgr.cacheMu.RLock()
	_, inCache := mgr.addressCache["10.0.0.1"]
	mgr.cacheMu.RUnlock()
	if inCache {
		t.Error("address should NOT be in cache after add error")
	}
}

// ===========================================================================
// handleUnban tests
// ===========================================================================

// TestHandleUnban_NilDecision verifies that a nil decision is silently ignored.
func TestHandleUnban_NilDecision(t *testing.T) {
	mock := &mockROS{}
	mgr := newTestManager(mock, baseConfig())
	mgr.handleUnban(nil)
	if len(mock.findAddressCalls) != 0 {
		t.Error("expected no calls for nil decision")
	}
}

// TestHandleUnban_DisabledProto verifies that an unban for a disabled protocol
// family is skipped entirely.
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

// TestHandleUnban_NotInCache verifies the fast-path: if the address is not in
// the local cache, no RouterOS API call is made (it was never added or already
// expired and was cleaned up).
func TestHandleUnban_NotInCache(t *testing.T) {
	mock := &mockROS{}
	mgr := newTestManager(mock, baseConfig())

	mgr.handleUnban(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1"})

	if len(mock.findAddressCalls) != 0 {
		t.Error("expected no FindAddress call when address not in cache")
	}
}

// TestHandleUnban_InCache_FoundAndRemoved verifies the full unban flow: address
// is in cache → FindAddress locates it on the router → RemoveAddress deletes it
// → cache entry is cleared.
func TestHandleUnban_InCache_FoundAndRemoved(t *testing.T) {
	mock := &mockROS{
		findAddressEntry: &ros.AddressEntry{ID: "*7", Address: "10.0.0.1"},
	}
	mgr := newTestManager(mock, baseConfig())
	mgr.addressCache["10.0.0.1"] = struct{}{}

	mgr.handleUnban(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1"})

	if len(mock.removeAddressCalls) != 1 {
		t.Fatalf("expected 1 RemoveAddress call, got %d", len(mock.removeAddressCalls))
	}
	if mock.removeAddressCalls[0].ID != "*7" {
		t.Errorf("expected remove ID *7, got %s", mock.removeAddressCalls[0].ID)
	}

	mgr.cacheMu.RLock()
	_, inCache := mgr.addressCache["10.0.0.1"]
	mgr.cacheMu.RUnlock()
	if inCache {
		t.Error("address should be removed from cache after unban")
	}
}

// TestHandleUnban_InCache_NotFoundOnRouter verifies that when an address is in
// the local cache but not found on the router (expired naturally), the cache
// entry is cleaned up without attempting a remove call.
func TestHandleUnban_InCache_NotFoundOnRouter(t *testing.T) {
	mock := &mockROS{findAddressEntry: nil}
	mgr := newTestManager(mock, baseConfig())
	mgr.addressCache["10.0.0.1"] = struct{}{}

	mgr.handleUnban(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1"})

	if len(mock.removeAddressCalls) != 0 {
		t.Error("should not call RemoveAddress when entry not found on router")
	}

	mgr.cacheMu.RLock()
	_, inCache := mgr.addressCache["10.0.0.1"]
	mgr.cacheMu.RUnlock()
	if inCache {
		t.Error("address should be removed from cache when not found on router")
	}
}

// TestHandleUnban_FindError verifies that a FindAddress error preserves the
// cache entry (we don't know if the address is still on the router) and does
// not attempt a remove.
func TestHandleUnban_FindError(t *testing.T) {
	mock := &mockROS{findAddressErr: errors.New("timeout")}
	mgr := newTestManager(mock, baseConfig())
	mgr.addressCache["10.0.0.1"] = struct{}{}

	mgr.handleUnban(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1"})

	if len(mock.removeAddressCalls) != 0 {
		t.Error("should not try remove after find error")
	}
	mgr.cacheMu.RLock()
	_, inCache := mgr.addressCache["10.0.0.1"]
	mgr.cacheMu.RUnlock()
	if !inCache {
		t.Error("cache entry should be preserved on find error")
	}
}

// TestHandleUnban_RemoveError verifies that a RemoveAddress error preserves
// the cache entry (the address may still be on the router).
func TestHandleUnban_RemoveError(t *testing.T) {
	mock := &mockROS{
		findAddressEntry: &ros.AddressEntry{ID: "*7", Address: "10.0.0.1"},
		removeAddressErr: errors.New("connection reset"),
	}
	mgr := newTestManager(mock, baseConfig())
	mgr.addressCache["10.0.0.1"] = struct{}{}

	mgr.handleUnban(&crowdsec.Decision{Proto: "ip", Value: "10.0.0.1"})

	mgr.cacheMu.RLock()
	_, inCache := mgr.addressCache["10.0.0.1"]
	mgr.cacheMu.RUnlock()
	if !inCache {
		t.Error("cache entry should be preserved on remove error")
	}
}

// ===========================================================================
// ensureFirewallRule tests
// ===========================================================================

// TestEnsureFirewallRule_AlreadyExists verifies that when a rule with the same
// comment already exists, no new rule is created and the existing ID is stored.
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

// TestEnsureFirewallRule_Creates verifies the creation path: no existing rule
// found → AddFirewallRule is called → the returned ID is stored in ruleIDs.
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

// TestEnsureFirewallRule_FindError verifies that a FindFirewallRuleByComment
// failure is propagated as an error.
func TestEnsureFirewallRule_FindError(t *testing.T) {
	mock := &mockROS{findRuleErr: errors.New("timeout")}
	mgr := newTestManager(mock, baseConfig())

	rule := ros.FirewallRule{Comment: "test-comment"}
	err := mgr.ensureFirewallRule("ip", "filter", rule)
	if err == nil {
		t.Fatal("expected error from FindFirewallRuleByComment failure")
	}
}

// TestEnsureFirewallRule_AddError verifies that an AddFirewallRule failure
// is propagated as an error.
func TestEnsureFirewallRule_AddError(t *testing.T) {
	mock := &mockROS{addRuleErr: errors.New("out of memory")}
	mgr := newTestManager(mock, baseConfig())

	rule := ros.FirewallRule{Comment: "test-comment"}
	err := mgr.ensureFirewallRule("ip", "filter", rule)
	if err == nil {
		t.Fatal("expected error from AddFirewallRule failure")
	}
}

// ===========================================================================
// createFirewallRules tests
// ===========================================================================

// TestCreateFirewallRules_FilterOnly verifies that enabling only the filter
// table with a single chain creates rules for both IPv4 and IPv6.
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

// TestCreateFirewallRules_FilterWithOutput verifies that enabling block_output
// doubles the number of filter rules (input + output per proto).
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

// TestCreateFirewallRules_RawOnly verifies that enabling only the raw table
// creates rules for both protocol families.
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

// TestCreateFirewallRules_FilterAndRaw verifies that enabling both filter and
// raw tables creates the combined set of rules.
func TestCreateFirewallRules_FilterAndRaw(t *testing.T) {
	mock := &mockROS{addRuleID: "*R1"}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	cfg.Firewall.Raw.Enabled = true
	cfg.Firewall.Raw.Chains = []string{"prerouting"}
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// (filter input + raw prerouting) × 2 protos = 4
	if len(mock.addRuleCalls) != 4 {
		t.Errorf("expected 4 rule creations (filter+raw × ipv4+ipv6), got %d", len(mock.addRuleCalls))
	}
}

// TestCreateFirewallRules_WithInterface verifies that the block_input.interface
// config option is propagated to all input rules as in-interface.
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

// TestCreateFirewallRules_WithInterfaceList verifies that the
// block_input.interface_list config option is propagated to all input rules.
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

// TestCreateFirewallRules_TopPlacement verifies that rule_placement: "top"
// sets PlaceBefore=0 on all created rules.
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

// TestCreateFirewallRules_NoneEnabled verifies that no rules are created when
// both filter and raw tables are disabled.
func TestCreateFirewallRules_NoneEnabled(t *testing.T) {
	mock := &mockROS{}
	cfg := baseConfig()
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.addRuleCalls) != 0 {
		t.Errorf("expected 0 rule creations when nothing enabled, got %d", len(mock.addRuleCalls))
	}
}

// TestCreateFirewallRules_OutputInterfaceSettings verifies that
// block_output.interface and block_output.interface_list are applied only to
// output rules (not input rules).
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

// ===========================================================================
// removeFirewallRules tests
// ===========================================================================

// TestRemoveFirewallRules verifies that all tracked rules are removed from the
// router and the ruleIDs map is cleared afterwards.
func TestRemoveFirewallRules(t *testing.T) {
	mock := &mockROS{}
	mgr := newTestManager(mock, baseConfig())

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

// TestRemoveFirewallRules_ErrorContinues verifies that removal errors do not
// stop the cleanup of remaining rules. All tracked rules are attempted and the
// ruleIDs map is reset regardless of errors.
func TestRemoveFirewallRules_ErrorContinues(t *testing.T) {
	mock := &mockROS{removeRuleErr: errors.New("not found")}
	mgr := newTestManager(mock, baseConfig())
	mgr.ruleIDs["crowdsec-bouncer:filter-input-input-v4"] = "*A1"
	mgr.ruleIDs["crowdsec-bouncer:raw-prerouting-input-v6"] = "*A2"

	mgr.removeFirewallRules()

	if len(mock.removeRuleCalls) != 2 {
		t.Errorf("expected 2 remove attempts despite errors, got %d", len(mock.removeRuleCalls))
	}
	if len(mgr.ruleIDs) != 0 {
		t.Errorf("ruleIDs should be cleared even after errors, got %d entries", len(mgr.ruleIDs))
	}
}

// TestRemoveFirewallRules_Empty verifies that calling removeFirewallRules with
// no tracked rules is a no-op.
func TestRemoveFirewallRules_Empty(t *testing.T) {
	mock := &mockROS{}
	mgr := newTestManager(mock, baseConfig())

	mgr.removeFirewallRules()

	if len(mock.removeRuleCalls) != 0 {
		t.Errorf("expected 0 remove calls for empty ruleIDs, got %d", len(mock.removeRuleCalls))
	}
}

// TestRemoveFirewallRules_UnparseableComment verifies that a rule with an
// unparseable comment is skipped (not sent to RemoveFirewallRule) but the
// ruleIDs map is still reset.
func TestRemoveFirewallRules_UnparseableComment(t *testing.T) {
	mock := &mockROS{}
	mgr := newTestManager(mock, baseConfig())
	mgr.ruleIDs["invalid-comment-format"] = "*X1"
	mgr.ruleIDs["crowdsec-bouncer:filter-input-input-v4"] = "*A1"

	mgr.removeFirewallRules()

	// Only the valid comment should result in a remove call
	if len(mock.removeRuleCalls) != 1 {
		t.Errorf("expected 1 remove call (skipping unparseable), got %d", len(mock.removeRuleCalls))
	}
	if len(mgr.ruleIDs) != 0 {
		t.Errorf("ruleIDs should be cleared, got %d entries", len(mgr.ruleIDs))
	}
}

// ===========================================================================
// reconcileAddresses tests
// ===========================================================================

// TestReconcileAddresses_Empty verifies that nil decisions with an empty router
// list results in no bulk-add or remove calls.
func TestReconcileAddresses_Empty(t *testing.T) {
	mock := &mockROS{listAddresses: []ros.AddressEntry{}}
	mgr := newTestManager(mock, baseConfig())

	mgr.reconcileAddresses(nil)

	if len(mock.bulkAddCalls) != 0 {
		t.Error("expected no bulk add calls for nil decisions")
	}
}

// TestReconcileAddresses_AddOnly verifies that when the router list is empty
// and there are CrowdSec decisions, all addresses are bulk-added.
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

// TestReconcileAddresses_RemoveOnly verifies that addresses on the router that
// are NOT in the CrowdSec decision list are removed during reconciliation.
// Uses IPv4-only config to keep assertions simple.
func TestReconcileAddresses_RemoveOnly(t *testing.T) {
	mock := &mockROS{
		listAddresses: []ros.AddressEntry{
			{ID: "*1", Address: "10.0.0.99", Comment: "crowdsec-bouncer|old"},
		},
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	mgr.reconcileAddresses([]*crowdsec.Decision{})

	if len(mock.removeAddressCalls) != 1 {
		t.Fatalf("expected 1 RemoveAddress call, got %d", len(mock.removeAddressCalls))
	}
	if mock.removeAddressCalls[0].ID != "*1" {
		t.Errorf("expected remove ID *1, got %s", mock.removeAddressCalls[0].ID)
	}
}

// TestReconcileAddresses_ListError verifies that a ListAddresses error is
// handled gracefully: no bulk-add is attempted and the proto is skipped.
func TestReconcileAddresses_ListError(t *testing.T) {
	mock := &mockROS{listAddressesErr: errors.New("connection reset")}
	mgr := newTestManager(mock, baseConfig())

	mgr.reconcileAddresses([]*crowdsec.Decision{
		{Proto: "ip", Value: "10.0.0.1"},
	})

	if len(mock.bulkAddCalls) != 0 {
		t.Error("should not attempt bulk add after list error")
	}
}

// TestReconcileAddresses_MixedAddRemove verifies the core reconcile logic:
// addresses that should exist are added, and stale addresses are removed.
// Uses IPv4-only config to keep assertions simple.
func TestReconcileAddresses_MixedAddRemove(t *testing.T) {
	mock := &mockROS{
		listAddresses: []ros.AddressEntry{
			{ID: "*1", Address: "10.0.0.1", Comment: "crowdsec-bouncer|keep"},
			{ID: "*2", Address: "10.0.0.99", Comment: "crowdsec-bouncer|stale"},
		},
		bulkAddCount: 1,
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	decisions := []*crowdsec.Decision{
		{Proto: "ip", Value: "10.0.0.1", Origin: "cscli"}, // Already exists
		{Proto: "ip", Value: "10.0.0.2", Origin: "cscli"}, // New → add
	}

	mgr.reconcileAddresses(decisions)

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

// TestReconcileAddresses_PopulatesCache verifies that the address cache is
// populated with both existing router addresses and newly added addresses
// after reconciliation.
func TestReconcileAddresses_PopulatesCache(t *testing.T) {
	mock := &mockROS{
		listAddresses: []ros.AddressEntry{
			{ID: "*1", Address: "10.0.0.1", Comment: "crowdsec-bouncer|existing"},
		},
		bulkAddCount: 1,
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	decisions := []*crowdsec.Decision{
		{Proto: "ip", Value: "10.0.0.1", Origin: "cscli"},
		{Proto: "ip", Value: "10.0.0.2", Origin: "cscli"},
	}

	mgr.reconcileAddresses(decisions)

	mgr.cacheMu.RLock()
	_, has1 := mgr.addressCache["10.0.0.1"]
	_, has2 := mgr.addressCache["10.0.0.2"]
	mgr.cacheMu.RUnlock()

	if !has1 {
		t.Error("expected existing address 10.0.0.1 in cache")
	}
	if !has2 {
		t.Error("expected newly added address 10.0.0.2 in cache")
	}
}

// ===========================================================================
// getAddressListName tests
// ===========================================================================

// TestGetAddressListName verifies the protocol-to-list-name mapping for both
// IPv4 and IPv6.
func TestGetAddressListName(t *testing.T) {
	mgr := newTestManager(&mockROS{}, baseConfig())

	if got := mgr.getAddressListName("ip"); got != "crowdsec-banned" {
		t.Errorf("expected crowdsec-banned for ip, got %s", got)
	}
	if got := mgr.getAddressListName("ipv6"); got != "crowdsec6-banned" {
		t.Errorf("expected crowdsec6-banned for ipv6, got %s", got)
	}
}
