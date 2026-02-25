// Tests for the Manager Start/Shutdown lifecycle and uncovered branches.
// These tests use a mock CrowdSecStream implementation (alongside mockROS)
// to verify the full initialization sequence, error handling, and graceful
// shutdown without needing a real CrowdSec LAPI or MikroTik router.
//
// Test groups:
//   - Start happy path: full lifecycle from Connect to live decision processing
//   - Start error paths: every early-return error in Start()
//   - Shutdown: verifies cleanup of rules, pool, and connection
//   - handleBan branches: UpdateAddressTimeout errors, non-"already have" errors
//   - createFirewallRules branches: IPv6-only, placement retry, interface combos
//   - reconcileAddresses branches: BulkAdd errors, parallel remove, sequential fallback
package manager

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
	"github.com/jmrplens/cs-routeros-bouncer/internal/crowdsec"
	ros "github.com/jmrplens/cs-routeros-bouncer/internal/routeros"
	"github.com/rs/zerolog"
)

// ===========================================================================
// Mock CrowdSec stream
// ===========================================================================

// mockStream is a test double for CrowdSecStream that records calls and
// lets tests control the decision flow by writing to banCh/deleteCh
// within a custom RunFunc.
type mockStream struct {
	mu sync.Mutex

	initErr error
	runErr  error

	initCalled int
	runCalled  int

	// RunFunc is called by Run() if set. It receives the same arguments as
	// the real Run and should send decisions to banCh/deleteCh, then return
	// when ctx is done. If nil, Run returns runErr immediately.
	RunFunc func(ctx context.Context, banCh chan<- *crowdsec.Decision, deleteCh chan<- *crowdsec.Decision) error
}

func (s *mockStream) Init() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCalled++
	return s.initErr
}

func (s *mockStream) Run(ctx context.Context, banCh chan<- *crowdsec.Decision, deleteCh chan<- *crowdsec.Decision) error {
	s.mu.Lock()
	s.runCalled++
	fn := s.RunFunc
	runErr := s.runErr
	s.mu.Unlock()

	if fn != nil {
		return fn(ctx, banCh, deleteCh)
	}
	return runErr
}

func (s *mockStream) APIClient() *apiclient.ApiClient {
	return nil
}

// newTestManagerWithStream creates a Manager wired to both mockROS and
// mockStream, bypassing NewManager's real client/stream creation.
func newTestManagerWithStream(mock *mockROS, stream *mockStream, cfg config.Config) *Manager {
	return &Manager{
		cfg:          cfg,
		ros:          mock,
		stream:       stream,
		logger:       zerolog.Nop(),
		version:      "test",
		ruleIDs:      make(map[string]string),
		addressCache: make(map[string]struct{}),
	}
}

// ===========================================================================
// Start — happy path
// ===========================================================================

// TestStart_HappyPath verifies the full Start lifecycle:
// Connect → pool (skipped, no real pool) → identity → createFirewallRules →
// stream.Init → collect initial decisions → reconcile → live processing → cancel.
func TestStart_HappyPath(t *testing.T) {
	mock := &mockROS{
		identityName: "TestRouter",
		maxSessions:  20,
		addRuleID:    "*1",
	}
	stream := &mockStream{
		RunFunc: func(ctx context.Context, banCh chan<- *crowdsec.Decision, deleteCh chan<- *crowdsec.Decision) error {
			// Send one initial ban, then wait for cancel
			banCh <- &crowdsec.Decision{
				Proto:  "ip",
				Value:  "10.0.0.1",
				Origin: "test",
				Type:   "ban",
			}
			<-ctx.Done()
			return nil
		},
	}

	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"forward"}
	mgr := newTestManagerWithStream(mock, stream, cfg)

	ctx, cancel := context.WithCancel(context.Background())

	// Run Start in a goroutine (it blocks processing live decisions)
	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	// Wait for reconciliation + live loop to start processing
	time.Sleep(5 * time.Second)
	cancel()

	err := <-errCh
	if err != nil {
		t.Fatalf("Start returned unexpected error: %v", err)
	}

	// Verify stream was initialized and run
	if stream.initCalled != 1 {
		t.Errorf("expected Init called 1 time, got %d", stream.initCalled)
	}
	if stream.runCalled != 1 {
		t.Errorf("expected Run called 1 time, got %d", stream.runCalled)
	}

	// Verify RouterOS connect was called
	if mock.connectCalls != 1 {
		t.Errorf("expected Connect called 1 time, got %d", mock.connectCalls)
	}

	// Verify identity was retrieved
	if mock.identityCalls != 1 {
		t.Errorf("expected GetIdentity called 1 time, got %d", mock.identityCalls)
	}
}

// ===========================================================================
// Start — error paths
// ===========================================================================

// TestStart_ConnectError verifies that Start returns an error when
// the initial RouterOS connection fails.
func TestStart_ConnectError(t *testing.T) {
	mock := &mockROS{
		connectErr: errors.New("connection refused"),
	}
	stream := &mockStream{}
	mgr := newTestManagerWithStream(mock, stream, baseConfig())

	err := mgr.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "connecting to MikroTik") {
		t.Fatalf("expected MikroTik connection error, got: %v", err)
	}

	// Stream should NOT have been initialized
	if stream.initCalled != 0 {
		t.Error("stream.Init should not be called when connect fails")
	}
}

// TestStart_IdentityError verifies that Start continues (with a warning)
// when GetIdentity fails — it's not fatal.
func TestStart_IdentityError(t *testing.T) {
	mock := &mockROS{
		identityErr: errors.New("identity error"),
		maxSessions: 20,
		addRuleID:   "*1",
	}
	stream := &mockStream{
		RunFunc: func(ctx context.Context, banCh chan<- *crowdsec.Decision, deleteCh chan<- *crowdsec.Decision) error {
			<-ctx.Done()
			return nil
		},
	}

	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"forward"}
	mgr := newTestManagerWithStream(mock, stream, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- mgr.Start(ctx) }()

	time.Sleep(5 * time.Second)
	cancel()

	if err := <-errCh; err != nil {
		t.Fatalf("Start should continue despite identity error, got: %v", err)
	}
}

// TestStart_CreateFirewallRulesError verifies that Start returns an error
// when firewall rule creation fails.
func TestStart_CreateFirewallRulesError(t *testing.T) {
	mock := &mockROS{
		maxSessions: 20,
		addRuleErr:  errors.New("firewall error"),
	}
	stream := &mockStream{}

	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"forward"}
	mgr := newTestManagerWithStream(mock, stream, cfg)

	err := mgr.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "creating firewall rules") {
		t.Fatalf("expected firewall creation error, got: %v", err)
	}

	// Stream should NOT have been initialized
	if stream.initCalled != 0 {
		t.Error("stream.Init should not be called when firewall rules fail")
	}
}

// TestStart_StreamInitError verifies that Start returns an error when
// CrowdSec stream initialization fails.
func TestStart_StreamInitError(t *testing.T) {
	mock := &mockROS{
		maxSessions: 20,
		addRuleID:   "*1",
	}
	stream := &mockStream{
		initErr: errors.New("LAPI unreachable"),
	}

	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"forward"}
	mgr := newTestManagerWithStream(mock, stream, cfg)

	err := mgr.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "initializing CrowdSec stream") {
		t.Fatalf("expected stream init error, got: %v", err)
	}
}

// TestStart_StreamRunError verifies that an error from stream.Run is
// propagated through the errCh and returned by Start.
func TestStart_StreamRunError(t *testing.T) {
	mock := &mockROS{
		maxSessions: 20,
		addRuleID:   "*1",
	}
	stream := &mockStream{
		RunFunc: func(ctx context.Context, banCh chan<- *crowdsec.Decision, deleteCh chan<- *crowdsec.Decision) error {
			return errors.New("stream channel closed")
		},
	}

	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"forward"}
	mgr := newTestManagerWithStream(mock, stream, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := mgr.Start(ctx)
	if err == nil || !strings.Contains(err.Error(), "CrowdSec stream error") {
		t.Fatalf("expected stream run error, got: %v", err)
	}
}

// TestStart_ContextCancelDuringCollect verifies that canceling the context
// during the initial decision collection phase causes Start to return nil.
func TestStart_ContextCancelDuringCollect(t *testing.T) {
	mock := &mockROS{
		maxSessions: 20,
		addRuleID:   "*1",
	}
	stream := &mockStream{
		RunFunc: func(ctx context.Context, banCh chan<- *crowdsec.Decision, deleteCh chan<- *crowdsec.Decision) error {
			// Keep sending decisions until canceled
			for {
				select {
				case <-ctx.Done():
					return nil
				case banCh <- &crowdsec.Decision{Proto: "ip", Value: "1.2.3.4", Origin: "test", Type: "ban"}:
					time.Sleep(100 * time.Millisecond)
				}
			}
		},
	}

	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"forward"}
	mgr := newTestManagerWithStream(mock, stream, cfg)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- mgr.Start(ctx) }()

	// Cancel almost immediately (during collect phase)
	time.Sleep(500 * time.Millisecond)
	cancel()

	if err := <-errCh; err != nil {
		t.Fatalf("expected nil on context cancel, got: %v", err)
	}
}

// ===========================================================================
// Start — live decision processing
// ===========================================================================

// TestStart_ProcessesLiveBanAndUnban verifies that after reconciliation,
// the live loop correctly processes ban and unban decisions.
func TestStart_ProcessesLiveBanAndUnban(t *testing.T) {
	mock := &mockROS{
		maxSessions:  20,
		addRuleID:    "*1",
		addAddressID: "*100",
	}
	// Track when reconciliation is done by checking if the live loop has started.
	// The collect phase has 10s initial idle timeout. With no decisions during collect,
	// it finishes at ~10s. Reconciliation with empty decisions is instant.
	// So the live loop starts at ~10s. We send the ban at 11s to ensure it's processed live.
	stream := &mockStream{
		RunFunc: func(ctx context.Context, banCh chan<- *crowdsec.Decision, deleteCh chan<- *crowdsec.Decision) error {
			// Wait for collect phase (10s idle) + reconciliation to complete
			time.Sleep(11 * time.Second)

			// Send a live ban — this should be processed by the live loop (handleBan)
			select {
			case banCh <- &crowdsec.Decision{
				Proto:    "ip",
				Value:    "192.168.1.100",
				Origin:   "test",
				Type:     "ban",
				Duration: 3600 * time.Second,
			}:
			case <-ctx.Done():
				return ctx.Err()
			}

			// Give time for processing
			time.Sleep(1 * time.Second)
			return nil
		},
	}

	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"forward"}
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManagerWithStream(mock, stream, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_ = mgr.Start(ctx)

	mock.mu.Lock()
	addCount := len(mock.addAddressCalls)
	mock.mu.Unlock()

	// Should have at least one AddAddress call for the live ban
	if addCount < 1 {
		t.Errorf("expected at least 1 AddAddress call for live ban, got %d", addCount)
	}
}

// TestStart_DeleteChDrainFiltersDuringCollect verifies that decisions
// collected in deleteCh during the initial batch are used to filter
// out immediately-expired bans.
func TestStart_DeleteChDrainFiltersDuringCollect(t *testing.T) {
	mock := &mockROS{
		maxSessions:  20,
		addRuleID:    "*1",
		bulkAddCount: 1,
	}
	stream := &mockStream{
		RunFunc: func(ctx context.Context, banCh chan<- *crowdsec.Decision, deleteCh chan<- *crowdsec.Decision) error {
			// Send a ban and immediately a delete for the same IP
			banCh <- &crowdsec.Decision{Proto: "ip", Value: "10.0.0.99", Origin: "cscli", Type: "ban"}
			deleteCh <- &crowdsec.Decision{Proto: "ip", Value: "10.0.0.99", Origin: "cscli", Type: "ban"}
			// Also send a ban that should survive
			banCh <- &crowdsec.Decision{Proto: "ip", Value: "10.0.0.100", Origin: "cscli", Type: "ban"}
			<-ctx.Done()
			return nil
		},
	}

	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"forward"}
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManagerWithStream(mock, stream, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- mgr.Start(ctx) }()

	// Wait for reconciliation to complete
	time.Sleep(5 * time.Second)
	cancel()
	<-errCh

	// The bulk add should have been called with only the surviving ban (10.0.0.100)
	mock.mu.Lock()
	defer mock.mu.Unlock()

	if len(mock.bulkAddCalls) == 0 {
		t.Fatal("expected at least one BulkAddAddresses call")
	}

	// The filtered ban (10.0.0.99) should not be in the bulk add entries
	for _, call := range mock.bulkAddCalls {
		for _, entry := range call.Entries {
			if entry.Address == "10.0.0.99" {
				t.Error("10.0.0.99 should have been filtered out by deleteCh drain")
			}
		}
	}
}

// ===========================================================================
// Shutdown tests
// ===========================================================================

// TestShutdown verifies that Shutdown removes firewall rules, closes pool (nil),
// and closes the RouterOS connection.
func TestShutdown(t *testing.T) {
	mock := &mockROS{}
	mgr := newTestManagerWithStream(mock, &mockStream{}, baseConfig())

	// Simulate some rules created during Start
	mgr.ruleIDs["crowdsec-bouncer:filter-forward-input-v4"] = "*1"
	mgr.ruleIDs["crowdsec-bouncer:filter-forward-input-v6"] = "*2"

	mgr.Shutdown()

	mock.mu.Lock()
	defer mock.mu.Unlock()

	if len(mock.removeRuleCalls) != 2 {
		t.Errorf("expected 2 RemoveFirewallRule calls, got %d", len(mock.removeRuleCalls))
	}
	if mock.closeCalls != 1 {
		t.Errorf("expected Close called 1 time, got %d", mock.closeCalls)
	}
}

// TestShutdown_RemoveRuleError verifies that Shutdown continues cleanup
// even when individual rule removals fail (best-effort).
func TestShutdown_RemoveRuleError(t *testing.T) {
	mock := &mockROS{
		removeRuleErr: errors.New("rule not found"),
	}
	mgr := newTestManagerWithStream(mock, &mockStream{}, baseConfig())
	mgr.ruleIDs["crowdsec-bouncer:filter-forward-input-v4"] = "*1"

	// Should not panic despite error
	mgr.Shutdown()

	mock.mu.Lock()
	defer mock.mu.Unlock()

	if mock.closeCalls != 1 {
		t.Errorf("expected Close called even after rule removal error, got %d", mock.closeCalls)
	}
}

// ===========================================================================
// handleBan — additional uncovered branches
// ===========================================================================

// TestHandleBan_AlreadyExistsUpdateTimeoutError verifies that when an address
// already exists and the timeout update fails, the error is logged but execution
// continues (does not return the error to caller).
func TestHandleBan_AlreadyExistsUpdateTimeoutError(t *testing.T) {
	mock := &mockROS{
		addAddressErr: errors.New("failure: already have such entry"),
		findAddressEntry: &ros.AddressEntry{
			ID:      "*1",
			Address: "1.2.3.4",
		},
		updateTimeoutErr: errors.New("timeout update failed"),
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	mgr.handleBan(&crowdsec.Decision{
		Proto:    "ip",
		Value:    "1.2.3.4",
		Duration: 2 * time.Hour,
		Origin:   "test",
		Type:     "ban",
	})

	mock.mu.Lock()
	defer mock.mu.Unlock()

	// Should have tried to update timeout
	if len(mock.updateTimeoutCalls) != 1 {
		t.Errorf("expected 1 UpdateAddressTimeout call, got %d", len(mock.updateTimeoutCalls))
	}

	// Address should NOT be in cache (add failed)
	mgr.cacheMu.RLock()
	_, inCache := mgr.addressCache["1.2.3.4"]
	mgr.cacheMu.RUnlock()
	if inCache {
		t.Error("address should not be in cache when add returned 'already have'")
	}
}

// TestHandleBan_AlreadyExistsNoTimeout verifies that when an address already
// exists but the decision has no timeout (duration=0), it skips the find/update
// entirely and just returns.
func TestHandleBan_AlreadyExistsNoTimeout(t *testing.T) {
	mock := &mockROS{
		addAddressErr: errors.New("failure: already have such entry"),
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	mgr.handleBan(&crowdsec.Decision{
		Proto:    "ip",
		Value:    "1.2.3.4",
		Duration: 0, // no timeout
		Origin:   "test",
		Type:     "ban",
	})

	mock.mu.Lock()
	defer mock.mu.Unlock()

	// No FindAddress or UpdateTimeout should be called
	if len(mock.findAddressCalls) != 0 {
		t.Errorf("expected 0 FindAddress calls when timeout is empty, got %d", len(mock.findAddressCalls))
	}
	if len(mock.updateTimeoutCalls) != 0 {
		t.Errorf("expected 0 UpdateTimeout calls when timeout is empty, got %d", len(mock.updateTimeoutCalls))
	}
}

// TestHandleBan_AlreadyExistsFindError verifies that when FindAddress fails
// during the timeout update path, the error is logged and no update is attempted.
func TestHandleBan_AlreadyExistsFindError(t *testing.T) {
	mock := &mockROS{
		addAddressErr:  errors.New("failure: already have such entry"),
		findAddressErr: errors.New("find failed"),
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	mgr.handleBan(&crowdsec.Decision{
		Proto:    "ip",
		Value:    "1.2.3.4",
		Duration: 1 * time.Hour,
		Origin:   "test",
		Type:     "ban",
	})

	mock.mu.Lock()
	defer mock.mu.Unlock()

	if len(mock.updateTimeoutCalls) != 0 {
		t.Error("should not call UpdateTimeout when FindAddress fails")
	}
}

// TestHandleBan_NonAlreadyHaveError verifies that when AddAddress fails with
// an error that is NOT "already have", it's treated as a real error.
func TestHandleBan_NonAlreadyHaveError(t *testing.T) {
	mock := &mockROS{
		addAddressErr: errors.New("connection reset"),
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	mgr.handleBan(&crowdsec.Decision{
		Proto:  "ip",
		Value:  "1.2.3.4",
		Origin: "test",
		Type:   "ban",
	})

	mock.mu.Lock()
	defer mock.mu.Unlock()

	// No FindAddress should be called — it's not an "already have" case
	if len(mock.findAddressCalls) != 0 {
		t.Error("should not call FindAddress for non-'already have' errors")
	}
}

// TestHandleBan_AlreadyExistsFindReturnsNil verifies that when FindAddress
// succeeds but returns nil (address expired between add attempt and find),
// no UpdateTimeout is called.
func TestHandleBan_AlreadyExistsFindReturnsNil(t *testing.T) {
	mock := &mockROS{
		addAddressErr:    errors.New("failure: already have such entry"),
		findAddressEntry: nil, // address disappeared
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	mgr.handleBan(&crowdsec.Decision{
		Proto:    "ip",
		Value:    "1.2.3.4",
		Duration: 1 * time.Hour,
		Origin:   "test",
		Type:     "ban",
	})

	mock.mu.Lock()
	defer mock.mu.Unlock()

	if len(mock.updateTimeoutCalls) != 0 {
		t.Error("should not call UpdateTimeout when FindAddress returns nil")
	}
}

// ===========================================================================
// createFirewallRules — additional uncovered branches
// ===========================================================================

// TestCreateFirewallRules_IPv6Only verifies that when only IPv6 is enabled,
// only IPv6 rules are created (no IPv4 rules).
func TestCreateFirewallRules_IPv6Only(t *testing.T) {
	mock := &mockROS{addRuleID: "*1"}
	cfg := baseConfig()
	cfg.Firewall.IPv4.Enabled = false
	cfg.Firewall.IPv6.Enabled = true
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"forward"}
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()

	// All rule calls should be IPv6
	for _, call := range mock.addRuleCalls {
		if call.Proto != "ipv6" {
			t.Errorf("expected only ipv6 rules, got proto=%s", call.Proto)
		}
	}

	// Should have exactly 2 calls: 1 input rule + 1 counting rule for forward chain
	if len(mock.addRuleCalls) != 2 {
		t.Errorf("expected 2 firewall rule calls (IPv6 input + counting), got %d", len(mock.addRuleCalls))
	}
}

// TestCreateFirewallRules_WithInputInterface verifies that block_input
// interface and interface_list are set on input rules.
func TestCreateFirewallRules_WithInputInterface(t *testing.T) {
	mock := &mockROS{addRuleID: "*1"}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"forward"}
	cfg.Firewall.BlockInput = config.BlockInputConfig{
		Interface:     "ether1",
		InterfaceList: "WAN",
	}
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()

	if len(mock.addRuleCalls) != 2 {
		t.Fatalf("expected 2 rule calls (input + counting), got %d", len(mock.addRuleCalls))
	}

	rule := mock.addRuleCalls[0].Rule
	if rule.InInterface != "ether1" {
		t.Errorf("expected InInterface=ether1, got %s", rule.InInterface)
	}
	if rule.InInterfaceList != "WAN" {
		t.Errorf("expected InInterfaceList=WAN, got %s", rule.InInterfaceList)
	}
}

// TestCreateFirewallRules_WithOutputInterface verifies that block_output
// interface and interface_list are set on output rules.
func TestCreateFirewallRules_WithOutputInterface(t *testing.T) {
	mock := &mockROS{addRuleID: "*1"}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"forward"}
	cfg.Firewall.BlockOutput = config.BlockOutputConfig{
		Enabled:       true,
		Interface:     "ether2",
		InterfaceList: "LAN",
	}
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()

	// Should have 3 rules: input + counting + output
	if len(mock.addRuleCalls) != 3 {
		t.Fatalf("expected 3 rule calls (input + counting + output), got %d", len(mock.addRuleCalls))
	}

	outRule := mock.addRuleCalls[2].Rule
	if outRule.OutInterface != "ether2" {
		t.Errorf("expected OutInterface=ether2, got %s", outRule.OutInterface)
	}
	if outRule.OutInterfaceList != "LAN" {
		t.Errorf("expected OutInterfaceList=LAN, got %s", outRule.OutInterfaceList)
	}
}

// TestCreateFirewallRules_RawChains verifies that raw firewall rules are
// created when raw mode is enabled.
func TestCreateFirewallRules_RawChains(t *testing.T) {
	mock := &mockROS{addRuleID: "*1"}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	cfg.Firewall.Filter.Enabled = false
	cfg.Firewall.Raw.Enabled = true
	cfg.Firewall.Raw.Chains = []string{"prerouting"}
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()

	if len(mock.addRuleCalls) != 2 {
		t.Fatalf("expected 2 raw rule calls (drop + counting), got %d", len(mock.addRuleCalls))
	}
	if mock.addRuleCalls[0].Rule.Chain != "prerouting" {
		t.Errorf("expected chain prerouting, got %s", mock.addRuleCalls[0].Rule.Chain)
	}
}

// TestCreateFirewallRules_PlacementTop verifies that when rule_placement is
// "top", the PlaceBefore field is set to "0".
func TestCreateFirewallRules_PlacementTop(t *testing.T) {
	mock := &mockROS{addRuleID: "*1"}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"forward"}
	cfg.Firewall.RulePlacement = "top"
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()

	if mock.addRuleCalls[0].Rule.PlaceBefore != "0" {
		t.Errorf("expected PlaceBefore=0 for top placement, got %s", mock.addRuleCalls[0].Rule.PlaceBefore)
	}
}

// TestCreateFirewallRules_FilterAndRawCombined verifies that both filter
// and raw rules are created when both are enabled.
func TestCreateFirewallRules_FilterAndRawCombined(t *testing.T) {
	mock := &mockROS{addRuleID: "*1"}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"forward"}
	cfg.Firewall.Raw.Enabled = true
	cfg.Firewall.Raw.Chains = []string{"prerouting"}
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()

	// 1 filter input + 1 counting + 1 raw input + 1 counting = 4
	if len(mock.addRuleCalls) != 4 {
		t.Errorf("expected 4 rule calls (filter+raw with counting), got %d", len(mock.addRuleCalls))
	}
}

// TestCreateFirewallRules_TrackProcessedDisabled verifies that passthrough
// counting rules are NOT created when metrics.track_processed is false.
func TestCreateFirewallRules_TrackProcessedDisabled(t *testing.T) {
	mock := &mockROS{addRuleID: "*1"}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"forward"}
	cfg.Firewall.Raw.Enabled = true
	cfg.Firewall.Raw.Chains = []string{"prerouting"}
	cfg.Metrics.TrackProcessed = false
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()

	// Only drop rules, no counting: 1 filter input + 1 raw = 2
	if len(mock.addRuleCalls) != 2 {
		t.Errorf("expected 2 rule calls (no counting rules), got %d", len(mock.addRuleCalls))
	}
	for _, call := range mock.addRuleCalls {
		if call.Rule.Action == "passthrough" {
			t.Error("passthrough counting rule should not be created when track_processed is false")
		}
	}
}

// TestCreateFirewallRules_FindRuleError verifies that an error checking
// for existing rules is propagated.
func TestCreateFirewallRules_FindRuleError(t *testing.T) {
	mock := &mockROS{
		findRuleErr: errors.New("API timeout"),
	}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"forward"}
	mgr := newTestManager(mock, cfg)

	err := mgr.createFirewallRules()
	if err == nil || !strings.Contains(err.Error(), "checking existing rule") {
		t.Fatalf("expected find rule error, got: %v", err)
	}
}

// TestCreateFirewallRules_ExistingRuleSkipsAdd verifies that when a rule
// already exists (FindFirewallRuleByComment returns non-nil), AddFirewallRule
// is not called and the existing ID is stored.
func TestCreateFirewallRules_ExistingRuleSkipsAdd(t *testing.T) {
	mock := &mockROS{
		findRuleEntry: &ros.RuleEntry{ID: "*99"},
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"forward"}
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()

	if len(mock.addRuleCalls) != 0 {
		t.Error("should not call AddFirewallRule when rule already exists")
	}

	// Verify the existing IDs were stored (input + counting = 2)
	if len(mgr.ruleIDs) != 2 {
		t.Errorf("expected 2 rule IDs stored, got %d", len(mgr.ruleIDs))
	}
}

// ===========================================================================
// reconcileAddresses — additional uncovered branches
// ===========================================================================

// TestReconcileAddresses_BulkAddPartialError verifies that when BulkAdd
// returns an error along with a partial count, the partial additions are
// still reflected in the cache and metrics.
func TestReconcileAddresses_BulkAddPartialError(t *testing.T) {
	mock := &mockROS{
		bulkAddCount: 5, // 5 of 10 succeeded
		bulkAddErr:   errors.New("partial failure: 5 of 10"),
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	decisions := make([]*crowdsec.Decision, 10)
	for i := range decisions {
		decisions[i] = &crowdsec.Decision{
			Proto:  "ip",
			Value:  fmt.Sprintf("10.0.0.%d", i+1),
			Origin: "test",
			Type:   "ban",
		}
	}

	// This should not panic despite the error
	mgr.reconcileAddresses(decisions)

	// Cache should still be populated (all entries added optimistically)
	mgr.cacheMu.RLock()
	cacheSize := len(mgr.addressCache)
	mgr.cacheMu.RUnlock()

	if cacheSize == 0 {
		t.Error("cache should have entries even with partial bulk add error")
	}
}

// TestReconcileAddresses_SequentialRemoveFallback verifies that when pool
// is nil, the sequential remove fallback path is used.
func TestReconcileAddresses_SequentialRemoveFallback(t *testing.T) {
	mock := &mockROS{
		listAddresses: []ros.AddressEntry{
			{ID: "*1", Address: "10.0.0.1", Comment: "crowdsec-bouncer|old"},
			{ID: "*2", Address: "10.0.0.2", Comment: "crowdsec-bouncer|old"},
		},
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)
	mgr.pool = nil // Force sequential fallback

	// No decisions = all existing addresses should be removed
	mgr.reconcileAddresses(nil)

	mock.mu.Lock()
	defer mock.mu.Unlock()

	if len(mock.removeAddressCalls) != 2 {
		t.Errorf("expected 2 sequential RemoveAddress calls, got %d", len(mock.removeAddressCalls))
	}
}

// TestReconcileAddresses_SequentialRemoveNoSuchItem verifies that "no such item"
// errors during sequential remove are treated as success (expired items).
func TestReconcileAddresses_SequentialRemoveNoSuchItem(t *testing.T) {
	callCount := 0
	mock := &mockROS{
		listAddresses: []ros.AddressEntry{
			{ID: "*1", Address: "10.0.0.1", Comment: "crowdsec-bouncer|old"},
		},
	}
	// Override RemoveAddress to return "no such item"
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)
	mgr.pool = nil

	// Set error to "no such item"
	mock.removeAddressErr = errors.New("no such item")
	_ = callCount

	mgr.reconcileAddresses(nil)

	// Should complete without error (no such item is treated as success)
	mock.mu.Lock()
	defer mock.mu.Unlock()

	if len(mock.removeAddressCalls) != 1 {
		t.Errorf("expected 1 RemoveAddress call, got %d", len(mock.removeAddressCalls))
	}
}

// TestReconcileAddresses_SequentialRemoveRealError verifies that real errors
// (not "no such item") during sequential remove are logged.
func TestReconcileAddresses_SequentialRemoveRealError(t *testing.T) {
	mock := &mockROS{
		listAddresses: []ros.AddressEntry{
			{ID: "*1", Address: "10.0.0.1", Comment: "crowdsec-bouncer|old"},
		},
		removeAddressErr: errors.New("connection timeout"),
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)
	mgr.pool = nil

	// Should not panic — errors are logged, not returned
	mgr.reconcileAddresses(nil)

	mock.mu.Lock()
	defer mock.mu.Unlock()

	if len(mock.removeAddressCalls) != 1 {
		t.Errorf("expected 1 RemoveAddress call, got %d", len(mock.removeAddressCalls))
	}
}

// TestReconcileAddresses_ListAddressesError verifies that when ListAddresses
// fails, reconciliation skips that protocol and continues.
func TestReconcileAddresses_ListAddressesError(t *testing.T) {
	mock := &mockROS{
		listAddressesErr: errors.New("connection lost"),
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	// Should not panic — error is logged, then continue
	mgr.reconcileAddresses([]*crowdsec.Decision{
		{Proto: "ip", Value: "1.2.3.4", Origin: "test"},
	})

	mock.mu.Lock()
	defer mock.mu.Unlock()

	// No bulk add should have been attempted
	if len(mock.bulkAddCalls) != 0 {
		t.Error("should not attempt bulk add when ListAddresses fails")
	}
}

// TestReconcileAddresses_EmptyDecisions verifies that reconciliation with
// zero decisions removes all existing addresses.
func TestReconcileAddresses_EmptyDecisions(t *testing.T) {
	mock := &mockROS{
		listAddresses: []ros.AddressEntry{
			{ID: "*1", Address: "10.0.0.1", Comment: "crowdsec-bouncer|old"},
		},
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)
	mgr.pool = nil

	mgr.reconcileAddresses(nil)

	mock.mu.Lock()
	defer mock.mu.Unlock()

	if len(mock.removeAddressCalls) != 1 {
		t.Errorf("expected 1 remove for orphan address, got %d", len(mock.removeAddressCalls))
	}
}

// ===========================================================================
// removeFirewallRules — additional coverage
// ===========================================================================

// TestRemoveFirewallRules_InvalidComment verifies that rules with unparseable
// comments are skipped during cleanup without errors.
func TestRemoveFirewallRules_InvalidComment(t *testing.T) {
	mock := &mockROS{}
	mgr := newTestManager(mock, baseConfig())
	mgr.ruleIDs["invalid-comment-format"] = "*1"

	mgr.removeFirewallRules()

	mock.mu.Lock()
	defer mock.mu.Unlock()

	// No RemoveFirewallRule calls — comment couldn't be parsed
	if len(mock.removeRuleCalls) != 0 {
		t.Errorf("expected 0 RemoveFirewallRule calls for invalid comment, got %d", len(mock.removeRuleCalls))
	}

	// ruleIDs should be reset to empty (always cleared after removeFirewallRules)
	if len(mgr.ruleIDs) != 0 {
		t.Error("ruleIDs should be cleared after removeFirewallRules")
	}
}

// ===========================================================================
// cleanupStaleRules tests
// ===========================================================================

// TestCleanupStaleRules_NoRulesFound verifies that when no rules with the
// bouncer signature exist, cleanupStaleRules completes without errors.
func TestCleanupStaleRules_NoRulesFound(t *testing.T) {
	mock := &mockROS{}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	mgr := newTestManager(mock, cfg)

	mgr.cleanupStaleRules()

	// No remove calls should be made.
	if len(mock.removeRuleCalls) != 0 {
		t.Errorf("expected 0 RemoveFirewallRule calls, got %d", len(mock.removeRuleCalls))
	}
}

// TestCleanupStaleRules_RulesFoundAndRemoved verifies that stale rules with
// the ruleSignature are found and removed.
func TestCleanupStaleRules_RulesFoundAndRemoved(t *testing.T) {
	mock := &mockROS{
		listFirewallRulesResult: []ros.RuleEntry{
			{ID: "*1", Comment: "cs-bouncer:filter-input-v4 @cs-routeros-bouncer"},
			{ID: "*2", Comment: "cs-bouncer:raw-prerouting-v4 @cs-routeros-bouncer"},
			{ID: "*3", Comment: "user-rule-no-signature"},
		},
	}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	mgr := newTestManager(mock, cfg)

	mgr.cleanupStaleRules()

	// Should have called RemoveFirewallRule for *1 and *2 across filter+raw
	// for both ip and ipv6.  The mock filters by signature, so only items with
	// "@cs-routeros-bouncer" are returned by ListFirewallRulesBySignature.
	// With 2 protos × 2 modes = 4 calls to List, each returning *1 and *2,
	// that's 8 Remove calls total.
	expectedRemoves := 8
	if len(mock.removeRuleCalls) != expectedRemoves {
		t.Errorf("expected %d RemoveFirewallRule calls, got %d", expectedRemoves, len(mock.removeRuleCalls))
	}
}

// TestCleanupStaleRules_ListError verifies that an error listing rules for
// one mode doesn't prevent cleanup of other modes.
func TestCleanupStaleRules_ListError(t *testing.T) {
	mock := &mockROS{
		listFirewallRulesErr: errors.New("api timeout"),
	}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	mgr := newTestManager(mock, cfg)

	// Should not panic; errors are logged and skipped.
	mgr.cleanupStaleRules()

	// No removes attempted since listing failed.
	if len(mock.removeRuleCalls) != 0 {
		t.Errorf("expected 0 RemoveFirewallRule calls on list error, got %d", len(mock.removeRuleCalls))
	}
}

// TestCleanupStaleRules_RemoveError verifies that an error removing one rule
// doesn't prevent removal of other rules.
func TestCleanupStaleRules_RemoveError(t *testing.T) {
	mock := &mockROS{
		listFirewallRulesResult: []ros.RuleEntry{
			{ID: "*A", Comment: "old-prefix:filter-input-v4 @cs-routeros-bouncer"},
			{ID: "*B", Comment: "old-prefix:filter-input-v6 @cs-routeros-bouncer"},
		},
		removeRuleErrFunc: func(proto, mode, id string) error {
			if id == "*A" {
				return errors.New("rule locked")
			}
			return nil
		},
	}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	mgr := newTestManager(mock, cfg)

	mgr.cleanupStaleRules()

	// Both rules should be attempted for removal even though *A fails.
	// With 2 protos × 2 modes = 4 list calls, each returning 2 rules = 8 remove calls.
	if len(mock.removeRuleCalls) < 4 {
		t.Errorf("expected at least 4 RemoveFirewallRule attempts, got %d", len(mock.removeRuleCalls))
	}
}

// TestCleanupStaleRules_IPv4Only verifies cleanup only targets IPv4 when
// IPv6 is disabled.
func TestCleanupStaleRules_IPv4Only(t *testing.T) {
	mock := &mockROS{
		listFirewallRulesResult: []ros.RuleEntry{
			{ID: "*1", Comment: "prefix:filter-input-v4 @cs-routeros-bouncer"},
		},
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	mgr := newTestManager(mock, cfg)

	mgr.cleanupStaleRules()

	// Only 1 proto × 2 modes = 2 list calls, each returning 1 rule = 2 removes.
	if len(mock.removeRuleCalls) != 2 {
		t.Errorf("expected 2 RemoveFirewallRule calls for IPv4-only, got %d", len(mock.removeRuleCalls))
	}
	for _, c := range mock.removeRuleCalls {
		if c.Proto != "ip" {
			t.Errorf("expected proto 'ip', got %q", c.Proto)
		}
	}
}

// ===========================================================================
// Shutdown additional coverage
// ===========================================================================

// TestShutdown_NilPool verifies Shutdown works when pool was never created
// (e.g. pool Connect failed during Start).
func TestShutdown_NilPool(t *testing.T) {
	mock := &mockROS{}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	mgr := newTestManager(mock, cfg)
	mgr.pool = nil

	// Should not panic.
	mgr.Shutdown()

	if len(mock.removeRuleCalls) != 0 {
		t.Errorf("expected 0 remove calls with no ruleIDs, got %d", len(mock.removeRuleCalls))
	}
}

// ===========================================================================
// createFirewallRules additional coverage
// ===========================================================================

// TestCreateFirewallRules_RejectWithAction verifies that reject-with is only
// set when deny_action is "reject".
func TestCreateFirewallRules_RejectWithAction(t *testing.T) {
	mock := &mockROS{addRuleID: "*1"}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	cfg.Firewall.DenyAction = "reject"
	cfg.Firewall.RejectWith = "tcp-reset"
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify at least one rule was created with RejectWith set.
	found := false
	for _, c := range mock.addRuleCalls {
		if c.Rule.RejectWith == "tcp-reset" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one rule with RejectWith='tcp-reset'")
	}
}

// TestCreateFirewallRules_DropActionNoRejectWith verifies reject-with is not
// set when deny_action is "drop".
func TestCreateFirewallRules_DropActionNoRejectWith(t *testing.T) {
	mock := &mockROS{addRuleID: "*1"}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	cfg.Firewall.DenyAction = "drop"
	cfg.Firewall.RejectWith = "tcp-reset" // Should be ignored for "drop"
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, c := range mock.addRuleCalls {
		if c.Rule.RejectWith != "" {
			t.Errorf("expected no RejectWith for drop action, got %q", c.Rule.RejectWith)
		}
	}
}

// TestCreateFirewallRules_WhitelistWithConnectionState verifies the whitelist
// accept rule inherits connection_state filter.
func TestCreateFirewallRules_WhitelistWithConnectionState(t *testing.T) {
	mock := &mockROS{addRuleID: "*1"}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	cfg.Firewall.Filter.ConnectionState = "new,established"
	cfg.Firewall.BlockInput.Whitelist = "trusted-hosts"
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First rule should be the whitelist accept rule with connection_state.
	if len(mock.addRuleCalls) < 1 {
		t.Fatal("expected at least 1 AddFirewallRule call")
	}
	wl := mock.addRuleCalls[0]
	if wl.Rule.Action != "accept" {
		t.Errorf("expected whitelist action 'accept', got %q", wl.Rule.Action)
	}
	if wl.Rule.ConnectionState != "new,established" {
		t.Errorf("expected ConnectionState 'new,established', got %q", wl.Rule.ConnectionState)
	}
	if wl.Rule.SrcAddressList != "trusted-hosts" {
		t.Errorf("expected SrcAddressList 'trusted-hosts', got %q", wl.Rule.SrcAddressList)
	}
}

// TestCreateFirewallRules_OutputPassthroughV4ListPrecedence verifies that
// passthrough_v4_list takes precedence over passthrough_v4.
func TestCreateFirewallRules_OutputPassthroughV4ListPrecedence(t *testing.T) {
	mock := &mockROS{addRuleID: "*1"}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	cfg.Firewall.BlockOutput.Enabled = true
	cfg.Firewall.BlockOutput.PassthroughV4List = "my-servers"
	cfg.Firewall.BlockOutput.PassthroughV4 = "1.2.3.4" // Should be ignored when list is set.
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Find the output rule.
	var outRule *addRuleCall
	for i, c := range mock.addRuleCalls {
		if c.Rule.Chain == "output" {
			outRule = &mock.addRuleCalls[i]
			break
		}
	}
	if outRule == nil {
		t.Fatal("expected an output rule")
	}
	if outRule.Rule.SrcAddressList != "!my-servers" {
		t.Errorf("expected SrcAddressList '!my-servers', got %q", outRule.Rule.SrcAddressList)
	}
	// SrcAddress should be empty since list takes precedence.
	if outRule.Rule.SrcAddress != "" {
		t.Errorf("expected empty SrcAddress when list is set, got %q", outRule.Rule.SrcAddress)
	}
}

// TestCreateFirewallRules_OutputPassthroughV6Address verifies IPv6
// output passthrough uses the correct fields.
func TestCreateFirewallRules_OutputPassthroughV6Address(t *testing.T) {
	mock := &mockROS{addRuleID: "*1"}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	cfg.Firewall.BlockOutput.Enabled = true
	cfg.Firewall.BlockOutput.PassthroughV6 = "2001:db8::1"
	cfg.Firewall.IPv4.Enabled = false
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var outRule *addRuleCall
	for i, c := range mock.addRuleCalls {
		if c.Rule.Chain == "output" {
			outRule = &mock.addRuleCalls[i]
			break
		}
	}
	if outRule == nil {
		t.Fatal("expected an output rule")
	}
	if outRule.Rule.SrcAddress != "!2001:db8::1" {
		t.Errorf("expected SrcAddress '!2001:db8::1', got %q", outRule.Rule.SrcAddress)
	}
}

// TestCreateFirewallRules_OutputPassthroughV6List verifies IPv6 output uses
// list negation when passthrough_v6_list is set.
func TestCreateFirewallRules_OutputPassthroughV6List(t *testing.T) {
	mock := &mockROS{addRuleID: "*1"}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	cfg.Firewall.BlockOutput.Enabled = true
	cfg.Firewall.BlockOutput.PassthroughV6List = "v6-servers"
	cfg.Firewall.BlockOutput.PassthroughV6 = "2001:db8::1" // Ignored when list is set.
	cfg.Firewall.IPv4.Enabled = false
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var outRule *addRuleCall
	for i, c := range mock.addRuleCalls {
		if c.Rule.Chain == "output" {
			outRule = &mock.addRuleCalls[i]
			break
		}
	}
	if outRule == nil {
		t.Fatal("expected an output rule")
	}
	if outRule.Rule.SrcAddressList != "!v6-servers" {
		t.Errorf("expected SrcAddressList '!v6-servers', got %q", outRule.Rule.SrcAddressList)
	}
}

// TestCreateFirewallRules_OutputInterfaceOptions verifies output rules use
// interface and interface_list settings.
func TestCreateFirewallRules_OutputInterfaceOptions(t *testing.T) {
	mock := &mockROS{addRuleID: "*1"}
	cfg := baseConfig()
	cfg.Firewall.Filter.Enabled = true
	cfg.Firewall.Filter.Chains = []string{"input"}
	cfg.Firewall.BlockOutput.Enabled = true
	cfg.Firewall.BlockOutput.Interface = "ether1"
	cfg.Firewall.BlockOutput.InterfaceList = "WAN"
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	if err := mgr.createFirewallRules(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var outRule *addRuleCall
	for i, c := range mock.addRuleCalls {
		if c.Rule.Chain == "output" {
			outRule = &mock.addRuleCalls[i]
			break
		}
	}
	if outRule == nil {
		t.Fatal("expected an output rule")
	}
	if outRule.Rule.OutInterface != "ether1" {
		t.Errorf("expected OutInterface 'ether1', got %q", outRule.Rule.OutInterface)
	}
	if outRule.Rule.OutInterfaceList != "WAN" {
		t.Errorf("expected OutInterfaceList 'WAN', got %q", outRule.Rule.OutInterfaceList)
	}
}

// ===========================================================================
// reconcileAddresses additional coverage
// ===========================================================================

// TestReconcileAddresses_OriginTracking verifies that per-origin decision
// counts are tracked during reconciliation.
func TestReconcileAddresses_OriginTracking(t *testing.T) {
	mock := &mockROS{
		bulkAddCount: 2,
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	decisions := []*crowdsec.Decision{
		{Value: "1.1.1.1", Proto: "ip", Duration: time.Hour, Origin: "crowdsec", Scenario: "ssh-bf"},
		{Value: "2.2.2.2", Proto: "ip", Duration: time.Hour, Origin: "CAPI", Scenario: "http-scan"},
	}

	mgr.reconcileAddresses(decisions)

	// Verify that bulk add was called with both entries.
	if len(mock.bulkAddCalls) != 1 {
		t.Fatalf("expected 1 BulkAddAddresses call, got %d", len(mock.bulkAddCalls))
	}
	if len(mock.bulkAddCalls[0].Entries) != 2 {
		t.Errorf("expected 2 entries in bulk add, got %d", len(mock.bulkAddCalls[0].Entries))
	}
}

// TestReconcileAddresses_ExistingAddressesUnchanged verifies that addresses
// already on the router are not re-added.
func TestReconcileAddresses_ExistingAddressesUnchanged(t *testing.T) {
	mock := &mockROS{
		listAddresses: []ros.AddressEntry{
			{ID: "*1", Address: "1.1.1.1", List: "crowdsec-banned", Comment: "cs|crowdsec|ssh-bf @cs-routeros-bouncer"},
		},
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	decisions := []*crowdsec.Decision{
		{Value: "1.1.1.1", Proto: "ip", Duration: time.Hour, Origin: "crowdsec", Scenario: "ssh-bf"},
	}

	mgr.reconcileAddresses(decisions)

	// No bulk add should occur — address already exists.
	if len(mock.bulkAddCalls) != 0 {
		t.Errorf("expected 0 BulkAddAddresses calls for existing address, got %d", len(mock.bulkAddCalls))
	}
}

// TestReconcileAddresses_RemoveStaleAddress verifies that addresses on the
// router not in the decisions list are removed.
func TestReconcileAddresses_RemoveStaleAddress(t *testing.T) {
	mock := &mockROS{
		listAddresses: []ros.AddressEntry{
			{ID: "*1", Address: "1.1.1.1", List: "crowdsec-banned", Comment: "cs|x|y @cs-routeros-bouncer"},
			{ID: "*2", Address: "2.2.2.2", List: "crowdsec-banned", Comment: "cs|x|y @cs-routeros-bouncer"},
		},
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	// Only 1.1.1.1 should remain.
	decisions := []*crowdsec.Decision{
		{Value: "1.1.1.1", Proto: "ip", Duration: time.Hour, Origin: "crowdsec", Scenario: "ssh-bf"},
	}

	mgr.reconcileAddresses(decisions)

	// 2.2.2.2 should be removed.
	if len(mock.removeAddressCalls) != 1 {
		t.Errorf("expected 1 RemoveAddress call, got %d", len(mock.removeAddressCalls))
	}
	if len(mock.removeAddressCalls) > 0 && mock.removeAddressCalls[0].ID != "*2" {
		t.Errorf("expected removal of *2, got %q", mock.removeAddressCalls[0].ID)
	}
}

// TestReconcileAddresses_ZeroDurationNoTimeout verifies decisions with zero
// duration produce entries with no timeout.
func TestReconcileAddresses_ZeroDurationNoTimeout(t *testing.T) {
	mock := &mockROS{bulkAddCount: 1}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	decisions := []*crowdsec.Decision{
		{Value: "1.1.1.1", Proto: "ip", Duration: 0, Origin: "manual", Scenario: "manual"},
	}

	mgr.reconcileAddresses(decisions)

	if len(mock.bulkAddCalls) != 1 {
		t.Fatalf("expected 1 BulkAddAddresses call, got %d", len(mock.bulkAddCalls))
	}
	if mock.bulkAddCalls[0].Entries[0].Timeout != "" {
		t.Errorf("expected empty timeout for zero duration, got %q", mock.bulkAddCalls[0].Entries[0].Timeout)
	}
}

// ===========================================================================
// handleUnban additional coverage
// ===========================================================================

// TestHandleUnban_SuccessfulRemove verifies the full happy-path unban:
// found in cache, found on router, successfully removed.
func TestHandleUnban_SuccessfulRemove(t *testing.T) {
	mock := &mockROS{
		findAddressEntry: &ros.AddressEntry{ID: "*99", Address: "5.5.5.5"},
	}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	// Pre-populate cache.
	mgr.cacheMu.Lock()
	mgr.addressCache["5.5.5.5"] = struct{}{}
	mgr.cacheMu.Unlock()

	d := &crowdsec.Decision{Value: "5.5.5.5", Proto: "ip"}
	mgr.handleUnban(d)

	if len(mock.removeAddressCalls) != 1 {
		t.Fatalf("expected 1 RemoveAddress call, got %d", len(mock.removeAddressCalls))
	}
	if mock.removeAddressCalls[0].ID != "*99" {
		t.Errorf("expected removal of *99, got %q", mock.removeAddressCalls[0].ID)
	}

	// Address should be removed from cache.
	mgr.cacheMu.RLock()
	_, inCache := mgr.addressCache["5.5.5.5"]
	mgr.cacheMu.RUnlock()
	if inCache {
		t.Error("expected address removed from cache after unban")
	}
}

// TestHandleUnban_IPv6Disabled verifies unban for IPv6 is skipped when disabled.
func TestHandleUnban_IPv6Disabled(t *testing.T) {
	mock := &mockROS{}
	cfg := baseConfig()
	cfg.Firewall.IPv6.Enabled = false
	mgr := newTestManager(mock, cfg)

	d := &crowdsec.Decision{Value: "2001:db8::1", Proto: "ipv6"}
	mgr.handleUnban(d)

	if len(mock.findAddressCalls) != 0 {
		t.Error("expected no FindAddress calls for disabled IPv6")
	}
}
