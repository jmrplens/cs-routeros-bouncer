// stream_test.go contains unit tests for Stream.Init, Stream.Run, and
// Stream.APIClient using MockBouncer. These tests cover the decision-routing
// logic, error paths, and channel lifecycle without requiring a real LAPI.
package crowdsec

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/rs/zerolog"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// newTestStream builds a Stream wired to the given MockBouncer.
func newTestStream(mb *MockBouncer) *Stream {
	return &Stream{
		bouncer: mb,
		cfg: config.CrowdSecConfig{
			APIURL: "http://test:8080/",
			APIKey: "test-key",
		},
		logger: zerolog.Nop(),
	}
}

// TestInitSuccess verifies that a successful Init call is propagated.
func TestInitSuccess(t *testing.T) {
	mb := NewMockBouncer()
	s := newTestStream(mb)
	if err := s.Init(); err != nil {
		t.Fatalf("Init() returned unexpected error: %v", err)
	}
	if !mb.InitCalled {
		t.Fatal("expected Init to be called on bouncer")
	}
}

// TestInitError verifies that an Init error is wrapped and returned.
func TestInitError(t *testing.T) {
	mb := NewMockBouncer()
	mb.InitErr = fmt.Errorf("connection refused")
	s := newTestStream(mb)
	err := s.Init()
	if err == nil {
		t.Fatal("expected error from Init")
	}
	if got := err.Error(); got != "initializing CrowdSec bouncer: connection refused" {
		t.Errorf("unexpected error message: %s", got)
	}
}

// --- APIClient tests ---

// TestAPIClientReturnsValue verifies that APIClient returns the mock's client.
func TestAPIClientReturnsValue(t *testing.T) {
	mb := NewMockBouncer()
	client := &apiclient.ApiClient{}
	mb.APIClientVal = client
	s := newTestStream(mb)
	got := s.APIClient()
	if got != client {
		t.Error("APIClient() did not return expected client")
	}
}

// TestAPIClientNil verifies that APIClient returns nil when not set.
func TestAPIClientNil(t *testing.T) {
	mb := NewMockBouncer()
	s := newTestStream(mb)
	if got := s.APIClient(); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

// --- Run tests ---

// TestRunNewBanDecisions verifies that new ban decisions are parsed and sent
// to the banCh channel.
func TestRunNewBanDecisions(t *testing.T) {
	mb := NewMockBouncer()
	s := newTestStream(mb)

	banCh := make(chan *Decision, 10)
	deleteCh := make(chan *Decision, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()

	// Send a new ban decision.
	mb.DecisionCh <- &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			{
				Value:    strPtr("1.2.3.4"),
				Type:     strPtr("ban"),
				Duration: strPtr("4h"),
				Origin:   strPtr("crowdsec"),
				Scenario: strPtr("http-probing"),
			},
		},
	}

	select {
	case d := <-banCh:
		if d.Value != "1.2.3.4" {
			t.Errorf("Value = %q, want 1.2.3.4", d.Value)
		}
		if d.Proto != "ip" {
			t.Errorf("Proto = %q, want ip", d.Proto)
		}
		if d.Origin != "crowdsec" {
			t.Errorf("Origin = %q, want crowdsec", d.Origin)
		}
		if d.Duration != 4*time.Hour {
			t.Errorf("Duration = %v, want 4h", d.Duration)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ban decision")
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("Run returned error: %v", err)
	}
}

// TestRunDeleteDecisions verifies that deleted decisions are sent to deleteCh.
func TestRunDeleteDecisions(t *testing.T) {
	mb := NewMockBouncer()
	s := newTestStream(mb)

	banCh := make(chan *Decision, 10)
	deleteCh := make(chan *Decision, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()

	mb.DecisionCh <- &models.DecisionsStreamResponse{
		Deleted: models.GetDecisionsResponse{
			{
				Value:    strPtr("10.0.0.1"),
				Type:     strPtr("ban"),
				Duration: strPtr("1h"),
				Origin:   strPtr("cscli"),
			},
		},
	}

	select {
	case d := <-deleteCh:
		if d.Value != "10.0.0.1" {
			t.Errorf("Value = %q, want 10.0.0.1", d.Value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for delete decision")
	}

	cancel()
	<-errCh
}

// TestRunNilDecisionFieldsSkipped verifies that decisions with nil required
// fields are silently skipped.
func TestRunNilDecisionFieldsSkipped(t *testing.T) {
	mb := NewMockBouncer()
	s := newTestStream(mb)

	banCh := make(chan *Decision, 10)
	deleteCh := make(chan *Decision, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()

	// Send decisions with missing required fields — all should be skipped.
	mb.DecisionCh <- &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			nil, // nil decision
			{Value: nil, Type: strPtr("ban"), Duration: strPtr("1h")},      // nil Value
			{Value: strPtr("1.1.1.1"), Type: nil, Duration: strPtr("1h")},  // nil Type
			{Value: strPtr("1.1.1.1"), Type: strPtr("ban"), Duration: nil}, // nil Duration
		},
	}

	// Send a valid decision so we know processing reached it.
	mb.DecisionCh <- &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			{Value: strPtr("9.9.9.9"), Type: strPtr("ban"), Duration: strPtr("1h")},
		},
	}

	select {
	case d := <-banCh:
		if d.Value != "9.9.9.9" {
			t.Errorf("expected 9.9.9.9 (first valid), got %q", d.Value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out — nil decisions may have blocked processing")
	}

	cancel()
	<-errCh
}

// TestRunNonBanTypeSkipped verifies that non-ban decision types are ignored.
func TestRunNonBanTypeSkipped(t *testing.T) {
	mb := NewMockBouncer()
	s := newTestStream(mb)

	banCh := make(chan *Decision, 10)
	deleteCh := make(chan *Decision, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()

	// Captcha type should be skipped.
	mb.DecisionCh <- &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			{Value: strPtr("1.1.1.1"), Type: strPtr("captcha"), Duration: strPtr("1h")},
		},
	}
	// Follow with a valid ban to confirm we're still processing.
	mb.DecisionCh <- &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			{Value: strPtr("2.2.2.2"), Type: strPtr("ban"), Duration: strPtr("1h")},
		},
	}

	select {
	case d := <-banCh:
		if d.Value != "2.2.2.2" {
			t.Errorf("expected 2.2.2.2, got %q", d.Value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}

	cancel()
	<-errCh
}

// TestRunChannelClosed verifies that Run returns an error when the decision
// channel is closed (bouncer stopped unexpectedly).
func TestRunChannelClosed(t *testing.T) {
	mb := NewMockBouncer()
	s := newTestStream(mb)

	banCh := make(chan *Decision, 10)
	deleteCh := make(chan *Decision, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()

	// Close the decision channel.
	close(mb.DecisionCh)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error when channel closed")
		}
		if got := err.Error(); got != "CrowdSec stream channel closed" {
			t.Errorf("unexpected error: %s", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Run to return")
	}
}

// TestRunContextCancel verifies that Run returns nil when the context is
// canceled (graceful shutdown).
func TestRunContextCancel(t *testing.T) {
	mb := NewMockBouncer()
	s := newTestStream(mb)

	banCh := make(chan *Decision, 10)
	deleteCh := make(chan *Decision, 10)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()

	// Give Run a moment to start, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected nil error on ctx cancel, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Run to return")
	}
}

// TestRunIPv6Decision verifies that IPv6 decisions are detected correctly.
func TestRunIPv6Decision(t *testing.T) {
	mb := NewMockBouncer()
	s := newTestStream(mb)

	banCh := make(chan *Decision, 10)
	deleteCh := make(chan *Decision, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()

	mb.DecisionCh <- &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			{
				Value:    strPtr("2001:db8::1"),
				Type:     strPtr("ban"),
				Duration: strPtr("2h"),
				Origin:   strPtr("CAPI"),
			},
		},
	}

	select {
	case d := <-banCh:
		if d.Proto != "ipv6" {
			t.Errorf("Proto = %q, want ipv6", d.Proto)
		}
		if d.Value != "2001:db8::1" {
			t.Errorf("Value = %q", d.Value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}

	cancel()
	<-errCh
}

// TestRunCIDRRange verifies that CIDR range decisions set IsRange=true.
func TestRunCIDRRange(t *testing.T) {
	mb := NewMockBouncer()
	s := newTestStream(mb)

	banCh := make(chan *Decision, 10)
	deleteCh := make(chan *Decision, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()

	mb.DecisionCh <- &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			{
				Value:    strPtr("10.0.0.0/24"),
				Type:     strPtr("ban"),
				Duration: strPtr("1h"),
			},
		},
	}

	select {
	case d := <-banCh:
		if !d.IsRange {
			t.Error("expected IsRange=true for CIDR")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}

	cancel()
	<-errCh
}

// TestRunMixedNewAndDeleted verifies that a single DecisionsStreamResponse
// with both New and Deleted decisions routes them correctly.
func TestRunMixedNewAndDeleted(t *testing.T) {
	mb := NewMockBouncer()
	s := newTestStream(mb)

	banCh := make(chan *Decision, 10)
	deleteCh := make(chan *Decision, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()

	mb.DecisionCh <- &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			{Value: strPtr("5.5.5.5"), Type: strPtr("ban"), Duration: strPtr("1h")},
		},
		Deleted: models.GetDecisionsResponse{
			{Value: strPtr("6.6.6.6"), Type: strPtr("ban"), Duration: strPtr("1h")},
		},
	}

	// Collect both.
	var gotBan, gotDelete bool
	timeout := time.After(2 * time.Second)
	for !gotBan || !gotDelete {
		select {
		case d := <-banCh:
			if d.Value == "5.5.5.5" {
				gotBan = true
			}
		case d := <-deleteCh:
			if d.Value == "6.6.6.6" {
				gotDelete = true
			}
		case <-timeout:
			t.Fatalf("timed out: gotBan=%v, gotDelete=%v", gotBan, gotDelete)
		}
	}

	cancel()
	<-errCh
}

// TestRunEmptyDecisionBatch verifies that an empty batch (no New or Deleted)
// doesn't block or error.
func TestRunEmptyDecisionBatch(t *testing.T) {
	mb := NewMockBouncer()
	s := newTestStream(mb)

	banCh := make(chan *Decision, 10)
	deleteCh := make(chan *Decision, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()

	// Send empty batch.
	mb.DecisionCh <- &models.DecisionsStreamResponse{}

	// Follow with a valid ban to confirm processing continues.
	mb.DecisionCh <- &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			{Value: strPtr("7.7.7.7"), Type: strPtr("ban"), Duration: strPtr("1h")},
		},
	}

	select {
	case d := <-banCh:
		if d.Value != "7.7.7.7" {
			t.Errorf("expected 7.7.7.7, got %q", d.Value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out — empty batch may have blocked processing")
	}

	cancel()
	<-errCh
}

// TestRunDeletedNilFields verifies that deleted decisions with nil fields are
// skipped without error.
func TestRunDeletedNilFields(t *testing.T) {
	mb := NewMockBouncer()
	s := newTestStream(mb)

	banCh := make(chan *Decision, 10)
	deleteCh := make(chan *Decision, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()

	mb.DecisionCh <- &models.DecisionsStreamResponse{
		Deleted: models.GetDecisionsResponse{
			nil,                                   // nil decision
			{Value: nil, Type: strPtr("ban")},     // nil Value
			{Value: strPtr("1.1.1.1"), Type: nil}, // nil Type
		},
	}

	// Follow with valid delete to confirm processing continues.
	mb.DecisionCh <- &models.DecisionsStreamResponse{
		Deleted: models.GetDecisionsResponse{
			{Value: strPtr("8.8.8.8"), Type: strPtr("ban"), Duration: strPtr("1h")},
		},
	}

	select {
	case d := <-deleteCh:
		if d.Value != "8.8.8.8" {
			t.Errorf("expected 8.8.8.8, got %q", d.Value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}

	cancel()
	<-errCh
}

// TestRunBanDuringContextCancel verifies that if context is canceled while
// writing to banCh, Run returns nil.
func TestRunBanDuringContextCancel(t *testing.T) {
	mb := NewMockBouncer()
	s := newTestStream(mb)

	// Use unbuffered channels to force the select in Run to block.
	banCh := make(chan *Decision)
	deleteCh := make(chan *Decision)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()

	// Send a decision — Run will try to write to banCh but it's unbuffered.
	mb.DecisionCh <- &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			{Value: strPtr("3.3.3.3"), Type: strPtr("ban"), Duration: strPtr("1h")},
		},
	}

	// Give Run time to reach the select, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected nil, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
}

// TestRunDeleteDuringContextCancel verifies that if context is canceled while
// writing to deleteCh, Run returns nil.
func TestRunDeleteDuringContextCancel(t *testing.T) {
	mb := NewMockBouncer()
	s := newTestStream(mb)

	banCh := make(chan *Decision)
	deleteCh := make(chan *Decision)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()

	mb.DecisionCh <- &models.DecisionsStreamResponse{
		Deleted: models.GetDecisionsResponse{
			{Value: strPtr("4.4.4.4"), Type: strPtr("ban"), Duration: strPtr("1h")},
		},
	}

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected nil, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
}
