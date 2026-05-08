// stream_test.go contains unit tests for Stream.Init, Stream.Run, and
// Stream.APIClient using MockBouncer. These tests cover the decision-routing
// logic, error paths, and channel lifecycle without requiring a real LAPI.
package crowdsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestActiveDecisionsRequiresInitializedClient(t *testing.T) {
	mb := NewMockBouncer()
	s := newTestStream(mb)

	decisions, err := s.ActiveDecisions(context.Background())
	if err == nil {
		t.Fatal("expected uninitialized API client error")
	}
	if decisions != nil {
		t.Fatalf("expected nil decisions, got %v", decisions)
	}
	if !strings.Contains(err.Error(), "API client is not initialized") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestActiveDecisionsUsesDecisionListEndpoint verifies that periodic
// reconciliation snapshots use the active-decision listing endpoint instead of
// the delta stream's startup mode.
func TestActiveDecisionsUsesDecisionListEndpoint(t *testing.T) { // NOSONAR: HTTP fixture and endpoint assertions share one scenario.
	var requestOffsets []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decisions" {
			t.Errorf("expected /v1/decisions path, got %s", r.URL.Path)
		}
		if strings.Contains(r.URL.RawQuery, "startup") {
			t.Errorf("snapshot request should not use startup query: %s", r.URL.RawQuery)
		}
		query := r.URL.Query()
		if query.Get("type") != "ban" {
			t.Errorf("expected type=ban, got %q", query.Get("type"))
		}
		if query.Get("limit") != fmt.Sprintf("%d", activeDecisionPageSize) {
			t.Errorf("expected paginated limit, got %q", query.Get("limit"))
		}
		if query.Get("scopes") != "ip,range" {
			t.Errorf("expected scopes filter, got %q", query.Get("scopes"))
		}
		if query.Get("origins") != "crowdsec,CAPI" {
			t.Errorf("expected origins filter, got %q", query.Get("origins"))
		}
		if query.Get("scenarios_containing") != "ssh" {
			t.Errorf("expected scenarios_containing filter, got %q", query.Get("scenarios_containing"))
		}
		offset := query.Get("offset")
		requestOffsets = append(requestOffsets, offset)

		response := models.GetDecisionsResponse{}
		switch offset {
		case "0":
			for i := range activeDecisionPageSize {
				value := fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)
				response = append(response, &models.Decision{
					Value:    new(value),
					Type:     new("ban"),
					Duration: new("1h"),
					Origin:   new("crowdsec"),
					Scenario: new("ssh-bf"),
				})
			}
		case fmt.Sprintf("%d", activeDecisionPageSize):
			response = append(response,
				&models.Decision{Value: new("192.0.2.55"), Type: new("ban"), Duration: new("1h"), Origin: new("crowdsec"), Scenario: new("ssh-bf")},
				&models.Decision{Value: new("5.6.7.8"), Type: new("captcha"), Duration: new("1h")},
			)
		default:
			t.Errorf("unexpected offset %q", offset)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer server.Close()

	apiURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	client, err := apiclient.NewDefaultClient(apiURL, "v1", "test", server.Client())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	mb := NewMockBouncer()
	mb.APIClientVal = client
	s := newTestStream(mb)
	s.cfg.Scopes = []string{"ip", "range"}
	s.cfg.Origins = []string{"crowdsec", "CAPI"}
	s.cfg.ScenariosContaining = []string{"ssh"}

	decisions, err := s.ActiveDecisions(context.Background())
	if err != nil {
		t.Fatalf("ActiveDecisions returned error: %v", err)
	}
	if len(requestOffsets) != 2 || requestOffsets[0] != "0" || requestOffsets[1] != fmt.Sprintf("%d", activeDecisionPageSize) {
		t.Fatalf("expected two paginated requests, got offsets %v", requestOffsets)
	}
	if len(decisions) != activeDecisionPageSize+1 {
		t.Fatalf("expected %d parsed ban decisions, got %d", activeDecisionPageSize+1, len(decisions))
	}
	last := decisions[len(decisions)-1]
	if last.Value != "192.0.2.55" || last.Duration != time.Hour {
		t.Fatalf("unexpected final decision: %+v", last)
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

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()

	// Send a new ban decision.
	mb.DecisionCh <- &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			{
				Value:    new("1.2.3.4"),
				Type:     new("ban"),
				Duration: new("4h"),
				Origin:   new("crowdsec"),
				Scenario: new("http-probing"),
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

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()

	mb.DecisionCh <- &models.DecisionsStreamResponse{
		Deleted: models.GetDecisionsResponse{
			{
				Value:    new("10.0.0.1"),
				Type:     new("ban"),
				Duration: new("1h"),
				Origin:   new("cscli"),
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
			{Value: nil, Type: new("ban"), Duration: new("1h")},      // nil Value
			{Value: new("1.1.1.1"), Type: nil, Duration: new("1h")},  // nil Type
			{Value: new("1.1.1.1"), Type: new("ban"), Duration: nil}, // nil Duration
		},
	}

	// Send a valid decision so we know processing reached it.
	mb.DecisionCh <- &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			{Value: new("9.9.9.9"), Type: new("ban"), Duration: new("1h")},
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
			{Value: new("1.1.1.1"), Type: new("captcha"), Duration: new("1h")},
		},
	}
	// Follow with a valid ban to confirm we're still processing.
	mb.DecisionCh <- &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			{Value: new("2.2.2.2"), Type: new("ban"), Duration: new("1h")},
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
	ctx := t.Context()

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

func TestRunBouncerRunCanceledError(t *testing.T) {
	mb := NewMockBouncer()
	mb.RunErr = context.Canceled
	s := newTestStream(mb)

	banCh := make(chan *Decision, 10)
	deleteCh := make(chan *Decision, 10)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()
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

func TestRunBouncerRunUnexpectedError(t *testing.T) {
	mb := NewMockBouncer()
	mb.RunReturnsImmediately = true
	mb.RunErr = fmt.Errorf("bouncer stopped")
	s := newTestStream(mb)

	banCh := make(chan *Decision, 10)
	deleteCh := make(chan *Decision, 10)
	ctx := t.Context()

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, banCh, deleteCh) }()
	waitForMockRun(t, mb)
	close(mb.DecisionCh)

	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "stream channel closed") {
			t.Fatalf("expected channel closed error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Run to return")
	}
}

func waitForMockRun(t *testing.T, mb *MockBouncer) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mb.mu.Lock()
		called := mb.RunCalled
		mb.mu.Unlock()
		if called {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("mock bouncer Run was not called")
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
				Value:    new("2001:db8::1"),
				Type:     new("ban"),
				Duration: new("2h"),
				Origin:   new("CAPI"),
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
				Value:    new("10.0.0.0/24"),
				Type:     new("ban"),
				Duration: new("1h"),
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
			{Value: new("5.5.5.5"), Type: new("ban"), Duration: new("1h")},
		},
		Deleted: models.GetDecisionsResponse{
			{Value: new("6.6.6.6"), Type: new("ban"), Duration: new("1h")},
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
			{Value: new("7.7.7.7"), Type: new("ban"), Duration: new("1h")},
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
			nil,                                // nil decision
			{Value: nil, Type: new("ban")},     // nil Value
			{Value: new("1.1.1.1"), Type: nil}, // nil Type
		},
	}

	// Follow with valid delete to confirm processing continues.
	mb.DecisionCh <- &models.DecisionsStreamResponse{
		Deleted: models.GetDecisionsResponse{
			{Value: new("8.8.8.8"), Type: new("ban"), Duration: new("1h")},
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
			{Value: new("3.3.3.3"), Type: new("ban"), Duration: new("1h")},
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
			{Value: new("4.4.4.4"), Type: new("ban"), Duration: new("1h")},
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
