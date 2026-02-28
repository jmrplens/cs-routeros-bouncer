// mock_bouncer_test.go provides a MockBouncer that implements BouncerEngine
// for unit-testing Stream.Init, Stream.Run, and Stream.APIClient without a
// real CrowdSec LAPI connection.
package crowdsec

import (
	"context"
	"sync"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// MockBouncer implements BouncerEngine for testing.
type MockBouncer struct {
	mu sync.Mutex

	// InitErr is the error returned by Init().
	InitErr error
	// InitCalled is true after Init() is called.
	InitCalled bool

	// RunErr is the error returned when Run() finishes.
	RunErr error
	// RunCalled is true after Run() is called.
	RunCalled bool
	// RunCtx captures the context passed to Run().
	RunCtx context.Context

	// DecisionCh is the channel returned by DecisionStream().
	// Tests send *models.DecisionsStreamResponse on it to feed Run().
	DecisionCh chan *models.DecisionsStreamResponse

	// APIClientVal is returned by Client().
	APIClientVal *apiclient.ApiClient
}

// NewMockBouncer creates a MockBouncer with a buffered decision channel.
func NewMockBouncer() *MockBouncer {
	return &MockBouncer{
		DecisionCh: make(chan *models.DecisionsStreamResponse, 10),
	}
}

// Init implements BouncerIface.Init and records whether it was called, returning
// the pre-configured InitErr.
func (m *MockBouncer) Init() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.InitCalled = true
	return m.InitErr
}

// Run implements BouncerIface.Run and blocks until the context is canceled,
// mimicking the real bouncer's lifecycle.
func (m *MockBouncer) Run(ctx context.Context) error {
	m.mu.Lock()
	m.RunCalled = true
	m.RunCtx = ctx
	m.mu.Unlock()
	// Block until context is canceled (mimics real bouncer).
	<-ctx.Done()
	return m.RunErr
}

// DecisionStream implements BouncerIface.DecisionStream and returns the mock's
// decision channel for test-driven decision delivery.
func (m *MockBouncer) DecisionStream() <-chan *models.DecisionsStreamResponse {
	return m.DecisionCh
}

// Client implements BouncerIface.Client and returns the pre-configured mock API
// client (or nil if not set).
func (m *MockBouncer) Client() *apiclient.ApiClient {
	return m.APIClientVal
}
