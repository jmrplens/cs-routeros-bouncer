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
	// RunReturnsImmediately makes Run return RunErr without waiting for ctx.
	RunReturnsImmediately bool
	// RunStarted is closed when Run starts, letting tests wait without polling.
	RunStarted     chan struct{}
	runStartedOnce sync.Once

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
		RunStarted: make(chan struct{}),
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
	immediate := m.RunReturnsImmediately
	runErr := m.RunErr
	runStarted := m.RunStarted
	m.mu.Unlock()
	if runStarted != nil {
		m.runStartedOnce.Do(func() { close(runStarted) })
	}
	if immediate {
		return runErr
	}
	// Block until context is canceled (mimics real bouncer).
	<-ctx.Done()
	return runErr
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
