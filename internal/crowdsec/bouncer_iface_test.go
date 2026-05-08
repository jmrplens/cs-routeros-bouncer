package crowdsec

import (
	"context"
	"errors"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockBouncerInner is a testify mock for the concrete StreamBouncer methods
// wrapped by bouncerAdapter.
type MockBouncerInner struct {
	mock.Mock
}

// Init records and returns the configured mock Init result.
func (m *MockBouncerInner) Init() error {
	args := m.Called()
	return args.Error(0)
}

// Run records the context passed through bouncerAdapter.Run.
func (m *MockBouncerInner) Run(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// TestBouncerAdapterDelegatesAndReadsPointers verifies method delegation and
// dynamic reads of the StreamBouncer stream/client fields.
func TestBouncerAdapterDelegatesAndReadsPointers(t *testing.T) {
	stream := make(chan *models.DecisionsStreamResponse)
	defer close(stream)
	client := &apiclient.ApiClient{}
	inner := &MockBouncerInner{}
	inner.On("Init").Return(nil)
	inner.On("Run", mock.Anything).Return(nil)
	adapter := &bouncerAdapter{
		inner:        inner,
		streamPtr:    &stream,
		apiClientPtr: &client,
	}

	assert.NoError(t, adapter.Init())
	inner.AssertCalled(t, "Init")
	assert.NoError(t, adapter.Run(context.Background()))
	inner.AssertCalled(t, "Run", mock.Anything)
	assert.Equal(t, (<-chan *models.DecisionsStreamResponse)(stream), adapter.DecisionStream())
	assert.Equal(t, client, adapter.Client())
	inner.AssertExpectations(t)
}

// TestBouncerAdapterPropagatesErrors verifies Init and Run errors are returned unchanged.
func TestBouncerAdapterPropagatesErrors(t *testing.T) {
	stream := make(chan *models.DecisionsStreamResponse)
	defer close(stream)
	client := &apiclient.ApiClient{}
	initErr := errors.New("init failed")
	runErr := errors.New("run failed")
	inner := &MockBouncerInner{}
	inner.On("Init").Return(initErr)
	inner.On("Run", mock.Anything).Return(runErr)
	adapter := &bouncerAdapter{
		inner:        inner,
		streamPtr:    &stream,
		apiClientPtr: &client,
	}

	assert.ErrorIs(t, adapter.Init(), initErr)
	assert.ErrorIs(t, adapter.Run(context.Background()), runErr)
	inner.AssertExpectations(t)
}
