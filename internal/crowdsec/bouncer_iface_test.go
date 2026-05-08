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

type MockBouncerInner struct {
	mock.Mock
}

func (m *MockBouncerInner) Init() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockBouncerInner) Run(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

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
