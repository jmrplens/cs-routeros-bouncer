package crowdsec

import (
	"context"
	"errors"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type fakeBouncerInner struct {
	initCalled bool
	runCalled  bool
	initErr    error
	runErr     error
}

func (f *fakeBouncerInner) Init() error {
	f.initCalled = true
	return f.initErr
}

func (f *fakeBouncerInner) Run(context.Context) error {
	f.runCalled = true
	return f.runErr
}

func TestBouncerAdapterDelegatesAndReadsPointers(t *testing.T) {
	stream := make(chan *models.DecisionsStreamResponse)
	client := &apiclient.ApiClient{}
	inner := &fakeBouncerInner{}
	adapter := &bouncerAdapter{
		inner:        inner,
		streamPtr:    &stream,
		apiClientPtr: &client,
	}

	if err := adapter.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !inner.initCalled {
		t.Fatal("expected Init to delegate to inner bouncer")
	}
	if err := adapter.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !inner.runCalled {
		t.Fatal("expected Run to delegate to inner bouncer")
	}
	if adapter.DecisionStream() != stream {
		t.Fatal("DecisionStream did not read current stream pointer")
	}
	if adapter.Client() != client {
		t.Fatal("Client did not read current API client pointer")
	}
}

func TestBouncerAdapterPropagatesErrors(t *testing.T) {
	stream := make(chan *models.DecisionsStreamResponse)
	client := &apiclient.ApiClient{}
	initErr := errors.New("init failed")
	runErr := errors.New("run failed")
	adapter := &bouncerAdapter{
		inner:        &fakeBouncerInner{initErr: initErr, runErr: runErr},
		streamPtr:    &stream,
		apiClientPtr: &client,
	}

	if !errors.Is(adapter.Init(), initErr) {
		t.Fatal("expected Init error to propagate")
	}
	if !errors.Is(adapter.Run(context.Background()), runErr) {
		t.Fatal("expected Run error to propagate")
	}
}
