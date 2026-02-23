// bouncer_iface.go defines the interface that abstracts the CrowdSec
// StreamBouncer. By depending on this interface instead of the concrete
// *csbouncer.StreamBouncer, the Stream methods become unit-testable with
// a mock that feeds decisions through a channel without a real LAPI.
package crowdsec

import (
	"context"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// BouncerEngine abstracts the CrowdSec StreamBouncer operations used by
// Stream. The concrete implementation is *csbouncer.StreamBouncer.
type BouncerEngine interface {
	// Init registers the bouncer with the CrowdSec LAPI.
	Init() error
	// Run starts the polling loop; blocks until ctx is canceled.
	Run(ctx context.Context) error
	// DecisionStream returns the channel that delivers decision batches.
	DecisionStream() <-chan *models.DecisionsStreamResponse
	// Client returns the underlying LAPI API client (available after Init).
	Client() *apiclient.ApiClient
}

// bouncerAdapter wraps *csbouncer.StreamBouncer to satisfy BouncerEngine.
// It stores the concrete bouncer so channel and field reads happen
// dynamically (the Stream channel is nil until Init creates it).
type bouncerAdapter struct {
	inner interface {
		Init() error
		Run(ctx context.Context) error
	}
	// streamPtr points to the bouncer's Stream field so we read
	// the channel after Init() creates it.
	streamPtr *chan *models.DecisionsStreamResponse
	// apiClientPtr points to the bouncer's APIClient field,
	// populated during Init().
	apiClientPtr **apiclient.ApiClient
}

func (a *bouncerAdapter) Init() error                   { return a.inner.Init() }
func (a *bouncerAdapter) Run(ctx context.Context) error  { return a.inner.Run(ctx) }
func (a *bouncerAdapter) DecisionStream() <-chan *models.DecisionsStreamResponse {
	return *a.streamPtr
}
func (a *bouncerAdapter) Client() *apiclient.ApiClient { return *a.apiClientPtr }
