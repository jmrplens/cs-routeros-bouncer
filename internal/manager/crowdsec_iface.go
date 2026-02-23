package manager

import (
	"context"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"

	"github.com/jmrplens/cs-routeros-bouncer/internal/crowdsec"
)

// CrowdSecStream abstracts the CrowdSec streaming operations that Manager
// depends on. It follows the same consumer-side interface pattern as
// RouterOSClient — the concrete *crowdsec.Stream implicitly satisfies it.
// Test code provides a mock implementation (mockStream) to exercise the
// Start/Shutdown lifecycle without a real CrowdSec LAPI.
type CrowdSecStream interface {
	// Init registers the bouncer with the CrowdSec LAPI.
	Init() error

	// Run starts the decision stream. It sends new bans to banCh and
	// deleted decisions to deleteCh. It blocks until ctx is canceled.
	Run(ctx context.Context, banCh chan<- *crowdsec.Decision, deleteCh chan<- *crowdsec.Decision) error

	// APIClient returns the underlying LAPI client for metrics reporting.
	// Must be called after Init().
	APIClient() *apiclient.ApiClient
}
