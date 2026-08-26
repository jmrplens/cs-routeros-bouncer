package crowdsec

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// Decision represents a parsed CrowdSec decision.
type Decision struct {
	Value    string        // IP or range
	Proto    string        // "ip" or "ipv6"
	Duration time.Duration // ban duration (0 = indefinite)
	Origin   string        // "crowdsec", "cscli", "CAPI", etc.
	Scenario string
	Type     string // "ban", etc.
	IsRange  bool   // true if CIDR range
}

// Stream wraps the CrowdSec StreamBouncer for decision streaming.
type Stream struct {
	bouncer BouncerEngine
	cfg     config.CrowdSecConfig
	logger  zerolog.Logger
	// enforcedTypes is resolved once at construction; parseDecision consults it
	// for every decision on both the live stream and the snapshot path.
	enforcedTypes map[string]struct{}
}

// defaultDecisionType is the only type CrowdSec defines as a constant, and the
// only one a firewall can act on without further machinery.
const defaultDecisionType = "ban"

// activeDecisionPageSize caps each CrowdSec active-decision page request.
const activeDecisionPageSize = 1000

// NewStream creates a new CrowdSec stream client.
func NewStream(cfg config.CrowdSecConfig, version string) *Stream {
	bouncer := &csbouncer.StreamBouncer{
		APIUrl:                 cfg.APIURL,
		APIKey:                 cfg.APIKey,
		TickerInterval:         cfg.UpdateFrequency.String(),
		UserAgent:              "cs-routeros-bouncer/" + version,
		Scopes:                 cfg.Scopes,
		ScenariosContaining:    cfg.ScenariosContaining,
		ScenariosNotContaining: cfg.ScenariosNotContaining,
		Origins:                cfg.Origins,
		RetryInitialConnect:    cfg.RetryInitialConnect,
	}

	// TLS configuration
	if cfg.CertPath != "" {
		bouncer.CertPath = cfg.CertPath
		bouncer.KeyPath = cfg.KeyPath
		bouncer.CAPath = cfg.CACertPath
	}
	if cfg.InsecureSkipVerify {
		bouncer.InsecureSkipVerify = &cfg.InsecureSkipVerify
	}

	return &Stream{
		bouncer: &bouncerAdapter{
			inner:        bouncer,
			streamPtr:    &bouncer.Stream,
			apiClientPtr: &bouncer.APIClient,
		},
		cfg:           cfg,
		logger:        log.With().Str("component", "crowdsec").Logger(),
		enforcedTypes: enforcedDecisionTypes(cfg),
	}
}

// Init initializes the stream bouncer (registers with LAPI).
func (s *Stream) Init() error {
	s.logger.Info().
		Str("api_url", s.cfg.APIURL).
		Dur("ticker", s.cfg.UpdateFrequency).
		Strs("origins", s.cfg.Origins).
		Strs("scopes", s.cfg.Scopes).
		Strs("decision_types", slices.Sorted(maps.Keys(s.enforcedTypes))).
		Msg("initializing CrowdSec stream bouncer")

	if err := s.bouncer.Init(); err != nil {
		return fmt.Errorf("initializing CrowdSec bouncer: %w", err)
	}

	return nil
}

// APIClient returns the underlying CrowdSec API client for use with
// the MetricsProvider. Must be called after Init().
func (s *Stream) APIClient() *apiclient.ApiClient {
	return s.bouncer.Client()
}

// ActiveDecisions fetches a full snapshot of currently active CrowdSec
// decisions. It carries the streaming bouncer's scope, origin and scenario
// filters, and adds one the stream does not: activeDecisionListPath sets
// type=ban server-side when the enforced set is exactly the default, so the
// snapshot asks for less than the stream receives. See onlyDefaultDecisionType
// for why that split exists.
func (s *Stream) ActiveDecisions(ctx context.Context) ([]*Decision, error) {
	client := s.bouncer.Client()
	if client == nil {
		return nil, errors.New("CrowdSec API client is not initialized")
	}

	var data models.GetDecisionsResponse
	for offset := 0; ; offset += activeDecisionPageSize {
		var page models.GetDecisionsResponse
		req, err := client.PrepareRequest(ctx, http.MethodGet, s.activeDecisionListPath(client, activeDecisionPageSize, offset), nil)
		if err != nil {
			return nil, fmt.Errorf("preparing active CrowdSec decision request: %w", err)
		}

		_, err = client.Do(ctx, req, &page)
		if err != nil {
			return nil, fmt.Errorf("fetching active CrowdSec decisions: %w", err)
		}

		data = append(data, page...)
		if len(page) < activeDecisionPageSize {
			break
		}
	}

	return parseDecisionBatch(data, true, s.enforcedTypes), nil
}

// activeDecisionListPath builds a filtered /decisions request for the periodic
// reconciliation snapshot without using the delta-stream startup mode.
func (s *Stream) activeDecisionListPath(client *apiclient.ApiClient, limit, offset int) string {
	values := url.Values{}
	// See onlyDefaultDecisionType: the Local API matches `type` exactly, so a
	// wider configured set has to be filtered client-side instead.
	if onlyDefaultDecisionType(s.enforcedTypes) {
		values.Set("type", defaultDecisionType)
	}
	values.Set("limit", strconv.Itoa(limit))
	values.Set("offset", strconv.Itoa(offset))
	if len(s.cfg.Scopes) > 0 {
		values.Set("scopes", strings.Join(s.cfg.Scopes, ","))
	} else {
		values.Set("scopes", "ip,range")
	}
	if len(s.cfg.Origins) > 0 {
		values.Set("origins", strings.Join(s.cfg.Origins, ","))
	}
	if len(s.cfg.ScenariosContaining) > 0 {
		values.Set("scenarios_containing", strings.Join(s.cfg.ScenariosContaining, ","))
	}
	if len(s.cfg.ScenariosNotContaining) > 0 {
		values.Set("scenarios_not_containing", strings.Join(s.cfg.ScenariosNotContaining, ","))
	}

	prefix := strings.Trim(client.URLPrefix, "/")
	path := "/decisions"
	if prefix != "" {
		path = "/" + prefix + path
	}

	return fmt.Sprintf("%s?%s", path, values.Encode())
}

// Run starts the stream bouncer and returns channels for new and deleted decisions.
// The banCh receives decisions to add, deleteCh receives decisions to remove.
// The function blocks until ctx is canceled.
func (s *Stream) Run(ctx context.Context, banCh, deleteCh chan<- *Decision) error {
	s.logger.Info().Msg("starting CrowdSec decision stream")

	go func() {
		if err := s.bouncer.Run(ctx); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
				errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				s.logger.Debug().Err(err).Msg("CrowdSec bouncer run loop stopped")
				return
			}
			s.logger.Error().Err(err).Msg("CrowdSec bouncer run loop stopped unexpectedly")
		}
	}()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info().Msg("CrowdSec stream stopped")
			return nil

		case decisions, ok := <-s.bouncer.DecisionStream():
			if !ok {
				return errors.New("CrowdSec stream channel closed")
			}

			if !s.forwardBatch(ctx, decisions.New, true, banCh) {
				return nil
			}
			if !s.forwardBatch(ctx, decisions.Deleted, false, deleteCh) {
				return nil
			}
		}
	}
}

// forwardBatch parses a decision batch, logs every entry, and forwards it to ch.
// isBan selects the ban-specific validation and log fields. It reports false
// when ctx is canceled mid-batch, so the caller can stop the stream loop.
func (s *Stream) forwardBatch(
	ctx context.Context,
	decisions models.GetDecisionsResponse,
	isBan bool,
	ch chan<- *Decision,
) bool {
	for _, parsed := range parseDecisionBatch(decisions, isBan, s.enforcedTypes) {
		if isBan {
			s.logger.Debug().
				Str("value", parsed.Value).
				Str("proto", parsed.Proto).
				Str("type", parsed.Type).
				Str("origin", parsed.Origin).
				Dur("duration", parsed.Duration).
				Msg("new decision")
		} else {
			s.logger.Debug().
				Str("value", parsed.Value).
				Str("proto", parsed.Proto).
				Str("origin", parsed.Origin).
				Msg("deleted decision")
		}

		select {
		case ch <- parsed:
		case <-ctx.Done():
			return false
		}
	}

	return true
}

// parseDecisionBatch converts an LAPI decision response into internal
// decisions. New bans require a duration; deleted decisions do not always
// include one, so callers choose that validation rule explicitly.
func parseDecisionBatch(decisions models.GetDecisionsResponse, requireDuration bool, enforced map[string]struct{}) []*Decision {
	parsed := make([]*Decision, 0, len(decisions))
	for _, d := range decisions {
		if d == nil {
			continue
		}
		if requireDuration && d.Duration == nil {
			continue
		}
		decision := parseDecision(d, enforced)
		if decision == nil {
			continue
		}
		parsed = append(parsed, decision)
	}
	return parsed
}

// enforcedDecisionTypes returns the decision types this bouncer acts on, lower
// cased for comparison. CrowdSec's Decision.Type is a free string — only "ban"
// is a defined constant, and `cscli decisions add --type anything` is accepted —
// so an operator running a scenario that emits a custom type can name it here
// and have it enforced as a block.
func enforcedDecisionTypes(cfg config.CrowdSecConfig) map[string]struct{} {
	types := make(map[string]struct{}, len(cfg.SupportedDecisionTypes))
	for _, t := range cfg.SupportedDecisionTypes {
		if trimmed := strings.ToLower(strings.TrimSpace(t)); trimmed != "" {
			types[trimmed] = struct{}{}
		}
	}
	if len(types) == 0 {
		types[defaultDecisionType] = struct{}{}
	}
	return types
}

// onlyDefaultDecisionType reports whether the configured set is exactly the
// default. When it is, the snapshot query can keep its server-side `type=ban`
// filter: the Local API matches that parameter EXACTLY (verified — `type=a,b`
// returns nothing, and omitting it returns every type), so supporting a wider
// set means fetching everything and filtering here. That is the right trade
// only for operators who asked for it; on a busy Local API the default set
// would otherwise pull captcha decisions across the wire on every
// reconciliation snapshot just to discard them.
func onlyDefaultDecisionType(types map[string]struct{}) bool {
	// Empty means unconfigured, which is the default set — same reasoning as
	// isEnforced: an unset map must not silently change the query.
	if len(types) == 0 {
		return true
	}
	if len(types) != 1 {
		return false
	}
	_, ok := types[defaultDecisionType]
	return ok
}

// isEnforced reports whether a decision type should be acted on. An empty set
// means the default: a Stream assembled without NewStream (tests, and any future
// construction path) must not silently discard every decision it is handed —
// that failure mode looks exactly like a quiet Local API.
func isEnforced(enforced map[string]struct{}, decisionType string) bool {
	normalised := strings.ToLower(strings.TrimSpace(decisionType))
	if len(enforced) == 0 {
		return normalised == defaultDecisionType
	}
	_, ok := enforced[normalised]
	return ok
}

// parseDecision converts a CrowdSec SDK decision model to our internal Decision type.
func parseDecision(d *models.Decision, enforced map[string]struct{}) *Decision {
	if d.Value == nil || d.Type == nil {
		return nil
	}

	value := *d.Value
	decType := *d.Type

	// Only process the decision types this bouncer was configured to enforce.
	if !isEnforced(enforced, decType) {
		return nil
	}

	var duration time.Duration
	if d.Duration != nil {
		var err error
		duration, err = ParseDuration(*d.Duration)
		if err != nil {
			log.Warn().Str("duration", *d.Duration).Err(err).Msg("failed to parse decision duration")
			duration = 4 * time.Hour // fallback
		}
	}

	origin := ""
	if d.Origin != nil {
		origin = *d.Origin
	}
	scenario := ""
	if d.Scenario != nil {
		scenario = *d.Scenario
	}

	proto := DetectProto(value)
	isRange := IsRange(value)

	return &Decision{
		Value:    value,
		Proto:    proto,
		Duration: duration,
		Origin:   origin,
		Scenario: scenario,
		Type:     decType,
		IsRange:  isRange,
	}
}

// DetectProto detects whether an address is IPv4 or IPv6.
func DetectProto(address string) string {
	// Remove CIDR prefix if present
	host := address
	if before, _, found := strings.Cut(address, "/"); found {
		host = before
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// Try as CIDR
		_, _, err := net.ParseCIDR(address)
		if err != nil {
			// Default to IPv4 if unparseable
			return "ip"
		}
	}

	if ip != nil && ip.To4() == nil {
		return "ipv6"
	}
	return "ip"
}

// IsRange returns true if the address is a CIDR range.
func IsRange(address string) bool {
	return strings.Contains(address, "/")
}

// ParseDuration parses a CrowdSec duration string (e.g., "4h", "3600s", "1h30m15.5s")
// into a time.Duration. CrowdSec durations typically use Go duration format.
func ParseDuration(s string) (time.Duration, error) {
	// CrowdSec can return durations with trailing fractions like "3599.xxxx..."
	// time.ParseDuration handles most Go-format durations
	d, err := time.ParseDuration(s)
	if err != nil {
		// Try as plain seconds (number-only string)
		s = strings.TrimSuffix(s, "s")
		d, err = time.ParseDuration(s + "s")
		if err != nil {
			return 0, fmt.Errorf("parse duration %q: %w", s, err)
		}
	}
	return d, nil
}
