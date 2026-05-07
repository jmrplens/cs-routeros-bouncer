package crowdsec

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
}

const activeDecisionPageSize = 1000

// NewStream creates a new CrowdSec stream client.
func NewStream(cfg config.CrowdSecConfig, version string) *Stream {
	bouncer := &csbouncer.StreamBouncer{
		APIUrl:                 cfg.APIURL,
		APIKey:                 cfg.APIKey,
		TickerInterval:         cfg.UpdateFrequency.String(),
		UserAgent:              fmt.Sprintf("cs-routeros-bouncer/%s", version),
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
		cfg:    cfg,
		logger: log.With().Str("component", "crowdsec").Logger(),
	}
}

// Init initializes the stream bouncer (registers with LAPI).
func (s *Stream) Init() error {
	s.logger.Info().
		Str("api_url", s.cfg.APIURL).
		Dur("ticker", s.cfg.UpdateFrequency).
		Strs("origins", s.cfg.Origins).
		Strs("scopes", s.cfg.Scopes).
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
// decisions using the same filters as the streaming bouncer.
func (s *Stream) ActiveDecisions(ctx context.Context) ([]*Decision, error) {
	client := s.bouncer.Client()
	if client == nil {
		return nil, fmt.Errorf("CrowdSec API client is not initialized")
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

	return parseDecisionBatch(data, true), nil
}

// activeDecisionListPath builds a filtered /decisions request for the periodic
// reconciliation snapshot without using the delta-stream startup mode.
func (s *Stream) activeDecisionListPath(client *apiclient.ApiClient, limit, offset int) string {
	values := url.Values{}
	values.Set("type", "ban")
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
func (s *Stream) Run(ctx context.Context, banCh chan<- *Decision, deleteCh chan<- *Decision) error {
	s.logger.Info().Msg("starting CrowdSec decision stream")

	go func() {
		_ = s.bouncer.Run(ctx) //nolint:errcheck // error is logged internally by the bouncer
	}()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info().Msg("CrowdSec stream stopped")
			return nil

		case decisions, ok := <-s.bouncer.DecisionStream():
			if !ok {
				return fmt.Errorf("CrowdSec stream channel closed")
			}

			// Process new decisions (bans)
			for _, parsed := range parseDecisionBatch(decisions.New, true) {
				s.logger.Debug().
					Str("value", parsed.Value).
					Str("proto", parsed.Proto).
					Str("type", parsed.Type).
					Str("origin", parsed.Origin).
					Dur("duration", parsed.Duration).
					Msg("new decision")

				select {
				case banCh <- parsed:
				case <-ctx.Done():
					return nil
				}
			}

			// Process deleted decisions (unbans)
			for _, parsed := range parseDecisionBatch(decisions.Deleted, false) {
				s.logger.Debug().
					Str("value", parsed.Value).
					Str("proto", parsed.Proto).
					Str("origin", parsed.Origin).
					Msg("deleted decision")

				select {
				case deleteCh <- parsed:
				case <-ctx.Done():
					return nil
				}
			}
		}
	}
}

// parseDecisionBatch converts an LAPI decision response into internal
// decisions. New bans require a duration; deleted decisions do not always
// include one, so callers choose that validation rule explicitly.
func parseDecisionBatch(decisions models.GetDecisionsResponse, requireDuration bool) []*Decision {
	parsed := make([]*Decision, 0, len(decisions))
	for _, d := range decisions {
		if d == nil {
			continue
		}
		if requireDuration && d.Duration == nil {
			continue
		}
		decision := parseDecision(d)
		if decision == nil {
			continue
		}
		parsed = append(parsed, decision)
	}
	return parsed
}

// parseDecision converts a CrowdSec SDK decision model to our internal Decision type.
func parseDecision(d *models.Decision) *Decision {
	if d.Value == nil || d.Type == nil {
		return nil
	}

	value := *d.Value
	decType := *d.Type

	// Only process supported decision types
	if !strings.EqualFold(decType, "ban") {
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
	if idx := strings.Index(address, "/"); idx != -1 {
		host = address[:idx]
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
