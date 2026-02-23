package crowdsec

import (
	"context"
	"fmt"
	"net"
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
	bouncer *csbouncer.StreamBouncer
	cfg     config.CrowdSecConfig
	logger  zerolog.Logger
}

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
		bouncer: bouncer,
		cfg:     cfg,
		logger:  log.With().Str("component", "crowdsec").Logger(),
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
	return s.bouncer.APIClient
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

		case decisions, ok := <-s.bouncer.Stream:
			if !ok {
				return fmt.Errorf("CrowdSec stream channel closed")
			}

			// Process new decisions (bans)
			if decisions.New != nil {
				for _, d := range decisions.New {
					if d == nil || d.Value == nil || d.Type == nil || d.Duration == nil {
						continue
					}

					parsed := parseDecision(d)
					if parsed == nil {
						continue
					}

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
			}

			// Process deleted decisions (unbans)
			if decisions.Deleted != nil {
				for _, d := range decisions.Deleted {
					if d == nil || d.Value == nil || d.Type == nil {
						continue
					}

					parsed := parseDecision(d)
					if parsed == nil {
						continue
					}

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
