package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// Server serves Prometheus metrics and a health endpoint.
// The health endpoint is always registered so that container health checks
// work regardless of whether Prometheus metrics collection is enabled.
type Server struct {
	httpServer *http.Server
	version    string
	connected  atomic.Bool
}

var healthJSONMarshal = json.Marshal

// NewServer creates a new metrics HTTP server.
// When cfg.Enabled is true the /metrics endpoint is registered;
// the /health endpoint is always available.
func NewServer(cfg config.MetricsConfig, version string) *Server {
	s := &Server{
		version: version,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)

	if cfg.Enabled {
		mux.Handle("/metrics", promhttp.Handler())
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			http.Redirect(w, r, "/metrics", http.StatusMovedPermanently)
		})
	}

	s.httpServer = &http.Server{
		Addr:              net.JoinHostPort(cfg.ListenAddr, strconv.Itoa(cfg.ListenPort)),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	return s
}

// SetConnected updates the connection status used by the health endpoint.
func (s *Server) SetConnected(connected bool) {
	s.connected.Store(connected)
}

// Start begins serving the health (and optionally metrics) endpoint.
// The listener is bound synchronously so that address-in-use errors are
// returned to the caller. Serving itself runs in a background goroutine.
func (s *Server) Start() error {
	logger := log.With().Str("component", "metrics").Logger()

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.httpServer.Addr, err)
	}

	logger.Info().Str("addr", ln.Addr().String()).Msg("starting health/metrics server")

	go func() {
		if serveErr := s.httpServer.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Error().Err(serveErr).Msg("health/metrics server error")
		}
	}()

	return nil
}

// Shutdown gracefully stops the metrics server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{
		"status":             "ok",
		"routeros_connected": s.connected.Load(),
		"version":            s.version,
	}
	payload, err := healthJSONMarshal(resp)
	if err != nil {
		log.Error().Err(err).Msg("failed to encode health response")
		http.Error(w, "failed to encode health response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, writeErr := w.Write(append(payload, '\n')); writeErr != nil {
		log.Error().Err(writeErr).Msg("failed to write health response")
	}
}
