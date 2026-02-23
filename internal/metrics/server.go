package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// Server serves Prometheus metrics and a health endpoint.
type Server struct {
	httpServer *http.Server
	version    string
	connected  atomic.Bool
}

// NewServer creates a new metrics HTTP server.
func NewServer(cfg config.MetricsConfig, version string) *Server {
	s := &Server{
		version: version,
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/metrics", http.StatusMovedPermanently)
	})

	s.httpServer = &http.Server{
		Addr:              net.JoinHostPort(cfg.ListenAddr, fmt.Sprintf("%d", cfg.ListenPort)),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	return s
}

// SetConnected updates the connection status used by the health endpoint.
func (s *Server) SetConnected(connected bool) {
	s.connected.Store(connected)
}

// Start begins serving metrics. It returns immediately; the server runs in a goroutine.
func (s *Server) Start() error {
	logger := log.With().Str("component", "metrics").Logger()
	logger.Info().Str("addr", s.httpServer.Addr).Msg("starting metrics server")

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error().Err(err).Msg("metrics server error")
		}
	}()

	return nil
}

// Shutdown gracefully stops the metrics server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"status":             "ok",
		"routeros_connected": s.connected.Load(),
		"version":            s.version,
	}
	_ = json.NewEncoder(w).Encode(resp)
}
