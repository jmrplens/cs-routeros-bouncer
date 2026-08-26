// Tests for the profiler endpoint: it must be absent unless the operator asks
// for it, and present without depending on Prometheus metrics being on.
package metrics

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// TestPprofOffByDefault pins that the profiler is not reachable unless the
// operator asked for it — the metrics listener binds 0.0.0.0 by default, and
// heap profiles can carry anything the process has held.
func TestPprofOffByDefault(t *testing.T) {
	srv := NewServer(config.MetricsConfig{Enabled: true}, "test")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("pprof must be absent by default, got HTTP %d", rec.Code)
	}
}

// TestPprofServedWhenEnabled pins the other half, including that it does not
// depend on metrics.enabled — profiling a bouncer with metrics off is exactly
// when you would need it.
func TestPprofServedWhenEnabled(t *testing.T) {
	srv := NewServer(config.MetricsConfig{Enabled: false, PprofEnabled: true}, "test")
	for _, path := range []string{"/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/symbol"} {
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: expected HTTP 200, got %d", path, rec.Code)
		}
	}
	// /health must still work alongside it.
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK && rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/health broke: HTTP %d", rec.Code)
	}
}

// TestPprofWarnsOnStart pins the warning, which is the part that matters most:
// a flag left on by accident has to be visible in the log, and the message has
// to name the exposure rather than merely mention pprof.
func TestPprofWarnsOnStart(t *testing.T) {
	var buf bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = previous })

	srv := NewServer(config.MetricsConfig{
		Enabled:      true,
		PprofEnabled: true,
		ListenAddr:   "127.0.0.1",
	}, "test")
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	out := buf.String()
	if !strings.Contains(out, "pprof") {
		t.Fatalf("no pprof warning in the log: %s", out)
	}
	if !strings.Contains(out, "warn") {
		t.Errorf("the pprof notice must be a warning, got: %s", out)
	}
	for _, want := range []string{"credentials", "localhost"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning should mention %q, got: %s", want, out)
		}
	}
}

// TestNoPprofWarningWhenDisabled pins the other half — no cry-wolf on a normal
// start, or the warning stops meaning anything.
func TestNoPprofWarningWhenDisabled(t *testing.T) {
	var buf bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = previous })

	srv := NewServer(config.MetricsConfig{Enabled: true, ListenAddr: "127.0.0.1"}, "test")
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	if strings.Contains(buf.String(), "pprof") {
		t.Errorf("no pprof warning expected when disabled: %s", buf.String())
	}
}
