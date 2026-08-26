// Tests for the profiler endpoint: it must be absent unless the operator asks
// for it, and present without depending on Prometheus metrics being on.
package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
