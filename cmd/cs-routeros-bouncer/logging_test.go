package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// restoreGlobalLogger snapshots the process-wide zerolog state so a test that
// repoints the logger at a temporary file cannot leak into other tests.
func restoreGlobalLogger(t *testing.T) {
	t.Helper()
	oldLogger := log.Logger
	oldLevel := zerolog.GlobalLevel()
	t.Cleanup(func() {
		log.Logger = oldLogger
		zerolog.SetGlobalLevel(oldLevel)
	})
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
}

// TestConfigureLogOutput verifies the logging.file destination: an empty path
// keeps the stderr-only default, a writable path is created with restrictive
// permissions and receives log lines, and an unopenable path is a startup error.
func TestConfigureLogOutput(t *testing.T) {
	const message = "log line from configureLogOutput"

	tests := []struct {
		name     string
		format   string
		file     string
		prepare  func(t *testing.T, dir string)
		wantErr  string
		wantLine string
	}{
		{
			name:   "empty path keeps stderr only",
			format: "text",
		},
		{
			name:   "empty path keeps stderr only in json format",
			format: "json",
		},
		{
			name:     "text format writes to the configured file",
			format:   "text",
			file:     "bouncer.log",
			wantLine: message,
		},
		{
			name:     "json format writes structured lines to the file",
			format:   "json",
			file:     "bouncer.log",
			wantLine: `"message":"` + message + `"`,
		},
		{
			name:    "missing parent directory is a startup error",
			format:  "text",
			file:    filepath.Join("absent", "bouncer.log"),
			wantErr: "cannot open logging.file",
		},
		{
			name:   "parent path that is a regular file is a startup error",
			format: "text",
			file:   filepath.Join("notadir", "bouncer.log"),
			prepare: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, "notadir"), []byte("not a directory"), 0o600); err != nil {
					t.Fatalf("create blocking file: %v", err)
				}
			},
			wantErr: "cannot open logging.file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreGlobalLogger(t)
			dir := t.TempDir()
			if tt.prepare != nil {
				tt.prepare(t, dir)
			}

			path := ""
			if tt.file != "" {
				path = filepath.Join(dir, tt.file)
			}

			out, err := configureLogOutput(config.LoggingConfig{Level: "info", Format: tt.format, File: path})
			if tt.wantErr != "" {
				assertLogOutputError(t, out, err, path, tt.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			log.Info().Msg(message)
			if closeErr := out.Close(); closeErr != nil {
				t.Fatalf("close log output: %v", closeErr)
			}

			if tt.file == "" {
				assertNoFilesCreated(t, dir)
				return
			}
			assertLogFile(t, path, tt.wantLine)
		})
	}
}

// assertLogOutputError checks that an unopenable logging.file fails startup
// with a message naming the configured path.
func assertLogOutputError(t *testing.T, out logOutput, err error, path, wantErr string) {
	t.Helper()
	if err == nil {
		closeLogOutput(out)
		t.Fatalf("expected error for logging.file %q", path)
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("error %q should contain %q", err, wantErr)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error should name the configured path %q: %v", path, err)
	}
}

// assertNoFilesCreated verifies the stderr-only default touches no files.
func assertNoFilesCreated(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("empty logging.file must not create any file, got %d entries", len(entries))
	}
}

// assertLogFile verifies the log file permissions and contents.
func assertLogFile(t *testing.T, path, wantLine string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("log file was not created: %v", err)
	}
	// The process umask can only clear bits from logFileMode, never add them,
	// so assert the created file carries no bit outside the chosen mask and
	// stays readable and writable by its owner.
	mode := info.Mode().Perm()
	if mode&^logFileMode.Perm() != 0 || mode&0o600 != 0o600 {
		t.Errorf("log file mode %v is not within %v", mode, logFileMode.Perm())
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(content), wantLine) {
		t.Errorf("log file should contain %q, got: %s", wantLine, content)
	}
}

// TestConfigureLogOutputAppendsAcrossRuns verifies a restart appends to an
// existing log file instead of truncating it.
func TestConfigureLogOutputAppendsAcrossRuns(t *testing.T) {
	restoreGlobalLogger(t)
	path := filepath.Join(t.TempDir(), "bouncer.log")

	runs := []string{"line from the first run", "line from the second run"}
	for _, message := range runs {
		out, err := configureLogOutput(config.LoggingConfig{Level: "info", Format: "json", File: path})
		if err != nil {
			t.Fatalf("configure log output for %q: %v", message, err)
		}
		log.Info().Msg(message)
		if closeErr := out.Close(); closeErr != nil {
			t.Fatalf("close log output: %v", closeErr)
		}
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	for _, message := range runs {
		if !strings.Contains(string(content), message) {
			t.Errorf("log file should still contain %q after the second run, got: %s", message, content)
		}
	}
}

// TestCloseLogOutputWithoutFile verifies the stderr-only handle closes cleanly.
func TestCloseLogOutputWithoutFile(t *testing.T) {
	if err := (logOutput{}).Close(); err != nil {
		t.Fatalf("closing a stderr-only log output should succeed: %v", err)
	}
	closeLogOutput(logOutput{})
}
