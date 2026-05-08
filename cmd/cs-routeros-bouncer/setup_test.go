package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// resetSetupHooks restores package-level setup hooks after a test or benchmark.
func resetSetupHooks(tb testing.TB) {
	tb.Helper()
	oldGetuid := setupGetuid
	oldExecutable := setupExecutable
	oldEvalSymlinks := setupEvalSymlinks
	oldMkdirAll := setupMkdirAll
	oldStat := setupStat
	oldWriteFile := setupWriteFile
	oldRemove := setupRemove
	oldRemoveAll := setupRemoveAll
	oldCopyFile := setupCopyFile
	oldSystemctl := setupSystemctl
	oldServicePath := setupServicePath
	oldConfigDir := setupConfigDir
	tb.Cleanup(func() {
		setupGetuid = oldGetuid
		setupExecutable = oldExecutable
		setupEvalSymlinks = oldEvalSymlinks
		setupMkdirAll = oldMkdirAll
		setupStat = oldStat
		setupWriteFile = oldWriteFile
		setupRemove = oldRemove
		setupRemoveAll = oldRemoveAll
		setupCopyFile = oldCopyFile
		setupSystemctl = oldSystemctl
		setupServicePath = oldServicePath
		setupConfigDir = oldConfigDir
	})
}

// configureRootSetup installs root-mode test doubles for a successful setup path.
func configureRootSetup(tb testing.TB) (binSrc, servicePath string, systemctlCalls *[][]string) {
	tb.Helper()
	resetSetupHooks(tb)
	tmpDir := tb.TempDir()
	binSrc = filepath.Join(tmpDir, "source-bin")
	servicePath = filepath.Join(tmpDir, "cs-routeros-bouncer.service")
	if err := os.WriteFile(binSrc, []byte("binary"), 0o700); err != nil {
		tb.Fatalf("write source binary: %v", err)
	}
	calls := [][]string{}
	setupGetuid = func() int { return 0 }
	setupExecutable = func() (string, error) { return binSrc, nil }
	setupEvalSymlinks = func(path string) (string, error) { return path, nil }
	setupServicePath = servicePath
	setupSystemctl = func(args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		return nil
	}
	return binSrc, servicePath, &calls
}

// TestRunSetupRequiresRoot verifies setup refuses to run without root privileges.
func TestRunSetupRequiresRoot(t *testing.T) {
	resetSetupHooks(t)
	setupGetuid = func() int { return 1000 }

	err := runSetup(filepath.Join(t.TempDir(), "bin"), filepath.Join(t.TempDir(), "config"))
	if err == nil || !strings.Contains(err.Error(), "setup must be run as root") {
		t.Fatalf("expected root error, got %v", err)
	}
}

// TestRunUninstallRequiresRoot verifies uninstall refuses to run without root privileges.
func TestRunUninstallRequiresRoot(t *testing.T) {
	resetSetupHooks(t)
	setupGetuid = func() int { return 1000 }

	err := runUninstall(filepath.Join(t.TempDir(), "bin"), false)
	if err == nil || !strings.Contains(err.Error(), "uninstall must be run as root") {
		t.Fatalf("expected root error, got %v", err)
	}
}

// TestRunSetupSuccess verifies binary, config, service, and systemctl setup steps.
func TestRunSetupSuccess(t *testing.T) {
	_, servicePath, systemctlCalls := configureRootSetup(t)
	tmpDir := t.TempDir()
	binDst := filepath.Join(tmpDir, "bin", "cs-routeros-bouncer")
	configDir := filepath.Join(tmpDir, "config")
	if err := os.MkdirAll(filepath.Dir(binDst), 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}

	_ = captureStdout(t, func() {
		if err := runSetup(binDst, configDir); err != nil {
			t.Fatalf("runSetup: %v", err)
		}
	})

	binData, err := os.ReadFile(binDst)
	if err != nil {
		t.Fatalf("read installed binary: %v", err)
	}
	if string(binData) != "binary" {
		t.Fatalf("unexpected installed binary contents: %q", string(binData))
	}
	configPath := filepath.Join(configDir, defaultConfigFile)
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	if !strings.Contains(string(configData), `reconciliation_interval: "15m"`) {
		t.Fatalf("generated config missing reconciliation interval")
	}
	if strings.Contains(string(configData), "\t") {
		t.Fatalf("generated config should not contain YAML tabs")
	}
	if !strings.Contains(string(configData), `${CROWDSEC_BOUNCER_API_KEY}`) || !strings.Contains(string(configData), `${MIKROTIK_PASS}`) {
		t.Fatalf("generated config missing environment variable placeholders")
	}
	unitData, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatalf("read service unit: %v", err)
	}
	if !strings.Contains(string(unitData), "ExecStart="+binDst+" -c "+configPath) {
		t.Fatalf("service unit does not reference installed paths: %s", string(unitData))
	}
	assert.Len(t, *systemctlCalls, 3, "systemctl calls")
	assert.Equal(t, []string{"daemon-reload"}, (*systemctlCalls)[0], "first call")
	assert.Equal(t, []string{"enable", serviceName}, (*systemctlCalls)[1], "second call")
	assert.Equal(t, []string{"start", serviceName}, (*systemctlCalls)[2], "third call")
}

// TestRunSetupCopyError verifies binary copy failures are reported.
func TestRunSetupCopyError(t *testing.T) {
	resetSetupHooks(t)
	setupGetuid = func() int { return 0 }
	setupExecutable = func() (string, error) { return filepath.Join(t.TempDir(), "missing"), nil }
	setupEvalSymlinks = func(path string) (string, error) { return path, nil }

	err := runSetup(filepath.Join(t.TempDir(), "bin"), filepath.Join(t.TempDir(), "config"))
	if err == nil || !strings.Contains(err.Error(), "failed to copy binary") {
		t.Fatalf("expected copy error, got %v", err)
	}
}

// TestRunSetupMkdirError verifies config directory creation failures are reported.
func TestRunSetupMkdirError(t *testing.T) {
	_, _, _ = configureRootSetup(t)
	setupMkdirAll = func(string, os.FileMode) error { return errors.New("mkdir denied") }

	err := runSetup(filepath.Join(t.TempDir(), "bin"), filepath.Join(t.TempDir(), "config"))
	if err == nil || !strings.Contains(err.Error(), "failed to create config dir") {
		t.Fatalf("expected mkdir error, got %v", err)
	}
}

// TestRunSetupConfigWriteError verifies generated config write failures are reported.
func TestRunSetupConfigWriteError(t *testing.T) {
	_, _, _ = configureRootSetup(t)
	configDir := filepath.Join(t.TempDir(), "config")
	setupWriteFile = func(path string, data []byte, perm os.FileMode) error {
		if path == filepath.Join(configDir, defaultConfigFile) {
			return errors.New("config denied")
		}
		return os.WriteFile(path, data, perm)
	}

	err := runSetup(filepath.Join(t.TempDir(), "bin"), configDir)
	if err == nil || !strings.Contains(err.Error(), "failed to write config") {
		t.Fatalf("expected config write error, got %v", err)
	}
}

// TestRunSetupServiceWriteError verifies systemd unit write failures are reported.
func TestRunSetupServiceWriteError(t *testing.T) {
	_, servicePath, _ := configureRootSetup(t)
	setupWriteFile = func(path string, data []byte, perm os.FileMode) error {
		if path == servicePath {
			return errors.New("service denied")
		}
		return os.WriteFile(path, data, perm)
	}

	err := runSetup(filepath.Join(t.TempDir(), "bin"), filepath.Join(t.TempDir(), "config"))
	if err == nil || !strings.Contains(err.Error(), "failed to write service file") {
		t.Fatalf("expected service write error, got %v", err)
	}
}

// TestRunSetupSystemctlErrors verifies each systemctl setup failure is surfaced.
func TestRunSetupSystemctlErrors(t *testing.T) {
	tests := []struct {
		name    string
		failCmd string
		want    string
	}{
		{"reload", "daemon-reload", "reload systemd daemon"},
		{"enable", "enable", "enable cs-routeros-bouncer"},
		{"start", "start", "start cs-routeros-bouncer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _ = configureRootSetup(t)
			setupSystemctl = func(args ...string) error {
				if args[0] == tt.failCmd {
					return errors.New("systemctl failed")
				}
				return nil
			}

			err := runSetup(filepath.Join(t.TempDir(), "bin"), filepath.Join(t.TempDir(), "config"))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q error, got %v", tt.want, err)
			}
		})
	}
}

// TestRunUninstallSuccess verifies uninstall removes service, binary, and optional config.
func TestRunUninstallSuccess(t *testing.T) {
	resetSetupHooks(t)
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "cs-routeros-bouncer")
	servicePath := filepath.Join(tmpDir, "cs-routeros-bouncer.service")
	configDir := filepath.Join(tmpDir, "config")
	for path, data := range map[string]string{binPath: "binary", servicePath: "unit"} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	var calls [][]string
	setupGetuid = func() int { return 0 }
	setupServicePath = servicePath
	setupConfigDir = configDir
	setupSystemctl = func(args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		return nil
	}

	_ = captureStdout(t, func() {
		if err := runUninstall(binPath, true); err != nil {
			t.Fatalf("runUninstall: %v", err)
		}
	})

	for _, path := range []string{binPath, servicePath, configDir} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed, stat err=%v", path, err)
		}
	}
	if got := len(calls); got != 3 {
		t.Fatalf("expected 3 systemctl calls, got %d: %v", got, calls)
	}
}

// TestCopyFileCopiesContents verifies copyFile preserves contents and permissions.
func TestCopyFileCopiesContents(t *testing.T) {
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "source")
	dst := filepath.Join(tmpDir, "dest")

	if err := os.WriteFile(src, []byte("routeros bouncer"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := copyFile(src, dst, 0o600); err != nil {
		t.Fatalf("copyFile: %v", err)
	}

	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(data) != "routeros bouncer" {
		t.Fatalf("unexpected copied contents: %q", string(data))
	}
}

// TestCopyFileMissingSource verifies copyFile reports source open errors.
func TestCopyFileMissingSource(t *testing.T) {
	err := copyFile(filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "dest"), 0o600)
	if err == nil {
		t.Fatal("expected missing source error")
	}
}

// TestCopyFileDestinationOpenError verifies copyFile reports destination open errors.
func TestCopyFileDestinationOpenError(t *testing.T) {
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "source")
	if err := os.WriteFile(src, []byte("data"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	err := copyFile(src, filepath.Join(tmpDir, "missing", "dest"), 0o600)
	if err == nil {
		t.Fatal("expected destination open error")
	}
}

// TestCopyFileReadError verifies copyFile reports read errors from the source.
func TestCopyFileReadError(t *testing.T) {
	tmpDir := t.TempDir()
	err := copyFile(tmpDir, filepath.Join(t.TempDir(), "dest"), 0o600)
	if err == nil {
		t.Fatal("expected read error when copying a directory")
	}
}

// TestExampleConfigIncludesExpectedDefaults verifies generated YAML includes key defaults.
func TestExampleConfigIncludesExpectedDefaults(t *testing.T) {
	cfg := exampleConfig()
	for _, want := range []string{
		`api_url: "http://localhost:8080/"`,
		`reconciliation_interval: "15m"`,
		`address: "192.168.0.1:8728"`,
		`rule_placement: "top"`,
		`listen_port: 2112`,
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("example config missing %q", want)
		}
	}
}

// TestSystemctlUsesPathAndReportsStderr verifies systemctl error messages include stderr.
func TestSystemctlUsesPathAndReportsStderr(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "systemctl.args")
	scriptPath := filepath.Join(tmpDir, "systemctl")
	script := `#!/bin/sh
printf '%s\n' "$@" > "$SYSTEMCTL_LOG"
if [ "$1" = "fail" ]; then
  echo "denied by test" >&2
  exit 7
fi
exit 0
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}
	t.Setenv("PATH", tmpDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SYSTEMCTL_LOG", logPath)

	if err := systemctl("daemon-reload"); err != nil {
		t.Fatalf("systemctl success path: %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read systemctl log: %v", err)
	}
	if string(data) != "daemon-reload\n" {
		t.Fatalf("unexpected systemctl args: %q", string(data))
	}

	err = systemctl("fail")
	if err == nil {
		t.Fatal("expected fake systemctl failure")
	}
	if !strings.Contains(err.Error(), "denied by test") {
		t.Fatalf("expected stderr in error, got %v", err)
	}
}
