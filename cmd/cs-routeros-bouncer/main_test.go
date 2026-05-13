package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// TestHandleSubcommand verifies non-administrative argv values are ignored.
func TestHandleSubcommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "no args", args: []string{"cs-routeros-bouncer"}},
		{name: "unknown", args: []string{"cs-routeros-bouncer", "run"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldArgs := os.Args
			t.Cleanup(func() { os.Args = oldArgs })
			os.Args = tt.args

			if got := handleSubcommand(); got != tt.want {
				t.Fatalf("handleSubcommand() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNormalizeRunArgs verifies the optional run subcommand preserves default command behavior.
func TestNormalizeRunArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{name: "implicit run", args: []string{"-c", "config.yaml"}, want: []string{"-c", "config.yaml"}},
		{name: "explicit run", args: []string{"run", "-c", "config.yaml"}, want: []string{"-c", "config.yaml"}},
		{name: "run only", args: []string{"run"}, want: []string{}},
		{name: "compose shell wrapper", args: []string{"sh", "-c", "until nc -z crowdsec 8080; do sleep 2; done; exec /usr/local/bin/crowdsec-cloudflare-bouncer"}, want: []string{}},
		{name: "compose shell wrapper string", args: []string{"sh -c \"until nc -z crowdsec 8080; do sleep 2; done; exec /usr/local/bin/crowdsec-cloudflare-bouncer\""}, want: []string{}},
		{name: "compose shell wrapper absolute", args: []string{"/bin/sh", "-c", "echo ready"}, want: []string{}},
		{name: "run then shell wrapper", args: []string{"run", "sh", "-c", "echo ready"}, want: []string{}},
		{name: "shell without command flag", args: []string{"sh", "script.sh"}, want: []string{"sh", "script.sh"}},
		{name: "run non-first", args: []string{"-c", "config.yaml", "run"}, want: []string{"-c", "config.yaml", "run"}},
		{name: "run as value", args: []string{"-mode", "run"}, want: []string{"-mode", "run"}},
		{name: "empty", args: nil, want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeRunArgs(tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("normalizeRunArgs(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

// TestResolveRunConfigPath verifies Docker's default mounted config file is
// used only when no explicit path was supplied and the file is present.
func TestResolveRunConfigPath(t *testing.T) {
	oldStat := runConfigStat
	oldPath := runConfigPath
	t.Cleanup(func() {
		runConfigStat = oldStat
		runConfigPath = oldPath
	})

	runConfigPath = "/etc/cs-routeros-bouncer/config.yaml"

	t.Run("explicit path wins", func(t *testing.T) {
		called := false
		runConfigStat = func(string) (os.FileInfo, error) {
			called = true
			return nil, nil
		}
		if got := resolveRunConfigPath("custom.yaml"); got != "custom.yaml" {
			t.Fatalf("resolveRunConfigPath() = %q, want custom.yaml", got)
		}
		if called {
			t.Fatal("stat should not be called for an explicit config path")
		}
	})

	t.Run("default path exists", func(t *testing.T) {
		runConfigStat = func(path string) (os.FileInfo, error) {
			if path != runConfigPath {
				t.Fatalf("stat path = %q, want %q", path, runConfigPath)
			}
			return nil, nil
		}
		if got := resolveRunConfigPath(""); got != runConfigPath {
			t.Fatalf("resolveRunConfigPath() = %q, want %q", got, runConfigPath)
		}
	})

	t.Run("default path missing", func(t *testing.T) {
		runConfigStat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
		if got := resolveRunConfigPath(""); got != "" {
			t.Fatalf("resolveRunConfigPath() = %q, want empty", got)
		}
	})

	t.Run("default path stat error", func(t *testing.T) {
		runConfigStat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
		if got := resolveRunConfigPath(""); got != runConfigPath {
			t.Fatalf("resolveRunConfigPath() = %q, want %q", got, runConfigPath)
		}
	})
}

// TestParseRunFlags verifies valid run-mode flags are parsed.
func TestParseRunFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantConfig  string
		wantVersion bool
	}{
		{name: "default", args: nil},
		{name: "config path", args: []string{"-c", "config.yaml"}, wantConfig: "config.yaml"},
		{name: "version", args: []string{"--version"}, wantVersion: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotConfig, gotVersion, err := parseRunFlags(tt.args)
			if err != nil {
				t.Fatalf("parseRunFlags(%v): %v", tt.args, err)
			}
			if *gotConfig != tt.wantConfig || *gotVersion != tt.wantVersion {
				t.Fatalf("parseRunFlags(%v) = config=%q version=%v, want config=%q version=%v", tt.args, *gotConfig, *gotVersion, tt.wantConfig, tt.wantVersion)
			}
		})
	}
}

// TestParseRunFlagsErrors verifies invalid run-mode args fail before config load.
func TestParseRunFlagsErrors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "unexpected positional", args: []string{"typo"}, wantErr: `unexpected argument "typo"`},
		{name: "unknown flag", args: []string{"-bad"}, wantErr: "flag provided but not defined"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			_ = captureStdout(t, func() {
				_, _, err = parseRunFlags(tt.args)
			})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("parseRunFlags(%v) error = %v, want containing %q", tt.args, err, tt.wantErr)
			}
		})
	}
}

// TestRunBouncerRejectsPositionalArgs verifies invalid run-mode args stop before config load.
func TestRunBouncerRejectsPositionalArgs(t *testing.T) {
	if os.Getenv("CS_ROUTEROS_BOUNCER_TEST_RUN_BOUNCER") == "1" {
		runBouncer([]string{"typo"})
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunBouncerRejectsPositionalArgs")
	cmd.Env = append(os.Environ(), "CS_ROUTEROS_BOUNCER_TEST_RUN_BOUNCER=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected runBouncer to exit with error, output: %s", output)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected exec.ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got %d; output: %s", exitErr.ExitCode(), output)
	}
	if !strings.Contains(string(output), `unexpected argument "typo"`) || !strings.Contains(string(output), "Usage:") {
		t.Fatalf("expected error and usage output, got: %s", output)
	}
}

// TestRunBouncerVersionExits verifies run-mode version output exits cleanly.
func TestRunBouncerVersionExits(t *testing.T) {
	if os.Getenv("CS_ROUTEROS_BOUNCER_TEST_RUN_BOUNCER_VERSION") == "1" {
		runBouncer([]string{"--version"})
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunBouncerVersionExits")
	cmd.Env = append(os.Environ(), "CS_ROUTEROS_BOUNCER_TEST_RUN_BOUNCER_VERSION=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected runBouncer version to exit cleanly, err=%v output=%s", err, output)
	}
	if !strings.Contains(string(output), "cs-routeros-bouncer") || !strings.Contains(string(output), "commit:") {
		t.Fatalf("expected version metadata, got: %s", output)
	}
}

// TestRunBouncerInvalidConfigExits verifies config load failures exit before startup.
func TestRunBouncerInvalidConfigExits(t *testing.T) {
	if os.Getenv("CS_ROUTEROS_BOUNCER_TEST_RUN_BOUNCER_CONFIG") == "1" {
		runBouncer([]string{"-c", "/nonexistent/cs-routeros-bouncer.yaml"})
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunBouncerInvalidConfigExits")
	cmd.Env = append(os.Environ(), "CS_ROUTEROS_BOUNCER_TEST_RUN_BOUNCER_CONFIG=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected invalid config to exit with error, output: %s", output)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected exec.ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got %d; output: %s", exitErr.ExitCode(), output)
	}
	if !strings.Contains(string(output), "failed to load configuration") {
		t.Fatalf("expected config load error, got: %s", output)
	}
}

// TestHandleSubcommandAdminCommands verifies administrative subcommands parse their flags.
func TestHandleSubcommandAdminCommands(t *testing.T) {
	oldSetup := runSetupFn
	oldUninstall := runUninstallFn
	t.Cleanup(func() {
		runSetupFn = oldSetup
		runUninstallFn = oldUninstall
	})

	var setupBin, setupConfigDir string
	runSetupFn = func(binPath, configDir string) error {
		setupBin = binPath
		setupConfigDir = configDir
		return nil
	}

	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"cs-routeros-bouncer", "setup", "-bin", "/tmp/bouncer", "-config-dir", "/tmp/config"}
	if !handleSubcommand() {
		t.Fatal("expected setup subcommand to be handled")
	}
	if setupBin != "/tmp/bouncer" || setupConfigDir != "/tmp/config" {
		t.Fatalf("setup parsed bin=%q configDir=%q", setupBin, setupConfigDir)
	}

	var uninstallBin, uninstallConfigDir string
	var uninstallPurge bool
	runUninstallFn = func(binPath, configDir string, purge bool) error {
		uninstallBin = binPath
		uninstallConfigDir = configDir
		uninstallPurge = purge
		return nil
	}
	os.Args = []string{"cs-routeros-bouncer", "uninstall", "-bin", "/tmp/bouncer", "-config-dir", "/tmp/config", "-purge"}
	if !handleSubcommand() {
		t.Fatal("expected uninstall subcommand to be handled")
	}
	if uninstallBin != "/tmp/bouncer" || uninstallConfigDir != "/tmp/config" || !uninstallPurge {
		t.Fatalf("uninstall parsed bin=%q configDir=%q purge=%v", uninstallBin, uninstallConfigDir, uninstallPurge)
	}
}

// TestHandleSubcommandHelp verifies the help subcommand prints usage output.
func TestHandleSubcommandHelp(t *testing.T) {
	for _, helpArg := range []string{"help", "-h", "--help", "-help"} {
		t.Run(helpArg, func(t *testing.T) {
			oldArgs := os.Args
			t.Cleanup(func() { os.Args = oldArgs })
			os.Args = []string{"cs-routeros-bouncer", helpArg}

			output := captureStdout(t, func() {
				if !handleSubcommand() {
					t.Fatal("expected help subcommand to be handled")
				}
			})

			if !strings.Contains(output, "Usage:") {
				t.Fatalf("help output missing usage: %q", output)
			}
			if !strings.Contains(output, config.Version) {
				t.Fatalf("help output missing version %q: %q", config.Version, output)
			}
			if strings.Contains(output, "cs-routeros-bouncer run") {
				t.Fatalf("help output should not advertise compatibility alias: %q", output)
			}
		})
	}
}

// TestHandleSubcommandVersion verifies version aliases print build metadata.
func TestHandleSubcommandVersion(t *testing.T) {
	for _, versionArg := range []string{"version", "-version", "--version"} {
		t.Run(versionArg, func(t *testing.T) {
			oldArgs := os.Args
			t.Cleanup(func() { os.Args = oldArgs })
			os.Args = []string{"cs-routeros-bouncer", versionArg}

			output := captureStdout(t, func() {
				if !handleSubcommand() {
					t.Fatal("expected version command to be handled")
				}
			})

			if !strings.Contains(output, config.Version) {
				t.Fatalf("version output missing version %q: %q", config.Version, output)
			}
			if !strings.Contains(output, "commit:") {
				t.Fatalf("version output missing commit metadata: %q", output)
			}
			if !strings.Contains(output, "built:") {
				t.Fatalf("version output missing built metadata: %q", output)
			}
		})
	}
}

// captureStdout captures standard output emitted while fn runs.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = w
	restoreStdout := func() {
		os.Stdout = oldStdout
	}
	defer restoreStdout()

	fn()
	restoreStdout()
	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("close stdout writer: %v", closeErr)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if closeErr := r.Close(); closeErr != nil {
		t.Fatalf("close stdout reader: %v", closeErr)
	}
	return string(out)
}
