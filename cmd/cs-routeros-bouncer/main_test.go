package main

import (
	"io"
	"os"
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
