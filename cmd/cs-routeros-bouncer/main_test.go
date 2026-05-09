package main

import (
	"io"
	"os"
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
		{name: "empty", args: nil, want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeRunArgs(tt.args)
			if strings.Join(got, "\x00") != strings.Join(tt.want, "\x00") {
				t.Fatalf("normalizeRunArgs(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
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
			if !strings.Contains(output, "commit:") || !strings.Contains(output, "built:") {
				t.Fatalf("version output missing metadata: %q", output)
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
