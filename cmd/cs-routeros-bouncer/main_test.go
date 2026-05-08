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

// TestHandleSubcommandHelp verifies the help subcommand prints usage output.
func TestHandleSubcommandHelp(t *testing.T) {
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"cs-routeros-bouncer", "help"}

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
