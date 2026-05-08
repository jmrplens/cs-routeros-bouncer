package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

func TestHandleSubcommandNoArgs(t *testing.T) {
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"cs-routeros-bouncer"}

	if handleSubcommand() {
		t.Fatal("expected no subcommand to be handled")
	}
}

func TestHandleSubcommandUnknown(t *testing.T) {
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"cs-routeros-bouncer", "run"}

	if handleSubcommand() {
		t.Fatal("expected unknown subcommand to be ignored")
	}
}

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

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = w
	restored := false
	restoreStdout := func() {
		if !restored {
			os.Stdout = oldStdout
			restored = true
		}
	}
	defer restoreStdout()
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()

	fn()
	restoreStdout()
	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("close stdout writer: %v", closeErr)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(out)
}
