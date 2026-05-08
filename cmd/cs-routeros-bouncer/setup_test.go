package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestCopyFileMissingSource(t *testing.T) {
	err := copyFile(filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "dest"), 0o600)
	if err == nil {
		t.Fatal("expected missing source error")
	}
}

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

func TestCopyFileReadError(t *testing.T) {
	tmpDir := t.TempDir()
	err := copyFile(tmpDir, filepath.Join(t.TempDir(), "dest"), 0o600)
	if err == nil {
		t.Fatal("expected read error when copying a directory")
	}
}

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
