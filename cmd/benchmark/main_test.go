package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestConfigPathDefault(t *testing.T) {
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"benchmark"}

	if got := configPath(); got != "config/test.yaml" {
		t.Fatalf("configPath default = %q", got)
	}
}

func TestConfigPathFromArg(t *testing.T) {
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"benchmark", "custom.yaml"}

	if got := configPath(); got != "custom.yaml" {
		t.Fatalf("configPath arg = %q", got)
	}
}

func TestLoadConfig(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	configYAML := `crowdsec:
  api_url: "http://crowdsec.local:8080/"
mikrotik:
  address: "192.0.2.1:8728"
  username: "crowdsec"
firewall:
  deny_action: "drop"
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg := loadConfig(configPath)
	if cfg.CrowdSec.APIURL != "http://crowdsec.local:8080/" {
		t.Fatalf("unexpected crowdsec api url: %q", cfg.CrowdSec.APIURL)
	}
	if cfg.MikroTik.Address != "192.0.2.1:8728" {
		t.Fatalf("unexpected mikrotik address: %q", cfg.MikroTik.Address)
	}
}

func TestBenchReportsStatus(t *testing.T) {
	output := captureBenchmarkStdout(t, func() {
		bench("success", func() error { return nil })
		bench("failure", func() error { return errors.New("boom") })
	})

	if !strings.Contains(output, "success") || !strings.Contains(output, "OK") {
		t.Fatalf("success output missing status: %q", output)
	}
	if !strings.Contains(output, "failure") || !strings.Contains(output, "ERR: boom") {
		t.Fatalf("failure output missing status: %q", output)
	}
}

func captureBenchmarkStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = oldStdout })

	fn()
	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("close stdout writer: %v", closeErr)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(out)
}
