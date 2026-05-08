package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestConfigPath verifies benchmark config path selection from argv.
func TestConfigPath(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "default", args: []string{"benchmark"}, want: "config/test.yaml"},
		{name: "from arg", args: []string{"benchmark", "custom.yaml"}, want: "custom.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldArgs := os.Args
			t.Cleanup(func() { os.Args = oldArgs })
			os.Args = tt.args

			if got := configPath(); got != tt.want {
				t.Fatalf("configPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestLoadConfig verifies the benchmark config loader reads YAML fields.
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

	cfg, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.CrowdSec.APIURL != "http://crowdsec.local:8080/" {
		t.Fatalf("unexpected crowdsec api url: %q", cfg.CrowdSec.APIURL)
	}
	if cfg.MikroTik.Address != "192.0.2.1:8728" {
		t.Fatalf("unexpected mikrotik address: %q", cfg.MikroTik.Address)
	}
}

// TestLoadConfigErrors verifies the benchmark loader returns read/parse errors.
func TestLoadConfigErrors(t *testing.T) {
	tests := []struct {
		name      string
		writeFile bool
		content   string
	}{
		{name: "invalid YAML syntax", writeFile: true, content: "crowdsec:\n  api_url: ["},
		{name: "non-existent file"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)

			configPath := filepath.Join(t.TempDir(), "config.yaml")
			if tt.writeFile {
				if err := os.WriteFile(configPath, []byte(tt.content), 0o600); err != nil {
					t.Fatalf("write config: %v", err)
				}
			}

			_, err := loadConfig(configPath)
			assert.Error(t, err)
		})
	}
}

// TestBenchReportsStatus verifies success and error labels in benchmark output.
func TestBenchReportsStatus(t *testing.T) {
	output := captureBenchmarkStdout(t, func() {
		bench("success", func() error { return nil })
		bench("failure", func() error { return errors.New("boom") })
	})

	assert.Contains(t, output, "success")
	assert.Contains(t, output, "OK")
	assert.Contains(t, output, "failure")
	assert.Contains(t, output, "ERR: boom")
}

// captureBenchmarkStdout captures benchmark output emitted while fn runs.
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
