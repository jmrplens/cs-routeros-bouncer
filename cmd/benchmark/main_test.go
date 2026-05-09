package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	rosClient "github.com/jmrplens/cs-routeros-bouncer/internal/routeros"

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

// TestRunBenchmarksExercisesClientFlow verifies the standalone benchmark runner without RouterOS.
func TestRunBenchmarksExercisesClientFlow(t *testing.T) {
	client := &fakeBenchmarkClient{}

	output := captureBenchmarkStdout(t, func() {
		runBenchmarks(client)
	})

	assert.Contains(t, output, "Connected to: test-router")
	assert.Contains(t, output, "SINGLE OPERATION BENCHMARKS")
	assert.Contains(t, output, "FIREWALL RULE BENCHMARKS")
	assert.Contains(t, output, "BATCH ADD BENCHMARKS")
	assert.Contains(t, output, "Add 500 IPv4 (sequential)")
	assert.Contains(t, output, "SKIPPED")
	assert.Contains(t, output, "BENCHMARK COMPLETE")
	assert.Positive(t, client.addAddressCalls)
	assert.Positive(t, client.removeAddressCalls)
	assert.Positive(t, client.addFirewallRuleCalls)
	assert.Positive(t, client.removeFirewallRuleCalls)
}

// TestRunBenchmarksUsesUnknownIdentityOnError verifies identity read failures do not stop benchmarks.
func TestRunBenchmarksUsesUnknownIdentityOnError(t *testing.T) {
	client := &fakeBenchmarkClient{identityErr: errors.New("identity unavailable")}

	output := captureBenchmarkStdout(t, func() {
		runBenchmarks(client)
	})

	assert.Contains(t, output, "Connected to: unknown")
	assert.Contains(t, output, "BENCHMARK COMPLETE")
}

type fakeBenchmarkClient struct {
	identityErr             error
	addAddressCalls         int
	removeAddressCalls      int
	addFirewallRuleCalls    int
	removeFirewallRuleCalls int
}

func (f *fakeBenchmarkClient) GetIdentity() (string, error) {
	if f.identityErr != nil {
		return "", f.identityErr
	}
	return "test-router", nil
}

func (f *fakeBenchmarkClient) AddAddress(_, _, address, _, _ string) (string, error) {
	f.addAddressCalls++
	return "addr-" + address, nil
}

func (f *fakeBenchmarkClient) FindAddress(_, _, address string) (*rosClient.AddressEntry, error) {
	return &rosClient.AddressEntry{ID: "found-" + address, Address: address}, nil
}

func (f *fakeBenchmarkClient) ListAddresses(_, list, _ string) ([]rosClient.AddressEntry, error) {
	return []rosClient.AddressEntry{
		{ID: "list-1", Address: "198.51.100.1", List: list},
		{ID: "list-2", Address: "198.51.100.2", List: list},
	}, nil
}

func (f *fakeBenchmarkClient) RemoveAddress(_, _ string) error {
	f.removeAddressCalls++
	return nil
}

func (f *fakeBenchmarkClient) AddFirewallRule(_, _ string, _ rosClient.FirewallRule) (string, error) {
	f.addFirewallRuleCalls++
	return "rule-id", nil
}

func (f *fakeBenchmarkClient) FindFirewallRuleByComment(_, _, comment string) (*rosClient.RuleEntry, error) {
	return &rosClient.RuleEntry{ID: "rule-id", Comment: comment}, nil
}

func (f *fakeBenchmarkClient) RemoveFirewallRule(_, _, _ string) error {
	f.removeFirewallRuleCalls++
	return nil
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
