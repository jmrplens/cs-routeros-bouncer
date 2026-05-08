package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

const (
	defaultBinPath     = "/usr/local/bin/cs-routeros-bouncer"
	defaultConfigDir   = "/etc/cs-routeros-bouncer"
	defaultConfigFile  = "cs-routeros-bouncer.yaml"
	defaultServicePath = "/etc/systemd/system/cs-routeros-bouncer.service"
	serviceName        = "cs-routeros-bouncer"
	systemctlPath      = "/usr/bin/systemctl"
)

// serviceTemplate is the systemd unit file content.
// %s placeholders: binary path, config file path.
const serviceTemplate = `[Unit]
Description=CrowdSec RouterOS Bouncer
Documentation=https://github.com/jmrplens/cs-routeros-bouncer
After=network-online.target crowdsec.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s -c %s
Restart=on-failure
RestartSec=10
TimeoutStopSec=90
LimitNOFILE=65536

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
`

// runSetup installs the bouncer as a systemd service.
func runSetup(binDst, configDir string) error {
	if os.Getuid() != 0 {
		return errors.New("setup must be run as root")
	}

	binSrc, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine own path: %w", err)
	}
	binSrc, err = filepath.EvalSymlinks(binSrc)
	if err != nil {
		return fmt.Errorf("cannot resolve symlinks: %w", err)
	}

	configFile := filepath.Join(configDir, defaultConfigFile)

	// 1. Copy binary
	fmt.Printf("→ Installing binary to %s ...\n", binDst)
	if copyErr := copyFile(binSrc, binDst, 0o755); copyErr != nil {
		return fmt.Errorf("failed to copy binary: %w", copyErr)
	}

	// 2. Create config directory and example config
	if mkdirErr := os.MkdirAll(configDir, 0o750); mkdirErr != nil {
		return fmt.Errorf("failed to create config dir: %w", mkdirErr)
	}
	if _, statErr := os.Stat(configFile); os.IsNotExist(statErr) {
		fmt.Printf("→ Creating example config at %s ...\n", configFile)
		// #nosec G306 -- config must be group-readable by service operators.
		if writeErr := os.WriteFile(configFile, []byte(exampleConfig()), 0o640); writeErr != nil {
			return fmt.Errorf("failed to write config: %w", writeErr)
		}
		fmt.Println("  ⚠ Edit the config file to set your CrowdSec API key and MikroTik credentials.")
	} else {
		fmt.Printf("→ Config already exists at %s, skipping.\n", configFile)
	}

	// 3. Write systemd unit
	fmt.Printf("→ Creating systemd service at %s ...\n", defaultServicePath)
	unit := fmt.Sprintf(serviceTemplate, binDst, configFile)
	// #nosec G306 -- systemd units must be world-readable.
	if writeErr := os.WriteFile(defaultServicePath, []byte(unit), 0o644); writeErr != nil {
		return fmt.Errorf("failed to write service file: %w", writeErr)
	}

	// 4. Reload, enable, start
	fmt.Println("→ Reloading systemd daemon ...")
	if systemctlErr := systemctl("daemon-reload"); systemctlErr != nil {
		return fmt.Errorf("reload systemd daemon: %w", systemctlErr)
	}
	fmt.Printf("→ Enabling %s ...\n", serviceName)
	if systemctlErr := systemctl("enable", serviceName); systemctlErr != nil {
		return fmt.Errorf("enable %s: %w", serviceName, systemctlErr)
	}
	fmt.Printf("→ Starting %s ...\n", serviceName)
	if systemctlErr := systemctl("start", serviceName); systemctlErr != nil {
		return fmt.Errorf("start %s: %w", serviceName, systemctlErr)
	}

	fmt.Println()
	fmt.Printf("✓ %s installed and running (version %s)\n", serviceName, config.Version)
	fmt.Printf("  Config : %s\n", configFile)
	fmt.Printf("  Binary : %s\n", binDst)
	fmt.Printf("  Service: systemctl status %s\n", serviceName)
	fmt.Printf("  Logs   : journalctl -u %s -f\n", serviceName)
	return nil
}

// runUninstall stops and removes the systemd service and binary.
func runUninstall(binDst string, removeConfig bool) error {
	if os.Getuid() != 0 {
		return errors.New("uninstall must be run as root")
	}

	fmt.Printf("→ Stopping %s ...\n", serviceName)
	_ = systemctl("stop", serviceName)

	fmt.Printf("→ Disabling %s ...\n", serviceName)
	_ = systemctl("disable", serviceName)

	if _, err := os.Stat(defaultServicePath); err == nil {
		fmt.Printf("→ Removing %s ...\n", defaultServicePath)
		_ = os.Remove(defaultServicePath)
	}
	_ = systemctl("daemon-reload")

	if _, err := os.Stat(binDst); err == nil {
		fmt.Printf("→ Removing %s ...\n", binDst)
		_ = os.Remove(binDst)
	}

	if removeConfig {
		fmt.Printf("→ Removing config dir %s ...\n", defaultConfigDir)
		_ = os.RemoveAll(defaultConfigDir)
	} else {
		fmt.Printf("→ Config dir %s preserved (use -purge to remove).\n", defaultConfigDir)
	}

	fmt.Printf("✓ %s uninstalled.\n", serviceName)
	return nil
}

// systemctl runs a systemctl command with the given arguments.
func systemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// #nosec G204 -- systemctl arguments are controlled by setup/uninstall callers.
	cmd := exec.CommandContext(ctx, systemctlPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderrText := strings.TrimSpace(stderr.String()); stderrText != "" {
			return fmt.Errorf("systemctl %v failed: %s: %w", args, stderrText, err)
		}
		return fmt.Errorf("systemctl %v failed: %w", args, err)
	}
	return nil
}

// copyFile copies a file from src to dst with the given permissions.
func copyFile(src, dst string, mode os.FileMode) error {
	// #nosec G304 -- setup runs as root and copies between resolved install paths.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	// #nosec G304 -- setup runs as root and writes to the selected install path.
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, copyErr := io.Copy(out, in); copyErr != nil {
		return copyErr
	}
	return out.Close()
}

// exampleConfig returns a YAML configuration template with sensible defaults.
func exampleConfig() string {
	return `# cs-routeros-bouncer configuration
# Documentation: https://github.com/jmrplens/cs-routeros-bouncer

crowdsec:
  api_url: "http://localhost:8080/"
  api_key: ""          # Required: cscli bouncers add cs-routeros-bouncer
  update_frequency: "10s"
  reconciliation_interval: "15m"

mikrotik:
  address: "192.168.0.1:8728"
  username: "crowdsec"
  password: ""         # Required: RouterOS API password

firewall:
  ipv4:
    enabled: true
  ipv6:
    enabled: true
  filter:
    enabled: true
    chains: ["input"]
  raw:
    enabled: true
    chains: ["prerouting"]
  deny_action: "drop"
  rule_placement: "top"

logging:
  level: "info"
  format: "text"

metrics:
  enabled: false
  listen_port: 2112
`
}
