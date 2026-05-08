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

// Default installation paths and command names used by setup and uninstall.
const (
	defaultBinPath     = "/usr/local/bin/cs-routeros-bouncer"
	defaultConfigDir   = "/etc/cs-routeros-bouncer"
	defaultConfigFile  = "cs-routeros-bouncer.yaml"
	defaultServicePath = "/etc/systemd/system/cs-routeros-bouncer.service"
	serviceName        = "cs-routeros-bouncer"
	systemctlPath      = "systemctl"
)

// setup hooks wrap OS operations so setup/uninstall behavior can be tested
// without touching the host system.
var (
	setupGetuid       = os.Getuid
	setupExecutable   = os.Executable
	setupEvalSymlinks = filepath.EvalSymlinks
	setupMkdirAll     = os.MkdirAll
	setupStat         = os.Stat
	setupWriteFile    = os.WriteFile
	setupRemove       = os.Remove
	setupRemoveAll    = os.RemoveAll
	setupCopyFile     = copyFile
	setupSystemctl    = systemctl
	setupServicePath  = defaultServicePath
	setupConfigDir    = defaultConfigDir
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
	if setupGetuid() != 0 {
		return errors.New("setup must be run as root")
	}

	binSrc, err := setupExecutable()
	if err != nil {
		return fmt.Errorf("cannot determine own path: %w", err)
	}
	binSrc, err = setupEvalSymlinks(binSrc)
	if err != nil {
		return fmt.Errorf("cannot resolve symlinks: %w", err)
	}

	configFile := filepath.Join(configDir, defaultConfigFile)

	// 1. Copy binary
	fmt.Printf("→ Installing binary to %s ...\n", binDst)
	if copyErr := setupCopyFile(binSrc, binDst, 0o755); copyErr != nil {
		return fmt.Errorf("failed to copy binary: %w", copyErr)
	}

	// 2. Create config directory and example config
	if mkdirErr := setupMkdirAll(configDir, 0o750); mkdirErr != nil {
		return fmt.Errorf("failed to create config dir: %w", mkdirErr)
	}
	if _, statErr := setupStat(configFile); os.IsNotExist(statErr) {
		fmt.Printf("→ Creating example config at %s ...\n", configFile)
		// #nosec G306 -- config must be group-readable by service operators.
		if writeErr := setupWriteFile(configFile, []byte(exampleConfig()), 0o640); writeErr != nil {
			return fmt.Errorf("failed to write config: %w", writeErr)
		}
		fmt.Println("  ⚠ Edit the config file to set your CrowdSec API key and MikroTik credentials.")
	} else {
		fmt.Printf("→ Config already exists at %s, skipping.\n", configFile)
	}

	// 3. Write systemd unit
	fmt.Printf("→ Creating systemd service at %s ...\n", setupServicePath)
	unit := fmt.Sprintf(serviceTemplate, binDst, configFile)
	// #nosec G306 -- systemd units must be world-readable.
	if writeErr := setupWriteFile(setupServicePath, []byte(unit), 0o644); writeErr != nil {
		return fmt.Errorf("failed to write service file: %w", writeErr)
	}

	// 4. Reload, enable, start
	fmt.Println("→ Reloading systemd daemon ...")
	if systemctlErr := setupSystemctl("daemon-reload"); systemctlErr != nil {
		return fmt.Errorf("reload systemd daemon: %w", systemctlErr)
	}
	fmt.Printf("→ Enabling %s ...\n", serviceName)
	if systemctlErr := setupSystemctl("enable", serviceName); systemctlErr != nil {
		return fmt.Errorf("enable %s: %w", serviceName, systemctlErr)
	}
	fmt.Printf("→ Starting %s ...\n", serviceName)
	if systemctlErr := setupSystemctl("start", serviceName); systemctlErr != nil {
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
	if setupGetuid() != 0 {
		return errors.New("uninstall must be run as root")
	}

	fmt.Printf("→ Stopping %s ...\n", serviceName)
	_ = setupSystemctl("stop", serviceName)

	fmt.Printf("→ Disabling %s ...\n", serviceName)
	_ = setupSystemctl("disable", serviceName)

	if _, err := setupStat(setupServicePath); err == nil {
		fmt.Printf("→ Removing %s ...\n", setupServicePath)
		_ = setupRemove(setupServicePath)
	}
	_ = setupSystemctl("daemon-reload")

	if _, err := setupStat(binDst); err == nil {
		fmt.Printf("→ Removing %s ...\n", binDst)
		_ = setupRemove(binDst)
	}

	if removeConfig {
		fmt.Printf("→ Removing config dir %s ...\n", setupConfigDir)
		_ = setupRemoveAll(setupConfigDir)
	} else {
		fmt.Printf("→ Config dir %s preserved (use -purge to remove).\n", setupConfigDir)
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

	if _, copyErr := io.Copy(out, in); copyErr != nil {
		_ = out.Close()
		return copyErr
	}
	return out.Close()
}

// exampleConfig returns a YAML configuration template with sensible defaults.
func exampleConfig() string {
	return strings.ReplaceAll(`# cs-routeros-bouncer configuration
# Documentation: https://github.com/jmrplens/cs-routeros-bouncer

crowdsec:
  api_url: "http://localhost:8080/"
	# Environment variables in config values are expanded at runtime.
	api_key: "${CROWDSEC_BOUNCER_API_KEY}" # Required: cscli bouncers add cs-routeros-bouncer
  update_frequency: "10s"
  reconciliation_interval: "15m"

mikrotik:
  address: "192.168.0.1:8728"
  username: "crowdsec"
	password: "${MIKROTIK_PASS}" # Required: RouterOS API password

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
`, "\t", "  ")
}
