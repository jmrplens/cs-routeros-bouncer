// Command cs-routeros-bouncer is a CrowdSec remediation component (bouncer)
// for MikroTik RouterOS. It streams ban/unban decisions from the CrowdSec LAPI
// and manages address lists and firewall rules on a MikroTik router via its API.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
	"github.com/jmrplens/cs-routeros-bouncer/internal/manager"
	"github.com/jmrplens/cs-routeros-bouncer/internal/metrics"
)

var (
	runSetupFn     = runSetup
	runUninstallFn = runUninstall
	runConfigStat  = os.Stat
	runConfigPath  = defaultConfigDir + "/config.yaml"
)

const cliErrorFormat = "Error: %v\n"

// main dispatches setup/uninstall subcommands before starting the long-running bouncer.
func main() {
	if handleSubcommand() {
		return
	}
	runBouncer(normalizeRunArgs(os.Args[1:]))
}

// handleSubcommand runs one-shot administrative subcommands and reports whether one matched.
func handleSubcommand() bool {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "setup":
			runSetupCommand(os.Args[2:])
			return true
		case "uninstall":
			runUninstallCommand(os.Args[2:])
			return true
		case "version", "-version", "--version":
			printVersion()
			return true
		case "help", "-h", "--help", "-help":
			printUsage()
			return true
		}
	}
	return false
}

// normalizeRunArgs accepts legacy Docker Compose command wrappers and `run` as
// compatibility aliases for the default command.
func normalizeRunArgs(args []string) []string {
	if len(args) > 0 && args[0] == "run" {
		args = args[1:]
	}
	if isShellCommandWrapper(args) {
		return []string{}
	}
	return args
}

func isShellCommandWrapper(args []string) bool {
	if len(args) >= 3 && args[1] == "-c" {
		return isShellCommand(args[0])
	}
	if len(args) == 1 {
		fields := strings.Fields(args[0])
		return len(fields) >= 3 && fields[1] == "-c" && isShellCommand(fields[0])
	}
	return false
}

func isShellCommand(command string) bool {
	switch filepath.Base(command) {
	case "sh", "ash", "bash", "dash":
		return true
	default:
		return false
	}
}

// runSetupCommand parses setup flags and installs the binary as a systemd service.
func runSetupCommand(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	binPath := fs.String("bin", defaultBinPath, "installation path for the binary")
	cfgDir := fs.String("config-dir", defaultConfigDir, "directory for configuration files")
	_ = fs.Parse(args)
	if err := runSetupFn(*binPath, *cfgDir); err != nil {
		fmt.Fprintf(os.Stderr, cliErrorFormat, err)
		os.Exit(1)
	}
}

// runUninstallCommand parses uninstall flags and removes the systemd service.
func runUninstallCommand(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	binPath := fs.String("bin", defaultBinPath, "path of the installed binary")
	cfgDir := fs.String("config-dir", defaultConfigDir, "directory for configuration files")
	purge := fs.Bool("purge", false, "also remove configuration files")
	_ = fs.Parse(args)
	if err := runUninstallFn(*binPath, *cfgDir, *purge); err != nil {
		fmt.Fprintf(os.Stderr, cliErrorFormat, err)
		os.Exit(1)
	}
}

// runBouncer loads configuration, starts metrics/health endpoints, and blocks on Manager.Start.
func runBouncer(args []string) {
	configPath, showVersion, err := parseRunFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, cliErrorFormat, err)
		printUsage()
		os.Exit(1)
	}

	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	// Default log setup (overridden after config load)
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	resolvedConfigPath := resolveRunConfigPath(*configPath)

	// Load configuration
	cfg, err := config.Load(resolvedConfigPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load configuration")
	}

	// Apply log level from config
	level, err := zerolog.ParseLevel(cfg.Logging.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	if cfg.Logging.Format == "json" {
		log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
	}

	log.Info().
		Str("version", config.Version).
		Str("config", resolvedConfigPath).
		Msg("starting cs-routeros-bouncer")

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Initialize manager
	mgr := manager.NewManager(*cfg, config.Version)

	// Always start the health/metrics server so the /health endpoint is
	// available for container health checks even when metrics are disabled.
	metricsSrv := metrics.NewServer(cfg.Metrics, config.Version)
	metrics.SetHealthConnectedCallback(metricsSrv.SetConnected)
	if startMetricsErr := metricsSrv.Start(); startMetricsErr != nil {
		cancel()
		log.Fatal().Err(startMetricsErr).Msg("failed to start health/metrics server") //nolint:gocritic // exitAfterDefer: intentional early exit before goroutines start
	}

	go func() {
		sig := <-sigChan
		log.Info().Str("signal", sig.String()).Msg("received shutdown signal")
		cancel()
	}()

	// Start manager (blocks until context canceled or error)
	startErr := mgr.Start(ctx)

	// Graceful shutdown: remove firewall rules, close connections
	mgr.Shutdown()

	// Shutdown health/metrics server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if shutdownErr := metricsSrv.Shutdown(shutdownCtx); shutdownErr != nil {
		log.Error().Err(shutdownErr).Msg("error shutting down health/metrics server")
	}

	if startErr != nil {
		// Context cancellation from SIGTERM/SIGINT is a clean shutdown, not a failure.
		if ctx.Err() != nil {
			log.Info().Msg("cs-routeros-bouncer stopped")
			return
		}
		log.Error().Err(startErr).Msg("cs-routeros-bouncer stopped with error")
		os.Exit(1)
	}

	log.Info().Msg("cs-routeros-bouncer stopped")
}

func resolveRunConfigPath(configPath string) string {
	if configPath != "" {
		return configPath
	}
	if _, err := runConfigStat(runConfigPath); err == nil || !os.IsNotExist(err) {
		return runConfigPath
	}
	return ""
}

func parseRunFlags(args []string) (configPath *string, showVersion *bool, err error) {
	fs := flag.NewFlagSet("cs-routeros-bouncer", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = printUsage
	configPath = fs.String("c", "", "path to configuration file")
	showVersion = fs.Bool("version", false, "show version and exit")
	err = fs.Parse(args)
	if err != nil {
		return nil, nil, err
	}
	if fs.NArg() > 0 {
		return nil, nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return configPath, showVersion, nil
}

// printVersion writes version metadata to standard output.
func printVersion() {
	fmt.Printf("cs-routeros-bouncer %s (commit: %s, built: %s)\n",
		config.Version, config.Commit, config.BuildDate)
}

// printUsage writes the command help text to standard output.
func printUsage() {
	fmt.Printf(`cs-routeros-bouncer %s — CrowdSec bouncer for MikroTik RouterOS

Usage:
	cs-routeros-bouncer [flags]           Run the bouncer
	cs-routeros-bouncer setup [flags]     Install as systemd service
	cs-routeros-bouncer uninstall [flags] Remove systemd service and binary
	cs-routeros-bouncer version           Show version and exit
	cs-routeros-bouncer help              Show this help message

Run flags:
  -c string    Path to configuration file
  -version     Show version and exit

Setup flags:
  -bin string        Installation path (default: /usr/local/bin/cs-routeros-bouncer)
  -config-dir string Config directory (default: /etc/cs-routeros-bouncer)

Uninstall flags:
  -bin string        Path of installed binary (default: /usr/local/bin/cs-routeros-bouncer)
  -config-dir string Config directory to purge (default: /etc/cs-routeros-bouncer)
  -purge             Also remove configuration files
`, config.Version)
}
