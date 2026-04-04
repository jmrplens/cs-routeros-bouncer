// Command cs-routeros-bouncer is a CrowdSec remediation component (bouncer)
// for MikroTik RouterOS. It streams ban/unban decisions from the CrowdSec LAPI
// and manages address lists and firewall rules on a MikroTik router via its API.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
	"github.com/jmrplens/cs-routeros-bouncer/internal/manager"
	"github.com/jmrplens/cs-routeros-bouncer/internal/metrics"
)

func main() {
	// Handle subcommands before flag parsing
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "setup":
			fs := flag.NewFlagSet("setup", flag.ExitOnError)
			binPath := fs.String("bin", defaultBinPath, "installation path for the binary")
			cfgDir := fs.String("config-dir", defaultConfigDir, "directory for configuration files")
			_ = fs.Parse(os.Args[2:])
			if err := runSetup(*binPath, *cfgDir); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return
		case "uninstall":
			fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
			binPath := fs.String("bin", defaultBinPath, "path of the installed binary")
			purge := fs.Bool("purge", false, "also remove configuration files")
			_ = fs.Parse(os.Args[2:])
			if err := runUninstall(*binPath, *purge); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return
		case "help":
			printUsage()
			return
		}
	}

	configPath := flag.String("c", "", "path to configuration file")
	showVersion := flag.Bool("version", false, "show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("cs-routeros-bouncer %s (commit: %s, built: %s)\n",
			config.Version, config.Commit, config.BuildDate)
		os.Exit(0)
	}

	// Default log setup (overridden after config load)
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// Load configuration
	cfg, err := config.Load(*configPath)
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
		Str("config", *configPath).
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
	if err := metricsSrv.Start(); err != nil {
		cancel()
		log.Fatal().Err(err).Msg("failed to start health/metrics server") //nolint:gocritic // exitAfterDefer: intentional early exit before goroutines start
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
	if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("error shutting down health/metrics server")
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

func printUsage() {
	fmt.Printf(`cs-routeros-bouncer %s — CrowdSec bouncer for MikroTik RouterOS

Usage:
  cs-routeros-bouncer [flags]         Run the bouncer
  cs-routeros-bouncer setup [flags]   Install as systemd service
  cs-routeros-bouncer uninstall       Remove systemd service and binary
  cs-routeros-bouncer help            Show this help message

Run flags:
  -c string    Path to configuration file
  -version     Show version and exit

Setup flags:
  -bin string        Installation path (default: /usr/local/bin/cs-routeros-bouncer)
  -config-dir string Config directory (default: /etc/cs-routeros-bouncer)

Uninstall flags:
  -bin string  Path of installed binary (default: /usr/local/bin/cs-routeros-bouncer)
  -purge       Also remove configuration files
`, config.Version)
}
