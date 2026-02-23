# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **LAPI usage metrics** — reports active decisions (per-origin and per-IP-type) and dropped traffic (bytes/packets delta) to CrowdSec LAPI `/v1/usage-metrics` endpoint
  - Per-origin decision counts (e.g., `crowdsec`, `cscli`, `CAPI`)
  - Per-IP-type decision counts (`ipv4`, `ipv6`)
  - Firewall dropped bytes and packets read from MikroTik rule counters (delta between pushes)
  - Configurable interval via `crowdsec.lapi_metrics_interval` (default `15m`, `0` to disable)
- **CrowdSec SDK version metadata** — bouncer now reports correct version to CrowdSec LAPI via `go-cs-lib/version.Version` ldflags
- **Input interface filtering** — restrict firewall rules to a specific interface or interface-list via `firewall.block_input.interface` / `firewall.block_input.interface_list`
- **Connection pool auto-capping** — automatically reduces `pool_size` if it would exceed RouterOS `max-sessions` limit
- **Comprehensive unit test suite**:
  - `internal/manager` — 90.3% coverage with mock-based CrowdSecStream and RouterOSClient interfaces
  - `internal/routeros` — 93.0% coverage with MockConn and extracted RouterConn interface
  - `internal/crowdsec` — 93.4% coverage with BouncerEngine interface and mock-based stream tests
  - `internal/metrics/lapi` — 71.8% coverage (metricsUpdater 100%, SDK wiring excluded)

### Fixed

- **Firewall rule placement** — iterate all chain positions when dynamic/builtin rules occupy top slots
- **Empty version in LAPI metadata** — added `go-cs-lib/version.Version` ldflags to Makefile, Dockerfile, and `.goreleaser.yaml`

### Changed

- **LAPI metrics format** — migrated from single `active_decisions` total to per-origin and per-IP-type breakdown with dropped traffic deltas
- **metricsUpdater** — refactored from package-level function to `Provider` method for `CounterCollector` support

## [0.1.0] - 2025-07-22

### Added

- **CrowdSec integration**: Stream-based bouncer connecting to CrowdSec LAPI for real-time ban/unban decisions
- **RouterOS API client**: Persistent connection with auto-reconnect, TLS support, and mutex-safe concurrent access
- **Automatic firewall rule management**: Creates filter and raw rules on startup, removes them on shutdown
  - IPv4 filter (`/ip/firewall/filter`) and raw (`/ip/firewall/raw`) chains
  - IPv6 filter (`/ipv6/firewall/filter`) and raw (`/ipv6/firewall/raw`) chains
  - Configurable deny action (`drop` or `reject`)
  - Move-based rule placement at top of chain with builtin rule fallback
- **Individual IP management**: Adds IPs on ban, removes on unban — no bulk re-upload, no duplicates
  - Optimistic-add pattern (~1ms per IP vs ~400ms with lookup-first)
  - Named address lists: `crowdsec-banned` (IPv4), `crowdsec6-banned` (IPv6)
  - Comment-based resource identification (`crowdsec-bouncer:` prefix)
- **Startup reconciliation**: On start/restart, compares CrowdSec decisions with MikroTik address lists
  - Adds missing IPs that should be blocked
  - Removes stale IPs that are no longer in CrowdSec decisions
- **IPv4 and IPv6 support**: Independently toggleable per protocol
- **Input and output blocking**: Output blocking optional with configurable interface or interface-list
- **Decision origin filtering**: Configure `crowdsec.origins` to sync only local decisions or include CAPI community blocklists
- **Prometheus metrics**: 8 metrics exposed at `/metrics` endpoint
  - Active decisions gauge, total decisions counter, error counter
  - Operation duration histogram, connection status, build info
- **Health endpoint**: HTTP `/health` with RouterOS connection status and version info
- **Configuration**: YAML config file with environment variable overrides (Viper-based)
- **Structured logging**: Zerolog-based JSON/console logging with configurable level
- **Docker support**: Multi-arch Docker images (amd64, arm64) with minimal scratch-based image
- **Binary releases**: Cross-compiled binaries for Linux (amd64, arm64, armv7), macOS, and Windows via GoReleaser
- **Systemd support**: Example unit file and install/uninstall Makefile targets
- **CI/CD**: GitHub Actions for lint, test, build, Docker build, and automated releases

### Performance

- Single IPv4 add: ~1 ms (optimistic-add pattern)
- Single IPv6 add: ~8 ms
- **Bulk add** (script-based, chunks of 100): ~168 IPs/s for local (~1,500 IPs in ~9 s), ~147 IPs/s for CAPI (~25,000 IPs in ~2 min 50 s)
- **Mass removal** (parallel, 4 connections): ~105 removes/s (~23,500 IPs in ~3 min 45 s)
- **Restart with existing entries**: ~10 s for 25,000 IPs (diff-only, no bulk needed)
- Router CPU peak during reconciliation: 14% (local), 23% (CAPI 25k)
- Steady-state router CPU: 8–11% (local-only), 15–20% (with CAPI)
