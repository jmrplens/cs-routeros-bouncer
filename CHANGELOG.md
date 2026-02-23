# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
