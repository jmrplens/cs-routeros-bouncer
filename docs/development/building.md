# Building & Testing

This page covers how to build, test, and develop cs-routeros-bouncer from source.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| [Go](https://go.dev/dl/) | 1.25+ | Compilation |
| [golangci-lint](https://golangci-lint.run/welcome/install/) | v2+ | Linting |
| [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | latest | Vulnerability scanning |
| [Docker](https://docs.docker.com/get-docker/) | 20+ | Container builds (optional) |
| [Make](https://www.gnu.org/software/make/) | any | Build automation |

## Clone & Setup

```bash
git clone https://github.com/jmrplens/cs-routeros-bouncer.git
cd cs-routeros-bouncer
go mod download
```

## Building

### Using Make (recommended)

```bash
make build
```

This produces `bin/cs-routeros-bouncer` with version metadata embedded via `-ldflags`:

- `Version` — git tag or `dev`
- `Commit` — short git SHA
- `BuildDate` — UTC build timestamp

### Manual Build

```bash
CGO_ENABLED=0 go build \
  -ldflags "-X github.com/jmrplens/cs-routeros-bouncer/internal/config.Version=dev" \
  -o bin/cs-routeros-bouncer \
  ./cmd/cs-routeros-bouncer/
```

### Cross-compilation

The binary is pure Go (`CGO_ENABLED=0`), so cross-compilation is straightforward:

```bash
# ARM64 (e.g., Raspberry Pi, MikroTik CHR on ARM)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/cs-routeros-bouncer-arm64 ./cmd/cs-routeros-bouncer/

# AMD64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/cs-routeros-bouncer-amd64 ./cmd/cs-routeros-bouncer/
```

### Docker Build

```bash
make docker-build
```

This creates `cs-routeros-bouncer:latest` and `cs-routeros-bouncer:<version>`.

## Running

### From Source

```bash
make run
# or
go run ./cmd/cs-routeros-bouncer/ -c config/cs-routeros-bouncer.yaml
```

### From Binary

```bash
./bin/cs-routeros-bouncer -c /path/to/config.yaml
```

### Subcommands

```bash
# Install systemd service
sudo ./bin/cs-routeros-bouncer setup -c /path/to/config.yaml

# Uninstall systemd service
sudo ./bin/cs-routeros-bouncer uninstall

# Show help
./bin/cs-routeros-bouncer help
```

## Testing

The project has three layers of tests:

| Layer | Tool | Scope | Hardware needed |
|-------|------|-------|-----------------|
| **Unit tests** | `go test` | Individual functions, parsing, validation | No |
| **Integration tests** | `go test -tags integration` | RouterOS API + LAPI with real connections | Yes |
| **Functional tests** | Bash (`run_tests.sh`) | Compiled binary, end-to-end against real router | Yes |

### Unit Tests

#### Run All Unit Tests

```bash
make test
```

This runs:
```bash
go test -v -race -coverprofile=coverage.out ./...
```

Flags explained:

- `-v` — verbose output
- `-race` — enables the race detector
- `-coverprofile` — generates coverage data

#### Run Tests for a Single Package

```bash
go test -v ./internal/config/...
go test -v ./internal/crowdsec/...
go test -v ./internal/manager/...
go test -v ./internal/metrics/...
go test -v ./internal/routeros/...
```

#### Coverage Report

Generate an HTML coverage report:

```bash
make coverage
# Opens coverage.html with per-line highlights
```

Or check coverage in the terminal:

```bash
go test -coverprofile=coverage.out ./internal/...
go tool cover -func=coverage.out
```

#### Current Coverage

| Package | Coverage | Tests |
|---------|----------|-------|
| `internal/config` | ~98% | Config loading, validation, env overrides |
| `internal/crowdsec` | ~48% | Decision parsing, stream creation, duration parsing |
| `internal/manager` | ~12% | Rule comment building/parsing, address comments, protos |
| `internal/metrics` | ~97% | All metric recording, health endpoint, server lifecycle |
| `internal/routeros` | ~11% | Duration formatting, address normalization, path helpers |

!!! note
    Manager and RouterOS packages have lower coverage because their core methods
    require a live RouterOS connection. Integration and functional tests cover those paths.

### Integration Tests

Integration tests connect to a real MikroTik router and CrowdSec LAPI using
Go's `testing` package with build tags:

```bash
make test-integration
```

These tests are build-tagged with `//go:build integration` and require:

- A running MikroTik router accessible via API
- A running CrowdSec LAPI instance
- A valid configuration file

### Functional Tests

The functional test suite is a **black-box testing framework** that validates the
compiled bouncer binary against real MikroTik hardware. Unlike integration tests
(which import Go packages), these tests exercise the actual installed binary
through its systemd service, verifying end-to-end behavior.

All verification is done **out-of-band** — the tests never call the bouncer
directly. Instead they use:

- **SSH** to the MikroTik router (read address lists, verify state)
- **cscli** to interact with CrowdSec LAPI (add/remove decisions)
- **SNMP** to monitor router CPU and memory
- **curl** to read the bouncer's Prometheus `/metrics` endpoint

#### Prerequisites

| Requirement | Purpose |
|-------------|---------|
| MikroTik router with SSH access | Target device under test |
| CrowdSec LAPI with `cscli` | Decision source |
| Bouncer installed as systemd service | The binary being tested |
| `snmpget` (net-snmp) | CPU/memory monitoring (optional — t6 skipped if missing) |
| `jq` | JSON parsing for LAPI responses |
| `curl` | Prometheus metrics queries |

#### Environment Setup

Tests are configured through a `.env` file in the `tests/functional/` directory.
Copy the example and fill in your values:

```bash
cd tests/functional
cp .env.example .env
# Edit .env with your router/CrowdSec credentials
```

The `.env.example` file includes RouterOS commands to configure SNMP on your
router if it's not already set up.

Key variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `MIKROTIK_SSH_HOST` | Router IP address | `192.168.0.1` |
| `MIKROTIK_SSH_PORT` | SSH port | `2200` |
| `MIKROTIK_SSH_USER` | SSH username | `admin` |
| `MIKROTIK_SSH_KEY` | Path to SSH private key | `~/.ssh/id_mikrotik` |
| `MIKROTIK_SNMP_COMMUNITY` | SNMP v2c community string | `public` |
| `CROWDSEC_LIST_IPV4` | IPv4 address list name | `crowdsec-banned` |
| `CROWDSEC_LIST_IPV6` | IPv6 address list name | `crowdsec6-banned` |
| `CPU_THRESHOLD` | Max acceptable steady-state CPU % | `30` |

#### Running Tests

```bash
# Run all test groups (t1–t7, excludes CAPI)
./run_tests.sh

# Run specific groups
./run_tests.sh t1          # Only data integrity tests
./run_tests.sh t1 t2 t3    # Multiple groups

# Include CAPI stress tests (~25,000 IPs — takes several minutes)
./run_tests.sh --capi       # All groups including t8
./run_tests.sh --capi t8    # Only CAPI group

# List available test groups
./run_tests.sh --list
```

#### Test Groups

The 44 tests are organized into 8 groups:

| Group | File | Tests | Description |
|-------|------|-------|-------------|
| **T1** | `t1_integrity.sh` | 7 | **Data integrity** — IPv4/IPv6 completeness vs LAPI, orphan detection, address format validation, comment prefix integrity, duplicate detection, router reachability |
| **T2** | `t2_cache.sh` | 6 | **Cache consistency** — Prometheus metrics vs router count, live ban/unban lifecycle, expired-on-router resilience, cache fast-path verification, rapid ban/unban cycles |
| **T3** | `t3_bulk.sh` | 6 | **Bulk operations** — Full reconciliation from empty, partial sync (restore missing addresses), orphan removal, bulk script error checking, stale script cleanup, batch remove |
| **T4** | `t4_pool.sh` | 3 | **Connection pool** — Pool establishment logging, concurrent operation verification, clean shutdown and restart with state preservation |
| **T5** | `t5_edge.sh` | 6 | **Edge cases** — Duplicate IP handling, rapid ban/unban within single poll cycle, 20 parallel bans stress test, restart idempotency (3× consecutive), deleteCh drain optimization, IPv6 full lifecycle |
| **T6** | `t6_cpu.sh` | 3 | **CPU monitoring** — Steady-state CPU via SNMP, reconciliation peak CPU measurement, post-reconciliation recovery (requires `snmpget`) |
| **T7** | `t7_timing.sh` | 5 | **Timing measurements** — Full reconciliation wall-clock time, single ban latency, single unban latency, restart time with existing data, bulk add throughput (addr/s) |
| **T8** | `t8_capi.sh` | 8 | **CAPI stress** — Full reconciliation with ~25k community IPs, CPU peak during bulk import, IP completeness, IPv6 parity, restart idempotency at scale, unban latency with large cache, steady-state CPU, restore to local-only (requires `--capi` flag) |

#### Writing New Tests

Each test group is a standalone Bash script sourced by `run_tests.sh`. To add a
new group:

1. **Create the file** as `tests/functional/tN_name.sh` (e.g., `t9_network.sh`)
2. **Source helpers** — the file is `source`d by the runner, so all `helpers.sh`
   functions are available automatically
3. **Use `run_test`** for each test case:

```bash
# T9.1: Example test
run_test "T9.1" "Description of what this test verifies" '
    local result
    result=$(ssh_cmd "/some/command")
    [[ "$result" == "expected" ]]
'
```

The `run_test` function:

- Captures the test body's exit code (0 = pass, non-zero = fail)
- Displays pass/fail with colors
- Tracks totals for the summary

Use `skip_test` for tests that require optional infrastructure:

```bash
if ! snmp_available; then
    skip_test "T9.2" "Requires SNMP" && return
fi
```

4. **Register the group** in `run_tests.sh`'s `--list` output and default group
   array

#### Helper Library Reference

The shared library (`lib/helpers.sh`) provides these function categories:

| Category | Functions | Purpose |
|----------|-----------|---------|
| **Test framework** | `run_test`, `skip_test`, `print_summary` | Test execution and reporting |
| **SSH** | `ssh_cmd`, `ssh_count_addresses`, `ssh_list_addresses`, `ssh_add_address`, `ssh_clean_list` | Out-of-band router verification |
| **LAPI** | `lapi_get_ips`, `lapi_count`, `lapi_add_decision`, `lapi_remove_decision` | CrowdSec decision management |
| **Bouncer** | `bouncer_start`, `bouncer_stop`, `bouncer_restart`, `bouncer_wait_reconciliation` | Systemd service control |
| **SNMP** | `snmp_cpu_avg`, `query_cpu`, `snmp_mem_percent`, `snmp_uptime_secs` | Router monitoring |
| **Metrics** | `bouncer_metric` | Prometheus endpoint queries |
| **Utility** | `wait_for`, `is_valid_ipv4`, `is_valid_ipv6`, `diff_sets` | General purpose |

#### Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| SSH tests fail with "connection refused" | Wrong port or key | Verify `MIKROTIK_SSH_PORT` and `MIKROTIK_SSH_KEY` in `.env` |
| SNMP tests skipped | `snmpget` not installed | `apt install snmp` or `dnf install net-snmp-utils` |
| T1.1 fails with >5 diff | Timing drift between LAPI query and SSH query | Re-run — transient decisions may expire between queries |
| T3.1 hangs at "waiting for reconciliation" | Bouncer failed to start | Check `journalctl -u cs-routeros-bouncer` |
| T8 tests timeout | Router overwhelmed by ~25k entries | Ensure router has ≥512MB free RAM; check CPU |
| All tests fail at preflight | `.env` not configured | Copy `.env.example` to `.env` and fill in values |

## Linting

### Run Linter

```bash
make lint
```

This uses golangci-lint v2 with the project's `.golangci.yml` configuration.

### Linter Configuration

The project uses golangci-lint v2 format (`.golangci.yml`):

```yaml
version: "2"
linters:
  enable:
    - errcheck
    - govet
    - staticcheck
    - unused
    # ... (see .golangci.yml for full list)
```

### Format Code

```bash
make fmt   # go fmt
make vet   # go vet
```

## Vulnerability Scanning

Scan dependencies for known vulnerabilities (CVEs):

```bash
make vulncheck
```

This runs [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck),
the official Go vulnerability scanner. It checks your dependencies against the
[Go vulnerability database](https://vuln.go.dev/) and only reports vulnerabilities
that are actually reachable in your code.

Install it with:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
```

## Dependencies

Key dependencies from `go.mod`:

| Dependency | Purpose |
|-----------|---------|
| `github.com/crowdsecurity/crowdsec` | CrowdSec decision models |
| `github.com/crowdsecurity/go-cs-bouncer` | StreamBouncer client for LAPI |
| `github.com/go-routeros/routeros/v3` | RouterOS API client |
| `github.com/prometheus/client_golang` | Prometheus metrics exposition |
| `github.com/rs/zerolog` | Structured JSON logging |
| `github.com/spf13/viper` | Configuration file + env var binding |

Update dependencies:

```bash
go get -u ./...
go mod tidy
```

## Makefile Reference

| Target | Description |
|--------|-------------|
| `make all` | lint + test + build |
| `make build` | Compile binary to `bin/` |
| `make test` | Run tests with race detector and coverage |
| `make lint` | Run golangci-lint |
| `make vulncheck` | Scan for known vulnerabilities |
| `make fmt` | Format code |
| `make vet` | Run go vet |
| `make clean` | Remove build artifacts |
| `make coverage` | Generate HTML coverage report |
| `make run` | Run from source with default config |
| `make install` | Install binary + config to system paths |
| `make uninstall` | Remove installed binary |
| `make docker-build` | Build Docker image |
| `make docker-push` | Push to GHCR |
| `make test-integration` | Run integration tests |
| `make release-snapshot` | GoReleaser snapshot build |

## CI/CD

The project uses GitHub Actions with two workflows:

### CI (`ci.yml`)

Triggered on push/PR to `main`:

1. **Lint** — golangci-lint v2
2. **Vulncheck** — govulncheck vulnerability scanning
3. **Test** — `go test -race` with coverage
4. **Docker** — build verification
5. **Build AMD64** — cross-compile check
6. **Build ARM64** — cross-compile check

### Release (`release.yml`)

Triggered on version tags (`v*`):

- GoReleaser builds binaries for multiple platforms
- Docker images pushed to GHCR
- GitHub release with changelog

### Documentation (`docs.yml`)

Triggered on changes to `docs/` or `mkdocs.yml`:

- Builds mkdocs-material site
- Deploys to GitHub Pages
