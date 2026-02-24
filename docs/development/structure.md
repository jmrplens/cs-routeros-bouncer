# Project Structure

```
cs-routeros-bouncer/
├── cmd/
│   ├── benchmark/
│   │   └── main.go             # Connection pool benchmark utility
│   └── cs-routeros-bouncer/
│       ├── main.go             # CLI entrypoint, subcommand routing
│       └── setup.go            # setup/uninstall subcommands
├── internal/
│   ├── config/
│   │   ├── config.go           # Configuration loading, validation, env binding
│   │   ├── config_test.go      # Config unit tests
│   │   └── doc.go              # Package documentation
│   ├── crowdsec/
│   │   ├── bouncer_iface.go    # BouncerEngine interface (for testing)
│   │   ├── stream.go           # CrowdSec LAPI streaming client
│   │   ├── stream_test.go      # Stream unit tests
│   │   ├── crowdsec_test.go    # CrowdSec package tests
│   │   ├── mock_bouncer_test.go # Mock bouncer for tests
│   │   ├── logrus_adapter.go   # Logrus-to-zerolog adapter
│   │   ├── logrus_adapter_test.go
│   │   └── doc.go              # Package documentation
│   ├── manager/
│   │   ├── manager.go          # Central orchestrator
│   │   ├── manager_test.go     # Manager unit tests
│   │   ├── start_test.go       # Start/Shutdown lifecycle tests
│   │   ├── mock_test.go        # Mock implementations for tests
│   │   ├── routeros_iface.go   # RouterOSClient interface (for testing)
│   │   ├── crowdsec_iface.go   # CrowdSecStream interface (for testing)
│   │   └── doc.go              # Package documentation
│   ├── metrics/
│   │   ├── metrics.go          # Prometheus metrics definitions and helpers
│   │   ├── metrics_test.go     # Metrics unit tests
│   │   ├── server.go           # HTTP server for /metrics and /health
│   │   ├── doc.go              # Package documentation
│   │   └── lapi/
│   │       ├── lapi.go         # CrowdSec LAPI usage metrics reporting
│   │       └── lapi_test.go    # LAPI metrics unit tests
│   └── routeros/
│       ├── client.go           # RouterOS API connection and pool
│       ├── pool.go             # Connection pool implementation
│       ├── addresslist.go      # Address list management
│       ├── bulk.go             # Bulk operations (script-based)
│       ├── firewall.go         # Firewall rule management and counters
│       ├── conn_iface.go       # RouterConn interface (for testing)
│       ├── routeros_test.go    # RouterOS unit tests
│       ├── client_mock_test.go # Client mock tests
│       ├── mock_conn_test.go   # Mock connection for tests
│       └── doc.go              # Package documentation
├── config/
│   ├── cs-routeros-bouncer.yaml  # Annotated config reference
│   └── test.yaml               # Test configuration
├── docker/
│   ├── Dockerfile              # Multi-stage build
│   ├── Dockerfile.goreleaser   # GoReleaser-specific Dockerfile
│   └── docker-compose.yml      # Example compose file
├── grafana/
│   └── dashboard.json          # Grafana dashboard (portable with ${DS_PROMETHEUS})
├── tests/
│   ├── integration/            # Integration tests (build-tagged)
│   │   ├── docker_test.go      # Docker integration tests
│   │   └── routeros_test.go    # RouterOS integration tests
│   └── functional/             # Bash test suite against real hardware
│       ├── run_tests.sh        # Test runner (CLI entrypoint)
│       ├── lib/
│       │   └── helpers.sh      # Shared library (SSH, SNMP, LAPI, framework)
│       ├── t1_integrity.sh     # T1: Data integrity (completeness, format)
│       ├── t2_cache.sh         # T2: Cache consistency (ban/unban lifecycle)
│       ├── t3_bulk.sh          # T3: Bulk operations (reconciliation, sync)
│       ├── t4_pool.sh          # T4: Connection pool verification
│       ├── t5_edge.sh          # T5: Edge cases (duplicates, stress, IPv6)
│       ├── t6_cpu.sh           # T6: CPU monitoring via SNMP
│       ├── t7_timing.sh        # T7: Timing & latency measurements
│       ├── t8_capi.sh          # T8: CAPI stress test (~25k IPs)
│       ├── t9_advanced.sh      # T9: Advanced firewall config (reject-with, whitelist, etc.)
│       ├── .env.example        # Configuration template
│       └── .env                # Local config (git-ignored)
├── docs/                       # Documentation site (mkdocs-material)
├── .github/
│   ├── workflows/
│   │   ├── ci.yml              # CI pipeline (lint, shellcheck, vulncheck, test, build, docker)
│   │   ├── release.yml         # Release pipeline (GoReleaser: binaries + Docker)
│   │   └── docs.yml            # Documentation deployment (GitHub Pages)
│   ├── ISSUE_TEMPLATE/         # Bug report and feature request templates
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── CODEOWNERS              # Code ownership
│   └── FUNDING.yml             # GitHub Sponsors
├── mkdocs.yml                  # MkDocs configuration
├── Makefile                    # Build commands
├── .goreleaser.yaml            # GoReleaser v2 configuration
├── go.mod / go.sum             # Go module files
├── .golangci.yml               # Linter configuration (v2)
├── docker-compose.yml          # Root-level compose file
├── CONTRIBUTING.md             # Contribution guide
├── CHANGELOG.md                # Release changelog
├── SECURITY.md                 # Security policy
├── LICENSE                     # MIT License
└── README.md                   # Project overview
```

## Package responsibilities

### `cmd/cs-routeros-bouncer`

The CLI entrypoint. Handles:

- Subcommand routing (`setup`, `uninstall`, `help`)
- Flag parsing (`-c` for config file)
- Signal handling (SIGTERM, SIGINT)
- Bouncer lifecycle (start → run → shutdown)

### `internal/config`

Configuration loading and validation:

- YAML file parsing
- Environment variable binding (48 env vars)
- Default values
- Validation (required fields, value ranges)

### `internal/crowdsec`

CrowdSec LAPI client:

- StreamBouncer-based streaming client
- Decision polling at configurable intervals
- TLS authentication support
- Retry logic for initial connection

### `internal/manager`

Central orchestrator that ties everything together:

- Coordinates CrowdSec decisions → MikroTik actions
- Manages firewall rule lifecycle (create on start, remove on stop)
- Handles reconciliation on startup (bulk add/remove)
- Decision filtering (origins, scenarios, scopes)
- Address cache for unban fast-path (avoids API calls for unknown IPs)
- Duplicate IP handling with timeout update (if a ban already exists, the timeout is updated)
- Connection pool delegation for parallel reconciliation

### `internal/metrics`

Observability:

- Prometheus metric definitions and registration
- HTTP server for `/metrics` and `/health` endpoints
- 11 Prometheus metrics (gauges, counters, histograms)

### `internal/metrics/lapi`

CrowdSec LAPI usage metrics reporting:

- Wraps `go-cs-bouncer.MetricsProvider` for periodic reporting to `/v1/usage-metrics`
- Reports active decisions per-origin and per-IP-type
- Reports firewall dropped bytes/packets (delta between pushes)
- `CounterCollector` callback to refresh MikroTik firewall counters before each push
- Sends bouncer metadata (type, version, OS) via the CrowdSec SDK

### `internal/routeros`

MikroTik RouterOS API client:

- Connection management (plaintext and TLS)
- Connection pool for parallel operations
- Bulk script-based address operations (chunked, 100 per script)
- Address list operations (add, remove, list, find, update timeout)
- Firewall rule operations (create, delete, list, move, counters)
- Comment-based resource identification
