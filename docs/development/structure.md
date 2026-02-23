# Project Structure

```
cs-routeros-bouncer/
├── cmd/
│   └── cs-routeros-bouncer/
│       ├── main.go             # CLI entrypoint, subcommand routing
│       └── setup.go            # setup/uninstall subcommands
├── internal/
│   ├── config/
│   │   └── config.go           # Configuration loading, validation, env binding
│   ├── crowdsec/
│   │   └── client.go           # CrowdSec LAPI streaming client
│   ├── manager/
│   │   └── manager.go          # Central orchestrator
│   ├── metrics/
│   │   ├── metrics.go          # Prometheus metrics and health endpoint
│   │   └── lapi/
│   │       └── lapi.go         # CrowdSec LAPI usage metrics reporting
│   └── routeros/
│       ├── client.go           # RouterOS API connection
│       ├── addresses.go        # Address list management
│       └── firewall.go         # Firewall rule management
├── config/
│   └── cs-routeros-bouncer.yaml  # Annotated config reference
├── docker/
│   ├── Dockerfile              # Multi-stage build
│   └── docker-compose.yml      # Example compose file
├── grafana/
│   └── dashboard.json          # Grafana dashboard
├── tests/
│   ├── integration/            # Integration tests (build-tagged)
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
│       ├── .env.example        # Configuration template
│       └── .env                # Local config (git-ignored)
├── docs/                       # Documentation site (mkdocs-material)
├── .github/
│   ├── workflows/
│   │   ├── ci.yml              # CI pipeline (lint, test, build, docker)
│   │   ├── release.yml         # Release pipeline (binaries + Docker)
│   │   └── docs.yml            # Documentation deployment
│   ├── ISSUE_TEMPLATE/         # Bug report and feature request templates
│   ├── CODEOWNERS              # Code ownership
│   └── FUNDING.yml             # GitHub Sponsors
├── mkdocs.yml                  # MkDocs configuration
├── Makefile                    # Build commands
├── go.mod / go.sum             # Go module files
├── .golangci.yml               # Linter configuration (v2)
├── CONTRIBUTING.md             # Contribution guide
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
- Environment variable binding (22 env vars)
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
- Handles reconciliation on startup
- Decision filtering (origins, scenarios, scopes)

### `internal/metrics`

Observability:

- Prometheus metric definitions and registration
- HTTP server for `/metrics` and `/health` endpoints
- 8 metrics (gauges, counters, histograms)

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
- Address list operations (add, remove, list)
- Firewall rule operations (create, delete, list, move)
- Comment-based resource identification
