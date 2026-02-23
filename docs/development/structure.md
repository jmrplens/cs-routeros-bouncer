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
│   │   └── metrics.go          # Prometheus metrics and health endpoint
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
│   └── integration/            # Integration tests (build-tagged)
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

### `internal/routeros`

MikroTik RouterOS API client:

- Connection management (plaintext and TLS)
- Address list operations (add, remove, list)
- Firewall rule operations (create, delete, list, move)
- Comment-based resource identification
