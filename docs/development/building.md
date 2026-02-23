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

### Run All Tests

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

### Run Tests for a Single Package

```bash
go test -v ./internal/config/...
go test -v ./internal/crowdsec/...
go test -v ./internal/manager/...
go test -v ./internal/metrics/...
go test -v ./internal/routeros/...
```

### Coverage Report

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

### Current Coverage

| Package | Coverage | Tests |
|---------|----------|-------|
| `internal/config` | ~98% | Config loading, validation, env overrides |
| `internal/crowdsec` | ~48% | Decision parsing, stream creation, duration parsing |
| `internal/manager` | ~12% | Rule comment building/parsing, address comments, protos |
| `internal/metrics` | ~97% | All metric recording, health endpoint, server lifecycle |
| `internal/routeros` | ~11% | Duration formatting, address normalization, path helpers |

!!! note
    Manager and RouterOS packages have lower coverage because their core methods
    require a live RouterOS connection. Integration tests cover those paths.

### Integration Tests

Integration tests connect to a real MikroTik router and CrowdSec LAPI:

```bash
make test-integration
```

These tests are build-tagged with `//go:build integration` and require:

- A running MikroTik router accessible via API
- A running CrowdSec LAPI instance
- A valid configuration file

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
