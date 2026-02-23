# Contributing to cs-routeros-bouncer

Thank you for your interest in contributing! This guide will help you get started.

## Getting Started

### Prerequisites

- **Go 1.25+** — [Download](https://go.dev/dl/)
- **golangci-lint** — `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`
- **Docker** (optional) — for container builds and testing
- **MikroTik router** (optional) — for integration testing

### Setup

```bash
git clone https://github.com/jmrplens/cs-routeros-bouncer.git
cd cs-routeros-bouncer
go mod download
make build
make test
```

### Project Structure

```
cmd/cs-routeros-bouncer/    # CLI entrypoint
internal/
  config/                   # Configuration loading and validation
  crowdsec/                 # CrowdSec LAPI stream client
  manager/                  # Central orchestrator (ties everything together)
  metrics/                  # Prometheus metrics and health endpoint
  routeros/                 # RouterOS API client (addresses, firewall rules)
config/                     # Example configuration files
docker/                     # Dockerfile and Docker Compose
tests/integration/          # Integration tests
```

## Development Workflow

1. **Fork the repository** and create a feature branch from `main`
2. **Make your changes** — keep commits focused and well-described
3. **Run tests**: `make test`
4. **Run linter**: `make lint`
5. **Build**: `make build`
6. **Submit a Pull Request** with a clear description

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add support for address list timeout override
fix: handle RouterOS connection timeout during reconciliation
docs: update configuration reference for block_output
test: add integration test for IPv6 address removal
```

Prefixes: `feat`, `fix`, `docs`, `test`, `ci`, `chore`, `refactor`, `perf`.

### Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use `golangci-lint` (config in `.golangci.yml`)
- Add comments for exported types and functions
- Use structured logging (`zerolog`) — never `fmt.Println` or `log.*`
- Handle errors explicitly — never silently ignore them

## Testing

### Unit Tests

```bash
make test             # Run all tests
go test ./internal/config/...  # Run specific package tests
```

### Integration Tests

Integration tests require a real MikroTik router and CrowdSec instance.
They are guarded by build tags and not run in CI:

```bash
# Set environment variables for your test router
export MIKROTIK_TEST_HOST="192.168.0.1:8728"
export MIKROTIK_TEST_USER="crowdsec"
export MIKROTIK_TEST_PASS="password"

go test -tags=integration ./tests/integration/
```

### Docker Build

```bash
make docker-build     # Build the container image
```

## RouterOS Testing Notes

When testing against a real router:

- **Use a dedicated API user** with minimal permissions
- **Use a test chain/list** to avoid affecting production firewall rules
- **RouterOS 7.x is required** — the API behavior differs from v6
- **Be aware of rate limits** — the RouterOS API can be slow with large batches

## Reporting Issues

- Use the [bug report template](https://github.com/jmrplens/cs-routeros-bouncer/issues/new?template=bug_report.yml)
- Include your RouterOS version, bouncer version, and relevant logs
- Redact sensitive information (passwords, API keys, public IPs)

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
