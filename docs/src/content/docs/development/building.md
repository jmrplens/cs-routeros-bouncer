---
title: Building
description: How to build, test, and lint the bouncer from source.
---

## Prerequisites

- **Go** 1.24 or later
- **Docker** (for Docker image builds)
- **golangci-lint** (for linting)

## Building

### Binary

```bash
# Clone the repository
git clone https://github.com/jmrplens/cs-routeros-bouncer.git
cd cs-routeros-bouncer

# Build
go build -o cs-routeros-bouncer ./cmd/cs-routeros-bouncer
```

### With version information

```bash
go build -ldflags "-X main.version=1.3.0 -X main.commit=$(git rev-parse HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o cs-routeros-bouncer ./cmd/cs-routeros-bouncer
```

### Docker image

```bash
docker build -t cs-routeros-bouncer:local .
```

### Cross-compilation

Build for different architectures:

```bash
# ARM64 (e.g., Raspberry Pi 4, Apple Silicon)
GOOS=linux GOARCH=arm64 go build -o cs-routeros-bouncer-arm64 ./cmd/cs-routeros-bouncer

# ARMv7 (e.g., Raspberry Pi 3)
GOOS=linux GOARCH=arm GOARM=7 go build -o cs-routeros-bouncer-armv7 ./cmd/cs-routeros-bouncer

# AMD64
GOOS=linux GOARCH=amd64 go build -o cs-routeros-bouncer-amd64 ./cmd/cs-routeros-bouncer
```

## Testing

### Unit tests

```bash
# Run all tests
go test ./...

# With verbose output
go test -v ./...

# With coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Run specific package tests

```bash
# Test configuration package
go test -v ./internal/config/...

# Test RouterOS client
go test -v ./internal/routeros/...

# Test metrics
go test -v ./internal/metrics/...
```

### Test coverage

```bash
# Generate coverage report
go test -coverprofile=coverage.out -covermode=atomic ./...

# View coverage in browser
go tool cover -html=coverage.out -o coverage.html

# Check coverage percentage
go tool cover -func=coverage.out | tail -1
```

### Functional tests

The repository includes functional tests that test against a real MikroTik router. These are skipped by default (they require `FUNCTIONAL_TEST=1` and actual router credentials).

```bash
# Run functional tests (requires real router)
FUNCTIONAL_TEST=1 \
  MIKROTIK_HOST="192.168.0.1:8728" \
  MIKROTIK_USER="crowdsec" \
  MIKROTIK_PASS="your-password" \
  go test -v ./internal/routeros/... -run TestFunctional
```

:::note
Functional tests create and delete firewall rules and address list entries on the target router. Use a test router or ensure you understand the impact.
:::

## Linting

### golangci-lint

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
golangci-lint run

# Run with auto-fix
golangci-lint run --fix
```

The project uses `.golangci.yml` for linter configuration.

### Go vet

```bash
go vet ./...
```

## CI/CD

The project uses GitHub Actions for CI/CD:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `test.yml` | Push, PR | Run tests and linting |
| `release.yml` | Tag push | Build binaries, Docker images, create GitHub release |
| `docker.yml` | Push to main | Build and push Docker image to GHCR |

### Release process

1. Update version in code
2. Create and push a git tag:
   ```bash
   git tag v1.3.0
   git push origin v1.3.0
   ```
3. GitHub Actions automatically:
   - Builds binaries for linux/amd64, linux/arm64, linux/arm/v7
   - Builds and pushes Docker images (multi-arch)
   - Creates a GitHub release with binaries attached

## Makefile targets

If a Makefile is present:

```bash
make build       # Build binary
make test        # Run tests
make lint        # Run linter
make docker      # Build Docker image
make clean       # Remove build artifacts
make coverage    # Generate coverage report
```

## Development workflow

1. Create a feature branch: `git checkout -b feat/my-feature`
2. Make changes
3. Run tests: `go test ./...`
4. Run linter: `golangci-lint run`
5. Commit with conventional message: `feat: add new feature`
6. Push and create PR
