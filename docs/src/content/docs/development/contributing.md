---
title: Contributing
description: Guidelines for contributing to cs-routeros-bouncer.
---

Thank you for considering contributing to cs-routeros-bouncer!

## Getting started

### Prerequisites

- Go 1.24+
- A MikroTik router (for functional testing — optional)
- Git

### Setup

```bash
# Fork and clone the repository
git clone https://github.com/YOUR-USERNAME/cs-routeros-bouncer.git
cd cs-routeros-bouncer

# Install dependencies
go mod download

# Verify everything builds
go build ./...

# Run tests
go test ./...
```

## Development workflow

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make your changes** — keep commits focused and atomic

3. **Write tests** for new functionality

4. **Run the test suite**:
   ```bash
   go test ./...
   ```

5. **Run the linter**:
   ```bash
   golangci-lint run
   ```

6. **Commit** using conventional commit messages:
   ```
   feat: add support for new feature
   fix: correct handling of edge case
   docs: update configuration reference
   test: add tests for decision filtering
   refactor: simplify reconciliation logic
   ```

7. **Push** and create a Pull Request

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Usage |
|--------|-------|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation changes |
| `test:` | Adding or modifying tests |
| `refactor:` | Code change that neither fixes a bug nor adds a feature |
| `perf:` | Performance improvement |
| `chore:` | Build process or auxiliary tool changes |
| `ci:` | CI/CD changes |

## Code style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use meaningful variable and function names
- Add comments for exported functions and complex logic
- Keep functions focused — one function, one responsibility
- Handle errors explicitly — no silent failures

## Pull request guidelines

- Keep PRs focused on a single change
- Include tests for new functionality
- Update documentation if behavior changes
- Ensure all CI checks pass
- Provide a clear description of what and why

## Reporting issues

When reporting bugs, please include:

1. Bouncer version (`cs-routeros-bouncer version`)
2. MikroTik RouterOS version
3. Configuration (with credentials redacted)
4. Relevant log output (`LOG_LEVEL=debug`)
5. Steps to reproduce
