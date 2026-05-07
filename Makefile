BINARY_NAME := cs-routeros-bouncer
MODULE := github.com/jmrplens/cs-routeros-bouncer
CMD_PATH := ./cmd/$(BINARY_NAME)
BIN_DIR := bin
DIST_DIR := dist
PKGS := ./...
GO_ANALYSIS_PKGS := ./cmd/... ./internal/...
GO_SOURCE_DIRS := cmd internal tests
GOFILES := $(shell find $(GO_SOURCE_DIRS) -name '*.go' -type f 2>/dev/null)

PROJECT_GO_VERSION := $(shell awk '/^go / {print $$2; exit}' go.mod)
GO_TOOLCHAIN ?= go$(PROJECT_GO_VERSION)
export GOTOOLCHAIN := $(GO_TOOLCHAIN)

GOLANGCI_LINT_VERSION ?= v2.12.2
STATICCHECK_VERSION ?= v0.7.0
ACTIONLINT_VERSION ?= v1.7.12
MODERNIZE_VERSION ?= latest
GOSEC_VERSION ?= latest

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w -X $(MODULE)/internal/config.Version=$(VERSION) \
           -X $(MODULE)/internal/config.Commit=$(COMMIT) \
           -X $(MODULE)/internal/config.BuildDate=$(BUILD_DATE) \
           -X github.com/crowdsecurity/go-cs-lib/version.Version=$(VERSION)

.PHONY: help all build build-all build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64 build-windows-amd64 \
	run test test-short test-race test-integration test-docker coverage \
	fmt goimports goimports-check gofmt-check vet modernize modernize-fix golangci-lint gosec staticcheck govulncheck actionlint mdlint mdlint-fix \
        lint analyze install-tools docs-install docs-check docs-build docs-preview docs-analyze \
        clean install uninstall docker-build docker-push release-snapshot

## help: show available make targets
help:
	@awk 'BEGIN {printf "Usage:\n  make <target>\n\nTargets:\n"} /^## / {line=$$0; sub(/^## /, "", line); split(line, parts, ": "); printf "  %-22s %s\n", parts[1], parts[2]}' $(MAKEFILE_LIST)

## all: run analysis, tests, and build
all: analyze test build

## build: build the local binary with version metadata
build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -buildmode=pie -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_PATH)

## build-all: cross-compile common release binaries
build-all: build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64 build-windows-amd64

build-linux-amd64:
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildmode=pie -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_PATH)

build-linux-arm64:
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildmode=pie -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_PATH)

build-darwin-amd64:
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -buildmode=pie -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_PATH)

build-darwin-arm64:
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -buildmode=pie -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_PATH)

build-windows-amd64:
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -buildmode=pie -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_PATH)

## run: run the bouncer against the sample config
run:
	go run $(CMD_PATH) -c config/$(BINARY_NAME).yaml

## test: run all tests with race detector and coverage
test:
	go test -v -race -coverprofile=coverage.out $(PKGS)

## test-short: run all tests once without race detector
test-short:
	go test -count=1 $(PKGS)

## test-race: run tests with race detector
test-race: test

## test-integration: run integration-tagged Go tests
test-integration:
	go test -v -tags integration -count=1 -timeout 300s ./tests/integration/...

## test-docker: run Docker integration tests
test-docker:
	go test -v -tags integration -run TestDocker -count=1 -timeout 300s ./tests/integration/...

## coverage: generate an HTML coverage report
coverage: test
	go tool cover -html=coverage.out -o coverage.html

## fmt: format Go sources with gofmt and goimports
fmt: goimports
	gofmt -w -s $(GOFILES)

## goimports: apply import grouping/order
goimports:
	goimports -local $(MODULE) -w $(GOFILES)

## goimports-check: verify goimports formatting
goimports-check:
	@test -z "$$(goimports -local $(MODULE) -l $(GOFILES) | tee /dev/stderr)"

## gofmt-check: verify gofmt -s formatting
gofmt-check:
	@test -z "$$(gofmt -l -s $(GOFILES) | tee /dev/stderr)"

## vet: run go vet
vet:
	go vet $(GO_ANALYSIS_PKGS)

## modernize: run Go's modernize analyzer
modernize:
	modernize $(GO_ANALYSIS_PKGS)

## modernize-fix: apply modernize suggested fixes
modernize-fix:
	modernize -fix $(GO_ANALYSIS_PKGS)

## staticcheck: run Staticcheck
staticcheck:
	staticcheck $(GO_ANALYSIS_PKGS)

## golangci-lint: run configured golangci-lint suite
golangci-lint:
	golangci-lint run $(GO_ANALYSIS_PKGS)

## gosec: run standalone Go security analysis
gosec:
	gosec -quiet -severity medium -confidence medium -exclude-generated -fmt text $(GO_ANALYSIS_PKGS)

## govulncheck: scan reachable Go vulnerabilities
govulncheck:
	govulncheck $(GO_ANALYSIS_PKGS)

## actionlint: lint GitHub Actions workflows
actionlint:
	actionlint

## mdlint: lint Markdown files with markdownlint-cli2
mdlint:
	npx --yes markdownlint-cli2 "**/*.md"

## mdlint-fix: auto-fix Markdown files where possible
mdlint-fix:
	npx --yes markdownlint-cli2 --fix "**/*.md"

## lint: fast local lint alias
lint: vet staticcheck golangci-lint

## analyze: run full static analysis suite
analyze: gofmt-check goimports-check vet modernize golangci-lint gosec staticcheck govulncheck actionlint mdlint docs-check

## install-tools: install Go analysis tools pinned to CI versions
install-tools:
	go install golang.org/x/tools/cmd/goimports@latest
	go install golang.org/x/tools/go/analysis/passes/modernize/cmd/modernize@$(MODERNIZE_VERSION)
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

## docs-install: install documentation dependencies
docs-install:
	pnpm --dir docs install --frozen-lockfile

## docs-check: run Astro/Starlight static checks
docs-check:
	pnpm --dir docs check

## docs-build: build the documentation site
docs-build:
	pnpm --dir docs build

## docs-preview: preview the built documentation site
docs-preview:
	pnpm --dir docs preview

## docs-analyze: run all documentation checks
docs-analyze: docs-check docs-build mdlint

## clean: remove generated build and coverage artifacts
clean:
	rm -rf $(BIN_DIR) $(DIST_DIR) coverage.out coverage.html docs/dist

## install: build and install the binary and default config
install: build
	install -d /etc/$(BINARY_NAME)
	install -m 755 $(BIN_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	@if [ ! -f /etc/$(BINARY_NAME)/config.yaml ]; then \
		install -m 600 config/$(BINARY_NAME).yaml /etc/$(BINARY_NAME)/config.yaml; \
		echo "Config installed at /etc/$(BINARY_NAME)/config.yaml - edit before starting"; \
	fi

## uninstall: remove installed binary, keeping config
uninstall:
	rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Config at /etc/$(BINARY_NAME)/ preserved. Remove manually if desired."

## docker-build: build local Docker image
docker-build:
	docker build -f docker/Dockerfile \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(BINARY_NAME):$(VERSION) \
		-t $(BINARY_NAME):latest .

## docker-push: tag and push Docker image to GHCR
docker-push:
	docker tag $(BINARY_NAME):$(VERSION) ghcr.io/jmrplens/$(BINARY_NAME):$(VERSION)
	docker tag $(BINARY_NAME):latest ghcr.io/jmrplens/$(BINARY_NAME):latest
	docker push ghcr.io/jmrplens/$(BINARY_NAME):$(VERSION)
	docker push ghcr.io/jmrplens/$(BINARY_NAME):latest

## release-snapshot: run GoReleaser snapshot build
release-snapshot:
	goreleaser release --snapshot --clean
