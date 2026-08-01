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

# Analysis tools are installed as standalone pinned binaries rather than tracked
# in go.mod via a `tool` directive. Keeping them out of the module graph means
# each tool resolves its own dependencies independently: gosec and actionlint
# require incompatible go.yaml.in/yaml/v4 revisions, which is unresolvable when
# a single MVS graph has to satisfy both.
#
# These pins are the single source of truth — CI installs from here too.
# Bump deliberately, in their own commit.
TOOLS_BIN             := $(CURDIR)/bin/tools
GOLANGCI_LINT_VERSION := v2.12.2
GOSEC_VERSION         := v2.28.0
ACTIONLINT_VERSION    := v1.7.12
STATICCHECK_VERSION   := v0.7.0
GOVULNCHECK_VERSION   := v1.6.0
# goimports and modernize both ship from golang.org/x/tools.
GOTOOLS_VERSION       := v0.48.0

GOLANGCI_LINT := $(TOOLS_BIN)/golangci-lint
GOSEC         := $(TOOLS_BIN)/gosec
ACTIONLINT    := $(TOOLS_BIN)/actionlint
STATICCHECK   := $(TOOLS_BIN)/staticcheck
GOVULNCHECK   := $(TOOLS_BIN)/govulncheck
GOIMPORTS     := $(TOOLS_BIN)/goimports
MODERNIZE     := $(TOOLS_BIN)/modernize

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w -X $(MODULE)/internal/config.Version=$(VERSION) \
           -X $(MODULE)/internal/config.Commit=$(COMMIT) \
           -X $(MODULE)/internal/config.BuildDate=$(BUILD_DATE) \
           -X github.com/crowdsecurity/go-cs-lib/version.Version=$(VERSION)

.PHONY: help all build build-all build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64 build-windows-amd64 \
	run test test-short test-race test-integration test-docker coverage \
	fmt fmt-check goimports goimports-check gofmt-check vet modernize modernize-fix golangci-lint gosec staticcheck govulncheck actionlint mdlint mdlint-fix \
	lint analyze install-tools go-mod-download tools tools-versions \
	docs-install docs-check docs-lint docs-format-check docs-format docs-build docs-html-validate docs-preview docs-analyze \
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

## fmt: apply every formatter configured in .golangci.yml (goimports, gofumpt, gci)
fmt: $(TOOLS_BIN)/.golangci-lint-$(GOLANGCI_LINT_VERSION)
	$(GOLANGCI_LINT) fmt $(GO_ANALYSIS_PKGS)

## fmt-check: report formatting drift without rewriting files
fmt-check: $(TOOLS_BIN)/.golangci-lint-$(GOLANGCI_LINT_VERSION)
	$(GOLANGCI_LINT) fmt --diff $(GO_ANALYSIS_PKGS)

# Tool installation ----------------------------------------------------------
# Each binary is tracked by a version-stamped marker, so bumping a *_VERSION
# variable above forces a reinstall instead of silently reusing a stale build.
# `go install pkg@version` deliberately ignores the surrounding module, which is
# what keeps these tools out of go.mod.

$(TOOLS_BIN)/.golangci-lint-$(GOLANGCI_LINT_VERSION):
	@mkdir -p $(TOOLS_BIN)
	@rm -f $(GOLANGCI_LINT) $(TOOLS_BIN)/.golangci-lint-*
	GOBIN=$(TOOLS_BIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@touch $@

$(TOOLS_BIN)/.gosec-$(GOSEC_VERSION):
	@mkdir -p $(TOOLS_BIN)
	@rm -f $(GOSEC) $(TOOLS_BIN)/.gosec-*
	GOBIN=$(TOOLS_BIN) go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	@touch $@

$(TOOLS_BIN)/.actionlint-$(ACTIONLINT_VERSION):
	@mkdir -p $(TOOLS_BIN)
	@rm -f $(ACTIONLINT) $(TOOLS_BIN)/.actionlint-*
	GOBIN=$(TOOLS_BIN) go install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)
	@touch $@

$(TOOLS_BIN)/.staticcheck-$(STATICCHECK_VERSION):
	@mkdir -p $(TOOLS_BIN)
	@rm -f $(STATICCHECK) $(TOOLS_BIN)/.staticcheck-*
	GOBIN=$(TOOLS_BIN) go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
	@touch $@

$(TOOLS_BIN)/.govulncheck-$(GOVULNCHECK_VERSION):
	@mkdir -p $(TOOLS_BIN)
	@rm -f $(GOVULNCHECK) $(TOOLS_BIN)/.govulncheck-*
	GOBIN=$(TOOLS_BIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	@touch $@

$(TOOLS_BIN)/.gotools-$(GOTOOLS_VERSION):
	@mkdir -p $(TOOLS_BIN)
	@rm -f $(GOIMPORTS) $(MODERNIZE) $(TOOLS_BIN)/.gotools-*
	GOBIN=$(TOOLS_BIN) go install golang.org/x/tools/cmd/goimports@$(GOTOOLS_VERSION)
	GOBIN=$(TOOLS_BIN) go install golang.org/x/tools/go/analysis/passes/modernize/cmd/modernize@$(GOTOOLS_VERSION)
	@touch $@

## goimports: apply import grouping/order
goimports: $(TOOLS_BIN)/.gotools-$(GOTOOLS_VERSION)
	$(GOIMPORTS) -local $(MODULE) -w $(GOFILES)

## goimports-check: verify goimports formatting
goimports-check: $(TOOLS_BIN)/.gotools-$(GOTOOLS_VERSION)
	@test -z "$$($(GOIMPORTS) -local $(MODULE) -l $(GOFILES) | tee /dev/stderr)"

## gofmt-check: verify gofmt -s formatting
gofmt-check:
	@test -z "$$(gofmt -l -s $(GOFILES) | tee /dev/stderr)"

## vet: run go vet
vet:
	go vet $(GO_ANALYSIS_PKGS)

## modernize: run Go's modernize analyzer
modernize: $(TOOLS_BIN)/.gotools-$(GOTOOLS_VERSION)
	$(MODERNIZE) $(GO_ANALYSIS_PKGS)

## modernize-fix: apply modernize suggested fixes
modernize-fix: $(TOOLS_BIN)/.gotools-$(GOTOOLS_VERSION)
	$(MODERNIZE) -fix $(GO_ANALYSIS_PKGS)

## staticcheck: run Staticcheck
staticcheck: $(TOOLS_BIN)/.staticcheck-$(STATICCHECK_VERSION)
	$(STATICCHECK) $(GO_ANALYSIS_PKGS)

## golangci-lint: run configured golangci-lint suite
golangci-lint: $(TOOLS_BIN)/.golangci-lint-$(GOLANGCI_LINT_VERSION)
	$(GOLANGCI_LINT) run $(GO_ANALYSIS_PKGS)

## gosec: run standalone Go security analysis
gosec: $(TOOLS_BIN)/.gosec-$(GOSEC_VERSION)
	$(GOSEC) -quiet -severity medium -confidence medium -exclude-generated -fmt text $(GO_ANALYSIS_PKGS)

## govulncheck: scan reachable Go vulnerabilities
govulncheck: $(TOOLS_BIN)/.govulncheck-$(GOVULNCHECK_VERSION)
	$(GOVULNCHECK) $(GO_ANALYSIS_PKGS)

## actionlint: lint GitHub Actions workflows
actionlint: $(TOOLS_BIN)/.actionlint-$(ACTIONLINT_VERSION)
	$(ACTIONLINT)

## mdlint: lint Markdown files with markdownlint-cli2
mdlint:
	pnpm --dir docs exec markdownlint-cli2 --config ../.markdownlint-cli2.jsonc "../**/*.md"

## mdlint-fix: auto-fix Markdown files where possible
mdlint-fix:
	pnpm --dir docs exec markdownlint-cli2 --config ../.markdownlint-cli2.jsonc --fix "../**/*.md"

## lint: fast local lint alias
lint: vet staticcheck golangci-lint

## analyze: run full static analysis suite
analyze: gofmt-check goimports-check vet modernize golangci-lint gosec staticcheck govulncheck actionlint mdlint docs-analyze

## install-tools: download Go modules and install pinned analysis binaries
install-tools: go-mod-download tools

## go-mod-download: download the module dependency graph
go-mod-download:
	go mod download

## tools: install every pinned analysis binary into bin/tools
tools: $(TOOLS_BIN)/.golangci-lint-$(GOLANGCI_LINT_VERSION) \
	$(TOOLS_BIN)/.gosec-$(GOSEC_VERSION) \
	$(TOOLS_BIN)/.actionlint-$(ACTIONLINT_VERSION) \
	$(TOOLS_BIN)/.staticcheck-$(STATICCHECK_VERSION) \
	$(TOOLS_BIN)/.govulncheck-$(GOVULNCHECK_VERSION) \
	$(TOOLS_BIN)/.gotools-$(GOTOOLS_VERSION)

## tools-versions: print the pinned analysis tool versions
tools-versions:
	@echo "golangci-lint $(GOLANGCI_LINT_VERSION)"
	@echo "gosec         $(GOSEC_VERSION)"
	@echo "actionlint    $(ACTIONLINT_VERSION)"
	@echo "staticcheck   $(STATICCHECK_VERSION)"
	@echo "govulncheck   $(GOVULNCHECK_VERSION)"
	@echo "x/tools       $(GOTOOLS_VERSION) (goimports, modernize)"

## docs-install: install documentation dependencies
docs-install:
	pnpm --dir docs install --frozen-lockfile --ignore-scripts
	docs/node_modules/.bin/playwright install --with-deps chromium

## docs-check: run Astro/Starlight static checks
docs-check:
	pnpm --dir docs check

## docs-lint: run ESLint for the documentation site
docs-lint:
	pnpm --dir docs lint

## docs-format-check: verify documentation formatting
docs-format-check:
	pnpm --dir docs format:check

## docs-format: format documentation sources
docs-format:
	pnpm --dir docs format

## docs-build: build the documentation site
docs-build:
	pnpm --dir docs build

## docs-html-validate: validate generated documentation HTML
docs-html-validate: docs-build
	pnpm --dir docs html:validate

## docs-preview: preview the built documentation site
docs-preview:
	pnpm --dir docs preview

## docs-analyze: run all documentation checks
docs-analyze:
	pnpm --dir docs analyze

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
