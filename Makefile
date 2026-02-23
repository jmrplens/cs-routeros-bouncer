BINARY_NAME := cs-routeros-bouncer
MODULE := github.com/jmrplens/cs-routeros-bouncer
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X $(MODULE)/internal/config.Version=$(VERSION) \
           -X $(MODULE)/internal/config.Commit=$(COMMIT) \
           -X $(MODULE)/internal/config.BuildDate=$(BUILD_DATE)

.PHONY: all build test lint vulncheck clean docker-build docker-push fmt vet install uninstall release-snapshot

all: lint test build

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME) ./cmd/$(BINARY_NAME)/

test:
	go test -v -race -coverprofile=coverage.out ./...

lint:
	golangci-lint run ./...

vulncheck:
	govulncheck ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -rf bin/ dist/ coverage.out coverage.html

## --- Binary installation ---

install: build
	install -d /etc/cs-routeros-bouncer
	install -m 755 bin/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	@if [ ! -f /etc/cs-routeros-bouncer/config.yaml ]; then \
		install -m 600 config/cs-routeros-bouncer.yaml /etc/cs-routeros-bouncer/config.yaml; \
		echo "Config installed at /etc/cs-routeros-bouncer/config.yaml — edit before starting"; \
	fi

uninstall:
	rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Config at /etc/cs-routeros-bouncer/ preserved. Remove manually if desired."

## --- Docker ---

docker-build:
	docker build -f docker/Dockerfile \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(BINARY_NAME):$(VERSION) \
		-t $(BINARY_NAME):latest .

docker-push:
	docker tag $(BINARY_NAME):$(VERSION) ghcr.io/jmrplens/$(BINARY_NAME):$(VERSION)
	docker tag $(BINARY_NAME):latest ghcr.io/jmrplens/$(BINARY_NAME):latest
	docker push ghcr.io/jmrplens/$(BINARY_NAME):$(VERSION)
	docker push ghcr.io/jmrplens/$(BINARY_NAME):latest

## --- Release ---

release-snapshot:
	goreleaser release --snapshot --clean

## --- Dev ---

coverage: test
	go tool cover -html=coverage.out -o coverage.html

run:
	go run ./cmd/$(BINARY_NAME)/ -c config/cs-routeros-bouncer.yaml

## --- Integration tests ---

test-integration:
	go test -v -tags integration -count=1 -timeout 300s ./tests/integration/...

test-docker:
	go test -v -tags integration -run TestDocker -count=1 -timeout 300s ./tests/integration/...
