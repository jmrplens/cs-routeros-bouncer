# Build stage
FROM golang:1.25-alpine AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w \
      -X github.com/jmrplens/cs-routeros-bouncer/internal/config.Version=${VERSION} \
      -X github.com/jmrplens/cs-routeros-bouncer/internal/config.Commit=${COMMIT} \
      -X github.com/jmrplens/cs-routeros-bouncer/internal/config.BuildDate=${BUILD_DATE}" \
    -o /cs-routeros-bouncer \
    ./cmd/cs-routeros-bouncer/

# Runtime stage
FROM alpine:3.21

ARG VERSION=dev

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S bouncer && adduser -S bouncer -G bouncer

COPY --from=builder /cs-routeros-bouncer /usr/local/bin/cs-routeros-bouncer

RUN mkdir -p /etc/cs-routeros-bouncer && \
    chown bouncer:bouncer /etc/cs-routeros-bouncer

USER bouncer

LABEL org.opencontainers.image.title="cs-routeros-bouncer" \
      org.opencontainers.image.description="CrowdSec bouncer for MikroTik RouterOS" \
      org.opencontainers.image.source="https://github.com/jmrplens/cs-routeros-bouncer" \
      org.opencontainers.image.license="MIT" \
      org.opencontainers.image.version="${VERSION}"

EXPOSE 2112

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:2112/health || exit 1

ENTRYPOINT ["cs-routeros-bouncer"]
CMD ["-c", "/etc/cs-routeros-bouncer/config.yaml"]
