# cs-routeros-bouncer

[![CI](https://github.com/jmrplens/cs-routeros-bouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/jmrplens/cs-routeros-bouncer/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jmrplens/cs-routeros-bouncer)](https://github.com/jmrplens/cs-routeros-bouncer/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/jmrplens/cs-routeros-bouncer/total)](https://github.com/jmrplens/cs-routeros-bouncer/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/jmrplens/cs-routeros-bouncer.svg)](https://pkg.go.dev/github.com/jmrplens/cs-routeros-bouncer)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=jmrplens_cs-routeros-bouncer&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=jmrplens_cs-routeros-bouncer)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=jmrplens_cs-routeros-bouncer&metric=coverage)](https://sonarcloud.io/summary/new_code?id=jmrplens_cs-routeros-bouncer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/jmrplens/cs-routeros-bouncer)](https://go.dev/)

A [CrowdSec](https://www.crowdsec.net/) remediation component (bouncer) for [MikroTik RouterOS](https://mikrotik.com/software) that automatically manages firewall rules and address lists via the RouterOS API.

## Documentation

**📖 [Full documentation](https://jmrp.io/docs/cs-routeros-bouncer/)** — available in English and Spanish.

This README covers installation and the settings most deployments need. The documentation site carries the rest, and carries it more reliably: its [configuration reference](https://jmrp.io/docs/cs-routeros-bouncer/configuration/) is **generated from `internal/config/config.go`** and regenerated in CI, which fails on any diff. The [firewall rule listing](https://jmrp.io/docs/cs-routeros-bouncer/architecture/firewall-rules/) is not generated but is single-sourced: one module, read field by field out of `internal/manager`, rendered on every page that shows the rules — so the three copies that used to disagree are now one. A hand-written copy here would be a fourth, and the last one drifted.

| If you want to | Go to |
| --- | --- |
| Every setting, its default and env var | [Configuration reference](https://jmrp.io/docs/cs-routeros-bouncer/configuration/) |
| Worked config examples | [Examples](https://jmrp.io/docs/cs-routeros-bouncer/configuration/examples/) |
| Exactly what gets written to the router | [Firewall rules](https://jmrp.io/docs/cs-routeros-bouncer/architecture/firewall-rules/) |
| How reconciliation works and what it costs | [Reconciliation](https://jmrp.io/docs/cs-routeros-bouncer/architecture/reconciliation/) |
| Metrics, health checks, Grafana | [Monitoring](https://jmrp.io/docs/cs-routeros-bouncer/monitoring/prometheus/) |
| Tuning for large CAPI lists | [Performance tuning](https://jmrp.io/docs/cs-routeros-bouncer/configuration/performance-tuning/) |
| Measured numbers on real hardware | [Benchmarking](https://jmrp.io/docs/cs-routeros-bouncer/development/benchmarking/) |

For machine consumption: [llms.txt](https://jmrp.io/docs/cs-routeros-bouncer/llms.txt) and [llms-full.txt](https://jmrp.io/docs/cs-routeros-bouncer/llms-full.txt).

## Highlights

- **Zero manual router configuration** — auto-creates and auto-removes firewall filter/raw rules on start/stop
- **Individual IP management** — adds on ban, removes on unban (no bulk re-upload, no duplicates)
- **State reconciliation** — on start/restart and periodically, syncs CrowdSec decisions with MikroTik state (adds missing, removes stale)
- **High-performance sync** — connection pool, script-based bulk add, in-memory cache (~22,000 IPs imported in ~29 s on an RB5009, measured at 100 ms resolution)
- **Graceful shutdown** — removes firewall rules on stop (address list entries expire via MikroTik timeout)
- **IPv4 + IPv6** — independently toggleable
- **Input + Output blocking** — output blocking optional with configurable interface/interface-list
- **Decision filtering** — sync only local decisions or include CrowdSec community blocklists (CAPI)
- **Observable** — Prometheus metrics (`/metrics`), structured logging, health endpoint (`/health`), LAPI usage metrics (active decisions, dropped traffic)
- **Multiple deployment options** — Docker, systemd, or standalone binary

## Why Another Bouncer?

Existing MikroTik bouncers have significant limitations that this project addresses:

| Feature                              | funkolab (archived) |   nvtkaszpir-alt    | **cs-routeros-bouncer** |
| ------------------------------------ | :-----------------: | :-----------------: | :---------------------: |
| Auto-create firewall rules           |         ❌          |         ❌          |           ✅            |
| Individual IP add/remove             |         ✅          | ❌ (bulk re-upload) |           ✅            |
| No duplicate IPs                     |         ✅          |         ❌          |           ✅            |
| State reconciliation on restart      |         ❌          |         ❌          |           ✅            |
| Remove rules on shutdown             |         ❌          |         ❌          |           ✅            |
| IPv6 support                         |         ✅          |         ✅          |           ✅            |
| Output blocking                      |         ❌          |         ✅          |           ✅            |
| Origin filtering (local-only mode)   |         ❌          |         ❌          |           ✅            |
| Prometheus metrics                   |         ❌          |         ✅          |           ✅            |
| LAPI usage metrics (dropped traffic) |         ❌          |         ❌          |           ✅            |
| Health endpoint                      |         ❌          |         ❌          |           ✅            |
| Go (compiled, low resource usage)    |         ✅          |         ✅          |           ✅            |

## Background

This bouncer exists because of a specific setup, not as an exercise. It is the
enforcement end of a pipeline that starts with a MikroTik router deliberately
exposing closed ports to catch scanners, and with an nginx tier that slows down
the ones that get through:

- [Implementing a MikroTik honeypot](https://jmrp.io/blog/006-implementing-mikrotik-honeypot/)
  — RAW-table detection that turns a scanner's first reconnaissance packet into an
  address-list entry, and how those events reach CrowdSec.
- [Implementing a tarpit in nginx](https://jmrp.io/blog/005-implementing-tarpit-nginx/)
  — the nginx half of the same setup, including a write-up of the failure mode
  where Brotli silently compressed the tarpit payload below the rate-limit
  threshold and disabled the throttle for months.

Both run on the author's own network against real traffic; the decisions in this
bouncer (state reconciliation on restart, individual IP add/remove, origin
filtering) come from that.

## Requirements

- **CrowdSec** 1.5+ with LAPI accessible from the bouncer host
- **MikroTik RouterOS** 7.x with API enabled (port 8728 or 8729 for TLS)
- A dedicated RouterOS API user (see [Create a RouterOS API user](#2-create-a-routeros-api-user))

## Quick Start

### 1. Register the bouncer with CrowdSec

```bash
sudo cscli bouncers add cs-routeros-bouncer
```

Save the API key shown in the output.

### 2. Create a RouterOS API user

Connect to your MikroTik router and create a dedicated user:

```routeros
/user group add name=crowdsec policy=read,write,api,sensitive,!ftp,!local,!ssh,!reboot,!policy,!test,!password,!sniff,!romon,!rest-api
/user add name=crowdsec group=crowdsec password=YOUR_SECURE_PASSWORD
```

### 3. Install and configure

Choose your preferred installation method below.

---

## Installation

### Docker Compose

```yaml
services:
  cs-routeros-bouncer:
    image: ghcr.io/jmrplens/cs-routeros-bouncer:latest
    container_name: cs-routeros-bouncer
    restart: unless-stopped
    ports:
      - "2112:2112" # Prometheus metrics (optional)
    environment:
      CROWDSEC_URL: "http://crowdsec:8080/"
      CROWDSEC_BOUNCER_API_KEY: "your-bouncer-api-key"
      MIKROTIK_HOST: "192.168.0.1:8728"
      MIKROTIK_USER: "crowdsec"
      MIKROTIK_PASS: "your-password"
    # Optional: mount a config file; this path is loaded automatically when present.
    # volumes:
    #   - ./config.yaml:/etc/cs-routeros-bouncer/config.yaml
```

```bash
docker compose up -d
```

### Binary + systemd

Download the latest release from the [Releases page](https://github.com/jmrplens/cs-routeros-bouncer/releases):

**Automatic setup (recommended):**

```bash
# Resolve the latest version (release assets embed it in the filename)
VERSION=$(curl -fsSL https://api.github.com/repos/jmrplens/cs-routeros-bouncer/releases/latest | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -n1)
[ -n "$VERSION" ] || { echo "could not resolve the latest version; pick a tag from the Releases page" >&2; exit 1; }

# Download (replace with your architecture, e.g. x86_64, i386, arm64, armv6, armv7)
ARCH=x86_64
wget "https://github.com/jmrplens/cs-routeros-bouncer/releases/download/v${VERSION}/cs-routeros-bouncer_${VERSION}_linux_${ARCH}.tar.gz"
tar xzf "cs-routeros-bouncer_${VERSION}_linux_${ARCH}.tar.gz"

# Automated install: copies binary, creates config, installs and starts systemd service
sudo ./cs-routeros-bouncer setup

# Edit configuration with your CrowdSec API key and MikroTik credentials
sudo nano /etc/cs-routeros-bouncer/cs-routeros-bouncer.yaml

# Restart after editing config
sudo systemctl restart cs-routeros-bouncer
```

The `setup` subcommand accepts optional flags:

| Flag          | Default                              | Description                       |
| ------------- | ------------------------------------ | --------------------------------- |
| `-bin`        | `/usr/local/bin/cs-routeros-bouncer` | Installation path for the binary  |
| `-config-dir` | `/etc/cs-routeros-bouncer`           | Directory for configuration files |

To uninstall:

```bash
sudo cs-routeros-bouncer uninstall        # Keeps config files
sudo cs-routeros-bouncer uninstall -purge  # Also removes config
```

If setup used custom paths, pass the same values to uninstall:

```bash
sudo cs-routeros-bouncer uninstall \
  -bin /opt/cs-routeros-bouncer/cs-routeros-bouncer \
  -config-dir /opt/cs-routeros-bouncer/config \
  -purge
```

<details>
<summary><strong>Manual setup</strong></summary>

```bash
# Download (e.g. x86_64, i386, arm64, armv6, armv7 — see the release assets for the full list)
VERSION=$(curl -fsSL https://api.github.com/repos/jmrplens/cs-routeros-bouncer/releases/latest | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -n1)
[ -n "$VERSION" ] || { echo "could not resolve the latest version; pick a tag from the Releases page" >&2; exit 1; }
ARCH=x86_64
wget "https://github.com/jmrplens/cs-routeros-bouncer/releases/download/v${VERSION}/cs-routeros-bouncer_${VERSION}_linux_${ARCH}.tar.gz"
tar xzf "cs-routeros-bouncer_${VERSION}_linux_${ARCH}.tar.gz"

# Install (the archive ships the sample config under config/)
sudo install -m 755 cs-routeros-bouncer /usr/local/bin/
sudo mkdir -p /etc/cs-routeros-bouncer
sudo cp config/cs-routeros-bouncer.yaml /etc/cs-routeros-bouncer/cs-routeros-bouncer.yaml

# Edit configuration
sudo nano /etc/cs-routeros-bouncer/cs-routeros-bouncer.yaml

# Install systemd service
sudo tee /etc/systemd/system/cs-routeros-bouncer.service > /dev/null << 'EOF'
[Unit]
Description=CrowdSec RouterOS Bouncer
After=network-online.target crowdsec.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cs-routeros-bouncer -c /etc/cs-routeros-bouncer/cs-routeros-bouncer.yaml
Restart=on-failure
RestartSec=10
TimeoutStopSec=90

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now cs-routeros-bouncer
```

</details>

### Build from source

```bash
git clone https://github.com/jmrplens/cs-routeros-bouncer.git
cd cs-routeros-bouncer
make build

# Option 1: Automated install
sudo bin/cs-routeros-bouncer setup

# Option 2: Manual install
sudo install -m 755 bin/cs-routeros-bouncer /usr/local/bin/
```

---

## Configuration

Settings come from a YAML file, environment variables, or both — environment variables win. The annotated sample ships with every release as [`config/cs-routeros-bouncer.yaml`](config/cs-routeros-bouncer.yaml).

### A minimal working configuration

Everything below is either required or worth being explicit about. Nothing else has to be set.

```yaml
crowdsec:
  api_url: "http://localhost:8080/"
  api_key: "your-bouncer-api-key" # from `cscli bouncers add`

mikrotik:
  address: "192.168.0.1:8728" # 8729 with tls: true
  username: "crowdsec"
  password: "your-password"

firewall:
  ipv4:
    enabled: true
  ipv6:
    enabled: true

logging:
  level: "info"
```

### The settings you are most likely to touch

| Config key | Env variable | Default | Description |
| --- | --- | --- | --- |
| `crowdsec.api_url` | `CROWDSEC_URL` | `http://localhost:8080/` | CrowdSec LAPI URL |
| `crowdsec.api_key` | `CROWDSEC_BOUNCER_API_KEY` | _(required)_ | Bouncer API key |
| `crowdsec.origins` | `CROWDSEC_ORIGINS` | _(all)_ | Restrict to e.g. `["crowdsec","cscli"]` for local-only |
| `crowdsec.reconciliation_interval` | `CROWDSEC_RECONCILIATION_INTERVAL` | `15m` | Periodic drift repair; `0` disables |
| `mikrotik.address` | `MIKROTIK_HOST` | _(required)_ | RouterOS API address (`host:port`) |
| `mikrotik.username` | `MIKROTIK_USER` | _(required)_ | API username |
| `mikrotik.password` | `MIKROTIK_PASS` | _(required)_ | API password |
| `mikrotik.tls` | `MIKROTIK_TLS` | `false` | Use TLS (port 8729) |
| `mikrotik.pool_size` | `MIKROTIK_POOL_SIZE` | `4` | Parallel API sessions |
| `firewall.ipv4.enabled` | `FIREWALL_IPV4_ENABLED` | `true` | Enable IPv4 blocking |
| `firewall.ipv6.enabled` | `FIREWALL_IPV6_ENABLED` | `true` | Enable IPv6 blocking |
| `firewall.deny_action` | `FIREWALL_DENY_ACTION` | `drop` | `drop` or `reject` |
| `metrics.enabled` | `METRICS_ENABLED` | `false` | Serve `/metrics` and `/health` |
| `logging.level` | `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

That is 14 of 94 keys. The other 80 — decision filtering, TLS material, per-protocol rule placement, chain selection, logging to file, pprof — are in the **[generated configuration reference](https://jmrp.io/docs/cs-routeros-bouncer/configuration/)**, which is built from the Go struct and fails CI when it disagrees with it.

---

## What it does to your router

**On startup** it connects to CrowdSec and RouterOS, creates its firewall rules, fetches every active decision and reconciles them against what the router already holds.

**At runtime** it streams new decisions: a ban adds an address-list entry, an unban removes one. Every `reconciliation_interval` it re-reads the list and repairs any drift.

**On shutdown** (SIGTERM/SIGINT) it removes the firewall rules it created. Address-list entries are left to expire via their MikroTik timeout, so a restart does not leave your router unprotected.

A stock configuration writes **eight** firewall rules — a deny rule and a passthrough counting rule, in both the `filter` and `raw` tables, for both IPv4 and IPv6. The counting rules come from `metrics.track_processed`, which defaults to `true`; set it to `false` and you get four. Each rule, its exact RouterOS command and its placement is listed on the [firewall rules page](https://jmrp.io/docs/cs-routeros-bouncer/architecture/firewall-rules/), which renders from the same module the daemon reads.

For what reconciliation costs on real hardware, and how to size the interval for your list, see [reconciliation](https://jmrp.io/docs/cs-routeros-bouncer/architecture/reconciliation/) and [performance tuning](https://jmrp.io/docs/cs-routeros-bouncer/configuration/performance-tuning/).

---

## Monitoring

Set `metrics.enabled: true` and the bouncer serves two endpoints on `metrics.listen_port` (default `2112`):

```bash
curl http://localhost:2112/health
# {"routeros_connected":true,"status":"ok","version":"X.Y.Z"}

curl http://localhost:2112/metrics
```

Metrics cover decisions processed, active decisions by origin, operation latencies, RouterOS connection state and router CPU/memory, plus CrowdSec LAPI usage metrics (including traffic dropped by the bouncer's own rules, which is what makes it show up in `cscli metrics`).

Neither endpoint is authenticated, and `metrics.listen_addr` defaults to `0.0.0.0` — so enabling metrics exposes them on every interface the host has. Bind them to `127.0.0.1`, or firewall the port, unless the scrape genuinely comes from elsewhere. The same applies with more force to `metrics.pprof_enabled`: a heap profile carries fragments of whatever the process has held, including the CrowdSec API key and the RouterOS password.

The full metric list, a ready-made Grafana dashboard and alerting examples are in [Monitoring](https://jmrp.io/docs/cs-routeros-bouncer/monitoring/prometheus/).

## Troubleshooting

<details>
<summary><b>Cannot connect to RouterOS API</b></summary>

- Verify the API service is enabled: `/ip/service/print` — `api` should be enabled on your router
- Check the router firewall doesn't block port 8728/8729 from the bouncer host
- Verify username/password and that the user has `api` policy
- For TLS: ensure `mikrotik.tls: true` and the correct port (8729)

</details>

<details>
<summary><b>Firewall rules are not in the expected position</b></summary>

- RouterOS dynamic/built-in rules (e.g., fasttrack counters) cannot be moved. With `top` or `position`, the bouncer iterates through lower positions until it finds one where the managed block can be placed
- Verify with: `/ip/firewall/filter/print` on the router
- For comment placement, verify the anchor comment and `comment_match`; matching is case-sensitive
- Check logs for placement fallback messages:
  - systemd: `journalctl -u cs-routeros-bouncer -f | grep -i placement`
  - Docker: `docker logs cs-routeros-bouncer | grep -i placement`
  - Standalone: `journalctl -u cs-routeros-bouncer`, or the process stderr if you run it by hand
- Ensure `firewall.rule_placement: "top"` is set, or use structured placement with `strategy: "position"`, `before_comment`, or `after_comment`. Also check any YAML-only `firewall.ipv4.rule_placement` or `firewall.ipv6.rule_placement` override.

</details>

<details>
<summary><b>Address list not being populated</b></summary>

- Check CrowdSec has active decisions: `sudo cscli decisions list`
- Verify the API key is correct — check bouncer logs for authentication errors
- Set `logging.level: debug` for detailed decision processing logs
- If using `crowdsec.origins`, ensure it includes the expected sources

</details>

<details>
<summary><b>High memory/CPU usage at startup</b></summary>

- Large community blocklists (CAPI) can contain 20,000+ IPs — initial reconciliation processes them all
- Use `crowdsec.origins: ["crowdsec", "cscli"]` to sync only local decisions
- The large full-sync cost is paid at startup; periodic reconciliation is configurable via `crowdsec.reconciliation_interval` (default `15m`) and is usually light when there is no drift, while cached duplicates skip RouterOS entirely
- Sustained high RouterOS CPU after reconciliation is not normal. Check logs for repeated `already have such entry` or reconnect messages, and verify you are running a version where RouterOS device errors do not trigger reconnects.

</details>

More failure modes, each with the check that identifies it, are on the [troubleshooting page](https://jmrp.io/docs/cs-routeros-bouncer/troubleshooting/).

---

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

```bash
make build          # Build binary
make test           # Run tests
make lint           # Run linter
make analyze        # Every check CI runs, reporting all failures rather than the first
make docker-build   # Build Docker image
```

A Bash suite exercises the compiled binary against a real MikroTik router over SSH, `cscli`, `systemctl` and SNMP — no Go internals imported. Nine groups, from data integrity to a ~28k-IP CAPI stress test:

```bash
cp tests/functional/.env.example tests/functional/.env   # fill in router + LAPI credentials
tests/functional/run_tests.sh --list                     # see the groups
tests/functional/run_tests.sh                            # all but the CAPI stress test
tests/functional/run_tests.sh --capi                     # include it
```

There is also a developer benchmark (`go run ./cmd/benchmark`) and self-installing router instrumentation that samples CPU and RAM at 10 Hz (`go run ./cmd/perfmon install`). Both, and the method for measuring against a live router without fooling yourself, are covered in [Benchmarking](https://jmrp.io/docs/cs-routeros-bouncer/development/benchmarking/).

## Security

See [SECURITY.md](SECURITY.md) for the security policy and responsible disclosure process.

## License

[MIT](LICENSE)

## Acknowledgments

- [CrowdSec](https://www.crowdsec.net/) — open-source collaborative security engine
- [go-routeros](https://github.com/go-routeros/routeros) — the RouterOS API client this project's `internal/rosapi` is vendored from (MIT), pruned to the synchronous subset this bouncer uses
- [funkolab/cs-mikrotik-bouncer](https://github.com/funkolab/cs-mikrotik-bouncer) — original Go bouncer (archived)
- [nvtkaszpir/cs-mikrotik-bouncer-alt](https://github.com/nvtkaszpir/cs-mikrotik-bouncer-alt) — alternative Go bouncer
