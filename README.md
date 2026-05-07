# cs-routeros-bouncer

[![CI](https://github.com/jmrplens/cs-routeros-bouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/jmrplens/cs-routeros-bouncer/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/jmrplens/cs-routeros-bouncer)](https://goreportcard.com/report/github.com/jmrplens/cs-routeros-bouncer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/jmrplens/cs-routeros-bouncer)](https://go.dev/)

A [CrowdSec](https://www.crowdsec.net/) remediation component (bouncer) for [MikroTik RouterOS](https://mikrotik.com/software) that automatically manages firewall rules and address lists via the RouterOS API.

## Highlights

- **Zero manual router configuration** — auto-creates and auto-removes firewall filter/raw rules on start/stop
- **Individual IP management** — adds on ban, removes on unban (no bulk re-upload, no duplicates)
- **State reconciliation** — on start/restart and periodically, syncs CrowdSec decisions with MikroTik state (adds missing, removes stale)
- **High-performance sync** — connection pool, script-based bulk add, in-memory cache (~28,700 IPs in ~58 s wall-clock on RB5009 with CAPI)
- **Graceful shutdown** — removes firewall rules on stop (address list entries expire via MikroTik timeout)
- **IPv4 + IPv6** — independently toggleable
- **Input + Output blocking** — output blocking optional with configurable interface/interface-list
- **Decision filtering** — sync only local decisions or include CrowdSec community blocklists (CAPI)
- **Observable** — Prometheus metrics (`/metrics`), structured logging, health endpoint (`/health`), LAPI usage metrics (active decisions, dropped traffic)
- **Multiple deployment options** — Docker, systemd, or standalone binary

## Why Another Bouncer?

Existing MikroTik bouncers have significant limitations that this project addresses:

| Feature | funkolab (archived) | nvtkaszpir-alt | **cs-routeros-bouncer** |
|---------|:---:|:---:|:---:|
| Auto-create firewall rules | ❌ | ❌ | ✅ |
| Individual IP add/remove | ✅ | ❌ (bulk re-upload) | ✅ |
| No duplicate IPs | ✅ | ❌ | ✅ |
| State reconciliation on restart | ❌ | ❌ | ✅ |
| Remove rules on shutdown | ❌ | ❌ | ✅ |
| IPv6 support | ✅ | ✅ | ✅ |
| Output blocking | ❌ | ✅ | ✅ |
| Origin filtering (local-only mode) | ❌ | ❌ | ✅ |
| Prometheus metrics | ❌ | ✅ | ✅ |
| LAPI usage metrics (dropped traffic) | ❌ | ❌ | ✅ |
| Health endpoint | ❌ | ❌ | ✅ |
| Go (compiled, low resource usage) | ✅ | ✅ | ✅ |

## Requirements

- **CrowdSec** 1.5+ with LAPI accessible from the bouncer host
- **MikroTik RouterOS** 7.x with API enabled (port 8728 or 8729 for TLS)
- A dedicated RouterOS API user (see [Router Setup](#1-register-the-bouncer-with-crowdsec))

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
      - "2112:2112"  # Prometheus metrics (optional)
    environment:
      CROWDSEC_URL: "http://crowdsec:8080/"
      CROWDSEC_BOUNCER_API_KEY: "your-bouncer-api-key"
      MIKROTIK_HOST: "192.168.0.1:8728"
      MIKROTIK_USER: "crowdsec"
      MIKROTIK_PASS: "your-password"
    # Or mount a config file:
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
# Download (replace with your architecture: amd64, arm64, armv7)
wget https://github.com/jmrplens/cs-routeros-bouncer/releases/latest/download/cs-routeros-bouncer_linux_amd64.tar.gz
tar xzf cs-routeros-bouncer_linux_amd64.tar.gz

# Automated install: copies binary, creates config, installs and starts systemd service
sudo ./cs-routeros-bouncer setup

# Edit configuration with your CrowdSec API key and MikroTik credentials
sudo nano /etc/cs-routeros-bouncer/cs-routeros-bouncer.yaml

# Restart after editing config
sudo systemctl restart cs-routeros-bouncer
```

The `setup` subcommand accepts optional flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-bin` | `/usr/local/bin/cs-routeros-bouncer` | Installation path for the binary |
| `-config-dir` | `/etc/cs-routeros-bouncer` | Directory for configuration files |

To uninstall:

```bash
sudo cs-routeros-bouncer uninstall        # Keeps config files
sudo cs-routeros-bouncer uninstall -purge  # Also removes config
```

<details>
<summary><strong>Manual setup</strong></summary>

```bash
# Download
wget https://github.com/jmrplens/cs-routeros-bouncer/releases/latest/download/cs-routeros-bouncer_linux_amd64.tar.gz
tar xzf cs-routeros-bouncer_linux_amd64.tar.gz

# Install
sudo install -m 755 cs-routeros-bouncer /usr/local/bin/
sudo mkdir -p /etc/cs-routeros-bouncer
sudo cp cs-routeros-bouncer.yaml /etc/cs-routeros-bouncer/cs-routeros-bouncer.yaml

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

All options can be set via YAML config file or environment variables. Environment variables override config file values.

See [`config/cs-routeros-bouncer.yaml`](config/cs-routeros-bouncer.yaml) for the full annotated reference.

### Basic parameters

The essential settings to get the bouncer running. Most deployments only need these.

| Config Key | Env Variable | Default | Description |
|---|---|---|---|
| `crowdsec.api_url` | `CROWDSEC_URL` | `http://localhost:8080/` | CrowdSec LAPI URL |
| `crowdsec.api_key` | `CROWDSEC_BOUNCER_API_KEY` | *(required)* | Bouncer API key |
| `mikrotik.address` | `MIKROTIK_HOST` | `192.168.0.1:8728` | RouterOS API address (`host:port`) |
| `mikrotik.username` | `MIKROTIK_USER` | `crowdsec` | API username |
| `mikrotik.password` | `MIKROTIK_PASS` | *(required)* | API password |
| `firewall.ipv4.enabled` | `FIREWALL_IPV4_ENABLED` | `true` | Enable IPv4 blocking |
| `firewall.ipv6.enabled` | `FIREWALL_IPV6_ENABLED` | `true` | Enable IPv6 blocking |
| `firewall.filter.enabled` | `FIREWALL_FILTER_ENABLED` | `true` | Create filter firewall rules |
| `firewall.raw.enabled` | `FIREWALL_RAW_ENABLED` | `true` | Create raw/prerouting rules |
| `firewall.deny_action` | `FIREWALL_DENY_ACTION` | `drop` | Action: `drop` or `reject` |
| `logging.level` | `LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |

### Advanced parameters

Fine-tuning options for decision filtering, TLS, performance, firewall customization, and observability. The defaults work well for most setups.

<details>
<summary><b>CrowdSec — polling, filtering & TLS</b></summary>

| Config Key | Env Variable | Default | Description |
|---|---|---|---|
| `crowdsec.update_frequency` | `CROWDSEC_UPDATE_FREQUENCY` | `10s` | Poll interval for decision updates |
| `crowdsec.reconciliation_interval` | `CROWDSEC_RECONCILIATION_INTERVAL` | `15m` | Periodic address-list reconciliation interval (`0` to disable; minimum `1m` when enabled) |
| `crowdsec.lapi_metrics_interval` | `CROWDSEC_LAPI_METRICS_INTERVAL` | `15m` | LAPI usage metrics interval: active decisions, dropped traffic (`0` = disabled) |
| `crowdsec.origins` | `CROWDSEC_ORIGINS` | `[]` (all) | Filter by origin (`["crowdsec","cscli"]` = local only) |
| `crowdsec.scopes` | `CROWDSEC_SCOPES` | `["ip","range"]` | Decision scopes to process |
| `crowdsec.supported_decisions_types` | `CROWDSEC_DECISIONS_TYPES` | `["ban"]` | Decision types to process (only `ban` is implemented — see [details](docs/configuration/crowdsec.md#crowdsecsupported_decisions_types)) |
| `crowdsec.scenarios_containing` | `CROWDSEC_SCENARIOS_CONTAINING` | `[]` | Only process decisions matching these scenarios |
| `crowdsec.scenarios_not_containing` | `CROWDSEC_SCENARIOS_NOT_CONTAINING` | `[]` | Exclude decisions matching these scenarios |
| `crowdsec.retry_initial_connect` | `CROWDSEC_RETRY_INITIAL_CONNECT` | `true` | Retry LAPI connection on startup failure |
| `crowdsec.insecure_skip_verify` | `CROWDSEC_INSECURE_SKIP_VERIFY` | `false` | Skip TLS certificate verification for LAPI |
| `crowdsec.cert_path` | `CROWDSEC_CERT_PATH` | | TLS client certificate path |
| `crowdsec.key_path` | `CROWDSEC_KEY_PATH` | | TLS client key path |
| `crowdsec.ca_cert_path` | `CROWDSEC_CA_CERT_PATH` | | TLS CA certificate path |

</details>

<details>
<summary><b>MikroTik — TLS & performance</b></summary>

| Config Key | Env Variable | Default | Description |
|---|---|---|---|
| `mikrotik.tls` | `MIKROTIK_TLS` | `false` | Use TLS (port 8729) |
| `mikrotik.tls_insecure` | `MIKROTIK_TLS_INSECURE` | `false` | Skip TLS certificate verification for RouterOS |
| `mikrotik.connection_timeout` | `MIKROTIK_CONN_TIMEOUT` | `10s` | Connection timeout |
| `mikrotik.command_timeout` | `MIKROTIK_CMD_TIMEOUT` | `30s` | Command execution timeout |
| `mikrotik.pool_size` | `MIKROTIK_POOL_SIZE` | `4` | Number of parallel API connections for bulk operations (1–20) |

> **Auto-capping:** On startup the bouncer queries the router's `max-sessions` for the API service and automatically reduces `pool_size` if it would exceed the router limit. To check or change the limit on your router:
>
> ```routeros
> # Check current max-sessions for the API service
> /ip/service/print where name=api
>
> # Increase the limit (default is 20, maximum 1000)
> /ip/service/set api max-sessions=1000
> ```

</details>

<details>
<summary><b>Firewall — rules, interfaces & logging</b></summary>

| Config Key | Env Variable | Default | Description |
|---|---|---|---|
| `firewall.ipv4.address_list` | `FIREWALL_IPV4_ADDRESS_LIST` | `crowdsec-banned` | IPv4 address list name in MikroTik |
| `firewall.ipv6.address_list` | `FIREWALL_IPV6_ADDRESS_LIST` | `crowdsec6-banned` | IPv6 address list name in MikroTik |
| `firewall.filter.chains` | `FIREWALL_FILTER_CHAINS` | `["input"]` | Chains for filter rules |
| `firewall.raw.chains` | `FIREWALL_RAW_CHAINS` | `["prerouting"]` | Chains for raw rules |
| `firewall.rule_placement` | `FIREWALL_RULE_PLACEMENT` | `top` | Placement: `top` or `bottom` |
| `firewall.comment_prefix` | `FIREWALL_COMMENT_PREFIX` | `crowdsec-bouncer` | Comment prefix for managed resources |
| `firewall.log` | `FIREWALL_LOG` | `false` | Enable RouterOS logging on firewall rules |
| `firewall.log_prefix` | `FIREWALL_LOG_PREFIX` | `crowdsec-bouncer` | Global prefix for RouterOS log entries |
| `firewall.reject_with` | `FIREWALL_REJECT_WITH` | | Reject type when `deny_action=reject` (e.g. `tcp-reset`, `icmp-admin-prohibited`) |
| `firewall.filter.log_prefix` | `FIREWALL_FILTER_LOG_PREFIX` | | Override global log prefix for filter rules |
| `firewall.filter.connection_state` | `FIREWALL_FILTER_CONNECTION_STATE` | | Connection-state matcher for filter rules (e.g. `new`, `new,invalid`) |
| `firewall.raw.log_prefix` | `FIREWALL_RAW_LOG_PREFIX` | | Override global log prefix for raw rules |
| `firewall.block_input.interface` | `FIREWALL_INPUT_INTERFACE` | | Restrict input/raw rules to this interface (empty = all) |
| `firewall.block_input.interface_list` | `FIREWALL_INPUT_INTERFACE_LIST` | | Restrict input/raw rules to this interface list (empty = all) |
| `firewall.block_input.whitelist` | `FIREWALL_INPUT_WHITELIST` | | Address-list name for input whitelist (accept rule before drop) |
| `firewall.block_output.enabled` | `FIREWALL_BLOCK_OUTPUT` | `false` | Block outbound traffic to banned IPs |
| `firewall.block_output.interface` | `FIREWALL_OUTPUT_INTERFACE` | | WAN interface for output rules |
| `firewall.block_output.interface_list` | `FIREWALL_OUTPUT_INTERFACE_LIST` | | WAN interface list for output rules |
| `firewall.block_output.log_prefix` | `FIREWALL_OUTPUT_LOG_PREFIX` | | Override global log prefix for output rules |
| `firewall.block_output.passthrough_v4` | `FIREWALL_OUTPUT_PASSTHROUGH_V4` | | IPv4 client IP to bypass output blocking (`src-address=!IP`) |
| `firewall.block_output.passthrough_v4_list` | `FIREWALL_OUTPUT_PASSTHROUGH_V4_LIST` | | IPv4 address-list to bypass output blocking (precedence over IP) |
| `firewall.block_output.passthrough_v6` | `FIREWALL_OUTPUT_PASSTHROUGH_V6` | | IPv6 client IP to bypass output blocking |
| `firewall.block_output.passthrough_v6_list` | `FIREWALL_OUTPUT_PASSTHROUGH_V6_LIST` | | IPv6 address-list to bypass output blocking (precedence over IP) |

</details>

<details>
<summary><b>Logging & Metrics — format, file output & Prometheus</b></summary>

| Config Key | Env Variable | Default | Description |
|---|---|---|---|
| `logging.format` | `LOG_FORMAT` | `text` | Log format: `text` or `json` |
| `logging.file` | `LOG_FILE` | | Log to file (empty = stdout only) |
| `metrics.enabled` | `METRICS_ENABLED` | `false` | Enable Prometheus `/metrics` endpoint |
| `metrics.listen_addr` | `METRICS_ADDR` | `0.0.0.0` | Metrics server listen address |
| `metrics.listen_port` | `METRICS_PORT` | `2112` | Metrics server listen port |
| `metrics.routeros_poll_interval` | `METRICS_ROUTEROS_POLL_INTERVAL` | `30s` | RouterOS system metrics poll interval (0 to disable) |
| `metrics.track_processed` | `METRICS_TRACK_PROCESSED` | `true` | Track processed (non-blocked) traffic via passthrough counting rules |

</details>

### Configuration Examples

<details>
<summary><b>Minimal — IPv4 only, filter rules</b></summary>

```yaml
crowdsec:
  api_url: "http://localhost:8080/"
  api_key: "your-key"
mikrotik:
  address: "192.168.0.1:8728"
  username: "crowdsec"
  password: "your-password"
firewall:
  ipv6:
    enabled: false
  raw:
    enabled: false
```

</details>

<details>
<summary><b>Full protection — IPv4 + IPv6, filter + raw, input + output</b></summary>

```yaml
crowdsec:
  api_url: "http://localhost:8080/"
  api_key: "your-key"
mikrotik:
  address: "192.168.0.1:8729"
  username: "crowdsec"
  password: "your-password"
  tls: true
firewall:
  ipv4:
    enabled: true
  ipv6:
    enabled: true
  filter:
    enabled: true
    chains: ["input"]
  raw:
    enabled: true
    chains: ["prerouting"]
  deny_action: "drop"
  rule_placement: "top"
  block_input:
    interface_list: "WAN"
  block_output:
    enabled: true
    interface_list: "WAN"
metrics:
  enabled: true
  listen_port: 2112
logging:
  level: "info"
```

</details>

<details>
<summary><b>Local decisions only — no community blocklists</b></summary>

```yaml
crowdsec:
  api_url: "http://localhost:8080/"
  api_key: "your-key"
  origins: ["crowdsec", "cscli"]
mikrotik:
  address: "192.168.0.1:8728"
  username: "crowdsec"
  password: "your-password"
```

</details>

---

## How It Works

### Startup

1. Connects to CrowdSec LAPI and MikroTik RouterOS API (connection pool with 4 connections)
2. Creates firewall rules (filter and/or raw) that reference named address lists
3. Collects all current CrowdSec decisions (bans and deletes are collected simultaneously to avoid stale data)
4. **Reconciles** with MikroTik address lists — adds missing IPs using script-based bulk add (chunks of 100), removes stale ones in parallel
5. Populates in-memory address cache for O(1) lookups during runtime

### Runtime

- **Ban**: Checks the in-memory cache first. New addresses are added to the MikroTik address list with the CrowdSec ban duration as timeout (~1–3 ms); cached duplicate ban events skip the RouterOS API entirely.
- **Unban**: Checks in-memory cache first — if IP not present, skips API call entirely; otherwise finds and removes the IP immediately
- **Periodic reconciliation**: Every `crowdsec.reconciliation_interval` (default `15m`), fetches active CrowdSec decisions and repairs address-list drift. Set it to `0` to disable; values below `1m` are rejected.
- Uses an optimistic-add pattern for cache misses (~1–3 ms per IP vs ~400 ms with lookup-first)

### Shutdown (SIGTERM / SIGINT)

- Removes all bouncer-managed firewall rules from MikroTik
- Address list entries remain and expire naturally via their MikroTik timeout

### Firewall Rules

The bouncer creates rules with descriptive comments for identification:

```text
;;; crowdsec-bouncer:filter-input-input-v4 @cs-routeros-bouncer
chain=input action=drop src-address-list=crowdsec-banned

;;; crowdsec-bouncer:raw-prerouting-input-v4 @cs-routeros-bouncer
chain=prerouting action=drop src-address-list=crowdsec-banned
```

Rules are placed at the **top** of the chain by default (`rule_placement: top`) to ensure they are evaluated first. If dynamic/built-in rules occupy the top positions (e.g., RouterOS fasttrack counters), the bouncer iterates through subsequent positions until it finds one where the rule can be placed.

### Performance

Tested on a **MikroTik RB5009UG+S+** (ARM64, 4 cores @ 1400 MHz, 1 GB RAM, RouterOS 7.22.1) with the bouncer running on a separate Linux host connected via the RouterOS API (plaintext, port 8728). The CAPI measurements below used `mikrotik.pool_size: 10` and `crowdsec.reconciliation_interval: 1m`.

Router CPU can spike during reconciliation, especially at startup or whenever real drift requires add/remove work. Sustained high RouterOS CPU after reconciliation is not expected from simply keeping entries in memory; it usually points to repeated RouterOS API writes/reconnects, duplicate-decision churn, or unrelated router workload.

The bouncer uses a configurable **connection pool** (default 4 parallel API connections), **script-based bulk add** (chunks of 100 entries), and an **in-memory address cache** for O(1) lookups during unban operations.

#### Initial reconciliation (cold start, empty router)

| Scenario | IPs synced | Time | Throughput | Router CPU peak |
|----------|-----------|------|------------|-----------------|
| Local + CAPI community | **28,686** (28,269 IPv4 + 417 IPv6) | **~58 s** test wall-clock; **~36 s** RouterOS bulk work | ~500 IPs/s wall-clock; ~790 IPs/s bulk add | 39% observed |

#### Restart with existing entries on router

| Scenario | Existing IPs | Time | Notes |
|----------|-------------|------|-------|
| Restart, all IPs already present | **~28,700** | **~75–77 s** functional wall-clock | Includes service restart, rule cleanup, list scan, and reconciliation wait |
| Periodic reconciliation, no drift | **~28,700** | **~3–4 s** internal reconciliation | Performs list/read/diff only, no add/remove writes |

#### Mass removal (switching from CAPI to local-only)

| Removed | Remaining | Time | Throughput | Router CPU peak |
|---------|-----------|------|------------|-----------------|
| **26,810** (26,396 IPv4 + 414 IPv6) | 1,873 IPv4 + 3 IPv6 | **~77 s** RouterOS removal work | ~348 removes/s | ~30–39% observed during large churn |

#### Live operation (individual ban/unban)

| Operation | Typical latency | Notes |
|-----------|----------------|-------|
| Ban (add IP) | **~1–3 ms** | Optimistic-add, no lookup needed |
| Ban (cached duplicate IP) | **< 1 ms** | Address already known in cache → skip RouterOS API call entirely |
| Ban (router duplicate after cache miss) | **~5–8 ms** | Detects "already have" → finds and updates existing entry without reconnecting |
| Unban (remove IP) | **~7 s** end-to-end | Includes LAPI polling interval (15 s max). API call itself ~2 ms |
| Unban cache fast-path | **< 1 ms** | IP not in cache → skip API call entirely |

#### Resource usage

| Metric | Value |
|--------|-------|
| Firewall rules created | 4 rules in ~2 s |
| Bouncer memory (steady state) | ~30 MB |
| Bouncer CPU (steady state) | < 1% |
| Router CPU (steady state, after reconciliation) | typically 0–2% observed; traffic and firewall config dependent |

> **Note:** All benchmarks measured on a real RB5009UG+S+ with production traffic. Router CPU includes
> SNMP monitoring (10 s interval), normal network forwarding, and any active firewall workload. Individual
> add/remove operations are typically **1–3 ms per IP** (median). Occasional latency spikes (p95 up to
> ~50 ms) are caused by RouterOS internal scheduling on large address lists.

---

### Duplicate IP handling

When CrowdSec sends a ban decision for an IP that is already known to be present on the router, the bouncer returns from the in-memory cache fast-path and does not write to RouterOS again. This avoids RouterOS management/API churn during repeated stream updates.

If the local cache is cold or out of sync and RouterOS replies with `already have such entry`, the bouncer treats that as a RouterOS device error, not a connection failure. It keeps the API connection open, finds the existing address-list entry, and updates its timeout/comment without creating a duplicate.

The address list only ever contains one entry per IP. Cached duplicate decisions do not refresh the RouterOS timeout during the same run; startup and periodic reconciliation restore membership by adding missing entries and removing stale ones.

---

## Monitoring

### Health Endpoint

```bash
curl http://localhost:2112/health
# {"status":"ok","routeros_connected":true,"version":"vX.Y.Z"}
```

### Prometheus Metrics

Enable with `metrics.enabled: true`. Available at `http://localhost:2112/metrics`.

| Metric | Type | Description |
|--------|------|-------------|
| `crowdsec_bouncer_info` | Gauge | Build info (version, RouterOS identity) |
| `crowdsec_bouncer_start_time_seconds` | Gauge | Unix timestamp of bouncer startup |
| `crowdsec_bouncer_active_decisions` | Gauge | Active decisions by protocol (`ipv4`/`ipv6`) |
| `crowdsec_bouncer_active_decisions_by_origin` | Gauge | Active decisions by CrowdSec origin (`crowdsec`/`cscli`/`CAPI`) |
| `crowdsec_bouncer_decisions_total` | Counter | Total decisions processed (action, protocol, origin) |
| `crowdsec_bouncer_errors_total` | Counter | Total errors by type (`api`/`routeros`/`reconcile`) |
| `crowdsec_bouncer_operation_duration_seconds` | Histogram | Operation latency (`add`/`remove`/`reconcile`) |
| `crowdsec_bouncer_routeros_connected` | Gauge | RouterOS connection status (1/0) |
| `crowdsec_bouncer_routeros_cpu_load` | Gauge | RouterOS CPU load percentage (0–100) |
| `crowdsec_bouncer_routeros_memory_used_bytes` | Gauge | RouterOS used memory in bytes |
| `crowdsec_bouncer_routeros_memory_total_bytes` | Gauge | RouterOS total memory in bytes |
| `crowdsec_bouncer_routeros_cpu_temperature_celsius` | Gauge | RouterOS CPU temperature (°C) |
| `crowdsec_bouncer_reconciliation_total` | Counter | Total reconciliation actions (`added`/`removed`) |
| `crowdsec_bouncer_dropped_bytes_total` | Gauge | Cumulative bytes dropped by firewall rules |
| `crowdsec_bouncer_dropped_packets_total` | Gauge | Cumulative packets dropped by firewall rules |
| `crowdsec_bouncer_dropped_bytes_by_proto` | Gauge | Dropped bytes by protocol (`ipv4`/`ipv6`) |
| `crowdsec_bouncer_dropped_packets_by_proto` | Gauge | Dropped packets by protocol |
| `crowdsec_bouncer_processed_bytes_total` | Gauge | Cumulative bytes processed (evaluated) by firewall rules |
| `crowdsec_bouncer_processed_packets_total` | Gauge | Cumulative packets processed by firewall rules |
| `crowdsec_bouncer_processed_bytes_by_proto` | Gauge | Processed bytes by protocol (`ipv4`/`ipv6`) |
| `crowdsec_bouncer_processed_packets_by_proto` | Gauge | Processed packets by protocol |

> **Note:** `dropped_bytes_total` and `dropped_packets_total` use the `_total` suffix despite being Gauges. This is because they reflect cumulative counters read from RouterOS — the bouncer sets (not increments) the value each cycle, making Gauge the correct instrument type. The `_total` suffix is retained for semantic clarity.

### CrowdSec LAPI Metrics

The bouncer reports usage metrics directly to the CrowdSec LAPI (default: every 15 min). These metrics appear in the CrowdSec Console and include:

- **Active decisions** — per-origin (`crowdsec`, `cscli`, `CAPI`) and per-IP-type (`ipv4`, `ipv6`)
- **Dropped traffic** — bytes and packets blocked by MikroTik firewall rules (delta between pushes), per IP type
- **Processed traffic** — bytes and packets evaluated by all bouncer chains (delta between pushes), per IP type
- **Bouncer metadata** — type (`cs-routeros-bouncer`), version, OS info, startup timestamp

Configure with `crowdsec.lapi_metrics_interval` (set to `0` to disable).

### Grafana Dashboard

A ready-to-use Grafana dashboard is included at [`grafana/dashboard.json`](grafana/dashboard.json).

**Import steps:**

1. In Grafana, go to **Dashboards → Import**
2. Upload `grafana/dashboard.json` or paste its contents
3. Select your Prometheus datasource
4. Click **Import**

The dashboard provides real-time visibility into the bouncer's operation:

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/grafana-dashboard-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="docs/images/grafana-dashboard-light.png">
    <img alt="Grafana Dashboard" src="docs/images/grafana-dashboard-dark.png" width="100%">
  </picture>
</p>

**Dashboard panels (27 panels in 8 rows):**

| Row | Panels |
|-----|--------|
| **Overview** | RouterOS Connected, Active Decisions (IPv4/IPv6/Total), Uptime, Bouncer Info |
| **Active Decisions** | Active Decisions Over Time, IPv4/IPv6 Ratio |
| **Decision Processing** | Decisions Processed (Rate), Cumulative Decisions |
| **Performance & Operations** | Operation Latency (p50/p95/p99), Operation Rate |
| **Errors & Reconciliation** | Error Rate, Total Errors, RouterOS Connection, Last Reconciliation, Reconciliation Duration |
| **Dropped Traffic** | Dropped Bytes, Dropped Packets, Dropped Traffic Rate, Dropped Traffic (Cumulative) |
| **Processed Traffic** | Processed Traffic Rate (Bytes/s, Packets/s), Drop Rate % |
| **Decisions by Origin** | Active Decisions by Origin, Decisions by Origin (Rate), Cumulative Decisions by Origin |
| **Process Resources** | Memory Usage, CPU Usage, Goroutines & File Descriptors |

---

## Troubleshooting

<details>
<summary><b>Cannot connect to RouterOS API</b></summary>

- Verify the API service is enabled: `/ip/service/print` — `api` should be enabled on your router
- Check the router firewall doesn't block port 8728/8729 from the bouncer host
- Verify username/password and that the user has `api` policy
- For TLS: ensure `mikrotik.tls: true` and the correct port (8729)

</details>

<details>
<summary><b>Firewall rules not at the top of the chain</b></summary>

- RouterOS dynamic/built-in rules (e.g., fasttrack counters) cannot be moved — the bouncer iterates through positions until it finds one where the rule can be placed
- Verify with: `/ip/firewall/filter/print` on the router
- Ensure `firewall.rule_placement: "top"` is set in your config

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

---

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

```bash
make build          # Build binary
make test           # Run tests
make lint           # Run linter
make docker-build   # Build Docker image
```

### Functional Tests (Real Hardware)

A comprehensive Bash test suite validates the compiled binary against a
real MikroTik router. Tests use SSH, `cscli`, `systemctl`, and SNMP —
no Go internals are imported.

```bash
# Setup: copy and fill in your environment
cp tests/functional/.env.example tests/functional/.env
# Edit .env with your MikroTik SSH credentials, CrowdSec API key, etc.

# Run all groups (except CAPI stress test)
tests/functional/run_tests.sh

# Run specific groups
tests/functional/run_tests.sh t1 t2

# Include CAPI stress test (~28k IPs — takes several minutes)
tests/functional/run_tests.sh --capi

# List available groups
tests/functional/run_tests.sh --list
```

| Group | Tests | Description |
|-------|-------|-------------|
| `t1`  | 7     | Data integrity — IP completeness, format, comments |
| `t2`  | 6     | Cache consistency — live ban/unban, expiry, fast-path |
| `t3`  | 6     | Bulk operations — reconciliation, partial sync, orphans |
| `t4`  | 3     | Connection pool — establishment, shutdown |
| `t5`  | 6     | Edge cases — duplicates, rapid cycle, restart idempotency |
| `t6`  | 3     | CPU monitoring — steady-state, peak, recovery |
| `t7`  | 5     | Timing — reconciliation time, ban/unban latency |
| `t8`  | 8     | CAPI stress ~28k IPs (requires `--capi`) |
| `t9`  | 12    | Advanced firewall config — reject-with, connection-state, log-prefix, whitelist, passthrough |

## Security

See [SECURITY.md](SECURITY.md) for the security policy and responsible disclosure process.

## License

[MIT](LICENSE)

## Acknowledgments

- [CrowdSec](https://www.crowdsec.net/) — open-source collaborative security engine
- [go-routeros](https://github.com/go-routeros/routeros) — Go library for the RouterOS API
- [funkolab/cs-mikrotik-bouncer](https://github.com/funkolab/cs-mikrotik-bouncer) — original Go bouncer (archived)
- [nvtkaszpir/cs-mikrotik-bouncer-alt](https://github.com/nvtkaszpir/cs-mikrotik-bouncer-alt) — alternative Go bouncer
