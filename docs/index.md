---
hide:
  - toc
---

# cs-routeros-bouncer

<div class="grid cards" markdown>

-   :material-shield-check:{ .lg .middle } **Zero Manual Configuration**

    ---

    Auto-creates and auto-removes firewall filter/raw rules on start/stop — no manual router setup needed.

-   :material-ip:{ .lg .middle } **Individual IP Management**

    ---

    Adds IPs on ban, removes on unban. No bulk re-upload, no duplicates. ~1ms per operation.

-   :material-sync:{ .lg .middle } **State Reconciliation**

    ---

    On start or restart, syncs CrowdSec decisions with MikroTik state — adds missing, removes stale entries.

-   :material-chart-line:{ .lg .middle } **Observable**

    ---

    Prometheus metrics, structured logging, health endpoint, and a ready-to-use Grafana dashboard.

</div>

## What is cs-routeros-bouncer?

A [CrowdSec](https://www.crowdsec.net/) remediation component (bouncer) for [MikroTik RouterOS](https://mikrotik.com/software) that automatically manages firewall rules and address lists via the RouterOS API.

It bridges CrowdSec's threat intelligence with MikroTik's firewall, automatically blocking malicious IPs detected by CrowdSec on your MikroTik router.

## Key Features

- **Zero manual router configuration** — auto-creates and auto-removes firewall filter/raw rules on start/stop
- **Individual IP management** — adds on ban, removes on unban (no bulk re-upload, no duplicates)
- **State reconciliation** — on start/restart, syncs CrowdSec decisions with MikroTik state
- **Graceful shutdown** — removes firewall rules on stop (address list entries expire via timeout)
- **IPv4 + IPv6** — independently toggleable
- **Input + Output blocking** — output blocking optional with configurable interface/interface-list
- **Decision filtering** — sync only local decisions or include CrowdSec community blocklists
- **Observable** — Prometheus metrics (`/metrics`), structured logging, health endpoint (`/health`)
- **Multiple deployment options** — Docker, systemd, or standalone binary

## Why Another Bouncer?

Existing MikroTik bouncers have significant limitations:

| Feature | funkolab (archived) | nvtkaszpir-alt | **cs-routeros-bouncer** |
|---------|:---:|:---:|:---:|
| Auto-create firewall rules | :material-close: | :material-close: | :material-check: |
| Individual IP add/remove | :material-check: | :material-close: | :material-check: |
| No duplicate IPs | :material-check: | :material-close: | :material-check: |
| State reconciliation on restart | :material-close: | :material-close: | :material-check: |
| Remove rules on shutdown | :material-close: | :material-close: | :material-check: |
| IPv6 support | :material-check: | :material-check: | :material-check: |
| Output blocking | :material-close: | :material-check: | :material-check: |
| Origin filtering (local-only mode) | :material-close: | :material-close: | :material-check: |
| Prometheus metrics | :material-close: | :material-check: | :material-check: |
| Health endpoint | :material-close: | :material-close: | :material-check: |
| Go (compiled, low resource) | :material-close: | :material-close: | :material-check: |

## Requirements

- **CrowdSec** 1.5+ with LAPI accessible from the bouncer host
- **MikroTik RouterOS** 7.x with API enabled (port 8728 or 8729 for TLS)
- A dedicated RouterOS API user with appropriate permissions

## Quick Links

<div class="grid cards" markdown>

-   [:material-rocket-launch: **Quick Start**](getting-started/quickstart.md)

    Get up and running in 5 minutes

-   [:material-cog: **Configuration**](configuration/index.md)

    All configuration options explained

-   [:material-chart-areaspline: **Monitoring**](monitoring/prometheus.md)

    Prometheus metrics & Grafana dashboard

-   [:material-hammer-wrench: **Troubleshooting**](troubleshooting.md)

    Common issues and solutions

</div>
