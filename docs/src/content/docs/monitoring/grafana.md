---
title: Grafana Dashboard
description: Pre-built Grafana dashboard for monitoring the bouncer.
---

A pre-built Grafana dashboard is included for monitoring the bouncer and router health.

## Screenshots

**Dark theme:**

![Grafana dashboard dark theme](/images/grafana-dashboard-dark.png)

**Light theme:**

![Grafana dashboard light theme](/images/grafana-dashboard-light.png)

## Installation

1. Open Grafana → **Dashboards** → **New** → **Import**
2. Upload `grafana/cs-routeros-bouncer.json` from the repository
3. Select your Prometheus data source

## Requirements

- Prometheus data source configured in Grafana
- Bouncer running with `metrics.enabled: true`
- Prometheus scraping the bouncer's `/metrics` endpoint

## Dashboard panels

The dashboard includes:

| Panel | Description |
|-------|-------------|
| Active Decisions | Gauge showing total active bans |
| Active Decisions by Origin | Breakdown by origin (crowdsec, cscli, CAPI, lists) |
| Active Decisions by Scope | Breakdown by scope (IP, Range) |
| Decisions Processed | Time series of ban/unban operations over time |
| LAPI / RouterOS API Calls | API call rates and error rates |
| Stream Events | LAPI polling events and errors |
| LAPI Latency | Polling latency gauge |
| Reconciliation | Duration and success/failure counts |
| Router CPU | Per-core CPU load |
| Router Memory | Memory usage percentage |
| Router Temperature | System temperature |
| Configuration | Current bouncer configuration parameters |

:::tip
Use the time range selector to zoom into specific events. The "Decisions Processed" panel is useful for correlating ban spikes with specific incidents.
:::
