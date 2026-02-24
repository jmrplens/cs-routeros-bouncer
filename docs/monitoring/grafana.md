# Grafana Dashboard

A ready-to-use Grafana dashboard is included for monitoring the bouncer.

## Preview

<figure markdown>
  ![Grafana Dashboard Dark](../images/grafana-dashboard-dark.png){ width="100%" }
  <figcaption>Dashboard in dark theme</figcaption>
</figure>

<figure markdown>
  ![Grafana Dashboard Light](../images/grafana-dashboard-light.png){ width="100%" }
  <figcaption>Dashboard in light theme</figcaption>
</figure>

## Import

The dashboard JSON is located at [`grafana/dashboard.json`](https://github.com/jmrplens/cs-routeros-bouncer/blob/main/grafana/dashboard.json).

### Steps

1. In Grafana, go to **Dashboards → Import**
2. Upload `grafana/dashboard.json` or paste its contents
3. Select your Prometheus datasource when prompted
4. Click **Import**

!!! tip "Datasource variable"
    The dashboard uses `${DS_PROMETHEUS}` as a datasource placeholder. During import, Grafana will ask you to map it to your Prometheus datasource.

## Panels

The dashboard contains **27 panels** organized in **8 rows**:

### Overview (top row)

| Panel | Type | Description |
|-------|------|-------------|
| **RouterOS Connected** | stat | Connection status indicator |
| **Active Decisions (IPv4)** | stat | Current IPv4 banned IPs |
| **Active Decisions (IPv6)** | stat | Current IPv6 banned IPs |
| **Total Active Decisions** | stat | Combined IPv4 + IPv6 count |
| **Uptime** | stat | Time since bouncer started |
| **Bouncer Info** | stat | Version and RouterOS identity |

### Active Decisions

| Panel | Type | Description |
|-------|------|-------------|
| **Active Decisions Over Time** | timeseries | IPv4/IPv6 decisions over time |
| **IPv4 / IPv6 Ratio** | piechart | Proportion of IPv4 vs IPv6 bans |

### Decision Processing

| Panel | Type | Description |
|-------|------|-------------|
| **Decisions Processed (Rate)** | timeseries | Ban/unban rate per second |
| **Cumulative Decisions** | timeseries | Total decisions since startup |

### Performance & Operations

| Panel | Type | Description |
|-------|------|-------------|
| **Operation Latency (p50/p95/p99)** | timeseries | Add/remove/reconcile latency percentiles |
| **Operation Rate** | timeseries | Operations per second |

### Errors & Reconciliation

| Panel | Type | Description |
|-------|------|-------------|
| **Error Rate** | timeseries | Errors per second by category |
| **Total Errors** | stat | Cumulative error count |
| **RouterOS Connection** | state-timeline | Connection status history |
| **Last Reconciliation** | stat | Time since last reconciliation |
| **Reconciliation Duration** | stat | Duration of last reconciliation |

### Dropped Traffic

| Panel | Type | Description |
|-------|------|-------------|
| **Dropped Bytes** | stat | Total bytes dropped by bouncer rules |
| **Dropped Packets** | stat | Total packets dropped by bouncer rules |
| **Dropped Traffic Rate** | timeseries | Bytes/packets dropped per second |
| **Dropped Traffic (Cumulative)** | timeseries | Running total of dropped traffic |

### Decisions by Origin

| Panel | Type | Description |
|-------|------|-------------|
| **Active Decisions by Origin** | bargauge | Per-origin decision count (crowdsec, cscli, CAPI) |
| **Decisions by Origin (Rate)** | timeseries | Decision rate per origin |
| **Cumulative Decisions by Origin** | timeseries | Running total per origin |

### Process Resources

| Panel | Type | Description |
|-------|------|-------------|
| **Memory Usage** | timeseries | Bouncer process memory consumption |
| **CPU Usage** | timeseries | Bouncer process CPU usage |
| **Goroutines & File Descriptors** | timeseries | Go runtime internals |

## Requirements

- **Grafana** 9.0+ (tested with 12.x)
- **Prometheus** datasource configured and scraping the bouncer
- Bouncer running with `metrics.enabled: true`

## Customization

The dashboard is designed as a starting point. Common customizations:

- **Time range**: Adjust the default time range for your monitoring needs
- **Thresholds**: Modify alert thresholds on panels
- **Additional panels**: Add panels for specific metrics you care about
