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

| Panel | Description |
|-------|-------------|
| **Bouncer Info** | Version, RouterOS identity, and uptime |
| **Active Decisions** | Current banned IPs by protocol (IPv4/IPv6) |
| **RouterOS Connection** | Connection status over time |
| **Decisions Processed** | Rate of ban/unban operations |
| **Cumulative Decisions** | Total decisions processed since startup |
| **Errors** | Error rate by type (api, routeros, reconcile) |
| **Operation Latency** | p50/p95/p99 latency for add/remove/reconcile |
| **Reconciliation Events** | Full sync events timeline |

## Requirements

- **Grafana** 9.0+ (tested with 12.x)
- **Prometheus** datasource configured and scraping the bouncer
- Bouncer running with `metrics.enabled: true`

## Customization

The dashboard is designed as a starting point. Common customizations:

- **Time range**: Adjust the default time range for your monitoring needs
- **Thresholds**: Modify alert thresholds on panels
- **Additional panels**: Add panels for specific metrics you care about
