# Quick Start

Get cs-routeros-bouncer running in 5 minutes.

## 1. Register the bouncer with CrowdSec

On the machine running CrowdSec:

```bash
sudo cscli bouncers add cs-routeros-bouncer
```

!!! note "Save the API key"
    Copy the API key shown in the output — you'll need it for the bouncer configuration.

## 2. Create a RouterOS API user

Connect to your MikroTik router (via SSH, Winbox, or WebFig) and create a dedicated user:

```routeros
/user group add name=crowdsec policy=read,write,api,sensitive,!ftp,!local,!ssh,!reboot,!policy,!test,!password,!sniff,!romon,!rest-api
/user add name=crowdsec group=crowdsec password=YOUR_SECURE_PASSWORD
```

!!! warning "Security"
    Use a strong, unique password. The API user should have only the minimum required permissions.

For more details, see [Router Setup](router-setup.md).

## 3. Deploy the bouncer

=== "Docker Compose (recommended)"

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
    ```

    ```bash
    docker compose up -d
    ```

=== "Binary + systemd"

    ```bash
    # Download (replace with your architecture: amd64, arm64, armv7)
    wget https://github.com/jmrplens/cs-routeros-bouncer/releases/latest/download/cs-routeros-bouncer_linux_amd64.tar.gz
    tar xzf cs-routeros-bouncer_linux_amd64.tar.gz

    # Automated install
    sudo ./cs-routeros-bouncer setup

    # Edit configuration
    sudo nano /etc/cs-routeros-bouncer/cs-routeros-bouncer.yaml

    # Restart after editing config
    sudo systemctl restart cs-routeros-bouncer
    ```

## 4. Verify it's working

```bash
# Check the health endpoint
curl http://localhost:2112/health
# {"status":"ok","routeros_connected":true,"version":"vX.Y.Z"}

# Check logs
sudo journalctl -u cs-routeros-bouncer -f
```

On the router, you should see new firewall rules and address list entries:

```routeros
/ip/firewall/filter/print where comment~"crowdsec"
/ip/firewall/address-list/print where list=crowdsec-banned
```

## Next Steps

- [Full installation guide](installation.md) — all deployment options in detail
- [Configuration reference](../configuration/index.md) — all options explained
- [Monitoring setup](../monitoring/prometheus.md) — Prometheus & Grafana
