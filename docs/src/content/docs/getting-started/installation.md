---
title: Installation
description: Deploy cs-routeros-bouncer using Docker, systemd, or build from source.
---

cs-routeros-bouncer supports multiple deployment methods. Choose the one that best fits your infrastructure.

## Docker Compose (recommended)

The simplest deployment method, especially if you already run CrowdSec in Docker.

### Basic setup

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

### With config file

```yaml
services:
  cs-routeros-bouncer:
    image: ghcr.io/jmrplens/cs-routeros-bouncer:latest
    container_name: cs-routeros-bouncer
    restart: unless-stopped
    ports:
      - "2112:2112"
    volumes:
      - ./config.yaml:/etc/cs-routeros-bouncer/config.yaml
```

Start the service:

```bash
docker compose up -d
```

### Environment variables

All configuration options can be set via environment variables. See the [Configuration](/configuration/) section for the full list.

## Binary + systemd

### Automatic setup (recommended)

Download the latest release and use the built-in setup command:

```bash
# Download (replace architecture as needed: amd64, arm64, armv7)
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

### Manual setup

If you prefer to set things up manually:

```bash
# Download
wget https://github.com/jmrplens/cs-routeros-bouncer/releases/latest/download/cs-routeros-bouncer_linux_amd64.tar.gz
tar xzf cs-routeros-bouncer_linux_amd64.tar.gz

# Install binary
sudo install -m 755 cs-routeros-bouncer /usr/local/bin/

# Create config directory and copy config
sudo mkdir -p /etc/cs-routeros-bouncer
sudo cp cs-routeros-bouncer.yaml /etc/cs-routeros-bouncer/cs-routeros-bouncer.yaml

# Edit configuration
sudo nano /etc/cs-routeros-bouncer/cs-routeros-bouncer.yaml

# Create systemd service
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

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now cs-routeros-bouncer
```

### Uninstall

```bash
# Keep config files
sudo cs-routeros-bouncer uninstall

# Also remove config
sudo cs-routeros-bouncer uninstall -purge
```

## Build from source

### Prerequisites

- **Go 1.25+** — [Download](https://go.dev/dl/)
- **Make** — typically pre-installed on Linux

### Build

```bash
git clone https://github.com/jmrplens/cs-routeros-bouncer.git
cd cs-routeros-bouncer
make build
```

The binary is created at `bin/cs-routeros-bouncer`.

### Install

```bash
# Option 1: Automated install
sudo bin/cs-routeros-bouncer setup

# Option 2: Manual install
sudo install -m 755 bin/cs-routeros-bouncer /usr/local/bin/
```

## Verify installation

After installing, verify the bouncer is running correctly:

```bash
# Check service status
sudo systemctl status cs-routeros-bouncer

# Check health endpoint
curl http://localhost:2112/health

# Check logs
sudo journalctl -u cs-routeros-bouncer -f
```

On the router, verify firewall rules were created:

```routeros
/ip/firewall/filter/print where comment~"crowdsec"
/ip/firewall/raw/print where comment~"crowdsec"
/ip/firewall/address-list/print where list=crowdsec-banned
```
