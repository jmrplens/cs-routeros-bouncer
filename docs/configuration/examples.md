# Configuration Examples

Complete configuration examples for common deployment scenarios.

## Minimal — IPv4 only, filter rules

The simplest configuration: blocks IPv4 traffic using filter rules only.

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

## Full protection — IPv4 + IPv6, filter + raw, input + output

Maximum protection with all features enabled.

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
  block_output:
    enabled: true
    interface_list: "WAN"

metrics:
  enabled: true
  listen_port: 2112

logging:
  level: "info"
```

## Local decisions only — no community blocklists

Syncs only locally-generated decisions (from your CrowdSec engine and manual `cscli` bans). No CAPI community blocklists.

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

!!! tip "When to use local-only mode"
    Community blocklists (CAPI) can contain 20,000+ IPs. If your router has limited resources or you only want to block IPs detected on your network, local-only mode is recommended.

## Docker Compose with environment variables

All configuration via environment variables — no config file needed.

```yaml
services:
  cs-routeros-bouncer:
    image: ghcr.io/jmrplens/cs-routeros-bouncer:latest
    container_name: cs-routeros-bouncer
    restart: unless-stopped
    ports:
      - "2112:2112"
    environment:
      # CrowdSec
      CROWDSEC_URL: "http://crowdsec:8080/"
      CROWDSEC_BOUNCER_API_KEY: "your-bouncer-api-key"
      CROWDSEC_UPDATE_FREQUENCY: "10s"
      CROWDSEC_ORIGINS: "crowdsec,cscli"

      # MikroTik
      MIKROTIK_HOST: "192.168.0.1:8728"
      MIKROTIK_USER: "crowdsec"
      MIKROTIK_PASS: "your-password"

      # Firewall
      FIREWALL_IPV4_ENABLED: "true"
      FIREWALL_IPV6_ENABLED: "true"
      FIREWALL_DENY_ACTION: "drop"
      FIREWALL_RULE_PLACEMENT: "top"

      # Logging
      LOG_LEVEL: "info"
      LOG_FORMAT: "json"

      # Metrics
      METRICS_ENABLED: "true"
      METRICS_PORT: "2112"
```

## With TLS and logging

Secure connection with rule logging enabled.

```yaml
crowdsec:
  api_url: "https://crowdsec.example.com:8080/"
  api_key: "your-key"
  cert_path: "/etc/cs-routeros-bouncer/tls/cert.pem"
  key_path: "/etc/cs-routeros-bouncer/tls/key.pem"
  ca_cert_path: "/etc/cs-routeros-bouncer/tls/ca.pem"

mikrotik:
  address: "192.168.0.1:8729"
  username: "crowdsec"
  password: "your-password"
  tls: true

firewall:
  log: true
  log_prefix: "crowdsec-bouncer"
  deny_action: "drop"

logging:
  level: "info"
  format: "json"
  file: "/var/log/cs-routeros-bouncer.log"

metrics:
  enabled: true
```
