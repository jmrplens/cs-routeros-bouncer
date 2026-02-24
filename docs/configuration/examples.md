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

Maximum protection with all features enabled. Input rules are restricted to WAN traffic.

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

## Full protection with firewall customization

All features enabled with advanced firewall rule customization: reject action, connection-state filtering, log prefixes, input whitelist, and output passthrough.

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
    # Only block new connections (allow established/related responses)
    connection_state: ["new"]
    log_prefix: "CS-FILTER"
  raw:
    enabled: true
    chains: ["prerouting"]
    log_prefix: "CS-RAW"
  # Use reject instead of drop so clients get an ICMP response
  deny_action: "reject"
  reject_with: "icmp-host-prohibited"
  rule_placement: "top"
  log: true
  log_prefix: "CS"
  block_input:
    interface_list: "WAN"
    # Trust IPs in this address list — place accept rule before drop
    whitelist: "crowdsec-whitelist"
  block_output:
    enabled: true
    interface_list: "WAN"
    log_prefix: "CS-OUT"
    # Allow this local IP to bypass output blocking
    passthrough_v4: "10.0.0.100"
    # Or use a RouterOS address list (takes precedence over IP)
    # passthrough_v4_list: "crowdsec-passthrough"

metrics:
  enabled: true
  listen_port: 2112

logging:
  level: "info"
```

!!! tip "Reject vs Drop"
    Using `deny_action: reject` with `reject_with: icmp-host-prohibited` sends an ICMP unreachable message to the banned IP, making the rejection explicit. Use `drop` (the default) for silent blocking. `reject_with` is only valid when `deny_action` is `reject`.

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
    Community blocklists (CAPI) can contain 20,000+ IPs. If your router has limited resources or you only want to block IPs detected on your network, local-only mode is recommended. Local-only (~1,500 IPs) reconciles in ~9 s with 14% CPU peak. Full CAPI (~25,000 IPs) takes ~2 min 50 s with 23% CPU peak.

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
