---
title: Firewall
description: IPv4/IPv6 blocking, firewall rule creation, and output blocking configuration.
---

Settings for IPv4/IPv6 blocking, firewall rule creation, and output blocking.

## IPv4

### `firewall.ipv4.enabled`

| | |
|---|---|
| **Env** | `FIREWALL_IPV4_ENABLED` |
| **Default** | `true` |

Enable IPv4 address blocking. When enabled, the bouncer creates IPv4 firewall rules and manages the IPv4 address list.

### `firewall.ipv4.address_list`

| | |
|---|---|
| **Env** | `FIREWALL_IPV4_ADDRESS_LIST` |
| **Default** | `crowdsec-banned` |

Name of the IPv4 address list in MikroTik where banned IPs are stored.

## IPv6

### `firewall.ipv6.enabled`

| | |
|---|---|
| **Env** | `FIREWALL_IPV6_ENABLED` |
| **Default** | `true` |

Enable IPv6 address blocking. When enabled, the bouncer creates IPv6 firewall rules and manages the IPv6 address list.

### `firewall.ipv6.address_list`

| | |
|---|---|
| **Env** | `FIREWALL_IPV6_ADDRESS_LIST` |
| **Default** | `crowdsec6-banned` |

Name of the IPv6 address list in MikroTik.

## Filter Rules

### `firewall.filter.enabled`

| | |
|---|---|
| **Env** | `FIREWALL_FILTER_ENABLED` |
| **Default** | `true` |

Create rules in `/ip/firewall/filter` (and `/ipv6/firewall/filter` if IPv6 enabled). Filter rules are the standard RouterOS firewall rules processed after connection tracking.

### `firewall.filter.chains`

| | |
|---|---|
| **Env** | `FIREWALL_FILTER_CHAINS` |
| **Default** | `["input"]` |

Which chains to create filter rules in. Common values:

- `input` — blocks traffic destined to the router itself
- `forward` — blocks traffic passing through the router

```yaml
firewall:
  filter:
    chains: ["input", "forward"]
```

## Raw Rules

### `firewall.raw.enabled`

| | |
|---|---|
| **Env** | `FIREWALL_RAW_ENABLED` |
| **Default** | `true` |

Create rules in `/ip/firewall/raw` (and `/ipv6/firewall/raw` if IPv6 enabled). Raw rules are processed before connection tracking, providing earlier packet filtering with less CPU usage.

:::tip[Best practice]
Enable both filter and raw rules for defense-in-depth. Raw rules block traffic earlier in the packet processing pipeline.
:::

### `firewall.raw.chains`

| | |
|---|---|
| **Env** | `FIREWALL_RAW_CHAINS` |
| **Default** | `["prerouting"]` |

Which chains to create raw rules in. Typically `prerouting`.

## Rule Behavior

### `firewall.deny_action`

| | |
|---|---|
| **Env** | `FIREWALL_DENY_ACTION` |
| **Default** | `drop` |

Action for firewall rules. Options:

- `drop` — silently drops packets (recommended)
- `reject` — sends a rejection response to the sender

### `firewall.rule_placement`

| | |
|---|---|
| **Env** | `FIREWALL_RULE_PLACEMENT` |
| **Default** | `top` |

Where to place new firewall rules in the chain:

- `top` — at position 0 (processed first, most secure)
- `bottom` — at the end of the chain

:::note
If a dynamic/built-in rule occupies position 0 (e.g., RouterOS fasttrack counters), the bouncer iterates through subsequent positions until it finds one where the rule can be placed.
:::

### `firewall.comment_prefix`

| | |
|---|---|
| **Env** | `FIREWALL_COMMENT_PREFIX` |
| **Default** | `crowdsec-bouncer` |

Prefix for comments on all bouncer-managed resources in MikroTik. Used to identify and manage rules.

Example comments generated:

```text
crowdsec-bouncer:filter-input-input-v4 @cs-routeros-bouncer
crowdsec-bouncer:raw-prerouting-input-v4 @cs-routeros-bouncer
crowdsec-bouncer:filter-input-input-v6 @cs-routeros-bouncer
```

## Rule Logging

### `firewall.log`

| | |
|---|---|
| **Env** | `FIREWALL_LOG` |
| **Default** | `false` |

Enable RouterOS logging on firewall rules. When enabled, matched packets are logged in the RouterOS system log.

### `firewall.log_prefix`

| | |
|---|---|
| **Env** | `FIREWALL_LOG_PREFIX` |
| **Default** | `crowdsec-bouncer` |

Prefix for RouterOS log entries when logging is enabled. Helps identify bouncer-related log entries in the router log.

```yaml
firewall:
  log: true
  log_prefix: "crowdsec-bouncer"
```

## Input Interface Filtering

Restrict input (filter) and prerouting (raw) rules to specific interfaces. By default, rules apply to **all interfaces**.

:::note[Default behavior]
When both `interface` and `interface_list` are empty (the default), firewall rules match traffic arriving on **every** interface. This blocks banned IPs regardless of whether the traffic comes from WAN, LAN, or any other interface.
:::

Use this setting to limit blocking to the WAN interface only, so that banned IPs on the LAN side can still reach the router (e.g., for management or internal services).

### `firewall.block_input.interface`

| | |
|---|---|
| **Env** | `FIREWALL_INPUT_INTERFACE` |
| **Default** | — (all interfaces) |

Restrict input/raw rules to a single interface.

```yaml
firewall:
  block_input:
    interface: "ether1"
```

### `firewall.block_input.interface_list`

| | |
|---|---|
| **Env** | `FIREWALL_INPUT_INTERFACE_LIST` |
| **Default** | — (all interfaces) |

Restrict input/raw rules to an interface list. Alternative to specifying a single interface.

```yaml
firewall:
  block_input:
    interface_list: "WAN"
```

:::note
If both `interface` and `interface_list` are set, both are applied to the rule (RouterOS evaluates them as AND).
:::

## Output Blocking

Block outbound traffic to banned IPs. Disabled by default.

### `firewall.block_output.enabled`

| | |
|---|---|
| **Env** | `FIREWALL_BLOCK_OUTPUT` |
| **Default** | `false` |

Enable blocking of outgoing traffic to banned IPs. This prevents your network from establishing connections to known malicious IPs.

### `firewall.block_output.interface`

| | |
|---|---|
| **Env** | `FIREWALL_OUTPUT_INTERFACE` |
| **Default** | — |

WAN interface for output rules. Required if `block_output.enabled` is true (unless `interface_list` is set).

```yaml
firewall:
  block_output:
    enabled: true
    interface: "ether1"
```

### `firewall.block_output.interface_list`

| | |
|---|---|
| **Env** | `FIREWALL_OUTPUT_INTERFACE_LIST` |
| **Default** | — |

WAN interface list for output rules. Alternative to specifying a single interface.

```yaml
firewall:
  block_output:
    enabled: true
    interface_list: "WAN"
```

:::note
If both `interface` and `interface_list` are set, `interface` takes precedence.
:::

---

## Rule Customization

Advanced options for customizing how firewall rules are created and what traffic they match.

Each option below shows the bouncer YAML configuration and the equivalent RouterOS command that the bouncer generates. The RouterOS commands are shown to help you understand exactly what rules are created on the router.

### `firewall.reject_with`

| | |
|---|---|
| **Env** | `FIREWALL_REJECT_WITH` |
| **Default** | — |

Customize the ICMP response type when `deny_action` is `reject`. Only valid when `deny_action: "reject"`.

Valid values:

| Value | Description |
|---|---|
| `icmp-network-unreachable` | Network is unreachable |
| `icmp-host-unreachable` | Host is unreachable |
| `icmp-port-unreachable` | Port is unreachable |
| `icmp-protocol-unreachable` | Protocol is unreachable |
| `icmp-network-prohibited` | Network administratively prohibited |
| `icmp-host-prohibited` | Host administratively prohibited |
| `icmp-admin-prohibited` | Communication administratively prohibited |
| `tcp-reset` | Send TCP RST (recommended for TCP-heavy services) |

**Bouncer configuration:**

```yaml
firewall:
  deny_action: "reject"
  reject_with: "icmp-admin-prohibited"
```

**Equivalent RouterOS commands generated by the bouncer:**

```routeros
# Without reject_with (default reject behavior):
/ip/firewall/filter add chain=input action=reject src-address-list=crowdsec-banned comment="crowdsec-bouncer:filter-input-input-v4 @cs-routeros-bouncer"

# With reject_with="icmp-admin-prohibited":
/ip/firewall/filter add chain=input action=reject reject-with=icmp-admin-prohibited src-address-list=crowdsec-banned comment="crowdsec-bouncer:filter-input-input-v4 @cs-routeros-bouncer"

# With reject_with="tcp-reset":
/ip/firewall/filter add chain=input action=reject reject-with=tcp-reset src-address-list=crowdsec-banned comment="crowdsec-bouncer:filter-input-input-v4 @cs-routeros-bouncer"
```

:::tip
Use `tcp-reset` if you mainly want to reject TCP connections (SSH brute-force, web scanners). Use `icmp-admin-prohibited` for a generic "access denied" response that works with any protocol.
:::

---

### `firewall.filter.connection_state`

| | |
|---|---|
| **Env** | `FIREWALL_FILTER_CONNECTION_STATE` |
| **Default** | — (matches all connection states) |

Add a `connection-state` matcher to filter rules. This restricts rule matching to specific connection states, allowing established/related connections to pass through even if the source IP is banned.

Valid states (comma-separated for multiple):

| State | Description |
|---|---|
| `new` | A new connection (first packet of a flow) |
| `established` | Part of an already established connection |
| `related` | Related to an existing connection (e.g., FTP data channel) |
| `invalid` | Cannot be identified or does not have any known state |
| `untracked` | Packet is untracked (bypassing connection tracking) |

:::caution
This option only applies to **filter** rules. RAW rules do not support connection-state matching because raw operates before connection tracking.
:::

**Bouncer configuration — block only new connections:**

```yaml
firewall:
  filter:
    enabled: true
    chains: ["input"]
    connection_state: "new"
```

**Equivalent RouterOS commands:**

```routeros
# Without connection_state (default — blocks ALL packets from banned IPs):
/ip/firewall/filter add chain=input action=drop src-address-list=crowdsec-banned comment="crowdsec-bouncer:filter-input-input-v4 @cs-routeros-bouncer"

# With connection_state="new" (only blocks NEW connections, existing ones can finish):
/ip/firewall/filter add chain=input action=drop connection-state=new src-address-list=crowdsec-banned comment="crowdsec-bouncer:filter-input-input-v4 @cs-routeros-bouncer"

# With connection_state="new,invalid" (blocks new and invalid packets):
/ip/firewall/filter add chain=input action=drop connection-state=new,invalid src-address-list=crowdsec-banned comment="crowdsec-bouncer:filter-input-input-v4 @cs-routeros-bouncer"
```

:::tip[Use case]
Setting `connection_state: "new"` is useful if you want to block new connections from banned IPs but allow already-established connections (e.g., ongoing downloads) to finish gracefully. This prevents abruptly cutting off legitimate sessions that were started before the IP was banned.
:::

---

### `firewall.filter.log_prefix` / `firewall.raw.log_prefix` / `firewall.block_output.log_prefix`

| | |
|---|---|
| **Env** | `FIREWALL_FILTER_LOG_PREFIX` / `FIREWALL_RAW_LOG_PREFIX` / `FIREWALL_OUTPUT_LOG_PREFIX` |
| **Default** | — (uses global `firewall.log_prefix`) |

Override the global `log_prefix` for specific rule types. This allows differentiating log entries from filter, raw, and output rules when parsing RouterOS logs.

**Resolution order:** per-type prefix → global `firewall.log_prefix`.

| Rule type | Config key | Env var |
|---|---|---|
| Filter input rules | `firewall.filter.log_prefix` | `FIREWALL_FILTER_LOG_PREFIX` |
| Raw input rules | `firewall.raw.log_prefix` | `FIREWALL_RAW_LOG_PREFIX` |
| Output rules | `firewall.block_output.log_prefix` | `FIREWALL_OUTPUT_LOG_PREFIX` |

**Bouncer configuration:**

```yaml
firewall:
  log: true
  log_prefix: "crowdsec"       # global default
  filter:
    log_prefix: "cs-filter"    # overrides global for filter rules
  raw:
    log_prefix: "cs-raw"       # overrides global for raw rules
  block_output:
    log_prefix: "cs-output"    # overrides global for output rules
```

**Equivalent RouterOS commands:**

```routeros
# Filter rules use "cs-filter" prefix:
/ip/firewall/filter add chain=input action=drop src-address-list=crowdsec-banned log=yes log-prefix="cs-filter" comment="crowdsec-bouncer:filter-input-input-v4 @cs-routeros-bouncer"

# Raw rules use "cs-raw" prefix:
/ip/firewall/raw add chain=prerouting action=drop src-address-list=crowdsec-banned log=yes log-prefix="cs-raw" comment="crowdsec-bouncer:raw-prerouting-input-v4 @cs-routeros-bouncer"

# Output rules use "cs-output" prefix:
/ip/firewall/filter add chain=output action=drop dst-address-list=crowdsec-banned out-interface=ether1 log=yes log-prefix="cs-output" comment="crowdsec-bouncer:filter-output-output-v4 @cs-routeros-bouncer"
```

**RouterOS log output example** (with different prefixes per type):

```text
jan/15 14:30:01 firewall,info cs-filter input: in:ether1 out:(unknown 0), src-mac 00:11:22:33:44:55, proto TCP (SYN), 185.220.101.1:45678->192.168.1.1:22, len 60
jan/15 14:30:01 firewall,info cs-raw prerouting: in:ether1 out:(unknown 0), src-mac 00:11:22:33:44:55, proto TCP (SYN), 185.220.101.1:45679->192.168.1.1:443, len 60
jan/15 14:30:02 firewall,info cs-output output: in:(unknown 0) out:ether1, proto TCP, 192.168.1.100:54321->185.220.101.1:80, len 60
```

:::tip[Use case]
Per-type log prefixes are essential for log parsing tools (e.g., syslog parsers, fail2ban, or SIEM systems) that need to distinguish between inbound blocked traffic (filter/raw) and outbound blocked traffic (output).
:::

---

### `firewall.block_input.whitelist`

| | |
|---|---|
| **Env** | `FIREWALL_INPUT_WHITELIST` |
| **Default** | — |

Name of a RouterOS address-list containing trusted IPs that should bypass CrowdSec blocking. When set, the bouncer creates an **accept** rule before the drop/reject rule for each chain, allowing traffic from the whitelisted sources to pass through even if they are in the CrowdSec ban list.

This works with both filter and raw rules. The address-list must be created and managed separately on the router.

**Step 1 — Create the whitelist on your router:**

```routeros
# Add trusted IPs to the whitelist address-list (manage this yourself):
/ip/firewall/address-list add list=crowdsec-whitelist address=10.0.0.1 comment="monitoring server"
/ip/firewall/address-list add list=crowdsec-whitelist address=192.168.1.0/24 comment="LAN subnet"
```

**Step 2 — Configure the bouncer:**

```yaml
firewall:
  block_input:
    whitelist: "crowdsec-whitelist"
```

**Equivalent RouterOS commands generated by the bouncer:**

```routeros
# For each chain, the bouncer creates TWO rules — accept BEFORE drop:

# 1) Accept rule for whitelisted IPs (placed first):
/ip/firewall/filter add chain=input action=accept src-address-list=crowdsec-whitelist comment="crowdsec-bouncer:filter-input-whitelist-v4 @cs-routeros-bouncer"
# 2) Drop rule for banned IPs (placed after accept):
/ip/firewall/filter add chain=input action=drop src-address-list=crowdsec-banned comment="crowdsec-bouncer:filter-input-input-v4 @cs-routeros-bouncer"

# Same pattern for raw rules:
/ip/firewall/raw add chain=prerouting action=accept src-address-list=crowdsec-whitelist comment="crowdsec-bouncer:raw-prerouting-whitelist-v4 @cs-routeros-bouncer"
/ip/firewall/raw add chain=prerouting action=drop src-address-list=crowdsec-banned comment="crowdsec-bouncer:raw-prerouting-input-v4 @cs-routeros-bouncer"

# And for IPv6 (if enabled):
/ipv6/firewall/filter add chain=input action=accept src-address-list=crowdsec-whitelist comment="crowdsec-bouncer:filter-input-whitelist-v6 @cs-routeros-bouncer"
/ipv6/firewall/filter add chain=input action=drop src-address-list=crowdsec6-banned comment="crowdsec-bouncer:filter-input-input-v6 @cs-routeros-bouncer"
```

:::tip[Use case]
The whitelist is useful when you have trusted monitoring systems, security scanners, or internal services whose IPs might end up in CrowdSec ban lists (e.g., a vulnerability scanner that triggers brute-force detection). Instead of modifying CrowdSec itself, you can whitelist them at the firewall level.
:::

:::note[Interaction with `connection_state`]
When [`connection_state`](#firewallfilterconnection_state) is configured, it also applies to the whitelist accept rule. This means the accept rule will only match packets in the specified connection states. For most use cases this is fine, but be aware that whitelisted IPs in other connection states will fall through to subsequent rules.
:::

---

### `firewall.block_output.passthrough_v4` / `passthrough_v6`

| | |
|---|---|
| **Env** | `FIREWALL_OUTPUT_PASSTHROUGH_V4` / `FIREWALL_OUTPUT_PASSTHROUGH_V6` |
| **Default** | — |

Allow a specific local client IP to bypass output blocking. Uses `src-address` negation (`!IP`) on the output drop/reject rule, so packets from this source address are not blocked even when going to a banned destination.

**Bouncer configuration:**

```yaml
firewall:
  block_output:
    enabled: true
    interface: "ether1"
    passthrough_v4: "192.168.1.100"
    passthrough_v6: "fd00::100"
```

**Equivalent RouterOS commands:**

```routeros
# Without passthrough (default — blocks ALL local clients from reaching banned IPs):
/ip/firewall/filter add chain=output action=drop dst-address-list=crowdsec-banned out-interface=ether1 comment="crowdsec-bouncer:filter-output-output-v4 @cs-routeros-bouncer"

# With passthrough_v4="192.168.1.100" (all clients blocked EXCEPT 192.168.1.100):
/ip/firewall/filter add chain=output action=drop dst-address-list=crowdsec-banned out-interface=ether1 src-address=!192.168.1.100 comment="crowdsec-bouncer:filter-output-output-v4 @cs-routeros-bouncer"

# With passthrough_v6="fd00::100":
/ipv6/firewall/filter add chain=output action=drop dst-address-list=crowdsec6-banned out-interface=ether1 src-address=!fd00::100 comment="crowdsec-bouncer:filter-output-output-v6 @cs-routeros-bouncer"
```

:::tip[Use case]
Use this when you have a security scanner or honeypot (e.g., `192.168.1.100`) that needs to communicate with known malicious IPs for research purposes, while still blocking outbound access for all other local clients.
:::

---

### `firewall.block_output.passthrough_v4_list` / `passthrough_v6_list`

| | |
|---|---|
| **Env** | `FIREWALL_OUTPUT_PASSTHROUGH_V4_LIST` / `FIREWALL_OUTPUT_PASSTHROUGH_V6_LIST` |
| **Default** | — |

Same as passthrough but using an address-list instead of a single IP. Uses `src-address-list` negation (`!list`) on the output rule. This is more flexible when multiple clients need to bypass output blocking.

:::note
When both a single IP and an address-list are configured for the same protocol, the **address-list takes precedence** and the single IP is ignored.
:::

**Step 1 — Create the passthrough list on your router:**

```routeros
# Add clients that should bypass output blocking:
/ip/firewall/address-list add list=trusted-clients-v4 address=192.168.1.100 comment="security scanner"
/ip/firewall/address-list add list=trusted-clients-v4 address=192.168.1.200 comment="honeypot server"
```

**Step 2 — Configure the bouncer:**

```yaml
firewall:
  block_output:
    enabled: true
    interface: "ether1"
    passthrough_v4_list: "trusted-clients-v4"
    passthrough_v6_list: "trusted-clients-v6"
```

**Equivalent RouterOS commands:**

```routeros
# With passthrough_v4_list="trusted-clients-v4" (all clients blocked EXCEPT those in the list):
/ip/firewall/filter add chain=output action=drop dst-address-list=crowdsec-banned out-interface=ether1 src-address-list=!trusted-clients-v4 comment="crowdsec-bouncer:filter-output-output-v4 @cs-routeros-bouncer"

# With passthrough_v6_list="trusted-clients-v6":
/ipv6/firewall/filter add chain=output action=drop dst-address-list=crowdsec6-banned out-interface=ether1 src-address-list=!trusted-clients-v6 comment="crowdsec-bouncer:filter-output-output-v6 @cs-routeros-bouncer"
```

---

## Complete Example

Here is a full configuration combining multiple rule customization options:

```yaml
firewall:
  deny_action: "reject"
  reject_with: "tcp-reset"
  log: true
  log_prefix: "crowdsec"
  rule_placement: "top"
  filter:
    enabled: true
    chains: ["input", "forward"]
    connection_state: "new"
    log_prefix: "cs-filter"
  raw:
    enabled: true
    chains: ["prerouting"]
    log_prefix: "cs-raw"
  block_input:
    interface: "ether1"
    whitelist: "crowdsec-whitelist"
  block_output:
    enabled: true
    interface: "ether1"
    log_prefix: "cs-output"
    passthrough_v4_list: "trusted-clients-v4"
```

**This configuration generates the following RouterOS rules** (for IPv4, similar rules are created for IPv6):

```routeros
# Filter — input chain (whitelist + reject with connection-state):
/ip/firewall/filter add chain=input action=accept src-address-list=crowdsec-whitelist in-interface=ether1 connection-state=new log=yes log-prefix="cs-filter" comment="crowdsec-bouncer:filter-input-whitelist-v4 @cs-routeros-bouncer" place-before=0
/ip/firewall/filter add chain=input action=reject reject-with=tcp-reset src-address-list=crowdsec-banned in-interface=ether1 connection-state=new log=yes log-prefix="cs-filter" comment="crowdsec-bouncer:filter-input-input-v4 @cs-routeros-bouncer" place-before=1

# Filter — forward chain (same pattern):
/ip/firewall/filter add chain=forward action=accept src-address-list=crowdsec-whitelist in-interface=ether1 connection-state=new log=yes log-prefix="cs-filter" comment="crowdsec-bouncer:filter-forward-whitelist-v4 @cs-routeros-bouncer" place-before=0
/ip/firewall/filter add chain=forward action=reject reject-with=tcp-reset src-address-list=crowdsec-banned in-interface=ether1 connection-state=new log=yes log-prefix="cs-filter" comment="crowdsec-bouncer:filter-forward-input-v4 @cs-routeros-bouncer" place-before=1

# Raw — prerouting chain (no connection-state, no reject-with):
/ip/firewall/raw add chain=prerouting action=accept src-address-list=crowdsec-whitelist in-interface=ether1 log=yes log-prefix="cs-raw" comment="crowdsec-bouncer:raw-prerouting-whitelist-v4 @cs-routeros-bouncer" place-before=0
/ip/firewall/raw add chain=prerouting action=drop src-address-list=crowdsec-banned in-interface=ether1 log=yes log-prefix="cs-raw" comment="crowdsec-bouncer:raw-prerouting-input-v4 @cs-routeros-bouncer" place-before=1

# Filter — output chain (with passthrough list):
/ip/firewall/filter add chain=output action=reject reject-with=tcp-reset dst-address-list=crowdsec-banned out-interface=ether1 src-address-list=!trusted-clients-v4 log=yes log-prefix="cs-output" comment="crowdsec-bouncer:filter-output-output-v4 @cs-routeros-bouncer" place-before=0
```
