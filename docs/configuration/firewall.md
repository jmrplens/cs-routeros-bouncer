# Firewall Configuration

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

!!! tip "Best practice"
    Enable both filter and raw rules for defense-in-depth. Raw rules block traffic earlier in the packet processing pipeline.

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

!!! note
    If a dynamic/built-in rule occupies position 0 (e.g., RouterOS fasttrack counters), the bouncer iterates through subsequent positions until it finds one where the rule can be placed.

### `firewall.comment_prefix`

| | |
|---|---|
| **Env** | `FIREWALL_COMMENT_PREFIX` |
| **Default** | `crowdsec-bouncer` |

Prefix for comments on all bouncer-managed resources in MikroTik. Used to identify and manage rules.

Example comments generated:

```
crowdsec-bouncer:filter-input-input-v4
crowdsec-bouncer:raw-prerouting-input-v4
crowdsec-bouncer:filter-input-input-v6
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

!!! info "Default behavior"
    When both `interface` and `interface_list` are empty (the default), firewall rules match traffic arriving on **every** interface. This blocks banned IPs regardless of whether the traffic comes from WAN, LAN, or any other interface.

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

!!! note
    If both `interface` and `interface_list` are set, both are applied to the rule (RouterOS evaluates them as AND).

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

!!! note
    If both `interface` and `interface_list` are set, `interface` takes precedence.
