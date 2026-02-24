---
title: Firewall Rules
description: How the bouncer creates and manages firewall rules on the MikroTik router.
---

How the bouncer creates and manages firewall rules.

## Rule types

The bouncer can create rules in three locations:

| Type | RouterOS path | Purpose |
|------|--------------|---------|
| Filter input | `/ip/firewall/filter` | Block incoming traffic (after connection tracking) |
| Raw prerouting | `/ip/firewall/raw` | Block incoming traffic (before connection tracking — lower CPU) |
| Filter output | `/ip/firewall/filter` (output chain) | Block outgoing traffic to banned IPs |

Each type has an IPv6 equivalent (e.g., `/ipv6/firewall/filter`).

## Rule creation flow

On startup, the bouncer:

1. Checks for existing bouncer-managed rules (by comment pattern)
2. Removes any existing rules to ensure clean state
3. Creates new rules according to configuration
4. Places rules at the configured position (top or bottom)

## Rule structure

Each rule has:

- **Chain**: `input`, `forward`, `prerouting`, or `output`
- **Action**: `drop` or `reject` (with optional `reject-with`)
- **Source/destination address list**: References the banned IP list
- **Interface**: Optional input/output interface restriction
- **Connection state**: Optional connection-state matcher (filter only)
- **Log settings**: Optional logging with configurable prefix
- **Comment**: Structured identifier for management

Example rule as seen in RouterOS:

```routeros
/ip/firewall/filter print where comment~"crowdsec-bouncer"
# chain=input action=drop src-address-list=crowdsec-banned
#   in-interface=ether1 log=no
#   comment="crowdsec-bouncer:filter-input-input-v4 @cs-routeros-bouncer"
```

## Rule placement

With `rule_placement: "top"`, the bouncer places rules at position 0 for maximum priority. If a dynamic/built-in rule occupies position 0, the bouncer iterates through positions until finding a valid placement.

```routeros
# Rules appear at the top of the firewall:
/ip/firewall/filter print
# 0  chain=input action=drop src-address-list=crowdsec-banned ...
# 1  chain=forward action=drop src-address-list=crowdsec-banned ...
# 2  ... (your other rules)
```

## Rule identification

Rules are identified by a structured comment:

```
{prefix}:{type}-{chain}-{direction}-{protocol} @cs-routeros-bouncer
```

Components:

| Part | Values |
|------|--------|
| `prefix` | Configurable via `comment_prefix` (default: `crowdsec-bouncer`) |
| `type` | `filter` or `raw` |
| `chain` | `input`, `forward`, `prerouting`, `output` |
| `direction` | `input`, `output`, or `whitelist` |
| `protocol` | `v4` or `v6` |

:::note
The `@cs-routeros-bouncer` suffix is always appended and is used to distinguish rules created by this bouncer from rules that may happen to have similar comments.
:::

## Cleanup on shutdown

When the bouncer receives a SIGTERM signal:

1. All firewall rules with matching comments are removed
2. Address list entries are **not** removed — they expire naturally via their timeout

This design means:

- Protection continues briefly after bouncer stops (until entries expire)
- No mass-delete operations are needed on shutdown
- Quick restart doesn't leave the router unprotected during the gap
