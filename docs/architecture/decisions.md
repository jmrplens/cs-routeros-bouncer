# Decision Processing

How the bouncer processes CrowdSec decisions and translates them into MikroTik actions.

## Decision types

The bouncer processes decisions from CrowdSec LAPI. Each decision has:

| Field | Description |
|-------|-------------|
| **Type** | Action to take (e.g., `ban`) |
| **Value** | IP address or CIDR range |
| **Scope** | `ip` or `range` |
| **Duration** | How long the ban lasts |
| **Origin** | Where the decision came from (`crowdsec`, `cscli`, `CAPI`) |
| **Scenario** | Detection scenario that triggered the decision |

## Processing flow

### Ban (new decision)

When a new ban decision arrives:

1. Determine if it's IPv4 or IPv6
2. Check if the protocol is enabled
3. Add the IP to the appropriate MikroTik address list
4. Set the MikroTik timeout to match the CrowdSec ban duration

```mermaid
flowchart TD
    D[New ban decision] --> Check{IPv4 or IPv6?}
    Check -->|IPv4| V4{IPv4 enabled?}
    Check -->|IPv6| V6{IPv6 enabled?}
    V4 -->|Yes| Add4[Add to crowdsec-banned]
    V4 -->|No| Skip[Skip]
    V6 -->|Yes| Add6[Add to crowdsec6-banned]
    V6 -->|No| Skip
    Add4 --> Done[Done]
    Add6 --> Done
```

### Unban (deleted decision)

When a decision is deleted (expired or manually removed):

1. Determine if it's IPv4 or IPv6
2. Search for the IP in the MikroTik address list
3. Remove it immediately

!!! note
    Even without explicit unban, address list entries expire via their MikroTik timeout. The unban operation provides immediate removal.

## Origin filtering

The `crowdsec.origins` setting controls which decisions are processed:

| Configuration | Behavior |
|--------------|----------|
| `origins: []` (default) | All decisions (local + community blocklists) |
| `origins: ["crowdsec", "cscli"]` | Only local decisions |
| `origins: ["CAPI"]` | Only community blocklists |

### Why use local-only mode?

Community blocklists (CAPI) can contain 20,000+ IP addresses. Pushing all of these to a MikroTik router:

- Increases memory usage on the router
- Takes longer during initial reconciliation (~2 min 50 s for ~25,000 IPs vs ~9 s for ~1,500 local IPs)
- Increases steady-state router CPU usage (15–20% vs 8–11% for local-only)

For most home and small-business setups, `origins: ["crowdsec", "cscli"]` is recommended.

## Scenario filtering

For fine-grained control, you can filter by scenario name:

```yaml
crowdsec:
  # Only process SSH and HTTP-related scenarios
  scenarios_containing: ["ssh", "http"]

  # Exclude specific scenarios
  scenarios_not_containing: ["false-positive"]
```

## Scope handling

The bouncer supports two scopes:

- `ip` — single IP addresses (e.g., `192.168.1.100`)
- `range` — CIDR ranges (e.g., `192.168.1.0/24`)

Both are added to the MikroTik address list in the same way — RouterOS natively supports CIDR notation in address lists.
