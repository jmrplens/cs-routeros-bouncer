// Package routeros provides a high-level client for the MikroTik RouterOS API.
//
// It wraps the go-routeros library with connection management, automatic
// reconnection, and domain-specific operations for address list and firewall
// rule management. All operations are goroutine-safe via internal mutex locking.
//
// Key components:
//   - [Client]: connection lifecycle, auto-reconnect, generic command execution
//   - [AddressEntry]: address list CRUD and timeout/comment refresh behavior
//   - [FirewallRule]: filter/raw rule creation with move-based placement
//   - [FirewallCounters]: byte/packet aggregation for Prometheus and LAPI metrics
package routeros
