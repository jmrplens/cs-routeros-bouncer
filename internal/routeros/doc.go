// Package routeros provides a high-level client for the MikroTik RouterOS API.
//
// It wraps the go-routeros library with connection management, automatic
// reconnection, and domain-specific operations for address list and firewall
// rule management. All operations are goroutine-safe via internal mutex locking.
//
// Key components:
//   - Client: connection lifecycle, auto-reconnect, generic command execution
//   - AddressEntry / address list CRUD: add, find, list, remove, update timeout
//   - FirewallRule / firewall CRUD: create filter/raw rules with move-based placement
package routeros
