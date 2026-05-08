package manager

import (
	ros "github.com/jmrplens/cs-routeros-bouncer/internal/routeros"
)

// RouterOSClient abstracts the RouterOS operations that Manager depends on.
// It is defined in the consumer package (manager) following the Go idiom
// "accept interfaces, return structs". The concrete *routeros.Client
// implicitly satisfies this interface; no explicit implements declaration
// is needed. Test code provides a mock implementation (mockROS) to exercise
// Manager logic without a real MikroTik router.
type RouterOSClient interface {
	// Connect establishes the RouterOS connection and returns connection,
	// authentication, TLS, or timeout errors from the RouterOS API client.
	Connect() error
	// Close releases the RouterOS connection.
	Close()
	// GetAPIMaxSessions returns the router API max-sessions limit when available.
	GetAPIMaxSessions() int
	// GetIdentity returns the RouterOS system identity, or network, timeout, or
	// permission errors if the identity cannot be read.
	GetIdentity() (string, error)

	// Address list operations
	// AddAddress adds an address to an address list, returning validation,
	// duplicate reconciliation, network, timeout, or RouterOS API errors.
	AddAddress(proto, list, address, timeout, comment string) (string, error)
	// FindAddress finds one address-list entry, returning routeros.ErrNotFound
	// when absent, or network, timeout, or RouterOS API errors.
	FindAddress(proto, list, address string) (*ros.AddressEntry, error)
	// UpdateAddressTimeout updates an existing address-list timeout, returning
	// validation, network, timeout, permission, or RouterOS API errors.
	UpdateAddressTimeout(proto, id, timeout string) error
	// RemoveAddress removes an address-list entry by ID, returning
	// routeros.ErrNotFound when the entry is absent, or network, timeout,
	// permission, or RouterOS API errors.
	RemoveAddress(proto, id string) error
	// ListAddresses lists address-list entries matching the comment prefix,
	// returning network, timeout, permission, or RouterOS API errors.
	ListAddresses(proto, list, commentPrefix string) ([]ros.AddressEntry, error)
	// BulkAddAddresses adds multiple address-list entries efficiently, returning
	// validation, partial-add, network, timeout, or RouterOS API errors.
	BulkAddAddresses(proto, list string, entries []ros.BulkEntry) (int, error)

	// Firewall operations
	// AddFirewallRule creates a firewall rule, returning validation, permission,
	// network, timeout, or RouterOS API errors.
	AddFirewallRule(proto, mode string, rule ros.FirewallRule) (string, error)
	// RemoveFirewallRule removes a firewall rule by ID, returning
	// routeros.ErrNotFound when the rule is absent, or network, timeout,
	// permission, or RouterOS API errors.
	RemoveFirewallRule(proto, mode, id string) error
	// FindFirewallRuleByComment finds one firewall rule, returning
	// routeros.ErrNotFound when absent, or network, timeout, or RouterOS API errors.
	FindFirewallRuleByComment(proto, mode, comment string) (*ros.RuleEntry, error)
	// ListFirewallRules lists rules matching a comment prefix, returning network,
	// timeout, permission, or RouterOS API errors.
	ListFirewallRules(proto, mode, commentPrefix string) ([]ros.RuleEntry, error)
	// ListFirewallRulesBySignature lists rules containing the bouncer signature,
	// returning network, timeout, permission, or RouterOS API errors.
	ListFirewallRulesBySignature(proto, mode, signature string) ([]ros.RuleEntry, error)
	// MoveFirewallRule moves one firewall rule before another in the same RouterOS
	// menu, returning network, timeout, permission, or RouterOS API errors.
	MoveFirewallRule(proto, mode, ruleID, beforeID string) error
	// GetFirewallCounters returns aggregated counters for bouncer firewall rules,
	// returning network, timeout, permission, or RouterOS API errors.
	GetFirewallCounters(commentPrefix string) (*ros.FirewallCounters, error)

	// System metrics
	// GetSystemResources returns RouterOS resource metrics, or network, timeout,
	// permission, or RouterOS API errors.
	GetSystemResources() (*ros.SystemResources, error)
	// GetSystemHealth returns RouterOS health metrics, or network, timeout,
	// permission, or RouterOS API errors.
	GetSystemHealth() (*ros.SystemHealth, error)
}
