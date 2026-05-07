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
	// Connect establishes the RouterOS connection.
	Connect() error
	// Close releases the RouterOS connection.
	Close()
	// GetAPIMaxSessions returns the router API max-sessions limit when available.
	GetAPIMaxSessions() int
	// GetIdentity returns the RouterOS system identity.
	GetIdentity() (string, error)

	// Address list operations
	// AddAddress adds an address to an address list.
	AddAddress(proto, list, address, timeout, comment string) (string, error)
	// FindAddress finds one address-list entry or returns routeros.ErrNotFound.
	FindAddress(proto, list, address string) (*ros.AddressEntry, error)
	// UpdateAddressTimeout updates an existing address-list timeout.
	UpdateAddressTimeout(proto, id, timeout string) error
	// RemoveAddress removes an address-list entry by ID.
	RemoveAddress(proto, id string) error
	// ListAddresses lists address-list entries matching the comment prefix.
	ListAddresses(proto, list, commentPrefix string) ([]ros.AddressEntry, error)
	// BulkAddAddresses adds multiple address-list entries efficiently.
	BulkAddAddresses(proto, list string, entries []ros.BulkEntry) (int, error)

	// Firewall operations
	// AddFirewallRule creates a firewall rule.
	AddFirewallRule(proto, mode string, rule ros.FirewallRule) (string, error)
	// RemoveFirewallRule removes a firewall rule by ID.
	RemoveFirewallRule(proto, mode, id string) error
	// FindFirewallRuleByComment finds one firewall rule or returns routeros.ErrNotFound.
	FindFirewallRuleByComment(proto, mode, comment string) (*ros.RuleEntry, error)
	// ListFirewallRules lists rules matching a comment prefix.
	ListFirewallRules(proto, mode, commentPrefix string) ([]ros.RuleEntry, error)
	// ListFirewallRulesBySignature lists rules containing the bouncer signature.
	ListFirewallRulesBySignature(proto, mode, signature string) ([]ros.RuleEntry, error)
	// GetFirewallCounters returns aggregated counters for bouncer firewall rules.
	GetFirewallCounters(commentPrefix string) (*ros.FirewallCounters, error)

	// System metrics
	// GetSystemResources returns RouterOS resource metrics.
	GetSystemResources() (*ros.SystemResources, error)
	// GetSystemHealth returns RouterOS health metrics.
	GetSystemHealth() (*ros.SystemHealth, error)
}
