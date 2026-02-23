package manager

import (
	ros "github.com/jmrplens/cs-routeros-bouncer/internal/routeros"
)

// RouterOSClient abstracts the RouterOS operations used by Manager.
// This interface enables unit testing with mock implementations.
type RouterOSClient interface {
	Connect() error
	Close()
	GetAPIMaxSessions() int
	GetIdentity() (string, error)

	// Address list operations
	AddAddress(proto, list, address, timeout, comment string) (string, error)
	FindAddress(proto, list, address string) (*ros.AddressEntry, error)
	UpdateAddressTimeout(proto, id, timeout string) error
	RemoveAddress(proto, id string) error
	ListAddresses(proto, list, commentPrefix string) ([]ros.AddressEntry, error)
	BulkAddAddresses(proto, list string, entries []ros.BulkEntry) (int, error)

	// Firewall operations
	AddFirewallRule(proto, mode string, rule ros.FirewallRule) (string, error)
	RemoveFirewallRule(proto, mode, id string) error
	FindFirewallRuleByComment(proto, mode, comment string) (*ros.RuleEntry, error)
}
