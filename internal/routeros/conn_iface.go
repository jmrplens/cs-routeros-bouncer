// conn_iface.go defines the low-level RouterOS connection interface.
// By depending on this interface instead of the concrete *routeros.Client,
// all Client methods become unit-testable with a mock connection.
package routeros

import (
	"github.com/go-routeros/routeros/v3"
)

// RouterConn abstracts the low-level RouterOS API connection.
// The concrete implementation is *routeros.Client from go-routeros.
type RouterConn interface {
	// RunArgs sends a command sentence and waits for the reply.
	RunArgs(args []string) (*routeros.Reply, error)
	// Close terminates the connection.
	Close() error
}
