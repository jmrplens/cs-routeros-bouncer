// mock_conn_test.go provides a thread-safe mock for the RouterConn interface.
// It lets unit tests control exactly what the RouterOS API returns for every
// RunArgs invocation, enabling deterministic testing of Client, address-list,
// firewall, and bulk operations without a real router.
package routeros

import (
	"fmt"
	"sync"

	"github.com/go-routeros/routeros/v3"
	"github.com/go-routeros/routeros/v3/proto"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// mockConn implements RouterConn for testing.
type mockConn struct {
	mu      sync.Mutex
	calls   [][]string        // recorded RunArgs calls
	replies []*routeros.Reply // FIFO queue of replies (shifted on each call)
	errors  []error           // FIFO queue of errors (shifted on each call)
	closed  bool
}

// newMockConn creates a mock with no pre-configured responses.
// Call pushReply / pushError to enqueue responses before exercising code.
func newMockConn() *mockConn {
	return &mockConn{}
}

// pushReply enqueues a successful reply for the next RunArgs call.
func (m *mockConn) pushReply(r *routeros.Reply) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.replies = append(m.replies, r)
	m.errors = append(m.errors, nil)
}

// pushError enqueues an error (with nil reply) for the next RunArgs call.
func (m *mockConn) pushError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.replies = append(m.replies, nil)
	m.errors = append(m.errors, err)
}

// RunArgs records the call and returns the next enqueued reply/error.
func (m *mockConn) RunArgs(args []string) (*routeros.Reply, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, args)

	if len(m.replies) == 0 {
		return nil, fmt.Errorf("mock: no reply enqueued for call %d: %v", len(m.calls)-1, args)
	}

	r := m.replies[0]
	e := m.errors[0]
	m.replies = m.replies[1:]
	m.errors = m.errors[1:]
	return r, e
}

// Close marks the mock as closed.
func (m *mockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// callCount returns the number of RunArgs invocations so far.
func (m *mockConn) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// lastArgs returns the arguments of the most recent RunArgs call.
func (m *mockConn) lastArgs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.calls) == 0 {
		return nil
	}
	return m.calls[len(m.calls)-1]
}

// --- helpers to build routeros.Reply values ---

// emptyReply creates a Reply with an empty Done sentence and no Re entries.
func emptyReply() *routeros.Reply {
	return &routeros.Reply{
		Done: &proto.Sentence{Map: map[string]string{}},
	}
}

// doneReply creates a Reply whose Done sentence contains the given key-value pairs.
func doneReply(kv map[string]string) *routeros.Reply {
	return &routeros.Reply{
		Done: &proto.Sentence{Map: kv},
	}
}

// reReply creates a Reply with one or more Re sentences (result rows).
func reReply(rows ...map[string]string) *routeros.Reply {
	re := make([]*proto.Sentence, len(rows))
	for i, row := range rows {
		re[i] = &proto.Sentence{Map: row}
	}
	return &routeros.Reply{
		Re:   re,
		Done: &proto.Sentence{Map: map[string]string{}},
	}
}

// --- helper to build a Client wired to a mock ---

// newTestClient creates a Client backed by the given mockConn.
// The client starts in "connected" state so tests don't need to call Connect().
func newTestClient(mc *mockConn) *Client {
	return &Client{
		conn: mc,
		dialFunc: func(_ config.MikroTikConfig) (RouterConn, error) {
			return mc, nil
		},
	}
}

// newDuplicateDeviceError returns a DeviceError simulating the RouterOS
// "already have such entry" trap, used across multiple tests.
func newDuplicateDeviceError() *routeros.DeviceError {
	return &routeros.DeviceError{
		Sentence: &proto.Sentence{
			Word: "!trap",
			Map:  map[string]string{"message": "failure: already have such entry"},
		},
	}
}
