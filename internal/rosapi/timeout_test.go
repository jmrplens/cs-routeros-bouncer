package routeros

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jmrplens/cs-routeros-bouncer/internal/rosapi/proto"
)

// newNetPair builds a client over a net.Pipe, whose ends carry real deadlines
// — the io.Pipe pair the other tests use cannot, which is exactly what makes
// it useless for testing the command timeout.
func newNetPair(t *testing.T) (*Client, net.Conn) {
	t.Helper()
	clientEnd, serverEnd := net.Pipe()
	c, err := NewClient(clientEnd)
	require.NoError(t, err)
	return c, serverEnd
}

// TestCommandTimeoutOnStalledReply pins the reason SetCommandTimeout exists: a
// device that reads the command and never replies must not hold the command
// forever. Before mikrotik.command_timeout was wired, it did — the key was
// parsed, defaulted to 30s, and read by nothing.
func TestCommandTimeoutOnStalledReply(t *testing.T) {
	c, server := newNetPair(t)
	t.Cleanup(func() { _ = server.Close() })

	c.SetCommandTimeout(150 * time.Millisecond)

	// The server drains what the client writes and then stalls forever.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()

	start := time.Now()
	_, err := c.RunArgs([]string{"/system/resource/print"})
	elapsed := time.Since(start)

	require.Error(t, err, "a stalled reply must not block forever")
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Less(t, elapsed, 2*time.Second, "the deadline should fire near 150ms, not hang")
}

// TestCommandTimeoutClearsBetweenCommands pins that the deadline covers ONE
// command, not the connection's lifetime: an idle gap longer than the timeout
// between two commands must not fail the second one.
func TestCommandTimeoutClearsBetweenCommands(t *testing.T) {
	c, server := newNetPair(t)
	t.Cleanup(func() { _ = server.Close() })

	c.SetCommandTimeout(200 * time.Millisecond)

	// A fake server answering !done to every sentence, forever.
	go func() {
		r := proto.NewReader(server)
		w := proto.NewWriter(server)
		for {
			if _, err := r.ReadSentence(); err != nil {
				return
			}
			w.BeginSentence()
			w.WriteWord("!done")
			if err := w.EndSentence(); err != nil {
				return
			}
		}
	}()

	_, err := c.RunArgs([]string{"/system/identity/print"})
	require.NoError(t, err, "first command")

	// Idle for longer than the timeout: a deadline left armed would fire here.
	time.Sleep(450 * time.Millisecond)

	_, err = c.RunArgs([]string{"/system/identity/print"})
	require.NoError(t, err, "second command after an idle gap longer than the timeout")
}

// TestCommandTimeoutZeroMeansUnbounded pins the opt-out: without a timeout the
// old behavior holds (the read blocks until the transport dies).
func TestCommandTimeoutZeroMeansUnbounded(t *testing.T) {
	c, server := newNetPair(t)

	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()

	done := make(chan error, 1)
	go func() {
		_, err := c.RunArgs([]string{"/system/resource/print"})
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("unbounded command returned early: %v", err)
	case <-time.After(400 * time.Millisecond):
		// Still blocked, as it always was. Unblock it the way Close does.
		_ = server.Close()
	}
	err := <-done
	require.Error(t, err)
	require.False(t, errors.Is(err, os.ErrDeadlineExceeded), "must not be a deadline error")
}
