package routeros

import (
	"context"
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

// serveRe answers each command with n `!re` sentences, one every gap, then
// `!done`; with stall it sends the n sentences and then nothing more.
func serveRe(server net.Conn, n int, gap time.Duration, stall bool) {
	r := proto.NewReader(server)
	w := proto.NewWriter(server)
	for {
		if _, err := r.ReadSentence(); err != nil {
			return
		}
		for i := range n {
			time.Sleep(gap)
			w.BeginSentence()
			w.WriteWord("!re")
			w.WriteWord("=.id=*" + string(rune('A'+i)))
			if err := w.EndSentence(); err != nil {
				return
			}
		}
		if stall {
			return
		}
		w.BeginSentence()
		w.WriteWord("!done")
		if err := w.EndSentence(); err != nil {
			return
		}
	}
}

// TestCommandTimeoutExtendsWhileReplyArrives pins that the timeout bounds a
// router that stops answering, not a long reply that keeps coming: a listing
// of tens of thousands of entries on a slow router takes longer than the
// timeout as a whole, and used to fail every time, retry included.
func TestCommandTimeoutExtendsWhileReplyArrives(t *testing.T) {
	c, server := newNetPair(t)
	t.Cleanup(func() { _ = server.Close() })
	c.SetCommandTimeout(200 * time.Millisecond)
	go serveRe(server, 8, 80*time.Millisecond, false) // 640 ms in all

	reply, err := c.RunArgs([]string{"/ip/firewall/address-list/print"})
	require.NoError(t, err, "a reply still arriving must not time out")
	require.Len(t, reply.Re, 8)
}

// TestCommandTimeoutFiresWhenReplyStops pins that a router that stops midway
// through a reply still fails the command once the timeout passes.
func TestCommandTimeoutFiresWhenReplyStops(t *testing.T) {
	c, server := newNetPair(t)
	t.Cleanup(func() { _ = server.Close() })
	c.SetCommandTimeout(150 * time.Millisecond)
	go serveRe(server, 3, 20*time.Millisecond, true)

	start := time.Now()
	_, err := c.RunArgs([]string{"/ip/firewall/address-list/print"})
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Less(t, time.Since(start), 2*time.Second)
}

// TestRunArgsContextCancelEndsBlockedRead pins that a done ctx ends a command
// blocked on its reply at once, also without a command timeout: a shutdown
// during a long listing does not wait for it.
func TestRunArgsContextCancelEndsBlockedRead(t *testing.T) {
	c, server := newNetPair(t)
	t.Cleanup(func() { _ = server.Close() })
	go func() { // drains the command, never answers
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	_, err := c.RunArgsContext(ctx, []string{"/ip/firewall/address-list/print"})
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, time.Since(start), 2*time.Second)
}

// TestRunArgsContextDoneSendsNothing pins that a ctx already done returns its
// error without writing the command.
func TestRunArgsContextDoneSendsNothing(t *testing.T) {
	c, server := newNetPair(t)
	t.Cleanup(func() { _ = server.Close() })
	got := make(chan int, 64)
	go func() { // reads all the time, so a written command lands here
		buf := make([]byte, 4096)
		for {
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			got <- n
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.RunArgsContext(ctx, []string{"/system/identity/print"})
	require.ErrorIs(t, err, context.Canceled)

	select {
	case n := <-got:
		t.Fatalf("%d bytes reached the router", n)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestRunArgsContextLateCancelLeavesNextCommand pins that a ctx done after its
// command ended leaves the connection alone: with no command timeout nothing
// else would clear a deadline it put in the past.
func TestRunArgsContextLateCancelLeavesNextCommand(t *testing.T) {
	c, server := newNetPair(t)
	t.Cleanup(func() { _ = server.Close() })
	go serveRe(server, 1, 0, false)

	ctx, cancel := context.WithCancel(context.Background())
	_, err := c.RunArgsContext(ctx, []string{"/system/identity/print"})
	require.NoError(t, err)
	cancel()
	time.Sleep(20 * time.Millisecond)

	_, err = c.RunArgs([]string{"/system/identity/print"})
	require.NoError(t, err, "the next command must not see the late cancel")
}
