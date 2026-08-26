package proto

import (
	"bufio"
	"io"
	"sync/atomic"
)

// ctxReader wraps the connection reader with a closeable gate.
//
// Upstream v3.0.1 dispatched EVERY Read to a fresh goroutine with a channel
// and a copy buffer, so a `select` could race the read against cancellation.
// The parser issues two Reads per API word — a length byte, then the payload —
// which at this bouncer's scale meant ~294,000 goroutine spawns and ~62 MB of
// garbage per reconcile cycle, all to service `Cancel()`: a method only the
// async/listen mode ever called, and that mode is pruned from this vendored
// copy outright. With no caller left, the read is direct.
//
// What survives is Close(): after it, Reads report EOF. The pending-Read case
// needs no goroutine either — routeros.Client.Close() closes the underlying
// net.Conn right after, which unblocks any Read at the socket. Upstream's
// version was also subtly racy here: when `done` fired mid-read it discarded
// the bytes the abandoned goroutine had consumed from the shared bufio.Reader,
// and after Close() a live Read raced a random `select` between io.EOF and the
// real result. The direct form has neither problem.
type ctxReader struct {
	io.Reader
	close atomic.Bool
	done  chan struct{}
}

func (c *ctxReader) Close() {
	// CompareAndSwap, not Load-then-Store: two concurrent Closers could both
	// observe false and both reach close(c.done), and the second one panics.
	if c.close.CompareAndSwap(false, true) {
		close(c.done)
	}
}

func (c *ctxReader) Read(p []byte) (int, error) {
	select {
	case <-c.done:
		return 0, io.EOF
	default:
	}

	return c.Reader.Read(p)
}

// ctxWriter is the write-side twin of ctxReader; same reasoning, smaller
// stakes — writes were a negligible share of the per-cycle cost.
type ctxWriter struct {
	*bufio.Writer
	close atomic.Bool
	done  chan struct{}
}

func (c *ctxWriter) Close() {
	if c.close.CompareAndSwap(false, true) {
		close(c.done)
	}
}

func (c *ctxWriter) Write(p []byte) (int, error) {
	select {
	case <-c.done:
		return 0, io.EOF
	default:
	}

	return c.Writer.Write(p)
}
