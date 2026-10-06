package routeros

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// redactSecrets masks the value of any word that carries a credential, so a
// debug-level logger never writes the RouterOS password to its output. The
// default handler sits at Info and emits nothing; this guards the day someone
// turns Debug on to chase a protocol problem.
func redactSecrets(sentences []string) []string {
	out := make([]string, len(sentences))
	for i, sentence := range sentences {
		switch {
		case strings.HasPrefix(sentence, "=password="):
			out[i] = "=password=***"
		case strings.HasPrefix(sentence, "=response="):
			out[i] = "=response=***"
		default:
			out[i] = sentence
		}
	}
	return out
}

// Run simply calls RunArgs().
func (c *Client) Run(sentences ...string) (*Reply, error) {
	return c.RunArgs(sentences)
}

// RunContext simply calls RunArgsContext().
func (c *Client) RunContext(ctx context.Context, sentences ...string) (*Reply, error) {
	return c.RunArgsContext(ctx, sentences)
}

// RunArgs sends a sentence to the RouterOS device and waits for the reply.
func (c *Client) RunArgs(sentences []string) (*Reply, error) {
	return c.RunArgsContext(context.Background(), sentences)
}

// RunArgsContext sends a sentence to the RouterOS device and waits for the
// reply. Once ctx is done a blocked write or read ends at once and the error
// wraps ctx's; the reply is then cut short and the connection must not be
// used again. A ctx already done sends nothing.
func (c *Client) RunArgsContext(ctx context.Context, sentences []string) (*Reply, error) {
	c.logger().Debug("RunArgsContext", slog.Any("sentences", redactSecrets(sentences)))

	// One command at a time, held across the reply. Without tags — pruned with
	// the async mode — replies carry nothing to match them to requests, so two
	// concurrent RunArgs on one client could each read the other's reply. The
	// bouncer serializes at its own layer today; this makes the vendored
	// client safe on its own terms rather than by its caller's discipline.
	// Deliberately not c.mu: Close() takes that one, and it must stay able to
	// unblock a pending read by closing the connection under it.
	c.cmdMu.Lock()
	defer c.cmdMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var cd *commandDeadline
	if d, ok := c.rwc.(deadliner); ok && (c.cmdTimeout > 0 || ctx.Done() != nil) {
		cd = &commandDeadline{conn: d, timeout: c.cmdTimeout}
		cd.extend()
		// Cleared on the way out so an idle gap between commands can never
		// trip it. Deferred first, so it runs after stop below.
		defer cd.finish()
		if ctx.Done() != nil {
			stop := context.AfterFunc(ctx, cd.interrupt)
			defer stop()
		}
	}

	c.w.BeginSentence()
	for _, sentence := range sentences {
		c.w.WriteWord(sentence)
	}

	// runArgsContextSync ends the sentence itself. Upstream's async branch,
	// pruned here, was the one that needed to end it early — it had to append
	// a `.tag=` word first.
	reply, err := c.runArgsContextSync(cd)
	if err != nil && ctx.Err() != nil {
		return nil, fmt.Errorf("%w: %w", ctx.Err(), err)
	}
	return reply, err
}

// commandDeadline is the connection deadline of one command. With a command
// timeout it starts at that timeout and moves forward each time a reply
// sentence arrives, so it bounds a router that stops answering, not a long
// reply that keeps coming, such as tens of thousands of address-list entries
// on a slow router. interrupt puts it in the past, which ends a blocked write
// or read at once; finish clears it.
type commandDeadline struct {
	mu      sync.Mutex
	conn    deadliner
	timeout time.Duration
	done    bool // the command ended or was interrupted: extend no more
}

// extend moves the deadline to timeout from now, unless the command is done.
// A nil commandDeadline or a zero timeout does nothing.
func (cd *commandDeadline) extend() {
	if cd == nil || cd.timeout <= 0 {
		return
	}
	cd.mu.Lock()
	defer cd.mu.Unlock()
	if !cd.done {
		_ = cd.conn.SetDeadline(time.Now().Add(cd.timeout))
	}
}

// interrupt ends a blocked write or read of the command at once. It does
// nothing once the command is done, so a late call leaves the connection's
// next command alone.
func (cd *commandDeadline) interrupt() {
	cd.mu.Lock()
	defer cd.mu.Unlock()
	if !cd.done {
		cd.done = true
		_ = cd.conn.SetDeadline(time.Unix(1, 0))
	}
}

// finish clears the deadline when the command ends.
func (cd *commandDeadline) finish() {
	cd.mu.Lock()
	defer cd.mu.Unlock()
	cd.done = true
	_ = cd.conn.SetDeadline(time.Time{})
}

// runArgsContextSync - read command reply in sync mode and return
func (c *Client) runArgsContextSync(cd *commandDeadline) (*Reply, error) {
	if err := c.w.EndSentence(); err != nil {
		return nil, err
	}

	out := new(Reply)

	var lastErr error
	for {
		// read next sentence
		sen, err := c.r.ReadSentence()
		if err != nil {
			return nil, err
		}
		cd.extend()

		switch done, perr := out.processSentence(sen); {
		case perr != nil && done:
			// processed error sentence and it was fatal
			return nil, perr
		case perr != nil:
			// processed error sentence, but it was not fatal, read next, store last error
			lastErr = perr
		case done:
			// processed sentence is Done, return result and last error
			return out, lastErr
		}
	}
}
