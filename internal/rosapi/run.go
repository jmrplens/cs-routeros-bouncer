package routeros

import (
	"context"
	"log/slog"
	"strings"
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

// RunArgsContext sends a sentence to the RouterOS device and waits for the reply.
func (c *Client) RunArgsContext(_ context.Context, sentences []string) (*Reply, error) {
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

	c.w.BeginSentence()
	for _, sentence := range sentences {
		c.w.WriteWord(sentence)
	}

	// runArgsContextSync ends the sentence itself. Upstream's async branch,
	// pruned here, was the one that needed to end it early — it had to append
	// a `.tag=` word first.
	return c.runArgsContextSync()
}

// runArgsContextSync - read command reply in sync mode and return
func (c *Client) runArgsContextSync() (*Reply, error) {
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
