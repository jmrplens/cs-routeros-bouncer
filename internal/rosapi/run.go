package routeros

import (
	"context"
	"log/slog"
)

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
	c.logger().Debug("RunArgsContext", slog.Any("sentences", sentences))

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
