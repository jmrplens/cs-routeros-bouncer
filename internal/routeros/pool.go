package routeros

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// Pool manages a set of RouterOS API connections for concurrent operations.
type Pool struct {
	cfg       config.MikroTikConfig
	size      int
	conns     chan *Client
	logger    zerolog.Logger
	once      sync.Once
	mu        sync.Mutex // guards closed against Put
	closed    bool
	newClient func(config.MikroTikConfig) *Client // injectable for testing

	ownerPrefix string // handed to every client, see Client.SetOwnerPrefix
}

// SetOwnerPrefix sets the owner prefix of the clients Connect opens. Call it
// before Connect.
func (p *Pool) SetOwnerPrefix(prefix string) {
	p.ownerPrefix = prefix
}

// OwnerPrefix returns the prefix set with SetOwnerPrefix.
func (p *Pool) OwnerPrefix() string {
	return p.ownerPrefix
}

// NewPool creates a pool of n RouterOS client connections.
func NewPool(cfg config.MikroTikConfig, size int) *Pool {
	if size < 1 {
		size = 1
	}
	return &Pool{
		cfg:       cfg,
		size:      size,
		conns:     make(chan *Client, size),
		logger:    log.With().Str("component", "routeros-pool").Logger(),
		newClient: NewClient,
	}
}

// Connect initializes all pool connections.
func (p *Pool) Connect() error {
	if p.newClient == nil {
		p.newClient = NewClient
	}
	for i := range p.size {
		c := p.newClient(p.cfg)
		if c == nil {
			p.Close()
			return fmt.Errorf("pool connection %d: newClient returned nil client", i)
		}
		c.SetOwnerPrefix(p.ownerPrefix)
		if err := c.Connect(); err != nil {
			p.Close()
			return fmt.Errorf("pool connection %d: %w", i, err)
		}
		p.conns <- c
	}
	p.logger.Info().Int("size", p.size).Msg("connection pool ready")
	return nil
}

// Get borrows a client from the pool (blocks if none available).
func (p *Pool) Get() *Client {
	return <-p.conns
}

// Put returns a client to the pool. It closes the client instead once the
// pool is closed, or when the pool is full and has no room for it.
func (p *Pool) Put(c *Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		c.Close()
		return
	}
	select {
	case p.conns <- c:
	default:
		c.Close()
	}
}

// Close closes all pool connections.
func (p *Pool) Close() {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		close(p.conns)
		p.mu.Unlock()
		for c := range p.conns {
			c.Close()
		}
	})
}

// Size returns the pool size.
func (p *Pool) Size() int {
	return p.size
}

// ErrPoolClosed reports an item ParallelExec could not run because the pool
// yielded no client.
var ErrPoolClosed = errors.New("routeros connection pool closed")

// ParallelExec runs fn concurrently using pool connections, as
// ParallelExecContext without a context.
func ParallelExec[T any](pool *Pool, items []T, fn func(c *Client, item T) error) []error {
	return ParallelExecContext(context.Background(), pool, items, fn)
}

// ParallelExecContext runs fn concurrently using pool connections. items is
// split across pool workers; errors are collected but don't stop other
// workers. Once ctx is done the workers take no more items. Every item left
// untaken, also when the pool is closed and yields no client, is reported as
// an error of its own (ctx.Err(), else ErrPoolClosed) without calling fn.
func ParallelExecContext[T any](ctx context.Context, pool *Pool, items []T, fn func(c *Client, item T) error) []error {
	if len(items) == 0 {
		return nil
	}

	workers := min(pool.Size(), len(items))

	work := make(chan T, len(items))
	for _, item := range items {
		work <- item
	}
	close(work)

	var mu sync.Mutex
	var errs []error
	var wg sync.WaitGroup

	for range workers {
		wg.Go(func() {
			c := pool.Get()
			if c == nil {
				return
			}
			defer pool.Put(c)
			for ctx.Err() == nil {
				item, ok := <-work
				if !ok {
					return
				}
				if err := fn(c, item); err != nil {
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
				}
			}
		})
	}
	wg.Wait()

	cause := ctx.Err()
	if cause == nil {
		cause = ErrPoolClosed
	}
	for range work {
		errs = append(errs, cause)
	}
	return errs
}

// AddAddresses adds address-list entries concurrently through the pool, one
// API call each, never through a script. It counts every entry AddAddress
// accepts, including one the router already had, whose timeout and comment
// AddAddress refreshes, as AddAddressesEach does, and returns the entries whose
// add failed. It sets ID on every entry it adds.
// Once ctx is done no more entries are added; those left are failed too.
func (p *Pool) AddAddresses(ctx context.Context, proto, list string, entries []BulkEntry) (added int, failed []BulkEntry, errs []error) {
	var count atomic.Int64
	var mu sync.Mutex
	indices := make([]int, len(entries))
	for i := range indices {
		indices[i] = i
	}
	// Each index is written by the one worker that takes it and read after
	// ParallelExecContext has returned.
	taken := make([]bool, len(entries))
	errs = ParallelExecContext(ctx, p, indices, func(c *Client, i int) error {
		taken[i] = true
		entry := &entries[i]
		id, err := c.AddAddress(proto, list, entry.Address, entry.Timeout, entry.Comment)
		if err != nil {
			if isDuplicateEntryError(err) {
				return nil
			}
			mu.Lock()
			failed = append(failed, *entry)
			mu.Unlock()
			return err
		}
		entry.ID = id // each worker writes only the index it took
		count.Add(1)
		return nil
	})
	for i, entry := range entries {
		if !taken[i] {
			failed = append(failed, entry)
		}
	}
	return int(count.Load()), failed, errs
}

// RemoveAddresses removes address-list entries concurrently through the pool.
// Once ctx is done no further entry is removed; each one left is reported
// with ctx's error.
func (p *Pool) RemoveAddresses(ctx context.Context, proto string, entries []AddressEntry) []error {
	return ParallelExecContext(ctx, p, entries, func(c *Client, entry AddressEntry) error {
		return c.RemoveAddress(proto, entry.ID)
	})
}
