package routeros

import (
	"fmt"
	"sync"

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
	newClient func(config.MikroTikConfig) *Client // injectable for testing
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
	for i := 0; i < p.size; i++ {
		c := p.newClient(p.cfg)
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

// Put returns a client to the pool.
func (p *Pool) Put(c *Client) {
	p.conns <- c
}

// Close closes all pool connections.
func (p *Pool) Close() {
	p.once.Do(func() {
		close(p.conns)
		for c := range p.conns {
			c.Close()
		}
	})
}

// Size returns the pool size.
func (p *Pool) Size() int {
	return p.size
}

// ParallelExec runs fn concurrently using pool connections.
// items is split across pool workers; errors are collected but don't stop other workers.
func ParallelExec[T any](pool *Pool, items []T, fn func(c *Client, item T) error) []error {
	if len(items) == 0 {
		return nil
	}

	workers := pool.Size()
	if workers > len(items) {
		workers = len(items)
	}

	work := make(chan T, len(items))
	for _, item := range items {
		work <- item
	}
	close(work)

	var mu sync.Mutex
	var errs []error
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := pool.Get()
			defer pool.Put(c)
			for item := range work {
				if err := fn(c, item); err != nil {
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()
	return errs
}
