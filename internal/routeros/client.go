package routeros

import (
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/go-routeros/routeros/v3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// Client wraps the RouterOS API connection with reconnection logic.
type Client struct {
	cfg    config.MikroTikConfig
	conn   *routeros.Client
	mu     sync.Mutex
	logger zerolog.Logger
}

// NewClient creates a new RouterOS API client.
func NewClient(cfg config.MikroTikConfig) *Client {
	return &Client{
		cfg:    cfg,
		logger: log.With().Str("component", "routeros").Logger(),
	}
}

// Connect establishes a connection to the RouterOS device.
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connectLocked()
}

// connectLocked does the actual connection work. Caller must hold c.mu.
func (c *Client) connectLocked() error {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}

	c.logger.Info().
		Str("address", c.cfg.Address).
		Bool("tls", c.cfg.TLS).
		Msg("connecting to RouterOS")

	var conn *routeros.Client
	var err error

	if c.cfg.TLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: c.cfg.TLSInsecure, //nolint:gosec // G402: user-configurable option for self-signed certs
		}
		conn, err = routeros.DialTLS(c.cfg.Address, c.cfg.Username, c.cfg.Password, tlsConfig)
	} else {
		conn, err = routeros.Dial(c.cfg.Address, c.cfg.Username, c.cfg.Password)
	}

	if err != nil {
		return fmt.Errorf("connecting to RouterOS at %s: %w", c.cfg.Address, err)
	}

	c.conn = conn
	c.logger.Info().Msg("connected to RouterOS")
	return nil
}

// Close closes the RouterOS API connection.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
		c.logger.Info().Msg("RouterOS connection closed")
	}
}

// IsConnected returns true if a connection is active.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// Reconnect closes the current connection and establishes a new one.
func (c *Client) Reconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	return c.connectLocked()
}

// ensureConnected checks if connected and reconnects if needed.
// Caller must hold c.mu.
func (c *Client) ensureConnected() error {
	if c.conn == nil {
		return c.connectLocked()
	}
	return nil
}

// Run executes a RouterOS API command and returns the reply.
// Automatically reconnects on connection failure.
func (c *Client) Run(args ...string) (*routeros.Reply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureConnected(); err != nil {
		return nil, err
	}

	reply, err := c.conn.RunArgs(args)
	if err != nil {
		// Try reconnect once
		c.logger.Warn().Err(err).Msg("RouterOS command failed, attempting reconnect")
		_ = c.conn.Close()
		c.conn = nil

		if err := c.ensureConnected(); err != nil {
			return nil, fmt.Errorf("reconnect failed: %w", err)
		}

		reply, err = c.conn.RunArgs(args)
		if err != nil {
			return nil, fmt.Errorf("command failed after reconnect: %w", err)
		}
	}

	return reply, nil
}

// Add creates a new resource at the given path with the specified attributes.
// Returns the `.id` of the created resource.
func (c *Client) Add(path string, attrs map[string]string) (string, error) {
	args := make([]string, 0, 1+len(attrs))
	args = append(args, path+"/add")
	for k, v := range attrs {
		args = append(args, "="+k+"="+v)
	}

	reply, err := c.Run(args...)
	if err != nil {
		return "", fmt.Errorf("add %s: %w", path, err)
	}

	// The .id is returned in the Done message
	if id, ok := reply.Done.Map["ret"]; ok {
		return id, nil
	}

	return "", nil
}

// Set modifies an existing resource identified by its `.id`.
func (c *Client) Set(path string, id string, attrs map[string]string) error {
	args := make([]string, 0, 2+len(attrs))
	args = append(args, path+"/set", "=numbers="+id)
	for k, v := range attrs {
		args = append(args, "="+k+"="+v)
	}

	_, err := c.Run(args...)
	if err != nil {
		return fmt.Errorf("set %s %s: %w", path, id, err)
	}

	return nil
}

// Remove deletes a resource identified by its `.id`.
func (c *Client) Remove(path string, id string) error {
	_, err := c.Run(path+"/remove", "=numbers="+id)
	if err != nil {
		return fmt.Errorf("remove %s %s: %w", path, id, err)
	}

	return nil
}

// Print lists resources at the given path with optional query filters and property selection.
func (c *Client) Print(path string, query []string, proplist []string) ([]map[string]string, error) {
	args := []string{path + "/print"}

	// Add property list
	if len(proplist) > 0 {
		props := ""
		for i, p := range proplist {
			if i > 0 {
				props += ","
			}
			props += p
		}
		args = append(args, "=.proplist="+props)
	}

	// Add query filters
	args = append(args, query...)

	reply, err := c.Run(args...)
	if err != nil {
		return nil, fmt.Errorf("print %s: %w", path, err)
	}

	results := make([]map[string]string, 0, len(reply.Re))
	for _, re := range reply.Re {
		results = append(results, re.Map)
	}

	return results, nil
}

// Find returns the first resource matching the query, or nil if not found.
func (c *Client) Find(path string, query []string, proplist []string) (map[string]string, error) {
	results, err := c.Print(path, query, proplist)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, nil
	}

	return results[0], nil
}

// Ping sends a simple command to verify the connection is alive.
func (c *Client) Ping() error {
	_, err := c.Run("/system/identity/print")
	if err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}
	return nil
}

// GetIdentity returns the router identity name.
func (c *Client) GetIdentity() (string, error) {
	result, err := c.Find("/system/identity", nil, []string{"name"})
	if err != nil {
		return "", err
	}
	if result == nil {
		return "", fmt.Errorf("no identity found")
	}
	return result["name"], nil
}

// GetAPIMaxSessions queries the router for the API service max-sessions limit.
// Returns 0 if the value cannot be determined (non-fatal).
func (c *Client) GetAPIMaxSessions() int {
	result, err := c.Find("/ip/service", []string{"?name=api"}, []string{"max-sessions"})
	if err != nil {
		c.logger.Warn().Err(err).Msg("could not query API max-sessions")
		return 0
	}
	if result == nil {
		return 0
	}
	val, ok := result["max-sessions"]
	if !ok || val == "" {
		return 0
	}
	var n int
	if _, err := fmt.Sscanf(val, "%d", &n); err != nil {
		return 0
	}
	return n
}

// DurationToMikroTik converts a Go duration to MikroTik timeout format.
// MikroTik format: "1d2h3m4s" or "2h30m" etc.
func DurationToMikroTik(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}

	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	result := ""
	if days > 0 {
		result += fmt.Sprintf("%dd", days)
	}
	if hours > 0 {
		result += fmt.Sprintf("%dh", hours)
	}
	if minutes > 0 {
		result += fmt.Sprintf("%dm", minutes)
	}
	if seconds > 0 || result == "" {
		result += fmt.Sprintf("%ds", seconds)
	}

	return result
}
