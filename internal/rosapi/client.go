/*
Package routeros is a pure Go client library for accessing Mikrotik devices using the RouterOS API.
*/
package routeros

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/jmrplens/cs-routeros-bouncer/internal/rosapi/proto"
)

// Client is a RouterOS API client.
type Client struct {
	Queue int

	log      *slog.Logger
	logMutex sync.Mutex

	rwc     io.ReadWriteCloser
	closing bool
	mu      sync.Mutex
	// cmdMu serializes one whole command (write + reply); see RunArgsContext.
	cmdMu sync.Mutex
	// cmdTimeout bounds one whole command via connection deadlines; zero means
	// no bound. Set through SetCommandTimeout.
	cmdTimeout time.Duration

	r proto.Reader
	w proto.Writer
}

var (
	ErrNoChallengeReceived = errors.New("no ret (challenge) received")
	// ErrLegacyLoginUnsupported reports a pre-6.43 RouterOS asking for its MD5
	// challenge login, which this vendored client no longer speaks.
	ErrLegacyLoginUnsupported = errors.New("RouterOS older than 6.43 wants an MD5 challenge login; this client requires 6.43+ (the bouncer documents 7.x)")
)

var defaultHandler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
	AddSource: true,
	Level:     slog.LevelInfo,
})

// NewClient returns a new Client over rwc. Login must be called.
func NewClient(rwc io.ReadWriteCloser) (*Client, error) {
	return &Client{
		rwc: rwc,
		log: slog.New(defaultHandler),

		r: proto.NewReader(rwc),
		w: proto.NewWriter(rwc),
	}, nil
}

// Dial connects and logs in to a RouterOS device.
func Dial(address, username, password string) (*Client, error) {
	return DialContext(context.Background(), address, username, password)
}

// DialTimeout connects and logs in to a RouterOS device with timeout.
func DialTimeout(address, username, password string, timeout time.Duration) (*Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return DialContext(ctx, address, username, password)
}

// DialContext connects and logs in to a RouterOS device using context.
func DialContext(ctx context.Context, address, username, password string) (*Client, error) {
	conn, err := new(net.Dialer).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("could not connect to router os: %w", err)
	}
	return newClientAndLogin(ctx, conn, username, password)
}

// DialTLS connects and logs in to a RouterOS device using TLS.
func DialTLS(address, username, password string, tlsConfig *tls.Config) (*Client, error) {
	return DialTLSContext(context.Background(), address, username, password, tlsConfig)
}

// DialTLSTimeout connects and logs in to a RouterOS device using TLS with timeout.
func DialTLSTimeout(address, username, password string, tlsConfig *tls.Config, timeout time.Duration) (*Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return DialTLSContext(ctx, address, username, password, tlsConfig)
}

// DialTLSContext connects and logs in to a RouterOS device using TLS and context.
func DialTLSContext(ctx context.Context, address, username, password string, tlsConfig *tls.Config) (*Client, error) {
	conn, err := (&tls.Dialer{Config: tlsConfig}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("could not connect to router os: %w", err)
	}
	return newClientAndLogin(ctx, conn, username, password)
}

// newClientAndLogin - creates a new client with context over specified rwc, then logs in to the RouterOS, returns new client.
func newClientAndLogin(ctx context.Context, rwc io.ReadWriteCloser, username, password string) (*Client, error) {
	c, err := NewClient(rwc)
	if err != nil {
		return nil, fmt.Errorf("could not connect to router os: %w; close: %w", err, rwc.Close())
	}
	err = c.LoginContext(ctx, username, password)
	if err != nil {
		return nil, fmt.Errorf("could not login: %w; close %w", err, c.Close())
	}
	return c, nil
}

func (c *Client) SetLogHandler(handler LogHandler) {
	c.logMutex.Lock()
	c.log = slog.New(handler)
	c.logMutex.Unlock()
}

func (c *Client) logger() *slog.Logger {
	c.logMutex.Lock()
	defer c.logMutex.Unlock()

	return c.log
}

// deadliner is the subset of net.Conn the command timeout needs. Declared
// here so tests can hand in a net.Pipe end and mocks can opt out.
type deadliner interface {
	SetDeadline(t time.Time) error
}

// SetCommandTimeout bounds every subsequent command (write + full reply) with
// a connection deadline. It exists because a RouterOS device that accepts the
// TCP connection and then stalls — mid-reply, or before one — would otherwise
// block a command forever: the sync client has no other cancellation left.
// A zero duration removes the bound. No-op when the transport cannot carry
// deadlines (the mock used in tests, for one).
func (c *Client) SetCommandTimeout(d time.Duration) {
	c.cmdMu.Lock()
	defer c.cmdMu.Unlock()
	c.cmdTimeout = d
}

// Close closes the connection to the RouterOS device.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.r.Close()
	c.w.Close()

	if c.closing {
		return nil
	}

	c.closing = true

	return c.rwc.Close()
}

// Login runs the /login command. Dial and DialTLS call this automatically.
func (c *Client) Login(username, password string) error {
	return c.LoginContext(context.Background(), username, password)
}

// LoginContext runs the /login command. DialContext and DialTLSContext call this automatically.
func (c *Client) LoginContext(ctx context.Context, username, password string) error {
	r, err := c.RunContext(ctx, "/login", "=name="+username, "=password="+password)
	if err != nil {
		return err
	}
	if _, ok := r.Done.Map["ret"]; ok {
		// A `ret` value is the MD5 challenge of the pre-6.43 two-stage login.
		// This vendored copy removes that path outright: the bouncer documents
		// RouterOS 7.x as its floor, 6.43 is from 2018, and answering the
		// challenge means hashing the password with MD5 — the one thing left
		// in this package a security scanner rightly refuses to look away from.
		return fmt.Errorf("RouterOS: /login: %w", ErrLegacyLoginUnsupported)
	}

	if r.Done != nil {
		return nil
	}

	return fmt.Errorf("RouterOS: /login: %w", ErrNoChallengeReceived)
}
