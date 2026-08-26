/*
Package routeros is a pure Go client library for accessing Mikrotik devices using the RouterOS API.
*/
package routeros

import (
	"context"
	"crypto/md5" // #nosec G501 -- pre-6.43 RouterOS login is an MD5 challenge; the protocol demands it
	"crypto/tls"
	"encoding/hex"
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

	r proto.Reader
	w proto.Writer
}

var (
	ErrNoChallengeReceived      = errors.New("no ret (challenge) received")
	ErrInvalidChallengeReceived = errors.New("invalid ret (challenge) hex string received")
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
	ret, ok := r.Done.Map["ret"]
	if !ok {
		// Login method post-6.43 one stage, cleartext and no challenge
		if r.Done != nil {
			return nil
		}
		return fmt.Errorf("RouterOS: /login: %w", ErrNoChallengeReceived)
	}

	// Login method pre-6.43 two stages, challenge
	var dec []byte
	if dec, err = hex.DecodeString(ret); err != nil {
		return fmt.Errorf("RouterOS: /login: %w: %w", ErrInvalidChallengeReceived, err)
	}

	_, err = c.RunContext(ctx, "/login", "=name="+username, "=response="+c.challengeResponse(dec, password))

	return err
}

// challengeResponse - prepare MD5 hash for auth challenge response.
// MD5 here is not a cryptographic choice: RouterOS versions before 6.43
// authenticate with an MD5 challenge, and speaking to them requires it.
func (c *Client) challengeResponse(cha []byte, password string) string {
	h := md5.New() // #nosec G401 -- pre-6.43 login challenge, mandated by the protocol
	h.Write([]byte{0})
	h.Write([]byte(password))
	h.Write(cha)
	return fmt.Sprintf("00%x", h.Sum(nil))
}
