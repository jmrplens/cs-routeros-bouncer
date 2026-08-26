package routeros

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
	"github.com/jmrplens/cs-routeros-bouncer/internal/rosapi/proto"
)

// fakeLAPIServer accepts one connection and answers the post-6.43 login with
// !done, which is all Dial needs to succeed. It runs over real TCP so the
// production dial path — including the command-timeout wiring — is exercised
// end to end rather than through a mock.
func fakeLoginServer(t *testing.T, ln net.Listener, wrap func(net.Conn) net.Conn) {
	t.Helper()
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		if wrap != nil {
			conn = wrap(conn)
		}
		r := proto.NewReader(conn)
		w := proto.NewWriter(conn)
		for {
			if _, readErr := r.ReadSentence(); readErr != nil {
				return
			}
			w.BeginSentence()
			w.WriteWord("!done")
			if endErr := w.EndSentence(); endErr != nil {
				return
			}
		}
	}()
}

func TestDefaultDialPlain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	fakeLoginServer(t, ln, nil)

	conn, err := defaultDial(config.MikroTikConfig{
		Address:        ln.Addr().String(),
		Username:       "u",
		Password:       "p",
		CommandTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// The dial wired the timeout: a live command still works inside it.
	_, err = conn.RunArgs([]string{"/system/identity/print"})
	require.NoError(t, err)
}

func TestDefaultDialTLS(t *testing.T) {
	// A throwaway self-signed cert; the client dials with TLSInsecure, which
	// is exactly the RouterOS-ships-a-self-signed-cert scenario the config
	// comment describes.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "router-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	fakeLoginServer(t, ln, nil)

	conn, err := defaultDial(config.MikroTikConfig{
		Address:        ln.Addr().String(),
		Username:       "u",
		Password:       "p",
		TLS:            true,
		TLSInsecure:    true,
		CommandTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = conn.RunArgs([]string{"/system/identity/print"})
	require.NoError(t, err)
}
