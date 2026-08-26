package routeros

import (
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jmrplens/cs-routeros-bouncer/internal/rosapi/proto"
)

// Pruned relative to upstream v3.0.1: TestAsyncTwice, TestRunWithListen,
// TestProtoRunAsync, TestRunEOFAsync and TestListen exercised the async/listen
// mode, which this vendored copy removes outright — see PRUNED.md.

func TestRandomData(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	defer deferCloser(t, c)

	go func() {
		defer deferCloser(t, s)

		randomBytes := make([]byte, 1024)
		_, err := rand.Read(randomBytes)
		require.NoError(t, err, "read random bytes error")

		s.readSentence(t, "/login @ [{`name` `userTest`} {`password` `passTest`}]")
		s.writeSentence(t, "!done", string(randomBytes))
	}()

	err := c.Login("userTest", "passTest")
	require.Error(t, err)
}

func TestLoginPre643(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	defer deferCloser(t, c)

	go func() {
		defer deferCloser(t, s)
		s.readSentence(t, "/login @ [{`name` `userTest`} {`password` `passTest`}]")
		s.writeSentence(t, "!done", "=ret=abc123")
		s.readSentence(t, "/login @ [{`name` `userTest`} {`response` `0021277bff9ac7caf06aa608e46616d47f`}]")
		s.writeSentence(t, "!done")
	}()

	err := c.Login("userTest", "passTest")
	require.NoError(t, err)
}

func TestLoginPost643(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	defer deferCloser(t, c)

	go func() {
		defer deferCloser(t, s)
		s.readSentence(t, "/login @ [{`name` `userTest`} {`password` `passTest`}]")
		s.writeSentence(t, "!done")
	}()

	err := c.Login("userTest", "passTest")
	require.NoError(t, err)
}

func TestLoginIncorrectPre643(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	defer deferCloser(t, c)

	go func() {
		defer deferCloser(t, s)
		s.readSentence(t, "/login @ [{`name` `userTest`} {`password` `passTest`}]")
		s.writeSentence(t, "!done", "=ret=abc123")
		s.readSentence(t, "/login @ [{`name` `userTest`} {`response` `0021277bff9ac7caf06aa608e46616d47f`}]")
		s.writeSentence(t, "!trap", "=message=incorrect login")
		s.writeSentence(t, "!done")
	}()

	err := c.Login("userTest", "passTest")
	require.Error(t, err, "Login succeeded; want error")

	var top *DeviceError
	require.Truef(t, errors.As(err, &top), "want=DeviceError, have=%#v", err)
	require.Contains(t, []string{"incorrect login"}, top.fetchMessage())
}

func TestLoginIncorrectPost643(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	defer deferCloser(t, c)

	go func() {
		defer deferCloser(t, s)
		s.readSentence(t, "/login @ [{`name` `userTest`} {`password` `passTest`}]")
		s.writeSentence(t, "!trap", "=message=invalid user name or password (6)")
		s.writeSentence(t, "!done")
	}()

	err := c.Login("userTest", "passTest")
	require.Error(t, err, "Login succeeded; want error")

	var top *DeviceError
	require.Truef(t, errors.As(err, &top), "want=DeviceError, have=%#v", err)
	require.Contains(t, []string{"invalid user name or password (6)"}, top.fetchMessage())
}

func TestLoginNoChallenge(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	defer deferCloser(t, c)

	go func() {
		defer deferCloser(t, s)
		s.readSentence(t, "/login @ [{`name` `userTest`} {`password` `passTest`}]")
		s.writeSentence(t, "!done")
	}()

	require.NoError(t, c.Login("userTest", "passTest"))
}

func TestLoginInvalidChallenge(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	defer deferCloser(t, c)

	go func() {
		defer deferCloser(t, s)
		s.readSentence(t, "/login @ [{`name` `userTest`} {`password` `passTest`}]")
		s.writeSentence(t, "!done", "=ret=Invalid Hex String")
	}()

	err := c.Login("userTest", "passTest")
	require.Error(t, err, "Login succeeded; want error")
	require.Truef(t, errors.Is(err, ErrInvalidChallengeReceived),
		"want=ErrInvalidChallengeReceived, have=%#v", err)
}

func TestLoginEOF(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	defer deferCloser(t, c)
	require.NoError(t, s.Close())

	err := c.Login("userTest", "passTest")
	require.Error(t, err, "Login succeeded; want error")
	require.EqualError(t, err, io.ErrClosedPipe.Error())
}

func TestCloseTwice(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	defer deferCloser(t, s)
	require.NoError(t, c.Close())
	require.NoError(t, c.Close())
}

func TestProtoRun(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	defer deferCloser(t, c)

	go func() {
		defer deferCloser(t, s)
		s.readSentence(t, "/ip/address @ []")
		s.writeSentence(t, "!re", "=address=1.2.3.4/32")
		s.writeSentence(t, "!done")
	}()

	sen, err := c.Run("/ip/address")
	require.NoError(t, err)

	want := "!re @ [{`address` `1.2.3.4/32`}]\n!done @ []"
	require.Equal(t, want, sen.String(), "for /ip/address")
}

func TestRunEmptySentence(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	defer deferCloser(t, c)

	go func() {
		defer deferCloser(t, s)
		s.readSentence(t, "/ip/address @ []")
		s.writeSentence(t)
		s.writeSentence(t, "!re", "=address=1.2.3.4/32")
		s.writeSentence(t, "!done")
	}()

	sen, err := c.Run("/ip/address")
	require.NoError(t, err)

	want := "!re @ [{`address` `1.2.3.4/32`}]\n!done @ []"
	require.Equal(t, want, sen.String(), "for /ip/address")
}

func TestRunEOF(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	defer deferCloser(t, c)

	go func() {
		defer deferCloser(t, s)
		s.readSentence(t, "/ip/address @ []")
	}()

	_, err := c.Run("/ip/address")
	require.Error(t, err, "Run succeeded; want error")
	require.Truef(t, errors.Is(err, io.EOF), "want=io.EOF, have=%#v", err)
}

func TestRunInvalidSentence(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	defer deferCloser(t, c)

	go func() {
		defer deferCloser(t, s)
		s.readSentence(t, "/ip/address @ []")
		s.writeSentence(t, "!xxx")
	}()

	_, err := c.Run("/ip/address")
	require.Error(t, err, "Run succeeded; want error")

	var unkErr *UnknownReplyError
	require.Truef(t, errors.As(err, &unkErr), "want=UnknownReplyError, have=%#v", err)
	require.Equal(t, unkErr.Sentence.Word, "!xxx")
}

func TestRunTrap(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	defer deferCloser(t, c)

	go func() {
		defer deferCloser(t, s)
		s.readSentence(t, "/ip/address @ []")
		s.writeSentence(t, "!trap", "=message=Some device error message")
		s.writeSentence(t, "!done")
	}()

	_, err := c.Run("/ip/address")
	require.Error(t, err, "Run succeeded; want error")

	var devErr *DeviceError
	require.Truef(t, errors.As(err, &devErr), "want=DeviceError, have=%#v", err)
	require.Equal(t, devErr.fetchMessage(), "Some device error message")
}

func TestRunTrapWithoutMessage(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	defer deferCloser(t, c)

	go func() {
		defer deferCloser(t, s)
		s.readSentence(t, "/ip/address @ []")
		s.writeSentence(t, "!trap", "=some=unknown key")
		s.writeSentence(t, "!done")
	}()

	_, err := c.Run("/ip/address")
	require.Error(t, err, "Run succeeded; want error")

	var devErr *DeviceError
	require.Truef(t, errors.As(err, &devErr), "want=DeviceError, have=%#v", err)
	require.Equal(t, devErr.fetchMessage(), "unknown error: !trap @ [{`some` `unknown key`}]")
}

func TestRunFatal(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	defer deferCloser(t, c)

	go func() {
		defer deferCloser(t, s)
		s.readSentence(t, "/ip/address @ []")
		s.writeSentence(t, fatalSentence, "=message=Some device error message")
	}()

	_, err := c.Run("/ip/address")
	require.Error(t, err, "Run succeeded; want error")

	var devErr *DeviceError
	require.Truef(t, errors.As(err, &devErr), "want=DeviceError, have=%#v", err)
	require.Equal(t, devErr.fetchMessage(), "Some device error message")
}

func TestRunAfterClose(t *testing.T) {
	t.Helper()
	c, s := newPair(t)
	require.NoError(t, c.Close())
	require.NoError(t, s.Close())

	_, err := c.Run("/ip/address")
	require.Error(t, err, "Run succeeded; want error")
	require.EqualError(t, err, io.EOF.Error())
}

type conn struct {
	*io.PipeReader
	*io.PipeWriter
}

func (c *conn) Close() error {
	if err := c.PipeReader.Close(); err != nil {
		return err
	}

	return c.PipeWriter.Close()
}

func newPair(t *testing.T) (*Client, *fakeServer) {
	t.Helper()
	ar, aw := io.Pipe()
	br, bw := io.Pipe()

	c, err := NewClient(&conn{ar, bw})
	require.NoError(t, err)

	return c, &fakeServer{
		proto.NewReader(br),
		proto.NewWriter(aw),
		&conn{br, aw},
	}
}

type fakeServer struct {
	r proto.Reader
	w proto.Writer
	io.Closer
}

func (f *fakeServer) readSentence(t *testing.T, want string) {
	t.Helper()
	sen, err := f.r.ReadSentence()
	require.NoError(t, err)
	require.Equal(t, want, sen.String(), "wrong sentence")
	t.Logf("< %s\n", sen)
}

func (f *fakeServer) writeSentence(t *testing.T, sentence ...string) {
	t.Helper()
	t.Logf("> %#q\n", sentence)
	f.w.BeginSentence()
	for _, word := range sentence {
		f.w.WriteWord(word)
	}

	require.NoError(t, f.w.EndSentence())
}
