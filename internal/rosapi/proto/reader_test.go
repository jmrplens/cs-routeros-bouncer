package proto

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadLength(t *testing.T) {
	for i, d := range []struct {
		length   int64
		rawBytes []byte
	}{
		{0x00000001, []byte{0x01}},
		{0x00000087, []byte{0x80, 0x87}},
		{0x00004321, []byte{0xC0, 0x43, 0x21}},
		{0x002acdef, []byte{0xE0, 0x2a, 0xcd, 0xef}},
		{0x10000080, []byte{0xF0, 0x10, 0x00, 0x00, 0x80}},
	} {
		t.Run(fmt.Sprintf("#%d length=%d", i, d.length), func(t *testing.T) {
			r := NewReader(bytes.NewBuffer(d.rawBytes)).(*reader)
			l, err := r.readLength()
			require.NoError(t, err, "read length error")
			require.Equal(t, d.length, l, "expected length is wrong")
		})
	}
}

func TestReadRandom(t *testing.T) {
	// Upstream fed 4 random bytes and required no error — but a first byte in
	// 0xF0..0xF7 makes readLength ask for FOUR more bytes, and only three
	// remain: an ~3% random failure. Five bytes cover the longest encoding.
	randomBytes := make([]byte, 5)
	_, err := rand.Read(randomBytes)
	require.NoError(t, err, "read random bytes error")

	r := NewReader(bytes.NewBuffer(randomBytes)).(*reader)
	_, err = r.readLength()
	require.NoError(t, err, "read length error")
}

func TestReadWordRejectsOversizedLength(t *testing.T) {
	// 0xF0 prefix + 0xFFFFFFFF: a declared 4 GiB word. Must fail BEFORE the
	// allocation, with the bounded protocol error, not with an OOM attempt.
	r := NewReader(bytes.NewBuffer([]byte{0xF0, 0xFF, 0xFF, 0xFF, 0xFF})).(*reader)
	_, err := r.readWord()
	require.ErrorIs(t, err, errWordTooLong)
}
