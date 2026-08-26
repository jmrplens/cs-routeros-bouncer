package proto

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"testing"
)

// encodeWord writes one API word with its RouterOS length prefix.
func encodeWord(buf *bytes.Buffer, word string) {
	n := len(word)
	switch {
	case n < 0x80:
		buf.WriteByte(byte(n))
	case n < 0x4000:
		v := uint16(n) | 0x8000
		_ = binary.Write(buf, binary.BigEndian, v)
	default:
		v := uint32(n) | 0xC00000
		buf.Write([]byte{byte(v >> 16), byte(v >> 8), byte(v)})
	}
	buf.WriteString(word)
}

// reply builds the wire form of a full address-list print reply.
func reply(entries int) []byte {
	var buf bytes.Buffer
	for i := range entries {
		encodeWord(&buf, "!re")
		encodeWord(&buf, fmt.Sprintf("=.id=*%X", i+1))
		encodeWord(&buf, fmt.Sprintf("=address=192.0.2.%d", i%254+1))
		encodeWord(&buf, "=comment=crowdsec-bouncer|crowdsec|sshd-bf|2026-08-26T00:00:00Z @cs-routeros-bouncer")
		buf.WriteByte(0)
	}
	encodeWord(&buf, "!done")
	buf.WriteByte(0)
	return buf.Bytes()
}

// TestReaderFingerprintAtScale parses a 22,037-entry reply — the size of the
// production address list the day this was written — and asserts a structural
// fingerprint over every parsed sentence. The direct-read rewrite of ctxReader
// was originally validated against upstream v3.0.1 by exactly this kind of
// differential (SHA-256 identical across all sentences); this pins that shape
// so a future edit that drops, reorders or corrupts words fails loudly instead
// of shipping a parser that is merely fast.
func TestReaderFingerprintAtScale(t *testing.T) {
	const entries = 22037
	r := NewReader(bytes.NewReader(reply(entries)))
	h := sha256.New()
	n := 0
	for {
		sen, err := r.ReadSentence()
		if err != nil {
			t.Fatalf("sentence %d: %v", n, err)
		}
		h.Write([]byte(sen.Word))
		for _, p := range sen.List {
			h.Write([]byte(p.Key))
			h.Write([]byte{0})
			h.Write([]byte(p.Value))
			h.Write([]byte{1})
		}
		if sen.Word == "!done" {
			break
		}
		n++
	}
	if n != entries {
		t.Fatalf("parsed %d entries, want %d", n, entries)
	}
	const want = "f8fd35ee5c26a6b62d9f3c33a20f97ac92dc73951209188b4270a548d6af95fe"
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		t.Fatalf("fingerprint drifted: %s", got)
	}
	t.Logf("fingerprint: %s", got)
}

// TestReaderErrorShapes pins the error semantics the bouncer's reconnect logic
// depends on: a truncated stream is io.ErrUnexpectedEOF (client reconnects),
// and a closed reader reports io.EOF from the gate.
func TestReaderErrorShapes(t *testing.T) {
	full := reply(3)

	t.Run("truncated mid-payload", func(t *testing.T) {
		r := NewReader(bytes.NewReader(full[:len(full)-9]))
		var err error
		for err == nil {
			_, err = r.ReadSentence()
		}
		if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			t.Fatalf("want (Unexpected)EOF, got %T %v", err, err)
		}
	})

	t.Run("closed gate reports EOF", func(t *testing.T) {
		cr := &ctxReader{Reader: bufio.NewReader(bytes.NewReader(full)), done: make(chan struct{})}
		cr.Close()
		if _, err := cr.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("want io.EOF after Close, got %v", err)
		}
		cr.Close() // segunda vez: no debe entrar en panico
	})
}

// BenchmarkReadSentence documents why ctxReader reads directly: upstream
// v3.0.1 spawned a goroutine per Read (~13 per address-list row).
func BenchmarkReadSentence(b *testing.B) {
	wire := reply(1000)
	b.ReportAllocs()
	for b.Loop() {
		r := NewReader(bytes.NewReader(wire))
		for {
			sen, err := r.ReadSentence()
			if err != nil {
				b.Fatal(err)
			}
			if sen.Word == "!done" {
				break
			}
		}
	}
}
