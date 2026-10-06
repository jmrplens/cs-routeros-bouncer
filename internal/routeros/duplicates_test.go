package routeros

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
	routeros "github.com/jmrplens/cs-routeros-bouncer/internal/rosapi"
)

// TestNormalizeAddressMatchesRouterOS pins NormalizeAddress to the form
// RouterOS 7.24.4 stores and lists each address in (checked on a CHR): a
// decision and the entry it became must compare equal, or the reconciliation
// removes and adds the entry again on every pass. Each RouterOS form must map
// to itself, as the listing does.
func TestNormalizeAddressMatchesRouterOS(t *testing.T) {
	cases := []struct{ in, proto, routeros string }{
		{"198.51.100.7/24", "ip", "198.51.100.0/24"},
		{"198.51.100.1/32", "ip", "198.51.100.1"},
		{"198.51.100.2", "ip", "198.51.100.2"},
		{"10.0.0.0/8", "ip", "10.0.0.0/8"},
		{"2001:db8::1", "ipv6", "2001:db8::1/128"},
		{"2001:DB8:0:0::2", "ipv6", "2001:db8::2/128"},
		{"2001:db8::3/128", "ipv6", "2001:db8::3/128"},
		{"2001:db8:1::5/64", "ipv6", "2001:db8:1::/64"},
		{"2001:0db8:0002::/48", "ipv6", "2001:db8:2::/48"},
		{"::ffff:198.51.100.9", "ipv6", "::ffff:198.51.100.9/128"},
		{"2001:db8::ffff:1.2.3.4", "ipv6", "2001:db8::ffff:102:304/128"},
		// CrowdSec gives an IPv4-mapped address proto ip, and the IPv4 list
		// refuses the mapped form.
		{"::ffff:198.51.100.9", "ip", "198.51.100.9"},
		{"::ffff:198.51.100.0/120", "ip", "198.51.100.0/24"},
		// Not an address: left as it was.
		{"not-an-address", "ip", "not-an-address"},
	}
	for _, tc := range cases {
		if got := NormalizeAddress(tc.in, tc.proto); got != tc.routeros {
			t.Errorf("NormalizeAddress(%q, %q) = %q, RouterOS lists %q", tc.in, tc.proto, got, tc.routeros)
		}
		if got := NormalizeAddress(tc.routeros, tc.proto); got != tc.routeros {
			t.Errorf("NormalizeAddress(%q, %q) = %q, want the RouterOS form unchanged", tc.routeros, tc.proto, got)
		}
	}
}

// lookupQueries returns the address-list prints among the recorded calls.
func lookupQueries(mc *mockConn) [][]string {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	var out [][]string
	for _, call := range mc.calls {
		if strings.HasSuffix(call[0], "/address-list/print") {
			out = append(out, call)
		}
	}
	return out
}

// TestAddAddressesEach_DuplicatesFoundTogether verifies that the duplicates of
// a per-entry pass are found with one lookup, not one each: RouterOS walks
// the whole list for every lookup, about 1 s at 60,000 entries on a virtual
// router. Owned ones are refreshed and counted with their ids; a foreign one
// and one the lookup does not return fail.
func TestAddAddressesEach_DuplicatesFoundTogether(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	c.ownerPrefix = "crowdsec-bouncer"
	entries := []BulkEntry{
		{Address: "10.0.0.1", Timeout: "1h", Comment: "crowdsec-bouncer|a"},
		{Address: "10.0.0.2", Timeout: "1h", Comment: "crowdsec-bouncer|b"},
		{Address: "10.0.0.3", Timeout: "1h", Comment: "crowdsec-bouncer|c"},
		{Address: "10.0.0.4", Timeout: "1h", Comment: "crowdsec-bouncer|d"},
		{Address: "10.0.0.5", Timeout: "1h", Comment: "crowdsec-bouncer|e"},
	}
	mc.pushError(newDuplicateDeviceError())                  // 10.0.0.1: ours
	mc.pushReply(doneReply(map[string]string{"ret": "*B2"})) // 10.0.0.2: added
	mc.pushError(newDuplicateDeviceError())                  // 10.0.0.3: foreign
	mc.pushError(newDuplicateDeviceError())                  // 10.0.0.4: not returned
	mc.pushError(newDuplicateDeviceError())                  // 10.0.0.5: ours
	mc.pushReply(reReply(
		map[string]string{".id": "*A1", "address": "10.0.0.1", "comment": "crowdsec-bouncer|old"},
		map[string]string{".id": "*A3", "address": "10.0.0.3", "comment": "manual"},
		map[string]string{".id": "*A5", "address": "10.0.0.5", "comment": "crowdsec-bouncer|old"},
	))
	mc.pushReply(emptyReply()) // refresh 10.0.0.1
	mc.pushReply(emptyReply()) // refresh 10.0.0.5

	added, failed, err := c.AddAddressesEach(context.Background(), "ip", "crowdsec", entries)

	if added != 3 || len(failed) != 2 {
		t.Fatalf("expected 3 added (one new, two refreshed) and 2 failed, got %d added, %+v", added, failed)
	}
	if !errors.Is(err, ErrDuplicateReportedButNotFound) {
		t.Fatalf("expected the not-found duplicate in the error, got %v", err)
	}
	if entries[0].ID != "*A1" || entries[1].ID != "*B2" || entries[4].ID != "*A5" {
		t.Fatalf("expected the ids *A1, *B2, *A5, got %q, %q, %q", entries[0].ID, entries[1].ID, entries[4].ID)
	}
	lookups := lookupQueries(mc)
	if len(lookups) != 1 {
		t.Fatalf("expected one lookup for the four duplicates, got %d", len(lookups))
	}
	want := []string{"?list=crowdsec", "?address=10.0.0.1", "?address=10.0.0.3", "?address=10.0.0.4", "?address=10.0.0.5", "?#|||&"}
	if q := lookups[0]; !slices.Equal(q[len(q)-len(want):], want) {
		t.Fatalf("expected the OR'd query %v, got %v", want, q)
	}
}

// TestBulkAddAddresses_DuplicatesOfAllChunksFoundTogether verifies that the
// duplicates the scripts report are looked up once for the whole bulk add, not
// once per chunk: on a virtual router 45 duplicates spread over a 60,000-entry
// load fell into 45 chunks and took 31 s instead of 13 s.
func TestBulkAddAddresses_DuplicatesOfAllChunksFoundTogether(t *testing.T) {
	mc := newMockConn()
	c := newExecuteTestClient(mc)
	entries := make([]BulkEntry, bulkChunkSize+50)
	for i := range entries {
		entries[i] = BulkEntry{Address: fmt.Sprintf("10.1.%d.%d", i/250, i%250+1), Timeout: "1h"}
	}
	pushRun(mc, bulkDoneMarker+"5,")
	mc.pushError(newDuplicateDeviceError()) // chunk 1, entry 5
	pushRun(mc, bulkDoneMarker+"10,")
	mc.pushError(newDuplicateDeviceError()) // chunk 2, entry 10
	mc.pushReply(reReply(
		map[string]string{".id": "*D1", "address": entries[5].Address},
		map[string]string{".id": "*D2", "address": entries[bulkChunkSize+10].Address},
	))
	mc.pushReply(emptyReply())
	mc.pushReply(emptyReply())

	added, failed, err := c.BulkAddAddresses(context.Background(), "ip", "crowdsec", entries)

	if err != nil || added != len(entries) || len(failed) != 0 {
		t.Fatalf("expected all %d added, got %d, %+v, %v", len(entries), added, failed, err)
	}
	if got := len(lookupQueries(mc)); got != 1 {
		t.Fatalf("expected one lookup for the duplicates of both chunks, got %d", got)
	}
	if entries[5].ID != "*D1" || entries[bulkChunkSize+10].ID != "*D2" {
		t.Fatalf("expected the refreshed ids *D1 and *D2, got %q and %q", entries[5].ID, entries[bulkChunkSize+10].ID)
	}
}

// TestAddAddressesEach_DuplicateLookupBatches verifies that a lookup asks for
// at most duplicateLookupBatch addresses.
func TestAddAddressesEach_DuplicateLookupBatches(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	n := duplicateLookupBatch + 1
	entries := make([]BulkEntry, n)
	var first, second []map[string]string
	for i := range entries {
		addr := fmt.Sprintf("10.0.%d.%d", i/250, i%250+1)
		entries[i] = BulkEntry{Address: addr}
		mc.pushError(newDuplicateDeviceError())
		row := map[string]string{".id": fmt.Sprintf("*%X", i+1), "address": addr}
		if i < duplicateLookupBatch {
			first = append(first, row)
		} else {
			second = append(second, row)
		}
	}
	mc.pushReply(reReply(first...))
	mc.pushReply(reReply(second...))

	added, failed, err := c.AddAddressesEach(context.Background(), "ip", "crowdsec", entries)

	if err != nil || added != n || len(failed) != 0 {
		t.Fatalf("expected all %d refreshed, got %d, %+v, %v", n, added, failed, err)
	}
	if got := len(lookupQueries(mc)); got != 2 {
		t.Fatalf("expected 2 lookups for %d duplicates, got %d", n, got)
	}
}

// cancelOnCall is a mock connection that cancels a context on its nth
// command, after answering it.
type cancelOnCall struct {
	*mockConn
	n      int
	cancel context.CancelFunc
}

func (c *cancelOnCall) RunArgs(args []string) (*routeros.Reply, error) {
	reply, err := c.mockConn.RunArgs(args)
	if c.callCount() == c.n {
		c.cancel()
	}
	return reply, err
}

// TestAddAddressesEach_ShutdownLeavesDuplicates verifies that duplicates are
// not looked up once the context is done: the lookup walks the whole list, and
// a shutdown should not wait for it. They are failed, for the next pass.
func TestAddAddressesEach_ShutdownLeavesDuplicates(t *testing.T) {
	mc := newMockConn()
	ctx, cancel := context.WithCancel(context.Background())
	conn := &cancelOnCall{mockConn: mc, n: 2, cancel: cancel} // done during the last add
	c := &Client{conn: conn, dialFunc: func(_ config.MikroTikConfig) (RouterConn, error) { return conn, nil }}
	entries := []BulkEntry{{Address: "10.0.0.1"}, {Address: "10.0.0.2"}}
	mc.pushError(newDuplicateDeviceError())
	mc.pushError(newDuplicateDeviceError())

	added, failed, err := c.AddAddressesEach(ctx, "ip", "crowdsec", entries)

	if added != 0 || len(failed) != 2 || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected both duplicates failed with the context's error, got %d, %+v, %v", added, failed, err)
	}
	if got := len(lookupQueries(mc)); got != 0 {
		t.Fatalf("expected no lookup after a shutdown, got %d", got)
	}
}

// TestPoolAddAddresses_DuplicatesFoundTogether verifies that the pooled adds
// find their duplicates with one lookup per batch too.
func TestPoolAddAddresses_DuplicatesFoundTogether(t *testing.T) {
	mc := newMockConn()
	p := NewPool(config.MikroTikConfig{}, 1) // one client: the replies come in order
	p.newClient = func(_ config.MikroTikConfig) *Client {
		return &Client{dialFunc: func(_ config.MikroTikConfig) (RouterConn, error) { return mc, nil }}
	}
	if err := p.Connect(); err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	t.Cleanup(p.Close)
	entries := []BulkEntry{{Address: "10.0.0.1", Timeout: "1h"}, {Address: "10.0.0.2", Timeout: "1h"}, {Address: "10.0.0.3", Timeout: "1h"}}
	mc.pushError(newDuplicateDeviceError())
	mc.pushReply(doneReply(map[string]string{"ret": "*B2"}))
	mc.pushError(newDuplicateDeviceError())
	mc.pushReply(reReply(
		map[string]string{".id": "*A1", "address": "10.0.0.1"},
		map[string]string{".id": "*A3", "address": "10.0.0.3"},
	))
	mc.pushReply(emptyReply())
	mc.pushReply(emptyReply())

	added, failed, errs := p.AddAddresses(context.Background(), "ip", "crowdsec", entries)

	if added != 3 || len(failed) != 0 || len(errs) != 0 {
		t.Fatalf("expected all 3 added or refreshed, got %d, %+v, %v", added, failed, errs)
	}
	if entries[0].ID != "*A1" || entries[2].ID != "*A3" {
		t.Fatalf("expected the refreshed ids *A1 and *A3, got %q and %q", entries[0].ID, entries[2].ID)
	}
	if got := len(lookupQueries(mc)); got != 1 {
		t.Fatalf("expected one lookup for both duplicates, got %d", got)
	}
}
