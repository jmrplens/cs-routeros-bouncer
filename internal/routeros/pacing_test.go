package routeros

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// TestBulkAddAddresses_WaitsOnThePacerPerChunk verifies a pause before each
// bulk-add script while the router is busy.
func TestBulkAddAddresses_WaitsOnThePacerPerChunk(t *testing.T) {
	mc := newMockConn()
	c := newExecuteTestClient(mc)
	tp, _ := throttledPacer(400 * time.Millisecond)
	c.SetPacer(tp.Pacer)
	entries := make([]BulkEntry, 2*bulkChunkSize+50)
	for i := range entries {
		entries[i] = BulkEntry{Address: fmt.Sprintf("10.2.%d.%d", i/250, i%250+1)}
	}
	for range 3 {
		pushRun(mc, bulkDoneMarker)
	}

	added, failed, err := c.BulkAddAddresses(context.Background(), "ip", "crowdsec", entries)

	if err != nil || added != len(entries) || len(failed) != 0 {
		t.Fatalf("expected all %d added, got %d, %d failed, %v", len(entries), added, len(failed), err)
	}
	if len(tp.sleeps()) != 3 {
		t.Fatalf("expected a pause before each of the 3 chunks, got %v", tp.sleeps())
	}
}

// TestBulkAddAddresses_ShutdownDuringPause verifies that a shutdown during a
// pause runs no further script and fails the entries left, as a shutdown
// between chunks does.
func TestBulkAddAddresses_ShutdownDuringPause(t *testing.T) {
	mc := newMockConn()
	c := newExecuteTestClient(mc)
	tp, _ := throttledPacer(5 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	tp.sleep = func(context.Context, time.Duration) error {
		cancel()
		return context.Canceled
	}
	c.SetPacer(tp.Pacer)
	entries := []BulkEntry{{Address: "10.3.0.1"}, {Address: "10.3.0.2"}}

	added, failed, err := c.BulkAddAddresses(ctx, "ip", "crowdsec", entries)

	if added != 0 || len(failed) != 2 || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected both failed with the context's error, got %d, %+v, %v", added, failed, err)
	}
	if mc.callCount() != 0 {
		t.Fatalf("expected no script after the shutdown, got %d calls", mc.callCount())
	}
}

// TestAddAddressesEach_WaitsEveryHundredEntries verifies the per-entry adds
// wait on the pacer once every pacerBlockEntries entries.
func TestAddAddressesEach_WaitsEveryHundredEntries(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	tp, _ := throttledPacer(400 * time.Millisecond)
	c.SetPacer(tp.Pacer)
	entries := make([]BulkEntry, 2*pacerBlockEntries+50)
	for i := range entries {
		entries[i] = BulkEntry{Address: fmt.Sprintf("10.4.%d.%d", i/250, i%250+1)}
		mc.pushReply(doneReply(map[string]string{"ret": fmt.Sprintf("*%X", i+1)}))
	}

	added, failed, err := c.AddAddressesEach(context.Background(), "ip", "crowdsec", entries)

	if err != nil || added != len(entries) || len(failed) != 0 {
		t.Fatalf("expected all added, got %d, %d failed, %v", added, len(failed), err)
	}
	if len(tp.sleeps()) != 2 {
		t.Fatalf("expected 2 pauses for %d entries, got %v", len(entries), tp.sleeps())
	}
}

// TestRefreshDuplicates_WaitsPerLookup verifies a pause before each lookup:
// each one walks the whole list on the router.
func TestRefreshDuplicates_WaitsPerLookup(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	tp, _ := throttledPacer(400 * time.Millisecond)
	c.SetPacer(tp.Pacer)
	dups := make([]*BulkEntry, duplicateLookupBatch+50)
	var first, second []map[string]string
	for i := range dups {
		addr := fmt.Sprintf("10.5.%d.%d", i/250, i%250+1)
		dups[i] = &BulkEntry{Address: addr}
		row := map[string]string{".id": fmt.Sprintf("*%X", i+1), "address": addr}
		if i < duplicateLookupBatch {
			first = append(first, row)
		} else {
			second = append(second, row)
		}
	}
	mc.pushReply(reReply(first...))
	mc.pushReply(reReply(second...))

	refreshed, failed, errs := c.refreshDuplicates(context.Background(), "ip", "crowdsec", dups)

	if refreshed != len(dups) || len(failed) != 0 || len(errs) != 0 {
		t.Fatalf("expected all refreshed, got %d, %d failed, %v", refreshed, len(failed), errs)
	}
	if len(tp.sleeps()) != 2 {
		t.Fatalf("expected a pause before each of the 2 lookups, got %v", tp.sleeps())
	}
}

// TestLiveAddAndRemove_NeverWait verifies that a live ban and unban neither
// read the router's CPU nor wait, however busy it is.
func TestLiveAddAndRemove_NeverWait(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	tp, cpu := throttledPacer(pacerMaxPause)
	tp.lastRead = time.Time{} // a call through the pacer would read
	c.SetPacer(tp.Pacer)
	mc.pushReply(doneReply(map[string]string{"ret": "*1"}))
	mc.pushReply(emptyReply())

	if _, err := c.AddAddress("ip", "crowdsec", "10.6.0.1", "1h", "c"); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveAddress("ip", "*1"); err != nil {
		t.Fatal(err)
	}

	if cpu.readCount() != 0 || len(tp.sleeps()) != 0 {
		t.Fatalf("live paths read %d times and slept %v", cpu.readCount(), tp.sleeps())
	}
}

// newPacedPool returns a connected pool of size clients over mc, waiting on
// pacer.
func newPacedPool(t *testing.T, mc *mockConn, size int, pacer *Pacer) *Pool {
	t.Helper()
	p := NewPool(config.MikroTikConfig{}, size)
	p.newClient = func(_ config.MikroTikConfig) *Client {
		return &Client{dialFunc: func(_ config.MikroTikConfig) (RouterConn, error) { return mc, nil }}
	}
	p.SetPacer(pacer)
	if err := p.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

// TestPoolConnect_HandsThePacerToClients verifies that the clients a pool
// opens wait on its pacer, so their duplicate lookups do.
func TestPoolConnect_HandsThePacerToClients(t *testing.T) {
	tp, _ := throttledPacer(400 * time.Millisecond)
	p := newPacedPool(t, newMockConn(), 2, tp.Pacer)

	c := p.Get()
	defer p.Put(c)
	if c.pacer != tp.Pacer {
		t.Fatal("expected the pool's client to carry the pool's pacer")
	}
}

// TestParallelExecContext_OneAtATimeWhileSlowing verifies that the pool's
// workers take turns while the router is busy.
func TestParallelExecContext_OneAtATimeWhileSlowing(t *testing.T) {
	tp, _ := throttledPacer(400 * time.Millisecond)
	p := newPacedPool(t, newMockConn(), 4, tp.Pacer)
	items := make([]int, 40)
	var cur, peak atomic.Int32

	errs := ParallelExecContext(context.Background(), p, items, func(*Client, int) error {
		raisePeak(&peak, cur.Add(1))
		time.Sleep(time.Millisecond)
		cur.Add(-1)
		return nil
	})

	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if got := peak.Load(); got != 1 {
		t.Fatalf("expected one item at a time while slowing down, saw %d", got)
	}
}

// TestParallelExecContext_ShutdownWhileSlowing verifies that a shutdown frees
// workers waiting for their turn: the call returns, and every item not run
// is reported.
func TestParallelExecContext_ShutdownWhileSlowing(t *testing.T) {
	tp, _ := throttledPacer(400 * time.Millisecond)
	p := newPacedPool(t, newMockConn(), 4, tp.Pacer)
	items := make([]int, 20)
	ctx, cancel := context.WithCancel(context.Background())
	var ran atomic.Int32
	var once sync.Once
	done := make(chan []error, 1)

	go func() {
		done <- ParallelExecContext(ctx, p, items, func(*Client, int) error {
			ran.Add(1)
			once.Do(cancel) // the first item shuts down while holding the turn
			time.Sleep(10 * time.Millisecond)
			return nil
		})
	}()

	select {
	case errs := <-done:
		if int(ran.Load())+len(errs) != len(items) {
			t.Fatalf("expected every item run or reported, ran %d, reported %d", ran.Load(), len(errs))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ParallelExecContext did not return after the shutdown")
	}
}
