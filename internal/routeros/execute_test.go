package routeros

import (
	"context"
	"strings"
	"testing"
)

// TestExecuteAsStringSupported verifies the version gate: as-string arrived on
// :execute in 7.8rc1, and 7.8beta2 and beta3 do not have it.
func TestExecuteAsStringSupported(t *testing.T) {
	cases := map[string]bool{
		"7.24.4 (stable)":         true,
		"7.25beta3 (development)": true,
		"7.8 (stable)":            true,
		"7.8.1":                   true,
		"7.8rc1 (testing)":        true,
		"7.8rc2":                  true,
		"7.8beta3 (development)":  false,
		"7.7.10 (stable)":         false,
		"7.1":                     false,
		"6.49.18 (long-term)":     false,
		"8.0":                     true,
		"":                        false,
		"garbage":                 false,
	}
	for version, want := range cases {
		if got := executeAsStringSupported(version); got != want {
			t.Errorf("executeAsStringSupported(%q) = %v, want %v", version, got, want)
		}
	}
}

func bulkEntries(n int) []BulkEntry {
	entries := make([]BulkEntry, n)
	for i := range entries {
		entries[i] = BulkEntry{Address: "10.0.0." + string(rune('1'+i)), Timeout: "1h", Comment: "crowdsec|test"}
	}
	return entries
}

// TestBulkAddAddresses_ExecuteOneCall verifies that a chunk goes out as one
// /execute with as-string and that a closing line without positions counts
// every entry as added.
func TestBulkAddAddresses_ExecuteOneCall(t *testing.T) {
	mc := newMockConn()
	c := newExecuteTestClient(mc)
	pushRun(mc, bulkDoneMarker)

	added, failed, err := c.BulkAddAddresses(context.Background(), "ip", "list", bulkEntries(2))
	if err != nil || added != 2 || len(failed) != 0 {
		t.Fatalf("expected 2 added and nothing failed, got %d, %v, %v", added, failed, err)
	}
	if got := mc.callCount(); got != 1 {
		t.Fatalf("expected a single API call, got %d: %v", got, mc.calls)
	}
	call := mc.calls[0]
	if call[0] != "/execute" || call[len(call)-1] != "=as-string=" || !strings.Contains(call[1], "address-list/add") {
		t.Fatalf("expected /execute with the script and as-string, got %v", call)
	}
}

// pushRun queues the reply of an /execute bulk script run whose output is out.
func pushRun(mc *mockConn, out string) {
	mc.pushReply(doneReply(map[string]string{"ret": out}))
}

// TestBulkAddAddresses_ExecuteFailuresRetriedEach verifies that the positions
// the script reported as failed get one AddAddress each: a duplicate the router
// already holds, as after a script run repeated by a reconnect, counts as
// added, and only a refused add stays failed. Repeated and out-of-range
// positions count once or not at all.
func TestBulkAddAddresses_ExecuteFailuresRetriedEach(t *testing.T) {
	mc := newMockConn()
	c := newExecuteTestClient(mc)
	entries := []BulkEntry{{Address: "1.1.1.1"}, {Address: "2.2.2.2"}, {Address: "3.3.3.3"}}

	pushRun(mc, "noise\r\n"+bulkDoneMarker+"1,0,1,9,")
	mc.pushReply(doneReply(map[string]string{"ret": "*A1"})) // retry 1.1.1.1: added
	mc.pushError(newDeviceError("failure: invalid value"))   // retry 2.2.2.2: refused

	added, failed, err := c.BulkAddAddresses(context.Background(), "ip", "list", entries)
	if err == nil || added != 2 || len(failed) != 1 || failed[0].Address != "2.2.2.2" {
		t.Fatalf("expected 2 added and 2.2.2.2 failed with an error, got %d, %+v, %v", added, failed, err)
	}
	if got := mc.callCount(); got != 3 {
		t.Fatalf("expected two retries after the run, got %d calls", got)
	}
}

// TestBulkAddAddresses_ExecuteErrorRetriesEntryByEntry verifies that an :error
// inside the script, which comes back as output rather than as an API error,
// fails the chunk and retries it one add per entry.
func TestBulkAddAddresses_ExecuteErrorRetriesEntryByEntry(t *testing.T) {
	mc := newMockConn()
	c := newExecuteTestClient(mc)
	mc.pushReply(doneReply(map[string]string{"ret": "\r\nboom (:error; line 3)"}))
	mc.pushReply(doneReply(map[string]string{"ret": "*A1"}))
	mc.pushReply(doneReply(map[string]string{"ret": "*A2"}))

	added, failed, err := c.BulkAddAddresses(context.Background(), "ip", "list", bulkEntries(2))
	if err != nil || added != 2 || len(failed) != 0 {
		t.Fatalf("expected the retry to add both, got %d, %v, %v", added, failed, err)
	}
	if got := mc.callCount(); got != 3 || mc.calls[1][0] != "/ip/firewall/address-list/add" {
		t.Fatalf("expected /execute then two adds, got %v", mc.calls)
	}
	if !c.useExecute {
		t.Fatal("an error inside the script must not switch the runner off")
	}
}

// TestBulkAddAddresses_ExecuteRefusedUsesStoredScript verifies that a router
// without as-string gets the stored /system/script for that chunk and for every
// later one.
func TestBulkAddAddresses_ExecuteRefusedUsesStoredScript(t *testing.T) {
	mc := newMockConn()
	c := newExecuteTestClient(mc)
	mc.pushError(newDeviceError("unknown parameter as-string"))
	mc.pushReply(emptyReply())                                    // find existing script
	mc.pushReply(doneReply(map[string]string{"ret": "*SCRIPT1"})) // add script
	mc.pushReply(emptyReply())                                    // run script
	mc.pushReply(emptyReply())                                    // remove script

	if added, _, err := c.BulkAddAddresses(context.Background(), "ip", "list", bulkEntries(2)); err != nil || added != 2 {
		t.Fatalf("expected the stored script to add both, got %d, %v", added, err)
	}
	if c.useExecute {
		t.Fatal("expected the refusal to switch /execute off")
	}

	mc.pushReply(emptyReply())
	mc.pushReply(doneReply(map[string]string{"ret": "*SCRIPT2"}))
	mc.pushReply(emptyReply())
	mc.pushReply(emptyReply())
	if _, _, err := c.BulkAddAddresses(context.Background(), "ip", "list", bulkEntries(1)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mc.calls[5][0] != "/system/script/print" {
		t.Fatalf("expected the next chunk to skip /execute, got %v", mc.calls[5])
	}
}

// TestBulkAddAddresses_RunnerFromVersion verifies that the first chunk reads
// the router's version and picks /execute on 7.8rc1 and later.
func TestBulkAddAddresses_RunnerFromVersion(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	c.runnerKnown = false
	mc.pushReply(reReply(map[string]string{"version": "7.24.4 (stable)"}))
	pushRun(mc, bulkDoneMarker)

	if added, _, err := c.BulkAddAddresses(context.Background(), "ip", "list", bulkEntries(1)); err != nil || added != 1 {
		t.Fatalf("expected 1 added, got %d, %v", added, err)
	}
	if mc.calls[0][0] != "/system/resource/print" || mc.calls[1][0] != "/execute" {
		t.Fatalf("expected the version read then /execute, got %v", mc.calls)
	}
}

// TestBulkAddAddresses_RunnerOldRouter verifies that a router older than
// 7.8rc1 keeps the stored /system/script.
func TestBulkAddAddresses_RunnerOldRouter(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	c.runnerKnown = false
	mc.pushReply(reReply(map[string]string{"version": "7.7.10 (stable)"}))
	mc.pushReply(emptyReply())
	mc.pushReply(doneReply(map[string]string{"ret": "*SCRIPT1"}))
	mc.pushReply(emptyReply())
	mc.pushReply(emptyReply())

	if _, _, err := c.BulkAddAddresses(context.Background(), "ip", "list", bulkEntries(1)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mc.calls[1][0] != "/system/script/print" {
		t.Fatalf("expected the stored script after the version read, got %v", mc.calls)
	}
}

// TestBulkAddAddresses_VersionReadRetried verifies that a failed version read
// falls back to the stored script for that chunk and is tried again on the next.
func TestBulkAddAddresses_VersionReadRetried(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	c.runnerKnown = false
	mc.pushError(newDeviceError("failure: busy"))
	mc.pushReply(emptyReply())
	mc.pushReply(doneReply(map[string]string{"ret": "*SCRIPT1"}))
	mc.pushReply(emptyReply())
	mc.pushReply(emptyReply())

	if _, _, err := c.BulkAddAddresses(context.Background(), "ip", "list", bulkEntries(1)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.runnerKnown {
		t.Fatal("a failed version read must not settle the runner")
	}

	mc.pushReply(reReply(map[string]string{"version": "7.24.4 (stable)"}))
	pushRun(mc, bulkDoneMarker)
	if _, _, err := c.BulkAddAddresses(context.Background(), "ip", "list", bulkEntries(1)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.runnerKnown || !c.useExecute || mc.calls[6][0] != "/execute" {
		t.Fatalf("expected the second chunk to read the version and use /execute, got %v", mc.calls)
	}
}

// TestBulkAddAddresses_ExecuteOverSizeUsesStoredScript verifies that a script
// above the 64 kB /execute limit goes through the stored /system/script.
func TestBulkAddAddresses_ExecuteOverSizeUsesStoredScript(t *testing.T) {
	mc := newMockConn()
	c := newExecuteTestClient(mc)
	entries := bulkEntries(2)
	for i := range entries {
		entries[i].Comment = strings.Repeat("c", executeMaxScriptBytes/2)
	}
	mc.pushReply(emptyReply())
	mc.pushReply(doneReply(map[string]string{"ret": "*SCRIPT1"}))
	mc.pushReply(emptyReply())
	mc.pushReply(emptyReply())

	if _, _, err := c.BulkAddAddresses(context.Background(), "ip", "list", entries); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mc.calls[0][0] != "/system/script/print" {
		t.Fatalf("expected the stored script for an oversized chunk, got %v", mc.calls[0][0])
	}
	if !c.useExecute {
		t.Fatal("an oversized chunk must not switch /execute off")
	}
}

// TestBulkAddAddresses_ExecuteOtherTrapKeepsExecute verifies that a trap other
// than "the router lacks /execute" fails only that chunk, which is retried
// entry by entry, and that the next chunk still goes through /execute.
func TestBulkAddAddresses_ExecuteOtherTrapKeepsExecute(t *testing.T) {
	mc := newMockConn()
	c := newExecuteTestClient(mc)
	mc.pushError(newDeviceError("not enough permissions (9)"))
	mc.pushReply(doneReply(map[string]string{"ret": "*A1"}))

	if added, _, err := c.BulkAddAddresses(context.Background(), "ip", "list", bulkEntries(1)); err != nil || added != 1 {
		t.Fatalf("expected the retry to add the entry, got %d, %v", added, err)
	}
	if !c.useExecute || mc.calls[1][0] != "/ip/firewall/address-list/add" {
		t.Fatalf("expected an entry-by-entry retry with /execute kept, got %v", mc.calls)
	}

	pushRun(mc, bulkDoneMarker)
	if _, _, err := c.BulkAddAddresses(context.Background(), "ip", "list", bulkEntries(1)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mc.calls[2][0] != "/execute" {
		t.Fatalf("expected the next chunk to use /execute again, got %v", mc.calls[2])
	}
}

// TestExecuteUnsupported verifies which RouterOS traps mean the router lacks
// /execute as-string.
func TestExecuteUnsupported(t *testing.T) {
	cases := map[string]bool{
		"unknown parameter as-string": true,
		"no such command":             true,
		"not enough permissions (9)":  false,
		"failure: busy":               false,
	}
	for message, want := range cases {
		if got := executeUnsupported(newDeviceError(message)); got != want {
			t.Errorf("executeUnsupported(%q) = %v, want %v", message, got, want)
		}
	}
}
