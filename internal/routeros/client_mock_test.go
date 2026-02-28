// client_mock_test.go contains unit tests for the routeros package that use
// the mockConn to exercise Client, address-list, firewall, and bulk operations
// without a real RouterOS device.
package routeros

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// ─────────────────────────────────────────────────────────────────────────────
// Client core operations (Run, Add, Set, Remove, Print, Find)
// ─────────────────────────────────────────────────────────────────────────────

// TestRun_Success verifies that Run delegates to conn.RunArgs and returns the reply.
func TestRun_Success(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(doneReply(map[string]string{"status": "ok"}))

	reply, err := c.Run("/system/identity/print")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reply.Done.Map["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", reply.Done.Map)
	}
	if mc.callCount() != 1 {
		t.Fatalf("expected 1 call, got %d", mc.callCount())
	}
}

// TestRun_ErrorReconnectsAndRetries verifies the auto-reconnect on failure.
func TestRun_ErrorReconnectsAndRetries(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	// First call fails, triggers reconnect; second call succeeds.
	mc.pushError(errors.New("connection lost"))
	mc.pushReply(emptyReply()) // retry succeeds

	_, err := c.Run("/test/cmd")
	if err != nil {
		t.Fatalf("expected success after reconnect, got: %v", err)
	}
	// Expect 2 RunArgs calls (original + retry after reconnect).
	if mc.callCount() != 2 {
		t.Fatalf("expected 2 calls, got %d", mc.callCount())
	}
}

// TestRun_ReconnectAlsoFails verifies error propagation when reconnect fails.
func TestRun_ReconnectAlsoFails(t *testing.T) {
	mc := newMockConn()
	dialCount := 0
	c := &Client{
		conn: mc,
		dialFunc: func(_ config.MikroTikConfig) (RouterConn, error) {
			dialCount++
			return nil, errors.New("dial failed")
		},
	}

	mc.pushError(errors.New("first call fails"))

	_, err := c.Run("/test/cmd")
	if err == nil {
		t.Fatal("expected error when reconnect fails")
	}
	if !strings.Contains(err.Error(), "reconnect failed") {
		t.Fatalf("expected 'reconnect failed', got: %v", err)
	}
}

// TestRun_RetryAlsoFails verifies error when retry after reconnect fails.
func TestRun_RetryAlsoFails(t *testing.T) {
	mc := newMockConn()
	mc2 := newMockConn()
	c := &Client{
		conn: mc,
		dialFunc: func(_ config.MikroTikConfig) (RouterConn, error) {
			return mc2, nil
		},
	}

	mc.pushError(errors.New("first fails"))
	mc2.pushError(errors.New("retry also fails"))

	_, err := c.Run("/test/cmd")
	if err == nil {
		t.Fatal("expected error on retry failure")
	}
	if !strings.Contains(err.Error(), "command failed after reconnect") {
		t.Fatalf("expected 'command failed after reconnect', got: %v", err)
	}
}

// TestRun_NilConnAutoConnects verifies that Run auto-connects when conn is nil.
func TestRun_NilConnAutoConnects(t *testing.T) {
	mc := newMockConn()
	c := &Client{
		conn: nil,
		dialFunc: func(_ config.MikroTikConfig) (RouterConn, error) {
			return mc, nil
		},
	}

	mc.pushReply(emptyReply())

	_, err := c.Run("/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestAdd_ReturnsID verifies that Add parses the ret field from Done.
func TestAdd_ReturnsID(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(doneReply(map[string]string{"ret": "*1A"}))

	id, err := c.Add("/ip/firewall/address-list", map[string]string{
		"list":    "test",
		"address": "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "*1A" {
		t.Fatalf("expected id *1A, got %s", id)
	}
	// Verify the command sent
	args := mc.lastArgs()
	if args[0] != "/ip/firewall/address-list/add" {
		t.Fatalf("expected add command, got: %v", args)
	}
}

// TestAdd_NoRetField verifies Add returns empty string when no ret in Done.
func TestAdd_NoRetField(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	id, err := c.Add("/path", map[string]string{"key": "val"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "" {
		t.Fatalf("expected empty id, got %q", id)
	}
}

// TestAdd_Error verifies Add wraps the error.
func TestAdd_Error(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushError(errors.New("connection lost"))
	mc.pushError(errors.New("still lost")) // reconnect retry

	_, err := c.Add("/path", nil)
	if err == nil || !strings.Contains(err.Error(), "add /path") {
		t.Fatalf("expected wrapped add error, got: %v", err)
	}
}

// TestSet_Success verifies Set sends the correct arguments.
func TestSet_Success(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	err := c.Set("/ip/firewall/address-list", "*1A", map[string]string{"timeout": "1h"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	args := mc.lastArgs()
	found := false
	for _, a := range args {
		if a == "=numbers=*1A" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected =numbers=*1A in args, got: %v", args)
	}
}

// TestRemove_Success verifies Remove sends the correct command.
func TestRemove_Success(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	err := c.Remove("/ip/firewall/address-list", "*5B")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	args := mc.lastArgs()
	if args[0] != "/ip/firewall/address-list/remove" || args[1] != "=numbers=*5B" {
		t.Fatalf("unexpected args: %v", args)
	}
}

// TestPrint_ParsesResults verifies Print converts Re sentences to maps.
func TestPrint_ParsesResults(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(reReply(
		map[string]string{".id": "*1", "address": "1.2.3.4", "list": "blocked"},
		map[string]string{".id": "*2", "address": "5.6.7.8", "list": "blocked"},
	))

	results, err := c.Print("/ip/firewall/address-list", []string{"?list=blocked"}, []string{".id", "address", "list"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0]["address"] != "1.2.3.4" {
		t.Fatalf("wrong first address: %s", results[0]["address"])
	}
}

// TestPrint_NoProplist verifies Print works without a property list.
func TestPrint_NoProplist(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	_, err := c.Print("/path", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	args := mc.lastArgs()
	if args[0] != "/path/print" {
		t.Fatalf("expected /path/print, got %s", args[0])
	}
	// No =.proplist= should be sent
	for _, a := range args {
		if strings.HasPrefix(a, "=.proplist=") {
			t.Fatalf("unexpected proplist in args: %v", args)
		}
	}
}

// TestFind_ReturnsFirst verifies Find returns only the first match.
func TestFind_ReturnsFirst(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(reReply(
		map[string]string{"name": "first"},
		map[string]string{"name": "second"},
	))

	result, err := c.Find("/path", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["name"] != "first" {
		t.Fatalf("expected 'first', got %q", result["name"])
	}
}

// TestFind_ReturnsNilWhenEmpty verifies Find returns nil when no results.
func TestFind_ReturnsNilWhenEmpty(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	result, err := c.Find("/path", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection management
// ─────────────────────────────────────────────────────────────────────────────

// TestConnect_Success verifies that Connect sets conn via dialFunc.
func TestConnect_Success(t *testing.T) {
	mc := newMockConn()
	c := &Client{
		dialFunc: func(_ config.MikroTikConfig) (RouterConn, error) {
			return mc, nil
		},
	}

	if err := c.Connect(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.IsConnected() {
		t.Fatal("expected connected after Connect()")
	}
}

// TestConnect_Error verifies that Connect propagates dial errors.
func TestConnect_Error(t *testing.T) {
	c := &Client{
		dialFunc: func(_ config.MikroTikConfig) (RouterConn, error) {
			return nil, errors.New("refused")
		},
	}

	err := c.Connect()
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("expected dial error, got: %v", err)
	}
	if c.IsConnected() {
		t.Fatal("should not be connected after dial error")
	}
}

// TestClose_SetsConnNil verifies that Close nils the connection.
func TestClose_SetsConnNil(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	c.Close()
	if c.IsConnected() {
		t.Fatal("expected disconnected after Close()")
	}
	if !mc.closed {
		t.Fatal("expected mockConn.Close() to be called")
	}
}

// TestReconnect verifies Reconnect closes existing and dials new.
func TestReconnect(t *testing.T) {
	mc1 := newMockConn()
	mc2 := newMockConn()
	dialCount := 0
	c := &Client{
		conn: mc1,
		dialFunc: func(_ config.MikroTikConfig) (RouterConn, error) {
			dialCount++
			return mc2, nil
		},
	}

	if err := c.Reconnect(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mc1.closed {
		t.Fatal("old connection should be closed")
	}
	if dialCount != 1 {
		t.Fatalf("expected 1 dial call, got %d", dialCount)
	}
	if !c.IsConnected() {
		t.Fatal("expected connected after Reconnect()")
	}
}

// TestIsConnected_FalseWhenNil verifies IsConnected with nil conn.
func TestIsConnected_FalseWhenNil(t *testing.T) {
	c := &Client{}
	if c.IsConnected() {
		t.Fatal("expected false with nil conn")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Identity and service queries
// ─────────────────────────────────────────────────────────────────────────────

// TestGetIdentity_Success verifies GetIdentity parses the router name.
func TestGetIdentity_Success(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(reReply(map[string]string{"name": "MikroTik-GW"}))

	name, err := c.GetIdentity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "MikroTik-GW" {
		t.Fatalf("expected MikroTik-GW, got %q", name)
	}
}

// TestGetIdentity_NoResult verifies GetIdentity error when no result.
func TestGetIdentity_NoResult(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	_, err := c.GetIdentity()
	if err == nil || !strings.Contains(err.Error(), "no identity found") {
		t.Fatalf("expected 'no identity found', got: %v", err)
	}
}

// TestGetAPIMaxSessions_ParsesValue verifies max-sessions parsing.
func TestGetAPIMaxSessions_ParsesValue(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(reReply(map[string]string{"max-sessions": "100"}))

	n := c.GetAPIMaxSessions()
	if n != 100 {
		t.Fatalf("expected 100, got %d", n)
	}
}

// TestGetAPIMaxSessions_TLS verifies the TLS service name is used.
func TestGetAPIMaxSessions_TLS(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	c.cfg.TLS = true

	mc.pushReply(reReply(map[string]string{"max-sessions": "50"}))

	n := c.GetAPIMaxSessions()
	if n != 50 {
		t.Fatalf("expected 50, got %d", n)
	}
	// Verify the query used "api-ssl"
	args := mc.lastArgs()
	found := false
	for _, a := range args {
		if a == "?name=api-ssl" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected ?name=api-ssl in args, got: %v", args)
	}
}

// TestGetAPIMaxSessions_NoResult verifies fallback to 0.
func TestGetAPIMaxSessions_NoResult(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	n := c.GetAPIMaxSessions()
	if n != 0 {
		t.Fatalf("expected 0, got %d", n)
	}
}

// TestGetAPIMaxSessions_InvalidValue verifies fallback on parse error.
func TestGetAPIMaxSessions_InvalidValue(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(reReply(map[string]string{"max-sessions": "unlimited"}))

	n := c.GetAPIMaxSessions()
	if n != 0 {
		t.Fatalf("expected 0 on parse error, got %d", n)
	}
}

// TestGetAPIMaxSessions_EmptyValue verifies fallback on empty string.
func TestGetAPIMaxSessions_EmptyValue(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(reReply(map[string]string{"max-sessions": ""}))

	n := c.GetAPIMaxSessions()
	if n != 0 {
		t.Fatalf("expected 0 on empty value, got %d", n)
	}
}

// TestGetAPIMaxSessions_Error verifies fallback on API error.
func TestGetAPIMaxSessions_Error(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushError(errors.New("fail"))
	mc.pushError(errors.New("fail")) // reconnect retry

	n := c.GetAPIMaxSessions()
	if n != 0 {
		t.Fatalf("expected 0 on error, got %d", n)
	}
}

// TestPing_Success verifies Ping sends identity/print.
func TestPing_Success(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	if err := c.Ping(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	args := mc.lastArgs()
	if args[0] != "/system/identity/print" {
		t.Fatalf("expected identity print, got: %v", args)
	}
}

// TestPing_Error verifies Ping returns wrapped error.
func TestPing_Error(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushError(errors.New("dead"))
	mc.pushError(errors.New("dead"))

	err := c.Ping()
	if err == nil || !strings.Contains(err.Error(), "ping failed") {
		t.Fatalf("expected 'ping failed', got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Address list operations
// ─────────────────────────────────────────────────────────────────────────────

// TestAddAddress_IPv4WithTimeout verifies AddAddress for IPv4 with timeout.
func TestAddAddress_IPv4WithTimeout(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(doneReply(map[string]string{"ret": "*A1"}))

	id, err := c.AddAddress("ip", "blocked", "1.2.3.4", "1h", "crowdsec|ban")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "*A1" {
		t.Fatalf("expected *A1, got %s", id)
	}
	// Verify path
	args := mc.lastArgs()
	if args[0] != "/ip/firewall/address-list/add" {
		t.Fatalf("expected ip path, got: %s", args[0])
	}
}

// TestAddAddress_IPv6Normalization verifies IPv6 address gets /128 suffix.
func TestAddAddress_IPv6Normalization(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(doneReply(map[string]string{"ret": "*B2"}))

	_, err := c.AddAddress("ipv6", "blocked6", "2001:db8::1", "2h", "crowdsec|ban")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify address was normalized to include /128
	args := mc.lastArgs()
	found := false
	for _, a := range args {
		if a == "=address=2001:db8::1/128" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected =address=2001:db8::1/128, got: %v", args)
	}
}

// TestAddAddress_NoTimeout verifies AddAddress without timeout.
func TestAddAddress_NoTimeout(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(doneReply(map[string]string{"ret": "*C3"}))

	_, err := c.AddAddress("ip", "list", "10.0.0.1", "", "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify no timeout arg was sent
	args := mc.lastArgs()
	for _, a := range args {
		if strings.HasPrefix(a, "=timeout=") {
			t.Fatalf("unexpected timeout arg: %v", args)
		}
	}
}

// TestAddAddress_Error verifies error wrapping.
func TestAddAddress_Error(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushError(errors.New("fail"))
	mc.pushError(errors.New("fail"))

	_, err := c.AddAddress("ip", "list", "1.2.3.4", "", "test")
	if err == nil || !strings.Contains(err.Error(), "add address 1.2.3.4") {
		t.Fatalf("expected wrapped error, got: %v", err)
	}
}

// TestRemoveAddress_Success verifies RemoveAddress.
func TestRemoveAddress_Success(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	err := c.RemoveAddress("ip", "*D4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	args := mc.lastArgs()
	if args[0] != "/ip/firewall/address-list/remove" {
		t.Fatalf("expected address-list/remove, got: %s", args[0])
	}
}

// TestRemoveAddress_IPv6Path verifies the IPv6 path.
func TestRemoveAddress_IPv6Path(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	_ = c.RemoveAddress("ipv6", "*E5")
	args := mc.lastArgs()
	if args[0] != "/ipv6/firewall/address-list/remove" {
		t.Fatalf("expected ipv6 path, got: %s", args[0])
	}
}

// TestListAddresses_FiltersCommentPrefix verifies comment prefix filtering.
func TestListAddresses_FiltersCommentPrefix(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(reReply(
		map[string]string{".id": "*1", "address": "1.1.1.1", "list": "blocked", "timeout": "1h", "comment": "crowdsec|ban"},
		map[string]string{".id": "*2", "address": "2.2.2.2", "list": "blocked", "timeout": "", "comment": "manual"},
		map[string]string{".id": "*3", "address": "3.3.3.3", "list": "blocked", "timeout": "2h", "comment": "crowdsec|test"},
	))

	entries, err := c.ListAddresses("ip", "blocked", "crowdsec|")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries matching prefix, got %d", len(entries))
	}
	if entries[0].Address != "1.1.1.1" || entries[1].Address != "3.3.3.3" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

// TestListAddresses_NoFilter verifies listing without comment filter.
func TestListAddresses_NoFilter(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(reReply(
		map[string]string{".id": "*1", "address": "1.1.1.1", "list": "all", "timeout": "", "comment": "any"},
	))

	entries, err := c.ListAddresses("ip", "all", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
}

// TestListAddresses_Error verifies error propagation.
func TestListAddresses_Error(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushError(errors.New("fail"))
	mc.pushError(errors.New("fail"))

	_, err := c.ListAddresses("ip", "list", "")
	if err == nil || !strings.Contains(err.Error(), "list addresses") {
		t.Fatalf("expected wrapped error, got: %v", err)
	}
}

// TestFindAddress_Found verifies FindAddress returns the entry.
func TestFindAddress_Found(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(reReply(map[string]string{
		".id": "*F6", "address": "10.0.0.1", "list": "blocked", "timeout": "30m", "comment": "test",
	}))

	entry, err := c.FindAddress("ip", "blocked", "10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}
	if entry.ID != "*F6" || entry.Timeout != "30m" {
		t.Fatalf("unexpected entry: %+v", entry)
	}
}

// TestFindAddress_NotFound verifies FindAddress returns nil.
func TestFindAddress_NotFound(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	entry, err := c.FindAddress("ip", "blocked", "10.0.0.99")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry != nil {
		t.Fatalf("expected nil, got %+v", entry)
	}
}

// TestFindAddress_IPv6Normalization verifies IPv6 normalization in query.
func TestFindAddress_IPv6Normalization(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	_, _ = c.FindAddress("ipv6", "blocked6", "2001:db8::1")
	args := mc.lastArgs()
	found := false
	for _, a := range args {
		if a == "?address=2001:db8::1/128" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected normalized address in query, got: %v", args)
	}
}

// TestUpdateAddressTimeout_Success verifies timeout update.
func TestUpdateAddressTimeout_Success(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	err := c.UpdateAddressTimeout("ip", "*G7", "2h")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Firewall operations
// ─────────────────────────────────────────────────────────────────────────────

// TestAddFirewallRule_NoPlacement verifies simple rule creation without top placement.
func TestAddFirewallRule_NoPlacement(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(doneReply(map[string]string{"ret": "*R1"}))

	rule := FirewallRule{
		Chain:          "forward",
		Action:         "drop",
		SrcAddressList: "blocked",
		Comment:        "crowdsec",
	}

	id, err := c.AddFirewallRule("ip", "filter", rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "*R1" {
		t.Fatalf("expected *R1, got %s", id)
	}
	// Should be only 1 call (just Add, no list/move)
	if mc.callCount() != 1 {
		t.Fatalf("expected 1 call (no placement), got %d", mc.callCount())
	}
}

// TestAddFirewallRule_TopPlacement_AlreadyAtTop verifies skip when already at top.
func TestAddFirewallRule_TopPlacement_AlreadyAtTop(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	// Add returns the rule ID
	mc.pushReply(doneReply(map[string]string{"ret": "*R1"}))
	// List returns our rule already at position 0
	mc.pushReply(reReply(
		map[string]string{".id": "*R1"},
		map[string]string{".id": "*R2"},
	))

	rule := FirewallRule{Chain: "input", Action: "drop", PlaceBefore: "top", Comment: "test"}
	id, err := c.AddFirewallRule("ip", "filter", rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "*R1" {
		t.Fatalf("expected *R1, got %s", id)
	}
	// 2 calls: Add + Print (no move needed)
	if mc.callCount() != 2 {
		t.Fatalf("expected 2 calls, got %d", mc.callCount())
	}
}

// TestAddFirewallRule_TopPlacement_MoveSucceeds verifies move to position 0.
func TestAddFirewallRule_TopPlacement_MoveSucceeds(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	// Add
	mc.pushReply(doneReply(map[string]string{"ret": "*R3"}))
	// List: other rules first, ours at the end
	mc.pushReply(reReply(
		map[string]string{".id": "*R1"},
		map[string]string{".id": "*R2"},
		map[string]string{".id": "*R3"},
	))
	// Move succeeds
	mc.pushReply(emptyReply())

	rule := FirewallRule{Chain: "input", Action: "drop", PlaceBefore: "0", Comment: "test"}
	id, err := c.AddFirewallRule("ip", "filter", rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "*R3" {
		t.Fatalf("expected *R3, got %s", id)
	}
	// 3 calls: Add + Print + Move
	if mc.callCount() != 3 {
		t.Fatalf("expected 3 calls, got %d", mc.callCount())
	}
}

// TestAddFirewallRule_TopPlacement_MoveRetries verifies position retry loop.
func TestAddFirewallRule_TopPlacement_MoveRetries(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	// Add
	mc.pushReply(doneReply(map[string]string{"ret": "*R5"}))
	// List: dynamic rule at 0, another at 1, ours at 2
	mc.pushReply(reReply(
		map[string]string{".id": "*D0"}, // dynamic, can't displace
		map[string]string{".id": "*D1"}, // another unmovable
		map[string]string{".id": "*R5"}, // our rule
	))
	// Move to position 0 fails (dynamic rule)
	mc.pushError(errors.New("cannot move"))
	// Move to position 1 also fails
	mc.pushError(errors.New("cannot move"))
	// Position 2 is our own rule — loop ends (already as high as possible)

	rule := FirewallRule{Chain: "input", Action: "drop", PlaceBefore: "top", Comment: "test"}
	id, err := c.AddFirewallRule("ip", "filter", rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "*R5" {
		t.Fatalf("expected *R5, got %s", id)
	}
}

// TestAddFirewallRule_AllOptionalFields verifies all interface/log fields.
func TestAddFirewallRule_AllOptionalFields(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(doneReply(map[string]string{"ret": "*R6"}))

	rule := FirewallRule{
		Chain:            "input",
		Action:           "reject",
		SrcAddress:       "!10.0.0.5",
		SrcAddressList:   "src-list",
		DstAddressList:   "dst-list",
		InInterface:      "ether1",
		InInterfaceList:  "WAN",
		OutInterface:     "ether2",
		OutInterfaceList: "LAN",
		Comment:          "full-rule",
		Log:              true,
		LogPrefix:        "CS-DROP",
		ConnectionState:  "new,invalid",
		RejectWith:       "tcp-reset",
	}

	_, err := c.AddFirewallRule("ip", "filter", rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	args := mc.lastArgs()
	// Verify all attrs present
	argSet := make(map[string]bool)
	for _, a := range args {
		argSet[a] = true
	}
	expected := []string{
		"=in-interface=ether1",
		"=in-interface-list=WAN",
		"=out-interface=ether2",
		"=out-interface-list=LAN",
		"=log=true",
		"=log-prefix=CS-DROP",
		"=src-address=!10.0.0.5",
		"=src-address-list=src-list",
		"=dst-address-list=dst-list",
		"=connection-state=new,invalid",
		"=reject-with=tcp-reset",
	}
	for _, e := range expected {
		if !argSet[e] {
			t.Errorf("missing expected arg %q in %v", e, args)
		}
	}
}

// TestAddFirewallRule_ListError verifies fallback when list fails after Add.
func TestAddFirewallRule_ListError(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(doneReply(map[string]string{"ret": "*R7"}))
	// List fails (first call fails, reconnect retry also fails)
	mc.pushError(errors.New("list failed"))
	mc.pushError(errors.New("list failed"))

	rule := FirewallRule{Chain: "input", Action: "drop", PlaceBefore: "top", Comment: "test"}
	id, err := c.AddFirewallRule("ip", "filter", rule)
	if err != nil {
		t.Fatalf("unexpected error (should succeed with rule appended): %v", err)
	}
	if id != "*R7" {
		t.Fatalf("expected *R7, got %s", id)
	}
}

// TestAddFirewallRule_AddError verifies error propagation from Add.
func TestAddFirewallRule_AddError(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushError(errors.New("add failed"))
	mc.pushError(errors.New("add failed"))

	rule := FirewallRule{Chain: "input", Action: "drop", Comment: "test"}
	_, err := c.AddFirewallRule("ip", "filter", rule)
	if err == nil || !strings.Contains(err.Error(), "add ip/filter rule") {
		t.Fatalf("expected wrapped add error, got: %v", err)
	}
}

// TestMoveRule_Success verifies the move command arguments.
func TestMoveRule_Success(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	err := c.moveRule("/ip/firewall/filter", "*R1", "*R0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	args := mc.lastArgs()
	if args[0] != "/ip/firewall/filter/move" {
		t.Fatalf("expected move command, got: %s", args[0])
	}
	if args[1] != "=numbers=*R1" || args[2] != "=destination=*R0" {
		t.Fatalf("unexpected move args: %v", args)
	}
}

// TestMoveRule_Error verifies move error propagation.
func TestMoveRule_Error(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushError(errors.New("cannot move"))

	err := c.moveRule("/ip/firewall/filter", "*R1", "*R0")
	if err == nil {
		t.Fatal("expected error from moveRule")
	}
}

// TestMoveRule_NotConnected verifies moveRule auto-connects.
func TestMoveRule_NotConnected(t *testing.T) {
	mc := newMockConn()
	c := &Client{
		conn: nil,
		dialFunc: func(_ config.MikroTikConfig) (RouterConn, error) {
			return mc, nil
		},
	}
	mc.pushReply(emptyReply())

	err := c.moveRule("/ip/firewall/filter", "*R1", "*R0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRemoveFirewallRule_Success verifies RemoveFirewallRule.
func TestRemoveFirewallRule_Success(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	err := c.RemoveFirewallRule("ip", "filter", "*R1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestListFirewallRules_FiltersByComment verifies comment prefix filtering.
func TestListFirewallRules_FiltersByComment(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(reReply(
		map[string]string{".id": "*1", "chain": "input", "action": "drop", "comment": "crowdsec-drop-input",
			"src-address-list": "blocked", "dst-address-list": "", "in-interface": "ether1",
			"in-interface-list": "", "out-interface": "", "out-interface-list": ""},
		map[string]string{".id": "*2", "chain": "forward", "action": "accept", "comment": "other-rule",
			"src-address-list": "", "dst-address-list": "", "in-interface": "",
			"in-interface-list": "", "out-interface": "", "out-interface-list": ""},
		map[string]string{".id": "*3", "chain": "output", "action": "drop", "comment": "crowdsec-drop-output",
			"src-address-list": "", "dst-address-list": "blocked", "in-interface": "",
			"in-interface-list": "", "out-interface": "", "out-interface-list": ""},
	))

	entries, err := c.ListFirewallRules("ip", "filter", "crowdsec-")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].ID != "*1" || entries[1].ID != "*3" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

// TestListFirewallRules_NoFilter verifies listing all rules.
func TestListFirewallRules_NoFilter(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(reReply(
		map[string]string{".id": "*1", "chain": "input", "action": "drop", "comment": "rule1",
			"src-address-list": "", "dst-address-list": "", "in-interface": "",
			"in-interface-list": "", "out-interface": "", "out-interface-list": ""},
	))

	entries, err := c.ListFirewallRules("ip", "filter", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
}

// TestListFirewallRules_ParsesAllFields verifies all RuleEntry fields.
func TestListFirewallRules_ParsesAllFields(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(reReply(map[string]string{
		".id": "*1", "chain": "input", "action": "reject",
		"src-address":      "!10.0.0.5",
		"src-address-list": "src", "dst-address-list": "dst",
		"in-interface": "ether1", "in-interface-list": "WAN",
		"out-interface": "ether2", "out-interface-list": "LAN",
		"connection-state": "new,invalid",
		"reject-with":      "tcp-reset",
		"comment":          "full",
	}))

	entries, err := c.ListFirewallRules("ip", "filter", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := entries[0]
	if e.Chain != "input" || e.Action != "reject" || e.SrcAddressList != "src" ||
		e.DstAddressList != "dst" || e.InInterface != "ether1" || e.InInterfaceList != "WAN" ||
		e.OutInterface != "ether2" || e.OutInterfaceList != "LAN" || e.Comment != "full" {
		t.Fatalf("field mismatch: %+v", e)
	}
	if e.SrcAddress != "!10.0.0.5" {
		t.Errorf("expected SrcAddress '!10.0.0.5', got %q", e.SrcAddress)
	}
	if e.ConnectionState != "new,invalid" {
		t.Errorf("expected ConnectionState 'new,invalid', got %q", e.ConnectionState)
	}
	if e.RejectWith != "tcp-reset" {
		t.Errorf("expected RejectWith 'tcp-reset', got %q", e.RejectWith)
	}
}

// TestFindFirewallRuleByComment_Found verifies finding a rule by comment.
func TestFindFirewallRuleByComment_Found(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(reReply(map[string]string{
		".id": "*1", "chain": "input", "action": "drop", "comment": "crowdsec-drop",
		"src-address-list": "blocked", "dst-address-list": "", "in-interface": "",
		"in-interface-list": "", "out-interface": "", "out-interface-list": "",
	}))

	entry, err := c.FindFirewallRuleByComment("ip", "filter", "crowdsec-drop")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry == nil || entry.ID != "*1" {
		t.Fatalf("unexpected entry: %+v", entry)
	}
}

// TestFindFirewallRuleByComment_NotFound verifies nil return.
func TestFindFirewallRuleByComment_NotFound(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	entry, err := c.FindFirewallRuleByComment("ip", "filter", "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry != nil {
		t.Fatalf("expected nil, got %+v", entry)
	}
}

// TestFindFirewallRuleByComment_IPv6Path verifies IPv6 path.
func TestFindFirewallRuleByComment_IPv6Path(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	_, _ = c.FindFirewallRuleByComment("ipv6", "raw", "test")
	args := mc.lastArgs()
	if !strings.HasPrefix(args[0], "/ipv6/firewall/raw/print") {
		t.Fatalf("expected ipv6 raw path, got: %s", args[0])
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Bulk operations
// ─────────────────────────────────────────────────────────────────────────────

// TestBulkAddAddresses_EmptyInput verifies zero entries returns immediately.
func TestBulkAddAddresses_EmptyInput(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	added, err := c.BulkAddAddresses("ip", "list", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if added != 0 {
		t.Fatalf("expected 0 added, got %d", added)
	}
	if mc.callCount() != 0 {
		t.Fatalf("expected 0 API calls, got %d", mc.callCount())
	}
}

// TestBulkAddAddresses_SingleChunk verifies a single chunk script execution.
func TestBulkAddAddresses_SingleChunk(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	entries := []BulkEntry{
		{Address: "1.1.1.1", Timeout: "1h", Comment: "crowdsec|test1"},
		{Address: "2.2.2.2", Timeout: "2h", Comment: "crowdsec|test2"},
	}

	// runBulkScript flow: Find existing script → not found, Add script, Run script, Remove script
	mc.pushReply(emptyReply())                                    // Find existing → no results
	mc.pushReply(doneReply(map[string]string{"ret": "*SCRIPT1"})) // Add script
	mc.pushReply(emptyReply())                                    // Run script
	mc.pushReply(emptyReply())                                    // Remove script

	added, err := c.BulkAddAddresses("ip", "list", entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if added != 2 {
		t.Fatalf("expected 2 added, got %d", added)
	}
}

// TestBulkAddAddresses_MultipleChunks verifies chunking at 100 entries.
func TestBulkAddAddresses_MultipleChunks(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	// Create 150 entries → 2 chunks (100 + 50)
	entries := make([]BulkEntry, 150)
	for i := range entries {
		entries[i] = BulkEntry{Address: "10.0.0.1", Timeout: "1h", Comment: "test"}
	}

	// Chunk 1: Find + Add + Run + Remove
	mc.pushReply(emptyReply())
	mc.pushReply(doneReply(map[string]string{"ret": "*S1"}))
	mc.pushReply(emptyReply())
	mc.pushReply(emptyReply())
	// Chunk 2: Find + Add + Run + Remove
	mc.pushReply(emptyReply())
	mc.pushReply(doneReply(map[string]string{"ret": "*S2"}))
	mc.pushReply(emptyReply())
	mc.pushReply(emptyReply())

	added, err := c.BulkAddAddresses("ip", "list", entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if added != 150 {
		t.Fatalf("expected 150 added, got %d", added)
	}
}

// TestBulkAddAddresses_ScriptFailsFallsBack verifies individual add fallback.
func TestBulkAddAddresses_ScriptFailsFallsBack(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	entries := []BulkEntry{
		{Address: "1.1.1.1", Timeout: "1h", Comment: "crowdsec|test1"},
	}

	// runBulkScript fails: Find OK, Add script fails
	mc.pushReply(emptyReply())       // Find existing → not found
	mc.pushError(errors.New("fail")) // Add script fails
	mc.pushError(errors.New("fail")) // reconnect retry fails

	// Fallback to individual AddAddress
	mc.pushReply(doneReply(map[string]string{"ret": "*A1"})) // AddAddress succeeds

	added, err := c.BulkAddAddresses("ip", "list", entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if added != 1 {
		t.Fatalf("expected 1 added via fallback, got %d", added)
	}
}

// TestBulkAddAddresses_FallbackAlreadyHaveIgnored verifies "already have" skipping.
func TestBulkAddAddresses_FallbackAlreadyHaveIgnored(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	entries := []BulkEntry{
		{Address: "1.1.1.1", Timeout: "1h", Comment: "test"},
	}

	// Script fails
	mc.pushReply(emptyReply())
	mc.pushError(errors.New("fail"))
	mc.pushError(errors.New("fail"))

	// Individual add returns "already have"
	mc.pushError(errors.New("already have such entry"))
	mc.pushError(errors.New("already have such entry"))

	added, err := c.BulkAddAddresses("ip", "list", entries)
	// No error because "already have" is silently ignored
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if added != 0 {
		t.Fatalf("expected 0 added (already exists), got %d", added)
	}
}

// TestRemoveAddresses_Success verifies sequential removes.
func TestRemoveAddresses_Success(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(emptyReply())
	mc.pushReply(emptyReply())
	mc.pushReply(emptyReply())

	removed, errs := c.RemoveAddresses("ip", []string{"*1", "*2", "*3"})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if removed != 3 {
		t.Fatalf("expected 3 removed, got %d", removed)
	}
}

// TestRemoveAddresses_NoSuchItemTolerated verifies "no such item" is silently skipped.
func TestRemoveAddresses_NoSuchItemTolerated(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(emptyReply())               // *1 OK
	mc.pushError(errors.New("no such item")) // *2 already gone
	mc.pushError(errors.New("no such item")) // reconnect retry for *2
	mc.pushReply(emptyReply())               // *3 OK

	removed, errs := c.RemoveAddresses("ip", []string{"*1", "*2", "*3"})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if removed != 2 {
		t.Fatalf("expected 2 removed, got %d", removed)
	}
}

// TestRemoveAddresses_MixedErrors verifies error collection for non-"no such item" errors.
func TestRemoveAddresses_MixedErrors(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(emptyReply())          // *1 OK
	mc.pushError(errors.New("timeout")) // *2 fails
	mc.pushError(errors.New("timeout")) // reconnect retry for *2

	removed, errs := c.RemoveAddresses("ip", []string{"*1", "*2"})
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}
	if removed != 1 {
		t.Fatalf("expected 1 removed, got %d", removed)
	}
}

// TestRemoveAddresses_Empty verifies empty input.
func TestRemoveAddresses_Empty(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	removed, errs := c.RemoveAddresses("ip", nil)
	if len(errs) != 0 || removed != 0 {
		t.Fatalf("expected 0/0, got %d/%d", removed, len(errs))
	}
}

// TestRunBulkScript_CleansUpExistingScript verifies pre-cleanup of existing script.
func TestRunBulkScript_CleansUpExistingScript(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	// Find existing script → found
	mc.pushReply(reReply(map[string]string{".id": "*OLD"}))
	// Remove old script
	mc.pushReply(emptyReply())
	// Add new script
	mc.pushReply(doneReply(map[string]string{"ret": "*NEW"}))
	// Run script
	mc.pushReply(emptyReply())
	// Remove new script
	mc.pushReply(emptyReply())

	script := buildBulkAddScript("ip", "list", []BulkEntry{{Address: "1.1.1.1", Timeout: "1h", Comment: "test"}})
	n, err := c.runBulkScript(script)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1, got %d", n)
	}
}

// TestRunBulkScript_RunError verifies script cleanup on execution error.
func TestRunBulkScript_RunError(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	// Find → not found
	mc.pushReply(emptyReply())
	// Add script
	mc.pushReply(doneReply(map[string]string{"ret": "*S1"}))
	// Run fails
	mc.pushError(errors.New("script error"))
	mc.pushError(errors.New("script error")) // reconnect retry
	// Remove script (cleanup)
	mc.pushReply(emptyReply())

	_, err := c.runBulkScript("test-script")
	if err == nil || !strings.Contains(err.Error(), "run bulk script") {
		t.Fatalf("expected run error, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Pool operations
// ─────────────────────────────────────────────────────────────────────────────

// TestPool_GetPut verifies borrowing and returning clients.
func TestPool_GetPut(t *testing.T) {
	cfg := config.MikroTikConfig{Address: "127.0.0.1"}
	p := NewPool(cfg, 2)

	// Manually inject mock clients
	mc1 := newMockConn()
	mc2 := newMockConn()
	c1 := newTestClient(mc1)
	c2 := newTestClient(mc2)
	p.conns <- c1
	p.conns <- c2

	// Get both
	got1 := p.Get()
	got2 := p.Get()
	if got1 == nil || got2 == nil {
		t.Fatal("expected non-nil clients")
	}

	// Put them back
	p.Put(got1)
	p.Put(got2)

	// Verify we can get them again
	got3 := p.Get()
	if got3 == nil {
		t.Fatal("expected non-nil client after Put")
	}
	p.Put(got3)
}

// TestPool_Close verifies all connections are closed.
func TestPool_Close(t *testing.T) {
	cfg := config.MikroTikConfig{Address: "127.0.0.1"}
	p := NewPool(cfg, 2)

	mc1 := newMockConn()
	mc2 := newMockConn()
	p.conns <- newTestClient(mc1)
	p.conns <- newTestClient(mc2)

	p.Close()

	if !mc1.closed || !mc2.closed {
		t.Fatal("expected all mock connections to be closed")
	}
}

// TestPool_CloseIdempotent verifies Close can be called multiple times safely.
func TestPool_CloseIdempotent(t *testing.T) {
	cfg := config.MikroTikConfig{Address: "127.0.0.1"}
	p := NewPool(cfg, 1)
	p.conns <- newTestClient(newMockConn())

	p.Close()
	p.Close() // should not panic
}

// TestParallelExec_Success verifies parallel execution with all successes.
func TestParallelExec_Success(t *testing.T) {
	cfg := config.MikroTikConfig{Address: "127.0.0.1"}
	p := NewPool(cfg, 2)

	mc1 := newMockConn()
	mc2 := newMockConn()
	p.conns <- newTestClient(mc1)
	p.conns <- newTestClient(mc2)

	items := []string{"a", "b", "c"}
	var mu sync.Mutex
	var processed []string

	errs := ParallelExec(p, items, func(c *Client, item string) error {
		mu.Lock()
		processed = append(processed, item)
		mu.Unlock()
		return nil
	})

	if len(errs) != 0 {
		t.Fatalf("expected no errors, got: %v", errs)
	}
	if len(processed) != 3 {
		t.Fatalf("expected 3 processed, got %d", len(processed))
	}
}

// TestParallelExec_CollectsErrors verifies error collection.
func TestParallelExec_CollectsErrors(t *testing.T) {
	cfg := config.MikroTikConfig{Address: "127.0.0.1"}
	p := NewPool(cfg, 1)
	p.conns <- newTestClient(newMockConn())

	items := []int{1, 2, 3}
	errs := ParallelExec(p, items, func(c *Client, item int) error {
		if item == 2 {
			return errors.New("fail on 2")
		}
		return nil
	})

	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}
}

// TestParallelExec_EmptyItems verifies no-op with empty input.
func TestParallelExec_EmptyItems(t *testing.T) {
	cfg := config.MikroTikConfig{Address: "127.0.0.1"}
	p := NewPool(cfg, 2)

	errs := ParallelExec(p, []string{}, func(c *Client, item string) error {
		t.Fatal("should not be called")
		return nil
	})

	if errs != nil {
		t.Fatalf("expected nil, got: %v", errs)
	}
}

// TestParallelExec_WorkersLimitedByItems verifies workers capped at item count.
func TestParallelExec_WorkersLimitedByItems(t *testing.T) {
	cfg := config.MikroTikConfig{Address: "127.0.0.1"}
	p := NewPool(cfg, 10)

	// Only add 1 client — but only 1 item so only 1 worker needed
	p.conns <- newTestClient(newMockConn())

	called := false
	errs := ParallelExec(p, []string{"only-one"}, func(c *Client, item string) error {
		called = true
		return nil
	})

	if !called {
		t.Fatal("expected function to be called")
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got: %v", errs)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetFirewallCounters tests
// ─────────────────────────────────────────────────────────────────────────────

// TestGetFirewallCounters_AllPaths verifies that GetFirewallCounters queries
// all 4 firewall paths and aggregates bytes/packets per IP type, separating
// dropped (drop/reject) from processed (all rules).
func TestGetFirewallCounters_AllPaths(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	// Path 1: ip/firewall/filter — drop rule + accept (whitelist) rule
	mc.pushReply(reReply(
		map[string]string{".id": "*1", "bytes": "1000", "packets": "10", "comment": "crowdsec-bouncer:filter-input-v4", "action": "drop"},
		map[string]string{".id": "*A", "bytes": "200", "packets": "2", "comment": "crowdsec-bouncer:filter-wl-v4", "action": "accept"},
		map[string]string{".id": "*2", "bytes": "500", "packets": "5", "comment": "other-rule", "action": "drop"},
	))
	// Path 2: ip/firewall/raw — reject rule
	mc.pushReply(reReply(
		map[string]string{".id": "*3", "bytes": "2000", "packets": "20", "comment": "crowdsec-bouncer:raw-prerouting-v4", "action": "reject"},
	))
	// Path 3: ipv6/firewall/filter — drop rule
	mc.pushReply(reReply(
		map[string]string{".id": "*4", "bytes": "300", "packets": "3", "comment": "crowdsec-bouncer:filter-input-v6", "action": "drop"},
	))
	// Path 4: ipv6/firewall/raw — passthrough rule
	mc.pushReply(reReply(
		map[string]string{".id": "*5", "bytes": "700", "packets": "7", "comment": "crowdsec-bouncer:raw-prerouting-v6", "action": "passthrough"},
	))

	fc, err := c.GetFirewallCounters("crowdsec-bouncer:")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 5 rules should match (not "other-rule").
	if len(fc.Rules) != 5 {
		t.Errorf("want 5 matching rules, got %d", len(fc.Rules))
	}

	// IPv4 totals (processed): 1000 + 200 + 2000 = 3200 bytes, 10 + 2 + 20 = 32 packets.
	if fc.IPv4Bytes != 3200 || fc.IPv4Pkts != 32 {
		t.Errorf("IPv4: want (3200,32), got (%d,%d)", fc.IPv4Bytes, fc.IPv4Pkts)
	}

	// IPv6 totals (processed): 300 + 700 = 1000 bytes, 3 + 7 = 10 packets.
	if fc.IPv6Bytes != 1000 || fc.IPv6Pkts != 10 {
		t.Errorf("IPv6: want (1000,10), got (%d,%d)", fc.IPv6Bytes, fc.IPv6Pkts)
	}

	// Grand totals (processed): 3200 + 1000 = 4200 bytes, 32 + 10 = 42 packets.
	if fc.TotalBytes != 4200 || fc.TotalPkts != 42 {
		t.Errorf("Total: want (4200,42), got (%d,%d)", fc.TotalBytes, fc.TotalPkts)
	}

	// Dropped IPv4: drop(1000,10) + reject(2000,20) = (3000,30). Accept is excluded.
	if fc.DroppedIPv4Bytes != 3000 || fc.DroppedIPv4Pkts != 30 {
		t.Errorf("DroppedIPv4: want (3000,30), got (%d,%d)", fc.DroppedIPv4Bytes, fc.DroppedIPv4Pkts)
	}

	// Dropped IPv6: only drop(300,3). Passthrough is excluded.
	if fc.DroppedIPv6Bytes != 300 || fc.DroppedIPv6Pkts != 3 {
		t.Errorf("DroppedIPv6: want (300,3), got (%d,%d)", fc.DroppedIPv6Bytes, fc.DroppedIPv6Pkts)
	}

	// Dropped total: 3000 + 300 = 3300 bytes, 30 + 3 = 33 packets.
	if fc.DroppedBytes != 3300 || fc.DroppedPkts != 33 {
		t.Errorf("DroppedTotal: want (3300,33), got (%d,%d)", fc.DroppedBytes, fc.DroppedPkts)
	}

	// Processed: only passthrough rules. IPv4 has none, IPv6 has (700,7).
	if fc.ProcessedIPv4Bytes != 0 || fc.ProcessedIPv4Pkts != 0 {
		t.Errorf("ProcessedIPv4: want (0,0), got (%d,%d)", fc.ProcessedIPv4Bytes, fc.ProcessedIPv4Pkts)
	}
	if fc.ProcessedIPv6Bytes != 700 || fc.ProcessedIPv6Pkts != 7 {
		t.Errorf("ProcessedIPv6: want (700,7), got (%d,%d)", fc.ProcessedIPv6Bytes, fc.ProcessedIPv6Pkts)
	}
}

// TestGetFirewallCounters_EmptyPrefix verifies that an empty comment prefix
// matches ALL rules, not just those with the bouncer prefix.
func TestGetFirewallCounters_EmptyPrefix(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	// Only one path with two rules (both should match with empty prefix).
	mc.pushReply(reReply(
		map[string]string{".id": "*1", "bytes": "100", "packets": "1", "comment": "anything", "action": "drop"},
		map[string]string{".id": "*2", "bytes": "200", "packets": "2", "comment": "", "action": "accept"},
	))
	mc.pushReply(reReply()) // empty paths
	mc.pushReply(reReply())
	mc.pushReply(reReply())

	fc, err := c.GetFirewallCounters("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.Rules) != 2 {
		t.Errorf("want 2 rules with empty prefix, got %d", len(fc.Rules))
	}
	if fc.TotalBytes != 300 {
		t.Errorf("want 300 total bytes, got %d", fc.TotalBytes)
	}
}

// TestGetFirewallCounters_PathError verifies that errors on individual paths
// are skipped without failing the entire operation.
func TestGetFirewallCounters_PathError(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	// Path 1: success
	mc.pushReply(reReply(
		map[string]string{".id": "*1", "bytes": "500", "packets": "5", "comment": "cs:test", "action": "drop"},
	))
	// Path 2: error (e.g. ipv6 not enabled)
	mc.pushError(errors.New("no such command prefix"))
	// Path 3: success
	mc.pushReply(reReply(
		map[string]string{".id": "*2", "bytes": "100", "packets": "1", "comment": "cs:test6", "action": "drop"},
	))
	// Path 4: error
	mc.pushError(errors.New("no such command prefix"))

	fc, err := c.GetFirewallCounters("cs:")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.Rules) != 2 {
		t.Errorf("want 2 rules (skipped errored paths), got %d", len(fc.Rules))
	}
	if fc.TotalBytes != 600 {
		t.Errorf("want 600 total bytes, got %d", fc.TotalBytes)
	}
}

// TestGetFirewallCounters_InvalidNumbers verifies that non-numeric byte/packet
// values are parsed as 0 (no error).
func TestGetFirewallCounters_InvalidNumbers(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(reReply(
		map[string]string{".id": "*1", "bytes": "notanumber", "packets": "", "comment": "cs:test", "action": "drop"},
	))
	mc.pushReply(reReply())
	mc.pushReply(reReply())
	mc.pushReply(reReply())

	fc, err := c.GetFirewallCounters("cs:")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fc.TotalBytes != 0 || fc.TotalPkts != 0 {
		t.Errorf("want (0,0) for invalid numbers, got (%d,%d)", fc.TotalBytes, fc.TotalPkts)
	}
}

// ===========================================================================
// ListFirewallRulesBySignature tests — 0% coverage before
// ===========================================================================

// TestListFirewallRulesBySignature_FiltersMatching verifies that only rules
// whose comment contains the signature substring are returned.
func TestListFirewallRulesBySignature_FiltersMatching(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(reReply(
		map[string]string{
			".id": "*1", "chain": "input", "action": "drop",
			"comment": "cs-bouncer:filter-input-v4 @cs-routeros-bouncer",
		},
		map[string]string{
			".id": "*2", "chain": "forward", "action": "accept",
			"comment": "user rule - no signature",
		},
		map[string]string{
			".id": "*3", "chain": "input", "action": "reject",
			"comment": "other:raw-prerouting-v6 @cs-routeros-bouncer",
		},
	))

	entries, err := c.ListFirewallRulesBySignature("ip", "filter", "@cs-routeros-bouncer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].ID != "*1" || entries[1].ID != "*3" {
		t.Errorf("wrong IDs: %q, %q", entries[0].ID, entries[1].ID)
	}
}

// TestListFirewallRulesBySignature_NoMatches verifies an empty result when
// no rules contain the signature.
func TestListFirewallRulesBySignature_NoMatches(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(reReply(
		map[string]string{".id": "*1", "comment": "user rule"},
		map[string]string{".id": "*2", "comment": "another rule"},
	))

	entries, err := c.ListFirewallRulesBySignature("ip", "raw", "@cs-routeros-bouncer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

// TestListFirewallRulesBySignature_EmptyList verifies handling of no rules.
func TestListFirewallRulesBySignature_EmptyList(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)
	mc.pushReply(emptyReply())

	entries, err := c.ListFirewallRulesBySignature("ipv6", "filter", "@cs-routeros-bouncer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

// TestListFirewallRulesBySignature_ParsesAllFields verifies all RuleEntry
// fields are populated.
func TestListFirewallRulesBySignature_ParsesAllFields(t *testing.T) {
	mc := newMockConn()
	c := newTestClient(mc)

	mc.pushReply(reReply(map[string]string{
		".id": "*A", "chain": "forward", "action": "reject",
		"src-address": "10.0.0.0/8", "src-address-list": "banned",
		"dst-address-list": "servers", "in-interface": "ether1",
		"in-interface-list": "LAN", "out-interface": "ether2",
		"out-interface-list": "WAN", "connection-state": "new",
		"reject-with": "icmp-net-unreachable",
		"comment":     "cs:filter-forward-v4 @cs-routeros-bouncer",
	}))

	entries, err := c.ListFirewallRulesBySignature("ip", "filter", "@cs-routeros-bouncer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	checks := []struct {
		name, got, want string
	}{
		{"ID", e.ID, "*A"},
		{"Chain", e.Chain, "forward"},
		{"Action", e.Action, "reject"},
		{"SrcAddress", e.SrcAddress, "10.0.0.0/8"},
		{"SrcAddressList", e.SrcAddressList, "banned"},
		{"DstAddressList", e.DstAddressList, "servers"},
		{"InInterface", e.InInterface, "ether1"},
		{"InInterfaceList", e.InInterfaceList, "LAN"},
		{"OutInterface", e.OutInterface, "ether2"},
		{"OutInterfaceList", e.OutInterfaceList, "WAN"},
		{"ConnectionState", e.ConnectionState, "new"},
		{"RejectWith", e.RejectWith, "icmp-net-unreachable"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: expected %q, got %q", c.name, c.want, c.got)
		}
	}
}

// ---------------------------------------------------------------------------
// GetSystemResources
// ---------------------------------------------------------------------------

// TestGetSystemResources_HappyPath verifies that GetSystemResources correctly
// parses a complete RouterOS /system/resource response into the SystemResources
// struct, including CPU load, memory, uptime, version, and board name.
func TestGetSystemResources_HappyPath(t *testing.T) {
	mc := newMockConn()
	client := newTestClient(mc)

	mc.pushReply(reReply(map[string]string{
		"cpu-load":     "15",
		"free-memory":  "536870912",
		"total-memory": "1073741824",
		"uptime":       "1w2d3h4m5s",
		"version":      "7.16.2",
		"board-name":   "RB4011iGS+",
	}))

	sr, err := client.GetSystemResources()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sr.CPULoad != 15 {
		t.Errorf("CPULoad: expected 15, got %d", sr.CPULoad)
	}
	if sr.FreeMemory != 536870912 {
		t.Errorf("FreeMemory: expected 536870912, got %d", sr.FreeMemory)
	}
	if sr.TotalMemory != 1073741824 {
		t.Errorf("TotalMemory: expected 1073741824, got %d", sr.TotalMemory)
	}
	if sr.Uptime != "1w2d3h4m5s" {
		t.Errorf("Uptime: expected %q, got %q", "1w2d3h4m5s", sr.Uptime)
	}
	if sr.Version != "7.16.2" {
		t.Errorf("Version: expected %q, got %q", "7.16.2", sr.Version)
	}
	if sr.BoardName != "RB4011iGS+" {
		t.Errorf("BoardName: expected %q, got %q", "RB4011iGS+", sr.BoardName)
	}
}

// TestGetSystemResources_Error verifies that GetSystemResources propagates
// connection errors from the underlying RouterOS command.
func TestGetSystemResources_Error(t *testing.T) {
	mc := newMockConn()
	client := newTestClient(mc)

	mc.pushError(fmt.Errorf("connection lost"))
	mc.pushError(fmt.Errorf("connection lost")) // retry path also fails

	_, err := client.GetSystemResources()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestGetSystemResources_EmptyResponse verifies that GetSystemResources returns
// an "empty response" error when the router replies with no data sentences.
func TestGetSystemResources_EmptyResponse(t *testing.T) {
	mc := newMockConn()
	client := newTestClient(mc)

	mc.pushReply(emptyReply())

	_, err := client.GetSystemResources()
	if err == nil {
		t.Fatal("expected error for empty response, got nil")
	}
	if !strings.Contains(err.Error(), "empty response") {
		t.Errorf("expected error to mention 'empty response', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetSystemHealth
// ---------------------------------------------------------------------------

// TestGetSystemHealth_HappyPath verifies that GetSystemHealth correctly parses
// the cpu-temperature entry from a RouterOS /system/health response.
func TestGetSystemHealth_HappyPath(t *testing.T) {
	mc := newMockConn()
	client := newTestClient(mc)

	mc.pushReply(reReply(map[string]string{
		"name":  "cpu-temperature",
		"value": "47",
	}))

	sh, err := client.GetSystemHealth()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sh.CPUTemperature != 47 {
		t.Errorf("CPUTemperature: expected 47, got %f", sh.CPUTemperature)
	}
}

// TestGetSystemHealth_NoTemperature verifies that GetSystemHealth returns -1
// for CPUTemperature when the response contains health entries but none for
// cpu-temperature (e.g., devices without a temperature sensor).
func TestGetSystemHealth_NoTemperature(t *testing.T) {
	mc := newMockConn()
	client := newTestClient(mc)

	mc.pushReply(reReply(map[string]string{
		"name":  "voltage",
		"value": "24.1",
	}))

	sh, err := client.GetSystemHealth()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sh.CPUTemperature != -1 {
		t.Errorf("CPUTemperature: expected -1 when not found, got %f", sh.CPUTemperature)
	}
}

// TestGetSystemHealth_Error verifies that GetSystemHealth propagates connection
// errors from the underlying RouterOS command.
func TestGetSystemHealth_Error(t *testing.T) {
	mc := newMockConn()
	client := newTestClient(mc)

	mc.pushError(fmt.Errorf("connection lost"))
	mc.pushError(fmt.Errorf("connection lost")) // retry path also fails

	_, err := client.GetSystemHealth()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestGetSystemHealth_EmptyResults verifies that GetSystemHealth returns -1
// for CPUTemperature when the router replies with an empty health table.
func TestGetSystemHealth_EmptyResults(t *testing.T) {
	mc := newMockConn()
	client := newTestClient(mc)

	mc.pushReply(emptyReply())

	sh, err := client.GetSystemHealth()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sh.CPUTemperature != -1 {
		t.Errorf("CPUTemperature: expected -1 for empty results, got %f", sh.CPUTemperature)
	}
}
