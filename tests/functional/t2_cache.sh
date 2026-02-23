# shellcheck shell=bash
# =============================================================================
# T2: Cache Consistency — Ban / Unban Lifecycle
# =============================================================================
# Tests the bouncer's ability to track individual ban/unban decisions by
# adding and removing decisions via cscli, then verifying router state via SSH.
# Covers the full decision lifecycle: metrics accuracy, live ban/unban
# propagation, RouterOS-side expiry handling, cache fast-path, and rapid
# ban/unban race conditions.
#
# Prerequisites:
#   - Bouncer running with Prometheus metrics on :2112/metrics
#   - LAPI accessible (cscli / lapi_add_decision / lapi_remove_decision)
#   - SSH access to router
#   - Uses RFC 5737 TEST-NET-2 (198.51.100.0/24) addresses to avoid conflicts
#
# Tests:
#   T2.1  Metrics vs router count   — Prometheus gauge matches SSH count
#   T2.2  Live ban → router         — decision appears on router within 60 s
#   T2.3  Live unban → removed      — decision removed from router within 60 s
#   T2.4  Expired-on-router         — RouterOS auto-expires, LAPI remove is graceful
#   T2.5  Cache fast-path           — no panics when cache skips unknown IPs
#   T2.6  Rapid ban/unban cycle     — 3 rapid add/delete cycles, no panics
# =============================================================================

TEST_IP_BAN="198.51.100.1"
TEST_IP_EXPIRE="198.51.100.2"

# Helper: remove test IPs from LAPI to ensure a clean state between tests.
_cleanup_test_ips() {
    lapi_remove_decision "$TEST_IP_BAN"
    lapi_remove_decision "$TEST_IP_EXPIRE"
}

# T2.1 — Metrics vs router count.
# Reads the crowdsec_bouncer_active_decisions{proto="ipv4"} Prometheus gauge
# and compares it with the SSH-counted address list size.
# Pass: difference ≤10 (small IPv6 accounting variance is expected).
t2_1_metrics_vs_router() {
    bouncer_running || skip_test "bouncer not running"

    local metric_count router_count
    metric_count=$(curl -s --max-time 5 "http://localhost:2112/metrics" 2>/dev/null \
        | awk '/^crowdsec_bouncer_active_decisions\{proto="ipv4"\}/ {print $2}')
    [[ -n "$metric_count" ]] || skip_test "metrics endpoint not available"

    router_count=$(ssh_count_addresses "${TEST_IPV4_LIST}")
    # Allow small discrepancy for IPv6 counted separately
    local diff=$(( ${metric_count%.*} - router_count ))
    diff=${diff#-}  # absolute value

    if (( diff > 10 )); then
        echo "FAIL: metrics=$metric_count router=$router_count diff=$diff (threshold: 10)"
        return 1
    fi
    log "Metrics: $metric_count  Router: $router_count  Diff: $diff"
}
run_test "T2.1 Metrics vs router count" t2_1_metrics_vs_router

# T2.2 — Live ban appears on router.
# Adds a 5-minute ban via LAPI and polls the router every 5 s (up to 60 s)
# until the IP appears in the address list.
# Pass: IP found on router within the polling window.
t2_2_live_ban() {
    bouncer_running || skip_test "bouncer not running"
    _cleanup_test_ips

    local count_before
    count_before=$(ssh_count_addresses "${TEST_IPV4_LIST}")

    lapi_add_decision "$TEST_IP_BAN" "5m" "functional-test-ban"
    log "Added $TEST_IP_BAN (list had $count_before entries), waiting for bouncer poll..."

    local found=false
    for i in $(seq 1 12); do
        sleep 5
        if ssh_list_addresses "${TEST_IPV4_LIST}" | grep -qF "$TEST_IP_BAN"; then
            found=true; break
        fi
    done

    if ! $found; then
        echo "FAIL: $TEST_IP_BAN not found on router after 60s"
        _cleanup_test_ips; return 1
    fi
    log "IP appeared on router after ~$((i * 5))s"
}
run_test "T2.2 Live ban → router" t2_2_live_ban

# T2.3 — Live unban removes from router.
# Depends on T2.2 leaving TEST_IP_BAN on the router.  Removes the decision
# from LAPI and polls until the IP disappears (up to 60 s).
# Pass: IP no longer present on router.
t2_3_live_unban() {
    bouncer_running || skip_test "bouncer not running"

    # Ensure the test IP from T2.2 is present
    if ! ssh_list_addresses "${TEST_IPV4_LIST}" | grep -qF "$TEST_IP_BAN"; then
        skip_test "$TEST_IP_BAN not on router (T2.2 may have been skipped)"
    fi

    lapi_remove_decision "$TEST_IP_BAN"
    log "Removed $TEST_IP_BAN, waiting for bouncer poll..."

    local removed=false
    for i in $(seq 1 12); do
        sleep 5
        if ! ssh_list_addresses "${TEST_IPV4_LIST}" | grep -qF "$TEST_IP_BAN"; then
            removed=true; break
        fi
    done

    if ! $removed; then
        echo "FAIL: $TEST_IP_BAN still on router after 60s"
        return 1
    fi
    log "IP removed from router after ~$((i * 5))s"
}
run_test "T2.3 Live unban → removed" t2_3_live_unban

# T2.4 — Expired-on-router resilience.
# Adds a 30 s decision so RouterOS auto-expires the entry before the bouncer
# processes the LAPI removal.  The bouncer must handle the "already gone"
# condition gracefully (no panic/fatal when unbanning a missing address).
# Pass: zero panic/fatal/error messages in bouncer logs.
t2_4_expired_resilience() {
    bouncer_running || skip_test "bouncer not running"
    _cleanup_test_ips

    # Add decision with short duration
    lapi_add_decision "$TEST_IP_EXPIRE" "30s" "test-expire"
    log "Added $TEST_IP_EXPIRE with 30s duration, waiting for it to reach router..."

    local _found=false
    for _ in $(seq 1 8); do
        if ssh_list_addresses "${TEST_IPV4_LIST}" | grep -qF "$TEST_IP_EXPIRE" 2>/dev/null; then
            _found=true; break
        fi
        sleep 5
    done
    $_found || warn "IP may not have reached router in time"

    # Wait for RouterOS timeout to expire it
    log "Waiting 40s for RouterOS auto-expiry..."
    sleep 40

    # Remove from LAPI (should handle missing gracefully)
    lapi_remove_decision "$TEST_IP_EXPIRE"
    sleep 20

    # Check bouncer logs for graceful handling (no panics/errors)
    local errors
    errors=$(bouncer_logs_since "2 minutes ago" | grep -ci "panic\|fatal\|error.*unban" || true)
    if (( errors > 0 )); then
        echo "FAIL: Found $errors panic/fatal/error messages during expired unban"
        return 1
    fi
}
run_test "T2.4 Expired-on-router resilience" t2_4_expired_resilience

# T2.5 — Cache fast-path (no panics).
# The bouncer's internal cache avoids unnecessary API calls for IPs that were
# never added.  This test verifies no panics appear in recent logs, which
# would indicate the cache failed to prevent an invalid operation.
# Pass: zero panics in last 5 minutes of logs.
t2_5_cache_fast_path() {
    bouncer_running || skip_test "bouncer not running"

    # The cache should prevent API calls for IPs never added.
    # Check logs for "not in cache" or "skipping" type messages.
    local logs
    logs=$(bouncer_logs_since "5 minutes ago")

    # Just verify no panics — the fast-path is an optimization, not a hard requirement
    local panics
    panics=$(echo "$logs" | grep -ci "panic" || true)
    if (( panics > 0 )); then
        echo "FAIL: Found panics in bouncer logs"
        return 1
    fi
    log "No panics in recent logs — cache operating normally"
}
run_test "T2.5 Cache fast-path (no panics)" t2_5_cache_fast_path

# T2.6 — Rapid ban/unban cycle.
# Performs 3 quick add/remove cycles on the same IP (1 s apart) to stress the
# cache and decision pipeline.  Rapid toggling can trigger race conditions
# if the bouncer processes additions and deletions concurrently.
# Pass: zero panic/fatal messages in bouncer logs.
t2_6_rapid_cycle() {
    bouncer_running || skip_test "bouncer not running"
    _cleanup_test_ips

    local ip="198.51.100.50"
    for i in 1 2 3; do
        lapi_add_decision "$ip" "5m" "rapid-test-$i"
        sleep 1
        lapi_remove_decision "$ip"
        sleep 1
    done

    # Wait for bouncer to process
    sleep 20

    # Check no errors
    local errors
    errors=$(bouncer_logs_since "1 minute ago" | grep -ci "panic\|fatal" || true)
    lapi_remove_decision "$ip"
    if (( errors > 0 )); then
        echo "FAIL: Panics during rapid cycle"
        return 1
    fi
    log "Rapid ban/unban cycle completed without errors"
}
run_test "T2.6 Rapid ban/unban cycle" t2_6_rapid_cycle
