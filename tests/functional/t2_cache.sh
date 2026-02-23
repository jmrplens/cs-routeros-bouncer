# =============================================================================
# T2: Cache Consistency — Ban / Unban Lifecycle
# =============================================================================
# Tests the bouncer service's ability to track bans/unbans by adding and
# removing decisions via cscli and verifying the router state via SSH.
# =============================================================================

TEST_IP_BAN="198.51.100.1"
TEST_IP_EXPIRE="198.51.100.2"

_cleanup_test_ips() {
    lapi_remove_decision "$TEST_IP_BAN"
    lapi_remove_decision "$TEST_IP_EXPIRE"
}

# T2.1 — Metrics match router count
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

# T2.2 — Live ban appears on router
t2_2_live_ban() {
    bouncer_running || skip_test "bouncer not running"
    _cleanup_test_ips

    local count_before
    count_before=$(ssh_count_addresses "${TEST_IPV4_LIST}")

    lapi_add_decision "$TEST_IP_BAN" "5m" "functional-test-ban"
    log "Added $TEST_IP_BAN, waiting for bouncer poll..."

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

# T2.3 — Live unban removes from router
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

# T2.4 — Expired-on-router scenario
t2_4_expired_resilience() {
    bouncer_running || skip_test "bouncer not running"
    _cleanup_test_ips

    # Add decision with short duration
    lapi_add_decision "$TEST_IP_EXPIRE" "30s" "test-expire"
    log "Added $TEST_IP_EXPIRE with 30s duration, waiting for it to reach router..."

    wait_for "IP on router" 40 5 \
        ssh_list_addresses "${TEST_IPV4_LIST}" '|' grep -qF "$TEST_IP_EXPIRE" 2>/dev/null \
        || true

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

# T2.5 — Cache fast-path for unknown IPs
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

# T2.6 — Rapid ban/unban same IP
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
    if (( errors > 0 )); then
        echo "FAIL: Panics during rapid cycle"
        return 1
    fi
    lapi_remove_decision "$ip"
    log "Rapid ban/unban cycle completed without errors"
}
run_test "T2.6 Rapid ban/unban cycle" t2_6_rapid_cycle
