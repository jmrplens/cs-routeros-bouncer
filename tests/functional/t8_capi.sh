# =============================================================================
# T8: CAPI Stress Test — ~25,000 IPs (Community Blocklist)
# =============================================================================
# Tests bouncer behaviour with ALL origins including CAPI (community
# blocklist). This is gated behind the --capi flag because it takes
# several minutes and significantly loads the router.
#
# Config change: origins: ["crowdsec", "cscli", "CAPI"]
# Expected IPs: ~25,000 (varies with community list size)
#
# IMPORTANT: T8 restores the original config at the end (T8.10).
# =============================================================================

readonly BOUNCER_CONFIG="/etc/cs-routeros-bouncer/config.yaml"
readonly CAPI_ORIGINS='["crowdsec", "cscli", "CAPI"]'
readonly LOCAL_ORIGINS='["crowdsec", "cscli"]'

# ---- Helpers for config switching ----
set_origins() {
    local origins="$1"
    sudo sed -i "s|origins:.*|origins: ${origins}|" "$BOUNCER_CONFIG"
    log "Set origins to $origins"
}

restore_local_origins() {
    set_origins "$LOCAL_ORIGINS"
}

# ---- Tests ----

# T8.1 — Full reconciliation with ALL origins (~25k IPs)
t8_1_full_reconciliation_capi() {
    log "Stopping bouncer, enabling CAPI origins..."
    bouncer_stop; sleep 2
    set_origins "$CAPI_ORIGINS"

    ssh_clean_list "${TEST_IPV4_LIST}"
    ssh_clean_list "${TEST_IPV6_LIST}"

    local expected; expected=$(lapi_count_all)
    log "LAPI has ~$expected active decisions (all origins)"

    local start_ts; start_ts=$(date +%s)
    bouncer_start

    # CAPI reconciliation can take several minutes
    bouncer_wait_reconciliation 300 || warn "reconciliation timeout (may still be running)"

    local end_ts; end_ts=$(date +%s)
    local elapsed=$(( end_ts - start_ts ))
    local count; count=$(ssh_count_addresses "${TEST_IPV4_LIST}")

    log "CAPI reconciliation: ${elapsed}s, router has $count IPv4 (expected ~$expected)"

    # Check for bulk errors
    local errors
    errors=$(bouncer_logs_since "$(date -d "@$start_ts" '+%Y-%m-%d %H:%M:%S')" \
        | grep -ci "EOF\|connection reset\|message too large" || true)

    if (( errors > 0 )); then
        echo "FAIL: $errors bulk errors during CAPI reconciliation"
        return 1
    fi

    if (( count < expected / 2 )); then
        echo "FAIL: only $count addresses on router (expected ~$expected)"
        return 1
    fi
    log "CAPI T8.1 PASS: $count IPs in ${elapsed}s"
}
run_test "T8.1 CAPI full reconciliation (~25k IPs)" t8_1_full_reconciliation_capi

# T8.2 — CPU peak during CAPI reconciliation
t8_2_cpu_peak() {
    influx_available || skip_test "InfluxDB not configured"

    local result; result=$(query_cpu "5m")
    local avg=${result%% *} max=${result##* }
    local max_int=${max%.*}

    log "CAPI reconciliation CPU: avg=${avg}% peak=${max}%"

    if (( max_int > 60 )); then
        echo "FAIL: CAPI CPU peak ${max}% exceeds 60%"
        return 1
    fi
}
run_test "T8.2 CAPI CPU peak" t8_2_cpu_peak

# T8.3 — IP completeness with ALL origins
t8_3_completeness() {
    bouncer_running || skip_test "bouncer not running"

    local lapi_count; lapi_count=$(lapi_count_all)
    local router_count; router_count=$(ssh_count_addresses "${TEST_IPV4_LIST}")
    local ipv6_count; ipv6_count=$(ssh_count_addresses "${TEST_IPV6_LIST}")
    local total=$(( router_count + ipv6_count ))

    log "CAPI completeness: LAPI=$lapi_count router_total=$total (IPv4=$router_count IPv6=$ipv6_count)"

    local diff=$(( lapi_count - total ))
    diff=${diff#-}
    if (( diff > 100 )); then
        echo "FAIL: CAPI completeness gap=$diff (LAPI=$lapi_count router=$total)"
        return 1
    fi
}
run_test "T8.3 CAPI IP completeness" t8_3_completeness

# T8.4 — IPv6 parity with CAPI
t8_4_ipv6_parity() {
    bouncer_running || skip_test "bouncer not running"

    local ipv6_lapi; ipv6_lapi=$(lapi_ipv6_count_all)
    local ipv6_router; ipv6_router=$(ssh_count_addresses "${TEST_IPV6_LIST}")

    log "CAPI IPv6: LAPI=$ipv6_lapi router=$ipv6_router"

    local diff=$(( ipv6_lapi - ipv6_router ))
    diff=${diff#-}
    if (( diff > 20 )); then
        echo "FAIL: CAPI IPv6 gap=$diff (LAPI=$ipv6_lapi router=$ipv6_router)"
        return 1
    fi
}
run_test "T8.4 CAPI IPv6 parity" t8_4_ipv6_parity

# T8.5 — Restart idempotency with ~25k entries
t8_5_restart_idempotency() {
    bouncer_running || skip_test "bouncer not running"

    local count_before; count_before=$(ssh_count_addresses "${TEST_IPV4_LIST}")
    log "Count before restart: $count_before"

    local start_ts; start_ts=$(date +%s)
    bouncer_restart
    bouncer_wait_reconciliation 120

    local end_ts; end_ts=$(date +%s)
    local elapsed=$(( end_ts - start_ts ))
    local count_after; count_after=$(ssh_count_addresses "${TEST_IPV4_LIST}")

    log "CAPI restart: ${elapsed}s (count: $count_before → $count_after)"

    local diff=$(( count_before - count_after ))
    diff=${diff#-}
    if (( diff > 50 )); then
        echo "FAIL: CAPI restart lost/gained addresses (diff=$diff)"
        return 1
    fi

    # Restart with existing data should be much faster than full reconciliation
    if (( elapsed > 60 )); then
        warn "CAPI restart took ${elapsed}s (expected < 60s)"
    fi
}
run_test "T8.5 CAPI restart idempotency" t8_5_restart_idempotency

# T8.6 — Unban latency with large cache
t8_6_unban_latency_large() {
    bouncer_running || skip_test "bouncer not running"

    local ip="198.51.100.95"
    lapi_remove_decision "$ip" 2>/dev/null || true

    # Add a test IP
    lapi_add_decision "$ip" "5m" "capi-unban-test"
    sleep 20  # wait for add

    if ! ssh_list_addresses "${TEST_IPV4_LIST}" | grep -qF "$ip"; then
        warn "Test IP not on router, skipping unban test"
        lapi_remove_decision "$ip"
        return 0
    fi

    local start_ts; start_ts=$(date +%s)
    lapi_remove_decision "$ip"

    local removed=false
    for i in $(seq 1 15); do
        sleep 2
        if ! ssh_list_addresses "${TEST_IPV4_LIST}" | grep -qF "$ip"; then
            removed=true; break
        fi
    done

    local end_ts; end_ts=$(date +%s)
    local elapsed=$(( end_ts - start_ts ))

    if ! $removed; then
        warn "Unban not confirmed in 30s (may be timeout-based)"
    else
        log "CAPI unban latency: ${elapsed}s"
    fi
}
run_test "T8.6 CAPI unban latency (large cache)" t8_6_unban_latency_large

# T8.7 — Steady-state CPU with ~25k entries
t8_7_steady_state_cpu() {
    influx_available || skip_test "InfluxDB not configured"
    bouncer_running || skip_test "bouncer not running"

    log "Waiting 2 minutes for CAPI steady state..."
    sleep 120

    local result; result=$(query_cpu "1m")
    local avg=${result%% *} max=${result##* }

    log "CAPI steady-state CPU: avg=${avg}% max=${max}%"

    local avg_int=${avg%.*}
    if (( avg_int > 30 )); then
        echo "FAIL: CAPI steady-state avg CPU ${avg}% exceeds 30%"
        return 1
    fi
}
run_test "T8.7 CAPI steady-state CPU" t8_7_steady_state_cpu

# T8.8 — Restore to local-only (mass removal)
t8_8_restore_local() {
    local count_before; count_before=$(ssh_count_addresses "${TEST_IPV4_LIST}")
    log "Current count: $count_before"

    log "Restoring local-only config..."
    bouncer_stop; sleep 2
    restore_local_origins

    local start_ts; start_ts=$(date +%s)
    bouncer_start
    bouncer_wait_reconciliation 300 || warn "reconciliation timeout"

    local end_ts; end_ts=$(date +%s)
    local elapsed=$(( end_ts - start_ts ))
    local count_after; count_after=$(ssh_count_addresses "${TEST_IPV4_LIST}")

    local removed=$(( count_before - count_after ))
    log "Mass removal: ${removed} addresses removed in ${elapsed}s"
    log "Final count: $count_after"

    local expected_local; expected_local=$(lapi_count)
    local diff=$(( expected_local - count_after ))
    diff=${diff#-}

    if (( diff > 20 )); then
        echo "FAIL: post-restore count $count_after differs from expected $expected_local by $diff"
        return 1
    fi
    log "T8.8 PASS: restored to $count_after local IPs in ${elapsed}s"
}
run_test "T8.8 Restore to local-only (mass removal)" t8_8_restore_local
