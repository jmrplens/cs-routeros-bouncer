# =============================================================================
# T7: Timing Measurements
# =============================================================================
# Measures real-world latencies of key bouncer operations by parsing
# timestamps from journalctl logs and SSH verification.
# =============================================================================

# T7.1 — Full reconciliation time (empty → full)
t7_1_reconciliation_time() {
    log "Stopping bouncer, cleaning lists for timing..."
    bouncer_stop; sleep 2
    ssh_clean_list "${TEST_IPV4_LIST}"
    ssh_clean_list "${TEST_IPV6_LIST}"

    local start_ts; start_ts=$(date +%s)
    bouncer_start

    bouncer_wait_reconciliation 120

    local end_ts; end_ts=$(date +%s)
    local elapsed=$(( end_ts - start_ts ))
    local count; count=$(ssh_count_addresses "${TEST_IPV4_LIST}")

    log "Full reconciliation: ${elapsed}s for $count addresses"

    if (( elapsed > 60 )); then
        echo "FAIL: reconciliation took ${elapsed}s (threshold: 60s)"
        return 1
    fi
}
run_test "T7.1 Full reconciliation time" t7_1_reconciliation_time

# T7.2 — Single ban latency (LAPI → router)
t7_2_ban_latency() {
    bouncer_running || skip_test "bouncer not running"

    local ip="198.51.100.90"
    lapi_remove_decision "$ip" 2>/dev/null || true

    local start_ts; start_ts=$(date +%s)
    lapi_add_decision "$ip" "5m" "latency-test"

    local found=false
    for i in $(seq 1 20); do
        sleep 2
        if ssh_list_addresses "${TEST_IPV4_LIST}" | grep -qF "$ip"; then
            found=true; break
        fi
    done

    local end_ts; end_ts=$(date +%s)
    local elapsed=$(( end_ts - start_ts ))

    lapi_remove_decision "$ip"

    if ! $found; then
        echo "FAIL: ban not applied within 40s"
        return 1
    fi

    log "Ban latency: ${elapsed}s"
    if (( elapsed > 30 )); then
        echo "FAIL: ban latency ${elapsed}s (threshold: 30s)"
        return 1
    fi
}
run_test "T7.2 Single ban latency" t7_2_ban_latency

# T7.3 — Single unban latency
t7_3_unban_latency() {
    bouncer_running || skip_test "bouncer not running"

    local ip="198.51.100.91"
    lapi_remove_decision "$ip" 2>/dev/null || true

    # First, add and wait for it to appear
    lapi_add_decision "$ip" "10m" "unban-latency-test"
    wait_for "IP on router" 40 3 \
        bash -c "ssh_list_addresses ${TEST_IPV4_LIST} | grep -qF $ip" \
        || { echo "FAIL: ban setup failed"; return 1; }

    # Now measure unban
    local start_ts; start_ts=$(date +%s)
    lapi_remove_decision "$ip"

    local removed=false
    for i in $(seq 1 20); do
        sleep 2
        if ! ssh_list_addresses "${TEST_IPV4_LIST}" | grep -qF "$ip"; then
            removed=true; break
        fi
    done

    local end_ts; end_ts=$(date +%s)
    local elapsed=$(( end_ts - start_ts ))

    if ! $removed; then
        echo "FAIL: unban not applied within 40s"
        return 1
    fi

    log "Unban latency: ${elapsed}s"
    if (( elapsed > 30 )); then
        echo "FAIL: unban latency ${elapsed}s (threshold: 30s)"
        return 1
    fi
}
run_test "T7.3 Single unban latency" t7_3_unban_latency

# T7.4 — Restart with existing data (skip reconciliation)
t7_4_restart_time() {
    bouncer_running || skip_test "bouncer not running"

    local count_before; count_before=$(ssh_count_addresses "${TEST_IPV4_LIST}")
    [[ "$count_before" -gt 100 ]] || skip_test "too few addresses ($count_before) for meaningful test"

    local start_ts; start_ts=$(date +%s)
    bouncer_restart

    bouncer_wait_reconciliation 60

    local end_ts; end_ts=$(date +%s)
    local elapsed=$(( end_ts - start_ts ))

    log "Restart with $count_before existing addresses: ${elapsed}s"

    # Restart with existing data should be fast (only diff)
    if (( elapsed > 30 )); then
        echo "FAIL: restart took ${elapsed}s (threshold: 30s)"
        return 1
    fi
}
run_test "T7.4 Restart time (existing data)" t7_4_restart_time

# T7.5 — Bulk add throughput estimate
t7_5_bulk_throughput() {
    bouncer_running || skip_test "bouncer not running"

    # Parse reconciliation log for addresses added and time elapsed
    local logs
    logs=$(bouncer_logs_since "10 minutes ago")

    local added
    added=$(echo "$logs" | grep -oP 'added[=:]\s*\K[0-9]+' | tail -1 || echo "")
    local elapsed_s
    elapsed_s=$(echo "$logs" | grep -oP 'elapsed[=:]\s*\K[0-9.]+' | tail -1 || echo "")

    if [[ -n "$added" && -n "$elapsed_s" ]]; then
        local rate
        rate=$(awk "BEGIN {printf \"%.0f\", $added / $elapsed_s}" 2>/dev/null || echo "N/A")
        log "Bulk throughput: $added addresses in ${elapsed_s}s = ${rate} addr/s"
    else
        log "Could not parse throughput from logs (added=$added elapsed=$elapsed_s)"
    fi
    # This is informational — no pass/fail threshold
}
run_test "T7.5 Bulk add throughput" t7_5_bulk_throughput
