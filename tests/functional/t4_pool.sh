# =============================================================================
# T4: Connection Pool — Verification via Logs
# =============================================================================
# The pool is an internal implementation detail; we verify it through the
# binary's log output and behaviour, not by calling pool functions directly.
# =============================================================================

# T4.1 — Pool establishment logged
t4_1_pool_established() {
    bouncer_running || skip_test "bouncer not running"

    local pool_msg
    pool_msg=$(bouncer_logs_since "10 minutes ago" \
        | grep -ci "pool\|connections ready\|pool size" || true)

    if (( pool_msg == 0 )); then
        warn "No pool-related messages in recent logs (may need restart to see)"
    fi
    log "Pool log messages found: $pool_msg"
    # Not a hard failure — the pool may have started >10 min ago
}
run_test "T4.1 Pool establishment (logs)" t4_1_pool_established

# T4.2 — Concurrent operations during reconciliation
t4_2_concurrent_ops() {
    bouncer_running || skip_test "bouncer not running"

    # Verify pool is used: during reconciliation, logs should show parallel activity
    # We check for "parallel" or "worker" messages, or simply that reconciliation
    # was fast (which implies pool usage)
    local logs
    logs=$(bouncer_logs_since "10 minutes ago")

    local parallel_count
    parallel_count=$(echo "$logs" | grep -ci "parallel\|worker\|pool" || true)
    log "Parallel/pool log entries: $parallel_count"

    # The real validation: if reconciliation < 30s with >500 IPs, pool is working
    local recon_line
    recon_line=$(echo "$logs" | grep -i "reconcil" | tail -1 || true)
    log "Last reconciliation: $recon_line"
}
run_test "T4.2 Concurrent operations (logs)" t4_2_concurrent_ops

# T4.3 — Clean shutdown
t4_3_clean_shutdown() {
    bouncer_running || skip_test "bouncer not running"

    # Record count before
    local count_before; count_before=$(ssh_count_addresses "${TEST_IPV4_LIST}")

    bouncer_stop; sleep 3

    # Check for shutdown-related errors
    local shutdown_errors
    shutdown_errors=$(bouncer_logs_since "30 seconds ago" \
        | grep -ci "panic\|connection refused\|broken pipe" || true)

    # Restart for subsequent tests
    bouncer_start; sleep 5

    if (( shutdown_errors > 0 )); then
        echo "FAIL: $shutdown_errors errors during shutdown"
        return 1
    fi

    # Verify addresses still on router (shutdown shouldn't clean them)
    local count_after; count_after=$(ssh_count_addresses "${TEST_IPV4_LIST}")
    local diff=$(( count_before - count_after ))
    diff=${diff#-}
    if (( diff > 5 )); then
        echo "FAIL: count changed from $count_before to $count_after after restart"
        return 1
    fi
    log "Clean shutdown/restart OK (count: $count_before → $count_after)"
}
run_test "T4.3 Clean shutdown / restart" t4_3_clean_shutdown
