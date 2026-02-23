# shellcheck shell=bash
# =============================================================================
# T3: Bulk Operations — Reconciliation from Different States
# =============================================================================
# Tests the bouncer's reconciliation logic by stopping the service, mutating
# the router's address lists, then restarting and verifying the router converges
# to the LAPI source of truth.  Exercises bulk-add (empty → full), partial
# restore, orphan removal, and batch decision removal.
#
# Prerequisites:
#   - Bouncer service controllable (bouncer_stop / bouncer_start)
#   - SSH access to router (address list manipulation)
#   - LAPI accessible for decision count and decision add/remove
#
# Tests:
#   T3.1  Full reconciliation    — empty router → full sync from LAPI
#   T3.2  Partial sync           — ~20 addresses removed, bouncer restores them
#   T3.3  Orphan removal         — fake address injected, bouncer removes it
#   T3.4  No bulk script errors  — recent logs free of EOF/reset/oversize errors
#   T3.5  No stale scripts       — no leftover crowdsec-bulk scripts on router
#   T3.6  Batch remove           — 5 test IPs added then removed via LAPI
#
# NOTE: T3.1 and T3.2 stop/start the bouncer service and will temporarily
#       interrupt normal operation.
# =============================================================================

# T3.1 — Full reconciliation (empty → full).
# Stops the bouncer, wipes both IPv4 and IPv6 address lists, then restarts.
# After reconciliation completes, the router count must match LAPI (±10)
# and logs must be free of bulk-script transport errors.
# Pass: count within threshold AND zero bulk errors in logs.
t3_1_full_reconciliation() {
    log "Stopping bouncer..."
    bouncer_stop; sleep 2

    log "Cleaning address lists..."
    ssh_clean_list "${TEST_IPV4_LIST}"
    ssh_clean_list "${TEST_IPV6_LIST}"

    local before_count
    before_count=$(ssh_count_addresses "${TEST_IPV4_LIST}")
    [[ "$before_count" -eq 0 ]] || { echo "FAIL: lists not empty ($before_count)"; return 1; }

    local expected; expected=$(lapi_get_ipv4 | grep -c . || echo 0)
    log "LAPI has $expected active IPv4 decisions"

    local ts_before; ts_before=$(date '+%Y-%m-%d %H:%M:%S')
    log "Starting bouncer..."
    bouncer_start

    bouncer_wait_reconciliation 120

    local ts_after; ts_after=$(date '+%Y-%m-%d %H:%M:%S')
    log "Reconciliation finished at $ts_after"
    local after_count
    after_count=$(ssh_count_addresses "${TEST_IPV4_LIST}")

    # Check logs for errors
    local errors
    errors=$(bouncer_logs_since "$ts_before" | grep -ci "EOF\|connection reset\|message too large" || true)

    log "Router count: $after_count (expected ~$expected)"
    log "Errors in logs: $errors"

    if (( errors > 0 )); then
        echo "FAIL: $errors bulk script errors during reconciliation"
        return 1
    fi

    local diff=$(( expected - after_count ))
    diff=${diff#-}
    if (( diff > 10 )); then
        echo "FAIL: count mismatch expected=$expected actual=$after_count diff=$diff"
        return 1
    fi
}
run_test "T3.1 Full reconciliation (empty→full)" t3_1_full_reconciliation

# T3.2 — Partial sync (restore missing addresses).
# Removes ~20 random addresses from the router via SSH, then restarts the
# bouncer.  Reconciliation should detect the missing entries and re-add them.
# Pass: recovered count ≥ (removed − 5).
t3_2_partial_sync() {
    bouncer_running || skip_test "bouncer not running"
    bouncer_stop; sleep 2

    local before; before=$(ssh_count_addresses "${TEST_IPV4_LIST}")
    log "Router has $before addresses before deletion"

    # Remove ~20 random addresses from router
    local to_remove
    to_remove=$(ssh_list_addresses "${TEST_IPV4_LIST}" | shuf | head -20)
    for addr in $to_remove; do
        ssh_cmd "/ip/firewall/address-list/remove [find list=${TEST_IPV4_LIST} address=$addr]" 2>/dev/null || true
    done

    local after_delete; after_delete=$(ssh_count_addresses "${TEST_IPV4_LIST}")
    local removed=$(( before - after_delete ))
    log "Removed $removed addresses"

    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    bouncer_start
    bouncer_wait_reconciliation 60

    local after_sync; after_sync=$(ssh_count_addresses "${TEST_IPV4_LIST}")
    log "After reconciliation: $after_sync (was $after_delete, original $before)"

    # Should have restored the missing addresses
    local recovered=$(( after_sync - after_delete ))
    if (( recovered < removed - 5 )); then
        echo "FAIL: only recovered $recovered of $removed deleted addresses"
        return 1
    fi

    # Check for "existing" in logs (skipped existing addresses)
    local existing_logged
    existing_logged=$(bouncer_logs_since "$ts" | grep -ci "existing\|already" || true)
    log "Log mentions existing/skipped: $existing_logged"
}
run_test "T3.2 Partial sync (restore missing)" t3_2_partial_sync

# T3.3 — Orphan removal.
# Injects a fake address (192.0.2.99, RFC 5737 TEST-NET-1) into the router list
# with the bouncer's comment prefix, then restarts.  The reconciliation diff
# should identify the address as absent from LAPI and remove it.
# Pass: fake IP no longer on router after reconciliation.
t3_3_orphan_removal() {
    bouncer_running || skip_test "bouncer not running"
    bouncer_stop; sleep 2

    # Inject a fake address that shouldn't exist in LAPI
    local fake_ip="192.0.2.99"
    ssh_add_address "${TEST_IPV4_LIST}" "$fake_ip" "${TEST_COMMENT_PREFIX}|fake-test"
    log "Injected orphan: $fake_ip"

    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    bouncer_start
    bouncer_wait_reconciliation 60

    sleep 5
    # Verify the orphan was removed
    if ssh_list_addresses "${TEST_IPV4_LIST}" | grep -qF "$fake_ip"; then
        echo "FAIL: orphan $fake_ip still on router after reconciliation"
        return 1
    fi
    log "Orphan correctly removed"
}
run_test "T3.3 Orphan removal" t3_3_orphan_removal

# T3.4 — No bulk script errors.
# Scans the last 5 minutes of bouncer logs for transport-level errors that
# indicate the bulk RouterOS script exceeded size limits or the SSH channel
# was interrupted (EOF, connection reset, message too large, script failed).
# Pass: zero matching log lines.
t3_4_no_script_errors() {
    bouncer_running || skip_test "bouncer not running"

    local errors
    errors=$(bouncer_logs_since "5 minutes ago" \
        | grep -ci "EOF\|connection reset\|message too large\|script failed" || true)
    if (( errors > 0 )); then
        echo "FAIL: $errors bulk script errors in recent logs"
        return 1
    fi
    log "No bulk script errors"
}
run_test "T3.4 No bulk script errors" t3_4_no_script_errors

# T3.5 — No stale scripts on router.
# After bulk operations the bouncer uploads temporary RouterOS scripts named
# "crowdsec-bulk*".  They must be cleaned up after execution.
# Pass: zero scripts matching "crowdsec-bulk" in /system/script.
t3_5_script_cleanup() {
    bouncer_running || skip_test "bouncer not running"

    local stale
    stale=$(ssh_cmd "/system/script/print proplist=name" \
        | grep -c "crowdsec-bulk" || true)
    if (( stale > 0 )); then
        echo "FAIL: $stale stale 'crowdsec-bulk' scripts on router"
        return 1
    fi
    log "No stale scripts"
}
run_test "T3.5 No stale scripts on router" t3_5_script_cleanup

# T3.6 — Batch remove.
# Adds 5 test IPs (198.51.100.10–14) via LAPI, waits 20 s for them to appear
# on the router, then removes them from LAPI and waits another 20 s.
# Pass: ≤1 test IP remains on router (allows for one poll-cycle lag).
t3_6_batch_remove() {
    bouncer_running || skip_test "bouncer not running"

    # Add 5 test IPs
    local test_ips=("198.51.100.10" "198.51.100.11" "198.51.100.12" "198.51.100.13" "198.51.100.14")
    for ip in "${test_ips[@]}"; do
        lapi_add_decision "$ip" "10m" "batch-remove-test"
    done
    log "Added ${#test_ips[@]} test IPs"
    sleep 20  # wait for bouncer to pick them up

    # Verify at least some arrived
    local on_router=0
    for ip in "${test_ips[@]}"; do
        if ssh_list_addresses "${TEST_IPV4_LIST}" | grep -qF "$ip"; then
            on_router=$((on_router + 1))
        fi
    done
    log "$on_router/${#test_ips[@]} test IPs on router"

    # Remove from LAPI
    for ip in "${test_ips[@]}"; do
        lapi_remove_decision "$ip"
    done
    sleep 20

    # Verify removal
    local remaining=0
    for ip in "${test_ips[@]}"; do
        if ssh_list_addresses "${TEST_IPV4_LIST}" | grep -qF "$ip"; then
            remaining=$((remaining + 1))
        fi
    done
    if (( remaining > 1 )); then
        echo "FAIL: $remaining test IPs still on router (expected ≤1)"
        return 1
    fi
    log "Batch remove OK ($remaining remaining)"
}
run_test "T3.6 Batch remove" t3_6_batch_remove
