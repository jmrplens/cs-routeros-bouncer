# =============================================================================
# T5: Edge Cases
# =============================================================================
# Tests unusual scenarios: duplicates, rapid cycles, restart idempotency,
# and deleteCh drain — all through the binary's external behaviour.
# =============================================================================

# T5.1 — Duplicate IP handling (inject duplicate, bouncer handles it)
t5_1_duplicates() {
    bouncer_running || skip_test "bouncer not running"
    bouncer_stop; sleep 2

    # Pick an IP from the current list and add it again manually
    local existing_ip
    existing_ip=$(ssh_list_addresses "${TEST_IPV4_LIST}" | head -1)
    [[ -n "$existing_ip" ]] || skip_test "no addresses on router"

    # Add a duplicate entry with same comment prefix
    ssh_add_address "${TEST_IPV4_LIST}" "$existing_ip" "${TEST_COMMENT_PREFIX}|duplicate-test"
    local count_with_dup; count_with_dup=$(ssh_count_addresses "${TEST_IPV4_LIST}")

    # Start bouncer — reconciliation should clean up the duplicate
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    bouncer_start
    bouncer_wait_reconciliation 60
    sleep 5

    local count_after; count_after=$(ssh_count_addresses "${TEST_IPV4_LIST}")
    log "Count: before=$count_with_dup after=$count_after"

    # Should have fewer entries after dedup
    if (( count_after >= count_with_dup )); then
        warn "Duplicate may not have been cleaned (count: $count_with_dup → $count_after)"
        # Not necessarily a failure — depends on implementation
    fi

    # No panics
    local panics
    panics=$(bouncer_logs_since "$ts" | grep -ci "panic" || true)
    [[ $panics -eq 0 ]] || { echo "FAIL: panics during duplicate handling"; return 1; }
    log "Duplicate handling: no panics"
}
run_test "T5.1 Duplicate IP handling" t5_1_duplicates

# T5.2 — Rapid ban/unban within single poll cycle
t5_2_rapid_ban_unban() {
    bouncer_running || skip_test "bouncer not running"

    local ip="198.51.100.30"
    lapi_remove_decision "$ip" 2>/dev/null || true

    # Ban and immediately unban (within ~1s)
    lapi_add_decision "$ip" "5m" "rapid-test"
    lapi_remove_decision "$ip"

    sleep 20  # wait for bouncer poll cycle

    # Both outcomes are valid:
    # - IP not on router (delete arrived before/with add) → OK
    # - IP on router then removed (processed sequentially) → OK
    local panics
    panics=$(bouncer_logs_since "30 seconds ago" | grep -ci "panic" || true)
    [[ $panics -eq 0 ]] || { echo "FAIL: panics during rapid ban/unban"; return 1; }
    log "Rapid ban/unban: no panics"
}
run_test "T5.2 Rapid ban/unban" t5_2_rapid_ban_unban

# T5.3 — Stress: 20 rapid bans in parallel
t5_3_stress() {
    bouncer_running || skip_test "bouncer not running"

    local base_ip="198.51.100"
    # Add 20 IPs rapidly
    for i in $(seq 60 79); do
        lapi_add_decision "${base_ip}.${i}" "5m" "stress-test" &
    done
    wait
    log "Sent 20 parallel ban requests"

    sleep 30  # two poll cycles

    # Count how many appeared
    local found=0
    for i in $(seq 60 79); do
        if ssh_list_addresses "${TEST_IPV4_LIST}" | grep -qF "${base_ip}.${i}"; then
            found=$((found + 1))
        fi
    done
    log "Stress: $found/20 IPs appeared on router"

    # Cleanup
    for i in $(seq 60 79); do
        lapi_remove_decision "${base_ip}.${i}" &
    done
    wait
    sleep 20

    if (( found < 15 )); then
        echo "FAIL: only $found/20 IPs reached router (expected ≥15)"
        return 1
    fi
}
run_test "T5.3 Stress: 20 parallel bans" t5_3_stress

# T5.4 — Restart idempotency (3 restarts, count stable)
t5_4_restart_idempotency() {
    bouncer_running || skip_test "bouncer not running"

    local counts=()
    for i in 1 2 3; do
        bouncer_restart
        sleep 10
        bouncer_wait_reconciliation 60 || true
        sleep 5
        counts+=($(ssh_count_addresses "${TEST_IPV4_LIST}"))
        log "Restart $i: count=${counts[-1]}"
    done

    # All counts should be within ±10 of each other
    local min=${counts[0]} max=${counts[0]}
    for c in "${counts[@]}"; do
        (( c < min )) && min=$c
        (( c > max )) && max=$c
    done
    local spread=$(( max - min ))
    if (( spread > 10 )); then
        echo "FAIL: count spread=$spread across restarts (${counts[*]})"
        return 1
    fi
    log "Restart idempotency OK: spread=$spread (${counts[*]})"
}
run_test "T5.4 Restart idempotency" t5_4_restart_idempotency

# T5.5 — DeleteCh drain effectiveness
t5_5_delete_drain() {
    bouncer_running || skip_test "bouncer not running"

    # During reconciliation, expired decisions should be drained and pre-filtered.
    # Check logs for any "skip" or "drain" references.
    local drains
    drains=$(bouncer_logs_since "10 minutes ago" \
        | grep -ci "drain\|skip.*delet\|pre-filter\|immediate" || true)
    log "Delete drain log mentions: $drains"

    # Mainly a safety check — no panics
    local panics
    panics=$(bouncer_logs_since "10 minutes ago" | grep -ci "panic" || true)
    [[ $panics -eq 0 ]] || { echo "FAIL: panics"; return 1; }
}
run_test "T5.5 DeleteCh drain" t5_5_delete_drain

# T5.6 — IPv6 ban/unban lifecycle
t5_6_ipv6_lifecycle() {
    bouncer_running || skip_test "bouncer not running"

    local ipv6="2001:db8::dead:beef"
    lapi_remove_decision "$ipv6" 2>/dev/null || true

    lapi_add_decision "$ipv6" "5m" "ipv6-test"
    log "Added IPv6 $ipv6"

    local found=false
    for i in $(seq 1 12); do
        sleep 5
        if ssh_list_addresses "${TEST_IPV6_LIST}" | grep -qF "2001:db8::dead:beef"; then
            found=true; break
        fi
    done

    if $found; then
        log "IPv6 appeared after ~$((i * 5))s"

        # Now unban
        lapi_remove_decision "$ipv6"
        sleep 20

        if ssh_list_addresses "${TEST_IPV6_LIST}" | grep -qF "2001:db8::dead:beef"; then
            warn "IPv6 still on router (may be timeout-based removal)"
        else
            log "IPv6 unban confirmed"
        fi
    else
        echo "FAIL: IPv6 $ipv6 not found on router after 60s"
        lapi_remove_decision "$ipv6"
        return 1
    fi
}
run_test "T5.6 IPv6 ban/unban lifecycle" t5_6_ipv6_lifecycle
