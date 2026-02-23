# =============================================================================
# T6: CPU Impact Monitoring
# =============================================================================
# Monitors MikroTik CPU usage via SNMP (hrProcessorLoad) during and after
# bouncer operations.  Requires snmpget and SNMP access to the router.
# =============================================================================

# T6.1 — Steady-state CPU
t6_1_steady_state() {
    snmp_available || skip_test "snmpget not available or MIKROTIK_SSH_HOST not set"
    bouncer_running || skip_test "bouncer not running"

    # Wait for things to settle
    sleep 10

    local result; result=$(query_cpu 6 5)  # 6 samples, 5s apart = 30s window
    local avg=${result%% *} max=${result##* }

    log "Steady-state CPU: avg=${avg}% max=${max}%"

    local threshold=${TEST_CPU_THRESHOLD:-30}
    if (( avg > threshold )); then
        echo "FAIL: steady-state avg CPU ${avg}% exceeds threshold ${threshold}%"
        return 1
    fi
}
run_test "T6.1 Steady-state CPU" t6_1_steady_state

# T6.2 — Reconciliation CPU peak
t6_2_reconciliation_peak() {
    snmp_available || skip_test "snmpget not available or MIKROTIK_SSH_HOST not set"

    log "Stopping bouncer, cleaning lists..."
    bouncer_stop; sleep 2
    ssh_clean_list "${TEST_IPV4_LIST}"
    ssh_clean_list "${TEST_IPV6_LIST}"

    log "Starting bouncer for full reconciliation..."
    bouncer_start

    # Poll CPU while reconciliation runs (12 samples × 5s = 60s)
    local sum=0 max_val=0 current n=12
    for _ in $(seq 1 $n); do
        current=$(query_cpu_instant)
        sum=$((sum + current))
        (( current > max_val )) && max_val=$current
        sleep 5
    done
    local avg=$((sum / n))

    bouncer_wait_reconciliation 120 || true

    log "Reconciliation CPU: avg=${avg}% peak=${max_val}%"

    local threshold=${TEST_CPU_THRESHOLD:-30}
    if (( max_val > threshold + 20 )); then
        echo "FAIL: reconciliation peak CPU ${max_val}% exceeds ${threshold}+20%"
        return 1
    fi
}
run_test "T6.2 Reconciliation CPU peak" t6_2_reconciliation_peak

# T6.3 — Post-reconciliation CPU recovery
t6_3_recovery() {
    snmp_available || skip_test "snmpget not available or MIKROTIK_SSH_HOST not set"
    bouncer_running || skip_test "bouncer not running"

    # Wait 2 minutes for CPU to settle after reconciliation
    log "Waiting 2 minutes for post-reconciliation recovery..."
    sleep 120

    local result; result=$(query_cpu 4 5)  # 4 samples, 5s apart = 20s window
    local avg=${result%% *} max=${result##* }

    log "Post-recovery CPU: avg=${avg}% max=${max}%"

    local threshold=${TEST_CPU_THRESHOLD:-30}
    if (( avg > threshold )); then
        echo "FAIL: post-reconciliation avg CPU ${avg}% still above ${threshold}%"
        return 1
    fi
}
run_test "T6.3 Post-reconciliation recovery" t6_3_recovery
