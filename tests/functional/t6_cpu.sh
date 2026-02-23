# =============================================================================
# T6: CPU Impact Monitoring
# =============================================================================
# Monitors MikroTik CPU usage via InfluxDB (SNMP data) during and after
# bouncer operations.  Requires INFLUXDB_URL and INFLUXDB_TOKEN.
# =============================================================================

# T6.1 — Steady-state CPU
t6_1_steady_state() {
    influx_available || skip_test "InfluxDB not configured"
    bouncer_running || skip_test "bouncer not running"

    # Wait for things to settle
    sleep 10

    local result; result=$(query_cpu "2m")
    local avg=${result%% *} max=${result##* }

    log "Steady-state CPU: avg=${avg}% max=${max}%"

    # Convert to integer for comparison
    local avg_int=${avg%.*}
    local threshold=${TEST_CPU_THRESHOLD:-30}
    if (( avg_int > threshold )); then
        echo "FAIL: steady-state avg CPU ${avg}% exceeds threshold ${threshold}%"
        return 1
    fi
}
run_test "T6.1 Steady-state CPU" t6_1_steady_state

# T6.2 — Reconciliation CPU peak
t6_2_reconciliation_peak() {
    influx_available || skip_test "InfluxDB not configured"

    log "Stopping bouncer, cleaning lists..."
    bouncer_stop; sleep 2
    ssh_clean_list "${TEST_IPV4_LIST}"
    ssh_clean_list "${TEST_IPV6_LIST}"

    log "Starting bouncer for full reconciliation..."
    bouncer_start

    # Monitor CPU during reconciliation
    bouncer_wait_reconciliation 120

    # Give SNMP time to report the peak
    sleep 15

    local result; result=$(query_cpu "3m")
    local avg=${result%% *} max=${result##* }
    local max_int=${max%.*}

    log "Reconciliation CPU: avg=${avg}% peak=${max}%"

    local threshold=${TEST_CPU_THRESHOLD:-30}
    if (( max_int > threshold + 20 )); then
        echo "FAIL: reconciliation peak CPU ${max}% exceeds ${threshold}+20%"
        return 1
    fi
}
run_test "T6.2 Reconciliation CPU peak" t6_2_reconciliation_peak

# T6.3 — Post-reconciliation CPU recovery
t6_3_recovery() {
    influx_available || skip_test "InfluxDB not configured"
    bouncer_running || skip_test "bouncer not running"

    # Wait 2 minutes for CPU to settle after reconciliation
    log "Waiting 2 minutes for post-reconciliation recovery..."
    sleep 120

    local result; result=$(query_cpu "1m")
    local avg=${result%% *} max=${result##* }

    log "Post-recovery CPU: avg=${avg}% max=${max}%"

    local avg_int=${avg%.*}
    local threshold=${TEST_CPU_THRESHOLD:-30}
    if (( avg_int > threshold )); then
        echo "FAIL: post-reconciliation avg CPU ${avg}% still above ${threshold}%"
        return 1
    fi
}
run_test "T6.3 Post-reconciliation recovery" t6_3_recovery
