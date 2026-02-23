# =============================================================================
# T1: Data Integrity — Full Address Set Verification
# =============================================================================
# Verifies that the compiled bouncer correctly synchronises all CrowdSec
# decisions to the MikroTik router.  Every check uses SSH (out-of-band) so
# we never rely on the same API the bouncer itself uses.
# =============================================================================

# T1.1 — Post-reconciliation IP completeness (IPv4)
t1_1_ipv4_completeness() {
    bouncer_running || skip_test "bouncer not running"

    local tmp; tmp=$(mktemp -d)
    lapi_get_ipv4 > "$tmp/lapi.txt"
    ssh_list_addresses "${TEST_IPV4_LIST}" > "$tmp/router.txt"

    local lapi_count router_count
    lapi_count=$(wc -l < "$tmp/lapi.txt")
    router_count=$(wc -l < "$tmp/router.txt")
    log "LAPI IPv4: $lapi_count  Router: $router_count"

    local missing; missing=$(diff_sets "$tmp/lapi.txt" "$tmp/router.txt" | wc -l)
    rm -rf "$tmp"

    if (( missing > 5 )); then
        echo "FAIL: $missing IPs in LAPI but not on router (threshold: 5)"
        return 1
    fi
}
run_test "T1.1 IPv4 completeness" t1_1_ipv4_completeness

# T1.2 — No ghost/orphan addresses
t1_2_no_orphans() {
    bouncer_running || skip_test "bouncer not running"

    local tmp; tmp=$(mktemp -d)
    lapi_get_ipv4 > "$tmp/lapi.txt"
    ssh_list_addresses "${TEST_IPV4_LIST}" > "$tmp/router.txt"

    local orphans; orphans=$(diff_sets "$tmp/router.txt" "$tmp/lapi.txt" | wc -l)
    rm -rf "$tmp"

    if (( orphans > 3 )); then
        echo "FAIL: $orphans addresses on router but not in LAPI (threshold: 3)"
        return 1
    fi
}
run_test "T1.2 No orphan addresses" t1_2_no_orphans

# T1.3 — IPv6 parity
t1_3_ipv6_parity() {
    bouncer_running || skip_test "bouncer not running"

    local tmp; tmp=$(mktemp -d)
    lapi_get_ipv6 | while read -r ip; do normalize_ipv6 "$ip"; done | sort > "$tmp/lapi6.txt"
    ssh_list_addresses "${TEST_IPV6_LIST}" | while read -r ip; do normalize_ipv6 "$ip"; done | sort > "$tmp/router6.txt"

    local diff_count; diff_count=$(diff "$tmp/lapi6.txt" "$tmp/router6.txt" | grep -c '^[<>]' || true)
    rm -rf "$tmp"

    if (( diff_count > 5 )); then
        echo "FAIL: IPv6 diff=$diff_count (threshold: 5)"
        return 1
    fi
}
run_test "T1.3 IPv6 parity" t1_3_ipv6_parity

# T1.4 — Address format correctness
t1_4_format() {
    bouncer_running || skip_test "bouncer not running"

    local bad=0
    while IFS= read -r addr; do
        if ! is_valid_ipv4 "$addr" && ! is_valid_ipv6 "$addr"; then
            echo "Bad format: $addr"
            bad=$((bad + 1))
        fi
    done < <(ssh_list_addresses "${TEST_IPV4_LIST}")

    while IFS= read -r addr; do
        if ! is_valid_ipv6 "$addr"; then
            echo "Bad IPv6 format: $addr"
            bad=$((bad + 1))
        fi
    done < <(ssh_list_addresses "${TEST_IPV6_LIST}")

    [[ $bad -eq 0 ]] || { echo "FAIL: $bad addresses with incorrect format"; return 1; }
}
run_test "T1.4 Address format correctness" t1_4_format

# T1.5 — Comment integrity
t1_5_comments() {
    bouncer_running || skip_test "bouncer not running"

    local total bad=0
    total=$(ssh_count_addresses "${TEST_IPV4_LIST}")
    bad=$(ssh_list_addresses_full "${TEST_IPV4_LIST}" \
        | grep -c -v "comment=${TEST_COMMENT_PREFIX}" || true)

    if (( bad > 0 )); then
        echo "FAIL: $bad/$total entries missing '${TEST_COMMENT_PREFIX}' comment prefix"
        return 1
    fi
}
run_test "T1.5 Comment prefix integrity" t1_5_comments

# T1.6 — No duplicate addresses
t1_6_no_duplicates() {
    bouncer_running || skip_test "bouncer not running"

    local tmp; tmp=$(mktemp)
    ssh_list_addresses "${TEST_IPV4_LIST}" | sort > "$tmp"
    local total; total=$(wc -l < "$tmp")
    local unique; unique=$(sort -u "$tmp" | wc -l)
    rm -f "$tmp"

    if (( total != unique )); then
        echo "FAIL: $((total - unique)) duplicate addresses found"
        return 1
    fi
}
run_test "T1.6 No duplicate addresses" t1_6_no_duplicates

# T1.7 — Router hostname sanity
t1_7_hostname() {
    local identity
    identity=$(ssh_cmd "/system/identity/print" | awk -F= '/name/ {print $2}')
    [[ -n "$identity" ]] || { echo "FAIL: could not read router identity"; return 1; }
    log "Router: $identity"
}
run_test "T1.7 Router reachable (sanity)" t1_7_hostname
