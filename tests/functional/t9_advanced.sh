# shellcheck shell=bash
# =============================================================================
# T9: Advanced Firewall Configuration
# =============================================================================
# Verifies that advanced firewall rule customization options produce the
# expected rules on the MikroTik router.  Each test reconfigures the bouncer
# with specific settings, restarts it, waits for reconciliation, then checks
# the resulting firewall rules via SSH.
#
# The production config is backed up at the start and restored after each
# test (or on failure), so the bouncer always returns to its original state.
#
# Prerequisites:
#   - Bouncer installed and configured as systemd service
#   - SSH access to MikroTik router
#   - CrowdSec LAPI running with at least 1 active ban
#   - python3 + PyYAML installed (for config_set_kv)
#   - Helper functions sourced (run_test, ssh_*, config_*, bouncer_*)
#
# Coverage:
#   T9.1   deny_action=reject + reject_with
#   T9.2   connection_state on filter rules
#   T9.3   log + log_prefix (global)
#   T9.4   hierarchical log_prefix (per-mode override)
#   T9.5   block_output with passthrough IP
#   T9.6   block_output with passthrough address-list
#   T9.7   input whitelist (accept before drop)
#   T9.8   raw rules enabled (prerouting chain)
#   T9.9   rule_placement=top
#   T9.10  block_input interface filtering
#   T9.11  filter disabled, raw only
#   T9.12  custom comment_prefix
# =============================================================================

# ─── Guard: at least one ban must exist ─────────────────────────────────────
_t9_ban_count=$(lapi_count 2>/dev/null || echo 0)
if (( _t9_ban_count < 1 )); then
    warn "T9 requires at least 1 active ban — injecting a test IP"
    lapi_add_decision "198.51.100.200" "10m" "t9-setup"
    sleep 5
fi

# ─── Helper: generate a test config from template ───────────────────────────
# Creates a full YAML config with sensible defaults and allows overriding
# specific firewall keys.  This avoids partial config_set_kv calls that can
# leave the config in an inconsistent state.

_t9_write_config() {
    # Base config values from .env
    cat > "$_BOUNCER_CONFIG" <<YAML
crowdsec:
  api_url: "${CROWDSEC_URL}"
  api_key: "${CROWDSEC_BOUNCER_API_KEY}"
  update_frequency: "10s"
  origins: ["crowdsec", "cscli"]
  scopes: ["ip", "range"]
  supported_decisions_types: ["ban"]
  retry_initial_connect: true

mikrotik:
  address: "${MIKROTIK_HOST}"
  username: "${MIKROTIK_USER}"
  password: "${MIKROTIK_PASS}"
  tls: false
  connection_timeout: "10s"
  command_timeout: "30s"
  pool_size: 4

firewall:
  ipv4:
    enabled: true
    address_list: "${TEST_IPV4_LIST}"
  ipv6:
    enabled: true
    address_list: "${TEST_IPV6_LIST}"
$(cat)

logging:
  level: "debug"
  format: "text"

metrics:
  enabled: true
  listen_addr: "0.0.0.0"
  listen_port: 2112
YAML
}

# ─── T9.1 — deny_action=reject + reject_with ───────────────────────────────
# Configures the bouncer with deny_action=reject and reject_with=icmp-admin-prohibited.
# Verifies that filter rules have action=reject and reject-with set correctly.
t9_1_reject_with() {
    bouncer_running || skip_test "bouncer not running"
    config_backup

    _t9_write_config <<'FWCFG'
  filter:
    enabled: true
    chains: ["input"]
  raw:
    enabled: false
  deny_action: "reject"
  reject_with: "icmp-admin-prohibited"
  block_output:
    enabled: false
  rule_placement: "top"
  comment_prefix: "crowdsec-bouncer"
FWCFG

    config_restart_and_wait 60

    local rules
    rules=$(ssh_list_filter_rules "ip")

    # Find the input drop/reject rule (not the whitelist)
    local input_rule
    input_rule=$(echo "$rules" | grep "input-v4" | grep -v "whitelist" | head -1)

    if [[ -z "$input_rule" ]]; then
        config_restore
        echo "FAIL: no input filter rule found"
        return 1
    fi

    local action reject_with
    action=$(ssh_get_rule_prop "$input_rule" "action")
    reject_with=$(ssh_get_rule_prop "$input_rule" "reject-with")

    log "Rule action=$action reject-with=$reject_with"

    config_restore

    if [[ "$action" != "reject" ]]; then
        echo "FAIL: expected action=reject, got action=$action"
        return 1
    fi
    if [[ "$reject_with" != "icmp-admin-prohibited" ]]; then
        echo "FAIL: expected reject-with=icmp-admin-prohibited, got $reject_with"
        return 1
    fi
}
run_test "T9.1 deny_action=reject + reject_with" t9_1_reject_with

# ─── T9.2 — connection_state on filter rules ───────────────────────────────
# Configures connection_state="new,invalid" on filter rules.
# Verifies the connection-state property is set on the router rules.
t9_2_connection_state() {
    bouncer_running || skip_test "bouncer not running"
    config_backup

    _t9_write_config <<'FWCFG'
  filter:
    enabled: true
    chains: ["input"]
    connection_state: "new,invalid"
  raw:
    enabled: false
  deny_action: "drop"
  block_output:
    enabled: false
  rule_placement: "top"
  comment_prefix: "crowdsec-bouncer"
FWCFG

    config_restart_and_wait 60

    local rules
    rules=$(ssh_list_filter_rules "ip")

    local input_rule
    input_rule=$(echo "$rules" | grep "input-v4" | grep -v "whitelist" | head -1)

    if [[ -z "$input_rule" ]]; then
        config_restore
        echo "FAIL: no input filter rule found"
        return 1
    fi

    local conn_state
    conn_state=$(ssh_get_rule_prop "$input_rule" "connection-state")

    log "connection-state=$conn_state"

    config_restore

    if [[ -z "$conn_state" ]]; then
        echo "FAIL: connection-state not set on filter rule"
        return 1
    fi
    # RouterOS may reorder states; check both are present
    if [[ "$conn_state" != *"new"* ]] || [[ "$conn_state" != *"invalid"* ]]; then
        echo "FAIL: expected new,invalid in connection-state, got $conn_state"
        return 1
    fi
}
run_test "T9.2 connection_state on filter rules" t9_2_connection_state

# ─── T9.3 — log + global log_prefix ────────────────────────────────────────
# Enables logging with a global log_prefix.
# Verifies that filter rules have log=yes and the correct log-prefix.
t9_3_log_prefix_global() {
    bouncer_running || skip_test "bouncer not running"
    config_backup

    _t9_write_config <<'FWCFG'
  filter:
    enabled: true
    chains: ["input"]
  raw:
    enabled: false
  deny_action: "drop"
  block_output:
    enabled: false
  rule_placement: "top"
  comment_prefix: "crowdsec-bouncer"
  log: true
  log_prefix: "CS-BLOCK"
FWCFG

    config_restart_and_wait 60

    local rules
    rules=$(ssh_list_filter_rules "ip")

    local input_rule
    input_rule=$(echo "$rules" | grep "input-v4" | grep -v "whitelist" | head -1)

    if [[ -z "$input_rule" ]]; then
        config_restore
        echo "FAIL: no input filter rule found"
        return 1
    fi

    local log_val log_prefix
    log_val=$(ssh_get_rule_prop "$input_rule" "log")
    log_prefix=$(ssh_get_rule_prop "$input_rule" "log-prefix")

    log "log=$log_val log-prefix=$log_prefix"

    config_restore

    if [[ "$log_val" != "yes" ]]; then
        echo "FAIL: expected log=yes, got log=$log_val"
        return 1
    fi
    if [[ "$log_prefix" != "CS-BLOCK" ]]; then
        echo "FAIL: expected log-prefix=CS-BLOCK, got $log_prefix"
        return 1
    fi
}
run_test "T9.3 log + global log_prefix" t9_3_log_prefix_global

# ─── T9.4 — hierarchical log_prefix (per-mode override) ────────────────────
# Sets a global log_prefix but overrides it for filter rules.
# Verifies filter uses the override and raw uses the global.
t9_4_log_prefix_hierarchy() {
    bouncer_running || skip_test "bouncer not running"
    config_backup

    _t9_write_config <<'FWCFG'
  filter:
    enabled: true
    chains: ["input"]
    log_prefix: "FILTER-OVERRIDE"
  raw:
    enabled: true
    chains: ["prerouting"]
    log_prefix: ""
  deny_action: "drop"
  block_output:
    enabled: false
  rule_placement: "top"
  comment_prefix: "crowdsec-bouncer"
  log: true
  log_prefix: "CS-GLOBAL"
FWCFG

    config_restart_and_wait 60

    local filter_rules raw_rules
    filter_rules=$(ssh_list_filter_rules "ip")
    raw_rules=$(ssh_list_raw_rules "ip")

    local filter_rule raw_rule
    filter_rule=$(echo "$filter_rules" | grep "input-v4" | grep -v "whitelist" | head -1)
    raw_rule=$(echo "$raw_rules" | grep "input-v4" | head -1)

    local filter_prefix raw_prefix
    filter_prefix=$(ssh_get_rule_prop "$filter_rule" "log-prefix")
    raw_prefix=$(ssh_get_rule_prop "$raw_rule" "log-prefix")

    log "filter log-prefix=$filter_prefix  raw log-prefix=$raw_prefix"

    config_restore

    if [[ "$filter_prefix" != "FILTER-OVERRIDE" ]]; then
        echo "FAIL: filter should use override 'FILTER-OVERRIDE', got '$filter_prefix'"
        return 1
    fi
    if [[ "$raw_prefix" != "CS-GLOBAL" ]]; then
        echo "FAIL: raw should use global 'CS-GLOBAL', got '$raw_prefix'"
        return 1
    fi
}
run_test "T9.4 hierarchical log_prefix" t9_4_log_prefix_hierarchy

# ─── T9.5 — block_output with passthrough IP ───────────────────────────────
# Enables output blocking with a passthrough IP (negated src-address).
# Verifies the output rule has src-address=!<IP>.
t9_5_output_passthrough_ip() {
    bouncer_running || skip_test "bouncer not running"
    config_backup

    _t9_write_config <<'FWCFG'
  filter:
    enabled: true
    chains: ["input"]
  raw:
    enabled: false
  deny_action: "drop"
  block_output:
    enabled: true
    interface: "ether1"
    passthrough_v4: "10.0.0.100"
  rule_placement: "top"
  comment_prefix: "crowdsec-bouncer"
FWCFG

    config_restart_and_wait 60

    local rules
    rules=$(ssh_list_filter_rules "ip")

    local output_rule
    output_rule=$(echo "$rules" | grep "output-output-v4" | head -1)

    if [[ -z "$output_rule" ]]; then
        config_restore
        echo "FAIL: no output filter rule found"
        return 1
    fi

    local src_addr dst_list
    src_addr=$(ssh_get_rule_prop "$output_rule" "src-address")
    dst_list=$(ssh_get_rule_prop "$output_rule" "dst-address-list")

    log "output rule: src-address=$src_addr dst-address-list=$dst_list"

    config_restore

    if [[ "$src_addr" != "!10.0.0.100" ]]; then
        echo "FAIL: expected src-address=!10.0.0.100, got $src_addr"
        return 1
    fi
    if [[ "$dst_list" != "${TEST_IPV4_LIST}" ]]; then
        echo "FAIL: expected dst-address-list=${TEST_IPV4_LIST}, got $dst_list"
        return 1
    fi
}
run_test "T9.5 block_output passthrough IP" t9_5_output_passthrough_ip

# ─── T9.6 — block_output with passthrough address-list ─────────────────────
# Enables output blocking with a passthrough address-list (negated src-address-list).
# Verifies list negation takes precedence over IP.
t9_6_output_passthrough_list() {
    bouncer_running || skip_test "bouncer not running"
    config_backup

    _t9_write_config <<'FWCFG'
  filter:
    enabled: true
    chains: ["input"]
  raw:
    enabled: false
  deny_action: "drop"
  block_output:
    enabled: true
    interface: "ether1"
    passthrough_v4: "10.0.0.100"
    passthrough_v4_list: "trusted-clients"
  rule_placement: "top"
  comment_prefix: "crowdsec-bouncer"
FWCFG

    config_restart_and_wait 60

    local rules
    rules=$(ssh_list_filter_rules "ip")

    local output_rule
    output_rule=$(echo "$rules" | grep "output-output-v4" | head -1)

    if [[ -z "$output_rule" ]]; then
        config_restore
        echo "FAIL: no output filter rule found"
        return 1
    fi

    local src_list src_addr
    src_list=$(ssh_get_rule_prop "$output_rule" "src-address-list")
    src_addr=$(ssh_get_rule_prop "$output_rule" "src-address")

    log "output rule: src-address-list=$src_list src-address=$src_addr"

    config_restore

    # List negation should take precedence — src-address-list should be !trusted-clients
    if [[ "$src_list" != "!trusted-clients" ]]; then
        echo "FAIL: expected src-address-list=!trusted-clients, got $src_list"
        return 1
    fi
    # When list is set, single IP should NOT be set (list takes precedence)
    if [[ -n "$src_addr" ]]; then
        echo "FAIL: src-address should be empty when list takes precedence, got $src_addr"
        return 1
    fi
}
run_test "T9.6 block_output passthrough list precedence" t9_6_output_passthrough_list

# ─── T9.7 — input whitelist (accept before drop) ───────────────────────────
# Configures an input whitelist address-list.
# Verifies that an accept rule is created with the whitelist and appears
# before the drop/reject rule in the chain.
t9_7_input_whitelist() {
    bouncer_running || skip_test "bouncer not running"
    config_backup

    _t9_write_config <<'FWCFG'
  filter:
    enabled: true
    chains: ["input"]
  raw:
    enabled: false
  deny_action: "drop"
  block_input:
    whitelist: "crowdsec-whitelist"
  block_output:
    enabled: false
  rule_placement: "top"
  comment_prefix: "crowdsec-bouncer"
FWCFG

    config_restart_and_wait 60

    local rules
    rules=$(ssh_list_filter_rules "ip")

    # Check that whitelist rule exists
    local wl_rule
    wl_rule=$(echo "$rules" | grep "whitelist-v4" | head -1)

    if [[ -z "$wl_rule" ]]; then
        config_restore
        echo "FAIL: no whitelist accept rule found"
        return 1
    fi

    local wl_action wl_src_list
    wl_action=$(ssh_get_rule_prop "$wl_rule" "action")
    wl_src_list=$(ssh_get_rule_prop "$wl_rule" "src-address-list")

    log "whitelist rule: action=$wl_action src-address-list=$wl_src_list"

    # Check that drop rule also exists
    local drop_rule
    drop_rule=$(echo "$rules" | grep "input-v4" | grep -v "whitelist" | head -1)

    if [[ -z "$drop_rule" ]]; then
        config_restore
        echo "FAIL: no input drop rule found alongside whitelist"
        return 1
    fi

    config_restore

    if [[ "$wl_action" != "accept" ]]; then
        echo "FAIL: whitelist rule action should be 'accept', got '$wl_action'"
        return 1
    fi
    if [[ "$wl_src_list" != "crowdsec-whitelist" ]]; then
        echo "FAIL: whitelist src-address-list should be 'crowdsec-whitelist', got '$wl_src_list'"
        return 1
    fi
}
run_test "T9.7 input whitelist" t9_7_input_whitelist

# ─── T9.8 — raw rules enabled ──────────────────────────────────────────────
# Verifies that raw/prerouting rules are created with correct properties.
t9_8_raw_rules() {
    bouncer_running || skip_test "bouncer not running"
    config_backup

    _t9_write_config <<'FWCFG'
  filter:
    enabled: false
  raw:
    enabled: true
    chains: ["prerouting"]
  deny_action: "drop"
  block_output:
    enabled: false
  rule_placement: "top"
  comment_prefix: "crowdsec-bouncer"
FWCFG

    config_restart_and_wait 60

    local raw_count filter_count
    raw_count=$(ssh_count_raw_rules "ip")
    filter_count=$(ssh_count_filter_rules "ip")

    local raw_rules
    raw_rules=$(ssh_list_raw_rules "ip")

    local raw_rule
    raw_rule=$(echo "$raw_rules" | grep "input-v4" | head -1)

    local chain action src_list
    if [[ -n "$raw_rule" ]]; then
        chain=$(ssh_get_rule_prop "$raw_rule" "chain")
        action=$(ssh_get_rule_prop "$raw_rule" "action")
        src_list=$(ssh_get_rule_prop "$raw_rule" "src-address-list")
    fi

    log "raw rules: $raw_count  filter rules: $filter_count"
    log "raw rule: chain=$chain action=$action src-address-list=$src_list"

    config_restore

    if (( raw_count < 1 )); then
        echo "FAIL: expected at least 1 raw rule, got $raw_count"
        return 1
    fi
    if (( filter_count > 0 )); then
        echo "FAIL: filter should be disabled but found $filter_count rules"
        return 1
    fi
    if [[ "$chain" != "prerouting" ]]; then
        echo "FAIL: expected chain=prerouting, got $chain"
        return 1
    fi
    if [[ "$action" != "drop" ]]; then
        echo "FAIL: expected action=drop, got $action"
        return 1
    fi
}
run_test "T9.8 raw rules (prerouting)" t9_8_raw_rules

# ─── T9.9 — rule_placement=top ─────────────────────────────────────────────
# Verifies that with rule_placement=top, bouncer rules appear at or near
# position 0 in the chain.
t9_9_rule_placement_top() {
    bouncer_running || skip_test "bouncer not running"
    config_backup

    _t9_write_config <<'FWCFG'
  filter:
    enabled: true
    chains: ["input"]
  raw:
    enabled: false
  deny_action: "drop"
  block_output:
    enabled: false
  rule_placement: "top"
  comment_prefix: "crowdsec-bouncer"
FWCFG

    config_restart_and_wait 60

    # Get ALL filter rules (not just bouncer ones) to check position
    local all_rules
    all_rules=$(ssh_cmd "/ip/firewall/filter/print terse proplist=comment")

    # Find the position (line number) of our bouncer rule
    local position
    position=$(echo "$all_rules" | grep -n "${TEST_COMMENT_PREFIX}" | head -1 | cut -d: -f1)

    log "Bouncer rule position in filter chain: $position"

    config_restore

    if [[ -z "$position" ]]; then
        echo "FAIL: bouncer rule not found in filter chain"
        return 1
    fi
    # Position should be within first 5 rules (allowing for fasttrack/defconf)
    if (( position > 5 )); then
        echo "FAIL: rule_placement=top but rule at position $position (expected ≤5)"
        return 1
    fi
}
run_test "T9.9 rule_placement=top" t9_9_rule_placement_top

# ─── T9.10 — block_input interface filtering ───────────────────────────────
# Configures in-interface on input rules.
# Verifies the in-interface property is set on the created rules.
t9_10_input_interface() {
    bouncer_running || skip_test "bouncer not running"
    config_backup

    _t9_write_config <<'FWCFG'
  filter:
    enabled: true
    chains: ["input"]
  raw:
    enabled: false
  deny_action: "drop"
  block_input:
    interface: "ether1"
  block_output:
    enabled: false
  rule_placement: "top"
  comment_prefix: "crowdsec-bouncer"
FWCFG

    config_restart_and_wait 60

    local rules
    rules=$(ssh_list_filter_rules "ip")

    local input_rule
    input_rule=$(echo "$rules" | grep "input-v4" | grep -v "whitelist" | head -1)

    if [[ -z "$input_rule" ]]; then
        config_restore
        echo "FAIL: no input filter rule found"
        return 1
    fi

    local in_iface
    in_iface=$(ssh_get_rule_prop "$input_rule" "in-interface")

    log "in-interface=$in_iface"

    config_restore

    if [[ "$in_iface" != "ether1" ]]; then
        echo "FAIL: expected in-interface=ether1, got '$in_iface'"
        return 1
    fi
}
run_test "T9.10 block_input interface" t9_10_input_interface

# ─── T9.11 — filter disabled, raw only ─────────────────────────────────────
# Disables filter and enables raw only.  Verifies no filter rules exist and
# raw rules are correctly created.  Also verifies raw rules do NOT have
# connection-state (it's filter-only).
t9_11_raw_only_no_connection_state() {
    bouncer_running || skip_test "bouncer not running"
    config_backup

    _t9_write_config <<'FWCFG'
  filter:
    enabled: false
    connection_state: "new,invalid"
  raw:
    enabled: true
    chains: ["prerouting"]
  deny_action: "drop"
  block_output:
    enabled: false
  rule_placement: "top"
  comment_prefix: "crowdsec-bouncer"
FWCFG

    config_restart_and_wait 60

    local filter_count raw_count
    filter_count=$(ssh_count_filter_rules "ip")
    raw_count=$(ssh_count_raw_rules "ip")

    # Check raw rules don't have connection-state (raw doesn't support it)
    local raw_rules
    raw_rules=$(ssh_list_raw_rules "ip")
    local raw_rule
    raw_rule=$(echo "$raw_rules" | grep "input-v4" | head -1)

    local conn_state=""
    if [[ -n "$raw_rule" ]]; then
        conn_state=$(ssh_get_rule_prop "$raw_rule" "connection-state")
    fi

    log "filter=$filter_count raw=$raw_count  raw connection-state='$conn_state'"

    config_restore

    if (( filter_count > 0 )); then
        echo "FAIL: filter disabled but $filter_count rules found"
        return 1
    fi
    if (( raw_count < 1 )); then
        echo "FAIL: raw enabled but no rules found"
        return 1
    fi
    if [[ -n "$conn_state" ]]; then
        echo "FAIL: raw rule should NOT have connection-state, got '$conn_state'"
        return 1
    fi
}
run_test "T9.11 raw only, no connection-state" t9_11_raw_only_no_connection_state

# ─── T9.12 — custom comment_prefix ─────────────────────────────────────────
# Uses a custom comment prefix to verify the bouncer creates rules with the
# correct prefix.  After the test, manually cleans up orphaned rules because
# the restored bouncer (with default prefix) won't remove custom-prefix rules.
t9_12_custom_comment_prefix() {
    bouncer_running || skip_test "bouncer not running"
    config_backup

    local custom_prefix="cs-test-t9"

    _t9_write_config <<FWCFG
  filter:
    enabled: true
    chains: ["input"]
  raw:
    enabled: false
  deny_action: "drop"
  block_output:
    enabled: false
  rule_placement: "top"
  comment_prefix: "${custom_prefix}"
FWCFG

    # Explicit stop→verify→start to avoid race with previous test's restart.
    bouncer_stop
    sleep 2
    log "config comment_prefix: $(grep comment_prefix "$_BOUNCER_CONFIG")"
    _BOUNCER_START_TS=$(date '+%Y-%m-%d %H:%M:%S')
    bouncer_start
    bouncer_wait_reconciliation 60
    sleep 3

    # Check that rules with the custom prefix exist
    local custom_count
    custom_count=$(ssh_count_filter_rules "ip" "$custom_prefix")

    log "custom prefix rules: $custom_count"

    # Clean up custom-prefix rules before restoring (the restored bouncer
    # only manages rules with the default prefix, so these would be orphaned).
    ssh_cmd "/ip/firewall/filter/remove [find where comment~\"${custom_prefix}\"]" >/dev/null 2>&1 || true
    ssh_cmd "/ipv6/firewall/filter/remove [find where comment~\"${custom_prefix}\"]" >/dev/null 2>&1 || true

    config_restore

    if (( custom_count < 1 )); then
        echo "FAIL: no rules with custom prefix '$custom_prefix' found"
        return 1
    fi
}
run_test "T9.12 custom comment_prefix" t9_12_custom_comment_prefix

# ─── Cleanup: ensure test IP is removed ─────────────────────────────────────
lapi_remove_decision "198.51.100.200" 2>/dev/null || true
