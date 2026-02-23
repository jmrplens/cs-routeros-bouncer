#!/usr/bin/env bash
# =============================================================================
# Shared helpers for functional tests
# =============================================================================
set -euo pipefail

# ─── Colors & output ────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

TESTS_RUN=0; TESTS_PASSED=0; TESTS_FAILED=0; TESTS_SKIPPED=0
FAILED_NAMES=()

log()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; }

# ─── Test framework ─────────────────────────────────────────────────────────
run_test() {
    local name="$1"; shift
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -e "\n${BOLD}▶ ${name}${NC}"
    local start_ts; start_ts=$(date +%s%N)
    local output rc=0
    output=$("$@" 2>&1) || rc=$?
    local end_ts; end_ts=$(date +%s%N)
    local elapsed_ms=$(( (end_ts - start_ts) / 1000000 ))

    if [[ $rc -eq 0 ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✔ PASS${NC} (${elapsed_ms}ms)"
    elif [[ $rc -eq 77 ]]; then
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
        echo -e "  ${YELLOW}⊘ SKIP${NC}: ${output}"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        FAILED_NAMES+=("$name")
        echo -e "  ${RED}✘ FAIL${NC} (${elapsed_ms}ms)"
        echo "$output" | sed 's/^/    /'
    fi
}

skip_test() { echo "$*"; exit 77; }

print_summary() {
    echo -e "\n${BOLD}═══════════════════════════════════════════${NC}"
    echo -e "  Total: ${TESTS_RUN}  ${GREEN}Passed: ${TESTS_PASSED}${NC}" \
            " ${RED}Failed: ${TESTS_FAILED}${NC}" \
            " ${YELLOW}Skipped: ${TESTS_SKIPPED}${NC}"
    if [[ ${#FAILED_NAMES[@]} -gt 0 ]]; then
        echo -e "\n  ${RED}Failed tests:${NC}"
        for n in "${FAILED_NAMES[@]}"; do echo "    - $n"; done
    fi
    echo -e "${BOLD}═══════════════════════════════════════════${NC}"
    [[ ${TESTS_FAILED} -eq 0 ]]
}

# ─── Environment ─────────────────────────────────────────────────────────────
load_env() {
    local envfile="${SCRIPT_DIR:-.}/.env"
    if [[ -f "$envfile" ]]; then
        set -a; source "$envfile"; set +a
    else
        err ".env not found at $envfile"; exit 1
    fi
}

require_var() {
    local var="$1"
    if [[ -z "${!var:-}" ]]; then
        err "Required variable $var is not set"; exit 1
    fi
}

# ─── SSH helpers ─────────────────────────────────────────────────────────────
ssh_cmd() {
    ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes \
        -i "${MIKROTIK_SSH_KEY}" -p "${MIKROTIK_SSH_PORT}" \
        "${MIKROTIK_SSH_USER}@${MIKROTIK_SSH_HOST}" "$1" 2>/dev/null | tr -d '\r'
}

ssh_available() {
    ssh_cmd "/system/identity/print" &>/dev/null
}

# Count addresses in a list via SSH (out-of-band verification)
ssh_count_addresses() {
    local list="$1"
    local count
    count=$(ssh_cmd "/ip/firewall/address-list/print count-only where list=$list" 2>/dev/null)
    echo "${count:-0}"
}

# List addresses via SSH
ssh_list_addresses() {
    local list="$1"
    ssh_cmd "/ip/firewall/address-list/print proplist=address where list=$list" \
        | awk '/address=/ {sub(/address=/, ""); print $1}'
}

# List addresses with comments
ssh_list_addresses_full() {
    local list="$1"
    ssh_cmd "/ip/firewall/address-list/print proplist=address,comment where list=$list"
}

# Add an address via SSH (bypass bouncer for test setup)
ssh_add_address() {
    local list="$1" address="$2" comment="${3:-test-injected}"
    ssh_cmd "/ip/firewall/address-list/add list=$list address=$address comment=$comment"
}

# Remove ALL addresses from a list
ssh_clean_list() {
    local list="$1"
    ssh_cmd "/ip/firewall/address-list/remove [find list=$list]" 2>/dev/null || true
}

# ─── CrowdSec LAPI helpers ──────────────────────────────────────────────────
lapi_available() {
    cscli version &>/dev/null
}

# Get all active decisions for the bouncer's origins
lapi_get_ips() {
    local origins="${1:-crowdsec,cscli}"
    cscli decisions list --all -o json 2>/dev/null \
        | jq -r --arg origins "$origins" '
            [.[] | select(.decisions != null) | .decisions[]
             | select(.type == "ban")
             | select((.origin // "") as $o | ($origins | split(",")) | map(. == $o) | any)
             | .value] | unique | .[]' 2>/dev/null || true
}

lapi_get_ipv4() {
    lapi_get_ips "${1:-crowdsec,cscli}" | grep -v ':' || true
}

lapi_get_ipv6() {
    lapi_get_ips "${1:-crowdsec,cscli}" | grep ':' || true
}

lapi_count() {
    lapi_get_ips "${1:-crowdsec,cscli}" | grep -c . || echo 0
}

# Count ALL decisions regardless of origin (includes CAPI)
lapi_count_all() {
    lapi_get_ips "crowdsec,cscli,CAPI" | grep -c . || echo 0
}

lapi_ipv6_count_all() {
    lapi_get_ipv6 "crowdsec,cscli,CAPI" | grep -c . || echo 0
}

lapi_add_decision() {
    local ip="$1" duration="${2:-5m}" reason="${3:-functional-test}"
    cscli decisions add -i "$ip" -d "$duration" -R "$reason" &>/dev/null
}

lapi_remove_decision() {
    local ip="$1"
    cscli decisions delete -i "$ip" &>/dev/null || true
}

# ─── Bouncer service control ────────────────────────────────────────────────
bouncer_start()   { systemctl start cs-routeros-bouncer 2>/dev/null; }
bouncer_stop()    { systemctl stop cs-routeros-bouncer 2>/dev/null; }
bouncer_restart() { systemctl restart cs-routeros-bouncer 2>/dev/null; }
bouncer_running() { systemctl is-active --quiet cs-routeros-bouncer; }

# Wait for bouncer to complete reconciliation (look for log marker)
bouncer_wait_reconciliation() {
    local timeout="${1:-120}"
    local start; start=$(date +%s)
    while true; do
        if journalctl -u cs-routeros-bouncer --since "30s ago" --no-pager 2>/dev/null \
            | grep -q "reconciliation complete\|reconciliation finished\|initial sync complete"; then
            return 0
        fi
        if (( $(date +%s) - start > timeout )); then
            err "Timeout waiting for reconciliation (${timeout}s)"
            return 1
        fi
        sleep 2
    done
}

# Get bouncer logs since a timestamp
bouncer_logs_since() {
    local since="$1"
    journalctl -u cs-routeros-bouncer --since "$since" --no-pager 2>/dev/null
}

# ─── SNMP helpers (CPU / system monitoring) ─────────────────────────────────
# Uses standard HOST-RESOURCES-MIB — no vendor-specific dependencies.
# Only requires the 'snmpget' binary (package: snmp / net-snmp-utils).

# OIDs
_OID_CPU_PREFIX=".1.3.6.1.2.1.25.3.3.1.2"   # hrProcessorLoad per core
_OID_UPTIME=".1.3.6.1.2.1.1.3.0"             # sysUpTime
_OID_MEM_TOTAL=".1.3.6.1.2.1.25.2.3.1.5.65536"  # hrStorageSize (main memory)
_OID_MEM_USED=".1.3.6.1.2.1.25.2.3.1.6.65536"   # hrStorageUsed (main memory)

snmp_available() {
    command -v snmpget &>/dev/null && [[ -n "${MIKROTIK_SSH_HOST:-}" ]]
}

# Raw SNMP get — returns just the integer value
_snmp_get_int() {
    local oid="$1"
    snmpget -v2c -c "${SNMP_COMMUNITY:-public}" -Oqv \
        "${MIKROTIK_SSH_HOST}" "$oid" 2>/dev/null | awk '{print $1}'
}

# Get per-core CPU array — echo space-separated percentages
snmp_cpu_cores() {
    local cores="${MIKROTIK_CPU_CORES:-4}"
    local vals=()
    for i in $(seq 1 "$cores"); do
        vals+=("$(_snmp_get_int "${_OID_CPU_PREFIX}.$i")")
    done
    echo "${vals[*]}"
}

# Average CPU across all cores — returns integer percentage
snmp_cpu_avg() {
    local cores="${MIKROTIK_CPU_CORES:-4}"
    local sum=0 val
    for i in $(seq 1 "$cores"); do
        val=$(_snmp_get_int "${_OID_CPU_PREFIX}.$i")
        sum=$((sum + ${val:-0}))
    done
    echo $((sum / cores))
}

# Sample CPU N times over a window and return "avg max"
# Usage: query_cpu [samples] [interval_secs]
query_cpu() {
    local samples="${1:-6}" interval="${2:-5}"
    local sum=0 max_val=0 current
    for _ in $(seq 1 "$samples"); do
        current=$(snmp_cpu_avg)
        sum=$((sum + current))
        (( current > max_val )) && max_val=$current
        sleep "$interval"
    done
    local avg=$((sum / samples))
    echo "$avg $max_val"
}

# Quick single-shot CPU reading (no sleep, for fast checks)
query_cpu_instant() {
    snmp_cpu_avg
}

# Memory used percentage
snmp_mem_percent() {
    local total used
    total=$(_snmp_get_int "$_OID_MEM_TOTAL")
    used=$(_snmp_get_int "$_OID_MEM_USED")
    if [[ -n "$total" && "$total" -gt 0 ]]; then
        echo $(( used * 100 / total ))
    else
        echo 0
    fi
}

# Router uptime in seconds (parses D:H:M:S.cs format from -Oqv)
snmp_uptime_secs() {
    local raw
    raw=$(snmpget -v2c -c "${SNMP_COMMUNITY:-public}" -Oqv \
        "${MIKROTIK_SSH_HOST}" "$_OID_UPTIME" 2>/dev/null)
    # Format: D:H:M:S.cs — extract numeric parts
    local d h m s
    IFS=':' read -r d h m s <<< "${raw%%.*}"
    echo $(( d*86400 + h*3600 + m*60 + s ))
}

# ─── Metrics helpers ────────────────────────────────────────────────────────
bouncer_metric() {
    local metric="$1"
    curl -s --max-time 5 "http://localhost:2112/metrics" 2>/dev/null \
        | grep "^${metric}" | awk '{print $2}' | head -1
}

# ─── Utility ────────────────────────────────────────────────────────────────
wait_for() {
    local description="$1" timeout="$2" interval="${3:-2}"
    shift 3
    local start; start=$(date +%s)
    while true; do
        if "$@" 2>/dev/null; then return 0; fi
        if (( $(date +%s) - start > timeout )); then
            err "Timeout waiting for: $description (${timeout}s)"
            return 1
        fi
        sleep "$interval"
    done
}

is_valid_ipv4() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]
}

is_valid_ipv6() {
    [[ "$1" =~ : ]]
}

# Normalize IPv6: ensure /128 suffix
normalize_ipv6() {
    local addr="$1"
    if [[ "$addr" != */* ]]; then
        echo "${addr}/128"
    else
        echo "$addr"
    fi
}

# Diff two sorted files, output lines unique to each
diff_sets() {
    local file_a="$1" file_b="$2"
    comm -23 <(sort "$file_a") <(sort "$file_b")
}
