#!/usr/bin/env bash
# =============================================================================
# helpers.sh — Core shared library for cs-routeros-bouncer functional tests
# =============================================================================
#
# Purpose:
#   Provides reusable functions for functional tests that verify the
#   cs-routeros-bouncer binary against real MikroTik hardware.  Tests exercise
#   the full loop: CrowdSec LAPI → bouncer process → RouterOS firewall
#   address-lists, with out-of-band verification via SSH and SNMP.
#
# Usage:
#   Source this file at the top of each test script:
#
#       SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#       source "${SCRIPT_DIR}/lib/helpers.sh"
#       load_env          # reads .env for connection details
#       require_var MIKROTIK_SSH_HOST
#       ...
#       print_summary     # exits non-zero if any test failed
#
# Dependencies:
#   - bash ≥ 4.3 (associative arrays, nameref)
#   - ssh, cscli, systemctl, journalctl, curl, jq, awk, comm, tr
#   - snmpget (net-snmp / snmp package) — only for SNMP helpers
#   - A .env file (next to the calling script) containing at minimum:
#       MIKROTIK_SSH_HOST, MIKROTIK_SSH_PORT, MIKROTIK_SSH_USER,
#       and optionally MIKROTIK_SSH_KEY, SNMP_COMMUNITY, MIKROTIK_CPU_CORES.
#
# RouterOS quirks handled here:
#   • SSH output from RouterOS appends \r to every line; all ssh_cmd output
#     is piped through `tr -d '\r'` to strip carriage returns.
#   • IPv6 firewall address-lists live under /ipv6/firewall/address-list
#     (not /ip/); the helpers auto-detect this when the list name contains
#     the substring "6-".
#   • RouterOS `print terse` produces one entry per line (key=value pairs),
#     which is far easier to parse than the default multi-line table format.
#
# =============================================================================
set -euo pipefail

# ─── Colors & output ────────────────────────────────────────────────────────
# ANSI escape codes for terminal colouring and a small set of logging helpers
# used throughout every test script.  The counters (TESTS_RUN, etc.) and the
# FAILED_NAMES array are module-level state consumed by print_summary().

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# Cumulative test-run counters (updated by run_test / skip_test).
TESTS_RUN=0; TESTS_PASSED=0; TESTS_FAILED=0; TESTS_SKIPPED=0
FAILED_NAMES=()

# log — informational message prefixed with a timestamp.
log()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $*"; }
# warn — warning message highlighted in yellow.
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
# err — error message highlighted in red.
err()  { echo -e "${RED}[ERROR]${NC} $*"; }

# ─── Test framework ─────────────────────────────────────────────────────────
# Minimal TAP-like test harness.  Each test is a callable (function or
# command) executed inside a sub-shell by run_test.  Exit code semantics:
#   0  → PASS
#   77 → SKIP  (convention borrowed from Automake; message in stdout)
#   *  → FAIL  (captured output shown indented under the test name)

# run_test — execute a single named test and record the result.
#
# Args:
#   $1        — human-readable test name (printed to the terminal)
#   $2...$N   — command (and arguments) to execute as the test body
#
# Side-effects:
#   Increments TESTS_RUN and one of TESTS_PASSED / TESTS_FAILED / TESTS_SKIPPED.
#   On failure, appends the test name to FAILED_NAMES[].
#   Prints a ✔ PASS / ⊘ SKIP / ✘ FAIL line with elapsed time in milliseconds.
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
        # shellcheck disable=SC2001
        echo "$output" | sed 's/^/    /'
    fi
}

# skip_test — called from inside a test body to signal a SKIP.
# Prints the reason to stdout and exits with code 77 (caught by run_test).
#
# Args:
#   $* — human-readable skip reason
skip_test() { echo "$*"; exit 77; }

# print_summary — display a summary table and exit non-zero if any test failed.
#
# Must be called at the very end of the test script; its return code is
# typically used as the script's own exit code so that CI pipelines detect
# failures.

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
# Helpers for loading test configuration from a .env file located next to the
# calling test script (path derived from SCRIPT_DIR, which each test script
# must set before sourcing this library).

# load_env — source the .env file, exporting every variable it defines.
#
# Expects SCRIPT_DIR to be set by the caller.  If the .env file is missing
# the function prints an error and exits immediately.
#
# Side-effects: all variables in .env become exported environment variables.
load_env() {
    local envfile="${SCRIPT_DIR:-.}/.env"
    if [[ -f "$envfile" ]]; then
        set -a
        # shellcheck disable=SC1090
        source "$envfile"
        set +a
    else
        err ".env not found at $envfile"; exit 1
    fi
}

# require_var — assert that a named environment variable is set and non-empty.
#
# Args:
#   $1 — variable name (not its value; uses bash indirect expansion ${!var})
#
# Exits with an error message if the variable is unset or empty.
require_var() {
    local var="$1"
    if [[ -z "${!var:-}" ]]; then
        err "Required variable $var is not set"; exit 1
    fi
}

# ─── SSH helpers ─────────────────────────────────────────────────────────────
# Functions that execute commands on the MikroTik router over SSH for
# out-of-band verification.  "Out-of-band" means these do NOT go through the
# bouncer; they let tests confirm that address-list entries actually exist on
# the device (or clean them up before/after a test).
#
# RouterOS quirk: every line of SSH output is terminated with \r\n.  All
# helpers strip \r via `tr -d '\r'` so callers never see carriage returns.
#
# IPv6 detection: RouterOS keeps IPv6 address-lists under a separate path
# (/ipv6/firewall/address-list).  The helpers detect IPv6 lists by checking
# whether the list name contains the substring "6-" (e.g. "crowdsec6-blocklist").

# ssh_cmd — run a single RouterOS CLI command over SSH and return its output.
#
# Args:
#   $1 — RouterOS CLI command string (e.g. "/ip/firewall/address-list/print")
#
# Returns: command output with \r stripped; stderr is suppressed.
# Uses env vars: MIKROTIK_SSH_KEY (optional), MIKROTIK_SSH_PORT, MIKROTIK_SSH_USER,
#                MIKROTIK_SSH_HOST.
# shellcheck disable=SC2153
ssh_cmd() {
    local ssh_key_opt=()
    local batch_opt=()
    if [[ -n "${MIKROTIK_SSH_KEY:-}" && -f "${MIKROTIK_SSH_KEY}" ]]; then
        ssh_key_opt=(-i "${MIKROTIK_SSH_KEY}")
        batch_opt=(-o BatchMode=yes)
    fi
    ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
        "${batch_opt[@]}" "${ssh_key_opt[@]}" -p "${MIKROTIK_SSH_PORT}" \
        "${MIKROTIK_SSH_USER}@${MIKROTIK_SSH_HOST}" "$1" 2>/dev/null | tr -d '\r'
}

# ssh_available — quick connectivity check; returns 0 if SSH to the router works.
ssh_available() {
    ssh_cmd "/system/identity/print" &>/dev/null
}

# ssh_count_addresses — return the number of entries in a RouterOS address-list.
#
# Uses RouterOS `print count-only` which returns a plain integer.
# Auto-selects /ip/ or /ipv6/ path based on list name (see "6-" convention).
#
# Args:
#   $1 — address-list name (e.g. "crowdsec-blocklist" or "crowdsec6-blocklist")
#
# Returns (stdout): integer count, or 0 if the query fails.
ssh_count_addresses() {
    local list="$1"
    local path="/ip/firewall/address-list"
    [[ "$list" == *"6-"* ]] && path="/ipv6/firewall/address-list"
    local count
    count=$(ssh_cmd "${path}/print count-only where list=$list" 2>/dev/null)
    echo "${count:-0}"
}

# ssh_list_addresses — list the IP/prefix values in a RouterOS address-list.
#
# Uses `print terse proplist=address` to get one-line-per-entry output, then
# extracts the address= field with awk.
#
# Args:
#   $1 — address-list name
#
# Returns (stdout): one address per line (e.g. "192.168.1.0/24").
ssh_list_addresses() {
    local list="$1"
    local path="/ip/firewall/address-list"
    [[ "$list" == *"6-"* ]] && path="/ipv6/firewall/address-list"
    ssh_cmd "${path}/print terse proplist=address where list=$list" \
        | awk '/address=/ { for(i=1;i<=NF;i++) if($i ~ /^address=/) {sub(/address=/, "", $i); print $i} }'
}

# ssh_list_addresses_full — list addresses with their comment fields.
#
# Returns the raw `print terse` output including both address= and comment=
# fields, which tests can parse to verify that the bouncer wrote the expected
# CrowdSec decision metadata into each entry's comment.
#
# Args:
#   $1 — address-list name
#
# Returns (stdout): raw terse output lines, e.g. " .id=*1 address=1.2.3.4/32 comment=crowdsec:ban"
ssh_list_addresses_full() {
    local list="$1"
    local path="/ip/firewall/address-list"
    [[ "$list" == *"6-"* ]] && path="/ipv6/firewall/address-list"
    ssh_cmd "${path}/print terse proplist=address,comment where list=$list"
}

# ssh_add_address — add an entry to a RouterOS address-list via SSH.
#
# Used during test setup to inject addresses directly (bypassing the bouncer)
# so that tests can verify the bouncer's reconciliation / cleanup behaviour.
#
# Args:
#   $1 — address-list name
#   $2 — IP address or CIDR to add
#   $3 — (optional) comment string, defaults to "test-injected"
ssh_add_address() {
    local list="$1" address="$2" comment="${3:-test-injected}"
    local path="/ip/firewall/address-list"
    [[ "$list" == *"6-"* ]] && path="/ipv6/firewall/address-list"
    ssh_cmd "${path}/add list=$list address=$address comment=$comment"
}

# ssh_clean_list — remove ALL entries from a RouterOS address-list.
#
# Uses `remove [find list=<name>]` which is a no-op if the list is already
# empty.  Errors are suppressed so the function is safe to call in teardown
# even when the router is unreachable.
#
# Args:
#   $1 — address-list name
ssh_clean_list() {
    local list="$1"
    local path="/ip/firewall/address-list"
    [[ "$list" == *"6-"* ]] && path="/ipv6/firewall/address-list"
    ssh_cmd "${path}/remove [find list=$list]" 2>/dev/null || true
}

# ─── CrowdSec LAPI helpers ──────────────────────────────────────────────────
# Functions that interact with the local CrowdSec LAPI (Local API) through the
# `cscli` CLI tool.  These let tests add/remove ban decisions and then query
# back what the LAPI currently knows, independent of what the bouncer has
# pushed to the router.

# lapi_available — return 0 if cscli is installed and reachable.
lapi_available() {
    cscli version &>/dev/null
}

# lapi_get_ips — return unique IP values of all active "ban" decisions.
#
# Filters decisions by origin (default: "crowdsec,cscli") to exclude CAPI
# community blocklist entries unless explicitly requested.  Uses jq to parse
# the JSON output from `cscli decisions list`.
#
# Args:
#   $1 — (optional) comma-separated list of origins, default "crowdsec,cscli"
#
# Returns (stdout): one IP/CIDR per line, sorted unique.
lapi_get_ips() {
    local origins="${1:-crowdsec,cscli}"
    cscli decisions list --all -o json 2>/dev/null \
        | jq -r --arg origins "$origins" '
            [.[] | select(.decisions != null) | .decisions[]
             | select(.type == "ban")
             | select((.origin // "") as $o | ($origins | split(",")) | map(. == $o) | any)
             | .value] | unique | .[]' 2>/dev/null || true
}

# lapi_get_ipv4 — return only IPv4 addresses from active ban decisions.
# Filters out any line containing ':' (i.e. IPv6 addresses).
#
# Args:
#   $1 — (optional) comma-separated origins, default "crowdsec,cscli"
lapi_get_ipv4() {
    lapi_get_ips "${1:-crowdsec,cscli}" | grep -v ':' || true
}

# lapi_get_ipv6 — return only IPv6 addresses from active ban decisions.
# Keeps only lines containing ':'.
#
# Args:
#   $1 — (optional) comma-separated origins, default "crowdsec,cscli"
lapi_get_ipv6() {
    lapi_get_ips "${1:-crowdsec,cscli}" | grep ':' || true
}

# lapi_count — count active ban decisions (IPv4 + IPv6).
#
# Args:
#   $1 — (optional) comma-separated origins, default "crowdsec,cscli"
#
# Returns (stdout): integer count.
lapi_count() {
    lapi_get_ips "${1:-crowdsec,cscli}" | grep -c . || echo 0
}

# lapi_count_all — count ALL active ban decisions including CAPI (community) origin.
lapi_count_all() {
    lapi_get_ips "crowdsec,cscli,CAPI" | grep -c . || echo 0
}

# lapi_ipv6_count_all — count ALL active IPv6 ban decisions including CAPI origin.
lapi_ipv6_count_all() {
    lapi_get_ipv6 "crowdsec,cscli,CAPI" | grep -c . || echo 0
}

# lapi_add_decision — create a new ban decision in CrowdSec LAPI.
#
# Args:
#   $1 — IP address or CIDR to ban
#   $2 — (optional) decision duration, default "5m"
#   $3 — (optional) reason string, default "functional-test"
lapi_add_decision() {
    local ip="$1" duration="${2:-5m}" reason="${3:-functional-test}"
    cscli decisions add -i "$ip" -d "$duration" -R "$reason" &>/dev/null
}

# lapi_remove_decision — delete an existing decision from CrowdSec LAPI.
#
# Args:
#   $1 — IP address or CIDR whose decision should be removed
#
# Errors are suppressed; safe to call even if the decision does not exist.
lapi_remove_decision() {
    local ip="$1"
    cscli decisions delete -i "$ip" &>/dev/null || true
}

# ─── Bouncer service control ────────────────────────────────────────────────
# Wrappers around systemctl for the cs-routeros-bouncer systemd unit.
#
# _BOUNCER_START_TS is a module-level variable that records the wall-clock
# time of the most recent bouncer_start() or bouncer_restart() call.  It is
# used as the --since argument to journalctl inside
# bouncer_wait_reconciliation() so the function only inspects log lines
# produced after the service was (re)started, avoiding false matches on
# stale entries from a previous run.

# The following functions are invoked indirectly by test scripts that source
# this library.  SC2317/SC2329 are suppressed because static analysis
# within helpers.sh alone cannot see calls in t1-t8 files.
# shellcheck disable=SC2317,SC2329

# bouncer_start — start the bouncer service.
bouncer_start()   { systemctl start cs-routeros-bouncer 2>/dev/null; }
# bouncer_stop — stop the bouncer service.
bouncer_stop()    { systemctl stop cs-routeros-bouncer 2>/dev/null; }
# bouncer_restart — restart the bouncer service.
# shellcheck disable=SC2317,SC2329
bouncer_restart() { systemctl restart cs-routeros-bouncer 2>/dev/null; }
# bouncer_running — return 0 if the bouncer service is active.
# shellcheck disable=SC2317,SC2329
bouncer_running() { systemctl is-active --quiet cs-routeros-bouncer; }

# Timestamp of the last bouncer_start / bouncer_restart, used by
# bouncer_wait_reconciliation() to scope journalctl queries.
_BOUNCER_START_TS=""

# bouncer_start (override) — start the bouncer and record the timestamp.
bouncer_start() {
    _BOUNCER_START_TS=$(date '+%Y-%m-%d %H:%M:%S')
    systemctl start cs-routeros-bouncer 2>/dev/null
}
# bouncer_restart (override) — restart the bouncer and record the timestamp.
bouncer_restart() {
    _BOUNCER_START_TS=$(date '+%Y-%m-%d %H:%M:%S')
    systemctl restart cs-routeros-bouncer 2>/dev/null
}

# bouncer_wait_reconciliation — block until the bouncer logs a reconciliation
# completion message, or until a timeout is reached.
#
# Polls journalctl every 2 seconds looking for one of several known log
# markers ("reconciliation complete", "reconciliation finished", or
# "initial sync complete").  The --since parameter is set to
# _BOUNCER_START_TS so that only log entries from the current run are
# inspected — this prevents false positives from stale journal entries.
#
# Args:
#   $1 — (optional) timeout in seconds, default 120
#
# Returns: 0 on success, 1 on timeout.
bouncer_wait_reconciliation() {
    local timeout="${1:-120}"
    local since="${_BOUNCER_START_TS:-30s ago}"
    local start; start=$(date +%s)
    while true; do
        if journalctl -u cs-routeros-bouncer --since "$since" --no-pager 2>/dev/null \
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

# bouncer_logs_since — retrieve bouncer journal entries from a given point in time.
#
# Args:
#   $1 — timestamp string accepted by journalctl --since (e.g. "2024-01-01 12:00:00")
#
# Returns (stdout): raw journalctl output for the cs-routeros-bouncer unit.
bouncer_logs_since() {
    local since="$1"
    journalctl -u cs-routeros-bouncer --since "$since" --no-pager 2>/dev/null
}

# ─── SNMP helpers (CPU / system monitoring) ─────────────────────────────────
# Monitor MikroTik router resource usage via SNMP.  Used by performance and
# stress tests to assert that the bouncer doesn't drive CPU unreasonably high.
#
# Uses standard HOST-RESOURCES-MIB OIDs — no vendor-specific (MikroTik)
# MIBs are required.  Only the 'snmpget' binary is needed (provided by the
# "snmp" or "net-snmp-utils" package).
#
# Environment variables:
#   MIKROTIK_SSH_HOST  — router IP (reused as SNMP target)
#   SNMP_COMMUNITY     — SNMPv2c community string, default "public"
#   MIKROTIK_CPU_CORES — number of CPU cores on the router, default 4

# OIDs — standard HOST-RESOURCES-MIB and SNMPv2-MIB identifiers.
_OID_CPU_PREFIX=".1.3.6.1.2.1.25.3.3.1.2"   # hrProcessorLoad per core
_OID_UPTIME=".1.3.6.1.2.1.1.3.0"             # sysUpTime
_OID_MEM_TOTAL=".1.3.6.1.2.1.25.2.3.1.5.65536"  # hrStorageSize (main memory)
_OID_MEM_USED=".1.3.6.1.2.1.25.2.3.1.6.65536"   # hrStorageUsed (main memory)

# snmp_available — return 0 if snmpget is installed and a target host is known.
snmp_available() {
    command -v snmpget &>/dev/null && [[ -n "${MIKROTIK_SSH_HOST:-}" ]]
}

# _snmp_get_int — (internal) perform an snmpget and return the raw integer value.
#
# Uses -Oqv (quick-print, value-only) to strip the OID prefix and type tag.
#
# Args:
#   $1 — full OID string
#
# Returns (stdout): integer value, or empty string on failure.
_snmp_get_int() {
    local oid="$1"
    snmpget -v2c -c "${SNMP_COMMUNITY:-public}" -Oqv \
        "${MIKROTIK_SSH_HOST}" "$oid" 2>/dev/null | awk '{print $1}'
}

# snmp_cpu_cores — read per-core CPU load and echo space-separated percentages.
#
# Returns (stdout): e.g. "12 8 15 9" for a 4-core router.
snmp_cpu_cores() {
    local cores="${MIKROTIK_CPU_CORES:-4}"
    local vals=()
    for i in $(seq 1 "$cores"); do
        vals+=("$(_snmp_get_int "${_OID_CPU_PREFIX}.$i")")
    done
    echo "${vals[*]}"
}

# snmp_cpu_avg — return the arithmetic mean CPU load across all cores.
#
# Returns (stdout): integer percentage (0-100).
snmp_cpu_avg() {
    local cores="${MIKROTIK_CPU_CORES:-4}"
    local sum=0 val
    for i in $(seq 1 "$cores"); do
        val=$(_snmp_get_int "${_OID_CPU_PREFIX}.$i")
        sum=$((sum + ${val:-0}))
    done
    echo $((sum / cores))
}

# query_cpu — sample the average CPU load N times over a window.
#
# Useful for smoothing out transient spikes during stress/performance tests.
#
# Args:
#   $1 — (optional) number of samples, default 6
#   $2 — (optional) interval between samples in seconds, default 5
#
# Returns (stdout): "avg max" — two space-separated integers (percentages).
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

# query_cpu_instant — single-shot CPU average reading with no sleep delay.
# Suitable for quick pre/post checks where high precision is not required.
query_cpu_instant() {
    snmp_cpu_avg
}

# snmp_mem_percent — return router memory utilisation as an integer percentage.
#
# Reads hrStorageSize and hrStorageUsed for the main-memory storage index
# (65536 on RouterOS) and computes used*100/total.
#
# Returns (stdout): integer 0-100, or 0 if the query fails.
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

# snmp_uptime_secs — return the router's uptime in whole seconds.
#
# Uses -Ot to get raw timeticks (hundredths of a second) from sysUpTime,
# then converts to whole seconds via integer division.
snmp_uptime_secs() {
    local raw
    raw=$(snmpget -v2c -c "${SNMP_COMMUNITY:-public}" -Oqvt \
        "${MIKROTIK_SSH_HOST}" "$_OID_UPTIME" 2>/dev/null)
    # Raw timeticks are in hundredths of a second
    echo $(( raw / 100 ))
}

# ─── Metrics helpers ────────────────────────────────────────────────────────
# Query the bouncer's Prometheus /metrics endpoint (default :2112).

# bouncer_metric — fetch a single Prometheus metric value from the bouncer.
#
# Looks for a line starting with the exact metric name, then extracts the
# numeric value (second whitespace-delimited field).
#
# Args:
#   $1 — metric name (e.g. "cs_routeros_bouncer_decisions_total")
#
# Returns (stdout): the metric's numeric value, or empty string if not found.
bouncer_metric() {
    local metric="$1"
    curl -s --max-time 5 "http://localhost:2112/metrics" 2>/dev/null \
        | grep "^${metric}" | awk '{print $2}' | head -1
}

# ─── Utility ────────────────────────────────────────────────────────────────
# General-purpose helpers used across many test scripts.

# wait_for — poll a command until it succeeds or a timeout is reached.
#
# Args:
#   $1 — human-readable description (used in the timeout error message)
#   $2 — timeout in seconds
#   $3 — (optional) poll interval in seconds, default 2
#   $4...$N — command (and arguments) to execute on each iteration
#
# Returns: 0 when the command succeeds, 1 on timeout.
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

# is_valid_ipv4 — return 0 if the argument looks like a dotted-quad IPv4,
# optionally followed by a CIDR prefix length (e.g. "10.0.0.1/32").
is_valid_ipv4() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]
}

# is_valid_ipv6 — return 0 if the argument contains a colon (simple heuristic).
is_valid_ipv6() {
    [[ "$1" =~ : ]]
}

# normalize_ipv6 — ensure an IPv6 address has a /128 prefix-length suffix.
#
# CrowdSec decisions may omit the prefix length for single-host addresses,
# but RouterOS always stores them with an explicit prefix.  This normalises
# both representations so string comparisons work correctly.
#
# Args:
#   $1 — IPv6 address, with or without /prefix
#
# Returns (stdout): address with /128 appended if no prefix was present.
normalize_ipv6() {
    local addr="$1"
    if [[ "$addr" != */* ]]; then
        echo "${addr}/128"
    else
        echo "$addr"
    fi
}

# diff_sets — output lines present in file_a but not in file_b.
#
# Both files are sorted before comparison.  Useful for finding addresses that
# exist on the router but are missing from LAPI (or vice-versa).
#
# Args:
#   $1 — path to first file  (the "expected" set)
#   $2 — path to second file (the "actual" set)
#
# Returns (stdout): lines unique to file_a (i.e. missing from file_b).
diff_sets() {
    local file_a="$1" file_b="$2"
    comm -23 <(sort "$file_a") <(sort "$file_b")
}
