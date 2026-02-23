#!/usr/bin/env bash
# =============================================================================
# Functional Test Runner — CrowdSec RouterOS Bouncer
# =============================================================================
# Black-box test suite that validates the compiled bouncer binary against real
# MikroTik hardware. All verification is out-of-band: SSH to the router,
# cscli queries to CrowdSec LAPI, SNMP for CPU/memory, and the bouncer's own
# Prometheus /metrics endpoint.
#
# The suite is organized into 8 test groups (t1–t8), each in its own file.
# Groups t1–t7 run with the default local-only decision set (~1,500 IPs).
# Group t8 (CAPI) exercises the community blocklist (~25,000 IPs) and must
# be explicitly enabled with --capi.
#
# Prerequisites:
#   - MikroTik router reachable via SSH (key-based auth)
#   - CrowdSec LAPI running with cscli available
#   - Bouncer binary installed and configured as a systemd service
#   - SNMP enabled on router (optional — CPU tests skipped if unavailable)
#   - .env file with connection parameters (see .env.example)
#
# Usage:
#   ./run_tests.sh                  # Run all test groups (except CAPI)
#   ./run_tests.sh t1               # Run only group 1 (integrity)
#   ./run_tests.sh t1 t2            # Run groups 1 and 2
#   ./run_tests.sh --capi           # Include CAPI stress tests (~25k IPs)
#   ./run_tests.sh --capi t8        # Run only CAPI group
#   ./run_tests.sh --list           # List available test groups
#
# Exit code:
#   0 — all tests passed
#   1 — one or more tests failed or preflight check failed
# =============================================================================
set -euo pipefail

# Resolve this script's directory for sourcing sibling files.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the shared helper library (test framework, SSH, LAPI, SNMP, etc.)
source "${SCRIPT_DIR}/lib/helpers.sh"

# Load environment variables from .env (router credentials, SNMP community, etc.)
load_env

ENABLE_CAPI=false   # Set to true by --capi flag
RUN_GROUPS=()       # Populated from CLI args or defaults to t1–t7

# ─── Parse CLI arguments ────────────────────────────────────────────────────
# Accepts --capi, --list, and group selectors (t1–t8).
while [[ $# -gt 0 ]]; do
    case "$1" in
        --capi) ENABLE_CAPI=true; shift ;;
        --list)
            echo "Available test groups:"
            echo "  t1  Data integrity (IP completeness, format, comments)"
            echo "  t2  Cache consistency (ban/unban, expiry, fast-path)"
            echo "  t3  Bulk operations (full reconciliation, partial sync, orphans)"
            echo "  t4  Connection pool (establishment, shutdown)"
            echo "  t5  Edge cases (duplicates, rapid cycle, restart idempotency)"
            echo "  t6  CPU monitoring (steady-state, peak, recovery)"
            echo "  t7  Timing measurements (reconciliation, ban/unban latency)"
            echo "  t8  CAPI stress test ~25k IPs (requires --capi flag)"
            exit 0 ;;
        t[1-8]) RUN_GROUPS+=("$1"); shift ;;
        *)  err "Unknown argument: $1"; exit 1 ;;
    esac
done

# Default: run t1–t7 when no groups specified. CAPI (t8) only if --capi given.
if [[ ${#RUN_GROUPS[@]} -eq 0 ]]; then
    RUN_GROUPS=(t1 t2 t3 t4 t5 t6 t7)
    if $ENABLE_CAPI; then RUN_GROUPS+=(t8); fi
fi

# ─── Preflight checks ──────────────────────────────────────────────────────
# Verify all required infrastructure is reachable before running any tests.
# Failures here abort immediately — no point running tests without hardware.
log "Preflight checks..."

# These four vars are mandatory; load_env should have set them from .env.
require_var MIKROTIK_SSH_HOST
require_var MIKROTIK_SSH_KEY
require_var MIKROTIK_SSH_PORT
require_var MIKROTIK_SSH_USER

if ! ssh_available; then
    err "Cannot SSH to MikroTik at ${MIKROTIK_SSH_HOST}:${MIKROTIK_SSH_PORT}"
    exit 1
fi

if ! lapi_available; then
    err "CrowdSec cscli not available"
    exit 1
fi

log "MikroTik SSH: ${GREEN}OK${NC}"
log "CrowdSec LAPI: ${GREEN}OK${NC}"

# SNMP is optional — CPU/memory tests (t6) will be skipped if snmpget is missing.
if snmp_available; then
    log "SNMP monitoring: ${GREEN}OK${NC} (CPU tests enabled)"
else
    warn "snmpget not available — CPU tests will be skipped"
fi

if bouncer_running; then
    log "Bouncer service: ${GREEN}running${NC}"
else
    warn "Bouncer service not running — some tests will start it"
fi

echo -e "\n${BOLD}Running groups: ${RUN_GROUPS[*]}${NC}"
if $ENABLE_CAPI; then
    echo -e "${YELLOW}⚠  CAPI stress tests enabled (~25k IPs — may take several minutes)${NC}"
fi

# ─── Run selected groups ───────────────────────────────────────────────────
# Each group is a separate file: t1_integrity.sh, t2_cache.sh, etc.
# The file is `source`d so its test functions execute in the current shell
# context with access to all helpers.sh functions and global variables.
for group in "${RUN_GROUPS[@]}"; do
    script="${SCRIPT_DIR}/${group}_*.sh"
    # shellcheck disable=SC2086
    found=(${script})
    if [[ -f "${found[0]}" ]]; then
        echo -e "\n${BOLD}━━━ ${group^^} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        source "${found[0]}"
    else
        warn "Test group $group not found"
    fi
done

# ─── Summary ────────────────────────────────────────────────────────────────
# Print pass/fail/skip counts and exit with appropriate code.
print_summary
