#!/usr/bin/env bash
# =============================================================================
# Functional Test Runner — CrowdSec RouterOS Bouncer
# =============================================================================
# Tests the compiled binary against real MikroTik hardware.
# All verification is done via SSH (out-of-band) and CrowdSec cscli.
#
# Usage:
#   ./run_tests.sh                  # Run all test groups (except CAPI)
#   ./run_tests.sh t1               # Run only group 1 (integrity)
#   ./run_tests.sh t1 t2            # Run groups 1 and 2
#   ./run_tests.sh --capi           # Include CAPI stress tests (~25k IPs)
#   ./run_tests.sh --capi t8        # Run only CAPI group
#   ./run_tests.sh --list           # List available test groups
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"
load_env

ENABLE_CAPI=false
GROUPS=()

# ─── Parse arguments ────────────────────────────────────────────────────────
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
        t[1-8]) GROUPS+=("$1"); shift ;;
        *)  err "Unknown argument: $1"; exit 1 ;;
    esac
done

# Default: all groups except t8 (CAPI)
if [[ ${#GROUPS[@]} -eq 0 ]]; then
    GROUPS=(t1 t2 t3 t4 t5 t6 t7)
    if $ENABLE_CAPI; then GROUPS+=(t8); fi
fi

# ─── Preflight checks ──────────────────────────────────────────────────────
log "Preflight checks..."
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

if influx_available; then
    log "InfluxDB: ${GREEN}OK${NC} (CPU monitoring enabled)"
else
    warn "InfluxDB not configured — CPU tests will be skipped"
fi

if bouncer_running; then
    log "Bouncer service: ${GREEN}running${NC}"
else
    warn "Bouncer service not running — some tests will start it"
fi

echo -e "\n${BOLD}Running groups: ${GROUPS[*]}${NC}"
if $ENABLE_CAPI; then
    echo -e "${YELLOW}⚠  CAPI stress tests enabled (~25k IPs — may take several minutes)${NC}"
fi

# ─── Run selected groups ───────────────────────────────────────────────────
for group in "${GROUPS[@]}"; do
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
print_summary
