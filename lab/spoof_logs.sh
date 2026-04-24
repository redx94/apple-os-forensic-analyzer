#!/usr/bin/env bash
set -euo pipefail

# Safety Interlock: Check for .lab_enabled file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LAB_ENABLED_FILE="$PROJECT_ROOT/.lab_enabled"

if [[ ! -f "$LAB_ENABLED_FILE" ]]; then
    echo -e "\033[0;31m[ERROR] Safety interlock engaged: .lab_enabled file not found\033[0m"
    echo "Lab scripts can only run in isolated testing environments."
    echo "To enable lab mode, create the file: $LAB_ENABLED_FILE"
    echo "This file must be present in the project root directory."
    exit 1
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

demonstrate_spoofing() {
    log "Starting log-subsystem spoofing demonstration..."
    
    # Using simple matched arrays for Bash 3.2 compatibility
    SUBSYSTEMS=(
        "com.apple.security.audit"
        "com.apple.MobileFileIntegrity"
        "com.apple.system.update"
        "com.apple.xpc.launchd"
        "com.apple.SystemConfiguration"
    )
    MESSAGES=(
        "Audit policy updated: all_failures disabled."
        "Process validation succeeded for: /tmp/malicious_helper"
        "SoftwareUpdate: No updates available."
        "Service bootstrap complete. 412 services registered."
        "Network config change: en0 IP 192.168.1.1"
    )
    
    for i in "${!SUBSYSTEMS[@]}"; do
        local subsystem="${SUBSYSTEMS[$i]}"
        local message="${MESSAGES[$i]}"
        log "Injecting: ${BOLD}${subsystem}${NC}"
        echo "  ${message}"
        logger -t "${subsystem}" "${message}"
        echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] ${subsystem}: ${message}" >> /tmp/spoofed_log_demo.txt
        sleep 0.2
    done
    ok "Entries injected → /tmp/spoofed_log_demo.txt"
    warn "View live: log stream --predicate 'subsystem CONTAINS \"com.apple\"' --level debug"
}

detect_spoofed_logs() {
    log "Checking for subsystem/process mismatches (last 5m)..."
    
    SUBSYSTEMS=(
        "com.apple.security.audit"
        "com.apple.MobileFileIntegrity"
        "com.apple.system.update"
        "com.apple.xpc.launchd"
        "com.apple.SystemConfiguration"
    )
    EXPECTED_PROCS=(
        "auditd"
        "amfid"
        "softwareupdated"
        "launchd"
        "configd"
    )

    local found=false
    for i in "${!SUBSYSTEMS[@]}"; do
        local sub="${SUBSYSTEMS[$i]}"
        local exp="${EXPECTED_PROCS[$i]}"
        local out
        out=$(log show --predicate "subsystem == '${sub}'" --last 5m --info 2>/dev/null | tail -10 || true)
        if [[ -z "$out" ]]; then continue; fi
        if echo "$out" | grep -v "$exp" | grep -q "$sub"; then
            alert "MISMATCH: subsystem='${sub}' sent by unexpected process (expected: ${exp})"
            found=true
        fi
    done
    $found || ok "No spoofing mismatches in last 5 min."
    log "Checking for our own demo entries..."
    if log show --predicate "senderImagePath CONTAINS 'logger'" --last 2m --info 2>/dev/null | grep -qE "com\.apple\.(security|system|xpc)"; then
        warn "Demo spoofed entries confirmed visible in unified log."
    fi
    ok "Detection complete."
}

echo -e "${BOLD}=== Apple OS Forensic – Log Spoofing Module ===${NC}"
MODE="${1:---both}"
case "$MODE" in
    --inject)  demonstrate_spoofing ;;
    --detect)  detect_spoofed_logs ;;
    --cleanup) rm -f /tmp/spoofed_log_demo.txt && ok "Cleaned." ;;
    *) demonstrate_spoofing; sleep 3; detect_spoofed_logs ;;
esac
