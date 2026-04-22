#!/usr/bin/env bash
# ============================================================
# parent_process_analyzer.sh - Parent Process Anomaly Detection
# ============================================================
# Apple OS Forensic Analyzer
#
# Purpose:
# Analyzes parent process relationships for com.apple.* objects
# to detect unusual parentage patterns indicative of masquerading.
# Based on mindmap: "Unusual Process Parentage Patterns"
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

# Suspicious parent processes for com.apple.* children
SUSPICIOUS_PARENTS=(
    "Terminal"
    "bash"
    "zsh"
    "python"
    "python3"
    "perl"
    "node"
    "unknown"
    "(unknown)"
)

echo -e "${BOLD}=== Apple OS Forensic Parent Process Analyzer ===${NC}"
log "Analyzing com.apple.* process parentage..."

TOTAL_PROCESSES=0
TOTAL_ALERTS=0

expected_parent_for() {
    local proc="$1"
    case "$proc" in
        UserEventAgent|NotificationCenter)
            echo "launchd"
            ;;
        loginwindow)
            echo "WindowServer"
            ;;
        kernel_task)
            echo "kernel"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Get all processes that have com.apple in their command path/name
while IFS= read -r pid ppid comm; do
    [[ -z "${pid:-}" ]] && continue
    [[ -z "${ppid:-}" ]] && continue
    [[ -z "${comm:-}" ]] && continue

    if [[ "$comm" != *"com.apple"* && "$comm" != com.apple.* ]]; then
        continue
    fi

    ((++TOTAL_PROCESSES))

    parent_comm=$(ps -p "$ppid" -o comm= 2>/dev/null || echo "unknown")
    
    log "Process: $comm (PID: $pid, Parent: $parent_comm)"
    
    # Check for suspicious parent
    for susp_parent in "${SUSPICIOUS_PARENTS[@]}"; do
        if [[ "$parent_comm" == *"$susp_parent"* ]]; then
            alert "SUSPICIOUS PARENT: $comm (PID: $pid) has parent $parent_comm (PID: $parent_pid)"
            ((++TOTAL_ALERTS))
            break
        fi
    done
    
    expected_parent=$(expected_parent_for "$comm")
    if [[ -n "$expected_parent" && "$parent_comm" != *"$expected_parent"* ]]; then
        warn "UNEXPECTED PARENT: $comm expected parent $expected_parent but has $parent_comm"
        ((++TOTAL_ALERTS))
    fi
    
done < <(ps -axo pid=,ppid=,comm= | grep -E "com\.apple" | awk '{print $1, $2, $3}')

echo -e "${BOLD}=== Analysis Complete ===${NC}"
ok "Total processes analyzed: $TOTAL_PROCESSES"
if [[ $TOTAL_ALERTS -gt 0 ]]; then
    alert "Total alerts: $TOTAL_ALERTS"
    alert "REVIEW ALL ALERTS ABOVE - Potential masquerading detected"
else
    ok "No suspicious parentage patterns detected"
fi
