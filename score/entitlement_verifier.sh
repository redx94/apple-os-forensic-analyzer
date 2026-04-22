#!/usr/bin/env bash
# ============================================================
# entitlement_verifier.sh - Entitlement Mismatch Detection
# ============================================================
# Apple OS Forensic Analyzer
#
# Purpose:
# Inspects entitlements of com.apple.* binaries to detect
# mismatches between expected and actual entitlements,
# which can indicate masquerading or compromised binaries.
# Based on mindmap: "Code Signing and Integrity Verification"
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

# Suspicious entitlements that shouldn't be in com.apple.* binaries
SUSPICIOUS_ENTITLEMENTS=(
    "com.apple.security.get-task-allow"
    "com.apple.security.cs.disable-library-validation"
    "com.apple.security.cs.allow-unsigned-executable-memory"
    "com.apple.security.cs.disable-executable-page-protection"
)

echo -e "${BOLD}=== Apple OS Forensic Entitlement Verifier ===${NC}"
log "Inspecting entitlements for com.apple.* binaries..."

TOTAL_CHECKED=0
TOTAL_ALERTS=0

expected_entitlement_for() {
    local label="$1"
    case "$label" in
        com.apple.endpointsecurity.endpointsecurityd)
            echo "com.apple.private.endpointsecurity-manager"
            ;;
        com.apple.trustevaluationagent)
            echo "com.apple.private.trust-cache"
            ;;
        com.apple.securityd)
            echo "com.apple.private.securityd"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Scan launchd plists for com.apple.* binaries
SCAN_DIRS=("/System/Library/LaunchDaemons" "/Library/LaunchDaemons" "/System/Library/LaunchAgents" "/Library/LaunchAgents")

for dir in "${SCAN_DIRS[@]}"; do
    [[ ! -d "$dir" ]] && continue
    log "Scanning: $dir"
    
    for plist in "$dir"/*.plist; do
        [[ ! -f "$plist" ]] && continue
        
        label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null || echo "")
        [[ "$label" != com.apple.* ]] && continue
        
        binary=$(/usr/libexec/PlistBuddy -c "Print :Program" "$plist" 2>/dev/null || /usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null || echo "")
        [[ "$binary" == "N/A" || ! -f "$binary" ]] && continue
        
        ((++TOTAL_CHECKED))
        
        # Get entitlements
        entitlements=$(codesign -d --entitlements - "$binary" 2>/dev/null || echo "")
        
        if [[ -z "$entitlements" ]]; then
            warn "NO ENTITLEMENTS: $label ($binary)"
            continue
        fi
        
        log "Checking: $label ($binary)"
        
        # Check for suspicious entitlements
        for susp_ent in "${SUSPICIOUS_ENTITLEMENTS[@]}"; do
            if echo "$entitlements" | grep -q "$susp_ent"; then
                alert "SUSPICIOUS ENTITLEMENT: $label has $susp_ent (allows code injection/bypass)"
                ((++TOTAL_ALERTS))
            fi
        done
        
        # Check for expected entitlements mismatch
        expected=$(expected_entitlement_for "$label")
        if [[ -n "$expected" ]]; then
            if ! echo "$entitlements" | grep -q "$expected"; then
                alert "MISSING EXPECTED ENTITLEMENT: $label missing $expected"
                ((++TOTAL_ALERTS))
            fi
        fi
        
        # Check for unexpected entitlements (too many entitlements can indicate compromise)
        ent_count=$(echo "$entitlements" | grep -c "key" 2>/dev/null)
        ent_count=${ent_count:-0}
        # Ensure ent_count is a clean number
        ent_count=$(echo "$ent_count" | tr -cd '0-9')
        if [[ "$ent_count" -gt 20 ]]; then
            warn "EXCESSIVE ENTITLEMENTS: $label has $ent_count entitlements (may indicate compromise)"
            ((++TOTAL_ALERTS))
        fi
    done
done

echo -e "${BOLD}=== Analysis Complete ===${NC}"
ok "Total binaries checked: $TOTAL_CHECKED"
if [[ $TOTAL_ALERTS -gt 0 ]]; then
    alert "Total alerts: $TOTAL_ALERTS"
    alert "REVIEW ALL ALERTS ABOVE - Potential entitlement-based masquerading detected"
else
    ok "No entitlement anomalies detected"
fi
