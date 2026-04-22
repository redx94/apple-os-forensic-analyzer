#!/usr/bin/env bash
# ============================================================
# detect_agents.sh - Enhanced Persistence Scanner with Behavioral Detection
# ============================================================
# Apple OS Forensic Analyzer
#
# Purpose:
# Scans launchd persistence directories for suspicious agents
# using behavioral detection: namespace squatting, path validation,
# signature verification, MachServices, KeepAlive, Sockets, symlinks.
# ============================================================

set -euo pipefail

SCAN_DIRS=("/Library/LaunchDaemons" "/Library/LaunchAgents" "/System/Library/LaunchDaemons" "/System/Library/LaunchAgents")
TRUSTED_PATHS=("/System/Library" "/usr/bin" "/usr/sbin" "/usr/libexec" "/bin" "/sbin" "/Library/Apple")
SUSPICIOUS_PATTERNS=("com.apple.update" "com.apple.system.update" "com.apple.crash" "com.apple.helper" "com.apple.analytics" "com.apple.metricsd")

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

TOTAL_SCANNED=0
TOTAL_ALERTS=0

echo -e "${BOLD}=== Apple OS Forensic Persistence Scanner ===${NC}"
log "Scanning persistence directories..."

check_namespace_squatting() {
    local label="$1"
    local binary="$2"
    
    # Flag if label claims Apple but binary isn't in system paths
    if [[ "$label" == com.apple.* && -n "$binary" && "$binary" != "N/A" ]]; then
        local is_trusted=false
        for path in "${TRUSTED_PATHS[@]}"; do
            if [[ "$binary" == "$path"* ]]; then
                is_trusted=true
                break
            fi
        done
        
        if [[ "$is_trusted" == "false" ]]; then
            alert "NAMESPACE SQUATTING: $label → $binary (non-system path)"
            ((++TOTAL_ALERTS))
            return 1
        fi
    fi
    return 0
}

check_binary_signature() {
    local binary="$1"
    local label="$2"
    
    if [[ -z "$binary" || "$binary" == "N/A" || ! -f "$binary" ]]; then
        return 0
    fi
    
    # Check if it's a script (Apple doesn't sign scripts)
    local file_type
    file_type=$(file "$binary" 2>/dev/null)
    if [[ "$file_type" == *"script"* ]] || [[ "$file_type" == *"text executable"* ]]; then
        log "Skipping signature check for script: $binary"
        return 0
    fi
    
    # Check if unsigned
    if ! codesign -v "$binary" 2>/dev/null; then
        alert "UNSIGNED APPLE-CLAIMING BINARY: $label → $binary"
        ((++TOTAL_ALERTS))
        return 1
    fi
    
    # Check signature authority
    local sig_info
    sig_info=$(codesign -dv --verbose=4 "$binary" 2>&1 || true)
    local authority
    authority=$(echo "$sig_info" | grep "Authority=" | head -1 | cut -d= -f2)
    
    if [[ "$label" == com.apple.* ]]; then
        if ! echo "$authority" | grep -qiE "Apple|Software Signing"; then
            alert "NON-APPLE SIGNATURE ON APPLE NAMESPACE: $label → $binary (Signer: $authority)"
            ((++TOTAL_ALERTS))
            return 1
        fi
    fi
    return 0
}

check_symlink_binary() {
    local binary="$1"
    local label="$2"
    
    if [[ -z "$binary" || "$binary" == "N/A" || ! -e "$binary" ]]; then
        return 0
    fi
    
    if [[ -L "$binary" ]]; then
        local target
        target=$(readlink "$binary")
        warn "SYMLINKED BINARY: $label → $binary -> $target"
        ((++TOTAL_ALERTS))
    fi
}

check_additional_keys() {
    local plist="$1"
    local label="$2"
    
    # Check MachServices (XPC service exposure)
    local mach_services
    mach_services=$(/usr/libexec/PlistBuddy -c "Print :MachServices" "$plist" 2>/dev/null || echo "")
    if [[ -n "$mach_services" && "$mach_services" != *"does not exist"* ]]; then
        log "MachServices found in $label"
    fi
    
    # Check KeepAlive (persistent restart)
    local keep_alive
    keep_alive=$(/usr/libexec/PlistBuddy -c "Print :KeepAlive" "$plist" 2>/dev/null || echo "")
    if [[ "$keep_alive" == "true" ]]; then
        warn "KeepAlive=true in $label (persistence mechanism)"
    fi
    
    # Check Sockets (network listening)
    local sockets
    sockets=$(/usr/libexec/PlistBuddy -c "Print :Sockets" "$plist" 2>/dev/null || echo "")
    if [[ -n "$sockets" && "$sockets" != *"does not exist"* ]]; then
        log "Network sockets defined in $label"
    fi
}

for dir in "${SCAN_DIRS[@]}"; do
    [[ ! -d "$dir" ]] && continue
    log "Scanning: $dir"
    
    for plist in "$dir"/*.plist; do
        [[ ! -f "$plist" ]] && continue
        ((++TOTAL_SCANNED))

        label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null || grep -A1 "<key>Label</key>" "$plist" | grep "<string>" | sed -E 's/.*<string>(.*)<\/string>.*/\1/')

        [[ -z "$label" ]] && continue

        # Try Program first (full path), fall back to ProgramArguments:0 (binary name only)
        binary=$(/usr/libexec/PlistBuddy -c "Print :Program" "$plist" 2>/dev/null || /usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null || echo "N/A")
        
        # Pattern-based detection
        for pat in "${SUSPICIOUS_PATTERNS[@]}"; do
            if [[ "$label" == *"$pat"* ]]; then
                alert "SUSPICIOUS LABEL PATTERN: $label ($plist)"
                ((++TOTAL_ALERTS))
            fi
        done
        
        # Behavioral detection
        check_namespace_squatting "$label" "$binary" || true
        check_binary_signature "$binary" "$label" || true
        check_symlink_binary "$binary" "$label" || true
        check_additional_keys "$plist" "$label" || true
    done
done

echo -e "${BOLD}=== Scan Summary ===${NC}"
ok "Total plists scanned: $TOTAL_SCANNED"
if [[ $TOTAL_ALERTS -gt 0 ]]; then
    alert "Total alerts: $TOTAL_ALERTS"
    alert "REVIEW ALL ALERTS ABOVE"
else
    ok "No suspicious persistence detected"
fi

