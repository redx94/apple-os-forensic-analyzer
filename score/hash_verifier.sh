#!/usr/bin/env bash
# ============================================================
# hash_verifier.sh - Hash-Based Binary Verification
# ============================================================
# Apple OS Forensic Analyzer
#
# Purpose:
# Compares SHA-256 hashes of com.apple.* binaries against
# known-good Apple hashes to detect tampering or replacement.
# Based on mindmap: "Code Signing and Integrity Verification"
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

HASH_DB="./score/known_good_hashes.db"
OUTPUT_DIR="./hash_verification_output"
TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
mkdir -p "$OUTPUT_DIR"

echo -e "${BOLD}=== Apple OS Forensic Hash Verifier ===${NC}"
log "Comparing binary hashes against known-good values..."

TOTAL_CHECKED=0
TOTAL_ALERTS=0
MISMATCHES=0

# Create hash database if it doesn't exist
if [[ ! -f "$HASH_DB" ]]; then
    warn "Hash database not found at $HASH_DB"
    warn "Run with --generate-db to create baseline from clean system"
    warn "Continuing with basic integrity checks..."
fi

# Function to check hash against database
check_hash() {
    local binary="$1"
    local label="$2"
    
    if [[ ! -f "$binary" ]]; then
        return 0
    fi
    
    local current_hash
    current_hash=$(shasum -a 256 "$binary" 2>/dev/null | cut -d' ' -f1)
    
    if [[ -z "$current_hash" ]]; then
        return 0
    fi
    
    log "Checking: $label ($binary)"
    log "SHA-256: $current_hash"
    
    # If hash database exists, check against it
    if [[ -f "$HASH_DB" ]]; then
        local expected_hash
        expected_hash=$(grep "^$binary:" "$HASH_DB" 2>/dev/null | cut -d: -f2)
        
        if [[ -n "$expected_hash" ]]; then
            if [[ "$current_hash" != "$expected_hash" ]]; then
                alert "HASH MISMATCH: $label ($binary)"
                alert "Expected: $expected_hash"
                alert "Current:  $current_hash"
                ((++TOTAL_ALERTS))
                ((++MISMATCHES))
            else
                ok "Hash verified: $label"
            fi
        else
            warn "No baseline hash for $binary - add to database"
        fi
    fi
    
    ((TOTAL_CHECKED++))
}

# Generate hash database mode
if [[ "${1:-}" == "--generate-db" ]]; then
    log "Generating hash database from current system..."
    
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
            
            hash=$(shasum -a 256 "$binary" 2>/dev/null | cut -d' ' -f1)
            [[ -n "$hash" ]] && echo "$binary:$hash" >> "$HASH_DB"
        done
    done
    
    ok "Hash database generated: $HASH_DB"
    exit 0
fi

# Normal verification mode
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
        
        check_hash "$binary" "$label"
    done
done

# Generate report
REPORT="${OUTPUT_DIR}/hash_verification_${TIMESTAMP}.txt"
{
    echo "=== Hash Verification Report ==="
    echo "Timestamp: $(date -u)"
    echo "Total binaries checked: $TOTAL_CHECKED"
    echo "Hash mismatches: $MISMATCHES"
    echo "Total alerts: $TOTAL_ALERTS"
    echo ""
    echo "Note: To create a baseline hash database, run:"
    echo "  ./score/hash_verifier.sh --generate-db"
} > "$REPORT"

echo -e "${BOLD}=== Analysis Complete ===${NC}"
ok "Total binaries checked: $TOTAL_CHECKED"
ok "Hash mismatches: $MISMATCHES"
ok "Report saved: $REPORT"

if [[ $TOTAL_ALERTS -gt 0 ]]; then
    alert "Total alerts: $TOTAL_ALERTS"
    alert "REVIEW ALL ALERTS ABOVE - Potential binary tampering detected"
else
    ok "No hash mismatches detected"
fi
