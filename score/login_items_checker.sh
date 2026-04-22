#!/usr/bin/env bash
# ============================================================
# login_items_checker.sh - Login Items & Background Task Auditor
# ============================================================
# Apple OS Forensic Analyzer
#
# Purpose:
# Scans for login items and background task management entries.
# These are common persistence vectors on macOS.
# Supports macOS 13+ with sfltool dumpbtm for modern background tasks.
#
# Usage:
#   ./login_items_checker.sh
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

OUTPUT_DIR="./login_items_output"
TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
mkdir -p "$OUTPUT_DIR"

OUTPUT_FILE="${OUTPUT_DIR}/login_items_${TIMESTAMP}.txt"

echo -e "${BOLD}=== Apple OS Forensic Login Items Auditor ===${NC}"
echo "# Login Items Audit - $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$OUTPUT_FILE"

# Check macOS version
OS_VERSION=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
OS_MAJOR=$(echo "$OS_VERSION" | cut -d. -f1)
log "macOS version: $OS_VERSION"

# 1. Traditional Login Items (LaunchServices)
log "Checking traditional login items..."
echo "=== Traditional Login Items ===" >> "$OUTPUT_FILE"

# Use osascript to query login items
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null | tr ',' '\n' | sed 's/^ *//;s/ *$//' | while read -r item; do
    [[ -z "$item" ]] && continue
    echo "  $item" >> "$OUTPUT_FILE"
    
    # Flag suspicious items
    if [[ "$item" =~ update|helper|daemon|agent ]]; then
        warn "Suspicious login item pattern: $item"
    fi
done

# 2. Background Task Management (macOS 13+)
if [[ "$OS_MAJOR" -ge 13 ]]; then
    log "Checking Background Task Management (macOS 13+)..."
    echo "" >> "$OUTPUT_FILE"
    echo "=== Background Task Management ===" >> "$OUTPUT_FILE"
    
    if command -v sfltool &>/dev/null; then
        sfltool dumpbtm 2>/dev/null >> "$OUTPUT_FILE" || warn "sfltool dumpbtm failed (may require Full Disk Access)"
        
        # Parse for com.apple.* entries
        sfltool dumpbtm 2>/dev/null | grep -A5 -B5 "com\.apple\." | tee -a "$OUTPUT_FILE" || true
    else
        warn "sfltool not available on this macOS version"
    fi
fi

# 3. LaunchAgents in user directory
log "Checking user LaunchAgents..."
echo "" >> "$OUTPUT_FILE"
echo "=== User LaunchAgents ===" >> "$OUTPUT_FILE"

if [[ -d "$HOME/Library/LaunchAgents" ]]; then
    for plist in "$HOME/Library/LaunchAgents"/*.plist; do
        [[ ! -f "$plist" ]] && continue
        label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null || echo "Unknown")
        echo "  $label ($plist)" >> "$OUTPUT_FILE"
        
        # Flag Apple namespace in user directory
        if [[ "$label" == com.apple.* ]]; then
            alert "Apple namespace in user LaunchAgent: $label"
        fi
    done
else
    echo "  No user LaunchAgents found" >> "$OUTPUT_FILE"
fi

# 4. Profile-based login items (MDM)
log "Checking for profile-based login items..."
echo "" >> "$OUTPUT_FILE"
echo "=== Configuration Profiles ===" >> "$OUTPUT_FILE"

if command -v profiles &>/dev/null; then
    profiles -P 2>/dev/null >> "$OUTPUT_FILE" || warn "profiles command failed"
else
    warn "profiles command not available"
fi

# 5. Check for suspicious locations
log "Checking for persistence in suspicious locations..."
echo "" >> "$OUTPUT_FILE"
echo "=== Suspicious Persistence Locations ===" >> "$OUTPUT_FILE"

SUSPICIOUS_LOCS=("/usr/local/bin" "/usr/local/sbin" "/opt/local/bin" "/opt/homebrew/bin")
for loc in "${SUSPICIOUS_LOCS[@]}"; do
    if [[ -d "$loc" ]]; then
        for item in "$loc"/*; do
            [[ ! -e "$item" ]] && continue
            echo "  $item" >> "$OUTPUT_FILE"
        done
    fi
done

# Summary
echo "" >> "$OUTPUT_FILE"
echo "# Audit completed at $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUTPUT_FILE"

ok "Login items audit complete"
log "Results: $OUTPUT_FILE"
