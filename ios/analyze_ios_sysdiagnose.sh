#!/usr/bin/env bash
# ============================================================
# analyze_ios_sysdiagnose.sh - Enhanced iOS Offline Forensic Parser
# ============================================================
# Apple OS Forensic Analyzer
#
# Purpose:
# Enhanced offline parser for iOS sysdiagnose dumps and unencrypted backups.
# Scans for code injection, unusual daemons, masquerading identifiers,
# installation anomalies, and suspicious crash patterns.
#
# Usage:
#   ./analyze_ios_sysdiagnose.sh /path/to/sysdiagnose.tar.gz
#   ./analyze_ios_sysdiagnose.sh /path/to/extracted/iOS/backup/
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

if [[ -z "${1:-}" ]]; then
    echo -e "${RED}[!] Usage: $0 <path_to_sysdiagnose_or_backup>${NC}"
    exit 1
fi

TARGET="$1"
if [[ ! -e "$TARGET" ]]; then
    echo -e "${RED}[!] Error: Path not found: $TARGET${NC}"
    exit 1
fi

OUTPUT_DIR="./ios_forensic_output"
TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
mkdir -p "$OUTPUT_DIR"

echo -e "${BOLD}=== Apple OS Forensic iOS Analyzer ===${NC}"
log "Target: $TARGET"
log "Output: $OUTPUT_DIR"

# Check if it's a sysdiagnose archive
if [[ "$TARGET" == *.tar.gz || "$TARGET" == *.zip ]]; then
    log "Extracting sysdiagnose archive..."
    EXTRACT_DIR="/tmp/ios_forensic_${TIMESTAMP}"
    mkdir -p "$EXTRACT_DIR"
    if [[ "$TARGET" == *.tar.gz ]]; then
        tar -xzf "$TARGET" -C "$EXTRACT_DIR" 2>/dev/null || true
    else
        unzip -q "$TARGET" -d "$EXTRACT_DIR" 2>/dev/null || true
    fi
    TARGET="$EXTRACT_DIR"
    ok "Extracted to: $TARGET"
fi

# Extract unified logs from sysdiagnose
log "Extracting unified logs..."
UNIFIED_LOGS="${OUTPUT_DIR}/unified_logs_${TIMESTAMP}.txt"
find "$TARGET" -name "*.logarchive" -print0 2>/dev/null | while IFS= read -r -d '' archive; do
    log show --archive "$archive" --info 2>/dev/null >> "$UNIFIED_LOGS" || true
done
[[ -f "$UNIFIED_LOGS" && -s "$UNIFIED_LOGS" ]] && ok "Unified logs extracted" || warn "No unified logs found"

# Parse installation database (mobile_installation.log)
log "Parsing installation database..."
INSTALL_LOG="${OUTPUT_DIR}/installation_lifecycle_${TIMESTAMP}.txt"
find "$TARGET" -name "mobile_installation.log" -print0 2>/dev/null | while IFS= read -r -d '' file; do
    grep -E "(Install|Update|Remove)" "$file" >> "$INSTALL_LOG" 2>/dev/null || true
done
[[ -f "$INSTALL_LOG" && -s "$INSTALL_LOG" ]] && ok "Installation lifecycle extracted" || warn "No installation log found"

# Check crash logs for code injection
log "Analyzing crash logs for code injection..."
INJECTION_FILE="${OUTPUT_DIR}/suspicious_crashes_${TIMESTAMP}.txt"
INJECTION_FOUND=false

INJECTION_PATTERNS=(
    "DYLD_INSERT_LIBRARIES"
    "_objc_msgForward"
    "fishhook"
    "Substrate"
    "Cydia"
    "frida"
    "MSHook"
)

find "$TARGET" -name "*.ips" -print0 2>/dev/null | while IFS= read -r -d '' crash_file; do
    for pattern in "${INJECTION_PATTERNS[@]}"; do
        if grep -q "$pattern" "$crash_file" 2>/dev/null; then
            alert "Potential injection detected in: $crash_file"
            echo "=== $crash_file ===" >> "$INJECTION_FILE"
            grep -E "Binary Images|DYLD_INSERT|Process Name" "$crash_file" >> "$INJECTION_FILE" 2>/dev/null
            echo "" >> "$INJECTION_FILE"
            INJECTION_FOUND=true
            break
        fi
    done
done

if [[ "$INJECTION_FOUND" == "true" ]]; then
    alert "Code injection patterns found - see $INJECTION_FILE"
else
    ok "No code injection patterns detected in crash logs"
fi

# Check for unusual daemons
log "Scanning for unusual daemons..."
DAEMON_FILE="${OUTPUT_DIR}/unusual_daemons_${TIMESTAMP}.txt"
WHITELIST=("com.apple.SpringBoard" "com.apple.backboardd" "com.apple.mediaserverd" "com.apple.locationd")

if [[ -f "$TARGET/ps.txt" ]]; then
    grep -E "^com\.apple\." "$TARGET/ps.txt" 2>/dev/null | while read -r daemon; do
        is_known=false
        for known in "${WHITELIST[@]}"; do
            if [[ "$daemon" == *"$known"* ]]; then
                is_known=true
                break
            fi
        done
        if [[ "$is_known" == "false" ]]; then
            echo "$daemon" >> "$DAEMON_FILE"
        fi
    done
    
    if [[ -f "$DAEMON_FILE" && -s "$DAEMON_FILE" ]]; then
        warn "Unusual daemons detected:"
        cat "$DAEMON_FILE" | while read -r daemon; do
            echo "  ? $daemon"
        done
    else
        ok "No unusual daemons detected"
    fi
else
    warn "No ps.txt found in sysdiagnose"
fi

# Scan for suspicious plist patterns
log "Scanning plists for masquerading patterns..."
PLIST_ALERTS="${OUTPUT_DIR}/suspicious_plists_${TIMESTAMP}.txt"
SUSPICIOUS_PATTERNS=("com.apple.update" "com.apple.system.update" "com.apple.helper" "com.apple.analytics")

find "$TARGET" -name "*.plist" -print0 2>/dev/null | while IFS= read -r -d '' plist; do
    for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
        if grep -q "$pattern" "$plist" 2>/dev/null; then
            alert "Suspicious pattern in: $plist"
            echo "=== $plist ===" >> "$PLIST_ALERTS"
            plutil -p "$plist" 2>/dev/null >> "$PLIST_ALERTS" || grep -A2 -B2 "$pattern" "$plist" >> "$PLIST_ALERTS"
            echo "" >> "$PLIST_ALERTS"
            break
        fi
    done
done

if [[ -f "$PLIST_ALERTS" && -s "$PLIST_ALERTS" ]]; then
    alert "Suspicious plist patterns found - see $PLIST_ALERTS"
else
    ok "No suspicious plist patterns detected"
fi

# Summary
echo -e "${BOLD}=== Analysis Complete ===${NC}"
ok "Results saved to: $OUTPUT_DIR"
log "Review these files for detailed findings:"
ls -la "$OUTPUT_DIR"
