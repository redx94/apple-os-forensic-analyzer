#!/usr/bin/env bash
# ============================================================
# tcc_scanner.sh - TCC (Transparency, Consent, Control) Privacy Scanner
# ============================================================
# Apple OS Forensic Analyzer
#
# Purpose:
# Queries the TCC database to identify apps with privacy permissions
# (camera, microphone, location, etc.). Unusual permission grants
# can indicate malicious activity or data exfiltration.
#
# Usage:
#   ./tcc_scanner.sh [--json]
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

OUTPUT_DIR="./tcc_scan_output"
TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
mkdir -p "$OUTPUT_DIR"

TCC_DB="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
TCC_DB_ALT="/Library/Application Support/com.apple.TCC/TCC.db"

echo -e "${BOLD}=== Apple OS Forensic TCC Privacy Scanner ===${NC}"

# Check for TCC database
if [[ -f "$TCC_DB" ]]; then
    TCC_PATH="$TCC_DB"
    log "Found user TCC database: $TCC_PATH"
elif [[ -f "$TCC_DB_ALT" ]]; then
    TCC_PATH="$TCC_DB_ALT"
    log "Found system TCC database: $TCC_PATH"
else
    warn "TCC database not found. Try running with Full Disk Access."
    exit 1
fi

OUTPUT_FILE="${OUTPUT_DIR}/tcc_permissions_${TIMESTAMP}.txt"

# Common services to check
SERVICES=("kTCCServiceCamera" "kTCCServiceMicrophone" "kTCCServiceLocation" 
          "kTCCServiceAddressBook" "kTCCServicePhotos" "kTCCServiceReminders"
          "kTCCServiceCalendar" "kTCCServicePostEvent" "kTCCServiceAppleEvents")

log "Scanning TCC permissions..."

if [[ "${1:-}" == "--json" ]]; then
    # JSON output
    echo "["
    first=true
    for service in "${SERVICES[@]}"; do
        if ! $first; then echo ","; fi
        first=false
        sqlite3 "$TCC_PATH" "SELECT client, service, allowed, last_modified FROM access WHERE service = '$service';" 2>/dev/null | while IFS='|' read -r client svc allowed last_modified; do
            echo "  {\"service\": \"$svc\", \"client\": \"$client\", \"allowed\": \"$allowed\", \"last_modified\": \"$last_modified\"}"
        done
    done
    echo "]"
else
    # Human-readable output
    echo "# TCC Permission Scan - $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    for service in "${SERVICES[@]}"; do
        echo "=== $service ===" >> "$OUTPUT_FILE"
        sqlite3 "$TCC_PATH" "SELECT client, allowed, last_modified FROM access WHERE service = '$service';" 2>/dev/null | while IFS='|' read -r client allowed last_modified; do
            if [[ "$allowed" == "1" ]]; then
                echo "  [GRANTED] $client (last modified: $last_modified)" | tee -a "$OUTPUT_FILE"
            else
                echo "  [DENIED]  $client (last modified: $last_modified)" | tee -a "$OUTPUT_FILE"
            fi
        done
        echo "" >> "$OUTPUT_FILE"
    done
    
    # Check for unusual clients (non-Apple apps with broad permissions)
    log "Checking for unusual permission grants..."
    sqlite3 "$TCC_PATH" "SELECT client, service FROM access WHERE allowed = 1 AND client NOT LIKE 'com.apple.%';" 2>/dev/null | while IFS='|' read -r client service; do
        warn "Non-Apple app with permission: $client -> $service"
    done
    
    ok "TCC scan complete. Results: $OUTPUT_FILE"
fi
