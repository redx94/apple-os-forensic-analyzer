#!/usr/bin/env bash
# ============================================================
# browser_extension_auditor.sh - Browser Extension Persistence Scanner
# ============================================================
# Apple OS Forensic Analyzer
#
# Purpose:
# Scans browser extensions for suspicious persistence vectors.
# Extensions are common attack vectors for data exfiltration
# and long-term surveillance.
#
# Usage:
#   ./browser_extension_auditor.sh [--json]
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

OUTPUT_DIR="./browser_audit_output"
TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
mkdir -p "$OUTPUT_DIR"

echo -e "${BOLD}=== Apple OS Forensic Browser Extension Auditor ===${NC}"

OUTPUT_FILE="${OUTPUT_DIR}/extensions_${TIMESTAMP}.txt"
echo "# Browser Extension Audit - $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$OUTPUT_FILE"

# Chrome extensions
if [[ -d "$HOME/Library/Application Support/Google/Chrome/Default/Extensions" ]]; then
    log "Scanning Chrome extensions..."
    echo "=== Chrome Extensions ===" >> "$OUTPUT_FILE"
    
    for ext_dir in "$HOME/Library/Application Support/Google/Chrome/Default/Extensions"/*; do
        [[ ! -d "$ext_dir" ]] && continue
        ext_id=$(basename "$ext_dir")
        
        for version_dir in "$ext_dir"/*; do
            [[ ! -d "$version_dir" ]] && continue
            manifest="$version_dir/manifest.json"
            
            if [[ -f "$manifest" ]]; then
                ext_name=$(python3 -c "import json; print(json.load(open('$manifest')).get('name', 'Unknown'))" 2>/dev/null || echo "Unknown")
                permissions=$(python3 -c "import json; print(','.join(json.load(open('$manifest')).get('permissions', [])))" 2>/dev/null || echo "None")
                
                echo "  ID: $ext_id" >> "$OUTPUT_FILE"
                echo "  Name: $ext_name" >> "$OUTPUT_FILE"
                echo "  Permissions: $permissions" >> "$OUTPUT_FILE"
                echo "" >> "$OUTPUT_FILE"
                
                # Flag suspicious permissions
                if echo "$permissions" | grep -qiE "tabs|history|cookies|webRequest|proxy|background"; then
                    warn "Chrome extension with broad permissions: $ext_name ($ext_id)"
                fi
            fi
        done
    done
    ok "Chrome scan complete"
else
    warn "Chrome not found or no extensions installed"
fi

# Safari extensions
if [[ -f "$HOME/Library/Containers/com.apple.Safari/Data/Library/Safari/Extensions/Extensions.plist" ]]; then
    log "Scanning Safari extensions..."
    echo "=== Safari Extensions ===" >> "$OUTPUT_FILE"
    
    plutil -p "$HOME/Library/Containers/com.apple.Safari/Data/Library/Safari/Extensions/Extensions.plist" >> "$OUTPUT_FILE" 2>/dev/null
    ok "Safari scan complete"
else
    warn "Safari extensions not found"
fi

# Firefox extensions
if [[ -d "$HOME/Library/Application Support/Firefox/Profiles" ]]; then
    log "Scanning Firefox extensions..."
    echo "=== Firefox Extensions ===" >> "$OUTPUT_FILE"
    
    for profile_dir in "$HOME/Library/Application Support/Firefox/Profiles"/*; do
        [[ ! -d "$profile_dir" ]] && continue
        extensions_json="$profile_dir/extensions.json"
        
        if [[ -f "$extensions_json" ]]; then
            python3 -c "
import json
with open('$extensions_json') as f:
    data = json.load(f)
    for addon_id, addon in data.get('addons', {}).items():
        if addon.get('active', False):
            print(f'  {addon.get(\"name\", \"Unknown\")} ({addon_id})')
            print(f'    Version: {addon.get(\"version\", \"Unknown\")}')
            print(f'    Permissions: {addon.get(\"permissions\", [])}')
            print()
" >> "$OUTPUT_FILE" 2>/dev/null
        fi
    done
    ok "Firefox scan complete"
else
    warn "Firefox not found or no extensions installed"
fi

# Summary
echo "" >> "$OUTPUT_FILE"
echo "# Scan completed at $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUTPUT_FILE"

ok "Browser extension audit complete"
log "Results: $OUTPUT_FILE"
