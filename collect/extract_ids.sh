#!/usr/bin/env bash
set -euo pipefail
OUTPUT_DIR="./extract_ids_output"; TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
OUTFILE="${OUTPUT_DIR}/apple_ids_${TIMESTAMP}.txt"
BASELINE_FILE="${OUTPUT_DIR}/baseline.txt"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
mkdir -p "$OUTPUT_DIR"
log()  { echo -e "${CYAN}[*]${NC} $*"; }; ok() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }; err() { echo -e "${RED}[X]${NC} $*"; }

scan_live() {
    log "Scanning live launchctl services..."
    local r; r=$(launchctl list 2>/dev/null | awk '{print $3}' | grep -Eo 'com\.apple\.[A-Za-z0-9._-]+' | sort -u)
    [[ -z "$r" ]] && warn "No com.apple.* in launchctl." && return
    echo "# --- Live (${TIMESTAMP}) ---" >> "$OUTFILE"; echo "$r" >> "$OUTFILE"; echo "" >> "$OUTFILE"
    ok "$(echo "$r"|wc -l|tr -d ' ') live labels found."; echo "$r"
}

scan_plists() {
    local DIRS=("/Library/LaunchDaemons" "/Library/LaunchAgents" "${HOME}/Library/LaunchAgents" "/System/Library/LaunchDaemons" "/System/Library/LaunchAgents")
    log "Scanning plist directories..."; echo "# --- Plists (${TIMESTAMP}) ---" >> "$OUTFILE"
    for dir in "${DIRS[@]}"; do
        [[ -d "$dir" ]] || continue; log "  -> $dir"
        for plist in "$dir"/*.plist; do
            [[ -f "$plist" ]] || continue
            label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null || true)
            if [[ "$label" == com.apple.* ]]; then
                prog=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null || echo "N/A")
                echo "LABEL=${label} BINARY=${prog} FILE=${plist}" | tee -a "$OUTFILE"
            fi
        done
    done; echo "" >> "$OUTFILE"; ok "Plist scan complete."
}

tag_nodes() {
    [[ ! -f "$OUTFILE" ]] && warn "No IDs file, skip tagging." && return
    local out="${OUTPUT_DIR}/tagged_nodes_${TIMESTAMP}.json"
    python3 -c "
import re,json
ids=[]
with open('$OUTFILE') as f:
    for line in f:
        line=line.strip()
        if line.startswith('#') or not line: continue
        ids.extend(re.findall(r'com\.apple\.[A-Za-z0-9._-]+',line))
u=sorted(set(ids))
nodes=[{'node_id':f'node_{i:04d}','title':s,'tags':[s],'extracted_at':'$TIMESTAMP'} for i,s in enumerate(u)]
json.dump({'nodes':nodes,'total':len(nodes)},open('$out','w'),indent=2)
print(f'[+] Tagged {len(nodes)} nodes -> $out')
"
}

save_baseline() {
    log "Saving baseline to: $BASELINE_FILE"
    scan_live > /dev/null
    scan_plists > /dev/null
    cp "$OUTFILE" "$BASELINE_FILE"
    ok "Baseline saved. Use --diff to compare against this baseline."
}

diff_baseline() {
    [[ ! -f "$BASELINE_FILE" ]] && err "No baseline found. Run --baseline first." && exit 1
    
    log "Comparing current state against baseline..."
    local current_file="${OUTPUT_DIR}/current_${TIMESTAMP}.txt"
    scan_live > /dev/null
    scan_plists > /dev/null
    cp "$OUTFILE" "$current_file"
    
    # Extract identifiers for comparison
    local baseline_ids
    local current_ids
    baseline_ids=$(grep -E '^com\.apple\.|^LABEL=com\.apple\.' "$BASELINE_FILE" | sort -u || true)
    current_ids=$(grep -E '^com\.apple\.|^LABEL=com\.apple\.' "$current_file" | sort -u || true)
    
    # Find new identifiers
    local new_ids
    new_ids=$(comm -13 <(echo "$baseline_ids") <(echo "$current_ids") || true)
    
    # Find removed identifiers
    local removed_ids
    removed_ids=$(comm -23 <(echo "$baseline_ids") <(echo "$current_ids") || true)
    
    echo -e "${BOLD}=== Differential Analysis ===${NC}"
    
    if [[ -n "$new_ids" ]]; then
        echo -e "${GREEN}[+] NEW identifiers since baseline:${NC}"
        echo "$new_ids" | while read -r id; do
            echo "  + $id"
        done
    else
        ok "No new identifiers detected."
    fi
    
    if [[ -n "$removed_ids" ]]; then
        echo -e "${RED}[-] REMOVED identifiers since baseline:${NC}"
        echo "$removed_ids" | while read -r id; do
            echo "  - $id"
        done
    else
        ok "No identifiers removed."
    fi
    
    ok "Current state saved to: $current_file"
}

MODE="${1:---all}"
case "$MODE" in
    --baseline) save_baseline ;;
    --diff)     diff_baseline ;;
    --live)     scan_live ;;
    --plists)   scan_plists ;;
    --all)      scan_live; scan_plists; tag_nodes ;;
    *)          [[ -d "$MODE" ]] && { while IFS= read -r -d '' f; do grep -Eo 'com\.apple\.[A-Za-z0-9._-]+' "$f" 2>/dev/null; done < <(find "$MODE" -type f -print0) | sort -u | tee -a "$OUTFILE"; } || { grep -Eo 'com\.apple\.[A-Za-z0-9._-]+' "$MODE" 2>/dev/null | sort -u | tee -a "$OUTFILE"; }; tag_nodes ;;
esac
ok "Output: ${OUTPUT_DIR}/"; ok "IDs: ${OUTFILE}"
