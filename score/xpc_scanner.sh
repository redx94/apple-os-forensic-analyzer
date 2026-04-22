#!/usr/bin/env bash
set -u
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
OUT_DIR="./xpc_scan_output"; TIMESTAMP=$(date "+%Y%m%d_%H%M%S"); REPORT="${OUT_DIR}/xpc_${TIMESTAMP}.txt"
mkdir -p "$OUT_DIR"
log()   { echo -e "${CYAN}[*]${NC} $*" | tee -a "$REPORT"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*" | tee -a "$REPORT"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$REPORT"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*" | tee -a "$REPORT"; }
TARGETS=("com.apple.security.authd" "com.apple.SecurityServer" "com.apple.trustd"
         "com.apple.MobileFileIntegrity" "com.apple.tccd" "com.apple.lsd"
         "com.apple.sharingd" "com.apple.coreservices.launchservicesd")

check_dupes() {
    log "Checking for duplicate label registrations..."
    local d; d=$(launchctl list 2>/dev/null | awk 'NR>1{print $3}' | sort | uniq -d)
    [[ -z "$d" ]] && ok "No duplicate labels." || { alert "Duplicates found!"; echo "$d" | while read -r l; do alert "  DUPE: $l"; done; }
}

check_targets() {
    log "Checking high-value XPC target registration..."
    for t in "${TARGETS[@]}"; do
        local s; s=$(launchctl list "$t" 2>/dev/null || echo "NOT_REGISTERED")
        if [[ "$s" == "NOT_REGISTERED" ]]; then
            warn "$t → UNREGISTERED (squattable)"
        else
            local pid; pid=$(echo "$s" | grep -o '"PID" = [0-9]*' | awk '{print $3}' || echo "")
            [[ -n "$pid" ]] && ok "$t (PID: $pid)" || warn "$t → stopped (transient squat window)"
        fi
    done
}

scan_bundles() {
    log "Scanning XPC bundles for non-Apple signatures..."
    local found=false
    while IFS= read -r -d '' b; do
        local bid; bid=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "${b}/Contents/Info.plist" 2>/dev/null || echo "")
        [[ "$bid" != com.apple.* ]] && continue
        local sig; sig=$(codesign -dv "$b" 2>&1 | grep "Authority=" | head -1 || echo "UNSIGNED")
        echo "$sig" | grep -qi "Apple" && ok "$bid — Apple signed" || { alert "NON-APPLE XPC: $b | $bid | $sig"; found=true; }
    done < <(find /System/Library/XPCServices /Library/Application\ Support /Applications -name "*.xpc" -print0 2>/dev/null)
    $found || ok "No suspicious XPC bundles found."
}

echo -e "${BOLD}=== Apple OS Forensic XPC Scanner ===${NC}" | tee "$REPORT"
MODE="${1:---scan}"
case "$MODE" in
    --list)   launchctl list 2>/dev/null | awk 'NR>1{print $3}' | sort | tee -a "$REPORT" ;;
    --verify) [[ -z "${2:-}" ]] && echo "Usage: $0 --verify <name>" && exit 1
              r=$(launchctl list "$2" 2>/dev/null || echo "NOT_REGISTERED")
              [[ "$r" == "NOT_REGISTERED" ]] && warn "$2 → NOT registered (squattable)" || { ok "$2 registered"; echo "$r"; } ;;
    *)        check_dupes; check_targets; scan_bundles ;;
esac
ok "Report: $REPORT"
