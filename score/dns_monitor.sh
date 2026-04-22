#!/usr/bin/env bash
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
OUT_DIR="./dns_monitor_output"; TIMESTAMP=$(date "+%Y%m%d_%H%M%S"); BASELINE="${OUT_DIR}/dns_baseline.txt"
mkdir -p "$OUT_DIR"
log()   { echo -e "${CYAN}[*]${NC} $*"; }; ok() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }; alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }
DOMAINS=("apple.com" "icloud.com" "mzstatic.com" "guzzoni.apple.com" "swscan.apple.com")

resolve() { dig +short "$1" A 2>/dev/null | head -1 || echo "UNRESOLVED"; }
reverse() { dig +short -x "$1" 2>/dev/null | sed 's/\.$//' || echo "NO_PTR"; }

audit() {
    log "Reverse-DNS audit for Apple domains..."; local bad=0
    for d in "${DOMAINS[@]}"; do
        local ip; ip=$(resolve "$d")
        [[ "$ip" == "UNRESOLVED" ]] && warn "$d → UNRESOLVED" && continue
        local ptr; ptr=$(reverse "$ip")
        echo "$ptr" | grep -qiE "apple\.com|icloud\.com|courier\.push\.apple\.com" \
            && ok "$d → $ip → $ptr" \
            || { alert "PTR MISMATCH: $d → $ip → $ptr"; ((bad++)); }
        echo "$d | $ip | $ptr" >> "${OUT_DIR}/audit_${TIMESTAMP}.txt"; sleep 0.3
    done
    [[ $bad -eq 0 ]] && ok "No PTR anomalies." || alert "$bad suspicious PTR record(s)!"
}

baseline() {
    local cur="${OUT_DIR}/current_${TIMESTAMP}.txt"
    for d in "${DOMAINS[@]}"; do echo "${d}=$(resolve "$d")" >> "$cur"; done
    [[ ! -f "$BASELINE" ]] && { cp "$cur" "$BASELINE"; ok "Baseline created: $BASELINE"; return; }
    local changed=false
    while IFS='=' read -r d bip; do
        local cip; cip=$(grep "^${d}=" "$cur" | cut -d= -f2 || echo "MISSING")
        [[ "$bip" != "$cip" ]] && { alert "DNS CHANGE: $d  was=$bip  now=$cip"; changed=true; }
    done < "$BASELINE"
    $changed || ok "DNS baseline unchanged."
    cp "$cur" "$BASELINE"
}

dnssec_check() {
    log "DNSSEC check..."
    for d in "${DOMAINS[@]}"; do
        local r; r=$(dig +dnssec "$d" 2>/dev/null || echo "FAILED")
        echo "$r" | grep -q "ad;" && ok "$d — DNSSEC validated" \
            || echo "$r" | grep -q "RRSIG" && warn "$d — RRSIG present, AD not set" \
            || warn "$d — No DNSSEC"
    done
}

echo -e "${BOLD}=== Apple OS Forensic DNS Monitor ===${NC}"
MODE="${1:---check}"
case "$MODE" in
    --check)  audit; baseline ;;
    --watch)  while true; do echo -e "${BOLD}--- $(date) ---${NC}"; baseline; sleep 60; done ;;
    --dnssec) dnssec_check ;;
    *)        audit; baseline ;;
esac
