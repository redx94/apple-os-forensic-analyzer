#!/usr/bin/env bash
set -euo pipefail
LABEL="com.apple.system.updatehelper"
DEST_PLIST="/Library/LaunchDaemons/${LABEL}.plist"
DEST_HELPER="/usr/local/bin/update_helper"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
log "Starting cleanup..."
sudo launchctl bootout "system/${LABEL}" 2>/dev/null || sudo launchctl unload "$DEST_PLIST" 2>/dev/null || warn "Agent not loaded."
[[ -f "$DEST_PLIST"   ]] && sudo rm -f "$DEST_PLIST"   && ok "Removed: $DEST_PLIST"   || warn "Not found: $DEST_PLIST"
[[ -f "$DEST_HELPER"  ]] && sudo rm -f "$DEST_HELPER"  && ok "Removed: $DEST_HELPER"  || warn "Not found: $DEST_HELPER"
for f in "/tmp/${LABEL}.out" "/tmp/${LABEL}.err" "/tmp/spoofed_log_demo.txt" "./${LABEL}.plist" "./malicious_helper.sh"; do
    [[ -f "$f" ]] && rm -f "$f" && ok "Removed: $f" || true
done
ok "Cleanup complete."
