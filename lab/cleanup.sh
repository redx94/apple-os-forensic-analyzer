#!/usr/bin/env bash
set -euo pipefail

# Safety Interlock: Check for .lab_enabled file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LAB_ENABLED_FILE="$PROJECT_ROOT/.lab_enabled"

if [[ ! -f "$LAB_ENABLED_FILE" ]]; then
    echo -e "\033[0;31m[ERROR] Safety interlock engaged: .lab_enabled file not found\033[0m"
    echo "Lab scripts can only run in isolated testing environments."
    echo "To enable lab mode, create the file: $LAB_ENABLED_FILE"
    echo "This file must be present in the project root directory."
    exit 1
fi

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
