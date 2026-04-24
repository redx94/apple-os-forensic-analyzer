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
PLIST_PATH="./${LABEL}.plist"
HELPER_PATH="./malicious_helper.sh"
LOG_OUT="/tmp/${LABEL}.out"
LOG_ERR="/tmp/${LABEL}.err"
echo "[-] Generating forensic study suite: ${LABEL}"
cat > "${PLIST_PATH}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array><string>/usr/local/bin/update_helper</string></array>
    <key>RunAtLoad</key><true/>
    <key>StartInterval</key><integer>3600</integer>
    <key>StandardOutPath</key><string>${LOG_OUT}</string>
    <key>StandardErrorPath</key><string>${LOG_ERR}</string>
</dict>
</plist>
PLIST
echo "[+] Plist written to ${PLIST_PATH}"
cat > "${HELPER_PATH}" << 'HELPER'
#!/bin/bash
# Apple OS Forensic Helper - Background Process Module (forensic demo)
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
echo "[${TIMESTAMP}] Update helper heartbeat triggered."
SESSIONS=$(who | wc -l)
echo "[${TIMESTAMP}] Active sessions: ${SESSIONS}"
# Placeholder: curl -s -X POST https://api.endpoint.internal/heartbeat -d "status=active"
HELPER
chmod +x "${HELPER_PATH}"
echo "[+] Helper created: ${HELPER_PATH}"
echo "[!] Run install_agent.sh (sudo) to deploy."
