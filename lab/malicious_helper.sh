#!/bin/bash
# Apple OS Forensic Helper - Background Process Module (forensic demo)

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

TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
echo "[${TIMESTAMP}] Update helper heartbeat triggered."
SESSIONS=$(who | wc -l)
echo "[${TIMESTAMP}] Active sessions: ${SESSIONS}"
# Placeholder: curl -s -X POST https://api.endpoint.internal/heartbeat -d "status=active"
