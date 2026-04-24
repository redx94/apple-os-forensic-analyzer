#!/usr/bin/env bash
# ============================================================
# collect_live_memory.sh - Live Memory Indicators Collector
# ============================================================
# Apple OS Forensic Analyzer
#
# Purpose:
# Captures vmmap and taskinfo output for processes running under
# the com.apple.* namespace to detect "Fileless" persistence where
# malicious threads are injected into legitimate Apple processes
# without corresponding on-disk plist modifications.
#
# v2.1 Enhancement:
# - Detects fileless persistence via memory analysis
# - Captures process memory maps for injection detection
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

OUTPUT_DIR="./live_memory_output"
TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
VMAP_OUTPUT="${OUTPUT_DIR}/vmmap_${TIMESTAMP}.txt"
TASKINFO_OUTPUT="${OUTPUT_DIR}/taskinfo_${TIMESTAMP}.txt"
INJECTION_OUTPUT="${OUTPUT_DIR}/injection_alerts_${TIMESTAMP}.txt"

mkdir -p "$OUTPUT_DIR"

log()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

log "Collecting live memory indicators for Apple processes..."

# Get list of all com.apple.* processes
APPLE_PROCS=$(ps aux | grep -E "com\.apple\." | grep -v grep || true)

if [[ -z "$APPLE_PROCS" ]]; then
    warn "No com.apple.* processes found"
    exit 0
fi

log "Found $(echo "$APPLE_PROCS" | wc -l) Apple processes"

# Collect vmmap for each Apple process
echo "=== VMMap Analysis ===" > "$VMAP_OUTPUT"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$VMAP_OUTPUT"
echo "" >> "$VMAP_OUTPUT"

while IFS= read -r proc_line; do
    pid=$(echo "$proc_line" | awk '{print $2}')
    proc_name=$(echo "$proc_line" | awk '{print $11}')
    
    # Only process com.apple.* processes
    if [[ ! "$proc_name" =~ com\.apple\. ]]; then
        continue
    fi
    
    log "Analyzing process: $proc_name (PID: $pid)"
    
    # Capture vmmap output
    echo "--- Process: $proc_name (PID: $pid) ---" >> "$VMAP_OUTPUT"
    if command -v vmmap &>/dev/null; then
        vmmap "$pid" >> "$VMAP_OUTPUT" 2>&1 || true
    else
        warn "vmmap command not available, skipping memory map for PID $pid"
        echo "vmmap not available" >> "$VMAP_OUTPUT"
    fi
    echo "" >> "$VMAP_OUTPUT"
    
    # Capture taskinfo output
    echo "--- Process: $proc_name (PID: $pid) ---" >> "$TASKINFO_OUTPUT"
    if command -v taskinfo &>/dev/null; then
        taskinfo "$pid" >> "$TASKINFO_OUTPUT" 2>&1 || true
    else
        warn "taskinfo command not available, skipping for PID $pid"
        echo "taskinfo not available" >> "$TASKINFO_OUTPUT"
    fi
    echo "" >> "$TASKINFO_OUTPUT"
done <<< "$APPLE_PROCS"

# Analyze for injection indicators
log "Analyzing memory for injection indicators..."

INJECTION_INDICATORS=(
    "DYLD_INSERT_LIBRARIES"
    "libinject"
    "libsubstitute"
    "libhook"
    "frida"
    "cycript"
    "substrate"
    "MSHook"
    "fishhook"
    "__DATA/__la_symbol_ptr"
    "executable_path"
)

echo "=== Memory Injection Analysis ===" > "$INJECTION_OUTPUT"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$INJECTION_OUTPUT"
echo "" >> "$INJECTION_OUTPUT"

INJECTION_FOUND=false

while IFS= read -r proc_line; do
    pid=$(echo "$proc_line" | awk '{print $2}')
    proc_name=$(echo "$proc_line" | awk '{print $11}')
    
    if [[ ! "$proc_name" =~ com\.apple\. ]]; then
        continue
    fi
    
    # Check vmmap output for suspicious regions
    proc_vmap=$(sed -n "/--- Process: $proc_name (PID: $pid) ---/,/^---/p" "$VMAP_OUTPUT" 2>/dev/null || true)
    
    for indicator in "${INJECTION_INDICATORS[@]}"; do
        if echo "$proc_vmap" | grep -qi "$indicator"; then
            alert "Potential injection indicator in $proc_name (PID: $pid): $indicator"
            echo "ALERT: $proc_name (PID: $pid)" >> "$INJECTION_OUTPUT"
            echo "Indicator: $indicator" >> "$INJECTION_OUTPUT"
            echo "Context:" >> "$INJECTION_OUTPUT"
            echo "$proc_vmap" | grep -i "$indicator" >> "$INJECTION_OUTPUT"
            echo "" >> "$INJECTION_OUTPUT"
            INJECTION_FOUND=true
        fi
    done
    
    # Check for suspicious memory regions (rwx permissions)
    if echo "$proc_vmap" | grep -q "r-x/rwx"; then
        alert "Suspicious rwx memory region in $proc_name (PID: $pid)"
        echo "ALERT: $proc_name (PID: $pid)" >> "$INJECTION_OUTPUT"
        echo "Indicator: rwx memory region detected" >> "$INJECTION_OUTPUT"
        echo "$proc_vmap" | grep "r-x/rwx" >> "$INJECTION_OUTPUT"
        echo "" >> "$INJECTION_OUTPUT"
        INJECTION_FOUND=true
    fi
    
    # Check for unusual library loads
    if echo "$proc_vmap" | grep -E "(/private/var|/tmp/|/Users/[^/]+/\.).*\.dylib" | grep -v "com.apple"; then
        alert "Unusual library load path in $proc_name (PID: $pid)"
        echo "ALERT: $proc_name (PID: $pid)" >> "$INJECTION_OUTPUT"
        echo "Indicator: Unusual library load path" >> "$INJECTION_OUTPUT"
        echo "$proc_vmap" | grep -E "(/private/var|/tmp/|/Users/[^/]+/\.).*\.dylib" >> "$INJECTION_OUTPUT"
        echo "" >> "$INJECTION_OUTPUT"
        INJECTION_FOUND=true
    fi
done <<< "$APPLE_PROCS"

if [[ "$INJECTION_FOUND" == "true" ]]; then
    alert "Memory injection indicators detected - review $INJECTION_OUTPUT"
else
    ok "No memory injection indicators detected"
fi

# Summary
echo -e "${BOLD}=== Live Memory Collection Complete ===${NC}"
ok "VMMap output: $VMAP_OUTPUT"
ok "TaskInfo output: $TASKINFO_OUTPUT"
if [[ "$INJECTION_FOUND" == "true" ]]; then
    alert "Injection alerts: $INJECTION_OUTPUT"
else
    ok "No injection alerts"
fi
