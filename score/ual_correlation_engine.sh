#!/usr/bin/env bash
# ============================================================
# ual_correlation_engine.sh - Unified Audit Log Correlation Engine
# ============================================================
# Apple OS Forensic Analyzer v3.0
#
# Purpose:
# Parses Unified Audit Logs for TCC bypass attempts and XPC communication anomalies.
# Moves beyond disk-based analysis to detect transient execution patterns that leave
# no files behind.
#
# v3.0 Enhancement:
# - Detects TCC (Transparency, Consent, and Control) bypass attempts
# - Identifies XPC communication anomalies between processes
# - Correlates log events across subsystems for threat hunting
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

OUTPUT_DIR="./ual_correlation_output"
TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
TCC_BYPASS_OUTPUT="${OUTPUT_DIR}/tcc_bypass_alerts_${TIMESTAMP}.txt"
XPC_ANOMALY_OUTPUT="${OUTPUT_DIR}/xpc_anomalies_${TIMESTAMP}.txt"
CORRELATION_OUTPUT="${OUTPUT_DIR}/correlation_report_${TIMESTAMP}.txt"

mkdir -p "$OUTPUT_DIR"

log()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

# TCC bypass patterns
TCC_BYPASS_PATTERNS=(
    "TCCAccessRequest.*denied"
    "kTCCService.*unauthorized"
    "csreq.*failed"
    "authorization.*denied"
    "security.*authorization.*denied"
    "access.*denied.*TCC"
    "privacy.*access.*denied"
    "entitlement.*not.*granted"
    "code.*signature.*invalid.*TCC"
)

# Suspicious XPC communication patterns
XPC_SUSPICIOUS_PATTERNS=(
    "com.apple.*spawned.*by.*non.*apple"
    "unexpected.*XPC.*connection"
    "anonymous.*XPC.*connection"
    "XPC.*connection.*from.*unknown"
    "bootstrap.*service.*unregistered"
    "launchd.*service.*not.*found"
    "XPC.*error.*connection.*invalid"
    "mach.*service.*lookup.*failed"
)

log "Starting Unified Audit Log Correlation Engine..."
log "Output directory: $OUTPUT_DIR"

# Collect Unified Logs for the last 24 hours
log "Collecting Unified Logs (last 24 hours)..."
UAL_LOG="${OUTPUT_DIR}/unified_logs_${TIMESTAMP}.txt"

if command -v log &>/dev/null; then
    log show --last 24h --info --style compact > "$UAL_LOG" 2>&1 || true
    if [[ -s "$UAL_LOG" ]]; then
        ok "Collected $(wc -l < "$UAL_LOG") log entries"
    else
        warn "No Unified Logs collected"
    fi
else
    warn "log command not available - UAL analysis requires macOS"
    exit 0
fi

# Detect TCC bypass attempts
log "Analyzing for TCC bypass attempts..."
TCC_ALERTS=0

for pattern in "${TCC_BYPASS_PATTERNS[@]}"; do
    if grep -qiE "$pattern" "$UAL_LOG" 2>/dev/null; then
        while IFS= read -r line; do
            if echo "$line" | grep -qiE "$pattern"; then
                alert "TCC Bypass Pattern Detected: $pattern"
                echo "$line" >> "$TCC_BYPASS_OUTPUT"
                TCC_ALERTS=$((TCC_ALERTS + 1))
            fi
        done < "$UAL_LOG"
    fi
done

if [[ "$TCC_ALERTS" -gt 0 ]]; then
    alert "TCC bypass attempts detected: $TCC_ALERTS"
    ok "TCC bypass alerts saved to: $TCC_BYPASS_OUTPUT"
else
    ok "No TCC bypass attempts detected"
fi

# Detect XPC communication anomalies
log "Analyzing for XPC communication anomalies..."
XPC_ALERTS=0

for pattern in "${XPC_SUSPICIOUS_PATTERNS[@]}"; do
    if grep -qiE "$pattern" "$UAL_LOG" 2>/dev/null; then
        while IFS= read -r line; do
            if echo "$line" | grep -qiE "$pattern"; then
                alert "XPC Anomaly Pattern Detected: $pattern"
                echo "$line" >> "$XPC_ANOMALY_OUTPUT"
                XPC_ALERTS=$((XPC_ALERTS + 1))
            fi
        done < "$UAL_LOG"
    fi
done

if [[ "$XPC_ALERTS" -gt 0 ]]; then
    alert "XPC communication anomalies detected: $XPC_ALERTS"
    ok "XPC anomalies saved to: $XPC_ANOMALY_OUTPUT"
else
    ok "No XPC communication anomalies detected"
fi

# Cross-correlation analysis
log "Performing cross-subsystem correlation analysis..."

# Look for processes that appear in both TCC and XPC alerts
if [[ "$TCC_ALERTS" -gt 0 && "$XPC_ALERTS" -gt 0 ]]; then
    log "Correlating TCC bypass attempts with XPC anomalies..."
    
    # Extract process names from TCC alerts
    TCC_PROCS=$(grep -oE "process.*[0-9]+" "$TCC_BYPASS_OUTPUT" | awk '{print $NF}' | sort -u || true)
    
    # Check if these processes also appear in XPC anomalies
    for proc in $TCC_PROCS; do
        if grep -q "$proc" "$XPC_ANOMALY_OUTPUT" 2>/dev/null; then
            alert "CORRELATION: Process $proc appears in both TCC bypass and XPC anomaly logs"
            echo "CORRELATION: $proc" >> "$CORRELATION_OUTPUT"
        fi
    done
    
    if [[ -f "$CORRELATION_OUTPUT" && -s "$CORRELATION_OUTPUT" ]]; then
        alert "Cross-correlation findings saved to: $CORRELATION_OUTPUT"
    fi
fi

# Time-based anomaly detection
log "Analyzing for burst patterns (potential automated threats)..."
BURST_OUTPUT="${OUTPUT_DIR}/burst_patterns_${TIMESTAMP}.txt"

# Count events per minute
if command -v awk &>/dev/null; then
    awk '{print $1}' "$UAL_LOG" | grep -E "^[0-9]{4}-[0-9]{2}-[0-9]{2}" | cut -d: -f1-2 | sort | uniq -c | sort -rn | head -20 > "$BURST_OUTPUT" 2>/dev/null || true
    
    if [[ -s "$BURST_OUTPUT" ]]; then
        log "Top 20 event-per-minute intervals:"
        head -5 "$BURST_OUTPUT"
        
        # Flag suspicious bursts (>100 events in a minute)
        if awk '$1 > 100' "$BURST_OUTPUT" | grep -q .; then
            alert "Suspicious burst patterns detected - see $BURST_OUTPUT"
        fi
    fi
fi

# Summary
echo -e "${BOLD}=== UAL Correlation Engine Analysis Complete ===${NC}"
ok "TCC bypass attempts: $TCC_ALERTS"
ok "XPC communication anomalies: $XPC_ALERTS"
ok "Results saved to: $OUTPUT_DIR"
log "Review these files for detailed findings:"
ls -la "$OUTPUT_DIR"
