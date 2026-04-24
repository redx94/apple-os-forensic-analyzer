#!/usr/bin/env bash
# ============================================================
# verify_extensions.sh - Kext & System Extension Integrity Validator
# ============================================================
# Apple OS Forensic Analyzer v3.0
#
# Purpose:
# Ensures that an attacker hasn't downgraded system security to load a malicious
# driver or bypass System Integrity Protection (SIP).
#
# v3.0 Enhancement:
# - Kext Validation: Checks notarization and load status of third-party kexts
# - System Extensions: Verifies state of modern dexts (System Extensions)
# - SIP Status: Logs System Integrity Protection configuration
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

OUTPUT_DIR="./verify_extensions_output"
TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
KEXT_REPORT="${OUTPUT_DIR}/kext_integrity_${TIMESTAMP}.txt"
SYSEXT_REPORT="${OUTPUT_DIR}/sysext_integrity_${TIMESTAMP}.txt"
SIP_REPORT="${OUTPUT_DIR}/sip_status_${TIMESTAMP}.txt"

mkdir -p "$OUTPUT_DIR"

log()   { echo -e "${CYAN}[*]${NC} $*" | tee -a "$KEXT_REPORT"; }
ok()    { echo -e "${GREEN}[+]${NC} $*" | tee -a "$KEXT_REPORT"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$KEXT_REPORT"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*" | tee -a "$KEXT_REPORT"; }

echo -e "${BOLD}=== Apple OS Forensic Extension Integrity Validator ===${NC}" | tee "$KEXT_REPORT"
log "Output directory: $OUTPUT_DIR"

# SIP Status Check
log "Checking System Integrity Protection (SIP) status..."
if command -v csrutil &>/dev/null; then
    csrutil status > "$SIP_REPORT" 2>&1 || true
    
    if grep -q "enabled" "$SIP_REPORT"; then
        ok "SIP is enabled - System Integrity Protection is active"
    else
        alert "SIP is DISABLED or partially disabled - System Integrity Protection is compromised!"
    fi
    
    # Check for specific SIP configuration flags
    if grep -q "Filesystem Protections: disabled" "$SIP_REPORT"; then
        alert "Filesystem Protections are DISABLED - attacker can modify system files"
    fi
    if grep -q "Kext Signing: disabled" "$SIP_REPORT"; then
        alert "Kext Signing is DISABLED - unsigned kexts can be loaded"
    fi
    if grep -q "System Integrity Protection: disabled" "$SIP_REPORT"; then
        alert "System Integrity Protection is FULLY DISABLED - critical security bypass"
    fi
    
    ok "SIP status report saved to: $SIP_REPORT"
else
    warn "csrutil not available - SIP status check skipped"
fi

# Kext Validation
log "Checking Kernel Extension (Kext) integrity..."
if command -v kmutil &>/dev/null; then
    log "Using kmutil to inspect loaded kexts..."
    
    # Get list of loaded kexts
    kmutil inspect --list-only > "${OUTPUT_DIR}/kext_list_${TIMESTAMP}.txt" 2>&1 || true
    
    # Check for unsigned or suspicious kexts
    UNSIGNED_KEXTS=0
    
    if [[ -f "${OUTPUT_DIR}/kext_list_${TIMESTAMP}.txt" ]]; then
        while IFS= read -r line; do
            if [[ -n "$line" && ! "$line" =~ ^# ]]; then
                kext_path=$(echo "$line" | awk '{print $1}')
                
                # Skip Apple kexts (they're in /System/Library/Extensions)
                if [[ "$kext_path" == "/System/Library/Extensions/"* ]]; then
                    continue
                fi
                
                # Check if third-party kext is notarized
                if command -v kmutil &>/dev/null; then
                    notarization=$(kmutil inspect --bundle-path "$kext_path" 2>&1 || true)
                    
                    if echo "$notarization" | grep -qi "not.*notarized\|not.*signed"; then
                        alert "UNSIGNED or UN-NOTARIZED KEXT: $kext_path"
                        echo "  Path: $kext_path" >> "$KEXT_REPORT"
                        echo "  Status: $notarization" >> "$KEXT_REPORT"
                        UNSIGNED_KEXTS=$((UNSIGNED_KEXTS + 1))
                    else
                        ok "Notarized kext: $kext_path"
                    fi
                fi
            fi
        done < "${OUTPUT_DIR}/kext_list_${TIMESTAMP}.txt"
    fi
    
    if [[ "$UNSIGNED_KEXTS" -gt 0 ]]; then
        alert "Found $UNSIGNED_KEXTS unsigned or un-notarized kexts - potential kernel-level compromise"
    else
        ok "All loaded kexts appear to be signed and notarized"
    fi
    
    ok "Kext integrity report saved to: $KEXT_REPORT"
else
    warn "kmutil not available - kext validation skipped (requires macOS)"
fi

# System Extensions (dexts) Validation
log "Checking System Extension (dext) integrity..."
if command -v systemextensionsctl &>/dev/null; then
    systemextensionsctl list > "$SYSEXT_REPORT" 2>&1 || true
    
    SUSPICIOUS_SYSEXT=0
    
    if [[ -f "$SYSEXT_REPORT" ]]; then
        # Check for suspicious states
        while IFS= read -r line; do
            if echo "$line" | grep -qi "activated-waiting-for-user"; then
                alert "System Extension in 'activated-waiting-for-user' state: $line"
                SUSPICIOUS_SYSEXT=$((SUSPICIOUS_SYSEXT + 1))
            fi
            if echo "$line" | grep -qi "invalid\|disabled"; then
                warn "System Extension in invalid/disabled state: $line"
            fi
        done < "$SYSEXT_REPORT"
    fi
    
    if [[ "$SUSPICIOUS_SYSEXT" -gt 0 ]]; then
        alert "Found $SUSPICIOUS_SYSEXT system extensions in suspicious states - potential persistence mechanism"
    else
        ok "All system extensions appear to be in valid states"
    fi
    
    ok "System extension report saved to: $SYSEXT_REPORT"
else
    warn "systemextensionsctl not available - system extension validation skipped"
fi

# Check for suspicious directories
log "Checking for suspicious kext installation directories..."
SUSPICIOUS_DIRS=(
    "/tmp/Extensions"
    "/var/tmp/Extensions"
    "/private/tmp/Extensions"
    "$HOME/Extensions"
    "/usr/local/lib/kext"
)

for dir in "${SUSPICIOUS_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        alert "SUSPICIOUS KEXT DIRECTORY FOUND: $dir"
        alert "  Malicious kexts may be loaded from non-standard locations"
        ls -la "$dir" >> "$KEXT_REPORT" 2>&1 || true
    fi
done

# Summary
echo -e "${BOLD}=== Extension Integrity Analysis Complete ===${NC}"
ok "SIP status report: $SIP_REPORT"
ok "Kext integrity report: $KEXT_REPORT"
ok "System extension report: $SYSEXT_REPORT"
log "Review these files for detailed findings:"
ls -la "$OUTPUT_DIR"
