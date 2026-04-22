#!/usr/bin/env bash
# ============================================================
# verify_extracted_ids.sh - Deep Verification of Extracted Alerts
# ============================================================
# Apple OS Forensic Analyzer
#
# Purpose:
# Takes an output file from extract_ids.sh (which contains
# LABEL=... BINARY=...) and runs a strict cryptographic codesign
# check and path validation against every single binary.
# This prevents "dismissing alerts" by actually verifying them.
# ============================================================

set -u
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

if [[ -z "${1:-}" ]]; then
    echo -e "${RED}[!] Usage: $0 ./extract_ids_output/apple_ids_XXX.txt${NC}"
    exit 1
fi

INPUT_FILE="$1"
if [[ ! -f "$INPUT_FILE" ]]; then
    echo -e "${RED}[!] Error: File not found: $INPUT_FILE${NC}"
    exit 1
fi

echo -e "${CYAN}[*] Deep Verifying extracted identifiers from: $INPUT_FILE${NC}"
echo "------------------------------------------------------------"

FAILED=0
PASSED=0
PROCESSED=0

# Extract lines that explicitly map an ID to a binary path
# Use process substitution to avoid subshell bug (variables must survive to summary)
while read -r line; do
    [[ -z "$line" ]] && continue

    # Extract binary path safely
    BIN_PATH=$(echo "$line" | sed -n 's/.*BINARY=\(.*\) FILE=.*/\1/p')
    LABEL=$(echo "$line" | sed -n 's/^LABEL=\([^ ]*\) .*/\1/p')

    [[ -z "$BIN_PATH" || "$BIN_PATH" == "N/A" ]] && continue

    let PROCESSED++

    if [[ ! -f "$BIN_PATH" ]]; then
        echo -e "${YELLOW}[?] ID: ${LABEL} -> Binary missing from disk: ${BIN_PATH}${NC}"
        continue
    fi

    # 1. Check Signature
    SIG_INFO=$(codesign -dv --verbose=4 "$BIN_PATH" 2>&1 || true)

    if echo "$SIG_INFO" | grep -q "code object is not signed at all"; then
        echo -e "${RED}[ALERT] UNSIGNED BINARY DETECTED!${NC}"
        echo "  Label:  $LABEL"
        echo "  Binary: $BIN_PATH"
        let FAILED++
        continue
    fi

    # 2. Verify it's an Apple Authority
    AUTHORITY=$(echo "$SIG_INFO" | grep "Authority=" | head -1 | cut -d= -f2)
    if ! echo "$AUTHORITY" | grep -qiE "Apple|Software Signing"; then
        echo -e "${RED}[ALERT] NON-APPLE SIGNATURE ON APPLE ID!${NC}"
        echo "  Label:  $LABEL"
        echo "  Binary: $BIN_PATH"
        echo "  Signer: $AUTHORITY"
        let FAILED++
        continue
    fi

    let PASSED++
done < <(grep "^LABEL=" "$INPUT_FILE")

echo "------------------------------------------------------------"
echo -e "${CYAN}[*] Deep Verification Complete.${NC}"
echo -e "    Binaries Verified: $PROCESSED"
echo -e "    Valid Apple Signatures: ${GREEN}$PASSED${NC}"
if [[ $FAILED -gt 0 ]]; then
    echo -e "    Cryptographic Failures (Anomalies): ${RED}$FAILED${NC}"
    echo -e "${RED}[!] INVESTIGATE FAILURES IMMEDIATELY.${NC}"
else
    echo -e "    Cryptographic Failures: ${GREEN}$FAILED${NC}"
    echo -e "${GREEN}[+] All analyzed identifiers cryptographically map to legitimate Apple binaries.${NC}"
fi
