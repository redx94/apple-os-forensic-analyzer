#!/usr/bin/env bash
# ============================================================
# manifest_generator.sh - Evidence Provenance Manifest Generator
# ============================================================
# Apple OS Forensic Analyzer
#
# Purpose:
# Generates a machine-readable manifest with UTC timestamps,
# hostname, OS build, user, command line, SHA-256 hashes for
# all artifacts, and tool version. This provides evidence
# provenance for forensic defensibility.
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
TOOL_VERSION="2.0.0"
OUTPUT_DIR="${1:-./manifest_output}"
TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
MANIFEST="${OUTPUT_DIR}/manifest_${TIMESTAMP}.json"

mkdir -p "$OUTPUT_DIR"

log()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }

log "Generating evidence manifest..."

# Collect system metadata
HOSTNAME=$(hostname)
OS_VERSION=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
OS_BUILD=$(sw_vers -buildVersion 2>/dev/null || echo "unknown")
USER=$(whoami)
ACQUISITION_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Start JSON manifest
cat > "$MANIFEST" << EOF
{
  "acquisition_timestamp": "${ACQUISITION_TIME}",
  "hostname": "${HOSTNAME}",
  "os_version": "${OS_VERSION}",
  "build": "${OS_BUILD}",
  "tool_version": "Apple_OS_Forensic_Analyzer ${TOOL_VERSION}",
  "user": "${USER}",
  "command_line": "$0 $*",
  "artifacts": [
EOF

# Hash all collected artifacts from output directories
ADDED_ARTIFACTS=false
for output_dir in extract_ids_output verify_trust_output xpc_scan_output validate_output dns_monitor_output; do
    if [[ -d "../$output_dir" ]]; then
        for f in "../$output_dir"/*; do
            if [[ -f "$f" ]]; then
                SHA256=$(shasum -a 256 "$f" 2>/dev/null | cut -d' ' -f1 || echo "hash_failed")
                FILENAME=$(basename "$f")
                FILESIZE=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f" 2>/dev/null || echo "0")
                
                if [[ "$ADDED_ARTIFACTS" == "true" ]]; then
                    echo "," >> "$MANIFEST"
                fi
                
                cat >> "$MANIFEST" << EOF
    {
      "file": "${FILENAME}",
      "path": "$f",
      "sha256": "${SHA256}",
      "size_bytes": ${FILESIZE},
      "collected_at": "${ACQUISITION_TIME}"
    }
EOF
                ADDED_ARTIFACTS=true
            fi
        done
    fi
done

# Close JSON
echo "" >> "$MANIFEST"
echo "  ]" >> "$MANIFEST"
echo "}" >> "$MANIFEST"

ok "Manifest generated: $MANIFEST"
log "Hostname: $HOSTNAME"
log "OS: $OS_VERSION ($OS_BUILD)"
log "Artifacts hashed: $(jq '.artifacts | length' "$MANIFEST" 2>/dev/null || echo "0")"

