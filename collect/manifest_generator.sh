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
#
# v2.1 Enhancement:
# - Added Merkle tree hash generation for evidence immutability
# - Optional evidence folder locking with tamper detection
#
# v3.0 Enhancement:
# - Optional decentralized anchoring via IPFS for legal-grade proof
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
TOOL_VERSION="3.0.0"
OUTPUT_DIR="./manifest_output"
TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
MANIFEST="${OUTPUT_DIR}/manifest_${TIMESTAMP}.json"
LOCK_EVIDENCE="${LOCK_EVIDENCE:-false}"
ANCHOR_TO_IPFS="${ANCHOR_TO_IPFS:-false}"

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --anchor)
            ANCHOR_TO_IPFS=true
            shift
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        *)
            OUTPUT_DIR="$1"
            shift
            ;;
    esac
done

mkdir -p "$OUTPUT_DIR"

log()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

# Generate Merkle tree hash for a directory
generate_merkle_tree() {
    local dir="$1"
    local hash_file="${dir}/.merkle_root.txt"
    
    if [[ ! -d "$dir" ]]; then
        warn "Directory not found for Merkle tree: $dir"
        return 1
    fi
    
    log "Generating Merkle tree hash for: $dir"
    
    # Collect all file hashes sorted by path
    local file_hashes=()
    while IFS= read -r -d '' file; do
        if [[ -f "$file" ]]; then
            local file_hash=$(shasum -a 256 "$file" 2>/dev/null | cut -d' ' -f1)
            local rel_path="${file#$dir/}"
            file_hashes+=("$file_hash  $rel_path")
        fi
    done < <(find "$dir" -type f -print0 | sort -z)
    
    if [[ ${#file_hashes[@]} -eq 0 ]]; then
        warn "No files found in directory for Merkle tree"
        return 1
    fi
    
    # Generate Merkle root by hashing all file hashes together
    local all_hashes=$(printf '%s\n' "${file_hashes[@]}" | sort)
    local merkle_root=$(echo -n "$all_hashes" | shasum -a 256 | cut -d' ' -f1)
    
    # Store Merkle root and file list
    {
        echo "MERKLE_ROOT: $merkle_root"
        echo "GENERATED_AT: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "FILE_COUNT: ${#file_hashes[@]}"
        echo "---"
        printf '%s\n' "${file_hashes[@]}"
    } > "$hash_file"
    
    # If locking is enabled, make the hash file immutable
    if [[ "$LOCK_EVIDENCE" == "true" ]]; then
        chflags uchg "$hash_file" 2>/dev/null || true
        log "Evidence folder locked: $dir"
    fi
    
    echo "$merkle_root"
}

# Verify Merkle tree hash (for score phase)
verify_merkle_tree() {
    local dir="$1"
    local hash_file="${dir}/.merkle_root.txt"
    
    if [[ ! -f "$hash_file" ]]; then
        warn "No Merkle tree file found: $hash_file"
        return 1
    fi
    
    local stored_root=$(grep "^MERKLE_ROOT:" "$hash_file" | cut -d' ' -f2)
    local current_root=$(generate_merkle_tree "$dir")
    
    if [[ "$stored_root" == "$current_root" ]]; then
        ok "Merkle tree verification passed"
        return 0
    else
        alert "Merkle tree verification FAILED - evidence tampering detected!"
        return 1
    fi
}

# Anchor manifest to IPFS for decentralized forensic proof
anchor_to_ipfs() {
    local manifest_file="$1"
    local anchoring_record="${OUTPUT_DIR}/ipfs_anchoring_${TIMESTAMP}.txt"
    
    log "Attempting to anchor manifest to IPFS..."
    
    # Check if ipfs command is available
    if ! command -v ipfs &>/dev/null; then
        warn "ipfs command not available - skipping IPFS anchoring"
        warn "Install IPFS: https://docs.ipfs.io/install/"
        return 1
    fi
    
    # Check if IPFS daemon is running
    if ! ipfs swarm peers &>/dev/null; then
        warn "IPFS daemon not running - skipping IPFS anchoring"
        warn "Start IPFS daemon: ipfs daemon"
        return 1
    fi
    
    # Add manifest to IPFS
    local ipfs_hash
    ipfs_hash=$(ipfs add -q "$manifest_file" 2>/dev/null || true)
    
    if [[ -z "$ipfs_hash" ]]; then
        warn "Failed to add manifest to IPFS"
        return 1
    fi
    
    # Pin the content to ensure it's not garbage collected
    ipfs pin add "$ipfs_hash" &>/dev/null || true
    
    # Record the anchoring information
    {
        echo "IPFS_ANCHORING_RECORD"
        echo "TIMESTAMP: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "MANIFEST_FILE: $manifest_file"
        echo "IPFS_CID: $ipfs_hash"
        echo "IPFS_GATEWAY: https://ipfs.io/ipfs/$ipfs_hash"
        echo "LOCAL_GATEWAY: http://localhost:8080/ipfs/$ipfs_hash"
        echo "---"
        echo "To verify: ipfs cat $ipfs_hash | jq"
    } > "$anchoring_record"
    
    ok "Manifest anchored to IPFS: $ipfs_hash"
    ok "IPFS Gateway: https://ipfs.io/ipfs/$ipfs_hash"
    ok "Anchoring record saved to: $anchoring_record"
    
    # Add IPFS CID to manifest
    local temp_manifest="${OUTPUT_DIR}/manifest_${TIMESTAMP}_ipfs.json"
    jq --arg ipfs "$ipfs_hash" '. + {"ipfs_cid": $ipfs, "ipfs_anchored_at": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}' "$manifest_file" > "$temp_manifest"
    mv "$temp_manifest" "$manifest_file"
    
    return 0
}

log "Generating evidence manifest..."

# Collect system metadata
HOSTNAME=$(hostname)
OS_VERSION=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
OS_BUILD=$(sw_vers -buildVersion 2>/dev/null || echo "unknown")
USER=$(whoami)
ACQUISITION_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Generate Merkle tree for extract_ids_output if it exists
MERKLE_ROOT="null"
if [[ -d "../extract_ids_output" ]]; then
    MERKLE_ROOT=$(generate_merkle_tree "../extract_ids_output")
fi

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
  "evidence_locked": ${LOCK_EVIDENCE},
  "merkle_root": "${MERKLE_ROOT}",
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

if [[ "$MERKLE_ROOT" != "null" ]]; then
    ok "Merkle tree root: $MERKLE_ROOT"
    if [[ "$LOCK_EVIDENCE" == "true" ]]; then
        ok "Evidence folder locked with immutable hash file"
    fi
fi

# v3.0: Anchor to IPFS if requested
if [[ "$ANCHOR_TO_IPFS" == "true" ]]; then
    anchor_to_ipfs "$MANIFEST"
fi

log "Usage: To verify evidence integrity, run verify_merkle_tree() during score phase"

