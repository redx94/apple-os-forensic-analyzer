#!/usr/bin/env bash
# ============================================================
# stress_test_framework.sh - Deep Stress Testing for Suspicious Findings
# ============================================================
# Apple OS Forensic Analyzer
#
# Purpose:
# Apply pressure to suspicious findings to determine if they are
# legitimate or hiding compromise. This is not a quick check - this
# is deep forensic analysis designed to expose hidden compromises.
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

STRESS_TEST_OUTPUT="./stress_test_output"
mkdir -p "$STRESS_TEST_OUTPUT"

# Test 1: Deep binary analysis
deep_binary_analysis() {
    local binary="$1"
    local label="$2"
    local output_dir="$3"
    
    log "Deep binary analysis for $label"
    
    # Check if binary exists
    if [[ ! -e "$binary" ]]; then
        warn "Binary not found: $binary"
        return 1
    fi
    
    # Get full binary info
    local binary_info
    binary_info=$(file "$binary")
    echo "FILE TYPE: $binary_info" > "$output_dir/binary_info.txt"
    
    # Check for embedded scripts or suspicious strings
    log "Checking for embedded scripts..."
    strings "$binary" 2>/dev/null | grep -Ei "(sh|bash|python|perl|ruby|curl|wget|nc|netcat|reverse|shell)" > "$output_dir/suspicious_strings.txt" || true
    
    # Check for suspicious URLs
    log "Checking for embedded URLs..."
    strings "$binary" 2>/dev/null | grep -Ei "(http|https|ftp)://" > "$output_dir/embedded_urls.txt" || true
    
    # Check for IP addresses
    log "Checking for embedded IP addresses..."
    strings "$binary" 2>/dev/null | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" > "$output_dir/embedded_ips.txt" || true
    
    # Check binary modification time
    local mtime
    mtime=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$binary")
    echo "MODIFICATION TIME: $mtime" >> "$output_dir/binary_info.txt"
    
    # Check if binary is in expected location
    local expected_locations=("/System/Library" "/usr/libexec" "/usr/bin" "/usr/sbin" "/Library")
    local in_expected=false
    for loc in "${expected_locations[@]}"; do
        if [[ "$binary" == "$loc"* ]]; then
            in_expected=true
            break
        fi
    done
    if [[ "$in_expected" == false ]]; then
        alert "Binary in unexpected location: $binary"
        echo "LOCATION: UNEXPECTED" >> "$output_dir/binary_info.txt"
    else
        echo "LOCATION: EXPECTED" >> "$output_dir/binary_info.txt"
    fi
    
    # Check binary hash
    local hash
    hash=$(shasum -a 256 "$binary" 2>/dev/null | cut -d' ' -f1)
    echo "SHA256: $hash" >> "$output_dir/binary_info.txt"
    
    ok "Binary analysis complete"
}

# Test 2: Deep signature verification
deep_signature_check() {
    local binary="$1"
    local label="$2"
    local output_dir="$3"
    
    log "Deep signature verification for $label"
    
    if [[ ! -e "$binary" ]]; then
        warn "Binary not found: $binary"
        return 1
    fi
    
    # Get full signature info
    codesign -dv --verbose=4 "$binary" 2>&1 > "$output_dir/full_signature.txt"
    
    # Check signature chain
    log "Checking signature chain..."
    local authorities
    authorities=$(codesign -dv --verbose=4 "$binary" 2>&1 | grep "Authority=" || echo "")
    echo "$authorities" > "$output_dir/signature_chain.txt"
    
    # Check for revoked or expired certificates
    log "Checking certificate validity..."
    codesign -v "$binary" 2>&1 > "$output_dir/signature_validity.txt" || true
    
    # Check signing timestamp
    local sign_time
    sign_time=$(codesign -dv "$binary" 2>&1 | grep "Signed Time" || echo "UNKNOWN")
    echo "$sign_time" > "$output_dir/signing_timestamp.txt"
    
    # Check if signature is ad-hoc (no certificate)
    local is_adhoc
    is_adhoc=$(codesign -dv "$binary" 2>&1 | grep -i "ad-hoc" || echo "")
    if [[ -n "$is_adhoc" ]]; then
        alert "AD-HOC SIGNATURE: $binary"
        echo "SIGNATURE_TYPE: AD-HOC" >> "$output_dir/signature_info.txt"
    else
        echo "SIGNATURE_TYPE: CERTIFICATE" >> "$output_dir/signature_info.txt"
    fi
    
    ok "Signature verification complete"
}

# Test 3: Process behavior analysis
process_behavior_analysis() {
    local label="$1"
    local output_dir="$2"
    
    log "Process behavior analysis for $label"
    
    # Check if process is running
    local pid
    pid=$(pgrep -f "$label" | head -1 || echo "")
    
    if [[ -z "$pid" ]]; then
        warn "Process not running: $label"
        echo "STATUS: NOT_RUNNING" > "$output_dir/process_status.txt"
        return 0
    fi
    
    echo "STATUS: RUNNING (PID: $pid)" > "$output_dir/process_status.txt"
    
    # Get process info
    ps aux | grep "$pid" | grep -v grep > "$output_dir/process_info.txt"
    
    # Check open files
    lsof -p "$pid" 2>/dev/null > "$output_dir/open_files.txt" || true
    
    # Check network connections
    lsof -p "$pid" -i 2>/dev/null > "$output_dir/network_connections.txt" || true
    
    # Check parent process
    local ppid
    ppid=$(ps -o ppid= -p "$pid" | tr -d ' ')
    local parent_name
    parent_name=$(ps -o comm= -p "$ppid" 2>/dev/null || echo "UNKNOWN")
    echo "PARENT: $parent_name (PID: $ppid)" > "$output_dir/parent_process.txt"
    
    # Check for suspicious environment variables
    cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' > "$output_dir/environment.txt" || true
    
    ok "Process behavior analysis complete"
}

# Test 4: Network behavior monitoring
network_behavior_monitor() {
    local label="$1"
    local output_dir="$2"
    local duration="${3:-30}"  # Default 30 seconds
    
    log "Monitoring network behavior for $label (duration: ${duration}s)"
    
    # Get process PID
    local pid
    pid=$(pgrep -f "$label" | head -1 || echo "")
    
    if [[ -z "$pid" ]]; then
        warn "Process not running: $label"
        return 0
    fi
    
    # Monitor network connections
    log "Starting network capture..."
    for i in $(seq 1 "$duration"); do
        lsof -p "$pid" -i 2>/dev/null >> "$output_dir/network_log.txt" || true
        sleep 1
    done
    
    # Analyze connections
    log "Analyzing network connections..."
    local unique_ips
    unique_ips=$(grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" "$output_dir/network_log.txt" 2>/dev/null | sort -u || echo "")
    echo "$unique_ips" > "$output_dir/unique_ips.txt"
    
    local unique_ports
    unique_ports=$(grep -oE ":[0-9]+" "$output_dir/network_log.txt" 2>/dev/null | sort -u || echo "")
    echo "$unique_ports" > "$output_dir/unique_ports.txt"
    
    # Check for connections to non-Apple infrastructure
    local non_apple
    non_apple=$(echo "$unique_ips" | grep -vE "(17\.|140\.|192\.168\.|10\.|127\.|::1)" || echo "")
    if [[ -n "$non_apple" ]]; then
        alert "Non-Apple infrastructure connections detected"
        echo "$non_apple" > "$output_dir/non_apple_connections.txt"
    fi
    
    ok "Network monitoring complete"
}

# Test 5: File integrity verification
file_integrity_check() {
    local path="$1"
    local label="$2"
    local output_dir="$3"
    
    log "File integrity check for $label"
    
    if [[ ! -e "$path" ]]; then
        warn "Path not found: $path"
        return 1
    fi
    
    # Calculate multiple hashes
    openssl dgst -sha256 "$path" > "$output_dir/sha256.txt" 2>/dev/null || echo "HASH_FAILED" > "$output_dir/sha256.txt"
    openssl dgst -sha1 "$path" > "$output_dir/sha1.txt" 2>/dev/null || echo "HASH_FAILED" > "$output_dir/sha1.txt"
    openssl dgst -md5 "$path" > "$output_dir/md5.txt" 2>/dev/null || echo "HASH_FAILED" > "$output_dir/md5.txt"
    
    # Check file permissions
    local perms
    perms=$(stat -f "%Lp" "$path")
    echo "PERMISSIONS: $perms" > "$output_dir/permissions.txt"
    
    # Check ownership
    local owner
    owner=$(stat -f "%Su:%Sg" "$path")
    echo "OWNERSHIP: $owner" >> "$output_dir/permissions.txt"
    
    # Check for extended attributes
    xattr -l "$path" > "$output_dir/extended_attributes.txt" 2>/dev/null || true
    
    # Check quarantine flags
    xattr -p "com.apple.quarantine" "$path" > "$output_dir/quarantine.txt" 2>/dev/null || echo "NO_QUARANTINE" > "$output_dir/quarantine.txt"
    
    # Check if file is signed
    if codesign -v "$path" 2>/dev/null; then
        echo "SIGNED: YES" > "$output_dir/signature_status.txt"
    else
        echo "SIGNED: NO" > "$output_dir/signature_status.txt"
    fi
    
    ok "File integrity check complete"
}

# Test 6: Timeline analysis
timeline_analysis() {
    local path="$1"
    local label="$2"
    local output_dir="$3"
    
    log "Timeline analysis for $label"
    
    if [[ ! -e "$path" ]]; then
        warn "Path not found: $path"
        return 1
    fi
    
    # Get all timestamps
    local birth_time
    birth_time=$(stat -f "%SB" -t "%Y-%m-%d %H:%M:%S" "$path")
    local mod_time
    mod_time=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$path")
    local change_time
    change_time=$(stat -f "%Sc" -t "%Y-%m-%d %H:%M:%S" "$path")
    local access_time
    access_time=$(stat -f "%Sa" -t "%Y-%m-%d %H:%M:%S" "$path")
    
    echo "BIRTH_TIME: $birth_time" > "$output_dir/timeline.txt"
    echo "MODIFICATION_TIME: $mod_time" >> "$output_dir/timeline.txt"
    echo "CHANGE_TIME: $change_time" >> "$output_dir/timeline.txt"
    echo "ACCESS_TIME: $access_time" >> "$output_dir/timeline.txt"
    
    # Check for timestamp anomalies
    # If mod time is newer than expected for system file
    if [[ "$path" == /System/* ]]; then
        local current_time
        current_time=$(date +%s)
        local mod_epoch
        mod_epoch=$(stat -f "%m" "$path")
        local days_old
        days_old=$(( (current_time - mod_epoch) / 86400 ))
        
        echo "DAYS_SINCE_MOD: $days_old" >> "$output_dir/timeline.txt"
        
        if [[ $days_old -lt 30 ]]; then
            alert "System file modified within last 30 days: $path"
        fi
    fi
    
    ok "Timeline analysis complete"
}

# Test 7: Plist structure analysis
plist_structure_analysis() {
    local plist="$1"
    local label="$2"
    local output_dir="$3"
    
    log "Plist structure analysis for $label"
    
    if [[ ! -e "$plist" ]]; then
        warn "Plist not found: $plist"
        return 1
    fi
    
    # Convert to xml for analysis
    local temp_xml
    temp_xml="$output_dir/plist_xml.xml"
    plutil -convert xml1 -o "$temp_xml" "$plist" 2>/dev/null || true
    
    # Check for suspicious keys
    log "Checking for suspicious keys..."
    grep -iE "(command|script|shell|exec|url|http|download|upload)" "$temp_xml" 2>/dev/null > "$output_dir/suspicious_keys.txt" || true
    
    # Check for hidden or encoded data
    log "Checking for encoded data..."
    grep -iE "(data|base64)" "$temp_xml" 2>/dev/null > "$output_dir/encoded_data.txt" || true
    
    # Check for unusual structure
    local line_count
    line_count=$(wc -l < "$temp_xml")
    local unique_lines
    unique_lines=$(sort "$temp_xml" | uniq | wc -l)
    local ratio
    ratio=$(echo "scale=2; $unique_lines / $line_count" | bc 2>/dev/null || echo "0")
    
    echo "LINE_COUNT: $line_count" > "$output_dir/structure_info.txt"
    echo "UNIQUE_LINES: $unique_lines" >> "$output_dir/structure_info.txt"
    echo "RATIO: $ratio" >> "$output_dir/structure_info.txt"
    
    # Check for binary plist
    if file "$plist" | grep -q "binary"; then
        echo "FORMAT: BINARY" >> "$output_dir/structure_info.txt"
    else
        echo "FORMAT: XML" >> "$output_dir/structure_info.txt"
    fi
    
    ok "Plist structure analysis complete"
}

# Main stress test function
run_stress_test() {
    local target_type="$1"  # binary, plist, process
    local target_path="$2"
    local label="$3"
    
    local test_dir="$STRESS_TEST_OUTPUT/${label}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$test_dir"
    
    log "Starting stress test for $label (type: $target_type)"
    log "Output directory: $test_dir"
    
    case "$target_type" in
        binary)
            deep_binary_analysis "$target_path" "$label" "$test_dir"
            deep_signature_check "$target_path" "$label" "$test_dir"
            file_integrity_check "$target_path" "$label" "$test_dir"
            timeline_analysis "$target_path" "$label" "$test_dir"
            process_behavior_analysis "$label" "$test_dir"
            ;;
        plist)
            plist_structure_analysis "$target_path" "$label" "$test_dir"
            file_integrity_check "$target_path" "$label" "$test_dir"
            timeline_analysis "$target_path" "$label" "$test_dir"
            ;;
        process)
            process_behavior_analysis "$label" "$test_dir"
            network_behavior_monitor "$label" "$test_dir" 30
            ;;
        *)
            alert "Unknown target type: $target_type"
            return 1
            ;;
    esac
    
    # Generate summary report
    log "Generating summary report..."
    echo "STRESS TEST SUMMARY FOR: $label" > "$test_dir/SUMMARY.txt"
    echo "TYPE: $target_type" >> "$test_dir/SUMMARY.txt"
    echo "PATH: $target_path" >> "$test_dir/SUMMARY.txt"
    echo "TIMESTAMP: $(date)" >> "$test_dir/SUMMARY.txt"
    echo "" >> "$test_dir/SUMMARY.txt"
    
    # Check for any alerts
    if grep -r "ALERT" "$test_dir" > /dev/null; then
        echo "STATUS: SUSPICIOUS" >> "$test_dir/SUMMARY.txt"
        alert "Stress test found suspicious indicators for $label"
    else
        echo "STATUS: PASSED" >> "$test_dir/SUMMARY.txt"
        ok "Stress test passed for $label"
    fi
    
    ok "Stress test complete: $test_dir"
    echo "$test_dir"
}

# Main entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -lt 3 ]]; then
        echo "Usage: $0 <target_type> <target_path> <label>"
        echo "  target_type: binary, plist, process"
        echo "  target_path: path to target"
        echo "  label: identifier for the target"
        exit 1
    fi
    
    run_stress_test "$@"
fi
