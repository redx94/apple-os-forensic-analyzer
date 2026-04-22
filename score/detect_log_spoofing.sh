#!/usr/bin/env bash
set -euo pipefail

# detect_log_spoofing.sh - Log Spoofing Detection Module
# Apple OS Forensic Analyzer
# Detects malware using os_log_create with fake Apple subsystem strings

OUTPUT_DIR="./log_spoof_output"
TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
OUTFILE="${OUTPUT_DIR}/log_spoof_report_${TIMESTAMP}.txt"
BASELINE_DIR="./log_baseline"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

mkdir -p "$OUTPUT_DIR"
log() { echo -e "${CYAN}[*]${NC} $*"; }
ok() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

TOTAL_CHECKED=0
TOTAL_ALERTS=0

# Known subsystem to expected process mappings
declare -a EXPECTED_SENDERS=(
  "com.apple.security.audit:auditd"
  "com.apple.securityd:securityd"
  "com.apple.system.log:syslogd"
  "com.apple.network:networkd"
  "com.apple.install:installerd"
)

get_expected_sender() {
  local subsystem="$1"
  for mapping in "${EXPECTED_SENDERS[@]}"; do
    local expected_subsystem="${mapping%%:*}"
    local expected_process="${mapping##*:}"
    if [[ "$subsystem" == "$expected_subsystem" ]]; then
      echo "$expected_process"
      return
    fi
  done
  echo "unknown"
}

# Detection Layer 1: Subsystem-Process Correlation
check_subsystem_correlation() {
  log "Checking subsystem-process correlation..."
  
  if ! command -v log &>/dev/null; then
    warn "log command not available, skipping unified log analysis"
    return
  fi

  local output_file="${OUTPUT_DIR}/subsystem_correlation_${TIMESTAMP}.txt"
  
  # Extract logs with com.apple.* subsystems and their sender paths
  log show --predicate 'subsystem CONTAINS "com.apple."' --style compact --last 1h 2>/dev/null | \
    grep -oE 'subsystem = [^,]+|senderImagePath = [^,]+' | \
    paste - - | \
    while read -r line; do
      [[ -z "$line" ]] && continue
      ((TOTAL_CHECKED++))
      
      local subsystem=$(echo "$line" | grep -oE 'subsystem = [^,]+' | cut -d' ' -f3)
      local sender=$(echo "$line" | grep -oE 'senderImagePath = [^,]+' | cut -d' ' -f3)
      
      if [[ -z "$subsystem" ]] || [[ -z "$sender" ]]; then
        continue
      fi
      
      local expected=$(get_expected_sender "$subsystem")
      local sender_name=$(basename "$sender")
      
      if [[ "$expected" != "unknown" ]] && [[ "$sender_name" != *"$expected"* ]]; then
        alert "Subsystem mismatch: $subsystem logs from $sender (expected: *$expected*)"
        echo "MISMATCH: $subsystem from $sender (expected: $expected)" >> "$output_file"
        ((TOTAL_ALERTS++))
      fi
    done
  
  if [[ -f "$output_file" ]]; then
    local mismatches=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    ok "Found $mismatches subsystem-process mismatches"
  fi
}

# Detection Layer 2: Log Entropy Analysis
check_log_entropy() {
  log "Analyzing log entropy patterns..."
  
  if ! command -v log &>/dev/null; then
    return
  fi

  local output_file="${OUTPUT_DIR}/entropy_analysis_${TIMESTAMP}.txt"
  
  # Count entries per subsystem in last hour
  log show --predicate 'subsystem CONTAINS "com.apple."' --style compact --last 1h 2>/dev/null | \
    grep -oE 'subsystem = [^,]+' | \
    sort | uniq -c | sort -rn | \
    while read -r count subsystem; do
      [[ -z "$count" ]] && continue
      ((TOTAL_CHECKED++))
      
      # Flag unusually high frequency (potential AI-generated log spam)
      if [[ "$count" -gt 100 ]]; then
        alert "Unusual log pattern: $count identical entries from $subsystem in 1-hour window"
        echo "HIGH_FREQUENCY: $subsystem count=$count" >> "$output_file"
        ((TOTAL_ALERTS++))
      fi
    done
  
  if [[ -f "$output_file" ]]; then
    local high_freq=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    ok "Found $high_freq high-frequency log patterns"
  fi
}

# Detection Layer 3: Immutable Log Verification
check_log_integrity() {
  log "Verifying log integrity against baseline..."
  
  if [[ ! -d "$BASELINE_DIR" ]]; then
    warn "No baseline directory found at $BASELINE_DIR"
    warn "Run with --baseline-save to create baseline"
    return
  fi
  
  local baseline_file="${BASELINE_DIR}/log_hashes.txt"
  if [[ ! -f "$baseline_file" ]]; then
    warn "No baseline hash file found"
    return
  fi
  
  local current_hashes="${OUTPUT_DIR}/current_hashes_${TIMESTAMP}.txt"
  
  # Generate current log hashes
  if command -v log &>/dev/null; then
    log show --predicate 'eventMessage CONTAINS "com.apple"' --style compact --last 1h 2>/dev/null | \
      shasum -a 256 | cut -d' ' -f1 > "$current_hashes"
  fi
  
  if [[ -f "$current_hashes" ]]; then
    local new_entries=$(comm -13 <(sort "$baseline_file") <(sort "$current_hashes") | wc -l 2>/dev/null || echo "0")
    local modified=$(comm -23 <(sort "$baseline_file") <(sort "$current_hashes") | wc -l 2>/dev/null || echo "0")
    
    ((TOTAL_CHECKED++))
    ok "Verified log entries: $new_entries new, $modified modified"
    
    if [[ "$new_entries" -gt 50 ]] || [[ "$modified" -gt 10 ]]; then
      alert "Significant log drift detected: $new_entries new, $modified modified entries"
      ((TOTAL_ALERTS++))
    fi
  fi
}

# Detection Layer 4: Cross-System Correlation
check_cross_system_correlation() {
  log "Checking cross-system log correlation..."
  
  local unified_count=0
  local syslog_count=0
  
  # Count unified log entries
  if command -v log &>/dev/null; then
    unified_count=$(log show --predicate 'subsystem CONTAINS "com.apple"' --style compact --last 1h 2>/dev/null | wc -l 2>/dev/null || echo "0")
  fi
  
  # Count syslog entries
  if [[ -f "/var/log/system.log" ]]; then
    syslog_count=$(grep -c "com.apple" /var/log/system.log 2>/dev/null || echo "0")
  fi
  
  ((TOTAL_CHECKED++))
  ok "Unified logs: $unified_count entries, Syslog: $syslog_count entries"
  
  # Flag significant discrepancies
  local ratio=0
  if [[ "$syslog_count" -gt 0 ]]; then
    ratio=$((unified_count / syslog_count))
  fi
  
  if [[ "$ratio" -gt 100 ]] || [[ "$ratio" -lt 1 ]]; then
    alert "Unusual log ratio between unified logs and syslog (ratio: $ratio:1)"
    ((TOTAL_ALERTS++))
  fi
}

save_baseline() {
  log "Saving log baseline to $BASELINE_DIR"
  mkdir -p "$BASELINE_DIR"
  
  local baseline_file="${BASELINE_DIR}/log_hashes.txt"
  
  if command -v log &>/dev/null; then
    log show --predicate 'eventMessage CONTAINS "com.apple"' --style compact --last 1h 2>/dev/null | \
      shasum -a 256 > "$baseline_file"
  fi
  
  ok "Baseline saved to $baseline_file"
}

main() {
  echo "=== Log Spoofing Detection ===" | tee "$OUTFILE"
  echo "Timestamp: $TIMESTAMP" | tee -a "$OUTFILE"
  echo "" | tee -a "$OUTFILE"
  
  local baseline_mode=false
  local check_correlation=true
  local check_entropy=true
  local check_integrity=true
  local check_cross=true
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --baseline-save)
        baseline_mode=true
        shift
        ;;
      --no-correlation)
        check_correlation=false
        shift
        ;;
      --no-entropy)
        check_entropy=false
        shift
        ;;
      --no-integrity)
        check_integrity=false
        shift
        ;;
      --no-cross)
        check_cross=false
        shift
        ;;
      *)
        warn "Unknown option: $1"
        shift
        ;;
    esac
  done
  
  if [[ "$baseline_mode" == true ]]; then
    save_baseline
    exit 0
  fi
  
  if [[ "$check_correlation" == true ]]; then
    check_subsystem_correlation 2>&1 | tee -a "$OUTFILE"
  fi
  
  if [[ "$check_entropy" == true ]]; then
    check_log_entropy 2>&1 | tee -a "$OUTFILE"
  fi
  
  if [[ "$check_integrity" == true ]]; then
    check_log_integrity 2>&1 | tee -a "$OUTFILE"
  fi
  
  if [[ "$check_cross" == true ]]; then
    check_cross_system_correlation 2>&1 | tee -a "$OUTFILE"
  fi
  
  echo "" | tee -a "$OUTFILE"
  echo "=== Summary ===" | tee -a "$OUTFILE"
  echo "Total checks performed: $TOTAL_CHECKED" | tee -a "$OUTFILE"
  echo "Total alerts: $TOTAL_ALERTS" | tee -a "$OUTFILE"
  
  if [[ "$TOTAL_ALERTS" -eq 0 ]]; then
    ok "No log spoofing detected"
  else
    alert "Detected $TOTAL_ALERTS potential log spoofing indicators"
  fi
  
  echo "Report saved to: $OUTFILE"
}

main "$@"
