#!/usr/bin/env bash
# ============================================================
# detect_agents.sh - Enhanced Persistence Scanner with Behavioral Detection
# ============================================================
# Apple OS Forensic Analyzer
#
# Purpose:
# Scans launchd persistence directories for suspicious agents
# using behavioral detection: namespace squatting, path validation,
# signature verification, MachServices, KeepAlive, Sockets, symlinks.
# ============================================================

set -euo pipefail

SCAN_DIRS=("/Library/LaunchDaemons" "/Library/LaunchAgents" "/System/Library/LaunchDaemons" "/System/Library/LaunchAgents")
TRUSTED_PATHS=("/System/Library" "/usr/bin" "/usr/sbin" "/usr/libexec" "/bin" "/sbin" "/Library/Apple")
SUSPICIOUS_PATTERNS=("com.apple.update" "com.apple.system.update" "com.apple.crash" "com.apple.helper" "com.apple.analytics" "com.apple.metricsd")

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

TOTAL_SCANNED=0
TOTAL_ALERTS=0

# Mode flags
AI_MODE=false
WATCH_MODE=false
BASELINE_SAVE=false
BASELINE_DIFF=false
BASELINE_DIR="./agent_baseline"

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ai-mode)
      AI_MODE=true
      shift
      ;;
    --watch)
      WATCH_MODE=true
      shift
      ;;
    --baseline-save)
      BASELINE_SAVE=true
      shift
      ;;
    --baseline-diff)
      BASELINE_DIFF=true
      shift
      ;;
    *)
      warn "Unknown option: $1"
      shift
      ;;
  esac
done

echo -e "${BOLD}=== Apple OS Forensic Persistence Scanner ===${NC}"
log "Scanning persistence directories..."

check_namespace_squatting() {
    local label="$1"
    local binary="$2"
    
    # Flag if label claims Apple but binary isn't in system paths
    if [[ "$label" == com.apple.* && -n "$binary" && "$binary" != "N/A" ]]; then
        local is_trusted=false
        for path in "${TRUSTED_PATHS[@]}"; do
            if [[ "$binary" == "$path"* ]]; then
                is_trusted=true
                break
            fi
        done
        
        if [[ "$is_trusted" == "false" ]]; then
            alert "NAMESPACE SQUATTING: $label → $binary (non-system path)"
            TOTAL_ALERTS=$((TOTAL_ALERTS + 1))
            return 1
        fi
    fi
    return 0
}

check_binary_signature() {
    local binary="$1"
    local label="$2"
    
    if [[ -z "$binary" || "$binary" == "N/A" || ! -f "$binary" ]]; then
        return 0
    fi
    
    # Check if it's a script (Apple doesn't sign scripts)
    local file_type
    file_type=$(file "$binary" 2>/dev/null)
    if [[ "$file_type" == *"script"* ]] || [[ "$file_type" == *"text executable"* ]]; then
        log "Skipping signature check for script: $binary"
        return 0
    fi
    
    # Check if unsigned
    if ! codesign -v "$binary" 2>/dev/null; then
        alert "UNSIGNED APPLE-CLAIMING BINARY: $label → $binary"
        TOTAL_ALERTS=$((TOTAL_ALERTS + 1))
        return 1
    fi
    
    # Check signature authority
    local sig_info
    sig_info=$(codesign -dv --verbose=4 "$binary" 2>&1 || true)
    local authority
    authority=$(echo "$sig_info" | grep "Authority=" | head -1 | cut -d= -f2)
    
    if [[ "$label" == com.apple.* ]]; then
        if ! echo "$authority" | grep -qiE "Apple|Software Signing"; then
            alert "NON-APPLE SIGNATURE ON APPLE NAMESPACE: $label → $binary (Signer: $authority)"
            TOTAL_ALERTS=$((TOTAL_ALERTS + 1))
            return 1
        fi
    fi
    return 0
}

check_symlink_binary() {
    local binary="$1"
    local label="$2"
    
    if [[ -z "$binary" || "$binary" == "N/A" || ! -e "$binary" ]]; then
        return 0
    fi
    
    if [[ -L "$binary" ]]; then
        local target
        target=$(readlink "$binary")
        warn "SYMLINKED BINARY: $label → $binary -> $target"
        TOTAL_ALERTS=$((TOTAL_ALERTS + 1))
    fi
}

check_additional_keys() {
    local plist="$1"
    local label="$2"

    # Check MachServices (XPC service exposure)
    local mach_services
    mach_services=$(/usr/libexec/PlistBuddy -c "Print :MachServices" "$plist" 2>/dev/null || echo "")
    if [[ -n "$mach_services" && "$mach_services" != *"does not exist"* ]]; then
        log "MachServices found in $label"
    fi

    # Check KeepAlive (persistent restart)
    local keep_alive
    keep_alive=$(/usr/libexec/PlistBuddy -c "Print :KeepAlive" "$plist" 2>/dev/null || echo "")
    if [[ "$keep_alive" == "true" ]]; then
        warn "KeepAlive=true in $label (persistence mechanism)"
    fi

    # Check Sockets (network listening)
    local sockets
    sockets=$(/usr/libexec/PlistBuddy -c "Print :Sockets" "$plist" 2>/dev/null || echo "")
    if [[ -n "$sockets" && "$sockets" != *"does not exist"* ]]; then
        log "Network sockets defined in $label"
    fi

    # AI Mode: Check timing patterns
    if [[ "$AI_MODE" == true ]]; then
        check_timing_patterns "$plist" "$label"
    fi
}

check_timing_patterns() {
    local plist="$1"
    local label="$2"

    # Check StartInterval for unusual timing (prime numbers used to evade periodic scans)
    local start_interval
    start_interval=$(/usr/libexec/PlistBuddy -c "Print :StartInterval" "$plist" 2>/dev/null || echo "")
    if [[ -n "$start_interval" && "$start_interval" != *"does not exist"* ]]; then
        # Flag intervals that are prime numbers (common evasion technique)
        local primes=(2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79 83 89 97 101 103 107 109 113 127 131 137 139 149 151 157 163 167 173 179 181 191 193 197 199)
        for prime in "${primes[@]}"; do
            if [[ "$start_interval" == "$prime" ]]; then
                warn "AI-DETECTION: Prime number interval ($prime) in $label (possible evasion pattern)"
                TOTAL_ALERTS=$((TOTAL_ALERTS + 1))
                break
            fi
        done
    fi

    # Check for UserName privilege escalation
    local username
    username=$(/usr/libexec/PlistBuddy -c "Print :UserName" "$plist" 2>/dev/null || echo "")
    if [[ -n "$username" && "$username" != *"does not exist"* ]]; then
        if [[ "$username" == "root" ]] && [[ "$label" != com.apple.* ]]; then
            alert "PRIVILEGE ESCALATION: $label running as root"
            TOTAL_ALERTS=$((TOTAL_ALERTS + 1))
        fi
    fi
}

check_plist_entropy() {
    local plist="$1"
    local label="$2"

    if [[ "$AI_MODE" != true ]]; then
        return
    fi

    # Check for suspiciously perfect plist formatting
    local line_count=$(wc -l < "$plist" 2>/dev/null || echo "0")
    if [[ "$line_count" -gt 10 ]]; then
        local unique_lines=$(sort "$plist" 2>/dev/null | uniq | wc -l || echo "0")
        if [[ "$line_count" -gt 0 ]]; then
            local ratio=$(echo "scale=2; $unique_lines / $line_count" | bc 2>/dev/null || echo "0")
            if (( $(echo "$ratio > 0.95" | bc -l 2>/dev/null || echo "0") )); then
                warn "AI-DETECTION: Suspiciously perfect plist formatting in $label (ratio: $ratio)"
            fi
        fi
    fi
}

save_baseline() {
    log "Saving baseline to $BASELINE_DIR"
    mkdir -p "$BASELINE_DIR"

    local baseline_file="${BASELINE_DIR}/baseline_$(date +%Y%m%d_%H%M%S).txt"

    for dir in "${SCAN_DIRS[@]}"; do
        [[ ! -d "$dir" ]] && continue
        for plist in "$dir"/*.plist; do
            [[ ! -f "$plist" ]] && continue
            local label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null || echo "unknown")
            local binary=$(/usr/libexec/PlistBuddy -c "Print :Program" "$plist" 2>/dev/null || /usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null || echo "N/A")
            local hash=$(shasum -a 256 "$plist" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
            echo "$label|$binary|$hash" >> "$baseline_file"
        done
    done

    ok "Baseline saved to $baseline_file"
}

diff_baseline() {
    if [[ ! -d "$BASELINE_DIR" ]]; then
        warn "No baseline directory found. Run --baseline-save first."
        return
    fi

    local latest_baseline=$(ls -t "$BASELINE_DIR"/baseline_*.txt 2>/dev/null | head -1)
    if [[ -z "$latest_baseline" ]]; then
        warn "No baseline file found. Run --baseline-save first."
        return
    fi

    log "Comparing against baseline: $latest_baseline"

    local current_file="${BASELINE_DIR}/current_$(date +%Y%m%d_%H%M%S).txt"

    for dir in "${SCAN_DIRS[@]}"; do
        [[ ! -d "$dir" ]] && continue
        for plist in "$dir"/*.plist; do
            [[ ! -f "$plist" ]] && continue
            local label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null || echo "unknown")
            local binary=$(/usr/libexec/PlistBuddy -c "Print :Program" "$plist" 2>/dev/null || /usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null || echo "N/A")
            local hash=$(shasum -a 256 "$plist" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
            echo "$label|$binary|$hash" >> "$current_file"
        done
    done

    # Find new entries
    local new_entries=$(comm -13 <(sort "$latest_baseline") <(sort "$current_file") || true)
    if [[ -n "$new_entries" ]]; then
        alert "NEW PLIST ENTRIES DETECTED:"
        echo "$new_entries" | while read -r entry; do
            alert "  $entry"
            TOTAL_ALERTS=$((TOTAL_ALERTS + 1))
        done
    fi

    # Find modified entries
    while IFS='|' read -r label binary hash; do
        local baseline_hash=$(grep "^$label|" "$latest_baseline" | cut -d'|' -f3)
        if [[ -n "$baseline_hash" && "$baseline_hash" != "$hash" ]]; then
            alert "MODIFIED PLIST: $label (hash changed)"
            TOTAL_ALERTS=$((TOTAL_ALERTS + 1))
        fi
    done < "$current_file"

    ok "Baseline comparison complete"
}

watch_mode() {
    log "Starting watch mode (monitoring launchd directories for changes)..."
    warn "Press Ctrl+C to stop watching"

    if command -v fswatch &>/dev/null; then
        fswatch -o -1 "${SCAN_DIRS[@]}" | while read -r event; do
            log "Change detected: $event"
            echo "--- Running scan ---"
            # Reset counters for each scan
            TOTAL_SCANNED=0
            TOTAL_ALERTS=0
            # Run the scan (would need to refactor scan logic into function)
        done
    else
        warn "fswatch not installed. Install with: brew install fswatch"
    fi
}

# Handle special modes
if [[ "$BASELINE_SAVE" == true ]]; then
    save_baseline
    exit 0
fi

if [[ "$BASELINE_DIFF" == true ]]; then
    diff_baseline
    exit 0
fi

if [[ "$WATCH_MODE" == true ]]; then
    watch_mode
    exit 0
fi

# Main scanning loop
for dir in "${SCAN_DIRS[@]}"; do
    [[ ! -d "$dir" ]] && continue
    log "Scanning: $dir"

    for plist in "$dir"/*.plist; do
        [[ ! -f "$plist" ]] && continue
        TOTAL_SCANNED=$((TOTAL_SCANNED + 1))

        label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null || grep -A1 "<key>Label</key>" "$plist" | grep "<string>" | sed -E 's/.*<string>(.*)<\/string>.*/\1/')

        [[ -z "$label" ]] && continue

        # Try Program first (full path), fall back to ProgramArguments:0 (binary name only)
        binary=$(/usr/libexec/PlistBuddy -c "Print :Program" "$plist" 2>/dev/null || /usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null || echo "N/A")

        # Pattern-based detection
        for pat in "${SUSPICIOUS_PATTERNS[@]}"; do
            if [[ "$label" == *"$pat"* ]]; then
                alert "SUSPICIOUS LABEL PATTERN: $label ($plist)"
                TOTAL_ALERTS=$((TOTAL_ALERTS + 1))
            fi
        done

        # Behavioral detection
        check_namespace_squatting "$label" "$binary" || true
        check_binary_signature "$binary" "$label" || true
        check_symlink_binary "$binary" "$label" || true
        check_additional_keys "$plist" "$label" || true

        # AI Mode: Check plist entropy
        check_plist_entropy "$plist" "$label"
    done
done

echo -e "${BOLD}=== Scan Summary ===${NC}"
ok "Total plists scanned: $TOTAL_SCANNED"
if [[ $TOTAL_ALERTS -gt 0 ]]; then
    alert "Total alerts: $TOTAL_ALERTS"
    alert "REVIEW ALL ALERTS ABOVE"
else
    ok "No suspicious persistence detected"
fi

# Always return 0 - alerts are informational, not errors
exit 0

