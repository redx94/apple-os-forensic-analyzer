#!/usr/bin/env bash
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
DIRS=("/Library/LaunchDaemons" "/Library/LaunchAgents" "${HOME}/Library/LaunchAgents")
OUT_DIR="./verify_trust_output"; TIMESTAMP=$(date "+%Y%m%d_%H%M%S"); REPORT="${OUT_DIR}/trust_${TIMESTAMP}.txt"
mkdir -p "$OUT_DIR"
log()   { echo -e "${CYAN}[*]${NC} $*" | tee -a "$REPORT"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*" | tee -a "$REPORT"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$REPORT"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*" | tee -a "$REPORT"; }

check_sig() {
    local b="$1"; [[ ! -f "$b" ]] && warn "Binary not found: $b" && return
    local s; s=$(codesign -dv --verbose=4 "$b" 2>&1 || echo "NOT_SIGNED")
    echo "$s" | grep -q "NOT_SIGNED\|code object is not signed" && alert "UNSIGNED: $b" && return
    local auth; auth=$(echo "$s" | grep "Authority=" | head -1 | cut -d= -f2)
    echo "$auth" | grep -qi "Apple" && ok "Apple signed: $b  [$auth]" || alert "NON-APPLE SIG on com.apple.* binary!  Auth=$auth  Binary=$b"
}

check_ents() {
    local b="$1"; local e; e=$(codesign -d --entitlements :- "$b" 2>/dev/null || echo "NONE")
    [[ "$e" == "NONE" ]] && return
    local DANGER=("com.apple.private.tcc.allow" "com.apple.rootless.install" "com.apple.security.get-task-allow" "com.apple.private.admin.writeconfig")
    for d in "${DANGER[@]}"; do echo "$e" | grep -q "$d" && alert "Dangerous entitlement: $d  ($b)"; done
}

check_loc() {
    local b="$1"; local TRUSTED=("/System/Library" "/usr/bin" "/usr/sbin" "/usr/libexec" "/bin" "/sbin" "/Library/Apple")
    local ok_loc=false; for p in "${TRUSTED[@]}"; do [[ "$b" == "$p"* ]] && ok_loc=true && break; done
    $ok_loc && ok "Trusted location: $b" || alert "SUSPICIOUS LOCATION: $b"
}

check_macho_load_commands() {
    local b="$1"; [[ ! -f "$b" ]] && return
    
    # v3.0 Enhancement: Mach-O Load Command Deep Analysis
    # Detects Dylib Hijacking via suspicious LC_RPATH and LC_LOAD_DYLIB commands
    
    if ! command -v otool &>/dev/null; then
        warn "otool not available - skipping Mach-O load command analysis"
        return
    fi
    
    log "Analyzing Mach-O load commands for: $b"
    
    # Get all load commands
    local load_commands
    load_commands=$(otool -l "$b" 2>/dev/null || true)
    
    if [[ -z "$load_commands" ]]; then
        return
    fi
    
    # Suspicious load command patterns
    local suspicious_rpaths=(
        "@loader_path/../"
        "@executable_path/../"
        "/tmp/"
        "/private/var/"
        "/Users/Shared/"
        "~/Library/"
        "@rpath/./"
    )
    
    # Check LC_RPATH entries
    local rpath_found=false
    if echo "$load_commands" | grep -q "LC_RPATH"; then
        while IFS= read -r line; do
            if echo "$line" | grep -q "path "; then
                local rpath=$(echo "$line" | sed 's/.*path \(.*\) (.*/\1/')
                
                for susp in "${suspicious_rpaths[@]}"; do
                    if echo "$rpath" | grep -q "$susp"; then
                        alert "SUSPICIOUS LC_RPATH: $rpath in $b (potential dylib hijacking)"
                        echo "  Load command: $line" >> "$REPORT"
                        rpath_found=true
                    fi
                done
            fi
        done <<< "$load_commands"
    fi
    
    # Check LC_LOAD_DYLIB commands pointing to non-standard locations
    local suspicious_dylibs=0
    if echo "$load_commands" | grep -q "LC_LOAD_DYLIB"; then
        while IFS= read -r line; do
            if echo "$line" | grep -q "name "; then
                local dylib=$(echo "$line" | sed 's/.*name \(.*\) (.*/\1/')
                
                # Check for non-standard library locations
                if echo "$dylib" | grep -qE "(/tmp/|/private/var/|/Users/[^/]+/\.|/usr/local/|@loader_path/\.\.|@executable_path/\.\.)"; then
                    alert "SUSPICIOUS LC_LOAD_DYLIB: $dylib in $b (non-standard location)"
                    echo "  Load command: $line" >> "$REPORT"
                    suspicious_dylibs=$((suspicious_dylibs + 1))
                fi
            fi
        done <<< "$load_commands"
    fi
    
    # Check for LC_LOAD_WEAK_DYLIB (often used in dylib hijacking)
    if echo "$load_commands" | grep -q "LC_LOAD_WEAK_DYLIB"; then
        while IFS= read -r line; do
            if echo "$line" | grep -q "name "; then
                local weak_dylib=$(echo "$line" | sed 's/.*name \(.*\) (.*/\1/')
                # Weak dylibs from non-standard locations are highly suspicious
                if echo "$weak_dylib" | grep -qE "(/tmp/|/private/var/|/usr/local/)"; then
                    alert "HIGH RISK: LC_LOAD_WEAK_DYLIB from suspicious path: $weak_dylib in $b"
                    echo "  Load command: $line" >> "$REPORT"
                fi
            fi
        done <<< "$load_commands"
    fi
    
    if [[ "$rpath_found" == "false" && "$suspicious_dylibs" -eq 0 ]]; then
        ok "Mach-O load commands appear normal"
    fi
}

inspect() {
    local b="$1"; echo "" | tee -a "$REPORT"; echo -e "${BOLD}=== $b ===${NC}" | tee -a "$REPORT"
    check_loc "$b"; check_sig "$b"; check_ents "$b"; check_macho_load_commands "$b"
}

scan_plists() {
    log "Scanning launchd plist directories..."
    for dir in "${DIRS[@]}"; do
        [[ -d "$dir" ]] || continue; log "Dir: $dir"
        for plist in "$dir"/*.plist; do
            [[ -f "$plist" ]] || continue
            local label; label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null || echo "")
            local binary; binary=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null || echo "")
            [[ "$label" == com.apple.* ]] && { log "Plist: $plist | Label: $label"; [[ -n "$binary" && -f "$binary" ]] && inspect "$binary" || warn "Binary missing: $binary"; }
        done
    done
}

echo -e "${BOLD}=== Apple OS Forensic Trust Verifier ===${NC}" | tee "$REPORT"
MODE="${1:---plists}"
case "$MODE" in
    --pid)    [[ -z "${2:-}" ]] && echo "Usage: $0 --pid <PID>" && exit 1
              b=$(ps -p "$2" -o comm= 2>/dev/null); pp=$(ps -p "$2" -o ppid= 2>/dev/null | tr -d ' ')
              pb=$(ps -p "$pp" -o comm= 2>/dev/null || echo "?")
              log "PID $2: $b  Parent: $pp ($pb)"; inspect "$b" ;;
    --binary) [[ -z "${2:-}" ]] && echo "Usage: $0 --binary <PATH>" && exit 1; inspect "$2" ;;
    *)        scan_plists ;;
esac
ok "Report: $REPORT"
