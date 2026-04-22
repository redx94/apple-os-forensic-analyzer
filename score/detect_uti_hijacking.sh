#!/usr/bin/env bash
set -euo pipefail

# detect_uti_hijacking.sh - UTI Hijacking Detection Module
# Apple OS Forensic Analyzer
# Detects malicious apps hijacking file type handlers via UTI declarations

OUTPUT_DIR="./uti_hijack_output"
TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
OUTFILE="${OUTPUT_DIR}/uti_hijack_report_${TIMESTAMP}.txt"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

mkdir -p "$OUTPUT_DIR"
log() { echo -e "${CYAN}[*]${NC} $*"; }
ok() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

TOTAL_CHECKED=0
TOTAL_ALERTS=0
TOTAL_SUSPICIOUS=0

# Apple-private UTIs that should only be claimed by Apple apps
APPLE_PRIVATE_UTIS=(
  "com.apple.quicktime-movie"
  "com.apple.m4v-audio"
  "com.apple.m4v-video"
  "com.apple.protected-mpeg-4-audio"
  "com.apple.protected-mpeg-4-video"
  "com.apple.iwork.keynote.key"
  "com.apple.iwork.pages.pages"
  "com.apple.iwork.numbers.numbers"
  "com.apple.disk-image"
  "com.apple.package"
  "com.apple.application-bundle"
)

# Common UTIs that are high-value hijacking targets
HIGH_VALUE_UTIS=(
  "public.jpeg"
  "public.png"
  "public.tiff"
  "public.image"
  "public.text"
  "public.plain-text"
  "public.html"
  "public.url"
  "public.file-url"
  "com.adobe.pdf"
)

is_apple_private_uti() {
  local uti="$1"
  for apple_uti in "${APPLE_PRIVATE_UTIS[@]}"; do
    if [[ "$uti" == "$apple_uti" ]]; then
      return 0
    fi
  done
  return 1
}

is_high_value_uti() {
  local uti="$1"
  for high_uti in "${HIGH_VALUE_UTIS[@]}"; do
    if [[ "$uti" == "$high_uti" ]]; then
      return 0
    fi
  done
  return 1
}

# Detection Layer 1: UTI Registry Audit
check_uti_registry() {
  log "Auditing UTI registry..."
  
  local apps=()
  apps+=("/Applications"/*.app)
  apps+=("~/Applications"/*.app)
  
  local output_file="${OUTPUT_DIR}/uti_registry_audit_${TIMESTAMP}.txt"
  
  for app in "${apps[@]}"; do
    [[ ! -d "$app" ]] && continue
    
    local info_plist="${app}/Contents/Info.plist"
    [[ ! -f "$info_plist" ]] && continue
    
    local bundle_id=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$info_plist" 2>/dev/null || echo "unknown")
    ((TOTAL_CHECKED++))
    
    # Check if app declares CFBundleDocumentTypes
    if /usr/libexec/PlistBuddy -c "Print :CFBundleDocumentTypes" "$info_plist" &>/dev/null; then
      local doc_types_count=$(/usr/libexec/PlistBuddy -c "Print :CFBundleDocumentTypes" "$info_plist" 2>/dev/null | grep -c "Dict" || echo "0")
      
      # Extract UTIs from document types
      local utis=$(/usr/libexec/PlistBuddy -c "Print :CFBundleDocumentTypes" "$info_plist" 2>/dev/null | \
        grep -A 10 "CFBundleTypeExtensions" | grep -oE 'public\.[a-z-]+' || \
        /usr/libexec/PlistBuddy -c "Print :CFBundleDocumentTypes" "$info_plist" 2>/dev/null | \
        grep -oE 'com\.[a-z.-]+' || true)
      
      for uti in $utis; do
        [[ -z "$uti" ]] && continue
        
        # Check if claiming Apple-private UTI
        if is_apple_private_uti "$uti"; then
          # Verify it's actually signed by Apple
          if ! codesign -dv "$app" 2>/dev/null | grep -q "Apple"; then
            alert "Non-Apple app claiming Apple-private UTI: $uti"
            echo "APPLE_UTI_CLAIM: $app ($bundle_id) claims $uti" >> "$output_file"
            ((TOTAL_ALERTS++))
            ((TOTAL_SUSPICIOUS++))
          fi
        fi
        
        # Check if claiming high-value UTI
        if is_high_value_uti "$uti"; then
          echo "HIGH_VALUE_UTI: $app ($bundle_id) claims $uti" >> "$output_file"
        fi
      done
    fi
  done
  
  if [[ -f "$output_file" ]]; then
    local claims=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    ok "Found $claims UTI claims analyzed"
  fi
}

# Detection Layer 2: Bundle-ID-to-UTI Correlation
check_bundle_uti_correlation() {
  log "Checking bundle-ID to UTI correlation..."
  
  local output_file="${OUTPUT_DIR}/bundle_uti_correlation_${TIMESTAMP}.txt"
  
  local apps=()
  apps+=("/Applications"/*.app)
  apps+=("~/Applications"/*.app)
  
  for app in "${apps[@]}"; do
    [[ ! -d "$app" ]] && continue
    
    local info_plist="${app}/Contents/Info.plist"
    [[ ! -f "$info_plist" ]] && continue
    
    local bundle_id=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$info_plist" 2>/dev/null || echo "unknown")
    ((TOTAL_CHECKED++))
    
    # If bundle ID starts with com.apple.*, verify it's actually signed by Apple
    if [[ "$bundle_id" == com.apple.* ]]; then
      if ! codesign -dv "$app" 2>/dev/null | grep -q "Apple"; then
        alert "Non-Apple app using com.apple.* bundle ID: $bundle_id"
        echo "FAKE_APPLE_BUNDLE: $app ($bundle_id)" >> "$output_file"
        ((TOTAL_ALERTS++))
        ((TOTAL_SUSPICIOUS++))
      fi
    fi
  done
  
  if [[ -f "$output_file" ]]; then
    local fakes=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    ok "Found $fakes fake Apple bundle IDs"
  fi
}

# Detection Layer 3: Default Handler Analysis
check_default_handlers() {
  log "Checking default handler changes..."
  
  local ls_plist="$HOME/Library/Preferences/com.apple.LaunchServices.plist"
  local output_file="${OUTPUT_DIR}/default_handlers_${TIMESTAMP}.txt"
  
  if [[ -f "$ls_plist" ]]; then
    # Extract LSHandlers entries
    /usr/libexec/PlistBuddy -c "Print :LSHandlers" "$ls_plist" 2>/dev/null | \
      while read -r line; do
        [[ -z "$line" ]] && continue
        ((TOTAL_CHECKED++))
        
        # Look for UTI and handler pairs
        if echo "$line" | grep -qE "LSHandlerContentType"; then
          local uti=$(echo "$line" | grep -oE 'public\.[a-z-]+|com\.[a-z.-]+' || echo "unknown")
          if is_high_value_uti "$uti"; then
            echo "HIGH_VALUE_HANDLER: UTI=$uti" >> "$output_file"
          fi
        fi
      done
  fi
  
  if [[ -f "$output_file" ]]; then
    local handlers=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    ok "Analyzed $handlers default handler entries"
  fi
}

# Detection Layer 4: Signature Verification
check_signatures() {
  log "Verifying signatures of UTI-claiming apps..."
  
  local output_file="${OUTPUT_DIR}/signature_check_${TIMESTAMP}.txt"
  local unsigned_count=0
  
  local apps=()
  apps+=("/Applications"/*.app)
  apps+=("~/Applications"/*.app)
  
  for app in "${apps[@]}"; do
    [[ ! -d "$app" ]] && continue
    
    local info_plist="${app}/Contents/Info.plist"
    [[ ! -f "$info_plist" ]] && continue
    
    # Check if app claims any document types
    if /usr/libexec/PlistBuddy -c "Print :CFBundleDocumentTypes" "$info_plist" &>/dev/null; then
      ((TOTAL_CHECKED++))
      
      # Verify signature
      if ! codesign -v "$app" 2>/dev/null; then
        alert "Unsigned or invalid signature: $app"
        echo "INVALID_SIGNATURE: $app" >> "$output_file"
        ((TOTAL_ALERTS++))
        ((unsigned_count++))
      fi
    fi
  done
  
  ok "Found $unsigned_count unsigned apps with UTI claims"
}

# Detection Layer 5: AI-Forgery Heuristics
check_ai_forgery_heuristics() {
  log "Checking for AI-forgery patterns..."
  
  local output_file="${OUTPUT_DIR}/ai_forgery_${TIMESTAMP}.txt"
  
  local apps=()
  apps+=("/Applications"/*.app)
  apps+=("~/Applications"/*.app)
  
  for app in "${apps[@]}"; do
    [[ ! -d "$app" ]] && continue
    
    local info_plist="${app}/Contents/Info.plist"
    [[ ! -f "$info_plist" ]] && continue
    
    ((TOTAL_CHECKED++))
    
    # Check for suspiciously perfect plist formatting
    local line_count=$(wc -l < "$info_plist" 2>/dev/null || echo "0")
    local unique_lines=$(sort "$info_plist" 2>/dev/null | uniq | wc -l || echo "0")
    
    # If ratio is too high (near 1.0), might be AI-generated
    if [[ "$line_count" -gt 10 ]]; then
      local ratio=$(echo "scale=2; $unique_lines / $line_count" | bc 2>/dev/null || echo "0")
      if (( $(echo "$ratio > 0.95" | bc -l 2>/dev/null || echo "0") )); then
        warn "Suspiciously perfect plist formatting: $app (ratio: $ratio)"
        echo "PERFECT_FORMATTING: $app ratio=$ratio" >> "$output_file"
        ((TOTAL_SUSPICIOUS++))
      fi
    fi
  done
  
  if [[ -f "$output_file" ]]; then
    local suspicious=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    ok "Found $suspicious suspicious formatting patterns"
  fi
}

main() {
  echo "=== UTI Hijacking Detection ===" | tee "$OUTFILE"
  echo "Timestamp: $TIMESTAMP" | tee -a "$OUTFILE"
  echo "" | tee -a "$OUTFILE"
  
  local check_registry=true
  local check_correlation=true
  local check_handlers=true
  local check_signatures=true
  local check_ai=true
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-registry)
        check_registry=false
        shift
        ;;
      --no-correlation)
        check_correlation=false
        shift
        ;;
      --no-handlers)
        check_handlers=false
        shift
        ;;
      --no-signatures)
        check_signatures=false
        shift
        ;;
      --no-ai)
        check_ai=false
        shift
        ;;
      *)
        warn "Unknown option: $1"
        shift
        ;;
    esac
  done
  
  if [[ "$check_registry" == true ]]; then
    check_uti_registry 2>&1 | tee -a "$OUTFILE"
  fi
  
  if [[ "$check_correlation" == true ]]; then
    check_bundle_uti_correlation 2>&1 | tee -a "$OUTFILE"
  fi
  
  if [[ "$check_handlers" == true ]]; then
    check_default_handlers 2>&1 | tee -a "$OUTFILE"
  fi
  
  if [[ "$check_signatures" == true ]]; then
    check_signatures 2>&1 | tee -a "$OUTFILE"
  fi
  
  if [[ "$check_ai" == true ]]; then
    check_ai_forgery_heuristics 2>&1 | tee -a "$OUTFILE"
  fi
  
  echo "" | tee -a "$OUTFILE"
  echo "=== Summary ===" | tee -a "$OUTFILE"
  echo "Total checks performed: $TOTAL_CHECKED" | tee -a "$OUTFILE"
  echo "Total alerts: $TOTAL_ALERTS" | tee -a "$OUTFILE"
  echo "Total suspicious: $TOTAL_SUSPICIOUS" | tee -a "$OUTFILE"
  
  if [[ "$TOTAL_ALERTS" -eq 0 ]]; then
    ok "No UTI hijacking detected"
  else
    alert "Detected $TOTAL_ALERTS potential UTI hijacking indicators"
  fi
  
  if [[ "$TOTAL_SUSPICIOUS" -gt 0 ]]; then
    warn "Found $TOTAL_SUSPICIOUS suspicious patterns requiring manual review"
  fi
  
  echo "Report saved to: $OUTFILE"
}

main "$@"
