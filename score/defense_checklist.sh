#!/usr/bin/env bash
set -euo pipefail

# defense_checklist.sh - Integrated Defense Checklist Engine
# Apple OS Forensic Analyzer
# Runs all 5 core defense checks and produces unified risk report

OUTPUT_DIR="./defense_checklist_output"
TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
REPORT_FILE="${OUTPUT_DIR}/defense_report_${TIMESTAMP}.json"
BASELINE_DIR="./defense_baseline"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

mkdir -p "$OUTPUT_DIR"
log() { echo -e "${CYAN}[*]${NC} $*"; }
ok() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

# Check weights (sum to 100%)
WEIGHT_PARENTAGE=20
WEIGHT_NETWORK=20
WEIGHT_SIGNING=25
WEIGHT_FILESYSTEM=20
WEIGHT_LAUNCH=15

# Initialize scores
SCORE_PARENTAGE=0
SCORE_NETWORK=0
SCORE_SIGNING=0
SCORE_FILESYSTEM=0
SCORE_LAUNCH=0

FINDINGS_PARENTAGE=0
FINDINGS_NETWORK=0
FINDINGS_SIGNING=0
FINDINGS_FILESYSTEM=0
FINDINGS_LAUNCH=0

# Check 1: Process Parentage (20%)
check_parentage() {
  log "Running parent process analysis..."
  
  if [[ -f "./score/parent_process_analyzer.sh" ]]; then
    local output="${OUTPUT_DIR}/parentage_${TIMESTAMP}.txt"
    if ./score/parent_process_analyzer.sh > "$output" 2>&1; then
      # Count alerts in output
      local alerts=$(grep -c "ALERT" "$output" 2>/dev/null || echo "0")
      FINDINGS_PARENTAGE=$alerts
      
      # Calculate score (inverse of findings, max 20)
      if [[ "$alerts" -eq 0 ]]; then
        SCORE_PARENTAGE=20
      elif [[ "$alerts" -lt 3 ]]; then
        SCORE_PARENTAGE=15
      elif [[ "$alerts" -lt 5 ]]; then
        SCORE_PARENTAGE=10
      else
        SCORE_PARENTAGE=5
      fi
      ok "Parentage check complete: $alerts findings"
    else
      warn "Parentage analyzer failed to run"
      SCORE_PARENTAGE=10  # Neutral score on failure
    fi
  else
    warn "parent_process_analyzer.sh not found, skipping"
    SCORE_PARENTAGE=10
  fi
}

# Check 2: Network Behavior (20%)
check_network() {
  log "Running network behavior analysis..."
  
  if [[ -f "./score/network_behavior_analyzer.sh" ]]; then
    local output="${OUTPUT_DIR}/network_${TIMESTAMP}.txt"
    if ./score/network_behavior_analyzer.sh > "$output" 2>&1; then
      local alerts=$(grep -c "ALERT" "$output" 2>/dev/null || echo "0")
      FINDINGS_NETWORK=$alerts
      
      if [[ "$alerts" -eq 0 ]]; then
        SCORE_NETWORK=20
      elif [[ "$alerts" -lt 3 ]]; then
        SCORE_NETWORK=15
      elif [[ "$alerts" -lt 5 ]]; then
        SCORE_NETWORK=10
      else
        SCORE_NETWORK=5
      fi
      ok "Network check complete: $alerts findings"
    else
      warn "Network analyzer failed to run"
      SCORE_NETWORK=10
    fi
  else
    warn "network_behavior_analyzer.sh not found, skipping"
    SCORE_NETWORK=10
  fi
}

# Check 3: Code Signing & Integrity (25%)
check_signing() {
  log "Running code signing and integrity verification..."
  
  local alerts=0
  
  # Run hash verifier
  if [[ -f "./score/hash_verifier.sh" ]]; then
    local output="${OUTPUT_DIR}/hash_${TIMESTAMP}.txt"
    if ./score/hash_verifier.sh > "$output" 2>&1; then
      local hash_alerts=$(grep -c "MISMATCH" "$output" 2>/dev/null || echo "0")
      alerts=$((alerts + hash_alerts))
    fi
  fi
  
  # Run entitlement verifier
  if [[ -f "./score/entitlement_verifier.sh" ]]; then
    local output="${OUTPUT_DIR}/entitlement_${TIMESTAMP}.txt"
    if ./score/entitlement_verifier.sh > "$output" 2>&1; then
      local ent_alerts=$(grep -c "ALERT" "$output" 2>/dev/null || echo "0")
      alerts=$((alerts + ent_alerts))
    fi
  fi
  
  FINDINGS_SIGNING=$alerts
  
  if [[ "$alerts" -eq 0 ]]; then
    SCORE_SIGNING=25
  elif [[ "$alerts" -lt 3 ]]; then
    SCORE_SIGNING=20
  elif [[ "$alerts" -lt 5 ]]; then
    SCORE_SIGNING=15
  else
    SCORE_SIGNING=5
  fi
  ok "Signing check complete: $alerts findings"
}

# Check 4: File System Modifications (20%)
check_filesystem() {
  log "Running filesystem modification check..."
  
  if [[ -f "./score/detect_agents.sh" ]]; then
    local output="${OUTPUT_DIR}/filesystem_${TIMESTAMP}.txt"
    
    # Run in baseline diff mode if baseline exists
    if [[ -d "$BASELINE_DIR" ]]; then
      if ./score/detect_agents.sh --baseline-diff > "$output" 2>&1; then
        local alerts=$(grep -c "ALERT" "$output" 2>/dev/null || echo "0")
        FINDINGS_FILESYSTEM=$alerts
        
        if [[ "$alerts" -eq 0 ]]; then
          SCORE_FILESYSTEM=20
        elif [[ "$alerts" -lt 3 ]]; then
          SCORE_FILESYSTEM=15
        elif [[ "$alerts" -lt 5 ]]; then
          SCORE_FILESYSTEM=10
        else
          SCORE_FILESYSTEM=5
        fi
        ok "Filesystem check complete: $alerts findings"
      else
        warn "Filesystem check failed"
        SCORE_FILESYSTEM=10
      fi
    else
      # Run normal detection if no baseline
      if ./score/detect_agents.sh > "$output" 2>&1; then
        local alerts=$(grep -c "ALERT" "$output" 2>/dev/null || echo "0")
        FINDINGS_FILESYSTEM=$alerts
        
        if [[ "$alerts" -eq 0 ]]; then
          SCORE_FILESYSTEM=20
        elif [[ "$alerts" -lt 3 ]]; then
          SCORE_FILESYSTEM=15
        elif [[ "$alerts" -lt 5 ]]; then
          SCORE_FILESYSTEM=10
        else
          SCORE_FILESYSTEM=5
        fi
        ok "Filesystem check complete: $alerts findings"
      else
        warn "Filesystem check failed"
        SCORE_FILESYSTEM=10
      fi
    fi
  else
    warn "detect_agents.sh not found, skipping"
    SCORE_FILESYSTEM=10
  fi
}

# Check 5: Launch Agent Configurations (15%)
check_launch_config() {
  log "Running launch agent configuration analysis..."
  
  if [[ -f "./score/detect_agents.sh" ]]; then
    local output="${OUTPUT_DIR}/launch_${TIMESTAMP}.txt"
    
    # Focus on configuration analysis
    if ./score/detect_agents.sh > "$output" 2>&1; then
      local alerts=$(grep -c "ALERT" "$output" 2>/dev/null || echo "0")
      FINDINGS_LAUNCH=$alerts
      
      if [[ "$alerts" -eq 0 ]]; then
        SCORE_LAUNCH=15
      elif [[ "$alerts" -lt 3 ]]; then
        SCORE_LAUNCH=10
      elif [[ "$alerts" -lt 5 ]]; then
        SCORE_LAUNCH=5
      else
        SCORE_LAUNCH=0
      fi
      ok "Launch config check complete: $alerts findings"
    else
      warn "Launch config check failed"
      SCORE_LAUNCH=7
    fi
  else
    warn "detect_agents.sh not found, skipping"
    SCORE_LAUNCH=7
  fi
}

# Calculate overall risk
calculate_overall_risk() {
  local total_score=$((SCORE_PARENTAGE + SCORE_NETWORK + SCORE_SIGNING + SCORE_FILESYSTEM + SCORE_LAUNCH))
  local total_findings=$((FINDINGS_PARENTAGE + FINDINGS_NETWORK + FINDINGS_SIGNING + FINDINGS_FILESYSTEM + FINDINGS_LAUNCH))
  
  local risk_level="LOW"
  if [[ "$total_score" -lt 50 ]]; then
    risk_level="HIGH"
  elif [[ "$total_score" -lt 70 ]]; then
    risk_level="MEDIUM"
  fi
  
  echo "$total_score:$risk_level:$total_findings"
}

# Generate JSON report
generate_report() {
  local overall_risk=$(calculate_overall_risk)
  local overall_score=$(echo "$overall_risk" | cut -d: -f1)
  local risk_level=$(echo "$overall_risk" | cut -d: -f2)
  local total_findings=$(echo "$overall_risk" | cut -d: -f3)
  
  cat > "$REPORT_FILE" << EOF
{
  "timestamp": "$TIMESTAMP",
  "overall_risk_score": $overall_score,
  "risk_level": "$risk_level",
  "total_findings": $total_findings,
  "checks": {
    "parentage": {
      "score": $SCORE_PARENTAGE,
      "weight": $WEIGHT_PARENTAGE,
      "findings": $FINDINGS_PARENTAGE,
      "status": $([ "$SCORE_PARENTAGE" -ge 15 ] && echo "PASS" || echo "FAIL")
    },
    "network": {
      "score": $SCORE_NETWORK,
      "weight": $WEIGHT_NETWORK,
      "findings": $FINDINGS_NETWORK,
      "status": $([ "$SCORE_NETWORK" -ge 15 ] && echo "PASS" || echo "FAIL")
    },
    "signing": {
      "score": $SCORE_SIGNING,
      "weight": $WEIGHT_SIGNING,
      "findings": $FINDINGS_SIGNING,
      "status": $([ "$SCORE_SIGNING" -ge 20 ] && echo "PASS" || echo "FAIL")
    },
    "filesystem": {
      "score": $SCORE_FILESYSTEM,
      "weight": $WEIGHT_FILESYSTEM,
      "findings": $FINDINGS_FILESYSTEM,
      "status": $([ "$SCORE_FILESYSTEM" -ge 15 ] && echo "PASS" || echo "FAIL")
    },
    "launch_config": {
      "score": $SCORE_LAUNCH,
      "weight": $WEIGHT_LAUNCH,
      "findings": $FINDINGS_LAUNCH,
      "status": $([ "$SCORE_LAUNCH" -ge 10 ] && echo "PASS" || echo "FAIL")
    }
  }
}
EOF
}

main() {
  echo "=== Integrated Defense Checklist ==="
  echo "Timestamp: $TIMESTAMP"
  echo ""
  
  local baseline_mode=false
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --baseline-save)
        log "Saving baseline for filesystem checks"
        mkdir -p "$BASELINE_DIR"
        if [[ -f "./score/detect_agents.sh" ]]; then
          ./score/detect_agents.sh --baseline-save
        fi
        exit 0
        ;;
      *)
        warn "Unknown option: $1"
        shift
        ;;
    esac
  done
  
  check_parentage
  check_network
  check_signing
  check_filesystem
  check_launch_config
  
  generate_report
  
  local overall_risk=$(calculate_overall_risk)
  local overall_score=$(echo "$overall_risk" | cut -d: -f1)
  local risk_level=$(echo "$overall_risk" | cut -d: -f2)
  local total_findings=$(echo "$overall_risk" | cut -d: -f3)
  
  echo ""
  echo "=== Defense Checklist Summary ==="
  echo "Overall Risk Score: $overall_score/100"
  echo "Risk Level: $risk_level"
  echo "Total Findings: $total_findings"
  echo ""
  echo "Check Breakdown:"
  echo "  Process Parentage: $SCORE_PARENTAGE/$WEIGHT_PARENTAGE ($FINDINGS_PARENTAGE findings)"
  echo "  Network Behavior: $SCORE_NETWORK/$WEIGHT_NETWORK ($FINDINGS_NETWORK findings)"
  echo "  Code Signing: $SCORE_SIGNING/$WEIGHT_SIGNING ($FINDINGS_SIGNING findings)"
  echo "  File System: $SCORE_FILESYSTEM/$WEIGHT_FILESYSTEM ($FINDINGS_FILESYSTEM findings)"
  echo "  Launch Config: $SCORE_LAUNCH/$WEIGHT_LAUNCH ($FINDINGS_LAUNCH findings)"
  echo ""
  ok "Report saved to: $REPORT_FILE"
}

main "$@"
