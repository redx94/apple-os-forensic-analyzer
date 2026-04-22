#!/usr/bin/env bash
# ============================================================
# network_behavior_analyzer.sh - Network Behavior Anomaly Detection
# ============================================================
# Apple OS Forensic Analyzer
#
# Purpose:
# Monitors outbound network connections initiated by com.apple.* 
# objects for suspicious IP addresses or unusual communication 
# patterns indicative of data exfiltration or command-and-control.
# Based on mindmap: "Network Behavior Anomalies"
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
alert() { echo -e "${RED}${BOLD}[ALERT]${NC} $*"; }

# Known legitimate Apple domains
APPLE_DOMAINS=(
    "apple.com"
    "icloud.com"
    "cdn.apple.com"
    "aaplimg.com"
    "akadns.net"
    "apple-cloudkit.com"
    "push.apple.com"
    "mesu.apple.com"
    "swscan.apple.com"
    "guzzoni.apple.com"
)

# Suspicious IP ranges (private/internal IPs that com.apple.* shouldn't connect to)
SUSPICIOUS_IPS=(
    "10."
    "192.168."
    "172.16."
    "127.0.0.1"  # localhost connections from system daemons
)

echo -e "${BOLD}=== Apple OS Forensic Network Behavior Analyzer ===${NC}"
log "Monitoring com.apple.* network connections..."

TOTAL_CONNECTIONS=0
TOTAL_ALERTS=0

# Get network connections for com.apple.* processes
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    ((TOTAL_CONNECTIONS++))
    
    protocol=$(echo "$line" | awk '{print $1}')
    local_addr=$(echo "$line" | awk '{print $4}')
    foreign_addr=$(echo "$line" | awk '{print $5}')
    state=$(echo "$line" | awk '{print $6}')
    pid=$(echo "$line" | awk '{print $9}')
    
    # Skip if no PID
    [[ -z "$pid" ]] && continue
    
    # Get process name
    comm=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
    
    # Check if this is a com.apple.* process
    if [[ "$comm" != com.apple.* ]]; then
        full_comm=$(ps -p "$pid" -o command= 2>/dev/null | head -1)
        if [[ "$full_comm" != *com.apple.* ]]; then
            continue
        fi
    fi
    
    # Extract IP and port from foreign address
    foreign_ip=$(echo "$foreign_addr" | cut -d: -f1)
    foreign_port=$(echo "$foreign_addr" | cut -d: -f2)
    
    log "Connection: $comm (PID: $pid) → $foreign_addr ($protocol)"
    
    # Check for suspicious IP ranges
    for susp_ip in "${SUSPICIOUS_IPS[@]}"; do
        if [[ "$foreign_ip" == "$susp_ip"* ]]; then
            alert "SUSPICIOUS DESTINATION: $comm connecting to $foreign_ip (internal/private IP)"
            ((TOTAL_ALERTS++))
            break
        fi
    done
    
    # Check if domain is non-Apple
    if [[ "$foreign_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # It's an IP, try to resolve
        domain=$(dig -x "$foreign_ip" +short 2>/dev/null | head -1)
        if [[ -n "$domain" ]]; then
            is_apple_domain=false
            for apple_domain in "${APPLE_DOMAINS[@]}"; do
                if [[ "$domain" == *"$apple_domain"* ]]; then
                    is_apple_domain=true
                    break
                fi
            done
            
            if [[ "$is_apple_domain" == "false" ]]; then
                alert "NON-APPLE DOMAIN: $comm connecting to $domain ($foreign_ip)"
                ((TOTAL_ALERTS++))
            fi
        fi
    fi
    
    # Check for unusual ports
    # Common Apple ports: 443 (HTTPS), 80 (HTTP), 5223 (push), 2197 (push)
    # Suspicious ports: high ports, non-standard ports
    if [[ "$foreign_port" -gt 1024 ]] && [[ "$foreign_port" != "5223" ]] && [[ "$foreign_port" != "2197" ]]; then
        warn "UNUSUAL PORT: $comm connecting to $foreign_ip:$foreign_port (non-standard port)"
        ((TOTAL_ALERTS++))
    fi
    
done < <(netstat -an | grep -E "ESTABLISHED|LISTEN" | grep -v "LISTEN" | tail -n +2)

echo -e "${BOLD}=== Analysis Complete ===${NC}"
ok "Total connections analyzed: $TOTAL_CONNECTIONS"
if [[ $TOTAL_ALERTS -gt 0 ]]; then
    alert "Total alerts: $TOTAL_ALERTS"
    alert "REVIEW ALL ALERTS ABOVE - Potential data exfiltration or C2 detected"
else
    ok "No suspicious network behavior detected"
fi
