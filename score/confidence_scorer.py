#!/usr/bin/env python3
"""
confidence_scorer.py - Risk Scoring Engine
Apple OS Forensic Analyzer

Purpose:
Replaces binary ALERT/PASSED with confidence-based risk scores (0-100).
Factors include namespace, path, signature, entitlements, and location.
Outputs risk levels: LOW (<30), MEDIUM (30-70), HIGH (>70).
"""
import re, json, argparse, subprocess, datetime, sys
from pathlib import Path

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
CYAN="\033[0;36m"; BOLD="\033[1m"; RESET="\033[0m"

def log(m):   print(f"{CYAN}[*]{RESET} {m}")
def ok(m):    print(f"{GREEN}[✓]{RESET} {m}")
def warn(m):  print(f"{YELLOW}[!]{RESET} {m}")
def alert(m): print(f"{RED}{BOLD}[ALERT]{RESET} {m}")

TRUSTED_PATHS = ("/System/Library", "/usr/bin", "/usr/sbin", "/usr/libexec", "/bin", "/sbin", "/Library/Apple")
DANGEROUS_ENTITLEMENTS = ("com.apple.private.tcc.allow", "com.apple.rootless.install", 
                          "com.apple.security.get-task-allow", "com.apple.private.admin.writeconfig",
                          "com.apple.security.cs.allow-unsigned-executable-memory")

def get_signature_info(binary_path):
    """Get code signature information for a binary"""
    if not Path(binary_path).exists():
        return {"signed": False, "authority": None}
    
    try:
        result = subprocess.run(
            ["codesign", "-dv", "--verbose=4", binary_path],
            capture_output=True, text=True, timeout=10
        )
        if "code object is not signed" in result.stderr:
            return {"signed": False, "authority": None}
        
        authority = None
        for line in result.stderr.split('\n'):
            if "Authority=" in line:
                authority = line.split("=")[1].strip()
                break
        
        return {"signed": True, "authority": authority}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"signed": False, "authority": None}

def get_entitlements(binary_path):
    """Get entitlements for a binary"""
    if not Path(binary_path).exists():
        return []
    
    try:
        result = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", binary_path],
            capture_output=True, text=True, timeout=10
        )
        # Parse entitlements from plist output
        ents = []
        for ent in DANGEROUS_ENTITLEMENTS:
            if ent in result.stdout:
                ents.append(ent)
        return ents
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

def score_namespace_risk(identifier, binary_path, signature_info):
    """Score namespace usage (0-50 points)"""
    score = 0
    reasons = []
    
    # +50 if claims Apple but not in system path
    if identifier.startswith("com.apple.") and binary_path:
        is_trusted = any(binary_path.startswith(p) for p in TRUSTED_PATHS)
        if not is_trusted:
            score += 50
            reasons.append("Non-system path with Apple namespace")
    
    # +30 if unsigned
    if not signature_info["signed"]:
        score += 30
        reasons.append("Unsigned binary")
    
    # +20 if non-Apple signature
    elif signature_info["authority"] and "Apple" not in signature_info["authority"]:
        score += 20
        reasons.append(f"Third-party signature: {signature_info['authority']}")
    
    return score, reasons

def score_entitlement_risk(entitlements):
    """Score dangerous entitlements (0-30 points)"""
    score = 0
    reasons = []
    
    for ent in entitlements:
        score += 10
        reasons.append(f"Dangerous entitlement: {ent}")
    
    return score, reasons

def score_path_risk(binary_path):
    """Score binary path (0-20 points)"""
    score = 0
    reasons = []
    
    if not binary_path:
        return score, reasons
    
    # +20 if in suspicious location
    suspicious_locations = ("/usr/local/", "/opt/", "~/Applications/", "/tmp/")
    for loc in suspicious_locations:
        if binary_path.startswith(loc) or loc in binary_path:
            score += 20
            reasons.append(f"Suspicious location: {binary_path}")
            break
    
    return score, reasons

def calculate_risk_score(identifier, binary_path):
    """Calculate overall risk score (0-100)"""
    signature_info = get_signature_info(binary_path)
    entitlements = get_entitlements(binary_path)
    
    namespace_score, namespace_reasons = score_namespace_risk(identifier, binary_path, signature_info)
    ent_score, ent_reasons = score_entitlement_risk(entitlements)
    path_score, path_reasons = score_path_risk(binary_path)
    
    total_score = min(namespace_score + ent_score + path_score, 100)
    all_reasons = namespace_reasons + ent_reasons + path_reasons
    
    risk_level = "LOW" if total_score < 30 else "MEDIUM" if total_score < 70 else "HIGH"
    
    return {
        "score": total_score,
        "level": risk_level,
        "reasons": all_reasons,
        "signature": signature_info,
        "entitlements": entitlements
    }

def print_score_report(identifier, binary_path, risk_result):
    """Print formatted risk score report"""
    level_colors = {"LOW": GREEN, "MEDIUM": YELLOW, "HIGH": RED}
    color = level_colors.get(risk_result["level"], RESET)
    
    print(f"\n{BOLD}=== {identifier} ==={RESET}")
    print(f"Binary: {binary_path}")
    print(f"Risk Score: {color}{risk_result['score']}/100 ({risk_result['level']}){RESET}")
    
    if risk_result["reasons"]:
        print(f"{BOLD}Reasons:{RESET}")
        for reason in risk_result["reasons"]:
            print(f"  - {reason}")
    
    if risk_result["signature"]["signed"]:
        print(f"  Signed: Yes (Authority: {risk_result['signature']['authority']})")
    else:
        print(f"  Signed: {RED}No{RESET}")
    
    if risk_result["entitlements"]:
        print(f"  Dangerous Entitlements: {', '.join(risk_result['entitlements'])}")

def main():
    p = argparse.ArgumentParser(description="Apple OS Forensic Confidence Scorer")
    p.add_argument("--input", type=Path, required=True, help="Input file with identifiers (from extract_ids.sh)")
    p.add_argument("--output-dir", type=Path, default=Path("./score_output"), help="Output directory")
    p.add_argument("--threshold", type=int, default=50, help="Alert threshold (default: 50)")
    args = p.parse_args()
    
    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    log(f"Scoring identifiers from: {args.input}")
    
    results = []
    high_risk_count = 0
    
    with open(args.input) as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line or "LABEL=" not in line:
                continue
            
            # Parse LABEL=... BINARY=... format
            label_match = re.search(r'LABEL=([^\s]+)', line)
            binary_match = re.search(r'BINARY=([^\s]+)', line)
            
            if not label_match:
                continue
            
            identifier = label_match.group(1)
            binary_path = binary_match.group(1) if binary_match else "N/A"
            
            risk_result = calculate_risk_score(identifier, binary_path)
            results.append({
                "identifier": identifier,
                "binary": binary_path,
                "risk": risk_result
            })
            
            if risk_result["level"] == "HIGH":
                high_risk_count += 1
                print_score_report(identifier, binary_path, risk_result)
    
    # Save results to JSON
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = args.output_dir / f"scores_{ts}.json"
    
    with open(output_file, "w") as f:
        json.dump({
            "timestamp": ts,
            "threshold": args.threshold,
            "high_risk_count": high_risk_count,
            "total_scored": len(results),
            "results": results
        }, f, indent=2)
    
    print(f"\n{BOLD}=== Summary ==={RESET}")
    print(f"Total scored: {len(results)}")
    print(f"{RED}High risk: {high_risk_count}{RESET}")
    ok(f"Results saved to: {output_file}")

if __name__ == "__main__":
    main()
