#!/usr/bin/env python3
"""
validate_nodes.py - Node Identifier Validation Tool
Apple OS Forensic Analyzer - Code Snippets Branch (4.4)
"""
import re, json, argparse, subprocess, datetime, sys
from pathlib import Path

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
CYAN="\033[0;36m"; BOLD="\033[1m"; RESET="\033[0m"

def log(m):   print(f"{CYAN}[*]{RESET} {m}")
def ok(m):    print(f"{GREEN}[✓]{RESET} {m}")
def warn(m):  print(f"{YELLOW}[!]{RESET} {m}")
def alert(m): print(f"{RED}{BOLD}[ALERT]{RESET} {m}")

BUILTIN_WHITELIST = {
    "com.apple.security.authd","com.apple.SecurityServer","com.apple.trustd",
    "com.apple.MobileFileIntegrity","com.apple.tccd","com.apple.lsd",
    "com.apple.sharingd","com.apple.UserNotifications","com.apple.softwareupdated",
    "com.apple.system.update","com.apple.Siri","com.apple.dock","com.apple.WindowServer",
    "com.apple.xpc.launchd","com.apple.SystemConfiguration","com.apple.mdmclient",
    "com.apple.nsurlsessiond","com.apple.cfnetwork","com.apple.coreservices.launchservicesd",
    "com.apple.audio.coreaudiod","com.apple.metadata.mds","com.apple.cloudd",
    "com.apple.icloud.fmfd","com.apple.parsecd","com.apple.rapportd","com.apple.Spotlight",
    "com.apple.ScreenTimeAgent","com.apple.private.alloy","com.apple.remindd",
}

DEMO_NODES = [
    {"node_id":"node_0001","title":"Security Audit Service","tags":["com.apple.security.authd"],"content":"Legit audit daemon."},
    {"node_id":"node_0002","title":"Masquerading Helper","tags":["com.apple.system.updatehelper"],"content":"Attacker plist."},
    {"node_id":"node_0003","title":"Fake Siri Service","tags":["com.apple.Siri.fake.voice"],"content":"XPC squatting on Siri namespace."},
    {"node_id":"node_0004","title":"Legit Cloud Daemon","tags":["com.apple.cloudd"],"content":"Apple iCloud sync daemon."},
    {"node_id":"node_0005","title":"Log Spoofer","tags":[],"content":"Uses os_log_create with com.apple.security.audit to blend into logs."},
]

def generate_system_whitelist():
    """Extract all com.apple.* identifiers from live system via launchctl"""
    try:
        r = subprocess.run(["launchctl","list"], capture_output=True, text=True, timeout=30)
        ids = sorted({l.split()[2] for l in r.stdout.splitlines()[1:]
                      if len(l.split())>=3 and re.match(r"com\.apple\.",l.split()[2])})
        log(f"Generated dynamic whitelist from launchctl: {len(ids)} entries")
        return set(ids)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError) as e:
        warn(f"Failed to generate dynamic whitelist: {e}")
        return None

def detect_ghost_identifiers(output_dir):
    """
    v3.0 Enhancement: Ghost Identifiers Detection (Orphaned Service Scanner)
    Identifies fileless persistence where a process is running in memory but its
    source .plist has been deleted to evade scanners.
    """
    log("Starting Ghost Identifiers Detection...")
    ghost_services = []
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_dir / f"ghost_identifiers_{timestamp}.txt"
    
    # Standard launchd directories
    launchd_dirs = [
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
        f"/Users/{Path.home().name}/Library/LaunchAgents",
        "/System/Library/LaunchDaemons",
        "/System/Library/LaunchAgents"
    ]
    
    # Collect all on-disk plist labels
    on_disk_labels = set()
    for dir_path in launchd_dirs:
        dir_p = Path(dir_path)
        if dir_p.exists():
            for plist_file in dir_p.glob("*.plist"):
                try:
                    # Extract Label from plist
                    result = subprocess.run(
                        ["/usr/libexec/PlistBuddy", "-c", "Print :Label", str(plist_file)],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        label = result.stdout.strip()
                        on_disk_labels.add(label)
                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                    continue
    
    log(f"Found {len(on_disk_labels)} labels on disk")
    
    # Get live services from launchctl print
    live_labels = set()
    
    # System services
    try:
        r = subprocess.run(
            ["launchctl", "print", "system"],
            capture_output=True, text=True, timeout=30
        )
        # Parse launchctl output for service labels
        for line in r.stdout.splitlines():
            if re.match(r"com\.", line.strip()):
                live_labels.add(line.strip())
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        warn("Failed to get system services via launchctl print")
    
    # User services
    try:
        user_id = subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip()
        r = subprocess.run(
            ["launchctl", "print", f"user/{user_id}"],
            capture_output=True, text=True, timeout=30
        )
        for line in r.stdout.splitlines():
            if re.match(r"com\.", line.strip()):
                live_labels.add(line.strip())
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        warn("Failed to get user services via launchctl print")
    
    log(f"Found {len(live_labels)} live services in memory")
    
    # Identify ghost services (live but not on disk)
    ghost_count = 0
    for label in live_labels:
        if label not in on_disk_labels:
            # Check if it's a legitimate system service (built-in, no plist required)
            if label in BUILTIN_WHITELIST:
                continue
            
            ghost_services.append(label)
            ghost_count += 1
            alert(f"GHOST IDENTIFIER DETECTED: {label}")
            alert(f"  → Service is loaded in memory but has no corresponding .plist file")
    
    # Write report
    with open(output_file, "w") as f:
        f.write(f"Ghost Identifiers Detection Report - {timestamp}\n")
        f.write(f"{'='*60}\n\n")
        f.write(f"Live services in memory: {len(live_labels)}\n")
        f.write(f"Labels on disk: {len(on_disk_labels)}\n")
        f.write(f"Ghost services detected: {ghost_count}\n\n")
        
        if ghost_services:
            f.write("GHOST SERVICES (fileless persistence):\n")
            for service in ghost_services:
                f.write(f"  - {service}\n")
        else:
            f.write("No ghost services detected.\n")
    
    if ghost_count > 0:
        alert(f"Ghost Identifier Detection complete: {ghost_count} fileless persistence services found")
        ok(f"Report saved to: {output_file}")
    else:
        ok("No ghost identifiers detected - all loaded services have corresponding plist files")
    
    return ghost_services, output_file

def load_whitelist(path):
    # First try dynamic generation if no file provided
    if not path.exists():
        dynamic = generate_system_whitelist()
        if dynamic:
            return dynamic
        # Fallback to builtin if dynamic generation fails
        warn("Using built-in static whitelist as fallback")
        return BUILTIN_WHITELIST
    # Load from file if provided
    return {l.strip() for l in path.read_text().splitlines() if l.strip() and not l.startswith("#")}

def extract_apple_ids(text):
    return re.findall(r"com\.apple\.[A-Za-z0-9._-]+", text)

def validate_nodes(nodes, whitelist):
    out = []
    for node in nodes:
        all_ids = set(node.get("tags",[])) | set(extract_apple_ids(node.get("content","")))
        apple_ids = {i for i in all_ids if i.startswith("com.apple.")}
        suspicious = [i for i in apple_ids if i not in whitelist]
        node["validation"] = {"passed": not suspicious, "checked_ids": sorted(apple_ids),
            "suspicious_ids": sorted(suspicious), "reason": "OK" if not suspicious else f"Unrecognized: {suspicious}"}
        out.append(node)
    return out

def print_report(nodes):
    passed = sum(1 for n in nodes if n["validation"]["passed"])
    failed = len(nodes) - passed
    print(f"\n{BOLD}{'='*50}{RESET}\n{BOLD} Node Validation Report{RESET}\n{BOLD}{'='*50}{RESET}\n")
    for node in nodes:
        v = node["validation"]; title = node.get("title","<untitled>")
        if v["passed"]:
            ok(f"{title}")
            for i in v["checked_ids"]: print(f"    {GREEN}✓{RESET} {i}")
        else:
            alert(f"{title}")
            for s in v["suspicious_ids"]: print(f"    {RED}✗{RESET} SUSPICIOUS: {s}")
    print(f"\n{BOLD}Summary:{RESET} {passed} passed, {failed} failed\n")
    if failed: alert(f"{failed} node(s) with unrecognized com.apple.* identifiers detected.")
    else: ok("All nodes validated against whitelist.")

def main():
    p = argparse.ArgumentParser(description="Apple OS Forensic Node Validator")
    p.add_argument("--nodes", type=Path, default=Path("nodes.json"))
    p.add_argument("--whitelist", type=Path, default=Path("apple_whitelist.txt"))
    p.add_argument("--generate-whitelist", action="store_true")
    p.add_argument("--demo", action="store_true")
    p.add_argument("--output-dir", type=Path, default=Path("./validate_output"))
    p.add_argument("--detect-ghost-identifiers", action="store_true", help="v3.0: Detect fileless persistence (orphaned services)")
    args = p.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    if args.generate_whitelist:
        r = subprocess.run(["launchctl","list"], capture_output=True, text=True)
        ids = sorted({l.split()[2] for l in r.stdout.splitlines()[1:] if len(l.split())>=3 and re.match(r"com\.apple\.",l.split()[2])})
        wl = args.output_dir/"apple_whitelist.txt"
        wl.write_text("\n".join(ids)+"\n")
        ok(f"Whitelist → {wl} ({len(ids)} entries)"); return

    if args.detect_ghost_identifiers:
        detect_ghost_identifiers(args.output_dir)
        return

    whitelist = load_whitelist(args.whitelist)
    nodes = DEMO_NODES if args.demo else (
        json.loads(args.nodes.read_text()).get("nodes",[]) if args.nodes.exists() else DEMO_NODES)
    log(f"Validating {len(nodes)} nodes against {len(whitelist)} whitelist entries...")
    validated = validate_nodes(nodes, whitelist)
    print_report(validated)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = args.output_dir/f"validated_{ts}.json"
    out.write_text(json.dumps({"nodes":validated,"timestamp":ts}, indent=2))
    ok(f"Saved → {out}")

if __name__ == "__main__": main()
