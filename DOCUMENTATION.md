# Apple OS Forensic Analyzer - Complete System Documentation

**Version:** 2.0.0  
**Author:** redx94  
**Last Updated:** 2026-04-22

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Directory Structure](#directory-structure)
4. [Tool Descriptions](#tool-descriptions)
5. [Usage Guide](#usage-guide)
6. [GUI Application](#gui-application)
7. [iOS Forensic Capabilities](#ios-forensic-capabilities)
8. [Security Considerations](#security-considerations)
9. [Troubleshooting](#troubleshooting)
10. [Development](#development)

---

## Overview

The Apple OS Forensic Analyzer is a comprehensive forensic analysis suite designed for macOS and iOS security investigation. It provides automated detection of persistence mechanisms, namespace squatting, unsigned binaries, code injection patterns, and other security indicators.

### Key Features

- **Automated Persistence Detection:** Scans for suspicious launchd agents and daemons
- **Namespace Squatting Detection:** Identifies Apple-claiming services from non-system paths
- **Cryptographic Verification:** Validates code signatures and detects anomalies
- **XPC Service Analysis:** Scans for XPC service squatting
- **DNS Monitoring:** Detects DNS hijacking and PTR record mismatches
- **Privacy Permission Auditing:** Scans TCC database for unusual permissions
- **Browser Extension Analysis:** Audits browser extensions for persistence vectors
- **Login Items Inspection:** Checks traditional and modern login items
- **iOS Forensic Analysis:** Analyzes iOS sysdiagnose and backups
- **Evidence Manifest Generation:** Creates chain-of-custody documentation
- **Modern GUI Interface:** Electron-based application for easy tool execution

---

## System Architecture

### Core Components

```
Apple OS Forensic Analyzer
├── Collection Layer (collect/)
│   ├── Identifier extraction
│   ├── Manifest generation
│   └── Baseline comparison
├── Analysis Layer (analyze/)
│   ├── Node validation
│   └── Whitelist management
├── Scoring Layer (score/)
│   ├── Persistence detection
│   ├── Trust verification
│   ├── XPC scanning
│   ├── DNS monitoring
│   ├── TCC scanning
│   ├── Browser auditing
│   └── Login items checking
├── iOS Layer (ios/)
│   └── Sysdiagnose analysis
├── Red Team Testing (lab/)
│   └── Offensive security tools
└── GUI Layer (gui-app/)
    ├── Electron main process
    ├── React frontend
    └── IPC communication
```

### Data Flow

1. **Collection Phase:** Extract identifiers from live system and plist files
2. **Analysis Phase:** Validate identifiers against dynamic whitelist
3. **Scoring Phase:** Apply risk scoring based on multiple detection heuristics
4. **Evidence Phase:** Generate manifest with cryptographic hashes
5. **Reporting Phase:** Output findings with severity classifications

---

## Directory Structure

```
Apple_OS_Forensic_Analyzer/
├── collect/                    # Data collection tools
│   ├── extract_ids.sh         # Extract com.apple.* identifiers
│   └── manifest_generator.sh  # Generate evidence manifest
├── analyze/                    # Analysis tools
│   └── validate_nodes.py      # Validate identifiers against whitelist
├── score/                      # Scoring and detection tools
│   ├── detect_agents.sh       # Persistence scanner
│   ├── verify_trust.sh        # Trust verification
│   ├── verify_extracted_ids.sh # Deep verification
│   ├── xpc_scanner.sh         # XPC service scanner
│   ├── dns_monitor.sh         # DNS monitoring
│   ├── tcc_scanner.sh         # TCC privacy scanner
│   ├── browser_extension_auditor.sh # Browser extension auditor
│   ├── login_items_checker.sh # Login items auditor
│   └── confidence_scorer.py   # Risk scoring engine
├── ios/                        # iOS forensic tools
│   └── analyze_ios_sysdiagnose.sh # iOS sysdiagnose analyzer
├── lab/                        # Red team testing tools
│   ├── WARNING.txt            # Warning notice
│   ├── generate_agent.sh      # Generate malicious agents
│   ├── install_agent.sh       # Install agents
│   ├── cleanup.sh             # Cleanup tools
│   ├── spoof_logs.sh          # Log spoofing tool
│   └── malicious_helper.sh    # Malicious helper
├── gui-app/                    # Electron GUI application
│   ├── electron/              # Electron main process
│   │   ├── main.cjs          # Main entry point
│   │   └── preload.js        # IPC bridge
│   ├── src/                   # React frontend
│   │   ├── App.jsx          # Main component
│   │   └── components/      # UI components
│   ├── package.json          # Dependencies
│   └── build/                # Build configuration
├── forensic_reports/          # Generated forensic reports
├── extract_ids_output/        # Identifier extraction output
├── manifest_output/          # Manifest generation output
├── score_output/             # Scoring tool output
└── README.md                 # Project README
```

---

## Tool Descriptions

### Collection Tools

#### extract_ids.sh

Extracts all `com.apple.*` identifiers from the system.

**Usage:**
```bash
./collect/extract_ids.sh --all        # Extract from all sources
./collect/extract_ids.sh --live       # Extract from running services only
./collect/extract_ids.sh --plists     # Extract from plist files only
./collect/extract_ids.sh --baseline   # Save current state as baseline
./collect/extract_ids.sh --diff       # Compare against baseline
```

**Output:** `extract_ids_output/apple_ids_TIMESTAMP.txt`

**Features:**
- Live service enumeration via `launchctl list`
- Plist file scanning in standard directories
- Differential mode for change detection
- JSON tagging for machine-readable output

#### manifest_generator.sh

Generates a machine-readable evidence manifest with cryptographic hashes.

**Usage:**
```bash
./collect/manifest_generator.sh [output_directory]
```

**Output:** `manifest_output/manifest_TIMESTAMP.json`

**Features:**
- SHA-256 hashing of all artifacts
- UTC timestamps for evidence provenance
- System metadata (hostname, OS version, build)
- Chain of custody documentation

### Analysis Tools

#### validate_nodes.py

Validates identifiers against a dynamic whitelist.

**Usage:**
```bash
./analyze/validate_nodes.py --input extract_ids_output/apple_ids.txt
./analyze/validate_nodes.py --generate-whitelist
```

**Features:**
- Dynamic whitelist generation from `launchctl list`
- Fallback to built-in whitelist
- Whitelist file support
- JSON and human-readable output

### Scoring Tools

#### detect_agents.sh

Scans for suspicious persistence mechanisms and namespace squatting.

**Usage:**
```bash
./score/detect_agents.sh
```

**Detection Capabilities:**
- Namespace squatting (Apple namespace from non-system paths)
- Suspicious label patterns
- Unsigned binaries claiming Apple namespace
- Non-Apple signatures on Apple-claiming labels
- Symlinked binaries
- MachServices, KeepAlive, Sockets checks
- Behavioral detection heuristics

**Output:** Console with alerts and summary

#### verify_trust.sh

Verifies code signatures, entitlements, and paths.

**Usage:**
```bash
./score/verify_trust.sh
```

**Verification Checks:**
- Code signature validity
- Certificate chain verification
- Entitlements analysis
- Path validation
- Team identifier verification

#### verify_extracted_ids.sh

Deep cryptographic verification of extracted identifiers.

**Usage:**
```bash
./score/verify_extracted_ids.sh extract_ids_output/apple_ids.txt
```

**Verification Steps:**
- Binary presence verification
- Code signature validation
- Hash comparison
- Path validation
- Cryptographic failure detection

**Output:** Verification report with pass/fail counts

#### xpc_scanner.sh

Scans for XPC service squatting.

**Usage:**
```bash
./score/xpc_scanner.sh
```

**Scanning Locations:**
- `/System/Library/XPCServices`
- `/Library/XPCServices`
- Application bundles
- Framework bundles

**Detection:** Non-Apple XPC services outside system paths

#### dns_monitor.sh

Monitors DNS for hijacking and drift.

**Usage:**
```bash
./score/dns_monitor.sh --check     # Check against baseline
./score/dns_monitor.sh --baseline   # Create baseline
```

**Detection Capabilities:**
- PTR record mismatches
- DNS resolution anomalies
- Known malicious domains
- DNS drift detection

#### tcc_scanner.sh

Scans TCC database for privacy permission anomalies.

**Usage:**
```bash
./score/tcc_scanner.sh
```

**Requirements:** Full Disk Access required

**Scanned Permissions:**
- Camera access
- Microphone access
- Location services
- Contacts access
- Photos access
- Full disk access

#### browser_extension_auditor.sh

Audits browser extensions for persistence vectors.

**Usage:**
```bash
./score/browser_extension_auditor.sh
```

**Supported Browsers:**
- Chrome
- Safari
- Firefox

**Detection:**
- Extension enumeration
- Permission analysis
- Persistence vector detection

#### login_items_checker.sh

Checks login items and background tasks.

**Usage:**
```bash
./score/login_items_checker.sh
```

**Scanning Areas:**
- Traditional login items
- macOS 13+ Background Task Management
- User LaunchAgents
- Profile-based login items
- Suspicious persistence locations

#### confidence_scorer.py

Risk scoring engine (0-100) for identifiers.

**Usage:**
```bash
./score/confidence_scorer.py --input extract_ids_output/apple_ids.txt
```

**Scoring Factors:**
- Namespace (Apple vs third-party)
- Path (system vs non-system)
- Code signature status
- Entitlements analysis
- Known suspicious patterns

**Risk Levels:**
- 0-30: LOW
- 31-70: MEDIUM
- 71-100: HIGH

### iOS Tools

#### analyze_ios_sysdiagnose.sh

Enhanced offline parser for iOS sysdiagnose and backups.

**Usage:**
```bash
./ios/analyze_ios_sysdiagnose.sh /path/to/sysdiagnose.tar.gz
./ios/analyze_ios_sysdiagnose.sh /path/to/extracted/iOS/backup/
```

**Analysis Capabilities:**
- Code injection detection (DYLD_INSERT_LIBRARIES, Frida, Cydia)
- Unusual daemon detection
- Masquerading identifier detection
- Installation anomaly detection
- Suspicious crash pattern detection
- Unified log parsing
- Installation database analysis

**How to Generate iOS Sysdiagnose:**
1. On iPhone: Settings > Privacy > Analytics > Analytics Data
2. Tap "Share Analytics Data"
3. Transfer archive to Mac
4. Run analyzer on archive

---

## Usage Guide

### Prerequisites

**macOS Requirements:**
- macOS 10.15 or later
- Root/sudo privileges for full system access
- Full Disk Access for TCC scanning
- bash 4.0 or later
- Python 3.8 or later (for Python tools)

**Dependencies:**
- PlistBuddy (built-in)
- codesign (built-in)
- launchctl (built-in)
- jq (optional, for JSON parsing)

### Basic Usage

1. **Clone or download the repository**
2. **Navigate to the project directory**
3. **Run tools with sudo for full access:**

```bash
sudo ./collect/extract_ids.sh --all
sudo ./score/detect_agents.sh
sudo ./score/verify_extracted_ids.sh ./extract_ids_output/apple_ids_*.txt
```

4. **Review output in respective output directories**

### Recommended Workflow

1. **Baseline Establishment:**
   ```bash
   sudo ./collect/extract_ids.sh --baseline
   ```

2. **Full System Scan:**
   ```bash
   sudo ./collect/extract_ids.sh --all
   sudo ./score/detect_agents.sh
   sudo ./score/verify_trust.sh
   sudo ./score/xpc_scanner.sh
   sudo ./score/verify_extracted_ids.sh ./extract_ids_output/apple_ids_*.txt
   sudo ./score/dns_monitor.sh --check
   sudo ./score/tcc_scanner.sh
   sudo ./score/browser_extension_auditor.sh
   sudo ./score/login_items_checker.sh
   ```

3. **Evidence Manifest Generation:**
   ```bash
   sudo ./collect/manifest_generator.sh
   ```

4. **Differential Analysis:**
   ```bash
   sudo ./collect/extract_ids.sh --diff
   ```

---

## GUI Application

### Overview

The Electron-based GUI provides a modern interface for running forensic tools and viewing results.

### Features

- **Dashboard:** System overview, quick stats, recent activity
- **Tool Catalog:** Organized by category with search
- **Execution Panel:** Real-time tool execution with live output
- **Results Viewer:** Browse output files and view contents
- **Permission Management:** Request Full Disk Access from GUI

### Running the GUI

**Development Mode:**
```bash
cd gui-app
npm install
npm run electron:dev
```

**Production Build:**
```bash
cd gui-app
npm run build
npm run pack
```

**Run Packaged App:**
```bash
open gui-app/dist/mac/Apple OS Forensic Analyzer.app
```

### GUI Permissions

The GUI requests Full Disk Access through a dialog that opens System Preferences. Grant the app Full Disk Access for complete TCC scanning capability.

### GUI Tool Execution

Tools in the GUI run with `sudo` for root privileges, ensuring complete system access for forensic analysis.

---

## iOS Forensic Capabilities

### Supported Data Sources

1. **iOS Sysdiagnose Archives:** `.tar.gz` format
2. **Unencrypted iOS Backups:** Extracted backup directories

### Analysis Features

- **Code Injection Detection:**
  - DYLD_INSERT_LIBRARIES patterns
  - Frida instrumentation
  - Cydia substrate
  - Dynamic library hijacking

- **Daemon Analysis:**
  - Unusual daemon processes
  - Suspicious launchd jobs
  - Masquerading identifiers

- **Installation Analysis:**
  - Installation database parsing
  - App bundle analysis
  - Provisioning profile verification

- **Log Analysis:**
  - Unified log parsing
  - Crash log analysis
  - System log analysis

### Limitations

- Requires unencrypted backups or sysdiagnose
- Encrypted backups cannot be analyzed
- Requires iOS device access to generate sysdiagnose

---

## Security Considerations

### Tool Safety

- All tools are read-only and do not modify system state
- No persistence mechanisms are installed
- No network connections are made (except DNS queries)
- All output is saved to local directories

### Privacy

- No data is transmitted externally
- All analysis is performed locally
- Output files contain only system metadata
- User data is not collected or stored

### Authorization

**Legal Requirements:**
- Only analyze systems you own or have explicit authorization to analyze
- Forensic analysis of systems without authorization may be illegal
- Ensure proper chain of custody for evidence collection
- Consult legal counsel before using in investigations

### Root Access

Many tools require root/sudo privileges for:
- Accessing system directories
- Reading protected files
- Running code signature verification
- Accessing TCC database

**Recommendation:** Run tools with `sudo` for complete system coverage.

---

## Troubleshooting

### Common Issues

**1. Permission Denied Errors**
- **Solution:** Run with `sudo`
- **Example:** `sudo ./score/detect_agents.sh`

**2. TCC Database Access Denied**
- **Solution:** Grant Full Disk Access to Terminal or the GUI app
- **Location:** System Preferences > Security & Privacy > Privacy > Full Disk Access

**3. "command not found" for tools**
- **Solution:** Ensure scripts are executable: `chmod +x toolname.sh`
- **Example:** `chmod +x score/detect_agents.sh`

**4. Python script errors**
- **Solution:** Ensure Python 3 is installed and in PATH
- **Check:** `python3 --version`

**5. GUI won't launch**
- **Solution:** Check Electron installation: `npm install` in gui-app directory
- **Check:** Node.js version compatibility

### Debug Mode

For troubleshooting, tools can be run with `bash -x` for verbose output:

```bash
bash -x ./score/detect_agents.sh
```

---

## Development

### Project Structure for Developers

**Frontend (GUI):**
- React 18 with hooks
- TailwindCSS for styling
- Electron for desktop wrapper
- Vite for build tooling

**Backend (Scripts):**
- Bash for shell scripts
- Python for complex analysis
- IPC for Electron communication

### Building the GUI

```bash
cd gui-app
npm install
npm run build
npm run pack
```

### Adding New Tools

1. Create script in appropriate directory (collect/, analyze/, score/, ios/)
2. Make executable: `chmod +x scriptname.sh`
3. Add to tool catalog in `gui-app/electron/main.cjs`
4. Test with sudo: `sudo ./scriptname.sh`

### Code Style

- Bash: Follow shellcheck recommendations
- Python: Follow PEP 8
- React: Follow ESLint recommendations

---

## Version History

### v2.0.0 (2026-04-22)
- Restructured project into modular directories
- Added iOS forensic analysis capabilities
- Enhanced detection with behavioral heuristics
- Added confidence-based scoring system
- Created modern Electron GUI application
- Added evidence manifest generation
- Fixed subshell bug in verify_extracted_ids.sh
- Added dynamic whitelist generation
- Implemented differential baseline comparison
- Added new modules: TCC scanner, browser auditor, login items checker
- Configured tools to run with root privileges
- Added comprehensive documentation

---

## Support

For issues, questions, or permission requests, contact: redx94

---

## Disclaimer

This software is for legitimate forensic analysis and security research purposes only. Users are responsible for ensuring they have proper authorization before analyzing any system. The authors are not responsible for misuse of this software.

**USE AT YOUR OWN RISK.**
