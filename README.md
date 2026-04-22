# Apple OS Forensic Analyzer

A professional, modular forensic analysis suite for macOS and iOS. Detects masquerading persistence, namespace squatting, code injection, and suspicious system modifications through evidence collection, offline analysis, and confidence-based risk scoring.

## ⚠️ Important: Architecture Change

This suite has been **restructured** to separate defensive forensics from red-team testing. Offensive/persistence scripts are now isolated in the `lab/` directory and should **never** be run on evidence-bearing machines.

## Directory Structure

```
Apple_OS_Forensic_Analyzer/
├── collect/              # Read-only evidence acquisition
│   ├── extract_ids.sh   # Identifier extraction (live/plists/files)
│   └── manifest_generator.sh  # Evidence provenance (hashes, timestamps)
├── analyze/              # Offline parsers and validators
│   └── validate_nodes.py     # Dynamic whitelist-based node validation
├── score/                # Risk assessment engines
│   ├── detect_agents.sh      # Enhanced persistence scanner with behavioral detection
│   ├── verify_trust.sh      # Signature/entitlement/path verification
│   ├── verify_extracted_ids.sh  # Deep cryptographic verification
│   ├── xpc_scanner.sh        # XPC service squatting detection
│   ├── dns_monitor.sh        # DNS baseline drift monitoring
│   ├── confidence_scorer.py  # Risk scoring engine (0-100)
│   ├── tcc_scanner.sh        # Privacy permission scanner
│   ├── browser_extension_auditor.sh  # Extension persistence audit
│   └── login_items_checker.sh      # Login items & background task audit
├── ios/                  # iOS-specific modules
│   └── analyze_ios_sysdiagnose.sh  # Enhanced sysdiagnose parser
├── lab/                  # ⚠️ RED TEAM TESTING ONLY
│   ├── WARNING.txt
│   ├── generate_agent.sh
│   ├── install_agent.sh
│   ├── spoof_logs.sh
│   ├── cleanup.sh
│   └── [other persistence demo scripts]
└── README.md
```

## Quick Start

### Basic macOS Scan

```bash
# Collect identifiers
./collect/extract_ids.sh --all

# Scan for suspicious persistence
./score/detect_agents.sh

# Verify trust of binaries
./score/verify_trust.sh

# Check XPC squatting
./score/xpc_scanner.sh
```

### Advanced Analysis

```bash
# Generate evidence manifest
./collect/manifest_generator.sh

# Confidence-based scoring
python3 ./score/confidence_scorer.py --input ./extract_ids_output/apple_ids_*.txt

# Differential mode (detect changes)
./collect/extract_ids.sh --baseline
# ... later ...
./collect/extract_ids.sh --diff

# Deep verification of alerts
./score/verify_extracted_ids.sh ./extract_ids_output/apple_ids_*.txt
```

### iOS Analysis

```bash
# Analyze iOS sysdiagnose or backup
./ios/analyze_ios_sysdiagnose.sh /path/to/sysdiagnose.tar.gz
```

### Privacy & Persistence Audit

```bash
# Scan TCC permissions
./score/tcc_scanner.sh

# Audit browser extensions
./score/browser_extension_auditor.sh

# Check login items
./score/login_items_checker.sh
```

## Module Details

### collect/ - Evidence Acquisition

**extract_ids.sh**
- Extracts `com.apple.*` identifiers from live system, plists, or files
- Modes: `--live`, `--plists`, `--all`, `--baseline`, `--diff`
- Differential mode detects new/removed identifiers since baseline

**manifest_generator.sh**
- Generates machine-readable evidence manifest
- Includes UTC timestamps, hostname, OS build, SHA-256 hashes
- Provides provenance for forensic defensibility

### analyze/ - Offline Analysis

**validate_nodes.py**
- Dynamic whitelist generation from `launchctl list`
- Validates nodes against system state
- Flags unrecognized `com.apple.*` identifiers
- Demo mode available for testing

### score/ - Risk Assessment

**detect_agents.sh** (Enhanced)
- Behavioral detection: namespace squatting, path validation
- Signature verification for Apple-claiming binaries
- Checks MachServices, KeepAlive, Sockets
- Symlinked binary detection

**verify_trust.sh**
- Code signature validation
- Entitlement scanning for dangerous privileges
- Path validation against trusted locations
- Parent process inspection

**verify_extracted_ids.sh** (Bug Fixed)
- Deep cryptographic verification of extracted identifiers
- **Fixed:** Process substitution prevents subshell bug (counts now accurate)
- Maps IDs to on-disk binaries
- Verifies Apple signature authority

**xpc_scanner.sh**
- Duplicate service label detection
- High-value target registration checks
- XPC bundle signature scanning
- Squatting opportunity identification

**dns_monitor.sh**
- Reverse-DNS audit for Apple domains
- Baseline drift detection
- DNSSEC validation

**confidence_scorer.py** (New)
- Risk scoring (0-100) instead of binary alerts
- Factors: namespace, path, signature, entitlements
- Risk levels: LOW (<30), MEDIUM (30-70), HIGH (>70)
- JSON output with reasoning

**tcc_scanner.sh** (New)
- TCC database scanner for privacy permissions
- Identifies apps with camera, microphone, location access
- Flags non-Apple apps with broad permissions

**browser_extension_auditor.sh** (New)
- Scans Chrome, Safari, Firefox extensions
- Identifies suspicious permission grants
- Detects data exfiltration risk

**login_items_checker.sh** (New)
- Traditional login items audit
- Background Task Management (macOS 13+)
- Profile-based persistence detection
- Suspicious location scanning

### ios/ - iOS Analysis

**analyze_ios_sysdiagnose.sh** (Enhanced)
- Enhanced sysdiagnose archive parsing
- Unified log extraction
- Installation lifecycle tracking
- Code injection detection (DYLD_INSERT_LIBRARIES, hooking patterns)
- Unusual daemon detection
- Masquerading plist pattern scanning

### lab/ - Red Team Testing (⚠️ ISOLATED USE ONLY)

**WARNING:** Scripts in this directory create persistence, spoof logs, and modify system state. Use ONLY in isolated lab VMs with snapshots. Never run on evidence-bearing machines.

- `generate_agent.sh` - Creates masquerading launchd plist
- `install_agent.sh` - Deploys persistence to system paths
- `spoof_logs.sh` - Injects fake Apple log entries
- `cleanup.sh` - Removes installed agents and artifacts

## Key Enhancements (v2.0)

### Critical Fixes
- **Fixed subshell bug** in `verify_extracted_ids.sh` - pass/fail counts now accurate
- **Dynamic whitelist** in `validate_nodes.py` - generates from live system instead of static list

### New Capabilities
- **Confidence-based scoring** - replaces binary alerts with risk scores (0-100)
- **Differential mode** - detects changes between baselines
- **Evidence manifest** - machine-readable provenance with hashes and timestamps
- **Enhanced iOS parser** - proper sysdiagnose parsing with code injection detection
- **Privacy audit modules** - TCC, browser extensions, login items
- **Behavioral detection** - namespace squatting, path validation in persistence scanner

### Architecture Improvements
- **Separated concerns** - collect/analyze/score/ios/lab structure
- **Isolated red-team tools** - offensive scripts moved to lab/ with warnings
- **Professional output** - structured JSON where appropriate, detailed reports

## Usage Examples

### Complete Forensic Workflow

```bash
# 1. Collect evidence
./collect/extract_ids.sh --all
./collect/manifest_generator.sh

# 2. Analyze
python3 ../analyze/validate_nodes.py --nodes ./extract_ids_output/tagged_nodes_*.json

# 3. Score risks
python3 ../score/confidence_scorer.py --input ./extract_ids_output/apple_ids_*.txt

# 4. Deep verification
./score/verify_extracted_ids.sh ./extract_ids_output/apple_ids_*.txt
```

### Monitoring for Changes

```bash
# Establish baseline
./collect/extract_ids.sh --baseline

# Periodic checks
./collect/extract_ids.sh --diff
./score/detect_agents.sh
```

### iOS Device Investigation

```bash
# Extract sysdiagnose from device (via Settings > Privacy > Analytics > Analytics Data)
# Then analyze on Mac:
./ios/analyze_ios_sysdiagnose.sh /path/to/sysdiagnose.tar.gz
```

## Requirements

- macOS 10.15+ (Catalina or later)
- Python 3.7+ for Python modules
- Full Disk Access for some modules (TCC, Safari extensions)
- `launchctl`, `codesign`, `plutil`, `sqlite3` (standard macOS tools)

## Output Directories

All modules write to their respective output directories:
- `extract_ids_output/` - Identifier extraction results
- `manifest_output/` - Evidence manifests
- `validate_output/` - Validation reports
- `verify_trust_output/` - Trust verification reports
- `xpc_scan_output/` - XPC scan results
- `dns_monitor_output/` - DNS monitoring results
- `score_output/` - Confidence scoring results
- `tcc_scan_output/` - TCC permission scans
- `browser_audit_output/` - Browser extension audits
- `login_items_output/` - Login items audits
- `ios_forensic_output/` - iOS analysis results

## License

This tool is provided for forensic analysis and security research purposes. Use responsibly and in accordance with applicable laws.

## Version

**Apple OS Forensic Analyzer v2.0.0**

Major restructure with enhanced detection capabilities, confidence-based scoring, and iOS support.
