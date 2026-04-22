# Analysis Contract: extract_ids.sh ↔ validate_nodes.py

This document defines the data contract between `collect/extract_ids.sh` and `analyze/validate_nodes.py`.

## Overview

- **Producer:** `collect/extract_ids.sh` - Extracts com.apple.* identifiers from live system and plists
- **Consumer:** `analyze/validate_nodes.py` - Validates extracted identifiers against whitelists

## Output Format: extract_ids.sh

### Raw Text Output (apple_ids_TIMESTAMP.txt)

The script outputs a plain text file with the following format:

```
# --- Live (TIMESTAMP) ---
com.apple.identifier1
com.apple.identifier2
...

# --- Plists (TIMESTAMP) ---
LABEL=com.apple.identifier3 BINARY=/path/to/binary FILE=/path/to/plist
LABEL=com.apple.identifier4 BINARY=/path/to/binary FILE=/path/to/plist
...
```

**Key Points:**
- Lines starting with `#` are comments/section headers
- Live section: One identifier per line
- Plist section: `LABEL=... BINARY=... FILE=...` format
- All identifiers follow the pattern: `com\.apple\.[A-Za-z0-9._-]+`

### JSON Output (tagged_nodes_TIMESTAMP.json)

The script also generates a JSON file for node-based analysis:

```json
{
  "nodes": [
    {
      "node_id": "node_0000",
      "title": "com.apple.identifier",
      "tags": ["com.apple.identifier"],
      "extracted_at": "YYYYMMDD_HHMMSS"
    },
    ...
  ],
  "total": N
}
```

**Expected Fields:**
- `node_id`: Unique string identifier (format: `node_XXXX`)
- `title`: String description of the node
- `tags`: Array of strings (may contain com.apple.* identifiers)
- `extracted_at`: Timestamp string (format: `YYYYMMDD_HHMMSS`)

## Input Format: validate_nodes.py

### JSON Nodes Input

The validator expects a JSON file with the following structure:

```json
{
  "nodes": [
    {
      "node_id": "string",
      "title": "string",
      "tags": ["string", ...],
      "content": "string (optional)"
    },
    ...
  ]
}
```

**Expected Fields:**
- `node_id`: Unique string identifier
- `title`: Human-readable name/description
- `tags`: Array of strings (may include com.apple.* identifiers)
- `content`: Optional free-form text that will be scanned for com.apple.* patterns

### Whitelist Input

The validator accepts whitelists in two formats:

1. **Text file (one identifier per line):**
   ```
   com.apple.identifier1
   com.apple.identifier2
   # Comments are ignored
   ```

2. **Dynamic generation via launchctl:**
   - If no whitelist file is provided, the script generates a dynamic whitelist from `launchctl list`
   - Falls back to built-in static whitelist if dynamic generation fails

## Validation Logic

The validator performs the following steps:

1. **Extract identifiers from nodes:**
   - Collects all strings from `tags` array
   - Scans `content` field for `com\.apple\.[A-Za-z0-9._-]+` patterns
   - Filters to only strings starting with `com.apple.`

2. **Compare against whitelist:**
   - Any identifier not in the whitelist is flagged as suspicious
   - Suspicious identifiers are added to `suspicious_ids` array

3. **Output validation result:**
   - `passed`: Boolean (true if no suspicious identifiers found)
   - `checked_ids`: Array of all com.apple.* identifiers found
   - `suspicious_ids`: Array of identifiers not in whitelist
   - `reason`: String explaining validation result

## Breaking Changes

If either script changes its output/input format, update this document and:

1. Update `extract_ids.sh` output format → Update `validate_nodes.py` parsing
2. Update `validate_nodes.py` input requirements → Update `extract_ids.sh` JSON generation
3. Add new fields to node structure → Update both scripts and this contract

## Testing

To verify the contract:

```bash
# Run extract_ids.sh
./collect/extract_ids.sh --all

# Run validate_nodes.py on the generated JSON
./analyze/validate_nodes.py --nodes extract_ids_output/tagged_nodes_*.json --demo

# Or use the text output with whitelist
./analyze/validate_nodes.py --whitelist apple_whitelist.txt --demo
```

## Version History

- **v2.0.0** (2026-04-22): Initial contract documentation
