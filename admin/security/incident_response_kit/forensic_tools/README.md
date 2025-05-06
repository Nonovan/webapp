# Forensic Tools for Incident Response

This directory contains tools for digital forensic acquisition, analysis, and investigation during security incidents. These tools follow forensic best practices to preserve evidence integrity and maintain proper chain of custody.

## Contents

- Overview
- Key Components
- Usage Examples
- Directory Structure
- Configuration
- Best Practices & Security
- Common Features
- Related Documentation

## Overview

The forensic tools provide capabilities for collecting, preserving, and analyzing digital evidence during security incidents. These tools implement proper forensic procedures to ensure evidence is collected in a forensically sound manner that preserves its integrity and admissibility. Each tool follows established forensic standards and maintains detailed chain of custody documentation.

## Key Components

- **`memory_acquisition.sh`**: Memory capture and analysis utilities
  - Live memory acquisition from running systems
  - Memory capture in various formats (raw, lime, aff4)
  - Memory acquisition verification through hashing
  - Support for multiple operating systems
  - Minimal footprint to prevent evidence contamination

- **`disk_imaging.sh`**: Disk imaging and storage tools
  - Forensic disk imaging with write-blocking capabilities
  - Support for multiple image formats (dd, raw, E01)
  - Sparse image creation for efficiency
  - Image verification with multiple hash algorithms
  - Partitioned disk support and filesystem awareness

- **`network_capture.sh`**: Network traffic acquisition tools
  - Full packet capture capabilities
  - Protocol filtering options
  - Traffic isolation mechanisms
  - PCAP file management
  - Capture integrity verification

- **`file_integrity.py`**: File integrity verification tools
  - Multi-algorithm hash calculation (MD5, SHA-1, SHA-256)
  - Recursive directory hashing
  - File system timeline extraction
  - Modified file detection
  - Baseline comparison functionality

- **`timeline_builder.py`**: Incident timeline construction
  - Event correlation across multiple log sources
  - Timeline visualization and export options (JSON, CSV, HTML, Markdown)
  - Automated timestamp normalization
  - Anomaly detection in event sequences
  - Pattern recognition in event data
  - Phase identification in incident timelines
  - Timeline merging and correlation capabilities
  - Template-based timeline creation

## Usage Examples

### Memory Acquisition

```bash
# Acquire memory from a live Linux system
./memory_acquisition.sh --target 10.0.0.5 --format lime --compress --output /secure/evidence/incident-42/memory.lime

# Acquire memory from a local system with verification
./memory_acquisition.sh --local --format raw --verify sha256 --output /secure/evidence/incident-42/memory.raw

# Memory acquisition with automatic chain of custody
./memory_acquisition.sh --target 10.0.0.5 --format aff4 --chain-of-custody --output /secure/evidence/incident-42/memory.aff4
```

### Disk Imaging

```bash
# Create a forensic disk image
./disk_imaging.sh --device /dev/sda --format dd --verify --output /secure/evidence/incident-42/disk.dd

# Create a sparse image of only allocated blocks
./disk_imaging.sh --device /dev/sda --sparse --format E01 --compression low --output /secure/evidence/incident-42/disk.E01

# Remote disk imaging over SSH with write-blocking
./disk_imaging.sh --remote 10.0.0.5 --device /dev/sda --write-block --format raw --output /secure/evidence/incident-42/disk.raw
```

### Network Capture

```bash
# Start full packet capture on a specific interface
./network_capture.sh --interface eth0 --duration 3600 --output /secure/evidence/incident-42/network.pcap

# Capture with specific protocol filtering
./network_capture.sh --interface eth0 --filter "port 80 or port 443" --output /secure/evidence/incident-42/http-traffic.pcap

# Remote network capture with automatic rotation
./network_capture.sh --remote 10.0.0.5 --interface eth0 --rotate size=1G --output /secure/evidence/incident-42/network_capture
```

### File Integrity Verification

```python
# Calculate and verify hashes for a directory
python file_integrity.py --directory /secure/evidence/incident-42/files --algorithms sha256,md5 --output /secure/evidence/incident-42/hashes.json

# Compare current files against a baseline
python file_integrity.py --directory /var/www --baseline /secure/baselines/www-baseline.json --output /secure/evidence/incident-42/integrity-changes.json

# Extract file system timeline
python file_integrity.py --directory /secure/evidence/incident-42/files --extract-timeline --output /secure/evidence/incident-42/filesystem-timeline.csv
```

### Timeline Building

```bash
# Create a new timeline from source files
python timeline_builder.py create --incident-id INC-2023-001 --sources /var/log/auth.log /var/log/apache2/access.log --output /secure/evidence/INC-2023-001/timeline.json

# Extract timeline from log files
python timeline_builder.py extract --logs /var/log/syslog /var/log/auth.log --incident-id INC-2023-001 --output /secure/evidence/INC-2023-001/logs-timeline.json

# Merge multiple timelines
python timeline_builder.py merge --timelines /secure/evidence/INC-2023-001/timeline1.json /secure/evidence/INC-2023-001/timeline2.json --output /secure/evidence/INC-2023-001/merged-timeline.json

# Correlate events across timelines
python timeline_builder.py correlate --timelines /secure/evidence/INC-2023-001/network.json /secure/evidence/INC-2023-001/auth.json --window 300 --output /secure/evidence/INC-2023-001/correlated-events.json

# Analyze timeline for anomalies and patterns
python timeline_builder.py analyze --timeline /secure/evidence/INC-2023-001/timeline.json --output /secure/evidence/INC-2023-001/analysis-results.json

# Create a timeline from a template
python timeline_builder.py template --incident-id INC-2023-001 --vars LEAD_RESPONDER="John Smith" --output /secure/evidence/INC-2023-001/incident-timeline.md
```

## Directory Structure

```plaintext
admin/security/incident_response_kit/forensic_tools/
├── README.md                 # This documentation
├── memory_acquisition.sh     # Memory dump acquisition script
├── disk_imaging.sh           # Disk imaging utilities
├── network_capture.sh        # Network traffic capture utilities
├── file_integrity.py         # File integrity validation tool
└── timeline_builder.py       # Incident timeline construction tool
```

## Configuration

These forensic tools use configurations from the central incident response configuration files:

```python
# Example configuration loading in Python tools
import json
import os

# Get base directory for the incident response kit
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load tool paths configuration
with open(os.path.join(base_dir, 'config', 'tool_paths.json'), 'r') as f:
    tool_paths = json.load(f)

# Access required external tool paths
volatility_path = tool_paths.get('forensic_tools', {}).get('volatility')
bulk_extractor_path = tool_paths.get('forensic_tools', {}).get('bulk_extractor')
```

Shell scripts similarly source configuration:

```bash
#!/bin/bash

# Source paths and configurations
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$BASE_DIR/config"

# Load tool paths configuration
TOOL_PATHS_CONFIG="$CONFIG_DIR/tool_paths.json"
TCPDUMP_PATH=$(jq -r '.system_tools.tcpdump // "/usr/sbin/tcpdump"' "$TOOL_PATHS_CONFIG")
DD_PATH=$(jq -r '.system_tools.dd // "/bin/dd"' "$TOOL_PATHS_CONFIG")
```

## Timeline Builder API

The timeline_builder.py module exposes the following key classes and functions:

### Classes

- **`Timeline`**: Class representing a chronological timeline of incident events
- **`Event`**: Class representing a single timeline event with standardized attributes
- **`TimelineSource`**: Class representing a source of timeline events
- **`CorrelationCluster`**: Class representing a cluster of correlated events
- **`TimelineBuilderError`**: Exception raised for errors in the timeline builder module

### Functions

- **`build_timeline`**: Build a timeline from various sources of events
- **`extract_timeline_from_logs`**: Extract a timeline from log files
- **`merge_timelines`**: Merge multiple timelines into a single timeline
- **`correlate_timelines`**: Correlate events across multiple timelines
- **`analyze_timeline`**: Analyze a timeline to identify patterns, anomalies, and key events
- **`identify_timeline_anomalies`**: Identify anomalies in a timeline
- **`create_template_timeline`**: Create a timeline document from a template

## Best Practices & Security

- **Evidence Integrity**: All tools use hashing to verify evidence integrity
- **Write Protection**: Implement write-blocking to prevent evidence modification
- **Chain of Custody**: Maintain proper documentation of all evidence handling
- **Minimal Footprint**: Tools design minimizes impact on target systems
- **Memory Safety**: Implement proper memory management to prevent evidence contamination
- **Encryption**: Evidence is encrypted during transport and storage
- **Access Control**: Evidence access is restricted and logged
- **Logging**: Detailed logging of all forensic operations
- **Validation**: Multiple validation methods to confirm tool accuracy
- **Documentation**: Automated documentation of all forensic processes

## Common Features

All forensic tools share these common features:

- **Chain of Custody Documentation**: Automated tracking of evidence handling
- **Multiple Hash Verification**: Support for MD5, SHA-1, SHA-256
- **Secure Output Handling**: Proper permissions and encryption for outputs
- **Detailed Logging**: Comprehensive logging of all operations
- **Error Recovery**: Graceful handling of errors during forensic operations
- **Time Synchronization**: Proper handling of timestamps across time zones
- **Evidence Tagging**: Consistent tagging and labeling of evidence artifacts
- **System Preservation**: Minimization of impact on target systems
- **Cross-Platform Support**: Tools work across Linux, Windows, and macOS
- **Output Formatting**: Standardized output formats (JSON, CSV, HTML, Markdown)

## Related Documentation

- Incident Response Kit Overview
- Configuration Files Documentation
- Chain of Custody Procedures
- Evidence Collection Guide
- Incident Response Procedures
- Digital Forensics Procedures
- Security Incident Response Plan
