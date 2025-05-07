# Forensic Tools for Incident Response

This directory contains tools for digital forensic acquisition, analysis, and investigation during security incidents. These tools follow forensic best practices to preserve evidence integrity and maintain proper chain of custody.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Usage Examples](#usage-examples)
- [Directory Structure](#directory-structure)
- [Configuration](#configuration)
- [Timeline Builder API](#timeline-builder-api)
- [User Activity Monitoring API](#user-activity-monitoring-api)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Related Documentation](#related-documentation)

## Overview

The forensic tools provide capabilities for collecting, preserving, and analyzing digital evidence during security incidents. These tools implement proper forensic procedures to ensure evidence is collected in a forensically sound manner that preserves its integrity and admissibility. Each tool follows established forensic standards and maintains detailed chain of custody documentation.

## Key Components

- **`disk_imaging.sh`**: Disk imaging and storage tools
  - Forensic disk imaging with write-blocking capabilities
  - Support for multiple image formats (dd, raw, E01)
  - Sparse image creation for efficiency
  - Image verification with multiple hash algorithms
  - Partitioned disk support and filesystem awareness

- **`file_integrity.py`**: File integrity verification tools
  - Multi-algorithm hash calculation (MD5, SHA-1, SHA-256)
  - Recursive directory hashing
  - File system timeline extraction
  - Modified file detection
  - Baseline comparison functionality

- **`memory_acquisition.sh`**: Memory capture and analysis utilities
  - Live memory acquisition from running systems
  - Memory capture in various formats (raw, lime, aff4)
  - Memory acquisition verification through hashing
  - Support for multiple operating systems
  - Minimal footprint to prevent evidence contamination

- **`network_capture.sh`**: Network traffic acquisition tools
  - Full packet capture capabilities
  - Protocol filtering options
  - Traffic isolation mechanisms
  - PCAP file management
  - Capture integrity verification

- **`timeline_builder.py`**: Incident timeline construction
  - Event correlation across multiple log sources
  - Timeline visualization and export options (JSON, CSV, HTML, Markdown)
  - Automated timestamp normalization
  - Anomaly detection in event sequences
  - Pattern recognition in event data
  - Phase identification in incident timelines
  - Timeline merging and correlation capabilities
  - Template-based timeline creation

- **`user_activity_monitor.py`**: User activity analysis and monitoring
  - User activity data collection and preservation
  - Activity timeline construction and visualization
  - Behavior pattern analysis and anomaly detection
  - Cross-system activity correlation
  - Authorization anomaly detection
  - Session reconstruction and analysis
  - User access pattern analysis
  - Evidence export in forensic formats

## Usage Examples

### Memory Acquisition

```bash
# Acquire memory from a Linux system
./memory_acquisition.sh --target 192.168.1.10 --auth-key /path/to/key --output /secure/evidence/incident-42/memory.lime

# Analyze a memory dump
python analyze_memory.py --memory-file /secure/evidence/incident-42/memory.lime --profile Linux4_15_0 --output /secure/evidence/incident-42/memory_analysis/
```

### Disk Imaging

```bash
# Create a forensic disk image
./disk_imaging.sh --device /dev/sdb --format raw --compress --verify --output /secure/evidence/incident-42/disk.dd

# Mount a disk image in read-only mode
./disk_imaging.sh --mount /secure/evidence/incident-42/disk.dd --mountpoint /mnt/evidence --read-only
```

### Network Capture

```bash
# Capture network traffic on a specific interface
./network_capture.sh --interface eth0 --duration 30m --filter "port 80 or port 443" --output /secure/evidence/incident-42/network.pcap

# Extract indicators from network capture
./network_capture.sh --analyze /secure/evidence/incident-42/network.pcap --extract-indicators --output /secure/evidence/incident-42/network_iocs.json
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

```python
# Create a timeline from multiple log sources
python timeline_builder.py --sources syslog,auth,apache,database --start "2023-06-10 08:00:00" --end "2023-06-12 18:00:00" --output /secure/evidence/incident-42/timeline.json

# Merge multiple timelines
python timeline_builder.py --merge /secure/evidence/incident-42/timeline1.json,/secure/evidence/incident-42/timeline2.json --output /secure/evidence/incident-42/merged-timeline.json

# Export timeline to different formats
python timeline_builder.py --input /secure/evidence/incident-42/timeline.json --export html,csv,md --output-dir /secure/evidence/incident-42/
```

### User Activity Monitoring

```bash
# Collect user activity data for a specific user
./user_activity_monitor.py collect --user-id john.doe --timeframe 48h --output /secure/evidence/IR-2023-042/user_activity

# Generate user activity timeline
./user_activity_monitor.py timeline --user-id john.doe --timeframe 72h --format json \
    --output /secure/evidence/IR-2023-042/user_timeline.json

# Detect anomalies in user behavior
./user_activity_monitor.py analyze --user-id john.doe --baseline 30d --detection-window 48h \
    --sensitivity high --output /secure/evidence/IR-2023-042/anomaly_report.json
```

## Directory Structure

```plaintext
admin/security/incident_response_kit/forensic_tools/
├── README.md                 # This documentation
├── disk_imaging.sh           # Disk imaging utilities
├── file_integrity.py         # File integrity validation tool
├── memory_acquisition.sh     # Memory dump acquisition script
├── network_capture.sh        # Network traffic capture utilities
├── timeline_builder.py       # Incident timeline construction tool
└── user_activity_monitor.py  # User activity monitoring and analysis tool
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
VOLATILITY_PATH=$(jq -r '.forensic_tools.volatility' "$TOOL_PATHS_CONFIG")
BULK_EXTRACTOR_PATH=$(jq -r '.forensic_tools.bulk_extractor' "$TOOL_PATHS_CONFIG")
```

## Timeline Builder API

The `timeline_builder.py` module exposes the following key classes and functions:

### Timeline Classes

- **`Timeline`**: Container for timeline events
  - **`add_event(timestamp, event_type, description, source, metadata=None)`**: Add an event to the timeline
  - **`export(format, output_path)`**: Export timeline to specified format
  - **`filter_by_time(start_time, end_time)`**: Filter events by time range
  - **`filter_by_type(event_types)`**: Filter events by specific types
  - **`merge(other_timeline)`**: Merge with another timeline
  - **`sort()`**: Sort timeline events chronologically

- **`TimelineBuilder`**: Helper for constructing timelines
  - **`add_log_source(path, source_type, parser=None)`**: Add a log file as event source
  - **`analyze()`**: Run analysis on the timeline
  - **`build()`**: Construct the timeline from all extracted events
  - **`parse_sources()`**: Parse added sources and extract events

- **`TimelineEvent`**: Individual timeline event
  - **`from_dict(data)`**: Create event from dictionary
  - **`to_dict()`**: Convert event to dictionary format
  - **`validate()`**: Validate event data completeness and integrity

### Functions

- **`analyze_timeline(timeline, analysis_type)`**: Run analysis on a timeline
- **`build_timeline(sources, start_time=None, end_time=None)`**: Build a timeline from multiple sources
- **`detect_anomalies(timeline)`**: Detect anomalous events in a timeline
- **`export_timeline(timeline, format, output_path)`**: Export a timeline to specified format
- **`merge_timelines(timeline_files)`**: Merge multiple timeline files
- **`normalize_timestamps(timeline, timezone='UTC')`**: Normalize all timestamps to given timezone
- **`parse_log_file(log_path, source_type)`**: Parse a log file into timeline events

## User Activity Monitoring API

The user_activity_monitor.py module provides the following functionality:

### Core Functions

- **`analyze_user_behavior(user_id, baseline_period, analysis_window, detection_sensitivity='medium')`**: Performs behavioral analysis to detect anomalies
- **`collect_user_activity(user_id, time_period, activity_types=None, include_metadata=True, output_dir=None)`**: Collects and preserves user activity data
- **`detect_access_anomalies(user_id, resource_type=None, resource_id=None, baseline_days=30, detection_hours=24)`**: Detects unusual resource access patterns
- **`detect_authorization_anomalies(user_id, detection_hours=24, sensitivity='medium')`**: Identifies unusual permission usage patterns
- **`generate_activity_timeline(user_id, time_period, include_related_events=False, add_context=True, output_format='json')`**: Creates chronological timeline of user activities

### Helper Functions

- **`correlate_activities(user_id, related_indicator=None, time_window=None)`**: Correlates user activities with other events
- **`export_activity_evidence(user_id, time_period, format='json', evidence_dir=None, chain_of_custody=True)`**: Exports user activity data in forensic format
- **`extract_login_patterns(user_id, days=30)`**: Extracts authentication patterns for the user
- **`find_concurrent_sessions(user_id, detection_hours=24)`**: Identifies potentially concurrent user sessions
- **`get_resource_access_summary(user_id, days=30)`**: Summarizes resource access by type

### Classes

- **`ActivityTimeline`**: Timeline representation of user activities
- **`UserActivityCollection`**: Container for collected user activity data with integrity verification
- **`UserBehaviorAnalysis`**: Analysis engine for user behavior patterns

### Constants

- **`ACTIVITY_TYPES`**: Activity type constants
  - `ADMIN_ACTION`: Administrative actions
  - `CONFIG_CHANGE`: Configuration changes
  - `LOGIN`: Authentication events
  - `LOGOUT`: Session termination events
  - `RESOURCE_ACCESS`: Resource access events
  - `SECURITY_EVENT`: Security-related events

- **`DETECTION_SENSITIVITY`**: Sensitivity levels for anomaly detection
  - `HIGH`: Detect subtle anomalies (may have more false positives)
  - `LOW`: Detect only significant anomalies (fewer false positives)
  - `MEDIUM`: Balanced detection threshold

- **`EVIDENCE_FORMATS`**: Supported evidence export formats
  - `CSV`: Comma-separated values
  - `EVTX`: Windows Event Log XML format
  - `JSON`: Structured JSON format
  - `MARKDOWN`: Markdown documentation format

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
- **Data Privacy**: Filter out personal information not relevant to the investigation
- **Legal Compliance**: Ensure monitoring complies with applicable privacy regulations
- **Principle of Least Privilege**: Only collect data necessary for the investigation
- **Time Synchronization**: Ensure consistent timestamps across all data sources

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

- Chain of Custody Procedures
- Configuration Files Documentation
- Digital Forensics Procedures
- Evidence Collection Guide
- Incident Response Kit Overview
- Incident Response Procedures
- Security Incident Response Plan
- User Activity Monitoring Guide
