# Live Response Forensic Tools

This directory contains specialized forensic tools for live system investigation during security incident response. These tools focus on capturing volatile data and system state information that would be lost after system shutdown, providing critical evidence for incident analysis while maintaining forensic integrity.

## Contents

- Overview
- Key Components
- Tool Usage
- Security Features
- Best Practices
- Configuration
- Related Documentation

## Overview

Live response tools are designed for use during active security incidents to capture volatile system state data before it is lost. These tools follow forensic best practices for evidence collection, maintaining evidence integrity through proper hashing, minimal system impact, and complete chain of custody documentation. They are a critical component of the Forensic Analysis Toolkit, specifically focused on capturing data from running systems.

## Key Components

- **`memory_acquisition.sh`**: Memory capture and analysis toolkit
  - Securely acquires full system memory dumps
  - Supports multiple memory acquisition techniques
  - Implements memory capture verification
  - Handles systems with limited resources
  - Creates hashed memory images with metadata

- **`volatile_data.sh`**: Active system state collection
  - Captures process listings with full details
  - Records open network connections and sockets
  - Documents logged-in users and sessions
  - Collects running services and startup items
  - Preserves command history and scheduled tasks
  - Gathers loaded kernel modules/drivers

- **`network_state.sh`**: Network activity documentation
  - Maps active network connections
  - Captures current routing tables
  - Documents ARP cache entries
  - Records listening ports and associated processes
  - Preserves network interface configurations
  - Collects DNS cache contents

## Tool Usage

### Memory Acquisition

```bash
# Acquire full memory dump with automated format detection
./memory_acquisition.sh --target hostname --output /secure/evidence/incident-42/memory.dump

# Use specific acquisition method with custom parameters
./memory_acquisition.sh --target hostname --method lime --compress \
  --output /secure/evidence/incident-42/memory.lime

# Capture memory and immediately analyze for IOCs
./memory_acquisition.sh --target hostname --analyze-volatility \
  --output /secure/evidence/incident-42/memory.dump \
  --ioc-file /secure/evidence/incident-42/indicators.txt
```

### Volatile Data Collection

```bash
# Collect all volatile data with default settings
./volatile_data.sh --target hostname --output /secure/evidence/incident-42/volatile/

# Collect specific volatile data categories
./volatile_data.sh --target hostname --collect processes,network,users \
  --output /secure/evidence/incident-42/volatile/

# Collect data with remote authentication
./volatile_data.sh --target hostname --user incident-responder \
  --key /secure/keys/ir_key.pem \
  --output /secure/evidence/incident-42/volatile/
```

### Network State Analysis

```bash
# Capture complete network state
./network_state.sh --target hostname --output /secure/evidence/incident-42/network/

# Focus on specific connection types with packet capture
./network_state.sh --target hostname --connections established \
  --capture-packets 1000 --output /secure/evidence/incident-42/network/

# Monitor for suspicious connections in real-time
./network_state.sh --target hostname --watch suspicious \
  --output /secure/evidence/incident-42/network/ --duration 30m
```

## Security Features

- **Forensic Integrity**: All tools use write-blocking techniques to prevent evidence contamination
- **Minimal Footprint**: Tools are designed to have minimal impact on the target system
- **Memory Protection**: Memory acquisition preserves critical structures and handles anti-forensic techniques
- **Secure Authentication**: Remote collection uses secure, audited authentication methods
- **Evidence Verification**: All collected data is hashed for integrity verification
- **Chain of Custody**: Automated documentation of all collection activities
- **Execution Logging**: Detailed logs of all tool operations for verification
- **Data Encryption**: Option to encrypt sensitive evidence during collection
- **Tamper Detection**: Verification steps to detect any evidence manipulation
- **Access Controls**: Proper permission requirements for tool execution

## Best Practices

1. **Prioritize Collection**: Follow this order of volatility:
   - System memory
   - Network connections and processes
   - File system metadata
   - Log files and registry data

2. **Document Everything**:
   - Record exact commands executed
   - Note system time vs. investigator time
   - Document any errors or anomalies
   - Maintain precise timeline of activities

3. **Minimize System Impact**:
   - Use read-only tools whenever possible
   - Avoid writing to the suspect system disk
   - Use external storage for evidence
   - Document any changes made to the system

4. **Verify Your Tools**:
   - Use known-good forensic tools
   - Verify tool hashes before use
   - Understand how tools affect the system
   - Test tools in a lab environment first

5. **Handle Evidence Properly**:
   - Create multiple copies of critical evidence
   - Store evidence securely with access controls
   - Maintain proper chain of custody documentation
   - Calculate and verify hashes of all evidence

## Configuration

Live response tools are configured through the primary forensic toolkit configuration file:

```json
// collection_config.json
{
  "live_response": {
    "memory_acquisition": {
      "preferred_method": "lime",
      "compression": true,
      "chunk_size_mb": 512,
      "verify_acquisition": true
    },
    "volatile_data": {
      "default_categories": ["processes", "network", "users", "services", "modules"],
      "process_arguments": true,
      "process_environment": false,
      "command_history_lines": 1000
    },
    "network_state": {
      "packet_capture": {
        "enabled": true,
        "max_packets": 10000,
        "max_size_mb": 100,
        "capture_filter": "not port 22"
      }
    },
    "output_options": {
      "format": "structured",
      "timestamp_format": "iso8601",
      "encrypt_evidence": true,
      "compression_algorithm": "zstd"
    }
  }
}
```

## Related Documentation

- Incident Response Procedures
- Forensic Analysis Toolkit
- Evidence Handling Guidelines
- Memory Analysis Techniques
- Chain of Custody Requirements
