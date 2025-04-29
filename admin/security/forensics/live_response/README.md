# Live Response Forensic Tools

This directory contains specialized forensic tools for live system investigation during security incident response. These tools focus on capturing volatile data and system state information that would be lost after system shutdown, providing critical evidence for incident analysis while maintaining forensic integrity.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Tool Usage](#tool-usage)
- [Security Features](#security-features)
- [Best Practices](#best-practices)
- [Configuration](#configuration)
- [Installation](#installation)
- [Evidence Handling](#evidence-handling)
- [Compatibility](#compatibility)
- [Troubleshooting](#troubleshooting)
- [Related Documentation](#related-documentation)

## Overview

Live response tools are designed for use during active security incidents to capture volatile system state data before it is lost. These tools follow forensic best practices for evidence collection, maintaining evidence integrity through proper hashing, minimal system impact, and complete chain of custody documentation. They are a critical component of the Forensic Analysis Toolkit, specifically focused on capturing data from running systems.

The toolkit is built for incident responders, security analysts, and digital forensic investigators who need to rapidly collect evidence from potentially compromised systems while preserving its admissibility and reliability.

## Key Components

- **`memory_acquisition.sh`**: Memory capture and analysis toolkit
  - Securely acquires full system memory dumps
  - Supports multiple memory acquisition techniques (LiME, AVML, /proc/mem)
  - Implements memory capture verification
  - Handles systems with limited resources
  - Creates hashed memory images with metadata
  - Supports various compression options
  - Optional integrated Volatility analysis for common IOCs

- **`volatile_data.sh`**: Active system state collection
  - Captures process listings with full details
  - Records open network connections and sockets
  - Documents logged-in users and sessions
  - Collects running services and startup items
  - Preserves command history and scheduled tasks
  - Gathers loaded kernel modules/drivers
  - Examines scheduled tasks and startup items
  - Records open file handles and mounted filesystems
  - Supports comprehensive or minimal collection modes

- **`network_state.sh`**: Network activity documentation
  - Maps active network connections
  - Captures current routing tables
  - Documents ARP cache entries
  - Records listening ports and associated processes
  - Preserves network interface configurations
  - Collects DNS cache contents
  - Analyzes firewall rules and configurations
  - Optional packet capture capabilities
  - Identifies potentially suspicious network activity

- **Common utilities**:
  - Chain of custody documentation
  - Evidence integrity verification
  - Safe evidence handling procedures
  - System compatibility checks
  - Secure remote evidence collection

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

# Capture memory from remote system with verification
./memory_acquisition.sh --target remote-host --user forensic-analyst \
  --key ~/.ssh/forensic_key --compress --verify \
  --output /secure/evidence/incident-42/memory.dump \
  --case-id CASE-2024-042 --examiner "Jane Smith"
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

# Collect process data with full command line arguments and environment variables
./volatile_data.sh --target hostname --collect processes \
  --process-args --process-env \
  --output /secure/evidence/incident-42/volatile/ \
  --case-id CASE-2024-042 --examiner "John Doe"

# Quick minimal collection for rapid triage
./volatile_data.sh --target hostname --minimal \
  --output /secure/evidence/incident-42/triage/
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

# Collect firewall rules and network state with integrity verification
./network_state.sh --target hostname --firewall \
  --output /secure/evidence/incident-42/network/ \
  --verify --case-id CASE-2024-042 --examiner "Jane Smith"
```

### Evidence Packaging

```bash
# Package collected evidence with automated chain of custody
./common/evidence_packaging.sh --source /secure/evidence/incident-42/ \
  --output /secure/packages/ --format tar.gz --encrypt \
  --case-id CASE-2024-042 --examiner "John Doe" \
  --description "Server memory and volatile data"
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
- **Audit Trail**: Complete audit logs of all operations performed
- **Timeline Preservation**: Accurate timestamps with timezone information
- **Secure Transfer**: Protected channels for remote evidence collection

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
   - Record environment variables and system state

3. **Minimize System Impact**:
   - Use read-only tools whenever possible
   - Avoid writing to the suspect system disk
   - Use external storage for evidence
   - Document any changes made to the system
   - Mount filesystems read-only when possible

4. **Verify Your Tools**:
   - Use known-good forensic tools
   - Verify tool hashes before use
   - Understand how tools affect the system
   - Test tools in a lab environment first
   - Validate output against known-good results

5. **Handle Evidence Properly**:
   - Create multiple copies of critical evidence
   - Store evidence securely with access controls
   - Maintain proper chain of custody documentation
   - Calculate and verify hashes of all evidence
   - Implement proper evidence storage procedures

6. **Follow Legal Requirements**:
   - Ensure proper authorization for collection
   - Document chain of custody meticulously
   - Follow jurisdiction-specific requirements
   - Consider privacy implications
   - Maintain evidence integrity for legal proceedings

## Installation

The live response toolkit is designed to be self-contained with minimal dependencies:

1. **Clone the repository**:

   ```bash
   git clone https://github.com/example/forensics-toolkit.git
   cd forensics-toolkit/live_response
   ```

2. **Verify integrity**:

   ```bash
   sha256sum -c checksums.sha256
   ```

3. **Make scripts executable**:

   ```bash
   chmod +x *.sh common/*.sh
   ```

4. **Configure defaults** (optional):

   ```bash
   cp config/collection_config.json.example config/collection_config.json
   vi config/collection_config.json  # Edit as needed
   ```

5. **Test in lab environment**:

   ```bash
   ./volatile_data.sh --help
   ./memory_acquisition.sh --list-methods
   ./network_state.sh --help
   ```

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

## Evidence Handling

All tools in the live response kit follow the guidelines outlined in EVIDENCE_GUIDELINES.md, which includes:

- Proper chain of custody documentation
- Cryptographic verification of evidence integrity
- Secure storage practices
- Access controls and audit trails
- Documentation requirements for legal proceedings

For detailed usage instructions, refer to the USAGE.md document, which provides comprehensive guidance on tool operation, parameters, and workflows.

## Compatibility

The toolkit is designed to work across a variety of environments:

| Operating System | Support Level | Notes |
|------------------|---------------|-------|
| Linux (Debian-based) | Full | Preferred platform for all tools |
| Linux (RHEL-based) | Full | CentOS, Fedora, RHEL supported |
| Linux (Other) | Partial | Core functionality works, some distro-specific features may vary |
| macOS | Partial | Most functionality works with Homebrew dependencies |
| Windows | Limited | Requires WSL for most functionality |

## Troubleshooting

Common issues and their solutions:

1. **Permission denied errors**: Ensure you're running with appropriate privileges (typically root/sudo)
2. **Tool not found**: Verify the tool exists and is executable (`chmod +x *.sh`)
3. **Remote connection failures**: Verify SSH connectivity, credentials, and target system availability
4. **Insufficient disk space**: Ensure adequate space for memory dumps and evidence collection
5. **Timeouts during collection**: Check network stability and increase timeout thresholds

For more detailed troubleshooting, refer to the USAGE.md document.

## Related Documentation

- USAGE.md - Detailed usage instructions for all tools
- EVIDENCE_GUIDELINES.md - Evidence handling procedures
- Forensic Analysis Toolkit - Complete forensics documentation
- Incident Response Playbooks - Standard response procedures
- Chain of Custody Templates - Documentation templates
- [NIST SP 800-86: Guide to Integrating Forensic Techniques](https://csrc.nist.gov/publications/detail/sp/800-86/final)
