# Live Response Forensic Toolkit Usage Guide

This guide provides instructions on how to use the Live Response Forensic Toolkit for digital evidence collection during security incident investigations. The toolkit follows forensic best practices to ensure proper evidence collection, preservation, and documentation.

## Contents

- [Overview](#overview)
- [Getting Started](#getting-started)
- [Tool Reference](#tool-reference)
  - [Memory Acquisition](#memory-acquisition)
  - [Volatile Data Collection](#volatile-data-collection)
  - [Network State Collection](#network-state-collection)
  - [Evidence Packaging](#evidence-packaging)
- [Common Workflows](#common-workflows)
- [Command Line Reference](#command-line-reference)
- [Authentication Options](#authentication-options)
- [Evidence Handling](#evidence-handling)
- [Troubleshooting](#troubleshooting)
- [Related Documentation](#related-documentation)

## Overview

The Live Response Forensic Toolkit provides a collection of specialized tools for capturing volatile data from live systems during security incident response. These tools prioritize evidence integrity while following the order of volatility to preserve the most perishable data first.

Key features:

- Memory acquisition with multiple supported methods
- Process, network connection, and user session data collection
- Kernel module and loaded driver analysis
- Comprehensive network state documentation
- Evidence integrity validation
- Automated chain of custody documentation

## Getting Started

### Prerequisites

- Administrative/root access on the target system
- External storage device for evidence collection (write once media preferred)
- Proper authorization for forensic activities (incident response authorization)

### Installation

The toolkit is designed to run with minimal dependencies, often directly from external media:

```bash
# Clone the repository (if not using pre-packaged version)
git clone https://github.com/example/live-response.git

# Make scripts executable
cd live-response
chmod +x *.sh

# Verify integrity (optional but recommended)
sha256sum -c checksums.txt
```

### Basic Usage

1. Mount external evidence media
2. Create a case identifier
3. Run the appropriate collection tools
4. Document all activities

## Tool Reference

### Memory Acquisition

The `memory_acquisition.sh` script provides memory capture capabilities for incident response.

#### Basic Usage

```bash
./memory_acquisition.sh --output /path/to/evidence/memory.dump
```

#### Common Options

| Option | Description | Example |
|--------|-------------|---------|
| `--output` | Output location for memory dump | `--output /mnt/evidence/memory.raw` |
| `--method` | Memory acquisition method to use | `--method lime` |
| `--compress` | Enable compression of memory dump | `--compress` |
| `--verify` | Verify dump integrity after acquisition | `--verify` |
| `--case-id` | Case identifier for documentation | `--case-id IR-2024-042` |
| `--examiner` | Name of forensic examiner | `--examiner "Jane Smith"` |

#### Examples

```bash
# Capture memory using LiME module with compression
./memory_acquisition.sh --method lime --compress --output /mnt/evidence/case-42/memory.lime --case-id CASE-2024-042 --examiner "John Doe"

# Capture memory and analyze for indicators of compromise
./memory_acquisition.sh --output /mnt/evidence/memory.raw --analyze --ioc-file /path/to/indicators.txt

# List available acquisition methods
./memory_acquisition.sh --list-methods
```

### Volatile Data Collection

The `volatile_data.sh` script collects process information, network connections, user sessions, loaded modules, and other volatile system state data.

#### Basic Usage

```bash
./volatile_data.sh --output /path/to/evidence/volatile/
```

#### Common Options

| Option | Description | Example |
|--------|-------------|---------|
| `--output` | Directory for evidence files | `--output /mnt/evidence/volatile/` |
| `--collect` | Categories of data to collect | `--collect processes,network,users` |
| `--target` | Remote host to collect from | `--target 192.168.1.10` |
| `--user` | Remote system username | `--user admin` |
| `--key` | SSH private key file | `--key ~/.ssh/ir_key` |
| `--minimal` | Perform minimal collection (faster) | `--minimal` |
| `--process-args` | Include process arguments | `--process-args` |
| `--process-env` | Include process environment | `--process-env` |
| `--case-id` | Case identifier for documentation | `--case-id IR-2024-042` |
| `--examiner` | Name of forensic examiner | `--examiner "Jane Smith"` |

#### Available Collection Categories

- `processes` - Running processes and related information
- `network` - Network connections and configuration
- `users` - User sessions and account information
- `system_info` - System configuration and hardware details
- services - Running services information
- `modules` - Loaded kernel modules/drivers
- `startup_items` - System startup configuration
- `scheduled_tasks` - Scheduled tasks/cron jobs
- `command_history` - Command history for users
- `login_history` - Login/authentication history
- `open_files` - Currently open file handles
- `mounted_devices` - Mounted filesystem information

#### Examples

```bash
# Collect all default categories with process arguments
./volatile_data.sh --output /mnt/evidence/case-42/volatile/ --process-args --case-id CASE-2024-042 --examiner "Jane Smith"

# Collect specific categories on a remote system
./volatile_data.sh --target 10.0.0.5 --user responder --key ~/.ssh/ir_key.pem --collect processes,network,users,system_info --output /mnt/evidence/case-42/volatile/

# Minimal collection for quick triage
./volatile_data.sh --minimal --output /mnt/evidence/case-42/triage/ --case-id CASE-2024-042
```

### Network State Collection

The network_state.sh script collects comprehensive information about network configuration and connections.

#### Basic Usage

```bash
./network_state.sh --output /path/to/evidence/network/
```

#### Common Options

| Option | Description | Example |
|--------|-------------|---------|
| `--output` | Directory for network evidence | `--output /mnt/evidence/network/` |
| `--target` | Remote system to collect from | `--target 192.168.1.25` |
| `--user` | Remote username | `--user admin` |
| `--key` | SSH private key file | `--key ~/.ssh/ir_key` |
| `--capture-packets` | Capture network packets | `--capture-packets 1000` |
| `--connections` | Connection types to focus on | `--connections established` |
| `--firewall` | Include firewall rules | `--firewall` |
| `--case-id` | Case identifier | `--case-id IR-2024-042` |
| `--examiner` | Examiner name | `--examiner "Jane Smith"` |
| `--duration` | Time duration for monitoring | `--duration 5m` |

#### Examples

```bash
# Collect comprehensive network state
./network_state.sh --output /mnt/evidence/case-42/network/ --firewall --case-id CASE-2024-042 --examiner "Jane Smith"

# Collect network state with packet capture
./network_state.sh --output /mnt/evidence/case-42/network/ --capture-packets 5000 --duration 2m

# Remote network state collection
./network_state.sh --target 10.0.0.5 --user responder --key ~/.ssh/ir_key.pem --output /mnt/evidence/case-42/network/
```

### Evidence Packaging

The `evidence_packaging.sh` script packages collected evidence with proper chain of custody documentation.

#### Basic Usage

```bash
./evidence_packaging.sh --source /path/to/evidence/ --output /path/to/packages/ --case-id CASE-42 --examiner "Jane Smith"
```

#### Common Options

| Option | Description | Example |
|--------|-------------|---------|
| `--source` | Source directory with evidence | `--source /mnt/evidence/case-42/` |
| `--output` | Output directory for packages | `--output /mnt/secure/packages/` |
| `--case-id` | Case identifier | `--case-id CASE-2024-042` |
| `--examiner` | Examiner name | `--examiner "Jane Smith"` |
| `--format` | Package format (zip/tar.gz) | `--format tar.gz` |
| `--encrypt` | Encrypt the evidence package | `--encrypt` |
| `--description` | Evidence description | `--description "Server memory and logs"` |
| `--notes` | Additional examiner notes | `--notes "Collected during IR-42"` |

#### Examples

```bash
# Package evidence as encrypted ZIP
./evidence_packaging.sh --source /mnt/evidence/case-42/ --output /mnt/secure/packages/ --case-id CASE-2024-042 --examiner "Jane Smith" --format zip --encrypt

# Package evidence with description and notes
./evidence_packaging.sh --source /mnt/evidence/case-42/memory/ --output /mnt/secure/packages/ --case-id CASE-2024-042 --examiner "Jane Smith" --description "Memory analysis artifacts" --notes "Collected after suspicious process identified"
```

## Common Workflows

### Basic Incident Response Collection

```bash
# Create case directory
export CASE_ID="IR-$(date +%Y%m%d)-001"
export EVIDENCE_DIR="/mnt/evidence/$CASE_ID"
export EXAMINER_NAME="Jane Smith"
mkdir -p "$EVIDENCE_DIR"

# Collect volatile data
./volatile_data.sh --output "$EVIDENCE_DIR/volatile/" --case-id "$CASE_ID" --examiner "$EXAMINER_NAME"

# Collect network state
./network_state.sh --output "$EVIDENCE_DIR/network/" --case-id "$CASE_ID" --examiner "$EXAMINER_NAME"

# Acquire memory
./memory_acquisition.sh --output "$EVIDENCE_DIR/memory.raw" --compress --verify --case-id "$CASE_ID" --examiner "$EXAMINER_NAME"

# Package evidence
./evidence_packaging.sh --source "$EVIDENCE_DIR" --output "/mnt/secure/packages/" --case-id "$CASE_ID" --examiner "$EXAMINER_NAME" --format tar.gz --encrypt
```

### Remote System Collection

```bash
# Set up variables
export CASE_ID="IR-$(date +%Y%m%d)-002"
export EVIDENCE_DIR="/mnt/evidence/$CASE_ID"
export EXAMINER_NAME="John Doe"
export TARGET_HOST="10.0.0.25"
export SSH_KEY="~/.ssh/incident_response_key"
mkdir -p "$EVIDENCE_DIR"

# Collect volatile data from remote system
./volatile_data.sh --target "$TARGET_HOST" --user responder --key "$SSH_KEY" --output "$EVIDENCE_DIR/volatile/" --case-id "$CASE_ID" --examiner "$EXAMINER_NAME"

# Collect network state from remote system
./network_state.sh --target "$TARGET_HOST" --user responder --key "$SSH_KEY" --output "$EVIDENCE_DIR/network/" --case-id "$CASE_ID" --examiner "$EXAMINER_NAME"
```

### Targeted Collection for Specific Incident Types

#### For Suspected Malware Infection

```bash
./volatile_data.sh --output "$EVIDENCE_DIR/volatile/" --collect processes,modules,startup_items,scheduled_tasks,command_history --process-args --process-env --case-id "$CASE_ID" --examiner "$EXAMINER_NAME"
```

#### For Network Intrusion Investigation

```bash
./network_state.sh --output "$EVIDENCE_DIR/network/" --connections established --capture-packets 10000 --firewall --duration 10m --case-id "$CASE_ID" --examiner "$EXAMINER_NAME"
```

## Command Line Reference

### Common Options Across All Tools

| Option | Description | Default |
|--------|-------------|---------|
| `-h`, `--help` | Show help message | N/A |
| `-v`, `--verbose` | Enable verbose output | disabled |
| `-q`, `--quiet` | Suppress all output except errors | disabled |
| `--version` | Show version information | N/A |
| `--log FILE` | Log to specified file | stderr |
| `--case-id ID` | Case identifier for documentation | empty |
| `--examiner ID` | Examiner identifier | current user |

## Authentication Options

### Local Authentication

By default, the tools require appropriate local privileges (typically root/administrator) to run.

### Remote Authentication

For remote collection, the following authentication methods are supported:

- **SSH Key Authentication** (preferred)

  ```bash
  ./volatile_data.sh --target 192.168.1.10 --user responder --key ~/.ssh/ir_key --output /mnt/evidence/
  ```

- **SSH Password Authentication** (not recommended for security reasons)

  ```bash
  # Will prompt for password
  ./volatile_data.sh --target 192.168.1.10 --user responder --output /mnt/evidence/
  ```

## Evidence Handling

See the EVIDENCE_GUIDELINES.md document for detailed information on proper evidence handling procedures. Key principles include:

1. Always collect in order of volatility (memory first, then process information, etc.)
2. Document all collection steps, including commands and timestamps
3. Use write-once or write-protected media for evidence storage
4. Generate and verify hashes for all evidence files
5. Maintain proper chain of custody documentation
6. Store evidence securely with appropriate access controls

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   - Ensure you have administrative/root privileges
   - Check file permissions on the scripts (should be executable)
   - Verify permissions on output directories

2. **SSH Connection Failures**
   - Confirm target system is reachable via SSH
   - Check that credentials or SSH key is valid
   - Verify the user has appropriate permissions on target

3. **Memory Acquisition Failures**
   - Insufficient disk space for memory dump
   - Kernel modules (such as LiME) may need to be compiled
   - Some acquisition methods may be restricted by security controls

4. **Output Validation Errors**
   - Verify output directory exists and is writable
   - Ensure sufficient space on output media
   - Check filesystem compatibility (supports large files, etc.)

### Logging and Debugging

All tools support enhanced logging and debugging:

```bash
# Enable verbose output
./volatile_data.sh --verbose --output /mnt/evidence/

# Log to file instead of console
./volatile_data.sh --log /mnt/evidence/collection.log --output /mnt/evidence/

# Maximum logging for troubleshooting
./volatile_data.sh --verbose --log /mnt/evidence/debug.log --output /mnt/evidence/
```

## Related Documentation

- EVIDENCE_GUIDELINES.md - Guidelines for proper evidence handling
- README.md - Overview of the Live Response Toolkit
- Digital Forensics Procedures - Complete forensics procedures
- Chain of Custody Form - Chain of custody documentation
- Evidence Inventory Template - Evidence inventory documentation
- Evidence Log Template - Evidence collection log
- [NIST SP 800-86: Guide to Integrating Forensic Techniques](https://csrc.nist.gov/publications/detail/sp/800-86/final)
