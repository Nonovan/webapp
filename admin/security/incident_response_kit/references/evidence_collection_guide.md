# Evidence Collection Guide

## Contents

- [Overview](#overview)
- [Evidence Collection Principles](#evidence-collection-principles)
- [Collection Procedures](#collection-procedures)
- [Chain of Custody](#chain-of-custody)
- [Evidence Types](#evidence-types)
- [File Evidence Collection](#file-evidence-collection)
- [Memory Evidence Collection](#memory-evidence-collection)
- [Network Evidence Collection](#network-evidence-collection)
- [Log Evidence Collection](#log-evidence-collection)
- [Evidence Packaging](#evidence-packaging)
- [Integrity Verification](#integrity-verification)
- [Implementation Examples](#implementation-examples)
- [Available Functions](#available-functions)
- [Best Practices & Security](#best-practices--security)
- [Related Documentation](#related-documentation)

## Overview

This guide provides standardized procedures for collecting digital evidence during security incident response. Proper evidence collection is critical for effective incident analysis, remediation verification, and potential legal proceedings. These procedures ensure that evidence remains admissible, maintains integrity, and preserves proper chain of custody throughout the collection, storage, and analysis processes.

Digital evidence is fragile and can be easily altered or destroyed. This guide helps ensure that response teams follow forensically sound methods to collect and preserve evidence in a manner that maintains its integrity, authenticity, and admissibility in both internal investigations and potential legal proceedings.

## Evidence Collection Principles

### Order of Volatility

Always collect evidence in order of volatility, from most volatile to least volatile:

1. **System memory** (RAM contents, kernel state)
   - Process memory and execution state
   - Network connections and sockets
   - Kernel modules and drivers
   - Clipboard contents
   - Running processes and services

2. **System state** (dynamic system information)
   - Running processes
   - Network connections
   - Logged-in users
   - Open file handles
   - Running services
   - Scheduled tasks

3. **Network data** (connection and traffic information)
   - Active connections
   - Routing tables
   - ARP cache
   - DNS cache
   - Network traffic captures

4. **Volatile storage** (temporary files and data)
   - Swap files
   - Temporary files
   - Cache files
   - Browser data
   - Recently accessed files

5. **System logs** (system and application logs)
   - Security logs
   - System logs
   - Application logs
   - Event logs
   - Authentication logs

6. **File system** (files and directories)
   - Configuration files
   - User files
   - Application files
   - Hidden files
   - File metadata

7. **Physical media** (persistent storage)
   - Disk images
   - Backup media
   - External storage
   - Network storage
   - Cloud storage

### Minimal Impact

Follow the principle of minimal impact during evidence collection:

- Use read-only tools and methods whenever possible
- Document any necessary changes to the system
- Understand the footprint of collection tools
- Avoid writing evidence to the source system disk
- Use write-blockers when accessing persistent storage
- Document any changes made to systems during collection
- Preserve original timestamps and metadata

### Documentation

Document all aspects of evidence collection:

- Collection date and time (with timezone)
- Collector's identity and role
- Collection methodology and tools
- System state at collection time
- Commands executed with full parameters
- Cryptographic hashes of all collected items
- Chain of custody information
- Storage location and access controls
- Known limitations or issues with collection

## Collection Procedures

### Pre-Collection Planning

Before collecting evidence:

1. **Determine required evidence types**
   - Review incident type requirements (`INCIDENT_TYPE_RECOMMENDED_EVIDENCE`)
   - Identify critical systems and data sources
   - Determine order of collection based on volatility
   - Estimate storage requirements
   - Identify necessary tools and permissions

2. **Prepare collection environment**
   - Verify authorization for evidence collection
   - Prepare storage media with sufficient space
   - Synchronize system clocks with trusted time source
   - Test collection tools in advance
   - Prepare evidence documentation templates
   - Verify write-protection mechanisms are working

3. **Documentation preparation**
   - Create incident-specific case identifier
   - Prepare chain of custody forms
   - Document system state before collection
   - Note current system time and time zone
   - Record collection team members and roles

### Collection Execution

During evidence collection:

1. **Environment initialization**
   - Create secure evidence storage location
   - Initialize the evidence collector with proper parameters
   - Document collection start time and conditions
   - Verify collection tools are functioning correctly

2. **Collection sequence**
   - Follow the order of volatility
   - Begin with memory acquisition if applicable
   - Proceed to system state collection
   - Collect network information
   - Gather logs and configuration files
   - Document each collection step

3. **Integrity preservation**
   - Calculate cryptographic hashes immediately after collection
   - Verify hashes after each transfer operation
   - Use write-once or write-protected media when possible
   - Document hash values in collection logs
   - Maintain proper chain of custody

### Post-Collection Tasks

After collecting evidence:

1. **Evidence verification**
   - Verify all evidence integrity via hashing
   - Document verification results
   - Record any anomalies or issues
   - Verify completeness of collection

2. **Evidence packaging**
   - Package evidence with proper protections
   - Apply tamper-evident seals if physical
   - Label all evidence with case identifier
   - Document package contents and structure
   - Apply appropriate access controls

3. **Final documentation**
   - Complete chain of custody forms
   - Finalize collection documentation
   - Securely store all documentation
   - Record evidence storage location and conditions
   - Update incident management system

## Chain of Custody

Chain of custody documentation must establish:

1. **Who** collected the evidence
   - Full name and role
   - Contact information
   - Organization affiliation
   - Qualification/training level

2. **When** evidence was collected
   - Date and time with timezone
   - Collection duration
   - Timeline of related collection activities
   - Timestamp accuracy verification

3. **Where** evidence was collected from
   - System identifiers
   - Physical location
   - Network location
   - Storage media information

4. **What** was collected
   - Evidence type and description
   - Size and format
   - Cryptographic hash values
   - Evidence identifiers

5. **Why** evidence was collected
   - Case/incident reference
   - Collection authority
   - Purpose of collection
   - Relevance to investigation

6. **How** evidence was collected
   - Tools and methods
   - Commands executed
   - Collection parameters
   - Safety measures implemented

For each evidence transfer, document:

- Source custodian
- Destination custodian
- Transfer date and time
- Transfer method
- Reason for transfer
- Verification steps
- Integrity confirmation

## Evidence Types

The incident response kit supports these evidence types (defined in `EvidenceType` class):

### Memory Evidence

Memory evidence includes dumps of system memory that can reveal:

- Running processes
- Network connections
- Malware artifacts
- Encryption keys
- Authentication tokens
- Execution traces
- Command history
- Injected code

Tools for memory acquisition:

- Linux: avml, LiME, Linux Memory Extractor
- Windows: winpmem, DumpIt, FTK Imager
- macOS: osxpmem, MacQuisition

### System State Evidence

System state evidence provides a snapshot of system conditions:

- Running processes
- Loaded modules
- System configuration
- User sessions
- Service status
- Scheduled tasks
- Installed software
- System resources

Tools for system state collection:

- Process listings: ps, tasklist, Get-Process
- System information: uname, systeminfo, hostnamectl
- Module information: lsmod, driverquery, Get-WmiObject
- User sessions: w, quser, query user

### Network Evidence

Network evidence captures connection information and traffic:

- Active connections
- Listening ports
- Network configuration
- Routing information
- DNS settings
- Network traffic captures
- ARP cache
- Network interfaces

Tools for network evidence collection:

- Connection information: netstat, ss, Get-NetTCPConnection
- Interface configuration: ifconfig, ip addr, ipconfig
- Routing information: route, ip route, Get-NetRoute
- Traffic capture: tcpdump, Wireshark, netsh trace

### Log Evidence

Log evidence includes system and application logs:

- Authentication logs
- System logs
- Application logs
- Security logs
- Access logs
- Error logs
- Audit logs
- Event logs

Log file locations:

- Linux: /var/log directory
- Windows: Event Logs, Application-specific logs
- macOS: /var/log, Console logs

### File Evidence

File evidence includes files and directories:

- Configuration files
- User data files
- Application files
- Database files
- Temporary files
- Web server files
- Malware samples
- Source code

File collection considerations:

- Maintain original metadata
- Calculate cryptographic hashes
- Preserve directory structure
- Document file permissions
- Note file timestamps

## File Evidence Collection

### Individual Files

To collect individual files with integrity preservation:

```python
from admin.security.incident_response_kit.collect_evidence import EvidenceCollector

# Initialize evidence collector
collector = EvidenceCollector(
    incident_id="IR-2023-042",
    analyst="security_analyst"
)

# Collect a configuration file
evidence_id = collector.collect_file(
    file_path="/etc/passwd",
    evidence_type="configuration",
    description="System password file containing user accounts"
)

# Collect a suspicious executable
evidence_id = collector.collect_file(
    file_path="/tmp/suspicious.exe",
    evidence_type="malware_sample",
    description="Suspicious executable found in temporary directory"
)
```

### Directory Collection

To collect entire directories while maintaining structure:

```python
# Collect application directory
evidence_id = collector.collect_directory(
    directory_path="/opt/application/",
    evidence_type="file_system",
    description="Application directory with possible compromise",
    create_baseline=True  # Create integrity baseline
)

# Collect user home directory
evidence_id = collector.collect_directory(
    directory_path="/home/compromised_user/",
    evidence_type="file_system",
    description="Home directory of potentially compromised user",
    create_baseline=True
)
```

### Command Output Collection

To collect command output as evidence:

```python
# Collect output of a system command
evidence_id = collector.collect_command_output(
    command=["ls", "-la", "/var/log"],
    evidence_type="system_state",
    description="Directory listing of system logs",
    timeout=30
)

# Collect more complex command output
evidence_id = collector.collect_command_output(
    command=["find", "/", "-name", "*.php", "-mtime", "-7"],
    evidence_type="system_state",
    description="Recently modified PHP files across the system",
    timeout=300
)
```

## Memory Evidence Collection

### Memory Acquisition

Memory acquisition must be performed early in the response process before system shutdown:

1. **Linux Memory Acquisition**

   Use the collector's command output function:

   ```python
   # Using AVML for Linux memory acquisition
   evidence_id = collector.collect_command_output(
       command=["/usr/bin/avml", "/tmp/memory.dump"],
       evidence_type="memory_dump",
       description="Full memory acquisition using AVML",
       timeout=3600  # Allow up to an hour for memory dumps
   )

   # Register the memory dump as evidence
   memory_evidence_id = collector.collect_file(
       file_path="/tmp/memory.dump",
       evidence_type="memory_dump",
       description="System memory dump acquired with AVML"
   )
   ```

2. **Windows Memory Acquisition**

   ```python
   # Using winpmem for Windows memory acquisition
   evidence_id = collector.collect_command_output(
       command=["winpmem.exe", "C:\\evidence\\memory.raw"],
       evidence_type="memory_dump",
       description="Full memory acquisition using winpmem",
       timeout=3600
   )

   # Register the memory dump as evidence
   memory_evidence_id = collector.collect_file(
       file_path="C:\\evidence\\memory.raw",
       evidence_type="memory_dump",
       description="System memory dump acquired with winpmem"
   )
   ```

3. **macOS Memory Acquisition**

   ```python
   # Using OSXPmem for macOS memory acquisition
   evidence_id = collector.collect_command_output(
       command=["/usr/local/bin/osxpmem", "-o", "/tmp/memory.raw"],
       evidence_type="memory_dump",
       description="Full memory acquisition using OSXPmem",
       timeout=3600
   )
   ```

### Process Memory

To capture memory of specific processes:

```python
# Capture memory of a specific process
pid = "1234"
evidence_id = collector.collect_command_output(
    command=["gcore", "-o", f"/tmp/process_{pid}", pid],
    evidence_type="memory_dump",
    description=f"Memory dump of process {pid}",
    timeout=300
)
```

## Network Evidence Collection

### Connection Information

To collect information about network connections:

```python
# Collect active network connections
evidence_id = collector.collect_command_output(
    command=["netstat", "-tuplan"],
    evidence_type="network_capture",
    description="Active network connections"
)

# Collect listening ports
evidence_id = collector.collect_command_output(
    command=["ss", "-lntp"],
    evidence_type="network_capture",
    description="Listening ports and processes"
)
```

### Network Configuration

To collect network configuration information:

```python
# Collect interface configuration
evidence_id = collector.collect_command_output(
    command=["ip", "addr"],
    evidence_type="network_capture",
    description="Network interface configuration"
)

# Collect routing information
evidence_id = collector.collect_command_output(
    command=["ip", "route"],
    evidence_type="network_capture",
    description="Routing table information"
)

# Collect ARP cache
evidence_id = collector.collect_command_output(
    command=["arp", "-a"],
    evidence_type="network_capture",
    description="ARP cache entries"
)
```

### Network Traffic Capture

To capture network traffic:

```python
# Short traffic capture with tcpdump
evidence_id = collector.collect_command_output(
    command=["tcpdump", "-i", "any", "-s", "0", "-c", "1000", "-w", "/tmp/traffic.pcap"],
    evidence_type="network_capture",
    description="Network traffic sample (1000 packets)",
    timeout=300
)

# Register the packet capture as evidence
evidence_id = collector.collect_file(
    file_path="/tmp/traffic.pcap",
    evidence_type="network_capture",
    description="Network traffic capture"
)
```

## Log Evidence Collection

### System Logs

To collect system logs:

```python
# Linux log collection
for log_path in ["/var/log/syslog", "/var/log/auth.log", "/var/log/messages"]:
    if os.path.exists(log_path) and os.access(log_path, os.R_OK):
        evidence_id = collector.collect_file(
            file_path=log_path,
            evidence_type="log_file",
            description=f"System log: {os.path.basename(log_path)}"
        )

# Windows Event Logs
if sys.platform == "win32":
    for log_name in ["System", "Application", "Security"]:
        output_file = f"C:\\evidence\\{log_name}.evtx"
        evidence_id = collector.collect_command_output(
            command=["wevtutil", "epl", log_name, output_file],
            evidence_type="log_file",
            description=f"Windows {log_name} event log"
        )
```

### Application Logs

To collect application-specific logs:

```python
# Web server logs
web_log_paths = [
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log"
]

for log_path in web_log_paths:
    if os.path.exists(log_path) and os.access(log_path, os.R_OK):
        evidence_id = collector.collect_file(
            file_path=log_path,
            evidence_type="log_file",
            description=f"Web server log: {os.path.basename(log_path)}"
        )

# Database logs
db_log_paths = [
    "/var/log/mysql/mysql.log",
    "/var/log/postgresql/postgresql.log"
]

for log_path in db_log_paths:
    if os.path.exists(log_path) and os.access(log_path, os.R_OK):
        evidence_id = collector.collect_file(
            file_path=log_path,
            evidence_type="log_file",
            description=f"Database log: {os.path.basename(log_path)}"
        )
```

### Log Analysis

To analyze logs and preserve findings:

```python
from admin.security.incident_response_kit import log_analyzer

# Analyze authentication logs
analysis_result = log_analyzer.collect_evidence(
    incident_id="IR-2023-042",
    log_files=["/var/log/auth.log"],
    output_dir="/secure/evidence/IR-2023-042",
    last_hours=24
)

if analysis_result["status"] == "success":
    print(f"Log analysis complete, findings: {analysis_result['findings_count']}")
    print(f"Output written to: {analysis_result['output_file']}")
```

## Evidence Packaging

### Creating Evidence Package

To create a complete evidence package:

```python
# Create an encrypted ZIP package
package_path = collector.create_evidence_package(
    output_path="/secure/evidence/IR-2023-042/evidence_package.zip",
    format="zip",
    include_chain=True,
    encrypt=True,
    password="SecurePassword123!"
)

# Create an unencrypted package
package_path = collector.create_evidence_package(
    output_path="/secure/evidence/IR-2023-042/evidence_package.tar.gz",
    format="tar",
    include_chain=True,
    encrypt=False
)

# Create a directory package
package_path = collector.create_evidence_package(
    output_path="/secure/evidence/IR-2023-042/evidence_package",
    format="directory",
    include_chain=True
)
```

### Package Contents Structure

The evidence package includes:

- `/evidence/` directory containing all collected evidence
- `/metadata/` directory containing:
  - `package_manifest.json`: Package metadata and inventory
  - `chain_of_custody.json`: Chain of custody records
  - Evidence integrity verification information
- Individual evidence metadata files
- Evidence integrity hash files
- Collection environment documentation

## Integrity Verification

### Verification Methods

To verify evidence integrity:

```python
# Verify all collected evidence
verification_results = collector.verify_evidence_integrity()

# Print verification summary
print(f"Evidence verification summary:")
print(f"  Total evidence items: {verification_results['summary']['total']}")
print(f"  Verified: {verification_results['summary']['verified']}")
print(f"  Modified: {verification_results['summary']['modified']}")
print(f"  Missing: {verification_results['summary']['missing']}")
print(f"  Errors: {verification_results['summary']['errors']}")

# Check for modified evidence
if verification_results['summary']['modified'] > 0:
    print("WARNING: Some evidence items appear to have been modified!")
    for item in verification_results["modified"]:
        print(f"  - {item['evidence_id']}: {item['path']}")
```

### Hash Verification

To calculate and verify file hashes:

```python
from admin.security.incident_response_kit.collect_evidence import calculate_hash

# Calculate hash of a file
file_hash = calculate_hash("/path/to/evidence.file")
print(f"SHA-256 hash: {file_hash}")

# Verify a file against known hash
expected_hash = "a1b2c3d4e5f6..."
actual_hash = calculate_hash("/path/to/evidence.file")
if actual_hash == expected_hash:
    print("Hash verification successful")
else:
    print("Hash verification failed")
```

## Implementation Examples

### Command Line Usage

```bash
# Initialize evidence collection with incident ID
python -m admin.security.incident_response_kit.collect_evidence \
  --incident-id IR-2023-042 \
  --output-dir /secure/evidence/IR-2023-042 \
  --analyst "Security Analyst" \
  --classification "Confidential"

# Collect system information
python -m admin.security.incident_response_kit.collect_evidence \
  --incident-id IR-2023-042 \
  --system-info \
  --process-list \
  --network \
  --logs

# Collect memory evidence
python -m admin.security.incident_response_kit.collect_evidence \
  --incident-id IR-2023-042 \
  --memory

# Collect specific files
python -m admin.security.incident_response_kit.collect_evidence \
  --incident-id IR-2023-042 \
  --file /etc/passwd \
  --file /var/log/auth.log

# Collect specific directories
python -m admin.security.incident_response_kit.collect_evidence \
  --incident-id IR-2023-042 \
  --directory /opt/application \
  --directory /home/compromised_user

# Create evidence package
python -m admin.security.incident_response_kit.collect_evidence \
  --incident-id IR-2023-042 \
  --create-package \
  --package-format zip \
  --encrypt \
  --password "SecurePassword123!"
```

### Python API Usage

```python
from admin.security.incident_response_kit import collect_evidence
from admin.security.incident_response_kit.incident_constants import EvidenceType

# Collect evidence from a system
results = collect_evidence(
    incident_id="IR-2023-042",
    target="compromised-host",
    output_dir="/secure/evidence/IR-2023-042",
    collect=["logs", "system_info", "process_list", "network_connections"],
    analyst="Security Analyst"
)

if results["status"] == "completed":
    print(f"Evidence collection complete")
    print(f"Evidence stored in: {results['evidence_dir']}")
    print(f"Total evidence items: {len(results['collected_evidence'])}")
```

### Advanced Collection Workflow

```python
from admin.security.incident_response_kit.collect_evidence import EvidenceCollector
from admin.security.incident_response_kit.incident_constants import EvidenceType, IncidentType

# Step 1: Initialize collector with incident ID
collector = EvidenceCollector(
    incident_id="IR-2023-042",
    evidence_dir="/secure/evidence/IR-2023-042",
    analyst="Security Analyst",
    classification="Confidential"
)

# Step 2: Collect volatile data first (memory)
if sys.platform == "linux":
    collector.collect_command_output(
        command=["/usr/bin/avml", "/tmp/memory.raw"],
        evidence_type=EvidenceType.MEMORY_DUMP,
        description="Memory acquisition with AVML",
        timeout=3600
    )
    collector.collect_file(
        file_path="/tmp/memory.raw",
        evidence_type=EvidenceType.MEMORY_DUMP,
        description="System memory dump"
    )

# Step 3: Collect system state information
collector.collect_command_output(
    command=["ps", "aux"],
    evidence_type=EvidenceType.SYSTEM_STATE,
    description="Running processes"
)

collector.collect_command_output(
    command=["netstat", "-tuplan"],
    evidence_type=EvidenceType.NETWORK_CAPTURE,
    description="Network connections"
)

# Step 4: Collect logs
for log_file in ["/var/log/syslog", "/var/log/auth.log"]:
    if os.path.exists(log_file) and os.access(log_file, os.R_OK):
        collector.collect_file(
            file_path=log_file,
            evidence_type=EvidenceType.LOG_FILE,
            description=f"System log file: {os.path.basename(log_file)}"
        )

# Step 5: Collect application data
collector.collect_directory(
    directory_path="/opt/webapp/",
    evidence_type=EvidenceType.FILE_SYSTEM,
    description="Web application directory",
    create_baseline=True
)

# Step 6: Verify evidence integrity
verification_results = collector.verify_evidence_integrity()
print(f"Evidence verification summary:")
print(f"  Verified items: {verification_results['summary']['verified']}")
print(f"  Modified items: {verification_results['summary']['modified']}")

# Step 7: Create evidence package
package_path = collector.create_evidence_package(
    output_path="/secure/evidence/IR-2023-042/evidence_package.zip",
    format="zip",
    include_chain=True,
    encrypt=True,
    password="SecurePassword123!"
)

print(f"Evidence package created: {package_path}")
```

## Available Functions

### Evidence Collection Functions

```python
from admin.security.incident_response_kit.collect_evidence import (
    EvidenceCollector,
    Evidence,
    collect_evidence,
    calculate_hash
)
```

#### `EvidenceCollector` Class

- **`__init__(incident_id, evidence_dir=None, analyst=None, retention_period=None, classification="Confidential")`** - Initialize evidence collector
  - Parameters:
    - `incident_id`: Identifier for the incident
    - `evidence_dir`: Base directory for evidence (default: system evidence dir)
    - `analyst`: Person collecting evidence
    - `retention_period`: How long to retain evidence
    - `classification`: Security classification of the evidence

- **`collect_file(file_path, evidence_type, description=None)`** - Collect a file as evidence
  - Parameters:
    - `file_path`: Path to the file to collect
    - `evidence_type`: Type of evidence (from `EvidenceType` constants)
    - `description`: Description of the evidence
  - Returns: Evidence ID if successful, None otherwise

- **`collect_directory(directory_path, evidence_type, description=None, create_baseline=True)`** - Collect a directory as evidence
  - Parameters:
    - `directory_path`: Path to the directory to collect
    - `evidence_type`: Type of evidence (from `EvidenceType` constants)
    - `description`: Description of the evidence
    - `create_baseline`: Whether to create an integrity baseline
  - Returns: Evidence ID if successful, None otherwise

- **`collect_command_output(command, evidence_type, description=None, shell=False, timeout=60, working_dir=None, env=None)`** - Run a command and collect its output as evidence
  - Parameters:
    - `command`: Command to run (string or list of arguments)
    - `evidence_type`: Type of evidence
    - `description`: Description of the evidence
    - `shell`: Whether to run the command in a shell
    - `timeout`: Timeout in seconds
    - `working_dir`: Working directory for the command
    - `env`: Environment variables for the command
  - Returns: Evidence ID if successful, None otherwise

- **`create_evidence_package(output_path=None, format="zip", include_chain=True, encrypt=False, password=None)`** - Create a package of all collected evidence
  - Parameters:
    - `output_path`: Where to store the package (default: evidence dir)
    - `format`: Package format (zip, tar, or directory)
    - `include_chain`: Whether to include chain of custody
    - `encrypt`: Whether to encrypt the package
    - `password`: Password for encryption if encrypt is True
  - Returns: Path to the created package if successful, None otherwise

- **`verify_evidence_integrity()`** - Verify the integrity of all collected evidence
  - Returns: Dictionary with verification results

#### Supporting Functions

- **`collect_evidence(incident_id, target, output_dir=None, collect=None, analyst=None)`** - High-level function to collect evidence from a target system
  - Parameters:
    - `incident_id`: Identifier for the incident
    - `target`: Target to collect from (hostname, IP, file path)
    - `output_dir`: Where to store collected evidence
    - `collect`: List of evidence types to collect
    - `analyst`: Person collecting evidence
  - Returns: Dictionary with collection results

- **`calculate_hash(file_path, algorithm="sha256")`** - Calculate cryptographic hash of a file
  - Parameters:
    - `file_path`: Path to the file
    - `algorithm`: Hash algorithm to use (default: SHA-256)
  - Returns: Hash value as a hexadecimal string

### Evidence Constants

```python
from admin.security.incident_response_kit.incident_constants import EvidenceType
```

#### `EvidenceType` Class

- **`LOG_FILE`**: Log file evidence
- **`MEMORY_DUMP`**: Memory dump evidence
- **`DISK_IMAGE`**: Disk image evidence
- **`NETWORK_CAPTURE`**: Network capture evidence
- **`SCREENSHOT`**: Screenshot evidence
- **`CONFIGURATION`**: Configuration file evidence
- **`MALWARE_SAMPLE`**: Malware sample evidence
- **`SYSTEM_STATE`**: System state evidence
- **`USER_INTERVIEW`**: User interview evidence
- **`EMAIL`**: Email evidence
- **`TIMELINE`**: Event timeline evidence
- **`FILE_SYSTEM`**: File system artifacts
- **`HASH_LIST`**: Hash values list

#### Recommended Evidence Types by Incident

```python
from admin.security.incident_response_kit.incident_constants import (
    INCIDENT_TYPE_RECOMMENDED_EVIDENCE,
    IncidentType
)
```

Example recommended evidence for malware incidents:

- `EvidenceType.MEMORY_DUMP`
- `EvidenceType.LOG_FILE`
- `EvidenceType.MALWARE_SAMPLE`
- `EvidenceType.SYSTEM_STATE`

Example recommended evidence for ransomware incidents:

- `EvidenceType.DISK_IMAGE`
- `EvidenceType.MEMORY_DUMP`
- `EvidenceType.MALWARE_SAMPLE`
- `EvidenceType.SCREENSHOT`

## Best Practices & Security

- **Minimal Impact**: Always prioritize minimal system impact during collection
- **Evidence First**: Collect evidence before attempting remediation
- **Authentication**: Document all authentication used during collection
- **Order of Volatility**: Follow the volatility order for collection sequence
- **Hash Everything**: Calculate and verify hashes for all collected evidence
- **Secure Storage**: Store evidence securely with appropriate access controls
- **Proper Documentation**: Document all collection steps and decisions
- **Chain of Custody**: Maintain unbroken chain of custody for all evidence
- **Write Protection**: Use write blockers or read-only access when possible
- **Access Control**: Limit access to evidence to authorized personnel only
- **Evidence Integrity**: Verify integrity at each transfer or access
- **Anti-Tampering**: Use tamper-evident mechanisms for physical evidence
- **Time Synchronization**: Ensure accurate time synchronization across systems
- **Contemporaneous Notes**: Take detailed, time-stamped notes during collection
- **Tool Validation**: Use validated, tested tools for evidence collection
- **Legal Review**: Have collection processes reviewed by legal counsel

## Related Documentation

- Chain of Custody Template - Template for documenting chain of custody
- Incident Response Plan - Overall incident response process
- Malware Analysis Guide - Guide for analyzing malware samples
- Traffic Analysis Guide - Guide for analyzing network traffic captures
- Forensic Analysis Templates - Templates for forensic analysis documentation
- Live Response Guidelines - Detailed live response procedures
- Malware Sample Handling Guidelines - Procedures for handling malware
- Security Incident Response Plan - Security incident response plan
- [NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/publications/detail/sp/800-86/final)
- [NIST SP 800-61: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
