# Evidence Handling Guidelines for Live Response

This document outlines the standards and procedures for proper evidence handling during live response forensic activities. Following these guidelines ensures the integrity, admissibility, and reliability of digital evidence collected from systems under investigation.

## Contents

- [Introduction](#introduction)
- [Evidence Collection Principles](#evidence-collection-principles)
- [Chain of Custody](#chain-of-custody)
- [Collection Procedures](#collection-procedures)
- [Evidence Storage](#evidence-storage)
- [Verification Methods](#verification-methods)
- [Documentation Requirements](#documentation-requirements)
- [Evidence Types](#evidence-types)
- [Legal Considerations](#legal-considerations)
- [Tools and Commands](#tools-and-commands)

## Introduction

Live response forensics involves collecting volatile data from running systems that would otherwise be lost upon system shutdown. These guidelines establish proper procedures for handling digital evidence during such collection activities to ensure its admissibility in legal proceedings and reliability for incident investigations.

## Evidence Collection Principles

### Order of Volatility

Collect evidence in order of volatility, from most volatile to least volatile:

1. **System memory** (RAM contents, kernel state)
2. **Execution state** (running processes, loaded modules)
3. **Network connections** (active connections, listening ports)
4. **File system metadata** (open files, mounted filesystems)
5. **Operating system logs** (system logs, application logs)
6. **Physical storage content** (disk images)

### Minimal Impact

All live response activities must minimize alteration of evidence:

- Use read-only tools and methods whenever possible
- Document any necessary changes to the system
- Understand the footprint of collection tools
- Avoid writing evidence to the source system disk
- Use write-blockers when accessing persistent storage

### Documentation

Document all collection activities including:

- Time and date of collection (with timezone information)
- Identity of the collector/examiner
- Methods and tools used for collection
- System state at the time of collection
- Commands executed on the system
- Hash values of all collected data

## Chain of Custody

Chain of custody documentation must be maintained for all evidence to establish:

1. **Who** collected the evidence
2. **When** it was collected (date and time with timezone)
3. **Where** it was collected from (system identifier)
4. **What** was collected (evidence description)
5. **Why** it was collected (case/incident reference)
6. **How** it was collected (tools and methods)

For each evidence item, track:

- Initial acquisition
- All access events
- All transfers between custodians
- Analysis activities
- Verification procedures
- Storage conditions

### Chain of Custody Form Fields

All evidence must be tracked using the standard chain of custody form with these fields:

| Field | Description |
|-------|-------------|
| Evidence ID | Unique identifier for the evidence item |
| Case ID | Investigation case identifier |
| Description | Brief description of the evidence |
| Collection Date/Time | When the evidence was collected (ISO 8601 format with timezone) |
| Collection Location | System or network location evidence was collected from |
| Collector Name | Name of the person who collected the evidence |
| Collection Method | Tools and commands used for collection |
| Hash Value | Cryptographic hash of the evidence (SHA-256 preferred) |
| Evidence Type | Category of evidence (memory dump, process list, etc.) |
| Evidence Format | File format or structure of the evidence |
| Storage Location | Where the evidence is stored |
| Access History | Log of all access to the evidence |

## Collection Procedures

### Pre-Collection

Before collecting evidence:

1. Verify authorization for evidence collection
2. Prepare clean, write-protected storage media
3. Synchronize system clock with a reliable time source
4. Document the current system state
5. Test collection tools in a controlled environment
6. Prepare collection command sequences in advance

### During Collection

While collecting evidence:

1. Use the tools from `volatile_data.sh`, `network_state.sh`, or `memory_acquisition.sh`
2. Execute collection in order of volatility
3. Document all commands executed on the system
4. Generate cryptographic hashes immediately after collection
5. Save outputs to write-once or write-protected media
6. Capture collection time with timezone information
7. Record any errors or anomalies encountered

### Evidence Handling

When handling the collected evidence:

1. Never modify original evidence files
2. Create working copies for analysis
3. Verify integrity through hash comparison
4. Store evidence securely with access controls
5. Maintain proper chain of custody documentation
6. Log all access to the evidence

## Evidence Storage

### Storage Media

Store evidence on appropriate media:

- Use write-once media when possible (e.g., DVD-R)
- If using rewritable media, implement write-protection
- Encrypt sensitive evidence in transit and at rest
- Use media appropriate for the retention period

### Storage Environment

Maintain proper storage environment:

- Physical security controls (locked cabinets, access control)
- Environmental controls (temperature, humidity)
- Protection from electromagnetic interference
- Redundant storage for critical evidence

### Storage Format

Use appropriate evidence storage formats:

- Raw formats for memory dumps (`.raw`, `.dump`, `.mem`)
- Structured formats for metadata (`.json`, `.xml`)
- Text formats for logs and command outputs (`.txt`, `.log`)
- Include collection metadata with each evidence file

## Verification Methods

Verify evidence integrity using:

### Hash Verification

- Calculate hashes immediately after acquisition
- Use SHA-256 as the primary hash algorithm
- Document hash values in the chain of custody
- Re-verify hashes before analysis and presentation

Example hash verification command:

```bash
# Calculate SHA-256 hash
sha256sum evidence_file.img > evidence_file.img.sha256

# Verify hash
sha256sum -c evidence_file.img.sha256
```

### Integrity Verification Tools

- Use tools from the live response toolkit that automatically verify evidence
- Implement dual-hash algorithms for critical evidence (SHA-256 and SHA-1)
- Document all verification attempts and results

## Documentation Requirements

Each evidence collection must include:

### Collection Documentation

- System identification information
- Date and time of collection (with timezone)
- Name and role of the collector
- Collection method and tools used
- Command line arguments used
- System state during collection
- Any errors or anomalies observed

### Evidence Metadata

- Evidence type and description
- Source location (hostname, IP, path)
- Hash values (algorithm and value)
- File size and format
- Classification level
- Retention requirements

### Analysis Documentation

- Analysis methodology
- Tools and versions used
- Findings and observations
- Interpretation of results
- Limitations of analysis
- Analyst identification

## Evidence Types

### Memory Evidence

Memory acquisitions should include:

- Full memory dumps (.raw/.dump)
- Memory analysis results
- Process memory dumps for suspicious processes
- Hash verification files

### Network Evidence

Network evidence should include:

- Active connection lists
- Network interface configurations
- Listening port information
- Routing tables
- ARP cache contents
- DNS settings and cache
- Firewall rules
- Packet captures (if collected)

### System State Evidence

System state evidence should include:

- Running process lists with full command lines
- Loaded kernel modules/drivers
- Logged-in user information
- Open file handles
- Mounted filesystems
- System configuration
- Startup items and scheduled tasks
- Command history

## Legal Considerations

### Evidence Admissibility Requirements

For evidence to be admissible in legal proceedings:

1. **Authentication**: Evidence must be what it purports to be
2. **Reliability**: Collection methods must be reliable and repeatable
3. **Integrity**: Evidence must not have been altered
4. **Chain of Custody**: Complete documentation of all handling
5. **Expert Testimony**: May require qualified expert explanation

### Regulatory Requirements

Consider regulatory requirements specific to the environment:

- Financial services (SOX, GLBA)
- Healthcare (HIPAA)
- Payment card (PCI DSS)
- Personal data (GDPR, CCPA)
- Critical infrastructure (NERC CIP)

### Privacy Considerations

Respect privacy requirements:

- Collect only relevant evidence
- Minimize collection of personal/sensitive information
- Follow legal authorization boundaries
- Apply appropriate data protection controls
- Document privacy impact assessment for sensitive collections

## Tools and Commands

### Approved Collection Tools

Use only approved collection tools from the live response toolkit:

- volatile_data.sh for system state acquisition
- network_state.sh for network evidence collection
- memory_acquisition.sh for memory dumps
- Common utility scripts from the toolkit

### Command Line Options

Use command line options that ensure:

- Minimal system impact
- Proper output formatting
- Accurate timestamps
- Complete evidence collection
- Automatic chain of custody entries
- Built-in integrity verification

Example commands:

```bash
# Memory acquisition with integrity verification
./memory_acquisition.sh --target hostname --output /secure/evidence/incident-42/memory.dump --compress --verify

# Volatile data collection
./volatile_data.sh --target hostname --collect processes,network,users,modules --output /secure/evidence/incident-42/volatile/ --case-id CASE-2024-42 --examiner "Jane Analyst"

# Network state collection
./network_state.sh --target hostname --output /secure/evidence/incident-42/network/ --case-id CASE-2024-42 --examiner "Jane Analyst"
```

### Command Documentation

Document commands with:

- Full command line with all options
- Purpose of command execution
- Timestamp of execution
- Expected output
- Actual result
- Any error messages

## Related Documentation

- Chain of Custody Form
- Evidence Inventory Template
- Evidence Log Template
- Digital Forensics Procedures
- [NIST SP 800-86: Guide to Integrating Forensic Techniques](https://csrc.nist.gov/publications/detail/sp/800-86/final)
