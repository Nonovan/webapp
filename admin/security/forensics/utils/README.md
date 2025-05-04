# Forensic Analysis Utilities

This directory contains shared utility functions and helper modules that support the Forensic Analysis Toolkit. These utilities provide common functionality used across different forensic tools to ensure consistency, maintainability, and security during digital forensic investigations.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Usage](#usage)
  - [Evidence Tracking](#evidence-tracking)
  - [Timestamp Handling](#timestamp-handling)
  - [Format Conversion](#format-conversion)
  - [Sanitization](#sanitization)
  - [Report Generation](#report-generation)
  - [HTML Report Generation](#html-report-generation)
  - [File Operations](#file-operations)
- [Security Features](#security-features)
- [Best Practices](#best-practices)
- [Related Documentation](#related-documentation)

## Overview

The forensic analysis utilities implement core functionality needed by multiple components of the toolkit, including secure logging, cryptographic operations, timestamp handling, and data sanitization. These utilities follow forensic best practices to maintain evidence integrity, support proper chain of custody, and ensure findings can withstand scrutiny in legal proceedings if necessary.

## Key Components

- **`sanitize.py`**: Data sanitization utilities
  - Removal of sensitive information from logs and reports
  - PII detection and redaction
  - Credential scrubbing from artifacts
  - Content normalization for consistent analysis
  - Safe data handling for external sharing

- **`crypto.py`**: Cryptographic verification tools
  - Evidence hash calculation and verification
  - Hash comparison with multiple algorithms
  - Digital signature verification
  - Secure evidence encryption/decryption
  - Key management for evidence protection

- **`logging_utils.py`**: Secure logging utilities
  - Forensically sound activity logging
  - Tamper-evident log generation
  - Chain of custody tracking
  - Timestamped operation recording
  - Evidence access auditing

- **`timestamp_utils.py`**: Timestamp normalization tools
  - Timestamp conversion across timezones
  - Timeline normalization and creation
  - Timestamp correlation across sources
  - Timestamp validation and verification
  - Time skew detection and anomaly identification
  - Timezone offset handling and conversions

- **`file_utils.py`**: Forensic file operations
  - Secure file reading with integrity checks
  - Write-blocking for evidence preservation
  - Forensic file copying with metadata preservation
  - File attribute preservation and extraction
  - Secure temporary file handling
  - Directory hash calculations
  - Secure archive extraction

- **`evidence_tracker.py`**: Evidence management utilities
  - Evidence tagging and classification
  - Chain of custody documentation
  - Evidence metadata management
  - Access tracking for evidence
  - Evidence relationship mapping
  - Evidence container creation
  - Chain of custody exports in multiple formats
  - Case-based evidence listing and management

- **`validation_utils.py`**: Input validation functions
  - Command parameter validation
  - Path sanitation and traversal prevention
  - File format verification
  - Integrity check validation
  - Type and range validation

- **`format_converter.py`**: File format conversion utilities
  - Binary to text conversions (base64, hex)
  - Timestamp format standardization
  - Data structure transformations (JSON, XML, CSV)
  - Character encoding detection and handling
  - Safe format conversion with validation

- **`report_builder.py`**: Report generation utilities
  - Standardized report templates
  - Multi-format output (text, JSON, HTML, PDF)
  - Template-based report generation
  - Findings categorization and formatting
  - Legal compliance with reporting standards

- **`network_utils.py`**: Network forensics utilities
  - Network capture parsing
  - Protocol analysis helpers
  - Connection reconstruction
  - Network identifier normalization
  - Traffic pattern analysis support

- **`forensic_constants.py`**: Common constants and configurations
  - Standardized timestamp formats
  - Default file paths and settings
  - Common forensic file signatures
  - Standard placeholder values
  - System-wide forensic settings

## Directory Structure

```plaintext
admin/security/forensics/utils/
├── README.md              # This documentation
├── crypto.py              # Cryptographic verification tools
├── evidence_tracker.py    # Evidence management utilities
├── file_utils.py          # Forensic file operations
├── format_converter.py    # File format conversion utilities
├── forensic_constants.py  # Common constants and configurations
├── logging_utils.py       # Secure logging utilities
├── network_utils.py       # Network forensics utilities
├── report_builder.py      # Report generation utilities
├── sanitize.py            # Data sanitization utilities
├── timestamp_utils.py     # Timestamp normalization tools
└── validation_utils.py    # Input validation functions
```

## Usage

The utility functions are designed to be imported and used by forensic tools:

```python
from admin.security.forensics.utils import crypto, file_utils, logging_utils

# Calculate and verify file hash
file_path = "/secure/evidence/incident-42/suspicious_file.exe"
hash_value = crypto.calculate_hash(file_path, algorithm="sha256")
logging_utils.log_forensic_operation("hash_calculation", {"file": file_path, "hash": hash_value})

# Secure file copy with metadata preservation
source_path = "/secure/evidence/incident-42/config.xml"
dest_path = "/secure/evidence/incident-42/analysis/config.xml"
file_utils.secure_copy(source_path, dest_path, preserve_metadata=True)

# Normalize timestamps across different log sources
server_log_time = "2023-07-15T08:24:15+00:00"
client_log_time = "2023-07-15 03:24:18 -0500"
normalized_times = timestamp_utils.normalize_timestamps([server_log_time, client_log_time])
```

### Evidence Tracking

```python
from admin.security.forensics.utils import evidence_tracker

# Register new evidence
evidence_id = evidence_tracker.register_evidence(
    file_path="/secure/evidence/incident-42/memory.dump",
    evidence_type="memory_dump",
    acquisition_method="live_acquisition",
    analyst="johndoe",
    case_id="incident-42"
)

# Update chain of custody
evidence_tracker.track_access(
    evidence_id=evidence_id,
    analyst="janedoe",
    purpose="memory analysis",
    action="read"
)

# Retrieve chain of custody for reporting
custody_chain = evidence_tracker.get_chain_of_custody(evidence_id)

# List evidence for a specific case
case_evidence = evidence_tracker.list_evidence_by_case("incident-42")

# Create an evidence container for transfer or storage
container_path = evidence_tracker.create_evidence_container(
    case_id="incident-42",
    evidence_ids=["EV-2023-001", "EV-2023-002"],
    analyst="johndoe",
    container_type="zip",
    encryption_password="secure-password-123"
)

# Export chain of custody documentation
export_path = evidence_tracker.export_chain_of_custody(
    case_id="incident-42",
    evidence_id="EV-2023-001",
    format="pdf",
    include_signatures=True
)
```

### Timestamp Handling

```python
from admin.security.forensics.utils import timestamp_utils

# Parse timestamps from various formats
parsed_time = timestamp_utils.parse_timestamp("Oct 15, 2023 14:30:45 -0700")

# Convert between timestamp formats
iso_time = timestamp_utils.convert_timestamp_format(
    timestamp=1697401845,  # Unix timestamp
    target_format="iso8601"
)

# Calculate time difference between events
time_diff = timestamp_utils.calculate_timestamp_difference(
    "2023-10-15T12:00:00Z",
    "2023-10-15T14:30:00Z"
)

# Create a timeline from events with different timestamp formats
timeline = timestamp_utils.create_timeline([
    {"id": 1, "timestamp": 1697342400, "event": "System startup"},
    {"id": 2, "timestamp": "2023-10-15T10:30:00Z", "event": "User login"},
    {"id": 3, "timestamp": "Oct 15 11:45:23 2023", "event": "Configuration change"}
])

# Detect timestamp anomalies in a dataset
anomalies = timestamp_utils.detect_timestamp_anomalies([
    "2023-10-15T08:00:00Z",
    "2023-10-15T08:15:00Z",
    "2023-10-15T10:30:00Z",  # Potential gap
    "2025-10-15T08:30:00Z"   # Future timestamp
])
```

### Format Conversion

```python
from admin.security.forensics.utils import format_converter

# Convert between binary and encoding formats
hex_data = format_converter.convert_binary_to_hex(binary_data)
original_binary = format_converter.convert_hex_to_binary(hex_data)

base64_data = format_converter.convert_binary_to_base64(binary_data)
original_binary = format_converter.convert_base64_to_binary(base64_data)

# Convert between data structure formats
xml_data = format_converter.convert_json_to_xml(json_data, root_name="evidence")
json_data = format_converter.convert_xml_to_json(xml_data)
csv_data = format_converter.convert_json_to_csv(json_data)

# Convert between timestamp types
epoch_time = format_converter.convert_between_timestamp_types(
    "2023-10-15T12:30:00Z",
    target_format="epoch"
)

# Handle text encodings
utf8_text = format_converter.convert_to_utf8(binary_data, source_encoding="latin-1")
encoding = format_converter.detect_encoding(binary_data)
```

### Sanitization

```python
from admin.security.forensics.utils import sanitize

# Redact sensitive information from a log file
sanitized_content = sanitize.redact_sensitive_data(
    content=log_content,
    patterns=["password", "api_key", "token", "credit_card", "ssn"],
    replacement="[REDACTED]"
)

# Sanitize an export for external sharing
sanitize.prepare_external_report(
    input_path="/secure/evidence/incident-42/analysis/findings.json",
    output_path="/secure/evidence/incident-42/reports/external_findings.json",
    redaction_policy="high"  # Removes all customer data, credentials, and internal IPs
)
```

### Report Generation

```python
from admin.security.forensics.utils import report_builder

# Generate a report in multiple formats
report_data = {
    "case_summary": "Investigation into unauthorized access on server WEB01.",
    "key_findings": [
        {"timestamp": "2023-10-27T10:15:00Z", "finding": "Suspicious login from IP 198.51.100.10", "severity": "High"},
        {"timestamp": "2023-10-27T10:22:00Z", "finding": "Malware detected: Trojan.GenericKD.123", "severity": "Critical"},
    ],
    "evidence_collected": ["Memory dump from WEB01", "Disk image of /var/log partition"]
}

# Generate a PDF report
report_builder.generate_forensic_report(
    report_data=report_data,
    output_path="/secure/evidence/incident-42/reports/forensic_report.pdf",
    report_format="pdf",
    case_id="incident-42",
    analyst_name="Jane Smith",
    report_title="Forensic Analysis of Server Compromise"
)
```

### HTML Report Generation

```python
from admin.security.forensics.utils import generate_html_report_basic

# Generate a basic HTML report when advanced templating is unavailable
report_data = {
    "incident_summary": "Unauthorized access detected on production server",
    "technical_findings": [
        {"finding": "SSH login from unusual IP address", "severity": "High", "time": "2023-11-12T15:45:30Z"},
        {"finding": "Privilege escalation attempt", "severity": "Critical", "time": "2023-11-12T15:52:10Z"},
        {"finding": "Firewall rule modification", "severity": "High", "time": "2023-11-12T15:58:22Z"}
    ],
    "compromised_systems": ["web-server-01", "proxy-server-02"],
    "timeline": {
        "detection": "2023-11-12T15:45:30Z",
        "containment": "2023-11-12T16:30:00Z",
        "remediation": "2023-11-12T19:15:45Z"
    },
    "remediation_steps": [
        "Reset affected user accounts",
        "Block malicious IPs at the firewall",
        "Update SSH configuration to enforce key-based authentication",
        "Deploy additional monitoring for privileged commands"
    ]
}

# Generate an HTML report with basic styling
generate_html_report_basic(
    report_data=report_data,
    output_path="/secure/evidence/incident-42/reports/incident_report.html",
    title="Security Incident Analysis",
    case_id="incident-42",
    analyst_name="John Smith"
)

# For more advanced HTML reports with custom templates
from admin.security.forensics.utils import report_builder

# Generate an HTML report with custom template
report_builder.generate_html_report(
    report_data=report_data,
    output_path="/secure/evidence/incident-42/reports/detailed_report.html",
    template_name="forensic_detailed_template.html",
    template_dirs=["/templates/forensic_reports"],
    metadata={
        "case_id": "incident-42",
        "analyst_name": "John Smith",
        "classification": "Confidential",
        "report_version": "1.0"
    }
)
```

### File Operations

```python
from admin.security.forensics.utils import file_utils

# Calculate hash of an entire directory
hash_results = file_utils.hash_directory_contents(
    directory_path="/secure/evidence/incident-42/extracted_files",
    output_file="/secure/evidence/incident-42/hashes.json",
    recursive=True,
    algorithms=["sha256", "md5"]
)

# Securely extract an archive
success, results = file_utils.extract_archive_securely(
    archive_path="/secure/evidence/incident-42/evidence.zip",
    output_dir="/secure/evidence/incident-42/extracted",
    verify_hash=True,
    expected_hash="a1b2c3...",
    allowed_extensions=[".txt", ".log", ".xml", ".json"]
)
```

## Security Features

- **Evidence Integrity**: All file operations maintain integrity through hashing
- **Non-Destructive Operations**: Default read-only access to evidence files
- **Chain of Custody**: Automatic tracking of all evidence handling
- **Audit Logging**: Comprehensive logging of all utility operations
- **Input Validation**: Thorough validation of all inputs to prevent injection attacks
- **Safe Error Handling**: Error responses that don't reveal sensitive information
- **Secure by Default**: Conservative defaults that prioritize evidence preservation
- **Least Privilege**: Functions operate with minimal required access
- **Secure Cleanup**: Proper cleanup of temporary files and sensitive data in memory
- **Compliance Support**: Features designed to maintain legal admissibility of evidence
- **Anomaly Detection**: Automated identification of timestamp inconsistencies
- **Secure Archive Handling**: Protection against zip bombs and path traversal

## Best Practices

When using these utilities:

1. **Evidence Handling**
   - Always use `file_utils` instead of direct Python file operations
   - Verify hashes before and after operations
   - Log all actions with `logging_utils`
   - Maintain chain of custody with `evidence_tracker`

2. **Secure Operation**
   - Validate all inputs with `validation_utils`
   - Use appropriate error handling
   - Follow principle of least privilege
   - Clean up temporary files and resources

3. **Documentation**
   - Document all forensic processes
   - Include tool versions and command parameters
   - Record timestamps for all operations
   - Maintain detailed chain of custody

4. **Data Protection**
   - Sanitize output before sharing with `sanitize`
   - Use `crypto` for protecting sensitive evidence
   - Apply appropriate access controls to evidence files
   - Securely delete temporary files when no longer needed

5. **Reporting**
   - Use standardized templates for consistency
   - Include all required metadata in reports
   - Maintain separation between facts and analysis
   - Ensure proper handling of sensitive information in reports
   - Use proper output formats based on audience needs

## Related Documentation

- Forensic Analysis Toolkit
- Evidence Handling Guidelines
- Chain of Custody Requirements
- Digital Forensics Procedures
- Incident Response Plan
- Legal and Compliance Considerations
