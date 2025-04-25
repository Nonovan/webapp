# Forensic Analysis Utilities

This directory contains shared utility functions and helper modules that support the Forensic Analysis Toolkit. These utilities provide common functionality used across different forensic tools to ensure consistency, maintainability, and security during digital forensic investigations.

## Contents

- Overview
- Key Components
- Directory Structure
- Usage
- Security Features
- Best Practices
- Related Documentation

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
  - Timeline normalization
  - Timestamp correlation across sources
  - Timestamp validation and verification
  - Time skew detection and correction

- **`file_utils.py`**: Forensic file operations
  - Secure file reading with integrity checks
  - Write-blocking for evidence preservation
  - Forensic file copying with metadata preservation
  - File attribute preservation and extraction
  - Secure temporary file handling

- **`evidence_tracker.py`**: Evidence management utilities
  - Evidence tagging and classification
  - Chain of custody documentation
  - Evidence metadata management
  - Access tracking for evidence
  - Evidence relationship mapping

- **`validation_utils.py`**: Input validation functions
  - Command parameter validation
  - Path sanitation and traversal prevention
  - File format verification
  - Integrity check validation
  - Type and range validation

## Directory Structure

```plaintext
admin/security/forensics/utils/
├── README.md              # This documentation
├── sanitize.py            # Data sanitization utilities
├── crypto.py              # Cryptographic verification tools
├── logging_utils.py       # Secure logging utilities
├── timestamp_utils.py     # Timestamp normalization tools
├── file_utils.py          # Forensic file operations
├── evidence_tracker.py    # Evidence management utilities
├── validation_utils.py    # Input validation functions
├── format_converter.py    # File format conversion utilities
├── report_builder.py      # Report generation utilities
├── network_utils.py       # Network forensics utilities
└── forensic_constants.py  # Common constants and configurations
```

## Usage

The utility functions are designed to be imported and used by forensic tools:

```python
from admin.security.forensics.utils import crypto, file_utils, logging_utils

# Calculate and verify file hash
file_path = "/secure/evidence/incident-42/suspicious_file.exe"
hash_value = crypto.calculate_hash(file_path, algorithm="sha256")
logging_utils.log_operation("hash_calculation", {"file": file_path, "hash": hash_value})

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

## Related Documentation

- Forensic Analysis Toolkit
- Evidence Handling Guidelines
- Chain of Custody Requirements
- Digital Forensics Procedures
- Incident Response Plan
- Legal and Compliance Considerations
