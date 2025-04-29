# Common Components for Static Analysis

This directory contains shared utilities and common components used by the static analysis tools within the Forensic Analysis Toolkit. These components provide core functionality for file analysis, signature detection, and hash-based identification of suspicious files.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Usage](#usage)
- [Security Features](#security-features)
- [Best Practices](#best-practices)
- [Related Documentation](#related-documentation)

## Overview

The common components provide foundational functionality required across all static analysis tools. They implement file handling utilities, signature checking capabilities, hash computation functions, and YARA rule integration. These shared components ensure consistent behavior across the toolkit while maintaining proper security controls and providing optimized implementations of frequently used operations.

## Key Components

- **`file_utils.py`**: File handling utilities
  - Secure file opening with integrity validation
  - File type identification
  - Metadata extraction
  - Structure parsing for common file formats
  - Safe temporary file handling
  - Permission-safe file operations
  - Non-destructive evidence analysis

- **`hash_utils.py`**: Hash calculation and comparison
  - Multi-algorithm hash generation (MD5, SHA-1, SHA-256, etc.)
  - Fuzzy hash implementation (SSDEEP, TLSH)
  - Hash comparison with configurable thresholds
  - Hash database integration
  - Optimized hash calculation for large files
  - Integrity verification functions
  - Hash-based similarity analysis

- **`output_constants.py`**: Shared constants for static analysis tools
  - Output format definitions
  - String analysis regex patterns
  - File analysis constants
  - Entropy analysis thresholds
  - Standardized IOC patterns
  - YARA scanning parameters
  - String extraction parameters

- **`signature_db/`**: Signature database system
  - File signature identification
  - Known malware signature detection
  - Code signing certificate verification
  - Signature database management
  - Threat intelligence integration
  - Regular database updates
  - Historical signature matching

- **`yara_rules/`**: YARA rule collection
  - Malware family detection rules
  - Ransomware-specific detection patterns
  - Suspicious code pattern identification
  - Rule management and organization
  - Optimized scanning capabilities
  - Regular rule updates
  - Custom rule development framework

## Directory Structure

```plaintext
admin/security/forensics/static_analysis/common/
├── __init__.py               # Package initialization
├── README.md                 # This documentation
├── file_utils.py             # File handling utilities
├── hash_utils.py             # Hash calculation and comparison
├── output_constants.py       # Shared constants and regex patterns
├── signature_db/             # Signature database system
│   ├── README.md             # Signature database documentation
│   ├── code_signing/         # Code signing certificate database
│   │   ├── corporate_certs.json  # Organization-approved certificates
│   │   ├── revoked_certs.json    # Revoked certificates list
│   │   └── trusted_certs.json    # Trusted certificate authorities
│   ├── file_types/           # File format signature database
│   │   ├── archive_formats.json  # Archive file signatures
│   │   ├── binary_formats.json   # Binary file signatures
│   │   ├── document_formats.json # Document file signatures
│   │   ├── executable_formats.json # Executable file signatures
│   │   └── magic_bytes.bin       # Magic bytes database
│   └── malware/              # Malware signature database
│       ├── README.md         # Malware database documentation
│       ├── yara_index.json   # YARA rule set index
│       ├── patterns/         # Binary pattern signatures
│       └── yara_rules/       # YARA rule definitions
└── yara_rules/               # YARA rule collection
    ├── README.md             # YARA rules documentation
    ├── malware/              # Malware detection rules
    │   ├── README.md         # Malware rules documentation
    │   ├── backdoors.yar     # Backdoor detection rules
    │   ├── keyloggers.yar    # Keylogger detection rules
    │   ├── ransomware.yar    # Generic ransomware rules
    │   └── trojans.yar       # Trojan detection rules
    ├── ransomware/           # Specific ransomware rules
    │   ├── README.md         # Ransomware rules documentation
    │   ├── crypto_functions.yar  # Encryption routine detection
    │   ├── file_markers.yar      # File extension and marker detection
    │   ├── ransom_notes.yar      # Ransom note templates
    │   └── specific_families/ # Family-specific rules
    └── suspicious/           # Suspicious code pattern rules
        ├── README.md         # Suspicious pattern documentation
        ├── credentials.yar   # Credential theft detection
        ├── evasion.yar       # Anti-analysis techniques
        ├── execution.yar     # Suspicious execution techniques
        ├── injection.yar     # Process/memory injection techniques
        ├── network.yar       # Suspicious network activity
        ├── obfuscation.yar   # Code obfuscation techniques
        ├── persistence.yar   # Persistence mechanism detection
        └── shellcode.yar     # Shellcode detection patterns
```

## Usage

The common components are designed to be imported and used by the static analysis tools:

### Basic File Analysis

```python
from admin.security.forensics.static_analysis.common import file_utils
from admin.security.forensics.static_analysis.common.output_constants import (
    DEFAULT_MIN_STRING_LENGTH, SUPPORTED_OUTPUT_FORMATS
)

# File type identification
file_info = file_utils.safe_analyze_file('/path/to/evidence/suspicious_file')
file_type = file_utils.identify_file_type('/path/to/evidence/suspicious_file')
print(f"File type: {file_type['description']}")

# Metadata extraction based on format
metadata = file_utils.extract_metadata_by_format('/path/to/evidence/suspicious_file')

# Extract strings with minimum length from constants
strings = file_utils.extract_file_strings(
    '/path/to/evidence/suspicious_file',
    min_length=DEFAULT_MIN_STRING_LENGTH
)

# Calculate entropy to detect potential encryption/obfuscation
entropy_data = file_utils.calculate_file_entropy('/path/to/evidence/suspicious_file')
if entropy_data['total_entropy'] > 7.5:
    print("High entropy detected, possible encryption or compression")

# Save results in a supported format
file_utils.save_analysis_report(
    {"file_info": file_info, "metadata": metadata, "strings": strings[:10], "entropy": entropy_data},
    '/path/to/evidence/analysis/results.json',
    format="json"  # from SUPPORTED_OUTPUT_FORMATS
)
```

### Hash Calculation and Verification

```python
from admin.security.forensics.static_analysis.common import hash_utils

# Calculate multiple hashes at once
hashes = hash_utils.calculate_multiple_hashes(
    '/path/to/evidence/suspicious_file',
    algorithms=['md5', 'sha1', 'sha256', 'ssdeep', 'tlsh']
)

# Verify file integrity
original_hash = "eacf1c27e5385b0e5f2d7a722ed7e41f9c9a7548ad170c2411dfe17e7415a3eb"
is_valid = hash_utils.verify_hash(
    '/path/to/evidence/suspicious_file',
    expected_hash=original_hash,
    algorithm='sha256'
)

# Find similar files using fuzzy hashing
similar_files = hash_utils.find_similar_files(
    directory_path='/path/to/evidence/directory',
    threshold=70,  # Similarity threshold percentage
    algorithm='ssdeep',
    recursive=True
)

# Create a hash database for future comparisons
hash_utils.create_hash_database(
    directory_path='/path/to/evidence/directory',
    output_path='/path/to/evidence/analysis/hash_database.json',
    algorithms=['sha256', 'ssdeep'],
    recursive=True,
    include_path_info=True
)

# Compare specific files using fuzzy hashing
similarity = hash_utils.compare_fuzzy_hashes(
    hash1="24:8emSDuPeJgfQcSrxY9MKJoJsYlBBhsS820yXs:aem6PeJf9MKJoJsYlBsS8Xs",
    hash2="24:8emSDuPeJgfQcSrAxY9MKJoJsYlBsS820yXs:aem6PeJf9MKJoJsYlBsS8Xs",
    algorithm='ssdeep'
)
print(f"File similarity: {similarity}%")
```

### Signature and YARA Analysis

```python
from admin.security.forensics.static_analysis.common.signature_db import SignatureDBManager
from admin.security.forensics.static_analysis.common.yara_rules import YaraScanner

# Initialize signature database manager
db_manager = SignatureDBManager()

# Check malware signatures
signature_matches = db_manager.check_malware_signatures('/path/to/evidence/suspicious_file')
if signature_matches:
    for match in signature_matches:
        print(f"Malware detected: {match.name}, Type: {match.malware_type}, Risk: {match.risk_level}")

# Verify code signing certificate
cert_status = db_manager.verify_code_signature('/path/to/evidence/signed_executable.exe')
if cert_status.verified:
    print(f"Signed by: {cert_status.signer_name}, {cert_status.signature_timestamp}")
    print(f"Certificate authority: {cert_status.issuer}")
    print(f"Valid from: {cert_status.valid_from} to {cert_status.valid_to}")
else:
    print(f"Signature verification failed: {cert_status.reason}")

# Perform YARA rule scanning with specific rule sets
scanner = YaraScanner(
    rule_paths=[
        "admin/security/forensics/static_analysis/common/yara_rules/malware",
        "admin/security/forensics/static_analysis/common/yara_rules/suspicious/execution.yar",
        "admin/security/forensics/static_analysis/common/yara_rules/suspicious/obfuscation.yar"
    ]
)
yara_matches = scanner.scan_file('/path/to/evidence/suspicious_file')

# Process and report on matches
for match in yara_matches:
    print(f"Rule: {match.rule}, Category: {match.meta.get('category', 'unknown')}")
    print(f"Description: {match.meta.get('description', 'No description')}")
    print(f"Severity: {match.meta.get('severity', 'unknown')}")

    # Extract matched strings if available
    if hasattr(match, 'strings') and match.strings:
        print("Matched patterns:")
        for string_match in match.strings[:3]:  # Show first 3 matches
            offset, identifier, data = string_match
            print(f"  - {identifier} at offset {offset}: {data[:50]}...")
```

### String Analysis with Standard Patterns

```python
from admin.security.forensics.static_analysis.common import file_utils
from admin.security.forensics.static_analysis.common.output_constants import (
    REGEX_URL, REGEX_IPV4, REGEX_DOMAIN, REGEX_EMAIL,
    REGEX_FILEPATH_WINDOWS, REGEX_CMD_EXEC, REGEX_API_KEY
)

# Extract strings from file
file_strings = file_utils.extract_file_strings('/path/to/evidence/suspicious_file')

# Analyze strings for network indicators
network_iocs = []
for string_data in file_strings:
    string_text = string_data["string"]
    string_offset = string_data["offset"]

    # Check against standard patterns from constants
    if REGEX_URL.search(string_text):
        network_iocs.append({
            "type": "url",
            "value": string_text,
            "offset": string_offset
        })
    elif REGEX_DOMAIN.search(string_text):
        network_iocs.append({
            "type": "domain",
            "value": string_text,
            "offset": string_offset
        })
    elif REGEX_IPV4.search(string_text):
        network_iocs.append({
            "type": "ip_address",
            "value": string_text,
            "offset": string_offset
        })

# Check for suspicious commands or credentials
suspicious_items = []
for string_data in file_strings:
    string_text = string_data["string"]
    if REGEX_CMD_EXEC.search(string_text):
        suspicious_items.append({
            "type": "command_execution",
            "value": string_text,
            "offset": string_data["offset"],
            "risk": "high"
        })
    elif REGEX_API_KEY.search(string_text):
        suspicious_items.append({
            "type": "potential_credential",
            "value": string_text,
            "offset": string_data["offset"],
            "risk": "medium"
        })

# Categorize extracted strings by type
categorized_strings = file_utils.categorize_strings(file_strings, [
    {"name": "urls", "pattern": REGEX_URL},
    {"name": "ip_addresses", "pattern": REGEX_IPV4},
    {"name": "file_paths", "pattern": REGEX_FILEPATH_WINDOWS},
    {"name": "commands", "pattern": REGEX_CMD_EXEC},
    {"name": "emails", "pattern": REGEX_EMAIL}
])

# Group and report findings
for category, strings in categorized_strings.items():
    if strings:
        print(f"Found {len(strings)} {category}:")
        for item in strings[:5]:  # Show first 5 matches
            print(f"  - {item['string']}")
        if len(strings) > 5:
            print(f"  ... and {len(strings) - 5} more")
```

### Working with Embedded Files

```python
from admin.security.forensics.static_analysis.common import file_utils

# Extract embedded files from documents, archives, and other containers
embedded_files = file_utils.extract_embedded_files(
    file_path='/path/to/evidence/document.docx',
    output_dir='/path/to/evidence/extracted_files',
    max_depth=2,  # Maximum recursion for nested containers
    max_size=50 * 1024 * 1024  # 50MB size limit
)

# Analyze each extracted file
for embedded_file in embedded_files:
    print(f"Found embedded file: {embedded_file['filename']}")
    print(f"  Original container: {embedded_file['container']}")
    print(f"  Path: {embedded_file['extracted_path']}")
    print(f"  Size: {embedded_file['size']} bytes")
    print(f"  Type: {embedded_file['type']}")

    # Calculate hash for extracted file
    from admin.security.forensics.static_analysis.common import hash_utils
    file_hash = hash_utils.calculate_hash(embedded_file['extracted_path'], 'sha256')
    print(f"  SHA-256: {file_hash}")

    # Scan extracted file with YARA
    from admin.security.forensics.static_analysis.common.yara_rules import YaraScanner
    scanner = YaraScanner()
    matches = scanner.scan_file(embedded_file['extracted_path'])
    if matches:
        print(f"  YARA matches: {len(matches)}")
        for match in matches:
            print(f"    - {match.rule}: {match.meta.get('description', 'No description')}")
```

## Security Features

- **Secure File Handling**: All file operations use proper permissions and secure access methods
- **Integrity Verification**: Evidence files are validated with hash checks before and after operations
- **Memory Protection**: Implements memory-safe operations to prevent execution of malicious code
- **Fail-Safe Defaults**: Uses conservative defaults requiring explicit opt-in for intensive operations
- **Input Validation**: All input parameters are validated before use
- **Error Handling**: Comprehensive error handling with secure error reporting
- **Resource Limits**: Implements safeguards against resource exhaustion
- **Principle of Least Privilege**: Components operate with minimal required permissions
- **Sandbox Execution**: Analysis is performed in restricted environments to prevent execution
- **Audit Logging**: All operations are logged for security and forensic verification
- **Chain of Custody**: Built-in controls to maintain evidence integrity throughout analysis
- **Read-Only Analysis**: Default operations are non-destructive to preserve original evidence
- **Security Classification**: Support for marking outputs with appropriate security classifications
- **Secure Temporary Files**: Temporary files are handled securely with proper permissions and cleanup
- **Buffer Overflow Prevention**: All operations implement measures to prevent buffer overflow attacks

## Best Practices

When using these common components:

1. **File Handling**
   - Always use `file_utils` for file operations instead of direct Python I/O
   - Validate file paths before access to prevent path traversal issues
   - Use read-only access when possible to preserve evidence integrity
   - Implement proper error handling for all file operations
   - Hash evidence files before and after analysis to verify integrity
   - Limit file sizes with configurable thresholds to prevent resource exhaustion

2. **Hash Verification**
   - Generate hashes before and after operations to verify integrity
   - Use multiple hash algorithms for comprehensive verification
   - Store hash values with evidence for future validation
   - Compare hashes against known malware databases
   - Document all hash values in analysis reports
   - Use appropriate algorithms based on requirements (cryptographic vs. fuzzy)

3. **Signature Analysis**
   - Regularly update signature databases to detect latest threats
   - Use multiple signature sources for better coverage
   - Document signature matches in analysis reports
   - Understand signature confidence levels for proper analysis
   - Implement proper error handling for signature database failures
   - Consider false positive rates when interpreting results

4. **YARA Rules**
   - Combine multiple YARA rules for more accurate detection
   - Optimize rules to prevent performance degradation
   - Handle rule exceptions properly to prevent analysis failure
   - Regularly update rules with emerging threat patterns
   - Test rule performance on representative sample sets
   - Implement timeouts to prevent hanging on complex rules

5. **Performance Considerations**
   - Use appropriate rule subsets for specific analysis types
   - Implement timeouts for all operations to prevent hanging
   - Process large files in chunks to manage memory consumption
   - Use appropriate parallelization for performance optimization
   - Monitor memory usage during complex analyses
   - Implement resource limits for automated batch processing

6. **Pattern Matching**
   - Use standardized regex patterns from `output_constants.py` for consistency
   - Validate regex matches to reduce false positives
   - Consider context when evaluating pattern matches
   - Group related patterns for more efficient analysis
   - Implement timeouts for complex pattern matching operations
   - Cache results for frequent pattern searches

7. **Evidence Handling**
   - Maintain proper chain of custody with logging of all operations
   - Document all analysis steps for reproducibility
   - Use the built-in report generation for consistent documentation
   - Follow standard evidence handling procedures
   - Never modify original evidence files
   - Track all generated artifacts for case completeness

8. **Reporting and Documentation**
   - Use standardized report formats for consistency
   - Include comprehensive metadata in all reports
   - Document analysis methodology and tool versions
   - Clearly separate facts from interpretation in reports
   - Include limitations and caveats in analysis results
   - Follow proper evidence handling guidelines for report distribution

## Related Documentation

- Static Analysis Tools Guide
- Forensic Analysis Toolkit
- [YARA Documentation](https://yara.readthedocs.io/)
- File Format Analysis Guide
- Malware Analysis Methodology
- Evidence Handling Guidelines
- Chain of Custody Requirements
- Signature Development Process
- Forensic Report Generation
- YARA Rule Development Guide
