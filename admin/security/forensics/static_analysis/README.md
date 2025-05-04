# Static Analysis Tools for Forensic Analysis

This directory contains tools for performing static analysis of files and artifacts during digital forensic investigations in the Cloud Infrastructure Platform. These tools enable security teams to analyze suspicious files, binaries, and other digital artifacts without executing them, providing critical insights during incident response.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Usage](#usage)
  - [File Analysis](#file-analysis)
  - [Signature Checking](#signature-checking)
  - [Hash Comparison](#hash-comparison)
  - [Memory String Analysis](#memory-string-analysis)
- [Security Features](#security-features)
- [Common Analysis Workflows](#common-analysis-workflows)
- [Integration](#integration)
- [Reporting](#reporting)
- [Best Practices](#best-practices)
- [Related Documentation](#related-documentation)

## Overview

The static analysis tools provide non-invasive examination capabilities for digital artifacts collected during security incidents. These tools analyze file structure, content, signatures, and characteristics to identify malicious code, suspicious patterns, and potential threats without executing the files. This approach enables safe handling of potentially dangerous artifacts while extracting valuable forensic insights.

Static analysis is typically the first step in forensic examination, providing initial triage before more resource-intensive dynamic analysis is performed. These tools maintain forensic integrity by operating in a read-only mode and preserving chain of custody through comprehensive logging.

## Key Components

- **`file_analyzer.py`**: Comprehensive file structure analysis
  - File format identification and validation
  - File structure parsing and visualization
  - Embedded object detection and extraction
  - Metadata extraction and analysis
  - String extraction with pattern matching
  - Entropy analysis for encryption/obfuscation detection
  - Script deobfuscation for common techniques
  - Resource extraction from executables
  - Header analysis for format verification
  - Compiler artifact identification

- **`signature_checker.py`**: File signature verification and analysis
  - Known malware signature checking
  - YARA rule-based pattern matching
  - Code signing verification
  - Digital signature validation
  - Heuristic-based detection of suspicious patterns
  - File type verification against declared format
  - Rich header analysis for PE files
  - Anti-analysis technique detection
  - Signature coverage assessment
  - Certificate chain validation

- **`hash_compare.py`**: Hash-based file analysis and comparison
  - Multi-algorithm hash calculation (MD5, SHA-1, SHA-256, SSDEEP)
  - Known-bad hash comparison against threat intelligence
  - File integrity verification
  - Similar file identification through fuzzy hashing
  - Binary similarity analysis
  - Historical hash comparison for change detection
  - Imphash calculation for import table analysis
  - Contextual hashing of specific file regions
  - Similarity reporting with confidence scores
  - Tagging of similar malware families

- **`memory_string_analyzer.py`**: Analysis of strings extracted from memory dumps
  - Command line parameter extraction
  - URL and IP address identification
  - Crypto key pattern detection
  - Suspicious API call sequence detection
  - Script/shellcode pattern recognition
  - Natural language processing for ransom notes
  - PII detection with data classification
  - Authentication credential pattern matching
  - Registry key and file path extraction
  - Evasion technique identification

## Directory Structure

```plaintext
admin/security/forensics/static_analysis/
├── README.md               # This documentation
├── __init__.py             # Package initialization and exports
├── file_analyzer.py        # File structure analysis tool
├── signature_checker.py    # File signature verification tool
├── hash_compare.py         # Hash calculation and comparison tool
├── memory_string_analyzer.py # Memory string analysis tool
└── common/                 # Shared components for static analysis
    ├── __init__.py         # Package initialization
    ├── file_utils.py       # File handling utilities
    ├── hash_utils.py       # Hashing functionality
    ├── output_constants.py # Shared constants and regex patterns
    ├── yara_rules/         # YARA rule definitions
    │   ├── README.md       # YARA rules documentation
    │   ├── malware/        # Malware-specific rules
    │   ├── ransomware/     # Ransomware-specific rules
    │   └── suspicious/     # General suspicious pattern rules
    └── signature_db/       # Signature databases
        ├── README.md       # Signature database documentation
        ├── code_signing/   # Trusted code signing certificates
        ├── file_types/     # File type signatures
        └── malware/        # Malware signature database
```

## Usage

### File Analysis

```bash
# Analyze file structure and extract metadata
./file_analyzer.py --file /secure/evidence/incident-42/suspicious.exe \
    --extract-strings \
    --extract-resources \
    --entropy-analysis \
    --output /secure/evidence/incident-42/analysis/file_analysis.json

# Analyze specific sections of a PE file
./file_analyzer.py --file /secure/evidence/incident-42/suspicious.exe \
    --pe-sections --section-entropy \
    --output /secure/evidence/incident-42/analysis/pe_sections.json

# Extract embedded files from document
./file_analyzer.py --file /secure/evidence/incident-42/document.docx \
    --extract-embedded \
    --output-dir /secure/evidence/incident-42/analysis/embedded_files/

# Recursively analyze multiple files
./file_analyzer.py --directory /secure/evidence/incident-42/suspicious_files/ \
    --recursive --file-types exe,dll,js,vbs,ps1 \
    --output-dir /secure/evidence/incident-42/analysis/directory_analysis/

# Analyze script for obfuscation techniques
./file_analyzer.py --file /secure/evidence/incident-42/suspicious.js \
    --deobfuscate --detect-evasion \
    --output /secure/evidence/incident-42/analysis/deobfuscated_script.json
```

### Signature Checking

```bash
# Check file against known malware signatures
./signature_checker.py --file /secure/evidence/incident-42/suspicious.exe \
    --check-signatures \
    --output /secure/evidence/incident-42/analysis/signature_check.json

# Perform YARA rule matching
./signature_checker.py --file /secure/evidence/incident-42/suspicious.js \
    --yara-rules common/yara_rules/suspicious/ \
    --output /secure/evidence/incident-42/analysis/yara_matches.json

# Verify digital signatures on binaries
./signature_checker.py --file /secure/evidence/incident-42/application.dll \
    --verify-signature \
    --output /secure/evidence/incident-42/analysis/signature_verification.json

# Apply all supported signature checks
./signature_checker.py --file /secure/evidence/incident-42/unknown_file \
    --comprehensive --report-level detailed \
    --output /secure/evidence/incident-42/analysis/comprehensive_checks.json

# Batch scanning with CSV report
./signature_checker.py --file-list /secure/evidence/incident-42/file_list.txt \
    --check-signatures --yara-rules common/yara_rules/malware \
    --output-format csv \
    --output /secure/evidence/incident-42/analysis/batch_signature_results.csv
```

### Hash Comparison

```bash
# Calculate multiple hashes of a file
./hash_compare.py --file /secure/evidence/incident-42/suspicious.exe \
    --algorithms md5,sha1,sha256,ssdeep \
    --output /secure/evidence/incident-42/analysis/file_hashes.json

# Compare file against known-bad hash database
./hash_compare.py --file /secure/evidence/incident-42/suspicious.exe \
    --check-database \
    --output /secure/evidence/incident-42/analysis/hash_check.json

# Find similar files using fuzzy hashing
./hash_compare.py --directory /secure/evidence/incident-42/files/ \
    --find-similar --similarity-threshold 80 \
    --output /secure/evidence/incident-42/analysis/similar_files.json

# Compare specific files for similarity
./hash_compare.py --file1 /secure/evidence/incident-42/sample1.bin \
    --file2 /secure/evidence/incident-42/sample2.bin \
    --algorithms ssdeep,tlsh \
    --output /secure/evidence/incident-42/analysis/file_comparison.json

# Create hash database of trusted system files
./hash_compare.py --directory /secure/baseline/system32/ \
    --recursive --algorithms sha256,md5 \
    --create-database --database-name windows_baseline \
    --output /secure/evidence/databases/windows_baseline_hashes.db
```

### Memory String Analysis

```bash
# Analyze strings extracted from memory dump
./memory_string_analyzer.py --file /secure/evidence/incident-42/memdump.raw \
    --detect-credentials \
    --detect-crypto \
    --detect-commands \
    --output /secure/evidence/incident-42/analysis/memory_strings.json

# Extract network indicators from memory strings
./memory_string_analyzer.py --file /secure/evidence/incident-42/memdump.raw \
    --extract-ioc --ioc-type network \
    --output /secure/evidence/incident-42/analysis/network_ioc.json

# Compare strings against known malicious patterns
./memory_string_analyzer.py --file /secure/evidence/incident-42/memdump.raw \
    --pattern-match common/signature_db/malware/patterns/ \
    --output /secure/evidence/incident-42/analysis/malicious_patterns.json

# Extract potential credentials and sensitive data
./memory_string_analyzer.py --file /secure/evidence/incident-42/memdump.raw \
    --extract-pii --credential-patterns \
    --classify-sensitivity \
    --output /secure/evidence/incident-42/analysis/sensitive_data.json

# Process strings from multiple memory dumps
./memory_string_analyzer.py --file-list /secure/evidence/incident-42/memory_files.txt \
    --consolidated-report \
    --detect-all \
    --output /secure/evidence/incident-42/analysis/multi_dump_analysis.json
```

## Common Analysis Workflows

### Suspicious File Triage

1. First, check file hashes against known malware databases:

   ```bash
   ./hash_compare.py --file suspicious_file.exe --check-database --json
   ```

2. If no matches, perform comprehensive file analysis:

   ```bash
   ./file_analyzer.py --file suspicious_file.exe --comprehensive --extract-strings
   ```

3. Run signature and YARA checks:

   ```bash
   ./signature_checker.py --file suspicious_file.exe --check-signatures --yara-rules common/yara_rules/
   ```

4. For executables, verify digital signatures:

   ```bash
   ./signature_checker.py --file suspicious_file.exe --verify-signature
   ```

5. Extract any embedded files or resources:

   ```bash
   ./file_analyzer.py --file suspicious_file.exe --extract-resources --extract-embedded
   ```

6. Generate comprehensive report:

   ```bash
   ./generate_static_analysis_report.py --input-dir analysis/ --template comprehensive
   ```

### Memory Forensics Integration

1. Extract strings from memory dump (using external memory forensics tool):

   ```bash
   ./extract_memory_strings.sh memdump.raw > strings.txt
   ```

2. Analyze extracted strings for indicators:

   ```bash
   ./memory_string_analyzer.py --file strings.txt --detect-all
   ```

3. Compare with known file hashes:

   ```bash
   ./hash_compare.py --file-list extracted_files.txt --check-database
   ```

4. Cross-reference findings with network traffic:

   ```bash
   ./correlate_findings.py --memory-analysis memory_analysis.json --network-pcap network.pcap
   ```

## Security Features

- **Sandbox Execution**: All tools operate in restricted environments to prevent accidental execution
- **Integrity Protection**: Evidence files are opened in read-only mode to preserve integrity
- **Chain of Custody**: All operations are logged with timestamps and analyst information
- **Evidence Hashing**: Files are hashed before and after analysis to verify integrity
- **Secure Output Handling**: Analysis results are stored with appropriate access controls
- **Memory Protection**: Tools implement memory protection to prevent code execution
- **Resource Limits**: Processing has strict resource limits to prevent denial of service
- **Secure Cleanup**: Memory and temporary files are securely wiped after processing
- **Privilege Separation**: Tools run with minimal required privileges
- **Input Validation**: All file inputs and parameters are validated before processing
- **File Quarantine**: Automatic quarantine of highly suspicious files
- **Secure Logging**: Tamper-evident logging of all analysis operations
- **Defense in Depth**: Multiple detection techniques applied to each artifact
- **Forensic Readiness**: Outputs designed for defensible findings in legal proceedings
- **Data Classification**: Automatic tagging of sensitive data in analysis reports
- **Analysis Traceability**: Each finding linked to its detection method and evidence source

## Integration

These static analysis tools integrate with other components of the forensic toolkit:

- Results can be used as input for the `timeline_builder.py` to establish incident chronology
- Hash information can be shared with `threat_intelligence.py` for threat context
- Analysis findings can be included in reports generated by `report_builder.py`
- Extracted IOCs can be added to detection systems via `ioc_manager.py`
- Suspicious files can be escalated to dynamic analysis in isolated environments
- Integration with `malware_classification.py` for automated malware family identification
- Findings can be correlated with `network_traffic_analyzer.py` to identify command and control patterns
- Results feed into `incident_risk_scorer.py` for overall incident risk assessment
- Evidence integrity checks integrate with `chain_of_custody.py` tracking
- Automatic inclusion in standardized forensic reports via templates
- Alerting integration for critical findings via `notification_system.py`
- Bidirectional integration with centralized case management system

## Reporting

Static analysis tools generate standardized outputs that can be used with the reporting system:

1. **Standardized Output Formats**:
   - JSON (default, machine-readable structured data)
   - CSV (spreadsheet-compatible format)
   - YAML (configuration-friendly output)
   - Plain text (human-readable logs)

2. **Report Templates**:
   - Executive Summary (high-level overview for management)
   - Technical Analysis (detailed technical findings)
   - Evidence Documentation (chain-of-custody compliant)
   - Indicator Extraction (IOCs for detection systems)

3. **Integration With Report Builder**:

   ```bash
   # Generate comprehensive analysis report
   ../utils/report_builder.py --template static_analysis \
       --data-sources /secure/evidence/incident-42/analysis/ \
       --output /secure/evidence/incident-42/reports/static_analysis_report.pdf \
       --case-id incident-42
   ```

## Best Practices

1. **Initial Setup**:
   - Update signature databases before beginning analysis
   - Verify tool integrity through hash validation
   - Set appropriate resource limits for large files
   - Configure secure output directories with proper permissions

2. **Analysis Workflow**:
   - Start with hash checks as they're fastest and most definitive
   - Always perform analysis on copies of evidence, never originals
   - Maintain chain of custody documentation for all artifacts
   - Extract and analyze embedded objects recursively
   - Correlate findings across multiple analysis techniques
   - Document all analysis steps for reproducibility
   - Set appropriate timeouts for resource-intensive operations

3. **Result Interpretation**:
   - Consider false positive possibilities in all findings
   - Correlate static findings with other evidence sources
   - Prioritize findings based on confidence and severity scores
   - Document analysis limitations and caveats
   - Maintain technical objectivity in observations
   - Separate facts from interpretations in reports

4. **Security Considerations**:
   - Restrict access to analysis tools and results
   - Use isolated environments for analyzing suspicious files
   - Implement secure coding practices in custom analysis scripts
   - Maintain comprehensive audit logs of all operations
   - Use defense-in-depth approaches for high-risk files

## Related Documentation

- Digital Forensics Procedures
- Evidence Handling Guidelines
- Incident Response Plan
- Malware Analysis Methodology
- Forensic Analysis Toolkit Guide
- YARA Rule Development Guide
- Chain of Custody Requirements
- Threat Intelligence Integration
- Static Analysis Report Template
- File Signature Database Guide
- Memory Forensics Integration
