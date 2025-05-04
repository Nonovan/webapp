# YARA Rules Collection for Static Analysis

This directory contains YARA rule definitions used by the static analysis tools in the Forensic Analysis Toolkit. These rules enable pattern-based identification of malicious code and suspicious patterns during forensic investigations.

## Contents

- [Overview](#overview)
- [Directory Structure](#directory-structure)
- [Rule Categories](#rule-categories)
- [Usage](#usage)
- [Development Guidelines](#development-guidelines)
- [Testing Process](#testing-process)
- [Contributing](#contributing)
- [Related Documentation](#related-documentation)

## Overview

YARA rules provide powerful pattern matching capabilities that enable the static analysis tools to identify malicious code, suspicious patterns, and indicators of compromise without executing potentially harmful files. This collection contains carefully crafted rules designed to detect various types of threats that might be encountered during security incident investigations.

The rules are organized by threat category for easy management and selective application, allowing for targeted scanning of suspected malicious files with minimal performance overhead.

## Directory Structure

```plaintext
admin/security/forensics/static_analysis/common/yara_rules/
├── README.md                 # This documentation
├── malware/                  # Malware detection rules
│   ├── README.md             # Malware rules documentation
│   ├── backdoors.yar         # Rules for detecting backdoors
│   ├── keyloggers.yar        # Rules for detecting keylogging functionality
│   ├── ransomware.yar        # Rules for detecting ransomware
│   └── trojans.yar           # Rules for detecting trojan malware
├── ransomware/               # Specific ransomware family rules
│   ├── README.md             # Ransomware rules documentation
│   ├── crypto_functions.yar  # Encryption routine detection
│   ├── file_markers.yar      # File extension and marker detection
│   ├── ransom_notes.yar      # Ransom note templates
│   └── specific_families/    # Rules for specific ransomware families
│       ├── README.md         # Family-specific documentation
│       ├── blackmatter.yar   # BlackMatter ransomware rules
│       ├── lockbit.yar       # LockBit ransomware rules
│       ├── locky.yar         # Locky ransomware rules
│       ├── revil.yar         # REvil/Sodinokibi ransomware rules
│       ├── ryuk.yar          # Ryuk ransomware rules
│       └── wannacry.yar      # WannaCry ransomware rules
└── suspicious/               # Suspicious code pattern rules
    ├── README.md             # Suspicious pattern documentation
    ├── credentials.yar       # Credential theft detection rules
    ├── evasion.yar           # Anti-analysis techniques
    ├── execution.yar         # Suspicious execution techniques
    ├── injection.yar         # Process/memory injection techniques
    ├── network.yar           # Suspicious network activity patterns
    ├── obfuscation.yar       # Code obfuscation techniques
    ├── persistence.yar       # Persistence mechanism detection
    └── shellcode.yar         # Shellcode detection patterns
```

## Rule Categories

### Malware Detection Rules

Rules designed to detect specific types of malware:

- **Trojans**: Patterns for identifying trojan malware
- **Backdoors**: Rules for detecting various backdoor implementations
- **Ransomware**: Generic ransomware detection rules
- **Keyloggers**: Rules for keyboard monitoring functionality

### Ransomware-Specific Rules

Rules targeting ransomware threats:

- **Crypto Functions**: Detection of encryption routines common in ransomware
- **Ransom Notes**: Templates and strings found in ransom notes
- **File Markers**: Detection of file extension changes and markers
- **Specific Families**: Rules for well-known ransomware families with unique signatures

### Suspicious Pattern Rules

Rules for detecting suspicious coding patterns:

- **Obfuscation**: Detection of code obfuscation techniques
- **Evasion**: Patterns for anti-analysis and sandbox evasion techniques
- **Shellcode**: Rules for identifying shellcode in various formats
- **Network Activity**: Suspicious network connection patterns
- **Persistence**: Detection of system persistence techniques
- **Injection**: Process and memory injection methods
- **Credentials**: Credential theft techniques
- **Execution**: Suspicious code execution patterns

## Usage

These YARA rules are used by the static analysis tools as follows:

```python
from admin.security.forensics.static_analysis.common import YaraScanner

# Initialize scanner with specific rule sets
scanner = YaraScanner(
    rule_paths=[
        "admin/security/forensics/static_analysis/common/yara_rules/malware",
        "admin/security/forensics/static_analysis/common/yara_rules/suspicious"
    ]
)

# Scan a file
results = scanner.scan_file("/path/to/suspicious_file")

# Process results
if results:
    print(f"Found {len(results)} suspicious patterns:")
    for match in results:
        print(f" - Rule: {match['rule']}")
        print(f"   Description: {match['meta'].get('description', 'N/A')}")
        print(f"   Severity: {match['meta'].get('severity', 'Unknown')}")

        # Process matched strings
        if match['strings']:
            print(f"   Matched {len(match['strings'])} patterns:")
            for string_match in match['strings'][:3]:  # Show first 3
                print(f"     - {string_match['identifier']} at offset {string_match['offset']}")

            if len(match['strings']) > 3:
                print(f"     - ... and {len(match['strings']) - 3} more matches")
```

### Advanced Usage

For more complex scanning requirements:

```python
# Scan with multiple rule sets, focusing on specific threat types
scanner = YaraScanner()

# Add ransomware-specific rules
scanner.add_rules([
    "admin/security/forensics/static_analysis/common/yara_rules/ransomware/specific_families/wannacry.yar",
    "admin/security/forensics/static_analysis/common/yara_rules/ransomware/specific_families/ryuk.yar"
])

# Scan binary data directly (e.g., from memory)
with open("/path/to/suspicious_file", "rb") as f:
    binary_data = f.read()
    matches = scanner.scan_data(binary_data)

# Set timeout for scanning large files or complex rules
matches = scanner.scan_file("/path/to/large_file", timeout=120)
```

## Development Guidelines

### Rule Naming Convention

- Use descriptive names that reflect the threat or pattern being detected
- Follow the format: `[Category]_[Threat]_[Specificity]`
- Examples:
  - `Ransomware_WannaCry_FileMarker`
  - `Suspicious_PowerShell_EncodedCommand`
  - `Malware_Generic_Keylogger`

### Rule Format

```yara
rule Ransomware_CryptoRoutine_AES {
    meta:
        description = "Detects potential AES crypto implementation used by ransomware"
        author = "Security Team"
        date = "2024-07-15"
        version = "1.0"
        severity = "high"
        reference = "Internal analysis of ransomware samples"
        sample_hash = "sha256:abcdef123456789..."
        mitre_att = "T1486" // Data Encrypted for Impact
        false_positive_rate = "low"
        confidence = "high"

    strings:
        $aes_sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
        $aes_func1 = "AES_set_encrypt_key" ascii wide
        $aes_func2 = "AES_encrypt" ascii wide
        $aes_const1 = { 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 }

        // File extension renames commonly used in ransomware
        $ext_pattern = /\.encrypted$|\.locked$|\.crypt$|\.enc$/

    condition:
        uint16(0) == 0x5A4D and // MZ header (PE file)
        filesize < 5MB and
        (
            ($aes_sbox and 1 of ($aes_func*)) or
            (2 of ($aes_func*) and $aes_const1) or
            ($ext_pattern and 1 of them)
        )
}
```

### Metadata Requirements

Each rule should include the following metadata:

- `description`: Clear explanation of what the rule detects
- `author`: Who created the rule
- `date`: Creation date in YYYY-MM-DD format
- `version`: Rule version
- `severity`: Impact level (critical, high, medium, low)
- `reference`: Source of information or analysis
- `mitre_att`: Relevant MITRE ATT&CK technique ID when applicable

Optional fields:

- `sample_hash`: Hash of a sample that triggered this rule
- `false_positive_rate`: Known false positive likelihood
- `confidence`: Detection confidence level (high, medium, low)

### Rule Development Best Practices

1. **Minimize False Positives**
   - Use multiple indicators to confirm suspicious behavior
   - Add context indicators to improve accuracy
   - Consider legitimate uses of similar code patterns
   - Set appropriate confidence levels based on specificity
   - Combine specific string matches with broader behavioral indicators

2. **Document Thoroughly**
   - Include clear descriptions of the detected behavior
   - Reference relevant technical documentation
   - Document potential false positives
   - Explain why the pattern is suspicious
   - Include MITRE ATT&CK mappings when applicable

3. **Optimize Performance**
   - Start conditions with fast filters (file type, size)
   - Use anchored patterns when possible
   - Limit use of expensive regex operations
   - Consider file section restrictions for executables
   - Avoid overly complex conditions that may time out

4. **Follow Security Standards**
   - Implement proper input validation in rule testing tools
   - Protect test samples using appropriate controls
   - Avoid including sensitive data in rule comments
   - Document any security implications
   - Ensure rule organization aligns with threat intelligence

5. **String Pattern Selection**
   - Prefer unique byte sequences over common strings
   - Use `wide` and `ascii` modifiers for cross-encoding detection
   - Consider case-insensitivity with `nocase` for text patterns
   - Include hex patterns for binary data
   - Use regex patterns sparingly and optimize when used

## Testing Process

Before committing new rules, follow this testing process:

1. **Validation Testing**:
   - Test against known malicious samples
   - Test against a collection of benign files
   - Document any false positives
   - Verify detection against variants of the same threat
   - Test with obfuscated versions of known samples

2. **Performance Testing**:
   - Measure scan time impact
   - Optimize regex patterns for efficiency
   - Consider memory usage for large file scanning
   - Test with timeout constraints
   - Verify behavior with large file samples

3. **Integration Testing**:
   - Verify compatibility with the static analysis pipeline
   - Check reporting format compatibility
   - Test with signature_checker.py
   - Ensure consistent behavior across different platforms
   - Verify logging and reporting works correctly

### Automated Testing

The toolkit provides automated testing capabilities for YARA rules:

```bash
# Test rules against known samples
./test_yara_rules.py --ruleset admin/security/forensics/static_analysis/common/yara_rules/malware --samples /path/to/samples

# Test for false positives
./test_yara_rules.py --ruleset admin/security/forensics/static_analysis/common/yara_rules/suspicious --benign /path/to/benign_files --report false_positives.json

# Performance testing
./test_yara_rules.py --ruleset admin/security/forensics/static_analysis/common/yara_rules --performance-test
```

## Contributing

To contribute new YARA rules:

1. Create rules following the format and naming conventions above
2. Test thoroughly against both malicious and benign samples
3. Document any potential false positives
4. Submit PR with:
   - New rule file or additions to existing rules
   - Test results showing effectiveness
   - Sample hashes that trigger the rule (if available)
   - Brief explanation of detection methodology
   - Consider providing benign files that might trigger false positives

### Rule Review Checklist

- [ ] Rule follows naming convention
- [ ] Required metadata is complete
- [ ] Conditions are optimized for performance
- [ ] False positives are documented
- [ ] Tests have been performed and documented
- [ ] Rule complements existing rules without duplication
- [ ] Security implications have been considered
- [ ] Rule has been tested with signature_checker.py

## Related Documentation

- Static Analysis Tools Guide
- Forensic Analysis Toolkit
- [YARA Documentation](https://yara.readthedocs.io/)
- Malware Analysis Guide
- Signature Development Process
- Incident Response Procedures
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- YARA Performance Optimization Guide
