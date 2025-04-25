# Ransomware Detection YARA Rules

This directory contains specialized YARA rules for detecting various ransomware families and their components during forensic analysis of suspicious files. These rules enable security teams to identify ransomware-specific patterns without executing potentially harmful files.

## Contents

- Overview
- Rule Categories
- Rule Structure
- Usage
- Development Guidelines
- Testing Procedures
- Contributing
- Related Documentation

## Overview

The ransomware detection YARA rules provide pattern-based detection capabilities specifically targeting known ransomware families, their encryption components, ransom notes, and other distinctive characteristics. These rules complement the general malware detection rules by focusing on the specific techniques and patterns used by ransomware. Each rule is designed to minimize false positives while effectively identifying ransomware code.

## Rule Categories

The ransomware rules are organized into several categories:

- **`encryption_routines/`**: Rules to detect encryption implementation patterns
  - Common cryptographic function signatures
  - File encryption loops
  - Key generation routines
  - Encryption initialization patterns

- **`ransom_notes/`**: Rules for detecting ransom note templates and content
  - Template structures used by known ransomware families
  - Common threatening language patterns
  - Payment instruction patterns
  - Cryptocurrency address formats

- **`file_markers/`**: Rules to detect ransomware file markers and extensions
  - File extension modification patterns
  - Header/footer modifications
  - File renaming routines
  - Identification markers left by ransomware

- **`specific_families/`**: Family-specific detection rules
  - WannaCry family detection
  - Ryuk family detection
  - Maze family detection
  - REvil/Sodinokibi detection
  - LockBit detection
  - BlackMatter detection

## Rule Structure

Each YARA rule follows a consistent structure:

```yara
rule Ransomware_Family_Component {
    meta:
        description = "Detects specific ransomware family or component"
        author = "Security Team"
        date = "YYYY-MM-DD"
        version = "1.0"
        hash = "SHA-256 hash of reference sample"
        reference = "Link to analysis or threat report"
        severity = "critical"
        family = "Ransomware family name"
        mitre_att = "T1486" // Data Encrypted for Impact

    strings:
        // Strings or byte patterns specific to this ransomware
        $encryption1 = {83 F8 00 74 ?? 8B ?? 24 ?? 83 ?? 01}
        $ransom_note = "All your files have been encrypted"
        $file_marker = {DE AD F0 01}

        // Additional context patterns that help confirm
        $context1 = "bitcoin"
        $context2 = "payment"

    condition:
        uint16(0) == 0x5A4D and // MZ header for PE files
        filesize < 2MB and
        (
            (all of ($encryption*) and 1 of ($context*)) or
            $file_marker or
            $ransom_note
        )
}
```

## Directory Structure

```plaintext
admin/security/forensics/static_analysis/common/yara_rules/ransomware/
├── README.md                     # This documentation
├── crypto_functions.yar          # Generic crypto function detection
├── ransom_notes.yar              # General ransom note patterns
├── encryption_routines/          # Encryption routine detection rules
│   ├── aes.yar                   # AES implementation detection
│   ├── rsa.yar                   # RSA implementation detection
│   └── custom_crypto.yar         # Custom encryption algorithms
├── file_markers/                 # File marker detection rules
│   ├── extensions.yar            # Extension modification detection
│   └── headers.yar               # File header modification detection
├── ransom_notes/                 # Ransom note detection rules
│   ├── payment_instructions.yar  # Payment instruction detection
│   ├── threats.yar               # Threatening language patterns
│   └── contact_info.yar          # Contact information patterns
└── specific_families/            # Family-specific rules
    ├── README.md                 # Family-specific documentation
    ├── blackmatter.yar           # BlackMatter ransomware rules
    ├── locky.yar                 # Locky ransomware rules
    ├── maze.yar                  # Maze ransomware rules
    ├── revil.yar                 # REvil/Sodinokibi ransomware rules
    ├── ryuk.yar                  # Ryuk ransomware rules
    └── wannacry.yar              # WannaCry ransomware rules
```

## Usage

These YARA rules are used by the forensic tools as follows:

```python
from static_analysis.common.yara_utils import YaraScanner

# Initialize scanner with ransomware-specific rules
scanner = YaraScanner(
    rule_paths=["admin/security/forensics/static_analysis/common/yara_rules/ransomware"]
)

# Scan a suspicious file
results = scanner.scan_file("/path/to/suspicious_file")

# Process results
if results:
    print(f"Found {len(results)} ransomware indicators:")
    for match in results:
        print(f"- Rule: {match.rule}")
        print(f"  Ransomware family: {match.meta.get('family', 'Unknown')}")
        print(f"  Severity: {match.meta.get('severity', 'Unknown')}")
        print(f"  MITRE ATT&CK: {match.meta.get('mitre_att', 'T1486')}")
        print(f"  Description: {match.meta.get('description', 'No description')}")
```

## Development Guidelines

When creating new ransomware detection rules:

1. **Research Thoroughly**
   - Analyze multiple samples of the ransomware family
   - Identify unique and persistent characteristics
   - Document encryption methods and ransom note templates
   - Determine file markers and extensions used

2. **Create Specific Rules**
   - Target unique ransomware characteristics
   - Include encryption routine patterns when possible
   - Document ransom note text patterns
   - Identify file marking behavior

3. **Document Properly**
   - Include full metadata for each rule
   - Reference sample hashes and analysis reports
   - Document MITRE ATT&CK techniques (primarily T1486)
   - Include severity assessment (typically critical)

4. **Follow Naming Conventions**
   - Use descriptive names that identify the ransomware family
   - Follow the format: `Ransomware_Family_Component`
   - Include variant information when applicable
   - Be consistent with existing rule naming

## Testing Procedures

Before submitting new rules:

1. **Positive Testing**
   - Verify detection against known ransomware samples
   - Test against multiple variants of the same family
   - Document detection effectiveness

2. **Negative Testing**
   - Test against benign encryption tools to verify no false positives
   - Include testing against legitimate file compression utilities
   - Perform broad testing across file types

3. **Performance Testing**
   - Evaluate impact on scanning performance
   - Optimize rules that cause significant slowdowns
   - Balance detection quality with performance

## Contributing

To contribute new ransomware detection rules:

1. Follow the development guidelines and testing procedures above
2. Ensure rules have been tested against both ransomware samples and benign files
3. Document the ransomware's encryption methods and behaviors
4. Include reference sample hashes (preferably SHA-256)
5. Submit a pull request with clear descriptions of the detection capabilities

## Related Documentation

- YARA Rule Development Guide
- Ransomware Analysis Methodology
- Static Analysis Tools
- Forensic Analysis Toolkit
- Incident Response Procedures
- [MITRE ATT&CK - T1486: Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
