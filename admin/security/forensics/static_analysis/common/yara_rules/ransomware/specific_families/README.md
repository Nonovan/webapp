# Ransomware Family-Specific YARA Rules

This directory contains specialized YARA rules for detecting specific ransomware families during forensic analysis. These rules target unique characteristics of known ransomware variants to enable precise identification during security investigations.

## Contents

- Overview
- Rule Organization
- Key Ransomware Families
- Rule Structure
- Usage
- Development Guidelines
- Testing Requirements
- Contributing
- Related Documentation

## Overview

The family-specific YARA rules in this directory provide targeted detection capabilities for known ransomware families. Each rule focuses on the unique characteristics, behaviors, and artifacts of specific ransomware variants, enabling precise identification during forensic analysis. These rules complement the generic ransomware detection rules by providing more accurate identification of specific threats.

## Rule Organization

Rules are organized by ransomware family name, with each file containing detection rules for a specific ransomware family and its variants:

```plaintext
admin/security/forensics/static_analysis/common/yara_rules/ransomware/specific_families/
├── README.md                # This documentation
├── wannacry.yar             # WannaCry ransomware family rules
├── ryuk.yar                 # Ryuk ransomware family rules
├── lockbit.yar              # LockBit ransomware family rules
├── revil.yar                # REvil/Sodinokibi ransomware family rules
├── blackmatter.yar          # BlackMatter ransomware family rules
├── maze.yar                 # Maze ransomware family rules
├── conti.yar                # Conti ransomware family rules
├── phobos.yar               # Phobos ransomware family rules
├── dharma.yar               # Dharma/CrySiS ransomware family rules
└── petya.yar                # Petya/NotPetya ransomware family rules
```

## Key Ransomware Families

### WannaCry

- **First Seen**: May 2017
- **Notable Characteristics**: SMB exploitation via EternalBlue, kill switch domain, specific encryption markers
- **Key Indicators**: `00000000.pky`, `00000000.eky` files, `.WNCRY` extension

### Ryuk

- **First Seen**: August 2018
- **Notable Characteristics**: Targeted attacks, often deployed after initial compromise via Trickbot/BazarLoader
- **Key Indicators**: `RyukReadMe.txt` ransom note, `.RYK` file extension

### LockBit

- **First Seen**: September 2019
- **Notable Characteristics**: Ransomware-as-a-service, self-spreading capability, fast encryption
- **Key Indicators**: `Restore-My-Files.txt` ransom note, `.lockbit` extension

### REvil/Sodinokibi

- **First Seen**: April 2019
- **Notable Characteristics**: Ransomware-as-a-service, double extortion tactic
- **Key Indicators**: Random extension, `[random].onion.readme.txt` ransom note

### BlackMatter

- **First Seen**: July 2021
- **Notable Characteristics**: Successor to DarkSide, targets critical infrastructure
- **Key Indicators**: `README.txt` ransom note, `.blackmatter` extension

## Rule Structure

Each family-specific rule follows a consistent format:

```yara
rule Ransomware_FamilyName_Component {
    meta:
        description = "Detects specific component of FamilyName ransomware"
        author = "Security Team"
        date = "YYYY-MM-DD"
        version = "1.0"
        hash = "SHA-256 hash of reference sample"
        reference = "Link to analysis or threat report"
        severity = "critical"
        family = "FamilyName"
        mitre_att = "T1486" // Data Encrypted for Impact

    strings:
        // Unique strings or byte patterns for this ransomware family
        $ransom_note = "Specific ransom note content"
        $encryption_marker = { FF FF FF FF 00 00 00 01 }
        $family_specific_string = "Unique string used by this family"

    condition:
        // Conditions for positive identification
        uint16(0) == 0x5A4D and // MZ header for PE files
        filesize < 2MB and
        2 of them
}

rule Ransomware_FamilyName_Variant {
    // Rule for specific variant of the family
    // ...
}
```

## Usage

These family-specific YARA rules are used by the forensic analysis tools as follows:

```python
from static_analysis.common.yara_utils import YaraScanner

# Initialize scanner with family-specific rules
scanner = YaraScanner(
    rule_paths=["admin/security/forensics/static_analysis/common/yara_rules/ransomware/specific_families"]
)

# Alternatively, scan for a specific family
scanner = YaraScanner(
    rule_paths=["admin/security/forensics/static_analysis/common/yara_rules/ransomware/specific_families/wannacry.yar"]
)

# Scan a suspicious file
results = scanner.scan_file("/path/to/suspicious_file")

# Process results
if results:
    for match in results:
        print(f"Detected ransomware family: {match.meta.get('family', 'Unknown')}")
        print(f"Rule name: {match.rule}")
        print(f"Reference sample: {match.meta.get('hash', 'N/A')}")
        print(f"Description: {match.meta.get('description', 'No description')}")
```

## Development Guidelines

When developing new family-specific rules:

1. **Research Thoroughly**
   - Analyze multiple samples of the ransomware family
   - Document unique strings, encryption markers, and behaviors
   - Identify variants within the family

2. **Create Specific Rules**
   - Focus on unique characteristics of each family
   - Include variant-specific rules when appropriate
   - Document the encryption techniques used

3. **Minimize False Positives**
   - Combine multiple identifiers in conditions
   - Use byte patterns when possible rather than short strings
   - Test against non-malicious software with similar functionality

4. **Document Properly**
   - Include sample hashes when available
   - Reference threat intelligence reports
   - Document first seen date and major variants
   - Keep track of rule effectiveness against new variants

## Testing Requirements

Before contributing new rules:

1. **Positive Testing**
   - Verify detection against known samples of the ransomware family
   - Test against multiple variants when available
   - Verify detection of both packed and unpacked samples

2. **Negative Testing**
   - Test against benign encryption tools
   - Test against other ransomware families to ensure specificity
   - Verify against clean system files

3. **Performance Testing**
   - Ensure rules don't cause significant scanning slowdowns
   - Optimize rules with high performance impact

## Contributing

To contribute new family-specific rules:

1. Follow the development guidelines and testing requirements
2. Use the standard naming convention: `Ransomware_FamilyName_Component`
3. Include comprehensive metadata in each rule
4. Document your research and reference sources
5. Submit pull requests with evidence of testing

## Related Documentation

- YARA Rule Development Guide
- Ransomware Analysis Methodology
- Static Analysis Tools
- Forensic Analysis Toolkit
- [MITRE ATT&CK - T1486: Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- Incident Response Plan
