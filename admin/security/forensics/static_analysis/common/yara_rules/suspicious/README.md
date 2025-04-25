# Suspicious Code Pattern YARA Rules

This directory contains YARA rules for detecting suspicious code patterns and techniques that may indicate malicious activity but aren't tied to specific malware families. These rules help identify potentially harmful behaviors during forensic investigations.

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

The suspicious pattern YARA rules focus on generic behaviors and techniques commonly used in malicious code but which may also appear in legitimate software. These rules complement the more specific malware and ransomware detection rules by identifying potentially malicious code patterns regardless of the specific malware family. They are particularly useful for detecting new or previously unseen threats that use known suspicious techniques.

## Rule Categories

The suspicious pattern rules are organized into several categories:

- **`obfuscation.yar`**: Rules to detect code obfuscation techniques
  - String encoding and encryption
  - Dynamic code generation
  - Control flow obfuscation
  - Anti-analysis tricks

- **`evasion.yar`**: Rules for detecting anti-analysis techniques
  - Sandbox detection methods
  - Debugger detection
  - Virtual machine detection
  - Analysis tool evasion

- **`shellcode.yar`**: Rules for identifying shellcode characteristics
  - Position-independent code patterns
  - Memory manipulation techniques
  - Shellcode loaders and injectors
  - Common shellcode encoders

- **`injection.yar`**: Rules for process injection techniques
  - Process hollowing techniques
  - DLL injection methods
  - Memory injection patterns
  - Thread execution hijacking

- **`persistence.yar`**: Rules for system persistence mechanisms
  - Registry autorun entries
  - Scheduled task creation
  - Startup folder usage
  - Service installation patterns

- **`credentials.yar`**: Rules for credential theft techniques
  - Password dumping code
  - Browser credential extraction
  - Keylogging functionality
  - Authentication bypass methods

## Rule Structure

Each YARA rule follows a consistent structure:

```yara
rule Suspicious_Category_Technique {
    meta:
        description = "Detects suspicious technique or behavior"
        author = "Security Team"
        date = "YYYY-MM-DD"
        version = "1.0"
        confidence = "medium"  // high, medium, low
        reference = "Link to technique documentation"
        mitre_att = "T1027"    // Reference to MITRE ATT&CK technique

    strings:
        // Strings or byte patterns indicative of the suspicious behavior
        $pattern1 = { 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 }
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide

        // Context indicators that help confirm the pattern
        $context1 = "svchost.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and // MZ header for PE files
        filesize < 2MB and
        (
            (all of ($pattern*)) or
            (all of ($api*) and 1 of ($context*))
        )
}
```

## Directory Structure

```plaintext
admin/security/forensics/static_analysis/common/yara_rules/suspicious/
├── README.md                # This documentation
├── obfuscation.yar          # Code obfuscation detection rules
├── evasion.yar              # Anti-analysis technique detection
├── shellcode.yar            # Shellcode detection rules
├── injection.yar            # Process/memory injection techniques
├── persistence.yar          # Persistence mechanism detection
├── credentials.yar          # Credential theft technique detection
├── network.yar              # Suspicious network activity patterns
└── execution.yar            # Suspicious execution techniques
```

## Usage

These YARA rules are used by the static analysis tools as follows:

```python
from static_analysis.common.yara_utils import YaraScanner

# Initialize scanner with suspicious pattern rules
scanner = YaraScanner(
    rule_paths=["admin/security/forensics/static_analysis/common/yara_rules/suspicious"]
)

# Scan a file for suspicious patterns
results = scanner.scan_file("/path/to/suspicious_file")

# Process results
if results:
    print(f"Found {len(results)} suspicious patterns:")
    for match in results:
        print(f"- Rule: {match.rule}")
        print(f"  Description: {match.meta.get('description', 'No description')}")
        print(f"  Confidence: {match.meta.get('confidence', 'Unknown')}")
        print(f"  MITRE ATT&CK: {match.meta.get('mitre_att', 'None')}")
```

## Development Guidelines

When creating new suspicious pattern rules:

1. **Focus on Techniques, Not Families**
   - Target specific suspicious behaviors rather than malware families
   - Document the technique being detected
   - Reference MITRE ATT&CK techniques when applicable

2. **Minimize False Positives**
   - Use multiple indicators to confirm suspicious behavior
   - Add context indicators to improve accuracy
   - Consider legitimate uses of similar code patterns
   - Set appropriate confidence levels based on specificity

3. **Document Thoroughly**
   - Include clear descriptions of the detected behavior
   - Reference relevant technical documentation
   - Document potential false positives
   - Explain why the pattern is suspicious

4. **Follow Naming Conventions**
   - Use descriptive names focused on the technique
   - Follow the format: `Suspicious_Category_Technique`
   - Use consistent terminology across rules
   - Be specific about the behavior being detected

## Testing Procedures

Before submitting new rules:

1. **Positive Testing**
   - Test against samples known to use the technique
   - Verify detection across multiple variants
   - Document detection effectiveness

2. **Negative Testing**
   - Test against legitimate software using similar APIs/patterns
   - Measure false positive rates on clean files
   - Test against standard system utilities
   - Adjust rule specificity based on false positive findings

3. **Performance Testing**
   - Evaluate impact on scanning speed
   - Optimize complex patterns or regular expressions
   - Balance detection quality with performance

## Contributing

To contribute new suspicious pattern rules:

1. Follow the development guidelines and testing procedures above
2. Ensure rules have been tested against both malicious and benign samples
3. Document the suspicious technique with references
4. Provide sample hashes demonstrating the technique (if available)
5. Submit a pull request with clear descriptions of the detection capabilities

## Related Documentation

- YARA Rule Development Guide
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- Static Analysis Tools
- Forensic Analysis Toolkit
- Malware Analysis Methodology
- Incident Response Procedures
