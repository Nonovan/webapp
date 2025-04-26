# Assessment Profiles

This directory contains configuration profiles that define parameters, scope, and settings for security assessments across different environments and compliance frameworks. These profiles ensure consistent application of security standards while allowing for environment-specific customization.

## Contents

- Overview
- Key Components
- Directory Structure
- Usage
- Profile Structure
- Customization Guidelines
- Best Practices & Security
- Common Features
- Related Documentation

## Overview

Assessment profiles define the configuration parameters used by security assessment tools when evaluating systems, applications, and infrastructure. These profiles provide environment-specific settings, determine assessment scope and depth, specify which security checks to perform, and define how findings are classified and prioritized. By using standardized profiles, security assessments maintain consistency while adapting to the specific requirements of each environment and compliance standard.

## Key Components

- **`compliance/`**: Compliance-specific assessment profiles
  - Checks mapped to specific regulatory requirements
  - Control verification parameters
  - Evidence collection requirements
  - Attestation documentation needs
  - Gap analysis configuration
  - Standard-specific classification schemes

- **`default.json`**: Base assessment profile
  - Core security checks for all environments
  - Default severity thresholds
  - Standard evidence collection parameters
  - Common reporting requirements
  - Baseline scanning depths
  - Default remediation timelines

- **`development.json`**: Profile tailored for development environments
  - Emphasis on early detection
  - Lower severity thresholds for certain findings
  - Integration with development workflow
  - Focus on secure coding practices
  - Relaxed requirements for non-critical components
  - CI/CD integration parameters

- **`production.json`**: Strict profile for production environments
  - Comprehensive security checks
  - Stricter severity classifications
  - Production-specific security requirements
  - Business impact considerations
  - Operational context awareness
  - Additional verification steps

## Directory Structure

```plaintext
admin/security/assessment_tools/config_files/assessment_profiles/
├── README.md                # This documentation
├── compliance/             # Compliance-specific assessment profiles
│   ├── hipaa.json          # HIPAA compliance profile
│   ├── iso27001.json       # ISO 27001 compliance profile
│   ├── nist-csf.json       # NIST Cybersecurity Framework profile
│   └── pci-dss.json        # PCI DSS compliance profile
├── default.json            # Default assessment profile
├── development.json        # Development environment profile
└── production.json         # Production environment profile
```

## Usage

The assessment profiles are used with the security assessment tools to configure assessment behavior:

```bash
# Run vulnerability scanner with development profile
./vulnerability_scanner.py --profile assessment_profiles/development.json --target dev-server-01

# Run configuration analyzer with production profile
./configuration_analyzer.py --profile assessment_profiles/production.json --target prod-db-01

# Run assessment with PCI DSS compliance profile
./access_control_auditor.py --profile assessment_profiles/compliance/pci-dss.json --target payment-system

# Run assessment with multiple profiles (base + compliance)
./network_security_tester.py --base-profile assessment_profiles/production.json \
  --compliance-profile assessment_profiles/compliance/iso27001.json \
  --target core-network
```

For scripted use in Python:

```python
import json
from pathlib import Path

def load_assessment_profile(profile_name, compliance_addon=None):
    """Load assessment profile with optional compliance addon."""
    profiles_dir = Path(__file__).parent.parent / "assessment_profiles"

    # Load base profile
    profile_path = profiles_dir / f"{profile_name}.json"
    with open(profile_path, "r") as f:
        profile = json.load(f)

    # Load compliance addon if specified
    if compliance_addon:
        compliance_path = profiles_dir / "compliance" / f"{compliance_addon}.json"
        with open(compliance_path, "r") as f:
            compliance_profile = json.load(f)

        # Merge profiles with compliance requirements taking precedence
        profile = deep_merge(profile, compliance_profile)

    return profile
```

## Profile Structure

Assessment profiles follow a standard JSON structure:

```json
{
  "metadata": {
    "name": "Production Environment Assessment",
    "version": "2.3.0",
    "description": "Security assessment profile for production systems",
    "environment": "production",
    "last_updated": "2023-07-15",
    "author": "Security Operations"
  },
  "assessment": {
    "scope": {
      "include": ["system_configuration", "network_security", "access_control", "authentication"],
      "exclude": ["developmental_features"]
    },
    "depth": "comprehensive",
    "evidence_collection": true,
    "auto_remediation": false,
    "report_format": "pdf"
  },
  "security_controls": {
    "authentication": {
      "password_policy": {
        "min_length": 12,
        "complexity_requirements": ["uppercase", "lowercase", "numbers", "special_chars"],
        "history_count": 24,
        "max_age_days": 90
      },
      "mfa": {
        "required": true,
        "approved_methods": ["app", "hardware_token"]
      }
    },
    "network_security": {
      "firewall": true,
      "ids_ips": true,
      "encryption_in_transit": true,
      "network_segmentation": true
    }
  },
  "finding_classification": {
    "critical": {
      "cvss_min": 9.0,
      "remediation_sla_days": 7,
      "requires_approval": ["security_lead", "system_owner"]
    },
    "high": {
      "cvss_min": 7.0,
      "remediation_sla_days": 30,
      "requires_approval": ["security_analyst"]
    }
  }
}
```

## Customization Guidelines

When customizing assessment profiles:

1. **Start with a Base Profile**
   - Create new profiles by extending existing ones
   - Make incremental changes to maintain consistency
   - Document clearly what was changed and why
   - Reference security standards for modifications

2. **Focus on Environment-Specific Needs**
   - Adapt to the security posture of the target environment
   - Consider operational constraints
   - Include relevant business context
   - Address specific threats to the environment

3. **Maintain Balance**
   - Balance security requirements with operational needs
   - Avoid overly restrictive settings that impede operations
   - Don't sacrifice security for convenience
   - Consider risk factors when adjusting thresholds

4. **Test Changes**
   - Validate profile changes in non-production first
   - Compare assessment results before and after changes
   - Ensure changes don't cause false positives/negatives
   - Verify report output is still useful and accurate

## Best Practices & Security

- **Alignment with Standards**: Align profiles with recognized security frameworks (NIST, CIS, ISO)
- **Assessment Balance**: Balance thoroughness with operational impact
- **Change Management**: Document changes to profiles and follow change control processes
- **Environment-Specific Controls**: Tailor control requirements to each environment's risk profile
- **Incremental Improvement**: Implement assessment improvements incrementally
- **Peer Review**: Have security experts review all profile changes
- **Regular Updates**: Update profiles quarterly or when security standards change
- **Risk-Based Approach**: Prioritize checks based on risk and business impact
- **Version Control**: Maintain all profiles in version control with clear history
- **Validation**: Validate profiles against a known baseline before deployment

## Common Features

All assessment profiles include these common elements:

- **Assessment Scope**: Definition of what should and should not be assessed
- **Control Requirements**: Specific security controls to evaluate
- **Depth Settings**: How thorough the assessment should be
- **Evidence Requirements**: What evidence should be collected
- **Finding Classification**: How security findings should be categorized
- **Metadata**: Profile version, author, and update information
- **Remediation Guidance**: Timelines and approaches for fixing issues
- **Reporting Configuration**: How assessment results should be presented
- **Risk Thresholds**: Thresholds for risk acceptance and escalation
- **Verification Requirements**: How control implementation is verified

## Related Documentation

- Assessment Engine Documentation
- Assessment Tool Usage Guide
- Compliance Requirement Mapping
- Configuration Analyzer Documentation
- Custom Profile Development
- Profile Inheritance Model
- Risk Scoring Methodology
- Security Assessment Guide
- Security Baseline Management
- Vulnerability Management Policy
