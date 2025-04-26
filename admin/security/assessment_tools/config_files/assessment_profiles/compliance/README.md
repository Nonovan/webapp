# Compliance Assessment Profiles

This directory contains compliance-specific assessment profiles that extend the base assessment profiles with regulatory and industry-standard specific security checks and requirements. These profiles are used by the security assessment tools to ensure systems meet specific compliance frameworks.

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

The compliance assessment profiles define configuration parameters focused on specific regulatory standards and industry frameworks. These profiles extend the base environment profiles (development, production) with additional checks, control requirements, and findings classifications required by each compliance standard. Using these profiles ensures that security assessments evaluate systems against the appropriate regulatory requirements and produce findings that properly map to compliance control objectives.

## Key Components

- **`hipaa.json`**: HIPAA Security Rule compliance profile
  - Administrative safeguards verification
  - Technical safeguards requirements
  - Physical safeguards assessment
  - Protected health information controls
  - Access control requirements
  - Audit logging requirements

- **`iso27001.json`**: ISO 27001 compliance profile
  - Control mapping to ISO 27001 Annex A domains
  - Information security policy assessment
  - Asset management controls
  - Access control verification
  - Cryptography requirement validation
  - Operations security assessment
  - Communications security verification

- **`nist-csf.json`**: NIST Cybersecurity Framework profile
  - Identify function controls
  - Protect function requirements
  - Detect function capabilities
  - Respond function assessment
  - Recover function validation
  - CSF category and subcategory mapping

- **`pci-dss.json`**: PCI DSS compliance profile
  - Secure network configuration requirements
  - Cardholder data protection controls
  - Vulnerability management requirements
  - Access control measure verification
  - Network monitoring validation
  - Security testing requirements
  - Information security policy assessment

## Directory Structure

```plaintext
admin/security/assessment_tools/config_files/assessment_profiles/compliance/
├── README.md       # This documentation
├── hipaa.json      # HIPAA Security Rule compliance profile
├── iso27001.json   # ISO 27001 compliance profile
├── nist-csf.json   # NIST Cybersecurity Framework profile
└── pci-dss.json    # PCI DSS compliance profile
```

## Usage

The compliance profiles are used with the security assessment tools to conduct compliance-focused assessments:

```bash
# Run a full PCI DSS assessment
./vulnerability_scanner.py --profile compliance/pci-dss.json --target payment-system

# Run ISO 27001 assessment on a production system
./configuration_analyzer.py --base-profile production.json --compliance-profile compliance/iso27001.json --target core-server

# Generate compliance report for HIPAA
./configuration_analyzer.py --profile compliance/hipaa.json --target healthcare-data --report-format detailed --output hipaa-assessment.pdf

# Layer compliance checks with environment profile
./access_control_auditor.py --base-profile development.json --compliance-profile compliance/nist-csf.json --components identify,protect
```

For programmatic use in Python:

```python
import json
from pathlib import Path

def load_compliance_profile(compliance_standard, environment=None):
    """Load a compliance profile with optional environment base profile."""
    profiles_dir = Path(__file__).parent.parent

    # Load compliance profile
    compliance_path = profiles_dir / "compliance" / f"{compliance_standard}.json"
    with open(compliance_path, "r") as f:
        compliance_profile = json.load(f)

    # If environment specified, load and merge with environment profile
    if environment:
        environment_path = profiles_dir / f"{environment}.json"
        with open(environment_path, "r") as f:
            environment_profile = json.load(f)

        # Merge profiles with compliance taking precedence
        profile = deep_merge(environment_profile, compliance_profile)
        return profile

    return compliance_profile
```

## Profile Structure

Compliance assessment profiles follow a standard JSON structure with sections specific to each regulatory framework:

```json
{
  "metadata": {
    "name": "PCI DSS Compliance Profile",
    "version": "3.2.1",
    "description": "Payment Card Industry Data Security Standard assessment profile",
    "standard": "PCI DSS",
    "standard_version": "3.2.1",
    "last_updated": "2023-07-15",
    "author": "Security Compliance Team"
  },
  "assessment": {
    "scope": {
      "include": ["cardholder_data_environment", "network_security", "access_control"],
      "exclude": ["non_payment_systems"]
    },
    "depth": "comprehensive",
    "evidence_collection": true,
    "evidence_requirements": ["configuration_files", "access_control_lists", "audit_logs"],
    "report_format": "compliance"
  },
  "compliance_mapping": {
    "requirement_1": {
      "title": "Install and maintain a firewall configuration",
      "controls": ["network_segmentation", "firewall_rules", "router_configuration"],
      "verification_methods": ["configuration_review", "penetration_testing"]
    },
    "requirement_2": {
      "title": "Do not use vendor-supplied defaults",
      "controls": ["password_policy", "system_hardening"],
      "verification_methods": ["configuration_review", "automated_scanning"]
    }
  },
  "finding_classification": {
    "critical": {
      "compliance_impact": "direct_violation",
      "remediation_sla_days": 7,
      "requires_compensating_control": false
    },
    "high": {
      "compliance_impact": "significant_weakness",
      "remediation_sla_days": 30,
      "requires_compensating_control": true
    }
  }
}
```

## Customization Guidelines

When customizing compliance assessment profiles:

1. **Start with Standard Framework**
   - Begin with the standard compliance framework requirements
   - Map requirements to specific technical controls
   - Document validation methods for each control
   - Reference specific sections of the standard

2. **Consider Environment Context**
   - Adapt requirements to organizational systems
   - Document any scoping decisions
   - Include organization-specific interpretations
   - Account for compensating controls

3. **Document Exceptions**
   - Clearly document any excluded requirements
   - Provide rationale for exclusions
   - Note alternative controls where applicable
   - Include risk acceptance documentation

4. **Maintain Version Control**
   - Track changes to compliance profiles
   - Document standard version references
   - Note changes from previous framework versions
   - Include update history with rationale

## Best Practices & Security

- **Baseline with Standards**: Always start with official compliance framework documentation
- **Compliance Mapping**: Maintain clear mapping between technical controls and compliance requirements
- **Documentation**: Include references to specific sections of standards
- **Evidence Requirements**: Define specific evidence needed for compliance verification
- **Granular Controls**: Break down complex requirements into specific technical controls
- **Gap Analysis**: Enable identification of compliance gaps
- **Interpretation Guidance**: Provide guidance on interpreting requirements in technical context
- **Quality Control**: Have compliance experts review profile customizations
- **Regular Updates**: Update profiles when standards or interpretations change
- **Risk-Based Approach**: Focus on high-risk compliance areas
- **Secondary Validation**: Implement separate validation methods for critical controls
- **Version Tracking**: Track compliance standard versions and profile updates

## Common Features

All compliance assessment profiles include these common elements:

- **Compliance Mapping**: Direct mapping to standard's sections and requirements
- **Control Categorization**: Grouping of controls by compliance domains
- **Control Verification Methods**: How each control should be validated
- **Evidence Requirements**: Specific evidence required for compliance documentation
- **Finding Classification**: Compliance-specific severity ratings
- **Framework References**: References to specific framework sections
- **Metadata**: Profile version, standard version, and update information
- **Remediation Requirements**: Compliance-specific remediation guidance
- **Reporting Requirements**: Compliance-specific reporting formats
- **Risk Assessment Parameters**: Risk assessment guidance for compliance context
- **Scope Definition**: Clear boundaries for compliance assessment
- **Standard Version**: Specific version of the compliance standard

## Related Documentation

- Compliance Framework Documentation
- Assessment Methodology Guide
- Compliance Control Mapping
- Control Implementation Guide
- Evidence Collection Requirements
- Assessment Profile Documentation
- Parent Assessment Profiles README
- Regulatory Requirement References
- Security Assessment Tool Usage Guide
- Standard Interpretation Guidelines
