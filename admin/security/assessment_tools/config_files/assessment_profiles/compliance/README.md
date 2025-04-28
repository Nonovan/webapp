# Compliance Assessment Profiles

This directory contains compliance-specific assessment profiles that extend the base assessment profiles with regulatory and industry-standard specific security checks and requirements. These profiles are used by the security assessment tools to ensure systems meet specific compliance frameworks.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Usage](#usage)
- [Profile Structure](#profile-structure)
- [Customization Guidelines](#customization-guidelines)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Related Documentation](#related-documentation)

## Overview

The compliance assessment profiles define configuration parameters focused on specific regulatory standards and industry frameworks. These profiles extend the base environment profiles (development, production) with additional checks, control requirements, and findings classifications required by each compliance standard. Using these profiles ensures that security assessments evaluate systems against the appropriate regulatory requirements and produce findings that properly map to compliance control objectives.

## Key Components

- **`ccpa.json`**: CCPA Compliance Profile
  - Data subject rights verification
  - Data inventory and mapping requirements
  - Consent and preference management
  - Third-party data sharing controls
  - Security procedures for personal information
  - Finding classification aligned with privacy impact

- **`fedramp.json`**: FedRAMP Moderate compliance profile
  - Based on NIST SP 800-53 Rev 5 controls
  - Moderate baseline control selection
  - Evidence requirements for FedRAMP authorization
  - Finding classification aligned with FedRAMP risk levels

- **`gdpr.json`**: GDPR compliance profile
  - Mapping to GDPR articles (e.g., Art. 5, 6, 7, 12-23, 25, 32, 33-34, 35)
  - Focus on personal data protection principles
  - Data subject rights verification
  - Security of processing requirements (Art. 32)
  - DPIA and breach notification checks

- **`hipaa.json`**: HIPAA Security Rule compliance profile
  - Administrative safeguards verification ([`164.308`](hipaa.json))
  - Technical safeguards requirements ([`164.312`](hipaa.json))
  - Physical safeguards assessment ([`164.310`](hipaa.json))
  - Protected health information (PHI) controls
  - Access control requirements
  - Audit logging requirements

- **`iso27001.json`**: ISO 27001:2013 compliance profile
  - Control mapping to ISO 27001 Annex A domains ([`A.5`](iso27001.json) - [`A.18`](iso27001.json))
  - Information security policy assessment ([`A.5.1`](iso27001.json))
  - Asset management controls ([`A.8`](iso27001.json))
  - Access control verification ([`A.9`](iso27001.json))
  - Cryptography requirement validation ([`A.10`](iso27001.json))
  - Operations security assessment ([`A.12`](iso27001.json))
  - Communications security verification ([`A.13`](iso27001.json))

- **`nist-csf.json`**: NIST Cybersecurity Framework v1.1 profile
  - Identify function controls ([`ID`](nist-csf.json))
  - Protect function requirements ([`PR`](nist-csf.json))
  - Detect function capabilities ([`DE`](nist-csf.json))
  - Respond function assessment ([`RS`](nist-csf.json))
  - Recover function validation ([`RC`](nist-csf.json))
  - CSF category and subcategory mapping

- **`pci-dss.json`**: PCI DSS v3.2.1 compliance profile
  - Secure network configuration requirements ([`Req 1`](pci-dss.json))
  - Cardholder data protection controls ([`Req 3`](pci-dss.json), [`Req 4`](pci-dss.json))
  - Vulnerability management requirements ([`Req 5`](pci-dss.json), [`Req 6`](pci-dss.json), [`Req 11`](pci-dss.json))
  - Access control measure verification ([`Req 7`](pci-dss.json), [`Req 8`](pci-dss.json), [`Req 9`](pci-dss.json))
  - Network monitoring validation ([`Req 10`](pci-dss.json))
  - Security testing requirements ([`Req 11`](pci-dss.json))
  - Information security policy assessment ([`Req 12`](pci-dss.json))

## Directory Structure

```plaintext
admin/security/assessment_tools/config_files/assessment_profiles/compliance/
├── README.md       # This documentation
├── ccpa.json       # CCPA compliance profile
├── fedramp.json    # FedRAMP Moderate compliance profile
├── gdpr.json       # GDPR compliance profile
├── hipaa.json      # HIPAA Security Rule compliance profile
├── iso27001.json   # ISO 27001:2013 compliance profile
├── nist-csf.json   # NIST Cybersecurity Framework v1.1 profile
└── pci-dss.json    # PCI DSS v3.2.1 compliance profile
```

## Usage

The compliance profiles are used with the security assessment tools (found in [`../../../core_assessment_tools/`](../../../core_assessment_tools/)) to conduct compliance-focused assessments. They can be used standalone or layered on top of base environment profiles ([`../development.json`](../development.json), [`../production.json`](../production.json)).

```bash
# Run a full PCI DSS assessment using the compliance profile directly
vulnerability_scanner.py --profile pci-dss.json --target payment-system

# Run ISO 27001 assessment on a production system, layering compliance over the base production profile
configuration_analyzer.py --base-profile production.json --compliance-profile iso27001.json --target core-server

# Generate compliance report for HIPAA using the configuration analyzer
configuration_analyzer.py --profile hipaa.json --target healthcare-data --report-format detailed --output hipaa-assessment.pdf

# Layer NIST CSF compliance checks with the development environment profile for access control audit
access_control_auditor.py --base-profile development.json --compliance-profile nist-csf.json --components identify,protect
```

For programmatic use in Python, a helper function can load and merge profiles (see [`../README.md`](../README.md) for an example `load_assessment_profile` function):

```python
# ...existing code...
from config_loader import load_assessment_profile # Assuming a utility function exists

# Load GDPR profile layered on production base profile
profile = load_assessment_profile(profile_name="production", compliance_addon="gdpr")

# Load FedRAMP profile directly
fedramp_profile = load_assessment_profile(profile_name=None, compliance_addon="fedramp")

# Use the loaded profile data for assessment configuration
# ... run assessment using profile ...
# ...existing code...
```

## Profile Structure

Compliance assessment profiles follow a standard JSON structure, extending the base profile structure (defined in `../README.md`) with sections specific to each regulatory framework. Key sections include:

- **`metadata`**: Includes standard name and version.
- **`assessment`**: Defines scope, evidence requirements, and report format specific to the compliance standard.
- **`compliance_mapping`**: Maps technical controls and verification methods to specific requirements or articles of the standard. This is the core section defining the compliance checks.
- **`finding_classification`**: Defines severity levels (e.g., critical, high) based on compliance impact (e.g., direct violation, significant weakness).
- **`remediation_requirements`**: Specifies approval processes, documentation, and validation needed for findings based on severity.
- **`assessment_controls`**: Defines specific technical control parameters required by the standard (e.g., password length, encryption algorithms).
- **`testing_requirements`**: Specifies frequency and scope for compliance-related testing (e.g., DSR process testing for GDPR, segmentation testing for PCI DSS).
- **`attestation_requirements`**: Outlines periodic review and approval requirements for compliance documentation (e.g., ROPA review for GDPR, policy review for PCI DSS).

Example snippet from `pci-dss.json`:

```json
{
  "metadata": {
    "name": "PCI DSS v3.2.1 Compliance Profile",
    "standard": "PCI DSS",
    "standard_version": "3.2.1",
  },
  "assessment": {
    "scope": {
      "include": ["cardholder_data_environment_cde", /* ... */],
      "exclude": ["systems_fully_segmented_from_cde", /* ... */]
    },
    "evidence_requirements": ["network_diagrams_showing_cde", /* ... */],
    "report_format": "pci_dss_roc"
  },
  "compliance_mapping": {
    "requirement_1": {
      "title": "Req 1: Install and maintain a firewall configuration to protect cardholder data",
      "controls": ["firewall_rule_review", "network_segmentation_verification", /* ... */],
      "verification_methods": ["configuration_review", "documentation_review", "network_testing"],
      "evidence_required": ["firewall_rulesets", "network_diagrams", /* ... */]
    },
    "requirement_2": {
    }
  },
  "finding_classification": {
    "critical": {
      "compliance_impact": "direct_violation_high_risk",
      "remediation_sla_days": 7,
    },
    "high": {
    }
  },
  "assessment_controls": {
      "authentication": {
          "password_policy": { "min_length": 7, /* ... */ },
          "mfa": { "required": true, /* ... */ }
      },
  },
  "testing_requirements": {
      "internal_vulnerability_scan": { "frequency_months": 3, /* ... */ },
  },
  "attestation_requirements": {
      "policy_review": { "frequency_months": 12, /* ... */ },
  }
}
```

## Customization Guidelines

When customizing compliance assessment profiles:

1. **Start with Standard Framework**:
    - Begin with the official compliance framework documentation (e.g., PCI DSS standard, GDPR text, ISO 27001 Annex A).
    - Map framework requirements accurately to specific technical controls within the profile's `compliance_mapping`.
    - Document validation methods (`verification_methods`) clearly for each control.
    - Reference specific sections or articles of the standard in descriptions or titles.

2. **Consider Environment Context**:
    - Adapt requirements based on how the standard applies to the organization's specific systems and data flows.
    - Document any scoping decisions (e.g., which systems are in scope for PCI DSS CDE) in the `assessment.scope` section.
    - Include organization-specific interpretations if necessary, ensuring they align with the standard's intent.
    - Account for compensating controls if allowed by the standard and document them appropriately.

3. **Document Exceptions**:
    - Clearly document any requirements deemed not applicable or excluded from the assessment scope.
    - Provide a strong rationale for exclusions, referencing the standard where possible.
    - Note any alternative or compensating controls implemented in lieu of standard requirements.
    - Link to formal risk acceptance documentation if applicable.

4. **Maintain Version Control**:
    - Track all changes to compliance profiles using Git.
    - Update the `metadata.version` and `metadata.last_updated` fields with each significant change.
    - Document the specific version of the compliance standard (`metadata.standard_version`) the profile aligns with.
    - Note changes from previous framework versions if the standard is updated.
    - Use commit messages to explain the rationale for changes.

## Best Practices & Security

- **Baseline with Standards**: Always start customizations from the official compliance framework documentation to ensure accuracy.
- **Compliance Mapping**: Maintain a clear, accurate, and traceable mapping between technical controls in the profile and the specific requirements of the compliance standard.
- **Documentation**: Include references to specific sections, articles, or control numbers of the standard within the profile for clarity and auditability.
- **Evidence Requirements**: Define specific, achievable evidence (`evidence_required`) needed for compliance verification for each control group.
- **Granular Controls**: Break down complex compliance requirements into specific, testable technical controls (`controls`) within the `compliance_mapping`.
- **Gap Analysis**: Structure the profile to facilitate gap analysis by clearly defining expected controls versus actual implementation.
- **Interpretation Guidance**: Where ambiguity exists, provide brief guidance or reference internal policy documents for interpreting requirements in the technical context.
- **Quality Control**: Have compliance subject matter experts (SMEs) and security engineers review profile customizations for accuracy and feasibility.
- **Regular Updates**: Update profiles promptly when compliance standards are revised or official interpretations change. Schedule periodic reviews (e.g., annually).
- **Risk-Based Approach**: While covering all requirements, ensure assessment depth and finding classification (`finding_classification`) reflect the risk associated with non-compliance for specific areas.
- **Secondary Validation**: For critical compliance controls, consider implementing secondary or independent validation methods.
- **Version Tracking**: Rigorously track the version of the compliance standard the profile corresponds to (`metadata.standard_version`) alongside the profile's own version (`metadata.version`).

## Common Features

All compliance assessment profiles include these common elements:

- **Compliance Mapping**: Direct mapping of technical controls to the standard's sections, articles, or requirements.
- **Control Categorization**: Grouping of controls logically based on the compliance standard's structure (e.g., by requirement number, article, or domain).
- **Control Verification Methods**: Specified methods (e.g., `configuration_review`, `documentation_review`, `system_testing`) for validating each control group.
- **Evidence Requirements**: Defined list of specific evidence artifacts needed to demonstrate compliance for control groups.
- **Finding Classification**: Severity ratings (e.g., `critical`, `high`) defined based on the impact on compliance status (e.g., `direct_violation`, `significant_weakness`).
- **Framework References**: Explicit references to the specific compliance standard and version in the `metadata`.
- **Metadata**: Includes profile name, version, description, standard name, standard version, author, and last update date.
- **Remediation Requirements**: Guidance on approvals, documentation, and validation needed for fixing compliance findings, often tied to severity.
- **Reporting Requirements**: Specifies the expected format or structure for compliance reports (`assessment.report_format`).
- **Risk Assessment Parameters**: May include guidance or parameters for assessing risk within the specific compliance context.
- **Scope Definition**: Clear definition of systems, data, or processes included and excluded from the compliance assessment (`assessment.scope`).
- **Standard Version**: The specific version of the compliance standard the profile is designed for (e.g., "3.2.1" for PCI DSS, "2013" for ISO 27001).

## Related Documentation

- Compliance Framework Documentation - Overview of the organization's compliance program.
- Assessment Methodology Guide - General security assessment approach.
- Compliance Control Mapping - Detailed mapping documents (if separate).
- Control Implementation Guide - Guides on implementing specific controls.
- Evidence Collection Requirements - General guidance on evidence collection.
- Assessment Profile Documentation - Documentation for the parent assessment profiles directory.
- Parent Assessment Profiles README - Describes base profiles like `default.json`, `production.json`.
- Regulatory Requirement References - Links to official standard documents (external).
- Security Assessment Tool Usage Guide - How to run the assessment tools.
- Standard Interpretation Guidelines - Internal documents clarifying standard interpretations.
