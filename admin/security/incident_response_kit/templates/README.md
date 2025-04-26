# Documentation Templates for Incident Response

This directory contains standardized templates for documenting security incidents, response activities, evidence handling, and communications throughout the incident response lifecycle. These templates ensure consistency, completeness, and compliance with documentation requirements.

## Contents

- Overview
- Key Components
- Directory Structure
- Usage Guidelines
- Best Practices & Security
- Common Features
- Related Documentation

## Overview

The documentation templates provide structured formats for capturing critical information during security incidents. They follow the NIST SP 800-61 framework and comply with regulatory documentation requirements. Each template is designed to ensure thorough documentation while minimizing administrative overhead during incidents. These templates facilitate consistent reporting, enable effective communication with stakeholders, and support post-incident analysis and improvement activities.

## Key Components

- **`incident_report.md`**: Comprehensive incident documentation
  - Executive summary section
  - Detailed technical narrative
  - Impact assessment
  - Response actions taken
  - Root cause analysis
  - Recommendations and next steps
  - References to related documents and evidence

- **`incident_timeline.md`**: Chronological event documentation
  - Structured format for event recording
  - Timestamp normalization guide
  - Detection, analysis, containment, and recovery phases
  - Evidence linkage markers
  - Attribution details when available
  - Confidence levels for timeline entries

- **`chain_of_custody.md`**: Evidence management documentation
  - Evidence identification information
  - Collection methodology details
  - Handling personnel tracking
  - Transfer and storage records
  - Access log and verification steps
  - Evidence disposition documentation

- **`communication_plan.md`**: Stakeholder communication templates
  - Internal team communication templates
  - Management notification templates
  - Customer/user notification templates
  - Regulatory notification templates
  - Media statement templates
  - Communication timing guidelines

- **`executive_briefing.md`**: Management reporting template
  - Non-technical incident summary
  - Business impact assessment
  - Resource requirements section
  - Risk assessment and mitigation status
  - Decision points requiring executive input
  - Recommended actions and timeline

- **`remediation_plan.md`**: Recovery planning document
  - Prioritized remediation actions
  - Resource requirements and assignments
  - Implementation timeline
  - Testing and verification procedures
  - Rollback procedures
  - Progress tracking metrics

## Directory Structure

```plaintext
admin/security/incident_response_kit/templates/
├── README.md                # This documentation
├── incident_report.md       # Complete incident report template
├── incident_timeline.md     # Timeline documentation template
├── chain_of_custody.md      # Evidence tracking documentation
├── communication_plan.md    # Stakeholder communication templates
├── executive_briefing.md    # Management briefing template
└── remediation_plan.md      # Recovery action planning template
```

## Usage Guidelines

### Template Selection

Select the appropriate template based on the current phase of incident response and documentation needs:

1. Use `incident_timeline.md` from the beginning of the incident to track all events chronologically
2. Use `chain_of_custody.md` whenever evidence is collected or transferred
3. Use `communication_plan.md` to prepare all stakeholder communications
4. Use `executive_briefing.md` for initial and ongoing management updates
5. Use `remediation_plan.md` during the recovery planning phase
6. Use `incident_report.md` to create the final comprehensive incident documentation

### Template Customization

```bash
# Create incident-specific templates using initialization script
../initialize.sh --incident-id IR-2023-042 \
    --create-templates \
    --output /secure/evidence/IR-2023-042/documentation/

# Update incident timeline with new events
cat << EOF >> /secure/evidence/IR-2023-042/documentation/incident_timeline.md
## 2023-07-15T15:30:00Z - Malware Identified

**Description:** Identified malware family as Emotet variant
**Source:** Malware analysis report
**Confidence:** High
**Actor:** Security Analyst (Sarah Williams)
**Evidence:** malware_analysis_report.pdf
**Notes:** Hash matches known Emotet samples in threat intelligence feed
EOF
```

### Template Integration

The templates are designed to work with other incident response tools:

```bash
# Generate initial timeline from log analysis
../log_analyzer.py --logs /var/log/auth.log,/var/log/syslog \
    --start-time "2023-07-15T10:00:00Z" \
    --template templates/incident_timeline.md \
    --output /secure/evidence/IR-2023-042/documentation/initial_timeline.md

# Generate executive briefing from incident data
../coordination/status_tracker.py --incident-id IR-2023-042 \
    --generate-report \
    --format executive \
    --template templates/executive_briefing.md \
    --output /secure/evidence/IR-2023-042/documentation/executive_briefing.md
```

## Best Practices & Security

- **Confidentiality**: Apply appropriate access controls to all incident documentation
- **Completeness**: Fill in all required sections of each template
- **Objectivity**: Focus on facts rather than assumptions or speculation
- **Precision**: Be specific about dates, times, systems, and actions
- **Security**: Treat all incident documentation as sensitive information
- **Version Control**: Track versions of all documents as they evolve
- **Legal Review**: Have critical communications reviewed by legal counsel
- **Sanitization**: Sanitize templates before sharing with external parties
- **Consistency**: Use consistent terminology throughout all documents
- **Attribution**: Clearly document who performed actions or made observations

## Common Features

All templates include these common elements:

- **Metadata Header**: Incident ID, classification, dates, author information
- **Version Tracking**: Document version and change history
- **Status Indicators**: Current document status (draft, final, etc.)
- **Security Classification**: Document sensitivity marking
- **Distribution List**: Authorized recipients of the document
- **Review Status**: Documentation of reviews and approvals
- **References Section**: Links to related documents and evidence
- **Footer Information**: Page numbers, document ID, date
- **Formatting Consistency**: Standardized headings and structure
- **Legal Disclaimer**: Standard legal text where applicable

## Related Documentation

- Incident Response Kit Overview
- Security Incident Response Plan
- Incident Response Procedures
- Documentation Requirements
- Regulatory Reporting Requirements
- Evidence Collection Guide
- [NIST SP 800-61: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- Chain of Custody Requirements
