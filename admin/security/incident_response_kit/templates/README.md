# Documentation Templates for Incident Response

This directory contains standardized templates for documenting security incidents, response activities, evidence handling, and communications throughout the incident response lifecycle. These templates ensure consistency, completeness, and compliance with documentation requirements.

## Contents

- Overview
- Key Components
- Directory Structure
- Usage Guidelines
- Template Variables
- API Reference
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
  - Classification of security events by severity

- **`chain_of_custody.md`**: Evidence management documentation
  - Evidence identification information
  - Collection methodology details
  - Handling personnel tracking
  - Transfer and storage records
  - Access log and verification steps
  - Evidence disposition documentation
  - SHA-256 integrity verification

- **`communication_plan.md`**: Stakeholder communication templates
  - Internal team communication templates
  - Management notification templates
  - Customer/user notification templates
  - Regulatory notification templates
  - Media statement templates
  - Communication timing guidelines
  - Severity-based notification requirements

- **`executive_briefing.md`**: Management reporting template
  - Non-technical incident summary
  - Business impact assessment
  - Resource requirements section
  - Risk assessment and mitigation status
  - Decision points requiring executive input
  - Recommended actions and timeline
  - Executive approval workflows

- **`remediation_plan.md`**: Recovery planning document
  - Prioritized remediation actions
  - Resource requirements and assignments
  - Implementation timeline
  - Testing and verification procedures
  - Rollback procedures
  - Progress tracking metrics
  - Security hardening measures
  - Integrity verification steps

## Directory Structure

```plaintext
admin/security/incident_response_kit/templates/
├── README.md                # This documentation
├── __init__.py              # Module initialization and exports
├── incident_report.md       # Complete incident report template
├── incident_timeline.md     # Timeline documentation template
├── chain_of_custody.md      # Evidence tracking documentation
├── communication_plan.md    # Stakeholder communication templates
├── executive_briefing.md    # Management briefing template
├── remediation_plan.md      # Recovery action planning template
└── template_variables.py    # Template variable definitions
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

# Integrate file integrity violations into reporting
../forensic_tools/file_integrity.py --verify \
    --baseline /secure/baselines/critical_files.json \
    --output-format markdown \
    >> /secure/evidence/IR-2023-042/documentation/incident_report.md
```

## Template Variables

Templates use standardized variables defined in `template_variables.py` that can be populated programmatically:

### Variable Categories

- **Common Variables**: Shared across all templates (incident ID, dates, etc.)
- **Incident Report Variables**: Specific to incident reporting
- **Timeline Variables**: For timeline documentation
- **Chain of Custody Variables**: For evidence tracking
- **Communication Variables**: For stakeholder communications
- **Remediation Variables**: For recovery planning

### Using Variables Programmatically

```python
from admin.security.incident_response_kit.templates import (
    get_template_variables, render_template, TemplateType
)

# Get variables for a specific template type
variables = get_variables_by_template(TemplateType.EXECUTIVE_BRIEFING)

# Set variable values for your specific incident
incident_vars = {
    "INCIDENT_ID": "IR-2023-042",
    "CLASSIFICATION": "Confidential",
    "STATUS": "Investigating",
    "DATE": "2023-07-15",
    "LEAD_RESPONDER": "John Smith",
    "EXECUTIVE_SUMMARY": "Critical database server compromise detected..."
    # Add other variables as needed
}

# Render the template with variables
rendered_template = render_template("executive_briefing.md", incident_vars)
with open("/secure/evidence/IR-2023-042/executive_briefing.md", "w") as f:
    f.write(rendered_template)
```

## API Reference

The templates module exposes the following functionality through `__init__.py`:

### Classes and Enums

- `TemplateType`: Enum of template types (INCIDENT_REPORT, INCIDENT_TIMELINE, etc.)
- `VariableCategory`: Enum of variable categories (COMMON, TIMELINE, etc.)

### Functions

- `get_variable_categories()`: Return all available variable categories
- `get_variables_by_category(category)`: Get variables for a specific category
- `get_variables_by_template(template_type)`: Get variables for a specific template type
- `get_available_templates()`: Get dictionary of available templates
- `get_template_path(template_name)`: Get full path to a specific template
- `render_template(template_name, variables)`: Render a template with provided variables
- `get_template_type(template_name)`: Determine template type from filename
- `get_template_variables(template_name)`: Get variables applicable to a template

### Constants

- `TEMPLATE_DIR`: Path to the templates directory
- `DEFAULT_INCIDENT_TEMPLATE`: Default incident report template filename
- `DEFAULT_TIMELINE_TEMPLATE`: Default timeline template filename
- `DEFAULT_CHAIN_OF_CUSTODY_TEMPLATE`: Default chain of custody template filename
- `DEFAULT_COMMUNICATION_TEMPLATE`: Default communication plan template filename
- `DEFAULT_EXECUTIVE_BRIEFING_TEMPLATE`: Default executive briefing template filename
- `DEFAULT_REMEDIATION_TEMPLATE`: Default remediation plan template filename

### Variable Dictionaries

- `COMMON_VARIABLES`: Common variables used across all templates
- `INCIDENT_REPORT_VARIABLES`: Variables specific to incident reports
- `TIMELINE_VARIABLES`: Variables specific to timelines
- `CHAIN_OF_CUSTODY_VARIABLES`: Variables specific to chain of custody
- `COMMUNICATION_VARIABLES`: Variables specific to communications
- `REMEDIATION_VARIABLES`: Variables specific to remediation
- `TEMPLATE_VARIABLES`: Combined dictionary of all variables

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
- **Integrity Verification**: Include file integrity validation in technical documentation
- **Time Synchronization**: Use consistent timezone (UTC) for all timestamps
- **Evidence Linking**: Reference evidence IDs consistently across all documents

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
- **Change History**: Timestamped record of document modifications
- **Document Owner**: Clear identification of document ownership
- **Review Frequency**: Required review cadence based on incident status

## Related Documentation

- Incident Response Kit Overview
- Security Incident Response Plan
- Incident Response Procedures
- Documentation Requirements
- Regulatory Reporting Requirements
- Evidence Collection Guide
- [NIST SP 800-61: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- Chain of Custody Requirements
- File Integrity Monitoring Guide
- Log Analysis Documentation
- AuditLog Model Reference
- Core Security Module Documentation
