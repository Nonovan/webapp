# Incident Documentation Templates

This directory contains standardized templates for documenting security incidents throughout the investigation lifecycle in the Cloud Infrastructure Platform. These templates ensure comprehensive, consistent, and legally sound documentation of security incidents for internal investigation, remediation, and potential legal proceedings.

## Contents

- Overview
- Key Templates
- Directory Structure
- Usage
- Template Variables
- Customization Guidelines
- Best Practices & Security
- Common Features
- Related Documentation

## Overview

The incident documentation templates provide structured formats for capturing critical information at various stages of security incident response. They ensure thorough documentation of initial findings, ongoing investigations, and final conclusions while maintaining proper evidentiary standards. These templates follow industry best practices for incident documentation, align with the NIST SP 800-61 incident response framework, and support potential legal and compliance requirements. They facilitate clear communication with stakeholders while ensuring that critical information is properly recorded and preserved.

## Key Templates

- **`executive_summary.md`**: Management-level incident overview
  - Business impact assessment
  - Critical timeline milestones
  - Key findings summary
  - Resource allocation summary
  - Risk assessment overview
  - Strategic recommendations

- **`incident_report.md`**: Comprehensive incident documentation
  - Affected assets inventory
  - Attacker methodology analysis
  - Complete timeline reconstruction
  - Containment actions documentation
  - Detailed impact assessment
  - Evidence inventory references
  - Indicators of compromise
  - Root cause analysis
  - Technical findings documentation

- **`investigation_notes.md`**: Ongoing investigation documentation
  - Analysis actions documentation
  - Hypothesis tracking
  - Investigation decision points
  - Open questions tracking
  - Pattern identification notes
  - Task allocation and status
  - Technical observations

- **`preliminary_report.md`**: Initial incident assessment
  - First responder observations
  - Initial containment actions
  - Preliminary evidence collection
  - Preliminary scope assessment
  - Priority recommendations
  - Risk assessment
  - Triage findings

## Directory Structure

```plaintext
admin/security/forensics/templates/incident_docs/
├── README.md                # This documentation
├── executive_summary.md     # Management briefing template
├── incident_report.md       # Complete incident report template
├── investigation_notes.md   # Ongoing investigation notes template
└── preliminary_report.md    # Initial incident assessment template
```

## Usage

These templates are designed to be used at different stages of the incident response process:

```bash
# Create preliminary report at incident discovery
cp admin/security/forensics/templates/incident_docs/preliminary_report.md \
   /secure/evidence/incident-42/documentation/preliminary_report.md

# Generate an executive summary for management using timeline data
../utils/report_builder.py \
   --template admin/security/forensics/templates/incident_docs/executive_summary.md \
   --timeline /secure/evidence/incident-42/timeline.json \
   --output /secure/evidence/incident-42/documentation/executive_summary.md \
   --incident-id "IR-2024-042" \
   --classification "Confidential"
```

For programmatic use with the incident documentation system:

```python
from forensics.utils.report_builder import generate_incident_document
from forensics.utils.timeline import get_incident_timeline

# Generate comprehensive incident report
timeline = get_incident_timeline('IR-2024-042')
generate_incident_document(
    template_path='admin/security/forensics/templates/incident_docs/incident_report.md',
    output_path='/secure/evidence/IR-2024-042/documentation/final_incident_report.md',
    incident_id='IR-2024-042',
    lead_investigator='Jane Smith',
    timeline=timeline,
    affected_systems=['web-app-01', 'database-02'],
    evidence_references=['/secure/evidence/IR-2024-042/evidence_log.md'],
    classification='Restricted'
)
```

## Template Variables

The templates use standardized variables that are populated during document generation:

### Common Variables

- `{{analyst_name}}` - Name of lead analyst/investigator
- `{{classification}}` - Document classification level
- `{{current_date}}` - Date document is generated
- `{{document_id}}` - Unique document identifier
- `{{document_status}}` - Status (Draft, Final, etc.)
- `{{incident_id}}` - Incident tracking identifier
- `{{incident_name}}` - Descriptive incident name
- `{{last_updated}}` - Last modification timestamp
- `{{report_version}}` - Document version number

### Executive Summary Variables

- `{{business_impact}}` - Business impact description
- `{{critical_findings}}` - Most important findings
- `{{executive_actions}}` - Required executive actions
- `{{incident_status}}` - Current incident status
- `{{key_metrics}}` - Critical incident metrics
- `{{remediation_summary}}` - Brief remediation strategy
- `{{risk_assessment}}` - Current risk assessment

### Incident Report Variables

- `{{affected_data}}` - Data potentially exposed/affected
- `{{affected_systems}}` - Systems affected by incident
- `{{attack_vector}}` - Initial access method
- `{{containment_actions}}` - Actions taken to contain
- `{{detection_method}}` - How incident was discovered
- `{{evidence_list}}` - List of collected evidence
- `{{indicators_of_compromise}}` - Technical IOCs
- `{{root_cause}}` - Root cause determination
- `{{timeline_summary}}` - Chronological event summary

### Investigation Variables

- `{{analysis_actions}}` - Investigative actions taken
- `{{current_hypotheses}}` - Working theories
- `{{investigation_status}}` - Current investigation status
- `{{investigating_team}}` - Team members involved
- `{{open_questions}}` - Unresolved questions
- `{{pending_actions}}` - Planned next steps
- `{{technical_findings}}` - Technical analysis results

## Customization Guidelines

When customizing these templates for specific incidents:

1. **Maintain Core Sections**
   - Keep all required metadata fields
   - Preserve standard section headers and structure
   - Maintain document control elements
   - Preserve classification markings
   - Retain chain of custody references

2. **Add Incident-Specific Content**
   - Include specific technical details and findings
   - Document specific timeline events chronologically
   - Add relevant evidence references
   - Include specific system and data impacts
   - Document specific containment and remediation actions

3. **Follow Documentation Standards**
   - Clearly distinguish facts from analysis/opinions
   - Document confidence levels for findings
   - Maintain technical accuracy and precision
   - Include all relevant timestamps with timezone
   - Document all sources of information
   - Use consistent terminology throughout

4. **Review Process**
   - Have documentation reviewed by peers
   - Verify technical accuracy of details
   - Ensure proper handling of sensitive information
   - Follow proper approval process before distribution

## Best Practices & Security

- **Attribution**: Clearly indicate who performed specific actions or made observations
- **Chain of Evidence**: Maintain proper references to evidence sources
- **Classification**: Apply appropriate sensitivity classification
- **Completeness**: Include all relevant details even if seemingly minor
- **Factual Basis**: Clearly distinguish facts from speculation or analysis
- **Need-to-Know**: Limit distribution to those with legitimate need
- **Objectivity**: Maintain neutral, factual language
- **Precision**: Be specific about systems, times, and actions
- **Revision Control**: Track all document versions and changes
- **Secure Handling**: Follow proper security protocols for incident documentation
- **Timely Documentation**: Document observations as soon as possible
- **Verification**: Verify information before including in documentation

## Common Features

All incident documentation templates include these common elements:

- **Case Identifiers**: Consistent incident reference information
- **Classification Banner**: Security classification markings
- **Document Control Information**: Version tracking and change history
- **Evidence References**: Links to supporting evidence
- **Handling Instructions**: Document handling requirements
- **Metadata Header**: Standard document metadata
- **Review Status**: Documentation of reviews and approvals
- **Revision History**: Tracking of document changes and versions
- **Signature Blocks**: Authentication of document authors and reviewers
- **Standard Disclaimers**: Legal and confidentiality notices
- **Table of Contents**: Navigation aid for longer documents
- **Timeline References**: Connections to master incident timeline

## Related Documentation

- Chain of Custody Procedures
- Digital Evidence Guidelines
- Evidence Handling Procedures
- Forensic Analysis Documentation
- Incident Response Plan
- Incident Response Procedures
- Legal and Compliance Requirements
- NIST SP 800-61: Computer Security Incident Handling Guide
- Regulatory Reporting Requirements
- Security Classification Guide
