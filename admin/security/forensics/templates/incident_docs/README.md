# Incident Documentation Templates

This directory contains standardized templates for documenting security incidents throughout the investigation lifecycle in the Cloud Infrastructure Platform. These templates ensure comprehensive, consistent, and legally sound documentation of security incidents for internal investigation, remediation, and potential legal proceedings.

## Contents

- Overview
- Key Templates
- Directory Structure
- Usage
- Template Variables
- Template Integration
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
  - Technical details abstraction
  - Executive action items

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
  - Lessons learned and recommendations

- **`investigation_notes.md`**: Ongoing investigation documentation
  - Analysis actions documentation
  - Hypothesis tracking
  - Investigation decision points
  - Open questions tracking
  - Pattern identification notes
  - Task allocation and status
  - Technical observations
  - Evidence examination details
  - Working theories and validation steps

- **`preliminary_report.md`**: Initial incident assessment
  - First responder observations
  - Initial containment actions
  - Preliminary evidence collection
  - Preliminary scope assessment
  - Priority recommendations
  - Risk assessment
  - Triage findings
  - Immediate action items
  - Resource requirements
  - Investigation priorities

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
cp preliminary_report.md \
   preliminary_report.md

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
- `{{classification}}` - Document classification level (e.g., "Confidential", "Restricted")
- `{{creation_date}}` - Date document was initially created
- `{{current_date}}` - Date document is generated or updated
- `{{document_id}}` - Unique document identifier (auto-generated format)
- `{{document_owner}}` - Person responsible for maintaining the document
- `{{document_status}}` - Status (Draft, Final, Under Review, etc.)
- `{{incident_id}}` - Incident tracking identifier (e.g., "IR-2024-042")
- `{{incident_name}}` - Descriptive incident name (e.g., "Web Server Compromise")
- `{{incident_type}}` - Category of incident (e.g., "Data Breach", "Ransomware")
- `{{last_updated}}` - Last modification timestamp with timezone
- `{{report_version}}` - Document version number (e.g., "1.2")
- `{{severity_level}}` - Incident severity classification (e.g., "Critical", "High")

### Incident Report Variables

- `{{affected_data}}` - Data potentially exposed/affected by the incident
- `{{affected_systems}}` - Systems affected by incident (names, functions, criticality)
- `{{attack_vector}}` - Initial access method and entry point
- `{{attack_progression}}` - Chronological progression of attacker activities
- `{{containment_actions}}` - Actions taken to contain the incident
- `{{detection_method}}` - How incident was discovered (tool, person, alert)
- `{{evidence_list}}` - List of collected evidence with chain of custody references
- `{{indicators_of_compromise}}` - Technical IOCs (hashes, IPs, domains, etc.)
- `{{mitre_tactics}}` - MITRE ATT&CK tactics identified in the incident
- `{{mitre_techniques}}` - MITRE ATT&CK techniques identified in the incident
- `{{persistence_mechanisms}}` - Methods used by attackers to maintain access
- `{{root_cause}}` - Root cause determination and vulnerability identification
- `{{timeline_summary}}` - Chronological event summary with timestamps
- `{{data_impact}}` - Assessment of data affected (confidentiality, integrity, availability)
- `{{lessons_learned}}` - Key takeaways and improvements identified

### Investigation Variables

- `{{activity_description}}` - Description of investigative activity performed
- `{{analysis_actions}}` - Investigative actions taken with results
- `{{artifact_description}}` - Description of artifacts being analyzed
- `{{artifact_hash}}` - Cryptographic hash of digital artifacts
- `{{artifact_location}}` - Storage location of the artifact
- `{{artifact_name}}` - Name or identifier of the artifact
- `{{artifact_significance}}` - Why the artifact is relevant to investigation
- `{{chain_of_custody_ref}}` - Reference to chain of custody documentation
- `{{confidence_level}}` - Confidence in findings (High, Medium, Low)
- `{{current_hypotheses}}` - Working theories about the incident
- `{{evidence_id}}` - Unique identifier for evidence items
- `{{hypothesis_description}}` - Detailed description of working theory
- `{{indicator_context}}` - Context around identified indicators
- `{{indicator_description}}` - Description of observed indicators
- `{{indicator_source}}` - Source where indicator was identified
- `{{indicator_type}}` - Type of indicator (file, network, registry, etc.)
- `{{investigation_status}}` - Current status of the investigation
- `{{investigating_team}}` - Team members involved in the investigation
- `{{investigation_objective}}` - Specific goals of the investigation
- `{{investigation_steps}}` - Steps to validate hypothesis or answer questions
- `{{open_question}}` - Unresolved question requiring investigation
- `{{pending_actions}}` - Planned next steps in investigation
- `{{technical_findings}}` - Technical analysis results and details
- `{{tools_used}}` - Tools used during investigation with versions

### Preliminary Report Variables

- `{{collection_method}}` - Method used to collect preliminary evidence
- `{{collection_status}}` - Status of evidence collection efforts
- `{{containment_measure}}` - Specific containment action implemented
- `{{containment_recommendation}}` - Recommended containment action
- `{{discovery_datetime}}` - When incident was initially discovered
- `{{discovery_method}}` - How incident was initially discovered
- `{{event_description}}` - Description of observed event
- `{{event_observer}}` - Person who observed the event
- `{{event_source}}` - Source of event information (log, system, user)
- `{{evidence_handler}}` - Person handling specific evidence
- `{{evidence_priority}}` - Priority for evidence collection
- `{{evidence_source}}` - Source system/location of evidence
- `{{evidence_type}}` - Type of evidence being collected
- `{{implementation_datetime}}` - When containment measure was implemented
- `{{implemented_by}}` - Person who implemented containment measure
- `{{initial_analysis}}` - Results of preliminary technical analysis
- `{{investigation_priority}}` - Priority area for investigation
- `{{measure_purpose}}` - Purpose of specific containment measure
- `{{next_update_datetime}}` - When next update will be provided
- `{{notification_datetime}}` - When stakeholder was notified
- `{{observed_impact}}` - Impact observed during initial assessment
- `{{observed_indicators}}` - Indicators observed during initial response
- `{{potential_attack_vectors}}` - Possible attack vectors based on initial data
- `{{reported_by}}` - Person who reported the incident
- `{{resource_priority}}` - Priority for resource allocation
- `{{resource_purpose}}` - Purpose of requested resource
- `{{resource_status}}` - Current status of resource
- `{{resource_type}}` - Type of resource needed for response
- `{{system_function}}` - Business function of affected system
- `{{system_identifier}}` - Identifier for affected system
- `{{system_name}}` - Name of affected system
- `{{system_status}}` - Current status of affected system
- `{{urgent_action}}` - Action requiring immediate attention

## Template Integration

These incident documentation templates are designed to integrate with other forensic templates in the repository:

### Integration with Evidence Handling Templates

- Link to chain of custody documents using the format `COC-{{case_id}}-{{evidence_id}}`
- Reference evidence inventory using evidence IDs consistent with evidence_inventory.md
- Use evidence log references to document collection methodologies

```plaintext
For complete details on evidence item E001, refer to [Evidence Log E001](../../../evidence/E001_memory_acquisition.md)
and [Chain of Custody COC-2024-042-E001](../../../evidence/COC-2024-042-E001.md).
```

### Integration with Analysis Templates

- Include references to detailed analysis reports using the standardized document ID format
- Link to specific malware or artifact analysis documents for technical details
- Reference timeline analysis through standard timeline IDs

```plaintext
For detailed analysis of the malware sample, see [Malware Analysis Report MAL-2024-042-01](../../../analysis/malware/MAL-2024-042-01.md).
```

### Integration with Response Documentation

- Link to incident response playbook used during the incident
- Reference post-incident review documentation
- Connect to remediation planning documents

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
- **Consistency**: Use consistent terminology across all incident documentation
- **Cross-Referencing**: Maintain proper references between related documents
- **Separation of Concerns**: Keep facts, hypotheses, and recommendations clearly separated

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
- **Document ID**: Unique standardized document identifier
- **Related Documents Section**: Links to associated documentation
- **Distribution List**: Authorized recipients tracking
- **Security Classification Footer**: Reminder of document sensitivity

## Related Documentation

- Chain of Custody Procedures
- Digital Evidence Guidelines
- Evidence Handling Procedures
- Forensic Analysis Documentation
- Incident Response Plan
- Incident Response Procedures
- Legal and Compliance Requirements
- [NIST SP 800-61: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- Regulatory Reporting Requirements
- Security Classification Guide
- Evidence Collection Tools Guide
- Malware Analysis Templates
- Timeline Construction Guide
