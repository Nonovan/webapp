# Forensic Analysis Templates

This directory contains standardized templates for forensic analysis documentation, reporting, and evidence handling in the Cloud Infrastructure Platform. These templates ensure consistency, completeness, and compliance with legal and regulatory requirements during security incident investigations.

## Contents

- Overview
- Template Categories
- Directory Structure
- Usage
- Template Standards
- Customization Guidelines
- Related Documentation

## Overview

The forensic analysis templates provide structured formats for documenting various aspects of the forensic investigation process. They ensure that all necessary information is properly captured, chain of custody is maintained, and reports are presented in a consistent, professional manner. These templates follow best practices for digital forensics and adhere to legal standards for evidence handling.

## Template Categories

### Analysis Documents

- **`artifact_analysis.md`** - Detailed artifact examination
  - Artifact metadata
  - Analysis methodology
  - Findings documentation
  - Technical interpretation
  - Forensic significance

- **`malware_report.md`** - Malware analysis documentation
  - Static analysis results
  - Behavioral analysis results
  - Indicators of compromise
  - Mitigation recommendations
  - Attribution data (when available)

- **`timeline_template.md`** - Event timeline construction
  - Chronological event mapping
  - Source correlation table
  - Confidence assessment
  - Time synchronization notes
  - Gap identification

### Evidence Handling

- **`chain_of_custody.md`** - Chain of custody documentation
  - Evidence transfer records
  - Custodian information
  - Access history
  - Integrity verification
  - Storage conditions

- **`evidence_inventory.md`** - Cataloging of evidence items
  - Physical evidence tracking
  - Digital evidence tracking
  - Evidence correlation matrix
  - Retention requirements
  - Disposition instructions

- **`evidence_log.md`** - Documentation of collected evidence
  - Evidence identifier schema
  - Acquisition metadata
  - Hash verification records
  - Storage location tracking
  - Access log

### Incident Documentation

- **`executive_summary.md`** - Management-level incident overview
  - Business impact assessment
  - Risk summary
  - Key findings
  - Strategic recommendations
  - Required actions

- **`incident_report.md`** - Comprehensive incident investigation report
  - Executive summary
  - Technical details section
  - Timeline of events
  - Evidence inventory
  - Findings and conclusions
  - Recommendations

- **`preliminary_report.md`** - Initial incident assessment
  - First responder observations
  - Initial scope determination
  - Preliminary timeline
  - Priority recommendations
  - Resource requirements

### Legal

- **`affidavit_template.md`** - Formal sworn statement template
  - Statement of qualifications
  - Scope of examination
  - Methodology description
  - Factual findings section
  - Conclusion statements
  - Certification section
  - Attachment references

- **`expert_witness.md`** - Expert witness documentation template
  - Forensic expert qualifications
  - Case background summary
  - Evidence examination methodology
  - Technical findings presentation
  - Opinion formulation framework
  - Supporting evidence references
  - Testimony preparation notes

- **`subpoena_response.md`** - Subpoena response documentation template
  - Request interpretation section
  - Evidence collection methodology
  - Chain of custody documentation
  - Data extraction procedures
  - Findings presentation
  - Compliance certification
  - Responsive materials inventory

## Directory Structure

```plaintext
admin/security/forensics/templates/
├── README.md                    # This documentation
├── analysis_docs/               # Analysis documentation templates
│   ├── README.md                # Analysis docs documentation
│   ├── artifact_analysis.md     # Artifact analysis template
│   ├── malware_report.md        # Malware analysis report template
│   └── timeline_template.md     # Event timeline template
├── evidence_handling/           # Evidence documentation templates
│   ├── README.md                # Evidence handling documentation
│   ├── chain_of_custody.md      # Chain of custody form
│   ├── evidence_inventory.md    # Evidence inventory template
│   └── evidence_log.md          # Evidence collection log template
├── incident_docs/               # Incident reporting templates
│   ├── README.md                # Incident docs documentation
│   ├── executive_summary.md     # Management briefing template
│   ├── incident_report.md       # Complete incident report template
│   ├── investigation_notes.md   # Ongoing investigation documentation
│   └── preliminary_report.md    # Initial assessment template
└── legal/                       # Legal and compliance templates
    ├── README.md                # Legal templates documentation
    ├── affidavit_template.md    # Affidavit template
    ├── expert_witness.md        # Expert witness documentation template
    ├── preservation_notice.md   # Evidence preservation notice template
    └── subpoena_response.md     # Subpoena response template
```

## Usage

Templates are designed to be used with the forensic toolkit as follows:

1. Copy the appropriate template to the case directory
2. Fill in required fields with case-specific information
3. Update content for each standard section
4. Add necessary attachments and references
5. Submit for peer review
6. Finalize and store according to evidence handling procedures

Some templates may be automatically populated by forensic tools:

```bash
# Generate an incident timeline using the standard template
./timeline_builder.py --incident-id 42 \
    --auth-logs /secure/evidence/incident-42/auth.log \
    --web-logs /secure/evidence/incident-42/nginx/ \
    --template ../templates/analysis_documents/timeline_template.md \
    --output /secure/evidence/incident-42/timeline.md
```

## Template Standards

All templates follow these standard formatting guidelines:

1. **Header Information**
   - Case/incident identifier
   - Document preparation date
   - Author information
   - Classification level
   - Document version

2. **Standard Sections**
   - Purpose and scope
   - Methodology
   - Findings
   - Conclusions
   - Recommendations

3. **Metadata Requirements**
   - Document control numbers
   - Review status and history
   - Distribution list
   - Related documents
   - Retention information

4. **Formatting**
   - Consistent heading hierarchy
   - Numbered sections for reference
   - Standard table formats
   - Evidence reference format
   - Citation format

## Customization Guidelines

When using these templates for specific incidents:

1. **Maintain Key Elements**
   - Do not remove standard sections
   - Keep consistent formatting
   - Preserve metadata fields
   - Retain document control elements

2. **Appropriate Customization**
   - Add incident-specific details
   - Include relevant screenshots and diagrams
   - Add additional sections when necessary
   - Tailor executive summary to audience

3. **Document Control**
   - Update version history for all changes
   - Record all contributors
   - Document review and approval status
   - Follow proper handling procedures for final documents

## Related Documentation

- Chain of Custody Requirements
- Digital Forensics Procedures
- Evidence Handling Guidelines
- Forensic Analysis Toolkit
- Incident Response Plan
- Legal and Compliance Considerations
