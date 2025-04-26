# Analysis Documentation Templates

This directory contains standardized templates for forensic analysis documentation used during security incident investigations in the Cloud Infrastructure Platform. These templates ensure thorough, consistent documentation of forensic analysis findings with proper evidentiary formatting.

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

The analysis documentation templates provide structured formats for documenting the technical analysis of artifacts, malware, and events during security incident investigations. These templates standardize the approach to documenting forensic findings, ensuring comprehensive coverage of analysis methodologies, findings, and interpretations. They help maintain proper documentation standards that support incident response efforts while ensuring findings are properly documented for potential legal proceedings.

## Key Templates

- **`artifact_analysis.md`**: Detailed artifact examination template
  - Artifact metadata documentation
  - Analysis methodology section
  - Findings documentation framework
  - Technical interpretation structure
  - Forensic significance evaluation
  - Chain of custody references
  - Tool and technique documentation

- **`malware_report.md`**: Malware analysis documentation template
  - Sample metadata section
  - Static analysis findings format
  - Behavioral analysis observations structure
  - Indicators of compromise (IOC) formatting
  - Mitigation recommendations framework
  - Attribution data documentation
  - MITRE ATT&CK framework mapping

- **`timeline_template.md`**: Event timeline construction template
  - Chronological event mapping structure
  - Source correlation table format
  - Event confidence rating system
  - Time synchronization documentation
  - Gap identification framework
  - Critical event highlighting
  - Timeline visualization guidance

## Directory Structure

```plaintext
admin/security/forensics/templates/analysis_docs/
├── README.md             # This documentation
├── artifact_analysis.md  # Artifact analysis template
├── malware_report.md     # Malware analysis report template
└── timeline_template.md  # Event timeline template
```

## Usage

These templates are designed to be used by forensic analysts when documenting their findings:

```bash
# Copy a template to a case-specific directory
cp admin/security/forensics/templates/analysis_docs/artifact_analysis.md \
   /secure/evidence/incident-42/analysis/usb_device_analysis.md

# Generate a timeline using the template with the timeline builder tool
../../../timeline_builder.py \
   --log-files /secure/evidence/incident-42/logs/* \
   --output /secure/evidence/incident-42/analysis/incident_timeline.md \
   --template timeline_template.md
```

For automated report generation:

```bash
# Generate a malware analysis report from analysis results
../../../static_analysis/report_generator.py \
   --analysis-results /secure/evidence/incident-42/analysis/malware_analysis.json \
   --template malware_report.md \
   --output /secure/evidence/incident-42/reports/malware_analysis_report.md \
   --case-id "incident-42" \
   --analyst "Jane Smith"
```

## Template Variables

The templates use standardized variables that are replaced during document generation:

### Common Variables

- `{{analyst_name}}` - Name of forensic analyst
- `{{analysis_date}}` - Date analysis was performed
- `{{case_id}}` - Investigation case identifier
- `{{classification}}` - Document classification level
- `{{creation_date}}` - Document creation date
- `{{document_id}}` - Unique document identifier
- `{{evidence_id}}` - Related evidence identifier
- `{{tools_used}}` - Analysis tools and versions

### Artifact Analysis Variables

- `{{acquisition_method}}` - How the artifact was acquired
- `{{artifact_description}}` - Description of the analyzed artifact
- `{{artifact_hash}}` - Cryptographic hash of the artifact
- `{{artifact_location}}` - Where artifact was discovered
- `{{artifact_type}}` - Type of artifact being analyzed
- `{{chain_of_custody_ref}}` - Reference to chain of custody document

### Malware Analysis Variables

- `{{av_detection_rate}}` - Anti-virus detection statistics
- `{{behavioral_indicators}}` - Observed behavioral characteristics
- `{{file_metadata}}` - File information and metadata
- `{{malware_classification}}` - Malware type/family classification
- `{{mitre_techniques}}` - MITRE ATT&CK techniques observed
- `{{network_indicators}}` - Network-based IOCs
- `{{static_indicators}}` - Static analysis indicators

### Timeline Variables

- `{{confidence_levels}}` - Description of confidence rating system
- `{{time_period_end}}` - End of timeline period
- `{{time_period_start}}` - Start of timeline period
- `{{time_source}}` - Authoritative time source
- `{{time_zone}}` - Time zone used for timestamps
- `{{timeline_sources}}` - Data sources used in timeline creation

## Customization Guidelines

When customizing these templates for specific analyses:

1. **Maintain Core Sections**
   - Keep all required section headers
   - Preserve metadata fields
   - Maintain proper section ordering
   - Keep chain of custody references

2. **Add Analysis-Specific Details**
   - Include all relevant technical details
   - Document specific methodologies used
   - Reference specific tools and versions
   - Include relevant screenshots or diagrams
   - Document unusual findings thoroughly

3. **Follow Evidence Standards**
   - Clearly separate facts from interpretation
   - Document confidence levels for findings
   - Reference supporting evidence
   - Document any limitations or constraints
   - Include negative findings when relevant

4. **Ensure Proper Review**
   - Document peer review status
   - Include reviewer information
   - Address review feedback in revisions
   - Note any disputed interpretations

## Best Practices & Security

- **Attribution Clarity**: Clearly indicate which analyst performed each analysis step
- **Classification**: Apply proper classification markings to all documents
- **Conciseness**: Be concise but complete in technical details
- **Consistency**: Use consistent terminology throughout documentation
- **Evidence References**: Include specific references to evidence artifacts
- **Factual Basis**: Clearly distinguish facts from interpretation
- **Methodology Documentation**: Document analysis methodology in detail
- **Objectivity**: Maintain objective, fact-based analysis
- **Reproducibility**: Ensure another analyst could reproduce findings
- **Source Documentation**: Document all sources of information
- **Time Accuracy**: Use consistent time formats and include time zones
- **Tool Documentation**: Document all tools and versions used in analysis

## Common Features

All analysis templates share these common elements:

- **Analyst Information**: Who performed the analysis
- **Case Reference**: References to the incident or case
- **Classification Banner**: Document security classification
- **Chronological Structure**: Time-ordered documentation
- **Document Control**: Version tracking and management
- **Evidence References**: Links to supporting evidence
- **Methodology Section**: Description of analysis approach
- **Peer Review Section**: Documentation of review process
- **Revision History**: Tracking of document changes
- **Source Attribution**: Clear sourcing of information
- **Template Version**: Template version tracking
- **Tool Documentation**: Analysis tools and versions used

## Related Documentation

- Chain of Custody Documentation
- Digital Forensics Procedures
- Evidence Collection Documentation
- Evidence Handling Guidelines
- Forensic Analysis Toolkit Documentation
- Incident Response Procedures
- Malware Analysis Methodology
- Static Analysis Tools Guide
- Technical Writing Guidelines
- Timeline Analysis Methodology
