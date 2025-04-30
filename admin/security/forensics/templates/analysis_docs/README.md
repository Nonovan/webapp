# Evidence Analysis Documentation Templates

This directory contains standardized templates for documenting forensic analysis of evidence collected during security incident investigations. These templates ensure consistent, thorough analysis documentation that maintains proper chain of custody and evidentiary standards.

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

The evidence analysis documentation templates provide structured formats for documenting the technical examination of collected evidence during security incident investigations. These templates standardize the approach to documenting forensic findings while maintaining proper evidence handling procedures and chain of custody. They help ensure that analysis is conducted and documented in a forensically sound manner that preserves evidence integrity and admissibility in legal proceedings.

## Key Templates

- **`evidence_examination.md`**: Initial evidence examination documentation
  - Preliminary assessment documentation
  - Evidence integrity verification
  - Examination environment setup
  - Chain of custody preservation
  - Non-destructive analysis steps
  - Initial findings documentation
  - Further analysis recommendations

- **`forensic_imaging_analysis.md`**: Forensic image examination template
  - Image verification procedures
  - File system analysis findings
  - Deleted content recovery documentation
  - Timestamp analysis and correlation
  - User activity reconstruction
  - Data carving results
  - Filesystem metadata examination

- **`data_extraction_report.md`**: Data extraction documentation template
  - Extraction methodology documentation
  - Data integrity preservation steps
  - Extracted data inventory
  - Filtering and search parameters
  - Processing methodology documentation
  - Chain of custody maintenance
  - Technical and legal limitations

- **`memory_analysis_report.md`**: Memory forensics documentation template
  - Process analysis findings
  - Network connection documentation
  - Memory artifact extraction
  - Malware indicators in memory
  - Timeline of memory events
  - String analysis findings
  - Registry artifacts in memory

- **`static_analysis_report.md`**: File analysis documentation template
  - File metadata documentation
  - Structural analysis findings
  - Signature analysis results
  - Entropy analysis visualization
  - Embedded resource documentation
  - YARA rule matches
  - Behavioral indicators identification

- **`timeline_template.md`**: Chronological event analysis template
  - Event correlation framework
  - Timeline visualization guidance
  - Source attribution mapping
  - Confidence level indicators
  - Gap analysis documentation
  - Timestamp normalization process
  - Supporting evidence linkage

- **`artifact_analysis.md`**: Individual artifact analysis template
  - Artifact categorization framework
  - Technical description standards
  - Forensic significance assessment
  - Related artifact correlation
  - Contextual interpretation guide
  - Attribution confidence metrics
  - Technical impact evaluation

- **`malware_report.md`**: Malware analysis documentation template
  - Static analysis methodology
  - Dynamic analysis procedures
  - Behavioral indicator mapping
  - Capability assessment framework
  - Persistence mechanism documentation
  - MITRE ATT&CK correlation
  - Indicator extraction guidance

## Directory Structure

```plaintext
admin/security/forensics/templates/analysis_docs/
├── README.md                     # This documentation
├── artifact_analysis.md          # Individual artifact analysis template
├── data_extraction_report.md     # Data extraction documentation template
├── evidence_examination.md       # Initial evidence examination template
├── forensic_imaging_analysis.md  # Forensic image analysis template
├── malware_report.md             # Malware analysis documentation template
├── memory_analysis_report.md     # Memory forensics documentation template
├── static_analysis_report.md     # File analysis documentation template
└── timeline_template.md          # Chronological event analysis template
```

## Usage

These templates are designed to be used by forensic analysts when documenting evidence analysis:

```bash
# Copy a template to a case-specific evidence directory
cp admin/security/forensics/templates/analysis_docs/evidence_examination.md \
   /secure/evidence/case-2024-042/evidence/E001/examination.md

# Generate an analysis report using data extraction results
../../../utils/report_builder.py \
   --extraction-results /secure/evidence/case-2024-042/evidence/E001/extraction_results.json \
   --template data_extraction_report.md \
   --output /secure/evidence/case-2024-042/evidence/E001/extraction_report.md \
   --case-id "case-2024-042" \
   --evidence-id "E001" \
   --analyst "Jane Smith"

# Generate a static analysis report for a suspicious file
../../../utils/report_builder.py \
   --static-analysis /secure/evidence/case-2024-042/analysis/file_analyzer_results.json \
   --template static_analysis_report.md \
   --output /secure/evidence/case-2024-042/reports/static_analysis.md \
   --case-id "case-2024-042" \
   --evidence-id "E001" \
   --analyst "John Doe"
```

## Template Variables

The templates use standardized variables that are replaced during document generation:

### Common Variables

- `{{analyst_name}}` - Name of forensic analyst
- `{{case_id}}` - Investigation case identifier
- `{{classification}}` - Document classification level
- `{{creation_date}}` - Document creation date
- `{{document_id}}` - Unique document identifier
- `{{evidence_id}}` - Related evidence identifier
- `{{acquisition_date}}` - Date evidence was acquired
- `{{examination_date}}` - Date evidence was examined
- `{{reviewer_name}}` - Name of reviewing analyst
- `{{review_date}}` - Date of peer review

### Evidence Examination Variables

- `{{evidence_description}}` - Description of the evidence item
- `{{evidence_type}}` - Type of evidence being examined
- `{{hash_algorithm}}` - Hash algorithm used for verification
- `{{original_hash}}` - Original acquisition hash value
- `{{verification_hash}}` - Verification hash value
- `{{chain_of_custody_ref}}` - Reference to chain of custody document
- `{{examination_environment}}` - Evidence examination environment
- `{{write_protection_method}}` - Write protection method used

### Forensic Image Variables

- `{{image_format}}` - Format of forensic image
- `{{imaging_tool}}` - Tool used to create the image
- `{{partition_table}}` - Partition table information
- `{{filesystem_types}}` - Types of filesystems identified
- `{{total_sectors}}` - Total sectors in the image
- `{{sector_size}}` - Sector size in bytes
- `{{compression_used}}` - Compression method if any
- `{{acquisition_method}}` - Method used to acquire the image

### Data Extraction Variables

- `{{extraction_tool}}` - Tool used for data extraction
- `{{extraction_parameters}}` - Parameters used for extraction
- `{{data_types_extracted}}` - Types of data extracted
- `{{total_items_extracted}}` - Number of items extracted
- `{{extraction_filters}}` - Filters applied during extraction
- `{{legal_authority}}` - Legal authority for extraction
- `{{scope_limitations}}` - Scope limitations for extraction

### Static Analysis Variables

- `{{file_name}}` - Name of analyzed file
- `{{file_size}}` - Size of analyzed file
- `{{file_type}}` - Identified file type
- `{{file_hash_md5}}` - MD5 hash of the file
- `{{file_hash_sha1}}` - SHA1 hash of the file
- `{{file_hash_sha256}}` - SHA256 hash of the file
- `{{analysis_tools}}` - Tools used for static analysis
- `{{yara_rules_used}}` - YARA rules applied in analysis

### Memory Analysis Variables

- `{{memory_acquisition_tool}}` - Tool used to acquire memory
- `{{memory_image_size}}` - Size of memory image
- `{{system_profile}}` - System profile used for analysis
- `{{os_version}}` - Operating system version identified
- `{{kernel_version}}` - Kernel version identified
- `{{memory_analysis_tools}}` - Tools used for memory analysis
- `{{plugin_list}}` - List of plugins/modules used

### Malware Analysis Variables

- `{{malware_name}}` - Identified malware name if known
- `{{malware_family}}` - Malware family classification
- `{{malware_type}}` - Type of malicious code
- `{{malware_capabilities}}` - Identified capabilities
- `{{c2_servers}}` - Command and control server information
- `{{persistence_mechanism}}` - Persistence mechanisms used
- `{{sandbox_environment}}` - Analysis environment details
- `{{evasion_techniques}}` - Identified evasion techniques

### Timeline Analysis Variables

- `{{event_source}}` - Source of timeline event data
- `{{time_window_start}}` - Start of timeline analysis period
- `{{time_window_end}}` - End of timeline analysis period
- `{{timezone}}` - Timezone used for analysis
- `{{normalization_method}}` - Timestamp normalization method
- `{{correlation_method}}` - Event correlation methodology
- `{{significant_events}}` - Key events in timeline
- `{{confidence_metric}}` - Confidence in timeline accuracy

## Customization Guidelines

When customizing these templates for specific evidence analysis:

1. **Maintain Evidentiary Standards**
   - Document all steps to maintain evidence integrity
   - Verify and document hash values at each stage
   - Record all tools and commands used
   - Document chain of custody throughout analysis
   - Note any potential alterations to the evidence

2. **Add Analysis-Specific Details**
   - Document specific methodologies employed
   - Include tool configurations and versions
   - Document significant findings with references
   - Include screenshots of significant findings
   - Maintain chronological documentation of analysis steps

3. **Follow Legal and Procedural Requirements**
   - Document compliance with legal requirements
   - Note scope limitations and authorizations
   - Document presence of potentially privileged material
   - Record any exclusions from analysis
   - Note any deviations from standard procedures

4. **Ensure Proper Verification**
   - Document verification of findings by second analyst
   - Include reviewer information and comments
   - Document any disputed interpretations
   - Note confidence levels for findings
   - Document limitations of analysis techniques

5. **Standardize Technical Documentation**
   - Use consistent naming conventions for artifacts
   - Document command line arguments precisely
   - Include version information for all tools
   - Create tables for structured findings
   - Cross-reference related evidence items

## Best Practices & Security

- **Chain of Custody**: Maintain and document chain of custody throughout analysis
- **Hash Verification**: Verify evidence integrity using cryptographic hashes
- **Write Protection**: Document write protection methods used during analysis
- **Sterile Environment**: Use and document forensically sound examination environments
- **Tool Documentation**: Document all tools, versions, and commands used
- **Time Synchronization**: Ensure and document time synchronization in examination environment
- **Reproducibility**: Document analysis steps to allow independent verification
- **Comprehensive Documentation**: Document both positive and negative findings
- **Access Control**: Document who had access to evidence during analysis
- **Evidence Storage**: Document proper evidence storage during analysis periods
- **Technical Limitations**: Acknowledge and document technical limitations of tools and methods
- **Legal Constraints**: Document compliance with legal and jurisdictional requirements
- **Malware Safety**: Document precautions taken when analyzing malicious code
- **Cross-Validation**: Verify significant findings with multiple tools when possible

## Common Features

All evidence analysis templates share these common elements:

- **Evidence Identification**: Clear identification of evidence being analyzed
- **Chain of Custody Reference**: Links to chain of custody documentation
- **Examination Environment**: Documentation of forensic environment used
- **Integrity Verification**: Hash verification of evidence at multiple stages
- **Chronological Structure**: Time-ordered documentation of analysis steps
- **Tool Documentation**: Documentation of tools and versions used
- **Analyst Information**: Who performed each analysis step
- **Evidence Storage**: How evidence was stored during analysis
- **Analysis Limitations**: Acknowledged limitations of analysis
- **Findings Section**: Structured presentation of analysis findings
- **Peer Review Documentation**: Information on independent review
- **Document Control**: Version tracking and management
- **Classification Headers**: Security classification markings
- **Reference Links**: Links to relevant standards and procedures

## Related Documentation

- Chain of Custody Documentation
- Evidence Collection Procedures
- Evidence Inventory Documentation
- Forensic Imaging Procedures
- Evidence Storage Guidelines
- Tool Validation Documentation
- Legal and Compliance Requirements
- Expert Witness Guidelines
- Evidence Handling Manual
- Digital Forensics Standard Operating Procedures
- NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response
- File Signature Analysis Procedures
- Memory Forensics Methodology Guide
