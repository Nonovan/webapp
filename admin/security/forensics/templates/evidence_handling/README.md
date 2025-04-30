# Evidence Handling Templates

This directory contains standardized templates for documenting the collection, preservation, and management of digital evidence during security incident investigations. These templates ensure proper chain of custody, evidence integrity, and compliance with legal and regulatory requirements.

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

The evidence handling templates provide structured formats for documenting the acquisition, storage, transfer, and disposition of digital evidence during security incident investigations. These templates ensure that all evidence is properly documented from collection through analysis and final disposition, maintaining a clear chain of custody that supports internal investigations and potential legal proceedings. They implement best practices in digital forensics while ensuring compliance with relevant legal standards for evidence admissibility.

## Key Templates

- **`chain_of_custody.md`**: Evidence transfer documentation template
  - Chronological custody record
  - Custodian identification and verification
  - Transfer purpose documentation
  - Evidence integrity verification
  - Access authorization records
  - Transfer conditions documentation
  - Tampering detection attestations

- **`evidence_inventory.md`**: Evidence cataloging template
  - Digital evidence cataloging
  - Evidence correlation framework
  - Evidence grouping structure
  - Metadata categorization
  - Physical evidence tracking
  - Reference system documentation
  - Retention requirement details

- **`evidence_log.md`**: Evidence collection documentation template
  - Acquisition circumstance documentation
  - Acquisition method details
  - Collection authority documentation
  - Collection environment details
  - Evidence identifier system
  - Hash verification records
  - System state documentation

- **`executive_summary.md`**: Evidence collection summary template
  - Collection scope overview
  - Key evidence items summary
  - Initial findings presentation
  - Collection challenges documentation
  - Next steps planning
  - Resource requirements documentation
  - Timeline and milestones tracking

- **`affidavit_template.md`**: Formal sworn statement for evidence
  - Professional qualifications documentation
  - Evidence handling methodology
  - Chain of custody attestation
  - Evidence preservation documentation
  - Legal certification elements
  - Notarization framework
  - Document control information

- **`preservation_notice.md`**: Legal preservation notice template
  - Legal obligation notification
  - Scope of preservation
  - Data types enumeration
  - Preservation methodology
  - Compliance requirements
  - Point of contact information
  - Legal consequences section

- **`subpoena_response.md`**: Legal subpoena response template
  - Request interpretation section
  - Evidence collection methodology
  - Chain of custody documentation
  - Data extraction procedures
  - Findings presentation
  - Compliance certification
  - Responsive materials inventory

- **`expert_witness.md`**: Expert witness documentation template
  - Forensic expert qualifications
  - Case background summary
  - Evidence examination methodology
  - Technical findings presentation
  - Opinion formulation framework
  - Supporting evidence references
  - Testimony preparation notes

## Directory Structure

```plaintext
admin/security/forensics/templates/evidence_handling/
├── README.md                # This documentation
├── affidavit_template.md    # Formal sworn statement template
├── chain_of_custody.md      # Evidence transfer documentation template
├── evidence_inventory.md    # Evidence cataloging template
├── evidence_log.md          # Evidence collection documentation template
├── executive_summary.md     # Evidence collection summary template
├── preservation_notice.md   # Legal preservation notice template
├── subpoena_response.md     # Subpoena response documentation
├── expert_witness.md        # Expert witness documentation template
```

## Usage

These templates are designed to be used by forensic analysts when documenting evidence handling:

```bash
# Copy a template to a case-specific directory
cp admin/security/forensics/templates/evidence_handling/evidence_log.md \
   /secure/evidence/incident-42/documentation/memory_evidence_log.md

# Generate evidence documentation with the evidence collection script
../collect_evidence.py \
   --hostname affected-server-01 \
   --memory \
   --output /secure/evidence/incident-42/ \
   --generate-docs \
   --evidence-log-template evidence_handling/evidence_log.md
```

For programmatic use in Python:

```python
from admin.security.forensics.utils import evidence_tracker
from admin.security.forensics.utils import report_builder

# Register new evidence and generate evidence log
evidence_id = evidence_tracker.register_evidence(
    file_path="/secure/evidence/incident-42/memory.dump",
    evidence_type="memory_dump",
    acquisition_method="live_acquisition",
    analyst="johndoe",
    case_id="incident-42"
)

# Generate evidence documentation
report_builder.generate_evidence_document(
    template_path='admin/security/forensics/templates/evidence_handling/evidence_log.md',
    output_path=f'/secure/evidence/incident-42/documentation/evidence_log_{evidence_id}.md',
    evidence_id=evidence_id,
    case_id="incident-42",
    analyst="John Doe",
    classification="Confidential"
)
```

## Template Variables

The templates use standardized variables that are replaced during document generation:

### Common Variables

- `{{analyst_name}}` - Name of forensic analyst
- `{{case_id}}` - Investigation case identifier
- `{{classification}}` - Document classification level
- `{{creation_date}}` - Document creation date
- `{{document_id}}` - Unique document identifier
- `{{incident_id}}` - Incident tracking identifier

### Chain of Custody Variables

- `{{access_authorization}}` - Access authorization details
- `{{custodian_contact}}` - Contact information for custodian
- `{{custodian_name}}` - Name of evidence custodian
- `{{evidence_id}}` - Unique evidence identifier
- `{{reason_for_transfer}}` - Purpose of evidence transfer
- `{{storage_conditions}}` - Evidence storage conditions
- `{{transfer_method}}` - Method used to transfer evidence
- `{{verification_method}}` - Method used to verify evidence integrity

### Evidence Inventory Variables

- `{{category}}` - Evidence category
- `{{description}}` - Evidence description
- `{{evidence_groups}}` - Logical groupings of evidence
- `{{evidence_location}}` - Storage location
- `{{integrity_hash}}` - Evidence integrity hash
- `{{parent_evidence}}` - Related parent evidence
- `{{retention_period}}` - Required retention timeframe
- `{{source_identifier}}` - Source system/device identifier

### Evidence Log Variables

- `{{acquisition_authority}}` - Authority for evidence collection
- `{{acquisition_date}}` - Date and time of acquisition
- `{{acquisition_hash}}` - Hash value at acquisition
- `{{acquisition_method}}` - Method used to collect evidence
- `{{acquisition_tool}}` - Tool used for acquisition
- `{{evidence_type}}` - Type of evidence collected
- `{{location}}` - Location where evidence was collected
- `{{system_state}}` - System state at collection time

### Analysis Documentation Variables

- `{{evidence_description}}` - Description of the evidence item
- `{{examination_environment}}` - Evidence examination environment
- `{{hash_algorithm}}` - Hash algorithm used for verification
- `{{original_hash}}` - Original acquisition hash value
- `{{verification_hash}}` - Verification hash value
- `{{chain_of_custody_ref}}` - Reference to chain of custody document
- `{{examination_methodology}}` - Methodology used for analysis
- `{{tool_name}}` - Analysis tool used
- `{{tool_version}}` - Version of analysis tool

## Customization Guidelines

When customizing these templates for specific cases:

1. **Maintain Legal Requirements**
   - Keep all legally required sections
   - Preserve chain of custody elements
   - Maintain integrity verification details
   - Keep all timestamp information
   - Preserve authentication elements

2. **Add Case-Specific Content**
   - Include specific evidence details
   - Document collection-specific methods
   - Add detailed system information
   - Include reference to relevant incident details
   - Document specific handling requirements

3. **Follow Documentation Standards**
   - Clearly document all actions chronologically
   - Use precise timestamps with timezone
   - Document all individuals involved
   - Be specific about methods and tools
   - Record all integrity verification steps

4. **Review for Completeness**
   - Ensure all required fields are completed
   - Verify all technical details are accurate
   - Check for gaps in chain of custody
   - Ensure proper signatures and authentications
   - Validate all cross-references to other evidence

## Best Practices & Security

- **Access Control**: Implement strict access controls for evidence documentation
- **Attribution**: Clearly identify all individuals who handle evidence
- **Authentication**: Require proper authentication for all evidence handling
- **Chronology**: Maintain strict chronological documentation of all evidence handling
- **Classification**: Properly classify evidence based on sensitivity
- **Completeness**: Document all aspects of evidence handling without gaps
- **Consistency**: Use consistent terminology throughout all documentation
- **Integrity Verification**: Always document hash values before and after transfers
- **Non-Repudiation**: Include mechanisms to prevent deniability of actions
- **Objectivity**: Maintain factual, unbiased documentation
- **Preservation**: Document all preservation methods used
- **Timestamping**: Use precise timestamps with timezone information
- **Tool Documentation**: Document all tools used for evidence handling
- **Verification**: Include multiple verification methods for critical evidence

## Common Features

All evidence handling templates include these common elements:

- **Case Reference**: Links to the parent case or incident
- **Classification Banner**: Security classification markings
- **Document Control Information**: Version tracking and change history
- **Evidence Identifier**: Unique identifier for each evidence item
- **Hash Values**: Cryptographic hash values for evidence verification
- **Integrity Protection**: Mechanisms to detect tampering with documentation
- **Metadata Section**: Standardized metadata about the evidence
- **Review Status**: Documentation of review and verification
- **Signature Blocks**: Electronic or physical signature fields
- **Timestamp Format**: Standardized timestamp format with timezone
- **Tool Information**: Version and configuration of evidence handling tools
- **Version Control**: Document version tracking

## Related Documentation

- Chain of Custody Procedures
- Digital Evidence Guidelines
- Digital Forensics Procedures
- Electronic Evidence Legal Requirements
- Evidence Collection Procedures
- Evidence Storage Standards
- Forensic Analysis Documentation
- Incident Response Procedures
- Legal Admissibility Guidelines
- NIST SP 800-86: Guide to Integrating Forensic Techniques
- Security Classification Guide
