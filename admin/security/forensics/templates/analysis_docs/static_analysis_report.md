# Static Analysis Report

**Classification:** {{classification}}
**Case ID:** {{case_id}}
**Evidence ID:** {{evidence_id}}
**Artifact ID:** {{artifact_id}}
**Document ID:** STAT-{{case_id}}-{{evidence_id}}-{{artifact_id}}
**Analyst:** {{analyst_name}}
**Date Created:** {{creation_date}}
**Last Updated:** {{last_updated}}

## Artifact Information

**Artifact Description:** {{artifact_description}}
**Artifact Type:** {{artifact_type}}
**Chain of Custody Reference:** COC-{{case_id}}-{{evidence_id}}
**Original Hash (SHA-256):** {{original_hash}}
**Acquisition Date:** {{acquisition_date}}
**Acquisition Method:** {{acquisition_method}}

## Analysis Environment

**Workstation ID:** {{workstation_id}}
**Operating System:** {{operating_system}}
**Analysis Tools:** {{analysis_tools}}
**Working Directory:** {{working_directory}}
**Time Synchronization:** {{time_sync_method}}
**Write Protection Mechanism:** {{write_protection}}

## Analysis Methodology

### Tools Used

| Tool Name | Version | Purpose | Validation Status |
|-----------|---------|---------|------------------|
| {{tool_name}} | {{tool_version}} | {{tool_purpose}} | {{validation_status}} |
| | | | |
| | | | |

### Analysis Procedures

{{analysis_procedures}}

## File Properties

### Basic Properties

**Filename:** {{original_filename}}
**File Size:** {{file_size}}
**File Type:** {{file_type}}
**MIME Type:** {{mime_type}}
**MD5:** {{md5_hash}}
**SHA-1:** {{sha1_hash}}
**SHA-256:** {{sha256_hash}}
**SSDeep:** {{ssdeep_hash}}
**Entropy:** {{entropy_value}}

### File Metadata

**Created Time:** {{created_time}}
**Modified Time:** {{modified_time}}
**Accessed Time:** {{accessed_time}}
**Owner/Permissions:** {{owner_permissions}}
**File System Attributes:** {{fs_attributes}}
**Digital Signature:** {{digital_signature_status}}

### File Structure Analysis

{{file_structure_analysis}}

## Content Analysis

### Strings of Interest

| String | Location | Context | Significance |
|--------|----------|---------|-------------|
| {{string_value}} | {{string_location}} | {{string_context}} | {{string_significance}} |
| | | | |
| | | | |

### Extracted URLS and Network Indicators

| Indicator Type | Value | Location | Context |
|---------------|-------|----------|---------|
| {{indicator_type}} | {{indicator_value}} | {{indicator_location}} | {{indicator_context}} |
| | | | |
| | | | |

### File Format Specific Analysis

#### Executable Analysis (if applicable)

**Architecture:** {{architecture}}
**Compiler/Packer:** {{compiler_packer}}
**Entry Point:** {{entry_point}}
**Sections:** {{sections_summary}}
**Import Tables:** {{import_summary}}
**Export Tables:** {{export_summary}}
**Resources:** {{resources_summary}}

**Executable Sections:**

| Section | Virtual Address | Virtual Size | Raw Size | Entropy | Characteristics |
|---------|----------------|-------------|----------|---------|----------------|
| {{section_name}} | {{virtual_address}} | {{virtual_size}} | {{raw_size}} | {{section_entropy}} | {{characteristics}} |
| | | | | | |
| | | | | | |

#### Document Analysis (if applicable)

**Document Type:** {{document_type}}
**Author:** {{document_author}}
**Creation Tool:** {{creation_tool}}
**Page Count:** {{page_count}}
**Embedded Objects:** {{embedded_objects_count}}
**Macros Present:** {{macros_present}}
**Custom XML Parts:** {{custom_xml_parts}}

**Embedded Objects:**

| Object Type | Size | SHA-256 | Description |
|------------|------|---------|-------------|
| {{object_type}} | {{object_size}} | {{object_hash}} | {{object_description}} |
| | | | |
| | | | |

#### Script Analysis (if applicable)

**Script Type:** {{script_type}}
**Script Size:** {{script_size}}
**Obfuscation Detected:** {{obfuscation_detected}}
**Obfuscation Methods:** {{obfuscation_methods}}
**Functions/Methods Count:** {{function_count}}
**Suspicious APIs:** {{suspicious_apis}}

**Code Structure Summary:**

{{code_structure_summary}}

## Signature-Based Analysis

### YARA Rule Matches

| Rule Name | Description | Match Location | Severity | Author |
|-----------|------------|---------------|----------|--------|
| {{yara_rule}} | {{yara_description}} | {{match_location}} | {{rule_severity}} | {{rule_author}} |
| | | | | |
| | | | | |

**Matched YARA Strings:**

| Rule | String Identifier | Location | Matched Content (Sample) |
|------|------------------|----------|-------------------------|
| {{rule_name}} | {{string_id}} | {{string_location}} | {{matched_content}} |
| | | | |
| | | | |

### Known Malware Signature Matches

| Signature Name | Signature Type | Match Location | Confidence | Reference |
|---------------|---------------|---------------|------------|-----------|
| {{signature_name}} | {{signature_type}} | {{match_location}} | {{confidence}} | {{reference}} |
| | | | | |
| | | | | |

### Digital Signature Verification (if applicable)

**Signature Status:** {{signature_status}}
**Signing Time:** {{signing_time}}
**Signer:** {{signer_name}}
**Certificate Issuer:** {{certificate_issuer}}
**Certificate Valid From:** {{certificate_valid_from}}
**Certificate Valid To:** {{certificate_valid_to}}
**Certificate Serial:** {{certificate_serial}}
**Verification Errors:** {{verification_errors}}

## Behavioral Indicators

### Potential Capabilities

| Capability | Evidence | Confidence |
|------------|----------|------------|
| {{capability}} | {{capability_evidence}} | {{confidence}} |
| | | |
| | | |

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|--------|------------|----------------|---------|
| {{mitre_tactic}} | {{mitre_technique_id}} | {{mitre_technique_name}} | {{technique_evidence}} |
| | | | |
| | | | |

## Indicators of Compromise (IOCs)

| IOC Type | Indicator Value | Context |
|----------|----------------|---------|
| {{ioc_type}} | {{ioc_value}} | {{ioc_context}} |
| | | |
| | | |

## Analysis Summary

{{analysis_summary}}

### Key Findings

- {{key_finding_1}}
- {{key_finding_2}}
- {{key_finding_3}}

### Technical Assessment

**Malicious Rating:** {{malicious_rating}} *(Confirmed/Suspected/Unknown)*
**Malware Classification:** {{malware_classification}}
**Risk Level:** {{risk_level}} *(Critical/High/Medium/Low)*

### Similar Files

| Relationship | File Hash | Similarity Score | Notes |
|-------------|-----------|------------------|-------|
| {{relationship_type}} | {{related_file_hash}} | {{similarity_score}} | {{similarity_notes}} |
| | | | |
| | | | |

## Technical Challenges and Limitations

| Challenge/Limitation | Impact on Analysis | Mitigation Strategy |
|---------------------|---------------------|---------------------|
| {{challenge}} | {{impact}} | {{mitigation}} |
| | | |
| | | |

## Recommendations for Further Analysis

1. {{recommendation_1}}
2. {{recommendation_2}}
3. {{recommendation_3}}

## Evidence Storage

**Working Copy Location:** {{working_copy_location}}
**Access Control Measures:** {{access_control}}
**Analysis Data Storage:** {{analysis_data_location}}

## Chain of Custody Maintenance

All access to evidence during analysis is documented in the chain of custody record referenced above. The following additional access events occurred during analysis:

| Date/Time (UTC) | Person | Action | Purpose |
|-----------------|--------|--------|---------|
| {{access_datetime}} | {{person}} | {{action}} | {{purpose}} |
| | | | |
| | | | |

## Supporting Documentation

| Document ID | Description | Location |
|-------------|------------|----------|
| {{supporting_doc_id}} | {{supporting_doc_description}} | {{supporting_doc_location}} |
| | | |
| | | |

## Reviewer Information

**Analysis Verified By:** {{verifier_name}}
**Verification Date:** {{verification_date}}
**Verification Method:** {{verification_method}}
**Technical Reviewer:** {{technical_reviewer}}
**Review Date:** {{review_date}}
**Review Comments:** {{review_comments}}

## Document History

| Version | Date | Modified By | Description of Changes |
|---------|------|------------|------------------------|
| 1.0 | {{creation_date}} | {{analyst_name}} | Initial document creation |
| {{version}} | {{modification_date}} | {{modifier_name}} | {{modification_description}} |

---

**Document Owner:** {{document_owner}}
**Review Frequency:** As needed during active investigation, minimum weekly review

This document must be stored in accordance with evidence handling procedures and access restricted to authorized personnel only. All changes must be documented in the Document History section.

## Reference

NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response
