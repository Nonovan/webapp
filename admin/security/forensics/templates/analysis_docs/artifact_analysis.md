# Artifact Analysis Form

**Classification:** {{classification}}
**Case ID:** {{case_id}}
**Evidence ID:** {{evidence_id}}
**Artifact ID:** {{artifact_id}}
**Document ID:** ART-{{case_id}}-{{evidence_id}}-{{artifact_id}}
**Analyst:** {{analyst_name}}
**Date Created:** {{creation_date}}
**Last Updated:** {{last_updated}}

## Artifact Information

**Artifact Name:** {{artifact_name}}
**Type:** {{artifact_type}}
**Location:** {{artifact_location}}
**Source Evidence:** {{source_evidence_id}}
**Chain of Custody Reference:** COC-{{case_id}}-{{source_evidence_id}}
**Parent Artifact:** {{parent_artifact_id}} *(if applicable)*
**Acquisition Method:** {{acquisition_method}}
**Acquisition Date/Time:** {{acquisition_datetime}}

### Integrity Verification

| Hash Type | Hash Value | Verification Status | Verification Date |
|-----------|------------|---------------------|-------------------|
| SHA-256   | {{sha256_hash}} | {{verification_status}} | {{verification_date}} |
| SHA-1     | {{sha1_hash}} | {{verification_status}} | {{verification_date}} |
| MD5       | {{md5_hash}} | {{verification_status}} | {{verification_date}} |

## Artifact Metadata

**File Size:** {{file_size}}
**File Type:** {{file_type}}
**MIME Type:** {{mime_type}}
**Created Time:** {{created_time}}
**Modified Time:** {{modified_time}}
**Accessed Time:** {{accessed_time}}
**Owner/Permissions:** {{owner_permissions}}
**File System Attributes:** {{fs_attributes}}

## Analysis Methodology

### Tools Used

| Tool Name | Version | Purpose |
|-----------|---------|---------|
| {{tool_name}} | {{tool_version}} | {{tool_purpose}} |
| | | |
| | | |

### Analysis Procedures

{{analysis_procedures}}

## Artifact Analysis

### Summary of Findings

{{findings_summary}}

### Technical Details

{{technical_details}}

### Indicators of Interest

| Indicator | Type | Context | Significance |
|-----------|------|---------|-------------|
| {{indicator_value}} | {{indicator_type}} | {{indicator_context}} | {{indicator_significance}} |
| | | | |
| | | | |

### Related Artifacts

| Artifact ID | Relationship | Description |
|-------------|-------------|-------------|
| {{related_artifact_id}} | {{relationship_type}} | {{relationship_description}} |
| | | |
| | | |

## Forensic Significance

**Relevance to Investigation:** {{investigation_relevance}}

**Key Evidence Value:**
{{evidence_value}}

**Confidence Level:** {{confidence_level}} *(High/Medium/Low)*

**Interpretations and Analysis:**
{{interpretation}}

## Analysis Limitations

{{analysis_limitations}}

## Conclusions and Recommendations

{{conclusions}}

**Recommended Actions:**

1. {{recommended_action_1}}
2. {{recommended_action_2}}
3. {{recommended_action_3}}

## Supporting Documentation

| Document ID | Description | Location |
|-------------|-------------|----------|
| {{supporting_doc_id}} | {{supporting_doc_description}} | {{supporting_doc_location}} |
| | | |
| | | |

## Reviewer Information

**Reviewed By:** {{reviewer_name}}
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
