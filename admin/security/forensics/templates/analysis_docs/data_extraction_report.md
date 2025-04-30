# Data Extraction Report

**Classification:** {{classification}}
**Case ID:** {{case_id}}
**Evidence ID:** {{evidence_id}}
**Extraction ID:** {{extraction_id}}
**Document ID:** EXT-{{case_id}}-{{evidence_id}}-{{extraction_id}}
**Analyst:** {{analyst_name}}
**Date Created:** {{creation_date}}
**Last Updated:** {{last_updated}}

## Source Evidence Information

**Evidence Description:** {{evidence_description}}
**Evidence Type:** {{evidence_type}}
**Chain of Custody Reference:** COC-{{case_id}}-{{evidence_id}}
**Original Hash (SHA-256):** {{original_hash}}

### Source Evidence Verification

| Hash Type | Expected Value | Computed Value | Verification Status | Verification Date/Time |
|-----------|---------------|---------------|---------------------|------------------------|
| SHA-256   | {{original_hash}} | {{verification_hash}} | {{verification_status}} | {{verification_datetime}} |

## Extraction Environment

**Workstation ID:** {{workstation_id}}
**Operating System:** {{operating_system}}
**Extraction Tool:** {{extraction_tool}}
**Tool Version:** {{tool_version}}
**Write Blocker Used:** {{write_blocker}}

## Extraction Methodology

### Extraction Parameters

**Extraction Type:** {{extraction_type}}
**Data Types Extracted:** {{data_types_extracted}}
**Extraction Filters Applied:** {{extraction_filters}}
**Date Range Filter:** {{date_range_filter}}
**Keyword Filters:** {{keyword_filters}}
**File Type Filters:** {{file_type_filters}}
**Legal Authority:** {{legal_authority}}
**Scope Limitations:** {{scope_limitations}}

### Extraction Process

{{extraction_process_description}}

**Commands/Scripts Used:**

```plaintext
{{extraction_commands}}
```

## Extraction Results

### Summary Statistics

| Data Category | Item Count | Total Size |
|---------------|------------|------------|
| Documents     | {{document_count}} | {{document_size}} |
| Emails        | {{email_count}} | {{email_size}} |
| Images        | {{image_count}} | {{image_size}} |
| Videos        | {{video_count}} | {{video_size}} |
| Databases     | {{database_count}} | {{database_size}} |
| User Files    | {{user_file_count}} | {{user_file_size}} |
| System Files  | {{system_file_count}} | {{system_file_size}} |
| Other         | {{other_count}} | {{other_size}} |
| **TOTAL**     | {{total_count}} | {{total_size}} |

### Extracted Items of Interest

| Item ID | Path/Location | File Type | Size | Hash (SHA-256) | Relevance | Notes |
|---------|--------------|-----------|------|----------------|-----------|-------|
| {{item_id}} | {{item_path}} | {{item_type}} | {{item_size}} | {{item_hash}} | {{item_relevance}} | {{item_notes}} |
| | | | | | | |
| | | | | | | |

## Processing and Analysis

### Processing Methodology

{{processing_methodology}}

### Analysis Results

{{analysis_results}}

### Indicators of Interest

| Indicator | Type | Context | Significance |
|-----------|------|---------|-------------|
| {{indicator_value}} | {{indicator_type}} | {{indicator_context}} | {{indicator_significance}} |
| | | | |
| | | | |

## Technical Limitations

{{technical_limitations}}

## Privacy and Confidentiality Considerations

{{privacy_considerations}}

## Extraction Outputs

| Output ID | Description | Location | Format | Size | Hash (SHA-256) |
|-----------|------------|----------|--------|------|----------------|
| {{output_id}} | {{output_description}} | {{output_location}} | {{output_format}} | {{output_size}} | {{output_hash}} |
| | | | | | |
| | | | | | |

## Recommendations for Further Analysis

1. {{recommendation_1}}
2. {{recommendation_2}}
3. {{recommendation_3}}

## Supporting Documentation

| Document ID | Description | Location |
|-------------|------------|----------|
| {{supporting_doc_id}} | {{supporting_doc_description}} | {{supporting_doc_location}} |
| | | |
| | | |

## Chain of Custody Maintenance

**Extraction Data Storage Location:** {{data_storage_location}}
**Access Control Measures:** {{access_control}}
**Data Export Information:** {{data_export_info}}

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
