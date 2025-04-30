# Forensic Image Analysis Report

**Classification:** {{classification}}
**Case ID:** {{case_id}}
**Evidence ID:** {{evidence_id}}
**Image ID:** {{image_id}}
**Document ID:** IMG-{{case_id}}-{{evidence_id}}-{{image_id}}
**Analyst:** {{analyst_name}}
**Date Created:** {{creation_date}}
**Last Updated:** {{last_updated}}

## Source Evidence Information

**Evidence Description:** {{evidence_description}}
**Evidence Type:** {{evidence_type}}
**Chain of Custody Reference:** COC-{{case_id}}-{{evidence_id}}
**Original Hash (SHA-256):** {{original_hash}}
**Acquisition Date:** {{acquisition_date}}
**Acquisition Method:** {{acquisition_method}}

## Forensic Image Properties

**Image Format:** {{image_format}}
**Image Size:** {{image_size}}
**Imaging Tool:** {{imaging_tool}}
**Tool Version:** {{tool_version}}
**Compression Used:** {{compression_used}}
**Encrypted:** {{is_encrypted}}
**Segmented:** {{is_segmented}}
**Segment Count:** {{segment_count}}
**Write Blocked:** {{write_blocked}}

### Forensic Image Integrity Verification

| Hash Type | Expected Value | Computed Value | Verification Status | Verification Date/Time |
|-----------|---------------|---------------|---------------------|------------------------|
| SHA-256   | {{expected_hash}} | {{verification_hash}} | {{verification_status}} | {{verification_datetime}} |
| MD5       | {{expected_md5}} | {{verification_md5}} | {{verification_md5_status}} | {{verification_datetime}} |

## Analysis Environment

**Workstation ID:** {{workstation_id}}
**Operating System:** {{operating_system}}
**Analysis Tools:** {{analysis_tools}}
**Working Directory:** {{working_directory}}
**Time Synchronization:** {{time_sync_method}}
**Evidence Mounting Method:** {{mounting_method}}
**Write Protection Mechanism:** {{write_protection}}

## Disk Image Structure Analysis

### Storage Device Information

**Device Type:** {{device_type}}
**Total Sectors:** {{total_sectors}}
**Sector Size:** {{sector_size}}
**Total Size:** {{total_size}}
**Device Model:** {{device_model}}
**Serial Number:** {{serial_number}}
**Hardware/BIOS Timestamps:** {{hardware_timestamps}}

### Partition Information

| Partition ID | Type | File System | Start Sector | End Sector | Size | Status |
|--------------|------|------------|-------------|-----------|------|--------|
| {{partition_id}} | {{partition_type}} | {{file_system}} | {{start_sector}} | {{end_sector}} | {{partition_size}} | {{partition_status}} |
| | | | | | | |
| | | | | | | |

### Volume Information

| Volume ID | Label | Mount Point | File System | Size | Created | Modified | Accessed |
|-----------|-------|------------|------------|------|---------|----------|----------|
| {{volume_id}} | {{volume_label}} | {{mount_point}} | {{volume_fs}} | {{volume_size}} | {{volume_created}} | {{volume_modified}} | {{volume_accessed}} |
| | | | | | | | |
| | | | | | | | |

### Unallocated Space Analysis

**Total Unallocated Space:** {{unallocated_size}}
**Unallocated Regions:** {{unallocated_regions}}
**Carving Results:** {{carving_results}}

## File System Analysis

### File System Metadata

| Volume | File Count | Directory Count | Deleted File Count | Creation Range | Modification Range |
|--------|------------|----------------|-------------------|----------------|-------------------|
| {{fs_volume}} | {{file_count}} | {{directory_count}} | {{deleted_count}} | {{creation_range}} | {{modification_range}} |
| | | | | | |
| | | | | | |

### Filesystem Timeline Analysis

{{filesystem_timeline_analysis}}

### Key User Profiles/Directories

| User/Directory | Path | Size | Created | Modified | Contents Summary |
|---------------|------|------|---------|----------|-----------------|
| {{user_directory}} | {{directory_path}} | {{directory_size}} | {{directory_created}} | {{directory_modified}} | {{directory_contents}} |
| | | | | | |
| | | | | | |

### Deleted File Recovery

| Recovery Method | Files Recovered | Success Rate | Notes |
|-----------------|----------------|--------------|-------|
| {{recovery_method}} | {{recovered_count}} | {{success_rate}} | {{recovery_notes}} |
| | | | |
| | | | |

## Content Analysis

### File Classification Summary

| File Category | Count | Total Size | Notes |
|--------------|-------|------------|-------|
| Documents | {{document_count}} | {{document_size}} | {{document_notes}} |
| Images | {{image_count}} | {{image_size}} | {{image_notes}} |
| Videos | {{video_count}} | {{video_size}} | {{video_notes}} |
| Executables | {{exe_count}} | {{exe_size}} | {{exe_notes}} |
| Archives | {{archive_count}} | {{archive_size}} | {{archive_notes}} |
| System Files | {{system_count}} | {{system_size}} | {{system_notes}} |
| Other | {{other_count}} | {{other_size}} | {{other_notes}} |

### Registry Analysis (Windows Only)

{{registry_analysis}}

### User Activity Timeline

{{user_activity_timeline}}

### Internet Artifacts

| Artifact Type | Source | Count | Date Range | Significance |
|--------------|--------|-------|------------|-------------|
| {{artifact_type}} | {{artifact_source}} | {{artifact_count}} | {{artifact_date_range}} | {{artifact_significance}} |
| | | | | |
| | | | | |

### Operating System Artifacts

{{operating_system_artifacts}}

### Application Artifacts

{{application_artifacts}}

## Items of Interest

### Summary of Findings

{{findings_summary}}

### Significant Files/Directories

| Item Path | Type | Size | Created | Modified | Accessed | Hash (SHA-256) | Significance |
|-----------|------|------|---------|----------|---------|----------------|-------------|
| {{item_path}} | {{item_type}} | {{item_size}} | {{item_created}} | {{item_modified}} | {{item_accessed}} | {{item_hash}} | {{item_significance}} |
| | | | | | | | |
| | | | | | | | |

### Hidden Content Analysis

| Detection Method | Location | Content Type | Description | Significance |
|-----------------|----------|--------------|-------------|-------------|
| {{detection_method}} | {{hidden_location}} | {{hidden_type}} | {{hidden_description}} | {{hidden_significance}} |
| | | | | |
| | | | | |

### Suspicious Artifacts

{{suspicious_artifacts}}

## Technical Challenges and Limitations

| Challenge/Limitation | Impact on Analysis | Mitigation Strategy |
|---------------------|---------------------|---------------------|
| {{challenge}} | {{impact}} | {{mitigation}} |
| | | |
| | | |

## Image Storage and Handling

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

## Recommendations for Further Analysis

1. {{recommendation_1}}
2. {{recommendation_2}}
3. {{recommendation_3}}

## Verification and Technical Review

**Analysis Verified By:** {{verifier_name}}
**Verification Date:** {{verification_date}}
**Verification Method:** {{verification_method}}
**Technical Reviewer:** {{technical_reviewer}}
**Review Date:** {{review_date}}
**Review Comments:** {{review_comments}}

## Related Documentation

| Document ID | Description | Location |
|-------------|------------|----------|
| {{related_doc_id}} | {{related_doc_description}} | {{related_doc_location}} |
| | | |
| | | |

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
