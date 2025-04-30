# Evidence Examination Report

**Classification:** {{classification}}
**Case ID:** {{case_id}}
**Evidence ID:** {{evidence_id}}
**Document ID:** EXAM-{{case_id}}-{{evidence_id}}
**Examiner:** {{analyst_name}}
**Date Created:** {{creation_date}}
**Last Updated:** {{last_updated}}

## Evidence Information

**Evidence Description:** {{evidence_description}}
**Evidence Type:** {{evidence_type}}
**Chain of Custody Reference:** COC-{{case_id}}-{{evidence_id}}
**Original Hash (SHA-256):** {{original_hash}}
**Acquisition Date:** {{acquisition_date}}
**Acquisition Method:** {{acquisition_method}}

## Examination Preparation

### Evidence Integrity Verification

| Hash Type | Expected Value | Computed Value | Verification Status | Verification Date/Time |
|-----------|---------------|---------------|---------------------|------------------------|
| SHA-256   | {{original_hash}} | {{verification_hash}} | {{verification_status}} | {{verification_datetime}} |

### Examination Environment

**Workstation ID:** {{workstation_id}}
**Operating System:** {{operating_system}}
**Write Blocker Used:** {{write_blocker}}
**Working Directory:** {{working_directory}}
**Time Synchronization:** {{time_sync_method}}

### Tools/Software Used

| Tool Name | Version | Purpose | Validation Status | Configuration |
|-----------|---------|---------|------------------|---------------|
| {{tool_name}} | {{tool_version}} | {{tool_purpose}} | {{validation_status}} | {{configuration}} |
| | | | | |
| | | | | |

## Examination Methodology

**Examination Objective:** {{examination_objective}}
**Examination Scope:** {{examination_scope}}
**Evidence Handling Procedures:** {{handling_procedures}}

### Examination Process

1. {{examination_step_1}}
   - {{substep_1_1}}
   - {{substep_1_2}}

2. {{examination_step_2}}
   - {{substep_2_1}}
   - {{substep_2_2}}

3. {{examination_step_3}}
   - {{substep_3_1}}
   - {{substep_3_2}}

## Examination Record

This section documents the detailed examination activities, observations, and findings. All examination activities are documented in chronological order.

| Date/Time (UTC) | Activity Type | Tools Used | Activity Description | Observations/Findings | Examiner |
|-----------------|--------------|------------|---------------------|----------------------|-------------|
| {{activity_datetime}} | {{activity_type}} | {{tools_used}} | {{activity_description}} | {{observations}} | {{examiner}} |
| | | | | | |
| | | | | | |

## Initial Findings

### Summary of Findings

{{findings_summary}}

### Items of Interest

1. **Item:** {{item_1_name}}
   - **Location:** {{item_1_location}}
   - **Description:** {{item_1_description}}
   - **Significance:** {{item_1_significance}}

2. **Item:** {{item_2_name}}
   - **Location:** {{item_2_location}}
   - **Description:** {{item_2_description}}
   - **Significance:** {{item_2_significance}}

3. **Item:** {{item_3_name}}
   - **Location:** {{item_3_location}}
   - **Description:** {{item_3_description}}
   - **Significance:** {{item_3_significance}}

### Areas Requiring Further Analysis

| Area | Rationale | Recommended Approach | Priority |
|------|-----------|---------------------|----------|
| {{analysis_area}} | {{analysis_rationale}} | {{recommended_approach}} | {{priority}} |
| | | | |
| | | | |

## Technical Challenges and Limitations

| Challenge/Limitation | Impact on Examination | Mitigation Strategy |
|---------------------|---------------------|---------------------|
| {{challenge}} | {{impact}} | {{mitigation}} |
| | | |
| | | |

## Evidence Storage

**Working Copy Location:** {{working_copy_location}}
**Access Control Measures:** {{access_control}}
**Examination Data Storage:** {{examination_data_location}}

## Chain of Custody Maintenance

All access to evidence during examination is documented in the chain of custody record referenced above. The following additional access events occurred during examination:

| Date/Time (UTC) | Person | Action | Purpose |
|-----------------|--------|--------|---------|
| {{access_datetime}} | {{person}} | {{action}} | {{purpose}} |
| | | | |
| | | | |

## Recommendations

1. {{recommendation_1}}
2. {{recommendation_2}}
3. {{recommendation_3}}

## Reference Materials

List reference materials used during the examination:

1. **Reference:** {{reference_title_1}}
   - **Source:** {{reference_source_1}}
   - **Relevance:** {{reference_relevance_1}}

2. **Reference:** {{reference_title_2}}
   - **Source:** {{reference_source_2}}
   - **Relevance:** {{reference_relevance_2}}

## Peer Review

**Review Status:** {{review_status}}
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

### Reference

NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response
