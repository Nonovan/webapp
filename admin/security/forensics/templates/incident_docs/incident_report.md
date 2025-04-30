# Incident Report

**Classification:** {{classification}}
**Incident ID:** {{incident_id}}
**Report ID:** IR-{{incident_id}}-{{report_version}}
**Date Created:** {{creation_date}}
**Last Updated:** {{last_updated}}
**Status:** {{document_status}}
**Prepared By:** {{analyst_name}}
**Approved By:** {{approver_name}}

## 1. Executive Summary

{{executive_summary}}

### 1.1 Incident Classification

- **Type:** {{incident_type}}
- **Severity:** {{severity_level}}
- **Current Status:** {{incident_status}}
- **MITRE ATT&CK Tactics:** {{mitre_tactics}}
- **MITRE ATT&CK Techniques:** {{mitre_techniques}}

### 1.2 Impact Summary

- **Systems Affected:** {{num_systems_affected}} systems
- **Data Impact:** {{data_impact}}
- **Operational Impact:** {{operational_impact}}
- **User Impact:** {{user_impact}}
- **Financial Impact:** {{financial_impact}}

## 2. Incident Timeline

### 2.1 Key Events

| Date/Time (UTC) | Event | Details | Source/Evidence |
|-----------------|-------|---------|----------------|
| {{event_datetime}} | {{event_type}} | {{event_details}} | {{event_source}} |
| | | | |
| | | | |

### 2.2 Discovery Information

- **Discovery Date/Time:** {{discovery_datetime}}
- **Discovery Method:** {{discovery_method}}
- **Discovered By:** {{discovered_by}}
- **Initial Alert/Ticket:** {{initial_alert_id}}
- **Time to Detection:** {{time_to_detection}}

### 2.3 Response Timeline

| Date/Time (UTC) | Response Action | Performed By | Outcome |
|-----------------|----------------|-------------|---------|
| {{action_datetime}} | {{response_action}} | {{response_by}} | {{action_outcome}} |
| | | | |
| | | | |

## 3. Technical Details

### 3.1 Affected Systems/Assets

| System/Asset | Function | IP/Hostname | Impact | Status |
|-------------|----------|------------|--------|--------|
| {{system_name}} | {{system_function}} | {{system_identifier}} | {{system_impact}} | {{system_status}} |
| | | | | |
| | | | | |

### 3.2 Attack Vector and Methodology

{{attack_vector_description}}

#### 3.2.1 Initial Access Method

{{initial_access_method}}

#### 3.2.2 Attack Progression

{{attack_progression}}

#### 3.2.3 Persistence Mechanisms

{{persistence_mechanisms}}

### 3.3 Indicators of Compromise (IOCs)

| IOC Type | Indicator Value | Description | Detection Location |
|----------|----------------|------------|-------------------|
| {{ioc_type}} | {{ioc_value}} | {{ioc_description}} | {{ioc_location}} |
| | | | |
| | | | |

### 3.4 Vulnerabilities Exploited

| CVE/ID | Description | Affected Component | Exploitability |
|--------|------------|-------------------|---------------|
| {{vulnerability_id}} | {{vulnerability_description}} | {{affected_component}} | {{exploitability}} |
| | | | |
| | | | |

## 4. Evidence Collection

### 4.1 Evidence Inventory

| Evidence ID | Description | Collection Date | Collection Method | Hash (SHA-256) | Chain of Custody Reference |
|------------|-------------|-----------------|------------------|----------------|---------------------------|
| {{evidence_id}} | {{evidence_description}} | {{collection_date}} | {{collection_method}} | {{evidence_hash}} | COC-{{incident_id}}-{{evidence_id}} |
| | | | | | |
| | | | | | |

### 4.2 Forensic Analysis Results

{{forensic_analysis_summary}}

#### 4.2.1 Key Findings

- {{key_finding_1}}
- {{key_finding_2}}
- {{key_finding_3}}

#### 4.2.2 Analysis Artifacts

| Artifact | Location | Analysis Results | Significance |
|----------|----------|-----------------|-------------|
| {{artifact_name}} | {{artifact_location}} | {{analysis_results}} | {{artifact_significance}} |
| | | | |
| | | | |

## 5. Incident Assessment

### 5.1 Root Cause Analysis

{{root_cause_analysis}}

### 5.2 Attack Attribution

{{attack_attribution}}

### 5.3 Scope of Compromise

{{scope_of_compromise}}

### 5.4 Data Exposure Assessment

| Data Type | Amount | Sensitivity | Exposure Method | Confirmed Exfiltration |
|-----------|--------|------------|----------------|------------------------|
| {{data_type}} | {{data_amount}} | {{data_sensitivity}} | {{exposure_method}} | {{confirmed_exfiltration}} |
| | | | | |
| | | | | |

## 6. Incident Response Actions

### 6.1 Containment Measures

| Measure | Implementation Date | Implemented By | Effectiveness |
|---------|-------------------|---------------|---------------|
| {{containment_measure}} | {{implementation_date}} | {{implemented_by}} | {{effectiveness}} |
| | | | |
| | | | |

### 6.2 Eradication Steps

| Step | Date Completed | Performed By | Verification Method |
|------|---------------|-------------|-------------------|
| {{eradication_step}} | {{completion_date}} | {{performed_by}} | {{verification_method}} |
| | | | |
| | | | |

### 6.3 Recovery Actions

| Action | Date Completed | Performed By | Results |
|--------|---------------|-------------|---------|
| {{recovery_action}} | {{action_date}} | {{action_by}} | {{action_results}} |
| | | | |
| | | | |

## 7. Regulatory and Compliance Implications

### 7.1 Applicable Regulations

- {{applicable_regulation_1}}
- {{applicable_regulation_2}}
- {{applicable_regulation_3}}

### 7.2 Notification Requirements

| Stakeholder | Notification Requirement | Deadline | Status | Date Completed |
|------------|------------------------|----------|--------|----------------|
| {{stakeholder}} | {{notification_requirement}} | {{notification_deadline}} | {{notification_status}} | {{notification_date}} |
| | | | | |
| | | | | |

## 8. Recommendations

### 8.1 Prevention Recommendations

| ID | Recommendation | Priority | Implementation Timeframe | Responsible Party |
|----|---------------|----------|-------------------------|------------------|
| PR-{{incident_id}}-01 | {{prevention_recommendation}} | {{priority}} | {{timeframe}} | {{responsible_party}} |
| | | | | |
| | | | | |

### 8.2 Detection Improvements

| ID | Improvement | Priority | Implementation Timeframe | Responsible Party |
|----|------------|----------|-------------------------|------------------|
| DI-{{incident_id}}-01 | {{detection_improvement}} | {{priority}} | {{timeframe}} | {{responsible_party}} |
| | | | | |
| | | | | |

### 8.3 Response Improvements

| ID | Improvement | Priority | Implementation Timeframe | Responsible Party |
|----|------------|----------|-------------------------|------------------|
| RI-{{incident_id}}-01 | {{response_improvement}} | {{priority}} | {{timeframe}} | {{responsible_party}} |
| | | | | |
| | | | | |

## 9. Lessons Learned

{{lessons_learned}}

### 9.1 What Worked Well

- {{worked_well_1}}
- {{worked_well_2}}
- {{worked_well_3}}

### 9.2 Improvement Opportunities

- {{improvement_opportunity_1}}
- {{improvement_opportunity_2}}
- {{improvement_opportunity_3}}

## 10. References and Related Documentation

| Document Type | Document ID | Name | Location | Relevance |
|--------------|------------|------|----------|-----------|
| {{document_type}} | {{related_document_id}} | {{document_name}} | {{document_location}} | {{relevance}} |
| | | | | |
| | | | | |

## 11. Approval and Distribution

### 11.1 Approval

| Role | Name | Approval Status | Date |
|------|------|----------------|------|
| Incident Lead | {{incident_lead}} | {{approval_status}} | {{approval_date}} |
| Security Manager | {{security_manager}} | {{approval_status}} | {{approval_date}} |
| Legal Counsel | {{legal_counsel}} | {{approval_status}} | {{approval_date}} |
| Executive Sponsor | {{executive_sponsor}} | {{approval_status}} | {{approval_date}} |

### 11.2 Distribution List

| Name | Role | Organization | Distribution Date |
|------|------|--------------|-------------------|
| {{recipient_name}} | {{recipient_role}} | {{recipient_org}} | {{distribution_date}} |
| | | | |
| | | | |

## 12. Document History

| Version | Date | Modified By | Description of Changes |
|---------|------|------------|------------------------|
| 1.0 | {{creation_date}} | {{analyst_name}} | Initial document creation |
| {{version}} | {{modification_date}} | {{modifier_name}} | {{modification_description}} |

---

**Document Owner:** {{document_owner}}
**Review Frequency:** As required by incident severity level and organizational policy
**Security Classification:** {{classification}}

This document must be handled in accordance with information classification policies. Distribution is restricted to authorized personnel with a legitimate need-to-know.

### Reference

NIST SP 800-61r2: Computer Security Incident Handling Guide
