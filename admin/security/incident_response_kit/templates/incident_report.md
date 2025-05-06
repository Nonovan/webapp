# Incident Report

**Classification:** {{CLASSIFICATION}}
**Incident ID:** {{INCIDENT_ID}}
**Report ID:** IR-{{INCIDENT_ID}}-{{REPORT_VERSION}}
**Date Created:** {{DATE}}
**Last Updated:** {{LAST_UPDATED}}
**Status:** {{STATUS}}
**Prepared By:** {{LEAD_RESPONDER}}

## 1. Executive Summary

{{EXECUTIVE_SUMMARY}}

### 1.1 Incident Classification

- **Type:** {{INCIDENT_TYPE}}
- **Severity:** {{SEVERITY}}
- **Current Status:** {{STATUS}}
- **Current Phase:** {{PHASE}}
- **MITRE ATT&CK Tactics:** {{MITRE_TACTICS}}
- **MITRE ATT&CK Techniques:** {{MITRE_TECHNIQUES}}

### 1.2 Impact Summary

- **Systems Affected:** {{NUM_SYSTEMS_AFFECTED}}
- **Data Impact:** {{DATA_IMPACT}}
- **Operational Impact:** {{OPERATIONAL_IMPACT}}
- **User Impact:** {{USER_IMPACT}}
- **Financial Impact:** {{FINANCIAL_IMPACT}}
- **Reputational Impact:** {{REPUTATIONAL_IMPACT}}

### 1.3 Key Dates and Times

- **Detection Date/Time:** {{DETECTION_DATETIME}}
- **Response Initiated:** {{RESPONSE_DATETIME}}
- **Containment Achieved:** {{CONTAINMENT_DATETIME}}
- **Recovery Completed:** {{RECOVERY_DATETIME}}
- **Report Date:** {{DATE}}

## 2. Incident Timeline

### 2.1 Key Events

| Date/Time (UTC) | Event | Details | Source/Evidence |
|-----------------|-------|---------|----------------|
| {{EVENT_DATETIME}} | {{EVENT_TYPE}} | {{EVENT_DETAILS}} | {{EVENT_SOURCE}} |
| | | | |

### 2.2 Discovery Information

- **Discovery Date/Time:** {{DISCOVERY_DATETIME}}
- **Discovery Method:** {{DISCOVERY_METHOD}}
- **Discovered By:** {{DISCOVERED_BY}}
- **Initial Alert/Ticket:** {{INITIAL_ALERT_ID}}
- **Time to Detection:** {{TIME_TO_DETECTION}}

### 2.3 Response Timeline

| Date/Time (UTC) | Response Action | Performed By | Outcome |
|-----------------|----------------|-------------|---------|
| {{ACTION_DATETIME}} | {{RESPONSE_ACTION}} | {{RESPONSE_BY}} | {{ACTION_OUTCOME}} |
| | | | |

## 3. Technical Details

### 3.1 Affected Systems/Assets

| System/Asset | Function | IP/Hostname | Impact | Status |
|-------------|----------|------------|--------|--------|
| {{SYSTEM_NAME}} | {{SYSTEM_FUNCTION}} | {{SYSTEM_IDENTIFIER}} | {{SYSTEM_IMPACT}} | {{SYSTEM_STATUS}} |
| | | | | |

### 3.2 Attack Vector and Methodology

{{ATTACK_VECTOR_DESCRIPTION}}

#### 3.2.1 Initial Access Method

{{INITIAL_ACCESS_METHOD}}

#### 3.2.2 Attack Progression

{{ATTACK_PROGRESSION}}

#### 3.2.3 Persistence Mechanisms

{{PERSISTENCE_MECHANISMS}}

### 3.3 Indicators of Compromise (IOCs)

| IOC Type | Indicator Value | Description | Detection Location |
|----------|----------------|------------|-------------------|
| {{IOC_TYPE}} | {{IOC_VALUE}} | {{IOC_DESCRIPTION}} | {{IOC_LOCATION}} |
| | | | |

### 3.4 Vulnerabilities Exploited

| CVE/ID | Description | Affected Component | Exploitability |
|--------|------------|-------------------|---------------|
| {{VULNERABILITY_ID}} | {{VULNERABILITY_DESCRIPTION}} | {{AFFECTED_COMPONENT}} | {{EXPLOITABILITY}} |
| | | | |

## 4. Evidence Collection

### 4.1 Evidence Inventory

| Evidence ID | Description | Collection Date | Collection Method | Hash (SHA-256) | Chain of Custody Reference |
|------------|-------------|-----------------|------------------|----------------|---------------------------|
| {{EVIDENCE_ID}} | {{EVIDENCE_DESCRIPTION}} | {{COLLECTION_DATE}} | {{COLLECTION_METHOD}} | {{EVIDENCE_HASH}} | COC-{{INCIDENT_ID}}-{{EVIDENCE_ID}} |
| | | | | | |

### 4.2 Forensic Analysis Results

{{FORENSIC_ANALYSIS_SUMMARY}}

#### 4.2.1 Key Findings

- {{KEY_FINDING_1}}
- {{KEY_FINDING_2}}
- {{KEY_FINDING_3}}

#### 4.2.2 Analysis Artifacts

| Artifact | Location | Analysis Results | Significance |
|----------|----------|-----------------|-------------|
| {{ARTIFACT_NAME}} | {{ARTIFACT_LOCATION}} | {{ANALYSIS_RESULTS}} | {{ARTIFACT_SIGNIFICANCE}} |
| | | | |

## 5. Incident Assessment

### 5.1 Root Cause Analysis

{{ROOT_CAUSE_ANALYSIS}}

### 5.2 Attack Attribution

{{ATTACK_ATTRIBUTION}}

### 5.3 Scope of Compromise

{{SCOPE_OF_COMPROMISE}}

### 5.4 Data Exposure Assessment

| Data Type | Amount | Sensitivity | Exposure Method | Confirmed Exfiltration |
|-----------|--------|------------|----------------|------------------------|
| {{DATA_TYPE}} | {{DATA_AMOUNT}} | {{DATA_SENSITIVITY}} | {{EXPOSURE_METHOD}} | {{CONFIRMED_EXFILTRATION}} |
| | | | | |

## 6. Incident Response Actions

### 6.1 Containment Measures

| Measure | Implementation Date | Implemented By | Effectiveness |
|---------|-------------------|---------------|---------------|
| {{CONTAINMENT_MEASURE}} | {{IMPLEMENTATION_DATE}} | {{IMPLEMENTED_BY}} | {{EFFECTIVENESS}} |
| | | | |

### 6.2 Eradication Steps

| Step | Date Completed | Performed By | Verification Method |
|------|---------------|-------------|-------------------|
| {{ERADICATION_STEP}} | {{COMPLETION_DATE}} | {{PERFORMED_BY}} | {{VERIFICATION_METHOD}} |
| | | | |

### 6.3 Recovery Actions

| Action | Date Completed | Performed By | Results |
|--------|---------------|-------------|---------|
| {{RECOVERY_ACTION}} | {{ACTION_DATE}} | {{ACTION_BY}} | {{ACTION_RESULTS}} |
| | | | |

## 7. Regulatory and Compliance Implications

### 7.1 Applicable Regulations

- {{APPLICABLE_REGULATION_1}}
- {{APPLICABLE_REGULATION_2}}
- {{APPLICABLE_REGULATION_3}}

### 7.2 Notification Requirements

| Stakeholder | Notification Requirement | Deadline | Status | Date Completed |
|------------|------------------------|----------|--------|----------------|
| {{STAKEHOLDER}} | {{NOTIFICATION_REQUIREMENT}} | {{NOTIFICATION_DEADLINE}} | {{NOTIFICATION_STATUS}} | {{NOTIFICATION_DATE}} |
| | | | | |

## 8. Recommendations

### 8.1 Prevention Recommendations

| ID | Recommendation | Priority | Implementation Timeframe | Responsible Party |
|----|---------------|----------|-------------------------|------------------|
| PR-{{INCIDENT_ID}}-01 | {{PREVENTION_RECOMMENDATION}} | {{PRIORITY}} | {{TIMEFRAME}} | {{RESPONSIBLE_PARTY}} |
| | | | | |

### 8.2 Detection Improvements

| ID | Improvement | Priority | Implementation Timeframe | Responsible Party |
|----|------------|----------|-------------------------|------------------|
| DI-{{INCIDENT_ID}}-01 | {{DETECTION_IMPROVEMENT}} | {{PRIORITY}} | {{TIMEFRAME}} | {{RESPONSIBLE_PARTY}} |
| | | | | |

### 8.3 Response Improvements

| ID | Improvement | Priority | Implementation Timeframe | Responsible Party |
|----|------------|----------|-------------------------|------------------|
| RI-{{INCIDENT_ID}}-01 | {{RESPONSE_IMPROVEMENT}} | {{PRIORITY}} | {{TIMEFRAME}} | {{RESPONSIBLE_PARTY}} |
| | | | | |

## 9. Lessons Learned

{{LESSONS_LEARNED}}

### 9.1 What Worked Well

- {{WORKED_WELL_1}}
- {{WORKED_WELL_2}}
- {{WORKED_WELL_3}}

### 9.2 Improvement Opportunities

- {{IMPROVEMENT_OPPORTUNITY_1}}
- {{IMPROVEMENT_OPPORTUNITY_2}}
- {{IMPROVEMENT_OPPORTUNITY_3}}

## 10. References and Related Documentation

| Document Type | Document ID | Name | Location | Relevance |
|--------------|------------|------|----------|-----------|
| {{DOCUMENT_TYPE}} | {{RELATED_DOCUMENT_ID}} | {{DOCUMENT_NAME}} | {{DOCUMENT_LOCATION}} | {{RELEVANCE}} |
| | | | | |

## 11. Approval and Distribution

### 11.1 Approval

| Role | Name | Approval Status | Date |
|------|------|----------------|------|
| Incident Lead | {{LEAD_RESPONDER}} | {{APPROVAL_STATUS}} | {{APPROVAL_DATE}} |
| Security Manager | {{SECURITY_MANAGER}} | {{APPROVAL_STATUS}} | {{APPROVAL_DATE}} |
| Legal Counsel | {{LEGAL_COUNSEL}} | {{APPROVAL_STATUS}} | {{APPROVAL_DATE}} |
| Executive Sponsor | {{EXECUTIVE_SPONSOR}} | {{APPROVAL_STATUS}} | {{APPROVAL_DATE}} |

### 11.2 Distribution List

| Name | Role | Organization | Distribution Date |
|------|------|--------------|-------------------|
| {{RECIPIENT_NAME}} | {{RECIPIENT_ROLE}} | {{RECIPIENT_ORG}} | {{DISTRIBUTION_DATE}} |
| | | | |

## 12. Document History

| Version | Date | Modified By | Description of Changes |
|---------|------|------------|------------------------|
| 1.0 | {{DATE}} | {{LEAD_RESPONDER}} | Initial document creation |
| {{VERSION}} | {{MODIFICATION_DATE}} | {{MODIFIER_NAME}} | {{MODIFICATION_DESCRIPTION}} |

---

**Document Owner:** {{DOCUMENT_OWNER}}
**Review Frequency:** As required by incident severity level and organizational policy
**Security Classification:** {{CLASSIFICATION}}

This document must be handled in accordance with information classification policies. Distribution is restricted to authorized personnel with a legitimate need-to-know.

### Reference

NIST SP 800-61r2: Computer Security Incident Handling Guide
