# Communication Plan

**Classification:** {{CLASSIFICATION}}
**Incident ID:** {{INCIDENT_ID}}
**Document ID:** COMM-{{INCIDENT_ID}}-{{DOCUMENT_VERSION}}
**Date Created:** {{DATE}}
**Last Updated:** {{LAST_UPDATED}}
**Status:** {{STATUS}}
**Prepared By:** {{LEAD_RESPONDER}}

## 1. Communication Objectives

{{COMMUNICATION_OBJECTIVES}}

## 2. Stakeholder Analysis

### 2.1 Internal Stakeholders

| Stakeholder | Role/Department | Communication Need | Priority | Point of Contact |
|-------------|-----------------|-------------------|----------|------------------|
| {{STAKEHOLDER_NAME}} | {{STAKEHOLDER_ROLE}} | {{COMMUNICATION_NEED}} | {{PRIORITY}} | {{POINT_OF_CONTACT}} |
| | | | | |

### 2.2 External Stakeholders

| Stakeholder | Relationship | Communication Need | Priority | Point of Contact |
|-------------|-------------|-------------------|----------|------------------|
| {{STAKEHOLDER_NAME}} | {{RELATIONSHIP}} | {{COMMUNICATION_NEED}} | {{PRIORITY}} | {{POINT_OF_CONTACT}} |
| | | | | |

### 2.3 Regulatory Bodies

| Regulatory Body | Requirement | Deadline | Priority | Point of Contact |
|-----------------|-------------|----------|----------|------------------|
| {{REGULATORY_BODY}} | {{REQUIREMENT}} | {{DEADLINE}} | {{PRIORITY}} | {{POINT_OF_CONTACT}} |
| | | | | |

## 3. Communication Protocols

### 3.1 Communication Channels

| Channel | Use Case | Security Level | Responsible Party |
|---------|----------|---------------|-------------------|
| {{CHANNEL_NAME}} | {{USE_CASE}} | {{SECURITY_LEVEL}} | {{RESPONSIBLE_PARTY}} |
| | | | |

### 3.2 Authorization Process

{{AUTHORIZATION_PROCESS}}

### 3.3 Security Requirements

- **Classification Handling:** {{CLASSIFICATION_HANDLING}}
- **Information Disclosure:** {{INFORMATION_DISCLOSURE_GUIDELINES}}
- **Secure Transmission:** {{SECURE_TRANSMISSION_REQUIREMENTS}}
- **Record Keeping:** {{RECORD_KEEPING_REQUIREMENTS}}

## 4. Communication Templates

### 4.1 Initial Internal Notification

```plaintext
SUBJECT: [{{SEVERITY}}] Security Incident Notification - {{INCIDENT_ID}}

RECIPIENTS: {{INITIAL_NOTIFICATION_RECIPIENTS}}

BODY:
A security incident has been identified and is currently being investigated.

Incident ID: {{INCIDENT_ID}}
Classification: {{CLASSIFICATION}}
Current Status: {{STATUS}}
Current Phase: {{PHASE}}

WHAT WE KNOW:
{{INITIAL_FINDINGS}}

CURRENT ACTIONS:
{{CURRENT_ACTIONS}}

NEXT STEPS:
{{NEXT_STEPS}}

ADDITIONAL INFORMATION:
Further updates will be provided as more information becomes available.
Please do not discuss this incident outside of authorized channels.

POINT OF CONTACT:
{{POC_NAME}}
{{POC_CONTACT}}
```

### 4.2 Executive Update

```plaintext
SUBJECT: Executive Update: Security Incident {{INCIDENT_ID}}

RECIPIENTS: {{EXECUTIVE_RECIPIENTS}}

BODY:
SECURITY INCIDENT EXECUTIVE SUMMARY

INCIDENT OVERVIEW:
Incident ID: {{INCIDENT_ID}}
Classification: {{CLASSIFICATION}}
Detection Time: {{DETECTION_DATETIME}}
Current Status: {{STATUS}}
Current Phase: {{PHASE}}

IMPACT ASSESSMENT:
Business Impact: {{BUSINESS_IMPACT}}
Operational Impact: {{OPERATIONAL_IMPACT}}
Data Impact: {{DATA_IMPACT}}

CURRENT SITUATION:
{{CURRENT_SITUATION_SUMMARY}}

RESPONSE ACTIONS:
{{RESPONSE_ACTIONS_SUMMARY}}

RESOURCE REQUIREMENTS:
{{RESOURCE_REQUIREMENTS}}

RECOMMENDATIONS:
{{EXECUTIVE_RECOMMENDATIONS}}

NEXT UPDATE:
{{NEXT_UPDATE_TIME}}

POINT OF CONTACT:
{{POC_NAME}}
{{POC_CONTACT}}
```

### 4.3 Customer/User Notification

```plaintext
SUBJECT: Important Security Notice - {{CUSTOMER_NOTIFICATION_SUBJECT}}

RECIPIENTS: {{CUSTOMER_RECIPIENTS}}

BODY:
Dear Valued {{CUSTOMER_TYPE}},

We are writing to inform you of a security incident that may affect {{AFFECTED_SERVICE_OR_DATA}}.

WHAT HAPPENED:
{{CUSTOMER_INCIDENT_DESCRIPTION}}

WHAT INFORMATION WAS INVOLVED:
{{AFFECTED_INFORMATION}}

WHAT WE ARE DOING:
{{COMPANY_ACTIONS}}

WHAT YOU CAN DO:
{{CUSTOMER_ACTIONS}}

FOR MORE INFORMATION:
{{ADDITIONAL_INFORMATION_SOURCES}}

We sincerely apologize for any inconvenience this may cause. The security of your information is our top priority, and we are committed to resolving this matter as quickly as possible.

Sincerely,
{{COMPANY_REPRESENTATIVE}}
{{COMPANY_NAME}}
```

### 4.4 Regulatory Notification

```plaintext
SUBJECT: Security Incident Notification: {{INCIDENT_ID}}

RECIPIENTS: {{REGULATORY_RECIPIENTS}}

BODY:
SECURITY INCIDENT NOTIFICATION
[Submitted pursuant to {{REGULATION_REFERENCE}}]

REPORTING ENTITY:
{{ENTITY_NAME}}
{{ENTITY_ADDRESS}}
{{ENTITY_REGISTRATION_NUMBERS}}

INCIDENT DETAILS:
Incident ID: {{INCIDENT_ID}}
Discovery Date: {{DISCOVERY_DATE}}
Incident Date(s): {{INCIDENT_DATES}}
Incident Type: {{INCIDENT_TYPE}}

INCIDENT DESCRIPTION:
{{REGULATORY_INCIDENT_DESCRIPTION}}

AFFECTED DATA/SYSTEMS:
{{AFFECTED_DATA_SYSTEMS}}

NUMBER OF INDIVIDUALS/RECORDS AFFECTED:
{{AFFECTED_COUNT}}

CONTAINMENT AND MITIGATION MEASURES:
{{CONTAINMENT_MEASURES}}

NOTIFICATION TO AFFECTED INDIVIDUALS:
{{NOTIFICATION_PLANS}}

CONTACT INFORMATION FOR ADDITIONAL INFORMATION:
{{REGULATORY_POC_NAME}}
{{REGULATORY_POC_TITLE}}
{{REGULATORY_POC_PHONE}}
{{REGULATORY_POC_EMAIL}}

This notification is being submitted in accordance with {{REGULATION_NAME}} requirements.
We are committed to cooperating fully with your office regarding this matter.
```

### 4.5 Media Statement

```plaintext
FOR IMMEDIATE RELEASE
[Alternative: HOLDING STATEMENT - NOT FOR DISTRIBUTION]

{{MEDIA_HEADLINE}}

{{ORGANIZATION_NAME}} ADDRESSES {{INCIDENT_TYPE_GENERAL}}

{{LOCATION}} — {{DATE}}

{{ORGANIZATION_NAME}} is [investigating/addressing] a {{INCIDENT_TYPE_GENERAL}} that [was discovered/occurred] on {{DISCOVERY_DATE_PUBLIC}}.

{{MEDIA_INCIDENT_DESCRIPTION}}

"{{EXECUTIVE_QUOTE}}" said {{EXECUTIVE_NAME}}, {{EXECUTIVE_TITLE}} at {{ORGANIZATION_NAME}}.

{{RESPONSE_ACTION_SUMMARY}}

{{AFFECTED_PARTIES_STATEMENT}}

{{CUSTOMER_GUIDANCE_BRIEF}}

{{ORGANIZATION_NAME}} is working with {{COOPERATING_ENTITIES}} to investigate the incident thoroughly and will provide updates as additional information becomes available.

For more information, please contact:
{{MEDIA_CONTACT_NAME}}
{{MEDIA_CONTACT_TITLE}}
{{MEDIA_CONTACT_EMAIL}}
{{MEDIA_CONTACT_PHONE}}

About {{ORGANIZATION_NAME}}:
{{ORGANIZATION_BOILERPLATE}}

###
```

### 4.6 Status Update

```plaintext
SUBJECT: Status Update: Security Incident {{INCIDENT_ID}}

RECIPIENTS: {{STATUS_UPDATE_RECIPIENTS}}

BODY:
SECURITY INCIDENT STATUS UPDATE

Incident ID: {{INCIDENT_ID}}
Update #: {{UPDATE_NUMBER}}
Date/Time: {{UPDATE_DATETIME}}
Current Status: {{STATUS}}
Current Phase: {{PHASE}}

KEY DEVELOPMENTS SINCE LAST UPDATE:
{{KEY_DEVELOPMENTS}}

CURRENT ACTIVITIES:
{{CURRENT_ACTIVITIES}}

PLANNED NEXT STEPS:
{{PLANNED_STEPS}}

UPDATED TIMELINE:
{{UPDATED_TIMELINE}}

BLOCKERS/CHALLENGES:
{{BLOCKERS}}

RESOURCE NEEDS:
{{RESOURCE_NEEDS}}

NEXT UPDATE EXPECTED:
{{NEXT_UPDATE_EXPECTED}}

POINT OF CONTACT:
{{POC_NAME}}
{{POC_CONTACT}}
```

## 5. Communication Schedule

| Stakeholder Group | Communication Type | Frequency | Timing | Channel | Responsible Party |
|-------------------|-------------------|-----------|--------|---------|------------------|
| {{STAKEHOLDER_GROUP}} | {{COMMUNICATION_TYPE}} | {{FREQUENCY}} | {{TIMING}} | {{CHANNEL}} | {{RESPONSIBLE_PARTY}} |
| | | | | | |

## 6. Incident Messaging Guidelines

### 6.1 General Communication Principles

- {{COMMUNICATION_PRINCIPLE_1}}
- {{COMMUNICATION_PRINCIPLE_2}}
- {{COMMUNICATION_PRINCIPLE_3}}
- {{COMMUNICATION_PRINCIPLE_4}}
- {{COMMUNICATION_PRINCIPLE_5}}

### 6.2 Approved Terminology

| Term | Approved Description | Terms to Avoid |
|------|----------------------|---------------|
| {{APPROVED_TERM}} | {{APPROVED_DESCRIPTION}} | {{TERMS_TO_AVOID}} |
| | | |

### 6.3 Talking Points

#### Initial Phase

- {{INITIAL_TALKING_POINT_1}}
- {{INITIAL_TALKING_POINT_2}}
- {{INITIAL_TALKING_POINT_3}}

#### Containment Phase

- {{CONTAINMENT_TALKING_POINT_1}}
- {{CONTAINMENT_TALKING_POINT_2}}
- {{CONTAINMENT_TALKING_POINT_3}}

#### Recovery Phase

- {{RECOVERY_TALKING_POINT_1}}
- {{RECOVERY_TALKING_POINT_2}}
- {{RECOVERY_TALKING_POINT_3}}

### 6.4 Questions & Answers

| Anticipated Question | Approved Response |
|----------------------|-------------------|
| {{ANTICIPATED_QUESTION}} | {{APPROVED_RESPONSE}} |
| | |

## 7. Escalation Procedures

### 7.1 Communication Escalation Paths

| Trigger | Escalation Level | Stakeholders to Notify | Timeframe | Responsible Party |
|---------|-----------------|------------------------|-----------|------------------|
| {{ESCALATION_TRIGGER}} | {{ESCALATION_LEVEL}} | {{NOTIFICATION_STAKEHOLDERS}} | {{TIMEFRAME}} | {{RESPONSIBLE_PARTY}} |
| | | | | |

### 7.2 Unplanned Communication Events

| Scenario | Response Protocol | Authorized Responders |
|----------|------------------|----------------------|
| {{UNPLANNED_SCENARIO}} | {{RESPONSE_PROTOCOL}} | {{AUTHORIZED_RESPONDERS}} |
| | | |

## 8. Post-Incident Communication

### 8.1 Final Notifications

| Stakeholder Group | Communication Type | Timing | Channel | Content Guidelines |
|-------------------|-------------------|--------|---------|-------------------|
| {{STAKEHOLDER_GROUP}} | {{COMMUNICATION_TYPE}} | {{TIMING}} | {{CHANNEL}} | {{CONTENT_GUIDELINES}} |
| | | | | |

### 8.2 Lessons Learned Communications

| Audience | Key Messages | Format | Distribution Method | Responsible Party |
|----------|-------------|--------|---------------------|------------------|
| {{AUDIENCE}} | {{KEY_MESSAGES}} | {{FORMAT}} | {{DISTRIBUTION_METHOD}} | {{RESPONSIBLE_PARTY}} |
| | | | | |

## 9. Communication Activity Log

| Date/Time | Stakeholder | Message Type | Channel | Sender | Status | Notes |
|-----------|------------|-------------|---------|--------|--------|-------|
| {{COMMUNICATION_DATETIME}} | {{STAKEHOLDER}} | {{MESSAGE_TYPE}} | {{CHANNEL}} | {{SENDER}} | {{STATUS}} | {{NOTES}} |
| | | | | | | |

## 10. Approvals and Distribution

### 10.1 Required Approvals

| Role | Name | Approval Status | Date |
|------|------|----------------|------|
| Incident Lead | {{LEAD_RESPONDER}} | {{APPROVAL_STATUS}} | {{APPROVAL_DATE}} |
| Communications Lead | {{COMMUNICATIONS_LEAD}} | {{APPROVAL_STATUS}} | {{APPROVAL_DATE}} |
| Legal Counsel | {{LEGAL_COUNSEL}} | {{APPROVAL_STATUS}} | {{APPROVAL_DATE}} |
| Executive Sponsor | {{EXECUTIVE_SPONSOR}} | {{APPROVAL_STATUS}} | {{APPROVAL_DATE}} |

### 10.2 Distribution List

| Name | Role | Organization | Distribution Date |
|------|------|--------------|-------------------|
| {{RECIPIENT_NAME}} | {{RECIPIENT_ROLE}} | {{RECIPIENT_ORG}} | {{DISTRIBUTION_DATE}} |
| | | | |

## 11. Document History

| Version | Date | Modified By | Description of Changes |
|---------|------|------------|------------------------|
| 1.0 | {{DATE}} | {{LEAD_RESPONDER}} | Initial document creation |
| {{VERSION}} | {{MODIFICATION_DATE}} | {{MODIFIER_NAME}} | {{MODIFICATION_DESCRIPTION}} |

---

**Document Owner:** {{DOCUMENT_OWNER}}
**Review Frequency:** As needed throughout incident lifecycle
**Security Classification:** {{CLASSIFICATION}}

This document must be handled in accordance with information classification policies. Distribution is restricted to authorized personnel with a legitimate need-to-know.

### Reference

NIST SP 800-61r2: Computer Security Incident Handling Guide
