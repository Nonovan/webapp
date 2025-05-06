# Incident Severity Classification Guide

## Contents

- [Overview](#overview)
- [Severity Levels](#severity-levels)
- [Classification Criteria](#classification-criteria)
- [Impact Assessment](#impact-assessment)
- [Severity Escalation](#severity-escalation)
- [Response Requirements](#response-requirements)
- [Implementation Reference](#implementation-reference)
- [Available Functions](#available-functions)
- [Best Practices & Security](#best-practices--security)
- [Related Documentation](#related-documentation)

## Overview

This guide provides standardized criteria for classifying security incidents by severity within the Cloud Infrastructure Platform. Severity classification ensures that incidents receive appropriate attention, resources, and response actions. The framework aligns with the organization's security policies and industry best practices including NIST SP 800-61 (Computer Security Incident Handling Guide).

Proper severity classification is critical for:

- Prioritizing incident response resources
- Determining notification requirements
- Establishing response timeframes
- Guiding escalation decisions
- Meeting regulatory reporting requirements

## Severity Levels

The incident response framework uses four severity levels to classify incidents:

| Level | Name | Description | Response Time | Example Scenarios |
|-------|------|-------------|---------------|-------------------|
| **1** | **Critical** | Severe business impact requiring immediate response | 1 hour | • Data breach of sensitive PII/PHI<br>• Ransomware infection<br>• Unauthorized admin/root access<br>• Complete system outage<br>• Active targeted attacks |
| **2** | **High** | Significant business impact requiring urgent response | 4 hours | • Limited data exposure<br>• Targeted attack on single system<br>• Web application compromise<br>• Privilege escalation<br>• Malware on multiple systems |
| **3** | **Medium** | Moderate business impact requiring timely response | 24 hours | • Unsuccessful intrusion attempts<br>• Limited malware infection<br>• Denial of service against non-critical systems<br>• Violation of security policy<br>• Unusual network activity |
| **4** | **Low** | Minor business impact requiring standard response | 72 hours | • Isolated policy violation<br>• Failed login attempts<br>• Port scanning activity<br>• Isolated non-sensitive system outage<br>• Suspicious but non-impactful activity |

## Classification Criteria

### Primary Factors

Severity classification should consider these primary factors:

1. **Data Impact**
   - What type and amount of data is potentially compromised?
   - What is the sensitivity classification of the affected data?
   - Are there regulatory implications related to the affected data?
   - How many data subjects are affected?
   - Is the data critical to business operations?

2. **System Impact**
   - What is the criticality of affected systems?
   - How many systems are affected?
   - What is the operational impact on affected systems?
   - Is there potential for further spread to other systems?
   - What is the recovery complexity?

3. **Business Impact**
   - What is the financial impact (actual or potential)?
   - Is there operational disruption?
   - What is the reputational impact?
   - Are there regulatory or compliance implications?
   - What is the impact on customers or partners?

4. **Attack Characteristics**
   - Is the attack targeted or opportunistic?
   - What is the sophistication level of the attack?
   - Is the attack active or has it been contained?
   - Is there evidence of data exfiltration?
   - What is the persistence level of the threat?

### Data Sensitivity Matrix

| Data Type | Examples | Recommended Minimum Severity |
|-----------|----------|------------------------------|
| **Highly Sensitive** | • PII/PHI<br>• Payment card data<br>• Authentication credentials<br>• Confidential business data | Critical or High |
| **Sensitive** | • Internal business documents<br>• Customer information (non-PII)<br>• Non-production credentials<br>• Configuration data | High or Medium |
| **Internal** | • Internal communications<br>• Non-sensitive employee data<br>• Operational data<br>• Testing data | Medium or Low |
| **Public** | • Marketing materials<br>• Published documentation<br>• Public-facing website content | Low |

### System Criticality Matrix

| System Type | Examples | Recommended Minimum Severity |
|-------------|----------|------------------------------|
| **Critical** | • Authentication systems<br>• Payment processing<br>• Core business applications<br>• Customer-facing systems | Critical or High |
| **High-Value** | • Internal business systems<br>• Data storage systems<br>• Communication systems<br>• Business reporting | High or Medium |
| **Supporting** | • Development environments<br>• Non-production systems<br>• Internal tools<br>• Testing platforms | Medium or Low |
| **Non-Essential** | • Isolated workstations<br>• Training systems<br>• Decommissioned systems | Low |

## Impact Assessment

### Technical Impact Assessment

For each incident, assess the technical impact across these dimensions:

1. **Confidentiality Impact**
   - None: No data was accessed
   - Low: Non-sensitive data was accessed
   - Moderate: Internal data was accessed
   - High: Sensitive data was accessed
   - Critical: Highly sensitive data was accessed

2. **Integrity Impact**
   - None: No data was modified
   - Low: Non-essential data modified
   - Moderate: Important data modified
   - High: Critical data modified
   - Critical: System integrity compromised

3. **Availability Impact**
   - None: No systems affected
   - Low: Non-essential systems affected
   - Moderate: Important systems affected
   - High: Critical systems affected
   - Critical: Multiple critical systems affected

### Business Impact Assessment

For each incident, assess the business impact across these dimensions:

1. **Operational Impact**
   - None: No operational impact
   - Low: Minor inconvenience
   - Moderate: Business process delays
   - High: Significant business disruption
   - Critical: Business operations halted

2. **Financial Impact**
   - None: No financial impact
   - Low: Under $10,000
   - Moderate: $10,000 - $100,000
   - High: $100,000 - $1,000,000
   - Critical: Over $1,000,000

3. **Reputational Impact**
   - None: No reputational impact
   - Low: Internal awareness only
   - Moderate: Limited external awareness
   - High: Public awareness
   - Critical: Major media coverage

4. **Regulatory Impact**
   - None: No compliance implications
   - Low: Minor compliance implications
   - Moderate: Reportable incident
   - High: Potential regulatory penalties
   - Critical: Significant regulatory consequences

## Severity Escalation

### Automatic Escalation Thresholds

Incident severity should be automatically escalated if key thresholds are reached:

| Current Severity | Escalation Threshold | New Severity |
|------------------|----------------------|--------------|
| Low | 48 hours without resolution | Medium |
| Medium | 12 hours without resolution | High |
| High | 2 hours without resolution | Critical |

### Manual Escalation Criteria

Consider manual severity escalation when:

1. **Scope Expansion**
   - Additional systems found to be affected
   - Increased number of affected users/customers
   - New data types identified as compromised
   - Wider attack surface discovered

2. **Impact Intensification**
   - Greater business disruption than initially assessed
   - Higher financial impact discovered
   - Increased media or regulatory attention
   - More sensitive data involved than initially known

3. **Threat Evolution**
   - New attack vectors identified
   - More sophisticated attack tactics discovered
   - Persistence mechanisms found
   - Evidence of targeted rather than opportunistic attack

4. **Response Complications**
   - Ineffective containment efforts
   - Recovery complications
   - Repeated or recurring compromise
   - Additional vulnerabilities discovered
   - Failure of security controls

## Response Requirements

### Notification Requirements by Severity

| Severity | Initial Notification | Status Updates | Required Recipients |
|----------|---------------------|----------------|---------------------|
| Critical | Immediate (15 minutes) | Hourly | IR Manager, CISO, Legal, Executive Team |
| High | Within 1 hour | Every 4 hours | IR Manager, CISO, Security Team |
| Medium | Within 4 hours | Daily | IR Manager, Security Team |
| Low | Within 24 hours | Weekly | Security Team |

### Response Team Requirements

| Severity | Response Team | War Room | Status Meetings |
|----------|---------------|----------|----------------|
| Critical | Full IR team + executives | Yes (physical or virtual) | Every 2-4 hours |
| High | Full IR team | Yes (virtual) | Daily |
| Medium | IR lead + assigned responders | No | Weekly |
| Low | Assigned responder | No | As needed |

### Documentation Requirements

| Severity | Documentation Requirements | Review/Approval |
|----------|----------------------------|----------------|
| Critical | Full timeline, detailed impact assessment, comprehensive executive briefing, formal remediation plan | CISO, Legal Review |
| High | Detailed timeline, impact assessment, executive summary, remediation plan | IR Manager Review |
| Medium | Incident summary, basic timeline, remediation activities | Team Lead Review |
| Low | Basic incident record, key findings, remediation actions | Security Analyst Review |

## Implementation Reference

### Command Line Usage

```bash
# Initialize incident with proper severity
python -m admin.security.incident_response_kit.initialize \
  --incident-id IR-2023-042 \
  --severity high \
  --incident-type data_breach \
  --affected-systems "web-server-01,database-server-02" \
  --summary "Potential unauthorized access to customer database" \
  --notify

# Evaluate severity based on impact factors
python -m admin.security.incident_response_kit.evaluate_severity \
  --data-sensitivity high \
  --system-criticality high \
  --user-impact medium \
  --business-impact medium \
  --output severity_evaluation.json

# Update incident severity with reason
python -m admin.security.incident_response_kit.update_incident \
  --incident-id IR-2023-042 \
  --severity critical \
  --reason "Evidence of data exfiltration discovered" \
  --notify
```

### API Usage Example

```python
from admin.security.incident_response_kit import evaluate_incident_severity
from admin.security.incident_response_kit.incident_constants import IncidentSeverity, IncidentType

# Evaluate severity based on multiple factors
severity = evaluate_incident_severity(
    data_sensitivity="confidential",
    system_criticality="high",
    affected_users=250,
    business_impact="moderate",
    attack_complexity="medium",
    attack_vector="remote"
)

# Check severity and take appropriate actions
if severity >= IncidentSeverity.HIGH:
    # Implement high-severity response procedures
    notify_incident_management_team(severity=severity.name)
    create_war_room(virtual=True)

# Initialize incident with calculated severity
from admin.security.incident_response_kit import initialize_incident

incident = initialize_incident(
    title="Potential data breach via compromised credentials",
    incident_type=IncidentType.DATA_BREACH,
    severity=severity,
    affected_systems=["web-server-01", "database-server-01"],
    initial_details="Login anomalies detected with potential data access",
    detection_source="SIEM alert",
    assigned_to="security-team@example.com"
)
```

### Severity Scoring Using Risk Matrix

The severity scoring uses this risk matrix for evaluation:

| Likelihood/Impact | Critical | High | Medium | Low |
|------------------|----------|------|--------|-----|
| **Very Likely** | Critical | Critical | High | Medium |
| **Likely** | Critical | High | High | Medium |
| **Possible** | High | High | Medium | Low |
| **Unlikely** | High | Medium | Low | Low |

The risk matrix is implemented in the `calculate_risk_level()` method of the `RiskRating` class.

## Available Functions

### Severity Evaluation Functions

```python
from admin.security.incident_response_kit import (
    evaluate_incident_severity,
    update_incident_severity,
    calculate_risk_level,
    evaluate_impact,
    get_severity_sla
)
```

#### Severity Assessment Functions

- **`evaluate_incident_severity()`** - Calculate incident severity based on multiple factors
  - Parameters:
    - `data_sensitivity`: Sensitivity level of affected data
    - `system_criticality`: Criticality of affected systems
    - `affected_users`: Number of affected users
    - `business_impact`: Impact on business operations
    - `attack_complexity`: Complexity level of the attack
    - `attack_vector`: Attack vector used
  - Returns: Incident severity level from IncidentSeverity

- **`update_incident_severity()`** - Update severity of an existing incident
  - Parameters:
    - `incident_id`: ID of the incident to update
    - `new_severity`: New severity level
    - `reason`: Reason for severity change
    - `user_id`: ID of user making the change
    - `notify`: Whether to send notifications about change
  - Returns: Boolean indicating success or failure

- **`calculate_risk_level()`** - Calculate risk level based on impact and likelihood
  - Parameters:
    - `impact`: Impact level (critical, high, medium, low)
    - `likelihood`: Likelihood level (very_likely, likely, possible, unlikely)
  - Returns: Risk level (critical, high, medium, low)

- **`evaluate_impact()`** - Evaluate impact across multiple dimensions
  - Parameters:
    - `confidentiality_impact`: Impact to data confidentiality
    - `integrity_impact`: Impact to data integrity
    - `availability_impact`: Impact to system availability
    - `financial_impact`: Financial impact
    - `reputational_impact`: Reputational impact
    - `regulatory_impact`: Regulatory impact
  - Returns: Overall impact level

- **`get_severity_sla()`** - Get SLA timeframe for incident severity
  - Parameters:
    - `severity`: Incident severity level
  - Returns: SLA timeframe in hours

### Constants

```python
from admin.security.incident_response_kit.incident_constants import (
    IncidentSeverity,
    SEVERITY_REQUIRED_NOTIFICATIONS,
    ESCALATION_THRESHOLDS
)
```

- **`IncidentSeverity`** - Severity level constants
  - `CRITICAL`: Critical severity
  - `HIGH`: High severity
  - `MEDIUM`: Medium severity
  - `LOW`: Low severity

- **`SEVERITY_REQUIRED_NOTIFICATIONS`** - Required notifications by severity
  - Maps severity levels to sets of roles that must be notified

- **`ESCALATION_THRESHOLDS`** - Automatic escalation thresholds in hours
  - Maps current severity to hours before automatic escalation

## Best Practices & Security

- **Consistency**: Apply severity classification consistently across all incidents
- **Worst-Case Assessment**: When uncertain, classify based on the worst reasonable outcome
- **Continuous Reassessment**: Regularly reassess severity as new information becomes available
- **Clear Documentation**: Document the rationale for severity classifications
- **Avoid Downplaying**: Resist pressure to downgrade severity without valid justification
- **Collaborative Assessment**: Involve cross-functional input for complex incidents
- **Factor Weighting**: Give higher weight to customer impact and data sensitivity
- **Severity Agreement**: Ensure incident team agrees on severity classification
- **Regulatory Consideration**: Consider regulatory reporting requirements when classifying
- **Impact Focus**: Focus on realistic impact, not theoretical maximum impact
- **Pattern Recognition**: Consider patterns of similar incidents when classifying
- **External Factors**: Include external dependencies in impact assessment
- **Threat Intelligence**: Incorporate threat intelligence into severity assessment
- **Detection Timing**: Consider time since occurrence when assessing severity
- **Response Capacity**: Consider current response capacity when assessing severity

## Related Documentation

- Incident Response Plan - Overall incident response process
- Incident Response Kit Overview - Overview of the incident response toolkit
- Regulatory Requirements - Regulatory reporting requirements
- Privilege Escalation Detection Guide - Guide for detecting privilege escalation
- Evidence Collection Guide - Guide to proper evidence collection
- [NIST SP 800-61r2: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) - NIST guidance on incident handling
- Contact List - Emergency contact information
- Incident Timeline Template - Template for incident timeline
- Incident Report Template - Template for incident reporting
- Executive Briefing Template - Template for executive communication

---

**Document Information**

- Version: 1.1
- Last Updated: 2023-09-25
- Document Owner: Security Operations Team
- Review Schedule: Annual
- Classification: Internal Use Only
