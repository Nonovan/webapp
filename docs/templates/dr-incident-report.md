# Disaster Recovery Incident Report Template

## Incident Summary

**Report ID:** DR-[INCIDENT_ID]  
**Date of Incident:** [YYYY-MM-DD]  
**Time of Incident:** [HH:MM] UTC  
**Duration:** [X] hours [Y] minutes  
**Affected Region(s):** [PRIMARY/SECONDARY/BOTH]  
**Severity Level:** [CRITICAL/HIGH/MEDIUM/LOW]  
**Report Prepared By:** [NAME], [ROLE]  
**Report Date:** [YYYY-MM-DD]

## Incident Timeline

| Time (UTC) | Event | Action Taken | Personnel |
|------------|-------|--------------|-----------|
| YYYY-MM-DD HH:MM | Initial detection | Alert received via monitoring system | NOC Engineer |
| YYYY-MM-DD HH:MM | Incident declared | DR Team notified | DR Coordinator |
| YYYY-MM-DD HH:MM | DR Plan activated | Command center established | DR Team |
| YYYY-MM-DD HH:MM | Failover initiated | Executed dr-failover.sh | System Administrator |
| YYYY-MM-DD HH:MM | Database recovery | Verified database integrity | Database Administrator |
| YYYY-MM-DD HH:MM | Application recovery | Deployed application to DR environment | Application Team |
| YYYY-MM-DD HH:MM | Recovery validation | Executed health-check.sh | QA Team |
| YYYY-MM-DD HH:MM | DNS update | Redirected traffic to recovery environment | Network Administrator |
| YYYY-MM-DD HH:MM | Recovery completed | All services verified operational | DR Coordinator |
| YYYY-MM-DD HH:MM | Incident closed | Final validation completed | DR Coordinator |

## Impact Assessment

### Service Disruption

**Services Affected:**
- [List affected services]

**Impact Duration:**
- Total downtime: [X] hours [Y] minutes
- Degraded performance period: [X] hours [Y] minutes

### Recovery Metrics

**Recovery Time:**
- RTO Target: [X] hours
- Actual Recovery Time: [Y] hours
- Variance: [Z] hours [WITHIN/EXCEEDING] target

**Data Loss:**
- RPO Target: [X] minutes
- Actual Data Loss: [Y] minutes
- Variance: [Z] minutes [WITHIN/EXCEEDING] target

### Business Impact

**User Impact:**
- Estimated number of affected users: [NUMBER]
- Critical business functions impacted: [LIST]

**Financial Impact:**
- Estimated revenue impact: [AMOUNT]
- Additional operational costs: [AMOUNT]

## Root Cause Analysis

### Incident Cause

**Primary Cause:** [Brief description of the root cause]

**Contributing Factors:**
- [Factor 1]
- [Factor 2]
- [Factor 3]

### Failure Analysis

**System Components Involved:**
- [Component 1] - [Description of failure mode]
- [Component 2] - [Description of failure mode]

**Detection Mechanism:**
- How the incident was detected: [DESCRIPTION]
- Detection delay factors: [DESCRIPTION]

## Recovery Process

### Recovery Actions

**Infrastructure Recovery:**
- Actions taken: [DESCRIPTION]
- Tools/scripts used: [SCRIPT NAMES/PATHS]
- Effectiveness: [HIGH/MEDIUM/LOW]

**Data Recovery:**
- Backup source: [LOCATION/ID]
- Recovery method: [DESCRIPTION]
- Verification process: [DESCRIPTION]

**Application Recovery:**
- Deployment method: [DESCRIPTION]
- Configuration adjustments: [DESCRIPTION]
- Validation process: [DESCRIPTION]

### Challenges Encountered

- [Challenge 1]: [Description and resolution]
- [Challenge 2]: [Description and resolution]
- [Challenge 3]: [Description and resolution]

## Post-Recovery Assessment

### Recovery Effectiveness

**Recovery Plan Execution:**
- Plan elements that worked well: [DESCRIPTION]
- Plan elements that need improvement: [DESCRIPTION]

**Team Performance:**
- Communication effectiveness: [HIGH/MEDIUM/LOW]
- Role clarity: [HIGH/MEDIUM/LOW]
- Resource availability: [SUFFICIENT/INSUFFICIENT]

### Validation Results

**Security Validation:**
- Security controls verified: [LIST]
- Issues identified: [DESCRIPTION]
- Remediation actions: [DESCRIPTION]

**Data Validation:**
- Data integrity checks performed: [DESCRIPTION]
- Discrepancies found: [YES/NO] - [DESCRIPTION if YES]

**Application Validation:**
- Functionality tests performed: [DESCRIPTION]
- Performance metrics: [DESCRIPTION]

## Lessons Learned and Recommendations

### What Worked Well
- [Item 1]
- [Item 2]
- [Item 3]

### Areas for Improvement
- [Area 1]: [Specific improvement needed]
- [Area 2]: [Specific improvement needed]
- [Area 3]: [Specific improvement needed]

### Recommended Actions

| Action Item | Priority | Owner | Target Date | Status |
|-------------|----------|-------|-------------|--------|
| [Action 1] | [HIGH/MEDIUM/LOW] | [NAME] | [YYYY-MM-DD] | [PENDING/IN PROGRESS/COMPLETED] |
| [Action 2] | [HIGH/MEDIUM/LOW] | [NAME] | [YYYY-MM-DD] | [PENDING/IN PROGRESS/COMPLETED] |
| [Action 3] | [HIGH/MEDIUM/LOW] | [NAME] | [YYYY-MM-DD] | [PENDING/IN PROGRESS/COMPLETED] |
| Update DR plan with findings | HIGH | DR Coordinator | 2024-06-15 | PENDING |

## Documentation Updates Required

- [ ] Disaster Recovery Plan
- [ ] Runbooks/Procedures
- [ ] Contact Lists
- [ ] System Architecture Diagrams
- [ ] Backup Strategy
- [ ] Monitoring Configuration
- [ ] Training Materials

## Compliance and Reporting

**Regulatory Requirements:**
- Notifications required: [YES/NO]
- Regulations applicable: [LIST if YES]
- Notification status: [COMPLETED/PENDING]
- Documentation archived: [YES/NO]

**Internal Reporting:**
- Executive briefing date: [YYYY-MM-DD]
- Stakeholders notified: [LIST]
- Incident recorded in compliance register: [YES/NO]

## Incident Costs

**Direct Costs:**
- Recovery labor hours: [HOURS]
- Infrastructure costs: [AMOUNT]
- External assistance: [AMOUNT]

**Indirect Costs:**
- Estimated revenue impact: [AMOUNT]
- Customer impact cost: [AMOUNT]
- Reputational impact: [DESCRIPTION]

## Follow-up Schedule

| Action | Owner | Due Date | Status |
|--------|-------|----------|--------|
| 30-day implementation review | [NAME] | [YYYY-MM-DD] | [PENDING/COMPLETED] |
| 90-day effectiveness assessment | [NAME] | [YYYY-MM-DD] | [PENDING/COMPLETED] |
| Update DR plan with findings | [NAME] | [YYYY-MM-DD] | [PENDING/COMPLETED] |

## Attachments

- Network diagrams: [Link to Network Diagrams](https://cloud-platform.example.com/documents/dr/incident-123-network-diagrams.pdf)
- System logs: [Link to System Logs](https://cloud-platform.example.com/documents/dr/incident-123-system-logs.zip)
- Screenshots: [Link to Screenshots](https://cloud-platform.example.com/documents/dr/incident-123-screenshots.zip)
- Recovery process recordings: [Link to Recovery Recordings](https://cloud-platform.example.com/documents/dr/incident-123-recovery-recordings.mp4)
- Post-recovery test results: [Link to Test Results](https://cloud-platform.example.com/documents/dr/incident-123-test-results.pdf)

## Approvals

| Role | Name | Signature | Date |
|------|------|-----------|------|
| DR Coordinator | Jane Smith | ___________________ | YYYY-MM-DD |
| IT Director | Michael Johnson | ___________________ | YYYY-MM-DD |
| CISO | Sarah Williams | ___________________ | YYYY-MM-DD |
| CIO | Robert Chen | ___________________ | YYYY-MM-DD |
| Business Unit Owner | David Miller | ___________________ | YYYY-MM-DD |

## Distribution List

- Executive team
- Incident response team members
- IT operations team
- Business continuity team
- Risk management
- Customer relations (if customer-impacting)
- Compliance team
- Legal team
- Affected business units
- Third-party service providers (if involved)

## Document History

| Version | Date | Author | Description |
|---------|------|--------|-------------|
| 1.0 | YYYY-MM-DD | [Report Author] | Initial report creation |
| 1.1 | YYYY-MM-DD | [Report Author] | Updated with technical findings |
| 1.2 | YYYY-MM-DD | [Report Reviewer] | Review and final approval |