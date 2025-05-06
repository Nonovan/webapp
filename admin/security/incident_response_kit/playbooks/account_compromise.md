# Account Compromise Response Playbook

## Incident Overview

This playbook provides structured procedures for responding to account compromise incidents in the Cloud Infrastructure Platform. Account compromise incidents involve unauthorized access to user accounts through credential theft, session hijacking, or other malicious means.

### Severity Classification Guidelines

| Severity | Description |
|----------|-------------|
| **Critical** | Privileged account compromise (admin, service account) with confirmed malicious activity |
| **High** | User account compromise with confirmed malicious activity or privileged account compromise with suspected access |
| **Medium** | User account compromise with no confirmed malicious activity or suspicious failed access to privileged accounts |
| **Low** | Suspicious failed login attempts with no evidence of successful compromise |

### Common Indicators of Compromise

- Unusual login times or locations
- Multiple failed login attempts followed by a successful login
- Session anomalies (e.g., multiple concurrent sessions)
- Unauthorized account modifications
- Unusual account activity patterns
- Password reset or MFA configuration changes
- Access from unusual IP addresses or user agents
- Unexpected privileged operations
- Authentication from new devices
- Suspicious API token usage

### Potential Business Impact

- Unauthorized data access or exfiltration
- System compromise through lateral movement
- Business service disruption
- Regulatory compliance violations
- Reputational damage
- Financial loss through fraud
- Operational disruption

### Required Response Team Roles

- **Security Analyst**: Lead investigation and response coordination
- **System Administrator**: Implement technical controls and gather evidence
- **Identity/Access Management**: Support account analysis and remediation
- **Legal/Compliance**: Advise on notification requirements and evidence handling
- **Communications Lead**: For incidents requiring stakeholder communication
- **Executive Sponsor**: For high/critical severity incidents

## Detection and Identification

### Detection Sources

- Security Information and Event Management (SIEM) alerts
- Login anomaly detection systems
- User reports of unexpected activity
- Failed login attempt patterns
- Multi-factor authentication failures
- Data Loss Prevention (DLP) alerts
- Unusual permission changes
- Unexpected password resets
- Identity Protection alerts
- Suspicious API usage patterns

### Initial Triage Procedures

1. **Gather Initial Information**
   - Identify affected user account(s)
   - Determine account type and privileges
   - Document reported anomalies or suspicious activities
   - Record detection method and time of discovery
   - Identify related systems accessed by the account

2. **Assess Scope and Severity**
   - Determine account privilege level
   - Identify potentially affected systems or data
   - Check for related suspicious activities
   - Establish initial severity rating
   - Create incident ticket with [`initialize_incident`](../initialize.py)

3. **Assign Response Team**
   - Assemble appropriate team based on severity
   - Designate incident lead
   - Establish communication channel
   - Schedule initial briefing

### Key Artifacts and Log Sources

- **Authentication Logs**
  - Directory service logs (Active Directory, LDAP)
  - VPN access logs
  - Application authentication logs
  - Single Sign-On (SSO) logs
  - Cloud provider access logs
  - MFA service logs

- **Activity Logs**
  - User session records
  - Command history
  - Database query logs
  - API access logs
  - File access logs
  - Access control changes
  - Permission modifications

- **System Logs**
  - System event logs
  - Security audit logs
  - Application logs
  - Network device logs
  - Cloud service logs
  - Endpoint Detection and Response (EDR) logs

### Verification Steps

1. **Review Authentication History**
   - Verify login times, locations, and IP addresses
   - Check for unusual patterns or anomalies
   - Compare with user's normal behavior patterns
   - Document all suspicious login events
   - Use [`analyze_logs`](../log_analyzer.py) to search for suspicious patterns

2. **Examine Account Activity**
   - Review actions taken while logged in
   - Look for unusual commands or queries
   - Check for permission changes or credential modifications
   - Identify resource access patterns
   - Review sensitive data access

3. **Validate User Activity**
   - Contact account owner if appropriate
   - Verify if observed activity was legitimate
   - Confirm working hours and locations
   - Document any travel or unusual circumstances
   - Validate expected device usage

4. **Timeline Construction**
   - Construct timeline of events using [`build_timeline`](../forensic_tools/timeline_builder.py)
   - Correlate authentication events with account activity
   - Identify initial access vector if possible
   - Map activity sequence across systems
   - Document timeline for incident report

### False Positive Checks

- Verify if activity correlates with planned maintenance
- Check for recent password resets or account changes initiated by user
- Validate if user was working remotely or traveling
- Confirm if shared credentials are being used legitimately
- Check for recent MFA enrollment or authentication method changes
- Review if security tools were recently updated or misconfigured
- Verify if VPN or proxy usage could explain unusual locations

## Containment

### Immediate Containment Actions

1. **Lock Compromised Account(s)**

   ```python
   # Access account management system to lock affected accounts
   # Replace with actual implementation in your environment
   from core.security import lock_user_account

   # Lock the compromised account
   lock_user_account(username="compromised_user",
                     reason="Security incident #IR-2023-042",
                     duration="indefinite")
   ```

2. **Revoke Active Sessions**

   ```python
   # Terminate all active sessions for the compromised account
   # Replace with actual implementation in your environment
   from core.security import terminate_user_sessions

   # Force logout all sessions
   terminate_user_sessions(username="compromised_user",
                          reason="Security incident response")
   ```

3. **Preserve Authentication Evidence**

   ```python
   # Collect authentication logs before they expire
   from admin.security.incident_response_kit import collect_evidence

   # Collect authentication logs for incident investigation
   collect_evidence(incident_id="IR-2023-042",
                   evidence_types=["auth_logs", "session_data"],
                   target_account="compromised_user",
                   time_range="48h")
   ```

4. **Reset API Keys and Tokens**

   ```python
   # Revoke all API keys and access tokens for the account
   # Replace with actual implementation in your environment
   from core.security import revoke_user_tokens

   # Revoke all access tokens
   revoke_user_tokens(username="compromised_user")
   ```

5. **Block Suspicious IPs**

   ```python
   # Add suspicious IPs to blocklist if detected
   from admin.security.incident_response_kit import network_isolation

   # Block suspicious IPs at the firewall/WAF level
   network_isolation.block_ip_addresses(ip_list=["203.0.113.42", "198.51.100.73"],
                                        reason="Account compromise #IR-2023-042",
                                        duration="14d")
   ```

### System Isolation Procedures

If the compromised account accessed critical systems or shows evidence of lateral movement:

1. **Identify Affected Systems**
   - Review access logs to identify all systems accessed by compromised account
   - Determine potential lateral movement paths
   - Identify connected systems at risk

2. **Isolate Critical Systems**

   ```python
   # Isolate affected systems using network isolation tool
   from admin.security.incident_response_kit import isolate_system

   # Isolate suspected compromised systems
   isolate_system(target="web-server-01",
                 isolation_method="acl",
                 allow_ip="10.0.0.5", # Security workstation
                 duration="8h")
   ```

3. **Enable Enhanced Monitoring**
   - Deploy additional logging on systems accessed by compromised account
   - Configure alerts for suspicious activities on connected systems
   - Increase retention period for relevant logs

### Evidence Preservation Steps

1. **Capture Authentication Logs**

   ```python
   # Use log analyzer to collect and analyze authentication logs
   from admin.security.incident_response_kit import analyze_logs

   # Analyze authentication logs for signs of compromise
   results = analyze_logs(
       log_paths=["/var/log/auth.log", "/var/log/secure", "/var/log/syslog"],
       pattern_type="unauthorized_access",
       start_time="2023-01-15T00:00:00Z",
       end_time="2023-01-16T00:00:00Z",
       output_dir="/secure/evidence/IR-2023-042/auth_logs"
   )
   ```

2. **Capture Session Activities**

   ```python
   # Collect user session data with proper chain of custody
   from admin.security.incident_response_kit import collect_evidence

   # Collect session data and command history
   collect_evidence(incident_id="IR-2023-042",
                  evidence_types=["command_history", "session_data", "file_access"],
                  target_user="compromised_user",
                  time_range="48h")
   ```

3. **Create Chain of Custody Documentation**
   - Document all evidence collected
   - Record timestamps and collection methods
   - Maintain proper chain of custody
   - Use [`verify_file_integrity`](../forensic_tools/file_integrity.py) on all collected evidence

### Communication Requirements

1. **Internal Notification**

   ```python
   # Notify necessary stakeholders using notification system
   from admin.security.incident_response_kit import notify_stakeholders

   # Send notification to security team
   notify_stakeholders(
       incident_id="IR-2023-042",
       message="Account compromise detected for user jdoe. Investigation in progress.",
       recipients=["security-team", "it-management"],
       channels=["email", "slack"],
       severity="high"
   )
   ```

2. **Executive Communication**
   - For high/critical severity incidents, prepare executive briefing
   - Use executive briefing template from [templates/executive_briefing.md](../templates/executive_briefing.md)

3. **Legal/Compliance Communication**
   - If sensitive data was potentially accessed, notify legal team
   - Prepare for potential regulatory notifications
   - Document communication for incident record

## Eradication

### Root Cause Identification

1. **Determine Compromise Vector**
   - Analyze how credentials were compromised (phishing, malware, etc.)
   - Check for publicly exposed credentials
   - Review for evidence of brute force or password spraying
   - Identify specific vulnerability exploited
   - Look for signs of social engineering or insider threat

2. **Analyze Attacker Actions**
   - Document specific actions taken by attacker
   - Identify accessed systems and data
   - Determine persistence mechanisms if any
   - Review any data potentially exfiltrated
   - Map full scope of compromise

3. **Determine Extent of Compromise**
   - Identify all affected systems and accounts
   - Check for unauthorized account creation
   - Look for privilege escalation or permission changes
   - Review for scheduled tasks or persistence mechanisms
   - Check for signs of lateral movement

### Threat Removal Procedures

1. **Reset Credentials**

   ```python
   # Reset credentials for affected accounts
   # Replace with actual implementation in your environment
   from core.security import reset_user_credentials

   # Reset to temporary password and require change on next login
   reset_user_credentials(username="compromised_user",
                          require_reset=True,
                          notify_user=True)
   ```

2. **Remove Unauthorized Access**
   - Delete any unauthorized accounts created
   - Revert unauthorized permission changes
   - Remove any scheduled tasks or persistence mechanisms
   - Reset any modified security settings

3. **Implement MFA Enforcement**

   ```python
   # Enforce MFA for affected account or group
   # Replace with actual implementation in your environment
   from core.security import enforce_mfa

   # Enable MFA requirement
   enforce_mfa(username="compromised_user",
               methods=["totp", "backup_codes"],
               grace_period_hours=0)  # Immediate enforcement
   ```

4. **Remove Malicious Content**
   - Scan for and remove any malware or unauthorized tools
   - Delete unauthorized files or scripts
   - Remove malicious email rules or forwarding
   - Check for data staging locations

### Affected Systems Validation

1. **Verify Clean System State**

   ```python
   # Scan systems for indicators of compromise
   from admin.security.incident_response_kit import verify_file_integrity

   # Verify integrity of critical system files
   results = verify_file_integrity(
       system="web-server-01",
       baseline="/secure/baselines/web-server-01.json",
       report_path="/secure/evidence/IR-2023-042/integrity_verification.json"
   )
   ```

2. **Verify Account Security**
   - Confirm all account settings are correct
   - Verify no unexpected authorized devices
   - Check login history after remediation
   - Validate MFA is properly configured

3. **Review API Access**
   - Verify all API keys have been rotated
   - Confirm no unauthorized tokens remain active
   - Check integration permissions
   - Validate third-party access

### Security Gap Closure

1. **Update Authentication Policies**
   - Implement or enhance password policy requirements
   - Enforce MFA for similar account types if not already required
   - Review session timeout settings
   - Implement geographic login restrictions if appropriate

2. **Enhance Monitoring**
   - Set up alerts for similar patterns
   - Monitor for the specific attack pattern identified
   - Implement additional logging if needed
   - Review detection capabilities

3. **Address Identified Vulnerabilities**
   - Patch systems related to the compromise
   - Fix misconfigurations that enabled the attack
   - Update security controls as needed
   - Document all security improvements

## Recovery

### System Restoration Procedures

1. **Validate Account Integrity**
   - Confirm account settings and permissions are correct
   - Verify expected access levels
   - Check for any remaining unauthorized changes
   - Validate security controls are functioning

2. **Return Systems to Production**

   ```python
   # If systems were isolated, return to production
   from admin.security.incident_response_kit import restore_service

   # Restore service with proper validation
   restore_service(
       target="web-server-01",
       verification_checks=["security_controls", "app_functionality", "network_connectivity"],
       approval_required=True
   )
   ```

3. **Unlock User Account**

   ```python
   # Unlock account after validation
   # Replace with actual implementation in your environment
   from core.security import unlock_user_account

   # Unlock with admin approval
   unlock_user_account(
       username="compromised_user",
       approver="security-analyst@example.com",
       reason="Recovery completed after account compromise"
   )
   ```

### Verification Testing Steps

1. **Security Control Validation**

   ```python
   # Verify security controls are properly implemented
   from admin.security.incident_response_kit.recovery.resources.verification_scripts import security_controls

   # Run verification tests
   results = security_controls.verify(
       target="user_management",
       checks=["mfa_enforcement", "password_policy", "session_controls"]
   )
   ```

2. **Activity Monitoring**
   - Monitor account activity for any anomalies
   - Verify logging is properly capturing events
   - Confirm alerts are functioning
   - Test security controls

3. **Authentication Testing**
   - Verify MFA is functioning correctly
   - Test password policy enforcement
   - Validate session management
   - Confirm account lockout functionality

### Monitoring Requirements

1. **Enhanced User Monitoring**
   - Implement additional logging for the affected account
   - Set up alerts for unusual behavior
   - Monitor for access pattern changes
   - Track sensitive data access

2. **System Monitoring**
   - Monitor affected systems for unusual activity
   - Implement additional logging for related systems
   - Set up alerts for similar attack patterns
   - Track authentication events closely

3. **Suspicious Activity Detection**
   - Configure alerts for indicators identified during the investigation
   - Monitor for similar attack patterns
   - Watch for potential recompromise attempts
   - Track API and service usage

### Business Continuity Coordination

1. **User Communication**
   - Notify user of account restoration
   - Provide guidance on secure account usage
   - Explain security enhancements implemented
   - Set expectations for monitoring

2. **Service Restoration Notification**
   - Notify stakeholders of service restoration
   - Communicate any remaining limitations
   - Provide timeline for full recovery
   - Document business impact duration

## Post-Incident Activities

### Incident Documentation Requirements

1. **Complete Incident Report**
   - Document complete timeline of events
   - Record all response actions taken
   - Document systems and data affected
   - Record business impact

2. **Update Security Documentation**
   - Update relevant security procedures
   - Document new detection capabilities
   - Record lessons learned
   - Update playbooks if needed

3. **Generate Formal Report**

   ```python
   # Generate incident report using the toolkit
   from admin.security.incident_response_kit import generate_report

   # Create comprehensive incident report
   report_path = generate_report(
       incident_id="IR-2023-042",
       report_type="complete",
       output_format="pdf",
       include_timeline=True,
       include_evidence=True
   )
   ```

### Lessons Learned Template

1. **What Went Well**
   - Detection capabilities that functioned properly
   - Effective response procedures
   - Successful containment actions
   - Team collaboration successes

2. **What Could Be Improved**
   - Detection gaps or delays
   - Response inefficiencies
   - Communication challenges
   - Tool limitations

3. **Recommended Improvements**
   - Detection enhancements
   - Process improvements
   - Tool improvements
   - Training needs

### Security Improvement Recommendations

1. **Technical Controls**
   - Implement or enhance MFA requirements
   - Improve session management
   - Enhance logging and monitoring
   - Deploy additional detection controls

2. **Policy Updates**
   - Revise authentication policies
   - Update account management procedures
   - Enhance access review process
   - Improve incident response procedures

3. **User Education**
   - Enhance security awareness training
   - Provide guidance on credential protection
   - Train on identifying phishing attempts
   - Educate on secure account practices

### Metrics and KPI Tracking

1. **Response Metrics**
   - Time to detection
   - Time to containment
   - Time to eradication
   - Time to recovery
   - Total incident duration

2. **Impact Metrics**
   - Number of affected accounts
   - Systems impacted
   - Data potentially accessed
   - Business operations affected
   - Recovery resource requirements

## References and Resources

### Related Playbooks

- [Data Breach Response Playbook](data_breach.md)
- [Malware Incident Playbook](malware_incident.md)
- [Privilege Escalation Playbook](privilege_escalation.md)
- [Unauthorized Access Playbook](unauthorized_access.md)

### External Resources

- [NIST SP 800-61r2: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS Incident Handler's Handbook](https://www.sans.org/reading-room/whitepapers/incident/incident-handlers-handbook-33901)
- [MITRE ATT&CK Framework - Initial Access Techniques](https://attack.mitre.org/tactics/TA0001/)
- [CISA Authentication Mechanisms Guide](https://www.cisa.gov/sites/default/files/publications/CISA_MS-ISAC_SixStepsToSecureRemoteAccess_508C.pdf)

### Internal Resources

- [Chain of Custody Template](../templates/chain_of_custody.md)
- [Executive Briefing Template](../templates/executive_briefing.md)
- [Incident Report Template](../templates/incident_report.md)
- [Evidence Collection Guide](../references/evidence_collection_guide.md)
