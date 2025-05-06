# Credential Compromise Remediation Guide

## Contents

- [Overview](#overview)
- [Password Reset Procedures](#password-reset-procedures)
- [Account Recovery Workflows](#account-recovery-workflows)
- [Multi-Factor Authentication Implementation](#multi-factor-authentication-implementation)
- [Session Invalidation Techniques](#session-invalidation-techniques)
- [Access Review Procedures](#access-review-procedures)
- [Service Token Rotation](#service-token-rotation)
- [Implementation Examples](#implementation-examples)
- [Best Practices & Security](#best-practices--security)
- [Common Pitfalls](#common-pitfalls)
- [Related Documentation](#related-documentation)

## Overview

This guide provides standardized procedures for remediating credential compromise incidents in the Cloud Infrastructure Platform. Credential compromise may occur through various attack vectors including phishing, password spraying, brute force attacks, credential stuffing, or malware. Proper remediation requires not only addressing the immediate compromise but also implementing measures to prevent reoccurrence.

## Password Reset Procedures

### Standard User Accounts

1. **Immediate Reset**
   - Reset password upon first indication of compromise
   - Do not reuse any part of previous passwords
   - Generate temporary password with sufficient entropy (16+ characters)
   - Set immediate password change requirement on next login
   - Document password reset with incident ID reference

2. **Notification Requirements**
   - Notify user through pre-established out-of-band method
   - Include reason for reset without revealing sensitive incident details
   - Provide instructions for secure password creation
   - Include contact information for assistance
   - Document all notification attempts

3. **Reset Verification**
   - Confirm password reset took effect across all systems
   - Verify password policy enforcement
   - Ensure password history prevents reuse
   - Check for secondary authentication factors
   - Document verification steps

### Privileged Accounts

1. **Additional Reset Requirements**
   - Reset all privileged accounts sharing similar access patterns
   - Implement higher-complexity temporary password (24+ characters)
   - Require in-person or video verification where possible
   - Reset associated emergency access accounts
   - Document all related account resets

2. **Additional Notification Requirements**
   - Notify account owner's manager
   - Notify security team lead
   - Include specific login restrictions during incident period
   - Outline additional monitoring implemented
   - Document all stakeholder notifications

3. **Access Reauthorization**
   - Require formal reauthorization of privileged access
   - Implement time-limited access where applicable
   - Consider just-in-time access model implementation
   - Document reauthorization approvals
   - Review least privilege requirements

### Service Accounts

1. **Reset Considerations**
   - Coordinate reset with application owners to minimize disruption
   - Prepare rollback procedures before reset
   - Implement higher complexity requirements (32+ random characters)
   - Consider maintenance window for critical services
   - Document all dependent applications and services

2. **Implementation Steps**
   - Update credential in secure vault first
   - Deploy new credential to dependent systems
   - Restart services to implement new credential
   - Verify functionality after reset
   - Document implementation timeline

3. **Rotation Procedures**
   - Establish regular rotation schedule post-incident
   - Implement automated rotation where possible
   - Document rotation procedures for future reference
   - Verify automated notification of rotation events
   - Test rotation procedures in non-production first

## Account Recovery Workflows

### Self-Service Recovery

1. **Recovery Method Requirements**
   - Require minimum of two verification factors
   - Include at least one out-of-band verification method
   - Implement progressive delays for repeated attempts
   - Log all recovery attempts with client information
   - Review logs for abnormal patterns

2. **Recovery Factors**
   - Avoid security questions with publicly available answers
   - Implement email verification with unique time-limited tokens
   - Consider SMS or authenticator app verification
   - Use pre-registered backup email addresses
   - Document all allowed recovery factors

3. **Recovery Limitations**
   - Restrict recovery for highly privileged accounts
   - Implement cool-down period between attempts
   - Consider geographic restrictions based on user profile
   - Limit number of recoveries within time period
   - Document all limitations and exceptions

### Administrator-Assisted Recovery

1. **Identity Verification Requirements**
   - Establish tiered verification based on account privilege level
   - Require manager approval for sensitive accounts
   - Implement standard verification script to ensure consistency
   - Document verification factors checked
   - Record verification method used

2. **Recovery Documentation Requirements**
   - Document date and time of recovery request
   - Record identity verification method used
   - Note approving administrator
   - Reference ticket or incident number
   - Create audit log entry with complete details

3. **Revocation Procedure**
   - Establish process to revoke access if compromise discovered
   - Implement automated alert for suspicious recovery patterns
   - Create emergency access revocation playbook
   - Test revocation procedures regularly
   - Document revocation authority and procedures

### Post-Recovery Monitoring

1. **Enhanced Monitoring Period**
   - Implement additional logging for recovered accounts
   - Set minimum 30-day enhanced monitoring period
   - Create baseline of normal activity for comparison
   - Configure alerts for behavioral anomalies
   - Document monitoring procedures and duration

2. **Alert Configuration**
   - Set alerts for access pattern changes
   - Monitor for unusual geographic access
   - Track sensitive resource access
   - Alert on administrative action usage
   - Document all alert thresholds

3. **Review Requirements**
   - Conduct 7-day review of account activity
   - Require account owner acknowledgment of activity
   - Document review process and findings
   - Schedule follow-up review at 30 days
   - Create incident linkage for any anomalies

## Multi-Factor Authentication Implementation

### MFA Deployment

1. **Factor Selection**
   - Select appropriate factors based on risk assessment:
     - Standard users: Minimum of one additional factor
     - Privileged users: Minimum of two additional factors
     - High-value assets: Consider hardware security keys
   - Avoid SMS where possible for high-security contexts
   - Document factor selection rationale

2. **Implementation Steps**

   ```python
   # Example implementation using core security module
   from core.security import enforce_mfa

   # For a single user after compromise
   enforce_mfa(
       username="compromised_user",
       methods=["totp", "backup_codes"],
       grace_period_hours=0,  # Immediate enforcement
       allow_exceptions=False,
       reason="Post-compromise remediation"
   )

   # For a group of similar users
   enforce_mfa(
       group="finance_department",
       methods=["totp", "backup_codes"],
       grace_period_hours=24,  # 24-hour grace period
       allow_exceptions=True,
       exception_approval="security_manager",
       reason="Security enhancement after similar account compromise"
   )
   ```

3. **Enrollment Verification**
   - Verify successful factor registration
   - Test authentication with new factors
   - Confirm backup factor registration
   - Document enrollment completion
   - Monitor for failed MFA attempts

### MFA Recovery Planning

1. **Backup Methods**
   - Require registration of multiple authentication factors
   - Implement backup codes for emergency access
   - Consider hardware backup keys for critical accounts
   - Document all registered backup methods
   - Store backup method information securely

2. **Lockout Recovery**
   - Establish clear MFA lockout recovery procedures
   - Define authentication requirements for recovery
   - Document required approvals for lockout override
   - Create secure storage for recovery credentials
   - Test recovery procedures regularly

3. **Bypass Monitoring**
   - Log all MFA bypass events
   - Require justification for any MFA exceptions
   - Implement time-limited bypasses only
   - Alert on multiple bypass attempts
   - Document all approved exceptions

### MFA Hardening

1. **Configuration Requirements**
   - Set minimum standards for each factor type
   - Define TOTP requirements (minimum 6 digits)
   - Specify hardware key requirements (FIDO2/WebAuthn)
   - Establish push notification timeout limits
   - Document all configuration settings

2. **Advanced Protection**
   - Implement phishing-resistant factors for privileged accounts
   - Consider location or device-based step-up authentication
   - Enable login attempt velocity controls
   - Set notification requirements for authentication events
   - Document advanced protection measures

3. **Security Review Schedule**
   - Establish quarterly review of MFA configurations
   - Conduct annual risk assessment of factor security
   - Document emerging threats to authentication factors
   - Test MFA implementations against threat models
   - Update procedures based on review findings

## Session Invalidation Techniques

### Immediate Session Termination

1. **Application Sessions**

   ```python
   # Example of session termination using core security module
   from core.security import terminate_user_sessions

   # Terminate all sessions for a specific user
   terminate_user_sessions(
       username="compromised_user",
       reason="Security incident response",
       notify=True,  # Notify user of termination
       log_details=True  # Create detailed audit log
   )

   # Terminate specific session by ID
   terminate_user_sessions(
       session_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
       reason="Suspicious activity detected",
       notify=True,
       log_details=True
   )
   ```

2. **Web Sessions**
   - Invalidate all active cookies and tokens
   - Update session tracking database
   - Clear cached session data
   - Force re-authentication on next request
   - Document all session termination actions

3. **API Token Sessions**
   - Revoke all active access tokens
   - Update token blacklists
   - Implement token revocation checks
   - Force new token issuance
   - Document all revoked tokens

### Verification Methods

1. **Session Termination Validation**
   - Verify session database records are updated
   - Confirm authentication system reflects changes
   - Test access attempts with previous sessions
   - Check application caches for stale session data
   - Document verification results

2. **Distributed System Considerations**
   - Ensure propagation of session revocation
   - Check all nodes in distributed systems
   - Verify CDN cache invalidation
   - Confirm API gateway configurations
   - Document system-wide validation steps

3. **Monitoring Requirements**
   - Monitor for continued activity post-invalidation
   - Set alerts for suspicious authentication attempts
   - Track session creation patterns
   - Review logs for unauthorized access attempts
   - Document monitoring configuration

### Session Hardening

1. **Session Configuration Updates**
   - Review and reduce session timeout values
   - Implement idle session termination
   - Configure automatic session refreshing requirements
   - Set absolute session lifetime limits
   - Document all updated settings

2. **Security Enhancement Implementation**

   ```python
   # Example of session security enhancements
   from core.security import update_session_policy

   # Update session policy for an application
   update_session_policy(
       application="customer_portal",
       idle_timeout_minutes=15,
       absolute_timeout_minutes=240,  # 4 hour maximum
       enforce_ip_binding=True,
       enforce_device_binding=True,
       require_reauthentication_for_sensitive_operations=True,
       reason="Post-incident security enhancement"
   )
   ```

3. **Advanced Session Protection**
   - Implement session binding to IP address
   - Consider device fingerprinting for critical applications
   - Enable step-up authentication for sensitive operations
   - Add session anomaly detection
   - Document all protection measures

## Access Review Procedures

### Emergency Access Review

1. **Initial Review**
   - Review all permissions of compromised account
   - Identify over-privileged access
   - Document all access roles and permissions
   - Determine business necessity for each access
   - Flag permissions for removal or adjustment

2. **Access Modification**

   ```python
   # Example of access review implementation
   from core.security import review_user_permissions

   # Generate comprehensive access report
   access_report = review_user_permissions(
       username="compromised_user",
       include_group_permissions=True,
       include_inherited_permissions=True,
       include_historical_changes=True,
       output_format="detailed"
   )

   # Apply least privilege adjustments
   from core.security import adjust_user_permissions

   adjustment_result = adjust_user_permissions(
       username="compromised_user",
       permission_adjustments=[
           {"resource": "customer_database", "action": "remove", "permission": "write_access"},
           {"resource": "financial_reports", "action": "downgrade", "from": "owner", "to": "viewer"}
       ],
       reason="Post-compromise least privilege enforcement",
       approval_id="IR-2023-042",
       notify_user=True
   )
   ```

3. **Validation Requirements**
   - Verify access changes took effect
   - Test user login with new permissions
   - Confirm business functions still operational
   - Document access change validation
   - Schedule follow-up review after incident

### Broader Access Review

1. **Similar Role Review**
   - Identify accounts with similar roles
   - Review permissions for all accounts in same groups
   - Document over-privileged access patterns
   - Create remediation plan for identified issues
   - Prioritize critical access adjustments

2. **Access Pattern Analysis**
   - Review historical access patterns
   - Identify unused permissions
   - Document access usage statistics
   - Look for permission creep indications
   - Create unused permission removal plan

3. **Role Definition Updates**
   - Review and update role definitions
   - Implement more granular roles if needed
   - Document role changes and rationale
   - Create migration plan for existing users
   - Test new role definitions for functionality

### Continuous Access Governance

1. **Automated Review Implementation**
   - Configure scheduled access reviews
   - Implement manager approval workflows
   - Set up automated notifications for reviews
   - Document review procedures and frequency
   - Create metrics for review completion

2. **Just-in-Time Access**

   ```python
   # Example of implementing just-in-time access
   from core.security import configure_jit_access

   # Configure JIT access for privileged operations
   jit_config = configure_jit_access(
       group="database_administrators",
       resources=["production_database", "customer_records"],
       max_access_duration_hours=4,
       require_justification=True,
       approver_group="security_managers",
       log_all_activities=True,
       reason="Post-incident security enhancement"
   )
   ```

3. **Risk-Based Access Controls**
   - Implement risk scoring for access requests
   - Configure additional verification for high-risk access
   - Develop dynamic access policies
   - Document risk-based access control framework
   - Test risk assessment algorithms

## Service Token Rotation

### API Key Management

1. **Inventory Requirements**
   - Identify all API keys in use
   - Document purpose, owner, and access scope
   - Locate all storage locations and files
   - Map application dependencies
   - Create rotation priority list

2. **Rotation Process**

   ```python
   # Example of API key rotation implementation
   from core.security import rotate_api_key

   # Rotate a specific API key with minimal disruption
   new_key_info = rotate_api_key(
       key_id="apk_123456789",
       grace_period_hours=24,  # Keep old key valid for 24 hours
       notification_recipients=["api_owner@example.com", "security@example.com"],
       reason="Scheduled post-incident security enhancement",
       update_references=True  # Attempt to update references in code repositories
   )

   # Output new key information securely to authorized user only
   print(f"New Key ID: {new_key_info['key_id']}")
   print(f"Old key deactivation date: {new_key_info['deactivation_date']}")
   ```

3. **Validation Requirements**
   - Test applications with new keys
   - Verify proper functionality
   - Confirm old key deactivation
   - Document validation steps
   - Monitor for failed API requests

### OAuth Token Management

1. **Token Revocation**
   - Identify all affected tokens
   - Implement immediate revocation
   - Update token blacklists
   - Force reauthentication flows
   - Document all revoked tokens

2. **Configuration Updates**
   - Reduce token lifetime values
   - Implement stricter scope limitations
   - Review redirect URI restrictions
   - Update client application verification
   - Document all configuration changes

3. **Enhanced Monitoring**
   - Implement token usage analytics
   - Set up anomaly detection for token usage
   - Configure alerts for unusual token activity
   - Document monitoring configuration
   - Test detection capabilities

### Secret Management Integration

1. **Centralized Secret Storage**
   - Migrate credentials to secure secret storage
   - Set up automated rotation where possible
   - Implement least privilege for secret access
   - Configure audit logging for all access
   - Document secret storage architecture

2. **Implementation Example**

   ```python
   # Example of secret manager integration
   from core.security import register_with_secret_manager

   # Register credential with secret manager
   secret_info = register_with_secret_manager(
       name="database_api_credential",
       value="current-credential-value",
       description="Production database API access key",
       rotation_schedule="30d",  # 30-day rotation
       access_groups=["db_admins"],
       auto_rotation=True,
       application_references=["inventory_service", "reporting_system"],
       reason="Security enhancement post-incident"
   )
   ```

3. **Application Integration**
   - Update applications to use secret manager
   - Implement credential fetching at runtime
   - Remove hardcoded credentials
   - Configure proper error handling
   - Document integration approach

## Implementation Examples

### Password Reset Implementation

```python
# Example for bulk credential reset after potential compromise
from core.security import mass_credential_reset
from core.security.cs_authentication import require_password_change

# Reset credentials for a group of users with similar risk profile
reset_results = mass_credential_reset(
    user_group="marketing_department",
    reset_type="temporary_password",
    notification_method="email",
    reset_reason="Security precaution due to potential credential exposure",
    track_notification_delivery=True,
    include_security_guidance=True
)

# Force password change for specific users
for username in ["user1", "user2", "user3"]:
    require_password_change(
        username=username,
        immediate=True,
        bypass_history_check=False,
        reason="Post-incident security measure"
    )

# Review results
print(f"Reset initiated for {reset_results['success_count']} users")
print(f"Failed resets: {reset_results['failed_count']}")
if reset_results['failed_count'] > 0:
    for failure in reset_results['failures']:
        print(f"Failed to reset {failure['username']}: {failure['reason']}")
```

### Session Invalidation Implementation

```python
# Example for targeted session invalidation
from core.security import get_active_sessions, revoke_session
from core.security.cs_session import terminate_all_sessions_for_user

# Get all active sessions for a specific IP range
suspicious_ip_sessions = get_active_sessions(
    ip_range="203.0.113.0/24",
    include_details=True,
    created_after="2023-06-01T00:00:00Z"
)

# Revoke specific sessions
for session in suspicious_ip_sessions:
    revoke_session(
        session_id=session['id'],
        reason=f"Suspicious IP address {session['ip_address']}",
        log_event=True
    )

# Force regeneration of all session tokens for a specific user
terminate_all_sessions_for_user(
    username="compromised_account",
    reason="Account compromise remediation",
    notify_user=True
)
```

### MFA Enforcement Implementation

```python
# Example for enforcing MFA after a credential compromise incident
from core.security import enforce_mfa_for_group
from core.security.cs_constants import MFA_ENFORCEMENT_LEVELS

# Apply enhanced MFA requirements to all users in a department
result = enforce_mfa_for_group(
    group_name="finance_department",
    enforcement_level=MFA_ENFORCEMENT_LEVELS.HIGH,
    grace_period_days=2,
    notification_message="Due to recent security events, additional authentication is now required for your account.",
    allowed_methods=["app_totp", "hardware_key"],
    require_multiple_factors=True
)

# Check results
print(f"MFA enforcement applied to {result['affected_users']} users")
print(f"Excluded users: {result['excluded_users']}")
```

## Best Practices & Security

- **Credential Segregation**: Use different credential types for different security contexts
- **Layered Authentication**: Implement multiple verification factors for high-value assets
- **Context-Aware Access**: Consider location, device, and behavior in access decisions
- **Recovery Planning**: Always establish secure recovery paths before implementing new controls
- **Default Denial**: Design systems to deny access by default and require explicit grants
- **Least Privilege**: Grant minimum permissions needed for function, not convenience
- **Automation**: Automate credential rotation and review processes where possible
- **Monitoring Integration**: Ensure all credential changes generate appropriate audit logs
- **Change Verification**: Validate all credential changes with independent verification
- **Response Preparation**: Maintain ready-to-use playbooks for credential compromise scenarios
- **Activity Logging**: Maintain comprehensive logs of all credential and session activities
- **Anomaly Detection**: Implement behavior-based anomaly detection for credential usage
- **Secure Defaults**: Configure security-focused defaults that require explicit opt-out
- **Documentation**: Maintain clear documentation of all credential management procedures
- **Regular Testing**: Periodically test recovery and remediation procedures

## Common Pitfalls

1. **Overlooking Dependencies**
   - Service account changes affecting multiple systems
   - Middleware using cached credentials
   - Automated jobs with embedded credentials
   - Mobile applications with stored tokens
   - Integration points with partners or third-party services

2. **Incomplete Remediation**
   - Failing to revoke all related sessions
   - Missing secondary authentication factors
   - Overlooking similar accounts or shared credentials
   - Incomplete token revocation across systems
   - Focusing only on direct compromise indicators

3. **Business Disruption Risks**
   - Implementing changes during peak business hours
   - Insufficient testing of credential rotation
   - Lack of rollback procedures
   - Incomplete stakeholder notification
   - Inadequate support resources during transition

4. **Security Gaps**
   - Sending new credentials through compromised channels
   - Using weak temporary passwords
   - Setting excessively long grace periods
   - Implementing similar vulnerable authentication patterns
   - Relying on security questions for recovery

5. **Process Failures**
   - Inadequate documentation of changes
   - Missing verification steps
   - Incomplete incident correlation
   - Poor communication between technical teams
   - Lack of follow-up validation

## Related Documentation

- Account Compromise Playbook
- Unauthorized Access Playbook
- Data Breach Playbook
- Privilege Escalation Detection Guide
- Evidence Collection Guide
- User Activity Monitoring Guide
- Application Authentication Security Guidelines
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- Core Security Authentication Module Documentation
- Core Security Session Management Documentation
- Core API Security Guidelines

---

**Document Information**
Version: 1.0
Last Updated: 2023-09-15
Document Owner: Security Engineering Team
Review Schedule: Quarterly
Classification: Internal Use Only
