# Authentication and Authorization Models

## Overview

This directory contains the database models and utilities for the Cloud Infrastructure Platform's authentication and authorization system. It implements a comprehensive Role-Based Access Control (RBAC) framework with hierarchical roles, fine-grained permissions, activity tracking, and session management.

The authentication system provides robust security features including password management, multi-factor authentication, brute force protection, and detailed audit logging to meet enterprise security requirements and compliance standards.

## Key Components

- **`User`**: Core user model with authentication, profile management, and security features
  - Secure password management with hashing and verification
  - Progressive account lockout for brute force protection
  - Session tracking and login monitoring
  - Password reset capabilities and expiration enforcement
  - User profile and status management

- **`Role`**: Role-based access control with inheritance hierarchies
  - Hierarchical role structures supporting permission inheritance
  - System and custom role management
  - Role-permission association with comprehensive auditing
  - Support for time-limited role assignments

- **`Permission`**: Fine-grained permission system using resource:action pattern
  - Resource-based permission structure (e.g., 'cloud_resources:read')
  - Permission categories for organizational structure
  - Support for both system and custom permissions
  - Permission lookup and verification methods

- **`UserSession`**: Comprehensive session tracking and management
  - Device fingerprinting and recognition
  - Geolocation tracking and suspicious activity detection
  - Session extension and explicit termination
  - Support for multiple client types (web, mobile, API, CLI)

- **`UserActivity`**: Detailed activity logging for security and audit purposes
  - Comprehensive event types for different actions
  - Resource-specific activity tracking
  - Support for compliance reporting and security analytics
  - Anomaly detection through activity patterns analysis

- **`PermissionDelegation`**: Temporary permission delegation between users
  - Time-limited permission transfers
  - Delegation audit trail
  - Revocation capabilities
  - Context-based permission constraints
  - Approval workflows for delegation requests

- **`MFAMethod`**: Multi-factor authentication method management
  - Support for multiple MFA types (TOTP, backup codes, WebAuthn)
  - Secure storage of MFA secrets
  - Enrollment and verification workflows
  - Device identification and management

- **`MFABackupCode`**: Recovery mechanism for MFA
  - Secure generation and storage of backup codes
  - One-time use validation
  - Tracking of backup code usage

- **`MFAVerification`**: Tracking of MFA verification attempts
  - Security event logging for MFA activities
  - Failed verification tracking
  - MFA bypass attempt detection

- **`OAuthProvider`** and **`OAuthConnection`**: Third-party authentication support
  - Integration with external identity providers
  - Secure token management and storage
  - User profile synchronization
  - Connection management and refreshing

- **`LoginAttempt`**: Authentication attempt tracking
  - Brute force protection through rate limiting
  - IP-based and account-based lockout mechanisms
  - Risk scoring for authentication attempts
  - Suspicious behavior detection

- **`PermissionContextRule`**: Context-based access control
  - Dynamic permission evaluation based on request context
  - Attribute-based access control implementation
  - Rule-based permission handling
  - Fine-grained access control beyond basic RBAC

- **`APIKey`**: Programmatic authentication for systems and applications
  - Secure key generation and verification
  - Scoped permissions for limited access
  - IP and referer restrictions
  - Usage tracking and monitoring

- **`SecurityApproval`**: Multi-person approval workflows for sensitive operations
  - Configurable approval requirements with quorums
  - Time-limited approval requests
  - Comprehensive approval tracking and audit logging
  - Support for different approval types and urgency levels
  - Notification integration for pending approval requests

## Directory Structure

```plaintext
models/auth/
├── __init__.py             # Package initialization and exports
├── api_key.py              # API key model for programmatic authentication
├── login_attempt.py        # Login attempt tracking and brute force protection
├── mfa_backup_code.py      # Backup codes for multi-factor authentication
├── mfa_method.py           # Multi-factor authentication methods
├── mfa_verification.py     # MFA verification attempt tracking
├── oauth_provider.py       # OAuth provider and connection models
├── permission.py           # Permission model and related utilities
├── permission_context.py   # Context-based permission evaluation rules
├── permission_delegation.py # Permission delegation between users
├── README.md               # This documentation
├── role.py                 # Role model with permission inheritance
├── security_approval.py    # Approval workflows for sensitive operations
├── user.py                 # User model with authentication features
├── user_activity.py        # User activity tracking for audit purposes
└── user_session.py         # Session tracking and management
```

## RBAC System in Detail

Our RBAC implementation provides sophisticated access control capabilities:

### 1. Hierarchical Permission Inheritance

Roles can inherit permissions from parent roles, allowing for organizational structures like:

```plaintext
Admin
├── Regional Admin
│   └── Regional Operator
└── Security Admin
    └── Security Analyst
```

Each child role automatically receives all permissions from its parent while being able to have its own specific permissions. The system enforces maximum hierarchy depth to prevent performance issues.

### 2. Resource-Action Permission Model

Permissions follow a standardized `resource:action` naming pattern:

- **Resource**: Represents the entity being protected (e.g., `cloud_resources`, `users`, `system_config`)
- **Action**: Represents the operation allowed on the resource (e.g., `read`, `create`, `update`, `delete`)

Examples:

- `cloud_resources:read` - View cloud resources
- `users:create` - Create new users
- `ics_devices:control` - Control industrial systems devices

This standardization allows for consistent access control across the platform.

### 3. Context-Based Permission Evaluation

Permissions can be evaluated with contextual data to implement attribute-based access control:

```python
context = {
    "owner_id": resource.owner_id,
    "region": "us-west-2",
    "resource_type": "vm"
}
user.has_permission_with_context("resources:modify", context)
```

This enables dynamic rules like "users can only modify resources they own" or "operators can only access resources in their assigned regions."

### 4. System vs. Custom Roles and Permissions

The system distinguishes between:

- **System roles/permissions**: Core components defined by the application with special protections
- **Custom roles/permissions**: User-defined components for organizational needs

System roles (like 'admin', 'user') cannot be deleted or deactivated, ensuring system integrity.

### 5. Time-Limited Permission Assignments

Roles can be assigned permissions with expiration dates, enabling temporary access elevation without permanent permission changes.

### 6. Permission Context Rules

Fine-grained access control is implemented through context rules that evaluate request attributes:

```python
# Rule definition stored in PermissionContextRule
rule = {
    "resource_owner_id": {"$eq": "${user.id}"},  # User can only access their own resources
    "resource_type": {"$in": ["vm", "storage"]}, # Only applies to VMs and storage
    "region": {"$eq": "us-west-2"}               # Only resources in us-west-2
}

# Rule evaluation happens during has_permission_with_context
if PermissionContextRule.evaluate_permission(
    permission_id=permission.id,
    context=context,
    user_data=user.to_dict()
):
    # Grant access
```

## Configuration

The authentication system uses several configuration settings that can be adjusted in the application config:

- **`SECRET_KEY`**: Used for JWT token generation and verification
- **`SESSION_LIFETIME_MINUTES`**: Default session duration (default: 30)
- **`SESSION_EXTEND_MINUTES`**: Time added when extending sessions (default: 30)
- **`PASSWORD_ROTATION_DAYS`**: Days before password change is required (default: 90)
- **`MAX_SESSIONS_PER_USER`**: Maximum concurrent sessions per user (default: 5)
- **`LOCKOUT_THRESHOLD`**: Failed attempts before lockout (default: varies by severity)
- **`MFA_REQUIRED_ROLES`**: Roles that require MFA enrollment (e.g., "admin", "security")
- **`OAUTH_PROVIDERS`**: Configuration for OAuth providers
- **`API_KEY_RATE_LIMITS`**: Default rate limits for API keys
- **`SECURITY_APPROVAL_EXPIRY`**: Default expiry time for approval requests (in minutes)
- **`SECURITY_APPROVAL_NOTIFICATIONS`**: Enable/disable notifications for approvals

## Best Practices & Security

- Always use the `has_permission()` methods rather than direct permission checks
- Use the `log_activity()` method to track security-relevant actions
- Handle session management through `UserSession` rather than Flask's session
- Never store sensitive data in the session or activity logs
- Use context-based permission checks for finer-grained access control
- Always validate ownership before allowing resource access
- Leverage the `AuditableMixin` for security-critical models to enable access tracking
- Use proper transaction management with commit/rollback patterns
- Implement MFA for administrative and sensitive operations
- Regularly audit active sessions and API keys
- Use multi-person approvals for critical configuration changes

## Common Features

- Role-based access control with hierarchical inheritance
- Progressive account lockout for brute force protection
- Comprehensive activity logging for audit purposes
- Session tracking with suspicious activity detection
- Password security with strength requirements and history checks
- Permission delegation with time limitations
- User profile management and status control
- JWT token generation for API authentication
- Multi-factor authentication with multiple methods
- OAuth integration for third-party authentication
- API key management for programmatic access
- Multi-person approval workflows for sensitive operations

## Usage Examples

### Authentication

```python
# Authenticate user
user = User.get_by_username("johndoe")
if user and user.check_password("secure_password"):
    if user.is_locked():
        return {"error": user.get_lockout_message()}, 403

    # Update login metrics
    user.update_last_login()

    # Create and store session
    session = UserSession(
        user_id=user.id,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        client_type=UserSession.SESSION_CLIENT_TYPE_WEB
    )
    db.session.add(session)
    db.session.commit()

    # Record login activity
    UserActivity.log_activity(
        activity_type=UserActivity.ACTIVITY_LOGIN,
        user_id=user.id,
        status=UserActivity.STATUS_SUCCESS
    )

    # Generate authentication token
    token = user.generate_token()
    return {"token": token}, 200
else:
    if user:
        # Record failed login
        user.record_failed_login()

    # Log failed attempt
    UserActivity.log_activity(
        activity_type=UserActivity.ACTIVITY_LOGIN,
        user_id=user.id if user else None,
        status=UserActivity.STATUS_FAILURE,
        ip_address=request.remote_addr
    )

    return {"error": "Invalid credentials"}, 401
```

### Permission Checking

```python
# Basic permission check
if user.has_permission("cloud_resources:read"):
    # Allow access to resource
    pass

# Context-based permission check
context = {
    "owner_id": resource.owner_id,
    "resource_type": "vm",
    "cloud_provider": "aws",
    "region": "us-west-2"
}
if user.has_permission_with_context("resources:modify", context):
    # Allow modification
    pass
```

### Role Management

```python
# Create a new role
admin_role = Role(
    name="Regional Admin",
    description="Administrator for specific regions"
)
db.session.add(admin_role)
db.session.commit()

# Add permissions to role
view_perm = Permission.get_by_name("resources:view")
create_perm = Permission.get_by_name("resources:create")
admin_role.add_permissions([view_perm, create_perm])

# Create hierarchical role relationship
regional_operator_role = Role(
    name="Regional Operator",
    description="Operator for specific regions",
    parent_id=admin_role.id  # Inherits permissions from Regional Admin
)
db.session.add(regional_operator_role)
db.session.commit()

# Assign role to user
user.assign_role(admin_role)
```

### Implementing RBAC in Views

```python
@app.route('/api/resources/<resource_id>', methods=['PUT'])
@jwt_required
def update_resource(resource_id):
    # Get current user from JWT token
    current_user = get_jwt_identity()
    user = User.query.get(current_user['id'])

    # Get resource
    resource = Resource.query.get_or_404(resource_id)

    # Context-based permission check
    context = {
        "resource_id": resource_id,
        "owner_id": resource.owner_id,
        "region": resource.region
    }

    if not user.has_permission_with_context("resources:update", context):
        # Log unauthorized access attempt
        UserActivity.log_activity(
            activity_type=UserActivity.ACTIVITY_SECURITY_EVENT,
            user_id=user.id,
            resource_type="resource",
            resource_id=resource_id,
            action="update",
            status=UserActivity.STATUS_UNAUTHORIZED
        )
        return jsonify({"error": "Insufficient permissions"}), 403

    # Process authorized update
    # ...

    # Log successful update
    UserActivity.log_activity(
        activity_type=UserActivity.ACTIVITY_RESOURCE_ACCESS,
        user_id=user.id,
        resource_type="resource",
        resource_id=resource_id,
        action=UserActivity.ACTION_UPDATE,
        status=UserActivity.STATUS_SUCCESS
    )

    return jsonify({"message": "Resource updated successfully"})
```

### Activity Tracking

```python
# Log user activity
UserActivity.log_activity(
    activity_type=UserActivity.ACTIVITY_RESOURCE_ACCESS,
    user_id=current_user.id,
    resource_type="cloud_instance",
    resource_id=instance_id,
    action=UserActivity.ACTION_UPDATE,
    data={"changes": changes_dict}
)

# Get activity trends
activity_trends = UserActivity.get_activity_trend(
    days=30,
    interval="day",
    activity_type=UserActivity.ACTIVITY_CONFIG_CHANGE
)

# Find security hotspots
hotspots = UserActivity.get_activity_hotspots(days=7)
```

### Session Management

```python
# Get user's active sessions
active_sessions = UserSession.get_active_sessions_by_user(user_id)

# Revoke all sessions for security incident
UserSession.revoke_all_sessions_for_user(
    user_id=compromised_user_id,
    reason=UserSession.REVOCATION_REASON_SUSPICIOUS,
    exclude_session_id=current_session_id
)

# Mark session as suspicious
if suspicious_behavior_detected:
    session.flag_as_suspicious("Unusual access pattern detected")
    security_alert("Suspicious session", session.to_dict())
```

### Permission Delegation

```python
# Delegate a permission temporarily to another user
delegation = PermissionDelegation.create_standard_delegation(
    delegator_id=manager.id,
    delegate_id=substitute.id,
    permissions=["invoices:approve", "payments:view"],
    valid_days=14,
    reason="Vacation coverage",
    context_constraints={"department_id": 42}
)

# Check if user has delegated permissions
delegated_permissions = PermissionDelegation.get_active_for_user(user.id)
for delegation in delegated_permissions:
    print(f"Delegated: {delegation.permissions} (until {delegation.end_time})")

# Revoke a delegation early
delegation.revoke(
    revoker_id=manager.id,
    reason="Returned from vacation early"
)
```

### Multi-Factor Authentication

```python
# Set up TOTP-based MFA for a user
mfa_method = MFAMethod(
    user_id=user.id,
    method_type=MFAMethod.METHOD_TYPE_TOTP,
    is_primary=True
)

# Generate secret and save
totp_secret = pyotp.random_base32()
mfa_method.set_secret(totp_secret)
db.session.add(mfa_method)
db.session.commit()

# Generate backup codes
backup_codes = MFABackupCode.generate_codes(user.id)

# Verify a TOTP code during login
if mfa_method.verify_code(submitted_code):
    # Log successful verification
    MFAVerification.log_verification(
        user_id=user.id,
        verification_type="totp",
        success=True,
        mfa_method_id=mfa_method.id
    )
    # Complete login process
else:
    # Log failed attempt
    MFAVerification.log_verification(
        user_id=user.id,
        verification_type="totp",
        success=False,
        mfa_method_id=mfa_method.id
    )
    # Handle failed verification
```

### OAuth Authentication

```python
# Find OAuth connection
oauth_connection = OAuthConnection.get_by_provider_user_id(
    provider_id=GITHUB_PROVIDER_ID,
    provider_user_id=github_user_id
)

if oauth_connection:
    # User exists, log them in
    user = User.query.get(oauth_connection.user_id)
    # Create session, etc.
else:
    # New user, create account
    user = User(
        username=github_username,
        email=github_email,
        status=User.STATUS_ACTIVE
    )
    db.session.add(user)
    db.session.flush()  # Get user ID before creating connection

    # Create OAuth connection
    oauth_connection = OAuthConnection(
        user_id=user.id,
        provider_id=GITHUB_PROVIDER_ID,
        provider_user_id=github_user_id,
        provider_username=github_username,
        provider_email=github_email,
        access_token=access_token,
        refresh_token=refresh_token,
        token_expiry=expiry_time
    )
    db.session.add(oauth_connection)
    db.session.commit()
```

### Security Approval Workflows

```python
# Request approval for sensitive operation
approval = SecurityApproval.create_approval_request(
    operation="system:maintenance:restart",
    requester_id=current_user.id,
    required_approvals=2,
    expiry_minutes=120,
    details={
        "reason": "Scheduled system maintenance",
        "affected_services": ["api", "worker"]
    }
)

# Check status of approval request
status = approval.get_status()
if status["is_approved"]:
    # Proceed with operation
    pass

# Approve a request (by different user)
approval.add_approval(
    approver_id=admin_user.id,
    comments="Verified maintenance window and impact"
)

# Reject a request
approval.add_rejection(
    approver_id=security_officer.id,
    reason="Insufficient details provided"
)
```

### API Key Management

```python
# Create a new API key for a user
api_key = APIKey(
    name="My Service Integration",
    user_id=current_user.id,
    scopes=["resources:read", "metrics:read"],
    expires_at=datetime.now(timezone.utc) + timedelta(days=90),
    allowed_ips=["192.168.1.100", "10.0.0.0/24"],
    rate_limit=200  # requests per minute
)
db.session.add(api_key)
db.session.commit()

# The raw key is available once
raw_key = api_key.get_raw_key()  # e.g., "cip-key-v1-abcdef123456..."

# Later, validate an API key from request
received_key = request.headers.get('X-API-Key')
api_key = APIKey.find_by_key(received_key)

if not api_key:
    return jsonify({"error": "Invalid API key"}), 401

# Validate the request is allowed
is_valid, error_reason = api_key.validate_request(
    request_ip=request.remote_addr,
    referer=request.headers.get('Referer')
)

if not is_valid:
    return jsonify({"error": error_reason}), 403

# Record usage and proceed
api_key.record_usage(ip_address=request.remote_addr)
```

## Related Documentation

- Security Best Practices
- API Authentication
- RBAC Implementation Guide
- User Management API
- Multi-Factor Authentication Setup Guide
- OAuth Integration Guide
- API Key Management
- Security Monitoring and Auditing
- Approval Workflows Guide
