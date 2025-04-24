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

## Directory Structure

```plaintext
models/auth/
├── __init__.py           # Package initialization and exports
├── permission.py         # Permission model and related utilities
├── README.md             # This documentation
├── role.py               # Role model with permission inheritance
├── user.py               # User model with authentication features
├── user_activity.py      # User activity tracking for audit purposes
└── user_session.py       # Session tracking and management

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

## Configuration

The authentication system uses several configuration settings that can be adjusted in the application config:

- **`SECRET_KEY`**: Used for JWT token generation and verification
- **`SESSION_LIFETIME_MINUTES`**: Default session duration (default: 30)
- **`SESSION_EXTEND_MINUTES`**: Time added when extending sessions (default: 30)
- **`PASSWORD_ROTATION_DAYS`**: Days before password change is required (default: 90)
- **`MAX_SESSIONS_PER_USER`**: Maximum concurrent sessions per user (default: 5)
- **`LOCKOUT_THRESHOLD`**: Failed attempts before lockout (default: varies by severity)

## Best Practices & Security

- Always use the `has_permission()` methods rather than direct permission checks
- Use the `log_activity()` method to track security-relevant actions
- Handle session management through `UserSession` rather than Flask's session
- Never store sensitive data in the session or activity logs
- Use context-based permission checks for finer-grained access control
- Always validate ownership before allowing resource access
- Leverage the `AuditableMixin` for security-critical models to enable access tracking
- Use proper transaction management with commit/rollback patterns

## Common Features

- Role-based access control with hierarchical inheritance
- Progressive account lockout for brute force protection
- Comprehensive activity logging for audit purposes
- Session tracking with suspicious activity detection
- Password security with strength requirements and history checks
- Permission delegation with time limitations
- User profile management and status control
- JWT token generation for API authentication

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
delegation = PermissionDelegation.create_delegation(
    delegator_id=manager.id,
    delegate_id=substitute.id,
    permission_id=approve_invoices_permission.id,
    valid_until=datetime.now(timezone.utc) + timedelta(days=14),
    reason="Vacation coverage"
)

# Check if user has delegated permissions
delegated_permissions = PermissionDelegation.get_active_for_user(user.id)
for delegation in delegated_permissions:
    print(f"Delegated: {delegation.permission.name} (until {delegation.valid_until})")

# Revoke a delegation early
delegation.revoke(
    revoked_by_id=manager.id,
    reason="Returned from vacation early"
)

```

## Related Documentation

- Security Best Practices
- API Authentication
- RBAC Implementation Guide
- User Management API
