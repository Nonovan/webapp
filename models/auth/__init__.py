"""
models/auth/__init__.py

This package contains database models and utilities related to authentication and authorization.

Modules:
- user: Defines the User model for account management and authentication.
- user_session: Defines the UserSession model for tracking user login sessions.
- user_activity: Defines the UserActivity model for auditing user actions.
- role: Defines the Role model and role-based access control (RBAC) utilities.
- permission: Defines the Permission model and permission management utilities.
- login_attempt: Defines the LoginAttempt model for tracking and limiting login attempts.
- api_key: Provides APIKey model for programmatic authentication.
- mfa_method: Multi-factor authentication methods implementation.
- mfa_backup_code: Backup codes for multi-factor authentication.
- mfa_verification: Tracks MFA verification attempts.
- mfa_totp: TOTP-based multi-factor authentication implementation.
- permission_delegation: Temporary delegation of permissions between users.
- permission_context: Context-based permission evaluation rules.
- oauth_provider: OAuth provider integration and connection management.
- security_approval: Approval workflows for sensitive administrative operations.

The authentication and authorization system implements a comprehensive RBAC approach with:
- Hierarchical roles that can inherit permissions from parent roles
- Fine-grained permissions using resource:action naming pattern
- Dynamic permission rules based on context attributes
- Temporary permission delegation between users
- Detailed activity and session tracking for security auditing
- Multi-person approval workflows for sensitive operations

Usage:
Import the necessary models or utilities from this package for authentication-related operations.

Examples:
    # Import core models
    from models.auth import User, Role, Permission

    # Import specific functionality
    from models.auth import UserSession, UserActivity

    # Check permissions
    if user.has_permission('cloud_resources:read'):
        # Allow access to resource

    # Check permissions with context for finer access control
    context = {'owner_id': project.owner_id, 'region': 'us-west-2'}
    if user.has_permission_with_context('project:update', context):
        # Allow access to modify project

    # Audit user activity
    UserActivity.log_activity(
        activity_type=UserActivity.ACTIVITY_RESOURCE_ACCESS,
        user_id=current_user.id,
        resource_type='cloud_instance',
        resource_id=instance_id,
        action='view'
    )

    # Create and track user sessions
    session = UserSession(
        user_id=user.id,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        client_type=UserSession.SESSION_CLIENT_TYPE_WEB
    )
    db.session.add(session)
    db.session.commit()

    # Delegate permission temporarily
    delegation = PermissionDelegation.create_delegation(
        delegator_id=manager.id,
        delegate_id=substitute.id,
        permission_id=permission.id,
        valid_until=datetime.now(timezone.utc) + timedelta(days=7),
        reason="Temporary access during team member absence"
    )

    # Request approval for sensitive operations
    approval = SecurityApproval.create_approval_request(
        operation="system:maintenance:restart",
        requester_id=current_user.id,
        required_approvals=2,
        expiry_minutes=120,
        details={"reason": "Scheduled system maintenance", "affected_services": ["api", "worker"]}
    )
"""

# Import core models
from .user import User
from .role import Role
from .permission import Permission
from .user_session import UserSession
from .user_activity import UserActivity

# Import security and authentication models
from .login_attempt import LoginAttempt

# Import additional auth-related models with graceful fallbacks
# for models that might not be available in all deployments
__all__ = [
    "User",
    "Role",
    "Permission",
    "UserSession",
    "UserActivity",
    "LoginAttempt"
]

# Optional authentication models
try:
    from .api_key import APIKey
    __all__.append("APIKey")
except ImportError:
    pass

# Multi-factor authentication models
try:
    from .mfa_method import MFAMethod
    __all__.append("MFAMethod")
except ImportError:
    pass

try:
    from .mfa_backup_code import MFABackupCode
    __all__.append("MFABackupCode")
except ImportError:
    pass

try:
    from .mfa_verification import MFAVerification
    __all__.append("MFAVerification")
except ImportError:
    pass

try:
    from .mfa_totp import MFATotp
    __all__.append("MFATotp")
except ImportError:
    pass

# Permission enhancement models
try:
    from .permission_delegation import PermissionDelegation
    __all__.append("PermissionDelegation")
except ImportError:
    pass

try:
    from .permission_context import PermissionContextRule
    __all__.append("PermissionContextRule")
except ImportError:
    pass

# OAuth provider model
try:
    from .oauth_provider import OAuthProvider, OAuthConnection
    __all__.extend(["OAuthProvider", "OAuthConnection"])
except ImportError:
    pass

# Security approval model
try:
    from .security_approval import SecurityApproval
    __all__.append("SecurityApproval")
except ImportError:
    pass
