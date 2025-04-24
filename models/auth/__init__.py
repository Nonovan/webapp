"""
models/auth/__init__.py

This package contains database models and utilities related to authentication and authorization.

Modules:
- user: Defines the User model for account management and authentication.
- user_session: Defines the UserSession model for tracking user login sessions.
- user_activity: Defines the UserActivity model for auditing user actions.
- role: Defines the Role model and role-based access control (RBAC) utilities.
- permission: Defines the Permission model and permission management utilities.

The authentication and authorization system implements a comprehensive RBAC approach with:
- Hierarchical roles that can inherit permissions from parent roles
- Fine-grained permissions using resource:action naming pattern
- Dynamic permission rules based on context attributes
- Temporary permission delegation between users
- Detailed activity and session tracking for security auditing

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
"""

# Import core models
from .user import User
from .role import Role
from .permission import Permission
from .user_session import UserSession
from .user_activity import UserActivity

# Import additional auth-related models if they exist
try:
    from .permission_delegation import PermissionDelegation
    __all__ = [
        "User",
        "Role",
        "Permission",
        "UserSession",
        "UserActivity",
        "PermissionDelegation"
    ]
except ImportError:
    # Define exports without PermissionDelegation if not available
    __all__ = [
        "User",
        "Role",
        "Permission",
        "UserSession",
        "UserActivity"
    ]
