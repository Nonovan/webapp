"""
models/auth/__init__.py

This package contains database models and utilities related to authentication and authorization.

Modules:
- user: Defines the User model and related functionality.
- user_session: Defines the UserSession model for tracking user login sessions.
- user_activity: Defines the UserActivity model for auditing user actions.
- role: Defines the Role model and role-based access control (RBAC) utilities.
- permission: Defines the Permission model and permission management utilities.

Usage:
Import the necessary models or utilities from this package for authentication-related operations.

Examples:
    from models.auth import User, Role, Permission
    from models.auth.user_activity import UserActivity
"""

from .user import User
from .role import Role
from .permission import Permission
from .user_session import UserSession
from .user_activity import UserActivity

__all__ = [
    "User",
    "Role",
    "Permission",
    "UserSession",
    "UserActivity"
]
