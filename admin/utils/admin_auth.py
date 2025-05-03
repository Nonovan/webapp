"""
Administrative Authentication and Authorization Utilities.

This module provides helper functions and decorators specifically for handling
authentication and authorization within administrative tools and scripts.
It ensures that administrative actions are performed only by authorized users
with the necessary permissions and potentially MFA verification.
"""

import datetime
import logging
import uuid
from functools import wraps
from typing import Optional, Dict, Any, Callable, List, Union

try:
    from flask import current_app, request, g
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# Core security imports
try:
    from core.security.cs_authentication import (
        authenticate_user as core_authenticate_user,
        verify_totp_code,
    )
    from core.security.cs_authorization import (
        verify_permission as core_verify_permission
    )
    from core.utils.logging_utils import logger as get_logger
    logger = get_logger(__name__)
except ImportError:
    # Fallback basic logger if core logging is unavailable
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.warning("Core logging or security modules not found, using basic logging.")
    def core_authenticate_user(*args, **kwargs): return None
    def core_verify_permission(*args, **kwargs): return False
    def verify_totp_code(*args, **kwargs): return False

try:
    from admin.utils.audit_utils import log_admin_action
except ImportError:
    logger.warning("Admin audit logging utility not found. Audit logs will be skipped.")
    def log_admin_action(*args, **kwargs) -> None: pass

from admin.utils.error_handling import (
    AdminAuthenticationError,
    AdminPermissionError,
    AdminConfigurationError
)

# Models
try:
    from models.auth.user import User
    from models.auth.role import Role
except ImportError:
    logger.error("Failed to import User/Role models. Admin auth checks might fail.")
    User = None
    Role = None

# Constants
ADMIN_ROLES = ['admin', 'security_admin']
ADMIN_PERMISSION_PREFIX = "admin:"

# Admin session storage
_admin_sessions: Dict[str, Dict[str, Any]] = {}
_token_expiration_hours = 12  # Default session expiration time in hours


def authenticate_admin(username: str, password: str, mfa_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Authenticates a user for administrative access.

    Args:
        username: The administrator's username
        password: The administrator's password
        mfa_token: Optional MFA token if required

    Returns:
        Dict containing session info including admin token

    Raises:
        AdminAuthenticationError: If authentication fails
        AdminConfigurationError: If core auth components missing
    """
    if not core_authenticate_user or not User:
        raise AdminConfigurationError("Core authentication unavailable")

    # Get authentication context
    auth_context = {"ip_address": "cli", "user_agent": "admin-cli"}
    if FLASK_AVAILABLE and request:
        auth_context["ip_address"] = request.remote_addr
        auth_context["user_agent"] = request.user_agent.string

    # Authenticate user
    auth_result = core_authenticate_user(
        username=username,
        password=password,
        ip_address=auth_context["ip_address"],
        user_agent=auth_context["user_agent"]
    )

    if not auth_result or not auth_result.get("success"):
        log_admin_action(
            action="admin.login_attempt",
            status="failure",
            details={"username": username, "reason": "Invalid credentials"}
        )
        raise AdminAuthenticationError("Invalid username or password")

    user = auth_result.get("user")
    if not user:
        raise AdminAuthenticationError("Authentication succeeded but user not found")

    # Verify admin privileges
    is_admin = False
    user_roles = [role.name for role in getattr(user, 'roles', [])]
    if any(role in ADMIN_ROLES for role in user_roles):
        is_admin = True
    elif core_verify_permission(user.id, f"{ADMIN_PERMISSION_PREFIX}*"):
        is_admin = True

    if not is_admin:
        log_admin_action(
            action="admin.login_attempt",
            status="failure",
            user_id=user.id,
            details={"username": username, "reason": "Not an admin"}
        )
        raise AdminAuthenticationError("User lacks admin privileges")

    # Verify MFA if required
    requires_mfa = getattr(user, 'require_mfa', False)
    if requires_mfa:
        if not mfa_token:
            log_admin_action(
                action="admin.login_attempt",
                status="failure",
                user_id=user.id,
                details={"username": username, "reason": "MFA required"}
            )
            raise AdminAuthenticationError("MFA token required")

        if not verify_mfa_token(username, mfa_token):
            log_admin_action(
                action="admin.login_attempt",
                status="failure",
                user_id=user.id,
                details={"username": username, "reason": "Invalid MFA"}
            )
            raise AdminAuthenticationError("Invalid MFA token")

    # Generate custom admin token - don't rely on auth_result token for admin sessions
    admin_token = str(uuid.uuid4())
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=_token_expiration_hours)

    # Collect permissions for session storage
    user_permissions = []
    if hasattr(user, 'get_all_permissions'):
        user_permissions = user.get_all_permissions()
    elif core_verify_permission:
        # Try to query common admin permissions
        admin_perms = ["admin:read", "admin:write", "admin:user:*", "admin:system:*"]
        user_permissions = [p for p in admin_perms if core_verify_permission(user.id, p)]

    # Store session
    session_data = {
        "user_id": user.id,
        "username": user.username,
        "roles": user_roles,
        "permissions": user_permissions,
        "mfa_verified": requires_mfa,
        "auth_context": auth_context,
        "issued_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "expires_at": expires_at.isoformat()
    }
    _admin_sessions[admin_token] = session_data

    # Log successful authentication
    log_admin_action(
        action="admin.login",
        status="success",
        user_id=user.id,
        username=user.username,
        source_ip=auth_context.get("ip_address"),
        details={"username": username}
    )

    # Return session info
    return {
        "token": admin_token,
        "user": {
            "user_id": user.id,
            "username": user.username,
            "roles": user_roles,
            "requires_mfa": requires_mfa,
            "session_expires": expires_at.isoformat()
        }
    }


def get_admin_session(token: str) -> Optional[Dict[str, Any]]:
    """
    Gets admin session data for a token.

    Args:
        token: The admin session token

    Returns:
        Session data dictionary or None if token invalid or expired
    """
    session_data = _admin_sessions.get(token)
    if not session_data:
        return None

    # Check for expiration
    try:
        expires_at = datetime.datetime.fromisoformat(session_data.get("expires_at", ""))
        if datetime.datetime.now(datetime.timezone.utc) > expires_at:
            # Session expired, remove it
            del _admin_sessions[token]
            return None

        # Update last access time
        session_data["last_accessed"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return session_data
    except (ValueError, KeyError):
        # Invalid session data
        return None


def invalidate_admin_session(token: str) -> None:
    """
    Invalidates an admin session.

    Args:
        token: The admin session token to invalidate
    """
    if token in _admin_sessions:
        session = _admin_sessions[token]
        del _admin_sessions[token]

        # Log the logout action
        log_admin_action(
            action="admin.logout",
            status="success",
            user_id=session.get("user_id"),
            username=session.get("username"),
            details={"username": session.get("username")}
        )

        logger.info("Admin session invalidated for user: %s", session.get("username"))


def check_permission(token: str, permission: str) -> bool:
    """
    Checks if admin token has required permission.

    Args:
        token: Admin session token
        permission: Permission to check

    Returns:
        True if user has permission, False otherwise
    """
    session = get_admin_session(token)
    if not session:
        return False

    user_id = session.get("user_id")
    if not user_id:
        return False

    # First check session cached permissions
    session_permissions = session.get("permissions", [])
    if any(perm == permission or perm.endswith(":*") and permission.startswith(perm[:-1]) for perm in session_permissions):
        return True

    # Fall back to runtime permission check
    if core_verify_permission:
        return core_verify_permission(user_id, permission)

    return False


def require_permission(permission: str, operation_name: str = None):
    """
    Decorator to enforce admin permission checks.

    Args:
        permission: Required permission
        operation_name: Optional descriptive name of the operation for audit logs

    Raises:
        AdminAuthenticationError: If no valid auth token
        AdminPermissionError: If user lacks permission
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            auth_token = kwargs.get('auth_token')

            if not auth_token and FLASK_AVAILABLE and g:
                auth_token = getattr(g, 'admin_auth_token', None)

            if not auth_token:
                raise AdminAuthenticationError("Authentication required")

            # Cache session retrieval result to avoid multiple lookups
            session = get_admin_session(auth_token)
            if not session:
                raise AdminAuthenticationError("Invalid or expired session")

            # Get operation name from parameter or function name
            op_name = operation_name or func.__name__

            if not check_permission(auth_token, permission):
                user_id = session.get("user_id")
                username = session.get("username", "unknown")

                log_admin_action(
                    action="admin.permission_denied",
                    status="failure",
                    user_id=user_id,
                    username=username,
                    details={
                        "username": username,
                        "permission": permission,
                        "operation": op_name,
                        "args": str(args),
                        "kwargs": {k: v for k, v in kwargs.items() if k != 'password'} # Safe logging
                    }
                )
                raise AdminPermissionError(f"Permission denied: {permission} for operation: {op_name}")

            # Store session in kwargs to make it available to the function
            kwargs['admin_session'] = session

            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_any_permission(permissions: List[str]):
    """
    Decorator to enforce that the user has at least one of the listed permissions.

    Args:
        permissions: List of permissions, any of which grants access

    Raises:
        AdminAuthenticationError: If no valid auth token
        AdminPermissionError: If user lacks all required permissions
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            auth_token = kwargs.get('auth_token')

            if not auth_token and FLASK_AVAILABLE and g:
                auth_token = getattr(g, 'admin_auth_token', None)

            if not auth_token:
                raise AdminAuthenticationError("Authentication required")

            # Cache session retrieval result to avoid multiple lookups
            session = get_admin_session(auth_token)
            if not session:
                raise AdminAuthenticationError("Invalid or expired session")

            # Check if user has any of the required permissions
            has_permission = False
            for perm in permissions:
                if check_permission(auth_token, perm):
                    has_permission = True
                    break

            if not has_permission:
                user_id = session.get("user_id")
                username = session.get("username", "unknown")

                log_admin_action(
                    action="admin.permission_denied",
                    status="failure",
                    user_id=user_id,
                    username=username,
                    details={
                        "username": username,
                        "permissions": permissions
                    }
                )
                raise AdminPermissionError(f"Permission denied: {permissions}")

            # Store session in kwargs to make it available to the function
            kwargs['admin_session'] = session

            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_mfa(operation_name: str = None):
    """
    Decorator to enforce MFA verification for sensitive admin operations.

    This decorator should be used in conjunction with require_permission to
    ensure sensitive operations require both proper permissions and MFA verification.

    Args:
        operation_name: Optional descriptive name of the operation for audit logs

    Raises:
        AdminAuthenticationError: If no valid auth token or session
        AdminPermissionError: If MFA token is missing or invalid
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            auth_token = kwargs.get('auth_token')
            mfa_token = kwargs.get('mfa_token')

            if not auth_token and FLASK_AVAILABLE and g:
                auth_token = getattr(g, 'admin_auth_token', None)
                mfa_token = getattr(g, 'mfa_token', None)

            if not auth_token:
                raise AdminAuthenticationError("Authentication required")

            # Get session information
            session = get_admin_session(auth_token)
            if not session:
                raise AdminAuthenticationError("Invalid or expired session")

            # Get operation name from parameter or function name
            op_name = operation_name or func.__name__

            # Check if MFA is already verified in session
            if session.get("mfa_verified"):
                # MFA already verified during authentication
                return func(*args, **kwargs)

            # Otherwise require MFA token
            username = session.get("username", "unknown")

            if not mfa_token:
                log_admin_action(
                    action="admin.mfa_required",
                    status="failure",
                    user_id=session.get("user_id"),
                    username=username,
                    details={
                        "username": username,
                        "operation": op_name
                    }
                )
                raise AdminPermissionError(f"MFA verification required for operation: {op_name}")

            # Verify the provided MFA token
            if not verify_mfa_token(username, mfa_token):
                log_admin_action(
                    action="admin.mfa_verification",
                    status="failure",
                    user_id=session.get("user_id"),
                    username=username,
                    details={
                        "username": username,
                        "operation": op_name
                    }
                )
                raise AdminPermissionError(f"Invalid MFA token for operation: {op_name}")

            # MFA verified, update session
            session["mfa_verified"] = True

            # Log successful MFA verification
            log_admin_action(
                action="admin.mfa_verification",
                status="success",
                user_id=session.get("user_id"),
                username=username,
                details={
                    "username": username,
                    "operation": op_name
                }
            )

            # Store session in kwargs to make it available to the function
            kwargs['admin_session'] = session

            return func(*args, **kwargs)
        return wrapper
    return decorator


def verify_mfa_token(username: str, token: str) -> bool:
    """
    Verifies an MFA token for a user.

    Args:
        username: Username to verify MFA for
        token: MFA token to verify

    Returns:
        True if valid, False otherwise
    """
    if not User:
        logger.error("User model unavailable for MFA verification")
        return False

    # Get the user
    try:
        user = User.query.filter_by(username=username).first()
        if not user:
            logger.warning(f"User not found during MFA verification: {username}")
            return False

        mfa_secret = getattr(user, 'mfa_secret', None)
        if not mfa_secret:
            logger.warning(f"User {username} has no MFA secret configured")
            return False

        # Verify token using core verification function
        return verify_totp_code(mfa_secret, token)
    except Exception as e:
        logger.error(f"MFA verification error: {e}")
        return False


def get_active_sessions() -> List[Dict[str, Any]]:
    """
    Gets all active admin sessions.

    Returns:
        List of active session data dictionaries with sensitive fields removed
    """
    # Clean expired sessions first
    current_time = datetime.datetime.now(datetime.timezone.utc)
    expired_tokens = []

    for token, session in _admin_sessions.items():
        try:
            expires_at = datetime.datetime.fromisoformat(session.get("expires_at", ""))
            if current_time > expires_at:
                expired_tokens.append(token)
        except (ValueError, KeyError):
            # Invalid session data
            expired_tokens.append(token)

    # Remove expired sessions
    for token in expired_tokens:
        del _admin_sessions[token]

    # Return sanitized session data
    return [
        {
            "username": session.get("username"),
            "user_id": session.get("user_id"),
            "roles": session.get("roles", []),
            "issued_at": session.get("issued_at"),
            "expires_at": session.get("expires_at"),
            "auth_context": {
                "ip_address": session.get("auth_context", {}).get("ip_address"),
                "user_agent": session.get("auth_context", {}).get("user_agent")
            },
            "last_accessed": session.get("last_accessed")
        }
        for session in _admin_sessions.values()
    ]


def extend_session(token: str, hours: int = 4) -> bool:
    """
    Extends the expiration time for an admin session.

    Args:
        token: Admin session token
        hours: Additional hours to extend session by

    Returns:
        True if session was extended, False if token invalid
    """
    session_data = _admin_sessions.get(token)
    if not session_data:
        return False

    try:
        current_expiry = datetime.datetime.fromisoformat(session_data.get("expires_at", ""))
        new_expiry = current_expiry + datetime.timedelta(hours=hours)
        session_data["expires_at"] = new_expiry.isoformat()

        # Log session extension
        log_admin_action(
            action="admin.session_extended",
            status="success",
            user_id=session_data.get("user_id"),
            username=session_data.get("username"),
            details={
                "username": session_data.get("username"),
                "hours_extended": hours,
                "new_expiry": new_expiry.isoformat()
            }
        )

        return True
    except (ValueError, KeyError):
        # Invalid session data
        return False


def revoke_all_sessions_for_user(username: str) -> int:
    """
    Revokes all active admin sessions for a specific user.

    Args:
        username: Username to revoke sessions for

    Returns:
        Number of sessions revoked
    """
    tokens_to_revoke = []

    # Find all sessions for this user
    for token, session in _admin_sessions.items():
        if session.get("username") == username:
            tokens_to_revoke.append(token)

    # Revoke all sessions
    for token in tokens_to_revoke:
        invalidate_admin_session(token)

    if tokens_to_revoke:
        logger.info(f"Revoked {len(tokens_to_revoke)} admin sessions for user: {username}")

    return len(tokens_to_revoke)
