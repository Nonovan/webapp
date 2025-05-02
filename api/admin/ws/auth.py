"""
Authentication handlers for Administrative WebSocket API.

This module provides authentication and authorization functionality for WebSocket
connections to the administrative API. It enforces strict security controls including
token validation, MFA verification, permission checks, and command approval workflows.
All security events are comprehensively logged for audit purposes.
"""

import logging
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Union, Tuple

from flask import current_app, request, session, g
from flask_socketio import disconnect

from extensions import db, metrics
from core.security.cs_authentication import get_client_ip, is_ip_in_whitelist
from core.security import (
    log_security_event,
    verify_token,
    is_mfa_verified,
    is_suspicious_ip
)
from models.auth.user import User
from models.auth.user_activity import UserActivity
from models.security.audit_log import AuditLog
from models.auth import SecurityApproval

# Initialize logger
logger = logging.getLogger(__name__)

# Define approval types
APPROVAL_TYPE_COMMAND = 'admin_command'

# Cache of admin permissions
_permission_cache = {}
_permission_cache_expiry = {}
_permission_cache_timeout = 300  # 5 minutes


def authenticate_connection(request_obj) -> Dict[str, Any]:
    """
    Authenticate a WebSocket connection request.

    Validates the token from query parameters or headers, checks for MFA verification
    if required, and verifies IP restrictions and other security controls.

    Args:
        request_obj: WebSocket request object

    Returns:
        Dict with authentication result and user object if successful
    """
    start_time = time.time()
    client_ip = get_client_ip()

    # Track metrics
    metrics.increment('admin_ws_auth_attempts_total')

    # Extract token from query parameter or headers
    token = request_obj.args.get('token')
    if not token and 'Authorization' in request_obj.headers:
        auth_header = request_obj.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]

    # Check if token is missing
    if not token:
        logger.warning("WebSocket authentication failed: Missing token")
        return {
            'success': False,
            'message': 'Authentication required',
            'user_id': None
        }

    # Verify token
    try:
        payload = verify_token(token)
        if not payload:
            logger.warning("WebSocket authentication failed: Invalid token")
            return {
                'success': False,
                'message': 'Invalid authentication token',
                'user_id': None
            }

        # Extract user ID from token
        user_id = payload.get('sub')
        if not user_id:
            logger.warning("WebSocket authentication failed: Missing user ID in token")
            return {
                'success': False,
                'message': 'Invalid token format',
                'user_id': None
            }

        # Get user from database
        user = User.query.get(user_id)
        if not user:
            logger.warning(f"WebSocket authentication failed: User ID {user_id} not found")
            return {
                'success': False,
                'message': 'User not found',
                'user_id': user_id
            }

        # Check if user is active
        if not user.is_active:
            logger.warning(f"WebSocket authentication failed: User {user.username} (ID: {user_id}) is inactive")
            return {
                'success': False,
                'message': 'User account is inactive',
                'user_id': user_id
            }

        # Check if MFA verification is required for admin WebSocket
        mfa_required = current_app.config.get('ADMIN_WS_MFA_REQUIRED', True)
        if mfa_required and not is_mfa_verified():
            logger.warning(f"WebSocket authentication failed: MFA verification required for user {user.username}")
            return {
                'success': False,
                'message': 'MFA verification required',
                'user_id': user_id,
                'require_mfa': True
            }

        # Check IP restrictions if enabled
        ip_restrictions_enabled = current_app.config.get('ADMIN_IP_RESTRICTION_ENABLED', True)
        if ip_restrictions_enabled:
            allowed_ips = current_app.config.get('ADMIN_IP_WHITELIST', [])
            if allowed_ips and not is_ip_in_whitelist(client_ip, allowed_ips):
                log_security_event(
                    event_type='admin_ws_ip_restricted',
                    description=f"Admin WebSocket access denied due to IP restriction: {client_ip}",
                    severity='medium',
                    user_id=user_id,
                    ip_address=client_ip
                )
                logger.warning(f"WebSocket authentication failed: IP {client_ip} not in whitelist for user {user.username}")
                return {
                    'success': False,
                    'message': 'Access denied from this IP address',
                    'user_id': user_id
                }

        # Check if IP is suspicious
        if is_suspicious_ip(client_ip):
            # Log but don't block - just a warning
            log_security_event(
                event_type='admin_ws_suspicious_ip',
                description=f"Admin WebSocket connection from suspicious IP: {client_ip}",
                severity='warning',
                user_id=user_id,
                ip_address=client_ip
            )
            logger.warning(f"WebSocket connection from suspicious IP: {client_ip} for user {user.username}")

        # Check if user has necessary admin role(s)
        if not validate_admin_access(user):
            log_security_event(
                event_type='admin_ws_access_denied',
                description=f"Admin WebSocket access denied: Insufficient privileges for user {user.username}",
                severity='medium',
                user_id=user_id,
                ip_address=client_ip
            )
            logger.warning(f"WebSocket authentication failed: Insufficient admin privileges for user {user.username}")
            return {
                'success': False,
                'message': 'Insufficient privileges for admin access',
                'user_id': user_id
            }

        # Update user's last active timestamp
        if hasattr(UserActivity, 'update_last_active'):
            UserActivity.update_last_active(user.id)

        # Log successful authentication
        logger.info(f"WebSocket authentication successful for user: {user.username}")
        auth_time = time.time() - start_time
        metrics.observe('admin_ws_auth_latency_seconds', auth_time)
        metrics.increment('admin_ws_auth_success_total')

        return {
            'success': True,
            'message': 'Authentication successful',
            'user': user,
            'user_id': user.id
        }

    except Exception as e:
        logger.error(f"WebSocket authentication error: {str(e)}", exc_info=True)
        metrics.increment('admin_ws_auth_error_total')
        return {
            'success': False,
            'message': 'Authentication error',
            'user_id': None
        }


def validate_admin_access(user: User) -> bool:
    """
    Verify if a user has admin access for WebSocket connections.

    Checks user roles and permissions to determine if they are allowed to
    use the admin WebSocket API.

    Args:
        user: User object to check

    Returns:
        True if user has admin access, False otherwise
    """
    if not user:
        return False

    # Check for admin roles
    admin_roles = current_app.config.get('ADMIN_ROLES', ['admin', 'super_admin', 'security_admin'])

    # Get user roles
    user_roles = []
    if hasattr(user, 'role'):
        user_roles = [user.role]
    if hasattr(user, 'roles') and user.roles:
        user_roles = [role.name for role in user.roles]

    # Check if user has an admin role
    if any(role in admin_roles for role in user_roles):
        return True

    # Check for admin permissions
    if hasattr(user, 'has_permission'):
        # Check for any admin permission
        return user.has_permission('admin:*')

    return False


def verify_channel_permission(user_id: int, permission: str) -> bool:
    """
    Verify if a user has permission to access a specific channel.

    Args:
        user_id: User ID to check
        permission: Permission string required for the channel

    Returns:
        True if the user has the required permission, False otherwise
    """
    if not user_id or not permission:
        return False

    # Check cache first
    cache_key = f"{user_id}:{permission}"
    current_time = time.time()

    if cache_key in _permission_cache and _permission_cache_expiry.get(cache_key, 0) > current_time:
        return _permission_cache[cache_key]

    # Get the user
    user = User.query.get(user_id)
    if not user:
        logger.warning(f"User ID {user_id} not found when checking channel permission {permission}")
        return False

    # Check permission
    has_permission = False
    if hasattr(user, 'has_permission'):
        has_permission = user.has_permission(permission)

    # Cache the result
    _permission_cache[cache_key] = has_permission
    _permission_cache_expiry[cache_key] = current_time + _permission_cache_timeout

    # Log denied access
    if not has_permission:
        logger.info(f"Channel access denied: User {user.username} lacks permission {permission}")

    return has_permission


def require_approval_for_command(operation: str, user_id: int, role: str) -> Dict[str, Any]:
    """
    Check if a command requires approval and if it already has approval.

    High-risk operations require a second person approval based on the
    configured approval matrix. This function checks if approval is needed
    and if it has already been granted.

    Args:
        operation: Command operation identifier
        user_id: User ID of the requester
        role: User's role

    Returns:
        Dict with approval status information
    """
    # Get approved operations from config
    high_risk_operations = current_app.config.get('ADMIN_HIGH_RISK_OPERATIONS', [
        'system.shutdown', 'system.restart', 'database.vacuum',
        'security.reset_mfa', 'config.update', 'user.delete',
        'file_integrity.update_baseline', 'security.disable_approval',
        'maintenance.start', 'maintenance.end'
    ])

    # Check if operation requires approval
    requires_approval = operation in high_risk_operations

    # Get exempted roles from config
    approval_exempt_roles = current_app.config.get('ADMIN_APPROVAL_EXEMPT_ROLES', ['super_admin'])

    # Check if user's role is exempt from approval
    is_exempt = role in approval_exempt_roles

    # If operation doesn't require approval or role is exempt, return immediately
    if not requires_approval or is_exempt:
        return {
            'requires_approval': False,
            'is_approved': True,
            'approval_id': None,
            'expires_at': None,
            'approvers': []
        }

    # Check if there's an existing approval for this operation
    approval = SecurityApproval.query.filter_by(
        operation=operation,
        requester_id=user_id,
        approval_type=APPROVAL_TYPE_COMMAND,
        is_approved=True,
        is_active=True
    ).first()

    if approval:
        # Check if approval has expired
        now = datetime.now(timezone.utc)
        if approval.expires_at and approval.expires_at <= now:
            # Approval expired
            approval.is_active = False
            db.session.commit()

            return {
                'requires_approval': True,
                'is_approved': False,
                'approval_id': str(uuid.uuid4()),  # Generate new ID for request
                'expires_at': None,
                'approvers': []
            }

        # Approval is valid
        return {
            'requires_approval': True,
            'is_approved': True,
            'approval_id': approval.id,
            'expires_at': approval.expires_at,
            'approvers': [approver.username for approver in approval.approvers]
        }

    # No existing approval found, generate new approval ID
    approval_id = str(uuid.uuid4())

    # Calculate expiration time based on config
    approval_expiry_minutes = current_app.config.get('ADMIN_APPROVAL_EXPIRY_MINUTES', 60)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=approval_expiry_minutes)

    # Create new approval request
    new_approval = SecurityApproval(
        id=approval_id,
        operation=operation,
        requester_id=user_id,
        approval_type=APPROVAL_TYPE_COMMAND,
        is_approved=False,
        is_active=True,
        created_at=datetime.now(timezone.utc),
        expires_at=expires_at
    )
    db.session.add(new_approval)
    db.session.commit()

    # Log approval request
    log_security_event(
        event_type='admin_command_approval_requested',
        description=f"Administrative command approval requested: {operation}",
        severity='medium',
        user_id=user_id,
        details={
            'operation': operation,
            'approval_id': approval_id,
            'expires_at': expires_at.isoformat()
        }
    )

    return {
        'requires_approval': True,
        'is_approved': False,
        'approval_id': approval_id,
        'expires_at': expires_at,
        'approvers': []
    }
