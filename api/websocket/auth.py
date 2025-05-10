"""
Authentication and security handlers for WebSocket connections.

This module provides authentication and authorization functionality for WebSocket
connections, including token validation, permission verification, and token
refreshing. It implements security best practices with comprehensive logging
and consistent error handling.

Key features:
- Token-based authentication for initial connection
- Permission verification for channel subscriptions
- Token refreshing for long-lived connections
- Security event logging for audit purposes
- Circuit breaking for external service calls
"""

import logging
import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Union, Tuple

from flask import current_app, request, session, g
from sqlalchemy.exc import SQLAlchemyError

from extensions import db, metrics, cache
from core.security import log_security_event, is_suspicious_ip
from models.auth import User, UserSession
from models.security import CircuitBreaker
from services.auth_service import AuthService

# Initialize logger
logger = logging.getLogger(__name__)

# Configure metrics
auth_attempt_counter = metrics.counter(
    'websocket_auth_attempts_total',
    'Total WebSocket authentication attempts'
)

auth_success_counter = metrics.counter(
    'websocket_auth_success_total',
    'Successful WebSocket authentication attempts'
)

auth_failure_counter = metrics.counter(
    'websocket_auth_failures_total',
    'Failed WebSocket authentication attempts',
    labels=['reason']
)

auth_latency = metrics.histogram(
    'websocket_auth_latency_seconds',
    'WebSocket authentication latency in seconds',
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
)

# Circuit breaker for authentication service
auth_circuit = CircuitBreaker(
    name="websocket_auth",
    failure_threshold=5,
    reset_timeout=60,
    half_open_after=30
)

# Cache settings
TOKEN_CACHE_TTL = 300  # 5 minutes


def authenticate_connection(request_obj) -> Dict[str, Any]:
    """
    Authenticate a WebSocket connection request.

    Validates the token from query parameters or headers, checks user status,
    and performs security verification. This is the main entry point for
    WebSocket authentication.

    Args:
        request_obj: WebSocket request object with connection details

    Returns:
        Dict with authentication result and user object if successful
    """
    start_time = time.time()
    client_ip = request_obj.remote_addr

    # Track metrics
    auth_attempt_counter.inc()

    # Extract token from query parameter or headers
    token = request_obj.args.get('token')
    if not token and 'Authorization' in request_obj.headers:
        auth_header = request_obj.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]

    # Check if token is missing
    if not token:
        logger.warning("WebSocket authentication failed: Missing token")
        auth_failure_counter.inc(labels={'reason': 'missing_token'})
        return {
            'success': False,
            'message': 'Authentication required',
            'user_id': None
        }

    try:
        # Verify token
        payload = verify_token(token)
        if not payload:
            logger.warning("WebSocket authentication failed: Invalid token")
            auth_failure_counter.inc(labels={'reason': 'invalid_token'})
            return {
                'success': False,
                'message': 'Invalid authentication token',
                'user_id': None
            }

        # Extract user ID from token
        user_id = payload.get('sub')
        if not user_id:
            logger.warning("WebSocket authentication failed: Missing user ID in token")
            auth_failure_counter.inc(labels={'reason': 'invalid_token_format'})
            return {
                'success': False,
                'message': 'Invalid token format',
                'user_id': None
            }

        # Get user from database
        user = User.query.get(user_id)
        if not user:
            logger.warning(f"WebSocket authentication failed: User ID {user_id} not found")
            auth_failure_counter.inc(labels={'reason': 'user_not_found'})
            return {
                'success': False,
                'message': 'User not found',
                'user_id': user_id
            }

        # Check if user is active
        if not user.is_active:
            logger.warning(f"WebSocket authentication failed: User {user.username} is inactive")
            auth_failure_counter.inc(labels={'reason': 'inactive_user'})
            return {
                'success': False,
                'message': 'User account is inactive',
                'user_id': user_id
            }

        # Check if user is locked
        if hasattr(user, 'is_locked') and user.is_locked():
            logger.warning(f"WebSocket authentication failed: User {user.username} is locked")
            auth_failure_counter.inc(labels={'reason': 'locked_user'})
            return {
                'success': False,
                'message': 'User account is locked',
                'user_id': user_id
            }

        # Check for suspicious IP (log but don't block)
        if is_suspicious_ip(client_ip):
            log_security_event(
                event_type='websocket_suspicious_ip',
                description=f"WebSocket connection from suspicious IP: {client_ip}",
                severity='warning',
                user_id=user_id,
                ip_address=client_ip
            )
            logger.warning(f"WebSocket connection from suspicious IP: {client_ip} for user {user.username}")
            metrics.increment('security.websocket_suspicious_ip')

        # Update user's last active timestamp
        if hasattr(UserActivity, 'update_last_active'):
            from models.auth.user_activity import UserActivity
            UserActivity.update_last_active(user.id)

        # Log successful authentication
        logger.info(f"WebSocket authentication successful for user: {user.username}")
        auth_time = time.time() - start_time
        auth_latency.observe(auth_time)
        auth_success_counter.inc()

        return {
            'success': True,
            'message': 'Authentication successful',
            'user': user,
            'user_id': user.id
        }

    except SQLAlchemyError as e:
        logger.error(f"Database error in WebSocket authentication: {str(e)}", exc_info=True)
        auth_failure_counter.inc(labels={'reason': 'database_error'})
        return {
            'success': False,
            'message': 'Authentication service unavailable',
            'user_id': None
        }

    except Exception as e:
        logger.error(f"WebSocket authentication error: {str(e)}", exc_info=True)
        auth_failure_counter.inc(labels={'reason': 'system_error'})
        return {
            'success': False,
            'message': 'Authentication error',
            'user_id': None
        }


@auth_circuit
def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify the JWT authentication token.

    Validates the token cryptographically and checks for expiration.
    Uses caching for performance optimization.

    Args:
        token: JWT token to verify

    Returns:
        Dict containing token payload if valid, None otherwise
    """
    if not token:
        return None

    # Check cache first if available
    if cache:
        cache_key = f"ws_token:{hashlib.sha256(token.encode()).hexdigest()}"
        cached_payload = cache.get(cache_key)
        if cached_payload:
            metrics.increment('websocket.token_cache_hit')
            return cached_payload

    try:
        # Use the central authentication service for verification
        success, user, payload = AuthService.verify_api_token(token)

        if success and user and payload:
            # Store in cache for reuse
            if cache:
                cache.set(cache_key, payload, timeout=TOKEN_CACHE_TTL)

            return payload
        else:
            # Return None for invalid token
            return None

    except Exception as e:
        logger.error(f"Error verifying token: {str(e)}", exc_info=True)
        metrics.increment('websocket.token_verify_error')
        return None


def validate_channel_permission(channel: str, user_id: int) -> bool:
    """
    Verify that a user has permission to subscribe to a channel.

    Implements the permission model for channel access, including
    resource-specific permissions and role-based checks.

    Args:
        channel: The channel name to validate
        user_id: The user ID to check permissions for

    Returns:
        bool: True if user has permission, False otherwise
    """
    try:
        # Initialize result as False (deny by default)
        has_permission = False

        # Special handling for different channel types
        if channel == 'system':
            # Require admin permission for system channel
            from core.security.cs_authorization import verify_permission
            has_permission = verify_permission(user_id, 'admin:system:view')

        elif channel.startswith('user:'):
            # User-specific channels require ID match or admin rights
            channel_parts = channel.split(':')
            if len(channel_parts) > 1:
                channel_user_id = channel_parts[1]
                # Allow if it's the user's own channel
                if str(user_id) == channel_user_id:
                    has_permission = True
                else:
                    # Otherwise require user admin permission
                    from core.security.cs_authorization import verify_permission
                    has_permission = verify_permission(user_id, 'admin:users:view')

        elif channel.startswith('resource:'):
            # Resource channels require specific permissions
            resource_type = "general"
            resource_id = None

            # Parse channel format: resource:<type>:<id>
            channel_parts = channel.split(':')
            if len(channel_parts) > 1:
                resource_type = channel_parts[1]
            if len(channel_parts) > 2:
                resource_id = channel_parts[2]

            # Check permission for this resource type
            from core.security.cs_authorization import verify_permission
            has_permission = verify_permission(user_id, f'{resource_type}:view')

            # If specific resource ID is provided, do additional checking
            if resource_id and has_permission:
                # Add resource-specific permission check here if needed
                pass

        elif channel.startswith('alerts:'):
            # Alert channels require alert permissions
            from core.security.cs_authorization import verify_permission
            has_permission = verify_permission(user_id, 'alerts:view')

        elif channel == 'metrics':
            # Metrics channel requires monitoring permissions
            from core.security.cs_authorization import verify_permission
            has_permission = verify_permission(user_id, 'metrics:view')

        else:
            # Default permission check for other channels
            # Allow access to basic channels by default
            has_permission = True

        # Log permission checks for sensitive channels
        if not has_permission and channel not in ['ping', 'status']:
            logger.info(f"Channel permission denied: {channel} for user {user_id}")

        return has_permission

    except Exception as e:
        # Log error and deny access on error
        logger.error(f"Error checking channel permission: {str(e)}", exc_info=True)
        return False


def refresh_token(user_id: int) -> Dict[str, Any]:
    """
    Generate a new access token for an authenticated user.

    Used to refresh WebSocket authentication tokens before they expire
    for long-lived connections.

    Args:
        user_id: The user ID to refresh the token for

    Returns:
        Dict containing refresh result, new token and expiry if successful
    """
    try:
        # Get user from database
        user = User.query.get(user_id)
        if not user:
            logger.warning(f"Token refresh failed: User {user_id} not found")
            return {
                'success': False,
                'message': 'User not found'
            }

        # Check if user is still active
        if not user.is_active:
            logger.warning(f"Token refresh failed: User {user.username} is inactive")
            return {
                'success': False,
                'message': 'User account is inactive'
            }

        # Generate new token with WebSocket-specific scopes
        token = AuthService.generate_api_token(
            user=user,
            expires_in=current_app.config.get('WS_TOKEN_LIFETIME', 3600),
            scopes=["websocket:connect"]
        )

        # Calculate expiry time
        expiry_seconds = current_app.config.get('WS_TOKEN_LIFETIME', 3600)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds)

        # Log token refresh
        logger.info(f"Token refreshed for user {user.username}")
        metrics.increment('websocket.token_refresh')

        return {
            'success': True,
            'message': 'Token refreshed successfully',
            'token': token,
            'expires_at': expires_at
        }

    except SQLAlchemyError as e:
        logger.error(f"Database error in token refresh: {str(e)}", exc_info=True)
        metrics.increment('websocket.token_refresh_error')
        return {
            'success': False,
            'message': 'Database error during token refresh'
        }

    except Exception as e:
        logger.error(f"Error refreshing token: {str(e)}", exc_info=True)
        metrics.increment('websocket.token_refresh_error')
        return {
            'success': False,
            'message': 'Token refresh failed'
        }


def is_connection_authorized(connection_id: str) -> bool:
    """
    Check if a WebSocket connection is currently authorized.

    Used for periodic validation of existing connections.

    Args:
        connection_id: WebSocket connection ID to check

    Returns:
        bool: True if connection is authorized, False otherwise
    """
    # This function would be implemented to check connection status
    # in the active_connections dictionary from routes.py
    #
    # This is a placeholder implementation that assumes access to
    # the active_connections dictionary from routes.py

    # Get active connections (implementation would depend on how this is shared)
    from .routes import active_connections

    if connection_id not in active_connections:
        return False

    # Check if connection data indicates an authenticated user
    connection_data = active_connections[connection_id]
    if 'user_id' not in connection_data:
        return False

    # Could add additional checks here like token expiry, user status, etc.
    return True


def get_connection_user(connection_id: str) -> Optional[Dict[str, Any]]:
    """
    Get user information for a WebSocket connection.

    Retrieves the user data associated with a connection ID.

    Args:
        connection_id: WebSocket connection ID

    Returns:
        Dict with user information if found, None otherwise
    """
    # This function would be implemented to access user information
    # from the active_connections dictionary in routes.py
    #
    # This is a placeholder implementation that assumes access to
    # the active_connections dictionary from routes.py

    # Get active connections (implementation would depend on how this is shared)
    from .routes import active_connections

    if connection_id not in active_connections:
        return None

    connection_data = active_connections[connection_id]
    if 'user_id' not in connection_data:
        return None

    # Return user information from connection data
    return {
        'user_id': connection_data['user_id'],
        'username': connection_data.get('username'),
        'role': connection_data.get('role')
    }


def generate_connection_token(user: User) -> str:
    """
    Generate a token specifically for WebSocket connections.

    Creates a JWT token with WebSocket-specific scopes and permissions.

    Args:
        user: User model instance to generate token for

    Returns:
        String containing the generated JWT token
    """
    # Generate token with websocket scope
    expiry_seconds = current_app.config.get('WS_TOKEN_LIFETIME', 3600)  # Default 1 hour

    token = AuthService.generate_api_token(
        user=user,
        expires_in=expiry_seconds,
        scopes=["websocket:connect"]
    )

    return token
