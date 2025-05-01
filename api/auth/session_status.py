"""
Session status management for API authentication.

This module provides functionality for retrieving and evaluating session status
information. It allows clients to check authentication state, session validity,
and expiration timing without requiring a full authentication flow.

The main uses are:
1. Client-side session status checks for UI state management
2. Remaining time checks before session timeout occurs
3. Session validation without modifying the session (non-extending)
4. MFA verification status
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Tuple, Optional

from flask import current_app, session, request, jsonify, g
from flask_limiter.util import get_remote_address
from sqlalchemy.exc import SQLAlchemyError

from core.security.cs_session import (
    validate_session as cs_validate_session,
    is_mfa_verified,
    log_security_event,
    _get_session_timeout
)
from extensions import limiter, metrics, db
from models import UserSession, AuditLog

# Initialize logger
logger = logging.getLogger(__name__)

# Define route decorator
from . import auth_api


@auth_api.route('/session/status', methods=['GET'])
@limiter.limit("30/minute")
def get_session_status() -> Tuple[Dict[str, Any], int]:
    """
    Get the current session status information.

    This endpoint provides information about the current session including
    authentication state, remaining time, and MFA verification status.

    Returns:
        JSON response with session status information
    """
    try:
        # Check if user is authenticated
        user_id = session.get('user_id')
        authenticated = user_id is not None

        result = {
            "authenticated": authenticated,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # If not authenticated, return early
        if not authenticated:
            return jsonify(result), 200

        # Add basic user information
        result.update({
            "user_id": user_id,
            "username": session.get('username'),
            "role": session.get('role'),
            "permissions": session.get('permissions', []),
        })

        # Add time information
        session_timeout = _get_session_timeout()

        if 'last_active' in session:
            try:
                last_active = datetime.fromisoformat(session['last_active'])
                elapsed = datetime.now(timezone.utc) - last_active
                remaining = timedelta(seconds=session_timeout) - elapsed

                result.update({
                    "last_active": session['last_active'],
                    "remaining_seconds": max(0, int(remaining.total_seconds())),
                    "expires_at": (last_active + timedelta(seconds=session_timeout)).isoformat()
                })
            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid timestamp in session: {e}")
                result["last_active_error"] = "Invalid timestamp format"

        # Check MFA status
        result["mfa_verified"] = is_mfa_verified()

        # Add client information
        result["client_ip"] = request.remote_addr
        result["user_agent"] = request.headers.get('User-Agent', '')

        # Get detailed session info from database if available
        session_id = session.get('session_id')
        if session_id:
            try:
                db_session = UserSession.query.filter_by(
                    session_id=session_id,
                    is_active=True
                ).first()

                if db_session:
                    result.update({
                        "session_id": session_id,
                        "created_at": db_session.created_at.isoformat() if db_session.created_at else None,
                        "login_method": db_session.login_method if hasattr(db_session, 'login_method') else None,
                        "client_type": db_session.client_type if hasattr(db_session, 'client_type') else "web"
                    })

                    # Check for concurrent sessions
                    if hasattr(db_session, 'user') and hasattr(db_session.user, 'id'):
                        active_sessions = UserSession.query.filter_by(
                            user_id=db_session.user.id,
                            is_active=True
                        ).count()
                        result["concurrent_sessions"] = active_sessions

            except SQLAlchemyError as e:
                logger.error(f"Database error retrieving session data: {e}")
                result["db_error"] = "Error retrieving session details"

        # Validate session integrity
        is_valid, error = cs_validate_session(session_data=session)
        result["session_valid"] = is_valid
        if not is_valid:
            result["validation_error"] = error

        # Track metrics
        metrics.increment('auth.session_status_check')

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Error processing session status request: {e}", exc_info=True)

        # Log security event for unexpected errors
        log_security_event(
            event_type=AuditLog.EVENT_SYSTEM_ERROR,
            description="Error in session status check",
            severity=AuditLog.SEVERITY_ERROR,
            user_id=session.get('user_id'),
            ip_address=request.remote_addr if request else None,
            details={"error": str(e)}
        )

        return jsonify({
            "error": "Session status check failed",
            "authenticated": False,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 500


@auth_api.route('/session/validate', methods=['POST'])
@limiter.limit("15/minute")
def validate_session() -> Tuple[Dict[str, Any], int]:
    """
    Validate the current session without extending it.

    This endpoint performs validation checks on the current session
    without updating the last_active time, allowing for validation
    without affecting session timeout calculations.

    Returns:
        JSON response with validation result
    """
    try:
        # Check if user is authenticated
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({
                "valid": False,
                "reason": "Not authenticated",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 401

        # Validate session without updating last_active
        is_valid, error = cs_validate_session(session_data=session, strict_mode=True)

        if is_valid:
            # Track metrics
            metrics.increment('auth.session_validation_success')

            return jsonify({
                "valid": True,
                "user_id": user_id,
                "username": session.get('username'),
                "role": session.get('role'),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 200
        else:
            # Track metrics
            metrics.increment('auth.session_validation_failure')

            # Log failed validation
            log_security_event(
                event_type=AuditLog.EVENT_SESSION_INVALID,
                description=f"Session validation failed: {error}",
                severity=AuditLog.SEVERITY_WARNING,
                user_id=user_id,
                ip_address=request.remote_addr
            )

            return jsonify({
                "valid": False,
                "reason": error or "Session validation failed",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 401

    except Exception as e:
        logger.error(f"Error validating session: {e}", exc_info=True)

        return jsonify({
            "valid": False,
            "reason": "Server error during validation",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 500
