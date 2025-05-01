"""
Password reset functionality for the API authentication module.

This module provides endpoints and utilities for securely resetting user passwords,
including password reset token generation, validation, and password change operations.
It implements security best practices such as time-limited tokens, rate limiting,
and comprehensive logging for security and compliance.
"""

import logging
import requests
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple, Union

from flask import Blueprint, current_app, request, jsonify, g
from sqlalchemy.exc import SQLAlchemyError

from models.auth import User
from models import AuditLog
from core.security import (
    log_security_event,
    sanitize_username,
    validate_password_strength,
    generate_secure_token
)
from extensions import db, limiter, metrics
from . import auth_api


logger = logging.getLogger(__name__)


@auth_api.route('/password/request-reset', methods=['POST'])
@limiter.limit("5/hour")
def request_password_reset() -> Tuple[Dict[str, Any], int]:
    """
    Request a password reset token.

    This endpoint initiates the password reset process by sending
    a reset token to the user's registered email address.

    Request Body:
        {
            "email": "user@example.com",
            "recaptcha_token": "optional-recaptcha-token"
        }

    Returns:
        JSON with status message (always returns success to prevent user enumeration)
    """
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    recaptcha_token = data.get('recaptcha_token')

    # Track metrics for reset requests
    metrics.increment('auth.password_reset_requested', 1)

    # Basic validation
    if not email:
        logger.info("Password reset requested with missing email")
        return jsonify({
            "success": True,
            "message": "If your email is registered, you will receive password reset instructions."
        }), 200

    # Optional reCAPTCHA verification
    if current_app.config.get('RECAPTCHA_ENABLED'):
        if not recaptcha_token:
            metrics.increment('auth.password_reset_recaptcha_missing')
            return jsonify({
                "error": "reCAPTCHA verification required",
                "recaptcha_site_key": current_app.config.get('RECAPTCHA_SITE_KEY'),
                "code": "RECAPTCHA_REQUIRED"
            }), 400

        # Verify reCAPTCHA token
        recaptcha_verified = _verify_recaptcha(recaptcha_token)
        if not recaptcha_verified:
            metrics.increment('auth.password_reset_recaptcha_failed')
            return jsonify({
                "error": "reCAPTCHA verification failed",
                "recaptcha_site_key": current_app.config.get('RECAPTCHA_SITE_KEY'),
                "code": "RECAPTCHA_INVALID"
            }), 400

    # Check for throttling based on email address
    if _is_reset_throttled(email):
        logger.info(f"Password reset throttled for email: {email}")
        metrics.increment('auth.password_reset_throttled')
        return jsonify({
            "success": True,
            "message": "If your email is registered, you will receive password reset instructions."
        }), 200

    try:
        # Find user by email
        user = User.query.filter_by(email=email).first()

        # Proceed with reset if user exists and is active
        if user and user.status == User.STATUS_ACTIVE:
            # Check if already pending reset
            existing_pending = bool(
                user.password_reset_token and
                user.password_reset_expires and
                user.password_reset_expires > datetime.now(timezone.utc)
            )

            # Generate token if no pending reset or existing one is about to expire
            if not existing_pending or (user.password_reset_expires - datetime.now(timezone.utc) < timedelta(minutes=10)):
                # Generate secure token with sufficient entropy
                token = generate_secure_token()

                # Set expiry time (15 minutes by default)
                expiry_minutes = current_app.config.get('PASSWORD_RESET_EXPIRATION_MINUTES', 15)
                expires_at = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)

                # Store token and expiry in user record
                user.password_reset_token = token
                user.password_reset_expires = expires_at

                # Add reset request timestamp for throttling
                if hasattr(user, 'last_password_reset_request'):
                    user.last_password_reset_request = datetime.now(timezone.utc)

                db.session.commit()

                # Send email with reset link
                _send_password_reset_email(user, token)

                # Log event
                log_security_event(
                    event_type='password_reset_requested',
                    description=f"Password reset requested for user: {user.username}",
                    severity='info',
                    user_id=user.id,
                    ip_address=request.remote_addr,
                    details={"method": "email"}
                )

                logger.info(f"Password reset token generated for user: {user.username}")
                metrics.increment('auth.password_reset_token_generated')
            else:
                # Resend email with existing token
                _send_password_reset_email(user, user.password_reset_token)

                logger.info(f"Resending password reset email for user: {user.username}")
                metrics.increment('auth.password_reset_email_resent')

        else:
            # Log attempt for non-existent or inactive user without exposing this information
            logger.info(f"Password reset attempted for non-existent or inactive email: {email}")
            metrics.increment('auth.password_reset_invalid_email')

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error in password reset request: {str(e)}")
        metrics.increment('auth.password_reset_db_error')

    except Exception as e:
        logger.error(f"Error processing password reset: {str(e)}", exc_info=True)
        metrics.increment('auth.password_reset_error')

    # Always return success to prevent user enumeration
    return jsonify({
        "success": True,
        "message": "If your email is registered, you will receive password reset instructions."
    }), 200


@auth_api.route('/password/verify-token/<token>', methods=['GET'])
@limiter.limit("10/minute")
def verify_reset_token(token: str) -> Tuple[Dict[str, Any], int]:
    """
    Verify a password reset token.

    This endpoint checks if a password reset token is valid without consuming it.

    Args:
        token: The password reset token to verify

    Returns:
        JSON with token validity status
    """
    if not token or len(token) < 16:
        return jsonify({
            "valid": False,
            "error": "Invalid token format"
        }), 400

    try:
        # Find user by reset token
        user = User.query.filter_by(password_reset_token=token).first()

        if not user:
            metrics.increment('auth.password_reset_token_invalid')
            return jsonify({"valid": False}), 404

        # Check if token has expired
        if not user.password_reset_expires or user.password_reset_expires < datetime.now(timezone.utc):
            metrics.increment('auth.password_reset_token_expired')
            return jsonify({
                "valid": False,
                "error": "Token has expired"
            }), 401

        # Check if user is active
        if user.status != User.STATUS_ACTIVE:
            metrics.increment('auth.password_reset_inactive_user')
            return jsonify({
                "valid": False,
                "error": "User account is not active"
            }), 403

        # Token is valid
        metrics.increment('auth.password_reset_token_valid')
        return jsonify({
            "valid": True,
            "user_id": user.id,
            "username": user.username,
            "expires_at": user.password_reset_expires.isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Error verifying password reset token: {str(e)}", exc_info=True)
        metrics.increment('auth.password_reset_token_verify_error')
        return jsonify({
            "valid": False,
            "error": "Error verifying token"
        }), 500


@auth_api.route('/password/reset/<token>', methods=['POST'])
@limiter.limit("5/hour")
def reset_password(token: str) -> Tuple[Dict[str, Any], int]:
    """
    Reset a password using a valid reset token.

    This endpoint allows a user to set a new password using a valid reset token.

    Args:
        token: The password reset token

    Request Body:
        {
            "password": "new-secure-password"
        }

    Returns:
        JSON with reset result
    """
    if not token or len(token) < 16:
        return jsonify({
            "success": False,
            "error": "Invalid token format"
        }), 400

    data = request.get_json() or {}
    new_password = data.get('password', '')

    # Basic validation
    if not new_password:
        return jsonify({
            "success": False,
            "error": "New password is required"
        }), 400

    try:
        # Validate password strength before checking token to avoid token enumeration attacks
        is_valid, validation_errors = validate_password_strength(new_password)
        if not is_valid:
            metrics.increment('auth.password_reset_weak_password')
            return jsonify({
                "success": False,
                "error": "Password does not meet security requirements",
                "validation_errors": validation_errors
            }), 400

        # Find user by reset token
        user = User.query.filter_by(password_reset_token=token).first()

        if not user:
            metrics.increment('auth.password_reset_token_invalid')
            return jsonify({
                "success": False,
                "error": "Invalid or expired password reset token"
            }), 401

        # Check if token has expired
        if not user.password_reset_expires or user.password_reset_expires < datetime.now(timezone.utc):
            metrics.increment('auth.password_reset_token_expired')
            return jsonify({
                "success": False,
                "error": "Password reset token has expired"
            }), 401

        # Check if user is active
        if user.status != User.STATUS_ACTIVE:
            metrics.increment('auth.password_reset_inactive_user')
            return jsonify({
                "success": False,
                "error": "User account is not active"
            }), 403

        # Check for password reuse if history tracking is enabled
        if hasattr(user, 'has_used_password') and user.has_used_password(new_password):
            metrics.increment('auth.password_reset_password_reused')
            return jsonify({
                "success": False,
                "error": "Cannot reuse a previous password"
            }), 400

        # Set the new password
        user.set_password(new_password)

        # Update password change timestamp
        user.last_password_change = datetime.now(timezone.utc)

        # Clear the reset token
        user.password_reset_token = None
        user.password_reset_expires = None

        # Clear forced password change flag if set
        if hasattr(user, 'force_password_change'):
            user.force_password_change = False

        # Add to password history if supported
        if hasattr(user, 'add_password_to_history'):
            user.add_password_to_history()

        # Save changes
        db.session.commit()

        # Invalidate all sessions for security
        _invalidate_user_sessions(user.id)

        # Log the password reset
        log_security_event(
            event_type='password_reset_completed',
            description=f"Password reset completed for user: {user.username}",
            severity='info',
            user_id=user.id,
            ip_address=request.remote_addr,
            details={"method": "token"}
        )

        logger.info(f"Password successfully reset for user: {user.username}")
        metrics.increment('auth.password_reset_success')

        return jsonify({
            "success": True,
            "message": "Password has been reset successfully. You can now log in with your new password."
        }), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error in password reset: {str(e)}")
        metrics.increment('auth.password_reset_db_error')
        return jsonify({
            "success": False,
            "error": "A database error occurred while resetting your password"
        }), 500

    except Exception as e:
        logger.error(f"Error processing password reset: {str(e)}", exc_info=True)
        metrics.increment('auth.password_reset_error')
        return jsonify({
            "success": False,
            "error": "An error occurred while resetting your password"
        }), 500


@auth_api.route('/password/change', methods=['POST'])
@limiter.limit("5/minute")
def change_password() -> Tuple[Dict[str, Any], int]:
    """
    Change password for authenticated user.

    This endpoint allows an authenticated user to change their password
    by providing their current password and a new password.

    Request Body:
        {
            "current_password": "current-password",
            "new_password": "new-secure-password"
        }

    Returns:
        JSON with change result
    """
    # Ensure user is authenticated
    user_id = g.user.id if hasattr(g, 'user') and g.user else None
    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json() or {}
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')

    # Basic validation
    if not current_password:
        return jsonify({"error": "Current password is required"}), 400

    if not new_password:
        return jsonify({"error": "New password is required"}), 400

    # Track metrics
    metrics.increment('auth.password_change_attempt')

    try:
        # Get user from database
        user = User.query.get(user_id)
        if not user:
            metrics.increment('auth.password_change_user_not_found')
            return jsonify({"error": "User not found"}), 404

        # Verify current password
        if not user.check_password(current_password):
            metrics.increment('auth.password_change_wrong_password')
            log_security_event(
                event_type='password_change_failed',
                description=f"Password change failed: wrong current password for user {user.username}",
                severity='warning',
                user_id=user.id,
                ip_address=request.remote_addr
            )
            return jsonify({"error": "Current password is incorrect"}), 401

        # Validate new password strength
        is_valid, validation_errors = validate_password_strength(new_password)
        if not is_valid:
            metrics.increment('auth.password_change_weak_password')
            return jsonify({
                "error": "Password does not meet security requirements",
                "validation_errors": validation_errors
            }), 400

        # Check if new password is the same as current
        if user.check_password(new_password):
            metrics.increment('auth.password_change_same_password')
            return jsonify({
                "error": "New password cannot be the same as current password"
            }), 400

        # Check for password reuse if history tracking is enabled
        if hasattr(user, 'has_used_password') and user.has_used_password(new_password):
            metrics.increment('auth.password_change_password_reused')
            return jsonify({
                "error": "Cannot reuse a previous password"
            }), 400

        # Update the password
        user.set_password(new_password)

        # Update password change timestamp
        user.last_password_change = datetime.now(timezone.utc)

        # Clear forced password change flag if set
        if hasattr(user, 'force_password_change'):
            user.force_password_change = False

        # Add to password history if supported
        if hasattr(user, 'add_password_to_history'):
            user.add_password_to_history()

        # Save changes
        db.session.commit()

        # Log the password change
        log_security_event(
            event_type='password_changed',
            description=f"Password changed for user: {user.username}",
            severity='info',
            user_id=user.id,
            ip_address=request.remote_addr
        )

        logger.info(f"Password successfully changed for user: {user.username}")
        metrics.increment('auth.password_change_success')

        # Option: invalidate other sessions for security
        if current_app.config.get('INVALIDATE_SESSIONS_ON_PASSWORD_CHANGE', True):
            # Keep current session active
            current_session_id = request.cookies.get('session', None)
            _invalidate_user_sessions(user.id, exclude_session_id=current_session_id)

        return jsonify({
            "success": True,
            "message": "Password changed successfully"
        }), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error in password change: {str(e)}")
        metrics.increment('auth.password_change_db_error')
        return jsonify({"error": "A database error occurred while changing your password"}), 500

    except Exception as e:
        logger.error(f"Error processing password change: {str(e)}", exc_info=True)
        metrics.increment('auth.password_change_error')
        return jsonify({"error": "An error occurred while changing your password"}), 500


# Helper functions

def _send_password_reset_email(user: User, token: str) -> bool:
    """
    Send password reset email with token.

    Args:
        user: User model instance
        token: Password reset token

    Returns:
        bool: True if email sent successfully
    """
    try:
        # Get reset URL from config with fallback
        reset_url_base = current_app.config.get('PASSWORD_RESET_URL', '/reset-password/')
        reset_url = f"{reset_url_base}/{token}"

        # Get email templates from config
        email_subject = current_app.config.get(
            'PASSWORD_RESET_EMAIL_SUBJECT',
            'Reset Your Password'
        )

        # Get expiry time in minutes
        expiry_minutes = current_app.config.get('PASSWORD_RESET_EXPIRATION_MINUTES', 15)

        # Send email using notification system
        from services.notification import send_email_notification

        send_email_notification(
            recipient=user.email,
            template="password_reset",
            data={
                "username": user.username,
                "reset_url": reset_url,
                "expiry_minutes": expiry_minutes,
                "token": token
            },
            subject=email_subject
        )

        return True

    except ImportError:
        # Fallback to direct email sending if notification service not available
        from flask_mail import Message
        from extensions import mail

        try:
            if not mail:
                logger.error("Flask-Mail not configured for password reset emails")
                return False

            reset_url_base = current_app.config.get('PASSWORD_RESET_URL', '/reset-password/')
            reset_url = f"{reset_url_base}/{token}"

            msg = Message(
                "Reset Your Password",
                recipients=[user.email]
            )

            msg.body = f"""
                Hello {user.username},

                You recently requested to reset your password. Please click the link below to reset it:

                {reset_url}

                This link will expire in 15 minutes.

                If you did not request a password reset, please ignore this email or contact support.
            """

            msg.html = f"""
                <p>Hello {user.username},</p>
                <p>You recently requested to reset your password. Please click the link below to reset it:</p>
                <p><a href="{reset_url}">Reset Password</a></p>
                <p>This link will expire in 15 minutes.</p>
                <p>If you did not request a password reset, please ignore this email or contact support.</p>
            """

            mail.send(msg)
            return True

        except Exception as e:
            logger.error(f"Error sending password reset email: {str(e)}")
            metrics.increment('auth.password_reset_email_error')
            return False

    except Exception as e:
        logger.error(f"Error sending password reset email: {str(e)}")
        metrics.increment('auth.password_reset_email_error')
        return False


def _is_reset_throttled(email: str) -> bool:
    """
    Check if password reset requests are being throttled for this email.

    Args:
        email: The email address to check

    Returns:
        bool: True if requests should be throttled
    """
    try:
        # Check if Redis is available
        from extensions import redis
        if not redis:
            return False

        # Normalize email
        email = email.strip().lower()

        # Create Redis key for this email
        redis_key = f"password_reset_throttle:{email}"

        # Get last reset time from Redis
        last_reset_time = redis.get(redis_key)
        if last_reset_time:
            throttle_minutes = current_app.config.get('PASSWORD_RESET_EMAIL_THROTTLE', 5)

            # Check if enough time has passed
            last_time = int(last_reset_time)
            current_time = int(datetime.now(timezone.utc).timestamp())

            if current_time - last_time < throttle_minutes * 60:
                return True

        # Update timestamp
        redis.setex(
            redis_key,
            current_app.config.get('PASSWORD_RESET_EMAIL_THROTTLE', 5) * 60,
            int(datetime.now(timezone.utc).timestamp())
        )

        return False

    except (ImportError, Exception):
        # If Redis not available or error occurs, don't throttle
        return False


def _verify_recaptcha(token: str) -> bool:
    """
    Verify a reCAPTCHA token.

    Args:
        token: The reCAPTCHA token to verify

    Returns:
        bool: True if token is valid
    """
    try:
        secret_key = current_app.config.get('RECAPTCHA_SECRET_KEY')
        if not secret_key:
            logger.warning("reCAPTCHA enabled but no secret key configured")
            return True  # Don't block if misconfigured

        verify_url = "https://www.google.com/recaptcha/api/siteverify"
        response = requests.post(
            verify_url,
            data={
                'secret': secret_key,
                'response': token,
                'remoteip': request.remote_addr
            },
            timeout=5
        )

        result = response.json()
        return result.get('success', False)

    except Exception as e:
        logger.error(f"Error verifying reCAPTCHA: {str(e)}")
        return False


def _invalidate_user_sessions(user_id: int, exclude_session_id: Optional[str] = None) -> None:
    """
    Invalidate all active sessions for a user.

    Args:
        user_id: The user ID
        exclude_session_id: Optional session ID to exclude from invalidation
    """
    try:
        # Import the session model
        from models.auth.user_session import UserSession

        # Get all active sessions for this user
        query = UserSession.query.filter_by(
            user_id=user_id,
            is_active=True
        )

        # Exclude current session if specified
        if exclude_session_id:
            query = query.filter(UserSession.session_id != exclude_session_id)

        # Update all matching sessions
        sessions = query.all()
        for session in sessions:
            session.is_active = False
            session.ended_at = datetime.now(timezone.utc)
            session.termination_reason = "password_change"

        db.session.commit()

        # Log the session invalidation
        if sessions:
            logger.info(f"Invalidated {len(sessions)} sessions for user ID {user_id}")

    except (ImportError, SQLAlchemyError, Exception) as e:
        db.session.rollback()
        logger.error(f"Error invalidating user sessions: {str(e)}")


# Export functions that might be useful elsewhere
__all__ = [
    'request_password_reset',
    'verify_reset_token',
    'reset_password',
    'change_password'
]
