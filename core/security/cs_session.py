"""
Session security management for Cloud Infrastructure Platform.

This module provides functions for secure session management including session
validation, timeout enforcement, secure session attributes, and protections
against session hijacking. It implements security best practices for session
management, including session regeneration, fingerprinting, and attribute binding.

The primary goals are:
1. Protect user sessions from theft and hijacking
2. Enforce proper session lifecycle and timeouts
3. Ensure session integrity with cryptographic protections
4. Provide secure attribute management
5. Support session validation and anomaly detection
"""

import uuid
import hashlib
import logging
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple, List, Union, Set, Callable

# Flask imports
from flask import session, request, current_app, has_request_context, has_app_context, g

# Internal imports
from extensions import db, metrics, get_redis_client
from models.security import AuditLog
from models.auth.user_session import UserSession
from .cs_constants import SECURITY_CONFIG
from .cs_audit import log_security_event, log_error, log_warning, log_info, log_debug

# Set up module-level logger
logger = logging.getLogger(__name__)


def validate_session(
    session_id: Optional[str] = None,
    session_data: Optional[Dict[str, Any]] = None,
    strict_mode: bool = False
) -> Tuple[bool, Optional[str]]:
    """
    Validate a user session for security and integrity.

    This function checks various security attributes of a session to ensure
    it hasn't been tampered with or hijacked, including validation of
    the session ID, user agent binding, and session timeout.

    Args:
        session_id: Optional session ID to validate (uses current if None)
        session_data: Optional session data to validate (uses current if None)
        strict_mode: Enable stricter validation rules

    Returns:
        Tuple of (is_valid, error_reason)
    """
    if not has_request_context():
        return False, "No request context"

    # Get current session data if not provided
    if session_data is None:
        session_data = session

    # If session is empty, it's invalid
    if not session_data:
        return False, "Empty session"

    # Check for required session attributes
    user_id = session_data.get('user_id')
    if not user_id:
        return False, "No user_id in session"

    # Check session expiration
    if 'last_active' in session_data:
        try:
            last_active = datetime.fromisoformat(session_data['last_active'])
            session_timeout = _get_session_timeout()

            if datetime.now(timezone.utc) - last_active > timedelta(seconds=session_timeout):
                metrics.increment('security.session_timeout')
                return False, "Session expired"
        except (ValueError, TypeError) as e:
            log_error(f"Invalid timestamp format in session: {e}")
            return False, "Invalid timestamp format"

    # Check user agent binding if enabled
    if _is_user_agent_binding_enabled():
        stored_user_agent = session_data.get('user_agent')
        if stored_user_agent and stored_user_agent != request.user_agent.string:
            log_security_event(
                event_type=AuditLog.EVENT_SESSION_ANOMALY,
                description="User agent mismatch in session validation",
                severity="warning",
                user_id=user_id,
                details={
                    "stored_agent": stored_user_agent,
                    "current_agent": request.user_agent.string
                }
            )
            if strict_mode:
                metrics.increment('security.user_agent_mismatch')
                return False, "User agent mismatch"

    # Check IP binding if enabled and in strict mode
    if strict_mode and _is_ip_binding_enabled():
        stored_ip = session_data.get('ip_address')
        if stored_ip and stored_ip != request.remote_addr:
            log_security_event(
                event_type=AuditLog.EVENT_SESSION_ANOMALY,
                description="IP address mismatch in session validation",
                severity="warning",
                user_id=user_id,
                details={
                    "stored_ip": stored_ip,
                    "current_ip": request.remote_addr
                }
            )
            metrics.increment('security.ip_mismatch')
            return False, "IP address mismatch"

    # Check session fingerprint if enabled and in strict mode
    if strict_mode and _is_fingerprint_binding_enabled():
        stored_fingerprint = session_data.get('fingerprint')
        if stored_fingerprint:
            current_fingerprint = generate_session_fingerprint()
            if stored_fingerprint != current_fingerprint:
                log_security_event(
                    event_type=AuditLog.EVENT_SESSION_ANOMALY,
                    description="Session fingerprint mismatch",
                    severity="warning",
                    user_id=user_id,
                    details={
                        "stored_fingerprint": stored_fingerprint[:8] + "...",
                        "current_fingerprint": current_fingerprint[:8] + "..."
                    }
                )
                metrics.increment('security.fingerprint_mismatch')
                return False, "Session fingerprint mismatch"

    # Check if session has been revoked in database
    if _should_check_db_session():
        session_id = session_data.get('session_id') or session_id
        if session_id:
            db_session = UserSession.query.filter_by(
                session_id=session_id,
                is_active=True,
                revoked=False
            ).first()

            if not db_session:
                metrics.increment('security.revoked_session_rejected')
                return False, "Session has been revoked"

            # Check if session has expired in database
            if db_session.expires_at and db_session.expires_at < datetime.now(timezone.utc):
                metrics.increment('security.expired_session_rejected')
                return False, "Session expired in database"

    # Session is valid
    metrics.increment('security.session_validation_success')
    return True, None


def regenerate_session_safely() -> bool:
    """
    Regenerate the session ID to prevent session fixation attacks.

    This function preserves important session data while creating a new
    session ID, effectively preventing session fixation attacks by
    rotating session identifiers after authentication events.

    Returns:
        bool: True if session was regenerated, False if there was an error
    """
    if not has_request_context():
        log_warning("Cannot regenerate session outside request context")
        return False

    try:
        # Save the important session values
        saved_data = {}
        keys_to_preserve = _get_session_keys_to_preserve()

        for key in keys_to_preserve:
            if key in session:
                saved_data[key] = session[key]

        # Generate a new session ID
        new_session_id = str(uuid.uuid4())

        # Clear the current session
        session.clear()

        # Set the new session ID
        session['session_id'] = new_session_id

        # Restore the saved values
        for key, value in saved_data.items():
            session[key] = value

        # Update last active time
        session['last_active'] = datetime.now(timezone.utc).isoformat()
        session['regenerated_at'] = datetime.now(timezone.utc).isoformat()

        # Update fingerprint if enabled
        if _is_fingerprint_binding_enabled():
            session['fingerprint'] = generate_session_fingerprint()

        # Generate new CSRF token if the app supports it
        if has_app_context() and hasattr(current_app, 'csrf'):
            session['csrf_token'] = current_app.csrf.generate_csrf_token()

        # Log the event
        user_id = saved_data.get('user_id', 'unknown')
        log_info(f"Session regenerated for user_id={user_id}")

        # Track metric
        metrics.increment('security.session_regenerated')

        # Log security event
        try:
            log_security_event(
                event_type='session_regenerated',
                description=f"Session regenerated safely",
                severity='info',
                user_id=saved_data.get('user_id'),
                ip_address=request.remote_addr
            )
        except Exception as e:
            log_warning(f"Failed to log security event for session regeneration: {e}")

        # Update the session in the database if persistent sessions are enabled
        _update_session_in_database(new_session_id)

        return True
    except Exception as e:
        log_error(f"Failed to regenerate session: {e}")
        metrics.increment('security.session_regeneration_failed')
        return False


def enforce_session_timeout() -> Tuple[bool, Optional[str]]:
    """
    Enforce session timeout based on inactivity.

    This function checks the session's last activity timestamp and enforces
    timeout if the configured timeout period has been exceeded.

    Returns:
        Tuple of (session_valid, error_reason)
    """
    if not has_request_context():
        return False, "No request context"

    if 'user_id' not in session:
        return True, None  # Not an authenticated session, no timeout needed

    if 'last_active' not in session:
        # No activity timestamp, can't determine timeout
        # Initialize it now
        session['last_active'] = datetime.now(timezone.utc).isoformat()
        return True, None

    try:
        last_active = datetime.fromisoformat(session['last_active'])
        timeout_seconds = _get_session_timeout()

        # Check if session has timed out
        if datetime.now(timezone.utc) - last_active > timedelta(seconds=timeout_seconds):
            # Session has timed out
            log_security_event(
                event_type=AuditLog.EVENT_SESSION_TIMEOUT,
                description="Session timeout enforced due to inactivity",
                severity="info",
                user_id=session.get('user_id'),
                ip_address=request.remote_addr
            )

            metrics.increment('security.session_timeout_enforced')

            # Clear the session to enforce the timeout
            session.clear()
            return False, "Session timeout due to inactivity"

        # Update last active time
        session['last_active'] = datetime.now(timezone.utc).isoformat()
        return True, None
    except (ValueError, TypeError) as e:
        # Invalid timestamp format, reset the timestamp
        log_error(f"Invalid timestamp in session: {e}")
        session['last_active'] = datetime.now(timezone.utc).isoformat()
        return True, None


def extend_session(minutes: int = None) -> bool:
    """
    Extend the current session lifetime.

    Args:
        minutes: Number of minutes to extend the session (uses default if None)

    Returns:
        bool: True if session was extended, False otherwise
    """
    if not has_request_context():
        return False

    if 'user_id' not in session:
        return False

    # Update last active time
    session['last_active'] = datetime.now(timezone.utc).isoformat()

    # Periodically regenerate session ID for security (20% chance)
    import random
    if random.random() < 0.2:
        regenerate_session_safely()

    # Update session in database if needed
    session_id = session.get('session_id')
    if session_id and _should_check_db_session():
        try:
            db_session = UserSession.query.filter_by(session_id=session_id).first()
            if db_session:
                # Calculate new expiration
                if minutes is None:
                    # Use default session timeout
                    extension = _get_session_timeout()
                else:
                    extension = minutes * 60

                db_session.expires_at = datetime.now(timezone.utc) + timedelta(seconds=extension)
                db_session.last_active = datetime.now(timezone.utc)
                db_session.activity_count += 1

                # Update location if available and changed
                if hasattr(g, 'location_data') and g.location_data:
                    current_location = g.location_data.get('location')
                    if current_location and current_location != db_session.last_location:
                        db_session.last_location = current_location

                        # Log location change if significant
                        if db_session.activity_count > 2:  # Don't log initial location setting
                            log_security_event(
                                event_type='session_location_change',
                                description="Session location changed",
                                severity='info',
                                user_id=db_session.user_id,
                                details={
                                    'previous_location': db_session.location_history[-1] if db_session.location_history else None,
                                    'new_location': current_location
                                }
                            )

                            # Add to location history
                            if not db_session.location_history:
                                db_session.location_history = []
                            db_session.location_history.append(current_location)

                db.session.add(db_session)
                db.session.commit()
        except Exception as e:
            log_error(f"Failed to extend session in database: {e}")
            db.session.rollback()
            return False

    # Cache last active time in Redis for high-traffic applications
    if _should_use_redis_session_cache():
        try:
            redis_client = get_redis_client()
            if redis_client and session_id:
                key = f"session:last_active:{session_id}"
                redis_client.setex(
                    key,
                    _get_session_timeout() * 2,  # Double timeout for safety
                    datetime.now(timezone.utc).timestamp()
                )
        except Exception as e:
            log_error(f"Failed to update session cache in Redis: {e}")

    return True


def set_secure_session_attribute(key: str, value: Any, encrypt: bool = False) -> bool:
    """
    Securely set a session attribute with optional encryption.

    This function sets a session attribute and provides the option to encrypt
    sensitive values before storing them in the session.

    Args:
        key: Session attribute key
        value: Value to store
        encrypt: Whether to encrypt the value (for sensitive data)

    Returns:
        bool: True if successful, False otherwise
    """
    if not has_request_context():
        return False

    try:
        if encrypt and value is not None:
            # Import here to avoid circular imports
            from .cs_crypto import encrypt_sensitive_data
            value = encrypt_sensitive_data(str(value))

        session[key] = value

        # Store sensitive attributes in database too if persistent sessions are used
        if encrypt and _should_check_db_session():
            session_id = session.get('session_id')
            if session_id:
                try:
                    db_session = UserSession.query.filter_by(session_id=session_id).first()
                    if db_session:
                        if not db_session.secure_attributes:
                            db_session.secure_attributes = {}

                        # Add encrypted value to secure attributes
                        db_session.secure_attributes[key] = value
                        db.session.add(db_session)
                        db.session.commit()
                except Exception as e:
                    log_error(f"Failed to store secure attribute in database: {e}")
                    db.session.rollback()

        return True
    except Exception as e:
        log_error(f"Failed to set secure session attribute: {e}")
        return False


def get_secure_session_attribute(key: str, decrypt: bool = False, default: Any = None) -> Any:
    """
    Securely get a session attribute with optional decryption.

    This function retrieves a session attribute and provides the option to decrypt
    sensitive values that were encrypted when stored.

    Args:
        key: Session attribute key
        decrypt: Whether to decrypt the value (for sensitive data)
        default: Default value if key does not exist

    Returns:
        The session attribute value or default if not found
    """
    if not has_request_context():
        return default

    try:
        value = session.get(key, default)

        if decrypt and value is not None:
            # Import here to avoid circular imports
            from .cs_crypto import decrypt_sensitive_data
            value = decrypt_sensitive_data(value)

        return value
    except Exception as e:
        log_error(f"Failed to get secure session attribute: {e}")
        return default


def generate_session_fingerprint() -> str:
    """
    Generate a fingerprint for the current session.

    This function creates a fingerprint based on various browser and
    environment characteristics to help identify session anomalies.

    Returns:
        str: Session fingerprint hash
    """
    if not has_request_context():
        return ""

    # Collect fingerprinting factors
    fingerprint_factors = [
        request.user_agent.string,
        request.user_agent.browser,
        request.user_agent.platform,
        request.user_agent.version,
        request.user_agent.language or "",
        request.accept_languages.to_header() if hasattr(request, 'accept_languages') else "",
        request.headers.get('Accept', ""),
        request.headers.get('Accept-Encoding', ""),
        request.headers.get('Accept-Language', ""),
        request.headers.get('Sec-CH-UA', ""),  # Client hints if available
        request.headers.get('Sec-CH-UA-Platform', ""),
        # Omitting IP address to allow for network changes
    ]

    # Create string from factors and hash it
    fingerprint_str = "|".join(str(factor) for factor in fingerprint_factors)

    # Add a server-side secret to prevent forgery if available
    if has_app_context():
        secret = current_app.config.get('SECRET_KEY', '')
        fingerprint_str = f"{fingerprint_str}|{secret}"

    # Create a hash of the fingerprint
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()


def check_session_attacks() -> Tuple[bool, Optional[str]]:
    """
    Check for common session attacks and hijacking attempts.

    This function analyzes the current session for signs of attacks such as
    session fixation, sidejacking, and other common session security exploits.

    Returns:
        Tuple of (is_secure, attack_type)
    """
    if not has_request_context():
        return True, None  # No request context, can't check

    if 'user_id' not in session:
        return True, None  # Not authenticated, no check needed

    # Check for session fixation attempts
    if 'created_at' not in session and 'auth_time' not in session:
        # Session doesn't have creation timestamp, which is suspicious
        log_security_event(
            event_type=AuditLog.EVENT_SESSION_ANOMALY,
            description="Potential session fixation - missing creation timestamp",
            severity="warning",
            user_id=session.get('user_id'),
            ip_address=request.remote_addr
        )
        metrics.increment('security.session_attack_detected')
        return False, "session_fixation"

    # Check for abnormal referrer
    http_referrer = request.headers.get('Referer', '')
    if http_referrer and _should_validate_referrer():
        try:
            from urllib.parse import urlparse
            referrer_domain = urlparse(http_referrer).netloc

            # Get allowed domains
            allowed_domains = _get_allowed_referrer_domains()

            if allowed_domains and referrer_domain and referrer_domain not in allowed_domains:
                log_security_event(
                    event_type=AuditLog.EVENT_SESSION_ANOMALY,
                    description=f"Suspicious referrer detected: {referrer_domain}",
                    severity="warning",
                    user_id=session.get('user_id'),
                    ip_address=request.remote_addr
                )
                metrics.increment('security.suspicious_referrer')
                if _is_in_strict_mode():
                    return False, "suspicious_referrer"
        except Exception as e:
            log_error(f"Error parsing referrer: {e}")

    # Check for cookie tampering by validating the session signature
    if _is_session_signing_enabled() and 'session_signature' in session:
        valid_sig = _verify_session_signature()
        if not valid_sig:
            log_security_event(
                event_type=AuditLog.EVENT_SESSION_ANOMALY,
                description="Session cookie tampering detected - invalid signature",
                severity="error",
                user_id=session.get('user_id'),
                ip_address=request.remote_addr
            )
            metrics.increment('security.session_tampering')
            return False, "cookie_tampering"

    # Check for unusual geolocation if available
    if hasattr(g, 'location_data') and g.location_data and _should_check_db_session():
        session_id = session.get('session_id')
        if session_id:
            try:
                db_session = UserSession.query.filter_by(session_id=session_id).first()
                if db_session and db_session.last_location:
                    current_location = g.location_data.get('location')
                    prev_location = db_session.last_location

                    # If locations are significantly different and changed rapidly
                    if current_location and current_location != prev_location:
                        # Check if distance is large and time is short
                        from .cs_monitoring import analyze_location_change
                        if analyze_location_change(prev_location, current_location, db_session.last_active):
                            log_security_event(
                                event_type=AuditLog.EVENT_SESSION_ANOMALY,
                                description="Suspicious location change detected",
                                severity="warning",
                                user_id=session.get('user_id'),
                                details={
                                    'previous_location': prev_location,
                                    'current_location': current_location
                                }
                            )
                            metrics.increment('security.suspicious_location')
                            if _is_in_strict_mode():
                                return False, "suspicious_location"
            except Exception as e:
                log_error(f"Error checking location changes: {e}")

    # Session appears to be secure
    return True, None


def end_session() -> bool:
    """
    Securely end the current user session.

    This function properly terminates the user's session, both in the
    browser and in any backend storage (like database or Redis).

    Returns:
        bool: True if session was successfully terminated
    """
    if not has_request_context():
        return False

    try:
        user_id = session.get('user_id')
        session_id = session.get('session_id')

        # Log session end event
        if user_id:
            log_security_event(
                event_type=AuditLog.EVENT_SESSION_END,
                description=f"User session ended",
                severity="info",
                user_id=user_id,
                ip_address=request.remote_addr
            )

        # Update database if persistent sessions are used
        if session_id and _should_check_db_session():
            try:
                db_session = UserSession.query.filter_by(session_id=session_id).first()
                if db_session:
                    db_session.is_active = False
                    db_session.ended_at = datetime.now(timezone.utc)
                    db.session.add(db_session)
                    db.session.commit()
            except Exception as e:
                log_error(f"Failed to update session in database on logout: {e}")
                db.session.rollback()

        # Clean up Redis cache if used
        if session_id and _should_use_redis_session_cache():
            try:
                redis_client = get_redis_client()
                if redis_client:
                    # Clean up any session-related keys
                    redis_client.delete(f"session:last_active:{session_id}")
                    redis_client.delete(f"session:data:{session_id}")
            except Exception as e:
                log_error(f"Failed to clean up Redis session cache: {e}")

        # Clear the session
        session.clear()
        metrics.increment('security.session_ended')
        return True
    except Exception as e:
        log_error(f"Error ending session: {e}")
        return False


def sign_session() -> bool:
    """
    Create a cryptographic signature of critical session data.

    This adds tamper protection to the session by creating a signature
    of critical session values that can be verified later.

    Returns:
        bool: True if signature was successfully added
    """
    if not has_request_context():
        return False

    if 'user_id' not in session:
        return False  # No need to sign unauthenticated sessions

    try:
        # Collect critical values to include in signature
        critical_keys = ['user_id', 'role', 'permissions', 'session_id', 'created_at', 'auth_method']
        signature_data = {}

        for key in critical_keys:
            if key in session:
                signature_data[key] = session[key]

        # Add a timestamp to the signature data
        signature_data['signature_time'] = datetime.now(timezone.utc).isoformat()

        # Create string representation of data
        data_str = json.dumps(signature_data, sort_keys=True)

        # Create signature using server secret
        if has_app_context():
            secret = current_app.config.get('SECRET_KEY', '')
            signature_str = f"{data_str}|{secret}"
            signature = hashlib.sha256(signature_str.encode()).hexdigest()

            # Store signature in session
            session['session_signature'] = signature
            session['signature_time'] = signature_data['signature_time']

            return True
    except Exception as e:
        log_error(f"Failed to sign session: {e}")

    return False


def initialize_secure_session(
    user_id: Union[int, str],
    role: Optional[str] = None,
    permissions: Optional[List[str]] = None,
    remember: bool = False,
    auth_method: str = "password"
) -> bool:
    """
    Initialize a secure user session after successful authentication.

    This function sets up a new session with security best practices including
    session ID generation, fingerprinting, and tamper protection.

    Args:
        user_id: Authenticated user ID
        role: User role (if applicable)
        permissions: List of user permissions (if applicable)
        remember: Whether to enable "remember me" functionality
        auth_method: Authentication method used ("password", "sso", "mfa", etc)

    Returns:
        bool: True if session was successfully initialized
    """
    if not has_request_context():
        return False

    try:
        # Clear any existing session
        session.clear()

        # Generate a new session ID
        session_id = str(uuid.uuid4())

        # Set basic session data
        session['user_id'] = user_id
        session['session_id'] = session_id
        session['created_at'] = datetime.now(timezone.utc).isoformat()
        session['last_active'] = datetime.now(timezone.utc).isoformat()
        session['auth_method'] = auth_method

        # Set user information
        if role:
            session['role'] = role

        if permissions:
            session['permissions'] = permissions

        # Set security attributes
        session['ip_address'] = request.remote_addr
        session['user_agent'] = request.user_agent.string

        # Add browser fingerprint if enabled
        if _is_fingerprint_binding_enabled():
            session['fingerprint'] = generate_session_fingerprint()

        # Set remember me flag if requested
        if remember:
            session.permanent = True
            # Set the lifetime from config
            if has_app_context():
                days = current_app.config.get('REMEMBER_ME_DAYS', 30)
                current_app.permanent_session_lifetime = timedelta(days=days)

        # Create session signature for tamper protection
        if _is_session_signing_enabled():
            sign_session()

        # Create database record if persistent sessions are used
        _create_session_in_database(session_id, user_id, remember, auth_method)

        # Log the session creation
        log_security_event(
            event_type=AuditLog.EVENT_SESSION_CREATE,
            description=f"New session created for user {user_id}",
            severity="info",
            user_id=user_id,
            ip_address=request.remote_addr,
            details={
                'auth_method': auth_method,
                'remember_me': remember
            }
        )

        metrics.increment('security.session_created')
        return True
    except Exception as e:
        log_error(f"Failed to initialize session: {e}")
        session.clear()  # Clean up on failure
        return False


def track_session_anomaly(
    anomaly_type: str,
    description: str,
    severity: str = "warning",
    details: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log a session anomaly for security monitoring.

    This function tracks unusual or suspicious session behaviors for
    security monitoring and threat detection purposes.

    Args:
        anomaly_type: Type of anomaly detected
        description: Description of the anomaly
        severity: Severity level ("info", "warning", "error", "critical")
        details: Additional details about the anomaly
    """
    if not has_request_context():
        return

    user_id = session.get('user_id')

    # Track the anomaly in metrics
    metrics.increment(f'security.session_anomaly.{anomaly_type}')

    # Log the security event
    log_security_event(
        event_type=AuditLog.EVENT_SESSION_ANOMALY,
        description=description,
        severity=severity,
        user_id=user_id,
        ip_address=request.remote_addr,
        details=details
    )

    # Flag the session as suspicious if in database
    if user_id and _should_check_db_session():
        session_id = session.get('session_id')
        if session_id:
            try:
                db_session = UserSession.query.filter_by(session_id=session_id).first()
                if db_session:
                    # Mark session as suspicious
                    db_session.is_suspicious = True
                    db_session.last_anomaly = description

                    # Add anomaly to history if it doesn't exist
                    if not db_session.anomaly_history:
                        db_session.anomaly_history = []

                    # Add to anomaly history with timestamp
                    db_session.anomaly_history.append({
                        'type': anomaly_type,
                        'description': description,
                        'severity': severity,
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    })

                    db.session.add(db_session)
                    db.session.commit()
            except Exception as e:
                log_error(f"Failed to flag session as suspicious: {e}")
                db.session.rollback()


def mark_requiring_mfa() -> None:
    """
    Mark the current session as requiring MFA verification.

    This function flags the current session as requiring multi-factor
    authentication before accessing protected resources.
    """
    if has_request_context():
        session['mfa_required'] = True
        session['mfa_verified'] = False


def mark_mfa_verified() -> None:
    """
    Mark the current session as having completed MFA verification.

    This function records that multi-factor authentication has been
    successfully completed in the current session.
    """
    if has_request_context():
        session['mfa_verified'] = True
        session['mfa_verified_at'] = datetime.now(timezone.utc).isoformat()

        # Record this in the database if using persistent sessions
        session_id = session.get('session_id')
        if session_id and _should_check_db_session():
            try:
                db_session = UserSession.query.filter_by(session_id=session_id).first()
                if db_session:
                    db_session.mfa_verified = True
                    db_session.mfa_verified_at = datetime.now(timezone.utc)

                    # Log event for audit purposes
                    log_security_event(
                        event_type='mfa_verified',
                        description=f"Multi-factor authentication verified",
                        severity='info',
                        user_id=db_session.user_id,
                        ip_address=request.remote_addr
                    )

                    db.session.add(db_session)
                    db.session.commit()
            except Exception as e:
                log_error(f"Failed to update MFA status in database: {e}")
                db.session.rollback()


def is_mfa_verified() -> bool:
    """
    Check if the current session has completed MFA verification.

    Returns:
        bool: True if MFA has been verified, False otherwise
    """
    if not has_request_context():
        return False

    # Check if MFA is verified
    mfa_verified = session.get('mfa_verified', False)

    # Check if verification has expired
    if mfa_verified and 'mfa_verified_at' in session:
        try:
            verified_at = datetime.fromisoformat(session['mfa_verified_at'])
            mfa_timeout = SECURITY_CONFIG.get('MFA_TIMEOUT', 24 * 3600)  # 24h default

            if datetime.now(timezone.utc) - verified_at > timedelta(seconds=mfa_timeout):
                return False
        except (ValueError, TypeError):
            return False

    return mfa_verified


def revoke_all_user_sessions(user_id: Union[int, str], exempt_current: bool = True) -> int:
    """
    Revoke all active sessions for a given user.

    This function is used when a user changes their password, when suspicious
    activity is detected, or for administrative session termination.

    Args:
        user_id: ID of the user whose sessions should be revoked
        exempt_current: Whether to exempt the current session from revocation

    Returns:
        int: Number of sessions revoked
    """
    if not _should_check_db_session():
        return 0

    try:
        # Build base query for active sessions
        query = UserSession.query.filter_by(
            user_id=int(user_id),  # Ensure user_id is an integer
            is_active=True,
            revoked=False
        )

        # Exclude current session if requested
        if exempt_current and has_request_context():
            current_session_id = session.get('session_id')
            if current_session_id:
                query = query.filter(UserSession.session_id != current_session_id)

        # Get sessions to revoke
        sessions_to_revoke = query.all()
        revoked_count = 0

        # Revoke each session
        for sess in sessions_to_revoke:
            sess.is_active = False
            sess.revoked = True
            sess.revoked_at = datetime.now(timezone.utc)
            sess.revocation_reason = "Administrative revocation"
            db.session.add(sess)
            revoked_count += 1

            # Clear from Redis if used
            if _should_use_redis_session_cache():
                try:
                    redis_client = get_redis_client()
                    if redis_client:
                        redis_client.delete(f"session:last_active:{sess.session_id}")
                        redis_client.delete(f"session:data:{sess.session_id}")
                except Exception as e:
                    log_error(f"Failed to clear Redis session cache: {e}")

        if revoked_count > 0:
            # Commit changes
            db.session.commit()

            # Log event
            log_security_event(
                event_type='sessions_revoked',
                description=f"Revoked {revoked_count} sessions for user {user_id}",
                severity='info',
                user_id=user_id,
                ip_address=request.remote_addr if has_request_context() else None,
                details={'exempt_current': exempt_current}
            )

            # Track metric
            metrics.increment('security.sessions_revoked', revoked_count)

        return revoked_count
    except Exception as e:
        log_error(f"Failed to revoke user sessions: {e}")
        db.session.rollback()
        return 0


def get_active_sessions(user_id: Union[int, str]) -> List[Dict[str, Any]]:
    """
    Get information about all active sessions for a user.

    This function retrieves information about active user sessions,
    useful for providing users with visibility into their account access.

    Args:
        user_id: ID of the user whose sessions should be retrieved

    Returns:
        List[Dict[str, Any]]: List of session information dictionaries
    """
    if not _should_check_db_session():
        return []

    try:
        # Query active sessions
        sessions = UserSession.query.filter_by(
            user_id=int(user_id),
            is_active=True,
            revoked=False
        ).order_by(UserSession.created_at.desc()).all()

        # Format session info
        session_info = []
        current_session_id = session.get('session_id') if has_request_context() else None

        for sess in sessions:
            # Create basic info dictionary
            info = {
                'session_id': sess.session_id,
                'created_at': sess.created_at.isoformat() if sess.created_at else None,
                'last_active': sess.last_active.isoformat() if sess.last_active else None,
                'user_agent': sess.user_agent,
                'ip_address': sess.ip_address,
                'location': sess.last_location,
                'device_info': sess.device_info,
                'is_current': sess.session_id == current_session_id,
                'login_method': sess.login_method,
                'mfa_verified': sess.mfa_verified,
            }

            session_info.append(info)

        return session_info
    except Exception as e:
        log_error(f"Failed to retrieve active sessions: {e}")
        return []


def revoke_session(session_id: str, reason: str = "User-initiated revocation") -> bool:
    """
    Revoke a specific session by ID.

    This function revokes a specific session, typically used when a user
    logs out a particular session from their account settings.

    Args:
        session_id: The session ID to revoke
        reason: The reason for revocation

    Returns:
        bool: True if the session was successfully revoked
    """
    if not _should_check_db_session():
        return False

    try:
        # Find the session
        db_session = UserSession.query.filter_by(session_id=session_id).first()

        if not db_session:
            return False

        # Check if the current user can revoke this session
        if has_request_context() and 'user_id' in session:
            current_user_id = session.get('user_id')

            # Only allow users to revoke their own sessions unless they're admin
            is_admin = 'role' in session and session.get('role') == 'admin'
            if str(db_session.user_id) != str(current_user_id) and not is_admin:
                log_security_event(
                    event_type='unauthorized_session_revocation',
                    description=f"Unauthorized attempt to revoke session",
                    severity='warning',
                    user_id=current_user_id,
                    details={'target_session': session_id, 'target_user_id': db_session.user_id}
                )
                return False

        # Revoke the session
        db_session.is_active = False
        db_session.revoked = True
        db_session.revoked_at = datetime.now(timezone.utc)
        db_session.revocation_reason = reason
        db.session.add(db_session)
        db.session.commit()

        # Clear from Redis if used
        if _should_use_redis_session_cache():
            try:
                redis_client = get_redis_client()
                if redis_client:
                    redis_client.delete(f"session:last_active:{session_id}")
                    redis_client.delete(f"session:data:{session_id}")
            except Exception as e:
                log_error(f"Failed to clear Redis session cache: {e}")

        # Log the event
        log_security_event(
            event_type='session_revoked',
            description=f"Session revoked: {reason}",
            severity='info',
            user_id=db_session.user_id,
            details={'session_id': session_id}
        )

        metrics.increment('security.session_revoked')
        return True
    except Exception as e:
        log_error(f"Failed to revoke session: {e}")
        db.session.rollback()
        return False


def initialize_session_security(app) -> bool:
    """
    Initialize session security for the Flask application.

    Args:
        app: Flask application instance

    Returns:
        bool: True if session security was successfully initialized
    """
    if not app:
        logger.error("Cannot initialize session security: No app provided")
        return False

    try:
        logger.info("Initializing session security")

        # Register before_request handler to validate sessions
        @app.before_request
        def validate_session_before_request():
            if not has_request_context():
                return

            # Skip validation for public routes or static files
            if _is_public_route():
                return

            # Check session timeout
            session_valid, error_reason = enforce_session_timeout()
            if not session_valid:
                # Handle session expiration
                _handle_invalid_session(error_reason)

            # Validate session security
            is_valid, error_reason = validate_session()
            if not is_valid:
                # Handle invalid session
                _handle_invalid_session(error_reason)

            # Check for session attacks
            is_secure, attack_type = check_session_attacks()
            if not is_secure:
                # Handle potential attack
                _handle_session_attack(attack_type)

        # Register after_request handler to apply security headers
        @app.after_request
        def secure_session_headers(response):
            # Add security headers
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

            # Set secure cookie flags if in production
            if not app.debug and not app.testing:
                response.set_cookie('session',
                    value=response.headers.get('Set-Cookie', ''),
                    secure=True,
                    httponly=True,
                    samesite='Lax'
                )

            return response

        logger.info("Session security initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize session security: {e}")
        return False


# Helper functions

def _get_session_timeout() -> int:
    """Get session timeout in seconds from config or default."""
    if has_app_context():
        return current_app.config.get('SESSION_TIMEOUT', SECURITY_CONFIG.get('SESSION_TIMEOUT', 1800))
    return SECURITY_CONFIG.get('SESSION_TIMEOUT', 1800)  # Default 30 minutes


def _get_session_keys_to_preserve() -> List[str]:
    """Get list of session keys to preserve during regeneration."""
    keys = [
        'user_id', 'username', 'role', 'last_active',
        'csrf_token', 'mfa_verified', 'permissions',
        'auth_method', 'mfa_verified_at'
    ]

    if has_app_context():
        custom_keys = current_app.config.get('SESSION_PRESERVE_KEYS', [])
        keys.extend(custom_keys)

    return keys


def _is_user_agent_binding_enabled() -> bool:
    """Check if user agent binding is enabled."""
    if has_app_context():
        return current_app.config.get('BIND_SESSION_TO_USER_AGENT', True)
    return SECURITY_CONFIG.get('BIND_SESSION_TO_USER_AGENT', True)


def _is_ip_binding_enabled() -> bool:
    """Check if IP binding is enabled."""
    if has_app_context():
        return current_app.config.get('BIND_SESSION_TO_IP', False)
    return SECURITY_CONFIG.get('BIND_SESSION_TO_IP', False)


def _is_fingerprint_binding_enabled() -> bool:
    """Check if fingerprint binding is enabled."""
    if has_app_context():
        return current_app.config.get('USE_SESSION_FINGERPRINTING', True)
    return SECURITY_CONFIG.get('USE_SESSION_FINGERPRINTING', True)


def _is_session_signing_enabled() -> bool:
    """Check if session signing is enabled."""
    if has_app_context():
        return current_app.config.get('SIGN_SESSION_DATA', True)
    return SECURITY_CONFIG.get('SIGN_SESSION_DATA', True)


def _is_in_strict_mode() -> bool:
    """Check if strict security mode is enabled."""
    if has_app_context():
        return current_app.config.get('STRICT_SESSION_SECURITY', False)
    return SECURITY_CONFIG.get('STRICT_SESSION_SECURITY', False)


def _should_check_db_session() -> bool:
    """Check if we should validate against database session."""
    if has_app_context():
        return current_app.config.get('USE_DB_SESSIONS', True)
    return SECURITY_CONFIG.get('USE_DB_SESSIONS', True)


def _should_validate_referrer() -> bool:
    """Check if referrer validation is enabled."""
    if has_app_context():
        return current_app.config.get('VALIDATE_REFERRER', True)
    return SECURITY_CONFIG.get('VALIDATE_REFERRER', True)


def _should_use_redis_session_cache() -> bool:
    """Check if Redis session cache should be used."""
    if has_app_context():
        return current_app.config.get('USE_REDIS_SESSION_CACHE', False)
    return SECURITY_CONFIG.get('USE_REDIS_SESSION_CACHE', False)


def _get_allowed_referrer_domains() -> Set[str]:
    """Get allowed referrer domains."""
    if has_app_context():
        domains = current_app.config.get('ALLOWED_REFERRERS', [])
        # Make sure SERVER_NAME is always in the list
        server_name = current_app.config.get('SERVER_NAME')
        if server_name and server_name not in domains:
            domains.append(server_name)
        return set(domains)
    return set(SECURITY_CONFIG.get('ALLOWED_REFERRERS', []))


def _is_public_route() -> bool:
    """Check if the current route is a public route (no auth required)."""
    if not has_app_context() or not has_request_context():
        return False

    # Skip validation for static files
    if request.path.startswith('/static/'):
        return True

    # Check against configured public routes
    public_routes = current_app.config.get('PUBLIC_ROUTES', ['/login', '/register', '/forgot-password'])
    public_prefixes = current_app.config.get('PUBLIC_ROUTE_PREFIXES', ['/public/', '/api/public/'])

    # Check exact matches
    if request.path in public_routes:
        return True

    # Check prefixes
    if any(request.path.startswith(prefix) for prefix in public_prefixes):
        return True

    return False


def _handle_invalid_session(reason: Optional[str]) -> None:
    """Handle an invalid session by redirecting or returning error."""
    if not has_request_context():
        return

    # Only clear session for GET requests (to avoid losing form data)
    if request.method == 'GET':
        # Keep some info for diagnostics before clearing
        user_id = session.get('user_id')
        session.clear()

        # Set a flash message if supported
        if has_app_context() and hasattr(current_app, 'extensions') and 'flask_login' in current_app.extensions:
            # Import here to avoid circular imports
            from flask import flash
            flash(f"Your session has expired or is invalid ({reason}). Please log in again.", "warning")

        # Log the event
        log_security_event(
            event_type='invalid_session_cleared',
            description=f"Invalid session cleared: {reason}",
            severity='info',
            user_id=user_id
        )

    # For API requests, set flag for middleware to return error
    if request.path.startswith('/api/'):
        g.session_invalid = True
        g.session_error = reason


def _handle_session_attack(attack_type: Optional[str]) -> None:
    """Handle a potential session attack."""
    if not has_request_context():
        return

    user_id = session.get('user_id')

    # Clear session and force re-login
    session.clear()

    # Log security event
    log_security_event(
        event_type='session_attack_mitigated',
        description=f"Session attack mitigated: {attack_type}",
        severity='warning',
        user_id=user_id,
        ip_address=request.remote_addr,
        details={'attack_type': attack_type}
    )

    # Set flag for middleware
    g.session_attack = True
    g.attack_type = attack_type


def _verify_session_signature() -> bool:
    """Verify the session's signature to detect tampering."""
    if not has_request_context() or 'session_signature' not in session:
        return False

    try:
        # Collect critical values included in signature
        critical_keys = ['user_id', 'role', 'permissions', 'session_id', 'created_at', 'auth_method']
        signature_data = {}

        for key in critical_keys:
            if key in session:
                signature_data[key] = session[key]

        # Add the timestamp used when signing
        if 'signature_time' in session:
            signature_data['signature_time'] = session['signature_time']

        # Create string representation of data
        data_str = json.dumps(signature_data, sort_keys=True)

        # Create signature using server secret
        if has_app_context():
            secret = current_app.config.get('SECRET_KEY', '')
            signature_str = f"{data_str}|{secret}"
            expected_signature = hashlib.sha256(signature_str.encode()).hexdigest()

            # Compare with stored signature using constant-time comparison
            stored_signature = session.get('session_signature', '')

            # Use hmac.compare_digest for constant-time comparison
            import hmac
            return hmac.compare_digest(stored_signature, expected_signature)
    except Exception as e:
        log_error(f"Error verifying session signature: {e}")

    return False


def _create_session_in_database(
    session_id: str,
    user_id: Union[int, str],
    remember: bool,
    auth_method: str
) -> None:
    """Create a session record in the database."""
    if not _should_check_db_session():
        return

    try:
        # Get session duration
        if remember and has_app_context():
            days = current_app.config.get('REMEMBER_ME_DAYS', 30)
            expires_at = datetime.now(timezone.utc) + timedelta(days=days)
        else:
            timeout_seconds = _get_session_timeout()
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=timeout_seconds)

        # Collect device and location information
        device_info = {}
        location_info = None

        if hasattr(request, 'user_agent'):
            if hasattr(request.user_agent, 'platform'):
                device_info = {
                    'platform': request.user_agent.platform,
                    'browser': request.user_agent.browser,
                    'version': request.user_agent.version,
                    'language': request.user_agent.language
                }

        # Get location info from request context if available
        if hasattr(g, 'location_data') and g.location_data:
            location_info = g.location_data.get('location')

        # Create UserSession object
        db_session = UserSession(
            user_id=int(user_id),  # Convert to int if it's a string
            session_id=session_id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            fingerprint=session.get('fingerprint'),
            expires_at=expires_at,
            is_active=True,
            login_method=auth_method,
            device_info=device_info,
            last_location=location_info
        )

        db.session.add(db_session)
        db.session.commit()

        # Cache session data in Redis if configured
        if _should_use_redis_session_cache():
            try:
                redis_client = get_redis_client()
                if redis_client:
                    # Cache last active time
                    redis_client.setex(
                        f"session:last_active:{session_id}",
                        _get_session_timeout() * 2,  # Double timeout for safety
                        time.time()
                    )
            except Exception as e:
                log_error(f"Failed to cache session data in Redis: {e}")

    except Exception as e:
        log_error(f"Failed to create session in database: {e}")
        db.session.rollback()


def _update_session_in_database(session_id: str) -> None:
    """Update a session record in the database."""
    if not _should_check_db_session():
        return

    try:
        db_session = UserSession.query.filter_by(session_id=session_id).first()

        if not db_session:
            # This is a new session ID, create a new database record
            _create_session_in_database(
                session_id=session_id,
                user_id=session.get('user_id'),
                remember=session.get('permanent', False),
                auth_method=session.get('auth_method', 'password')
            )
            return

        # Update the session record
        db_session.session_id = session_id
        db_session.last_active = datetime.now(timezone.utc)
        db_session.activity_count += 1

        # If fingerprint changed, update it
        if 'fingerprint' in session:
            db_session.fingerprint = session['fingerprint']

        # If location data available, update it
        if hasattr(g, 'location_data') and g.location_data:
            location_info = g.location_data.get('location')
            if location_info:
                db_session.last_location = location_info

        db.session.add(db_session)
        db.session.commit()
    except Exception as e:
        log_error(f"Failed to update session in database: {e}")
        db.session.rollback()
