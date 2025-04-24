"""
Security utilities for the Cloud Infrastructure Platform.

This module provides security-related functionality including:
- File integrity verification
- Access control and authentication
- Encryption and decryption of sensitive data
- Security event logging
- Anomaly detection and threat assessment

These utilities are used throughout the application to enforce security policies,
detect potential intrusions, and maintain audit trails for compliance purposes.
"""

import os
import hashlib
import logging
import base64
import time
import uuid
from ipaddress import ip_address, ip_network
import re
import requests
from typing import List, Dict, Any, Optional, Tuple, Union, Set, TypeVar, cast
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse

# SQLAlchemy imports
from sqlalchemy import func, desc, or_, and_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.hybrid import hybrid_property

# Flask imports
from flask import current_app, request, g, has_request_context, session, has_app_context
from flask_login import current_user
from werkzeug.local import LocalProxy

# Cryptography imports
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

# Internal imports
from models.audit_log import AuditLog
from models.security_incident import SecurityIncident
from models.base import BaseModel, AuditableMixin
from extensions import db, metrics
from extensions import get_redis_client
from core.utils import (
    detect_file_changes, calculate_file_hash, format_timestamp,
    log_critical, log_error, log_warning, log_info, log_debug
)

# Type definitions
T = TypeVar('T')
SecurityMetrics = Dict[str, Any]
AuditDetails = Dict[str, Any]

# Set up module-level logger
logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security')

# Security configuration constants
SECURITY_CONFIG = {
    # Encryption settings
    'ENCRYPTION_KEY': os.getenv('ENCRYPTION_KEY'),  # A strong random 32-byte key for encrypting sensitive data
    'ENCRYPTION_SALT': os.getenv('ENCRYPTION_SALT', b'cloud-infrastructure-platform-salt'),
    'DEFAULT_KEY_ITERATIONS': 100000,  # PBKDF2 iterations for key derivation

    # Token settings
    'TOKEN_EXPIRY': 3600,  # Default token expiry in seconds (1 hour)
    'REFRESH_TOKEN_EXPIRY': 30 * 24 * 3600,  # 30 days
    'RESET_TOKEN_EXPIRY': 3600,  # 1 hour

    # Password policy
    'MIN_PASSWORD_LENGTH': 12,  # Minimum password length
    'PASSWORD_HISTORY_SIZE': 5,  # Number of previous passwords to remember
    'PASSWORD_EXPIRY_DAYS': 90,  # Password expiry in days

    # Account security
    'MAX_LOGIN_ATTEMPTS': 5,  # Maximum failed login attempts before lockout
    'LOCKOUT_DURATION': 30 * 60,  # Account lockout duration in seconds (30 minutes)
    'SESSION_TIMEOUT': 30 * 60,  # Session timeout in seconds (30 minutes)
    'REQUIRE_MFA_FOR_SENSITIVE': True,  # Require MFA for sensitive operations

    # Monitoring settings
    'SUSPICIOUS_IP_THRESHOLD': 5,  # Failed attempts threshold for suspicious IP
    'SECURITY_ALERT_THRESHOLD': 7,  # Risk score threshold for security alerts
    'EVENT_CORRELATION_WINDOW': 300,  # Window for correlating events (5 minutes)

    # Network security
    'KNOWN_MALICIOUS_NETWORKS': [
        '185.159.128.0/18',  # Example - known botnet range
        '192.42.116.0/22',   # Example - known attack source
    ],

    # File integrity
    'FILE_HASH_ALGORITHM': 'sha256',  # Default hash algorithm for file integrity
    'FILE_CHECK_INTERVAL': 3600,  # File check interval in seconds (1 hour)
}


#
# Authentication and Authorization Functions
#

def get_suspicious_ips(hours: int = 24, min_attempts: int = 5) -> List[Dict[str, Any]]:
    """
    Get list of suspicious IPs with their activity counts.

    Analyzes failed login attempts and security events to identify potentially
    malicious IP addresses that may be attempting to breach the system.

    Args:
        hours: Number of hours to look back for failed login attempts
        min_attempts: Minimum number of failed attempts to consider an IP suspicious

    Returns:
        List[Dict[str, Any]]: List of suspicious IPs with their failed login counts
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    try:
        # Use cached results if available
        redis_client = get_redis_client()
        cache_key = f"suspicious_ips:{hours}:{min_attempts}"

        if redis_client:
            cached_data = redis_client.get(cache_key)
            if cached_data:
                try:
                    import json
                    return json.loads(cached_data)
                except Exception as e:
                    log_error(f"Failed to load cached suspicious IPs: {e}")

        # Subquery to count failed login attempts by IP
        failed_login_counts = db.session.query(
            AuditLog.ip_address,
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
            AuditLog.created_at >= cutoff,
            AuditLog.ip_address.isnot(None)
        ).group_by(AuditLog.ip_address).subquery()

        # Get IPs with more than min_attempts failed attempts
        suspicious = db.session.query(
            failed_login_counts.c.ip_address,
            failed_login_counts.c.count
        ).filter(failed_login_counts.c.count >= min_attempts).all()

        # Add additional fields for enriched data
        result = []
        for ip, count in suspicious:
            ip_data = {'ip': ip, 'count': count}

            # Add geolocation data if available
            ip_data['geolocation'] = _get_ip_geolocation(ip)

            # Add most recent failed attempt timestamp
            latest_attempt = db.session.query(func.max(AuditLog.created_at)).filter(
                AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
                AuditLog.ip_address == ip
            ).scalar()

            if latest_attempt:
                ip_data['latest_attempt'] = latest_attempt.isoformat()

            # Add targeted usernames
            targeted_users = db.session.query(AuditLog.details).filter(
                AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
                AuditLog.ip_address == ip,
                AuditLog.created_at >= cutoff
            ).limit(5).all()

            user_details = []
            for detail in targeted_users:
                if detail and detail[0]:
                    user_details.append(detail[0])

            ip_data['targeted_users'] = user_details
            result.append(ip_data)

        # Cache the results for 5 minutes
        if redis_client:
            try:
                import json
                redis_client.setex(cache_key, 300, json.dumps(result))
            except Exception as e:
                log_error(f"Failed to cache suspicious IPs: {e}")

        return result
    except SQLAlchemyError as e:
        log_error(f"Database error in get_suspicious_ips: {e}")
        return []


def get_failed_login_count(hours: int = 24) -> int:
    """
    Get count of failed logins in the past hours.

    Args:
        hours: Number of hours to look back

    Returns:
        int: Count of failed login events
    """
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Use cached results if available
        redis_client = get_redis_client()
        cache_key = f"failed_login_count:{hours}"

        if redis_client:
            cached_count = redis_client.get(cache_key)
            if cached_count:
                try:
                    return int(cached_count)
                except (ValueError, TypeError):
                    pass

        # Query database for count
        count = db.session.query(AuditLog).filter(
            AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
            AuditLog.created_at >= cutoff
        ).count()

        # Cache the result for 5 minutes
        if redis_client:
            redis_client.setex(cache_key, 300, str(count))

        # Track metric
        metrics.gauge('security.failed_logins', count)

        return count
    except SQLAlchemyError as e:
        log_error(f"Database error in get_failed_login_count: {e}")
        return 0


def get_account_lockout_count(hours: int = 24) -> int:
    """
    Get count of account lockouts in the past hours.

    Args:
        hours: Number of hours to look back

    Returns:
        int: Count of account lockout events
    """
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Use cached results if available
        redis_client = get_redis_client()
        cache_key = f"account_lockout_count:{hours}"

        if redis_client:
            cached_count = redis_client.get(cache_key)
            if cached_count:
                try:
                    return int(cached_count)
                except (ValueError, TypeError):
                    pass

        # Query database for count
        count = db.session.query(AuditLog).filter(
            AuditLog.event_type == AuditLog.EVENT_ACCOUNT_LOCKOUT,
            AuditLog.created_at >= cutoff
        ).count()

        # Cache the result for 5 minutes
        if redis_client:
            redis_client.setex(cache_key, 300, str(count))

        # Track metric
        metrics.gauge('security.account_lockouts', count)

        return count
    except SQLAlchemyError as e:
        log_error(f"Database error in get_account_lockout_count: {e}")
        return 0


def get_active_session_count() -> int:
    """
    Get count of active user sessions.

    This function queries Redis to count active user sessions, providing
    visibility into current system usage and potential session anomalies.

    Returns:
        int: Count of active sessions
    """
    try:
        # Use Redis client from extensions
        redis_client = get_redis_client()
        if not redis_client:
            log_warning("Redis unavailable for session count")
            return 0

        # Get session keys with cursor for large datasets
        cursor = '0'
        session_keys = set()

        while True:
            cursor, keys = redis_client.scan(
                cursor=cursor,
                match='session:*',
                count=1000
            )

            if keys:
                session_keys.update(keys)

            if cursor == b'0' or cursor == 0:
                break

        # Track metric
        count = len(session_keys)
        metrics.gauge('security.active_sessions', count)

        return count
    except Exception as e:
        log_error(f"Error in get_active_session_count: {e}")
        return 0


def verify_token(token: str, secret_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Verify JWT token and return payload if valid.

    Args:
        token: JWT token string
        secret_key: Secret key for JWT verification (uses app secret if None)

    Returns:
        Dict or None: Token payload if valid, None if invalid
    """
    if not token:
        return None

    try:
        import jwt

        # Use provided secret or fall back to app secret
        key = secret_key
        if key is None and has_app_context():
            key = current_app.config.get('JWT_SECRET_KEY')

        if not key:
            log_error('JWT_SECRET_KEY not configured')
            return None

        # Get audience from app config if available
        audience = None
        if has_app_context():
            audience = current_app.config.get('JWT_AUDIENCE')

        # Verify token with standard security options
        payload = jwt.decode(
            token,
            key,
            algorithms=['HS256'],
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_nbf': True,
                'verify_iat': True,
                'verify_aud': audience is not None,
            },
            audience=audience
        )

        # Additional validation
        if 'exp' not in payload:
            log_warning('Token missing expiration claim')
            return None

        if 'sub' not in payload:
            log_warning('Token missing subject claim')
            return None

        # Track success metric
        metrics.increment('security.token_verification_success')
        return payload

    except jwt.ExpiredSignatureError:
        metrics.increment('security.token_verification_expired')
        log_warning('Token expired')
        return None
    except jwt.InvalidTokenError as e:
        metrics.increment('security.token_verification_invalid')
        log_warning(f'Invalid token: {e}')
        return None
    except ImportError:
        log_error('JWT library not available')
        return None
    except Exception as e:
        metrics.increment('security.token_verification_error')
        log_error(f'Error verifying token: {e}')
        return None


def regenerate_session() -> bool:
    """
    Regenerate the session to prevent session fixation attacks.

    This function preserves important session data while creating a new
    session ID, effectively preventing session fixation attacks.

    Returns:
        bool: True if session was regenerated, False if there was an error
    """
    try:
        # Save the important session values
        saved_data = {}
        keys_to_preserve = [
            'user_id', 'username', 'role', 'last_active',
            'csrf_token', 'mfa_verified', 'permissions'
        ]

        for key in keys_to_preserve:
            if key in session:
                saved_data[key] = session[key]

        # Generate a new session ID
        session_id = str(uuid.uuid4())

        # Clear the current session
        session.clear()

        # Set the new session ID
        session['session_id'] = session_id

        # Restore the saved values
        for key, value in saved_data.items():
            session[key] = value

        # Update last active time
        session['last_active'] = datetime.now(timezone.utc).isoformat()

        # Generate new CSRF token if the app supports it
        if has_app_context() and hasattr(current_app, 'csrf'):
            session['csrf_token'] = current_app.csrf.generate_csrf_token()

        # Log the event
        user_id = saved_data.get('user_id', 'unknown')
        log_info(f"Session regenerated for user_id={user_id}")

        # Track metric
        metrics.increment('security.session_regenerated')

        return True
    except Exception as e:
        log_error(f"Failed to regenerate session: {e}")
        return False


def invalidate_user_sessions(user_id: int) -> bool:
    """
    Invalidate all sessions for a specific user.

    This function searches for and removes all active sessions belonging to
    the specified user, providing a way to force logout across all devices.

    Args:
        user_id: User ID whose sessions should be invalidated

    Returns:
        bool: True if sessions were invalidated, False otherwise
    """
    try:
        # Get Redis client
        redis_client = get_redis_client()
        if not redis_client:
            log_warning("Redis unavailable, unable to invalidate sessions")
            return False

        # Find all sessions for this user
        session_pattern = "session:*"
        sessions = []

        # Use cursor-based iteration to handle large sets of keys
        cursor = 0
        while True:
            cursor, keys = redis_client.scan(cursor=cursor, match=session_pattern, count=100)

            for key in keys:
                try:
                    session_data = redis_client.get(key)
                    if session_data:
                        # Check both integer and string formats to be safe
                        data_str = session_data.decode('utf-8')
                        if (f'"user_id":{user_id}' in data_str or
                            f'"user_id": {user_id}' in data_str or
                            f'"user_id":"{user_id}"' in data_str):
                            sessions.append(key)
                except Exception as e:
                    log_error(f"Error processing session key {key}: {e}")

            # Exit when we've scanned all keys
            if cursor == 0:
                break

        # Delete the sessions in batches to avoid timeout issues
        if sessions:
            batch_size = 100
            for i in range(0, len(sessions), batch_size):
                batch = sessions[i:i + batch_size]
                redis_client.delete(*batch)

            log_info(f"Invalidated {len(sessions)} sessions for user ID {user_id}")

            # Track metric
            metrics.increment('security.sessions_invalidated', len(sessions))
        else:
            log_info(f"No active sessions found for user ID {user_id}")

        return True
    except Exception as e:
        log_error(f"Failed to invalidate user sessions: {e}")
        return False


def is_suspicious_ip(ip_address: Optional[str], threshold: int = 5) -> bool:
    """
    Determine if an IP address is suspicious based on login failure history and blocklists.

    This function checks if an IP address should be considered suspicious by:
    1. Checking against known suspicious IP cache
    2. Looking up failed login attempts from this IP
    3. Checking against external IP reputation services
    4. Checking against known malicious IP ranges

    Args:
        ip_address: The IP address to check
        threshold: Minimum number of failed attempts to consider an IP suspicious

    Returns:
        bool: True if the IP is suspicious, False otherwise
    """
    if not ip_address:
        return False

    try:
        # Check if the IP is already blocked
        if check_ip_blocked(ip_address):
            return True

        # Check against known malicious networks
        try:
            ip_obj = ip_address(ip_address)
            for network_str in SECURITY_CONFIG.get('KNOWN_MALICIOUS_NETWORKS', []):
                if ip_obj in ip_network(network_str):
                    log_warning(f"IP {ip_address} found in known malicious network {network_str}")
                    # Track metric
                    metrics.increment('security.malicious_network_access')
                    return True
        except ValueError:
            # Invalid IP address format
            log_warning(f"Invalid IP address format: {ip_address}")
            return False

        # Check Redis cache first for known suspicious IPs (faster)
        redis_client = get_redis_client()
        if redis_client:
            cached_result = redis_client.get(f"suspicious_ip:{ip_address}")
            if cached_result:
                is_suspicious = cached_result.decode() == "True"
                if is_suspicious:
                    # Track metric on cache hit for suspicious IP
                    metrics.increment('security.suspicious_ip_cache_hit')
                return is_suspicious

        # Check for failed login attempts in audit log
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        failed_count = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
            AuditLog.ip_address == ip_address,
            AuditLog.created_at >= cutoff
        ).scalar()

        if failed_count >= threshold:
            # Cache the result for 1 hour
            if redis_client:
                redis_client.setex(f"suspicious_ip:{ip_address}", 3600, "True")

            # Track metric
            metrics.increment('security.suspicious_ip_detected')
            return True

        # Check for other security breach attempts
        breach_attempts = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.event_type.in_([
                AuditLog.EVENT_SECURITY_BREACH_ATTEMPT,
                AuditLog.EVENT_PERMISSION_DENIED,
                AuditLog.EVENT_RATE_LIMIT_EXCEEDED
            ]),
            AuditLog.ip_address == ip_address,
            AuditLog.created_at >= cutoff
        ).scalar()

        if breach_attempts > 0:
            # Cache the result for 1 hour
            if redis_client:
                redis_client.setex(f"suspicious_ip:{ip_address}", 3600, "True")

            # Track metric
            metrics.increment('security.breach_attempt_detected')
            return True

    except SQLAlchemyError as e:
        log_error(f"Database error when checking suspicious IP: {ip_address}: {e}")
        return False

    # Check against external IP reputation service if configured
    if has_app_context() and current_app.config.get('IP_REPUTATION_CHECK_ENABLED'):
        result = _check_ip_reputation(ip_address)
        if result:
            # Cache the result for 6 hours
            if redis_client:
                redis_client.setex(f"suspicious_ip:{ip_address}", 21600, "True")

            # Track metric
            metrics.increment('security.ip_reputation_detected')
            return True

    # Cache negative result for 30 minutes
    if redis_client:
        redis_client.setex(f"suspicious_ip:{ip_address}", 1800, "False")

    return False


def get_blocked_ips() -> Set[str]:
    """
    Get set of currently blocked IP addresses.

    Returns:
        Set[str]: Set of blocked IP addresses
    """
    blocked_ips = set()

    try:
        redis_client = get_redis_client()
        if not redis_client:
            log_warning("Redis unavailable for retrieving blocked IPs")
            return blocked_ips

        # Get all keys matching blocked IP pattern with cursor for large datasets
        cursor = '0'
        while True:
            cursor, keys = redis_client.scan(
                cursor=cursor,
                match="blocked_ip:*",
                count=1000
            )

            # Extract IP addresses from keys
            for key in keys:
                ip = key.decode('utf-8').split(':', 1)[1]
                blocked_ips.add(ip)

            if cursor == '0' or cursor == b'0' or cursor == 0:
                break

        # Track metric
        metrics.gauge('security.blocked_ips', len(blocked_ips))

        return blocked_ips
    except Exception as e:
        log_error(f"Error retrieving blocked IPs: {e}")
        return blocked_ips


def block_ip(ip_address: str, duration: int = 3600, reason: str = "security_policy") -> bool:
    """
    Block an IP address for a specified duration.

    Args:
        ip_address: IP address to block
        duration: Block duration in seconds (default: 1 hour)
        reason: Reason for the block

    Returns:
        bool: True if successfully blocked, False otherwise
    """
    try:
        if not ip_address or not _is_valid_ip(ip_address):
            log_error(f"Invalid IP address format: {ip_address}")
            return False

        redis_client = get_redis_client()
        if not redis_client:
            log_warning(f"Redis unavailable, unable to block IP: {ip_address}")
            return False

        # Store block information
        block_data = {
            'blocked_at': datetime.now(timezone.utc).isoformat(),
            'reason': reason,
            'duration': duration,
            'expiry': (datetime.now(timezone.utc) + timedelta(seconds=duration)).isoformat()
        }

        # Convert to string for storage
        import json
        block_str = json.dumps(block_data)

        # Set with expiry
        redis_client.setex(
            f"blocked_ip:{ip_address}",
            duration,
            block_str
        )

        # Log the event with appropriate severity
        log_warning(f"Blocked IP {ip_address} for {duration} seconds. Reason: {reason}")

        # Record security event
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_COUNTERMEASURE,
            description=f"Blocked IP address: {ip_address}",
            severity='warning',
            ip_address=ip_address,
            details=f"Duration: {duration} seconds, Reason: {reason}"
        )

        # Track metric
        metrics.increment('security.ip_blocked')

        return True
    except Exception as e:
        log_error(f"Failed to block IP {ip_address}: {e}")
        return False


def check_ip_blocked(ip_address: str) -> bool:
    """
    Check if an IP address is currently blocked.

    Args:
        ip_address: IP address to check

    Returns:
        bool: True if IP is blocked, False otherwise
    """
    try:
        if not ip_address:
            return False

        redis_client = get_redis_client()
        if not redis_client:
            log_warning("Redis unavailable, cannot check if IP is blocked")
            return False

        # Check if key exists
        return redis_client.exists(f"blocked_ip:{ip_address}") > 0
    except Exception as e:
        log_error(f"Error checking if IP {ip_address} is blocked: {e}")
        return False


def unblock_ip(ip_address: str) -> bool:
    """
    Remove a block on an IP address.

    Args:
        ip_address: IP address to unblock

    Returns:
        bool: True if successfully unblocked or wasn't blocked, False on error
    """
    try:
        if not ip_address:
            return False

        redis_client = get_redis_client()
        if not redis_client:
            log_warning(f"Redis unavailable, unable to unblock IP: {ip_address}")
            return False

        # Remove the block
        redis_client.delete(f"blocked_ip:{ip_address}")

        # Log the event
        log_info(f"Unblocked IP: {ip_address}")

        # Track metric
        metrics.increment('security.ip_unblocked')

        return True
    except Exception as e:
        log_error(f"Failed to unblock IP {ip_address}: {e}")
        return False


def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
    """
    Validate password strength against security requirements.

    Args:
        password: Password to validate

    Returns:
        Tuple of (bool, List[str]): Success flag and list of failed requirements
    """
    min_length = SECURITY_CONFIG.get('MIN_PASSWORD_LENGTH', 12)
    failed_requirements = []

    # Check length
    if len(password) < min_length:
        failed_requirements.append(f"Password must be at least {min_length} characters long")

    # Check for lowercase
    if not re.search(r'[a-z]', password):
        failed_requirements.append("Password must include lowercase letters")

    # Check for uppercase
    if not re.search(r'[A-Z]', password):
        failed_requirements.append("Password must include uppercase letters")

    # Check for numbers
    if not re.search(r'[0-9]', password):
        failed_requirements.append("Password must include numbers")

    # Check for special characters
    if not re.search(r'[^a-zA-Z0-9]', password):
        failed_requirements.append("Password must include special characters")

    # Check for common sequential patterns
    sequential_patterns = ['123456', 'abcdef', 'qwerty', 'password']
    if any(pattern in password.lower() for pattern in sequential_patterns):
        failed_requirements.append("Password contains common sequential patterns")

    # Check for common passwords if available
    if has_app_context() and current_app.config.get('COMMON_PASSWORDS_FILE'):
        common_passwords_file = current_app.config.get('COMMON_PASSWORDS_FILE')
        if os.path.exists(common_passwords_file):
            try:
                # Use hash to avoid loading the entire file into memory
                password_hash = hashlib.sha256(password.lower().encode()).hexdigest()

                with open(common_passwords_file, 'r') as f:
                    for line in f:
                        line_hash = line.strip()
                        if line_hash == password_hash:
                            failed_requirements.append("Password is too common or has been compromised")
                            break
            except Exception as e:
                log_error(f"Error checking common passwords: {e}")

    # Check for common password patterns based on app name or domain
    if has_app_context():
        app_name = current_app.config.get('APP_NAME', '').lower()
        domain = current_app.config.get('APP_DOMAIN', '').lower()

        if app_name and app_name in password.lower():
            failed_requirements.append("Password contains the application name")

        if domain and domain in password.lower():
            failed_requirements.append("Password contains the domain name")

    return len(failed_requirements) == 0, failed_requirements


def generate_secure_token(length: int = 64, url_safe: bool = True) -> str:
    """
    Generate a cryptographically secure random token.

    Creates a secure random token suitable for authentication,
    session management, or CSRF protection.

    Args:
        length: Length of the token in bytes (default: 64)
        url_safe: Whether to use URL-safe encoding (default: True)

    Returns:
        str: Base64-encoded secure token
    """
    # Generate secure random bytes
    token_bytes = os.urandom(length)

    # Convert to base64 encoding
    if url_safe:
        token = base64.urlsafe_b64encode(token_bytes).decode('utf-8').rstrip('=')
    else:
        token = base64.b64encode(token_bytes).decode('utf-8')

    return token


def require_permission(permission: str):
    """
    Decorator to ensure user has the required permission.

    This decorator checks that the current user has the specified permission
    before allowing access to the decorated function. If the user lacks the
    permission, a 403 Forbidden response is returned.

    Args:
        permission: The permission name required (format: 'resource:action')

    Returns:
        Decorator function that checks permission

    Example:
        @app.route('/admin/users')
        @require_permission('users:list')
        def list_users():
            return render_template('users.html')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                from flask import redirect, url_for, flash
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login', next=request.path))

            # Skip check if superuser or admin role, if such attributes exist
            if (hasattr(current_user, 'is_superuser') and current_user.is_superuser) or \
               (hasattr(current_user, 'role') and current_user.role == 'admin'):
                return f(*args, **kwargs)

            # Check permission
            if hasattr(current_user, 'has_permission') and current_user.has_permission(permission):
                # User has permission, proceed
                return f(*args, **kwargs)
            else:
                # Log the permission denial
                log_security_event(
                    event_type=AuditLog.EVENT_PERMISSION_DENIED,
                    description=f"Permission denied: {permission}",
                    severity='warning',
                    user_id=current_user.id if hasattr(current_user, 'id') else None,
                    details={
                        'permission': permission,
                        'endpoint': request.endpoint,
                        'path': request.path
                    }
                )

                # Track metric
                metrics.increment('security.permission_denied')

                # Return 403 Forbidden
                from flask import abort
                return abort(403, description=f"You don't have the required permission: {permission}")

        return decorated_function
    return decorator


def require_mfa(f):
    """
    Decorator to ensure user has completed Multi-Factor Authentication.

    This decorator checks that the current user has completed MFA verification
    before allowing access to the decorated function. If MFA is not verified,
    the user is redirected to the MFA verification page.

    Args:
        f: The function to decorate

    Returns:
        Decorated function that checks MFA verification

    Example:
        @app.route('/sensitive-data')
        @login_required
        @require_mfa
        def view_sensitive_data():
            return render_template('sensitive_data.html')
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            from flask import redirect, url_for
            return redirect(url_for('auth.login'))

        # Check if MFA is required for this user
        mfa_required = True
        if has_app_context():
            # Check if MFA is globally disabled
            mfa_enabled = current_app.config.get('MFA_ENABLED', True)
            if not mfa_enabled:
                return f(*args, **kwargs)

            # Check if user is exempt from MFA
            if hasattr(current_user, 'mfa_exempt') and current_user.mfa_exempt:
                return f(*args, **kwargs)

        # Check if MFA is verified in the session
        mfa_verified = session.get('mfa_verified', False)
        if not mfa_verified:
            from flask import redirect, url_for, flash
            flash('Please complete two-factor authentication to access this page.', 'warning')

            # Log the MFA requirement
            log_security_event(
                event_type='mfa_required',
                description='MFA verification required for sensitive action',
                severity='info',
                user_id=current_user.id if hasattr(current_user, 'id') else None,
                details={'endpoint': request.endpoint, 'path': request.path}
            )

            # Track metric
            metrics.increment('security.mfa_redirects')

            # Redirect to MFA verification with return URL
            return redirect(url_for('auth.verify_mfa', next=request.path))

        return f(*args, **kwargs)

    return decorated_function


def can_access_ui_element(element_id: str, required_permission: str = None):
    """
    Decorator factory to control access to UI elements based on permissions.

    This decorator manages UI element visibility based on user permissions without
    raising errors. It allows for progressive UI enhancement where elements are
    conditionally shown based on the user's access rights.

    Args:
        element_id: The UI element identifier that will be used in templates
        required_permission: The permission name required to see the element
                            (format: 'resource:action')

    Returns:
        Callable: A decorator that controls UI element access

    Example:
        @app.route('/dashboard')
        @can_access_ui_element('admin_panel', 'admin:access')
        def dashboard():
            return render_template('dashboard.html')
    """
    def decorator(view_func):
        @wraps(view_func)
        def decorated_function(*args, **kwargs):
            # Initialize ui_permissions dict if it doesn't exist
            kwargs['ui_permissions'] = kwargs.get('ui_permissions', {})

            # Default to showing the element
            has_access = True

            # Check permission if one is required
            if required_permission:
                # Guard against current_user not being authenticated
                if not hasattr(current_user, 'has_permission'):
                    has_access = False
                # Handle case where current_user isn't properly initialized
                elif getattr(current_user, 'is_authenticated', False) is False:
                    has_access = False
                # Check the actual permission
                elif not current_user.has_permission(required_permission):
                    has_access = False

            # Store the result in the ui_permissions dict
            kwargs['ui_permissions'][element_id] = has_access

            # Add element_id to a list of checked elements for debugging
            if 'checked_elements' not in kwargs:
                kwargs['checked_elements'] = []
            kwargs['checked_elements'].append(element_id)

            return view_func(*args, **kwargs)
        return decorated_function
    return decorator


#
# File Integrity and Security Functions
#

def check_file_integrity(file_path: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
    """
    Verify integrity of a file by comparing its hash with expected value.

    Args:
        file_path: Path to the file to check
        expected_hash: Expected hash value to compare against
        algorithm: Hash algorithm to use ('sha256', 'sha384', 'sha512')

    Returns:
        bool: True if file hash matches expected hash, False otherwise
    """
    if not os.path.exists(file_path):
        log_warning(f"File does not exist: {file_path}")
        return False

    try:
        current_hash = calculate_file_hash(file_path, algorithm)
        result = current_hash == expected_hash

        if not result:
            log_warning(f"File integrity check failed for {file_path}")
            metrics.increment('security.file_integrity_failed')

        return result
    except (IOError, OSError) as e:
        log_error(f"Error checking file integrity for {file_path}: {e}")
        return False
    except ValueError as e:
        log_error(f"Invalid hash algorithm '{algorithm}' for {file_path}: {e}")
        return False


def check_config_integrity(app=None) -> bool:
    """
    Verify integrity of critical configuration files.

    Args:
        app: Optional Flask app instance (uses current_app if None)

    Returns:
        bool: True if all files match their reference hashes, False otherwise
    """
    try:
        app = app or current_app

        # Get expected hashes from application configuration
        expected_hashes = app.config.get('CONFIG_FILE_HASHES', {})
        if not expected_hashes:
            log_warning("No reference hashes found for config files")
            return False

        failed_files = []

        # Check each file against its expected hash
        for file_path, expected_hash in expected_hashes.items():
            if not os.path.exists(file_path):
                log_warning(f"Configuration file not found: {file_path}")
                failed_files.append(file_path)
                continue

            try:
                if not check_file_integrity(file_path, expected_hash):
                    log_warning(f"Configuration file integrity check failed: {file_path}")
                    failed_files.append(file_path)

                    # Record security event
                    log_security_event(
                        event_type=AuditLog.EVENT_FILE_INTEGRITY,
                        description=f"Configuration file modified: {file_path}",
                        severity='error'
                    )
            except Exception as e:
                log_error(f"Error checking integrity for {file_path}: {e}")
                failed_files.append(file_path)

        # Track metrics
        metrics.gauge('security.failed_config_files', len(failed_files))

        return len(failed_files) == 0
    except Exception as e:
        log_error(f"Error in check_config_integrity: {e}")
        return False


def check_critical_file_integrity(app=None) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Verify integrity of critical application files.

    Args:
        app: Optional Flask app instance (uses current_app if None)

    Returns:
        Tuple of:
            bool: True if all files match their reference hashes, False otherwise
            List[Dict[str, Any]]: List of changes detected, each containing path, status, and severity
    """
    try:
        app = app or current_app

        # Get expected hashes from application configuration
        expected_hashes = app.config.get('CRITICAL_FILE_HASHES', {})
        if not expected_hashes:
            log_warning("No reference hashes found for critical files")
            return False, [{"path": "configuration", "status": "missing", "severity": "high"}]

        # Get monitoring settings
        basedir = os.path.dirname(os.path.abspath(app.root_path))
        critical_patterns = app.config.get('CRITICAL_FILE_PATTERNS', ['*.py', 'config.*', '.env*'])
        detect_permissions = app.config.get('DETECT_FILE_PERMISSIONS', True)
        check_signatures = app.config.get('CHECK_FILE_SIGNATURES', False)

        # Use the more comprehensive detection function
        changes = detect_file_changes(
            basedir,
            expected_hashes,
            critical_patterns=critical_patterns,
            detect_permissions=detect_permissions,
            check_signatures=check_signatures
        )

        if changes:
            # Log each detected change
            for change in changes:
                path = change.get('path', 'unknown')
                status = change.get('status', 'unknown')
                severity = change.get('severity', 'medium')

                log_warning(f"File integrity violation: {path} ({status})")

                # Record security event for high severity changes
                if severity in ('high', 'critical'):
                    try:
                        log_security_event(
                            event_type=AuditLog.EVENT_FILE_INTEGRITY,
                            description=f"Critical file modified: {path}",
                            severity='error',
                            details={
                                'path': path,
                                'status': status,
                                'severity': severity,
                                'timestamp': change.get('timestamp', format_timestamp())
                            }
                        )
                    except Exception as e:
                        log_error(f"Failed to record file integrity event: {e}")

            # Track metrics
            high_severity = sum(1 for c in changes if c.get('severity') in ('high', 'critical'))
            metrics.gauge('security.modified_critical_files', len(changes))
            metrics.gauge('security.high_severity_changes', high_severity)

            return False, changes

        return True, []
    except Exception as e:
        log_error(f"Error in check_critical_file_integrity: {e}")
        return False, [{"path": "system", "status": "error", "severity": "high", "details": str(e)}]


def verify_file_signature(file_path: str, signature_path: Optional[str] = None) -> bool:
    """
    Verify the cryptographic signature of a file.

    This function verifies that a file matches its cryptographic signature,
    ensuring the file has not been tampered with and comes from a trusted source.

    Args:
        file_path: Path to the file to verify
        signature_path: Path to signature file (defaults to file_path + '.sig')

    Returns:
        bool: True if signature is valid, False otherwise
    """
    if not os.path.exists(file_path):
        log_warning(f"File does not exist: {file_path}")
        return False

    if signature_path is None:
        signature_path = file_path + '.sig'

    if not os.path.exists(signature_path):
        log_warning(f"Signature file not found: {signature_path}")
        return False

    try:
        # Read the signature file
        with open(signature_path, 'rb') as f:
            signature = f.read()

        # Get public key from configuration
        public_key_path = None
        if has_app_context():
            public_key_path = current_app.config.get('SIGNATURE_PUBLIC_KEY_PATH')

        if not public_key_path or not os.path.exists(public_key_path):
            log_warning("Public key for signature verification not available")
            return False

        # Load the public key
        with open(public_key_path, 'rb') as f:
            public_key = load_pem_public_key(f.read())

        # Read the file content
        with open(file_path, 'rb') as f:
            file_data = f.read()

        # Verify the signature
        public_key.verify(
            signature,
            file_data,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # If we get here, verification succeeded
        return True

    except InvalidSignature:
        log_warning(f"Invalid signature for file: {file_path}")
        metrics.increment('security.invalid_signature')
        return False
    except Exception as e:
        log_error(f"Error verifying file signature {file_path}: {e}")
        return False


#
# Encryption and Sensitive Data Functions
#

def encrypt_sensitive_data(plaintext: str) -> str:
    """
    Encrypt sensitive data using Fernet symmetric encryption.

    This function encrypts sensitive configuration values, API keys,
    and other secret data that needs to be stored securely in the database.
    It uses Fernet (AES-128 in CBC mode with PKCS7 padding and HMAC authentication)
    which provides authenticated encryption.

    Args:
        plaintext: The plaintext string to encrypt

    Returns:
        str: Base64-encoded encrypted string

    Raises:
        RuntimeError: If encryption fails due to missing key or other issues
    """
    if not plaintext:
        return plaintext

    try:
        # Get the encryption key
        key = _get_encryption_key()

        # Convert the key to a URL-safe base64-encoded string as required by Fernet
        key_b64 = base64.urlsafe_b64encode(key)

        # Initialize the Fernet cipher with the key
        cipher = Fernet(key_b64)

        # Encrypt the plaintext and encode as a string
        encrypted_data = cipher.encrypt(plaintext.encode('utf-8'))
        return encrypted_data.decode('utf-8')

    except Exception as e:
        log_error(f"Encryption failed: {e}")
        metrics.increment('security.encryption_failure')
        raise RuntimeError(f"Failed to encrypt sensitive data: {e}")


def decrypt_sensitive_data(encrypted_data: str) -> str:
    """
    Decrypt sensitive data that was encrypted using encrypt_sensitive_data.

    This function decrypts configuration values, API keys, and other secrets
    that were previously encrypted with the encrypt_sensitive_data function.

    Args:
        encrypted_data: Base64-encoded encrypted string

    Returns:
        str: Decrypted plaintext string

    Raises:
        RuntimeError: If decryption fails due to invalid key, tampered data, etc.
    """
    if not encrypted_data:
        return encrypted_data

    try:
        # Get the encryption key
        key = _get_encryption_key()

        # Convert the key to a URL-safe base64-encoded string as required by Fernet
        key_b64 = base64.urlsafe_b64encode(key)

        # Initialize the Fernet cipher with the key
        cipher = Fernet(key_b64)

        # Decrypt the data
        try:
            decrypted_data = cipher.decrypt(encrypted_data.encode('utf-8'))
            return decrypted_data.decode('utf-8')
        except InvalidToken:
            log_warning("Decryption failed: Invalid token or key")
            metrics.increment('security.decryption_failure')
            raise RuntimeError("Decryption failed: Invalid token or key")

    except Exception as e:
        log_error(f"Failed to decrypt sensitive data: {e}")
        raise RuntimeError(f"Failed to decrypt sensitive data: {e}")


def encrypt_aes_gcm(plaintext: str, key: Optional[bytes] = None) -> str:
    """
    Encrypt data using AES-GCM for authenticated encryption.

    This function provides state-of-the-art authenticated encryption using
    AES-GCM mode, which ensures both confidentiality and integrity of the data.

    Args:
        plaintext: The plaintext string to encrypt
        key: Optional encryption key (uses derived key if None)

    Returns:
        str: Base64-encoded encrypted data with embedded nonce and tag

    Raises:
        RuntimeError: If encryption fails
    """
    if not plaintext:
        return plaintext

    try:
        # Get or derive key
        if key is None:
            key = _get_encryption_key()

        # Generate a random 96-bit nonce (recommended size for GCM)
        nonce = os.urandom(12)

        # Create the cipher
        algorithm = algorithms.AES(key)
        mode = modes.GCM(nonce)
        cipher = Cipher(algorithm, mode)

        # Encrypt the plaintext
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()

        # Get the authentication tag
        tag = encryptor.tag

        # Combine nonce, ciphertext and tag for storage
        encrypted_data = nonce + ciphertext + tag

        # Return base64 encoded data
        return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')

    except Exception as e:
        log_error(f"AES-GCM encryption failed: {e}")
        metrics.increment('security.aes_encryption_failure')
        raise RuntimeError(f"Failed to encrypt with AES-GCM: {e}")


def decrypt_aes_gcm(encrypted_data: str, key: Optional[bytes] = None) -> str:
    """
    Decrypt data that was encrypted using AES-GCM.

    This function decrypts data that was encrypted with the encrypt_aes_gcm
    function, verifying both the confidentiality and integrity of the data.

    Args:
        encrypted_data: Base64-encoded encrypted data with embedded nonce and tag
        key: Optional encryption key (uses derived key if None)

    Returns:
        str: Decrypted plaintext string

    Raises:
        RuntimeError: If decryption fails due to invalid key, tampered data, etc.
    """
    if not encrypted_data:
        return encrypted_data

    try:
        # Get or derive key
        if key is None:
            key = _get_encryption_key()

        # Decode the base64 data
        decoded_data = base64.urlsafe_b64decode(encrypted_data)

        # Extract nonce, ciphertext and tag
        nonce = decoded_data[:12]
        tag = decoded_data[-16:]  # GCM tag is 16 bytes
        ciphertext = decoded_data[12:-16]

        # Create the cipher
        algorithm = algorithms.AES(key)
        mode = modes.GCM(nonce, tag)
        cipher = Cipher(algorithm, mode)

        # Decrypt the ciphertext
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext.decode('utf-8')

    except Exception as e:
        log_error(f"AES-GCM decryption failed: {e}")
        metrics.increment('security.aes_decryption_failure')
        raise RuntimeError(f"Failed to decrypt with AES-GCM: {e}")


def sanitize_url(url: str) -> str:
    """
    Sanitize a URL to prevent open redirects and other URL-based attacks.

    This function ensures that URLs used for redirects or external resources
    are properly validated to prevent security vulnerabilities.

    Args:
        url: The URL to sanitize

    Returns:
        str: The sanitized URL or an empty string if invalid
    """
    if not url:
        return ''

    # Try to parse the URL
    try:
        parsed = urlparse(url)

        # Check for javascript: protocol and other potentially unsafe protocols
        if parsed.scheme.lower() in ['javascript', 'data', 'vbscript', 'file']:
            log_warning(f"Blocked unsafe URL scheme: {parsed.scheme}")
            metrics.increment('security.unsafe_url_blocked')
            return ''

        # Check for relative URLs (no scheme and no network location)
        if not parsed.scheme and not parsed.netloc:
            # Only allow paths starting with / to prevent path traversal
            if parsed.path.startswith('/'):
                return url
            else:
                log_warning(f"Blocked potentially unsafe relative URL: {url}")
                return ''

        # If URL has a scheme and host, check against allowlist if configured
        if parsed.scheme and parsed.netloc and has_app_context():
            allowed_domains = current_app.config.get('ALLOWED_REDIRECT_DOMAINS', [])

            # Always allow same-site redirects
            host = parsed.netloc.lower()
            server_name = current_app.config.get('SERVER_NAME', '')

            if server_name and host == server_name.lower():
                return url

            # Check against allowed domains
            if allowed_domains:
                for domain in allowed_domains:
                    if host == domain.lower() or host.endswith('.' + domain.lower()):
                        return url

                # If we reach here, domain is not allowed
                log_warning(f"Blocked redirect to non-allowed domain: {host}")
                metrics.increment('security.unauthorized_redirect')
                return ''
            else:
                # No domain allowlist defined, allow any external domain
                return url

        # If URL starts with a slash, it's a relative URL to the root - this is safe
        if url.startswith('/'):
            return url

        # If we get here with an external URL and no allowlist, it's potentially unsafe
        return ''

    except Exception as e:
        log_error(f"Error sanitizing URL: {e}")
        return ''


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal and other filename-based attacks.

    This function ensures that filenames used for file operations are safe
    and don't contain special characters or path traversal sequences.

    Args:
        filename: The filename to sanitize

    Returns:
        str: The sanitized filename or None if completely invalid
    """
    if not filename:
        return None

    # Remove path components
    filename = os.path.basename(filename)

    # Replace problematic characters
    # Allow letters, numbers, underscore, hyphen, and period
    sanitized = re.sub(r'[^\w\-\.]', '_', filename)

    # Additional security checks
    if sanitized.startswith('.'):
        # Don't allow hidden files
        sanitized = 'f' + sanitized

    if sanitized in ('.', '..'):
        return None

    # Check for common executable extensions
    executable_exts = ['.exe', '.bat', '.cmd', '.sh', '.com', '.dll', '.so', '.app']
    if any(sanitized.lower().endswith(ext) for ext in executable_exts):
        metrics.increment('security.executable_upload_attempt')
        sanitized = sanitized + '.txt'

    return sanitized


#
# Security Metrics and Monitoring
#

def log_security_event(
    event_type: str,
    description: str,
    severity: str = 'info',
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    details: Optional[Union[str, Dict[str, Any]]] = None
) -> bool:
    """
    Log a security event to both application logs and audit log.

    This function serves as the central point for all security event logging
    in the application. It logs to both the application logs and the database
    audit log for comprehensive security event tracking.

    Args:
        event_type: Type of security event (e.g., 'login_failed', 'file_integrity')
        description: Human-readable description of the event
        severity: Severity level ('info', 'warning', 'error', 'critical')
        user_id: ID of the user associated with the event, if any
        ip_address: IP address associated with the event, if any
        details: Additional details about the event

    Returns:
        bool: True if logging was successful, False otherwise
    """
    # Try to get user_id from flask.g if not provided
    if user_id is None and has_request_context() and hasattr(g, 'user_id'):
        user_id = g.user_id

    # Try to get IP address from request if not provided
    if ip_address is None and has_request_context():
        ip_address = request.remote_addr

    # Get proper forwarded IP if behind proxy
    if ip_address is None and has_request_context() and request.headers.get('X-Forwarded-For'):
        # Use the leftmost IP which is the client's IP
        ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()

    # Map severity to logging levels
    severity_levels = {
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }
    log_level = severity_levels.get(severity.lower(), logging.INFO)

    # Map severity to AuditLog severity constants
    audit_severity = {
        'info': AuditLog.SEVERITY_INFO,
        'warning': AuditLog.SEVERITY_WARNING,
        'error': AuditLog.SEVERITY_ERROR,
        'critical': AuditLog.SEVERITY_CRITICAL
    }
    db_severity = audit_severity.get(severity.lower(), AuditLog.SEVERITY_INFO)

    # Prepare details for logging
    log_details = None
    if details:
        if isinstance(details, dict):
            # Format dict as JSON string
            import json
            try:
                log_details = json.dumps(details)
            except (TypeError, ValueError):
                log_details = str(details)
        else:
            log_details = str(details)

    # Log to application log
    try:
        # Create extra data dictionary for structured logging
        extra_data = {
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address,
            'severity': severity
        }

        if log_details:
            extra_data['details'] = log_details

        # Log to security logger
        security_logger.log(
            log_level,
            description,
            extra=extra_data
        )
    except Exception as e:
        # Use a separate logger to avoid potential recursion
        logger.error(f"Error writing to security log: {e}")

    # Record in audit log
    try:
        # Use the AuditLog model
        audit_log = AuditLog(
            event_type=event_type,
            description=description,
            user_id=user_id,
            ip_address=ip_address,
            details=log_details,
            severity=db_severity,
            user_agent=request.user_agent.string if has_request_context() else None,
            created_at=datetime.now(timezone.utc)
        )

        db.session.add(audit_log)
        db.session.commit()

        # Track the security event
        metrics.increment(f'security.event.{event_type}')

        return True

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Failed to record audit log: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error in audit logging: {e}")
        return False


def get_security_metrics(hours: int = 24) -> SecurityMetrics:
    """
    Collect comprehensive security metrics.

    This function compiles a complete picture of the system's security status
    by gathering metrics about failed logins, suspicious IPs, account lockouts,
    session counts, and file integrity information.

    Args:
        hours: Number of hours to look back for metrics

    Returns:
        Dict[str, Any]: Dictionary of security metrics
    """
    try:
        # Cache key for Redis
        cache_key = f"security_metrics:{hours}"
        redis_client = get_redis_client()

        # Check cache first
        if redis_client:
            cached_data = redis_client.get(cache_key)
            if cached_data:
                try:
                    import json
                    return json.loads(cached_data)
                except Exception as e:
                    log_error(f"Failed to parse cached security metrics: {e}")

        # Start with basic metrics
        security_data = {
            'failed_logins_24h': get_failed_login_count(hours=hours),
            'account_lockouts_24h': get_account_lockout_count(hours=hours),
            'active_sessions': get_active_session_count(),
            'suspicious_ips': get_suspicious_ips(hours=hours),
            'config_integrity': True,
            'file_integrity': True,
            'incidents_active': 0,
            'permission_issues': 0,
            'last_checked': datetime.now(timezone.utc).isoformat(),
            'timestamp': int(time.time()),
            'period_hours': hours
        }

        # Only check integrity in application context
        if has_app_context():
            security_data['config_integrity'] = check_config_integrity()
            integrity_result, changes = check_critical_file_integrity()
            security_data['file_integrity'] = integrity_result
            security_data['integrity_changes'] = changes

            try:
                # Count active security incidents
                security_data['incidents_active'] = SecurityIncident.query.filter(
                    SecurityIncident.status.in_(['open', 'investigating'])
                ).count()

                # Get permission issues
                from core.utils import detect_permission_issues
                permission_issues = detect_permission_issues()
                security_data['permission_issues'] = len(permission_issues)
                security_data['permission_details'] = permission_issues[:10]  # First 10 issues

                # Blocked IPs
                security_data['blocked_ips'] = list(get_blocked_ips())
                security_data['blocked_ips_count'] = len(security_data['blocked_ips'])
            except Exception as e:
                log_error(f"Error collecting additional security metrics: {e

        # Calculate risk score (1-10)
        security_data['risk_score'] = calculate_risk_score(security_data)
        security_data['last_checked'] = datetime.utcnow().isoformat()

        return security_data
    except Exception as e:
        logger.error("Error collecting security metrics: %s", str(e))
        # Return minimal data on error
        return {
            'failed_logins_24h': 0,
            'suspicious_ips': [],
            'risk_score': 5,  # Medium risk when metrics can't be collected
            'last_checked': datetime.utcnow().isoformat(),
            'error': str(e)
        }


def encrypt_sensitive_data(plaintext: str) -> str:
    """
    Encrypt sensitive data using Fernet symmetric encryption.

    This function encrypts sensitive configuration values, API keys,
    and other secret data that needs to be stored securely in the database.
    It uses Fernet (AES-128 in CBC mode with PKCS7 padding and HMAC authentication)
    which provides authenticated encryption.

    Args:
        plaintext: The plaintext string to encrypt

    Returns:
        str: Base64-encoded encrypted string

    Raises:
        RuntimeError: If encryption fails due to missing key or other issues
    """
    if not plaintext:
        return plaintext

    try:
        # Get the encryption key
        key = _get_encryption_key()

        # Convert the key to a URL-safe base64-encoded string as required by Fernet
        key_b64 = base64.urlsafe_b64encode(key)

        # Initialize the Fernet cipher with the key
        cipher = Fernet(key_b64)

        # Encrypt the plaintext and encode as a string
        encrypted_data = cipher.encrypt(plaintext.encode('utf-8'))
        return encrypted_data.decode('utf-8')

    except Exception as e:
        log_error("Encryption failed", e)
        raise RuntimeError(f"Failed to encrypt sensitive data: {e}")


def decrypt_sensitive_data(encrypted_data: str) -> str:
    """
    Decrypt sensitive data that was encrypted using encrypt_sensitive_data.

    This function decrypts configuration values, API keys, and other secrets
    that were previously encrypted with the encrypt_sensitive_data function.

    Args:
        encrypted_data: Base64-encoded encrypted string

    Returns:
        str: Decrypted plaintext string

    Raises:
        RuntimeError: If decryption fails due to invalid key, tampered data, etc.
    """
    if not encrypted_data:
        return encrypted_data

    try:
        # Get the encryption key
        key = _get_encryption_key()

        # Convert the key to a URL-safe base64-encoded string as required by Fernet
        key_b64 = base64.urlsafe_b64encode(key)

        # Initialize the Fernet cipher with the key
        cipher = Fernet(key_b64)

        # Decrypt the data
        try:
            decrypted_data = cipher.decrypt(encrypted_data.encode('utf-8'))
            return decrypted_data.decode('utf-8')
        except InvalidToken:
            msg = "Decryption failed: Invalid token or key"
            logger.error(msg)
            raise RuntimeError(msg)

    except Exception as e:
        log_error("Failed to decrypt sensitive data", e)
        raise RuntimeError(f"Failed to decrypt sensitive data: {e}")


def is_suspicious_ip(ip_address: Optional[str], threshold: int = 5) -> bool:
    """
    Determine if an IP address is suspicious based on login failure history and blocklists.

    This function checks if an IP address should be considered suspicious by:
    1. Checking against known suspicious IP cache
    2. Looking up failed login attempts from this IP
    3. Checking against external IP reputation services (when configured)
    4. Checking against known malicious IP ranges

    Args:
        ip_address: The IP address to check
        threshold: Minimum number of failed attempts to consider an IP suspicious

    Returns:
        bool: True if the IP is suspicious, False otherwise
    """
    if not ip_address:
        return False

    try:
        # Check against known malicious networks
        try:
            ip_obj = ip_address(ip_address)
            for network_str in SECURITY_CONFIG.get('KNOWN_MALICIOUS_NETWORKS', []):
                if ip_obj in ip_network(network_str):
                    logger.warning(f"IP {ip_address} found in known malicious network {network_str}")
                    return True
        except ValueError:
            # Invalid IP address format
            pass

        # Check Redis cache first for known suspicious IPs (faster)
        redis_client = get_redis_client()
        if redis_client:
            cached_result = redis_client.get(f"suspicious_ip:{ip_address}")
            if cached_result:
                return cached_result.decode() == "True"

        # Check for failed login attempts in audit log
        cutoff = datetime.utcnow() - timedelta(hours=24)
        failed_count = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
            AuditLog.ip_address == ip_address,
            AuditLog.created_at >= cutoff
        ).scalar()

        if failed_count >= threshold:
            # Cache the result for 1 hour
            if redis_client:
                redis_client.setex(f"suspicious_ip:{ip_address}", 3600, "True")
            return True

        # Check for other security breach attempts
        breach_attempts = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.event_type.in_([
                AuditLog.EVENT_SECURITY_BREACH_ATTEMPT,
                AuditLog.EVENT_PERMISSION_DENIED,
                AuditLog.EVENT_RATE_LIMIT_EXCEEDED
            ]),
            AuditLog.ip_address == ip_address,
            AuditLog.created_at >= cutoff
        ).scalar()

        if breach_attempts > 0:
            # Cache the result for 1 hour
            if redis_client:
                redis_client.setex(f"suspicious_ip:{ip_address}", 3600, "True")
            return True

    except SQLAlchemyError as e:
        log_error(f"Database error when checking suspicious IP: {ip_address}", e)
        return False

    # Check against external IP reputation service if configured
    if has_app_context() and current_app.config.get('IP_REPUTATION_CHECK_ENABLED'):
        result = _check_ip_reputation(ip_address)
        if result:
            # Cache the result for 6 hours
            if redis_client:
                redis_client.setex(f"suspicious_ip:{ip_address}", 21600, "True")
            return True

    # Cache negative result for 30 minutes
    if redis_client:
        redis_client.setex(f"suspicious_ip:{ip_address}", 1800, "False")

    return False


def get_blocked_ips() -> Set[str]:
    """
    Get set of currently blocked IP addresses.

    Returns:
        Set[str]: Set of blocked IP addresses
    """
    blocked_ips = set()

    try:
        redis_client = get_redis_client()
        if not redis_client:
            logger.warning("Redis unavailable for retrieving blocked IPs")
            return blocked_ips

        # Get all keys matching blocked IP pattern
        keys = redis_client.keys("blocked_ip:*")

        # Extract IP addresses from keys
        for key in keys:
            ip = key.decode('utf-8').split(':', 1)[1]
            blocked_ips.add(ip)

        return blocked_ips
    except Exception as e:
        logger.error(f"Error retrieving blocked IPs: {str(e)}")
        return blocked_ips


def block_ip(ip_address: str, duration: int = 3600, reason: str = "security_policy") -> bool:
    """
    Block an IP address for a specified duration.

    Args:
        ip_address: IP address to block
        duration: Block duration in seconds (default: 1 hour)
        reason: Reason for the block

    Returns:
        bool: True if successfully blocked, False otherwise
    """
    try:
        if not ip_address or not _is_valid_ip(ip_address):
            logger.error(f"Invalid IP address format: {ip_address}")
            return False

        redis_client = get_redis_client()
        if not redis_client:
            logger.warning(f"Redis unavailable, unable to block IP: {ip_address}")
            return False

        # Store block information
        block_data = {
            'blocked_at': datetime.utcnow().isoformat(),
            'reason': reason,
            'duration': duration
        }

        # Set with expiry
        redis_client.setex(
            f"blocked_ip:{ip_address}",
            duration,
            str(block_data)
        )

        # Log the event
        logger.info(f"Blocked IP {ip_address} for {duration} seconds. Reason: {reason}")

        # Record security event
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_COUNTERMEASURE,
            description=f"Blocked IP address: {ip_address}",
            severity='warning',
            ip_address=ip_address,
            details=f"Duration: {duration} seconds, Reason: {reason}"
        )

        return True
    except Exception as e:
        logger.error(f"Failed to block IP {ip_address}: {str(e)}")
        return False


def check_ip_blocked(ip_address: str) -> bool:
    """
    Check if an IP address is currently blocked.

    Args:
        ip_address: IP address to check

    Returns:
        bool: True if IP is blocked, False otherwise
    """
    try:
        if not ip_address:
            return False

        redis_client = get_redis_client()
        if not redis_client:
            logger.warning("Redis unavailable, cannot check if IP is blocked")
            return False

        # Check if key exists
        return redis_client.exists(f"blocked_ip:{ip_address}") > 0
    except Exception as e:
        logger.error(f"Error checking if IP {ip_address} is blocked: {str(e)}")
        return False


def unblock_ip(ip_address: str) -> bool:
    """
    Remove a block on an IP address.

    Args:
        ip_address: IP address to unblock

    Returns:
        bool: True if successfully unblocked or wasn't blocked, False on error
    """
    try:
        if not ip_address:
            return False

        redis_client = get_redis_client()
        if not redis_client:
            logger.warning(f"Redis unavailable, unable to unblock IP: {ip_address}")
            return False

        # Remove the block
        redis_client.delete(f"blocked_ip:{ip_address}")

        # Log the event
        logger.info(f"Unblocked IP: {ip_address}")

        return True
    except Exception as e:
        logger.error(f"Failed to unblock IP {ip_address}: {str(e)}")
        return False


def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
    """
    Validate password strength against security requirements.

    Args:
        password: Password to validate

    Returns:
        Tuple of (bool, List[str]): Success flag and list of failed requirements
    """
    min_length = SECURITY_CONFIG.get('MIN_PASSWORD_LENGTH', 12)
    failed_requirements = []

    # Check length
    if len(password) < min_length:
        failed_requirements.append(f"Password must be at least {min_length} characters long")

    # Check for lowercase
    if not re.search(r'[a-z]', password):
        failed_requirements.append("Password must include lowercase letters")

    # Check for uppercase
    if not re.search(r'[A-Z]', password):
        failed_requirements.append("Password must include uppercase letters")

    # Check for numbers
    if not re.search(r'[0-9]', password):
        failed_requirements.append("Password must include numbers")

    # Check for special characters
    if not re.search(r'[^a-zA-Z0-9]', password):
        failed_requirements.append("Password must include special characters")

    # Check for common passwords if available
    if has_app_context() and current_app.config.get('COMMON_PASSWORDS_FILE'):
        common_passwords_file = current_app.config.get('COMMON_PASSWORDS_FILE')
        if os.path.exists(common_passwords_file):
            try:
                with open(common_passwords_file, 'r') as f:
                    common_password_hash = hashlib.sha256(password.lower().encode()).hexdigest()
                    for line in f:
                        if line.strip() == common_password_hash:
                            failed_requirements.append("Password is too common or has been compromised")
                            break
            except Exception as e:
                logger.error(f"Error checking common passwords: {str(e)}")

    return len(failed_requirements) == 0, failed_requirements


def generate_secure_token(length: int = 64) -> str:
    """
    Generate a cryptographically secure random token.

    Args:
        length: Length of the token in bytes (default: 64)

    Returns:
        str: Base64-encoded secure token
    """
    import os
    import base64

    # Generate secure random bytes
    token_bytes = os.urandom(length)

    # Convert to URL-safe base64 encoding and remove padding
    token = base64.urlsafe_b64encode(token_bytes).decode('utf-8').rstrip('=')

    return token


def _check_ip_reputation(ip_address: str) -> bool:
    """
    Check IP reputation against external threat intelligence services.

    Args:
        ip_address: IP address to check

    Returns:
        bool: True if IP is malicious according to reputation services
    """
    if not has_app_context():
        return False

    api_key = current_app.config.get('IP_REPUTATION_API_KEY')
    service = current_app.config.get('IP_REPUTATION_SERVICE', 'abuseipdb')

    if not api_key:
        return False

    try:
        if service.lower() == 'abuseipdb':
            headers = {
                'Accept': 'application/json',
                'Key': api_key
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 30,
                'verbose': False
            }
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params=params,
                timeout=3
            )

            if response.status_code == 200:
                data = response.json()
                confidence_score = data.get('data', {}).get('abuseConfidenceScore', 0)
                return confidence_score > 80  # Consider suspicious if over 80% confidence

        return False

    except Exception as e:
        log_error(f"Error checking IP reputation for {ip_address}", e)
        return False


def derive_key_from_password(password: str, salt: Optional[bytes] = None) -> bytes:
    """
    Derive a cryptographic key from a password using PBKDF2.

    Args:
        password: The password to derive key from
        salt: Optional salt for key derivation

    Returns:
        bytes: 32-byte key suitable for encryption
    """
    salt = salt or SECURITY_CONFIG.get('ENCRYPTION_SALT', b'cloud-infrastructure-platform-salt')
    iterations = SECURITY_CONFIG.get('DEFAULT_KEY_ITERATIONS', 100000)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )

    return kdf.derive(password.encode())


def _get_encryption_key() -> bytes:
    """
    Get or derive the encryption key for sensitive data.

    Returns:
        bytes: 32-byte encryption key

    Raises:
        RuntimeError: If key cannot be obtained
    """
    # First try environment variable
    key = SECURITY_CONFIG.get('ENCRYPTION_KEY')

    # Then try app config
    if not key and has_app_context():
        key = current_app.config.get('ENCRYPTION_KEY')

    if not key and has_app_context():
        # Derive a 32-byte key from the app secret key using SHA-256
        secret_key = current_app.config.get('SECRET_KEY')
        if secret_key:
            return hashlib.sha256(secret_key.encode()).digest()
        else:
            raise RuntimeError("No encryption key or SECRET_KEY available")
    elif not key:
        raise RuntimeError("No encryption key available and not in app context")

    # Convert string key to bytes if needed
    if isinstance(key, str):
        # Ensure key is 32 bytes (256 bits)
        return hashlib.sha256(key.encode()).digest()

    return key


def _is_valid_ip(ip_str: str) -> bool:
    """
    Check if a string is a valid IPv4 or IPv6 address.

    Args:
        ip_str: String to check

    Returns:
        bool: True if valid IP address, False otherwise
    """
    try:
        ip_address(ip_str)
        return True
    except ValueError:
        return False


def log_error(message: str, exception: Optional[Exception] = None) -> None:
    """
    Helper function to log errors consistently.

    Args:
        message: Error message
        exception: Optional exception that caused the error
    """
    error_message = message
    if exception:
        error_message = f"{message}: {str(exception)}"

    if has_app_context() and hasattr(current_app, 'logger'):
        current_app.logger.error(error_message)
    else:
        logger.error(error_message)


def can_access_ui_element(element_id: str, required_permission: str = None):
    """
    Decorator factory to control access to UI elements based on permissions.

    This decorator manages UI element visibility based on user permissions without
    raising errors. It allows for progressive UI enhancement where elements are
    conditionally shown based on the user's access rights.

    Args:
        element_id: The UI element identifier that will be used in templates
        required_permission: The permission name required to see the element
                            (format: 'resource:action')

    Returns:
        Callable: A decorator that controls UI element access

    Example:
        @app.route('/dashboard')
        @can_access_ui_element('admin_panel', 'admin:access')
        def dashboard():
            return render_template('dashboard.html')
    """
    def decorator(view_func):
        @wraps(view_func)
        def decorated_function(*args, **kwargs):
            # Initialize ui_permissions dict if it doesn't exist
            kwargs['ui_permissions'] = kwargs.get('ui_permissions', {})

            # Default to showing the element
            has_access = True

            # Check permission if one is required
            if required_permission:
                # Guard against current_user not being authenticated
                if not hasattr(current_user, 'has_permission'):
                    has_access = False
                # Handle case where current_user isn't properly initialized
                elif getattr(current_user, 'is_authenticated', False) is False:
                    has_access = False
                # Check the actual permission
                elif not current_user.has_permission(required_permission):
                    has_access = False

            # Store the result in the ui_permissions dict
            kwargs['ui_permissions'][element_id] = has_access

            # Add element_id to a list of checked elements for debugging
            if 'checked_elements' not in kwargs:
                kwargs['checked_elements'] = []
            kwargs['checked_elements'].append(element_id)

            return view_func(*args, **kwargs)
        return decorated_function
    return decorator
