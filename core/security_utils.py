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
from ipaddress import ip_address, ip_network
import re
import requests
from typing import List, Dict, Any, Optional, Tuple, Union, Set
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, desc, or_, and_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.hybrid import hybrid_property
from flask import current_app, request, g, has_request_context, session, has_app_context
from flask_login import current_user
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from models.audit_log import AuditLog
from models.security_incident import SecurityIncident
from models.base import BaseModel, AuditableMixin
from extensions import db
from extensions import get_redis_client
from core.utils import detect_file_changes
from functools import wraps

# Setup module-level logger
logger = logging.getLogger(__name__)

# Security configuration constants
SECURITY_CONFIG = {
    'ENCRYPTION_KEY': os.getenv('ENCRYPTION_KEY'),  # A strong random 32-byte key for encrypting sensitive data
    'ENCRYPTION_SALT': os.getenv('ENCRYPTION_SALT', b'cloud-infrastructure-platform-salt'),
    'DEFAULT_KEY_ITERATIONS': 100000,  # PBKDF2 iterations for key derivation
    'TOKEN_EXPIRY': 3600,  # Default token expiry in seconds (1 hour)
    'MIN_PASSWORD_LENGTH': 12,  # Minimum password length
    'MAX_LOGIN_ATTEMPTS': 5,  # Maximum failed login attempts before lockout
    'SUSPICIOUS_IP_THRESHOLD': 5,  # Failed attempts threshold for suspicious IP
    'LOCKOUT_DURATION': 30 * 60,  # Account lockout duration in seconds (30 minutes)
    'KNOWN_MALICIOUS_NETWORKS': [
        # Example malicious network blocks (replace with actual ones)
        '185.159.128.0/18',  # Example - known botnet range
        '192.42.116.0/22',  # Example - known attack source
    ],
}


def get_suspicious_ips(hours: int = 24, min_attempts: int = 5) -> List[Dict[str, Any]]:
    """
    Get list of suspicious IPs with their activity counts.

    Args:
        hours: Number of hours to look back for failed login attempts
        min_attempts: Minimum number of failed attempts to consider an IP suspicious

    Returns:
        List[Dict[str, Any]]: List of suspicious IPs with their failed login counts
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    try:
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

        return result
    except SQLAlchemyError as e:
        log_error("Database error in get_suspicious_ips", e)
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
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        return db.session.query(AuditLog).filter(
            AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
            AuditLog.created_at >= cutoff
        ).count()
    except SQLAlchemyError as e:
        log_error("Database error in get_failed_login_count", e)
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
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        return db.session.query(AuditLog).filter(
            AuditLog.event_type == AuditLog.EVENT_ACCOUNT_LOCKOUT,
            AuditLog.created_at >= cutoff
        ).count()
    except SQLAlchemyError as e:
        log_error("Database error in get_account_lockout_count", e)
        return 0


def get_active_session_count() -> int:
    """
    Get count of active user sessions.

    Returns:
        int: Count of active sessions
    """
    try:
        # Use Redis client from .extensions
        redis_client = get_redis_client()
        if redis_client:
            session_keys = redis_client.keys('session:*')
            return len(session_keys) if session_keys else 0

        # Fallback to database count if Redis unavailable
        return 0
    except Exception as e:
        log_error("Error in get_active_session_count", e)
        return 0


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
        logger.warning(f"File does not exist: {file_path}")
        return False

    try:
        current_hash = calculate_file_hash(file_path, algorithm)
        return current_hash == expected_hash
    except (IOError, OSError) as e:
        log_error(f"Error checking file integrity for {file_path}", e)
        return False
    except ValueError as e:
        log_error(f"Invalid hash algorithm for {file_path}", e)
        return False


def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """
    Calculate cryptographic hash of a file.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use ('sha256', 'sha384', 'sha512')

    Returns:
        str: Hexadecimal hash digest

    Raises:
        IOError: If file cannot be read
        ValueError: If algorithm is not supported
        OSError: If file system errors occur
    """
    hash_algorithms = {
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'md5': hashlib.md5,  # Included for legacy compatibility, not recommended for security
    }

    hash_func = hash_algorithms.get(algorithm.lower())
    if not hash_func:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    try:
        with open(file_path, 'rb') as f:
            file_hash = hash_func()
            # Read file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(8192), b''):
                file_hash.update(chunk)

        return file_hash.hexdigest()
    except (IOError, OSError) as e:
        logger.error(f"Failed to calculate hash for {file_path}: {str(e)}")
        raise


def log_security_event(
    event_type: str,
    description: str,
    severity: str = 'info',
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    details: Optional[str] = None
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

    Example:
        log_security_event(
            event_type=AuditLog.EVENT_LOGIN_FAILED,
            description='Failed login attempt for user admin',
            severity='warning',
            user_id=None,
            ip_address='192.168.1.1',
        )
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

    # Log to application log
    try:
        if has_app_context() and hasattr(current_app, 'logger'):
            current_app.logger.log(
                log_level,
                "[SECURITY] %s",
                description,
                extra={
                    'event_type': event_type,
                    'user_id': user_id,
                    'ip_address': ip_address
                }
            )
        else:
            # Fallback to standard logging if no Flask context
            logger.log(
                log_level,
                "[SECURITY] %s (user_id=%s, ip=%s)",
                description, user_id, ip_address
            )
    except Exception as e:
        # Use a separate logger to avoid potential recursion
        logger.error("Error writing to security log: %s", str(e))

    # Record in audit log
    try:
        # Directly create the AuditLog instance without using create()
        # to avoid potential method recursion
        audit_log = AuditLog(
            event_type=event_type,
            description=description,
            user_id=user_id,
            ip_address=ip_address,
            details=details,
            severity=db_severity,
            user_agent=request.user_agent.string if has_request_context() else None,
            created_at=datetime.now(timezone.utc)
        )

        db.session.add(audit_log)
        db.session.commit()
        return True

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Failed to record audit log: %s", str(e))
        return False
    except Exception as e:
        logger.error("Unexpected error in audit logging: %s", str(e))
        return False


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
        from extensions import metrics

        # Use provided secret or fall back to app secret
        key = secret_key
        if key is None and has_app_context():
            key = current_app.config.get('JWT_SECRET_KEY')

        if not key:
            logger.error('JWT_SECRET_KEY not configured')
            return None

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
                'verify_aud': True if has_app_context() and current_app.config.get('JWT_AUDIENCE') else False,
            }
        )

        # Additional validation
        if 'exp' not in payload:
            logger.warning('Token missing expiration claim')
            return None

        metrics.info('token_verification_success', 1)
        return payload

    except jwt.ExpiredSignatureError:
        metrics.info('token_verification_expired', 1)
        logger.warning('Token expired')
        return None
    except jwt.InvalidTokenError as e:
        metrics.info('token_verification_invalid', 1)
        logger.warning('Invalid token: %s', str(e))
        return None
    except ImportError as e:
        logger.error('JWT library not available: %s', str(e))
        return None
    except Exception as e:
        metrics.info('token_verification_error', 1)
        logger.error('Error verifying token: %s', str(e))
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
        import uuid

        # Save the important session values
        saved_data = {}
        keys_to_preserve = ['user_id', 'username', 'role', 'last_active', 'csrf_token']

        for key in keys_to_preserve:
            if key in session:
                saved_data[key] = session[key]

        # Clear the current session
        session.clear()

        # Generate a new session ID
        session['session_id'] = str(uuid.uuid4())

        # Restore the saved values
        for key, value in saved_data.items():
            session[key] = value

        # Update last active time
        session['last_active'] = datetime.utcnow().isoformat()

        # Generate new CSRF token
        if has_app_context() and hasattr(current_app, 'csrf'):
            session['csrf_token'] = current_app.csrf.generate_csrf_token()

        # Log the event
        user_id = saved_data.get('user_id', 'unknown')

        if has_app_context():
            current_app.logger.info("Session regenerated for user_id=%s", user_id)
        else:
            logger.info("Session regenerated for user_id=%s", user_id)

        return True
    except Exception as e:
        logger.error("Failed to regenerate session: %s", str(e))
        return False


def invalidate_user_sessions(user_id: int) -> bool:
    """
    Invalidate all sessions for a specific user.

    Args:
        user_id: User ID whose sessions should be invalidated

    Returns:
        bool: True if sessions were invalidated, False otherwise
    """
    try:
        # Get Redis client
        redis_client = get_redis_client()
        if not redis_client:
            logger.warning("Redis unavailable, unable to invalidate sessions")
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
                    logger.error("Error processing session key %s: %s", key, str(e))

            # Exit when we've scanned all keys
            if cursor == 0:
                break

        # Delete the sessions in batches to avoid timeout issues
        if sessions:
            batch_size = 100
            for i in range(0, len(sessions), batch_size):
                batch = sessions[i:i + batch_size]
                redis_client.delete(*batch)

            logger.info("Invalidated %d sessions for user ID %s", len(sessions), user_id)
        else:
            logger.info("No active sessions found for user ID %s", user_id)

        return True
    except Exception as e:
        logger.error("Failed to invalidate user sessions: %s", str(e))
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
            app.logger.warning("No reference hashes found for config files")
            return False

        failed_files = []

        # Check each file against its expected hash
        for file_path, expected_hash in expected_hashes.items():
            if not os.path.exists(file_path):
                app.logger.warning("Configuration file not found: %s", file_path)
                failed_files.append(file_path)
                continue

            if not check_file_integrity(file_path, expected_hash):
                app.logger.warning("Configuration file integrity check failed: %s", file_path)
                failed_files.append(file_path)

                # Record security event
                try:
                    log_security_event(
                        event_type=AuditLog.EVENT_FILE_INTEGRITY,
                        description=f"Configuration file modified: {file_path}",
                        severity='error'
                    )
                except Exception as e:
                    app.logger.error("Failed to record file integrity event: %s", str(e))

        return len(failed_files) == 0
    except Exception as e:
        logger.error("Error in check_config_integrity: %s", str(e))
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
            app.logger.warning("No reference hashes found for critical files")
            return False, [{"path": "configuration", "status": "missing", "severity": "high"}]

        # Use the more comprehensive detection function
        app_root = os.path.dirname(os.path.abspath(app.root_path))
        changes = detect_file_changes(app_root, expected_hashes)

        if changes:
            # Log each detected change
            for change in changes:
                path = change.get('path', 'unknown')
                status = change.get('status', 'unknown')
                severity = change.get('severity', 'medium')

                app.logger.warning("File integrity violation: %s (%s)", path, status)

                # Record security event for high severity changes
                if severity in ('high', 'critical'):
                    try:
                        log_security_event(
                            event_type=AuditLog.EVENT_FILE_INTEGRITY,
                            description=f"Critical file modified: {path}",
                            severity='error'
                        )
                    except Exception as e:
                        app.logger.error("Failed to record file integrity event: %s", str(e))

            return False, changes

        return True, []
    except Exception as e:
        logger.error("Error in check_critical_file_integrity: %s", str(e))
        return False, [{"path": "system", "status": "error", "severity": "high", "details": str(e)}]


def calculate_risk_score(security_data: Dict[str, Any]) -> int:
    """
    Calculate security risk score based on collected security metrics.

    Args:
        security_data: Dictionary containing security metrics

    Returns:
        int: Risk score on a scale of 1-10
    """
    score = 1  # Start with minimum risk

    try:
        # Check failed logins
        failed_logins = security_data.get('failed_logins_24h', 0)
        if failed_logins > 100:
            score += 3
        elif failed_logins > 50:
            score += 2
        elif failed_logins > 20:
            score += 1

        # Check account lockouts
        account_lockouts = security_data.get('account_lockouts_24h', 0)
        if account_lockouts > 5:
            score += 2
        elif account_lockouts > 0:
            score += 1

        # Check suspicious IPs
        suspicious_ips = security_data.get('suspicious_ips', [])
        if len(suspicious_ips) > 10:
            score += 3
        elif suspicious_ips:
            score += 1

        # Check file integrity
        if not security_data.get('config_integrity', True):
            score += 3

        if not security_data.get('file_integrity', True):
            score += 2

        # Check active security incidents
        active_incidents = security_data.get('incidents_active', 0)
        if active_incidents > 2:
            score += 3
        elif active_incidents > 0:
            score += 1

        # Check for permission problems
        permission_issues = security_data.get('permission_issues', 0)
        if permission_issues > 0:
            score += 1

        return min(score, 10)  # Cap at maximum risk of 10
    except Exception as e:
        logger.error("Error calculating risk score: %s", str(e))
        return 5  # Return medium risk on error


def calculate_threat_level(anomalies: Dict[str, Any], baseline_risk: Optional[int] = None) -> int:
    """
    Calculate overall threat level based on detected anomalies.

    This function analyzes security anomalies and determines a threat level
    on a scale of 1-10, with 10 being the most severe. Optionally incorporates
    a baseline risk score to provide context-aware threat assessment.

    Args:
        anomalies: Dictionary containing detected anomalies
        baseline_risk: Optional baseline risk score from security metrics (1-10)

    Returns:
        int: Threat level on scale of 1-10
    """
    try:
        # Start with a base threat level, incorporating baseline risk if available
        threat_level = 1
        if baseline_risk is not None:
            # The baseline risk (1-10) contributes to the starting threat level
            threat_level = max(1, min(5, baseline_risk // 2))

        # Check for login anomalies
        if 'login_anomalies' in anomalies:
            login_data = anomalies['login_anomalies']

            # Suspicious IPs
            suspicious_ips = login_data.get('suspicious_ips', [])
            if len(suspicious_ips) > 10:
                threat_level += 3
            elif suspicious_ips:
                threat_level += 1

            # Failed attempts
            if login_data.get('brute_force_attempts', []):
                threat_level += 2

            # Geolocation anomalies
            if login_data.get('geo_anomalies', []):
                threat_level += 2

        # Check for session anomalies
        if 'session_anomalies' in anomalies:
            session_data = anomalies['session_anomalies']

            # IP changes
            if session_data.get('ip_changes', []):
                threat_level += 2

            # Concurrent sessions
            if session_data.get('concurrent_sessions', []):
                threat_level += 1

            # Session hijacking attempts
            if session_data.get('hijacking_attempts', []):
                threat_level += 3

        # Check for API anomalies
        if 'api_anomalies' in anomalies:
            api_data = anomalies['api_anomalies']

            # Rate limit violations
            if api_data.get('rate_limit_violations', []):
                threat_level += 1

            # Unauthorized attempts
            if api_data.get('unauthorized_attempts', []):
                threat_level += 2

            # Suspicious patterns
            if api_data.get('suspicious_patterns', []):
                threat_level += 2

        # Check for database anomalies
        if 'database_anomalies' in anomalies:
            db_data = anomalies['database_anomalies']

            # Sensitive table access
            if db_data.get('sensitive_tables', []):
                threat_level += 3

            # Injection attempts
            if db_data.get('injection_attempts', []):
                threat_level += 3

            # Unusual query patterns
            if db_data.get('unusual_queries', []):
                threat_level += 2

        # Check for file access anomalies
        if 'file_access_anomalies' in anomalies:
            file_data = anomalies['file_access_anomalies']

            # Config file accessed
            if file_data.get('config_access', []):
                threat_level += 2

            # Critical file modified
            if not file_data.get('config_integrity', True):
                threat_level += 2

            if not file_data.get('file_integrity', True):
                threat_level += 3

        # Network anomalies
        if 'network_anomalies' in anomalies:
            network_data = anomalies['network_anomalies']

            # Unusual outbound connections
            if network_data.get('unusual_outbound', []):
                threat_level += 3

            # Port scanning activity
            if network_data.get('port_scanning', []):
                threat_level += 2

        # Cap the threat level at 10
        return min(threat_level, 10)
    except Exception as e:
        logger.error("Error calculating threat level: %s", str(e))
        return 5  # Return medium threat level on error


def get_security_metrics(hours: int = 24) -> Dict[str, Any]:
    """
    Collect comprehensive security metrics.

    Args:
        hours: Number of hours to look back for metrics

    Returns:
        Dict[str, Any]: Dictionary of security metrics
    """
    try:
        security_data = {
            'failed_logins_24h': get_failed_login_count(hours=hours),
            'account_lockouts_24h': get_account_lockout_count(hours=hours),
            'active_sessions': get_active_session_count(),
            'suspicious_ips': get_suspicious_ips(hours=hours),
            'config_integrity': True,
            'file_integrity': True,
            'incidents_active': 0,
            'permission_issues': 0
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
                from core.file_utils import get_permission_issues
                permission_issues = get_permission_issues()
                security_data['permission_issues'] = len(permission_issues)
                security_data['permission_details'] = permission_issues[:10]  # First 10 issues
            except Exception as e:
                logger.error("Error collecting additional security metrics: %s", str(e))

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
