# core/security_utils.py
import os
import hashlib
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app, request, g, has_request_context, session

from models.audit_log import AuditLog
from extensions import db
from extensions import get_redis_client

'ENCRYPTION_KEY': os.getenv('ENCRYPTION_KEY'),  # A strong random 32-byte key for encrypting sensitive data

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
    
    # Subquery to count failed login attempts by IP
    failed_login_counts = db.session.query(
        AuditLog.ip_address,
        func.count(AuditLog.id).label('count')
    ).filter(
        AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
        AuditLog.created_at >= cutoff,
        AuditLog.ip_address.isnot(None)  # Type-checker friendly version
    ).group_by(AuditLog.ip_address).subquery()
    
    # Get IPs with more than min_attempts failed attempts
    suspicious = db.session.query(
        failed_login_counts.c.ip_address,
        failed_login_counts.c.count
    ).filter(failed_login_counts.c.count > min_attempts).all()
    
    return [{'ip': ip, 'count': count} for ip, count in suspicious]


def get_failed_login_count(hours: int = 24) -> int:
    """
    Get count of failed logins in the past hours.
    
    Args:
        hours: Number of hours to look back
        
    Returns:
        int: Count of failed login events
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    return db.session.query(AuditLog).filter(
        AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
        AuditLog.created_at >= cutoff
    ).count()
    

def get_account_lockout_count(hours: int = 24) -> int:
    """
    Get count of account lockouts in the past hours.
    
    Args:
        hours: Number of hours to look back
        
    Returns:
        int: Count of account lockout events
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    return db.session.query(AuditLog).filter(
        AuditLog.event_type == AuditLog.EVENT_ACCOUNT_LOCKOUT,
        AuditLog.created_at >= cutoff
    ).count()


def get_active_session_count() -> int:
    """
    Get count of active user sessions.
    
    Returns:
        int: Count of active sessions
    """
    # Use Redis client from .extensions
    redis_client = get_redis_client()
    if redis_client:
        return len([k for k in redis_client.keys('session:*') or []])
    
    # Fallback to database count if Redis unavailable
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
        return False
        
    try:
        current_hash = calculate_file_hash(file_path, algorithm)
        return current_hash == expected_hash
    except (IOError, OSError):
        return False


def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """
    Calculate cryptographic hash of a file.
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use ('sha256', 'sha384', 'sha512')
        
    Returns:
        str: Hexadecimal hash digest
    """
    hash_algorithms = {
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384, 
        'sha512': hashlib.sha512
    }
    
    hash_func = hash_algorithms.get(algorithm.lower(), hashlib.sha256)
    
    with open(file_path, 'rb') as f:
        file_hash = hash_func()
        while chunk := f.read(8192):  # 8KB chunks
            file_hash.update(chunk)
    
    return file_hash.hexdigest()


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
    
    # Map severity to logging levels
    severity_levels = {
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }
    log_level = severity_levels.get(severity, logging.INFO)
    
    # Map severity to AuditLog severity constants
    audit_severity = {
        'info': AuditLog.SEVERITY_INFO,
        'warning': AuditLog.SEVERITY_WARNING,
        'error': AuditLog.SEVERITY_ERROR,
        'critical': AuditLog.SEVERITY_CRITICAL
    }
    db_severity = audit_severity.get(severity, AuditLog.SEVERITY_INFO)
    
    # Log to application log
    try:
        from flask import has_app_context
        if has_app_context() and has_request_context() and hasattr(current_app, 'logger'):
            current_app.logger.log(
                log_level,
                f"[SECURITY] {description}",
                extra={
                    'event_type': event_type,
                    'user_id': user_id,
                    'ip_address': ip_address
                }
            )
        else:
            # Fallback to standard logging if no Flask context
            logging.log(
                log_level,
                "[SECURITY] %s (user_id=%s, ip=%s)",
                description, user_id, ip_address
            )
    except (KeyError, ValueError, TypeError) as e:  # Replace with specific exceptions
        # Don't let logging errors prevent audit log entry
        from flask import has_app_context
        if has_app_context() and has_request_context() and hasattr(current_app, 'logger'):
            current_app.logger.error(f"Error writing to security log: {e}")
        else:
            logging.error("Error writing to security log: %s", e)
    
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
            severity=db_severity
        )
        
        db.session.add(audit_log)
        db.session.commit()
        return True
        
    except SQLAlchemyError as e:
        db.session.rollback()
        if has_request_context() and hasattr(current_app, 'logger'):
            current_app.logger.error(f"Failed to record audit log: {e}")
        else:
            logging.error("Failed to record audit log: %s", e)
        return False
    except (SQLAlchemyError, RuntimeError, ValueError) as e:  # Replace with specific exceptions
        # Handle any other exception types
        if has_request_context() and hasattr(current_app, 'logger'):
            current_app.logger.error(f"Unexpected error in audit logging: {e}")
        else:
            logging.error("Unexpected error in audit logging: %s", e)
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
    import jwt
    from extensions import metrics
    
    if not token:
        return None
        
    try:
        # Use provided secret or fall back to app secret
        key = secret_key or current_app.config.get('JWT_SECRET_KEY')
        if not key:
            current_app.logger.error('JWT_SECRET_KEY not configured')
            return None
            
        # Verify token
        payload = jwt.decode(token, key, algorithms=['HS256'])
        metrics.info('token_verification_success', 1)
        return payload
        
    except jwt.ExpiredSignatureError:
        metrics.info('token_verification_expired', 1)
        current_app.logger.warning('Token expired')
        return None


def regenerate_session() -> None:
    """
    Regenerate the session to prevent session fixation attacks.
    
    This function preserves important session data while creating a new
    session ID, effectively preventing session fixation attacks.
    """
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
    
    # Generate new CSRF token
    if hasattr(current_app, 'csrf'):
        session['csrf_token'] = current_app.csrf.generate_csrf_token()
        
    # Log the event
    user_id = saved_data.get('user_id', 'unknown')
    current_app.logger.info(f"Session regenerated for user_id={user_id}")


def invalidate_user_sessions(user_id: int) -> bool:
    """
    Invalidate all sessions for a specific user.
    
    Args:
        user_id: User ID whose sessions should be invalidated
        
    Returns:
        bool: True if sessions were invalidated, False otherwise
    """
    redis_client = get_redis_client()
    if not redis_client:
        current_app.logger.warning("Redis unavailable, unable to invalidate sessions")
        return False
    
    # Find all sessions for this user
    session_pattern = "session:*"
    sessions = []
    
    for key in redis_client.scan_iter(match=session_pattern):
        session_data = redis_client.get(key)
        if session_data and f'"user_id":{user_id}' in session_data:
            sessions.append(key)
    
    # Delete the sessions
    if sessions:
        redis_client.delete(*sessions)
    
    return True


def check_config_integrity(app=None) -> bool:
    """
    Verify integrity of critical configuration files.
    
    Args:
        app: Optional Flask app instance (uses current_app if None)
    
    Returns:
        bool: True if all files match their reference hashes, False otherwise
    """
    app = app or current_app
    
    # Get expected hashes from application configuration
    expected_hashes = app.config.get('CONFIG_FILE_HASHES', {})
    if not expected_hashes:
        app.logger.warning("No reference hashes found for config files")
        return False
    
    # Check each file against its expected hash
    for file_path, expected_hash in expected_hashes.items():
        if not check_file_integrity(file_path, expected_hash):
            app.logger.warning(f"Configuration file integrity check failed: {file_path}")
            
            # Record security event
            try:
                log_security_event(
                    event_type=AuditLog.EVENT_FILE_INTEGRITY,
                    description=f"Configuration file modified: {file_path}",
                    severity='error'
                )
            except SQLAlchemyError as e:
                app.logger.error(f"Failed to record file integrity event: {e}")
                
            return False
    
    return True


def check_critical_file_integrity(app=None) -> bool:
    """
    Verify integrity of critical application files.
    
    Args:
        app: Optional Flask app instance (uses current_app if None)
    
    Returns:
        bool: True if all files match their reference hashes, False otherwise
    """
    app = app or current_app
    
    from core.utils import detect_file_changes
    
    # Get expected hashes from application configuration
    expected_hashes = app.config.get('CRITICAL_FILE_HASHES', {})
    if not expected_hashes:
        app.logger.warning("No reference hashes found for critical files")
        return False
    
    # Use the more comprehensive detection function
    app_root = os.path.dirname(os.path.abspath(app.root_path))
    changes = detect_file_changes(app_root, expected_hashes)
    
    if changes:
        # Log each detected change
        for change in changes:
            path = change.get('path', 'unknown')
            status = change.get('status', 'unknown')
            severity = change.get('severity', 'medium')
            
            app.logger.warning(f"File integrity violation: {path} ({status})")
            
            # Record security event for high severity changes
            if severity in ('high', 'critical'):
                try:
                    log_security_event(
                        event_type=AuditLog.EVENT_FILE_INTEGRITY,
                        description=f"Critical file modified: {path}",
                        severity='error'
                    )
                except SQLAlchemyError as e:
                    app.logger.error(f"Failed to record file integrity event: {e}")
        
        return False
    
    return True


def calculate_risk_score(security_data: Dict[str, Any]) -> int:
    """
    Calculate security risk score based on collected security data.
    
    Args:
        security_data: Dictionary containing security metrics
        
    Returns:
        int: Risk score on a scale of 1-10
    """
    score = 1  # Start with minimum risk
    
    # Check failed logins
    if security_data['failed_logins_24h'] > 100:
        score += 3
    elif security_data['failed_logins_24h'] > 50:
        score += 2
    elif security_data['failed_logins_24h'] > 20:
        score += 1
    
    # Check account lockouts
    if security_data['account_lockouts_24h'] > 5:
        score += 2
    elif security_data['account_lockouts_24h'] > 0:
        score += 1
    
    # Check suspicious IPs
    if len(security_data['suspicious_ips']) > 10:
        score += 3
    elif len(security_data['suspicious_ips']) > 0:
        score += 1
    
    # Check file integrity
    if not security_data.get('config_integrity', True):
        score += 3
    
    if not security_data.get('file_integrity', True):
        score += 2
    
    return min(score, 10)  # Cap at maximum risk of 10


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
    # Start with a base threat level, incorporating baseline risk if available
    threat_level = 1
    if baseline_risk is not None:
        # The baseline risk (1-10) contributes to the starting threat level
        threat_level = max(1, min(5, baseline_risk // 2))
    
    # Check for login anomalies
    if anomalies.get('login_anomalies'):
        login_data = anomalies['login_anomalies']
        
        # Suspicious IPs
        suspicious_ips = login_data.get('suspicious_ips', [])
        if len(suspicious_ips) > 10:
            threat_level += 3
        elif len(suspicious_ips) > 0:
            threat_level += 1
            
        # Failed attempts
        if login_data.get('brute_force_attempts', []):
            threat_level += 2
            
    # Check for session anomalies
    if anomalies.get('session_anomalies'):
        session_data = anomalies['session_anomalies']
        
        # IP changes
        if session_data.get('ip_changes', []):
            threat_level += 2
            
        # Concurrent sessions
        if session_data.get('concurrent_sessions', []):
            threat_level += 1
    
    # Check for API anomalies
    if anomalies.get('api_anomalies'):
        api_data = anomalies['api_anomalies']
        
        # Rate limit violations
        if api_data.get('rate_limit_violations', []):
            threat_level += 1
            
        # Unauthorized attempts
        if api_data.get('unauthorized_attempts', []):
            threat_level += 2
    
    # Check for database anomalies
    if anomalies.get('database_anomalies'):
        db_data = anomalies['database_anomalies']
        
        # Sensitive table access
        if db_data.get('sensitive_tables', []):
            threat_level += 3
            
        # Injection attempts
        if db_data.get('injection_attempts', []):
            threat_level += 3
    
    # Check for file access anomalies
    if anomalies.get('file_access_anomalies'):
        file_data = anomalies['file_access_anomalies']
        
        # Config file accessed
        if file_data.get('config_access', []):
            threat_level += 2
            
        # Critical file modified
        if not file_data.get('config_integrity', True):
            threat_level += 2
            
        if not file_data.get('file_integrity', True):
            threat_level += 3
    
    # Cap the threat level at 10
    return min(threat_level, 10)


def get_security_metrics(hours: int = 24) -> Dict[str, Any]:
    """
    Collect comprehensive security metrics.
    
    Args:
        hours: Number of hours to look back for metrics
        
    Returns:
        Dict[str, Any]: Dictionary of security metrics
    """
    from models.security_incident import SecurityIncident
    
    security_data = {
        'failed_logins_24h': get_failed_login_count(hours=hours),
        'account_lockouts_24h': get_account_lockout_count(hours=hours),
        'active_sessions': get_active_session_count(),
        'suspicious_ips': get_suspicious_ips(hours=hours),
        'config_integrity': check_config_integrity(),
        'file_integrity': check_critical_file_integrity(),
        'incidents_active': SecurityIncident.query.filter(
            SecurityIncident.status.in_(['open', 'investigating'])
        ).count()
    }
    
    # Calculate risk score (1-10)
    security_data['risk_score'] = calculate_risk_score(security_data)
    security_data['last_checked'] = datetime.utcnow().isoformat()
    
    return security_data


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
        from cryptography.fernet import Fernet
        from flask import current_app
        import base64
        
        # Get the encryption key from app config, or generate one if not provided
        key = current_app.config.get('ENCRYPTION_KEY')
        if not key:
            current_app.logger.warning("No ENCRYPTION_KEY configured, using app secret key")
            # Derive a 32-byte key from the app secret key using SHA-256
            import hashlib
            key = hashlib.sha256(current_app.config['SECRET_KEY'].encode()).digest()
        elif len(key) != 32:
            # Ensure key is 32 bytes (256 bits)
            key = hashlib.sha256(key.encode()).digest()
            
        # Convert the key to a URL-safe base64-encoded string as required by Fernet
        key_b64 = base64.urlsafe_b64encode(key)
        
        # Initialize the Fernet cipher with the key
        cipher = Fernet(key_b64)
        
        # Encrypt the plaintext and encode as a string
        encrypted_data = cipher.encrypt(plaintext.encode('utf-8'))
        return encrypted_data.decode('utf-8')
        
    except Exception as e:
        if has_request_context() and hasattr(current_app, 'logger'):
            current_app.logger.error(f"Encryption failed: {e}")
        else:
            logging.error(f"Encryption failed: {e}")
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
    
    import logging
        
    try:
        from cryptography.fernet import Fernet, InvalidToken
        from flask import current_app, has_app_context
        import base64
        import hashlib
        
        # Get the encryption key from app config
        key = None
        if has_app_context():
            key = current_app.config.get('ENCRYPTION_KEY')
            
        if not key:
            if has_app_context():
                current_app.logger.warning("No ENCRYPTION_KEY configured, using app secret key")
                key = hashlib.sha256(current_app.config['SECRET_KEY'].encode()).digest()
            else:
                logging.warning("No app context and no encryption key provided")
                raise RuntimeError("Cannot decrypt: No encryption key available")
        elif len(key) != 32:
            # Ensure key is 32 bytes (256 bits)
            key = hashlib.sha256(key.encode()).digest()
        
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
            if has_app_context():
                current_app.logger.error(msg)
            else:
                logging.error(msg)
            raise RuntimeError(msg)
            
    except Exception as e:
        msg = f"Failed to decrypt sensitive data: {e}"
        from flask import has_app_context, current_app
        if has_app_context() and hasattr(current_app, 'logger'):
            current_app.logger.error(msg)
        else:
            logging.error(msg)
        raise RuntimeError(msg)