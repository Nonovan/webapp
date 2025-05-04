"""
Security utilities for the Cloud Infrastructure Platform.

This module provides security-related functionality including:
- File integrity verification and monitoring
- Access control and authentication
- Encryption and decryption of sensitive data
- Security event logging
- Anomaly detection and threat assessment
- Security metrics and reporting
- Security configuration management
- Baseline security management
- Circuit breakers for failure resilience
- Rate limiting for resource protection
"""

# Version information - increment for significant changes
__version__ = '0.1.1'

# Standard imports
import logging
from typing import Dict, Any, List, Optional, Union, Tuple, Callable

# Initialize module logger
logger = logging.getLogger(__name__)

# Import and expose key functions for backward compatibility
from .cs_audit import (
    log_security_event,
    log_model_event,
    log_error,
    log_warning,
    log_info,
    log_debug,
    detect_security_anomalies,
    get_recent_security_events,
    get_security_event_counts,
    get_critical_security_events,
    process_fallback_logs,
    get_critical_event_categories,
    initialize_audit_logging,

    # Add the new function and its aliases
    log_security_event_as_audit_log,
    log_audit_event,
    audit_log
)

from .cs_authentication import (
    is_valid_ip,
    verify_token,
    validate_password_strength,
    generate_secure_token,
    regenerate_session,
    invalidate_user_sessions,
    validate_url,
    is_safe_redirect_url,
    require_mfa
)

from .cs_authorization import (
    require_permission,
    can_access_ui_element,
    role_required,
    api_key_required,
    rate_limit,
    verify_permission
)

from .cs_crypto import (
    encrypt_sensitive_data,
    decrypt_sensitive_data,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    sanitize_url,
    sanitize_username,
    generate_secure_hash,
    generate_random_token,
    generate_hmac_token,
    verify_hmac_token,
    hash_password,
    verify_password_hash,
    generate_secure_password,
    compute_hash,
    generate_sri_hash
)

from .cs_file_integrity import (
    check_file_integrity,
    check_config_integrity,
    check_critical_file_integrity,
    verify_file_signature,
    create_file_hash_baseline,
    initialize_file_monitoring,
    get_last_integrity_status,
    update_file_integrity_baseline,
    verify_baseline_update,
    format_timestamp,
    detect_file_changes,
    _detect_file_changes,
    _check_for_permission_changes,
    _check_additional_critical_files,
    _consider_baseline_update,
    get_critical_file_hashes,
    log_file_integrity_event
)

from .cs_monitoring import (
    get_suspicious_ips,
    get_failed_login_count,
    get_account_lockout_count,
    get_active_session_count,
    is_suspicious_ip,
    block_ip,
    check_ip_blocked,
    unblock_ip,
    get_blocked_ips,
    detect_permission_issues,
    get_security_anomalies,
    get_threat_summary,
    analyze_location_change,
    detect_suspicious_activity
)

from .cs_session import (
    initialize_secure_session,
    regenerate_session_safely,
    check_session_attacks,
    track_session_anomaly,
    mark_requiring_mfa,
    mark_mfa_verified,
    is_mfa_verified,
    revoke_all_user_sessions,
    revoke_session,
    initialize_session_security
)

from .cs_utils import (
    initialize_security_components,
    validate_security_config,
    get_security_config,
    apply_security_headers,
    register_security_check_handler,
    get_file_integrity_report,
    get_security_status_summary,
    generate_csp_nonce,
    check_security_dependencies,
    sanitize_filename,
    sanitize_path,
    is_within_directory,
    is_safe_file_operation,
    obfuscate_sensitive_data
)

from .cs_constants import (
    SECURITY_CONFIG,
    SENSITIVE_EXTENSIONS,
    FILE_HASH_ALGORITHM,
    REQUEST_ID_PREFIX,
    FILE_INTEGRITY_SEVERITY,
    FILE_INTEGRITY_PRIORITIES,
    SECURITY_EVENT_SEVERITIES,
    MONITORED_FILES_BY_PRIORITY,
    INTEGRITY_MONITORED_SERVICES
)

# Track initialization status
INITIALIZED = False

def init_security():
    """
    Initialize security components.

    This function initializes various security components including:
    - Cryptographic components
    - File integrity monitoring
    - Session security
    - Security metrics

    It should be called during application startup to ensure all security
    systems are properly initialized.
    """
    global INITIALIZED
    if INITIALIZED:
        return

    try:
        # Initialize crypto components
        from .cs_crypto import initialize_crypto
        initialize_crypto()

        # Initialize file integrity baseline if needed
        from .cs_file_integrity import initialize_file_monitoring

        # Log successful initialization
        logger.info("Security package initialized successfully")
        INITIALIZED = True
    except Exception as e:
        logger.error(f"Failed to initialize security package: {e}")


def validate_request_security(request=None):
    """
    Validate security aspects of the current request.

    This function checks various security aspects of a request, including:
    - CSRF protection
    - Content security
    - Input validation
    - Rate limiting
    - IP reputation

    Args:
        request: The Flask request object to validate. If None, uses current request.

    Returns:
        tuple: (is_valid, reason) where is_valid is a boolean indicating if the request
               is secure, and reason is a string explanation if not valid
    """
    from flask import request as flask_request, has_request_context

    if not has_request_context():
        return False, "No request context"

    req = request if request is not None else flask_request

    # Check for suspicious activity
    is_suspicious, activity_type, details = detect_suspicious_activity(req)
    if is_suspicious:
        return False, f"Suspicious activity detected: {activity_type}"

    # Check for proper security headers
    if req.method == "POST" and not req.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # CSRF check for non-AJAX POST requests
        if not req.headers.get('X-CSRF-Token'):
            return False, "Missing CSRF token"

    return True, "Request is valid"

# Initialize automatically when imported
init_security()

# Package exports definition
__all__ = [
    # Version and constants
    '__version__',
    'SECURITY_CONFIG',
    'SENSITIVE_EXTENSIONS',
    'FILE_HASH_ALGORITHM',
    'REQUEST_ID_PREFIX',
    'FILE_INTEGRITY_SEVERITY',
    'FILE_INTEGRITY_PRIORITIES',
    'SECURITY_EVENT_SEVERITIES',
    'MONITORED_FILES_BY_PRIORITY',
    'INTEGRITY_MONITORED_SERVICES',

    # Circuit breaker components
    'CircuitBreaker',
    'CircuitBreakerState',
    'CircuitOpenError',
    'RateLimiter',
    'RateLimitExceededError',

    # Audit functions
    'log_security_event',
    'log_model_event',
    'log_error',
    'log_warning',
    'log_info',
    'log_debug',
    'detect_security_anomalies',
    'get_recent_security_events',
    'get_security_event_counts',
    'get_critical_security_events',
    'process_fallback_logs',
    'get_critical_event_categories',
    'initialize_audit_logging',
    'log_security_event_as_audit_log',
    'log_audit_event',
    'audit_log',

    # Authentication functions
    'is_valid_ip',
    'verify_token',
    'validate_password_strength',
    'generate_secure_token',
    'regenerate_session',
    'invalidate_user_sessions',
    'validate_url',
    'is_safe_redirect_url',

    # Authorization functions
    'require_permission',
    'require_mfa',
    'can_access_ui_element',
    'role_required',
    'api_key_required',
    'rate_limit',
    'verify_permission',

    # Crypto functions
    'encrypt_sensitive_data',
    'decrypt_sensitive_data',
    'encrypt_aes_gcm',
    'decrypt_aes_gcm',
    'sanitize_url',
    'sanitize_username',
    'sanitize_filename',
    'generate_secure_hash',
    'generate_random_token',
    'generate_hmac_token',
    'verify_hmac_token',
    'hash_password',
    'verify_password_hash',
    'generate_secure_password',
    'compute_hash',
    'generate_sri_hash',

    # File integrity functions
    'check_file_integrity',
    'check_config_integrity',
    'check_critical_file_integrity',
    'verify_file_signature',
    'create_file_hash_baseline',
    'initialize_file_monitoring',
    'get_last_integrity_status',
    'update_file_integrity_baseline',
    'verify_baseline_update',
    'get_critical_file_hashes',
    'format_timestamp',
    'detect_file_changes',
    '_detect_file_changes',
    '_check_for_permission_changes',
    '_check_additional_critical_files',
    '_consider_baseline_update',

    # Metrics functions
    'get_security_metrics',
    'calculate_risk_score',
    'generate_security_recommendations',
    'get_risk_trend',
    'get_threat_intelligence_summary',
    'update_daily_risk_score',
    'get_ip_geolocation',
    'setup_security_metrics',
    'setup_auth_metrics',

    # Monitoring functions
    'get_suspicious_ips',
    'get_failed_login_count',
    'get_account_lockout_count',
    'get_active_session_count',
    'is_suspicious_ip',
    'block_ip',
    'check_ip_blocked',
    'unblock_ip',
    'get_blocked_ips',
    'detect_permission_issues',
    'get_security_anomalies',
    'get_threat_summary',
    'analyze_location_change',
    'detect_suspicious_activity',

    # Session functions
    'initialize_secure_session',
    'regenerate_session_safely',
    'check_session_attacks',
    'track_session_anomaly',
    'mark_requiring_mfa',
    'mark_mfa_verified',
    'is_mfa_verified',
    'revoke_all_user_sessions',
    'revoke_session',
    'initialize_session_security',

    # Security utility functions
    'initialize_security_components',
    'validate_security_config',
    'get_security_config',
    'apply_security_headers',
    'register_security_check_handler',
    'get_file_integrity_report',
    'get_security_status_summary',
    'generate_csp_nonce',
    'check_security_dependencies',
    'obfuscate_sensitive_data',
    'sanitize_path',
    'is_within_directory',
    'is_safe_file_operation',
    'log_file_integrity_event',
    'validate_request_security',
    'init_security'
]
