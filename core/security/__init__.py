"""
Security utilities for the Cloud Infrastructure Platform.

This module provides security-related functionality including:
- File integrity verification
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
    _record_in_audit_log
)

from .cs_authentication import (
    is_valid_ip,
    verify_token,
    validate_password_strength,
    generate_secure_token,
    regenerate_session,
    invalidate_user_sessions,
    validate_url,
    is_safe_redirect_url
)

from .cs_authorization import (
    require_permission,
    require_mfa,
    can_access_ui_element,
    role_required,
    api_key_required,
    rate_limit
)

from .cs_crypto import (
    encrypt_sensitive_data,
    decrypt_sensitive_data,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    sanitize_url,
    sanitize_filename,
    sanitize_username,
    generate_secure_hash,
    generate_random_token,
    generate_hmac_token,
    verify_hmac_token,
    hash_password,
    verify_password_hash,
    generate_secure_password,
    compute_hash
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
    format_timestamp
)

from ...models.security.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerState,
    CircuitOpenError,
    RateLimiter,
    RateLimitExceededError
)

from .cs_metrics import (
    get_security_metrics,
    calculate_risk_score,
    generate_security_recommendations,
    get_risk_trend,
    get_threat_intelligence_summary,
    update_daily_risk_score,
    get_ip_geolocation,
    setup_security_metrics,
    setup_auth_metrics
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
    obfuscate_sensitive_data
)

# Constants available at package level
from .cs_constants import SECURITY_CONFIG

# Version information
__version__ = '0.1.1'  # Updated version to reflect circuit breaker and rate limiter additions
