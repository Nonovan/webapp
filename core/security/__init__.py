"""
Security utilities for the Cloud Infrastructure Platform.

This module provides security-related functionality including:
- File integrity verification
- Access control and authentication
- Encryption and decryption of sensitive data
- Security event logging
- Anomaly detection and threat assessment
"""

# Import and expose key functions for backward compatibility
from .cs_audit import log_security_event
from .cs_authentication import (
    is_valid_ip, verify_token, validate_password_strength,
    generate_secure_token, regenerate_session, invalidate_user_sessions
)
from .cs_authorization import require_permission, require_mfa, can_access_ui_element
from .cs_crypto import (
    encrypt_sensitive_data, decrypt_sensitive_data,
    encrypt_aes_gcm, decrypt_aes_gcm,
    sanitize_url, sanitize_filename
)
from .cs_file_integrity import (
    check_file_integrity, check_config_integrity,
    check_critical_file_integrity, verify_file_signature
)
from .cs_metrics import (
    get_security_metrics, calculate_risk_score,
    generate_security_recommendations
)
from .cs_monitoring import (
    get_suspicious_ips, get_failed_login_count, get_account_lockout_count,
    get_active_session_count, is_suspicious_ip, block_ip, check_ip_blocked,
    unblock_ip, get_blocked_ips, detect_permission_issues
)
from .security_utils import (
    initialize_security_components, SECURITY_CONFIG
)

# Constants available at package level
from .security_utils import SECURITY_CONFIG
