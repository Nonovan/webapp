"""
Security constants and configuration for Cloud Infrastructure Platform.

This module centralizes security configuration parameters used by various
security components of the platform, including encryption settings, token
management, password policies, account security, monitoring thresholds,
and file integrity settings.
"""

import os
from typing import Dict, Any, List

# Security configuration settings
SECURITY_CONFIG: Dict[str, Any] = {
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
    'PASSWORD_COMPLEXITY_REQUIRED': True,  # Require complex passwords with mixed characters

    # Account security
    'MAX_LOGIN_ATTEMPTS': 5,  # Maximum failed login attempts before lockout
    'LOCKOUT_DURATION': 30 * 60,  # Account lockout duration in seconds (30 minutes)
    'SESSION_TIMEOUT': 30 * 60,  # Session timeout in seconds (30 minutes)
    'REQUIRE_MFA_FOR_SENSITIVE': True,  # Require MFA for sensitive operations
    'MFA_TIMEOUT': 24 * 3600,  # Time before requiring MFA re-verification (24 hours)

    # Monitoring settings
    'SUSPICIOUS_IP_THRESHOLD': 5,  # Failed attempts threshold for suspicious IP
    'SECURITY_ALERT_THRESHOLD': 7,  # Risk score threshold for security alerts
    'EVENT_CORRELATION_WINDOW': 300,  # Window for correlating events (5 minutes)
    'AUDIT_LOG_RETENTION_DAYS': 180,  # Number of days to retain audit logs

    # Network security
    'KNOWN_MALICIOUS_NETWORKS': [
        '185.159.128.0/18',  # Example - known botnet range
        '192.42.116.0/22',   # Example - known attack source
    ],
    'IP_BLOCK_DURATION': 24 * 3600,  # Block suspicious IPs for 24 hours by default

    # File integrity
    'FILE_HASH_ALGORITHM': 'sha256',  # Default hash algorithm for file integrity
    'FILE_CHECK_INTERVAL': 3600,  # File check interval in seconds (1 hour)
    'CRITICAL_FILES_PATTERN': [
        'config/*.ini',
        'config/*.json',
        'config/*.yaml',
        'core/security/*.py',
        'deployment/security/*'
    ],

    # API security
    'API_RATE_LIMIT': 100,  # Default rate limit for API endpoints (requests per minute)
    'API_RATE_LIMIT_WINDOW': 60,  # Window for rate limiting (in seconds)
    'JWT_ALGORITHM': 'HS256',  # Algorithm used for JWT tokens

    # HTTP security headers
    'SECURITY_HEADERS': {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'",
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    },

    # Session security
    'BIND_SESSION_TO_IP': True,  # Bind sessions to IP addresses
    'USE_SESSION_FINGERPRINTING': True,  # Use browser fingerprinting for session security
    'SIGN_SESSION_DATA': True,  # Sign session data to prevent tampering
    'STRICT_SESSION_SECURITY': False,  # Enforce strict session security (rejects sessions that don't match all criteria)

    # File upload security
    'MAX_FILENAME_LENGTH': 255,  # Maximum allowed filename length
    'ALLOWED_UPLOAD_EXTENSIONS': ['.jpg', '.jpeg', '.png', '.pdf', '.txt', '.csv', '.xlsx'],  # Safe file extensions
}

# Export individual constants for easier access in other modules
ENCRYPTION_KEY = SECURITY_CONFIG.get('ENCRYPTION_KEY')
FILE_HASH_ALGORITHM = SECURITY_CONFIG.get('FILE_HASH_ALGORITHM')
MAX_LOGIN_ATTEMPTS = SECURITY_CONFIG.get('MAX_LOGIN_ATTEMPTS')
