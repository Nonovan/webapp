"""
Security constants and configuration for Cloud Infrastructure Platform.

This module centralizes security configuration parameters used by various
security components of the platform, including encryption settings, token
management, password policies, account security, monitoring thresholds,
and file integrity settings.
"""

import os
from typing import Dict, Any, List, Optional, Set, FrozenSet

# Security configuration settings
SECURITY_CONFIG: Dict[str, Any] = {
    # Encryption settings
    'ENCRYPTION_KEY': os.getenv('ENCRYPTION_KEY'),  # A strong random 32-byte key for encrypting sensitive data
    'ENCRYPTION_SALT': os.getenv('ENCRYPTION_SALT', b'cloud-infrastructure-platform-salt'),
    'DEFAULT_KEY_ITERATIONS': 100000,  # PBKDF2 iterations for key derivation
    'ENCRYPTION_ALGORITHM': 'AES-256-GCM',  # Default encryption algorithm

    # Token settings
    'TOKEN_EXPIRY': 3600,  # Default token expiry in seconds (1 hour)
    'REFRESH_TOKEN_EXPIRY': 30 * 24 * 3600,  # 30 days
    'RESET_TOKEN_EXPIRY': 3600,  # 1 hour
    'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY'),  # JWT signing key
    'TOKEN_ROTATION_ENABLED': True,  # Enable token rotation for enhanced security

    # Password policy
    'MIN_PASSWORD_LENGTH': 12,  # Minimum password length
    'PASSWORD_HISTORY_SIZE': 5,  # Number of previous passwords to remember
    'PASSWORD_EXPIRY_DAYS': 90,  # Password expiry in days
    'PASSWORD_COMPLEXITY_REQUIRED': True,  # Require complex passwords with mixed characters
    'PASSWORD_BREACH_CHECK': True,  # Check passwords against known breach databases
    'PASSWORD_COMPLEXITY_UPPERCASE': True,  # Require uppercase characters
    'PASSWORD_COMPLEXITY_LOWERCASE': True,  # Require lowercase characters
    'PASSWORD_COMPLEXITY_DIGITS': True,  # Require numeric digits
    'PASSWORD_COMPLEXITY_SPECIAL': True,  # Require special characters

    # Account security
    'MAX_LOGIN_ATTEMPTS': 5,  # Maximum failed login attempts before lockout
    'LOCKOUT_DURATION': 30 * 60,  # Account lockout duration in seconds (30 minutes)
    'SESSION_TIMEOUT': 30 * 60,  # Session timeout in seconds (30 minutes)
    'REQUIRE_MFA_FOR_SENSITIVE': True,  # Require MFA for sensitive operations
    'MFA_TIMEOUT': 24 * 3600,  # Time before requiring MFA re-verification (24 hours)
    'PROGRESSIVE_LOCKOUT': True,  # Enable progressive lockout durations
    'ACCOUNT_RECOVERY_TOKEN_EXPIRY': 15 * 60,  # Account recovery token expiry (15 minutes)

    # Monitoring settings
    'SUSPICIOUS_IP_THRESHOLD': 5,  # Failed attempts threshold for suspicious IP
    'SECURITY_ALERT_THRESHOLD': 7,  # Risk score threshold for security alerts
    'EVENT_CORRELATION_WINDOW': 300,  # Window for correlating events (5 minutes)
    'AUDIT_LOG_RETENTION_DAYS': 180,  # Number of days to retain audit logs
    'MONITORING_ENABLED': True,  # Enable security monitoring
    'SECURITY_METRICS_INTERVAL': 300,  # Metrics collection interval (5 minutes)
    'CRITICAL_EVENTS_RETENTION_DAYS': 90,  # Days to retain critical security events

    # Network security
    'KNOWN_MALICIOUS_NETWORKS': [
        '185.159.128.0/18',  # Example - known botnet range
        '192.42.116.0/22',   # Example - known attack source
    ],
    'IP_BLOCK_DURATION': 24 * 3600,  # Block suspicious IPs for 24 hours by default
    'GEO_BLOCKING_ENABLED': False,  # Enable geographic IP blocking
    'ALLOWED_COUNTRIES': [],  # List of allowed country codes when geo-blocking is enabled
    'DENIED_COUNTRIES': [],  # List of denied country codes

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
    'ENABLE_FILE_INTEGRITY_MONITORING': True,  # Enable file integrity monitoring
    'AUTO_UPDATE_BASELINE': False,  # Whether to auto-update baseline for non-critical changes
    'BASELINE_UPDATE_MAX_AGE': 86400,  # Maximum age (seconds) of files eligible for auto-update
    'FILE_INTEGRITY_VERIFY_PERMISSIONS': True,  # Check file permissions during integrity checks
    'FILE_SIGNATURE_VERIFICATION': True,  # Enable digital signature verification
    'HIGH_SENSITIVITY_PATTERNS': [  # Files requiring extra vigilance
        'core/security/*',
        'core/auth.py',
        'models/security/*',
        'deployment/security/scripts/*'
    ],
    'IGNORE_PATTERN': [  # Paths to ignore in file integrity checks
        '*.pyc',
        '*.pyo',
        '__pycache__/*',
        'logs/*',
        'tmp/*'
    ],
    'SECURITY_EVENT_ON_CRITICAL_CHANGE': True,  # Log security event on critical file change
    'FILE_INTEGRITY_CHECK_FREQUENCY': 100,  # Check file integrity every N requests
    'MAX_BASELINE_FILE_SIZE': 10 * 1024 * 1024,  # Maximum file size for baseline inclusion (10MB)
    'MALICIOUS_CONTENT_PATTERNS': [  # Patterns that could indicate malicious content
        r'eval\(\$_POST',
        r'passthru\(',
        r'shell_exec\(',
        r'base64_decode\(.+\)',
        r'preg_replace\(.+/e'
    ],
    'SAFE_BASELINE_UPDATE_PATH': 'instance/security/baseline',  # Default path for storing baselines

    # API security
    'API_RATE_LIMIT': 100,  # Default rate limit for API endpoints (requests per minute)
    'API_RATE_LIMIT_WINDOW': 60,  # Window for rate limiting (in seconds)
    'JWT_ALGORITHM': 'HS256',  # Algorithm used for JWT tokens
    'API_KEY_EXPIRY': 90,  # Days until API keys expire
    'API_KEY_LENGTH': 64,  # Length of generated API keys
    'CORS_MAX_AGE': 600,  # Max age for CORS preflight requests (10 minutes)
    'API_REQUIRE_TLS': True,  # Require TLS for all API requests
    'STRICT_URL_VALIDATION': True,  # Enable strict URL validation

    # HTTP security headers
    'SECURITY_HEADERS': {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'",
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), camera=(), microphone=()'
    },
    'SECURE_COOKIES': True,  # Use secure cookies

    # Session security
    'BIND_SESSION_TO_IP': True,  # Bind sessions to IP addresses
    'USE_SESSION_FINGERPRINTING': True,  # Use browser fingerprinting for session security
    'SIGN_SESSION_DATA': True,  # Sign session data to prevent tampering
    'STRICT_SESSION_SECURITY': False,  # Enforce strict session security (rejects sessions that don't match all criteria)
    'SESSION_GRACE_PERIOD': 60,  # Grace period (seconds) for IP changes in sessions
    'MAX_CONCURRENT_SESSIONS': 3,  # Maximum concurrent sessions per user
    'SESSION_ID_LENGTH': 64,  # Length of generated session IDs
    'SESSION_ENTROPY_BITS': 256,  # Entropy bits for session token generation

    # File upload security
    'MAX_FILENAME_LENGTH': 255,  # Maximum allowed filename length
    'ALLOWED_UPLOAD_EXTENSIONS': ['.jpg', '.jpeg', '.png', '.pdf', '.txt', '.csv', '.xlsx'],  # Safe file extensions
    'MAX_UPLOAD_SIZE': 10 * 1024 * 1024,  # Maximum upload size (10MB)
    'SCAN_UPLOADS': True,  # Scan uploads for malware
    'SANITIZE_FILENAMES': True,  # Sanitize uploaded filenames
    'VALIDATE_FILE_TYPES': True,  # Validate file content matches declared type
    'STRIP_FILE_METADATA': True,  # Remove metadata from uploaded files (EXIF, etc.)

    # Threat intelligence
    'THREAT_INTEL_ENABLED': True,  # Enable threat intelligence integration
    'THREAT_INTEL_UPDATE_INTERVAL': 86400,  # Interval for updating threat data (24 hours)
    'THREAT_INTEL_SOURCES': ['internal'],  # Sources for threat intelligence
    'THREAT_MATCH_THRESHOLD': 0.8,  # Threshold for threat matching (0.0-1.0)

    # Emergency response
    'EMERGENCY_CONTACT': 'security@example.com',  # Emergency contact for critical issues
    'EMERGENCY_MODE_ENABLED': False,  # Emergency mode with stricter security controls
    'EMERGENCY_IP_ALLOWLIST': [],  # IPs allowed during emergency mode
    'BREAK_GLASS_ENABLED': True,  # Enable break-glass emergency access
    'BREAK_GLASS_EXPIRY': 4 * 3600,  # Break-glass access expires after 4 hours

    # Request tracking and monitoring
    'REQUEST_ID_LENGTH': 16,  # Length of generated request IDs
    'REQUEST_ID_PREFIX': 'req-',  # Prefix for request IDs
    'REQUEST_ID_INCLUDE_TIMESTAMP': True,  # Include timestamp in request IDs
    'REQUEST_ID_INCLUDE_HOST': True,  # Include host in request IDs
    'REQUEST_ID_INCLUDE_PID': True,  # Include process ID in request IDs
    'TRACK_SLOW_REQUESTS': True,  # Track slow requests
    'SLOW_REQUEST_THRESHOLD': 2.0,  # Threshold for slow requests in seconds
    'MAX_CONTENT_LENGTH': 10 * 1024 * 1024,  # Max content length for requests (10MB)

    # Circuit breaker settings
    'CIRCUIT_BREAKER_ENABLED': True,  # Enable circuit breaker pattern
    'CIRCUIT_BREAKER_THRESHOLD': 5,  # Number of failures before opening circuit
    'CIRCUIT_BREAKER_TIMEOUT': 30,  # Time (seconds) before retrying after circuit opens
    'CIRCUIT_BREAKER_HALF_OPEN_RATIO': 0.1,  # Ratio of requests to let through when half-open
}

# Export individual constants for easier access in other modules
ENCRYPTION_KEY = SECURITY_CONFIG.get('ENCRYPTION_KEY')
FILE_HASH_ALGORITHM = SECURITY_CONFIG.get('FILE_HASH_ALGORITHM')
MAX_LOGIN_ATTEMPTS = SECURITY_CONFIG.get('MAX_LOGIN_ATTEMPTS')
REQUEST_ID_PREFIX = SECURITY_CONFIG.get('REQUEST_ID_PREFIX')

#-------------------------------------------------------------------------
# VALIDATION CONSTANTS - Shared with cs_validation.py
#-------------------------------------------------------------------------

# Security-sensitive fields for automatic redaction in logs
SENSITIVE_FIELDS: FrozenSet[str] = frozenset({
    'password', 'token', 'secret', 'key', 'auth', 'cred', 'private',
    'cookie', 'session', 'hash', 'sign', 'certificate', 'salt', 'api_key',
    'access_token', 'refresh_token', 'id_token', 'csrf', 'ssn', 'account'
})

# Path validation
DEFAULT_RESTRICTED_PATHS: List[str] = [
    '/etc/shadow', '/etc/passwd', '/etc/sudoers',
    '/etc/ssl/private', '/root', '/var/lib/secrets',
    '/boot', '/proc', '/sys', '/run', '/dev'
]

# Path traversal patterns
PATH_TRAVERSAL_PATTERNS: List[str] = [
    r'\.\.',        # Directory traversal
    r'~/',          # Home directory expansion
    r'\$\{.*\}',    # Variable expansion
    r'/%00',        # Null byte injection
    r'/\./',        # Hidden directory access
]

# Regular expression patterns for common validations
HOSTNAME_PATTERN = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
IP_ADDRESS_PATTERN = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
UUID_PATTERN = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
SAFE_FILENAME_PATTERN = r'^[a-zA-Z0-9][a-zA-Z0-9\._\-]+$'

# Common security constants
MIN_PASSWORD_LENGTH = 12
ALLOWED_JWT_ALGORITHMS = ['HS256', 'RS256', 'ES256']
UNSAFE_URL_SCHEMES = ['javascript', 'data', 'vbscript', 'file']

# File upload security
ALLOWED_FILE_EXTENSIONS: FrozenSet[str] = frozenset([
    '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt', '.csv', '.xlsx',
    '.docx', '.pptx', '.md', '.json', '.xml', '.html', '.css', '.js'
])

DANGEROUS_FILE_EXTENSIONS: FrozenSet[str] = frozenset([
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.sh', '.py', '.php',
    '.jar', '.vbs', '.msi', '.app', '.dmg', '.deb', '.rpm',
    '.apk', '.bin', '.pl', '.scr', '.so'
])

# Default security events severity mapping
SECURITY_EVENT_SEVERITIES: Dict[str, str] = {
    'authentication_success': 'info',
    'authentication_failure': 'warning',
    'authorization_failure': 'warning',
    'admin_action': 'info',
    'configuration_change': 'info',
    'password_change': 'info',
    'sensitive_data_access': 'warning',
    'mfa_required': 'info',
    'mfa_enabled': 'info',
    'mfa_disabled': 'warning',
    'account_locked': 'warning',
    'session_expired': 'info',
    'session_regenerated': 'info',
    'ip_blocked': 'warning',
    'api_key_created': 'info',
    'api_key_revoked': 'info',
    'file_integrity_violation': 'error',
    'system_configuration_change': 'info',
    'security_baseline_violation': 'error',
    'suspicious_activity': 'warning',
    'account_lockout': 'warning',
    'emergency_access': 'critical',
    'permission_change': 'info',
    'system_startup': 'info',
    'system_shutdown': 'info',
    'baseline_updated': 'info',
    'baseline_update_failed': 'warning',
    'unsafe_url_blocked': 'warning',
    'circuit_breaker_open': 'warning',
    'path_traversal_attempt': 'error',
    'security_validation_failure': 'warning'
}

# Map of services requiring integrity monitoring
INTEGRITY_MONITORED_SERVICES: Dict[str, List[str]] = {
    'web': ['app.py', 'wsgi.py', 'core/security/*.py', 'core/middleware.py'],
    'api': ['api/*', 'core/security/*.py'],
    'worker': ['worker.py', 'tasks/*', 'core/security/*.py'],
    'config': ['config/*', 'core/config.py', 'settings.py'],
    'security': ['core/security/*', 'models/security/*', 'blueprints/admin/*'],
    'database': ['models/*.py', 'migrations/*']
}

# File integrity severity classifications
FILE_INTEGRITY_SEVERITY: Dict[str, str] = {
    'missing': 'high',
    'modified': 'high',
    'world_writable': 'high',
    'world_writable_sensitive': 'critical',
    'world_executable': 'medium',
    'new_critical_file': 'medium',
    'signature_invalid': 'high',
    'recent_change': 'medium',
    'permission_changed': 'medium',
    'suspicious_content': 'high',
    'invalid_ownership': 'high',
    'unexpected_execution_bit': 'high',
    'timestamp_manipulation': 'high'
}

# File integrity monitoring priorities
FILE_INTEGRITY_PRIORITIES: Dict[str, int] = {
    'critical': 1,    # Security-critical system files
    'high': 2,        # Important application files
    'medium': 3,      # General application files
    'low': 4,         # Non-essential files
    'informational': 5 # Files that only generate informational events
}

# File extensions considered sensitive from a security perspective
SENSITIVE_EXTENSIONS: List[str] = [
    '.key', '.pem', '.p12', '.pfx', '.keystore', '.jks', '.env', '.secret',
    '.cer', '.crt', '.der', '.p7b', '.p7c', '.pkcs12', '.pfx', '.rsa',
    '.passwd', '.password', '.credentials', '.creds', '.id_rsa', '.id_dsa'
]

# Monitored file patterns by priority
MONITORED_FILES_BY_PRIORITY: Dict[str, List[str]] = {
    'critical': [
        'core/security/*.py',
        'core/middleware.py',
        'core/auth.py',
        'models/security/*.py',
        'config/security.ini',
        'app.py',
        'wsgi.py',
        'config/security/*.py',
        'deployment/security/*.sh'
    ],
    'high': [
        'api/*.py',
        'models/*.py',
        'core/*.py',
        'config/*.ini',
        'config/*.json',
        'config/*.yaml',
        'blueprints/admin/*.py',
        'services/security/*.py'
    ],
    'medium': [
        'blueprints/*.py',
        'services/*.py',
        'templates/*.html',
        'static/js/*.js',
        'core/utils/*.py',
        'docs/security/*.md'
    ],
    'low': [
        'static/css/*.css',
        'static/img/*',
        'docs/*',
        'tests/unit/*.py',
        'README.md'
    ]
}

# Testing related constants
class TestType:
    SECURITY = 'security'
    PERFORMANCE = 'performance'
    COMPLIANCE = 'compliance'
    FUNCTIONAL = 'functional'
    INTEGRATION = 'integration'

class AuthTestType:
    LOGIN = 'login'
    LOGOUT = 'logout'
    REGISTER = 'register'
    RESET_PASSWORD = 'reset_password'
    MFA = 'mfa'
    SESSION = 'session'
    TOKEN = 'token'

class AccessControlTestType:
    RBAC = 'rbac'
    PERMISSION = 'permission'
    RESOURCE_ACCESS = 'resource_access'
    OWNER_CHECK = 'owner_check'

class APISecurityTestType:
    RATE_LIMIT = 'rate_limit'
    INPUT_VALIDATION = 'input_validation'
    AUTH_TOKEN = 'auth_token'
    PARAMETER_TAMPERING = 'parameter_tampering'

class HeaderTestType:
    CSP = 'content_security_policy'
    HSTS = 'strict_transport_security'
    XFRAME = 'x_frame_options'
    XSS_PROTECTION = 'xss_protection'

class VerificationType:
    HASH = 'hash'
    SIGNATURE = 'signature'
    CHECKSUM = 'checksum'
    DIGITAL_SIGNATURE = 'digital_signature'
    HMAC = 'hmac'
