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
from .cs_metrics import get_security_metrics
from core.utils import (
    detect_file_changes, calculate_file_hash, format_timestamp,
    log_critical, log_error, log_warning, log_info, log_debug
)

# Type definitions
T = TypeVar('T')

# Set up module-level logger
logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security')

# Security configuration encryption settings
SECURITY_CONFIG = {
    'ENCRYPTION_KEY': os.getenv('ENCRYPTION_KEY'),  # A strong random 32-byte key for encrypting sensitive data
    'ENCRYPTION_SALT': os.getenv('ENCRYPTION_SALT', b'cloud-infrastructure-platform-salt'),
    'DEFAULT_KEY_ITERATIONS': 100000,  # PBKDF2 iterations for key derivation
    'TOKEN_EXPIRY': 3600,  # Default token expiry in seconds (1 hour)
    'REFRESH_TOKEN_EXPIRY': 30 * 24 * 3600,  # 30 days
    'RESET_TOKEN_EXPIRY': 3600,  # 1 hour
    'MIN_PASSWORD_LENGTH': 12,  # Minimum password length
    'PASSWORD_HISTORY_SIZE': 5,  # Number of previous passwords to remember
    'PASSWORD_EXPIRY_DAYS': 90,  # Password expiry in days
    'MAX_LOGIN_ATTEMPTS': 5,  # Maximum failed login attempts before lockout
    'LOCKOUT_DURATION': 30 * 60,  # Account lockout duration in seconds (30 minutes)
    'SESSION_TIMEOUT': 30 * 60,  # Session timeout in seconds (30 minutes)
    'REQUIRE_MFA_FOR_SENSITIVE': True,  # Require MFA for sensitive operations
    'SUSPICIOUS_IP_THRESHOLD': 5,  # Failed attempts threshold for suspicious IP
    'SECURITY_ALERT_THRESHOLD': 7,  # Risk score threshold for security alerts
    'EVENT_CORRELATION_WINDOW': 300,  # Window for correlating events (5 minutes)
    'KNOWN_MALICIOUS_NETWORKS': [
        '185.159.128.0/18',  # Example - known botnet range
        '192.42.116.0/22',   # Example - known attack source
    ],
    'FILE_HASH_ALGORITHM': 'sha256',  # Default hash algorithm for file integrity
    'FILE_CHECK_INTERVAL': 3600,  # File check interval in seconds (1 hour)

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


def initialize_security_components():
    """
    Initialize security components and settings.

    This function is called during application startup to set up security
    components, validate configuration, and ensure all security settings
    are properly initialized.
    """
    if not has_app_context():
        log_warning("Cannot initialize security components outside application context")
        return

    # Log initialization
    log_info("Initializing security components")

    # Verify security-critical configuration
    _verify_security_configuration()

    # Initialize file integrity monitoring
    _initialize_file_integrity_monitoring()

    # Set up security metrics tracking
    _initialize_security_metrics()

    log_info("Security components initialized successfully")


def _verify_security_configuration():
    """
    Verify that security-critical configuration settings are properly set.
    """
    if not has_app_context():
        return

    # Create a list of warnings for potentially insecure settings
    warnings = []

    # Check security headers
    if not current_app.config.get('SECURITY_HEADERS_ENABLED', True):
        warnings.append("Security headers are disabled")

    # Check for session security settings
    if not current_app.config.get('SESSION_COOKIE_SECURE', True):
        warnings.append("Session cookies are not secure (SESSION_COOKIE_SECURE=False)")

    if not current_app.config.get('SESSION_COOKIE_HTTPONLY', True):
        warnings.append("Session cookies are not HTTP-only (SESSION_COOKIE_HTTPONLY=False)")

    if current_app.config.get('SESSION_COOKIE_SAMESITE', 'Lax') == 'None':
        warnings.append("Session cookies have SameSite=None which may expose them to CSRF attacks")

    # Check for weak password settings
    min_password_length = current_app.config.get('PASSWORD_MIN_LENGTH', 12)
    if min_password_length < 12:
        warnings.append(f"Minimum password length ({min_password_length}) is less than recommended (12)")

    # Log all warnings
    if warnings:
        for warning in warnings:
            security_logger.warning(f"Security configuration warning: {warning}")

        # If running in production, these warnings are more serious
        if current_app.config.get('ENVIRONMENT') == 'production':
            security_logger.error(
                "Insecure configuration detected in production environment",
                extra={"warnings": warnings}
            )


def _initialize_file_integrity_monitoring():
    """
    Initialize file integrity monitoring.
    """
    if not has_app_context():
        return

    # Check if file integrity monitoring is enabled
    if not current_app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
        return

    # Get file paths to monitor from configuration
    critical_files = current_app.config.get('SECURITY_CRITICAL_FILES', [])
    if not critical_files:
        return

    # Calculate and store reference hashes
    try:
        from core.utils import get_critical_file_hashes
        hashes = get_critical_file_hashes(critical_files)
        current_app.config['CRITICAL_FILE_HASHES'] = hashes
        log_info(f"Initialized file integrity monitoring for {len(hashes)} files")
    except Exception as e:
        log_error(f"Failed to initialize file integrity monitoring: {e}")


def _initialize_security_metrics():
    """
    Initialize security metrics tracking.
    """
    if not has_app_context():
        return

    # Check if metrics tracking is enabled
    if not current_app.config.get('METRICS_ENABLED', True):
        return

    # Initialize baseline metrics
    try:
        # Register security metrics collectors
        metrics.register_collector('security', get_security_metrics)

        # Initialize gauges with default values
        metrics.gauge('security.risk_score', 1)
        metrics.gauge('security.failed_logins', 0)
        metrics.gauge('security.account_lockouts', 0)
        metrics.gauge('security.active_sessions', 0)
        metrics.gauge('security.suspicious_ips', 0)
        metrics.gauge('security.blocked_ips', 0)

        log_info("Security metrics initialized")
    except Exception as e:
        log_error(f"Failed to initialize security metrics: {e}")
