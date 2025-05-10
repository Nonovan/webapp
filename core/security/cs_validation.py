"""
Security validation utilities for Cloud Infrastructure Platform.

This module centralizes all validation functions used across security components,
providing consistent validation logic for:
- Password complexity and strength
- Path security and traversal prevention
- URL and domain validation
- File integrity validation
- Input sanitization
- Configuration validation
- Permission validation
- Baseline integrity validation

These utilities ensure consistent security validation across the platform.
"""

import os
import re
import hashlib
import ipaddress
import logging
import socket
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union, Set, Pattern
from urllib.parse import urlparse

from flask import current_app, has_app_context, request, has_request_context
from .cs_constants import SECURITY_CONFIG
from extensions import metrics

# Initialize logger
logger = logging.getLogger(__name__)

# Constants for validation
DEFAULT_MIN_PASSWORD_LENGTH = 12
DEFAULT_RESTRICTED_PATHS = [
    '/etc/shadow', '/etc/passwd', '/etc/sudoers',
    '/etc/ssl/private', '/root', '/var/lib/secrets'
]
PATH_TRAVERSAL_PATTERNS = [
    r'\.\.',        # Directory traversal
    r'~/',          # Home directory expansion
    r'\$\{.*\}',    # Variable expansion
]

HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
IP_ADDRESS_PATTERN = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)

# Type definitions
ValidationResult = Tuple[bool, List[str]]

#-------------------------------------------------------------------------
# PASSWORD VALIDATION
#-------------------------------------------------------------------------

def validate_password_complexity(password: str) -> bool:
    """
    Validate password complexity requirements.

    Checks if a password meets the required complexity standards:
    - Minimum length (default: 12 characters)
    - Contains uppercase letters
    - Contains lowercase letters
    - Contains numbers
    - Contains special characters
    - No common patterns or sequences

    Args:
        password: The password to validate

    Returns:
        bool: True if the password meets complexity requirements, False otherwise
    """
    if not password:
        logger.warning("Empty password provided for complexity validation")
        return False

    # Get configuration from app config if available, otherwise use defaults
    min_length = DEFAULT_MIN_PASSWORD_LENGTH
    require_uppercase = True
    require_lowercase = True
    require_digits = True
    require_special = True

    if has_app_context():
        min_length = current_app.config.get('PASSWORD_MIN_LENGTH',
                     SECURITY_CONFIG.get('MIN_PASSWORD_LENGTH', DEFAULT_MIN_PASSWORD_LENGTH))
        require_uppercase = current_app.config.get('PASSWORD_REQUIRE_UPPERCASE',
                            SECURITY_CONFIG.get('PASSWORD_COMPLEXITY_UPPERCASE', True))
        require_lowercase = current_app.config.get('PASSWORD_REQUIRE_LOWERCASE',
                            SECURITY_CONFIG.get('PASSWORD_COMPLEXITY_LOWERCASE', True))
        require_digits = current_app.config.get('PASSWORD_REQUIRE_DIGITS',
                         SECURITY_CONFIG.get('PASSWORD_COMPLEXITY_DIGITS', True))
        require_special = current_app.config.get('PASSWORD_REQUIRE_SPECIAL',
                          SECURITY_CONFIG.get('PASSWORD_COMPLEXITY_SPECIAL', True))

    # Check length
    if len(password) < min_length:
        logger.debug("Password complexity validation failed: insufficient length")
        return False

    # Check for required character classes
    if require_uppercase and not any(c.isupper() for c in password):
        logger.debug("Password complexity validation failed: missing uppercase letters")
        return False

    if require_lowercase and not any(c.islower() for c in password):
        logger.debug("Password complexity validation failed: missing lowercase letters")
        return False

    if require_digits and not any(c.isdigit() for c in password):
        logger.debug("Password complexity validation failed: missing digits")
        return False

    if require_special and not any(not c.isalnum() for c in password):
        logger.debug("Password complexity validation failed: missing special characters")
        return False

    # Check for common sequential patterns
    common_sequences = [
        '123456', 'abcdef', 'qwerty', 'password', 'admin', 'welcome',
        '12345', 'abc123', 'letmein'
    ]
    for seq in common_sequences:
        if seq.lower() in password.lower():
            logger.debug("Password complexity validation failed: contains common sequence")
            return False

    # Check for repeating characters (3+ in a row)
    if re.search(r'(.)\1{2,}', password):
        logger.debug("Password complexity validation failed: contains repeating characters")
        return False

    # Check for keyboard patterns (horizontal rows)
    keyboard_patterns = [
        'qwert', 'asdfg', 'zxcvb', 'yuiop', 'hjkl', 'nm,.'
    ]
    for pattern in keyboard_patterns:
        if pattern.lower() in password.lower():
            logger.debug("Password complexity validation failed: contains keyboard pattern")
            return False

    return True


def validate_password_strength(password: str) -> ValidationResult:
    """
    Validate password strength against security requirements.

    This function checks passwords against multiple security criteria including
    length, character types, common patterns, dictionary words, and context-specific
    terms to ensure strong password selection.

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
    sequential_patterns = ['123456', 'abcdef', 'qwerty', 'password', 'admin', '123123']
    if any(pattern in password.lower() for pattern in sequential_patterns):
        failed_requirements.append("Password contains common sequential patterns")

    # Check for repeating characters (3+ in a row)
    if re.search(r'(.)\1{2,}', password):
        failed_requirements.append("Password contains repeating characters")

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
                logger.error(f"Error checking common passwords: {e}")

    # Check for app-specific terms
    if has_app_context():
        app_name = current_app.config.get('APP_NAME', '').lower()
        domain = current_app.config.get('APP_DOMAIN', '').lower()

        if app_name and app_name in password.lower():
            failed_requirements.append("Password contains the application name")

        if domain and domain in password.lower():
            failed_requirements.append("Password contains the domain name")

    is_valid = len(failed_requirements) == 0

    # Track metrics
    if has_app_context() and hasattr(metrics, 'increment'):
        if is_valid:
            metrics.increment('security.password_validation_success')
        else:
            metrics.increment('security.password_validation_failure')

    return is_valid, failed_requirements

#-------------------------------------------------------------------------
# PATH VALIDATION
#-------------------------------------------------------------------------

def validate_path_security(path: str, base_dir: Optional[str] = None, allow_absolute: bool = False) -> bool:
    """
    Validate that a file path meets security requirements.

    Checks for security issues like directory traversal attempts, references to
    sensitive system files, and proper path containment within allowed directories.

    Args:
        path: The file path to validate
        base_dir: Optional base directory to check path is contained within
        allow_absolute: Whether to allow absolute paths

    Returns:
        bool: True if the path is secure, False otherwise
    """
    if not path:
        logger.warning("Empty path provided for security validation")
        return False

    # Check for path traversal attempts
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, path):
            logger.warning(f"Path security validation failed: potential traversal in '{path}'")
            return False

    # Check if path is absolute but not allowed
    if not allow_absolute and (os.path.isabs(path) or path.startswith('/')):
        logger.warning(f"Path security validation failed: absolute path not allowed '{path}'")
        return False

    # Check for additional restricted paths from configuration
    restricted_paths = list(DEFAULT_RESTRICTED_PATHS)
    if has_app_context():
        additional_paths = current_app.config.get('RESTRICTED_PATHS',
                          SECURITY_CONFIG.get('RESTRICTED_PATHS', []))
        restricted_paths.extend(additional_paths)

    # Normalize path for comparison
    try:
        normalized_path = os.path.normpath(path)
        if os.path.isabs(normalized_path):
            for restricted in restricted_paths:
                if normalized_path.startswith(restricted):
                    logger.warning(f"Path security validation failed: restricted path '{path}'")
                    return False
    except Exception as e:
        logger.error(f"Path normalization error: {str(e)}")
        return False

    # If base directory is specified, ensure path stays within it
    if base_dir:
        try:
            # Convert to absolute paths for comparison
            norm_base = os.path.normpath(os.path.abspath(base_dir))

            # Handle relative paths by joining with base_dir
            if not os.path.isabs(path):
                abs_path = os.path.normpath(os.path.join(norm_base, path))
            else:
                abs_path = os.path.normpath(path)

            # Check if the path is within the base directory
            if not abs_path.startswith(norm_base):
                logger.warning(f"Path security validation failed: path escapes base directory '{path}'")
                return False

        except Exception as e:
            logger.error(f"Error validating path containment: {str(e)}")
            return False

    return True


def validate_path(path: str, base_dir: Optional[str] = None, allow_absolute: bool = False) -> bool:
    """
    Validate that a path is safe to use in the system.

    Args:
        path: Path to validate
        base_dir: Optional base directory the path must stay within
        allow_absolute: Whether to allow absolute paths

    Returns:
        bool: True if path is safe, False otherwise
    """
    if not path:
        if has_app_context() and hasattr(metrics, 'increment'):
            metrics.increment('security.path_validation_failure')
        return False

    try:
        # Check for path traversal attempts
        if '..' in path.split('/') or '..' in path.split('\\'):
            logger.warning(f"Path traversal attempt detected: {path}")
            if has_app_context() and hasattr(metrics, 'increment'):
                metrics.increment('security.path_traversal_attempt')
            return False

        # Check for tilde (home directory) expansion
        if '~' in path:
            logger.warning(f"Home directory expansion attempt detected: {path}")
            if has_app_context() and hasattr(metrics, 'increment'):
                metrics.increment('security.path_validation_failure')
            return False

        # Check if path is absolute but not allowed
        if not allow_absolute and (path.startswith('/') or path.startswith('\\')):
            logger.warning(f"Absolute path not allowed: {path}")
            if has_app_context() and hasattr(metrics, 'increment'):
                metrics.increment('security.path_validation_failure')
            return False

        # If base directory is specified, ensure path stays within it
        if base_dir:
            import os
            # Normalize paths for consistent comparison
            norm_base = os.path.normpath(os.path.abspath(base_dir))

            # Handle both absolute and relative paths
            if os.path.isabs(path):
                norm_path = os.path.normpath(path)
            else:
                norm_path = os.path.normpath(os.path.join(norm_base, path))

            # Check if the normalized path starts with the base directory
            if not norm_path.startswith(norm_base):
                logger.warning(f"Path would escape base directory: {path}")
                if has_app_context() and hasattr(metrics, 'increment'):
                    metrics.increment('security.path_validation_failure')
                return False

        # Path validation passed
        if has_app_context() and hasattr(metrics, 'increment'):
            metrics.increment('security.path_validation_success')
        return True

    except Exception as e:
        logger.error(f"Error validating path: {e}")
        if has_app_context() and hasattr(metrics, 'increment'):
            metrics.increment('security.path_validation_error')
        return False


def is_within_directory(file_path: str, directory: str) -> bool:
    """
    Check if a file path is contained within a specified directory.

    Args:
        file_path: Path to check
        directory: Directory that should contain the path

    Returns:
        bool: True if the path is within the directory, False otherwise
    """
    try:
        real_directory = os.path.realpath(directory)
        real_file = os.path.realpath(file_path)
        return os.path.commonpath([real_file, real_directory]) == real_directory
    except (ValueError, OSError) as e:
        logger.error(f"Error checking if path is within directory: {e}")
        return False


def is_safe_file_operation(operation: str, file_path: str, safe_dirs: List[str]) -> bool:
    """
    Validate if a file operation is safe to perform.

    Args:
        operation: File operation (read, write, delete)
        file_path: Path to the file
        safe_dirs: List of directories considered safe for this operation

    Returns:
        bool: True if operation is safe, False otherwise
    """
    if not file_path:
        logger.warning("No file path provided for file operation")
        return False

    if not operation:
        logger.warning("No operation specified for file validation")
        return False

    if not safe_dirs:
        logger.warning("No safe directories provided for file operation validation")
        return False

    # Convert operation to lowercase
    op = operation.lower().strip()

    # Check if operation is supported
    if op not in ['read', 'write', 'delete', 'execute']:
        logger.warning(f"Unsupported file operation: {operation}")
        return False

    # Get absolute path
    abs_path = os.path.abspath(file_path)

    # Check if path exists for read operations
    if op == 'read' and not os.path.exists(abs_path):
        logger.warning(f"File does not exist for read operation: {file_path}")
        return False

    # Check if within allowed directories
    for safe_dir in safe_dirs:
        if is_within_directory(abs_path, safe_dir):
            return True

    logger.warning(f"File operation '{operation}' not allowed for path: {file_path}")
    return False


def sanitize_path(path: str, base_dir: str) -> Optional[str]:
    """
    Sanitize a file path to be safe to use within a base directory.

    Args:
        path: Path to sanitize
        base_dir: Base directory to ensure path stays within

    Returns:
        Optional[str]: Sanitized path, or None if path cannot be sanitized
    """
    if not path:
        return None

    try:
        # Remove any dangerous components
        path = path.replace('..', '').replace('~', '')

        # Remove any leading slashes or backslashes
        path = path.lstrip('/\\')

        # Join with base directory
        full_path = os.path.join(base_dir, path)

        # Resolve to absolute path
        abs_path = os.path.abspath(full_path)

        # Check if it's within the base directory
        if not is_within_directory(abs_path, base_dir):
            logger.warning(f"Sanitized path would escape base directory: {path}")
            return None

        return abs_path
    except Exception as e:
        logger.error(f"Error sanitizing path: {e}")
        return None

#-------------------------------------------------------------------------
# URL AND DOMAIN VALIDATION
#-------------------------------------------------------------------------

def validate_url(url: str, required_schemes: Optional[List[str]] = None) -> Tuple[bool, Optional[str]]:
    """
    Validate URL against security requirements.

    Args:
        url: URL to validate
        required_schemes: Optional list of allowed schemes (e.g., ['https', 'http'])

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not url:
        if has_app_context() and hasattr(metrics, 'increment'):
            metrics.increment('security.url_validation_failure')
        return False, "URL cannot be empty"

    try:
        # Try to parse the URL to validate its format
        from urllib.parse import urlparse
        parsed = urlparse(url)

        # Check if URL has both scheme and netloc for absolute URLs, or path for relative
        if not parsed.scheme and not parsed.netloc and not parsed.path:
            if has_app_context() and hasattr(metrics, 'increment'):
                metrics.increment('security.url_validation_failure')
            return False, "URL is malformed"

        # Block unsafe schemes
        unsafe_schemes = ['javascript', 'data', 'vbscript', 'file']
        if parsed.scheme and parsed.scheme.lower() in unsafe_schemes:
            if has_app_context() and hasattr(metrics, 'increment'):
                metrics.increment('security.unsafe_url_blocked')
            logger.warning(f"Blocked unsafe URL scheme: {parsed.scheme}")

            # Log security event if in request context
            if has_request_context():
                from .cs_audit import log_security_event
                try:
                    log_security_event(
                        event_type="unsafe_url_blocked",
                        severity="warning",
                        description=f"Blocked URL with unsafe scheme: {parsed.scheme}",
                        details={
                            "url": url,
                            "scheme": parsed.scheme,
                            "client_ip": request.remote_addr if hasattr(request, 'remote_addr') else None,
                            "user_agent": request.user_agent.string if hasattr(request, 'user_agent') else None
                        }
                    )
                except Exception as e:
                    logger.error(f"Failed to log security event for unsafe URL: {e}")

            return False, f"URL scheme '{parsed.scheme}' is not allowed"

        # Check if scheme is required and matches allowed schemes
        if required_schemes and parsed.scheme:
            if parsed.scheme.lower() not in [s.lower() for s in required_schemes]:
                if has_app_context() and hasattr(metrics, 'increment'):
                    metrics.increment('security.url_validation_failure')
                return False, f"URL scheme must be one of: {', '.join(required_schemes)}"

        # Special handling for relative URLs
        if not parsed.scheme and not parsed.netloc:
            if not parsed.path:
                if has_app_context() and hasattr(metrics, 'increment'):
                    metrics.increment('security.unsafe_path_blocked')
                return False, "Relative URL must start with /"

        # Additional validation based on project's security policies
        if SECURITY_CONFIG.get('STRICT_URL_VALIDATION', False) and has_app_context():
            # In strict mode, apply additional rules from config
            allowed_domains = current_app.config.get('ALLOWED_REDIRECT_DOMAINS', [])

            # If URL has host and we have domain restrictions
            if parsed.netloc and allowed_domains:
                host = parsed.netloc.lower()
                if not any(host == domain.lower() or host.endswith('.' + domain.lower()) for domain in allowed_domains):
                    if has_app_context() and hasattr(metrics, 'increment'):
                        metrics.increment('security.url_validation_failure')
                    return False, "Domain not in allowed list"

        # URL validation passed
        if has_app_context() and hasattr(metrics, 'increment'):
            metrics.increment('security.url_validation_success')
        return True, None

    except Exception as e:
        logger.error(f"Error validating URL: {e}")
        if has_app_context() and hasattr(metrics, 'increment'):
            metrics.increment('security.url_validation_error')
        return False, f"Error validating URL: {str(e)}"


def is_valid_domain(domain: str) -> bool:
    """
    Validate a domain name against DNS requirements.

    Args:
        domain: Domain name to validate

    Returns:
        bool: True if domain is valid, False otherwise
    """
    if not domain:
        return False

    try:
        # Basic format validation using regex
        if not HOSTNAME_PATTERN.match(domain):
            return False

        # Check domain parts
        parts = domain.split('.')

        # Domain must have at least 2 parts and TLD must be at least 2 chars
        if len(parts) < 2 or len(parts[-1]) < 2:
            return False

        # Each part must be between 1 and 63 chars
        if any(len(p) < 1 or len(p) > 63 for p in parts):
            return False

        # Try DNS resolution as additional validation
        socket.getaddrinfo(domain, None)

        # Track successful validation
        if has_app_context() and hasattr(metrics, 'increment'):
            metrics.increment('security.domain_validation_success')
        return True

    except socket.gaierror:
        # Failed DNS resolution
        if has_app_context() and hasattr(metrics, 'increment'):
            metrics.increment('security.domain_validation_failure')
        return False
    except Exception as e:
        logger.error(f"Error validating domain: {e}")
        if has_app_context() and hasattr(metrics, 'increment'):
            metrics.increment('security.domain_validation_error')
        return False


def is_valid_ip(ip: str) -> bool:
    """
    Validate that a string is a valid IP address (IPv4 or IPv6).

    Args:
        ip: IP address to validate

    Returns:
        bool: True if valid IP address, False otherwise
    """
    if not ip:
        return False

    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

#-------------------------------------------------------------------------
# INPUT VALIDATION
#-------------------------------------------------------------------------

def validate_input_against_pattern(input_value: str, pattern: str, exact_match: bool = False) -> bool:
    """
    Validate that an input value matches a specified pattern.

    Args:
        input_value: The input string to validate
        pattern: Regular expression pattern to validate against
        exact_match: Whether to require an exact match (vs. search)

    Returns:
        bool: True if the pattern matches, False otherwise
    """
    try:
        if not input_value or not pattern:
            return False

        regex = re.compile(pattern)
        if exact_match:
            match = regex.fullmatch(input_value) is not None
        else:
            match = regex.search(input_value) is not None

        return match
    except re.error as e:
        logger.error(f"Invalid regex pattern '{pattern}': {str(e)}")
        return False


def validate_sanitized_input(input_value: str, allow_chars: str = r'a-zA-Z0-9\s\-_\.') -> bool:
    """
    Validate that an input contains only allowed characters.

    Args:
        input_value: The input to validate
        allow_chars: String of allowed characters in regex format

    Returns:
        bool: True if input only contains allowed characters
    """
    if not input_value:
        return True

    pattern = f'^[{allow_chars}]+$'
    try:
        return bool(re.match(pattern, input_value))
    except re.error:
        logger.error(f"Invalid regex pattern for input validation: {pattern}")
        return False


def is_valid_username(username: str) -> bool:
    """
    Validate that a username meets security requirements.

    Args:
        username: Username to validate

    Returns:
        bool: True if username is valid, False otherwise
    """
    if not username:
        return False

    # Check length
    if len(username) < 3 or len(username) > 64:
        return False

    # Check for valid characters (alphanumeric, dots, dashes, underscores)
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        return False

    # Username should start with a letter or number
    if not username[0].isalnum():
        return False

    # Check for reserved usernames
    reserved = {
        'admin', 'administrator', 'root', 'system', 'anonymous',
        'user', 'guest', 'support', 'security', 'staff', 'operator'
    }
    if username.lower() in reserved:
        return False

    return True


def is_valid_hash(hash_value: str, algorithm: Optional[str] = None) -> bool:
    """
    Validate that a string is a valid cryptographic hash.

    Args:
        hash_value: Hash value to validate
        algorithm: Optional algorithm name to validate format against

    Returns:
        bool: True if valid hash format, False otherwise
    """
    if not hash_value:
        return False

    # Check common hash formats
    hash_formats = {
        'md5': r'^[a-f0-9]{32}$',
        'sha1': r'^[a-f0-9]{40}$',
        'sha224': r'^[a-f0-9]{56}$',
        'sha256': r'^[a-f0-9]{64}$',
        'sha384': r'^[a-f0-9]{96}$',
        'sha512': r'^[a-f0-9]{128}$'
    }

    # If specific algorithm is provided, check only that format
    if algorithm and algorithm.lower() in hash_formats:
        return bool(re.match(hash_formats[algorithm.lower()], hash_value, re.IGNORECASE))

    # Otherwise check if it matches any common hash format
    return any(
        bool(re.match(pattern, hash_value, re.IGNORECASE))
        for pattern in hash_formats.values()
    )

#-------------------------------------------------------------------------
# CONFIGURATION VALIDATION
#-------------------------------------------------------------------------

def validate_security_config() -> List[str]:
    """
    Validate the security configuration for required and recommended settings.

    Returns:
        List of validation errors/warnings
    """
    validation_issues = []

    # Check encryption settings
    if not SECURITY_CONFIG.get('ENCRYPTION_KEY'):
        validation_issues.append("CRITICAL: ENCRYPTION_KEY is not set")

    encryption_salt = SECURITY_CONFIG.get('ENCRYPTION_SALT')
    if not encryption_salt:
        validation_issues.append("WARNING: ENCRYPTION_SALT is not set")
    elif isinstance(encryption_salt, str) and len(encryption_salt) < 16:
        validation_issues.append("WARNING: ENCRYPTION_SALT should be at least 16 bytes")

    # Check key iterations
    key_iterations = SECURITY_CONFIG.get('DEFAULT_KEY_ITERATIONS', 0)
    if key_iterations < 100000:
        validation_issues.append(f"WARNING: DEFAULT_KEY_ITERATIONS ({key_iterations}) should be at least 100,000")

    # Check password policy
    min_length = SECURITY_CONFIG.get('MIN_PASSWORD_LENGTH', 0)
    if min_length < 12:
        validation_issues.append(f"WARNING: MIN_PASSWORD_LENGTH ({min_length}) should be at least 12")

    if not SECURITY_CONFIG.get('PASSWORD_COMPLEXITY_REQUIRED', False):
        validation_issues.append("WARNING: PASSWORD_COMPLEXITY_REQUIRED is not enabled")

    # Check session security
    session_timeout = SECURITY_CONFIG.get('SESSION_TIMEOUT', 0)
    if session_timeout > 24 * 3600:
        validation_issues.append(f"WARNING: SESSION_TIMEOUT ({session_timeout}s) exceeds recommended maximum of 24 hours")
    elif session_timeout <= 0:
        validation_issues.append("WARNING: SESSION_TIMEOUT is not properly set")

    # Check for MFA enforcement
    if not SECURITY_CONFIG.get('REQUIRE_MFA_FOR_SENSITIVE', False):
        validation_issues.append("WARNING: REQUIRE_MFA_FOR_SENSITIVE is not enabled")

    # Validate JWT algorithm
    jwt_algorithm = SECURITY_CONFIG.get('JWT_ALGORITHM')
    if jwt_algorithm not in ['HS256', 'RS256', 'ES256']:
        validation_issues.append(f"WARNING: JWT_ALGORITHM '{jwt_algorithm}' should be HS256, RS256, or ES256")

    # Check security headers
    security_headers = SECURITY_CONFIG.get('SECURITY_HEADERS', {})
    if 'Strict-Transport-Security' not in security_headers:
        validation_issues.append("WARNING: HSTS header not configured")
    if 'Content-Security-Policy' not in security_headers:
        validation_issues.append("WARNING: Content-Security-Policy header not configured")

    # Check file integrity settings
    file_check_interval = SECURITY_CONFIG.get('FILE_CHECK_INTERVAL', 0)
    if file_check_interval < 900:  # Minimum 15 minutes
        validation_issues.append(f"WARNING: FILE_CHECK_INTERVAL ({file_check_interval}s) is too frequent")

    critical_patterns = SECURITY_CONFIG.get('CRITICAL_FILES_PATTERN', [])
    if not critical_patterns:
        validation_issues.append("WARNING: No CRITICAL_FILES_PATTERN specified for file monitoring")

    return validation_issues

#-------------------------------------------------------------------------
# FILE INTEGRITY VALIDATION
#-------------------------------------------------------------------------

def validate_file_permissions(path: str, min_mode: int = 0o600, max_mode: int = 0o755) -> bool:
    """
    Validate that a file has secure permissions.

    Args:
        path: Path to the file
        min_mode: Minimum acceptable permission mode (octal)
        max_mode: Maximum acceptable permission mode (octal)

    Returns:
        bool: True if permissions are in acceptable range, False otherwise
    """
    try:
        if not os.path.exists(path):
            logger.warning(f"Cannot validate permissions of non-existent file: {path}")
            return False

        stat = os.stat(path)
        mode = stat.st_mode & 0o777  # Get permission bits

        # Check if permissions are too permissive or too restrictive
        if mode > max_mode:
            logger.warning(f"File permissions for {path} are too permissive: {oct(mode)}")
            return False

        if mode < min_mode:
            logger.warning(f"File permissions for {path} are too restrictive: {oct(mode)}")
            return False

        return True
    except Exception as e:
        logger.error(f"Error validating file permissions for {path}: {str(e)}")
        return False


def verify_file_integrity(file_path: str, expected_hash: str = None) -> bool:
    """
    Verify the integrity of a file by comparing its hash with expected value.

    Args:
        file_path: Path to the file to check
        expected_hash: Expected hash value, if None will attempt to retrieve from baseline

    Returns:
        bool: True if integrity check passes, False otherwise
    """
    if not os.path.exists(file_path):
        logger.warning(f"File not found for integrity check: {file_path}")
        return False

    try:
        if expected_hash is None:
            # Attempt to retrieve from baseline if no expected hash provided
            # This would typically call into your existing file integrity system
            logger.warning(f"No expected hash provided for {file_path}, cannot verify")
            return False

        # Calculate current hash
        from .cs_crypto import compute_hash
        actual_hash = compute_hash(file_path)

        # Compare hashes
        if actual_hash != expected_hash:
            logger.warning(f"File integrity check failed for {file_path}: Hash mismatch")
            return False

        return True
    except Exception as e:
        logger.error(f"Error verifying file integrity: {e}")
        return False


def verify_baseline_update(file_path: str, current_hash: str, expected_hash: str, max_age: int = 86400) -> bool:
    """
    Verify whether a baseline update for a file is valid and permissible.

    Args:
        file_path: Path to the file
        current_hash: Current hash of the file
        expected_hash: Expected hash from baseline
        max_age: Maximum allowed age (in seconds) of files eligible for auto-update

    Returns:
        bool: True if update is valid, False otherwise
    """
    if not file_path or not current_hash or not expected_hash:
        logger.warning("Missing required parameters for baseline update validation")
        return False

    try:
        # If the hashes match, no update needed
        if current_hash == expected_hash:
            logger.debug(f"No update needed for {file_path}, hashes match")
            return False

        # Check if file is too old for auto-update (needs manual review)
        if max_age > 0:
            try:
                file_stat = os.stat(file_path)
                file_mtime = file_stat.st_mtime
                current_time = datetime.now().timestamp()

                # If file was modified longer ago than max_age, reject auto-update
                if (current_time - file_mtime) > max_age:
                    logger.warning(f"File {file_path} exceeds maximum age for auto-update")
                    return False
            except OSError as e:
                logger.error(f"Error checking file modification time: {e}")
                return False

        # For security, check if this is a sensitive file that should never be auto-updated
        sensitive_patterns = SECURITY_CONFIG.get('HIGH_SENSITIVITY_PATTERNS', [])
        for pattern in sensitive_patterns:
            import fnmatch
            if fnmatch.fnmatch(file_path, pattern):
                logger.warning(f"Rejecting update for sensitive file {file_path}")
                return False

        # File can be updated
        return True

    except Exception as e:
        logger.error(f"Error in baseline update verification: {e}")
        return False

#-------------------------------------------------------------------------
# UTILITY VALIDATION FUNCTIONS
#-------------------------------------------------------------------------

def is_valid_email(email: str) -> bool:
    """
    Validate email format.

    Args:
        email: Email address to validate

    Returns:
        bool: True if valid email, False otherwise
    """
    if not email:
        return False

    # Basic format check
    if not EMAIL_PATTERN.match(email):
        return False

    # Domain must have at least one dot
    parts = email.split('@')
    if len(parts) != 2 or '.' not in parts[1]:
        return False

    return True


def is_valid_uuid(value: str, version: int = 4) -> bool:
    """
    Validate that a string is a valid UUID.

    Args:
        value: UUID string to validate
        version: UUID version to check for (default: 4)

    Returns:
        bool: True if valid UUID, False otherwise
    """
    if not value:
        return False

    try:
        import uuid
        parsed_uuid = uuid.UUID(value, version=version)
        return str(parsed_uuid) == value.lower()
    except (ValueError, AttributeError, TypeError):
        return False


def validate_request_security(request=None) -> Tuple[bool, str]:
    """
    Validate security aspects of an HTTP request.

    Args:
        request: Flask request object, uses current request if None

    Returns:
        Tuple[bool, str]: (is_valid, reason_if_invalid)
    """
    if not has_request_context():
        return False, "No request context"

    if request is None:
        from flask import request

    # Check origin header for CSRF protection
    if request.method in {'POST', 'PUT', 'DELETE', 'PATCH'}:
        origin = request.headers.get('Origin', '')
        referrer = request.headers.get('Referer', '')
        host = request.host_url.rstrip('/')

        # Check if origin matches host
        if origin and origin != 'null' and not origin.startswith(host):
            return False, "Origin mismatch"

        # Check if referrer is set and doesn't match host
        if referrer and not referrer.startswith(host):
            return False, "Referrer mismatch"

    # Check content type for JSON API requests
    if request.mimetype == 'application/json' and request.method != 'GET':
        if request.content_length and request.content_length > SECURITY_CONFIG.get('MAX_CONTENT_LENGTH', 10485760):
            return False, "Content length exceeds maximum"

    # Additional checks can be implemented here

    return True, "Valid request"


# Additional validation utilities can be added here
