"""
Custom validators for the admin blueprint.

This module provides custom validation functions for administrative forms,
configuration settings, and security controls. These validators enforce
security policies, logical constraints, and compliance requirements
across the Cloud Infrastructure Platform's administrative interface.

Validators work with WTForms validation as well as standalone validation
for programmatic use in API endpoints and background processes.

Key validator categories include:
- Configuration validation (security settings, system parameters)
- Security policy validation (password policies, access controls)
- Permission validation (RBAC constraints, permission hierarchies)
- Input sanitization (security-focused input cleansing)
- Cross-field validation (logical relationship enforcement)
- Compliance validation (regulatory requirement checks)
"""

import ipaddress
import logging
import re
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Pattern
from urllib.parse import urlparse

from flask import current_app
from sqlalchemy import and_, func
from wtforms.validators import ValidationError

from core.security.cs_validation import validate_path_security
from models.auth import Permission, Role, User
from models.security import SecurityIncident, SystemConfig

# Initialize logger
logger = logging.getLogger(__name__)

# Constants for validation
PATH_MAX_LENGTH = 512
URL_MAX_LENGTH = 2048
HOSTNAME_MAX_LENGTH = 255
CONFIG_KEY_PATTERN = re.compile(r'^[a-z0-9_\.]{3,64}$')
MIN_PASSWORD_LENGTH = 12
RESTRICTED_CONFIG_KEYS = {
    'security.jwt_secret',
    'security.admin_api_key',
    'database.password',
    'smtp.password',
}
RESERVED_USERNAMES = {
    'admin', 'administrator', 'system', 'root', 'superuser', 'security',
    'support', 'guest', 'test', 'user', 'anonymous', 'default'
}
EMAIL_DOMAIN_BLOCKLIST = {
    'example.com', 'test.com', 'localhost'
}

# File path validation
RESTRICTED_PATHS = [
    '/etc/shadow', '/etc/passwd', '/etc/sudoers',
    '/etc/ssl/private', '/root', '/var/lib/secrets'
]


def validate_role_name(name: str) -> Tuple[bool, str]:
    """
    Validate a role name according to naming rules and constraints.

    Args:
        name: The role name to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check for minimum/maximum length
    if len(name) < 3:
        return False, "Role name must be at least 3 characters long"
    if len(name) > 64:
        return False, "Role name must be at most 64 characters long"

    # Check for valid characters
    if not re.match(r'^[a-zA-Z0-9_]+$', name):
        return False, "Role name must contain only letters, numbers, and underscores"

    # Check for reserved role names (case insensitive)
    if name.lower() in {'admin', 'superadmin', 'system', 'anonymous', 'user'}:
        if not current_app.config.get('ALLOW_RESERVED_ROLE_NAMES', False):
            return False, f"'{name}' is a reserved role name"

    return True, ""


def validate_permission_format(permission: str) -> Tuple[bool, str]:
    """
    Validate a permission string follows the required format: resource:action.

    Args:
        permission: The permission string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Basic format check
    if not permission or not isinstance(permission, str):
        return False, "Permission cannot be empty"

    # Check permission format
    if not re.match(r'^[a-z_]+:[a-z_]+$', permission):
        return False, "Permission must follow format 'resource:action' using only lowercase letters and underscores"

    # Split into resource and action
    parts = permission.split(':')
    if len(parts) != 2:
        return False, "Permission must have exactly one colon separator"

    resource, action = parts

    # Check resource and action lengths
    if len(resource) < 2 or len(resource) > 30:
        return False, "Resource name must be between 2 and 30 characters"
    if len(action) < 2 or len(action) > 30:
        return False, "Action name must be between 2 and 30 characters"

    return True, ""


def validate_permission_hierarchy(permission: str) -> Tuple[bool, str]:
    """
    Validate permission against the permission hierarchy system.

    Args:
        permission: The permission string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    # First validate format
    is_valid, error = validate_permission_format(permission)
    if not is_valid:
        return is_valid, error

    parts = permission.split(':')
    resource, action = parts

    # Special actions that apply to any resource
    global_actions = {'create', 'read', 'update', 'delete', 'list', 'admin'}

    # Special resources with custom action sets
    special_resources = {
        'system': {'configure', 'backup', 'restore', 'monitor', 'admin'},
        'user': {'create', 'read', 'update', 'delete', 'list', 'impersonate'},
        'security': {'audit', 'configure', 'read', 'admin'}
    }

    # Validate action against resource
    if resource in special_resources:
        if action not in special_resources[resource] and action not in global_actions:
            return False, f"Action '{action}' is not valid for resource '{resource}'"
    elif action not in global_actions:
        # For standard resources, only allow global actions
        return False, f"Action '{action}' is not a standard action"

    return True, ""


def validate_username(username: str) -> Tuple[bool, str]:
    """
    Validate a username according to security policy.

    Args:
        username: The username to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check length
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    if len(username) > 64:
        return False, "Username cannot exceed 64 characters"

    # Check format
    if not re.match(r'^[a-zA-Z0-9_\.-]+$', username):
        return False, "Username must contain only letters, numbers, dots, underscores, or hyphens"

    # Check if username is reserved
    if username.lower() in RESERVED_USERNAMES:
        return False, f"Username '{username}' is reserved"

    # Check if username starts with a letter or number
    if not username[0].isalnum():
        return False, "Username must start with a letter or number"

    # Check for consecutive special characters
    if re.search(r'[_\.-]{2,}', username):
        return False, "Username cannot contain consecutive special characters"

    return True, ""


def validate_config_key(key: str) -> Tuple[bool, str]:
    """
    Validate configuration key naming.

    Args:
        key: The configuration key to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not key:
        return False, "Configuration key cannot be empty"

    if len(key) > 64:
        return False, "Configuration key cannot exceed 64 characters"

    if not CONFIG_KEY_PATTERN.match(key):
        return False, "Configuration key must contain only lowercase letters, numbers, dots, and underscores"

    # Check for reserved configuration keys that require special permissions
    if key in RESTRICTED_CONFIG_KEYS:
        return False, f"Configuration key '{key}' is restricted and requires special permissions"

    # Check for protected prefixes
    protected_prefixes = ['security.', 'auth.', 'admin.', 'compliance.']
    if any(key.startswith(prefix) for prefix in protected_prefixes):
        # These may require additional permission checks
        if not current_app.config.get('ALLOW_SECURITY_CONFIG_CHANGES', False):
            return False, f"Configuration key '{key}' is security-related and requires special permissions"

    return True, ""


def validate_file_path(path: str) -> Tuple[bool, str]:
    """
    Validate a file path for security concerns.

    Args:
        path: The file path to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not path:
        return False, "File path cannot be empty"

    if len(path) > PATH_MAX_LENGTH:
        return False, f"File path exceeds maximum length of {PATH_MAX_LENGTH} characters"

    # Check for path traversal attempts
    normalized_path = Path(path).resolve()
    try:
        # Use utility to check path security
        if not validate_path_security(str(normalized_path)):
            return False, "Path contains potential security risks"
    except (ValueError, OSError) as e:
        logger.warning(f"Path validation error: {str(e)}")
        return False, "Invalid file path"

    # Check for restricted paths
    for restricted in RESTRICTED_PATHS:
        if str(normalized_path).startswith(restricted):
            return False, f"Access to path '{restricted}' is restricted"

    return True, ""


def validate_config_value(key: str, value: Any) -> Tuple[bool, str]:
    """
    Validate a configuration value based on its key and expected type.

    Args:
        key: The configuration key
        value: The configuration value to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Define validators per config key prefix
    validators = {
        'security.password_min_length': lambda v: isinstance(v, int) and 8 <= v <= 128,
        'security.password_complexity': lambda v: isinstance(v, bool),
        'security.mfa_required': lambda v: isinstance(v, bool),
        'security.session_timeout': lambda v: isinstance(v, int) and 60 <= v <= 86400,
        'email.from_address': lambda v: isinstance(v, str) and '@' in v and '.' in v.split('@')[1],
        'email.server': lambda v: isinstance(v, str) and is_valid_hostname(v),
        'file_integrity.enabled': lambda v: isinstance(v, bool),
        'file_integrity.check_frequency': lambda v: isinstance(v, int) and 5 <= v <= 1440,
        'url.allowed_domains': lambda v: isinstance(v, list) and all(isinstance(d, str) for d in v),
    }

    # Find the matching validator
    exact_validator = validators.get(key)
    if exact_validator:
        if not exact_validator(value):
            return False, f"Invalid value for configuration key '{key}'"
        return True, ""

    # Try prefix matching for category-based validation
    for prefix, validator in validators.items():
        if prefix.endswith('*') and key.startswith(prefix[:-1]):
            if not validator(value):
                return False, f"Invalid value for configuration key '{key}'"
            return True, ""

    # Special checks for URL values
    if 'url' in key or 'endpoint' in key:
        if not isinstance(value, str):
            return False, "URL must be a string"
        if len(value) > URL_MAX_LENGTH:
            return False, f"URL exceeds maximum length of {URL_MAX_LENGTH}"
        if not is_valid_url(value):
            return False, "Invalid URL format"

    # Security configurations require additional validation
    if key.startswith('security.'):
        if 'password' in key and isinstance(value, str) and len(value) > 0:
            return False, "Cannot set security.password values directly"

    return True, ""


def validate_config_security_implications(changes: Dict[str, Dict[str, Any]]) -> Tuple[bool, str, Dict]:
    """
    Validate the security implications of configuration changes.

    Args:
        changes: Dictionary of changes with format {key: {'old': old_value, 'new': new_value}}

    Returns:
        Tuple of (is_valid, error_message, security_context)
    """
    security_context = {
        'security_impact': 'none',
        'requires_restart': False,
        'affects_compliance': False,
        'affected_components': set()
    }

    # Config keys that require system restart
    restart_required_keys = {
        'security.session_secret', 'security.jwt_algorithm', 'server.workers',
        'database.pool_size', 'server.host', 'server.port'
    }

    # Config keys with compliance implications
    compliance_keys = {
        'security.password_min_length', 'security.password_complexity',
        'security.mfa_required', 'security.mfa_methods', 'security.session_timeout',
        'audit.retention_days', 'file_integrity.enabled'
    }

    # Component mapping for affected services
    component_mapping = {
        'email': 'notification',
        'security': 'security',
        'database': 'database',
        'server': 'webserver',
        'audit': 'security',
        'file_integrity': 'security',
        'backup': 'storage',
        'log': 'logging'
    }

    for key, change in changes.items():
        # Skip if we're not actually changing the value
        if change['old'] == change['new']:
            continue

        # Validate key naming first
        is_valid, error = validate_config_key(key)
        if not is_valid:
            return False, error, security_context

        # Validate value
        is_valid, error = validate_config_value(key, change['new'])
        if not is_valid:
            return False, error, security_context

        # Check for restart requirements
        if key in restart_required_keys or any(key.startswith(rk + '.') for rk in restart_required_keys):
            security_context['requires_restart'] = True

        # Check for compliance implications
        if key in compliance_keys or any(key.startswith(ck + '.') for ck in compliance_keys):
            security_context['affects_compliance'] = True

        # Determine affected component
        for prefix, component in component_mapping.items():
            if key.startswith(prefix + '.'):
                security_context['affected_components'].add(component)

        # Assess security impact
        if key.startswith('security.'):
            # Security settings have at least medium impact
            if security_context['security_impact'] == 'none':
                security_context['security_impact'] = 'medium'

            # Critical security configurations have high impact
            high_impact_patterns = ['security.jwt_', 'security.admin_', 'security.mfa_required',
                                   'security.password_', 'security.session_secret']
            if any(pattern in key for pattern in high_impact_patterns):
                security_context['security_impact'] = 'high'

    # Convert affected components set to list for JSON serialization
    security_context['affected_components'] = list(security_context['affected_components'])

    return True, "", security_context


def validate_email_domain(email: str) -> Tuple[bool, str]:
    """
    Validate email domain against blocklist and DNS checks.

    Args:
        email: Email address to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not email or '@' not in email:
        return False, "Invalid email format"

    domain = email.split('@')[1].lower()

    # Check against blocklist
    if domain in EMAIL_DOMAIN_BLOCKLIST:
        return False, f"Email domain '{domain}' is not allowed"

    # Optional: Perform DNS check if configured
    if current_app.config.get('VALIDATE_EMAIL_DNS', False):
        try:
            # Check MX records
            socket.getaddrinfo(domain, 25)
        except socket.gaierror:
            return False, f"No mail server found for domain '{domain}'"

    return True, ""


def validate_incident_priority(incident_type: str, severity: str) -> int:
    """
    Calculate and validate priority for a security incident based on type and severity.

    Args:
        incident_type: Type of security incident
        severity: Severity level of the incident

    Returns:
        Priority level from 1-5 (1 being highest)
    """
    # Map severity to base priority
    severity_mapping = {
        'critical': 1,
        'high': 2,
        'medium': 3,
        'low': 4,
        'info': 5
    }

    # Adjust priority based on incident type
    type_adjustment = {
        'intrusion': -1,  # Higher priority (decrease number)
        'data_breach': -1,
        'malware': -1,
        'ransomware': -2,  # Much higher priority
        'ddos': 0,
        'policy_violation': +1,  # Lower priority (increase number)
        'misconfiguration': 0
    }

    # Start with base priority from severity
    priority = severity_mapping.get(severity.lower(), 3)

    # Apply adjustment based on incident type
    adjustment = type_adjustment.get(incident_type.lower(), 0)
    priority = max(1, min(5, priority + adjustment))

    return priority


def validate_compliance_report_dates(start_date: datetime, end_date: datetime) -> Tuple[bool, str]:
    """
    Validate date range for compliance reports.

    Args:
        start_date: Report start date
        end_date: Report end date

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Ensure start date is before end date
    if start_date >= end_date:
        return False, "Start date must be before end date"

    # Check that date range isn't too large
    max_days = current_app.config.get('MAX_REPORT_DATE_RANGE', 365)
    if (end_date - start_date).days > max_days:
        return False, f"Report date range cannot exceed {max_days} days"

    # Ensure dates are not in the future
    now = datetime.utcnow()
    if end_date > now:
        return False, "End date cannot be in the future"

    # Check that we have data for the requested range
    min_date = datetime.utcnow() - timedelta(days=current_app.config.get('MAX_DATA_RETENTION_DAYS', 730))
    if start_date < min_date:
        return False, f"Data is only available from {min_date.strftime('%Y-%m-%d')} onwards"

    return True, ""


def validate_baseline_paths(paths: List[str]) -> Tuple[bool, str, List[str]]:
    """
    Validate and sanitize paths for file integrity baseline.

    Args:
        paths: List of paths to validate

    Returns:
        Tuple of (is_valid, error_message, sanitized_paths)
    """
    if not paths:
        return False, "No paths provided", []

    sanitized_paths = []
    for path in paths:
        # Clean up path
        path = path.strip()
        if not path:
            continue

        # Validate individual path
        is_valid, error = validate_file_path(path)
        if not is_valid:
            return False, f"Invalid path '{path}': {error}", []

        sanitized_paths.append(path)

    if not sanitized_paths:
        return False, "No valid paths provided", []

    return True, "", sanitized_paths


def validate_pattern_syntax(patterns: List[str]) -> Tuple[bool, str, List[str]]:
    """
    Validate and sanitize patterns for file inclusion/exclusion.

    Args:
        patterns: List of glob patterns to validate

    Returns:
        Tuple of (is_valid, error_message, sanitized_patterns)
    """
    sanitized_patterns = []

    for pattern in patterns:
        # Skip empty patterns
        pattern = pattern.strip()
        if not pattern:
            continue

        # Check pattern length
        if len(pattern) > 255:
            return False, f"Pattern too long: {pattern[:50]}...", []

        # Check for dangerous patterns
        dangerous_patterns = ['/*', '/..', '/.', '~/', '*/', '/../', '/./', '//*']
        if any(dp in pattern for dp in dangerous_patterns):
            return False, f"Potentially unsafe pattern: {pattern}", []

        # Validate pattern syntax by compiling it
        try:
            import fnmatch
            # Test compilation of pattern
            fnmatch.translate(pattern)
            sanitized_patterns.append(pattern)
        except Exception as e:
            return False, f"Invalid pattern '{pattern}': {str(e)}", []

    return True, "", sanitized_patterns


def is_valid_hostname(hostname: str) -> bool:
    """
    Check if a hostname is valid.

    Args:
        hostname: Hostname to validate

    Returns:
        Boolean indicating if hostname is valid
    """
    if not hostname or len(hostname) > HOSTNAME_MAX_LENGTH:
        return False

    # Check hostname format
    if hostname.endswith('.'):
        hostname = hostname[:-1]

    # Check for valid hostname parts
    allowed = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')
    return all(allowed.match(x) for x in hostname.split('.'))


def is_valid_url(url: str) -> bool:
    """
    Check if a URL is valid.

    Args:
        url: URL to validate

    Returns:
        Boolean indicating if URL is valid
    """
    if not url:
        return False

    try:
        result = urlparse(url)
        valid_schemes = {'http', 'https'}
        return all([result.scheme in valid_schemes, result.netloc])
    except Exception:
        return False


def is_valid_ip_address(ip_address: str) -> bool:
    """
    Check if an IP address is valid (IPv4 or IPv6).

    Args:
        ip_address: IP address to validate

    Returns:
        Boolean indicating if IP address is valid
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


# Field validators for WTForms integration

def validate_role_name_field(form, field):
    """Validate role name field for WTForms."""
    is_valid, error = validate_role_name(field.data)
    if not is_valid:
        raise ValidationError(error)


def validate_permission_field(form, field):
    """Validate permission field for WTForms."""
    is_valid, error = validate_permission_format(field.data)
    if not is_valid:
        raise ValidationError(error)


def validate_username_field(form, field):
    """Validate username field for WTForms."""
    is_valid, error = validate_username(field.data)
    if not is_valid:
        raise ValidationError(error)


def validate_config_key_field(form, field):
    """Validate config key field for WTForms."""
    is_valid, error = validate_config_key(field.data)
    if not is_valid:
        raise ValidationError(error)


def validate_file_path_field(form, field):
    """Validate file path field for WTForms."""
    is_valid, error = validate_file_path(field.data)
    if not is_valid:
        raise ValidationError(error)


def validate_email_domain_field(form, field):
    """Validate email domain field for WTForms."""
    is_valid, error = validate_email_domain(field.data)
    if not is_valid:
        raise ValidationError(error)


def validate_pattern_field(form, field):
    """Validate pattern field for WTForms."""
    patterns = [p.strip() for p in field.data.split('\n') if p.strip()]
    is_valid, error, _ = validate_pattern_syntax(patterns)
    if not is_valid:
        raise ValidationError(error)


def validate_paths_field(form, field):
    """Validate paths field for WTForms."""
    paths = [p.strip() for p in field.data.split('\n') if p.strip()]
    is_valid, error, _ = validate_baseline_paths(paths)
    if not is_valid:
        raise ValidationError(error)
