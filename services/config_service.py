"""
Configuration Service for Cloud Infrastructure Platform.

This service provides centralized management of system configuration settings,
with support for validation, import/export, and environment-specific overrides.
It includes comprehensive security controls for sensitive configuration values
and maintains audit trails of all configuration changes.

The service handles:
- Reading and updating configuration values
- Validating configuration changes for security implications
- Exporting and importing configuration between environments
- Configuration value encryption for sensitive settings
- Audit logging of configuration operations
"""

import logging
import os
import json
import yaml
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime, timezone
from pathlib import Path
import re

# Import dependencies
try:
    from flask import current_app, g, request
    from sqlalchemy.exc import SQLAlchemyError

    from extensions import db, cache, metrics
    from models.security import SystemConfig, AuditLog
    from core.security import log_security_event, sanitize_path, is_safe_file_operation
    from core.security.cs_crypto import encrypt_sensitive_data, decrypt_sensitive_data
except ImportError as e:
    logging.warning(f"Some dependencies not available for ConfigService: {e}")

# Configure logging
logger = logging.getLogger(__name__)

# Constants
CONFIG_CACHE_TIMEOUT = 300  # 5 minutes
SENSITIVE_CONFIG_KEYS = [
    'api.secret', 'api.key', 'db.password', 'auth.secret',
    'jwt.secret', 'encryption.key', 'smtp.password', 'sms.api_key',
    '*.password', '*.secret', '*.key', '*.token', '*.private'
]
CONFIG_BACKUP_DIR = 'instance/backups/configs'
MAX_BACKUP_FILES = 10


def update_configuration(key: str, value: Any, category: str = 'system',
                         description: Optional[str] = None,
                         reason: Optional[str] = None) -> Tuple[bool, str]:
    """
    Update or create a system configuration value with proper validation and auditing.

    Args:
        key: Configuration key to update
        value: New configuration value
        category: Configuration category (default: 'system')
        description: Optional description for the configuration
        reason: Optional reason for the change

    Returns:
        Tuple of (success, message)
    """
    try:
        # Key validation
        if not _validate_config_key(key):
            return False, f"Invalid configuration key format: {key}"

        # Value validation
        value_type = type(value).__name__

        # Convert value to string if needed for storage
        if not isinstance(value, (str, int, float, bool, type(None))):
            try:
                value = json.dumps(value)
                value_type = 'json'
            except (TypeError, ValueError):
                return False, f"Unsupported value type for configuration: {type(value).__name__}"

        # Check if this is a sensitive configuration that needs encryption
        is_sensitive = _is_sensitive_key(key)
        if is_sensitive and isinstance(value, str):
            # Encrypt the value before storage
            try:
                value = encrypt_sensitive_data(value)
                value_type = 'encrypted'
            except Exception as e:
                logger.error(f"Failed to encrypt sensitive configuration: {e}")
                return False, "Failed to encrypt sensitive configuration value"

        # Check if config already exists
        existing_config = SystemConfig.query.filter_by(key=key).first()

        if existing_config:
            # Update existing config
            old_value = existing_config.value
            existing_config.value = value
            existing_config.updated_at = datetime.now(timezone.utc)
            existing_config.value_type = value_type

            if description:
                existing_config.description = description

            if hasattr(g, 'user') and g.user:
                existing_config.updated_by = g.user.id

            db.session.commit()

            # Clear cache for this config key
            cache.delete(f"config:{key}")

            # Log change
            _log_config_change('update', key, old_value, value, reason, category)

            metrics.increment('config.update_success')
            return True, f"Configuration '{key}' updated successfully"
        else:
            # Create new config entry
            new_config = SystemConfig(
                key=key,
                value=value,
                category=category,
                description=description or f"Added on {datetime.now(timezone.utc).isoformat()}",
                value_type=value_type,
                created_at=datetime.now(timezone.utc)
            )

            if hasattr(g, 'user') and g.user:
                new_config.created_by = g.user.id

            db.session.add(new_config)
            db.session.commit()

            # Log creation
            _log_config_change('create', key, None, value, reason, category)

            metrics.increment('config.create_success')
            return True, f"Configuration '{key}' created successfully"

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error updating configuration: {str(e)}")
        metrics.increment('config.update_error')
        return False, f"Database error: {str(e)}"

    except Exception as e:
        logger.error(f"Error updating configuration: {str(e)}")
        metrics.increment('config.update_error')
        return False, f"Error updating configuration: {str(e)}"


def validate_config(changes: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate configuration changes for security and consistency.

    Args:
        changes: Dictionary of configuration changes with old and new values

    Returns:
        Dictionary with validation results
    """
    result = {
        'valid': True,
        'message': 'Configuration changes are valid',
        'warnings': [],
        'errors': []
    }

    # Special config keys that require additional validation
    special_validators = {
        'security.allowed_hosts': _validate_allowed_hosts,
        'security.content_security_policy': _validate_csp,
        'auth.password_policy': _validate_password_policy,
        'system.scheduled_tasks': _validate_scheduled_tasks,
        'system.debug_mode': _validate_debug_mode,
        'api.rate_limits': _validate_rate_limits
    }

    # Check each changed config item
    for key, change in changes.items():
        new_value = change.get('new')

        # Validate key format
        if not _validate_config_key(key):
            result['errors'].append(f"Invalid configuration key format: {key}")
            result['valid'] = False
            continue

        # Check for any validators for this specific key
        if key in special_validators:
            validator_result = special_validators[key](new_value)
            if not validator_result['valid']:
                result['errors'].append(validator_result['message'])
                result['valid'] = False
            if validator_result.get('warnings'):
                result['warnings'].extend(validator_result['warnings'])

        # Check for dangerous values in any config
        dangerous_check = _check_dangerous_values(key, new_value)
        if dangerous_check:
            result['errors'].append(dangerous_check)
            result['valid'] = False

        # Check for validation based on key category
        if key.startswith('security.'):
            security_check = _validate_security_config(key, new_value)
            if not security_check['valid']:
                result['errors'].append(security_check['message'])
                result['valid'] = False

    # If any errors exist, update the result message
    if result['errors']:
        result['message'] = f"Configuration validation failed: {', '.join(result['errors'])}"

    # Log validation result
    if not result['valid']:
        logger.warning(f"Configuration validation failed: {result['message']}")
        metrics.increment('config.validation_failure')

    return result


def export_configuration(include_sensitive: bool = False,
                         format_type: str = 'json',
                         categories: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Export system configuration for backup or transfer.

    Args:
        include_sensitive: Whether to include sensitive values (passwords, keys)
        format_type: Export format ('json' or 'yaml')
        categories: Optional list of categories to include

    Returns:
        Dictionary containing configuration data
    """
    try:
        # Query configs from database
        query = SystemConfig.query

        # Filter by categories if specified
        if categories:
            query = query.filter(SystemConfig.category.in_(categories))

        configs = query.all()

        # Build export structure
        result = {
            'metadata': {
                'exported_at': datetime.now(timezone.utc).isoformat(),
                'exported_by': getattr(g, 'user', {}).get('id', 'system') if hasattr(g, 'user') else 'system',
                'version': '1.0',
                'include_sensitive': include_sensitive
            },
            'settings': {},
            'categories': {}
        }

        # Process each config
        for config in configs:
            # Skip sensitive configs if not included
            is_sensitive = _is_sensitive_key(config.key)
            if is_sensitive and not include_sensitive:
                # Store a placeholder instead
                masked_value = "[REDACTED]"
                result['settings'][config.key] = masked_value
            else:
                # For sensitive encrypted values, decrypt them for export
                if is_sensitive and config.value_type == 'encrypted':
                    try:
                        decrypted_value = decrypt_sensitive_data(config.value)
                        result['settings'][config.key] = decrypted_value
                    except Exception as e:
                        logger.error(f"Failed to decrypt configuration for export: {e}")
                        result['settings'][config.key] = "[ENCRYPTION_ERROR]"
                else:
                    # For non-sensitive values or when including sensitive ones
                    # Convert value from string to appropriate type if needed
                    if config.value_type == 'int':
                        result['settings'][config.key] = int(config.value)
                    elif config.value_type == 'float':
                        result['settings'][config.key] = float(config.value)
                    elif config.value_type == 'bool':
                        # Handle string representations of booleans
                        if config.value.lower() in ('true', 'yes', '1'):
                            result['settings'][config.key] = True
                        elif config.value.lower() in ('false', 'no', '0'):
                            result['settings'][config.key] = False
                        else:
                            result['settings'][config.key] = config.value
                    elif config.value_type == 'json':
                        try:
                            result['settings'][config.key] = json.loads(config.value)
                        except:
                            result['settings'][config.key] = config.value
                    else:
                        # Default to string
                        result['settings'][config.key] = config.value

            # Organize by category
            if config.category not in result['categories']:
                result['categories'][config.category] = {}

            # Add additional metadata
            result['categories'][config.category][config.key] = {
                'description': config.description,
                'is_sensitive': is_sensitive,
                'updated_at': config.updated_at.isoformat() if config.updated_at else None
            }

        # Log the export activity (with appropriate redaction)
        _log_config_action('export', {
            'include_sensitive': include_sensitive,
            'format_type': format_type,
            'categories': categories,
            'config_count': len(configs)
        })

        metrics.increment('config.export_success')
        return result

    except Exception as e:
        logger.error(f"Error exporting configuration: {str(e)}")
        metrics.increment('config.export_error')
        # Return minimal export data with error information
        return {
            'metadata': {
                'exported_at': datetime.now(timezone.utc).isoformat(),
                'error': str(e),
                'status': 'failed'
            },
            'settings': {}
        }


def import_configuration(config_data: Dict[str, Any],
                         merge: bool = True,
                         validate_only: bool = False,
                         reason: Optional[str] = None) -> Tuple[bool, str, Dict[str, int]]:
    """
    Import system configuration from exported data.

    Args:
        config_data: Dictionary containing configuration data
        merge: If True, update existing values; if False, skip them
        validate_only: If True, validate but don't apply changes
        reason: Reason for the import

    Returns:
        Tuple of (success, message, statistics)
    """
    try:
        # Validate import data structure
        if not isinstance(config_data, dict) or 'settings' not in config_data:
            return False, "Invalid configuration format", {
                "created": 0, "updated": 0, "failed": 0, "skipped": 0
            }

        # Initialize statistics
        stats = {
            "created": 0,
            "updated": 0,
            "failed": 0,
            "skipped": 0
        }

        # Validate configurations first
        validation_changes = {}
        for key, value in config_data['settings'].items():
            # Skip placeholders for sensitive data
            if value == "[REDACTED]" or value == "[ENCRYPTION_ERROR]":
                stats["skipped"] += 1
                continue

            # Check if config exists
            existing = SystemConfig.query.filter_by(key=key).first()
            if existing:
                validation_changes[key] = {
                    'old': existing.value,
                    'new': value
                }
            else:
                validation_changes[key] = {
                    'old': None,
                    'new': value
                }

        # Validate all changes
        validation_result = validate_config(validation_changes)
        if not validation_result['valid']:
            return False, validation_result['message'], stats

        # If validation only, return success without applying changes
        if validate_only:
            return True, f"Validation successful. Would import {len(validation_changes)} configurations", stats

        # Import configurations
        for key, value in config_data['settings'].items():
            try:
                # Skip placeholders for sensitive data
                if value == "[REDACTED]" or value == "[ENCRYPTION_ERROR]":
                    stats["skipped"] += 1
                    continue

                # Determine category and description from metadata if available
                category = 'system'
                description = None

                if 'categories' in config_data:
                    for cat_name, cat_settings in config_data['categories'].items():
                        if key in cat_settings:
                            category = cat_name
                            if 'description' in cat_settings[key]:
                                description = cat_settings[key]['description']

                # Check if config exists
                existing = SystemConfig.query.filter_by(key=key).first()

                if existing and not merge:
                    # Skip existing configs if not merging
                    stats["skipped"] += 1
                    continue

                # Update or create config
                success, message = update_configuration(
                    key=key,
                    value=value,
                    category=category,
                    description=description,
                    reason=reason
                )

                if success:
                    if existing:
                        stats["updated"] += 1
                    else:
                        stats["created"] += 1
                else:
                    stats["failed"] += 1
                    logger.error(f"Failed to import config {key}: {message}")

            except Exception as e:
                stats["failed"] += 1
                logger.error(f"Error importing config {key}: {str(e)}")

        # Create backup of current configuration
        _create_config_backup("pre_import")

        # Log import activity
        _log_config_action('import', {
            'reason': reason,
            'merge': merge,
            'created': stats["created"],
            'updated': stats["updated"],
            'failed': stats["failed"],
            'skipped': stats["skipped"]
        })

        message = (f"Configuration import complete: {stats['created']} created, "
                   f"{stats['updated']} updated, {stats['failed']} failed, "
                   f"{stats['skipped']} skipped")

        metrics.increment('config.import_success')
        return True, message, stats

    except Exception as e:
        logger.error(f"Error importing configuration: {str(e)}")
        metrics.increment('config.import_error')
        return False, f"Error importing configuration: {str(e)}", {
            "created": 0, "updated": 0, "failed": 0, "skipped": 0
        }


def get_configuration(key: str, default: Any = None) -> Any:
    """
    Get a configuration value by key.

    Args:
        key: Configuration key
        default: Default value if config doesn't exist

    Returns:
        Configuration value or default if not found
    """
    # Try to get from cache first
    cached_value = cache.get(f"config:{key}")
    if cached_value is not None:
        return cached_value

    try:
        # Get from database
        config = SystemConfig.query.filter_by(key=key).first()

        if config:
            value = config.value

            # Convert value based on type
            if config.value_type == 'int':
                value = int(value)
            elif config.value_type == 'float':
                value = float(value)
            elif config.value_type == 'bool':
                value = value.lower() in ('true', 'yes', '1')
            elif config.value_type == 'json':
                try:
                    value = json.loads(value)
                except:
                    # If JSON parsing fails, leave as string
                    pass
            elif config.value_type == 'encrypted':
                try:
                    value = decrypt_sensitive_data(value)
                except Exception as e:
                    logger.error(f"Failed to decrypt configuration {key}: {e}")
                    return default

            # Cache the value
            cache.set(f"config:{key}", value, timeout=CONFIG_CACHE_TIMEOUT)
            return value
        else:
            return default

    except Exception as e:
        logger.error(f"Error retrieving configuration {key}: {str(e)}")
        return default


# Helper functions for configuration management

def _validate_config_key(key: str) -> bool:
    """
    Validate that a configuration key has the proper format.

    Args:
        key: Configuration key to validate

    Returns:
        bool: True if key is valid
    """
    # Key should be lowercase, alphanumeric with dots for hierarchy
    # e.g. system.security.session_timeout
    import re
    return bool(re.match(r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$', key))


def _is_sensitive_key(key: str) -> bool:
    """
    Determine if a configuration key contains sensitive information.

    Args:
        key: Configuration key

    Returns:
        bool: True if key is sensitive
    """
    # Check against list of sensitive key patterns
    key_lower = key.lower()

    # Direct match
    if key_lower in SENSITIVE_CONFIG_KEYS:
        return True

    # Pattern match
    for pattern in SENSITIVE_CONFIG_KEYS:
        if '*' in pattern:
            # Convert glob pattern to regex pattern
            regex_pattern = pattern.replace('.', '\.').replace('*', '.*')
            if re.match(regex_pattern, key_lower):
                return True

    # Check for common sensitive keywords
    sensitive_terms = ['password', 'secret', 'key', 'token', 'private', 'credential']
    return any(term in key_lower for term in sensitive_terms)


def _log_config_change(action: str, key: str, old_value: Any, new_value: Any,
                     reason: Optional[str], category: str) -> None:
    """
    Log a configuration change to the audit log.

    Args:
        action: Action performed ('create', 'update', 'delete')
        key: Configuration key
        old_value: Previous value
        new_value: New value
        reason: Reason for the change
        category: Configuration category
    """
    # Mask sensitive values for logging
    is_sensitive = _is_sensitive_key(key)

    if is_sensitive:
        if old_value:
            old_value = "[REDACTED]"
        if new_value:
            new_value = "[REDACTED]"

    # Record in security events log
    severity = "info"
    if "security." in key or is_sensitive:
        severity = "medium"

    log_security_event(
        event_type=f"config_{action}",
        description=f"Configuration {action}: {key}",
        severity=severity,
        user_id=getattr(g, 'user', {}).get('id') if hasattr(g, 'user') else None,
        ip_address=getattr(request, 'remote_addr', None) if 'request' in globals() else None,
        details={
            'key': key,
            'category': category,
            'old_value': old_value,
            'is_sensitive': is_sensitive,
            'reason': reason
        }
    )

    # Track in metrics
    metrics.increment(f'config.{action}')


def _log_config_action(action: str, details: Dict[str, Any]) -> None:
    """
    Log a configuration management action to the audit log.

    Args:
        action: Action performed ('export', 'import', 'backup')
        details: Details about the action
    """
    # Record in security events log
    log_security_event(
        event_type=f"config_{action}",
        description=f"Configuration {action} performed",
        severity="medium",
        user_id=getattr(g, 'user', {}).get('id') if hasattr(g, 'user') else None,
        ip_address=getattr(request, 'remote_addr', None) if 'request' in globals() else None,
        details=details
    )

    # Track in metrics
    metrics.increment(f'config.{action}')


def _create_config_backup(backup_type: str = "manual") -> str:
    """
    Create a backup of the current system configuration.

    Args:
        backup_type: Type of backup ('auto', 'pre_import', 'manual')

    Returns:
        str: Backup filename
    """
    try:
        # Create backup directory if it doesn't exist
        os.makedirs(CONFIG_BACKUP_DIR, exist_ok=True)

        # Export current configuration
        config_data = export_configuration(include_sensitive=True)

        # Create timestamped backup filename
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename = f"config_backup_{backup_type}_{timestamp}.json"
        filepath = os.path.join(CONFIG_BACKUP_DIR, filename)

        # Check if path is safe
        if not is_safe_file_operation(filepath):
            logger.error(f"Unsafe file path for config backup: {filepath}")
            return ""

        # Write backup file
        with open(filepath, 'w') as f:
            json.dump(config_data, f, indent=2)

        # Set secure permissions
        os.chmod(filepath, 0o600)  # rw-------

        # Cleanup old backups
        _cleanup_old_backups()

        logger.info(f"Configuration backup created: {filename}")
        return filename

    except Exception as e:
        logger.error(f"Error creating configuration backup: {str(e)}")
        return ""


def _cleanup_old_backups() -> None:
    """Clean up old configuration backups, keeping only the most recent ones."""
    try:
        # Get all backup files
        backup_dir = Path(CONFIG_BACKUP_DIR)
        if not backup_dir.exists():
            return

        backup_files = list(backup_dir.glob('config_backup_*.json'))

        # Sort by modification time (newest first)
        backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)

        # Keep only the most recent files
        for old_file in backup_files[MAX_BACKUP_FILES:]:
            try:
                old_file.unlink()
                logger.debug(f"Removed old backup file: {old_file.name}")
            except OSError as e:
                logger.error(f"Failed to remove old backup file {old_file.name}: {e}")

    except Exception as e:
        logger.error(f"Error cleaning up old backups: {str(e)}")


# Validator functions for specific config types

def _validate_allowed_hosts(value: Any) -> Dict[str, Any]:
    """Validate allowed hosts configuration."""
    result = {'valid': True, 'message': '', 'warnings': []}

    if not isinstance(value, list):
        try:
            # Try to parse as JSON string
            if isinstance(value, str):
                value = json.loads(value)
                if not isinstance(value, list):
                    result['valid'] = False
                    result['message'] = "Allowed hosts must be a list of domains/IPs"
                    return result
        except:
            result['valid'] = False
            result['message'] = "Allowed hosts must be a list of domains/IPs"
            return result

    # Check for dangerous values
    if '*' in value or '*.*' in value:
        result['valid'] = False
        result['message'] = "Wildcard (*) not allowed in allowed_hosts due to security risks"
        return result

    # Check for overly permissive values
    dangerous_hosts = ['0.0.0.0', '0.0.0.0/0', '::', '::/0']
    for host in dangerous_hosts:
        if host in value:
            result['warnings'].append(f"Potentially insecure host in allowed_hosts: {host}")

    return result


def _validate_csp(value: Any) -> Dict[str, Any]:
    """Validate Content Security Policy configuration."""
    result = {'valid': True, 'message': '', 'warnings': []}

    if not isinstance(value, str):
        result['valid'] = False
        result['message'] = "Content Security Policy must be a string"
        return result

    # Check for unsafe CSP directives
    if "unsafe-inline" in value.lower() or "unsafe-eval" in value.lower():
        result['warnings'].append("CSP contains unsafe directives: unsafe-inline or unsafe-eval")

    # Check for overly permissive sources
    if " * " in value or "'*'" in value:
        result['warnings'].append("CSP contains wildcard source (*) which is overly permissive")

    return result


def _validate_password_policy(value: Any) -> Dict[str, Any]:
    """Validate password policy configuration."""
    result = {'valid': True, 'message': '', 'warnings': []}

    try:
        if isinstance(value, str):
            policy = json.loads(value)
        else:
            policy = value

        if not isinstance(policy, dict):
            result['valid'] = False
            result['message'] = "Password policy must be a dictionary"
            return result

        # Check for minimum requirements
        min_length = policy.get('min_length', 0)
        if min_length < 8:
            result['warnings'].append(f"Password minimum length ({min_length}) is below recommended (8)")

        # Check complexity requirements
        if not policy.get('require_uppercase', True):
            result['warnings'].append("Password policy does not require uppercase characters")
        if not policy.get('require_lowercase', True):
            result['warnings'].append("Password policy does not require lowercase characters")
        if not policy.get('require_numbers', True):
            result['warnings'].append("Password policy does not require numeric characters")
        if not policy.get('require_special', True):
            result['warnings'].append("Password policy does not require special characters")

    except (ValueError, TypeError):
        result['valid'] = False
        result['message'] = "Invalid password policy format"

    return result


def _validate_scheduled_tasks(value: Any) -> Dict[str, Any]:
    """Validate scheduled tasks configuration."""
    result = {'valid': True, 'message': '', 'warnings': []}

    try:
        if isinstance(value, str):
            tasks = json.loads(value)
        else:
            tasks = value

        if not isinstance(tasks, list):
            result['valid'] = False
            result['message'] = "Scheduled tasks must be a list"
            return result

        # Check each task
        for i, task in enumerate(tasks):
            if not isinstance(task, dict):
                result['valid'] = False
                result['message'] = f"Task {i} is not a dictionary"
                return result

            if 'command' not in task:
                result['valid'] = False
                result['message'] = f"Task {i} has no command"
                return result

            # Check for dangerous commands
            cmd = task['command'].lower()
            dangerous_cmds = ['rm -rf', 'sudo', 'chmod 777', 'shell_exec', 'eval(']
            for dangerous in dangerous_cmds:
                if dangerous in cmd:
                    result['valid'] = False
                    result['message'] = f"Task {i} contains potentially dangerous command: {dangerous}"
                    return result

    except (ValueError, TypeError):
        result['valid'] = False
        result['message'] = "Invalid scheduled tasks format"

    return result


def _validate_debug_mode(value: Any) -> Dict[str, Any]:
    """Validate debug mode configuration."""
    result = {'valid': True, 'message': '', 'warnings': []}

    # Convert to boolean for validation
    if isinstance(value, str):
        is_debug = value.lower() in ('true', 'yes', '1')
    else:
        is_debug = bool(value)

    if is_debug:
        result['warnings'].append("Debug mode is enabled, which is not recommended for production environments")

    return result


def _validate_rate_limits(value: Any) -> Dict[str, Any]:
    """Validate API rate limits configuration."""
    result = {'valid': True, 'message': '', 'warnings': []}

    try:
        if isinstance(value, str):
            limits = json.loads(value)
        else:
            limits = value

        if not isinstance(limits, dict):
            result['valid'] = False
            result['message'] = "Rate limits must be a dictionary"
            return result

        # Check for missing required keys
        for endpoint, limit_config in limits.items():
            if not isinstance(limit_config, dict):
                result['valid'] = False
                result['message'] = f"Rate limit for {endpoint} is not a dictionary"
                return result

            if 'limit' not in limit_config or 'period' not in limit_config:
                result['valid'] = False
                result['message'] = f"Rate limit for {endpoint} must include 'limit' and 'period'"
                return result

            # Check for very high limits
            limit = int(limit_config['limit'])
            if limit > 1000:
                result['warnings'].append(f"Very high rate limit ({limit}) for {endpoint}")

    except (ValueError, TypeError):
        result['valid'] = False
        result['message'] = "Invalid rate limits format"

    return result


def _validate_security_config(key: str, value: Any) -> Dict[str, bool]:
    """
    Additional validation for security-specific configurations.

    Args:
        key: Configuration key
        value: Configuration value

    Returns:
        Dictionary with validation result
    """
    result = {'valid': True, 'message': ''}

    # Specific security config validations
    if key == 'security.session_lifetime':
        try:
            lifetime = int(value)
            if lifetime > 86400:  # 24 hours
                result['valid'] = False
                result['message'] = f"Session lifetime too long: {lifetime}s (max 86400s)"
        except (ValueError, TypeError):
            result['valid'] = False
            result['message'] = "Session lifetime must be an integer"

    elif key == 'security.allowed_origins':
        if value == '*':
            result['valid'] = False
            result['message'] = "CORS wildcard (*) not allowed for allowed_origins"

    return result


def _check_dangerous_values(key: str, value: Any) -> Optional[str]:
    """
    Check for potentially dangerous configuration values.

    Args:
        key: Configuration key
        value: Configuration value

    Returns:
        Error message if dangerous, None otherwise
    """
    # Convert value to string for pattern matching
    str_value = str(value).lower()

    # Check for SQL injection patterns
    sql_patterns = ["select", "insert", "update", "delete", "drop", "--"]
    if any(pattern in str_value for pattern in sql_patterns) and not key.startswith('sql.'):
        return f"Potential SQL code detected in non-SQL configuration: {key}"

    # Check for code execution patterns
    code_patterns = ["eval(", "exec(", "system(", "subprocess", "os.system"]
    if any(pattern in str_value for pattern in code_patterns):
        return f"Potential code execution detected in configuration: {key}"

    # Check for file path traversal
    path_traversal = ["../", "..\\", "/etc/passwd", "/etc/shadow"]
    if any(pattern in str_value for pattern in path_traversal):
        return f"Potential path traversal detected in configuration: {key}"

    return None
