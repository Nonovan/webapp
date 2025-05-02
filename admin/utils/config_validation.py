"""
Configuration Validation Utilities for Administrative Tools.

This module provides utilities for validating configuration values against
defined schemas and rules. It supports JSON Schema validation, type checking,
and custom validation rules for configuration files used by administrative
tools and scripts.

The module works in conjunction with system_configuration.py and other admin
utilities to ensure configuration consistency and correctness.
"""

import os
import json
import logging
import re
import toml
import yaml
import hashlib
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, NamedTuple, Set, Callable
from jsonschema import validate, ValidationError as JsonSchemaValidationError, FormatChecker

try:
    from core.loggings import get_logger
    logger = get_logger(__name__)
except ImportError:
    # Fallback basic logger if core logging is unavailable
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.warning("Core logging module not found, using basic logging.")


class ValidationErrorType(Enum):
    """Types of validation errors that can occur."""
    TYPE_ERROR = "type_error"
    VALUE_ERROR = "value_error"
    RANGE_ERROR = "range_error"
    PATTERN_ERROR = "pattern_error"
    REQUIRED_ERROR = "required_error"
    FORMAT_ERROR = "format_error"
    SCHEMA_ERROR = "schema_error"
    DEPENDENCY_ERROR = "dependency_error"
    CONSTRAINT_ERROR = "constraint_error"
    SECURITY_ERROR = "security_error"
    REFERENCE_ERROR = "reference_error"
    OTHER_ERROR = "other_error"


class ValidationError(NamedTuple):
    """Structured validation error information."""
    path: str
    message: str
    error_type: ValidationErrorType
    constraint_value: Any = None


class ValidationResult(NamedTuple):
    """Result of a validation operation."""
    is_valid: bool
    errors: List[ValidationError]


# Constants for file format and schema handling
SUPPORTED_CONFIG_FORMATS = {
    '.json': 'json',
    '.yaml': 'yaml',
    '.yml': 'yaml',
    '.toml': 'toml',
    '.ini': 'ini',
    '.conf': 'ini',
    '.properties': 'properties'
}

# Constants for security validation
SECURE_ALGORITHM_PATTERNS = {
    'hash': r'(sha2|sha3|sha-2|sha-3|sha256|sha384|sha512)',
    'encryption': r'(aes256|aes-256|aes-gcm|chacha20|xchacha20)',
    'hmac': r'(hmac-sha2|hmac-sha256|hmac-sha384|hmac-sha512)',
    'insecure': r'(md5|sha1|des|3des|rc4|ecb)',
}

# Common paths for schema files for different configuration types
SCHEMA_TYPE_PATHS = {
    'system': ['admin/schemas/system', 'config/schemas/system'],
    'security': ['admin/schemas/security', 'config/schemas/security'],
    'api': ['admin/schemas/api', 'config/schemas/api'],
    'feature': ['admin/schemas/features', 'config/schemas/features'],
}


def load_schema(schema_name: str) -> Dict[str, Any]:
    """
    Loads a JSON schema from the schema directory.

    The schema can be specified either as a full path or as a name
    which will be resolved against standard schema locations.

    Args:
        schema_name: Name of the schema to load or full path to schema file

    Returns:
        Schema as a dictionary

    Raises:
        FileNotFoundError: If schema cannot be found
        json.JSONDecodeError: If schema is not valid JSON
    """
    # If this is a full path, use it directly
    if os.path.isfile(schema_name):
        schema_path = schema_name
    else:
        # Otherwise look in standard locations
        search_paths = [
            # First check current directory
            os.path.join(os.getcwd(), f"{schema_name}.json"),
            # Then project config schemas directory
            os.path.join(os.getcwd(), "config", "schemas", f"{schema_name}.json"),
            # Then admin schemas directory
            os.path.join(os.getcwd(), "admin", "schemas", f"{schema_name}.json"),
            # Then etc schemas directory
            os.path.join("/etc/cloud-platform/schemas", f"{schema_name}.json"),
        ]

        # Check type-specific paths
        for schema_type, paths in SCHEMA_TYPE_PATHS.items():
            if schema_name.startswith(f"{schema_type}_"):
                for path in paths:
                    search_paths.append(os.path.join(os.getcwd(), path, f"{schema_name}.json"))

        # Try to find the schema
        for path in search_paths:
            if os.path.isfile(path):
                schema_path = path
                break
        else:
            raise FileNotFoundError(f"Schema '{schema_name}' not found in any of the standard locations")

    # Load the schema
    with open(schema_path, 'r') as f:
        schema = json.load(f)

    logger.debug(f"Loaded schema from {schema_path}")
    return schema


def validate_config(config: Dict[str, Any], schema: Dict[str, Any]) -> ValidationResult:
    """
    Validates a configuration dictionary against a JSON schema.

    Args:
        config: Configuration dictionary to validate
        schema: JSON schema to validate against

    Returns:
        ValidationResult containing validation status and any errors
    """
    errors = []

    try:
        # Perform JSON Schema validation
        validate(instance=config, schema=schema, format_checker=FormatChecker())
        logger.debug("Configuration passed schema validation")
        return ValidationResult(is_valid=True, errors=[])

    except JsonSchemaValidationError as e:
        # Convert JSON Schema error to our format
        error_type = _map_json_schema_error_type(e)

        # Format the path as a string
        path = ".".join(str(p) for p in e.path) if e.path else "root"

        # Create a validation error
        error = ValidationError(
            path=path,
            message=e.message,
            error_type=error_type,
            constraint_value=e.validator_value if hasattr(e, 'validator_value') else None
        )
        errors.append(error)

        logger.warning(f"Schema validation failed: {error.message} at {error.path}")
        return ValidationResult(is_valid=False, errors=errors)


def validate_config_value(value: Any, rules: Dict[str, Any]) -> ValidationResult:
    """
    Validates a single configuration value against rules.

    This is useful for validating dynamic configuration values that
    don't have a fixed schema.

    Args:
        value: The configuration value to validate
        rules: Dictionary of validation rules to apply

    Returns:
        ValidationResult containing validation status and any errors

    Example rules:
        {
            "type": "string",
            "minLength": 8,
            "pattern": "^[A-Za-z0-9]+$"
        }
    """
    errors = []

    # Create a simple schema for this value
    schema = {
        "type": "object",
        "properties": {
            "value": rules
        },
        "required": ["value"]
    }

    # Validate using the schema
    try:
        validate({"value": value}, schema, format_checker=FormatChecker())
        return ValidationResult(is_valid=True, errors=[])

    except JsonSchemaValidationError as e:
        # Remove the "value." prefix from the path
        path_parts = list(e.path)
        if path_parts and path_parts[0] == "value":
            path_parts = path_parts[1:]

        path = ".".join(str(p) for p in path_parts) if path_parts else "value"

        error_type = _map_json_schema_error_type(e)
        error = ValidationError(
            path=path,
            message=e.message,
            error_type=error_type,
            constraint_value=e.validator_value if hasattr(e, 'validator_value') else None
        )
        errors.append(error)

        logger.warning(f"Value validation failed: {error.message}")
        return ValidationResult(is_valid=False, errors=errors)


def validate_config_file(file_path: str, schema_path: Optional[str] = None) -> ValidationResult:
    """
    Validates a configuration file against a schema.

    Args:
        file_path: Path to the configuration file
        schema_path: Optional path to the schema file (if not provided, will
                    attempt to infer from file name)

    Returns:
        ValidationResult containing validation status and any errors
    """
    file_path = os.path.abspath(file_path)

    # Determine file type and load accordingly
    _, ext = os.path.splitext(file_path)
    file_format = SUPPORTED_CONFIG_FORMATS.get(ext.lower())

    if not file_format:
        return ValidationResult(
            is_valid=False,
            errors=[ValidationError(
                path="file",
                message=f"Unsupported file format: {ext}",
                error_type=ValidationErrorType.OTHER_ERROR
            )]
        )

    # Load the config file
    try:
        config = _load_config_file(file_path, file_format)
    except Exception as e:
        return ValidationResult(
            is_valid=False,
            errors=[ValidationError(
                path="file",
                message=f"Failed to parse {file_format} configuration file: {str(e)}",
                error_type=ValidationErrorType.OTHER_ERROR
            )]
        )

    # If schema_path is not provided, try to infer it
    if not schema_path:
        file_name = os.path.splitext(os.path.basename(file_path))[0]
        try:
            schema = load_schema(file_name)
        except FileNotFoundError as e:
            return ValidationResult(
                is_valid=False,
                errors=[ValidationError(
                    path="schema",
                    message=f"Could not find schema for {file_name}: {str(e)}",
                    error_type=ValidationErrorType.OTHER_ERROR
                )]
            )
    else:
        try:
            schema = load_schema(schema_path)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            return ValidationResult(
                is_valid=False,
                errors=[ValidationError(
                    path="schema",
                    message=f"Failed to load schema: {str(e)}",
                    error_type=ValidationErrorType.OTHER_ERROR
                )]
            )

    # Perform validation
    return validate_config(config, schema)


def validate_sensitive_settings(config: Dict[str, Any]) -> ValidationResult:
    """
    Validates that sensitive configuration settings meet security requirements.

    Checks for things like minimum password complexity, secure defaults,
    and other security best practices.

    Args:
        config: Configuration dictionary to validate

    Returns:
        ValidationResult containing validation status and any errors
    """
    errors = []

    # List of security checks to perform
    security_checks = [
        # Check for development/testing settings in production
        {
            "check": lambda c: c.get("debug", False) is True,
            "error": ValidationError(
                path="debug",
                message="Debug mode should be disabled in production",
                error_type=ValidationErrorType.SECURITY_ERROR
            )
        },
        # Check TLS version if specified
        {
            "check": lambda c: c.get("min_tls_version") is not None and float(c.get("min_tls_version", "1.2")) < 1.2,
            "error": ValidationError(
                path="min_tls_version",
                message="Minimum TLS version should be at least 1.2",
                error_type=ValidationErrorType.SECURITY_ERROR
            )
        },
        # Check password policy
        {
            "check": lambda c: c.get("password_min_length") is not None and int(c.get("password_min_length", "12")) < 12,
            "error": ValidationError(
                path="password_min_length",
                message="Password minimum length should be at least 12 characters",
                error_type=ValidationErrorType.SECURITY_ERROR
            )
        },
        # Check session timeout
        {
            "check": lambda c: c.get("session_timeout_minutes") is not None and int(c.get("session_timeout_minutes", "60")) > 60,
            "error": ValidationError(
                path="session_timeout_minutes",
                message="Session timeout should not exceed 60 minutes for security",
                error_type=ValidationErrorType.SECURITY_ERROR
            )
        },
        # Check plain text credentials in connection strings
        {
            "check": lambda c: any(k for k in c if "url" in k.lower() and "://" in str(c[k]) and "@" in str(c[k])),
            "error": ValidationError(
                path="connection_strings",
                message="Connection strings should not contain credentials",
                error_type=ValidationErrorType.SECURITY_ERROR
            )
        },
        # Check CSRF protection
        {
            "check": lambda c: c.get("csrf_protection", True) is False,
            "error": ValidationError(
                path="csrf_protection",
                message="CSRF protection should not be disabled",
                error_type=ValidationErrorType.SECURITY_ERROR
            )
        },
        # Check for insecure hash algorithms
        {
            "check": lambda c: _check_insecure_algorithm(c),
            "error": ValidationError(
                path="algorithms",
                message="Insecure cryptographic algorithms detected (MD5, SHA1, DES, etc.)",
                error_type=ValidationErrorType.SECURITY_ERROR
            )
        },
        # Check for secure defaults on cookie settings
        {
            "check": lambda c: c.get("secure_cookies", True) is False,
            "error": ValidationError(
                path="secure_cookies",
                message="Secure cookies should be enabled",
                error_type=ValidationErrorType.SECURITY_ERROR
            )
        },
        # Check for HTTP-only cookies
        {
            "check": lambda c: c.get("http_only_cookies", True) is False,
            "error": ValidationError(
                path="http_only_cookies",
                message="HTTP-only cookies should be enabled",
                error_type=ValidationErrorType.SECURITY_ERROR
            )
        }
    ]

    # Run all security checks
    for check in security_checks:
        try:
            if check["check"](config):
                errors.append(check["error"])
        except (ValueError, TypeError, KeyError) as e:
            # Skip checks that fail due to missing or invalid data
            logger.debug(f"Security check skipped due to error: {e}")
            pass

    return ValidationResult(
        is_valid=len(errors) == 0,
        errors=errors
    )


def validate_environment_config(config: Dict[str, Any], environment: str) -> ValidationResult:
    """
    Validates configuration for a specific environment.

    Applies environment-specific rules and requirements.

    Args:
        config: Configuration dictionary to validate
        environment: Target environment (e.g., 'development', 'production')

    Returns:
        ValidationResult containing validation status and any errors
    """
    errors = []

    # Production environments have stricter requirements
    if environment.lower() in ['production', 'staging', 'dr-recovery']:
        # Ensure debug mode is disabled
        if config.get('debug', False) or config.get('debug_mode', False):
            errors.append(ValidationError(
                path="debug",
                message=f"Debug mode must be disabled in {environment} environment",
                error_type=ValidationErrorType.SECURITY_ERROR
            ))

        # Check for secure settings
        if not config.get('enforce_ssl', True):
            errors.append(ValidationError(
                path="enforce_ssl",
                message=f"SSL enforcement must be enabled in {environment} environment",
                error_type=ValidationErrorType.SECURITY_ERROR
            ))

        # Check for proper logging level
        log_level = str(config.get('log_level', '')).lower()
        if log_level == 'debug':
            errors.append(ValidationError(
                path="log_level",
                message=f"Debug logging should not be used in {environment} environment",
                error_type=ValidationErrorType.SECURITY_ERROR
            ))

        # Check that file integrity monitoring is enabled
        if config.get('file_integrity_monitoring', True) is False:
            errors.append(ValidationError(
                path="file_integrity_monitoring",
                message=f"File integrity monitoring should be enabled in {environment} environment",
                error_type=ValidationErrorType.SECURITY_ERROR
            ))

        # Check that automatic updates are disabled
        if config.get('auto_update', False) is True:
            errors.append(ValidationError(
                path="auto_update",
                message=f"Auto-update should be disabled in {environment} environment and managed through CI/CD",
                error_type=ValidationErrorType.SECURITY_ERROR
            ))

        # Check that rate limiting is enabled for APIs
        if config.get('api_rate_limiting', True) is False:
            errors.append(ValidationError(
                path="api_rate_limiting",
                message=f"API rate limiting should be enabled in {environment} environment",
                error_type=ValidationErrorType.SECURITY_ERROR
            ))

        # Check that audit logging is enabled
        if config.get('audit_logging', True) is False:
            errors.append(ValidationError(
                path="audit_logging",
                message=f"Audit logging must be enabled in {environment} environment",
                error_type=ValidationErrorType.SECURITY_ERROR
            ))

        # Check minimum audit log retention period
        if config.get('audit_log_retention_days', 90) < 90:
            errors.append(ValidationError(
                path="audit_log_retention_days",
                message=f"Audit log retention should be at least 90 days in {environment} environment",
                error_type=ValidationErrorType.SECURITY_ERROR
            ))

    return ValidationResult(
        is_valid=len(errors) == 0,
        errors=errors
    )


def validate_config_references(config: Dict[str, Any], reference_config: Dict[str, Any],
                              reference_fields: Dict[str, str]) -> ValidationResult:
    """
    Validates references between configuration settings.

    Checks that referenced values exist in the reference configuration.

    Args:
        config: Configuration dictionary to validate
        reference_config: Dictionary containing reference values
        reference_fields: Map of field names to reference paths

    Returns:
        ValidationResult containing validation status and any errors
    """
    errors = []

    for field_name, ref_path in reference_fields.items():
        if field_name not in config:
            continue

        field_value = config[field_name]
        if isinstance(field_value, list):
            # Validate list of references
            for i, item in enumerate(field_value):
                if not _check_reference_exists(item, reference_config, ref_path):
                    errors.append(ValidationError(
                        path=f"{field_name}[{i}]",
                        message=f"Referenced value '{item}' does not exist in {ref_path}",
                        error_type=ValidationErrorType.REFERENCE_ERROR
                    ))
        else:
            # Validate single reference
            if not _check_reference_exists(field_value, reference_config, ref_path):
                errors.append(ValidationError(
                    path=field_name,
                    message=f"Referenced value '{field_value}' does not exist in {ref_path}",
                    error_type=ValidationErrorType.REFERENCE_ERROR
                ))

    return ValidationResult(
        is_valid=len(errors) == 0,
        errors=errors
    )


def validate_file_integrity(file_path: str, expected_hash: Optional[str] = None,
                           algorithm: str = "sha256") -> ValidationResult:
    """
    Validates the integrity of a configuration file.

    Args:
        file_path: Path to the configuration file
        expected_hash: Expected hash value (if None, just returns current hash)
        algorithm: Hash algorithm to use (sha256, sha384, sha512)

    Returns:
        ValidationResult containing validation status and any errors
    """
    if not os.path.exists(file_path):
        return ValidationResult(
            is_valid=False,
            errors=[ValidationError(
                path="file",
                message=f"File does not exist: {file_path}",
                error_type=ValidationErrorType.OTHER_ERROR
            )]
        )

    try:
        # Calculate file hash
        file_hash = _calculate_file_hash(file_path, algorithm)

        # If no expected hash provided, just return success with current hash
        if expected_hash is None:
            return ValidationResult(
                is_valid=True,
                errors=[]
            )

        # Compare with expected hash
        if file_hash.lower() == expected_hash.lower():
            return ValidationResult(
                is_valid=True,
                errors=[]
            )
        else:
            return ValidationResult(
                is_valid=False,
                errors=[ValidationError(
                    path="file",
                    message=f"File integrity check failed. Expected: {expected_hash}, Got: {file_hash}",
                    error_type=ValidationErrorType.SECURITY_ERROR
                )]
            )
    except Exception as e:
        return ValidationResult(
            is_valid=False,
            errors=[ValidationError(
                path="file",
                message=f"Error checking file integrity: {str(e)}",
                error_type=ValidationErrorType.OTHER_ERROR
            )]
        )


def validate_with_rules(value: Any, rules: List[Dict[str, Any]]) -> ValidationResult:
    """
    Validates a value using custom rule-based validation.

    This allows more complex conditional validation logic than JSON Schema.

    Args:
        value: Value to validate
        rules: List of validation rule definitions

    Returns:
        ValidationResult containing validation status and any errors

    Example rules:
        [
            {
                "type": "string",
                "min_length": 8,
                "condition": "value.startswith('https://')",
                "error": "URL must use HTTPS protocol"
            }
        ]
    """
    errors = []

    for rule in rules:
        rule_type = rule.get("type")

        # Skip rule if condition is not met
        if "condition" in rule:
            condition = rule["condition"]
            try:
                # Use safe evaluation of condition with value in locals
                condition_met = eval(condition, {"__builtins__": {}}, {"value": value})
                if not condition_met:
                    continue
            except Exception as e:
                logger.warning(f"Error evaluating condition '{condition}': {e}")
                continue

        # Type validation
        if rule_type == "string" and not isinstance(value, str):
            errors.append(ValidationError(
                path="value",
                message=f"Value must be a string",
                error_type=ValidationErrorType.TYPE_ERROR
            ))
            continue

        elif rule_type == "number" and not isinstance(value, (int, float)):
            errors.append(ValidationError(
                path="value",
                message=f"Value must be a number",
                error_type=ValidationErrorType.TYPE_ERROR
            ))
            continue

        elif rule_type == "boolean" and not isinstance(value, bool):
            errors.append(ValidationError(
                path="value",
                message=f"Value must be a boolean",
                error_type=ValidationErrorType.TYPE_ERROR
            ))
            continue

        # String validations
        if isinstance(value, str):
            if "min_length" in rule and len(value) < rule["min_length"]:
                errors.append(ValidationError(
                    path="value",
                    message=f"String length must be at least {rule['min_length']} characters",
                    error_type=ValidationErrorType.RANGE_ERROR
                ))

            if "max_length" in rule and len(value) > rule["max_length"]:
                errors.append(ValidationError(
                    path="value",
                    message=f"String length must not exceed {rule['max_length']} characters",
                    error_type=ValidationErrorType.RANGE_ERROR
                ))

            if "pattern" in rule:
                pattern = rule["pattern"]
                if not re.match(pattern, value):
                    errors.append(ValidationError(
                        path="value",
                        message=rule.get("error") or f"Value does not match pattern: {pattern}",
                        error_type=ValidationErrorType.PATTERN_ERROR
                    ))

            if "enum" in rule and value not in rule["enum"]:
                errors.append(ValidationError(
                    path="value",
                    message=f"Value must be one of: {', '.join(str(v) for v in rule['enum'])}",
                    error_type=ValidationErrorType.CONSTRAINT_ERROR
                ))

        # Number validations
        if isinstance(value, (int, float)):
            if "min" in rule and value < rule["min"]:
                errors.append(ValidationError(
                    path="value",
                    message=f"Value must be at least {rule['min']}",
                    error_type=ValidationErrorType.RANGE_ERROR
                ))

            if "max" in rule and value > rule["max"]:
                errors.append(ValidationError(
                    path="value",
                    message=f"Value must not exceed {rule['max']}",
                    error_type=ValidationErrorType.RANGE_ERROR
                ))

        # Custom error message
        if "error" in rule and not errors:
            errors.append(ValidationError(
                path="value",
                message=rule["error"],
                error_type=ValidationErrorType.CONSTRAINT_ERROR
            ))

    return ValidationResult(
        is_valid=len(errors) == 0,
        errors=errors
    )


def format_validation_errors(errors: List[ValidationError], format_type: str = 'text') -> str:
    """
    Formats validation errors for display or logging.

    Args:
        errors: List of ValidationError objects
        format_type: Output format ('text', 'json', 'html', or 'markdown')

    Returns:
        Formatted error string
    """
    if format_type == 'json':
        import json
        error_dicts = [
            {
                'path': e.path,
                'message': e.message,
                'error_type': e.error_type.value,
                'constraint_value': e.constraint_value
            }
            for e in errors
        ]
        return json.dumps(error_dicts, indent=2)

    elif format_type == 'html':
        html_parts = ['<ul class="validation-errors">']
        for error in errors:
            severity_class = "severe" if error.error_type == ValidationErrorType.SECURITY_ERROR else ""
            html_parts.append(f'<li class="error-item error-{error.error_type.value} {severity_class}">')
            html_parts.append(f'<strong>{error.path}</strong>: {error.message}')
            html_parts.append('</li>')
        html_parts.append('</ul>')
        return ''.join(html_parts)

    elif format_type == 'markdown':
        md_parts = ['# Validation Errors\n']
        for error in errors:
            icon = "🔴" if error.error_type == ValidationErrorType.SECURITY_ERROR else "⚠️"
            md_parts.append(f"{icon} **{error.path}**: {error.message}  ")
        return '\n'.join(md_parts)

    else: # Default to text format
        text_parts = []
        for error in errors:
            prefix = "[SECURITY] " if error.error_type == ValidationErrorType.SECURITY_ERROR else ""
            text_parts.append(f"{prefix}{error.path}: {error.message}")
        return '\n'.join(text_parts)


def get_hashable_config(config: Dict[str, Any]) -> str:
    """
    Converts a configuration dictionary to a stable string representation
    that can be hashed consistently.

    Useful for configuration fingerprinting and change detection.

    Args:
        config: Configuration dictionary

    Returns:
        String representation suitable for hashing
    """
    import json

    # Sort keys to ensure consistent ordering
    return json.dumps(config, sort_keys=True, ensure_ascii=True)


def calculate_config_hash(config: Dict[str, Any], algorithm: str = "sha256") -> str:
    """
    Calculates a hash of the configuration for integrity checking.

    Args:
        config: Configuration dictionary
        algorithm: Hash algorithm to use

    Returns:
        Hexadecimal hash string
    """
    hash_str = get_hashable_config(config)

    if algorithm == "sha256":
        return hashlib.sha256(hash_str.encode('utf-8')).hexdigest()
    elif algorithm == "sha384":
        return hashlib.sha384(hash_str.encode('utf-8')).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(hash_str.encode('utf-8')).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


# --- Helper functions ---

def _load_config_file(file_path: str, file_format: str) -> Dict[str, Any]:
    """
    Loads a configuration file based on its format.

    Args:
        file_path: Path to configuration file
        file_format: Format of the file (json, yaml, etc.)

    Returns:
        Configuration as dictionary

    Raises:
        Exception: If file cannot be loaded or parsed
    """
    with open(file_path, 'r') as f:
        if file_format == 'json':
            return json.load(f)
        elif file_format == 'yaml':
            return yaml.safe_load(f)
        elif file_format == 'toml':
            try:
                import tomli
                return tomli.load(f)
            except ImportError:
                try:
                    return toml.load(f)
                except ImportError:
                    raise ImportError("No TOML parser available. Install tomli or toml package.")
        elif file_format == 'ini':
            import configparser
            config = configparser.ConfigParser()
            config.read(file_path)
            # Convert to dictionary
            result = {}
            for section in config.sections():
                result[section] = {}
                for key, value in config.items(section):
                    result[section][key] = value
            return result
        elif file_format == 'properties':
            # Simple properties file parser
            result = {}
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, value = line.split('=', 1)
                    result[key.strip()] = value.strip()
            return result
        else:
            raise ValueError(f"Unsupported file format: {file_format}")


def _check_reference_exists(value: Any, reference_config: Dict[str, Any], ref_path: str) -> bool:
    """
    Checks if a referenced value exists in the reference configuration.

    Args:
        value: Referenced value to check
        reference_config: Dictionary containing reference values
        ref_path: Path to reference container (dot notation)

    Returns:
        True if reference exists, False otherwise
    """
    current = reference_config
    path_parts = ref_path.split('.')

    # Navigate to the container
    for part in path_parts:
        if part not in current:
            return False
        current = current[part]

    # Check if value exists in the container
    if isinstance(current, dict):
        return value in current
    elif isinstance(current, list):
        return value in current
    else:
        return False


def _calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """
    Calculates the hash of a file.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use

    Returns:
        Hexadecimal hash string
    """
    hash_func = getattr(hashlib, algorithm)()
    with open(file_path, "rb") as f:
        # Read in chunks to handle large files
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()


def _check_insecure_algorithm(config: Dict[str, Any]) -> bool:
    """
    Checks for references to insecure cryptographic algorithms in the configuration.

    Args:
        config: Configuration dictionary

    Returns:
        True if insecure algorithms are found, False otherwise
    """
    # Convert config to string for pattern matching
    config_str = str(config).lower()

    # Check for insecure algorithms
    insecure_pattern = SECURE_ALGORITHM_PATTERNS['insecure']
    return bool(re.search(insecure_pattern, config_str))


def _map_json_schema_error_type(error: JsonSchemaValidationError) -> ValidationErrorType:
    """
    Maps JSON Schema validation error to our error type enum.

    Args:
        error: The JSON Schema validation error

    Returns:
        Corresponding ValidationErrorType
    """
    validator = error.validator

    if validator == 'type':
        return ValidationErrorType.TYPE_ERROR
    elif validator == 'required':
        return ValidationErrorType.REQUIRED_ERROR
    elif validator in ('minLength', 'maxLength', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum'):
        return ValidationErrorType.RANGE_ERROR
    elif validator == 'pattern':
        return ValidationErrorType.PATTERN_ERROR
    elif validator == 'format':
        return ValidationErrorType.FORMAT_ERROR
    elif validator == 'dependencies':
        return ValidationErrorType.DEPENDENCY_ERROR
    elif validator in ('enum', 'const', 'multipleOf'):
        return ValidationErrorType.CONSTRAINT_ERROR
    elif validator == '$ref':
        return ValidationErrorType.REFERENCE_ERROR
    elif validator == 'properties' and 'secure' in str(error.message).lower():
        return ValidationErrorType.SECURITY_ERROR
    else:
        return ValidationErrorType.OTHER_ERROR


def validate_configuration_integrity(config: Dict[str, Any], schema_path: Optional[str] = None,
                                    environment: Optional[str] = None) -> ValidationResult:
    """
    Comprehensively validates a configuration for integrity, security, and environment compliance.

    Combines multiple validation methods for a thorough check.

    Args:
        config: Configuration dictionary to validate
        schema_path: Path to schema file (optional)
        environment: Target environment (optional)

    Returns:
        ValidationResult from all validations combined
    """
    all_errors = []

    # 1. Schema validation
    if schema_path:
        try:
            schema = load_schema(schema_path)
            schema_result = validate_config(config, schema)
            all_errors.extend(schema_result.errors)
        except Exception as e:
            all_errors.append(ValidationError(
                path="schema",
                message=f"Schema validation error: {str(e)}",
                error_type=ValidationErrorType.SCHEMA_ERROR
            ))

    # 2. Security validation
    security_result = validate_sensitive_settings(config)
    all_errors.extend(security_result.errors)

    # 3. Environment-specific validation
    if environment:
        env_result = validate_environment_config(config, environment)
        all_errors.extend(env_result.errors)

    return ValidationResult(
        is_valid=len(all_errors) == 0,
        errors=all_errors
    )


if __name__ == '__main__':
    # Example usage
    import argparse

    parser = argparse.ArgumentParser(description='Validate configuration files')
    parser.add_argument('file', help='Path to configuration file')
    parser.add_argument('--schema', help='Path to schema file', default=None)
    parser.add_argument('--environment', help='Target environment', default=None)
    parser.add_argument('--format', choices=['text', 'json', 'html', 'markdown'],
                        help='Output format', default='text')
    parser.add_argument('--security-only', action='store_true',
                        help='Only perform security validation')
    parser.add_argument('--verify-hash', help='Verify file integrity against this hash')

    args = parser.parse_args()

    # Load the configuration
    try:
        _, ext = os.path.splitext(args.file)
        file_format = SUPPORTED_CONFIG_FORMATS.get(ext.lower(), 'json')
        config = _load_config_file(args.file, file_format)
    except Exception as e:
        print(f"Error loading configuration file: {e}")
        sys.exit(1)

    if args.verify_hash:
        # Check file integrity
        integrity_result = validate_file_integrity(args.file, args.verify_hash)
        if not integrity_result.is_valid:
            print(format_validation_errors(integrity_result.errors, args.format))
            sys.exit(1)
        else:
            print(f"File integrity verified: {args.file}")

    if args.security_only:
        # Security validation only
        result = validate_sensitive_settings(config)
    else:
        # Full validation
        result = validate_configuration_integrity(config, args.schema, args.environment)

    if result.is_valid:
        print("✅ Configuration is valid.")

        # Print hash for future integrity checks
        file_hash = _calculate_file_hash(args.file)
        print(f"File hash (SHA-256): {file_hash}")
    else:
        print("❌ Configuration validation failed:")
        print(format_validation_errors(result.errors, args.format))
        sys.exit(1)
