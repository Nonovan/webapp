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
import yaml
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, NamedTuple
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

    # Load the config file
    try:
        with open(file_path, 'r') as f:
            if ext.lower() in ['.json']:
                config = json.load(f)
            elif ext.lower() in ['.yaml', '.yml']:
                config = yaml.safe_load(f)
            else:
                return ValidationResult(
                    is_valid=False,
                    errors=[ValidationError(
                        path="file",
                        message=f"Unsupported file format: {ext}",
                        error_type=ValidationErrorType.OTHER_ERROR
                    )]
                )
    except (IOError, json.JSONDecodeError, yaml.YAMLError) as e:
        return ValidationResult(
            is_valid=False,
            errors=[ValidationError(
                path="file",
                message=f"Failed to parse configuration file: {str(e)}",
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
                error_type=ValidationErrorType.CONSTRAINT_ERROR
            )
        },
        # Check TLS version if specified
        {
            "check": lambda c: c.get("min_tls_version") is not None and float(c.get("min_tls_version", "1.2")) < 1.2,
            "error": ValidationError(
                path="min_tls_version",
                message="Minimum TLS version should be at least 1.2",
                error_type=ValidationErrorType.CONSTRAINT_ERROR
            )
        },
        # Check password policy
        {
            "check": lambda c: c.get("password_min_length") is not None and int(c.get("password_min_length", "12")) < 12,
            "error": ValidationError(
                path="password_min_length",
                message="Password minimum length should be at least 12 characters",
                error_type=ValidationErrorType.CONSTRAINT_ERROR
            )
        },
        # Check session timeout
        {
            "check": lambda c: c.get("session_timeout_minutes") is not None and int(c.get("session_timeout_minutes", "60")) > 60,
            "error": ValidationError(
                path="session_timeout_minutes",
                message="Session timeout should not exceed 60 minutes for security",
                error_type=ValidationErrorType.CONSTRAINT_ERROR
            )
        },
        # Check plain text credentials in connection strings
        {
            "check": lambda c: any(k for k in c if "url" in k.lower() and "://" in str(c[k]) and "@" in str(c[k])),
            "error": ValidationError(
                path="connection_strings",
                message="Connection strings should not contain credentials",
                error_type=ValidationErrorType.CONSTRAINT_ERROR
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
    if environment.lower() in ['production', 'dr-recovery']:
        # Ensure debug mode is disabled
        if config.get('debug', False) or config.get('debug_mode', False):
            errors.append(ValidationError(
                path="debug",
                message=f"Debug mode must be disabled in {environment} environment",
                error_type=ValidationErrorType.CONSTRAINT_ERROR
            ))

        # Check for secure settings
        if not config.get('enforce_ssl', True):
            errors.append(ValidationError(
                path="enforce_ssl",
                message=f"SSL enforcement must be enabled in {environment} environment",
                error_type=ValidationErrorType.CONSTRAINT_ERROR
            ))

        # Check for proper logging level
        log_level = str(config.get('log_level', '')).lower()
        if log_level == 'debug':
            errors.append(ValidationError(
                path="log_level",
                message=f"Debug logging should not be used in {environment} environment",
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
        format_type: Output format ('text', 'json', or 'html')

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
            html_parts.append(f'<li class="error-item error-{error.error_type.value}">')
            html_parts.append(f'<strong>{error.path}</strong>: {error.message}')
            html_parts.append('</li>')
        html_parts.append('</ul>')
        return ''.join(html_parts)

    else: # Default to text format
        text_parts = []
        for error in errors:
            text_parts.append(f"{error.path}: {error.message}")
        return '\n'.join(text_parts)


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
    else:
        return ValidationErrorType.OTHER_ERROR


if __name__ == '__main__':
    # Example usage
    import argparse

    parser = argparse.ArgumentParser(description='Validate configuration files')
    parser.add_argument('file', help='Path to configuration file')
    parser.add_argument('--schema', help='Path to schema file', default=None)
    args = parser.parse_args()

    result = validate_config_file(args.file, args.schema)

    if result.is_valid:
        print("Configuration is valid.")
    else:
        print("Configuration validation failed:")
        print(format_validation_errors(result.errors))
