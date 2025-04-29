"""
Input validation utilities for security assessment tools.

This module provides standardized validation functions for inputs used
across the security assessment tools, ensuring consistent and secure
parameter handling, preventing injection attacks, and validating
assessment-specific parameters and configurations.
"""

import ipaddress
import logging
import os
import re
import socket
import uuid
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union, cast
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Validation constants
MAX_STRING_LENGTH = 1024
VALID_OUTPUT_FORMATS = {"standard", "json", "csv", "xml", "html", "detailed", "markdown", "pdf", "sarif"}
VALID_COMPLIANCE_FRAMEWORKS = {
    "pci-dss", "hipaa", "gdpr", "iso27001", "nist-csf", "nist-800-53",
    "soc2", "cis", "owasp-asvs", "fedramp", "ccpa"
}

# Regular expressions for validation
HOSTNAME_REGEX = r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
UUID_REGEX = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
IDENTIFIER_REGEX = r"^[a-zA-Z0-9_\-\.]+$"
PATH_TRAVERSAL_REGEX = r"(\.\.[\\/]|^[\\/]|~)"
UNSAFE_CHARS_REGEX = r"[;&|<>$\\`'\"\*\?\[\]\(\)\{\}\s]"


class ValidationError(Exception):
    """Exception raised for validation errors."""
    pass


def sanitize_input(value: str) -> str:
    """
    Sanitize input string by removing potentially dangerous characters.

    Args:
        value: Input string to sanitize

    Returns:
        Sanitized string
    """
    if not isinstance(value, str):
        return str(value)

    # Replace unsafe characters with underscores
    sanitized = re.sub(UNSAFE_CHARS_REGEX, "_", value)
    return sanitized


def validate_string(value: Any, min_length: int = 1, max_length: int = MAX_STRING_LENGTH,
                   allow_empty: bool = False, pattern: Optional[str] = None) -> str:
    """
    Validate a string input.

    Args:
        value: Input to validate
        min_length: Minimum allowed length
        max_length: Maximum allowed length
        allow_empty: Whether empty string is allowed
        pattern: Optional regex pattern to match

    Returns:
        Validated string

    Raises:
        ValidationError: If validation fails
    """
    if value is None:
        if allow_empty:
            return ""
        raise ValidationError("String value cannot be None")

    value_str = str(value)

    if not allow_empty and not value_str:
        raise ValidationError("String value cannot be empty")

    if len(value_str) < min_length:
        raise ValidationError(f"String too short (minimum length: {min_length})")

    if len(value_str) > max_length:
        raise ValidationError(f"String too long (maximum length: {max_length})")

    if pattern and not re.match(pattern, value_str):
        raise ValidationError(f"String does not match required pattern: {pattern}")

    return value_str


def validate_identifier(value: Any) -> str:
    """
    Validate an identifier (alphanumeric with underscores, hyphens, and periods).

    Args:
        value: Identifier to validate

    Returns:
        Validated identifier

    Raises:
        ValidationError: If validation fails
    """
    try:
        value_str = validate_string(value, min_length=1, max_length=255)
        if not re.match(IDENTIFIER_REGEX, value_str):
            raise ValidationError("Identifier contains invalid characters")
        return value_str
    except ValidationError as e:
        raise ValidationError(f"Invalid identifier: {str(e)}")


def validate_uuid(value: Any) -> str:
    """
    Validate a UUID string.

    Args:
        value: UUID string to validate

    Returns:
        Validated UUID string

    Raises:
        ValidationError: If validation fails
    """
    try:
        value_str = validate_string(value)
        if not re.match(UUID_REGEX, value_str.lower()):
            # Try to parse as UUID to see if it's valid
            try:
                uuid_obj = uuid.UUID(value_str)
                return str(uuid_obj)
            except ValueError:
                raise ValidationError("String is not a valid UUID")
        return value_str
    except ValidationError as e:
        raise ValidationError(f"Invalid UUID: {str(e)}")


def validate_path(value: Any, must_exist: bool = False,
                 check_writable: bool = False, disallow_traversal: bool = True) -> Path:
    """
    Validate a file path.

    Args:
        value: Path to validate
        must_exist: Whether the path must exist
        check_writable: Whether to check if the path is writable
        disallow_traversal: Whether to disallow directory traversal

    Returns:
        Validated Path object

    Raises:
        ValidationError: If validation fails
    """
    if value is None:
        raise ValidationError("Path cannot be None")

    try:
        path = Path(value)
    except Exception:
        raise ValidationError(f"Invalid path format: {value}")

    # Check for directory traversal if specified
    if disallow_traversal and re.search(PATH_TRAVERSAL_REGEX, str(path)):
        raise ValidationError("Path contains directory traversal patterns")

    if must_exist and not path.exists():
        raise ValidationError(f"Path does not exist: {path}")

    if check_writable:
        if path.exists() and not os.access(str(path), os.W_OK):
            raise ValidationError(f"Path is not writable: {path}")
        elif not path.exists():
            # Check if parent directory is writable
            parent = path.parent
            if not parent.exists() or not os.access(str(parent), os.W_OK):
                raise ValidationError(f"Parent directory is not writable: {parent}")

    return path


def is_valid_ip_address(value: str) -> bool:
    """
    Check if a string is a valid IP address (IPv4 or IPv6).

    Args:
        value: String to check

    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_hostname(value: str) -> bool:
    """
    Check if a string is a valid hostname.

    Args:
        value: String to check

    Returns:
        True if valid hostname, False otherwise
    """
    if not value or len(value) > 255:
        return False
    if value[-1] == ".":
        value = value[:-1]  # Strip trailing dot
    return re.match(HOSTNAME_REGEX, value) is not None


def validate_target(value: Any) -> str:
    """
    Validate a target specification (hostname, IP, or identifier).

    Args:
        value: Target to validate

    Returns:
        Validated target string

    Raises:
        ValidationError: If validation fails
    """
    try:
        value_str = validate_string(value, min_length=1, max_length=255)

        # Check if it's an IP address
        if is_valid_ip_address(value_str):
            return value_str

        # Check if it's a hostname
        if is_valid_hostname(value_str):
            return value_str

        # Check if it's a valid identifier
        if re.match(IDENTIFIER_REGEX, value_str):
            return value_str

        raise ValidationError("Target must be a valid hostname, IP address, or identifier")
    except ValidationError as e:
        raise ValidationError(f"Invalid target: {str(e)}")


def validate_target_list(value: Any) -> List[str]:
    """
    Validate a list of targets.

    Args:
        value: List of targets or comma-separated string

    Returns:
        List of validated target strings

    Raises:
        ValidationError: If validation fails
    """
    if isinstance(value, str):
        targets = [t.strip() for t in value.split(',')]
    elif isinstance(value, list):
        targets = [str(t) for t in value]
    else:
        raise ValidationError("Target list must be a comma-separated string or list")

    validated_targets = []
    for target in targets:
        try:
            validated_targets.append(validate_target(target))
        except ValidationError as e:
            raise ValidationError(f"Invalid target in list: {str(e)}")

    return validated_targets


def validate_output_format(value: Any) -> str:
    """
    Validate an output format.

    Args:
        value: Output format to validate

    Returns:
        Validated output format

    Raises:
        ValidationError: If validation fails
    """
    try:
        value_str = validate_string(value).lower()
        if value_str not in VALID_OUTPUT_FORMATS:
            valid_formats = ", ".join(VALID_OUTPUT_FORMATS)
            raise ValidationError(f"Invalid output format. Must be one of: {valid_formats}")
        return value_str
    except ValidationError as e:
        raise ValidationError(f"Invalid output format: {str(e)}")


def validate_compliance_framework(value: Any) -> str:
    """
    Validate a compliance framework.

    Args:
        value: Compliance framework to validate

    Returns:
        Validated compliance framework

    Raises:
        ValidationError: If validation fails
    """
    try:
        value_str = validate_string(value).lower()
        if value_str not in VALID_COMPLIANCE_FRAMEWORKS:
            valid_frameworks = ", ".join(VALID_COMPLIANCE_FRAMEWORKS)
            raise ValidationError(f"Invalid compliance framework. Must be one of: {valid_frameworks}")
        return value_str
    except ValidationError as e:
        raise ValidationError(f"Invalid compliance framework: {str(e)}")


def validate_profile(value: Any) -> str:
    """
    Validate an assessment profile name.

    Args:
        value: Profile name to validate

    Returns:
        Validated profile name

    Raises:
        ValidationError: If validation fails
    """
    try:
        return validate_identifier(value)
    except ValidationError as e:
        raise ValidationError(f"Invalid profile name: {str(e)}")


def validate_url(value: Any, required_schemes: Optional[List[str]] = None) -> str:
    """
    Validate a URL.

    Args:
        value: URL to validate
        required_schemes: List of allowed schemes (e.g., ['http', 'https'])

    Returns:
        Validated URL

    Raises:
        ValidationError: If validation fails
    """
    try:
        value_str = validate_string(value)
        parsed_url = urlparse(value_str)

        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValidationError("URL must have a scheme and hostname")

        if required_schemes and parsed_url.scheme not in required_schemes:
            schemes_str = ", ".join(required_schemes)
            raise ValidationError(f"URL scheme must be one of: {schemes_str}")

        return value_str
    except ValidationError as e:
        raise ValidationError(f"Invalid URL: {str(e)}")


def validate_port(value: Any) -> int:
    """
    Validate a port number.

    Args:
        value: Port number to validate

    Returns:
        Validated port number

    Raises:
        ValidationError: If validation fails
    """
    try:
        port = int(value)
        if port < 1 or port > 65535:
            raise ValidationError("Port must be between 1 and 65535")
        return port
    except (ValueError, TypeError):
        raise ValidationError(f"Invalid port number: {value}")


def validate_ip_network(value: Any) -> str:
    """
    Validate an IP network specification (CIDR notation).

    Args:
        value: IP network to validate

    Returns:
        Validated IP network string

    Raises:
        ValidationError: If validation fails
    """
    try:
        value_str = validate_string(value)
        ipaddress.ip_network(value_str, strict=False)
        return value_str
    except (ValidationError, ValueError) as e:
        raise ValidationError(f"Invalid IP network: {str(e)}")


def validate_timeout(value: Any, min_value: int = 1, max_value: int = 3600) -> int:
    """
    Validate a timeout value.

    Args:
        value: Timeout value to validate
        min_value: Minimum allowed value
        max_value: Maximum allowed value

    Returns:
        Validated timeout value

    Raises:
        ValidationError: If validation fails
    """
    try:
        timeout = int(value)
        if timeout < min_value:
            raise ValidationError(f"Timeout cannot be less than {min_value}")
        if timeout > max_value:
            raise ValidationError(f"Timeout cannot be greater than {max_value}")
        return timeout
    except (ValueError, TypeError):
        raise ValidationError(f"Invalid timeout value: {value}")


def validate_boolean(value: Any) -> bool:
    """
    Validate and convert a value to boolean.

    Args:
        value: Value to validate

    Returns:
        Validated boolean

    Raises:
        ValidationError: If validation fails
    """
    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        return bool(value)

    if isinstance(value, str):
        value_lower = value.lower()
        if value_lower in ('true', 't', 'yes', 'y', '1'):
            return True
        if value_lower in ('false', 'f', 'no', 'n', '0'):
            return False

    raise ValidationError(f"Cannot convert to boolean: {value}")


def validate_evidence_parameters(
    evidence_collection: bool,
    evidence_types: Optional[List[str]] = None,
    evidence_path: Optional[str] = None
) -> Tuple[bool, Optional[List[str]], Optional[Path]]:
    """
    Validate evidence collection parameters.

    Args:
        evidence_collection: Whether to collect evidence
        evidence_types: Types of evidence to collect
        evidence_path: Path to store evidence

    Returns:
        Tuple of validated evidence_collection, evidence_types, evidence_path

    Raises:
        ValidationError: If validation fails
    """
    validated_evidence_collection = validate_boolean(evidence_collection)

    validated_evidence_types = None
    validated_evidence_path = None

    if validated_evidence_collection:
        # Only validate these if evidence collection is enabled
        if evidence_types:
            valid_types = {"screenshots", "logs", "configs", "network", "files", "database", "memory"}
            if isinstance(evidence_types, str):
                evidence_types = [t.strip() for t in evidence_types.split(',')]

            validated_evidence_types = []
            for ev_type in evidence_types:
                if ev_type not in valid_types:
                    raise ValidationError(f"Invalid evidence type: {ev_type}")
                validated_evidence_types.append(ev_type)

        if evidence_path:
            validated_evidence_path = validate_path(evidence_path, check_writable=True)

    return validated_evidence_collection, validated_evidence_types, validated_evidence_path


def validate_assessment_parameters(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate common assessment parameters.

    Args:
        params: Dictionary of assessment parameters

    Returns:
        Dictionary with validated parameters

    Raises:
        ValidationError: If validation fails
    """
    validated = {}

    # Required parameters
    if 'target' in params:
        validated['target'] = validate_target(params['target'])

    # Optional parameters with defaults
    validated['output_format'] = validate_output_format(params.get('output_format', 'standard'))
    validated['profile_name'] = validate_profile(params.get('profile_name', 'default'))
    validated['non_invasive'] = validate_boolean(params.get('non_invasive', True))

    # Optional parameters
    if 'assessment_id' in params:
        validated['assessment_id'] = validate_identifier(params['assessment_id'])

    if 'output_file' in params:
        validated['output_file'] = str(validate_path(params['output_file'], check_writable=True))

    if 'compliance_framework' in params:
        validated['compliance_framework'] = validate_compliance_framework(params['compliance_framework'])

    if 'timeout' in params:
        validated['timeout'] = validate_timeout(params['timeout'])

    # Evidence collection parameters
    evidence_collection = params.get('evidence_collection', False)
    evidence_types = params.get('evidence_types')
    evidence_path = params.get('evidence_path')

    validated['evidence_collection'], validated['evidence_types'], evidence_path = \
        validate_evidence_parameters(evidence_collection, evidence_types, evidence_path)

    if evidence_path:
        validated['evidence_path'] = str(evidence_path)

    return validated


def is_target_valid(target: str) -> bool:
    """
    Check if a target is valid without raising exceptions.

    Args:
        target: Target to validate

    Returns:
        True if target is valid, False otherwise
    """
    try:
        validate_target(target)
        return True
    except ValidationError:
        return False


def validate_json_payload(payload: Any, schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate a JSON payload against a schema.

    This is a simple implementation. For production use,
    consider using a full JSON Schema validator.

    Args:
        payload: JSON payload to validate
        schema: Schema to validate against

    Returns:
        Validated payload

    Raises:
        ValidationError: If validation fails
    """
    if not isinstance(payload, dict):
        raise ValidationError("Payload must be a dictionary")

    result = {}

    for key, field_schema in schema.items():
        field_type = field_schema.get('type', 'string')
        required = field_schema.get('required', False)

        if key not in payload:
            if required:
                raise ValidationError(f"Required field missing: {key}")
            continue

        value = payload[key]

        # Type validation
        if field_type == 'string':
            min_length = field_schema.get('min_length', 0)
            max_length = field_schema.get('max_length', MAX_STRING_LENGTH)
            pattern = field_schema.get('pattern')
            result[key] = validate_string(value, min_length=min_length, max_length=max_length, pattern=pattern)

        elif field_type == 'integer':
            min_value = field_schema.get('min', None)
            max_value = field_schema.get('max', None)

            try:
                int_value = int(value)
                if min_value is not None and int_value < min_value:
                    raise ValidationError(f"Field {key} value must be at least {min_value}")
                if max_value is not None and int_value > max_value:
                    raise ValidationError(f"Field {key} value must be at most {max_value}")
                result[key] = int_value
            except (ValueError, TypeError):
                raise ValidationError(f"Field {key} must be an integer")

        elif field_type == 'boolean':
            result[key] = validate_boolean(value)

        elif field_type == 'array':
            if not isinstance(value, list):
                raise ValidationError(f"Field {key} must be an array")

            item_schema = field_schema.get('items', {})
            item_type = item_schema.get('type', 'string')

            validated_array = []
            for item in value:
                if item_type == 'string':
                    validated_item = validate_string(item)
                elif item_type == 'integer':
                    try:
                        validated_item = int(item)
                    except (ValueError, TypeError):
                        raise ValidationError(f"Array item in {key} must be an integer")
                else:
                    validated_item = item  # No validation for other types

                validated_array.append(validated_item)

            result[key] = validated_array

        elif field_type == 'object':
            if not isinstance(value, dict):
                raise ValidationError(f"Field {key} must be an object")

            nested_schema = field_schema.get('properties', {})
            if nested_schema:
                result[key] = validate_json_payload(value, nested_schema)
            else:
                result[key] = value

        else:
            # For unsupported types, just pass through
            result[key] = value

    return result
