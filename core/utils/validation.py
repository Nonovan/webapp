"""
Validation utility functions for Cloud Infrastructure Platform.

This module provides common validation functionality used throughout the
application including:
- Input sanitation
- Value range checking
- Type validation
- Format verification
- Business rule validation

These utilities ensure consistent validation and error handling across
the application's components.
"""

from bs4 import BeautifulSoup
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union, Pattern, Callable


def is_valid_dict_keys(obj: Dict, required_keys: List[str]) -> Tuple[bool, Optional[str]]:
    """
    Validate that a dictionary contains all required keys.

    Args:
        obj: Dictionary to validate
        required_keys: List of keys that must be present

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(obj, dict):
        return False, "Value must be a dictionary"

    missing_keys = [key for key in required_keys if key not in obj]
    if missing_keys:
        return False, f"Missing required keys: {', '.join(missing_keys)}"

    return True, None


def is_in_range(value: Union[int, float], min_val: Union[int, float],
                max_val: Union[int, float], inclusive: bool = True) -> bool:
    """
    Check if a numeric value is within specified range.

    Args:
        value: Value to check
        min_val: Minimum allowed value
        max_val: Maximum allowed value
        inclusive: Whether the range is inclusive

    Returns:
        True if within range, False otherwise
    """
    if inclusive:
        return min_val <= value <= max_val
    else:
        return min_val < value < max_val


def is_valid_length(value: Union[str, List, Dict],
                   min_length: Optional[int] = None,
                   max_length: Optional[int] = None) -> Tuple[bool, Optional[str]]:
    """
    Check if a string, list or dict length is within specified range.

    Args:
        value: Value to check the length of
        min_length: Minimum allowed length (or None for no minimum)
        max_length: Maximum allowed length (or None for no maximum)

    Returns:
        Tuple of (is_valid, error_message)
    """
    if value is None:
        return False, "Value cannot be None"

    length = len(value)

    if min_length is not None and length < min_length:
        return False, f"Length must be at least {min_length}"

    if max_length is not None and length > max_length:
        return False, f"Length must be at most {max_length}"

    return True, None


def is_valid_pattern(value: str, pattern: Union[str, Pattern]) -> bool:
    """
    Check if a string matches a regex pattern.

    Args:
        value: String to check
        pattern: Regular expression pattern to match

    Returns:
        True if matches pattern, False otherwise
    """
    if not value:
        return False

    if isinstance(pattern, str):
        pattern = re.compile(pattern)

    return bool(pattern.match(value))


def is_valid_choice(value: Any, choices: List[Any]) -> bool:
    """
    Check if a value is one of the allowed choices.

    Args:
        value: Value to check
        choices: List of allowed values

    Returns:
        True if valid choice, False otherwise
    """
    return value in choices


def is_valid_uuid(value: str, version: int = 4) -> bool:
    """
    Check if a string is a valid UUID.

    Args:
        value: String to check
        version: UUID version to validate (1, 3, 4, 5)

    Returns:
        True if valid UUID, False otherwise
    """
    if not value:
        return False

    try:
        uuid_obj = uuid.UUID(value, version=version)
        return str(uuid_obj) == value
    except (ValueError, AttributeError, TypeError):
        return False


def is_valid_numeric(value: str, allow_negative: bool = False, allow_decimal: bool = False) -> bool:
    """
    Check if a string contains a valid number.

    Args:
        value: String to check
        allow_negative: Whether to allow negative numbers
        allow_decimal: Whether to allow decimal numbers

    Returns:
        True if valid number, False otherwise
    """
    if not value:
        return False

    # Determine pattern based on parameters
    if allow_decimal:
        if allow_negative:
            pattern = r'^-?\d+(\.\d+)?$'
        else:
            pattern = r'^\d+(\.\d+)?$'
    else:
        if allow_negative:
            pattern = r'^-?\d+$'
        else:
            pattern = r'^\d+$'

    return bool(re.match(pattern, value))


def normalize_boolean(value: Any) -> Optional[bool]:
    """
    Convert various values to boolean or None if not convertible.

    Args:
        value: Value to normalize

    Returns:
        True, False, or None if not convertible
    """
    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        return bool(value)

    if isinstance(value, str):
        value = value.lower().strip()
        if value in ('true', 't', 'yes', 'y', '1'):
            return True
        if value in ('false', 'f', 'no', 'n', '0'):
            return False

    return None


def validate_with_schema(
    value: Any,
    schema: Dict[str, Any],
    allow_extra_fields: bool = False
) -> Tuple[bool, List[str]]:
    """
    Validate a value against a schema definition.

    Args:
        value: Value to validate
        schema: Schema definition
        allow_extra_fields: Whether to allow fields not in schema

    Returns:
        Tuple of (is_valid, list_of_error_messages)
    """
    errors = []

    # Handle different schema types
    schema_type = schema.get('type')

    if schema_type == 'object':
        if not isinstance(value, dict):
            return False, ["Value must be an object"]

        properties = schema.get('properties', {})
        required = schema.get('required', [])

        # Check required properties
        for req_field in required:
            if req_field not in value:
                errors.append(f"Missing required field: {req_field}")

        # Check property values
        for field_name, field_value in value.items():
            if field_name in properties:
                field_schema = properties[field_name]
                field_valid, field_errors = validate_with_schema(field_value, field_schema)
                if not field_valid:
                    errors.extend([f"{field_name}: {err}" for err in field_errors])
            elif not allow_extra_fields:
                errors.append(f"Extra field not allowed: {field_name}")

    elif schema_type == 'array':
        if not isinstance(value, list):
            return False, ["Value must be an array"]

        items_schema = schema.get('items', {})
        for i, item in enumerate(value):
            item_valid, item_errors = validate_with_schema(item, items_schema)
            if not item_valid:
                errors.extend([f"Item {i}: {err}" for err in item_errors])

    elif schema_type == 'string':
        if not isinstance(value, str):
            errors.append("Value must be a string")
        else:
            min_length = schema.get('minLength')
            max_length = schema.get('maxLength')
            pattern = schema.get('pattern')

            if min_length is not None and len(value) < min_length:
                errors.append(f"String length must be at least {min_length}")

            if max_length is not None and len(value) > max_length:
                errors.append(f"String length must be at most {max_length}")

            if pattern and not re.match(pattern, value):
                errors.append(f"String must match pattern: {pattern}")

    elif schema_type == 'number' or schema_type == 'integer':
        if schema_type == 'integer' and not isinstance(value, int):
            errors.append("Value must be an integer")
        elif not isinstance(value, (int, float)):
            errors.append("Value must be a number")
        else:
            minimum = schema.get('minimum')
            maximum = schema.get('maximum')

            if minimum is not None and value < minimum:
                errors.append(f"Number must be at least {minimum}")

            if maximum is not None and value > maximum:
                errors.append(f"Number must be at most {maximum}")

    elif schema_type == 'boolean':
        if not isinstance(value, bool):
            errors.append("Value must be a boolean")

    elif schema_type == 'null':
        if value is not None:
            errors.append("Value must be null")

    return len(errors) == 0, errors


def sanitize_html(html: str, allowed_tags: List[str] = None) -> str:
    """
    Sanitize HTML content by removing unsafe tags and attributes.

    Args:
        html: HTML content to sanitize
        allowed_tags: List of allowed HTML tags (if None, removes all tags)

    Returns:
        Sanitized HTML string
    """
    # Import here to avoid requiring these libraries when not needed
    try:
        if allowed_tags is None:
            # Strip all tags if None provided
            soup = BeautifulSoup(html, "html.parser")
            return soup.get_text()
        else:
            # Keep only allowed tags and attributes
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all():
                if tag.name not in allowed_tags:
                    tag.unwrap()
            return str(soup)

    except ImportError:
        # Fallback to regex-based approach if BeautifulSoup is not available
        if allowed_tags is None:
            # Remove all tags
            return re.sub(r'<[^>]*>', '', html)
        else:
            # This is a basic implementation - for production use BeautifulSoup
            for tag in re.findall(r'<([^/ >]+)[^>]*>', html):
                if tag.lower() not in allowed_tags:
                    html = re.sub(r'<' + tag + '[^>]*>.*?</' + tag + '>', '', html, flags=re.DOTALL)
            return html


def validate_password_strength(
    password: str,
    min_length: int = 8,
    require_uppercase: bool = True,
    require_lowercase: bool = True,
    require_digit: bool = True,
    require_special: bool = True
) -> Tuple[bool, List[str]]:
    """
    Validate password strength using customizable rules.

    Args:
        password: Password to validate
        min_length: Minimum password length
        require_uppercase: Whether to require uppercase letters
        require_lowercase: Whether to require lowercase letters
        require_digit: Whether to require digits
        require_special: Whether to require special characters

    Returns:
        Tuple of (is_valid, list_of_error_messages)
    """
    errors = []

    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters long")

    if require_uppercase and not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")

    if require_lowercase and not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")

    if require_digit and not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit")

    if require_special and not any(not c.isalnum() for c in password):
        errors.append("Password must contain at least one special character")

    return len(errors) == 0, errors


def validate_dict(data: Dict, schema: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate a dictionary against a schema definition.

    This is a wrapper around validate_with_schema that specifically handles
    dictionary validation use cases.

    Args:
        data: Dictionary to validate
        schema: Schema definition to validate against

    Returns:
        Tuple of (is_valid, list_of_error_messages)
    """
    if not isinstance(data, dict):
        return False, ["Input must be a dictionary"]

    return validate_with_schema(data, schema)


def is_valid_ip_address(ip: str, version: Optional[int] = None) -> bool:
    """
    Validate if a string is a valid IPv4 or IPv6 address.

    Args:
        ip: IP address to validate
        version: IP version to validate against (4, 6, or None for both)

    Returns:
        True if valid IP address, False otherwise
    """
    if not ip or not isinstance(ip, str):
        return False

    try:
        import ipaddress

        # Try to create an IP address object
        if version == 4:
            ipaddress.IPv4Address(ip)
        elif version == 6:
            ipaddress.IPv6Address(ip)
        else:
            # If no version specified, try both
            ipaddress.ip_address(ip)

        return True
    except ValueError:
        # Invalid IP format
        return False


def is_valid_hostname(hostname: str, allow_ip: bool = False) -> bool:
    """
    Validate if a string is a valid hostname according to RFC 1123.

    Args:
        hostname: Hostname to validate
        allow_ip: Whether to allow IP addresses as valid hostnames

    Returns:
        True if valid hostname, False otherwise
    """
    if not hostname or not isinstance(hostname, str):
        return False

    # Check if it's an IP address and whether that's allowed
    if allow_ip and is_valid_ip_address(hostname):
        return True

    # Trim trailing dot if present
    if hostname.endswith('.'):
        hostname = hostname[:-1]

    # Check length constraints
    if len(hostname) > 253:
        return False

    # Check pattern
    # - Labels (between dots) can have alphanumeric, hyphens
    # - Labels can't start or end with hyphens
    # - Labels must be 1-63 characters
    hostname_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'

    return bool(re.match(hostname_pattern, hostname))


def is_valid_port(port: Union[str, int]) -> bool:
    """
    Validate if a value is a valid network port number (1-65535).

    Args:
        port: Port number to validate (string or integer)

    Returns:
        True if valid port, False otherwise
    """
    try:
        # Convert to integer if it's a string
        if isinstance(port, str):
            port = int(port)

        # Check range
        return 1 <= port <= 65535
    except (ValueError, TypeError):
        return False


def is_iterable(obj: Any) -> bool:
    """
    Check if an object is iterable (excluding strings).

    This function determines if an object can be iterated over using a for loop,
    but considers strings as non-iterables despite them technically being iterable.
    This is common practice as strings are often treated separately from container types.

    Args:
        obj: Object to check

    Returns:
        True if the object is iterable (and not a string), False otherwise

    Example:
        >>> is_iterable([1, 2, 3])
        True
        >>> is_iterable({"a": 1, "b": 2})
        True
        >>> is_iterable("string")
        False
        >>> is_iterable(5)
        False
    """
    if isinstance(obj, str):
        return False

    try:
        iter(obj)
        return True
    except TypeError:
        return False


def is_mapping(obj: Any) -> bool:
    """
    Check if an object is a mapping type (dict-like).

    This function determines if an object implements the mapping protocol,
    which includes dictionaries and other dict-like objects.

    Args:
        obj: Object to check

    Returns:
        True if the object is a mapping, False otherwise

    Example:
        >>> is_mapping({"a": 1, "b": 2})
        True
        >>> is_mapping([1, 2, 3])
        False
        >>> from collections import OrderedDict
        >>> is_mapping(OrderedDict([('a', 1), ('b', 2)]))
        True
    """
    from collections.abc import Mapping
    return isinstance(obj, Mapping)


def is_sequence(obj: Any) -> bool:
    """
    Check if an object is a sequence type (list-like, excluding strings).

    This function determines if an object implements the sequence protocol,
    which includes lists, tuples, and other list-like objects, but excludes strings
    which are technically sequences but often treated separately.

    Args:
        obj: Object to check

    Returns:
        True if the object is a sequence (and not a string), False otherwise

    Example:
        >>> is_sequence([1, 2, 3])
        True
        >>> is_sequence((1, 2, 3))
        True
        >>> is_sequence("string")
        False
        >>> is_sequence({"a": 1})
        False
    """
    if isinstance(obj, str):
        return False

    from collections.abc import Sequence
    return isinstance(obj, Sequence)


def is_numeric(obj: Any) -> bool:
    """
    Check if an object is a numeric type.

    This function determines if an object is a numeric type, including integers,
    floats, decimal.Decimal, and other numeric types like numpy numeric types
    if available.

    Args:
        obj: Object to check

    Returns:
        True if the object is numeric, False otherwise

    Example:
        >>> is_numeric(5)
        True
        >>> is_numeric(5.5)
        True
        >>> is_numeric("5")
        False
        >>> from decimal import Decimal
        >>> is_numeric(Decimal("5.5"))
        True
    """
    # Basic numeric types
    if isinstance(obj, (int, float, complex)):
        return True

    # Check for decimal.Decimal
    try:
        from decimal import Decimal
        if isinstance(obj, Decimal):
            return True
    except ImportError:
        pass

    # Check for numpy numeric types if available
    try:
        import numpy as np
        return isinstance(obj, np.number)
    except ImportError:
        pass

    # Some objects might implement numeric protocols but not inherit from numeric types
    # Try numeric operations as a last resort
    try:
        # Check if it behaves like a number
        obj + 0
        return True
    except (TypeError, ValueError):
        return False
