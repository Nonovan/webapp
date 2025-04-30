# Utility Modules for Cloud Infrastructure Platform

This directory contains specialized utility modules that provide reusable functionality across the Cloud Infrastructure Platform. These utilities implement common operations for string manipulation, file handling, data validation, security operations, collection management, and datetime handling.

## Contents

- [Overview](#overview)
- [Key Modules](#key-modules)
- [Directory Structure](#directory-structure)
- [Usage Examples](#usage-examples)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Related Documentation](#related-documentation)
- [Version Information](#version-information)

## Overview

The utility modules provide standardized implementations of common operations needed throughout the Cloud Infrastructure Platform. These modules follow consistent patterns, proper error handling, and strong security practices. They are designed to be imported individually to keep dependencies minimal and provide focused functionality that can be easily tested and maintained.

## Key Modules

- **`string.py`**: Text manipulation and processing utilities
  - URL-friendly slug generation
  - Text truncation and formatting
  - HTML sanitization and handling
  - Case conversion (snake_case, camelCase, etc.)
  - String validation and classification

- **`file.py`**: File operation utilities
  - Secure file handling with appropriate permissions
  - Integrity verification and hash generation
  - Atomic file operations to prevent corruption
  - File format handling and validation
  - Path manipulation and normalization

- **`collection.py`**: Collection data structure manipulation
  - Deep dictionary operations (get, set, merge)
  - List and dictionary transformations
  - Group by and other collection manipulations
  - Nested structure flattening and reconstruction
  - Collection validation and filtering

- **`validation.py`**: Input validation and sanitation
  - Type checking and validation
  - Schema-based data validation
  - Range and constraint checking
  - Input sanitization for security
  - Format validation (emails, URLs, etc.)

- **`security.py`**: Basic security utilities
  - Data obfuscation and masking
  - Token generation and validation
  - Password strength checking
  - Redirect URL validation
  - Secure random string generation

- **`date_time.py`**: Date and time handling utilities
  - Timezone-aware datetime operations
  - Date formatting and parsing with internationalization support
  - Duration calculations and human-readable formatting
  - Relative time expressions (e.g., "2 hours ago")
  - Date range generation and iteration
  - Date comparison and validation with business logic support
  - ISO 8601 compliant timestamp handling
  - Timestamp conversions (epoch, ISO, custom formats)

## Directory Structure

```plaintext
core/utils/
├── README.md          # This documentation
├── __init__.py        # Package initialization and exports
├── collection.py      # Collection manipulation utilities
├── date_time.py       # Date and time handling utilities
├── file.py            # File handling utilities
├── security.py        # Security-related utilities
├── string.py          # String manipulation utilities
└── validation.py      # Input validation utilities
```

## Usage Examples

### String Utilities

```python
from core.utils.string import slugify, truncate_text, sanitize_text

# Generate URL-friendly slug
post_slug = slugify("My Blog Post Title!")  # Output: "my-blog-post-title"

# Truncate text with word boundary
excerpt = truncate_text(long_content, length=150)  # Truncates at word boundary

# Sanitize potentially dangerous user input
safe_html = sanitize_text(user_input, allowed_tags=["p", "a", "strong", "em"])
```

### File Utilities

```python
from core.utils.file import compute_file_hash, save_json_file, is_path_safe

# Compute hash of file content
file_hash = compute_file_hash("/path/to/file.txt", algorithm="sha256")

# Atomically save JSON data to file
save_json_file("/path/to/output.json", {"key": "value"}, indent=2)

# Validate path safety (prevent path traversal)
if is_path_safe(user_supplied_path, allowed_base_dirs=["/allowed/path"]):
    # Safe to use the path
    with open(user_supplied_path, 'r') as f:
        content = f.read()
```

### Collection Utilities

```python
from core.utils.collection import deep_get, deep_set, flatten_dict

# Safely navigate nested dictionaries
user_name = deep_get(data, "user.profile.name", default="Unknown User")

# Set value in nested structure
deep_set(config, "security.headers.content_security_policy.enabled", True)

# Flatten nested dictionary to single level
flat_data = flatten_dict(nested_data, separator=".")
```

### Validation Utilities

```python
from core.utils.validation import is_valid_email, validate_with_schema

# Validate email format
if is_valid_email(user_email):
    send_email(user_email, "Welcome!", "Welcome to our platform!")

# Validate against schema definition
user_schema = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "minLength": 2},
        "email": {"type": "string"},
        "age": {"type": "integer", "minimum": 18}
    },
    "required": ["name", "email"]
}

is_valid, errors = validate_with_schema(user_data, user_schema)
if not is_valid:
    raise ValidationError(f"Invalid user data: {errors}")
```

### Security Utilities

```python
from core.utils.security import generate_random_token, is_safe_redirect_url

# Generate secure random token
reset_token = generate_random_token(length=32)

# Validate URL safety for redirects
if is_safe_redirect_url(redirect_url, allowed_hosts=["example.com", "api.example.org"]):
    return redirect(redirect_url)
else:
    return redirect(default_url)
```

### Date and Time Utilities

```python
from core.utils.date_time import utcnow, parse_iso_datetime, format_relative_time, date_range

# Get current UTC time with timezone information
current_time = utcnow()

# Parse ISO 8601 date string
event_date = parse_iso_datetime("2024-07-15T14:30:00Z")

# Format as human-readable relative time
time_display = format_relative_time(event_date)  # e.g., "2 hours ago" or "in 3 days"

# Format with specific format string
formatted_date = format_datetime(event_date, "%Y-%m-%d %H:%M", use_utc=True)

# Check if date is within business hours
is_business_hour = is_business_hours(current_time)

# Generate a date range for the next week
next_week = date_range(utcnow(), utcnow() + timedelta(days=7))

# Convert between timestamp formats
epoch_time = to_timestamp(current_time)  # Get Unix timestamp
datetime_obj = from_timestamp(epoch_time)  # Convert back to datetime

# Get start and end of day
day_start = beginning_of_day(current_time)
day_end = end_of_day(current_time)
```

## Best Practices & Security

- **Input Validation**: All utilities that accept user input implement thorough validation
- **Defensive Programming**: Functions check for edge cases and handle them gracefully
- **Security by Default**: Security-sensitive operations use secure defaults
- **Proper Error Handling**: Consistent error handling with meaningful messages
- **Type Annotations**: All functions use proper type hints for better IDE support
- **Documentation**: Comprehensive docstrings with examples for all functions
- **Immutability**: Input data is not modified unless explicitly specified
- **Performance Optimization**: Critical paths are optimized for performance
- **Resource Management**: Resources like file handles are properly closed using context managers
- **Unicode Support**: String functions properly handle Unicode characters
- **Secure Randomness**: Security functions use cryptographically strong random generators
- **Path Traversal Protection**: File operations validate paths to prevent directory traversal attacks
- **Timezone Awareness**: Date/time functions properly handle timezone information
- **Thread Safety**: Utilities are designed to be thread-safe where appropriate

## Common Features

All utility modules share these common features:

- **Consistent API Design**: Similar patterns and parameter naming across modules
- **Comprehensive Documentation**: Detailed docstrings with type annotations
- **Defensive Implementation**: Thorough error checking and safe defaults
- **Proper Typing**: Full type annotations for better IDE support and static analysis
- **Minimal Dependencies**: Limited dependencies on external packages
- **Unit Test Coverage**: Comprehensive test coverage for all functionality
- **Security Focus**: Security best practices applied throughout
- **Performance Awareness**: Implementations consider performance implications
- **Immutable Operations**: Non-destructive operations by default
- **Proper Encapsulation**: Implementation details hidden when appropriate

## Related Documentation

- Core Package Documentation
- String Utilities Reference
- File Utilities Reference
- Collection Utilities Reference
- Validation Utilities Reference
- Security Utilities Reference
- Date/Time Utilities Reference
- Security Controls Framework
- Configuration Management Guide
- Error Handling Standards
- Coding Standards

## Version Information

- **Version**: 0.1.1
- **Last Updated**: 2024-07-16
- **Maintainers**: Platform Engineering Team
