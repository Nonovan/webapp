# Utility Modules for Cloud Infrastructure Platform

This directory contains specialized utility modules that provide reusable functionality across the Cloud Infrastructure Platform. These utilities implement common operations for string manipulation, file handling, data validation, collection management, and datetime handling.

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
  - Secure text normalization and encoding

- **`file.py`**: File operation utilities
  - Secure file handling with appropriate permissions
  - File format handling and validation
  - Path manipulation and normalization
  - Secure temporary file management
  - Configuration file reading and writing (JSON, YAML)
  - Directory operations with permission management

- **`collection.py`**: Collection data structure manipulation
  - Deep dictionary operations (get, set, merge)
  - List and dictionary transformations
  - Group by and collection aggregation functions
  - Nested structure flattening and reconstruction
  - Collection filtering and transformation
  - Duplicate detection and key-based uniqueness
  - Efficient batch operations and list chunking
  - Safe JSON serialization for complex objects

- **`validation.py`**: Input validation and sanitation
  - Type checking and validation
  - Schema-based data validation
  - Range and constraint checking
  - Input sanitization for security
  - Format validation (emails, URLs, etc.)
  - Validation pipeline composition
  - Collection type verification
  - Cloud resource validation (IDs, regions, service names)
  - HTML content sanitization
  - Password strength validation

- **`date_time.py`**: Date and time handling utilities
  - Timezone-aware datetime operations
  - Date formatting and parsing with internationalization support
  - Duration calculations and human-readable formatting
  - Relative time expressions (e.g., "2 hours ago")
  - Date range generation and iteration
  - Date comparison and validation with business logic support
  - ISO 8601 compliant timestamp handling
  - Timestamp conversions (epoch, ISO, custom formats)

- **`system.py`**: System resource and request utilities
  - System resource monitoring
  - Process information retrieval
  - Request context management
  - Execution time measurement
  - Redis client management
  - Performance monitoring and tracking

- **`logging_utils.py`**: Logging configuration and utilities
  - Application logging setup
  - Security event logging
  - Audit logging capabilities
  - File integrity event logging
  - Logger creation and management
  - Module logging initialization
  - Secure log message handling
  - Sensitive data masking
  - Structured logging formatters

## Directory Structure

```plaintext
core/utils/
├── README.md          # This documentation
├── __init__.py        # Package initialization and exports
├── collection.py      # Collection manipulation utilities
├── date_time.py       # Date and time handling utilities
├── file.py            # File handling utilities
├── logging_utils.py   # Logging configuration utilities
├── string.py          # String manipulation utilities
├── system.py          # System resource utilities
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

# Convert between case styles
camel_case = snake_to_camel("user_profile_data")  # Output: "userProfileData"
snake_case = camel_to_snake("userProfileData")    # Output: "user_profile_data"

# Get text excerpt with ellipsis
short_description = generate_excerpt(article_content, max_length=200)

# Create secure filename
filename = generate_secure_filename(user_supplied_filename)
```

### File Utilities

```python
from core.utils.file import read_file, save_json_file, is_path_safe, read_yaml_file, ensure_directory_exists

# Safely read file with encoding handling
content = read_file("/path/to/file.txt", encoding="utf-8")

# Atomically save JSON data to file
save_json_file("/path/to/output.json", {"key": "value"}, indent=2)

# Validate path safety (prevent path traversal)
if is_path_safe(user_supplied_path, allowed_base_dirs=["/allowed/path"]):
    # Safe to use the path
    with open(user_supplied_path, 'r') as f:
        content = f.read()

# Read YAML configuration file
config = read_yaml_file("/path/to/config.yaml", default={})

# Ensure directory exists before writing
ensure_directory_exists("/path/to/output/directory")

# Get file metadata
metadata = get_file_metadata("/path/to/file.txt")
```

### Collection Utilities

```python
from core.utils.collection import deep_get, deep_set, merge_dicts, flatten_dict, unflatten_dict

# Safely access nested dictionary values
user_name = deep_get(data, "user.profile.name", default="Unknown User")

# Set value in nested structure
deep_set(config, "security.headers.content_security_policy.enabled", True)

# Merge multiple dictionaries with customizable behavior
merged = merge_dicts(dict1, dict2, dict3, deep=True)

# Flatten nested dictionary into dot-notation keys
flat = flatten_dict(nested_dict)  # {"user.profile.name": "John"}

# Convert flat dictionary back to nested structure
nested = unflatten_dict(flat_dict)

# Filter dictionary by specific keys
filtered = filter_dict_by_keys(data, ["id", "name", "email"])

# Transform dictionary keys
snake_case_dict = transform_keys(camel_case_dict, camel_to_snake)
```

### Validation Utilities

```python
from core.utils.validation import (
    validate_with_schema, is_valid_email, is_valid_ip_address,
    is_valid_uuid, is_valid_port, is_iterable, is_mapping,
    is_sequence, is_numeric, validate_resource_id,
    validate_service_name, validate_region
)

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

# Validate IP address
if is_valid_ip_address(client_ip):
    # Process valid IP
    pass

# Validate cloud resource identifiers
try:
    resource_id = validate_resource_id(input_resource_id)
    service = validate_service_name(input_service_name)
    region = validate_region(input_region)

    # Create alert for the validated cloud resource
    create_resource_alert(resource_id, service, region, alert_details)
except ValidationError as e:
    handle_validation_error(e)
```

### Date/Time Utilities

```python
from core.utils.date_time import (
    utcnow, now_with_timezone, format_datetime, parse_iso_datetime,
    format_relative_time, date_range, calculate_time_difference,
    format_timestamp
)

# Get current UTC time with timezone information
current_time = utcnow()

# Get current time in specific timezone
local_time = now_with_timezone(get_timezone("America/New_York"))

# Parse ISO 8601 date string
event_date = parse_iso_datetime("2024-07-15T14:30:00Z")

# Format as human-readable relative time
time_display = format_relative_time(event_date)  # e.g., "2 hours ago" or "in 3 days"

# Format timestamp for logging or display
formatted = format_timestamp(current_time)  # ISO 8601 format
```

### System Utilities

```python
from core.utils.system import (
    get_system_resources, get_process_info, get_request_context,
    measure_execution_time, get_redis_client
)

# Get system resource information
resources = get_system_resources()
print(f"CPU usage: {resources['cpu_percent']}%, Memory: {resources['memory_used']} MB")

# Get process information
process_info = get_process_info()

# Time a function's execution
with measure_execution_time() as timer:
    result = expensive_operation()
print(f"Operation took {timer.duration:.2f} seconds")

# Get Redis client with proper connection pooling
redis = get_redis_client()
```

### Logging Utilities

```python
from core.utils.logging_utils import (
    get_logger, get_security_logger, log_security_event
)

# Get logger for current module
logger = get_logger(__name__)
logger.info("Operation completed successfully")

# Get specialized security logger
security_logger = get_security_logger()
security_logger.warning("Unauthorized access attempt",
    extra={"ip": "192.168.1.1", "user_id": "guest"})

# Log security event
log_security_event(
    event_type="authorization_failure",
    description="User attempted to access restricted resource",
    severity="warning",
    user_id="user123",
    details={"resource": "/admin/users", "ip": "192.168.1.100"}
)
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
- **Path Traversal Protection**: File operations validate paths to prevent directory traversal attacks
- **Timezone Awareness**: Date/time functions properly handle timezone information
- **Thread Safety**: Utilities are designed to be thread-safe where appropriate
- **Parameter Validation**: Functions validate parameters before processing
- **Secure Defaults**: Conservative defaults that prioritize security
- **Atomic Operations**: File operations use atomic patterns to prevent partial writes
- **Separation of Concerns**: Security-related functions moved to security module
- **Regex Pattern Constants**: Reusable regex patterns as module constants
- **Cross-platform Support**: Utilities work on different operating systems
- **Comprehensive Error Messages**: Clear, detailed error messages for debugging
- **Reserved Name Validation**: Check for reserved names in service naming

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
- **Consistent Error Handling**: Standardized error patterns across modules
- **Docstring Examples**: Example usage in function docstrings
- **Edge Case Handling**: Graceful handling of boundary conditions
- **PEP 8 Compliance**: Adherence to Python style guidelines
- **Backward Compatibility**: Careful consideration of API changes

## Related Documentation

- Core Package Documentation
- String Utilities Reference
- File Utilities Reference
- Collection Utilities Reference
- Validation Utilities Reference
- Date/Time Utilities Reference
- System Utilities Reference
- Logging Utilities Reference
- Security Controls Framework
- Configuration Management Guide
- Error Handling Standards
- Coding Standards
- Cloud Resource Naming Conventions
- Input Validation Best Practices
- API Security Guidelines

## Version Information

- v0.0.3: Added cloud resource validation functions (resource_id, service_name, region)
- v0.0.2: Major restructuring with improved security measures
- v0.0.1: Initial stable release
