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
  - Integrity verification and hash generation
  - Atomic file operations to prevent corruption
  - File format handling and validation
  - Path manipulation and normalization
  - Secure temporary file management

- **`collection.py`**: Collection data structure manipulation
  - Deep dictionary operations (get, set, merge)
  - List and dictionary transformations
  - Group by and collection aggregation functions
  - Nested structure flattening and reconstruction
  - Collection filtering and transformation
  - Duplicate detection and key-based uniqueness
  - Efficient batch operations and list chunking

- **`validation.py`**: Input validation and sanitation
  - Type checking and validation
  - Schema-based data validation
  - Range and constraint checking
  - Input sanitization for security
  - Format validation (emails, URLs, etc.)
  - Validation pipeline composition
  - Collection type verification

- **`date_time.py`**: Date and time handling utilities
  - Timezone-aware datetime operations
  - Date formatting and parsing with internationalization support
  - Duration calculations and human-readable formatting
  - Relative time expressions (e.g., "2 hours ago")
  - Date range generation and iteration
  - Date comparison and validation with business logic support
  - ISO 8601 compliant timestamp handling
  - Timestamp conversions (epoch, ISO, custom formats)
  - Business calendar operations

## Directory Structure

```plaintext
core/utils/
├── README.md          # This documentation
├── __init__.py        # Package initialization and exports
├── collection.py      # Collection manipulation utilities
├── date_time.py       # Date and time handling utilities
├── file.py            # File handling utilities
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
from core.utils.file import compute_file_hash, save_json_file, is_path_safe, read_yaml_file

# Compute hash of file content
file_hash = compute_file_hash("/path/to/file.txt", algorithm="sha256")

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

# Read file with proper encoding handling
content = read_file("/path/to/file.txt", encoding="utf-8")
```

### Collection Utilities

```python
from core.utils.collection import (
    deep_get, deep_set, flatten_dict, group_by, filter_none,
    unique_by, find_duplicates, chunk_list, filter_empty,
    filter_dict_by_keys, transform_keys, transform_values
)

# Safely navigate nested dictionaries
user_name = deep_get(data, "user.profile.name", default="Unknown User")

# Set value in nested structure
deep_set(config, "security.headers.content_security_policy.enabled", True)

# Flatten nested dictionary to single level
flat_data = flatten_dict(nested_data, separator=".")

# Group items by attribute
users_by_role = group_by(users, key=lambda user: user.role)
for role, users in users_by_role.items():
    print(f"{role}: {len(users)} users")

# Filter out None values from dictionary
clean_data = filter_none(user_input)

# Filter out empty values (None, '', [], {}, ()) from dictionary
clean_data = filter_empty(user_input)

# Filter dictionary to include only specific keys
filtered_data = filter_dict_by_keys(data, ['id', 'name', 'email'], include=True)

# Filter dictionary to exclude specific keys
filtered_data = filter_dict_by_keys(data, ['password', 'token'], include=False)

# Get unique items based on a key function
unique_users = unique_by(users, key=lambda u: u.email)

# Find duplicate items in a list
duplicates = find_duplicates(items, key=lambda x: x.id)

# Split a list into chunks of specified size
batches = chunk_list(items, size=100)

# Transform all keys in a dictionary
transformed = transform_keys(data, lambda k: k.lower())

# Transform all values in a dictionary
doubled_values = transform_values(data, lambda v: v * 2 if isinstance(v, int) else v)

# Merge dictionaries with customizable conflict resolution
merged_config = merge_dicts(base_config, user_config,
                           conflict_resolver=lambda k, v1, v2: v2)
```

### Validation Utilities

```python
from core.utils.validation import (
    validate_with_schema, is_valid_email, is_valid_ip_address,
    is_valid_uuid, is_valid_port, is_iterable, is_mapping,
    is_sequence, is_numeric
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

# Check if string is valid UUID
if is_valid_uuid(resource_id):
    # Use UUID in database query
    pass

# Check if port number is valid
if is_valid_port(port_number):
    # Configure service with port
    pass

# Type checking for more reliable code
if is_iterable(data) and not isinstance(data, str):
    # Process iterable (but not string)
    pass

if is_mapping(data):
    # Process dictionary-like object
    pass

if is_sequence(data):
    # Process sequence-like object
    pass

if is_numeric(value):
    # Process numeric value (int, float, Decimal, etc.)
    pass
```

### Date and Time Utilities

```python
from core.utils.date_time import (
    utcnow, now_with_timezone, format_datetime, parse_iso_datetime,
    format_relative_time, date_range, calculate_time_difference
)

# Get current UTC time with timezone information
current_time = utcnow()

# Get current time in specific timezone
local_time = now_with_timezone(get_timezone("America/New_York"))

# Parse ISO 8601 date string
event_date = parse_iso_datetime("2024-07-15T14:30:00Z")

# Format as human-readable relative time
time_display = format_relative_time(event_date)  # e.g., "2 hours ago" or "in 3 days"

# Format with specific format string
formatted_date = format_datetime(event_date, "%Y-%m-%d %H:%M", use_utc=True)

# Generate a date range for the next week
next_week = date_range(utcnow(), utcnow() + timedelta(days=7))

# Calculate time difference with proper timezone handling
time_diff = calculate_time_difference(start_time, end_time)
duration_str = format_duration(time_diff)  # e.g., "2 hours 30 minutes"

# Check if a date is in the future
if is_future_date(event_date):
    # Schedule event
    pass

# Check if two dates are on the same day
if is_same_day(date1, date2):
    # Combine events
    pass

# Get start and end of business day
day_start = beginning_of_day(current_time)
day_end = end_of_day(current_time)

# Convert between timestamp formats
epoch_time = to_timestamp(current_time)  # Get Unix timestamp
datetime_obj = from_timestamp(epoch_time)  # Convert back to datetime
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
- Security Controls Framework
- Configuration Management Guide
- Error Handling Standards
- Coding Standards

## Version Information

- **Version**: 0.0.1
- **Last Updated**: 2024-07-22
- **Maintainers**: Platform Engineering Team
