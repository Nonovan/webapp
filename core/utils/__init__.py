"""
Core utility functions for the Cloud Infrastructure Platform.

This package provides common utility modules that can be reused across
different components of the application. It contains string manipulation,
file processing, format conversion, and other general-purpose utilities.

Key modules:
- string: Text manipulation, formatting, and conversion utilities
- date_time: Date and time handling with timezone support
- collection: Collection data structure operations
- file: File handling and path management
- validation: Input validation utilities
- security: Security-related utilities
"""

# Import slugify and other commonly used functions from string module
# to make them directly accessible via core.utils.string
from .string import (
    # Formatting and conversion
    slugify,
    truncate_text,
    strip_html_tags,
    sanitize_text,
    snake_to_camel,
    camel_to_snake,
    snake_to_pascal,
    format_bytes,

    # String generation and manipulation
    generate_random_string,
    generate_excerpt,
    generate_secure_filename,
    join_with_oxford_comma,
    joinlines,

    # Validation and checking
    is_valid_email,
    is_valid_url,
    is_valid_slug,
    has_common_substring,
    contains_html,

    # Security
    mask_sensitive_data,
    escape_html,
    escape_quotes,

    # Text operations
    normalize_whitespace,
    pluralize,
    extract_domain,
    replace_urls_with_links,
    get_string_length_in_bytes,
    truncate_middle
)

# Import date and time utilities
from .date_time import (
    # Core datetime functions
    utcnow,
    now_with_timezone,
    format_datetime,
    parse_iso_datetime,
    format_timestamp,

    # Timezone operations
    get_timezone,
    convert_timezone,

    # Formatting and display
    format_relative_time,
    format_duration,

    # Time calculations and comparison
    calculate_time_difference,
    is_same_day,
    is_future_date,
    is_past_date,

    # Date ranges and manipulation
    date_range,
    add_time_interval,
    beginning_of_day,
    end_of_day,

    # Timestamp conversions
    to_timestamp,
    from_timestamp
)

# Import collection utilities
from .collection import (
    # Dictionary operations
    deep_get,
    deep_set,
    merge_dicts,
    flatten_dict,
    unflatten_dict,

    # List and array operations
    chunk_list,
    find_duplicates,
    group_by,
    unique_by,

    # Filtering and transformation
    filter_none,
    filter_empty,
    filter_dict_by_keys,
    transform_keys,
    transform_values
)

# Import file utilities
from .file import (
    # File operations
    read_file,
    write_file,
    append_to_file,
    ensure_directory_exists,

    # File security and integrity
    compute_file_hash,
    is_path_safe,
    sanitize_filename,

    # File formats
    read_json_file,
    save_json_file,
    read_yaml_file,
    save_yaml_file
)

# Import validation utilities
from .validation import (
    # Schema validation
    validate_with_schema,
    validate_dict,

    # Input validation
    is_valid_ip_address,
    is_valid_hostname,
    is_valid_port,
    is_valid_uuid,

    # Type checking
    is_iterable,
    is_mapping,
    is_sequence,
    is_numeric
)

# Import security utilities
from .security import (
    # Security tokens
    generate_secure_token,
    validate_secure_token,

    # Password security
    check_password_strength,
    mask_password,

    # URL security
    is_safe_redirect_url,
    sanitize_url
)

__all__ = [
    # String utilities
    'slugify',
    'truncate_text',
    'strip_html_tags',
    'sanitize_text',
    'snake_to_camel',
    'camel_to_snake',
    'snake_to_pascal',
    'format_bytes',
    'generate_random_string',
    'generate_excerpt',
    'generate_secure_filename',
    'join_with_oxford_comma',
    'joinlines',
    'is_valid_email',
    'is_valid_url',
    'is_valid_slug',
    'has_common_substring',
    'contains_html',
    'mask_sensitive_data',
    'escape_html',
    'escape_quotes',
    'normalize_whitespace',
    'pluralize',
    'extract_domain',
    'replace_urls_with_links',
    'get_string_length_in_bytes',
    'truncate_middle',

    # Date and time utilities
    'utcnow',
    'now_with_timezone',
    'format_datetime',
    'parse_iso_datetime',
    'get_timezone',
    'convert_timezone',
    'format_relative_time',
    'format_duration',
    'calculate_time_difference',
    'is_same_day',
    'is_future_date',
    'is_past_date',
    'date_range',
    'add_time_interval',
    'beginning_of_day',
    'end_of_day',
    'to_timestamp',
    'from_timestamp',
    'format_timestamp',

    # Collection utilities
    'deep_get',
    'deep_set',
    'merge_dicts',
    'flatten_dict',
    'unflatten_dict',
    'chunk_list',
    'find_duplicates',
    'group_by',
    'unique_by',
    'filter_none',
    'filter_empty',
    'filter_dict_by_keys',
    'transform_keys',
    'transform_values',

    # File utilities
    'read_file',
    'write_file',
    'append_to_file',
    'ensure_directory_exists',
    'compute_file_hash',
    'is_path_safe',
    'sanitize_filename',
    'read_json_file',
    'save_json_file',
    'read_yaml_file',
    'save_yaml_file',

    # Validation utilities
    'validate_with_schema',
    'validate_dict',
    'is_valid_ip_address',
    'is_valid_hostname',
    'is_valid_port',
    'is_valid_uuid',
    'is_iterable',
    'is_mapping',
    'is_sequence',
    'is_numeric',

    # Security utilities
    'generate_secure_token',
    'validate_secure_token',
    'check_password_strength',
    'mask_password',
    'is_safe_redirect_url',
    'sanitize_url'
]
