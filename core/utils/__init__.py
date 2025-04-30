"""
Core utility functions for the Cloud Infrastructure Platform.

This package provides common utility modules that can be reused across
different components of the application. It contains string manipulation,
file processing, format conversion, and other general-purpose utilities.

Key modules:
- string: Text manipulation, formatting, and conversion utilities
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

__all__ = [
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
    'truncate_middle'
]
