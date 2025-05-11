"""
String utility functions for Cloud Infrastructure Platform.

This module provides reusable string manipulation functionality including:
- Slugification for URL-friendly strings
- Text sanitization for security purposes
- String truncation and formatting
- HTML and special character handling
- Case conversion utilities
- Pattern matching and validation helpers

These utilities are designed to be used across the application to ensure
consistent string handling behavior.
"""

import bleach
import re
import unicodedata
import uuid
from typing import Optional, List, Dict, Any, Set, Tuple, Union, Pattern

# Import centralized constants
from core.utils.core_utils_constants import (
    DEFAULT_TRUNCATE_LENGTH,
    DEFAULT_EXCERPT_LENGTH,
    DEFAULT_RANDOM_STRING_LENGTH,
    DEFAULT_RANDOM_STRING_CHARS,
    SECURE_RANDOM_STRING_CHARS,
    DEFAULT_ALLOWED_TAGS,
    DEFAULT_ALLOWED_ATTRIBUTES,
    ASCII_LOWERCASE,
    ASCII_UPPERCASE,
    ASCII_LETTERS,
    DIGITS,
    HEXDIGITS,
    EMAIL_PATTERN,
    URL_PATTERN,
    SLUG_PATTERN,
)

# String truncation defaults
DEFAULT_TRUNCATE_SUFFIX = "..."

# Slug generation defaults
DEFAULT_SLUG_SEPARATOR = "-"
DEFAULT_SLUG_LOWERCASE = True
DEFAULT_SLUG_STRIP_DIACRITICS = True

# Derived constants
ALPHANUMERIC = ASCII_LETTERS + DIGITS

# Compiled regexes for better performance
EMAIL_REGEX = re.compile(EMAIL_PATTERN)
URL_REGEX = re.compile(URL_PATTERN)
SLUG_REGEX = re.compile(SLUG_PATTERN)


def slugify(text: str, separator: str = DEFAULT_SLUG_SEPARATOR,
            lowercase: bool = DEFAULT_SLUG_LOWERCASE,
            strip_diacritics: bool = DEFAULT_SLUG_STRIP_DIACRITICS,
            allow_unicode: bool = False) -> str:
    """
    Convert text to URL-friendly slug.

    Args:
        text: String to convert to slug
        separator: Character to use between words (default: '-')
        lowercase: Whether to convert to lowercase (default: True)
        strip_diacritics: Whether to remove diacritical marks (default: True)
        allow_unicode: Whether to allow Unicode characters in output (default: False)

    Returns:
        URL-friendly slug string
    """
    if not text:
        return ""

    # Convert to lowercase if specified
    if lowercase:
        text = text.lower()

    # Normalize Unicode characters
    if not allow_unicode and strip_diacritics:
        # Convert to ASCII, removing diacritical marks
        text = unicodedata.normalize('NFKD', text)
        text = ''.join([c for c in text if not unicodedata.combining(c)])
    elif not allow_unicode:
        # Convert to ASCII but keep structure of diacritical marks if not stripping
        text = unicodedata.normalize('NFKC', text)
        text = ''.join([c for c in text if ord(c) < 128])
    else:
        # Just normalize Unicode if allowing Unicode
        text = unicodedata.normalize('NFKC', text)

    # Replace spaces and unwanted chars with separator
    text = re.sub(r'[^\w\s-]', '', text)  # Remove non-word, non-space, non-dash chars
    text = re.sub(r'[\s_-]+', separator, text)  # Replace spaces, underscores, dashes with separator
    text = text.strip(separator)  # Remove leading/trailing separators

    return text


def truncate_text(text: str, length: int = DEFAULT_TRUNCATE_LENGTH,
                 suffix: str = DEFAULT_TRUNCATE_SUFFIX,
                 word_boundary: bool = True) -> str:
    """
    Truncate text to specified length.

    Args:
        text: String to truncate
        length: Maximum length (default: 80)
        suffix: String to append to truncated text (default: "...")
        word_boundary: Whether to truncate at word boundary (default: True)

    Returns:
        Truncated string with suffix
    """
    if not text or len(text) <= length:
        return text

    # Adjust length to account for suffix
    length_with_suffix = length - len(suffix)
    if length_with_suffix <= 0:
        return suffix[:length]

    truncated = text[:length_with_suffix]

    # If truncating at word boundary, find last space
    if word_boundary:
        last_space = truncated.rfind(' ')
        if last_space > 0:
            truncated = truncated[:last_space]

    return truncated + suffix


def strip_html_tags(text: str) -> str:
    """
    Remove HTML tags from text.

    Args:
        text: String containing HTML markup

    Returns:
        String with HTML tags removed
    """
    if not text:
        return ""

    # Simple HTML tag removal
    clean_text = re.sub(r'<[^>]+>', '', text)

    # Fix common entity references
    clean_text = clean_text.replace('&nbsp;', ' ')
    clean_text = clean_text.replace('&amp;', '&')
    clean_text = clean_text.replace('&lt;', '<')
    clean_text = clean_text.replace('&gt;', '>')
    clean_text = clean_text.replace('&quot;', '"')

    # Normalize whitespace
    clean_text = ' '.join(clean_text.split())

    return clean_text


def sanitize_text(text: str, allowed_tags: Optional[List[str]] = None,
                 strip_comments: bool = True) -> str:
    """
    Sanitize text by removing or escaping potentially harmful content.

    Args:
        text: String to sanitize
        allowed_tags: List of HTML tags to allow (default: None)
        strip_comments: Whether to remove HTML comments (default: True)

    Returns:
        Sanitized string
    """
    if not text:
        return ""

    # Remove HTML comments if specified
    if strip_comments:
        text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL)

    # If no tags are allowed, strip all HTML tags
    if not allowed_tags:
        return strip_html_tags(text)

    # Convert allowed tags to lowercase for comparison
    allowed_tags = [tag.lower() for tag in allowed_tags]

    # Use regex to find all HTML tags
    def replace_tag(match):
        tag = match.group(1).lower()
        if tag in allowed_tags:
            return match.group(0)
        return '&lt;' + match.group(1) + match.group(2) + '&gt;'

    sanitized = re.sub(r'<([a-zA-Z][a-zA-Z0-9]*)([^>]*)>', replace_tag, text)
    sanitized = re.sub(r'</([a-zA-Z][a-zA-Z0-9]*)>', replace_tag, sanitized)

    return sanitized


def sanitize_html(html_content: str,
                  allowed_tags: Optional[List[str]] = None,
                  allowed_attributes: Optional[Dict[str, List[str]]] = None,
                  strip_comments: bool = True) -> str:
    """
    Sanitize HTML content to prevent XSS attacks and ensure safe rendering.

    This is a specialized version of sanitize_text that focuses specifically on
    sanitizing HTML content while maintaining the structure and formatting of the
    allowed HTML elements. It removes potentially dangerous tags and attributes.

    Args:
        html_content: The HTML content to sanitize
        allowed_tags: List of allowed HTML tags (defaults to safe subset)
        allowed_attributes: Dictionary mapping tags to allowed attributes
        strip_comments: Whether to remove HTML comments

    Returns:
        Sanitized HTML content safe for rendering
    """
    if not html_content:
        return ""

    # Default safe tags if none provided
    if allowed_tags is None:
        allowed_tags = DEFAULT_ALLOWED_TAGS

    # Default safe attributes if none provided
    if allowed_attributes is None:
        allowed_attributes = DEFAULT_ALLOWED_ATTRIBUTES

    try:
        # Try to use the html-sanitizer package if available (preferred)
        from html_sanitizer import Sanitizer

        sanitizer_config = {
            'tags': allowed_tags,
            'attributes': allowed_attributes,
            'empty': ['br', 'hr', 'img'],
            'separate': ['div', 'blockquote', 'p', 'table', 'tr', 'td', 'th'],
        }

        sanitizer = Sanitizer(sanitizer_config)
        return sanitizer.sanitize(html_content)
    except ImportError:
        # Fallback to using bleach if available
        try:
            # Use the allowed attributes format required by bleach
            bleach_attrs = {}
            for tag, attrs in allowed_attributes.items():
                for attr in attrs:
                    if attr in bleach_attrs:
                        bleach_attrs[attr].append(tag)
                    else:
                        bleach_attrs[attr] = [tag]

            sanitized = bleach.clean(
                html_content,
                tags=allowed_tags,
                attributes=bleach_attrs,
                strip=True,
                strip_comments=strip_comments
            )
            return sanitized
        except ImportError:
            # Last resort fallback using simple regex replacement
            import re

            # First strip all comments if requested
            if strip_comments:
                html_content = re.sub(r'<!--.*?-->', '', html_content, flags=re.DOTALL)

            # Simple tag stripping function
            def replace_tags(content):
                # Use regex to find all tags
                all_tags = re.findall(r'<([^<>]*)>', content)

                # Process content by replacing disallowed tags
                for tag_content in all_tags:
                    # Check if it's a closing tag
                    if tag_content.startswith('/'):
                        tag_name = tag_content[1:].split()[0].lower()
                        if tag_name not in allowed_tags:
                            # Remove disallowed closing tag
                            content = content.replace(f'<{tag_content}>', '')
                    else:
                        # Opening tag or self-closing tag
                        tag_parts = tag_content.split()
                        if not tag_parts:
                            continue

                        tag_name = tag_parts[0].lower()

                        # Handle self-closing tags
                        is_self_closing = tag_content.endswith('/')
                        if is_self_closing:
                            tag_name = tag_name.rstrip('/')

                        if tag_name not in allowed_tags:
                            # Remove disallowed tag
                            content = content.replace(f'<{tag_content}>', '')
                        else:
                            # For allowed tags, filter attributes
                            if len(tag_parts) > 1 and tag_name in allowed_attributes:
                                # Rebuild tag with only allowed attributes
                                allowed_attrs_list = allowed_attributes.get(tag_name, [])
                                filtered_parts = [tag_name]

                                # Extract attributes
                                attr_pattern = r'([a-zA-Z0-9_-]+)(?:=(?:"([^"]*)"|\\'([^\']*)\\'|([^ >]*)))?'
                                attr_matches = re.findall(attr_pattern, ' '.join(tag_parts[1:]))

                                for attr_name, dq_val, sq_val, nq_val in attr_matches:
                                    if attr_name.lower() in allowed_attrs_list:
                                        value = dq_val or sq_val or nq_val
                                        if value:
                                            # Escape attribute values to prevent XSS
                                            value = value.replace('"', '&quot;')
                                            filtered_parts.append(f'{attr_name}="{value}"')
                                        else:
                                            filtered_parts.append(attr_name)

                                # Rebuild the tag with allowed attributes
                                new_tag_content = ' '.join(filtered_parts)
                                if is_self_closing:
                                    new_tag_content += ' /'
                                content = content.replace(f'<{tag_content}>', f'<{new_tag_content}>')

                return content

            # Apply tag stripping iteratively until no more changes
            prev_content = ""
            filtered_content = html_content

            # Iterate until no more changes (avoid infinite loops)
            max_iterations = 10
            iteration = 0

            while prev_content != filtered_content and iteration < max_iterations:
                prev_content = filtered_content
                filtered_content = replace_tags(filtered_content)
                iteration += 1

            return filtered_content


def snake_to_camel(text: str) -> str:
    """
    Convert snake_case to camelCase.

    Args:
        text: String in snake_case

    Returns:
        String in camelCase
    """
    if not text:
        return ""

    components = text.split('_')
    return components[0] + ''.join(x.title() for x in components[1:])


def snake_to_pascal(text: str) -> str:
    """
    Convert snake_case to PascalCase.

    Args:
        text: String in snake_case

    Returns:
        String in PascalCase
    """
    if not text:
        return ""

    return ''.join(x.title() for x in text.split('_'))


def camel_to_snake(text: str) -> str:
    """
    Convert camelCase to snake_case.

    Args:
        text: String in camelCase

    Returns:
        String in snake_case
    """
    if not text:
        return ""

    # Insert underscore before uppercase letters and convert to lowercase
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', text)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def generate_random_string(length: int = DEFAULT_RANDOM_STRING_LENGTH,
                          chars: str = DEFAULT_RANDOM_STRING_CHARS) -> str:
    """
    Generate a random string of specified length.

    Args:
        length: Length of the random string (default from core_utils_constants)
        chars: Character set to use (default from core_utils_constants)

    Returns:
        Random string
    """
    import secrets

    # Use cryptographically strong random generation
    return ''.join(secrets.choice(chars) for _ in range(length))


def is_valid_email(email: str) -> bool:
    """
    Check if string is a valid email address.

    Args:
        email: String to validate as email address

    Returns:
        True if valid email, False otherwise
    """
    if not email:
        return False

    # Use compiled regex from module constants
    return bool(EMAIL_REGEX.match(email))


def is_valid_url(url: str) -> bool:
    """
    Check if string is a valid URL.

    Args:
        url: String to validate as URL

    Returns:
        True if valid URL, False otherwise
    """
    if not url:
        return False

    # Use compiled regex from module constants
    return bool(URL_REGEX.match(url))


def is_valid_slug(slug: str) -> bool:
    """
    Check if string is a valid slug.

    Args:
        slug: String to validate as slug

    Returns:
        True if valid slug, False otherwise
    """
    if not slug:
        return False

    # Use compiled regex from module constants
    return bool(SLUG_REGEX.match(slug))


def format_bytes(size_bytes: int) -> str:
    """
    Format bytes to human-readable string.

    Args:
        size_bytes: Size in bytes

    Returns:
        Human-readable string (e.g., "2.5 MB")
    """
    if size_bytes < 0:
        raise ValueError("Size must be non-negative")

    if size_bytes == 0:
        return "0 B"

    # Define size units and their threshold in bytes
    units = [('B', 1), ('KB', 1024), ('MB', 1024**2),
             ('GB', 1024**3), ('TB', 1024**4), ('PB', 1024**5)]

    # Find appropriate unit
    unit_index = 0
    for i, (unit, threshold) in enumerate(units):
        if size_bytes < threshold * 1024 or i == len(units) - 1:
            unit_index = i
            break

    # Format with appropriate precision
    unit, threshold = units[unit_index]
    value = size_bytes / threshold

    if value < 10:
        return f"{value:.2f} {unit}"
    elif value < 100:
        return f"{value:.1f} {unit}"
    else:
        return f"{int(value)} {unit}"


def pluralize(singular: str, count: int, plural: Optional[str] = None) -> str:
    """
    Return singular or plural form based on count.

    Args:
        singular: Singular form of word
        count: Count determining form
        plural: Plural form (if None, adds 's' to singular)

    Returns:
        Appropriate form based on count
    """
    if count == 1:
        return singular

    if plural is not None:
        return plural

    # Simple pluralization rules
    if singular.endswith(('s', 'sh', 'ch', 'x', 'z')):
        return singular + 'es'
    elif singular.endswith('y') and len(singular) > 1 and \
         singular[-2] not in 'aeiou':
        return singular[:-1] + 'ies'
    else:
        return singular + 's'


def generate_secure_filename(original_filename: str) -> str:
    """
    Generate a secure filename that preserves the original extension.

    Args:
        original_filename: Original filename

    Returns:
        Secure filename with original extension
    """
    if not original_filename:
        return ""

    # Extract extension if present
    parts = original_filename.rsplit('.', 1)

    # Generate a UUID for the filename
    secure_name = str(uuid.uuid4())

    # Add original extension if present and safe
    if len(parts) > 1:
        extension = parts[1].lower()
        # Only allow safe extensions - limit to alphanumeric characters
        # and ensure it's not too long
        if re.match(r'^[a-z0-9]{1,10}$', extension):
            return f"{secure_name}.{extension}"

    return secure_name


def join_with_oxford_comma(items: List[str],
                          conjunction: str = "and") -> str:
    """
    Join list items with commas and conjunction.

    Args:
        items: List of strings to join
        conjunction: Conjunction to use (default: "and")

    Returns:
        Comma-separated string with conjunction before last item
    """
    if not items:
        return ""

    if len(items) == 1:
        return items[0]

    if len(items) == 2:
        return f"{items[0]} {conjunction} {items[1]}"

    return ", ".join(items[:-1]) + f", {conjunction} {items[-1]}"


def joinlines(lines: List[str]) -> str:
    """
    Join multiple strings with newlines.

    Args:
        lines: List of strings to join

    Returns:
        Newline-joined string
    """
    if not lines:
        return ""

    return "\n".join(lines)


def extract_domain(url: str) -> str:
    """
    Extract domain name from URL.

    Args:
        url: URL string

    Returns:
        Domain name or empty string if not found
    """
    if not url:
        return ""

    import urllib.parse
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc
    except Exception:
        return ""


def normalize_whitespace(text: str) -> str:
    """
    Normalize whitespace in text (convert multiple spaces to single space).

    Args:
        text: String to normalize

    Returns:
        String with normalized whitespace
    """
    if not text:
        return ""

    # Replace tabs and newlines with spaces
    text = re.sub(r'[\t\n\r]+', ' ', text)

    # Replace multiple spaces with single space
    text = re.sub(r'\s+', ' ', text)

    return text.strip()


def contains_html(text: str) -> bool:
    """
    Check if text contains HTML markup.

    Args:
        text: String to check

    Returns:
        True if HTML markup detected, False otherwise
    """
    if not text:
        return False

    # Simple check for HTML tags
    return bool(re.search(r'<[a-z][a-z0-9]*(\s+[^>]*)?>', text, re.IGNORECASE))


def replace_urls_with_links(text: str, target: str = "_blank",
                           css_class: str = "auto-link") -> str:
    """
    Replace URLs in text with HTML links.

    Args:
        text: Text to process
        target: Link target attribute (default: "_blank")
        css_class: CSS class to add to links (default: "auto-link")

    Returns:
        Text with URLs converted to HTML links
    """
    if not text:
        return ""

    # Pattern for URLs
    url_pattern = r'(https?://[^\s<>"]+|www\.[^\s<>"]+)'

    def replacer(match):
        url = match.group(0)
        display_url = url

        # Add https:// to URLs starting with www.
        if url.startswith('www.'):
            url = 'https://' + url

        # Escape attributes to prevent XSS
        url = url.replace('"', '%22')
        target_attr = target.replace('"', '%22')
        css_class_attr = css_class.replace('"', '%22')

        return f'<a href="{url}" target="{target_attr}" class="{css_class_attr}">{display_url}</a>'

    return re.sub(url_pattern, replacer, text)


def get_string_length_in_bytes(text: str, encoding: str = 'utf-8') -> int:
    """
    Get length of string in bytes for specified encoding.

    Args:
        text: String to measure
        encoding: Character encoding (default: 'utf-8')

    Returns:
        Length in bytes
    """
    if not text:
        return 0

    return len(text.encode(encoding))


def escape_html(text: str) -> str:
    """
    Escape HTML special characters in text.

    Args:
        text: String to escape

    Returns:
        HTML-escaped string
    """
    if not text:
        return ""

    # Replace HTML special characters with entities
    replacements = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'  # or &apos;
    }

    for char, entity in replacements.items():
        text = text.replace(char, entity)

    return text


def escape_quotes(text: str, double_only: bool = False) -> str:
    """
    Escape quotes in text.

    Args:
        text: String to escape
        double_only: Whether to escape only double quotes (default: False)

    Returns:
        String with escaped quotes
    """
    if not text:
        return ""

    # Escape double quotes
    text = text.replace('"', '\\"')

    # Also escape single quotes if requested
    if not double_only:
        text = text.replace("'", "\\'")

    return text


def has_common_substring(text1: str, text2: str, min_length: int = 3) -> bool:
    """
    Check if two strings share a common substring of minimum length.

    Args:
        text1: First string
        text2: Second string
        min_length: Minimum substring length to consider (default: 3)

    Returns:
        True if common substring found, False otherwise
    """
    if not text1 or not text2 or min_length <= 0:
        return False

    # Use dynamic programming for efficiency
    len1, len2 = len(text1), len(text2)

    # Memory optimization for very long strings
    if len1 * len2 > 10_000_000:  # Arbitrary large threshold
        # Fall back to a simpler approach for very long strings
        for i in range(len(text1) - min_length + 1):
            substr = text1[i:i + min_length]
            if substr in text2:
                return True
        return False

    # For smaller strings use dynamic programming
    dp = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    max_length = 0

    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            if text1[i-1] == text2[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1
                max_length = max(max_length, dp[i][j])

    return max_length >= min_length


def generate_excerpt(content: str, max_length: int = DEFAULT_EXCERPT_LENGTH,
                    strip_markup: bool = True) -> str:
    """
    Generate a short excerpt from longer content.

    Args:
        content: Source content
        max_length: Maximum excerpt length (default from core_utils_constants)
        strip_markup: Whether to strip HTML markup (default: True)

    Returns:
        Truncated excerpt with proper word boundaries
    """
    if not content:
        return ""

    # Strip HTML tags if requested
    text = strip_html_tags(content) if strip_markup else content

    # Normalize whitespace
    text = normalize_whitespace(text)

    # Truncate with word boundaries
    return truncate_text(text, max_length, word_boundary=True)


def mask_sensitive_data(text: str, pattern: Optional[Union[str, Pattern]] = None,
                       mask_char: str = '*', keep_prefix: int = 0,
                       keep_suffix: int = 0) -> str:
    """
    Mask sensitive data in text based on pattern.

    Args:
        text: Text containing sensitive data
        pattern: Regular expression pattern (default: None - masks all)
        mask_char: Character to use for masking (default: '*')
        keep_prefix: Number of characters to keep at beginning (default: 0)
        keep_suffix: Number of characters to keep at end (default: 0)

    Returns:
        Text with sensitive data masked
    """
    if not text:
        return ""

    # Security check - ensure mask_char is a single, safe character
    if len(mask_char) != 1 or not mask_char.isprintable():
        mask_char = '*'

    if not pattern:
        # If no pattern specified, mask the entire string
        visible_length = keep_prefix + keep_suffix

        if visible_length >= len(text):
            return text

        if visible_length == 0:
            return mask_char * len(text)

        masked_part = mask_char * (len(text) - visible_length)
        return text[:keep_prefix] + masked_part + text[-keep_suffix:] if keep_suffix else text[:keep_prefix] + masked_part

    # If pattern is provided as string, compile it
    if isinstance(pattern, str):
        try:
            pattern = re.compile(pattern)
        except re.error:
            # If pattern is invalid, mask everything
            return mask_char * len(text)

    def replacer(match):
        matched = match.group(0)
        visible_length = keep_prefix + keep_suffix

        if visible_length >= len(matched):
            return matched

        if visible_length == 0:
            return mask_char * len(matched)

        masked_part = mask_char * (len(matched) - visible_length)
        return matched[:keep_prefix] + masked_part + matched[-keep_suffix:] if keep_suffix else matched[:keep_prefix] + masked_part

    return pattern.sub(replacer, text)


def truncate_middle(text: str, max_length: int,
                   placeholder: str = "...") -> str:
    """
    Truncate text in the middle, preserving start and end.

    Args:
        text: Text to truncate
        max_length: Maximum length of result including placeholder
        placeholder: String to insert in middle (default: "...")

    Returns:
        Text truncated in the middle
    """
    if not text or len(text) <= max_length:
        return text

    placeholder_len = len(placeholder)

    if max_length <= placeholder_len:
        return placeholder[:max_length]

    # Calculate lengths for start and end portions
    available = max_length - placeholder_len
    start_len = available // 2 + available % 2  # Give extra char to start if odd
    end_len = available // 2

    return text[:start_len] + placeholder + text[-end_len:]


# Define what's available for import from this module
__all__ = [
    # Formatting and conversion
    'slugify',
    'truncate_text',
    'strip_html_tags',
    'sanitize_text',
    'sanitize_html',
    'snake_to_camel',
    'camel_to_snake',
    'snake_to_pascal',
    'format_bytes',

    # String generation and manipulation
    'generate_random_string',
    'generate_excerpt',
    'generate_secure_filename',
    'join_with_oxford_comma',
    'joinlines',

    # Validation and checking
    'is_valid_email',
    'is_valid_url',
    'is_valid_slug',
    'has_common_substring',
    'contains_html',

    # Security
    'mask_sensitive_data',
    'escape_html',
    'escape_quotes',

    # Text operations
    'normalize_whitespace',
    'pluralize',
    'extract_domain',
    'replace_urls_with_links',
    'get_string_length_in_bytes',
    'truncate_middle',

    # Constants
    'DEFAULT_TRUNCATE_LENGTH',
    'DEFAULT_TRUNCATE_SUFFIX',
    'DEFAULT_SLUG_SEPARATOR',
    'DEFAULT_SLUG_LOWERCASE',
    'DEFAULT_SLUG_STRIP_DIACRITICS',
    'ASCII_LOWERCASE',
    'ASCII_UPPERCASE',
    'ASCII_LETTERS',
    'DIGITS',
    'HEXDIGITS',
    'ALPHANUMERIC',
]
