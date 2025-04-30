"""
Security utility functions for Cloud Infrastructure Platform.

This module provides lightweight security utilities that can be used outside
the core security module including:
- Simple encryption and hashing
- Token generation and validation
- Input sanitization
- Rate limiting helpers
- General security utilities

These utilities provide security functionality that doesn't require the full
security framework, suitable for lightweight usage across the application.
"""

import base64
import hashlib
import hmac
import os
import re
import secrets
import string
import time
from typing import Any, Dict, List, Optional, Tuple, Union, Callable
from datetime import datetime, timedelta


def generate_random_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.

    Args:
        length: Length of token to generate

    Returns:
        Secure random token string
    """
    return secrets.token_urlsafe(length)


def generate_hmac_token(
    key: str,
    message: str,
    algorithm: str = 'sha256',
    expires_in: Optional[int] = None
) -> str:
    """
    Generate an HMAC token with optional expiration time.

    Args:
        key: Secret key for HMAC generation
        message: Message to authenticate
        algorithm: Hash algorithm to use
        expires_in: Optional expiration time in seconds

    Returns:
        HMAC token with optional expiration
    """
    # Add expiration time if requested
    if expires_in is not None:
        expiration = int(time.time()) + expires_in
        message = f"{message}|{expiration}"

    # Generate HMAC
    h = hmac.new(key.encode('utf-8'), message.encode('utf-8'), getattr(hashlib, algorithm))
    signature = h.hexdigest()

    # Format token
    token = f"{message}|{signature}"

    # Encode for safe transport
    return base64.urlsafe_b64encode(token.encode('utf-8')).decode('utf-8')


def verify_hmac_token(token: str, key: str, algorithm: str = 'sha256') -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Verify an HMAC token and check expiration if applicable.

    Args:
        token: Token to verify
        key: Secret key for HMAC verification
        algorithm: Hash algorithm to use

    Returns:
        Tuple of (is_valid, message, error_reason)
    """
    try:
        # Decode token
        decoded = base64.urlsafe_b64decode(token.encode('utf-8')).decode('utf-8')

        # Split parts
        parts = decoded.split('|')
        if len(parts) < 2:
            return False, None, "Invalid token format"

        signature = parts[-1]
        message_parts = parts[:-1]
        message = '|'.join(message_parts)

        # Check for expiration
        if len(message_parts) > 1:
            try:
                expiration = int(message_parts[-1])
                if int(time.time()) > expiration:
                    return False, None, "Token expired"

                # Original message is everything except the last part (expiration)
                original_message = '|'.join(message_parts[:-1])
            except ValueError:
                # If we can't parse as int, treat it as part of the message
                original_message = message
        else:
            original_message = message

        # Verify HMAC
        h = hmac.new(key.encode('utf-8'), message.encode('utf-8'), getattr(hashlib, algorithm))
        expected_signature = h.hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            return False, None, "Invalid signature"

        return True, original_message, None

    except Exception as e:
        return False, None, f"Token validation error: {str(e)}"


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Generate a secure hash for a password with salt.

    Args:
        password: Password to hash
        salt: Optional salt (generated if None)

    Returns:
        Tuple of (hash, salt)
    """
    if salt is None:
        salt = secrets.token_hex(16)

    # Create hash with salt
    h = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # Number of iterations
    )

    return base64.b64encode(h).decode('utf-8'), salt


def verify_password_hash(password: str, password_hash: str, salt: str) -> bool:
    """
    Verify a password against a hash and salt.

    Args:
        password: Password to verify
        password_hash: Stored password hash
        salt: Salt used for hashing

    Returns:
        True if password matches hash, False otherwise
    """
    h = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # Number of iterations
    )

    calculated_hash = base64.b64encode(h).decode('utf-8')
    return hmac.compare_digest(calculated_hash, password_hash)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent directory traversal and other issues.

    Args:
        filename: Filename to sanitize

    Returns:
        Sanitized filename
    """
    # Remove directory traversal components and limit to basename
    sanitized = os.path.basename(filename)

    # Remove any null bytes or other control characters
    sanitized = re.sub(r'[\x00-\x1f]', '', sanitized)

    # Replace potentially dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', sanitized)

    # Ensure non-empty result
    if not sanitized:
        sanitized = "unnamed_file"

    return sanitized


def obfuscate_sensitive_data(
    data: str,
    prefix_visible: int = 0,
    suffix_visible: int = 4,
    mask_char: str = '*'
) -> str:
    """
    Obfuscate sensitive data like API keys or PII.

    Args:
        data: String to obfuscate
        prefix_visible: Number of characters to show at beginning
        suffix_visible: Number of characters to show at end
        mask_char: Character to use for masking

    Returns:
        Obfuscated string
    """
    if not data:
        return ""

    data_len = len(data)

    # Adjust visible parts if they exceed data length
    if prefix_visible + suffix_visible >= data_len:
        if data_len <= 4:
            # Very short string, mask it entirely
            return mask_char * data_len
        else:
            # Adjust to show at most half from each end
            total_visible = data_len // 2
            prefix_visible = total_visible // 2
            suffix_visible = total_visible - prefix_visible

    # Create masked string
    masked_length = data_len - prefix_visible - suffix_visible
    return data[:prefix_visible] + (mask_char * masked_length) + data[-suffix_visible:] if suffix_visible else data[:prefix_visible] + (mask_char * masked_length)


def is_safe_redirect_url(url: str, allowed_hosts: List[str] = None) -> bool:
    """
    Check if a URL is safe for redirection to prevent open redirects.

    Args:
        url: URL to check
        allowed_hosts: List of allowed redirect hosts (if None, only relative URLs are allowed)

    Returns:
        True if URL is safe for redirection, False otherwise
    """
    if not url:
        return False

    # Allow relative URLs that start with / and don't include protocol markers
    if url.startswith('/') and not url.startswith('//') and '//' not in url:
        return True

    # For absolute URLs, check against allowed hosts
    if allowed_hosts:
        import urllib.parse
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.netloc in allowed_hosts
        except ValueError:
            return False

    # If no allowed hosts specified, only allow relative URLs
    return False


def generate_secure_password(
    length: int = 16,
    include_uppercase: bool = True,
    include_lowercase: bool = True,
    include_digits: bool = True,
    include_special: bool = True
) -> str:
    """
    Generate a secure random password.

    Args:
        length: Length of password to generate
        include_uppercase: Whether to include uppercase letters
        include_lowercase: Whether to include lowercase letters
        include_digits: Whether to include digits
        include_special: Whether to include special characters

    Returns:
        Secure random password

    Raises:
        ValueError: If no character sets are selected
    """
    # Prepare character sets based on parameters
    char_sets = []

    if include_lowercase:
        char_sets.append(string.ascii_lowercase)

    if include_uppercase:
        char_sets.append(string.ascii_uppercase)

    if include_digits:
        char_sets.append(string.digits)

    if include_special:
        char_sets.append('!@#$%^&*()-_=+[]{}|;:,.<>?')

    if not char_sets:
        raise ValueError("At least one character set must be included")

    # Build full character set
    all_chars = ''.join(char_sets)

    # Ensure at least one character from each selected set
    password = []
    for char_set in char_sets:
        password.append(secrets.choice(char_set))

    # Fill the rest with random selections from all chars
    remaining = length - len(password)
    for _ in range(remaining):
        password.append(secrets.choice(all_chars))

    # Shuffle the password characters
    secrets.SystemRandom().shuffle(password)

    return ''.join(password)


def compute_hash(
    data: Union[str, bytes],
    algorithm: str = 'sha256',
    encoding: str = 'utf-8'
) -> str:
    """
    Compute a hash of data using specified algorithm.

    Args:
        data: Data to hash
        algorithm: Hash algorithm to use
        encoding: Encoding to use if data is a string

    Returns:
        Hexadecimal digest of hash

    Raises:
        ValueError: If algorithm is not supported
    """
    if algorithm not in hashlib.algorithms_guaranteed:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    hasher = hashlib.new(algorithm)

    # Convert string to bytes if needed
    if isinstance(data, str):
        data = data.encode(encoding)

    hasher.update(data)
    return hasher.hexdigest()
