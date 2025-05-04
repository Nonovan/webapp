"""
Security utilities for administrative tools.

This module provides security-related functions commonly used by administrative
tools, such as token generation, secure data handling, file integrity operations,
and baseline management.
"""

import secrets
import string
import logging
import os
import hashlib
import base64
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, Union

# Setup module logger
logger = logging.getLogger(__name__)

# Try to import core security components when available
try:
    from core.security import (
        generate_secure_token, generate_secure_hash,
        check_critical_file_integrity, _consider_baseline_update,
        update_file_integrity_baseline as core_update_baseline
    )
    from core.security.cs_utils import sanitize_path, is_within_directory
    CORE_SECURITY_AVAILABLE = True
except ImportError:
    logger.debug("Core security module not available, using local implementations")
    CORE_SECURITY_AVAILABLE = False


def generate_api_token(prefix: str = "api", length: int = 32) -> str:
    """
    Generate a secure API token.

    Args:
        prefix: Token prefix
        length: Token length in bytes (excluding prefix)

    Returns:
        Prefixed token with format: prefix_base64encodedvalue
    """
    # Try to use the core security token generator if available
    if CORE_SECURITY_AVAILABLE:
        try:
            token = generate_secure_token(length)
            return f"{prefix}_{token}"
        except Exception as e:
            logger.warning(f"Could not use core security token generator: {e}")

    # Fall back to local implementation
    token_bytes = secrets.token_bytes(length)
    token = base64.urlsafe_b64encode(token_bytes).decode('utf-8').rstrip('=')
    return f"{prefix}_{token}"


def compute_hash(data: str, salt: Optional[str] = None) -> tuple[str, str]:
    """
    Compute a secure hash of the data with salt.

    Args:
        data: String to hash
        salt: Optional salt (generated if None)

    Returns:
        Tuple of (hash, salt)
    """
    if salt is None:
        salt = secrets.token_hex(16)

    # Create hash with salt using PBKDF2
    hash_obj = hashlib.pbkdf2_hmac(
        'sha256',
        data.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # Number of iterations
    )

    return base64.b64encode(hash_obj).decode('utf-8'), salt


def calculate_file_hash(filepath: Union[str, Path], algorithm: str = 'sha256') -> Optional[str]:
    """
    Calculate a cryptographic hash for a file.

    Args:
        filepath: Path to the file
        algorithm: Hash algorithm to use ('sha256', 'sha512', etc.)

    Returns:
        Hex digest of the file hash, or None if file can't be read
    """
    if CORE_SECURITY_AVAILABLE:
        try:
            return generate_secure_hash(filepath, algorithm)
        except Exception as e:
            logger.warning(f"Could not use core security hash function: {e}")

    # Fall back to local implementation
    try:
        hash_func = getattr(hashlib, algorithm)()
        filepath = Path(filepath)

        if not filepath.exists() or not filepath.is_file():
            return None

        with open(filepath, 'rb') as f:
            # Read in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)

        return hash_func.hexdigest()
    except (IOError, AttributeError) as e:
        logger.error(f"Error calculating file hash: {e}")
        return None


def secure_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """
    Perform a constant-time comparison to prevent timing attacks.

    Args:
        a: First value to compare
        b: Second value to compare

    Returns:
        True if values match, False otherwise
    """
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')

    return secrets.compare_digest(a, b)


def verify_file_integrity(filepath: Union[str, Path], expected_hash: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
    """
    Verify the integrity of a file against an expected hash or baseline.

    Args:
        filepath: Path to the file to verify
        expected_hash: Expected hash value (if None, will check baseline)

    Returns:
        Tuple of (integrity_verified, details_dict)
    """
    if CORE_SECURITY_AVAILABLE:
        try:
            # Use core file integrity check if available
            return check_critical_file_integrity(filepath, expected_hash)
        except Exception as e:
            logger.warning(f"Could not use core file integrity check: {e}")

    # Fall back to local implementation
    result = {"path": str(filepath), "status": "unknown"}

    filepath = Path(filepath)
    if not filepath.exists():
        result["status"] = "missing"
        return False, result

    current_hash = calculate_file_hash(filepath)
    if current_hash is None:
        result["status"] = "error"
        result["error"] = "Could not calculate hash"
        return False, result

    result["current_hash"] = current_hash

    if expected_hash is None:
        result["status"] = "unknown_baseline"
        return False, result

    result["expected_hash"] = expected_hash
    if current_hash == expected_hash:
        result["status"] = "verified"
        return True, result
    else:
        result["status"] = "modified"
        return False, result


def validate_filepath_safety(filepath: str, allowed_dirs: List[str]) -> bool:
    """
    Validate that a filepath is within allowed directories and has no traversal risks.

    Args:
        filepath: Path to validate
        allowed_dirs: List of allowed directory paths

    Returns:
        True if path is safe, False otherwise
    """
    if CORE_SECURITY_AVAILABLE:
        try:
            for base_dir in allowed_dirs:
                safe_path = sanitize_path(filepath, base_dir)
                if safe_path and is_within_directory(safe_path, base_dir):
                    return True
            return False
        except Exception as e:
            logger.warning(f"Could not use core path safety check: {e}")

    # Fall back to local implementation
    filepath = os.path.abspath(filepath)
    return any(os.path.commonpath([filepath, allowed]) == allowed for allowed in map(os.path.abspath, allowed_dirs))


def generate_secure_random_string(length: int = 16,
                                 include_uppercase: bool = True,
                                 include_lowercase: bool = True,
                                 include_digits: bool = True,
                                 include_special: bool = False) -> str:
    """
    Generate a secure random string with configurable character sets.

    Args:
        length: Length of the string to generate
        include_uppercase: Whether to include uppercase letters
        include_lowercase: Whether to include lowercase letters
        include_digits: Whether to include digits
        include_special: Whether to include special characters

    Returns:
        Randomly generated string with the specified characteristics
    """
    char_set = ''
    if include_uppercase:
        char_set += string.ascii_uppercase
    if include_lowercase:
        char_set += string.ascii_lowercase
    if include_digits:
        char_set += string.digits
    if include_special:
        char_set += string.punctuation

    if not char_set:
        # Default to alphanumeric if no character sets are selected
        char_set = string.ascii_letters + string.digits

    return ''.join(secrets.choice(char_set) for _ in range(length))


def obfuscate_sensitive_data(data: str, sensitive_patterns: Optional[List[str]] = None) -> str:
    """
    Redact or obfuscate sensitive data in strings (like logs or output).

    Args:
        data: String that may contain sensitive data
        sensitive_patterns: List of regex patterns for sensitive data

    Returns:
        String with sensitive data replaced by "[REDACTED]"
    """
    if not data:
        return data

    if sensitive_patterns is None:
        sensitive_patterns = [
            r'password\s*[=:]\s*\S+',
            r'token\s*[=:]\s*\S+',
            r'secret\s*[=:]\s*\S+',
            r'key\s*[=:]\s*\S+',
            r'auth\s*[=:]\s*\S+',
            r'cred\S*\s*[=:]\s*\S+'
        ]

    import re
    result = data
    for pattern in sensitive_patterns:
        result = re.sub(pattern, lambda m: re.sub(r'[=:]\s*\S+', '= [REDACTED]', m.group(0)), result)

    return result
