"""
Security utilities for administrative tools.

This module provides security-related functions commonly used by administrative
tools, such as token generation and secure data handling.
"""

import secrets
import string
from typing import Optional


def generate_api_token(prefix: str = "api", length: int = 32) -> str:
    """
    Generate a secure API token.

    Args:
        prefix: Token prefix
        length: Token length in bytes (excluding prefix)

    Returns:
        Prefixed token with format: prefix_base64encodedvalue
    """
    token_bytes = secrets.token_bytes(length)
    import base64
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
    import hashlib
    import base64

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
