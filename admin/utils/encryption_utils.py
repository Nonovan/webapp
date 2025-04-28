"""
Encryption utilities for administrative authentication.

This module provides specialized encryption functionality for administrative
authentication operations, ensuring secure handling of authentication tokens,
session data, and other sensitive authentication-related information.

The module works in conjunction with admin_auth.py and secure_credentials.py
to provide a complete security layer for administrative operations.
"""

import logging
import base64
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timezone

# Internal imports
try:
    from core.security.cs_crypto import (
        encrypt_sensitive_data,
        decrypt_sensitive_data,
        generate_token,
        encrypt_with_rotation,
        decrypt_with_rotation
    )
    from core.loggings import get_logger
    logger = get_logger(__name__)
except ImportError:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.error("Failed to import core security modules. Auth encryption will not function.")
    def encrypt_sensitive_data(data: str) -> str:
        raise NotImplementedError("Core security module not available")
    def decrypt_sensitive_data(data: str) -> str:
        raise NotImplementedError("Core security module not available")
    def generate_token(*args, **kwargs) -> str:
        raise NotImplementedError("Core security module not available")
    def encrypt_with_rotation(*args, **kwargs) -> str:
        raise NotImplementedError("Core security module not available")
    def decrypt_with_rotation(*args, **kwargs) -> str:
        raise NotImplementedError("Core security module not available")

# Constants
AUTH_TOKEN_PREFIX = "adm_auth_"
SESSION_TOKEN_PREFIX = "adm_sess_"
ENCRYPTION_PURPOSE = "admin_auth"


def encrypt_auth_token(token: str) -> Optional[str]:
    """
    Encrypts an administrative authentication token.

    Provides an additional layer of protection for auth tokens by encrypting
    them before storage or transmission.

    Args:
        token: The authentication token to encrypt.

    Returns:
        The encrypted token string, or None if encryption fails.
    """
    if not token:
        return None

    try:
        # Use key rotation for auth tokens to support token revocation
        encrypted_token = encrypt_with_rotation(token, ENCRYPTION_PURPOSE)
        return base64.urlsafe_b64encode(encrypted_token.encode()).decode()
    except Exception as e:
        logger.error(f"Failed to encrypt auth token: {e}", exc_info=False)
        return None


def decrypt_auth_token(encrypted_token: str) -> Optional[str]:
    """
    Decrypts an administrative authentication token.

    Args:
        encrypted_token: The encrypted token to decrypt.

    Returns:
        The decrypted token string, or None if decryption fails.
    """
    if not encrypted_token:
        return None

    try:
        decoded_token = base64.urlsafe_b64decode(encrypted_token).decode()
        return decrypt_with_rotation(decoded_token, ENCRYPTION_PURPOSE)
    except Exception as e:
        logger.error(f"Failed to decrypt auth token: {e}", exc_info=False)
        return None


def encrypt_session_data(session_data: Dict[str, Any]) -> Optional[str]:
    """
    Encrypts administrative session data.

    Args:
        session_data: Dictionary containing session information.

    Returns:
        Encrypted session data string, or None if encryption fails.
    """
    if not session_data:
        return None

    try:
        # Add timestamp for session validation
        session_data['encrypted_at'] = datetime.now(timezone.utc).isoformat()

        # Convert to string for encryption
        data_str = base64.urlsafe_b64encode(
            str(session_data).encode()
        ).decode()

        return encrypt_sensitive_data(data_str)
    except Exception as e:
        logger.error(f"Failed to encrypt session data: {e}", exc_info=False)
        return None


def decrypt_session_data(encrypted_data: str) -> Optional[Dict[str, Any]]:
    """
    Decrypts administrative session data.

    Args:
        encrypted_data: The encrypted session data string.

    Returns:
        Dictionary containing decrypted session data, or None if decryption fails.
    """
    if not encrypted_data:
        return None

    try:
        decrypted_str = decrypt_sensitive_data(encrypted_data)
        if not decrypted_str or decrypted_str == "[DECRYPTION_ERROR]":
            return None

        # Decode the session data
        decoded_data = base64.urlsafe_b64decode(decrypted_str.encode()).decode()
        session_data = eval(decoded_data)  # Safe since we encrypted the data ourselves

        return session_data
    except Exception as e:
        logger.error(f"Failed to decrypt session data: {e}", exc_info=False)
        return None


def generate_auth_token_pair() -> Tuple[Optional[str], Optional[str]]:
    """
    Generates a pair of tokens for authentication and session management.

    Returns:
        Tuple of (auth_token, session_token), or (None, None) if generation fails.
    """
    try:
        auth_token = generate_token(prefix=AUTH_TOKEN_PREFIX)
        session_token = generate_token(prefix=SESSION_TOKEN_PREFIX)
        return auth_token, session_token
    except Exception as e:
        logger.error(f"Failed to generate token pair: {e}", exc_info=True)
        return None, None


def verify_encrypted_token(encrypted_token: str, expected_prefix: str) -> bool:
    """
    Verifies an encrypted authentication or session token.

    Args:
        encrypted_token: The encrypted token to verify.
        expected_prefix: Expected token prefix (AUTH_TOKEN_PREFIX or SESSION_TOKEN_PREFIX).

    Returns:
        True if token is valid, False otherwise.
    """
    try:
        decrypted_token = decrypt_auth_token(encrypted_token)
        if not decrypted_token:
            return False

        # Verify token has correct prefix and format
        return (decrypted_token.startswith(expected_prefix) and
                len(decrypted_token) > len(expected_prefix))
    except Exception as e:
        logger.error(f"Error verifying encrypted token: {e}", exc_info=False)
        return False
