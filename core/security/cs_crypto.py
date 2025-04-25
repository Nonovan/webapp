"""
Cryptography utilities for the Cloud Infrastructure Platform.

This module provides encryption, decryption, and other cryptographic functions
used to secure sensitive data throughout the application.
"""

import base64
import logging
import os
import re
from typing import Optional
from urllib.parse import urlparse

# Flask imports
from flask import current_app, request, g, has_request_context, session, has_app_context

# Cryptography imports
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Internal imports
from core.utils import log_error
from extensions import metrics
from .security_utils import SECURITY_CONFIG
from core.utils import (
    detect_file_changes, calculate_file_hash, format_timestamp,
    log_critical, log_error, log_warning, log_info, log_debug
)




def _get_encryption_key() -> bytes:
    """
    Retrieve or generate the encryption key.

    This function retrieves the encryption key from the environment variable
    or raises an error if the key is not properly configured.

    Returns:
        bytes: The encryption key as bytes

    Raises:
        RuntimeError: If the encryption key is not configured
    """
    encryption_key = SECURITY_CONFIG.get('ENCRYPTION_KEY')
    if not encryption_key:
        raise RuntimeError("Encryption key is not configured. Please set the ENCRYPTION_KEY environment variable.")
    return encryption_key.encode('utf-8')


def encrypt_sensitive_data(plaintext: str) -> str:
    """
    Encrypt sensitive data using Fernet symmetric encryption.

    This function encrypts sensitive configuration values, API keys,
    and other secret data that needs to be stored securely in the database.
    It uses Fernet (AES-128 in CBC mode with PKCS7 padding and HMAC authentication)
    which provides authenticated encryption.

    Args:
        plaintext: The plaintext string to encrypt

    Returns:
        str: Base64-encoded encrypted string

    Raises:
        RuntimeError: If encryption fails due to missing key or other issues
    """
    if not plaintext:
        return plaintext

    try:
        # Get the encryption key
        key = _get_encryption_key()

        # Convert the key to a URL-safe base64-encoded string as required by Fernet
        key_b64 = base64.urlsafe_b64encode(key)

        # Initialize the Fernet cipher with the key
        cipher = Fernet(key_b64)

        # Encrypt the plaintext and encode as a string
        encrypted_data = cipher.encrypt(plaintext.encode('utf-8'))
        return encrypted_data.decode('utf-8')

    except Exception as e:
        log_error(f"Encryption failed: {e}")
        metrics.increment('security.encryption_failure')
        raise RuntimeError(f"Failed to encrypt sensitive data: {e}")


def decrypt_sensitive_data(encrypted_data: str) -> str:
    """
    Decrypt sensitive data that was encrypted using encrypt_sensitive_data.

    This function decrypts configuration values, API keys, and other secrets
    that were previously encrypted with the encrypt_sensitive_data function.

    Args:
        encrypted_data: Base64-encoded encrypted string

    Returns:
        str: Decrypted plaintext string

    Raises:
        RuntimeError: If decryption fails due to invalid key, tampered data, etc.
    """
    if not encrypted_data:
        return encrypted_data

    try:
        # Get the encryption key
        key = _get_encryption_key()

        # Convert the key to a URL-safe base64-encoded string as required by Fernet
        key_b64 = base64.urlsafe_b64encode(key)

        # Initialize the Fernet cipher with the key
        cipher = Fernet(key_b64)

        # Decrypt the data
        try:
            decrypted_data = cipher.decrypt(encrypted_data.encode('utf-8'))
            return decrypted_data.decode('utf-8')
        except InvalidToken:
            log_warning("Decryption failed: Invalid token or key")
            metrics.increment('security.decryption_failure')
            raise RuntimeError("Decryption failed: Invalid token or key")

    except Exception as e:
        log_error(f"Failed to decrypt sensitive data: {e}")
        raise RuntimeError(f"Failed to decrypt sensitive data: {e}")


def encrypt_aes_gcm(plaintext: str, key: Optional[bytes] = None) -> str:
    """
    Encrypt data using AES-GCM for authenticated encryption.

    This function provides state-of-the-art authenticated encryption using
    AES-GCM mode, which ensures both confidentiality and integrity of the data.

    Args:
        plaintext: The plaintext string to encrypt
        key: Optional encryption key (uses derived key if None)

    Returns:
        str: Base64-encoded encrypted data with embedded nonce and tag

    Raises:
        RuntimeError: If encryption fails
    """
    if not plaintext:
        return plaintext

    try:
        # Get or derive key
        if key is None:
            key = _get_encryption_key()

        # Generate a random 96-bit nonce (recommended size for GCM)
        nonce = os.urandom(12)

        # Create the cipher
        algorithm = algorithms.AES(key)
        mode = modes.GCM(nonce)
        cipher = Cipher(algorithm, mode)

        # Encrypt the plaintext
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()

        # Get the authentication tag
        tag = encryptor.tag

        # Combine nonce, ciphertext and tag for storage
        encrypted_data = nonce + ciphertext + tag

        # Return base64 encoded data
        return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')

    except Exception as e:
        log_error(f"AES-GCM encryption failed: {e}")
        metrics.increment('security.aes_encryption_failure')
        raise RuntimeError(f"Failed to encrypt with AES-GCM: {e}")


def decrypt_aes_gcm(encrypted_data: str, key: Optional[bytes] = None) -> str:
    """
    Decrypt data that was encrypted using AES-GCM.

    This function decrypts data that was encrypted with the encrypt_aes_gcm
    function, verifying both the confidentiality and integrity of the data.

    Args:
        encrypted_data: Base64-encoded encrypted data with embedded nonce and tag
        key: Optional encryption key (uses derived key if None)

    Returns:
        str: Decrypted plaintext string

    Raises:
        RuntimeError: If decryption fails due to invalid key, tampered data, etc.
    """
    if not encrypted_data:
        return encrypted_data

    try:
        # Get or derive key
        if key is None:
            key = _get_encryption_key()

        # Decode the base64 data
        decoded_data = base64.urlsafe_b64decode(encrypted_data)

        # Extract nonce, ciphertext and tag
        nonce = decoded_data[:12]
        tag = decoded_data[-16:]  # GCM tag is 16 bytes
        ciphertext = decoded_data[12:-16]

        # Create the cipher
        algorithm = algorithms.AES(key)
        mode = modes.GCM(nonce, tag)
        cipher = Cipher(algorithm, mode)

        # Decrypt the ciphertext
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext.decode('utf-8')

    except Exception as e:
        log_error(f"AES-GCM decryption failed: {e}")
        metrics.increment('security.aes_decryption_failure')
        raise RuntimeError(f"Failed to decrypt with AES-GCM: {e}")


def sanitize_url(url: str) -> str:
    """
    Sanitize a URL to prevent open redirects and other URL-based attacks.

    This function ensures that URLs used for redirects or external resources
    are properly validated to prevent security vulnerabilities.

    Args:
        url: The URL to sanitize

    Returns:
        str: The sanitized URL or an empty string if invalid
    """
    if not url:
        return ''

    # Try to parse the URL
    try:
        parsed = urlparse(url)

        # Check for javascript: protocol and other potentially unsafe protocols
        if parsed.scheme.lower() in ['javascript', 'data', 'vbscript', 'file']:
            log_warning(f"Blocked unsafe URL scheme: {parsed.scheme}")
            metrics.increment('security.unsafe_url_blocked')
            return ''

        # Check for relative URLs (no scheme and no network location)
        if not parsed.scheme and not parsed.netloc:
            # Only allow paths starting with / to prevent path traversal
            if parsed.path.startswith('/'):
                return url
            else:
                log_warning(f"Blocked potentially unsafe relative URL: {url}")
                return ''

        # If URL has a scheme and host, check against allowlist if configured
        if parsed.scheme and parsed.netloc and has_app_context():
            allowed_domains = current_app.config.get('ALLOWED_REDIRECT_DOMAINS', [])

            # Always allow same-site redirects
            host = parsed.netloc.lower()
            server_name = current_app.config.get('SERVER_NAME', '')

            if server_name and host == server_name.lower():
                return url

            # Check against allowed domains
            if allowed_domains:
                for domain in allowed_domains:
                    if host == domain.lower() or host.endswith('.' + domain.lower()):
                        return url

                # If we reach here, domain is not allowed
                log_warning(f"Blocked redirect to non-allowed domain: {host}")
                metrics.increment('security.unauthorized_redirect')
                return ''
            else:
                # No domain allowlist defined, allow any external domain
                return url

        # If URL starts with a slash, it's a relative URL to the root - this is safe
        if url.startswith('/'):
            return url

        # If we get here with an external URL and no allowlist, it's potentially unsafe
        return ''

    except Exception as e:
        log_error(f"Error sanitizing URL: {e}")
        return ''


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal and other filename-based attacks.

    This function ensures that filenames used for file operations are safe
    and don't contain special characters or path traversal sequences.

    Args:
        filename: The filename to sanitize

    Returns:
        str: The sanitized filename or None if completely invalid
    """
    if not filename:
        return None

    # Remove path components
    filename = os.path.basename(filename)

    # Replace problematic characters
    # Allow letters, numbers, underscore, hyphen, and period
    sanitized = re.sub(r'[^\w\-\.]', '_', filename)

    # Additional security checks
    if sanitized.startswith('.'):
        # Don't allow hidden files
        sanitized = 'f' + sanitized

    if sanitized in ('.', '..'):
        return None

    # Check for common executable extensions
    executable_exts = ['.exe', '.bat', '.cmd', '.sh', '.com', '.dll', '.so', '.app']
    if any(sanitized.lower().endswith(ext) for ext in executable_exts):
        metrics.increment('security.executable_upload_attempt')
        sanitized = sanitized + '.txt'

    return sanitized
