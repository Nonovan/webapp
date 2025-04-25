"""
Cryptography utilities for the Cloud Infrastructure Platform.

This module provides encryption, decryption, and other cryptographic functions
used to secure sensitive data throughout the application.

Key functionality includes:
- Symmetric encryption using Fernet and AES-GCM
- Key derivation and management
- URL and filename sanitization
- Hashing utilities for various security needs
- Digital signature verification
"""

import base64
import hashlib
import logging
import os
import re
import secrets
from typing import Optional, Union, Dict, Any, Tuple, List
from urllib.parse import urlparse

# Flask imports
from flask import current_app, request, g, has_request_context, session, has_app_context

# Cryptography imports
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Internal imports
from core.utils import log_error, log_warning, log_info, log_debug
from extensions import metrics
from .cs_constants import SECURITY_CONFIG
from .cs_audit import log_security_event

# Set up module-level logger
logger = logging.getLogger(__name__)

# Type definitions
KeyDerivationInfo = Dict[str, Any]


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

    # Handle both string and bytes format
    if isinstance(encryption_key, str):
        return encryption_key.encode('utf-8')
    return encryption_key


def _derive_key(base_key: bytes, salt: Optional[bytes] = None,
               info: Optional[bytes] = None, length: int = 32) -> Tuple[bytes, bytes]:
    """
    Derive a cryptographic key using PBKDF2.

    This function derives a secure cryptographic key from a base key,
    optionally using a salt and context-specific info.

    Args:
        base_key: The base key to derive from
        salt: Optional salt (will be generated if None)
        info: Optional context info to include in derivation
        length: Length of the derived key in bytes

    Returns:
        Tuple of (derived_key, salt)
    """
    # Generate salt if not provided
    if salt is None:
        salt = SECURITY_CONFIG.get('ENCRYPTION_SALT', None)
        if salt is None or isinstance(salt, str):
            salt = os.urandom(16)
        elif isinstance(salt, str):
            salt = salt.encode('utf-8')

    # Create key derivation function
    iterations = SECURITY_CONFIG.get('DEFAULT_KEY_ITERATIONS', 100000)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )

    # Derive the key
    if info:
        key_material = base_key + info
    else:
        key_material = base_key

    derived_key = kdf.derive(key_material)

    return derived_key, salt


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

        # Track successful encryption
        metrics.increment('security.encryption_success')

        return encrypted_data.decode('utf-8')

    except Exception as e:
        log_error(f"Encryption failed: {e}")
        metrics.increment('security.encryption_failure')

        # Log security event for encryption failure
        try:
            log_security_event(
                event_type="encryption_failure",
                description="Failed to encrypt sensitive data",
                severity="error"
            )
        except Exception:
            # Don't let security logging failure impact main flow
            pass

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

            # Track successful decryption
            metrics.increment('security.decryption_success')

            return decrypted_data.decode('utf-8')

        except InvalidToken:
            log_warning("Decryption failed: Invalid token or key")
            metrics.increment('security.decryption_failure.invalid_token')

            # Log security event for invalid token
            try:
                log_security_event(
                    event_type="decryption_failure",
                    description="Decryption failed: Invalid token or key",
                    severity="warning"
                )
            except Exception:
                # Don't let security logging failure impact main flow
                pass

            raise RuntimeError("Decryption failed: Invalid token or key")

    except Exception as e:
        log_error(f"Failed to decrypt sensitive data: {e}")
        metrics.increment('security.decryption_failure')

        # Distinguish between key issues and other errors for metrics
        error_str = str(e).lower()
        if "key" in error_str:
            metrics.increment('security.decryption_failure.key_issue')

        # Don't expose specific error details in production
        raise RuntimeError("Failed to decrypt sensitive data")


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
        metrics.increment('security.aes_encryption_success')
        return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')

    except Exception as e:
        log_error(f"AES-GCM encryption failed: {e}")
        metrics.increment('security.aes_encryption_failure')

        # Log security event
        try:
            log_security_event(
                event_type="encryption_failure",
                description="AES-GCM encryption failed",
                severity="error"
            )
        except Exception:
            # Don't let security logging failure impact main flow
            pass

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

        # Verify minimum length for nonce (12) + tag (16)
        if len(decoded_data) < 28:
            log_warning("AES-GCM decryption failed: Data too short")
            metrics.increment('security.aes_decryption_failure.invalid_format')
            raise RuntimeError("Invalid encrypted data format")

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

        metrics.increment('security.aes_decryption_success')
        return plaintext.decode('utf-8')

    except Exception as e:
        log_error(f"AES-GCM decryption failed: {e}")
        metrics.increment('security.aes_decryption_failure')

        # Log security event only for suspected tampering
        error_str = str(e).lower()
        if "authentication" in error_str or "tag" in error_str:
            try:
                log_security_event(
                    event_type="decryption_failure",
                    description="AES-GCM authentication failure - possible data tampering",
                    severity="warning"
                )
            except Exception:
                # Don't let security logging failure impact main flow
                pass

        raise RuntimeError("Failed to decrypt with AES-GCM")


def generate_secure_hash(data: Union[str, bytes], algorithm: str = 'sha256') -> str:
    """
    Generate a secure hash of the provided data.

    This function creates a cryptographic hash of the input data using
    the specified algorithm.

    Args:
        data: The data to hash (string or bytes)
        algorithm: Hash algorithm to use ('sha256', 'sha384', 'sha512')

    Returns:
        str: Hexadecimal hash digest

    Raises:
        ValueError: If an unsupported algorithm is specified
    """
    if not data:
        return ""

    # Convert string to bytes if needed
    if isinstance(data, str):
        data = data.encode('utf-8')

    # Select hash algorithm
    if algorithm == 'sha256':
        hash_obj = hashlib.sha256()
    elif algorithm == 'sha384':
        hash_obj = hashlib.sha384()
    elif algorithm == 'sha512':
        hash_obj = hashlib.sha512()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    # Update hash with data and return hex digest
    hash_obj.update(data)
    return hash_obj.hexdigest()


def generate_hmac(data: Union[str, bytes], key: Optional[bytes] = None,
                 algorithm: str = 'sha256') -> str:
    """
    Generate an HMAC for data authentication.

    This function creates an HMAC (Hash-based Message Authentication Code)
    for authenticating the integrity and authenticity of data.

    Args:
        data: The data to authenticate (string or bytes)
        key: Secret key for HMAC (uses derived key if None)
        algorithm: Hash algorithm to use ('sha256', 'sha384', 'sha512')

    Returns:
        str: Hexadecimal HMAC digest

    Raises:
        ValueError: If an unsupported algorithm is specified
    """
    if not data:
        return ""

    # Get key if not provided
    if key is None:
        key = _get_encryption_key()

    # Convert string to bytes if needed
    if isinstance(data, str):
        data = data.encode('utf-8')

    # Select algorithm
    if algorithm == 'sha256':
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    elif algorithm == 'sha384':
        return hmac.new(key, data, hashlib.sha384).hexdigest()
    elif algorithm == 'sha512':
        return hmac.new(key, data, hashlib.sha512).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


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
        unsafe_schemes = ['javascript', 'data', 'vbscript', 'file']
        if parsed.scheme.lower() in unsafe_schemes:
            log_warning(f"Blocked unsafe URL scheme: {parsed.scheme}")
            metrics.increment('security.unsafe_url_blocked')

            # Log security event
            try:
                log_security_event(
                    event_type="unsafe_url_blocked",
                    description=f"Blocked unsafe URL scheme: {parsed.scheme}",
                    severity="warning",
                    ip_address=request.remote_addr if has_request_context() else None,
                    details={"url": url[:100]}  # Limit URL length in logs
                )
            except Exception:
                pass
            return ''

        # Check for relative URLs (no scheme and no network location)
        if not parsed.scheme and not parsed.netloc:
            # Only allow paths starting with / to prevent path traversal
            if parsed.path.startswith('/'):
                return url
            else:
                log_warning(f"Blocked potentially unsafe relative URL: {url}")
                metrics.increment('security.unsafe_path_blocked')
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

                # Log security event
                try:
                    log_security_event(
                        event_type="unauthorized_redirect",
                        description=f"Blocked redirect to non-allowed domain: {host}",
                        severity="warning",
                        ip_address=request.remote_addr if has_request_context() else None,
                        details={"url": url[:100]}  # Limit URL length in logs
                    )
                except Exception:
                    pass

                return ''
            else:
                # No domain allowlist defined, fall back to configuration
                strict_domain_check = SECURITY_CONFIG.get('STRICT_DOMAIN_VALIDATION', False)
                if strict_domain_check:
                    log_warning(f"Blocked external URL in strict mode: {host}")
                    return ''
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
    executable_exts = ['.exe', '.bat', '.cmd', '.sh', '.com', '.dll', '.so', '.app',
                      '.vbs', '.js', '.ps1', '.php', '.pl', '.py']
    if any(sanitized.lower().endswith(ext) for ext in executable_exts):
        metrics.increment('security.executable_upload_attempt')

        # Log security event
        try:
            log_security_event(
                event_type="executable_upload_attempt",
                description="Attempted upload of executable file",
                severity="warning",
                ip_address=request.remote_addr if has_request_context() else None,
                details={"original_filename": filename}
            )
        except Exception:
            pass

        sanitized = sanitized + '.txt'

    # Limit filename length
    max_length = SECURITY_CONFIG.get('MAX_FILENAME_LENGTH', 255)
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]

    return sanitized


def generate_token(length: int = 32, url_safe: bool = True) -> str:
    """
    Generate a cryptographically secure random token.

    Args:
        length: The desired length in bytes
        url_safe: Whether to generate a URL-safe token

    Returns:
        str: The generated token
    """
    if length < 16:
        # Ensure minimum security
        length = 16

    token_bytes = secrets.token_bytes(length)

    if url_safe:
        return base64.urlsafe_b64encode(token_bytes).decode('utf-8').rstrip('=')
    else:
        return base64.b64encode(token_bytes).decode('utf-8')


def constant_time_compare(val1: Union[str, bytes], val2: Union[str, bytes]) -> bool:
    """
    Perform a constant-time comparison of two strings or bytes.

    This function helps prevent timing attacks when comparing sensitive values
    like tokens and hashes.

    Args:
        val1: First value to compare
        val2: Second value to compare

    Returns:
        bool: True if values are equal, False otherwise
    """
    # Convert strings to bytes if needed
    if isinstance(val1, str):
        val1 = val1.encode('utf-8')
    if isinstance(val2, str):
        val2 = val2.encode('utf-8')

    # Use secrets module for constant time comparison
    try:
        return secrets.compare_digest(val1, val2)
    except Exception:
        # Fall back to regular comparison if secrets module is unavailable
        return val1 == val2


def verify_signature(data: Union[str, bytes], signature: Union[str, bytes],
                    key: Optional[bytes] = None) -> bool:
    """
    Verify the HMAC signature of data.

    Args:
        data: The data to verify
        signature: The signature to check against
        key: The key used for signing (uses derived key if None)

    Returns:
        bool: True if signature is valid, False otherwise
    """
    if not data or not signature:
        return False

    try:
        # Convert to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')

        if isinstance(signature, str):
            # Handle hex encoded signature
            if all(c in '0123456789abcdefABCDEF' for c in signature):
                signature = bytes.fromhex(signature)
            else:
                signature = signature.encode('utf-8')

        # Get key if not provided
        if key is None:
            key = _get_encryption_key()

        # Calculate HMAC
        computed_sig = hmac.new(key, data, hashlib.sha256).digest()

        # Compare signatures in constant time
        return constant_time_compare(computed_sig, signature)

    except Exception as e:
        log_error(f"Signature verification error: {e}")
        return False


# Import hmac here to avoid circular imports at module level
import hmac
