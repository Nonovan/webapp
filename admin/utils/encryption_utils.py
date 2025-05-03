"""
Encryption utilities for administrative operations.

This module provides secure encryption and hashing functionality for the
administrative tools, ensuring proper cryptographic practices for sensitive
data handling. It leverages the core security framework while adding
specialized functions for administrative operations.

The module provides functions for:
- Symmetric encryption of administrative data
- Hash generation and verification
- Secure key generation
- Random string generation for tokens and identifiers

All cryptographic operations follow industry best practices, including
the use of modern algorithms, proper key management, and secure defaults.
"""

import base64
import hashlib
import hmac
import logging
import os
import secrets
import string
from typing import Optional, Dict, Any, Tuple, Union, List, Callable

# Setup package logging
logger = logging.getLogger(__name__)

# Internal imports
try:
    # Attempt to import core security components
    from core.security.cs_authentication import generate_secure_token
    from core.security.cs_crypto import (
        encrypt_sensitive_data,
        decrypt_sensitive_data,
        encrypt_with_rotation,
        decrypt_with_rotation,
        generate_secure_hash as core_secure_hash,
        constant_time_compare,
        _get_encryption_key
    )
    CORE_SECURITY_AVAILABLE = True
except ImportError:
    # Fall back to basic logging if core is unavailable
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.warning("Core security module not available. Using fallback encryption that is NOT suitable for production.")
    CORE_SECURITY_AVAILABLE = False

    # Define minimal fallbacks for core functions
    def encrypt_sensitive_data(data: str) -> str:
        logger.error("Core security module not available: encrypt_sensitive_data")
        raise NotImplementedError("Core security module required for encryption")

    def decrypt_sensitive_data(data: str) -> str:
        logger.error("Core security module not available: decrypt_sensitive_data")
        raise NotImplementedError("Core security module required for decryption")

    def generate_secure_token(*args, **kwargs) -> str:
        logger.error("Core security module not available: generate_secure_token")
        raise NotImplementedError("Core security module required for token generation")

    def encrypt_with_rotation(*args, **kwargs) -> str:
        logger.error("Core security module not available: encrypt_with_rotation")
        raise NotImplementedError("Core security module required for encryption with rotation")

    def decrypt_with_rotation(*args, **kwargs) -> str:
        logger.error("Core security module not available: decrypt_with_rotation")
        raise NotImplementedError("Core security module required for decryption with rotation")

    def core_secure_hash(data: Union[str, bytes], algorithm: str = 'sha256') -> str:
        """Basic fallback for hash generation - NOT recommended for production."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(data)
        return hash_obj.hexdigest()

    def constant_time_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
        """
        Constant time comparison to prevent timing attacks.
        This is a fallback implementation - use hmac.compare_digest in production.
        """
        return hmac.compare_digest(
            a.encode('utf-8') if isinstance(a, str) else a,
            b.encode('utf-8') if isinstance(b, str) else b
        )

# Constants
DEFAULT_KEY_LENGTH = 32  # 256 bits, suitable for AES-256
DEFAULT_HASH_ALGORITHM = 'sha256'
MIN_PASSWORD_LENGTH = 12
DEFAULT_PASSWORD_LENGTH = 16
ADMIN_ENCRYPTION_PURPOSE = 'admin_data'

# Secure character sets for password generation
UPPERCASE_CHARS = string.ascii_uppercase
LOWERCASE_CHARS = string.ascii_lowercase
DIGIT_CHARS = string.digits
SPECIAL_CHARS = '!@#$%^&*()-_=+[]{}|;:,.<>?'


def encrypt_data(data: Union[str, Dict[str, Any]],
                purpose: str = ADMIN_ENCRYPTION_PURPOSE) -> Optional[str]:
    """
    Encrypts sensitive administrative data using secure encryption.

    Uses AES-GCM authenticated encryption with key rotation support through
    the core security framework, ensuring both confidentiality and integrity.

    Args:
        data: String or dictionary to encrypt
        purpose: Purpose identifier for key derivation and rotation

    Returns:
        Encrypted data string, or None if encryption fails

    Raises:
        TypeError: If data is not a string or dictionary
        RuntimeError: If core security is unavailable
    """
    if not CORE_SECURITY_AVAILABLE:
        raise RuntimeError("Core security module is required for encryption operations")

    if data is None:
        return None

    try:
        if isinstance(data, dict):
            import json
            data_str = json.dumps(data)
        elif isinstance(data, str):
            data_str = data
        else:
            raise TypeError("Data must be a string or dictionary")

        # Use the rotation-aware encryption for enhanced security
        encrypted = encrypt_with_rotation(data_str, purpose)

        # Add an additional encoding layer for safe transport/storage
        return base64.urlsafe_b64encode(encrypted.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {e}", exc_info=True)
        return None


def decrypt_data(encrypted_data: str,
                purpose: str = ADMIN_ENCRYPTION_PURPOSE) -> Optional[Union[str, Dict[str, Any]]]:
    """
    Decrypts administrative data that was encrypted using encrypt_data.

    Args:
        encrypted_data: The encrypted data string
        purpose: Purpose identifier matching the one used for encryption

    Returns:
        Decrypted string or dictionary, or None if decryption fails

    Raises:
        RuntimeError: If core security is unavailable
    """
    if not CORE_SECURITY_AVAILABLE:
        raise RuntimeError("Core security module is required for decryption operations")

    if not encrypted_data:
        return None

    try:
        # Decode the additional encoding layer
        decoded_data = base64.urlsafe_b64decode(encrypted_data).decode()

        # Decrypt the data using rotation-aware decryption
        decrypted_str = decrypt_with_rotation(decoded_data, purpose)

        # Try to interpret as JSON if possible
        try:
            import json
            return json.loads(decrypted_str)
        except (json.JSONDecodeError, TypeError):
            # If not valid JSON, return as string
            return decrypted_str
    except Exception as e:
        logger.error(f"Failed to decrypt data: {e}", exc_info=False)
        return None


def generate_key(length: int = DEFAULT_KEY_LENGTH,
                encoding: str = 'base64') -> str:
    """
    Generates a cryptographically secure random key.

    Args:
        length: Key length in bytes
        encoding: Output encoding ('hex', 'base64', or 'base64url')

    Returns:
        Securely generated key in the specified encoding

    Raises:
        ValueError: If encoding is not supported
    """
    # Ensure minimum security requirements
    if length < 16:
        logger.warning(f"Key length {length} bytes is too short, using minimum of 16 bytes")
        length = 16

    # Generate random bytes using a cryptographically secure RNG
    key_bytes = os.urandom(length)

    # Convert to the requested encoding
    if encoding.lower() == 'hex':
        return key_bytes.hex()
    elif encoding.lower() == 'base64':
        return base64.b64encode(key_bytes).decode('utf-8')
    elif encoding.lower() == 'base64url':
        return base64.urlsafe_b64encode(key_bytes).decode('utf-8').rstrip('=')
    else:
        raise ValueError(f"Unsupported encoding: {encoding}")


def secure_hash(data: Union[str, bytes],
               algorithm: str = DEFAULT_HASH_ALGORITHM,
               salt: Optional[str] = None) -> str:
    """
    Create a secure hash of the provided data.

    Args:
        data: The data to hash
        algorithm: Hash algorithm to use ('sha256', 'sha384', 'sha512')
        salt: Optional salt for the hash

    Returns:
        Secure hash as a hexadecimal string
    """
    if algorithm not in ('sha256', 'sha384', 'sha512'):
        logger.warning(f"Insecure algorithm {algorithm}, using sha256 instead")
        algorithm = 'sha256'

    # Convert string to bytes if necessary
    if isinstance(data, str):
        data = data.encode('utf-8')

    # Apply salt if provided
    if salt:
        salt_bytes = salt.encode('utf-8') if isinstance(salt, str) else salt
        data = salt_bytes + data

    # Use core security if available, otherwise use fallback
    if CORE_SECURITY_AVAILABLE:
        return core_secure_hash(data, algorithm)
    else:
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(data)
        return hash_obj.hexdigest()


def compare_hashes(hash1: str, hash2: str) -> bool:
    """
    Compare two hashes using constant time comparison to prevent timing attacks.

    Args:
        hash1: First hash string to compare
        hash2: Second hash string to compare

    Returns:
        True if the hashes match, False otherwise
    """
    if not hash1 or not hash2:
        return False

    try:
        return constant_time_compare(hash1, hash2)
    except Exception as e:
        logger.error(f"Hash comparison failed: {e}", exc_info=True)
        return False


def secure_random_string(length: int = 16,
                        include_uppercase: bool = True,
                        include_lowercase: bool = True,
                        include_digits: bool = True,
                        include_special: bool = False) -> str:
    """
    Generates a cryptographically secure random string with the specified characteristics.

    Args:
        length: Length of the string to generate
        include_uppercase: Include uppercase letters
        include_lowercase: Include lowercase letters
        include_digits: Include digits
        include_special: Include special characters

    Returns:
        A secure random string with the requested characteristics

    Raises:
        ValueError: If all character sets are excluded
    """
    # Build character set
    char_sets = []
    if include_uppercase:
        char_sets.append(UPPERCASE_CHARS)
    if include_lowercase:
        char_sets.append(LOWERCASE_CHARS)
    if include_digits:
        char_sets.append(DIGIT_CHARS)
    if include_special:
        char_sets.append(SPECIAL_CHARS)

    if not char_sets:
        raise ValueError("At least one character set must be included")

    char_set = ''.join(char_sets)

    # Generate secure random string
    rand_string = []

    # Ensure at least one character from each included set
    for charset in char_sets:
        rand_string.append(secrets.choice(charset))

    # Fill the rest with random selections
    remaining_length = max(0, length - len(rand_string))
    rand_string.extend(secrets.choice(char_set) for _ in range(remaining_length))

    # Shuffle to avoid predictable patterns
    secrets.SystemRandom().shuffle(rand_string)

    return ''.join(rand_string)


# Internal utility functions and specialized admin functions below

def _get_admin_encryption_key() -> bytes:
    """
    Internal method to get the admin encryption key.

    Returns:
        bytes: Admin encryption key

    Raises:
        RuntimeError: If the key cannot be retrieved
    """
    # Try to get the admin-specific key from environment or config
    admin_key = os.environ.get('ADMIN_ENCRYPTION_KEY')

    # Fall back to core encryption key if admin-specific key is not available
    if not admin_key and CORE_SECURITY_AVAILABLE:
        try:
            return _get_encryption_key()
        except Exception as e:
            logger.error(f"Failed to get core encryption key: {e}", exc_info=True)
            raise RuntimeError("No encryption key available")

    if not admin_key:
        raise RuntimeError("Admin encryption key not configured")

    # Handle both string and bytes format
    if isinstance(admin_key, str):
        return base64.urlsafe_b64decode(admin_key)
    return admin_key


def generate_admin_token(prefix: str = "adm", length: int = 32) -> str:
    """
    Generate an administrative access token with proper format and security.

    Args:
        prefix: Token prefix for identification
        length: Token length in bytes

    Returns:
        Secure administrative token
    """
    if CORE_SECURITY_AVAILABLE:
        return generate_secure_token(length=length, url_safe=True, prefix=prefix)
    else:
        # Fallback implementation
        token_bytes = secrets.token_bytes(length)
        token = base64.urlsafe_b64encode(token_bytes).decode('utf-8').rstrip('=')
        return f"{prefix}_{token}"


def validate_admin_key_strength(key: str, min_length: int = 32) -> Tuple[bool, List[str]]:
    """
    Validates the strength of an administrative key or token.

    Args:
        key: The key to validate
        min_length: Minimum required length in bytes

    Returns:
        Tuple of (is_valid, [reasons]) where reasons contains validation messages
    """
    reasons = []
    is_valid = True

    # Check length
    if len(key) < min_length:
        reasons.append(f"Key length ({len(key)}) is less than required minimum ({min_length})")
        is_valid = False

    # Check entropy (basic)
    has_uppercase = any(c.isupper() for c in key)
    has_lowercase = any(c.islower() for c in key)
    has_digit = any(c.isdigit() for c in key)
    has_special = any(not c.isalnum() for c in key)

    char_type_count = sum([has_uppercase, has_lowercase, has_digit, has_special])
    if char_type_count < 3:
        reasons.append("Key should contain at least 3 of: uppercase letters, lowercase letters, digits, special characters")
        is_valid = False

    return (is_valid, reasons)


if __name__ == "__main__":
    # Self-test
    test_data = "This is sensitive administrative data"
    print("Testing encryption utilities...")

    if CORE_SECURITY_AVAILABLE:
        print("Core security module available")
        # Test encryption and decryption
        encrypted = encrypt_data(test_data)
        if encrypted:
            print(f"Encrypted: {encrypted[:20]}...")
            decrypted = decrypt_data(encrypted)
            print(f"Decryption successful: {decrypted == test_data}")
        else:
            print("Encryption failed")
    else:
        print("Core security module NOT available - encryption disabled")

    # Test key generation
    print(f"\nKey generation test:")
    key = generate_key(32, 'base64')
    print(f"Generated key: {key[:10]}...")
    valid, reasons = validate_admin_key_strength(key)
    print(f"Key valid: {valid}")

    # Test secure hash
    print(f"\nHash generation test:")
    hash_value = secure_hash(test_data)
    print(f"SHA-256 hash: {hash_value[:15]}...")
    print(f"Hash comparison test: {compare_hashes(hash_value, secure_hash(test_data))}")

    # Test secure random string
    print(f"\nRandom string generation test:")
    rand_str = secure_random_string(16, include_special=True)
    print(f"Random string: {rand_str}")
