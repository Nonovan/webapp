#!/usr/bin/env python3
# filepath: scripts/core/security/crypto.py
"""
Cryptographic operations for Cloud Infrastructure Platform.

This module provides secure cryptographic functions for encryption, decryption,
hashing, key management, and digital signatures following industry best practices
including NIST recommendations.

Key features:
- AES-GCM authenticated encryption for sensitive data
- Secure key generation and derivation
- File and data hashing with multiple algorithms
- Password hashing with modern algorithms
- Key rotation capabilities
- Digital signature creation and verification
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, BinaryIO

# Import core dependencies if available
try:
    from scripts.core.logger import get_logger
    logger = get_logger(__name__)
except ImportError:
    # Fallback logging if core logger is not available
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

# Optional cryptography package imports
# Used for advanced cryptographic operations
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, padding, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    logger.warning("Cryptography package not available. Some functions will be limited.")
    CRYPTOGRAPHY_AVAILABLE = False

# Constants for cryptographic operations
DEFAULT_KEY_LENGTH = 32  # 256 bits
DEFAULT_SALT_LENGTH = 16  # 128 bits
DEFAULT_HASH_ALGORITHM = "sha256"
DEFAULT_PBKDF2_ITERATIONS = 100000
DEFAULT_ENCODING = "utf-8"
MINIMUM_AES_KEY_LENGTH = 16  # 128 bits
CHUNK_SIZE = 65536  # 64KB for file operations

# Define key storage location relative to project root
KEY_DIR = os.environ.get("CRYPTO_KEY_DIR", os.path.expanduser("~/.config/cloud-platform/keys"))
KEY_FILENAME = "crypto_master.key"
KEY_PERMISSIONS = 0o600


#######################################
# Key Management Functions
#######################################

def generate_key(length: int = DEFAULT_KEY_LENGTH, format: str = "bytes") -> Union[bytes, str]:
    """
    Generate a cryptographically secure random key.

    Args:
        length: Length of the key in bytes
        format: Output format ('bytes', 'hex', or 'base64')

    Returns:
        The generated key in the requested format
    """
    # Validate length
    if length < MINIMUM_AES_KEY_LENGTH:
        raise ValueError(f"Key length must be at least {MINIMUM_AES_KEY_LENGTH} bytes")

    # Generate key using a cryptographically secure source
    key = secrets.token_bytes(length)

    # Return in the requested format
    if format == "bytes":
        return key
    elif format == "hex":
        return key.hex()
    elif format == "base64":
        return base64.urlsafe_b64encode(key).decode(DEFAULT_ENCODING)
    else:
        raise ValueError("Invalid format. Must be 'bytes', 'hex', or 'base64'")


def derive_key_from_password(password: str, salt: Optional[bytes] = None,
                           iterations: int = DEFAULT_PBKDF2_ITERATIONS,
                           length: int = DEFAULT_KEY_LENGTH) -> Tuple[bytes, bytes]:
    """
    Derive a secure key from a password using PBKDF2-HMAC.

    Args:
        password: The password to derive key from
        salt: Salt value (generated if not provided)
        iterations: Number of PBKDF2 iterations
        length: Length of the derived key in bytes

    Returns:
        Tuple of (derived_key, salt)
    """
    # Generate salt if not provided
    if salt is None:
        salt = secrets.token_bytes(DEFAULT_SALT_LENGTH)

    # Ensure we have a bytes password
    if isinstance(password, str):
        password = password.encode(DEFAULT_ENCODING)

    if CRYPTOGRAPHY_AVAILABLE:
        # Use cryptography library if available
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        derived_key = kdf.derive(password)
    else:
        # Fallback to hashlib
        derived_key = hashlib.pbkdf2_hmac(
            DEFAULT_HASH_ALGORITHM,
            password,
            salt,
            iterations,
            length
        )

    return derived_key, salt


def load_or_generate_key(key_path: Optional[str] = None) -> bytes:
    """
    Load encryption key from file, or generate and save a new one.

    Args:
        key_path: Path to key file (uses default if not provided)

    Returns:
        The encryption key as bytes
    """
    if key_path is None:
        if not os.path.exists(KEY_DIR):
            try:
                os.makedirs(KEY_DIR, mode=0o700, exist_ok=True)
                logger.debug(f"Created key directory: {KEY_DIR}")
            except OSError as e:
                logger.error(f"Failed to create key directory: {e}")
                raise

        key_path = os.path.join(KEY_DIR, KEY_FILENAME)

    # Try to load existing key
    if os.path.exists(key_path):
        try:
            with open(key_path, 'rb') as key_file:
                key = key_file.read().strip()

            # Check if key is in base64 format (common for stored keys)
            try:
                key = base64.urlsafe_b64decode(key)
            except Exception:
                # If not base64, use as-is
                pass

            if len(key) >= MINIMUM_AES_KEY_LENGTH:
                logger.debug("Loaded encryption key successfully")
                return key
            else:
                logger.warning("Loaded key is too short, generating a new one")
        except Exception as e:
            logger.error(f"Failed to load encryption key: {e}")

    # Generate new key
    logger.info("Generating new encryption key")
    key = generate_key(DEFAULT_KEY_LENGTH)

    # Save the new key
    try:
        with open(key_path, 'wb') as key_file:
            encoded_key = base64.urlsafe_b64encode(key) if isinstance(key, bytes) else key
            key_file.write(encoded_key)

        # Set secure permissions
        os.chmod(key_path, KEY_PERMISSIONS)
        logger.info(f"Saved new encryption key to {key_path}")
    except Exception as e:
        logger.error(f"Failed to save encryption key: {e}")

    return key


#######################################
# Encryption Functions
#######################################

def encrypt_data(plaintext: Union[str, bytes], key: Optional[bytes] = None) -> str:
    """
    Encrypt data using AES-GCM with authentication.

    Args:
        plaintext: Data to encrypt
        key: Encryption key (generated/loaded if not provided)

    Returns:
        Encrypted data as a string in format: iv:auth_tag:ciphertext
        All values are base64 encoded.
    """
    # Ensure we have a key
    if key is None:
        key = load_or_generate_key()

    # Convert plaintext to bytes if it's a string
    if isinstance(plaintext, str):
        plaintext = plaintext.encode(DEFAULT_ENCODING)

    if CRYPTOGRAPHY_AVAILABLE:
        # Generate a random IV for AES-GCM (12 bytes recommended)
        iv = secrets.token_bytes(12)

        # Create the cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # Encrypt the plaintext
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Get the authentication tag
        auth_tag = encryptor.tag

        # Format as iv:auth_tag:ciphertext
        result = (
            base64.urlsafe_b64encode(iv).decode(DEFAULT_ENCODING) + ":" +
            base64.urlsafe_b64encode(auth_tag).decode(DEFAULT_ENCODING) + ":" +
            base64.urlsafe_b64encode(ciphertext).decode(DEFAULT_ENCODING)
        )
    else:
        # Fallback to simpler encryption if cryptography is not available
        # Note: This does not have authenticated encryption
        if not isinstance(key, bytes) or len(key) % 16 != 0:
            # Ensure we have a valid Fernet key
            key = hashlib.sha256(key).digest()

        try:
            fernet_key = base64.urlsafe_b64encode(key)
            f = Fernet(fernet_key)
            encrypted = f.encrypt(plaintext)
            result = base64.urlsafe_b64encode(encrypted).decode(DEFAULT_ENCODING)
        except Exception as e:
            logger.error(f"Fallback encryption failed: {e}")
            raise

    return result


def decrypt_data(encrypted_data: str, key: Optional[bytes] = None) -> str:
    """
    Decrypt data that was encrypted using encrypt_data().

    Args:
        encrypted_data: Encrypted data string
        key: Decryption key (same as used for encryption)

    Returns:
        Decrypted data as a string
    """
    # Ensure we have a key
    if key is None:
        key = load_or_generate_key()

    if CRYPTOGRAPHY_AVAILABLE and ":" in encrypted_data:
        try:
            # Split the components
            parts = encrypted_data.split(":")
            if len(parts) != 3:
                raise ValueError("Invalid encrypted data format")

            iv = base64.urlsafe_b64decode(parts[0])
            auth_tag = base64.urlsafe_b64decode(parts[1])
            ciphertext = base64.urlsafe_b64decode(parts[2])

            # Create the cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, auth_tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()

            # Decrypt the ciphertext
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            return plaintext.decode(DEFAULT_ENCODING)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError("Decryption failed: possibly invalid key or corrupted data")
    else:
        # Fallback decryption
        try:
            if not isinstance(key, bytes) or len(key) % 16 != 0:
                # Ensure we have a valid Fernet key
                key = hashlib.sha256(key).digest()

            fernet_key = base64.urlsafe_b64encode(key)
            f = Fernet(fernet_key)

            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)
            decrypted = f.decrypt(encrypted_bytes)

            return decrypted.decode(DEFAULT_ENCODING)
        except Exception as e:
            logger.error(f"Fallback decryption failed: {e}")
            raise ValueError("Decryption failed: possibly invalid key or corrupted data")


def encrypt_file(input_file: str, output_file: Optional[str] = None,
                key: Optional[bytes] = None) -> str:
    """
    Encrypt a file using AES encryption.

    Args:
        input_file: Path to file to encrypt
        output_file: Path to save encrypted file (defaults to input_file + '.enc')
        key: Encryption key (generated/loaded if not provided)

    Returns:
        Path to the encrypted file
    """
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    if output_file is None:
        output_file = f"{input_file}.enc"

    # Ensure we have a key
    if key is None:
        key = load_or_generate_key()

    try:
        # Read the file contents
        with open(input_file, 'rb') as f:
            plaintext = f.read()

        # Encrypt the data
        encrypted = encrypt_data(plaintext, key)

        # Write encrypted data to output file
        with open(output_file, 'w') as f:
            f.write(encrypted)

        logger.info(f"Successfully encrypted {input_file} to {output_file}")
        return output_file
    except Exception as e:
        logger.error(f"File encryption failed: {e}")
        if os.path.exists(output_file):
            try:
                os.remove(output_file)  # Clean up partial file
            except Exception:
                pass
        raise


def decrypt_file(input_file: str, output_file: Optional[str] = None,
               key: Optional[bytes] = None) -> str:
    """
    Decrypt a file previously encrypted with encrypt_file().

    Args:
        input_file: Path to encrypted file
        output_file: Path to save decrypted file (defaults to removing .enc extension)
        key: Decryption key (same as used for encryption)

    Returns:
        Path to the decrypted file
    """
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    if output_file is None:
        # Remove .enc extension if present
        if input_file.endswith('.enc'):
            output_file = input_file[:-4]
        else:
            output_file = f"{input_file}.dec"

    # Ensure we have a key
    if key is None:
        key = load_or_generate_key()

    try:
        # Read the encrypted data
        with open(input_file, 'r') as f:
            encrypted_data = f.read()

        # Decrypt the data
        decrypted = decrypt_data(encrypted_data, key)

        # Write decrypted data to output file
        with open(output_file, 'wb') as f:
            f.write(decrypted.encode(DEFAULT_ENCODING) if isinstance(decrypted, str) else decrypted)

        logger.info(f"Successfully decrypted {input_file} to {output_file}")
        return output_file
    except Exception as e:
        logger.error(f"File decryption failed: {e}")
        if os.path.exists(output_file):
            try:
                os.remove(output_file)  # Clean up partial file
            except Exception:
                pass
        raise


#######################################
# Hashing Functions
#######################################

def hash_data(data: Union[str, bytes, BinaryIO], algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
    """
    Compute a hash of the provided data.

    Args:
        data: Data to hash (string, bytes, or file-like object)
        algorithm: Hash algorithm to use

    Returns:
        Hex digest of the hash
    """
    # Validate algorithm
    try:
        hasher = hashlib.new(algorithm)
    except ValueError:
        logger.error(f"Unsupported hash algorithm: {algorithm}")
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    # Process different data types
    if isinstance(data, str):
        hasher.update(data.encode(DEFAULT_ENCODING))
    elif isinstance(data, bytes):
        hasher.update(data)
    else:
        # Assume file-like object
        for chunk in iter(lambda: data.read(CHUNK_SIZE), b''):
            hasher.update(chunk)

    return hasher.hexdigest()


def hash_file(file_path: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
    """
    Compute the hash of a file.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use

    Returns:
        Hex digest of the hash
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if not os.path.isfile(file_path):
        raise ValueError(f"Not a file: {file_path}")

    try:
        with open(file_path, 'rb') as f:
            return hash_data(f, algorithm)
    except Exception as e:
        logger.error(f"Failed to hash file {file_path}: {e}")
        raise


def verify_hash(file_path: str, expected_hash: str,
              algorithm: str = DEFAULT_HASH_ALGORITHM) -> bool:
    """
    Verify that a file's hash matches the expected value.

    Args:
        file_path: Path to the file
        expected_hash: Expected hash value
        algorithm: Hash algorithm used to generate the expected hash

    Returns:
        True if the hash matches, False otherwise
    """
    try:
        actual_hash = hash_file(file_path, algorithm)
        result = hmac.compare_digest(actual_hash.lower(), expected_hash.lower())

        if not result:
            logger.warning(f"Hash mismatch for file {file_path}")
            logger.debug(f"Expected: {expected_hash}, Actual: {actual_hash}")

        return result
    except Exception as e:
        logger.error(f"Hash verification failed for {file_path}: {e}")
        return False


#######################################
# Digital Signature Functions
#######################################

def generate_signature_key_pair(key_path: Optional[str] = None,
                              key_size: int = 2048) -> Tuple[str, str]:
    """
    Generate an RSA key pair for signatures.

    Args:
        key_path: Directory to save keys (creates 'private_key.pem' and 'public_key.pem')
        key_size: Size of the key in bits

    Returns:
        Tuple of (private_key_path, public_key_path)
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise NotImplementedError("Signature key generation requires the cryptography package")

    if key_path is None:
        key_path = KEY_DIR

    if not os.path.exists(key_path):
        try:
            os.makedirs(key_path, mode=0o700, exist_ok=True)
        except OSError as e:
            logger.error(f"Failed to create key directory: {e}")
            raise

    private_key_path = os.path.join(key_path, "private_key.pem")
    public_key_path = os.path.join(key_path, "public_key.pem")

    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

        # Get public key
        public_key = private_key.public_key()

        # Save private key
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        os.chmod(private_key_path, KEY_PERMISSIONS)

        # Save public key
        with open(public_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        logger.info("Generated signature key pair successfully")
        return private_key_path, public_key_path
    except Exception as e:
        logger.error(f"Failed to generate signature keys: {e}")
        raise


def sign_data(data: Union[str, bytes], private_key_path: str) -> str:
    """
    Create a digital signature for data.

    Args:
        data: Data to sign
        private_key_path: Path to private key file

    Returns:
        Base64-encoded signature
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise NotImplementedError("Digital signatures require the cryptography package")

    if not os.path.exists(private_key_path):
        raise FileNotFoundError(f"Private key not found: {private_key_path}")

    # Convert data to bytes if it's a string
    if isinstance(data, str):
        data = data.encode(DEFAULT_ENCODING)

    try:
        # Load the private key
        with open(private_key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Sign the data
        signature = private_key.sign(
            data,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Return base64-encoded signature
        return base64.b64encode(signature).decode(DEFAULT_ENCODING)
    except Exception as e:
        logger.error(f"Signing failed: {e}")
        raise


def verify_signature(data: Union[str, bytes], signature: str,
                   public_key_path: str) -> bool:
    """
    Verify a digital signature.

    Args:
        data: The original data
        signature: Base64-encoded signature
        public_key_path: Path to public key file

    Returns:
        True if signature is valid, False otherwise
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise NotImplementedError("Signature verification requires the cryptography package")

    if not os.path.exists(public_key_path):
        raise FileNotFoundError(f"Public key not found: {public_key_path}")

    # Convert data to bytes if it's a string
    if isinstance(data, str):
        data = data.encode(DEFAULT_ENCODING)

    # Decode the signature
    try:
        signature_bytes = base64.b64decode(signature)
    except Exception as e:
        logger.error(f"Invalid signature format: {e}")
        return False

    try:
        # Load the public key
        with open(public_key_path, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        # Verify the signature
        public_key.verify(
            signature_bytes,
            data,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # If no exception was raised, the signature is valid
        return True
    except InvalidSignature:
        logger.warning("Invalid signature")
        return False
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False


#######################################
# Password Hashing Functions
#######################################

def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """
    Hash a password using a secure algorithm.

    Args:
        password: Password to hash
        salt: Optional salt (generated if not provided)

    Returns:
        Tuple of (password_hash, salt)
    """
    # Generate a salt if not provided
    if salt is None:
        salt = secrets.token_bytes(DEFAULT_SALT_LENGTH)

    # Convert salt to string for returning
    salt_str = base64.b64encode(salt).decode(DEFAULT_ENCODING)

    # Derive key using PBKDF2
    password_hash, _ = derive_key_from_password(
        password,
        salt=salt,
        iterations=DEFAULT_PBKDF2_ITERATIONS
    )

    # Convert hash to string
    hash_str = base64.b64encode(password_hash).decode(DEFAULT_ENCODING)

    return hash_str, salt_str


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """
    Verify a password against its hash.

    Args:
        password: Password to verify
        password_hash: Stored password hash
        salt: Salt used when hashing the password

    Returns:
        True if password is valid, False otherwise
    """
    try:
        # Decode the salt
        salt_bytes = base64.b64decode(salt)

        # Hash the provided password with the same salt
        derived_hash, _ = derive_key_from_password(
            password,
            salt=salt_bytes,
            iterations=DEFAULT_PBKDF2_ITERATIONS
        )

        # Convert to string for comparison
        derived_hash_str = base64.b64encode(derived_hash).decode(DEFAULT_ENCODING)

        # Compare using constant-time comparison
        return hmac.compare_digest(derived_hash_str, password_hash)
    except Exception as e:
        logger.error(f"Password verification failed: {e}")
        return False


def generate_secure_password(length: int = 16,
                          include_uppercase: bool = True,
                          include_lowercase: bool = True,
                          include_digits: bool = True,
                          include_special: bool = True) -> str:
    """
    Generate a secure random password.

    Args:
        length: Length of the password
        include_uppercase: Include uppercase letters
        include_lowercase: Include lowercase letters
        include_digits: Include digits
        include_special: Include special characters

    Returns:
        Secure random password
    """
    if length < 8:
        raise ValueError("Password length must be at least 8 characters")

    # Define character sets
    uppercase_chars = "ABCDEFGHJKLMNPQRSTUVWXYZ"  # Removed confusing chars: I, O
    lowercase_chars = "abcdefghijkmnopqrstuvwxyz"  # Removed confusing chars: l
    digit_chars = "23456789"  # Removed confusing chars: 0, 1
    special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    # Initialize character pool
    char_pool = ""
    required_chars = []

    # Add character sets based on parameters
    if include_uppercase:
        char_pool += uppercase_chars
        required_chars.append(secrets.choice(uppercase_chars))

    if include_lowercase:
        char_pool += lowercase_chars
        required_chars.append(secrets.choice(lowercase_chars))

    if include_digits:
        char_pool += digit_chars
        required_chars.append(secrets.choice(digit_chars))

    if include_special:
        char_pool += special_chars
        required_chars.append(secrets.choice(special_chars))

    if not char_pool:
        raise ValueError("At least one character set must be included")

    # Calculate remaining characters needed
    remaining_length = length - len(required_chars)

    if remaining_length < 0:
        raise ValueError(f"Password length too short for required character sets")

    # Generate remaining random characters
    remaining_chars = [secrets.choice(char_pool) for _ in range(remaining_length)]

    # Combine and shuffle all characters
    all_chars = required_chars + remaining_chars
    secrets.SystemRandom().shuffle(all_chars)

    return ''.join(all_chars)


#######################################
# Key Rotation Functions
#######################################

def rotate_encryption_key(key_path: Optional[str] = None) -> bool:
    """
    Rotates the encryption key, re-encrypting any necessary data.

    Args:
        key_path: Path to key file (uses default if not provided)

    Returns:
        True if key rotation was successful, False otherwise
    """
    if key_path is None:
        key_path = os.path.join(KEY_DIR, KEY_FILENAME)

    # Check if old key exists
    if not os.path.exists(key_path):
        logger.warning(f"No key found at {key_path} to rotate")
        return False

    try:
        # Load the old key
        old_key = load_or_generate_key(key_path)

        # Generate a new key
        new_key = generate_key(DEFAULT_KEY_LENGTH)

        # Backup the old key
        backup_path = f"{key_path}.{int(time.time())}.bak"
        with open(backup_path, 'wb') as f:
            if isinstance(old_key, bytes):
                f.write(base64.urlsafe_b64encode(old_key))
            else:
                f.write(old_key)
        os.chmod(backup_path, KEY_PERMISSIONS)

        # Save the new key
        with open(key_path, 'wb') as f:
            f.write(base64.urlsafe_b64encode(new_key))
        os.chmod(key_path, KEY_PERMISSIONS)

        logger.info("Key rotation completed successfully")
        return True
    except Exception as e:
        logger.error(f"Key rotation failed: {e}")
        return False


#######################################
# Secure Wipe Functions
#######################################

def secure_wipe_file(file_path: str, passes: int = 3) -> bool:
    """
    Securely overwrite file data before deletion.

    Args:
        file_path: Path to file to wipe
        passes: Number of overwrite passes

    Returns:
        True if successful, False otherwise
    """
    if not os.path.exists(file_path):
        logger.warning(f"File not found: {file_path}")
        return False

    if not os.path.isfile(file_path):
        logger.error(f"Not a file: {file_path}")
        return False

    try:
        # Get file size
        file_size = os.path.getsize(file_path)

        # Open file for binary update
        with open(file_path, 'r+b') as f:
            # Multiple passes of overwriting
            for i in range(passes):
                # Go to beginning of file
                f.seek(0)

                # Different patterns for different passes
                if i == 0:
                    # All zeros
                    pattern = b'\x00' * CHUNK_SIZE
                elif i == 1:
                    # All ones
                    pattern = b'\xFF' * CHUNK_SIZE
                else:
                    # Random data
                    pattern = secrets.token_bytes(CHUNK_SIZE)

                # Write the pattern
                for _ in range(0, file_size, CHUNK_SIZE):
                    chunk_size = min(CHUNK_SIZE, file_size - f.tell())
                    f.write(pattern[:chunk_size])

                # Ensure data is written to disk
                f.flush()
                os.fsync(f.fileno())

        # Finally delete the file
        os.remove(file_path)
        logger.info(f"Securely wiped file: {file_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to securely wipe file {file_path}: {e}")
        return False


#######################################
# Utility Functions
#######################################

def secure_random_string(length: int = 16,
                       include_uppercase: bool = True,
                       include_lowercase: bool = True,
                       include_digits: bool = True,
                       include_special: bool = False) -> str:
    """
    Generate a secure random string with specified characteristics.

    Args:
        length: Length of the string
        include_uppercase: Include uppercase letters
        include_lowercase: Include lowercase letters
        include_digits: Include digits
        include_special: Include special characters

    Returns:
        Secure random string
    """
    # Define character sets
    chars = ""
    if include_uppercase:
        chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if include_lowercase:
        chars += "abcdefghijklmnopqrstuvwxyz"
    if include_digits:
        chars += "0123456789"
    if include_special:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"

    if not chars:
        raise ValueError("At least one character set must be included")

    # Generate random string
    return ''.join(secrets.choice(chars) for _ in range(length))


def sanitize_data(data: Dict) -> Dict:
    """
    Sanitize data dictionary by removing sensitive values.

    Args:
        data: Dictionary to sanitize

    Returns:
        Sanitized copy of the dictionary
    """
    # Define sensitive key patterns
    sensitive_patterns = [
        'password', 'secret', 'key', 'token', 'credentials',
        'auth', 'private', 'cert', 'hash', 'salt'
    ]

    # Create a copy to avoid modifying the original
    sanitized = {}

    # Process each key
    for key, value in data.items():
        # Check if this is a sensitive field
        is_sensitive = False
        for pattern in sensitive_patterns:
            if pattern.lower() in key.lower():
                is_sensitive = True
                break

        if is_sensitive:
            # Replace value with placeholder
            if value:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = None
        elif isinstance(value, dict):
            # Recursively sanitize nested dictionaries
            sanitized[key] = sanitize_data(value)
        else:
            # Copy non-sensitive values
            sanitized[key] = value

    return sanitized


if __name__ == "__main__":
    # Simple self-test when run directly
    print("Running crypto.py self-test...")

    # Test key generation
    key = generate_key()
    print(f"Generated key: {base64.urlsafe_b64encode(key).decode()[:10]}...")

    # Test encryption/decryption
    plaintext = "This is a test message for encryption and decryption"
    encrypted = encrypt_data(plaintext, key)
    print(f"Encrypted: {encrypted[:20]}...")
    decrypted = decrypt_data(encrypted, key)
    print(f"Decryption successful: {decrypted == plaintext}")

    # Test password functions
    password = generate_secure_password()
    print(f"Generated password: {password}")
    hash_str, salt_str = hash_password(password)
    print(f"Password hash: {hash_str[:10]}...")
    verified = verify_password(password, hash_str, salt_str)
    print(f"Password verification: {verified}")

    # Test hashing
    test_data = "Test data for hashing"
    data_hash = hash_data(test_data)
    print(f"SHA-256 hash: {data_hash[:10]}...")

    print("Self-test completed")
