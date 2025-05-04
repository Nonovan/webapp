"""
Cryptographic utilities for the Forensic Analysis Toolkit.

This module provides cryptographic functions specifically tailored for forensic
use cases, ensuring evidence integrity and secure handling of sensitive data
during investigations. It includes functions for hashing, hash verification,
and encryption/decryption of evidence files.

Functions prioritize forensic soundness, including support for standard forensic
hash algorithms (MD5, SHA1, SHA256) and secure handling of cryptographic keys.
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
from typing import Dict, List, Optional, Tuple, Union, Any

# Attempt to import core security and logging components
try:
    from core.security.cs_crypto import (
        encrypt_aes_gcm, decrypt_aes_gcm, generate_secure_hash,
        _get_encryption_key as _get_core_encryption_key,
        constant_time_compare
    )
    from core.loggings import get_logger
    from core.security.cs_audit import log_security_event
    CORE_CRYPTO_AVAILABLE = True
    logger = get_logger(__name__)
except ImportError:
    CORE_CRYPTO_AVAILABLE = False
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.warning("Core security modules not found. Using basic crypto functions.")
    # Define minimal fallbacks if core is unavailable
    def encrypt_aes_gcm(plaintext: str, key: Optional[bytes] = None) -> str:
        raise NotImplementedError("Core crypto module needed for AES-GCM encryption.")

    def decrypt_aes_gcm(encrypted_data: str, key: Optional[bytes] = None) -> str:
        raise NotImplementedError("Core crypto module needed for AES-GCM decryption.")

    def generate_secure_hash(data: Union[str, bytes], algorithm: str = 'sha256') -> str:
        hash_obj = hashlib.new(algorithm)
        if isinstance(data, str):
            data = data.encode('utf-8')
        hash_obj.update(data)
        return hash_obj.hexdigest()

    def log_security_event(*args, **kwargs):
        logger.info(f"Security Event (core unavailable): {args} {kwargs}")

    def _get_core_encryption_key() -> bytes:
        # In a real fallback, might load from env var or dedicated forensic key file
        # For safety, raise error if core isn't available and key isn't configured elsewhere
        raise NotImplementedError("Core crypto module needed for key management.")

    def constant_time_compare(val1: Union[str, bytes], val2: Union[str, bytes]) -> bool:
        """Constant time comparison to prevent timing attacks."""
        if isinstance(val1, str):
            val1 = val1.encode()
        if isinstance(val2, str):
            val2 = val2.encode()

        if len(val1) != len(val2):
            return False

        result = 0
        for x, y in zip(val1, val2):
            result |= x ^ y
        return result == 0

# Attempt to import forensic-specific logging
try:
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
except ImportError:
    logger.warning("Forensic logging utility not found. Using standard logger.")
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict] = None):
        level = logging.INFO if success else logging.ERROR
        log_msg = f"Forensic Operation: {operation}, Success: {success}"
        if details:
            log_msg += f", Details: {details}"
        logger.log(level, log_msg)

# Attempt to import secure credential handling for forensic keys
try:
    from admin.utils.secure_credentials import get_credential
    SECURE_CREDENTIALS_AVAILABLE = True
except ImportError:
    logger.warning("Secure credential utility not found. Forensic key management may be limited.")
    SECURE_CREDENTIALS_AVAILABLE = False
    def get_credential(name: str, source_preference: Optional[List[str]] = None) -> Optional[str]:
        # Fallback: try environment variable
        return os.environ.get(f"FORENSIC_KEY_{name.upper()}")

# Constants
SUPPORTED_HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha384", "sha512", "blake2b", "blake2s"]
DEFAULT_HASH_ALGORITHM = "sha256"
FORENSIC_ENCRYPTION_KEY_NAME = "forensic_evidence_encryption_key"
FORENSIC_HMAC_KEY_NAME = "forensic_hmac_key"
CHUNK_SIZE = 65536  # 64KB for file hashing
KEY_CACHE_DURATION = 300  # Cache keys for 5 minutes max
MAX_KEY_RETRIEVAL_ATTEMPTS = 3

# In-memory key cache with expiry time
_key_cache = {}

def _get_forensic_key(purpose: str = "encryption") -> Optional[bytes]:
    """
    Retrieves the forensic key securely for the specified purpose.

    Uses a cache to minimize key retrievals with a cache expiry for security.

    Args:
        purpose: Key purpose identifier ("encryption" or "hmac")

    Returns:
        Optional[bytes]: The key as bytes, or None if not found.
    """
    # Check cache first
    cache_key = f"forensic_{purpose}_key"
    cached_data = _key_cache.get(cache_key)
    if cached_data and cached_data.get("expiry", 0) > time.time():
        logger.debug(f"Using cached {purpose} key")
        return cached_data.get("key")

    # Key name based on purpose
    key_name = FORENSIC_ENCRYPTION_KEY_NAME if purpose == "encryption" else FORENSIC_HMAC_KEY_NAME

    # Try multiple retrieval sources with fallbacks
    for attempt in range(MAX_KEY_RETRIEVAL_ATTEMPTS):
        # 1. Try secure credential storage first
        if SECURE_CREDENTIALS_AVAILABLE:
            key_str = get_credential(key_name)
            if key_str:
                break

        # 2. Try environment variable
        key_str = os.environ.get(f"{key_name.upper()}")
        if key_str:
            break

        # 3. If encryption key and core is available, try that as last resort
        if purpose == "encryption" and CORE_CRYPTO_AVAILABLE and attempt == MAX_KEY_RETRIEVAL_ATTEMPTS - 1:
            try:
                logger.warning(f"Forensic {purpose} key not found. Falling back to core encryption key.")
                key = _get_core_encryption_key()
                # Cache the key
                _key_cache[cache_key] = {
                    "key": key,
                    "expiry": time.time() + KEY_CACHE_DURATION
                }
                log_forensic_operation(f"get_forensic_{purpose}_key", True, {"status": "Using core key fallback"})
                return key
            except Exception as e:
                logger.error(f"Failed to retrieve core encryption key as fallback: {e}")
                log_forensic_operation(f"get_forensic_{purpose}_key", False, {"error": f"Core key fallback failed: {e}"})
                return None

        # Short delay between attempts
        time.sleep(0.1)
    else:
        # No key found after all attempts
        logger.error(f"No suitable {purpose} key found for forensic operations.")
        log_forensic_operation(f"get_forensic_{purpose}_key", False, {"error": "No key found"})
        return None

    # Process the key string
    try:
        # Keys should be base64 encoded
        key = base64.urlsafe_b64decode(key_str)

        # Cache the key
        _key_cache[cache_key] = {
            "key": key,
            "expiry": time.time() + KEY_CACHE_DURATION
        }

        log_forensic_operation(f"get_forensic_{purpose}_key", True)
        return key
    except Exception as e:
        logger.error(f"Failed to decode forensic {purpose} key: {e}")
        log_forensic_operation(f"get_forensic_{purpose}_key", False, {"error": f"Failed to decode key: {e}"})
        return None


def calculate_file_hash(file_path: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> Optional[str]:
    """
    Calculates the hash of a file using the specified algorithm.

    Args:
        file_path: Path to the file.
        algorithm: Hash algorithm to use (md5, sha1, sha256, sha512, etc).

    Returns:
        The calculated hash as a hex string, or None if an error occurs.
    """
    if algorithm not in SUPPORTED_HASH_ALGORITHMS:
        logger.error(f"Unsupported hash algorithm: {algorithm}")
        log_forensic_operation("calculate_file_hash", False, {"file": file_path, "algorithm": algorithm, "error": "Unsupported algorithm"})
        return None

    start_time = time.time()
    try:
        hasher = hashlib.new(algorithm)
        file_size = os.path.getsize(file_path)

        with open(file_path, 'rb') as f:
            while chunk := f.read(CHUNK_SIZE):
                hasher.update(chunk)

        file_hash = hasher.hexdigest()
        duration = time.time() - start_time

        details = {
            "file": file_path,
            "algorithm": algorithm,
            "hash": file_hash,
            "file_size_bytes": file_size,
            "duration_seconds": round(duration, 3)
        }

        log_forensic_operation("calculate_file_hash", True, details)
        return file_hash
    except FileNotFoundError:
        logger.error(f"File not found for hashing: {file_path}")
        log_forensic_operation("calculate_file_hash", False, {"file": file_path, "algorithm": algorithm, "error": "File not found"})
        return None
    except PermissionError:
        logger.error(f"Permission denied for hashing file: {file_path}")
        log_forensic_operation("calculate_file_hash", False, {"file": file_path, "algorithm": algorithm, "error": "Permission denied"})
        return None
    except Exception as e:
        logger.error(f"Error hashing file {file_path}: {e}")
        log_forensic_operation("calculate_file_hash", False, {"file": file_path, "algorithm": algorithm, "error": str(e)})
        return None


def verify_file_hash(file_path: str, expected_hash: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> bool:
    """
    Verifies the hash of a file against an expected value.

    Args:
        file_path: Path to the file.
        expected_hash: The expected hash value (hex string).
        algorithm: Hash algorithm used for the expected hash.

    Returns:
        True if the calculated hash matches the expected hash, False otherwise.
    """
    calculated_hash = calculate_file_hash(file_path, algorithm)
    if calculated_hash is None:
        log_forensic_operation("verify_file_hash", False, {"file": file_path, "algorithm": algorithm, "error": "Hash calculation failed"})
        return False

    is_match = constant_time_compare(calculated_hash.lower(), expected_hash.lower())

    details = {
        "file": file_path,
        "algorithm": algorithm,
        "match": is_match,
        "basename": os.path.basename(file_path)
    }

    log_forensic_operation("verify_file_hash", True, details)

    if not is_match:
        logger.warning(f"Hash mismatch for file {file_path}. Expected: {expected_hash}, Calculated: {calculated_hash}")
        try:
            log_security_event(
                event_type="forensic_integrity_check_failed",
                description=f"Hash mismatch detected for file: {os.path.basename(file_path)}",
                severity="warning",
                details={
                    "file_path": file_path,
                    "expected_hash": expected_hash,
                    "calculated_hash": calculated_hash,
                    "algorithm": algorithm,
                    "timestamp": datetime.now().isoformat()
                }
            )
        except Exception as log_e:
            logger.error(f"Failed to log security event for hash mismatch: {log_e}")

    return is_match


def calculate_data_hash(data: Union[str, bytes], algorithm: str = DEFAULT_HASH_ALGORITHM) -> Optional[str]:
    """
    Calculates the hash of in-memory data.

    Args:
        data: The data to hash (string or bytes).
        algorithm: Hash algorithm to use.

    Returns:
        The calculated hash as a hex string, or None if an error occurs.
    """
    if algorithm not in SUPPORTED_HASH_ALGORITHMS:
        logger.error(f"Unsupported hash algorithm: {algorithm}")
        log_forensic_operation("calculate_data_hash", False, {"algorithm": algorithm, "error": "Unsupported algorithm"})
        return None
    try:
        # Use core function if available, otherwise use fallback
        data_hash = generate_secure_hash(data, algorithm=algorithm)
        details = {
            "algorithm": algorithm,
            "data_length": len(data) if isinstance(data, bytes) else len(data.encode())
        }
        log_forensic_operation("calculate_data_hash", True, details)
        return data_hash
    except Exception as e:
        logger.error(f"Error hashing data: {e}")
        log_forensic_operation("calculate_data_hash", False, {"algorithm": algorithm, "error": str(e)})
        return None


def encrypt_evidence_data(plaintext: str, add_timestamp: bool = True) -> Optional[str]:
    """
    Encrypts sensitive forensic data using AES-GCM.

    Uses the dedicated forensic key if available, otherwise falls back.
    Optionally adds a timestamp for time-of-protection evidence.

    Args:
        plaintext: The data to encrypt.
        add_timestamp: Whether to add an encryption timestamp to the data.

    Returns:
        The encrypted data as a base64 string, or None if encryption fails.
    """
    key = _get_forensic_key(purpose="encryption")
    if not key:
        log_forensic_operation("encrypt_evidence_data", False, {"error": "Encryption key unavailable"})
        return None

    try:
        # Add timestamp if requested
        if add_timestamp:
            timestamp = datetime.now().isoformat()
            if isinstance(plaintext, dict):
                plaintext_dict = plaintext.copy()
                plaintext_dict["_encryption_timestamp"] = timestamp
                data_to_encrypt = json.dumps(plaintext_dict)
            else:
                data_to_encrypt = f"{plaintext}\n[Encrypted: {timestamp}]"
        else:
            data_to_encrypt = plaintext

        encrypted_data = encrypt_aes_gcm(data_to_encrypt, key=key)

        details = {
            "data_length": len(data_to_encrypt),
            "timestamp_added": add_timestamp
        }
        log_forensic_operation("encrypt_evidence_data", True, details)
        return encrypted_data
    except Exception as e:
        logger.error(f"Failed to encrypt evidence data: {e}")
        log_forensic_operation("encrypt_evidence_data", False, {"error": str(e)})
        return None


def decrypt_evidence_data(encrypted_data: str) -> Optional[str]:
    """
    Decrypts sensitive forensic data encrypted with AES-GCM.

    Uses the dedicated forensic key if available, otherwise falls back.

    Args:
        encrypted_data: The base64 encoded encrypted data.

    Returns:
        The decrypted plaintext string, or None if decryption fails.
    """
    key = _get_forensic_key(purpose="encryption")
    if not key:
        log_forensic_operation("decrypt_evidence_data", False, {"error": "Decryption key unavailable"})
        return None

    try:
        plaintext = decrypt_aes_gcm(encrypted_data, key=key)
        log_forensic_operation("decrypt_evidence_data", True)
        return plaintext
    except Exception as e:
        logger.error(f"Failed to decrypt evidence data: {e}")
        log_forensic_operation("decrypt_evidence_data", False, {"error": str(e)})

        # Log potential tampering attempt
        if "invalid" in str(e).lower() or "tag" in str(e).lower() or "auth" in str(e).lower():
             try:
                log_security_event(
                    event_type="forensic_decryption_failed",
                    description="Failed to decrypt forensic data - possible tampering",
                    severity="critical",
                    details={
                        "error": str(e),
                        "timestamp": datetime.now().isoformat()
                    }
                )
             except Exception as log_e:
                 logger.error(f"Failed to log security event for decryption failure: {log_e}")
        return None


def generate_secure_id(prefix: str = "ev", length: int = 16) -> str:
    """
    Generates a secure random identifier for evidence tracking.

    Args:
        prefix: Optional prefix for the identifier (default: "ev").
        length: Length of the random part (default: 16).

    Returns:
        A secure random string identifier with the specified prefix.
    """
    if length < 12:
        # Enforce minimum security
        length = 12

    random_part = secrets.token_hex(length // 2)  # Each byte becomes 2 hex chars
    timestamp = int(time.time())

    # Format: prefix-timestamp-randomhex
    secure_id = f"{prefix}-{timestamp}-{random_part}"

    log_forensic_operation("generate_secure_id", True, {"prefix": prefix, "length": length})
    return secure_id


def generate_hmac(data: Union[str, bytes], key: Optional[bytes] = None,
                 algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
    """
    Generate an HMAC (Hash-based Message Authentication Code) for data verification.

    Creates a cryptographic hash that requires a secret key, providing both data
    integrity and authenticity verification for forensic evidence and data.

    Args:
        data: Input data to generate HMAC for (string or bytes)
        key: Secret key to use for HMAC generation (bytes)
             If None, attempts to use forensic HMAC key from secure storage
        algorithm: Hash algorithm to use (default: from forensic constants)

    Returns:
        Hexadecimal string representation of the HMAC

    Raises:
        ValueError: If algorithm is not supported or key cannot be obtained
    """
    operation = "generate_hmac"
    operation_details = {"algorithm": algorithm}

    if not data:
        logger.warning("Empty data provided for HMAC generation")
        log_forensic_operation(operation, False,
                              {**operation_details, "error": "Empty data provided"})
        return ""

    # Get key if not provided
    if key is None:
        key = _get_forensic_key(purpose="hmac")
        if not key:
            error = "No HMAC key available"
            logger.error(error)
            log_forensic_operation(operation, False,
                                 {**operation_details, "error": error})
            raise ValueError(error)

    # Convert data to bytes if it's a string
    if isinstance(data, str):
        data = data.encode('utf-8')

    try:
        # Select and validate hash algorithm
        if algorithm.lower() in SUPPORTED_HASH_ALGORITHMS:
            hash_obj = getattr(hashlib, algorithm.lower())
        else:
            error = f"Unsupported hash algorithm: {algorithm}"
            logger.error(error)
            log_forensic_operation(operation, False,
                                 {**operation_details, "error": error})
            raise ValueError(error)

        # Generate HMAC
        hmac_value = hmac.new(key, data, hash_obj).hexdigest()

        # Log the operation (without exposing the key)
        log_forensic_operation(operation, True, {
            **operation_details,
            "data_size": len(data),
        })

        return hmac_value

    except Exception as e:
        error = f"Failed to generate HMAC: {str(e)}"
        logger.error(error)
        log_forensic_operation(operation, False,
                             {**operation_details, "error": error})
        raise


def sign_evidence_data(data: Union[str, bytes], include_timestamp: bool = True) -> Optional[Dict[str, str]]:
    """
    Creates a digital signature for evidence data.

    Args:
        data: The data to sign (string or bytes)
        include_timestamp: Whether to include a timestamp in the signed data

    Returns:
        Dictionary with signature information or None if signing fails
    """
    hmac_key = _get_forensic_key(purpose="hmac")
    if not hmac_key:
        log_forensic_operation("sign_evidence_data", False, {"error": "HMAC key unavailable"})
        return None

    try:
        timestamp = datetime.now().isoformat() if include_timestamp else None

        # Prepare the data to be signed
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data

        # Add timestamp if requested
        if timestamp:
            data_bytes = data_bytes + b"|" + timestamp.encode('utf-8')

        # Create HMAC signature
        signature = hmac.new(hmac_key, data_bytes, hashlib.sha256).hexdigest()

        result = {
            "signature": signature,
            "algorithm": "hmac-sha256"
        }

        if timestamp:
            result["timestamp"] = timestamp

        log_forensic_operation("sign_evidence_data", True, {
            "data_size": len(data_bytes),
            "include_timestamp": include_timestamp
        })
        return result

    except Exception as e:
        logger.error(f"Failed to sign evidence data: {e}")
        log_forensic_operation("sign_evidence_data", False, {"error": str(e)})
        return None


def verify_evidence_signature(
    data: Union[str, bytes],
    signature: str,
    timestamp: Optional[str] = None
) -> bool:
    """
    Verifies the signature of evidence data.

    Args:
        data: The original data that was signed
        signature: The signature to verify
        timestamp: The timestamp that was included in signing, if any

    Returns:
        True if signature is valid, False otherwise
    """
    hmac_key = _get_forensic_key(purpose="hmac")
    if not hmac_key:
        log_forensic_operation("verify_evidence_signature", False, {"error": "HMAC key unavailable"})
        return False

    try:
        # Prepare the data for verification
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data

        # Add timestamp if it was included
        if timestamp:
            data_bytes = data_bytes + b"|" + timestamp.encode('utf-8')

        # Calculate expected signature
        expected_sig = hmac.new(hmac_key, data_bytes, hashlib.sha256).hexdigest()

        # Use constant-time comparison to prevent timing attacks
        is_valid = constant_time_compare(signature, expected_sig)

        log_forensic_operation("verify_evidence_signature", True, {
            "data_size": len(data_bytes),
            "is_valid": is_valid,
            "has_timestamp": timestamp is not None
        })

        if not is_valid:
            # Log security event for signature verification failure
            try:
                log_security_event(
                    event_type="forensic_signature_verification_failed",
                    description="Evidence signature verification failed - possible tampering",
                    severity="warning",
                    details={
                        "timestamp": datetime.now().isoformat()
                    }
                )
            except Exception as log_e:
                logger.error(f"Failed to log security event for signature verification failure: {log_e}")

        return is_valid

    except Exception as e:
        logger.error(f"Failed to verify evidence signature: {e}")
        log_forensic_operation("verify_evidence_signature", False, {"error": str(e)})
        return False


if __name__ == "__main__":
    # Create a dummy file for testing
    test_file = "test_evidence.txt"
    test_content = "This is sensitive forensic evidence."
    with open(test_file, "w") as f:
        f.write(test_content)

    # Test hashing
    print(f"--- Hashing ---")
    sha256_hash = calculate_file_hash(test_file, "sha256")
    print(f"SHA256 Hash: {sha256_hash}")
    md5_hash = calculate_file_hash(test_file, "md5")
    print(f"MD5 Hash: {md5_hash}")

    # Test verification
    print(f"\n--- Verification ---")
    if sha256_hash:
        print(f"Verify SHA256 (Correct): {verify_file_hash(test_file, sha256_hash, 'sha256')}")
        print(f"Verify SHA256 (Incorrect): {verify_file_hash(test_file, 'incorrecthash', 'sha256')}")

    # Test data hashing
    print(f"\n--- Data Hashing ---")
    data_hash = calculate_data_hash(test_content, "sha256")
    print(f"Data SHA256 Hash: {data_hash}")
    print(f"Data hash matches file hash: {data_hash == sha256_hash}")

    # Test secure ID generation
    print(f"\n--- Secure ID Generation ---")
    secure_id = generate_secure_id(prefix="evidence")
    print(f"Secure ID: {secure_id}")

    # Test digital signatures
    print(f"\n--- Digital Signatures ---")
    signature_data = sign_evidence_data(test_content)
    if signature_data:
        print(f"Signature: {signature_data['signature']}")
        print(f"Timestamp: {signature_data.get('timestamp')}")
        valid = verify_evidence_signature(
            test_content,
            signature_data['signature'],
            signature_data.get('timestamp')
        )
        print(f"Valid signature: {valid}")
        # Test invalid signature
        valid = verify_evidence_signature(
            test_content,
            "invalid_signature",
            signature_data.get('timestamp')
        )
        print(f"Invalid signature check result: {valid}")

    # Test encryption/decryption (requires a key to be available)
    print(f"\n--- Encryption/Decryption ---")
    # Ensure a key is available for this test, e.g., via env var FORENSIC_EVIDENCE_ENCRYPTION_KEY
    # Or ensure core crypto is available and has its key configured
    if _get_forensic_key():
        encrypted = encrypt_evidence_data(test_content)
        if encrypted:
            print(f"Encrypted: {encrypted[:30]}...")
            decrypted = decrypt_evidence_data(encrypted)
            print(f"Decrypted: {decrypted}")
            print(f"Match: {decrypted == test_content}" if decrypted else "Decryption failed")
        else:
            print("Encryption failed.")
    else:
        print("Skipping encryption/decryption test: No key available.")

    # Clean up dummy file
    try:
        os.remove(test_file)
    except OSError:
        pass
