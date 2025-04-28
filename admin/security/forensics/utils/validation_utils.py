"""
Input Validation Utilities for the Forensic Analysis Toolkit.

This module provides functions for validating various types of input commonly
encountered during forensic analysis, such as file paths, IP addresses, hashes,
and command parameters. It aims to ensure data integrity, prevent security issues
like path traversal, and enforce expected formats.

Integrates with forensic logging to record validation successes and failures.
"""

import logging
import re
import os
import ipaddress
import shutil
from typing import Any, Optional, List, Tuple, Dict, Union, Pattern

# Attempt to import forensic-specific logging and constants
try:
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
    FORENSIC_LOGGING_AVAILABLE = True
except ImportError:
    logging.warning("Forensic logging utility not found. Using standard logger for validation.")
    FORENSIC_LOGGING_AVAILABLE = False
    # Fallback logging function
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict] = None, level: int = logging.INFO):
        log_msg = f"Forensic Operation: {operation}, Success: {success}"
        if details:
            log_msg += f", Details: {details}"
        logging.log(level, log_msg)

try:
    # Potentially use crypto constants for hash validation
    from admin.security.forensics.utils.crypto import SUPPORTED_HASH_ALGORITHMS
except ImportError:
    SUPPORTED_HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"] # Fallback

logger = logging.getLogger(__name__)

# --- Constants ---

# Basic regex for common hash formats (adjust lengths as needed)
HASH_PATTERNS: Dict[str, Pattern[str]] = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "sha512": re.compile(r"^[a-fA-F0-9]{128}$"),
}

# Regex for MAC address validation (common formats)
MAC_ADDRESS_PATTERN: Pattern[str] = re.compile(
    r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
)

# Allowed characters in 'safe' file paths (adjust as needed for your environment)
# This is restrictive; consider specific needs. Avoids shell metacharacters.
SAFE_PATH_CHARS_PATTERN: Pattern[str] = re.compile(r"^[a-zA-Z0-9_\-\./]+$")

# --- Validation Functions ---

def validate_path(
    path_str: str,
    allow_absolute: bool = False,
    base_dir: Optional[str] = None,
    check_exists: bool = False,
    allowed_chars_pattern: Pattern[str] = SAFE_PATH_CHARS_PATTERN
) -> Tuple[bool, str]:
    """
    Validates a file path for safety and format constraints.

    Checks for:
    - Empty path.
    - Disallowed characters.
    - Directory traversal attempts (.., ~).
    - Absolute paths (if not allowed).
    - Path confinement within a base directory (if specified).
    - Existence (if requested).

    Args:
        path_str: The file path string to validate.
        allow_absolute: If True, allows absolute paths (e.g., starting with '/').
        base_dir: If set, ensures the resolved path is within this directory.
        check_exists: If True, checks if the path exists on the filesystem.
        allowed_chars_pattern: Regex pattern for allowed characters in the path.

    Returns:
        Tuple (is_valid: bool, message: str).
    """
    operation = "validate_path"
    details = {"path": path_str, "allow_absolute": allow_absolute, "base_dir": base_dir, "check_exists": check_exists}

    if not path_str:
        msg = "Path cannot be empty."
        log_forensic_operation(operation, False, {**details, "error": msg})
        return False, msg

    # Check for disallowed characters
    if not allowed_chars_pattern.match(path_str):
        msg = f"Path contains invalid characters: {path_str}"
        log_forensic_operation(operation, False, {**details, "error": msg})
        return False, msg

    # Check for directory traversal
    if ".." in path_str.split(os.path.sep) or "~" in path_str:
        msg = f"Potential directory traversal detected in path: {path_str}"
        log_forensic_operation(operation, False, {**details, "error": msg})
        return False, msg

    # Check for absolute paths
    if not allow_absolute and os.path.isabs(path_str):
        msg = f"Absolute paths are not allowed: {path_str}"
        log_forensic_operation(operation, False, {**details, "error": msg})
        return False, msg

    # Check base directory confinement
    if base_dir:
        try:
            resolved_base = os.path.realpath(os.path.abspath(base_dir))
            resolved_path = os.path.realpath(os.path.abspath(os.path.join(base_dir if not os.path.isabs(path_str) else '', path_str)))

            if not resolved_path.startswith(resolved_base):
                msg = f"Path escapes the allowed base directory '{base_dir}': {path_str}"
                log_forensic_operation(operation, False, {**details, "error": msg})
                return False, msg
        except OSError as e:
            msg = f"Error resolving path for base directory check: {e}"
            log_forensic_operation(operation, False, {**details, "error": msg}, level=logging.WARNING)
            # Decide if this is a hard fail or just a warning based on policy
            return False, msg # Fail validation if resolution fails

    # Check existence if requested
    if check_exists:
        # Use the potentially resolved path if base_dir was used
        path_to_check = resolved_path if base_dir else path_str
        if not os.path.exists(path_to_check):
            msg = f"Path does not exist: {path_to_check}"
            log_forensic_operation(operation, False, {**details, "error": msg})
            return False, msg

    log_forensic_operation(operation, True, details)
    return True, "Path is valid."


def validate_ip_address(ip_str: str) -> Tuple[bool, str]:
    """
    Validates if a string is a valid IPv4 or IPv6 address.

    Args:
        ip_str: The string to validate.

    Returns:
        Tuple (is_valid: bool, message: str).
    """
    operation = "validate_ip_address"
    details = {"ip": ip_str}
    try:
        ipaddress.ip_address(ip_str)
        log_forensic_operation(operation, True, details)
        return True, "Valid IP address."
    except ValueError:
        msg = f"Invalid IP address format: {ip_str}"
        log_forensic_operation(operation, False, {**details, "error": msg})
        return False, msg


def validate_mac_address(mac_str: str) -> Tuple[bool, str]:
    """
    Validates if a string is a valid MAC address (common formats).

    Args:
        mac_str: The string to validate.

    Returns:
        Tuple (is_valid: bool, message: str).
    """
    operation = "validate_mac_address"
    details = {"mac": mac_str}
    if MAC_ADDRESS_PATTERN.match(mac_str):
        log_forensic_operation(operation, True, details)
        return True, "Valid MAC address."
    else:
        msg = f"Invalid MAC address format: {mac_str}"
        log_forensic_operation(operation, False, {**details, "error": msg})
        return False, msg


def validate_hash_format(hash_str: str, algorithm: Optional[str] = None) -> Tuple[bool, str]:
    """
    Validates if a string matches the expected format for a given hash algorithm.

    Args:
        hash_str: The hash string to validate.
        algorithm: The expected hash algorithm (e.g., 'md5', 'sha256'). If None,
                   tries to match against all known patterns.

    Returns:
        Tuple (is_valid: bool, message: str).
    """
    operation = "validate_hash_format"
    details = {"hash": hash_str, "algorithm": algorithm}

    if algorithm:
        pattern = HASH_PATTERNS.get(algorithm.lower())
        if pattern:
            if pattern.match(hash_str):
                log_forensic_operation(operation, True, details)
                return True, f"Valid {algorithm.upper()} hash format."
            else:
                msg = f"Invalid {algorithm.upper()} hash format."
                log_forensic_operation(operation, False, {**details, "error": msg})
                return False, msg
        else:
            msg = f"Unsupported or unknown hash algorithm specified: {algorithm}"
            log_forensic_operation(operation, False, {**details, "error": msg}, level=logging.WARNING)
            return False, msg # Or potentially True if format check isn't strict for unknown algos
    else:
        # Try matching against all known patterns
        for algo_name, pattern in HASH_PATTERNS.items():
            if pattern.match(hash_str):
                details["matched_algorithm"] = algo_name
                log_forensic_operation(operation, True, details)
                return True, f"Valid hash format (matches {algo_name.upper()})."

        msg = "Hash does not match any known format (MD5, SHA1, SHA256, SHA512)."
        log_forensic_operation(operation, False, {**details, "error": msg})
        return False, msg


def validate_integer_range(
    value: Any,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None
) -> Tuple[bool, str]:
    """
    Validates if a value is an integer and falls within an optional range.

    Args:
        value: The value to validate.
        min_val: The minimum allowed integer value (inclusive).
        max_val: The maximum allowed integer value (inclusive).

    Returns:
        Tuple (is_valid: bool, message: str).
    """
    operation = "validate_integer_range"
    details = {"value": value, "min": min_val, "max": max_val}

    try:
        int_value = int(value)
    except (ValueError, TypeError):
        msg = f"Value is not a valid integer: {value}"
        log_forensic_operation(operation, False, {**details, "error": msg})
        return False, msg

    if min_val is not None and int_value < min_val:
        msg = f"Value {int_value} is less than minimum allowed ({min_val})."
        log_forensic_operation(operation, False, {**details, "error": msg})
        return False, msg

    if max_val is not None and int_value > max_val:
        msg = f"Value {int_value} is greater than maximum allowed ({max_val})."
        log_forensic_operation(operation, False, {**details, "error": msg})
        return False, msg

    log_forensic_operation(operation, True, details)
    return True, "Value is a valid integer within the specified range."


def validate_choice(value: Any, allowed_choices: List[Any]) -> Tuple[bool, str]:
    """
    Validates if a value is present in a list of allowed choices.

    Args:
        value: The value to validate.
        allowed_choices: A list of permissible values.

    Returns:
        Tuple (is_valid: bool, message: str).
    """
    operation = "validate_choice"
    details = {"value": value, "allowed": allowed_choices}

    if value in allowed_choices:
        log_forensic_operation(operation, True, details)
        return True, "Value is within the allowed choices."
    else:
        msg = f"Value '{value}' is not one of the allowed choices: {allowed_choices}"
        log_forensic_operation(operation, False, {**details, "error": msg})
        return False, msg


# --- Example Usage ---

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    print("--- Testing Validation Utilities ---")

    # Path Validation
    print("\n--- Path Validation ---")
    print(f"Valid relative path: {validate_path('data/evidence.log')}")
    print(f"Valid absolute path (allowed): {validate_path('/secure/data/file.txt', allow_absolute=True)}")
    print(f"Invalid absolute path (disallowed): {validate_path('/etc/passwd')}")
    print(f"Invalid characters: {validate_path('file;rm *')}")
    print(f"Directory traversal: {validate_path('../secrets.txt')}")
    # Create a dummy base dir for testing confinement
    TEST_BASE_DIR = "temp_base_dir_validation"
    TEST_SUB_DIR = os.path.join(TEST_BASE_DIR, "subdir")
    os.makedirs(TEST_SUB_DIR, exist_ok=True)
    print(f"Path within base dir: {validate_path('subdir/file.txt', base_dir=TEST_BASE_DIR)}")
    print(f"Path outside base dir: {validate_path('../outside.txt', base_dir=TEST_BASE_DIR)}")
    print(f"Path exists check (fail): {validate_path('nonexistent_file.xyz', check_exists=True)}")
    # Clean up dummy dir
    shutil.rmtree(TEST_BASE_DIR)


    # IP Address Validation
    print("\n--- IP Address Validation ---")
    print(f"Valid IPv4: {validate_ip_address('192.168.1.1')}")
    print(f"Valid IPv6: {validate_ip_address('::1')}")
    print(f"Invalid IP: {validate_ip_address('192.168.1.256')}")
    print(f"Invalid IP string: {validate_ip_address('not-an-ip')}")

    # MAC Address Validation
    print("\n--- MAC Address Validation ---")
    print(f"Valid MAC (colons): {validate_mac_address('00:1A:2B:3C:4D:5E')}")
    print(f"Valid MAC (hyphens): {validate_mac_address('00-1a-2b-3c-4d-5e')}")
    print(f"Invalid MAC: {validate_mac_address('00:1A:2B:3C:4D')}")
    print(f"Invalid MAC chars: {validate_mac_address('00:1A:2B:3G:4D:5E')}")

    # Hash Format Validation
    print("\n--- Hash Format Validation ---")
    print(f"Valid SHA256: {validate_hash_format('a'*64)}")
    print(f"Valid MD5: {validate_hash_format('b'*32, algorithm='md5')}")
    print(f"Invalid SHA256 (length): {validate_hash_format('a'*63, algorithm='sha256')}")
    print(f"Invalid SHA256 (chars): {validate_hash_format('g'*64, algorithm='sha256')}")
    print(f"Unknown Algo: {validate_hash_format('a'*64, algorithm='sha3')}")
    print(f"Auto-detect MD5: {validate_hash_format('c'*32)}")
    print(f"Auto-detect Fail: {validate_hash_format('d'*50)}")

    # Integer Range Validation
    print("\n--- Integer Range Validation ---")
    print(f"Valid integer (no range): {validate_integer_range(123)}")
    print(f"Valid integer (in range): {validate_integer_range(50, min_val=0, max_val=100)}")
    print(f"Invalid integer (below min): {validate_integer_range(-10, min_val=0)}")
    print(f"Invalid integer (above max): {validate_integer_range(101, max_val=100)}")
    print(f"Invalid type (float): {validate_integer_range(10.5)}")
    print(f"Invalid type (string): {validate_integer_range('abc')}")

    # Choice Validation
    print("\n--- Choice Validation ---")
    choices = ["option1", "option2", "default"]
    print(f"Valid choice: {validate_choice('option1', choices)}")
    print(f"Invalid choice: {validate_choice('option3', choices)}")
    print(f"Valid choice (numeric): {validate_choice(2, [1, 2, 3])}")
    print(f"Invalid choice (numeric): {validate_choice(4, [1, 2, 3])}")

    print("\n--- Validation Utilities Tests Complete ---")
