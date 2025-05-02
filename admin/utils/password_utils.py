"""
Password utility functions for administrative operations.

This module provides password-related functionality for administrative tools
including secure password generation, password validation, and password history
verification to enforce strong passwords and prevent password reuse.

Functions follow security best practices including NIST SP 800-63B guidelines
for authentication and implement additional controls required by compliance
frameworks like PCI-DSS, HIPAA, and CIS.
"""

import re
import logging
import secrets
import string
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any, Union

try:
    # Attempt to import core security components
    from core.security.cs_authentication import validate_password_strength as core_validate_password_strength
    from core.security.cs_constants import SECURITY_CONFIG
    from core.loggings import get_logger
    logger = get_logger(__name__)
    CORE_SECURITY_AVAILABLE = True
except ImportError:
    # Fall back to basic logging if core is unavailable
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.warning("Core security module not available. Using local password validation implementation.")
    CORE_SECURITY_AVAILABLE = False
    SECURITY_CONFIG = {}

# Constants
PASSWORD_MIN_LENGTH = 12  # Minimum password length (NIST recommends at least 8)
PASSWORD_MAX_LENGTH = 128  # Maximum reasonable password length
DEFAULT_HISTORY_SIZE = 24  # Remember 24 previous passwords by default

# Common password patterns to check against
COMMON_PATTERNS = [
    r'123456',
    r'password',
    r'qwerty',
    r'admin',
    r'welcome',
    r'letmein',
    r'abc123',
    r'(.)\\1{2,}',  # Repeating characters
    r'123',
    r'qwe',
    r'asd'
]


def generate_password(
    length: int = 16,
    include_uppercase: bool = True,
    include_lowercase: bool = True,
    include_digits: bool = True,
    include_special: bool = True
) -> str:
    """
    Generate a secure random password.

    Creates a cryptographically strong random password following security
    best practices. The generated password includes at least one character
    from each required character set.

    Args:
        length: Length of the password to generate
        include_uppercase: Whether to include uppercase letters
        include_lowercase: Whether to include lowercase letters
        include_digits: Whether to include digits
        include_special: Whether to include special characters

    Returns:
        Secure random password string

    Raises:
        ValueError: If no character sets are selected or length is too small
    """
    if length < PASSWORD_MIN_LENGTH:
        length = PASSWORD_MIN_LENGTH  # Enforce minimum secure length

    if length > PASSWORD_MAX_LENGTH:
        length = PASSWORD_MAX_LENGTH  # Enforce maximum reasonable length

    # Prepare character sets based on parameters
    char_sets = []

    if include_lowercase:
        char_sets.append(string.ascii_lowercase)

    if include_uppercase:
        char_sets.append(string.ascii_uppercase)

    if include_digits:
        char_sets.append(string.digits)

    if include_special:
        char_sets.append("!@#$%^&*()-_=+[]{}|;:,.<>?")

    if not char_sets:
        raise ValueError("At least one character set must be included")

    # Build password with at least one character from each set
    password = []
    for char_set in char_sets:
        password.append(secrets.choice(char_set))

    # Fill remaining characters with random selections
    all_chars = ''.join(char_sets)
    remaining_length = max(0, length - len(password))
    password.extend(secrets.choice(all_chars) for _ in range(remaining_length))

    # Shuffle the password characters for extra security
    secrets.SystemRandom().shuffle(password)

    return ''.join(password)


def validate_password_strength(
    password: str,
    username: Optional[str] = None,
    min_length: int = None,
    require_uppercase: bool = True,
    require_lowercase: bool = True,
    require_digit: bool = True,
    require_special: bool = True,
    check_common_patterns: bool = True
) -> Tuple[bool, List[str]]:
    """
    Validate password strength against security requirements.

    Checks passwords against multiple security criteria including
    length, character types, common patterns, and contextual information
    to ensure strong password selection. Can use core security module
    if available or fall back to local implementation.

    Args:
        password: Password to validate
        username: Username to check against (to prevent username in password)
        min_length: Minimum password length (defaults to PASSWORD_MIN_LENGTH)
        require_uppercase: Whether to require uppercase letters
        require_lowercase: Whether to require lowercase letters
        require_digit: Whether to require digits
        require_special: Whether to require special characters
        check_common_patterns: Whether to check for common password patterns

    Returns:
        Tuple of (is_valid, list_of_error_messages)
    """
    if not password or not isinstance(password, str):
        return False, ["Password cannot be empty"]

    # If core security is available, try to use its validation
    if CORE_SECURITY_AVAILABLE:
        try:
            is_valid, failed_requirements = core_validate_password_strength(password)

            # If valid according to core but we need to check username as well
            if is_valid and username and username.lower() in password.lower():
                is_valid = False
                failed_requirements.append("Password should not contain the username")

            return is_valid, failed_requirements
        except Exception as e:
            logger.warning(f"Error using core password validation: {e}")
            # Fall back to local implementation

    # Local password validation implementation
    errors = []

    # Use provided min_length or default
    min_length = min_length if min_length is not None else PASSWORD_MIN_LENGTH

    # Check length constraints
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters")

    if len(password) > PASSWORD_MAX_LENGTH:
        errors.append(f"Password must not exceed {PASSWORD_MAX_LENGTH} characters")

    # Check character type requirements
    if require_uppercase and not any(c.isupper() for c in password):
        errors.append("Password must include uppercase letters (A-Z)")

    if require_lowercase and not any(c.islower() for c in password):
        errors.append("Password must include lowercase letters (a-z)")

    if require_digit and not any(c.isdigit() for c in password):
        errors.append("Password must include numbers (0-9)")

    if require_special and not any(not c.isalnum() for c in password):
        errors.append("Password must include special characters (!@#$%, etc)")

    # Check for username in password
    if username and username.lower() in password.lower():
        errors.append("Password should not contain the username")

    # Check for common patterns
    if check_common_patterns:
        password_lower = password.lower()
        for pattern in COMMON_PATTERNS:
            if re.search(pattern, password_lower):
                errors.append("Password contains common patterns that are easily guessed")
                break

    return len(errors) == 0, errors


def check_password_history(
    password: str,
    password_history: List[str],
    history_size: int = DEFAULT_HISTORY_SIZE,
    hash_algorithm: str = 'sha256'
) -> Tuple[bool, Optional[str]]:
    """
    Check if a password exists in the password history.

    Compares a new password against a list of previous password hashes to
    prevent password reuse. Uses specified hashing algorithm for comparison.

    Args:
        password: New password to check
        password_history: List of previous password hashes
        history_size: Number of previous passwords to check against
        hash_algorithm: Hashing algorithm to use for comparison

    Returns:
        Tuple of (is_unique, error_message)
    """
    if not password or not isinstance(password, str):
        return False, "Password cannot be empty"

    if not password_history:
        return True, None

    # Limit history checking to specified size
    recent_history = password_history[-history_size:] if len(password_history) > history_size else password_history

    # Hash the new password for comparison
    # Note: In a real-world implementation, you would include a salt and use a proper
    # password hashing algorithm like bcrypt, but for simple history checking we use
    # a basic hash for comparison since the stored passwords would already be hashed.
    password_hash = hashlib.new(hash_algorithm)
    password_hash.update(password.encode('utf-8'))
    digest = password_hash.hexdigest()

    # Check if the password matches any in history
    for old_password in recent_history:
        # If the password history contains hashes
        if len(old_password) == len(digest) and all(c in '0123456789abcdef' for c in old_password.lower()):
            if old_password.lower() == digest.lower():
                return False, f"Password matches one of your last {history_size} passwords"
        # If the password history contains the actual passwords (not recommended)
        elif old_password == password:
            return False, f"Password matches one of your last {history_size} passwords"

    return True, None


def get_password_requirements() -> Dict[str, Any]:
    """
    Get the current password requirements for display to users.

    Retrieves password requirements from the security configuration or
    uses default values if configuration is not available.

    Returns:
        Dictionary with password requirements
    """
    min_length = SECURITY_CONFIG.get('MIN_PASSWORD_LENGTH', PASSWORD_MIN_LENGTH)

    return {
        'min_length': min_length,
        'require_uppercase': SECURITY_CONFIG.get('REQUIRE_UPPERCASE', True),
        'require_lowercase': SECURITY_CONFIG.get('REQUIRE_LOWERCASE', True),
        'require_digit': SECURITY_CONFIG.get('REQUIRE_DIGIT', True),
        'require_special': SECURITY_CONFIG.get('REQUIRE_SPECIAL', True),
        'history_size': SECURITY_CONFIG.get('PASSWORD_HISTORY_SIZE', DEFAULT_HISTORY_SIZE),
        'max_days': SECURITY_CONFIG.get('PASSWORD_MAX_DAYS', 90),
        'description': f"Password must be at least {min_length} characters long and include a mix of uppercase letters, lowercase letters, numbers, and special characters."
    }


if __name__ == "__main__":
    # Self-test functionality
    print("Testing password utilities...")

    # Test password generation
    print("\nGenerating passwords:")
    print(f"Default: {generate_password()}")
    print(f"Length 20: {generate_password(20)}")
    print(f"No special chars: {generate_password(include_special=False)}")
    print(f"Only digits and uppercase: {generate_password(include_lowercase=False, include_special=False)}")

    # Test password validation
    print("\nValidating passwords:")
    test_passwords = [
        "short",
        "nocapitals123!",
        "NOCAPS123!",
        "NoSpecials123",
        "Password123!",
        "usernameIsAdmin",
        "Tr0ub4dor&3Xample!"
    ]

    for pwd in test_passwords:
        valid, errors = validate_password_strength(pwd, username="admin")
        status = "Valid" if valid else "Invalid"
        print(f"'{pwd}': {status}")
        if not valid:
            for error in errors:
                print(f"  - {error}")

    # Test password history check
    print("\nChecking password history:")
    history = [
        hashlib.sha256("OldPassword123!".encode()).hexdigest(),
        hashlib.sha256("AnotherOld987@".encode()).hexdigest()
    ]

    unique, error = check_password_history("NewPassword456$", history)
    print(f"New password is unique: {unique}")

    unique, error = check_password_history("OldPassword123!", history)
    print(f"Old password reuse: {unique}")
    if error:
        print(f"  - {error}")
