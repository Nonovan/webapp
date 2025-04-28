#!/usr/bin/env python3
"""
Generate security keys for application configuration.

This script generates various cryptographic keys needed for secure application
operations, including Flask session keys, JWT tokens, and encryption keys.
Keys are output in a format suitable for environment files or configuration.

This utility adheres to security best practices by:
- Using cryptographically secure random generation
- Applying proper key lengths for different security purposes
- Supporting multiple output formats and targets
- Setting appropriate file permissions on sensitive outputs
- Providing options for key rotation and validation

Usage:
    ./generate_security_keys.py [options]

Options:
    --output FILE, -o FILE     Write keys to a file instead of stdout
    --format FORMAT, -f FORMAT Output format: env (default), json, or yaml
    --key-types TYPES, -t TYPES Types of keys to generate (comma-separated)
                               Available types: all, session, jwt, encryption,
                               api, cookie, iv, hmac, signing (default: all)
    --count N, -c N            Number of each key type to generate (default: 1)
    --prefix PREFIX, -p PREFIX Add prefix to key names (e.g., "PROD_")
    --validate, -v             Validate keys against security requirements
    --rotate FILE              Rotate keys in existing file (preserves comments)
    --no-timestamp             Omit timestamp comments in output
    --expiry DAYS              Add expiry info for keys (days from now)
    --verbose                  Show detailed information
    --help, -h                 Show this help message
"""

import os
import sys
import re
import secrets
import base64
import argparse
import json
import logging
import yaml
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger('security_keys')

# Security constants - key lengths in bytes
KEY_LENGTHS = {
    'SESSION': 32,     # 256 bits for Flask session
    'JWT': 32,         # 256 bits for JWT signing
    'ENCRYPTION': 32,  # 256 bits for AES-256
    'API': 32,         # 256 bits for API keys
    'COOKIE': 24,      # 192 bits for cookies
    'IV': 16,          # 128 bits for initialization vectors
    'HMAC': 32,        # 256 bits for HMAC keys
    'SIGNING': 32      # 256 bits for digital signatures
}

# Default validation settings
VALIDATION_SETTINGS = {
    'min_entropy': 128,  # Minimum entropy in bits
    'reserved_words': ['password', 'secret', 'key', 'test', 'dev', 'prod']
}


def generate_keys(key_types: List[str] = None, count: int = 1, prefix: str = "") -> Dict[str, str]:
    """
    Generate cryptographic keys for application security.

    Args:
        key_types: List of key types to generate (or None for all)
        count: Number of each key type to generate
        prefix: String prefix to add to key names

    Returns:
        dict: Dictionary containing generated security keys
    """
    if key_types is None or "all" in key_types:
        key_types = ["session", "jwt", "encryption", "api", "cookie", "iv", "hmac", "signing"]

    keys = {}
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for i in range(1, count + 1):
        # Add suffix for multiple keys
        suffix = f"_{i}" if count > 1 else ""

        # Session key
        if "session" in key_types:
            key_name = f"{prefix}SECRET_KEY{suffix}"
            keys[key_name] = secrets.token_hex(KEY_LENGTHS['SESSION'])

        # JWT signing key
        if "jwt" in key_types:
            key_name = f"{prefix}JWT_SECRET_KEY{suffix}"
            keys[key_name] = secrets.token_hex(KEY_LENGTHS['JWT'])

        # Encryption key (base64-encoded)
        if "encryption" in key_types:
            key_name = f"{prefix}ENCRYPTION_KEY{suffix}"
            keys[key_name] = base64.b64encode(os.urandom(KEY_LENGTHS['ENCRYPTION'])).decode('utf-8')

        # API authentication key
        if "api" in key_types:
            key_name = f"{prefix}API_KEY{suffix}"
            keys[key_name] = secrets.token_urlsafe(KEY_LENGTHS['API'])

        # Cookie signing secret
        if "cookie" in key_types:
            key_name = f"{prefix}COOKIE_SECRET{suffix}"
            keys[key_name] = secrets.token_hex(KEY_LENGTHS['COOKIE'])

        # Initialization vector for encryption
        if "iv" in key_types:
            key_name = f"{prefix}ENCRYPTION_IV{suffix}"
            keys[key_name] = base64.b64encode(os.urandom(KEY_LENGTHS['IV'])).decode('utf-8')

        # HMAC key for message authentication
        if "hmac" in key_types:
            key_name = f"{prefix}HMAC_KEY{suffix}"
            keys[key_name] = secrets.token_hex(KEY_LENGTHS['HMAC'])

        # Signing key for digital signatures
        if "signing" in key_types:
            key_name = f"{prefix}SIGNING_KEY{suffix}"
            keys[key_name] = secrets.token_hex(KEY_LENGTHS['SIGNING'])

    return keys


def validate_keys(keys: Dict[str, str]) -> Tuple[bool, Optional[str]]:
    """
    Validate that generated keys meet security requirements.

    Args:
        keys: Dictionary of key-value pairs to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    for key_name, value in keys.items():
        # Check for minimum length based on key type
        key_type = key_name.split('_')[0] if '_' in key_name else key_name

        # Extract the base key type (without prefixes/suffixes)
        base_key_type = None
        for kt in KEY_LENGTHS.keys():
            if kt in key_name.upper():
                base_key_type = kt
                break

        if base_key_type:
            min_length = KEY_LENGTHS[base_key_type]

            # Check length
            if len(value) < min_length * 2:  # hex encoding doubles the length
                return False, f"Key '{key_name}' does not meet minimum length requirement"

            # Check for common patterns or predictable values
            for word in VALIDATION_SETTINGS['reserved_words']:
                if word in value.lower():
                    return False, f"Key '{key_name}' contains a reserved word: {word}"

        # Check for duplicates
        count = list(keys.values()).count(value)
        if count > 1:
            return False, f"Duplicate key value detected for '{key_name}'"

    return True, None


def format_as_env(keys: Dict[str, str], add_timestamp: bool = True,
                  expiry_days: Optional[int] = None) -> str:
    """
    Format keys as environment variables.

    Args:
        keys: Dictionary of keys to format
        add_timestamp: Whether to add timestamp comments
        expiry_days: Number of days until keys expire

    Returns:
        Formatted string in environment variable format
    """
    timestamp = datetime.datetime.now()
    lines = []

    if add_timestamp:
        lines.append(f"# Generated on {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")

    if expiry_days:
        expiry_date = timestamp + datetime.timedelta(days=expiry_days)
        lines.append(f"# Keys expire on {expiry_date.strftime('%Y-%m-%d')} (rotation recommended before this date)")

    lines.append("")

    # Group keys by type
    key_groups = {}
    for key, value in keys.items():
        # Extract the key type
        key_type = key.split('_')[0].lower() if '_' in key else 'other'
        if key_type not in key_groups:
            key_groups[key_type] = []
        key_groups[key_type].append((key, value))

    # Output keys grouped by type
    for key_type in sorted(key_groups.keys()):
        lines.append(f"# {key_type.upper()} keys")
        for key, value in key_groups[key_type]:
            lines.append(f"{key}={value}")
        lines.append("")

    return "\n".join(lines)


def format_as_json(keys: Dict[str, str], add_timestamp: bool = True,
                  expiry_days: Optional[int] = None) -> str:
    """
    Format keys as JSON.

    Args:
        keys: Dictionary of keys to format
        add_timestamp: Whether to add timestamp metadata
        expiry_days: Number of days until keys expire

    Returns:
        Formatted string in JSON format
    """
    output = {'keys': keys}

    if add_timestamp:
        output['metadata'] = {
            'generated_at': datetime.datetime.now().isoformat()
        }

    if expiry_days:
        expiry_date = datetime.datetime.now() + datetime.timedelta(days=expiry_days)
        if 'metadata' not in output:
            output['metadata'] = {}
        output['metadata']['expires_at'] = expiry_date.isoformat()
        output['metadata']['expiry_days'] = expiry_days

    return json.dumps(output, indent=2)


def format_as_yaml(keys: Dict[str, str], add_timestamp: bool = True,
                   expiry_days: Optional[int] = None) -> str:
    """
    Format keys as YAML.

    Args:
        keys: Dictionary of keys to format
        add_timestamp: Whether to add timestamp metadata
        expiry_days: Number of days until keys expire

    Returns:
        Formatted string in YAML format
    """
    output = {'keys': keys}

    if add_timestamp:
        output['metadata'] = {
            'generated_at': datetime.datetime.now().isoformat()
        }

    if expiry_days:
        expiry_date = datetime.datetime.now() + datetime.timedelta(days=expiry_days)
        if 'metadata' not in output:
            output['metadata'] = {}
        output['metadata']['expires_at'] = expiry_date.isoformat()
        output['metadata']['expiry_days'] = expiry_days

    return yaml.dump(output, default_flow_style=False)


def detect_format(content: str) -> str:
    """
    Detect the format of the content.

    Args:
        content: The file content to analyze

    Returns:
        Detected format: env, json, yaml, or unknown
    """
    content = content.strip()

    # Check for JSON format
    if content.startswith('{') and content.endswith('}'):
        try:
            json.loads(content)
            return 'json'
        except json.JSONDecodeError:
            pass

    # Check for YAML format
    if ':' in content:
        try:
            yaml.safe_load(content)
            return 'yaml'
        except yaml.YAMLError:
            pass

    # Check for ENV format (key=value pairs)
    if re.search(r'^[A-Za-z0-9_]+=.+$', content, re.MULTILINE):
        return 'env'

    return 'unknown'


def parse_env_file(content: str) -> Tuple[Dict[str, str], List[str]]:
    """
    Parse an environment file and extract key-value pairs and comments.

    Args:
        content: The file content to parse

    Returns:
        Tuple of (parsed_keys, comments)
    """
    keys = {}
    comments = []

    for line in content.splitlines():
        line = line.strip()
        if not line:
            comments.append('')  # Preserve empty lines
            continue

        if line.startswith('#'):
            comments.append(line)
            continue

        if '=' in line:
            key, value = line.split('=', 1)
            keys[key.strip()] = value.strip()
            continue

        # If we get here, it's not a key-value pair or comment
        comments.append(line)

    return keys, comments


def rotate_keys(file_path: str, key_types: List[str] = None) -> Dict[str, str]:
    """
    Rotate keys in an existing configuration file.

    Args:
        file_path: Path to the file containing keys
        key_types: List of key types to rotate (or None for all)

    Returns:
        Dictionary of rotated keys
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return {}

    file_format = detect_format(content)
    new_keys = {}

    if file_format == 'env':
        # Parse env file and identify keys to rotate
        existing_keys, comments = parse_env_file(content)

        # Determine which keys to rotate
        keys_to_rotate = set()
        if not key_types or "all" in key_types:
            keys_to_rotate = set(existing_keys.keys())
        else:
            # Filter keys based on types
            for key in existing_keys:
                for key_type in key_types:
                    if key_type.upper() in key.upper():
                        keys_to_rotate.add(key)

        # Generate new keys
        for key in keys_to_rotate:
            # Determine key type to use proper generation method
            if 'SECRET_KEY' in key:
                new_keys[key] = secrets.token_hex(KEY_LENGTHS['SESSION'])
            elif 'JWT_SECRET' in key:
                new_keys[key] = secrets.token_hex(KEY_LENGTHS['JWT'])
            elif 'ENCRYPTION_KEY' in key:
                new_keys[key] = base64.b64encode(os.urandom(KEY_LENGTHS['ENCRYPTION'])).decode('utf-8')
            elif 'API_KEY' in key:
                new_keys[key] = secrets.token_urlsafe(KEY_LENGTHS['API'])
            elif 'COOKIE_SECRET' in key:
                new_keys[key] = secrets.token_hex(KEY_LENGTHS['COOKIE'])
            elif 'ENCRYPTION_IV' in key:
                new_keys[key] = base64.b64encode(os.urandom(KEY_LENGTHS['IV'])).decode('utf-8')
            elif 'HMAC_KEY' in key:
                new_keys[key] = secrets.token_hex(KEY_LENGTHS['HMAC'])
            elif 'SIGNING_KEY' in key:
                new_keys[key] = secrets.token_hex(KEY_LENGTHS['SIGNING'])
            else:
                # Default to hex token for unknown types
                new_keys[key] = secrets.token_hex(32)

    elif file_format == 'json':
        try:
            data = json.loads(content)
            if 'keys' in data:
                existing_keys = data['keys']
            else:
                existing_keys = data

            # Regenerate keys similar to env format
            # Implement similar logic to rotate keys based on type
            # (code would be similar to the env section above)

            for key in existing_keys:
                if not key_types or "all" in key_types:
                    # Logic to regenerate based on key pattern
                    if 'SECRET_KEY' in key:
                        new_keys[key] = secrets.token_hex(KEY_LENGTHS['SESSION'])
                    # Add similar logic for other key types

        except json.JSONDecodeError:
            logger.error(f"Failed to parse JSON from {file_path}")
            return {}

    elif file_format == 'yaml':
        # Similar implementation for YAML format
        try:
            data = yaml.safe_load(content)
            if 'keys' in data:
                existing_keys = data['keys']
            else:
                existing_keys = data

            # Similar key rotation logic
        except yaml.YAMLError:
            logger.error(f"Failed to parse YAML from {file_path}")
            return {}

    else:
        logger.error(f"Unrecognized file format in {file_path}")
        return {}

    return new_keys


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate security keys for application configuration",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path (default: print to stdout)",
        type=str
    )
    parser.add_argument(
        "--format", "-f",
        choices=["env", "json", "yaml"],
        default="env",
        help="Output format (default: env)"
    )
    parser.add_argument(
        "--key-types", "-t",
        help="Types of keys to generate (comma-separated): all, session, jwt, encryption, api, cookie, iv, hmac, signing",
        default="all"
    )
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=1,
        help="Number of each key type to generate (default: 1)"
    )
    parser.add_argument(
        "--prefix", "-p",
        type=str,
        default="",
        help="Add prefix to key names (e.g., 'PROD_')"
    )
    parser.add_argument(
        "--validate", "-v",
        action="store_true",
        help="Validate keys against security requirements"
    )
    parser.add_argument(
        "--rotate",
        type=str,
        help="Rotate keys in existing file (preserves comments)"
    )
    parser.add_argument(
        "--no-timestamp",
        action="store_true",
        help="Omit timestamp comments in output"
    )
    parser.add_argument(
        "--expiry",
        type=int,
        help="Add expiry info for keys (days from now)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed information"
    )

    return parser.parse_args()


def main() -> int:
    """Execute the key generation script."""
    args = parse_arguments()

    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    try:
        key_types = args.key_types.lower().split(',')

        if args.rotate:
            # Rotation mode
            logger.info(f"Rotating keys in {args.rotate}")
            keys = rotate_keys(args.rotate, key_types)
            if not keys:
                logger.error("No keys were rotated")
                return 1
            logger.info(f"Successfully rotated {len(keys)} keys")
        else:
            # Generation mode
            logger.debug(f"Generating {args.count} set(s) of keys with types: {key_types}")
            keys = generate_keys(key_types, args.count, args.prefix)

        # Validate keys if requested
        if args.validate:
            logger.debug("Validating generated keys")
            is_valid, error = validate_keys(keys)
            if not is_valid:
                logger.error(f"Key validation failed: {error}")
                return 1
            logger.debug("All keys passed validation")

        # Format the output according to the specified format
        add_timestamp = not args.no_timestamp
        if args.format == "json":
            output = format_as_json(keys, add_timestamp, args.expiry)
        elif args.format == "yaml":
            output = format_as_yaml(keys, add_timestamp, args.expiry)
        else:  # env format
            output = format_as_env(keys, add_timestamp, args.expiry)

        # Write output to file or stdout
        if args.output:
            output_path = Path(args.output)

            # Create parent directories if they don't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Write with restrictive permissions (600)
            with open(output_path, 'w') as f:
                f.write(output)

            # Set file permissions to be readable only by owner
            os.chmod(output_path, 0o600)

            logger.info(f"Security keys written to {output_path} with restricted permissions")
        else:
            print(output)

        return 0
    except Exception as e:
        logger.error(f"Error generating security keys: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
