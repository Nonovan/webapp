"""
File utility functions for Cloud Infrastructure Platform.

This module provides standardized file handling operations including:
- Secure file operations
- Path manipulation and validation
- File integrity verification
- File format conversion
- Temporary file handling

These utilities ensure consistent and secure file operations across the application.
"""

import os
import tempfile
import hashlib
import base64
import shutil
import json
import yaml
import pwd
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, BinaryIO, TextIO, Iterator
from contextlib import contextmanager
from datetime import datetime

# Constants
DEFAULT_CHUNK_SIZE = 8192  # 8KB chunks for file reading
DEFAULT_HASH_ALGORITHM = 'sha256'
SECURE_TEMP_DIR_PERMISSIONS = 0o700
SECURE_TEMP_FILE_PERMISSIONS = 0o600


def generate_sri_hash(file_path: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
    """
    Generate a Subresource Integrity hash for a file.

    Creates a base64-encoded hash suitable for use in SRI attributes
    in HTML to verify resource integrity.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use

    Returns:
        SRI hash string in the format "{algorithm}-{hash}"

    Raises:
        FileNotFoundError: If the specified file does not exist
        IOError: If the file cannot be read
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    hasher = hashlib.new(algorithm)

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(DEFAULT_CHUNK_SIZE), b''):
            hasher.update(chunk)

    hash_value = base64.b64encode(hasher.digest()).decode('utf-8')
    return f"{algorithm}-{hash_value}"


def compute_file_hash(file_path: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
    """
    Compute hash for a file using specified algorithm.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use

    Returns:
        Hex digest of file hash

    Raises:
        FileNotFoundError: If the specified file doesn't exist
        ValueError: If the algorithm is not supported
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        hasher = hashlib.new(algorithm)
    except ValueError:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(DEFAULT_CHUNK_SIZE), b''):
            hasher.update(chunk)

    return hasher.hexdigest()


@contextmanager
def secure_tempfile(prefix: str = "secure_", suffix: str = "") -> Iterator[str]:
    """
    Context manager for creating and automatically removing temporary files with secure permissions.

    Args:
        prefix: Prefix for the temporary file name
        suffix: Suffix for the temporary file name

    Yields:
        Path to the temporary file

    Example:
        with secure_tempfile() as tmp_path:
            # Use the temporary file
            with open(tmp_path, 'w') as f:
                f.write("sensitive data")
    """
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    try:
        os.close(fd)
        os.chmod(path, SECURE_TEMP_FILE_PERMISSIONS)
        yield path
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


@contextmanager
def secure_tempdir(prefix: str = "secure_") -> Iterator[str]:
    """
    Context manager for creating and automatically removing temporary directories with secure permissions.

    Args:
        prefix: Prefix for the temporary directory name

    Yields:
        Path to the temporary directory
    """
    path = tempfile.mkdtemp(prefix=prefix)
    try:
        os.chmod(path, SECURE_TEMP_DIR_PERMISSIONS)
        yield path
    finally:
        try:
            shutil.rmtree(path)
        except OSError:
            pass


def is_path_safe(path: str, allowed_base_dirs: Optional[List[str]] = None) -> bool:
    """
    Check if a path is safe (doesn't use path traversal).

    Args:
        path: Path to validate
        allowed_base_dirs: List of allowed base directories (if None, validates format only)

    Returns:
        True if path is safe, False otherwise
    """
    # Normalize path
    normalized_path = os.path.normpath(path)

    # Check for path traversal attempts
    if '..' in normalized_path.split(os.sep):
        return False

    # Check for absolute paths if relative is expected
    if os.path.isabs(normalized_path) and allowed_base_dirs is not None:
        # If absolute, check if it's within allowed base directories
        return any(normalized_path.startswith(os.path.normpath(base_dir))
                  for base_dir in allowed_base_dirs)

    return True


def load_json_file(file_path: str) -> Dict[str, Any]:
    """
    Load and parse JSON from file.

    Args:
        file_path: Path to the JSON file

    Returns:
        Parsed JSON data

    Raises:
        FileNotFoundError: If file does not exist
        json.JSONDecodeError: If JSON is invalid
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json_file(file_path: str, data: Dict[str, Any], indent: int = 2) -> None:
    """
    Save data as JSON to file atomically.

    Args:
        file_path: Path where to save the file
        data: Data to save
        indent: JSON indentation level

    Raises:
        IOError: If file cannot be written
    """
    # Create directory if it doesn't exist
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory)

    # Write to temporary file first (atomic operation)
    temp_file = f"{file_path}.tmp"
    with open(temp_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent)

    # Replace the original file with the temporary one
    os.replace(temp_file, file_path)


def load_yaml_file(file_path: str) -> Dict[str, Any]:
    """
    Load and parse YAML from file.

    Args:
        file_path: Path to the YAML file

    Returns:
        Parsed YAML data

    Raises:
        FileNotFoundError: If file does not exist
        yaml.YAMLError: If YAML is invalid
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def save_yaml_file(file_path: str, data: Dict[str, Any], default_flow_style: bool = False) -> None:
    """
    Save data as YAML to file atomically.

    Args:
        file_path: Path where to save the file
        data: Data to save
        default_flow_style: YAML flow style option

    Raises:
        IOError: If file cannot be written
    """
    # Create directory if it doesn't exist
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory)

    # Write to temporary file first (atomic operation)
    temp_file = f"{file_path}.tmp"
    with open(temp_file, 'w', encoding='utf-8') as f:
        yaml.safe_dump(data, f, default_flow_style=default_flow_style)

    # Replace the original file with the temporary one
    os.replace(temp_file, file_path)


def get_file_metadata(file_path: str) -> Dict[str, Any]:
    """
    Get metadata about a file for security and integrity checks.

    Args:
        file_path: Path to the file to analyze

    Returns:
        Dictionary containing file metadata including:
        - size: File size in bytes
        - created_at: Creation timestamp
        - modified_at: Last modification timestamp
        - accessed_at: Last access timestamp
        - owner: File owner username
        - permissions: File permissions as octal string
        - hash: SHA-256 hash of the file content

    Raises:
        FileNotFoundError: If the specified file does not exist
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    # Get file stats
    file_stats = os.stat(file_path)

    # Try to get owner name
    try:
        owner = pwd.getpwuid(file_stats.st_uid).pw_name
    except (KeyError, AttributeError):
        owner = str(file_stats.st_uid)

    # Compute file hash
    file_hash = compute_file_hash(file_path, DEFAULT_HASH_ALGORITHM)

    return {
        'size': file_stats.st_size,
        'created_at': datetime.fromtimestamp(file_stats.st_ctime).isoformat(),
        'modified_at': datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
        'accessed_at': datetime.fromtimestamp(file_stats.st_atime).isoformat(),
        'owner': owner,
        'permissions': oct(file_stats.st_mode)[-4:],
        'hash': file_hash
    }


def find_files(
    directory: str,
    patterns: List[str] = ["*"],
    recursive: bool = True,
    exclude_patterns: Optional[List[str]] = None
) -> List[str]:
    """
    Find files in a directory matching given patterns.

    Args:
        directory: Base directory to search
        patterns: List of glob patterns to match
        recursive: Whether to search recursively
        exclude_patterns: List of patterns to exclude

    Returns:
        List of file paths that match the patterns

    Raises:
        FileNotFoundError: If the directory doesn't exist
    """
    if not os.path.isdir(directory):
        raise FileNotFoundError(f"Directory not found: {directory}")

    exclude_patterns = exclude_patterns or []
    matched_files = []

    for pattern in patterns:
        glob_pattern = os.path.join(directory, '**', pattern) if recursive else os.path.join(directory, pattern)
        matched_files.extend(str(p) for p in Path(directory).glob(glob_pattern))

    # Apply exclusions
    if exclude_patterns:
        for exclude_pattern in exclude_patterns:
            exclude_glob = os.path.join(directory, '**', exclude_pattern) if recursive else os.path.join(directory, exclude_pattern)
            exclude_files = set(str(p) for p in Path(directory).glob(exclude_glob))
            matched_files = [f for f in matched_files if f not in exclude_files]

    return sorted(matched_files)
