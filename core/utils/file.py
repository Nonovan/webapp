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
import re
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


def read_file(file_path: str, encoding: str = "utf-8") -> str:
    """
    Securely read a file with proper error handling.

    Args:
        file_path: Path to the file to read
        encoding: File encoding (default: utf-8)

    Returns:
        String content of the file

    Raises:
        IOError: If the file cannot be read
        UnicodeDecodeError: If the file cannot be decoded with specified encoding
    """
    if not is_path_safe(file_path):
        raise ValueError(f"Unsafe file path: {file_path}")

    try:
        with open(file_path, 'r', encoding=encoding) as file:
            return file.read()
    except UnicodeDecodeError:
        # Try again with error handling for problematic characters
        with open(file_path, 'r', encoding=encoding, errors='replace') as file:
            return file.read()


def write_file(file_path: str, content: str, encoding: str = "utf-8",
               make_dirs: bool = True, atomic: bool = True) -> None:
    """
    Securely write content to a file with proper error handling.

    Args:
        file_path: Path to the file to write
        content: Content to write to the file
        encoding: File encoding (default: utf-8)
        make_dirs: Create parent directories if they don't exist
        atomic: Use atomic write operation to prevent corruption

    Raises:
        IOError: If the file cannot be written
        OSError: If directories cannot be created
    """
    if not is_path_safe(file_path):
        raise ValueError(f"Unsafe file path: {file_path}")

    # Create parent directories if needed
    if make_dirs:
        ensure_directory_exists(os.path.dirname(file_path))

    if atomic:
        # Use atomic write operation
        import tempfile
        temp_fd, temp_path = tempfile.mkstemp(
            dir=os.path.dirname(os.path.abspath(file_path))
        )
        try:
            with os.fdopen(temp_fd, 'w', encoding=encoding) as temp_file:
                temp_file.write(content)

            # Ensure proper permissions before moving
            if os.path.exists(file_path):
                # Try to preserve permissions from existing file
                try:
                    current_mode = os.stat(file_path).st_mode
                    os.chmod(temp_path, current_mode)
                except OSError:
                    pass

            # Atomic move/replace
            os.replace(temp_path, file_path)
        except Exception:
            # Clean up temp file on error
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise
    else:
        # Direct write
        with open(file_path, 'w', encoding=encoding) as file:
            file.write(content)


def append_to_file(file_path: str, content: str, encoding: str = "utf-8",
                  make_dirs: bool = True) -> None:
    """
    Securely append content to a file with proper error handling.

    Args:
        file_path: Path to the file to append to
        content: Content to append to the file
        encoding: File encoding (default: utf-8)
        make_dirs: Create parent directories if they don't exist

    Raises:
        IOError: If the file cannot be written
        OSError: If directories cannot be created
    """
    if not is_path_safe(file_path):
        raise ValueError(f"Unsafe file path: {file_path}")

    # Create parent directories if needed
    if make_dirs:
        ensure_directory_exists(os.path.dirname(file_path))

    with open(file_path, 'a', encoding=encoding) as file:
        file.write(content)


def ensure_directory_exists(directory_path: str, mode: int = 0o755) -> None:
    """
    Create a directory if it doesn't exist, including parent directories.

    Args:
        directory_path: Path of the directory to create
        mode: Permissions for the newly created directory

    Raises:
        OSError: If the directory cannot be created or modified
    """
    # Handle empty path
    if not directory_path:
        return

    if not is_path_safe(directory_path):
        raise ValueError(f"Unsafe directory path: {directory_path}")

    # No need to do anything if the directory already exists
    if os.path.isdir(directory_path):
        return

    try:
        os.makedirs(directory_path, mode=mode, exist_ok=True)
    except OSError as e:
        raise OSError(f"Failed to create directory {directory_path}: {str(e)}")


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal and other security issues.

    This function ensures filenames are safe for file operations by removing
    path components and replacing potentially dangerous characters.

    Args:
        filename: The filename to sanitize

    Returns:
        Sanitized filename string

    Example:
        >>> sanitize_filename("../etc/passwd")
        "passwd"
        >>> sanitize_filename("file<with>bad:chars?.txt")
        "file_with_bad_chars_.txt"
    """
    if not filename:
        return "unnamed_file"

    # Remove directory traversal components and limit to basename
    sanitized = os.path.basename(filename)

    # Remove null bytes and control characters
    sanitized = re.sub(r'[\x00-\x1f]', '', sanitized)

    # Replace potentially dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', sanitized)

    # Ensure the filename is not empty after sanitization
    if not sanitized:
        sanitized = "unnamed_file"

    # Limit length for safety (prevent extremely long filenames)
    if len(sanitized) > 255:
        # Preserve extension if present
        parts = sanitized.rsplit('.', 1)
        if len(parts) > 1:
            sanitized = parts[0][:250] + '.' + parts[1]
        else:
            sanitized = sanitized[:255]

    return sanitized


def read_json_file(file_path: str, default: Any = None) -> Dict[str, Any]:
    """
    Safely read and parse a JSON file with proper error handling.

    Args:
        file_path: Path to the JSON file
        default: Default value to return if the file doesn't exist or can't be parsed

    Returns:
        Parsed JSON data as dictionary or the default value on error

    Example:
        >>> config = read_json_file("/path/to/config.json", default={})
        >>> print(config.get("setting", "default_value"))
    """
    if not os.path.isfile(file_path):
        if default is not None:
            return default
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except json.JSONDecodeError as e:
        if default is not None:
            return default
        raise ValueError(f"Invalid JSON in {file_path}: {e}")
    except Exception as e:
        if default is not None:
            return default
        raise IOError(f"Error reading {file_path}: {e}")


def read_yaml_file(file_path: str, default: Any = None) -> Dict[str, Any]:
    """
    Safely read and parse a YAML file with proper error handling.

    Args:
        file_path: Path to the YAML file
        default: Default value to return if the file doesn't exist or can't be parsed

    Returns:
        Parsed YAML data as dictionary or the default value on error

    Example:
        >>> config = read_yaml_file("/path/to/config.yaml", default={})
        >>> print(config.get("setting", "default_value"))
    """
    if not os.path.isfile(file_path):
        if default is not None:
            return default
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file) or {}
    except yaml.YAMLError as e:
        if default is not None:
            return default
        raise ValueError(f"Invalid YAML in {file_path}: {e}")
    except Exception as e:
        if default is not None:
            return default
        raise IOError(f"Error reading {file_path}: {e}")


def get_critical_file_hashes(files: List[str], algorithm: str = DEFAULT_HASH_ALGORITHM) -> Dict[str, str]:
    """
    Generate hash dictionary for critical application files.

    Used to create reference hashes for integrity checking and monitoring
    of critical system files.

    Args:
        files: List of file paths to hash
        algorithm: Hash algorithm to use (default: sha256)

    Returns:
        Dictionary mapping file paths to their hash values

    Example:
        >>> critical_files = ['/path/to/app.py', '/path/to/config.py']
        >>> hashes = get_critical_file_hashes(critical_files)
        >>> print(f"Config hash: {hashes['/path/to/config.py']}")
    """
    hashes = {}
    errors = []

    for file_path in files:
        # Normalize the path for consistency
        normalized_path = os.path.normpath(file_path)

        if not os.path.exists(normalized_path):
            print(f"Warning: File not found for hashing: {normalized_path}")
            errors.append(f"File not found: {normalized_path}")
            continue

        try:
            file_hash = compute_file_hash(normalized_path, algorithm)
            hashes[normalized_path] = file_hash
        except (IOError, ValueError, PermissionError) as e:
            error_msg = f"Failed to hash {normalized_path}: {str(e)}"
            print(f"Error: {error_msg}")
            errors.append(error_msg)
            hashes[normalized_path] = None

    # Log a summary if there were errors
    if errors and len(errors) > 0:
        print(f"Completed file hash generation with {len(errors)} errors")

    return hashes
