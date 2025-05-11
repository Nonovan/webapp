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
import logging
import base64
import shutil
import json
import time
import pwd
import yaml
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, BinaryIO, TextIO, Iterator
from contextlib import contextmanager

# Import required security functions
from core.security.cs_crypto import compute_hash as compute_file_hash
from core.utils.logging_utils import log_error, log_warning

# Import centralized constants
from core.utils.core_utils_constants import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_FILE_PERMS,
    DEFAULT_DIR_PERMS,
    SECURE_FILE_PERMS,
    SECURE_DIR_PERMS,
    TEMP_DIR_PERMS,
    SMALL_FILE_THRESHOLD,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_HASH_ALGORITHM,
    SENSITIVE_FIELDS,
    MAX_FILENAME_LENGTH
)

# Type definitions
FileMetadata = Dict[str, Any]
ResourceMetrics = Dict[str, Any]
FileChangeInfo = Dict[str, Any]

# Module-specific constants
SUSPICIOUS_PATTERNS = ['backdoor', 'hack', 'exploit', 'rootkit', 'trojan', 'payload', 'malware']
SENSITIVE_EXTENSIONS = ['.key', '.pem', '.p12', '.pfx', '.keystore', '.jks', '.env', '.secret']
SECURE_TEMP_DIR_PERMISSIONS = TEMP_DIR_PERMS
SECURE_TEMP_FILE_PERMISSIONS = SECURE_FILE_PERMS

# Setup module-level logger
logger = logging.getLogger(__name__)


def get_file_metadata(file_path: str) -> FileMetadata:
    """
    Get metadata about a file for security and integrity checks.

    This function collects detailed metadata about a file that can be used
    for security analysis, integrity monitoring, and compliance purposes.
    Particularly useful for ICS and critical infrastructure files.

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
        - plus additional security-relevant attributes

    Raises:
        FileNotFoundError: If the specified file does not exist
        IOError: If the file cannot be read
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    stat_info = os.stat(file_path)

    # Get absolute and normalized path
    abs_path = os.path.abspath(file_path)
    normalized_path = os.path.normpath(abs_path)

    try:
        # Get owner name (Unix-specific)
        owner = pwd.getpwuid(stat_info.st_uid).pw_name
    except (KeyError, ImportError, AttributeError):
        # Fallback for Windows or if user lookup fails
        owner = str(stat_info.st_uid)

    try:
        # Generate hash for content verification
        file_hash = compute_file_hash(file_path, algorithm=DEFAULT_HASH_ALGORITHM)
    except IOError as e:
        log_error(f"Failed to hash file {file_path}: {str(e)}")
        file_hash = None

    try:
        # Get file type using file command if available
        file_type = None
        if os.path.exists('/usr/bin/file'):
            import subprocess
            result = subprocess.run(
                ['/usr/bin/file', '-b', file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2,
                check=False,
                text=True  # Handle text decoding within subprocess
            )
            if result.returncode == 0:
                file_type = result.stdout.strip()
    except (subprocess.SubprocessError, OSError) as e:
        logger.debug(f"Could not determine file type for {file_path}: {str(e)}")
        file_type = None

    # Extract filename and extension
    basename = os.path.basename(file_path)
    filename, extension = os.path.splitext(basename)
    if extension:
        # Remove the dot from extension
        extension = extension[1:]

    # Check for suspicious content in filename
    is_suspicious = any(pattern in basename.lower() for pattern in SUSPICIOUS_PATTERNS)
    is_sensitive = any(file_path.endswith(ext) for ext in SENSITIVE_EXTENSIONS)

    metadata = {
        'path': abs_path,
        'normalized_path': normalized_path,
        'filename': basename,
        'extension': extension,
        'size': stat_info.st_size,
        'size_kb': round(stat_info.st_size / 1024, 2),
        'created_at': datetime.fromtimestamp(stat_info.st_ctime, tz=timezone.utc),
        'modified_at': datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc),
        'accessed_at': datetime.fromtimestamp(stat_info.st_atime, tz=timezone.utc),
        'owner': owner,
        'permissions': oct(stat_info.st_mode & 0o777),
        'is_executable': bool(stat_info.st_mode & stat.S_IXUSR),
        'is_world_writable': bool(stat_info.st_mode & stat.S_IWOTH),
        'is_world_readable': bool(stat_info.st_mode & stat.S_IROTH),
        'is_setuid': bool(stat_info.st_mode & stat.S_ISUID),
        'is_setgid': bool(stat_info.st_mode & stat.S_ISGID),
        'is_hidden': basename.startswith('.'),
        'is_suspicious': is_suspicious,
        'is_sensitive': is_sensitive,
        'hash': file_hash,
        'file_type': file_type
    }

    return metadata


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
            if os.path.exists(path):
                os.remove(path)
        except OSError as e:
            logger.warning(f"Failed to remove temporary file {path}: {str(e)}")


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
            if os.path.exists(path):
                shutil.rmtree(path)
        except OSError as e:
            logger.warning(f"Failed to remove temporary directory {path}: {str(e)}")


def is_path_safe(path: str, allowed_base_dirs: Optional[List[str]] = None) -> bool:
    """
    Check if a path is safe (doesn't use path traversal).

    This function provides a basic path safety check. For more comprehensive
    path safety validation, use the dedicated functions in core.security.cs_utils.

    Args:
        path: Path to validate
        allowed_base_dirs: List of allowed base directories (if None, validates format only)

    Returns:
        True if path is safe, False otherwise
    """
    if not path:
        return False

    try:
        # Special case for empty paths or current directory
        if path.strip() in ('', '.'):
            return True

        # Try to import specialized path safety functions first
        try:
            from core.security.cs_utils import is_within_directory, sanitize_path
            if allowed_base_dirs:
                return any(is_within_directory(path, base_dir) for base_dir in allowed_base_dirs)
            else:
                # If no allowed dirs specified, just check for path traversal
                sanitized = sanitize_path(path)
                return sanitized is not None
        except ImportError:
            # Fallback to basic implementation
            pass

        # Normalize path
        normalized_path = os.path.normpath(path)

        # Check for path traversal attempts
        if '..' in normalized_path.split(os.sep):
            return False

        # Check for absolute paths against allowed base directories
        if os.path.isabs(normalized_path) and allowed_base_dirs is not None:
            return any(normalized_path.startswith(os.path.normpath(base_dir))
                      for base_dir in allowed_base_dirs)

        return True
    except Exception as e:
        logger.warning(f"Path safety check failed for '{path}': {str(e)}")
        return False


def read_file(file_path: str, encoding: str = "utf-8", max_size: int = DEFAULT_MAX_FILE_SIZE) -> str:
    """
    Securely read a file with proper error handling.

    Args:
        file_path: Path to the file to read
        encoding: File encoding (default: utf-8)
        max_size: Maximum file size to read (default: from constants)

    Returns:
        String content of the file

    Raises:
        IOError: If the file cannot be read
        UnicodeDecodeError: If the file cannot be decoded with specified encoding
        ValueError: If the file path is unsafe or file exceeds max size
    """
    if not is_path_safe(file_path):
        raise ValueError(f"Unsafe file path: {file_path}")

    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    # Check file size to prevent loading very large files into memory
    file_size = os.path.getsize(file_path)
    if file_size > max_size:
        raise ValueError(f"File too large: {file_size} bytes (max: {max_size} bytes)")

    try:
        with open(file_path, 'r', encoding=encoding) as file:
            return file.read()
    except UnicodeDecodeError:
        # Try again with error handling for problematic characters
        with open(file_path, 'r', encoding=encoding, errors='replace') as file:
            content = file.read()
            logger.warning(f"File {file_path} contained invalid characters for {encoding} encoding")
            return content
    except OSError as e:
        raise IOError(f"Error reading file {file_path}: {str(e)}")


def write_file(file_path: str, content: str, encoding: str = "utf-8",
               make_dirs: bool = True, atomic: bool = True,
               mode: int = DEFAULT_FILE_PERMS) -> None:
    """
    Securely write content to a file with proper error handling.

    Args:
        file_path: Path to the file to write
        content: Content to write to the file
        encoding: File encoding (default: utf-8)
        make_dirs: Create parent directories if they don't exist
        atomic: Use atomic write operation to prevent corruption
        mode: File permission mode (default: from constants)

    Raises:
        IOError: If the file cannot be written
        OSError: If directories cannot be created
        ValueError: If file path is unsafe
    """
    if not is_path_safe(file_path):
        raise ValueError(f"Unsafe file path: {file_path}")

    # Create parent directories if needed
    if make_dirs:
        directory = os.path.dirname(file_path)
        if directory:
            ensure_directory_exists(directory)

    if atomic:
        # Use atomic write operation
        directory = os.path.dirname(os.path.abspath(file_path))
        temp_fd, temp_path = tempfile.mkstemp(dir=directory)
        try:
            with os.fdopen(temp_fd, 'w', encoding=encoding) as temp_file:
                temp_file.write(content)

            # Ensure proper permissions
            try:
                # Preserve permissions from existing file if any
                if os.path.exists(file_path):
                    current_mode = os.stat(file_path).st_mode
                    os.chmod(temp_path, current_mode)
                else:
                    os.chmod(temp_path, mode)
            except OSError as e:
                logger.warning(f"Could not set permissions on {temp_path}: {str(e)}")

            # Atomic move/replace
            os.replace(temp_path, file_path)
        except Exception as e:
            # Clean up temp file on error
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            except OSError:
                pass
            raise IOError(f"Error writing to {file_path}: {str(e)}")
    else:
        # Direct write
        try:
            with open(file_path, 'w', encoding=encoding) as file:
                file.write(content)

            # Set permissions
            try:
                os.chmod(file_path, mode)
            except OSError as e:
                logger.warning(f"Could not set permissions on {file_path}: {str(e)}")
        except OSError as e:
            raise IOError(f"Error writing to {file_path}: {str(e)}")


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
        ValueError: If file path is unsafe
    """
    if not is_path_safe(file_path):
        raise ValueError(f"Unsafe file path: {file_path}")

    # Create parent directories if needed
    if make_dirs:
        directory = os.path.dirname(file_path)
        if directory:
            ensure_directory_exists(directory)

    try:
        with open(file_path, 'a', encoding=encoding) as file:
            file.write(content)
    except OSError as e:
        raise IOError(f"Error appending to {file_path}: {str(e)}")


def ensure_directory_exists(directory_path: str, mode: int = DEFAULT_DIR_PERMS) -> None:
    """
    Create a directory if it doesn't exist, including parent directories.

    Args:
        directory_path: Path of the directory to create
        mode: Permissions for the newly created directory (default: from constants)

    Raises:
        OSError: If the directory cannot be created or modified
        ValueError: If directory path is unsafe
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

    try:
        # Try using specialized security function if available
        try:
            from core.security.cs_utils import sanitize_filename as security_sanitize
            return security_sanitize(filename)
        except ImportError:
            # Fallback to basic implementation
            pass

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
        if len(sanitized) > MAX_FILENAME_LENGTH:
            # Preserve extension if present
            parts = sanitized.rsplit('.', 1)
            if len(parts) > 1:
                max_base = MAX_FILENAME_LENGTH - len(parts[1]) - 1  # -1 for the dot
                sanitized = parts[0][:max_base] + '.' + parts[1]
            else:
                sanitized = sanitized[:MAX_FILENAME_LENGTH]

        return sanitized
    except Exception as e:
        logger.warning(f"Error sanitizing filename '{filename}': {str(e)}")
        # Return a safe default if all else fails
        return "unnamed_file"


def save_json_file(file_path: str, data: Dict[str, Any], indent: int = 2,
                  atomic: bool = True, mode: int = DEFAULT_FILE_PERMS) -> None:
    """
    Save data as JSON to file atomically.

    Args:
        file_path: Path where to save the file
        data: Data to save
        indent: JSON indentation level
        atomic: Use atomic write operation to prevent corruption
        mode: File permission mode

    Raises:
        IOError: If file cannot be written
        ValueError: If file path is unsafe
    """
    if not is_path_safe(file_path):
        raise ValueError(f"Unsafe file path: {file_path}")

    # Create directory if it doesn't exist
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        ensure_directory_exists(directory)

    if atomic:
        # Write to temporary file first (atomic operation)
        temp_fd, temp_path = tempfile.mkstemp(
            dir=os.path.dirname(os.path.abspath(file_path))
        )
        try:
            with os.fdopen(temp_fd, 'w', encoding='utf-8') as temp_file:
                json.dump(data, temp_file, indent=indent)

            # Set permissions
            try:
                os.chmod(temp_path, mode)
            except OSError as e:
                logger.warning(f"Failed to set permissions on {temp_path}: {str(e)}")

            # Replace the original file with the temporary one
            os.replace(temp_path, file_path)
        except Exception as e:
            # Clean up temp file on error
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            except OSError:
                pass
            raise IOError(f"Failed to write JSON file {file_path}: {str(e)}")
    else:
        # Direct write
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=indent)

            # Set permissions
            try:
                os.chmod(file_path, mode)
            except OSError as e:
                logger.warning(f"Failed to set permissions on {file_path}: {str(e)}")
        except OSError as e:
            raise IOError(f"Failed to write JSON file {file_path}: {str(e)}")


def save_yaml_file(file_path: str, data: Dict[str, Any], default_flow_style: bool = False,
                  atomic: bool = True, mode: int = DEFAULT_FILE_PERMS) -> None:
    """
    Save data as YAML to file atomically.

    Args:
        file_path: Path where to save the file
        data: Data to save
        default_flow_style: YAML flow style option
        atomic: Use atomic write operation to prevent corruption
        mode: File permission mode (default: from constants)

    Raises:
        IOError: If file cannot be written
        ValueError: If file path is unsafe
    """
    if not is_path_safe(file_path):
        raise ValueError(f"Unsafe file path: {file_path}")

    # Create directory if it doesn't exist
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        ensure_directory_exists(directory)

    if atomic:
        # Write to temporary file first (atomic operation)
        temp_fd, temp_path = tempfile.mkstemp(
            dir=os.path.dirname(os.path.abspath(file_path))
        )
        try:
            with os.fdopen(temp_fd, 'w', encoding='utf-8') as temp_file:
                yaml.safe_dump(data, temp_file, default_flow_style=default_flow_style)

            # Set permissions
            try:
                os.chmod(temp_path, mode)
            except OSError as e:
                logger.warning(f"Failed to set permissions on {temp_path}: {str(e)}")

            # Replace the original file with the temporary one
            os.replace(temp_path, file_path)
        except Exception as e:
            # Clean up temp file on error
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            except OSError:
                pass
            raise IOError(f"Failed to write YAML file {file_path}: {str(e)}")
    else:
        # Direct write
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                yaml.safe_dump(data, f, default_flow_style=default_flow_style)

            # Set permissions
            try:
                os.chmod(file_path, mode)
            except OSError as e:
                logger.warning(f"Failed to set permissions on {file_path}: {str(e)}")
        except OSError as e:
            raise IOError(f"Failed to write YAML file {file_path}: {str(e)}")


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
    if not is_path_safe(file_path):
        if default is not None:
            logger.warning(f"Unsafe file path provided to read_json_file: {file_path}")
            return default
        raise ValueError(f"Unsafe file path: {file_path}")

    if not os.path.isfile(file_path):
        if default is not None:
            return default
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except json.JSONDecodeError as e:
        if default is not None:
            logger.warning(f"Invalid JSON in {file_path}: {str(e)}")
            return default
        raise ValueError(f"Invalid JSON in {file_path}: {str(e)}")
    except OSError as e:
        if default is not None:
            logger.warning(f"Error reading {file_path}: {str(e)}")
            return default
        raise IOError(f"Error reading {file_path}: {str(e)}")


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
    if not is_path_safe(file_path):
        if default is not None:
            logger.warning(f"Unsafe file path provided to read_yaml_file: {file_path}")
            return default
        raise ValueError(f"Unsafe file path: {file_path}")

    if not os.path.isfile(file_path):
        if default is not None:
            return default
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = yaml.safe_load(file)
            return data if data is not None else {}
    except yaml.YAMLError as e:
        if default is not None:
            logger.warning(f"Invalid YAML in {file_path}: {str(e)}")
            return default
        raise ValueError(f"Invalid YAML in {file_path}: {str(e)}")
    except OSError as e:
        if default is not None:
            logger.warning(f"Error reading {file_path}: {str(e)}")
            return default
        raise IOError(f"Error reading {file_path}: {str(e)}")


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
        ValueError: If directory path is unsafe
    """
    if not is_path_safe(directory):
        raise ValueError(f"Unsafe directory path: {directory}")

    if not os.path.isdir(directory):
        raise FileNotFoundError(f"Directory not found: {directory}")

    exclude_patterns = exclude_patterns or []
    matched_files = []

    try:
        for pattern in patterns:
            if recursive:
                glob_pattern = f"**/{pattern}"
                matches = Path(directory).glob(glob_pattern)
            else:
                glob_pattern = pattern
                matches = Path(directory).glob(glob_pattern)

            matched_files.extend(str(p) for p in matches if p.is_file())

        # Apply exclusions
        if exclude_patterns:
            excluded_files = set()
            for exclude_pattern in exclude_patterns:
                if recursive:
                    exclude_glob = f"**/{exclude_pattern}"
                    matches = Path(directory).glob(exclude_glob)
                else:
                    exclude_glob = exclude_pattern
                    matches = Path(directory).glob(exclude_glob)

                excluded_files.update(str(p) for p in matches if p.is_file())

            matched_files = [f for f in matched_files if f not in excluded_files]

        return sorted(matched_files)
    except Exception as e:
        raise IOError(f"Error finding files in {directory}: {str(e)}")


def get_critical_file_hashes(files: List[str], algorithm: str = DEFAULT_HASH_ALGORITHM) -> Dict[str, str]:
    """
    Generate hash dictionary for critical application files.

    Used to create reference hashes for integrity checking and monitoring
    of critical system files.

    Args:
        files: List of file paths to hash
        algorithm: Hash algorithm to use (default: from constants)

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
            log_warning(f"File not found for hashing: {normalized_path}")
            errors.append(f"File not found: {normalized_path}")
            continue

        try:
            file_hash = compute_file_hash(normalized_path, algorithm)
            hashes[normalized_path] = file_hash
        except (IOError, ValueError, PermissionError) as e:
            error_msg = f"Failed to hash {normalized_path}: {str(e)}"
            log_warning(error_msg)
            errors.append(error_msg)
            hashes[normalized_path] = None

    # Log a summary if there were errors
    if errors:
        log_warning(f"Completed file hash generation with {len(errors)} errors")

    return hashes


# Define what should be exported from this module
__all__ = [
    # File metadata and verification
    'get_file_metadata',
    'get_critical_file_hashes',

    # File reading and writing
    'read_file',
    'write_file',
    'append_to_file',

    # Directory operations
    'ensure_directory_exists',
    'find_files',

    # Security and safety
    'sanitize_filename',
    'is_path_safe',

    # Temporary file operations
    'secure_tempfile',
    'secure_tempdir',

    # Structured file formats
    'read_json_file',
    'save_json_file',
    'read_yaml_file',
    'save_yaml_file',
]
