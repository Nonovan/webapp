"""
Forensic File Operations Utilities.

This module provides utility functions for handling files in a forensically sound
manner. It focuses on preserving evidence integrity, maintaining metadata, and
ensuring secure file operations during forensic analysis.

Functions include secure copying, metadata extraction, integrity verification,
and safe file handling practices tailored for the Forensic Analysis Toolkit.
"""

import os
import shutil
import stat
import logging
import time
import json
import re
import io
from datetime import datetime, timezone
from typing import Dict, Optional, Any, List, Union, Tuple, BinaryIO

# Attempt to import forensic-specific logging, crypto, and constants
try:
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
    FORENSIC_LOGGING_AVAILABLE = True
except ImportError:
    logging.warning("Forensic logging utility not found. Using standard logger.")
    FORENSIC_LOGGING_AVAILABLE = False
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict] = None, level: int = logging.INFO):
        log_msg = f"Forensic Operation: {operation}, Success: {success}"
        if details:
            log_msg += f", Details: {details}"
        logging.log(level, log_msg)

try:
    from admin.security.forensics.utils.crypto import calculate_file_hash, verify_file_hash, DEFAULT_HASH_ALGORITHM
    CRYPTO_AVAILABLE = True
except ImportError:
    logging.warning("Forensic crypto utility not found. Hash calculation/verification unavailable.")
    CRYPTO_AVAILABLE = False
    DEFAULT_HASH_ALGORITHM = "sha256"
    def calculate_file_hash(file_path: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> Optional[str]:
        logging.error("calculate_file_hash function is unavailable.")
        return None
    def verify_file_hash(file_path: str, expected_hash: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> bool:
        logging.error("verify_file_hash function is unavailable.")
        return False

try:
    from admin.security.forensics.utils.validation_utils import validate_path
    VALIDATION_AVAILABLE = True
except ImportError:
    logging.warning("Validation utilities not found. Using basic validation.")
    VALIDATION_AVAILABLE = False
    def validate_path(path_str: str, **kwargs) -> Tuple[bool, str]:
        return True, "Path validation unavailable"

try:
    from admin.security.forensics.utils.forensic_constants import (
        DEFAULT_SECURE_FILE_PERMS,
        TEMP_DIR_FORENSICS,
        DEFAULT_READ_ONLY_FILE_PERMS,
        DEFAULT_EVIDENCE_STORAGE_DIR
    )
except ImportError:
    logging.warning("Forensic constants not found. Using default values.")
    DEFAULT_SECURE_FILE_PERMS_FALLBACK = 0o600  # Read/Write for owner only
    DEFAULT_READ_ONLY_FILE_PERMS = 0o400  # Read-only for owner
    TEMP_DIR_FORENSICS_FALLBACK = "/tmp/forensics"  # Example default
    DEFAULT_EVIDENCE_STORAGE_DIR = "/secure/evidence"  # Example default

logger = logging.getLogger(__name__)

# Ensure temporary directory exists with proper permissions
try:
    if not os.path.exists(TEMP_DIR_FORENSICS):
        os.makedirs(TEMP_DIR_FORENSICS, mode=0o700, exist_ok=True)
    else:
        os.chmod(TEMP_DIR_FORENSICS, 0o700)  # Ensure directory permissions are secure if it already exists
except (OSError, PermissionError) as e:
    logger.error(f"Failed to create or secure forensic temp directory: {e}")

# --- File Operation Core Functions ---

def secure_copy(
    source_path: str,
    destination_path: str,
    preserve_metadata: bool = True,
    verify_hash: bool = True,
    hash_algorithm: str = DEFAULT_HASH_ALGORITHM,
    read_only: bool = False
) -> bool:
    """
    Securely copies a file, preserving metadata and verifying integrity.

    Args:
        source_path: Path to the source file.
        destination_path: Path to the destination file.
        preserve_metadata: If True, attempts to preserve timestamps and permissions.
        verify_hash: If True, calculates hashes before and after copy to verify integrity.
        hash_algorithm: Algorithm to use for hash verification.
        read_only: If True, makes the destination file read-only after copying.

    Returns:
        True if the copy was successful and verified (if requested), False otherwise.
    """
    operation_details = {
        "source": source_path,
        "destination": destination_path,
        "preserve_metadata": preserve_metadata,
        "verify_hash": verify_hash,
        "read_only": read_only
    }
    source_hash = None

    try:
        # Validate paths if validation module is available
        if VALIDATION_AVAILABLE:
            is_valid, msg = validate_path(source_path, check_exists=True)
            if not is_valid:
                logger.error(f"Invalid source path: {msg}")
                log_forensic_operation("secure_copy", False, {**operation_details, "error": f"Invalid source path: {msg}"})
                return False

            is_valid, msg = validate_path(destination_path)
            if not is_valid:
                logger.error(f"Invalid destination path: {msg}")
                log_forensic_operation("secure_copy", False, {**operation_details, "error": f"Invalid destination path: {msg}"})
                return False

        # Check if source exists
        if not os.path.exists(source_path):
            logger.error(f"Source file not found: {source_path}")
            log_forensic_operation("secure_copy", False, {**operation_details, "error": "Source file not found"})
            return False

        # Check if source is accessible
        if not os.access(source_path, os.R_OK):
            logger.error(f"Source file not readable: {source_path}")
            log_forensic_operation("secure_copy", False, {**operation_details, "error": "Source file not readable"})
            return False

        # Generate hash of source if verification is requested
        if verify_hash and CRYPTO_AVAILABLE:
            source_hash = calculate_file_hash(source_path, hash_algorithm)
            if source_hash is None:
                logger.warning(f"Could not calculate source hash for {source_path}. Copying without verification.")
                verify_hash = False  # Disable verification if source hash failed
            operation_details["source_hash"] = source_hash
            operation_details["hash_algorithm"] = hash_algorithm

        # Ensure destination directory exists
        dest_dir = os.path.dirname(destination_path)
        try:
            if dest_dir:
                os.makedirs(dest_dir, exist_ok=True)
        except (OSError, PermissionError) as e:
            logger.error(f"Failed to create destination directory '{dest_dir}': {e}")
            log_forensic_operation("secure_copy", False, {**operation_details, "error": f"Failed to create destination directory: {e}"})
            return False

        # Perform the copy
        if preserve_metadata:
            shutil.copy2(source_path, destination_path)
        else:
            shutil.copy(source_path, destination_path)

        # Set secure permissions on the destination file
        try:
            if read_only:
                os.chmod(destination_path, DEFAULT_READ_ONLY_FILE_PERMS)
            else:
                os.chmod(destination_path, DEFAULT_SECURE_FILE_PERMS)
            operation_details["permissions_set"] = oct(DEFAULT_READ_ONLY_FILE_PERMS) if read_only else oct(DEFAULT_SECURE_FILE_PERMS)
        except OSError as chmod_err:
            logger.warning(f"Could not set secure permissions on {destination_path}: {chmod_err}")
            operation_details["permission_warning"] = str(chmod_err)
            # Continue despite permission warning

        # Verify destination hash if requested
        if verify_hash and source_hash and CRYPTO_AVAILABLE:
            dest_hash = calculate_file_hash(destination_path, hash_algorithm)
            operation_details["destination_hash"] = dest_hash
            if dest_hash != source_hash:
                logger.error(f"Hash mismatch after copying {source_path} to {destination_path}")
                log_forensic_operation("secure_copy", False, {**operation_details, "error": "Hash mismatch"})

                # Attempt to remove potentially corrupted destination file
                try:
                    os.remove(destination_path)
                    logger.info(f"Removed corrupted destination file: {destination_path}")
                except (OSError, PermissionError):
                    logger.warning(f"Failed to remove corrupted destination file: {destination_path}")

                return False

        log_forensic_operation("secure_copy", True, operation_details)
        return True

    except (OSError, shutil.Error) as e:
        logger.error(f"Error copying file {source_path} to {destination_path}: {e}")
        log_forensic_operation("secure_copy", False, {**operation_details, "error": str(e)})
        return False


def get_file_metadata(file_path: str, include_extended: bool = False) -> Optional[Dict[str, Any]]:
    """
    Retrieves forensic metadata for a file.

    Includes timestamps (MAC - Modified, Accessed, Created/Changed), size,
    permissions, owner, and group. With extended metadata, also attempts to
    determine file type and hashing.

    Args:
        file_path: Path to the file.
        include_extended: Whether to include extended metadata like hash and file type.

    Returns:
        A dictionary containing file metadata, or None if an error occurs.
    """
    operation_details = {"file": file_path, "include_extended": include_extended}

    try:
        # Validate path if validation module is available
        if VALIDATION_AVAILABLE:
            is_valid, msg = validate_path(file_path, check_exists=True)
            if not is_valid:
                logger.error(f"Invalid file path: {msg}")
                log_forensic_operation("get_file_metadata", False,
                                      {**operation_details, "error": f"Invalid path: {msg}"})
                return None

        if not os.path.exists(file_path):
            logger.error(f"File not found for metadata extraction: {file_path}")
            log_forensic_operation("get_file_metadata", False,
                                  {**operation_details, "error": "File not found"})
            return None

        if not os.access(file_path, os.R_OK):
            logger.error(f"File not readable: {file_path}")
            log_forensic_operation("get_file_metadata", False,
                                  {**operation_details, "error": "File not readable"})
            return None

        stat_info = os.stat(file_path)
        file_size = stat_info.st_size

        # Prepare ISO format timestamps with UTC timezone
        mtime = datetime.fromtimestamp(stat_info.st_mtime, timezone.utc)
        atime = datetime.fromtimestamp(stat_info.st_atime, timezone.utc)
        ctime = datetime.fromtimestamp(stat_info.st_ctime, timezone.utc)

        # Build basic metadata
        metadata = {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "directory": os.path.dirname(os.path.abspath(file_path)),
            "size_bytes": file_size,
            "size_human": _format_file_size(file_size),
            "permissions_octal": oct(stat.S_IMODE(stat_info.st_mode)),
            "permissions_human": _format_file_permissions(stat_info.st_mode),
            "owner_uid": stat_info.st_uid,
            "group_gid": stat_info.st_gid,
            "modified_time_utc": mtime.isoformat(),
            "accessed_time_utc": atime.isoformat(),
            "metadata_changed_time_utc": ctime.isoformat(),
            "device_id": stat_info.st_dev,
            "inode": stat_info.st_ino,
            "link_count": stat_info.st_nlink,
            "is_file": os.path.isfile(file_path),
            "is_directory": os.path.isdir(file_path),
            "is_symlink": os.path.islink(file_path),
            "is_executable": bool(stat_info.st_mode & stat.S_IXUSR),
        }

        # Attempt to get username/group name (best effort)
        try:
            import pwd
            metadata["owner_name"] = pwd.getpwuid(stat_info.st_uid).pw_name
        except (ImportError, KeyError):
            metadata["owner_name"] = None  # Not available or UID not found

        try:
            import grp
            metadata["group_name"] = grp.getgrgid(stat_info.st_gid).gr_name
        except (ImportError, KeyError):
            metadata["group_name"] = None  # Not available or GID not found

        # Add extended metadata if requested
        if include_extended:
            # Add file extension
            _, ext = os.path.splitext(file_path)
            metadata["extension"] = ext.lower()[1:] if ext else ""

            # Try to determine file type using 'file' command (if available on system)
            try:
                import subprocess
                file_cmd = subprocess.run(['file', '-b', file_path],
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE,
                                         timeout=5,
                                         check=False)
                if file_cmd.returncode == 0:
                    metadata["file_type"] = file_cmd.stdout.decode('utf-8', errors='replace').strip()
            except (subprocess.SubprocessError, FileNotFoundError, OSError):
                pass  # Silently ignore if 'file' command is unavailable

            # Calculate file hash if crypto is available
            if CRYPTO_AVAILABLE and os.path.isfile(file_path) and file_size > 0:
                try:
                    file_hash = calculate_file_hash(file_path, DEFAULT_HASH_ALGORITHM)
                    if file_hash:
                        metadata["hash"] = {DEFAULT_HASH_ALGORITHM: file_hash}
                except Exception as e:
                    logger.warning(f"Failed to calculate file hash for {file_path}: {e}")

        log_forensic_operation("get_file_metadata", True, operation_details)
        return metadata

    except OSError as e:
        logger.error(f"Error getting metadata for file {file_path}: {e}")
        log_forensic_operation("get_file_metadata", False, {**operation_details, "error": str(e)})
        return None


def verify_integrity(
    file_path: str,
    expected_hash: str,
    algorithm: str = DEFAULT_HASH_ALGORITHM
) -> bool:
    """
    Verifies file integrity using hash comparison.

    Args:
        file_path: Path to the file.
        expected_hash: The expected hash value.
        algorithm: The hash algorithm used.

    Returns:
        True if the hash matches, False otherwise or if verification fails.
    """
    operation_details = {"file": file_path, "algorithm": algorithm}

    if not CRYPTO_AVAILABLE:
        logger.error(f"Crypto functions unavailable for integrity verification of {file_path}")
        log_forensic_operation("verify_integrity", False,
                              {**operation_details, "error": "Crypto functions unavailable"})
        return False

    if not os.path.exists(file_path):
        logger.error(f"File not found for integrity verification: {file_path}")
        log_forensic_operation("verify_integrity", False,
                              {**operation_details, "error": "File not found"})
        return False

    # Verify file hash
    result = verify_file_hash(file_path, expected_hash, algorithm)

    # Log the verification result
    if result:
        log_forensic_operation("verify_integrity", True, operation_details)
    else:
        log_forensic_operation("verify_integrity", False,
                              {**operation_details, "error": "Hash mismatch"})

    return result


def create_secure_temp_file(prefix: str = "forensic_temp_", suffix: str = ".tmp",
                            content: Optional[bytes] = None) -> Optional[str]:
    """
    Creates a temporary file with secure permissions in the forensic temp directory.

    Args:
        prefix: Prefix for the temporary file name.
        suffix: Suffix for the temporary file name.
        content: Optional initial content to write to the file.

    Returns:
        The path to the created temporary file, or None if creation fails.
    """
    # Sanitize prefix and suffix
    prefix = re.sub(r'[^a-zA-Z0-9_-]', '', prefix)
    suffix = re.sub(r'[^a-zA-Z0-9._-]', '', suffix)

    operation_details = {"prefix": prefix, "suffix": suffix}

    try:
        # Create the file descriptor with secure permissions
        fd, temp_path = os.mkstemp(suffix=suffix, prefix=prefix, dir=TEMP_DIR_FORENSICS)
        try:
            # If content was provided, write it to the file
            if content:
                with os.fdopen(fd, 'wb') as f:
                    f.write(content)
                # Reopen in append mode to get a normal file descriptor
                os.close(fd)
            else:
                # Close the file descriptor if not using it
                os.close(fd)

            # Ensure proper permissions
            os.chmod(temp_path, DEFAULT_SECURE_FILE_PERMS)

            log_forensic_operation("create_secure_temp_file", True,
                                  {**operation_details, "path": temp_path})
            return temp_path

        except Exception as e:
            # Close the file descriptor if still open
            try:
                os.close(fd)
            except OSError:
                pass

            # Try to remove the file if it was created
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            except OSError:
                pass

            raise e

    except (OSError, IOError) as e:
        logger.error(f"Failed to create secure temporary file: {e}")
        log_forensic_operation("create_secure_temp_file", False,
                              {**operation_details, "error": str(e)})
        return None


def secure_delete(file_path: str, passes: int = 1) -> bool:
    """
    Attempts to securely delete a file by overwriting its content first.

    Note: True secure deletion is complex and depends heavily on the filesystem
    and underlying storage hardware (especially SSDs). This provides a basic
    overwrite attempt. For higher assurance, use specialized tools like 'shred'
    or filesystem-level secure deletion features if available.

    Args:
        file_path: Path to the file to delete.
        passes: Number of overwrite passes (default: 1).

    Returns:
        True if the file was overwritten (if possible) and removed, False otherwise.
    """
    operation_details = {"file": file_path, "passes": passes}

    try:
        # Validate path if validation module is available
        if VALIDATION_AVAILABLE:
            is_valid, msg = validate_path(file_path)
            if not is_valid:
                logger.error(f"Invalid file path for secure deletion: {msg}")
                log_forensic_operation("secure_delete", False,
                                      {**operation_details, "error": f"Invalid path: {msg}"})
                return False

        if not os.path.exists(file_path):
            logger.warning(f"File not found for secure deletion: {file_path}")
            # Consider it 'successful' deletion if file doesn't exist
            log_forensic_operation("secure_delete", True,
                                  {**operation_details, "status": "File not found"})
            return True

        # Check if file is writeable - required for secure deletion
        if not os.access(file_path, os.W_OK):
            try:
                # Try to make the file writeable first
                current_mode = os.stat(file_path).st_mode
                os.chmod(file_path, current_mode | stat.S_IWUSR)
            except (OSError, PermissionError) as e:
                logger.error(f"Cannot make file writeable for secure deletion: {file_path} - {e}")
                log_forensic_operation("secure_delete", False,
                                      {**operation_details, "error": f"File not writeable: {e}"})
                return False

        file_size = os.path.getsize(file_path)
        if file_size > 0 and passes > 0:
            try:
                # Attempt overwrite
                with open(file_path, 'wb') as f:
                    for pass_num in range(passes):
                        f.seek(0)
                        # Write random data - consider chunking for large files
                        chunk_size = 1024 * 1024  # 1MB chunks
                        remaining = file_size
                        while remaining > 0:
                            write_size = min(remaining, chunk_size)
                            f.write(os.urandom(write_size))
                            remaining -= write_size
                        f.flush()
                        os.fsync(f.fileno())  # Try to force write to disk

                operation_details["overwrite_status"] = "Completed"

            except (OSError, IOError) as ow_err:
                logger.warning(f"Failed to fully overwrite {file_path}: {ow_err}. Proceeding with deletion.")
                operation_details["overwrite_status"] = f"Failed: {ow_err}"
                # Continue to delete anyway

        # Perform the final deletion
        os.remove(file_path)
        log_forensic_operation("secure_delete", True, operation_details)
        return True

    except (OSError, IOError) as e:
        logger.error(f"Error during secure deletion of {file_path}: {e}")
        log_forensic_operation("secure_delete", False, {**operation_details, "error": str(e)})
        return False


# --- Additional Forensic File Operations ---

def write_only_open(file_path: str, mode: str = 'wb') -> Optional[BinaryIO]:
    """
    Opens a file in a write-only mode to prevent accidental reading of evidence.

    Creates a directory if needed and applies correct permissions to file.

    Args:
        file_path: Path to the file to open.
        mode: Mode to open the file in ('wb' or 'ab' only).

    Returns:
        An open file handle, or None if opening failed.
    """
    if mode not in ('wb', 'ab'):
        logger.error(f"Unsupported mode for write_only_open: {mode}")
        log_forensic_operation("write_only_open", False,
                              {"file": file_path, "error": "Unsupported mode"})
        return None

    try:
        # Ensure directory exists
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)

        # Open file and set permissions
        f = open(file_path, mode)
        try:
            # Try to set permissions
            os.chmod(file_path, DEFAULT_SECURE_FILE_PERMS)
        except OSError:
            # Continue even if chmod failed (might be on filesystems where this isn't supported)
            pass

        log_forensic_operation("write_only_open", True, {"file": file_path, "mode": mode})
        return f
    except (OSError, IOError) as e:
        logger.error(f"Failed to open file for writing: {file_path} - {e}")
        log_forensic_operation("write_only_open", False,
                              {"file": file_path, "error": str(e)})
        return None


def read_only_open(file_path: str) -> Optional[BinaryIO]:
    """
    Opens a file in a read-only mode to prevent accidental modification.

    Args:
        file_path: Path to the file to open.

    Returns:
        An open file handle, or None if opening failed.
    """
    try:
        # Validate file exists
        if not os.path.isfile(file_path):
            logger.error(f"File not found or not a regular file: {file_path}")
            log_forensic_operation("read_only_open", False,
                                  {"file": file_path, "error": "File not found"})
            return None

        # Open file in read-only binary mode
        f = open(file_path, 'rb')
        log_forensic_operation("read_only_open", True, {"file": file_path})
        return f
    except (OSError, IOError) as e:
        logger.error(f"Failed to open file for reading: {file_path} - {e}")
        log_forensic_operation("read_only_open", False,
                              {"file": file_path, "error": str(e)})
        return None


def write_metadata_file(metadata: Dict[str, Any], file_path: str, format: str = 'json') -> bool:
    """
    Writes metadata to a file in the specified format.

    Args:
        metadata: The metadata dictionary to write.
        file_path: Path to output file.
        format: Output format ('json' or 'text').

    Returns:
        True if successfully written, False otherwise.
    """
    operation_details = {"file": file_path, "format": format}

    try:
        with write_only_open(file_path) as f:
            if not f:
                return False

            if format.lower() == 'json':
                f.write(json.dumps(metadata, indent=2).encode('utf-8'))
            else:  # text format
                content = []
                for key, value in metadata.items():
                    content.append(f"{key}: {value}")
                f.write('\n'.join(content).encode('utf-8'))

        log_forensic_operation("write_metadata_file", True, operation_details)
        return True
    except (OSError, IOError, TypeError, ValueError) as e:
        logger.error(f"Failed to write metadata file: {file_path} - {e}")
        log_forensic_operation("write_metadata_file", False,
                              {**operation_details, "error": str(e)})
        return False


def set_file_read_only(file_path: str) -> bool:
    """
    Sets a file to read-only mode to prevent accidental modification.

    Args:
        file_path: Path to the file.

    Returns:
        True if successfully set to read-only, False otherwise.
    """
    operation_details = {"file": file_path}

    try:
        os.chmod(file_path, DEFAULT_READ_ONLY_FILE_PERMS)
        log_forensic_operation("set_file_read_only", True, operation_details)
        return True
    except (OSError, PermissionError) as e:
        logger.error(f"Failed to set file as read-only: {file_path} - {e}")
        log_forensic_operation("set_file_read_only", False,
                              {**operation_details, "error": str(e)})
        return False


def find_files_by_pattern(
    base_dir: str,
    pattern: str,
    recursive: bool = True,
    max_depth: int = -1,
    include_hidden: bool = False
) -> List[str]:
    """
    Finds files matching a pattern in a directory.

    Args:
        base_dir: The base directory to search in.
        pattern: Glob pattern for matching files.
        recursive: Whether to search recursively.
        max_depth: Maximum recursion depth (-1 for unlimited).
        include_hidden: Whether to include hidden files (starting with '.').

    Returns:
        List of matching file paths.
    """
    operation_details = {
        "base_dir": base_dir,
        "pattern": pattern,
        "recursive": recursive,
        "max_depth": max_depth,
        "include_hidden": include_hidden
    }

    if not os.path.exists(base_dir) or not os.path.isdir(base_dir):
        logger.error(f"Base directory not found or not a directory: {base_dir}")
        log_forensic_operation("find_files_by_pattern", False,
                              {**operation_details, "error": "Invalid base directory"})
        return []

    result = []
    current_depth = 0

    try:
        # Process base directory
        _find_files_recursive(base_dir, pattern, result, recursive, max_depth,
                             current_depth, include_hidden)

        log_forensic_operation("find_files_by_pattern", True,
                              {**operation_details, "files_found": len(result)})
        return result
    except (OSError, re.error) as e:
        logger.error(f"Error searching for files in {base_dir}: {e}")
        log_forensic_operation("find_files_by_pattern", False,
                              {**operation_details, "error": str(e)})
        return []


def compare_files(
    file1_path: str,
    file2_path: str,
    hash_compare: bool = True,
    content_compare: bool = False,
    max_bytes_compare: int = 1024 * 1024 * 10  # 10MB default limit for content comparison
) -> Tuple[bool, Dict[str, Any]]:
    """
    Compares two files by hash, metadata, and optionally content.

    Args:
        file1_path: Path to first file.
        file2_path: Path to second file.
        hash_compare: Whether to compare file hashes.
        content_compare: Whether to do a byte-by-byte comparison.
        max_bytes_compare: Maximum bytes to compare if content_compare is True.

    Returns:
        Tuple of (files_match, comparison_details).
    """
    operation_details = {
        "file1": file1_path,
        "file2": file2_path,
        "hash_compare": hash_compare,
        "content_compare": content_compare
    }

    # Initialize results
    comparison = {
        "files_exist": False,
        "size_match": False,
        "size1": None,
        "size2": None,
        "hash_match": None,
        "hash1": None,
        "hash2": None,
        "content_match": None,
        "mtime_match": False,
        "mtime1": None,
        "mtime2": None,
        "permissions_match": False,
        "permissions1": None,
        "permissions2": None,
        "difference_offset": None
    }

    # Check files exist
    if not os.path.isfile(file1_path) or not os.path.isfile(file2_path):
        logger.error(f"One or both files don't exist: {file1_path}, {file2_path}")
        log_forensic_operation("compare_files", False,
                              {**operation_details, "error": "One or both files don't exist"})
        return False, comparison

    comparison["files_exist"] = True

    try:
        # Get basic file stats
        stat1 = os.stat(file1_path)
        stat2 = os.stat(file2_path)

        # Compare sizes
        comparison["size1"] = stat1.st_size
        comparison["size2"] = stat2.st_size
        comparison["size_match"] = (stat1.st_size == stat2.st_size)

        # Compare modification times
        comparison["mtime1"] = datetime.fromtimestamp(stat1.st_mtime, timezone.utc).isoformat()
        comparison["mtime2"] = datetime.fromtimestamp(stat2.st_mtime, timezone.utc).isoformat()
        comparison["mtime_match"] = (stat1.st_mtime == stat2.st_mtime)

        # Compare permissions
        comparison["permissions1"] = stat.S_IMODE(stat1.st_mode)
        comparison["permissions2"] = stat.S_IMODE(stat2.st_mode)
        comparison["permissions_match"] = (comparison["permissions1"] == comparison["permissions2"])

        # Hash comparison
        if hash_compare and CRYPTO_AVAILABLE:
            hash1 = calculate_file_hash(file1_path, DEFAULT_HASH_ALGORITHM)
            hash2 = calculate_file_hash(file2_path, DEFAULT_HASH_ALGORITHM)

            comparison["hash1"] = hash1
            comparison["hash2"] = hash2
            comparison["hash_match"] = (hash1 == hash2) if hash1 and hash2 else False

            # If hashes match, files are identical - no need for byte comparison
            if comparison["hash_match"]:
                comparison["content_match"] = True
                content_compare = False

        # Content comparison if requested and files have the same size
        if content_compare and comparison["size_match"]:
            with open(file1_path, 'rb') as f1, open(file2_path, 'rb') as f2:
                bytes_compared = 0
                mismatch_found = False

                while bytes_compared < min(comparison["size1"], max_bytes_compare):
                    chunk_size = min(8192, max_bytes_compare - bytes_compared)
                    chunk1 = f1.read(chunk_size)
                    chunk2 = f2.read(chunk_size)

                    if chunk1 != chunk2:
                        # Find the exact byte where the difference starts
                        for i, (b1, b2) in enumerate(zip(chunk1, chunk2)):
                            if b1 != b2:
                                comparison["difference_offset"] = bytes_compared + i
                                mismatch_found = True
                                break

                        if mismatch_found:
                            break

                    if not chunk1:  # End of file
                        break

                    bytes_compared += len(chunk1)

                comparison["content_match"] = not mismatch_found

        # Determine overall match: if hash comparison was done, use that result
        # otherwise use content_match if available, or fall back to size_match
        files_match = False
        if comparison["hash_match"] is not None:
            files_match = comparison["hash_match"]
        elif comparison["content_match"] is not None:
            files_match = comparison["content_match"]
        else:
            files_match = comparison["size_match"]

        log_forensic_operation("compare_files", True, {
            **operation_details,
            "match_result": files_match,
            "size_match": comparison["size_match"],
            "hash_match": comparison["hash_match"]
        })
        return files_match, comparison

    except (OSError, IOError) as e:
        logger.error(f"Error comparing files: {e}")
        log_forensic_operation("compare_files", False, {**operation_details, "error": str(e)})
        return False, comparison


def create_file_evidence_record(
    file_path: str,
    case_id: str,
    evidence_type: str = "File",
    description: Optional[str] = None,
    copy_to_evidence_storage: bool = True,
    make_read_only: bool = True
) -> Dict[str, Any]:
    """
    Creates an evidence record for a file, with optional secure copying to evidence storage.

    Args:
        file_path: Path to the file.
        case_id: Case identifier.
        evidence_type: Type of evidence.
        description: Optional description of the evidence.
        copy_to_evidence_storage: Whether to copy the file to evidence storage.
        make_read_only: Whether to make the evidence file read-only.

    Returns:
        Dictionary with evidence metadata and operation results.
    """
    timestamp = datetime.now(timezone.utc)
    operation_details = {
        "file": file_path,
        "case_id": case_id,
        "evidence_type": evidence_type,
        "copy_requested": copy_to_evidence_storage
    }

    evidence_record = {
        "original_path": file_path,
        "case_id": case_id,
        "evidence_type": evidence_type,
        "description": description or f"File evidence: {os.path.basename(file_path)}",
        "acquisition_time": timestamp.isoformat(),
        "evidence_id": f"ev-{int(timestamp.timestamp())}-{os.path.basename(file_path)}",
        "copy_successful": None,
        "read_only": None,
        "evidence_storage_path": None,
        "metadata": None,
        "hash": None
    }

    try:
        # Get detailed file metadata
        metadata = get_file_metadata(file_path, include_extended=True)
        if not metadata:
            log_forensic_operation("create_file_evidence_record", False,
                                  {**operation_details, "error": "Failed to get file metadata"})
            return evidence_record

        evidence_record["metadata"] = metadata
        if "hash" in metadata and metadata["hash"]:
            evidence_record["hash"] = metadata["hash"]

        # Copy to evidence storage if requested
        if copy_to_evidence_storage:
            # Create case directory in evidence storage
            case_dir = os.path.join(DEFAULT_EVIDENCE_STORAGE_DIR, case_id, "files")
            os.makedirs(case_dir, exist_ok=True)

            # Copy with date-based filename to prevent collisions
            date_prefix = timestamp.strftime("%Y%m%d_%H%M%S")
            basename = os.path.basename(file_path)
            dest_path = os.path.join(case_dir, f"{date_prefix}_{basename}")

            # Copy with integrity verification
            copy_success = secure_copy(
                file_path,
                dest_path,
                preserve_metadata=True,
                verify_hash=True,
                read_only=make_read_only
            )

            evidence_record["copy_successful"] = copy_success
            if copy_success:
                evidence_record["evidence_storage_path"] = dest_path
                evidence_record["read_only"] = make_read_only

                # Write metadata file next to the evidence
                metadata_path = f"{dest_path}.metadata.json"
                write_metadata_file(
                    {**evidence_record, "metadata": metadata},
                    metadata_path
                )

        log_forensic_operation("create_file_evidence_record", True, {
            **operation_details,
            "evidence_id": evidence_record["evidence_id"],
            "copy_successful": evidence_record["copy_successful"]
        })
        return evidence_record
    except (OSError, IOError) as e:
        logger.error(f"Error creating evidence record: {e}")
        log_forensic_operation("create_file_evidence_record", False,
                              {**operation_details, "error": str(e)})
        evidence_record["error"] = str(e)
        return evidence_record


# --- Helper Functions ---

def _format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if size_bytes < 1024 or unit == 'PB':
            if unit == 'B':
                return f"{size_bytes} {unit}"
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024


def _format_file_permissions(mode: int) -> str:
    """Format file permissions in rwx notation."""
    perms = ""
    for who in "USR", "GRP", "OTH":
        for what in "R", "W", "X":
            if mode & getattr(stat, f"S_I{what}{who}"):
                perms += what.lower()
            else:
                perms += "-"
    return perms


def _find_files_recursive(
    dir_path: str,
    pattern: str,
    result: List[str],
    recursive: bool,
    max_depth: int,
    current_depth: int,
    include_hidden: bool
) -> None:
    """Helper function for recursive file searching."""
    try:
        # Check if we've exceeded max depth
        if max_depth >= 0 and current_depth > max_depth:
            return

        # Get all entries in directory
        with os.scandir(dir_path) as entries:
            for entry in entries:
                # Skip hidden files/dirs if not included
                if not include_hidden and entry.name.startswith('.'):
                    continue

                # For files, check if they match the pattern
                if entry.is_file():
                    if re.search(pattern, entry.name):
                        result.append(entry.path)
                # For directories, recurse if needed
                elif entry.is_dir() and recursive:
                    _find_files_recursive(
                        entry.path,
                        pattern,
                        result,
                        recursive,
                        max_depth,
                        current_depth + 1,
                        include_hidden
                    )
    except (OSError, PermissionError):
        # Skip directories we can't access
        pass


# --- Example Usage ---

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    TEST_SOURCE_FILE = "test_source_file.txt"
    TEST_DEST_FILE = os.path.join(TEMP_DIR_FORENSICS, "test_dest_file.txt")
    TEST_CONTENT = b"This is test content for forensic file utils.\n" * 10

    # Create a dummy source file
    try:
        with open(TEST_SOURCE_FILE, "wb") as f:
            f.write(TEST_CONTENT)
        logger.info(f"Created test source file: {TEST_SOURCE_FILE}")
    except OSError as e:
        logger.error(f"Failed to create test source file: {e}")
        exit(1)

    # 1. Test Secure Copy
    print("\n--- Testing Secure Copy ---")
    copy_success = secure_copy(TEST_SOURCE_FILE, TEST_DEST_FILE, verify_hash=True)
    if copy_success:
        print(f"Secure copy successful: {TEST_SOURCE_FILE} -> {TEST_DEST_FILE}")
        if os.path.exists(TEST_DEST_FILE):
            print(f"Destination file exists.")
            # Check permissions (will vary slightly based on umask)
            dest_stat = os.stat(TEST_DEST_FILE)
            print(f"Destination permissions: {oct(stat.S_IMODE(dest_stat.st_mode))}")
        else:
            print("ERROR: Destination file does not exist after successful copy.")
    else:
        print("Secure copy failed.")

    # 2. Test Get File Metadata
    print("\n--- Testing Get File Metadata ---")
    metadata = get_file_metadata(TEST_DEST_FILE, include_extended=True)
    if metadata:
        print("Metadata retrieved:")
        for key, value in sorted(metadata.items()):
            print(f"  {key}: {value}")
    else:
        print("Failed to retrieve metadata.")

    # 3. Test Integrity Verification
    print("\n--- Testing Integrity Verification ---")
    source_hash = calculate_file_hash(TEST_SOURCE_FILE) if CRYPTO_AVAILABLE else None
    if source_hash:
        print(f"Source Hash: {source_hash}")
        verify_ok = verify_integrity(TEST_DEST_FILE, source_hash)
        print(f"Integrity verification (correct hash): {verify_ok}")
        verify_fail = verify_integrity(TEST_DEST_FILE, "incorrecthash")
        print(f"Integrity verification (incorrect hash): {verify_fail}")
    else:
        print("Skipping integrity test - could not get source hash.")

    # 4. Test Secure Temp File
    print("\n--- Testing Secure Temp File ---")
    temp_file_path = create_secure_temp_file(content=b"Temporary test content")
    if temp_file_path:
        print(f"Secure temp file created: {temp_file_path}")
        if os.path.exists(temp_file_path):
            temp_stat = os.stat(temp_file_path)
            print(f"Temp file permissions: {oct(stat.S_IMODE(temp_stat.st_mode))}")
            # Check content
            with open(temp_file_path, 'rb') as f:
                content = f.read()
                print(f"Content verification: {'Success' if content == b'Temporary test content' else 'Failed'}")
            # Clean up temp file
            os.remove(temp_file_path)
        else:
            print("ERROR: Temp file does not exist after creation.")
    else:
        print("Failed to create secure temp file.")

    # 5. Test File Comparison
    print("\n--- Testing File Comparison ---")
    # Create a second test file with same content
    TEST_IDENTICAL_FILE = os.path.join(TEMP_DIR_FORENSICS, "test_identical_file.txt")
    with open(TEST_IDENTICAL_FILE, "wb") as f:
        f.write(TEST_CONTENT)

    # Create a third test file with different content
    TEST_DIFFERENT_FILE = os.path.join(TEMP_DIR_FORENSICS, "test_different_file.txt")
    with open(TEST_DIFFERENT_FILE, "wb") as f:
        f.write(TEST_CONTENT + b"Extra content to make files different")

    # Compare identical files
    match_result, comparison = compare_files(
        TEST_SOURCE_FILE,
        TEST_IDENTICAL_FILE,
        hash_compare=CRYPTO_AVAILABLE,
        content_compare=True
    )
    print(f"Identical files comparison result: {match_result}")
    print(f"  Size match: {comparison['size_match']}")
    print(f"  Content match: {comparison['content_match']}")
    if CRYPTO_AVAILABLE:
        print(f"  Hash match: {comparison['hash_match']}")

    # Compare different files
    match_result, comparison = compare_files(
        TEST_SOURCE_FILE,
        TEST_DIFFERENT_FILE,
        hash_compare=CRYPTO_AVAILABLE,
        content_compare=True
    )
    print(f"Different files comparison result: {match_result}")
    print(f"  Size match: {comparison['size_match']}")
    print(f"  Content match: {comparison['content_match']}")
    print(f"  Difference offset: {comparison['difference_offset']}")
    if CRYPTO_AVAILABLE:
        print(f"  Hash match: {comparison['hash_match']}")

    # 6. Test Set File Read-Only
    print("\n--- Testing Set File Read-Only ---")
    read_only_result = set_file_read_only(TEST_DEST_FILE)
    print(f"Set read-only result: {read_only_result}")
    if read_only_result:
        permissions = os.stat(TEST_DEST_FILE).st_mode & 0o777
        print(f"File permissions after setting read-only: {oct(permissions)}")
        print(f"Can write: {'No' if not os.access(TEST_DEST_FILE, os.W_OK) else 'Yes'}")

    # 7. Test File Finding
    print("\n--- Testing File Finding ---")
    # Create a temporary directory structure for testing
    TEST_FIND_DIR = os.path.join(TEMP_DIR_FORENSICS, "find_test")
    os.makedirs(TEST_FIND_DIR, exist_ok=True)
    # Create some test files
    open(os.path.join(TEST_FIND_DIR, "test1.txt"), 'w').close()
    open(os.path.join(TEST_FIND_DIR, "test2.log"), 'w').close()
    os.makedirs(os.path.join(TEST_FIND_DIR, "subdir"), exist_ok=True)
    open(os.path.join(TEST_FIND_DIR, "subdir", "test3.txt"), 'w').close()

    files = find_files_by_pattern(TEST_FIND_DIR, r"\.txt$", recursive=True)
    print(f"Found files with pattern '.txt$':")
    for file in files:
        print(f"  {file}")

    # 8. Test Secure Delete
    print("\n--- Testing Secure Delete ---")
    # Use the copied file for deletion test
    if os.path.exists(TEST_DEST_FILE):
        delete_success = secure_delete(TEST_DEST_FILE, passes=1)
        print(f"Secure delete successful: {delete_success}")
        if not os.path.exists(TEST_DEST_FILE):
            print(f"File {TEST_DEST_FILE} successfully removed.")
        else:
            print(f"ERROR: File {TEST_DEST_FILE} still exists after secure delete.")
    else:
        print(f"Skipping secure delete test - file {TEST_DEST_FILE} not found.")

    # 9. Test Evidence Record Creation
    if os.path.exists(DEFAULT_EVIDENCE_STORAGE_DIR) or os.access(os.path.dirname(DEFAULT_EVIDENCE_STORAGE_DIR), os.W_OK):
        print("\n--- Testing Evidence Record Creation ---")
        evidence_record = create_file_evidence_record(
            file_path=TEST_SOURCE_FILE,
            case_id="TEST-CASE-001",
            evidence_type="TestFile",
            description="Test file for evidence record creation"
        )
        print(f"Evidence record created with ID: {evidence_record['evidence_id']}")
        print(f"Copy successful: {evidence_record['copy_successful']}")
        print(f"Evidence stored at: {evidence_record['evidence_storage_path']}")
    else:
        print("\nSkipping evidence record test - evidence directory not accessible")

    # Final cleanup
    print("\n--- Final Cleanup ---")
    try:
        # Clean up all test files
        if os.path.exists(TEST_SOURCE_FILE):
            os.remove(TEST_SOURCE_FILE)
            print(f"Removed test source file: {TEST_SOURCE_FILE}")

        for file_path in [TEST_IDENTICAL_FILE, TEST_DIFFERENT_FILE]:
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"Removed test file: {file_path}")

        # Clean up test directory for find operation
        if os.path.exists(TEST_FIND_DIR):
            shutil.rmtree(TEST_FIND_DIR)
            print(f"Removed test directory: {TEST_FIND_DIR}")

        # Ensure dest file is gone if delete failed earlier
        if os.path.exists(TEST_DEST_FILE):
            os.remove(TEST_DEST_FILE)
            print(f"Force removed test destination file: {TEST_DEST_FILE}")
    except OSError as e:
        logger.warning(f"Cleanup failed: {e}")

    print("\n--- Tests Complete ---")
