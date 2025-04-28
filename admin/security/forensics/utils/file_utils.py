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
from datetime import datetime, timezone
from typing import Dict, Optional, Any, List

# Attempt to import forensic-specific logging, crypto, and constants
try:
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
except ImportError:
    logging.warning("Forensic logging utility not found. Using standard logger.")
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict] = None):
        level = logging.INFO if success else logging.ERROR
        log_msg = f"Forensic Operation: {operation}, Success: {success}"
        if details:
            log_msg += f", Details: {details}"
        logging.log(level, log_msg)

try:
    from admin.security.forensics.utils.crypto import calculate_file_hash, verify_file_hash, DEFAULT_HASH_ALGORITHM
except ImportError:
    logging.warning("Forensic crypto utility not found. Hash calculation/verification unavailable.")
    DEFAULT_HASH_ALGORITHM = "sha256"
    def calculate_file_hash(file_path: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> Optional[str]:
        logging.error("calculate_file_hash function is unavailable.")
        return None
    def verify_file_hash(file_path: str, expected_hash: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> bool:
        logging.error("verify_file_hash function is unavailable.")
        return False

try:
    from admin.security.forensics.utils.forensic_constants import (
        DEFAULT_SECURE_FILE_PERMS, TEMP_DIR_FORENSICS
    )
except ImportError:
    logging.warning("Forensic constants not found. Using default values.")
    DEFAULT_SECURE_FILE_PERMS = 0o600 # Read/Write for owner only
    TEMP_DIR_FORENSICS = "/tmp/forensics" # Example default

logger = logging.getLogger(__name__)

# Ensure temporary directory exists
os.makedirs(TEMP_DIR_FORENSICS, exist_ok=True)


def secure_copy(
    source_path: str,
    destination_path: str,
    preserve_metadata: bool = True,
    verify_hash: bool = True,
    hash_algorithm: str = DEFAULT_HASH_ALGORITHM
) -> bool:
    """
    Securely copies a file, preserving metadata and verifying integrity.

    Args:
        source_path: Path to the source file.
        destination_path: Path to the destination file.
        preserve_metadata: If True, attempts to preserve timestamps and permissions.
        verify_hash: If True, calculates hashes before and after copy to verify integrity.
        hash_algorithm: Algorithm to use for hash verification.

    Returns:
        True if the copy was successful and verified (if requested), False otherwise.
    """
    operation_details = {"source": source_path, "destination": destination_path, "preserve_metadata": preserve_metadata, "verify_hash": verify_hash}
    source_hash = None

    try:
        if not os.path.exists(source_path):
            logger.error(f"Source file not found: {source_path}")
            log_forensic_operation("secure_copy", False, {**operation_details, "error": "Source file not found"})
            return False

        if verify_hash:
            source_hash = calculate_file_hash(source_path, hash_algorithm)
            if source_hash is None:
                logger.warning(f"Could not calculate source hash for {source_path}. Copying without verification.")
                verify_hash = False # Disable verification if source hash failed
            operation_details["source_hash"] = source_hash
            operation_details["hash_algorithm"] = hash_algorithm

        # Ensure destination directory exists
        dest_dir = os.path.dirname(destination_path)
        os.makedirs(dest_dir, exist_ok=True)

        # Perform the copy
        if preserve_metadata:
            shutil.copy2(source_path, destination_path)
        else:
            shutil.copy(source_path, destination_path)

        # Set secure permissions on the destination file
        try:
            os.chmod(destination_path, DEFAULT_SECURE_FILE_PERMS)
        except OSError as chmod_err:
            logger.warning(f"Could not set secure permissions on {destination_path}: {chmod_err}")
            # Continue, but log the warning

        # Verify destination hash if requested
        if verify_hash and source_hash:
            dest_hash = calculate_file_hash(destination_path, hash_algorithm)
            operation_details["destination_hash"] = dest_hash
            if dest_hash != source_hash:
                logger.error(f"Hash mismatch after copying {source_path} to {destination_path}")
                log_forensic_operation("secure_copy", False, {**operation_details, "error": "Hash mismatch"})
                # Consider removing the potentially corrupted destination file?
                # For now, just report failure.
                return False

        log_forensic_operation("secure_copy", True, operation_details)
        return True

    except (OSError, shutil.Error) as e:
        logger.error(f"Error copying file {source_path} to {destination_path}: {e}")
        log_forensic_operation("secure_copy", False, {**operation_details, "error": str(e)})
        return False

def get_file_metadata(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves forensic metadata for a file.

    Includes timestamps (MAC - Modified, Accessed, Created/Changed), size,
    permissions, owner, and group.

    Args:
        file_path: Path to the file.

    Returns:
        A dictionary containing file metadata, or None if an error occurs.
    """
    try:
        if not os.path.exists(file_path):
            logger.error(f"File not found for metadata extraction: {file_path}")
            log_forensic_operation("get_file_metadata", False, {"file": file_path, "error": "File not found"})
            return None

        stat_info = os.stat(file_path)

        metadata = {
            "file_path": file_path,
            "size_bytes": stat_info.st_size,
            "permissions_octal": stat.S_IMODE(stat_info.st_mode),
            "owner_uid": stat_info.st_uid,
            "group_gid": stat_info.st_gid,
            "modified_time_utc": datetime.fromtimestamp(stat_info.st_mtime, timezone.utc).isoformat(),
            "accessed_time_utc": datetime.fromtimestamp(stat_info.st_atime, timezone.utc).isoformat(),
            # ctime varies by OS (creation on Windows, metadata change on Unix)
            "metadata_changed_time_utc": datetime.fromtimestamp(stat_info.st_ctime, timezone.utc).isoformat(),
            "device_id": stat_info.st_dev,
            "inode": stat_info.st_ino,
            "link_count": stat_info.st_nlink,
        }

        # Attempt to get username/group name (best effort)
        try:
            import pwd
            metadata["owner_name"] = pwd.getpwuid(stat_info.st_uid).pw_name
        except (ImportError, KeyError):
            metadata["owner_name"] = None # Not available or UID not found
        try:
            import grp
            metadata["group_name"] = grp.getgrgid(stat_info.st_gid).gr_name
        except (ImportError, KeyError):
            metadata["group_name"] = None # Not available or GID not found

        log_forensic_operation("get_file_metadata", True, {"file": file_path})
        return metadata

    except OSError as e:
        logger.error(f"Error getting metadata for file {file_path}: {e}")
        log_forensic_operation("get_file_metadata", False, {"file": file_path, "error": str(e)})
        return None

def verify_integrity(
    file_path: str,
    expected_hash: str,
    algorithm: str = DEFAULT_HASH_ALGORITHM
) -> bool:
    """
    Convenience function to verify file integrity using crypto utilities.

    Args:
        file_path: Path to the file.
        expected_hash: The expected hash value.
        algorithm: The hash algorithm used.

    Returns:
        True if the hash matches, False otherwise or if verification fails.
    """
    # Logging is handled within verify_file_hash
    return verify_file_hash(file_path, expected_hash, algorithm)


def create_secure_temp_file(prefix: str = "forensic_temp_", suffix: str = ".tmp") -> Optional[str]:
    """
    Creates a temporary file with secure permissions in the forensic temp directory.

    Args:
        prefix: Prefix for the temporary file name.
        suffix: Suffix for the temporary file name.

    Returns:
        The path to the created temporary file, or None if creation fails.
    """
    try:
        # Create the file descriptor with secure permissions
        fd, temp_path = os.mkstemp(suffix=suffix, prefix=prefix, dir=TEMP_DIR_FORENSICS)
        os.close(fd) # Close the descriptor, we just needed the path
        os.chmod(temp_path, DEFAULT_SECURE_FILE_PERMS) # Ensure permissions are strict
        log_forensic_operation("create_secure_temp_file", True, {"path": temp_path})
        return temp_path
    except (OSError, IOError) as e:
        logger.error(f"Failed to create secure temporary file: {e}")
        log_forensic_operation("create_secure_temp_file", False, {"error": str(e)})
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
        if not os.path.exists(file_path):
            logger.warning(f"File not found for secure deletion: {file_path}")
            # Consider it 'successful' deletion if file doesn't exist
            log_forensic_operation("secure_delete", True, {**operation_details, "status": "File not found"})
            return True

        file_size = os.path.getsize(file_path)
        if file_size > 0 and passes > 0:
            try:
                # Attempt overwrite
                with open(file_path, 'wb') as f:
                    for _ in range(passes):
                        f.seek(0)
                        # Write random data - consider chunking for large files
                        chunk_size = 1024 * 1024 # 1MB chunks
                        remaining = file_size
                        while remaining > 0:
                            write_size = min(remaining, chunk_size)
                            f.write(os.urandom(write_size))
                            remaining -= write_size
                        f.flush()
                        os.fsync(f.fileno()) # Try to force write to disk
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

# Example usage
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
    metadata = get_file_metadata(TEST_DEST_FILE)
    if metadata:
        print("Metadata retrieved:")
        for key, value in metadata.items():
            print(f"  {key}: {value}")
    else:
        print("Failed to retrieve metadata.")

    # 3. Test Integrity Verification
    print("\n--- Testing Integrity Verification ---")
    source_hash = calculate_file_hash(TEST_SOURCE_FILE)
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
    temp_file_path = create_secure_temp_file()
    if temp_file_path:
        print(f"Secure temp file created: {temp_file_path}")
        if os.path.exists(temp_file_path):
            temp_stat = os.stat(temp_file_path)
            print(f"Temp file permissions: {oct(stat.S_IMODE(temp_stat.st_mode))}")
            # Clean up temp file
            os.remove(temp_file_path)
        else:
            print("ERROR: Temp file does not exist after creation.")
    else:
        print("Failed to create secure temp file.")

    # 5. Test Secure Delete
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

    # Final cleanup
    print("\n--- Final Cleanup ---")
    try:
        if os.path.exists(TEST_SOURCE_FILE):
            os.remove(TEST_SOURCE_FILE)
            print(f"Removed test source file: {TEST_SOURCE_FILE}")
        # Ensure dest file is gone if delete failed earlier
        if os.path.exists(TEST_DEST_FILE):
             os.remove(TEST_DEST_FILE)
             print(f"Force removed test destination file: {TEST_DEST_FILE}")
    except OSError as e:
        logger.warning(f"Cleanup failed: {e}")
