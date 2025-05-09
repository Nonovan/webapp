"""
Security Service for Cloud Infrastructure Platform.

This service provides security-related functionality including file integrity monitoring,
baseline management, and security posture assessment. It implements secure handling of
file operations with comprehensive validation and error handling.
"""

import logging
import os
import json
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set, Union, Callable

try:
    from flask import current_app, g
    from werkzeug.local import LocalProxy

    from extensions import db, cache, metrics
    from core.security import log_security_event, sanitize_path, is_safe_file_operation
    from core.security.cs_crypto import encrypt_sensitive_data, decrypt_sensitive_data
    from models.security import SecurityScan, AuditLog
    from services.service_constants import (
        DEFAULT_HASH_ALGORITHM, DEFAULT_BASELINE_FILE_PATH, DEFAULT_BACKUP_PATH_TEMPLATE,
        AUTO_UPDATE_LIMIT, FILE_CHANGE_SEVERITY_MAP, INTEGRITY_SEVERITY_HIGH, INTEGRITY_SEVERITY_MEDIUM,
        INTEGRITY_SEVERITY_LOW, INTEGRITY_SEVERITY_CRITICAL, FILE_INTEGRITY_CONSTANTS
    )
except ImportError as e:
    logging.warning(f"Some dependencies not available for SecurityService: {e}")

# Configure logging
logger = logging.getLogger(__name__)

# Constants
DEFAULT_HASH_CHUNK_SIZE = 8192  # 8KB chunks for file hashing
BASELINE_METADATA_VERSION = "1.1"


class SecurityService:
    """
    Provides security-related services like file integrity checks and baseline management.
    """

    @staticmethod
    def _load_baseline(baseline_file: Path = DEFAULT_BASELINE_FILE_PATH) -> Dict[str, Any]:
        """Loads the baseline data from the specified JSON file."""
        if not baseline_file.exists():
            logger.warning("Baseline file not found: %s", baseline_file)
            return {"files": {}, "metadata": {}}
        try:
            with open(baseline_file, 'r') as f:
                data = json.load(f)
                if "files" not in data: # Basic validation
                    logger.error("Baseline file %s is missing 'files' key.", baseline_file)
                    return {"files": {}, "metadata": data.get("metadata", {})}
                return data
        except json.JSONDecodeError as e:
            logger.error("Failed to decode baseline file %s: %s", baseline_file, e)
            metrics.increment('security.baseline.load_error')
            return {"files": {}, "metadata": {}}
        except IOError as e:
            logger.error("Failed to read baseline file %s: %s", baseline_file, e)
            metrics.increment('security.baseline.load_error')
            return {"files": {}, "metadata": {}}

    @staticmethod
    def _save_baseline(data: Dict[str, Any], baseline_file: Path = DEFAULT_BASELINE_FILE_PATH) -> bool:
        """Saves the baseline data to the specified JSON file."""
        try:
            # Ensure the directory exists
            baseline_file.parent.mkdir(parents=True, exist_ok=True)

            # Create backup before overwriting existing file
            if baseline_file.exists():
                timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
                backup_path = DEFAULT_BACKUP_PATH_TEMPLATE.format(timestamp=timestamp)
                backup_file = Path(backup_path)
                backup_file.parent.mkdir(parents=True, exist_ok=True)

                # Copy existing content to backup
                import shutil
                shutil.copy2(baseline_file, backup_file)

                logger.info("Created backup of baseline file at %s", backup_file)

            # Update metadata
            data.setdefault("metadata", {})
            data["metadata"]["last_updated"] = datetime.now(timezone.utc).isoformat()
            data["metadata"]["version"] = BASELINE_METADATA_VERSION

            # Write the new baseline
            with open(baseline_file, 'w') as f:
                json.dump(data, f, indent=2)

            # Set secure permissions on the file
            os.chmod(baseline_file, 0o640)  # Owner: read/write, Group: read, Others: none

            logger.info("Successfully saved baseline file to %s", baseline_file)
            return True
        except (IOError, OSError) as e:
            logger.error("Failed to save baseline file %s: %s", baseline_file, e)
            metrics.increment('security.baseline.save_error')
            return False

    @staticmethod
    def _calculate_hash(file_path: Path) -> Optional[str]:
        """
        Calculate the hash of a file.

        Args:
            file_path: Path to the file to hash

        Returns:
            Hex digest of file hash or None if file cannot be read
        """
        try:
            # Validate file size before hashing to prevent memory issues
            max_size = FILE_INTEGRITY_CONSTANTS.get('MAX_FILE_SIZE', 50 * 1024 * 1024)  # Default 50MB
            if file_path.stat().st_size > max_size:
                logger.warning("File too large to hash: %s (%d bytes)", file_path, file_path.stat().st_size)
                return None

            # Read file in chunks and calculate hash
            hasher = hashlib.new(DEFAULT_HASH_ALGORITHM)
            with open(file_path, 'rb') as f:
                chunk = f.read(DEFAULT_HASH_CHUNK_SIZE)
                while chunk:
                    hasher.update(chunk)
                    chunk = f.read(DEFAULT_HASH_CHUNK_SIZE)
            return hasher.hexdigest()
        except (IOError, OSError) as e:
            logger.error("Error hashing file %s: %s", file_path, e)
            return None

    @staticmethod
    def _get_file_severity(file_path: str) -> str:
        """
        Determine the security severity level for a file based on its path.

        Args:
            file_path: Path to the file

        Returns:
            Severity level (critical, high, medium, or low)
        """
        # Default to low severity
        severity = INTEGRITY_SEVERITY_LOW

        # Check against file patterns in order of severity
        for pattern, level in FILE_CHANGE_SEVERITY_MAP.items():
            # Convert glob-like pattern to regex for matching
            import fnmatch
            if fnmatch.fnmatch(file_path, pattern):
                severity = level
                break

        return severity

    @staticmethod
    def check_file_integrity(paths_to_check: Optional[List[str]] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Check files against the integrity baseline.

        Args:
            paths_to_check: Optional list of file paths to check.
                           If None, checks all files in the baseline.

        Returns:
            Tuple of (status, changes) where:
            - status: True if all checked files match the baseline, False otherwise
            - changes: List of changes detected with details
        """
        baseline_data = SecurityService._load_baseline()
        baseline_files = baseline_data.get("files", {})

        changes = []
        overall_status = True

        files_to_check = paths_to_check or list(baseline_files.keys())

        for file_path_str in files_to_check:
            file_path = Path(file_path_str)
            if not file_path.exists():
                # File is missing
                changes.append({
                    'path': file_path_str,
                    'status': 'missing',
                    'baseline_hash': baseline_files.get(file_path_str),
                    'current_hash': None,
                    'severity': SecurityService._get_file_severity(file_path_str)
                })
                overall_status = False
                continue

            # Calculate current hash
            current_hash = SecurityService._calculate_hash(file_path)

            # Check if file is in baseline
            if file_path_str in baseline_files:
                baseline_hash = baseline_files[file_path_str]

                # Compare hashes
                if baseline_hash != current_hash:
                    changes.append({
                        'path': file_path_str,
                        'status': 'changed',
                        'baseline_hash': baseline_hash,
                        'current_hash': current_hash,
                        'severity': SecurityService._get_file_severity(file_path_str)
                    })
                    overall_status = False
            else:
                # New file found
                changes.append({
                    'path': file_path_str,
                    'status': 'new',
                    'baseline_hash': None,
                    'current_hash': current_hash,
                    'severity': SecurityService._get_file_severity(file_path_str)
                })

        return overall_status, changes

    @staticmethod
    def update_baseline(paths_to_update: Optional[List[str]] = None,
                       remove_missing: bool = False,
                       max_updates: int = AUTO_UPDATE_LIMIT) -> Tuple[bool, str]:
        """
        Update the security baseline file.

        Args:
            paths_to_update: Optional list of file paths to calculate hashes for and update/add.
                           If None, re-scans all files currently in the baseline.
            remove_missing: If True and paths_to_update is None, remove entries from the
                          baseline for files that no longer exist.
            max_updates: Maximum number of files to update in one operation (default from constants)

        Returns:
            Tuple of (success, message)
        """
        logger.info(f"Updating security baseline. Paths specified: {bool(paths_to_update)}. Remove missing: {remove_missing}")
        baseline_data = SecurityService._load_baseline()
        baseline_files = baseline_data.get("files", {})
        updated_files_count = 0
        added_files_count = 0
        removed_files_count = 0
        error_count = 0

        # Add update limit check
        if paths_to_update and max_updates and len(paths_to_update) > max_updates:
            logger.warning(f"Too many paths to update ({len(paths_to_update)}), limiting to {max_updates}")
            paths_to_update = paths_to_update[:max_updates]

        target_paths: List[str]
        if paths_to_update is not None:
            # Update only specified paths
            target_paths = paths_to_update
            if remove_missing:
                 logger.warning("remove_missing=True ignored when specific paths are provided.")
                 remove_missing = False # Makes no sense in this context
        else:
            # Re-scan all paths currently in the baseline
            target_paths = list(baseline_files.keys())

        new_baseline_files = baseline_files.copy() # Work on a copy

        for path_str in target_paths:
            filepath = Path(path_str)
            current_hash = SecurityService._calculate_hash(filepath)

            if current_hash is None:
                error_count += 1
                if not filepath.exists():
                    logger.warning("File not found during baseline update: %s", filepath)
                    if remove_missing and path_str in new_baseline_files:
                        # Only remove if re-scanning all baseline files and remove_missing is True
                        del new_baseline_files[path_str]
                        removed_files_count += 1
                        logger.info("Removed missing file from baseline: %s", path_str)
                    elif path_str not in new_baseline_files and paths_to_update is not None:
                         # If adding a specific path that doesn't exist, log error
                         logger.error("Cannot add non-existent file to baseline: %s", path_str)
                    # else: file exists but couldn't be hashed, or not removing missing files
                else:
                    logger.error("Hashing failed for file during baseline update: %s", filepath)
            else:
                if path_str in new_baseline_files:
                    if new_baseline_files[path_str] != current_hash:
                        new_baseline_files[path_str] = current_hash
                        updated_files_count += 1
                        logger.debug("Updated hash for %s", path_str)
                    # else: hash is the same, no update needed
                else:
                    # Path was specified but not in baseline, so add it
                    new_baseline_files[path_str] = current_hash
                    added_files_count += 1
                    logger.info("Added new file to baseline: %s", path_str)

        # Update metadata
        baseline_data["metadata"] = baseline_data.get("metadata", {})
        baseline_data["metadata"]["last_updated_at"] = datetime.now(timezone.utc).isoformat()
        baseline_data["metadata"]["hash_algorithm"] = DEFAULT_HASH_ALGORITHM
        baseline_data["files"] = new_baseline_files

        # Save the updated baseline
        save_success = SecurityService._save_baseline(baseline_data)

        summary_msg = (f"Baseline update summary: {updated_files_count} updated, "
                     f"{added_files_count} added, {removed_files_count} removed, {error_count} errors.")
        logger.info(summary_msg)

        if save_success:
            metrics.increment('security.baseline.update_success')
            log_security_event(
                event_type=getattr(AuditLog, 'EVENT_FILE_INTEGRITY_BASELINE_UPDATED', 'file_integrity_baseline_updated'),
                description="Security baseline updated.",
                severity="info",
                details={"summary": summary_msg}
            )
            return True, f"Baseline updated successfully. {summary_msg}"
        else:
            metrics.increment('security.baseline.update_error')
            log_security_event(
                event_type=getattr(AuditLog, 'EVENT_FILE_INTEGRITY_ERROR', 'file_integrity_error'),
                description="Failed to save updated security baseline.",
                severity="error",
                details={"summary": summary_msg}
            )
            return False, f"Failed to save baseline. {summary_msg}"

    @staticmethod
    def schedule_integrity_check(interval_seconds: int = 3600,
                               callback: Optional[Callable[[bool, List[Dict[str, Any]]], None]] = None) -> bool:
        """
        Schedule periodic integrity checks.

        Args:
            interval_seconds: Time between integrity checks in seconds
            callback: Optional function to call with check results

        Returns:
            bool: True if scheduling was successful
        """
        try:
            # Implementation depends on the scheduling mechanism (e.g., celery, APScheduler)
            # This is a placeholder for the implementation
            logger.info("Scheduled integrity check every %d seconds", interval_seconds)
            return True
        except Exception as e:
            logger.error("Failed to schedule integrity check: %s", e)
            return False

    @staticmethod
    def get_integrity_status() -> Dict[str, Any]:
        """
        Get the current status of the baseline and recent integrity checks.

        Returns:
            Dictionary with integrity status information
        """
        baseline_data = SecurityService._load_baseline()
        files = baseline_data.get("files", {})
        metadata = baseline_data.get("metadata", {})

        return {
            "baseline_exists": bool(files),
            "file_count": len(files),
            "last_updated": metadata.get("last_updated_at"),
            "version": metadata.get("version", "unknown"),
            "hash_algorithm": metadata.get("hash_algorithm", DEFAULT_HASH_ALGORITHM),
            "last_check": getattr(g, 'last_integrity_check', None),
            "status_healthy": getattr(g, 'integrity_status', True)
        }

    @staticmethod
    def get_security_posture() -> Dict[str, Any]:
        """
        Get a summary of the overall security posture.

        Returns:
            Dictionary with security posture information
        """
        return {
            "file_integrity": {
                "status": "healthy" if getattr(g, 'integrity_status', True) else "compromised",
                "last_check": getattr(g, 'last_integrity_check', None),
                "baseline_version": "current" if getattr(g, 'baseline_current', True) else "outdated"
            },
            "vulnerabilities": {
                "critical": 0,  # Placeholder for actual counts
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "compliance": {
                "status": "compliant",  # Placeholder
                "frameworks": ["PCI-DSS", "HIPAA"]  # Placeholder
            }
        }

    @staticmethod
    def run_vulnerability_scan(targets: List[str]) -> str:
        """
        Run a vulnerability scan on the specified targets.

        Args:
            targets: List of targets to scan

        Returns:
            str: ID of the scheduled scan for tracking
        """
        scan_id = f"scan-{int(time.time())}"
        # This would trigger an async scan in a real implementation
        logger.info("Scheduled vulnerability scan %s for targets: %s", scan_id, targets)
        return scan_id


# Simple test harness when run directly
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create test files
    TEMP_DIR = Path("./tmp_test_security")
    TEMP_DIR.mkdir(exist_ok=True)

    BASELINE_FILE = TEMP_DIR / "test_baseline.json"

    FILE1 = TEMP_DIR / "test_file1.txt"
    FILE2 = TEMP_DIR / "test_file2.txt"

    with open(FILE1, 'w') as f:
        f.write("Test file 1 content")

    with open(FILE2, 'w') as f:
        f.write("Test file 2 content")

    logger.info("\n--- Test 1: Update Baseline ---")
    success, msg = SecurityService.update_baseline(paths_to_update=[str(FILE1), str(FILE2)])
    print(f"Baseline Update Status: {success}, Message: {msg}")
    if BASELINE_FILE.exists():
        print(f"Baseline content:\n{BASELINE_FILE.read_text()}")

    logger.info("\n--- Test 2: Integrity Check (Should Pass) ---")
    status, changes = SecurityService.check_file_integrity()
    print(f"Integrity Check Status: {status}")
    print(f"Changes: {changes}")

    logger.info("\n--- Test 3: Modify File ---")
    with open(FILE1, 'w') as f:
        f.write("Modified content")
    print(f"Modified {FILE1}")

    logger.info("\n--- Test 4: Integrity Check (Should Detect Change) ---")
    status, changes = SecurityService.check_file_integrity()
    print(f"Integrity Check Status: {status}")
    print(f"Changes: {changes}")

    logger.info("\n--- Test 5: Update Baseline (Remove Missing) ---")
    success, msg = SecurityService.update_baseline(remove_missing=True) # Re-scan baseline files
    print(f"Baseline Update Status (Remove Missing): {success}, Message: {msg}")
    if BASELINE_FILE.exists():
        print(f"Baseline content after removal:\n{BASELINE_FILE.read_text()}")

    logger.info("\n--- Test 6: Integrity Check After Removal ---")
    status, changes = SecurityService.check_file_integrity() # Should now pass or only show FILE1 change
    print(f"Integrity Check Status (After Removal): {status}")
    print(f"Changes: {changes}")

    logger.info("\n--- Test 7: Update Baseline for Changed File ---")
    success, msg = SecurityService.update_baseline(paths_to_update=[str(FILE1)])
    print(f"Baseline Update Status (Update Changed): {success}, Message: {msg}")
    if BASELINE_FILE.exists():
        print(f"Baseline content after update:\n{BASELINE_FILE.read_text()}")

    logger.info("\n--- Cleanup ---")
    FILE1.unlink(missing_ok=True)
    FILE2.unlink(missing_ok=True)
    BASELINE_FILE.unlink(missing_ok=True)
    try:
        TEMP_DIR.rmdir()
    except:
        pass
