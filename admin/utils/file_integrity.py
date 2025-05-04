"""
File Integrity Monitoring Utilities

This module provides administrative utilities for file integrity verification,
allowing administrators to create and update integrity baselines, verify file
integrity against known-good baselines, and manage file integrity monitoring.

It wraps and extends the core file integrity checking functionality from the
security module to provide a consistent API for administrative tools while
maintaining security controls and proper access logging.
"""

import os
import json
import logging
import hashlib
import time
from typing import Dict, List, Any, Optional, Tuple, Union, Set

# Setup module logging
logger = logging.getLogger(__name__)

# Try to import core security modules
try:
    from core.security.cs_file_integrity import (
        check_critical_file_integrity as core_check_critical_file_integrity,
        update_file_integrity_baseline as core_update_baseline,
        create_file_hash_baseline as core_create_file_hash_baseline,
        detect_file_changes as core_detect_file_changes,
        verify_file_signature as core_verify_file_signature,
        get_last_integrity_status as core_get_last_integrity_status,
        log_file_integrity_event as core_log_file_integrity_event,
        initialize_file_monitoring as core_initialize_file_monitoring,
        calculate_file_hash as core_calculate_file_hash,
        verify_baseline_update as core_verify_baseline_update
    )
    CORE_SECURITY_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Core security module not available: {e}")
    CORE_SECURITY_AVAILABLE = False

# Try to import audit module for administrative events
try:
    from admin.utils.audit_utils import log_admin_action
    AUDIT_UTILS_AVAILABLE = True
except ImportError:
    logger.warning("Admin audit utilities not available")
    AUDIT_UTILS_AVAILABLE = False


def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """
    Calculate cryptographic hash of a file.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use (sha256, sha512, md5)

    Returns:
        str: Hex digest hash value
    """
    if CORE_SECURITY_AVAILABLE:
        return core_calculate_file_hash(file_path, algorithm)

    # Fallback implementation if core module is not available
    hash_functions = {
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
        "md5": hashlib.md5
    }

    hash_func = hash_functions.get(algorithm.lower(), hashlib.sha256)()

    try:
        with open(file_path, 'rb') as f:
            # Read and update hash in chunks for memory efficiency
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except (IOError, OSError) as e:
        logger.error(f"Error calculating hash for {file_path}: {e}")
        raise


def verify_file_integrity(file_path: str, expected_hash: str, algorithm: str = "sha256") -> bool:
    """
    Verify file integrity by comparing with expected hash.

    Args:
        file_path: Path to the file to verify
        expected_hash: Expected hash value
        algorithm: Hash algorithm to use

    Returns:
        bool: True if the file integrity is verified, False otherwise
    """
    try:
        current_hash = calculate_file_hash(file_path, algorithm)
        integrity_verified = current_hash == expected_hash

        # Log the verification result
        if AUDIT_UTILS_AVAILABLE:
            log_admin_action(
                action="verify_file_integrity",
                status="success" if integrity_verified else "failed",
                details={
                    "file_path": file_path,
                    "algorithm": algorithm,
                    "expected_hash": expected_hash,
                    "actual_hash": current_hash,
                    "verified": integrity_verified
                }
            )

        return integrity_verified

    except Exception as e:
        logger.error(f"Error verifying file integrity: {e}")
        if AUDIT_UTILS_AVAILABLE:
            log_admin_action(
                action="verify_file_integrity",
                status="error",
                details={"file_path": file_path, "error": str(e)}
            )
        return False


def check_critical_file_integrity(app=None) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Check integrity of critical system files.

    Performs a comprehensive check of critical system files by comparing
    current hashes with baseline values. Detects unauthorized modifications,
    permission changes, and new files matching critical patterns.

    Args:
        app: Optional Flask application instance

    Returns:
        Tuple containing:
        - bool: True if all critical files are unmodified
        - List[Dict[str, Any]]: Details about integrity violations if any
    """
    if CORE_SECURITY_AVAILABLE:
        result = core_check_critical_file_integrity(app)

        # Log administrative action for the check
        if AUDIT_UTILS_AVAILABLE:
            is_intact, changes = result
            log_admin_action(
                action="check_critical_file_integrity",
                status="success",
                details={
                    "intact": is_intact,
                    "violations_count": len(changes) if not is_intact else 0
                }
            )

        return result

    logger.error("Unable to check file integrity: Core security module not available")
    return False, [{"path": "system", "status": "error", "severity": "high",
                   "details": "Core security module not available"}]


def create_file_hash_baseline(basedir: str, patterns: List[str] = None,
                             output_file: str = None,
                             algorithm: str = "sha256") -> Dict[str, str]:
    """
    Create a baseline of file hashes for integrity monitoring.

    Args:
        basedir: Base directory to scan
        patterns: List of file patterns to include (e.g., ["*.py", "config/*"])
        output_file: Path to save the baseline JSON file
        algorithm: Hash algorithm to use

    Returns:
        Dict[str, str]: Dictionary mapping file paths to their hash values
    """
    if CORE_SECURITY_AVAILABLE:
        baseline = core_create_file_hash_baseline(basedir, patterns, output_file, algorithm)

        if AUDIT_UTILS_AVAILABLE:
            log_admin_action(
                action="create_file_hash_baseline",
                status="success",
                details={
                    "basedir": basedir,
                    "patterns": patterns,
                    "output_file": output_file,
                    "algorithm": algorithm,
                    "files_count": len(baseline)
                }
            )

        return baseline

    logger.error("Unable to create file hash baseline: Core security module not available")
    return {}


def detect_file_changes(basedir: str, reference_hashes: Dict[str, str],
                      critical_patterns: Optional[List[str]] = None,
                      detect_permissions: bool = True,
                      check_signatures: bool = False) -> List[Dict[str, Any]]:
    """
    Detect file changes compared to reference hashes.

    Args:
        basedir: Base directory to check files in
        reference_hashes: Dictionary mapping paths to expected hash values
        critical_patterns: List of glob patterns to match critical files
        detect_permissions: Whether to check for permission changes
        check_signatures: Whether to verify digital signatures on executables

    Returns:
        List of dictionaries containing information about modified files
    """
    if CORE_SECURITY_AVAILABLE:
        changes = core_detect_file_changes(basedir, reference_hashes, critical_patterns,
                                        detect_permissions, check_signatures)

        if AUDIT_UTILS_AVAILABLE and changes:
            log_admin_action(
                action="detect_file_changes",
                status="changes_detected" if changes else "no_changes",
                details={
                    "basedir": basedir,
                    "changes_count": len(changes),
                    "permissions_checked": detect_permissions,
                    "signatures_checked": check_signatures
                }
            )

        return changes

    logger.error("Unable to detect file changes: Core security module not available")
    return [{"path": "system", "status": "error", "severity": "high",
             "details": "Core security module not available"}]


def verify_file_signature(file_path: str) -> bool:
    """
    Verify digital signature of a file.

    Args:
        file_path: Path to the file to verify

    Returns:
        bool: True if signature is valid, False otherwise
    """
    if CORE_SECURITY_AVAILABLE:
        return core_verify_file_signature(file_path)

    logger.error("Unable to verify file signature: Core security module not available")
    return False


def get_last_integrity_status() -> Dict[str, Any]:
    """
    Get the status of the last file integrity check.

    Returns:
        Dictionary containing status information
    """
    if CORE_SECURITY_AVAILABLE:
        return core_get_last_integrity_status()

    logger.error("Unable to get integrity status: Core security module not available")
    return {
        "status": "error",
        "error": "Core security module not available",
        "has_violations": False,
        "last_check": None
    }


def log_file_integrity_event(changes: List[Dict[str, Any]]) -> None:
    """
    Log file integrity violations.

    Args:
        changes: List of file integrity violations to log
    """
    if CORE_SECURITY_AVAILABLE:
        core_log_file_integrity_event(changes)

        # Additionally log as admin action
        if AUDIT_UTILS_AVAILABLE:
            # Count changes by severity
            critical = sum(1 for c in changes if c.get('severity') == 'critical')
            high = sum(1 for c in changes if c.get('severity') == 'high')
            medium = sum(1 for c in changes if c.get('severity') == 'medium')

            log_admin_action(
                action="file_integrity_event",
                status="violation_detected",
                details={
                    "total_changes": len(changes),
                    "critical_severity": critical,
                    "high_severity": high,
                    "medium_severity": medium
                }
            )
    else:
        logger.error("Unable to log file integrity event: Core security module not available")


def initialize_file_monitoring(app, basedir: str = None,
                             patterns: List[str] = None,
                             interval: int = 3600) -> bool:
    """
    Initialize file integrity monitoring.

    Args:
        app: Flask application
        basedir: Base directory to monitor
        patterns: File patterns to monitor
        interval: Check interval in seconds

    Returns:
        bool: True if initialization was successful
    """
    if CORE_SECURITY_AVAILABLE:
        result = core_initialize_file_monitoring(app, basedir, patterns, interval)

        if AUDIT_UTILS_AVAILABLE:
            log_admin_action(
                action="initialize_file_monitoring",
                status="success" if result else "failed",
                details={
                    "basedir": basedir,
                    "patterns": patterns,
                    "interval": interval
                }
            )

        return result

    logger.error("Unable to initialize file monitoring: Core security module not available")
    return False


def update_file_integrity_baseline(
        app=None,
        baseline_path: Optional[str] = None,
        updates: Optional[List[Dict[str, Any]]] = None,
        remove_missing: bool = False) -> bool:
    """
    Update file integrity baseline with new file hashes.

    Args:
        app: Flask application
        baseline_path: Path to the baseline file
        updates: List of updates to apply
        remove_missing: Whether to remove entries for missing files

    Returns:
        bool: True if the baseline was updated successfully
    """
    if CORE_SECURITY_AVAILABLE:
        result = core_update_baseline(app, baseline_path, updates, remove_missing)

        if AUDIT_UTILS_AVAILABLE:
            log_admin_action(
                action="update_file_integrity_baseline",
                status="success" if result else "failed",
                details={
                    "baseline_path": baseline_path,
                    "updates_count": len(updates) if updates else 0,
                    "remove_missing": remove_missing
                }
            )

        return result

    logger.error("Unable to update file integrity baseline: Core security module not available")
    return False


def get_baseline_status(baseline_path: str) -> Dict[str, Any]:
    """
    Get status information about a file integrity baseline.

    Args:
        baseline_path: Path to the baseline file

    Returns:
        Dict: Status information about the baseline
    """
    try:
        if not os.path.exists(baseline_path):
            return {
                "status": "missing",
                "path": baseline_path,
                "exists": False,
                "file_count": 0,
                "last_modified": None
            }

        with open(baseline_path, 'r') as f:
            baseline = json.load(f)

        mtime = os.path.getmtime(baseline_path)
        mtime_dt = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))

        return {
            "status": "available",
            "path": baseline_path,
            "exists": True,
            "file_count": len(baseline),
            "last_modified": mtime_dt
        }

    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Error reading baseline file: {e}")
        return {
            "status": "error",
            "path": baseline_path,
            "exists": os.path.exists(baseline_path),
            "error": str(e)
        }


def validate_baseline_update(file_path: str, current_hash: str,
                          expected_hash: str, max_age: int = 86400) -> bool:
    """
    Validate if a baseline update for a file is acceptable.

    Args:
        file_path: Path to the file
        current_hash: Current hash of the file
        expected_hash: Expected hash from the baseline
        max_age: Maximum allowed file age for auto-updates in seconds

    Returns:
        bool: True if the update is valid
    """
    if CORE_SECURITY_AVAILABLE:
        return core_verify_baseline_update(file_path, current_hash, expected_hash, max_age)

    # Fallback implementation if core module is not available
    try:
        # Skip if file doesn't exist
        if not os.path.exists(file_path):
            return False

        # Skip critical system files
        file_name = os.path.basename(file_path).lower()
        critical_extensions = ['.so', '.dll', '.exe', '.sh', '.key', '.pem', '.env']
        if any(file_name.endswith(ext) for ext in critical_extensions):
            return False

        # Check file modification time
        mtime = os.path.getmtime(file_path)
        if (time.time() - mtime) > max_age:
            # File was modified more than max_age ago, don't update automatically
            return False

        return True

    except Exception as e:
        logger.error(f"Error validating baseline update for {file_path}: {e}")
        return False
