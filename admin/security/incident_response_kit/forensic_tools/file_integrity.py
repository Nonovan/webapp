"""
File Integrity Verification Module for Incident Response Toolkit

This module provides utilities for verifying file integrity during security incidents.
It supports calculating file hashes, comparing against baselines, detecting unauthorized
modifications, and maintaining chain of custody for evidence files.

The module integrates with the broader incident response toolkit and can leverage
core security functionality when available.
"""

import os
import sys
import json
import logging
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Set, Union
from datetime import datetime, timezone

# Configure module logger
logger = logging.getLogger(__name__)

# Determine module path
MODULE_PATH = Path(os.path.dirname(os.path.abspath(__file__)))
TOOLKIT_PATH = MODULE_PATH.parent

# Constants
DEFAULT_HASH_ALGORITHM = "sha256"
SUPPORTED_HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]
DEFAULT_CHUNK_SIZE = 65536  # 64KB chunks for efficient reading

# Try to import core security file integrity functions if available
CORE_SECURITY_AVAILABLE = False
try:
    from core.security.cs_file_integrity import (
        calculate_file_hash as core_calculate_hash,
        verify_file_integrity as core_verify_integrity,
        detect_file_changes as core_detect_changes
    )
    CORE_SECURITY_AVAILABLE = True
    logger.debug("Using core security file integrity functions")
except ImportError:
    logger.debug("Core security file integrity module not available, using local implementations")

# Try to import admin utilities file integrity functions if available
ADMIN_UTILS_AVAILABLE = False
try:
    from admin.utils.file_integrity import (
        calculate_file_hash as admin_calculate_hash,
        verify_file_integrity as admin_verify_integrity,
        detect_file_changes as admin_detect_changes
    )
    ADMIN_UTILS_AVAILABLE = True
    logger.debug("Using admin utilities file integrity functions")
except ImportError:
    logger.debug("Admin utilities file integrity module not available, using local implementations")

# Try to import forensic utilities if available
FORENSIC_UTILS_AVAILABLE = False
try:
    from admin.security.forensics.utils.file_utils import (
        verify_integrity as forensic_verify_integrity,
        calculate_file_hash as forensic_calculate_hash
    )
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
    FORENSIC_UTILS_AVAILABLE = True
    logger.debug("Using forensic utilities for integrity verification")
except ImportError:
    logger.debug("Forensic utilities not available, using local implementations")
    # Define a fallback for forensic logging
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict] = None, level: int = logging.INFO):
        """Fallback implementation of forensic logging."""
        log_msg = f"Forensic Operation: {operation}, Success: {success}"
        if details:
            log_msg += f", Details: {details}"
        logger.log(level, log_msg)

def calculate_file_hash(
    file_path: str,
    algorithm: str = DEFAULT_HASH_ALGORITHM
) -> str:
    """
    Calculate the hash of a file using the specified algorithm.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use (default: sha256)

    Returns:
        Hexadecimal string representation of the file hash

    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If file can't be read
        ValueError: If algorithm is not supported
    """
    if algorithm not in SUPPORTED_HASH_ALGORITHMS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    # Use available implementations in order of preference
    if CORE_SECURITY_AVAILABLE:
        return core_calculate_hash(file_path, algorithm)
    elif ADMIN_UTILS_AVAILABLE:
        return admin_calculate_hash(file_path, algorithm)
    elif FORENSIC_UTILS_AVAILABLE:
        return forensic_calculate_hash(file_path, algorithm)

    # Fallback implementation
    try:
        if algorithm == "md5":
            hash_obj = hashlib.md5()
        elif algorithm == "sha1":
            hash_obj = hashlib.sha1()
        elif algorithm == "sha256":
            hash_obj = hashlib.sha256()
        elif algorithm == "sha512":
            hash_obj = hashlib.sha512()
        else:
            raise ValueError(f"Hash algorithm not implemented: {algorithm}")

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(DEFAULT_CHUNK_SIZE), b""):
                hash_obj.update(chunk)

        return hash_obj.hexdigest()

    except (IOError, OSError) as e:
        logger.error(f"Error calculating hash for {file_path}: {e}")
        raise

def verify_file_integrity(
    file_path: str,
    expected_hash: Optional[str] = None,
    baseline_path: Optional[str] = None,
    algorithm: str = DEFAULT_HASH_ALGORITHM
) -> Dict[str, Any]:
    """
    Verify the integrity of a file by comparing its hash with an expected value.

    Args:
        file_path: Path to the file to verify
        expected_hash: Expected hash value (optional if baseline_path is provided)
        baseline_path: Path to JSON file with baseline hashes (optional if expected_hash is provided)
        algorithm: Hash algorithm to use (default: sha256)

    Returns:
        Dictionary with verification results:
        {
            "verified": bool,
            "file_path": str,
            "current_hash": str,
            "expected_hash": str,
            "algorithm": str,
            "timestamp": str (ISO format),
            "error": str (only if error occurred)
        }

    Example:
        >>> result = verify_file_integrity("/path/to/file", expected_hash="abc123")
        >>> if result["verified"]:
        ...     print("File integrity verified!")
        ... else:
        ...     print(f"Integrity check failed: {result.get('error', '')}")
    """
    result = {
        "verified": False,
        "file_path": file_path,
        "algorithm": algorithm,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    try:
        # Check if file exists
        if not os.path.exists(file_path):
            result["error"] = "File does not exist"
            log_forensic_operation(
                operation="verify_file_integrity",
                success=False,
                details={"file_path": file_path, "error": result["error"]}
            )
            return result

        # Get expected hash from baseline if provided
        if expected_hash is None and baseline_path:
            if not os.path.exists(baseline_path):
                result["error"] = f"Baseline file does not exist: {baseline_path}"
                return result

            try:
                with open(baseline_path, 'r') as f:
                    baseline = json.load(f)

                rel_path = os.path.relpath(file_path, os.path.dirname(baseline_path))
                expected_hash = baseline.get(rel_path)

                if not expected_hash:
                    result["error"] = f"File not found in baseline: {rel_path}"
                    return result

            except (IOError, json.JSONDecodeError) as e:
                result["error"] = f"Error reading baseline file: {str(e)}"
                return result

        # If we still don't have an expected hash, we can't verify
        if not expected_hash:
            result["error"] = "No expected hash provided"
            return result

        # Calculate current hash
        try:
            if FORENSIC_UTILS_AVAILABLE:
                verification_result = forensic_verify_integrity(file_path, expected_hash, algorithm)
                current_hash = forensic_calculate_hash(file_path, algorithm)
                result["verified"] = verification_result
            elif CORE_SECURITY_AVAILABLE:
                current_hash = core_calculate_hash(file_path, algorithm)
                result["verified"] = core_verify_integrity(file_path, expected_hash, algorithm)
            elif ADMIN_UTILS_AVAILABLE:
                current_hash = admin_calculate_hash(file_path, algorithm)
                result["verified"] = admin_verify_integrity(file_path, expected_hash, algorithm)
            else:
                # Use local implementation
                current_hash = calculate_file_hash(file_path, algorithm)
                result["verified"] = (current_hash == expected_hash)
        except Exception as e:
            result["error"] = f"Error calculating hash: {str(e)}"
            log_forensic_operation(
                operation="verify_file_integrity",
                success=False,
                details={"file_path": file_path, "error": str(e)}
            )
            return result

        result["current_hash"] = current_hash
        result["expected_hash"] = expected_hash

        # Log the operation
        log_forensic_operation(
            operation="verify_file_integrity",
            success=result["verified"],
            details={
                "file_path": file_path,
                "current_hash": current_hash,
                "expected_hash": expected_hash,
                "algorithm": algorithm,
                "verified": result["verified"]
            }
        )

        return result

    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
        logger.error(f"Error verifying file integrity for {file_path}: {e}", exc_info=True)
        log_forensic_operation(
            operation="verify_file_integrity",
            success=False,
            details={"file_path": file_path, "error": str(e)}
        )
        return result

def create_file_hash_baseline(
    directory_path: str,
    output_file: str,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None,
    recursive: bool = True,
    algorithm: str = DEFAULT_HASH_ALGORITHM
) -> Dict[str, str]:
    """
    Create a baseline of file hashes for a directory.

    Args:
        directory_path: Path to the directory to baseline
        output_file: Path to save the baseline JSON file
        include_patterns: List of glob patterns to include (default: ["*"])
        exclude_patterns: List of glob patterns to exclude (default: [])
        recursive: Whether to recurse into subdirectories (default: True)
        algorithm: Hash algorithm to use (default: sha256)

    Returns:
        Dictionary mapping relative file paths to their hash values

    Example:
        >>> baseline = create_file_hash_baseline(
        ...     "/path/to/critical/files",
        ...     "/path/to/baseline.json",
        ...     include_patterns=["*.py", "*.config"],
        ...     exclude_patterns=["__pycache__/*", "*.tmp"]
        ... )
    """
    include_patterns = include_patterns or ["*"]
    exclude_patterns = exclude_patterns or []
    baseline = {}

    try:
        directory = Path(directory_path)
        if not directory.exists() or not directory.is_dir():
            logger.error(f"Directory does not exist or is not a directory: {directory_path}")
            return baseline

        # Use glob to get files
        files_to_hash = []
        if recursive:
            for pattern in include_patterns:
                files_to_hash.extend(directory.glob(f"**/{pattern}"))
        else:
            for pattern in include_patterns:
                files_to_hash.extend(directory.glob(pattern))

        # Filter out excluded patterns and directories
        for file_path in files_to_hash:
            if not file_path.is_file():
                continue

            relative_path = file_path.relative_to(directory)
            str_path = str(relative_path)

            # Check if file matches any exclude pattern
            if any(Path(str_path).match(pattern) for pattern in exclude_patterns):
                continue

            try:
                file_hash = calculate_file_hash(str(file_path), algorithm)
                baseline[str_path] = file_hash
                logger.debug(f"Added to baseline: {str_path} - {file_hash}")
            except Exception as e:
                logger.warning(f"Failed to hash file {str_path}: {e}")

        # Save baseline to file
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(baseline, f, indent=2)

        logger.info(f"Created file hash baseline with {len(baseline)} files")
        log_forensic_operation(
            operation="create_file_hash_baseline",
            success=True,
            details={
                "directory_path": directory_path,
                "output_file": output_file,
                "file_count": len(baseline),
                "algorithm": algorithm
            }
        )

        return baseline

    except Exception as e:
        logger.error(f"Error creating file hash baseline: {e}", exc_info=True)
        log_forensic_operation(
            operation="create_file_hash_baseline",
            success=False,
            details={
                "directory_path": directory_path,
                "output_file": output_file,
                "error": str(e)
            }
        )
        return baseline

def detect_file_changes(
    baseline_path: str,
    verify_dir: Optional[str] = None,
    include_added: bool = True,
    include_permissions: bool = True
) -> List[Dict[str, Any]]:
    """
    Detect changes by comparing current files against a baseline.

    Args:
        baseline_path: Path to the baseline JSON file
        verify_dir: Directory to verify (defaults to baseline directory)
        include_added: Whether to report new files not in baseline
        include_permissions: Whether to check file permissions

    Returns:
        List of dictionaries describing detected changes:
        [
            {
                "path": str,
                "status": str ("modified", "missing", "added", "permission_change"),
                "severity": str ("high", "medium", "low"),
                "details": {...}
            },
            ...
        ]
    """
    changes = []

    try:
        # Load baseline
        if not os.path.exists(baseline_path):
            logger.error(f"Baseline file does not exist: {baseline_path}")
            return [{"path": baseline_path, "status": "error", "severity": "high", "details": {"error": "Baseline file not found"}}]

        try:
            with open(baseline_path, 'r') as f:
                baseline = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"Error reading baseline file: {e}")
            return [{"path": baseline_path, "status": "error", "severity": "high", "details": {"error": f"Failed to read baseline: {str(e)}"}}]

        # Determine directory to verify
        if verify_dir is None:
            verify_dir = os.path.dirname(baseline_path)

        # First try to use available implementations
        if CORE_SECURITY_AVAILABLE:
            return core_detect_changes(verify_dir, baseline, None, include_permissions)
        elif ADMIN_UTILS_AVAILABLE:
            return admin_detect_changes(verify_dir, baseline, None, include_permissions)

        # Otherwise use local implementation
        directory = Path(verify_dir)
        if not directory.exists() or not directory.is_dir():
            logger.error(f"Verify directory does not exist: {verify_dir}")
            return [{"path": verify_dir, "status": "error", "severity": "high", "details": {"error": "Directory not found"}}]

        # Track files we've seen
        checked_files = set()

        # Check each file in baseline
        for rel_path, expected_hash in baseline.items():
            file_path = os.path.join(verify_dir, rel_path)
            checked_files.add(rel_path)

            if not os.path.exists(file_path):
                # File is missing
                changes.append({
                    "path": rel_path,
                    "status": "missing",
                    "severity": "high",
                    "details": {
                        "expected_hash": expected_hash
                    }
                })
                continue

            # Verify hash
            current_hash = calculate_file_hash(file_path)
            if current_hash != expected_hash:
                changes.append({
                    "path": rel_path,
                    "status": "modified",
                    "severity": "high",
                    "details": {
                        "expected_hash": expected_hash,
                        "current_hash": current_hash
                    }
                })

            # Check permissions if requested
            if include_permissions:
                try:
                    file_stat = os.stat(file_path)
                    file_mode = file_stat.st_mode

                    # Check for world-writable files
                    if file_mode & 0o002:
                        changes.append({
                            "path": rel_path,
                            "status": "permission_change",
                            "severity": "high",
                            "details": {
                                "permissions": oct(file_mode),
                                "issue": "world_writable"
                            }
                        })
                except OSError as e:
                    logger.warning(f"Could not check permissions for {file_path}: {e}")

        # Find added files if requested
        if include_added:
            for root, _, files in os.walk(verify_dir):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, verify_dir)

                    if rel_path not in checked_files and not rel_path.startswith('.'):
                        # Skip the baseline file itself
                        baseline_filename = os.path.basename(baseline_path)
                        if rel_path == baseline_filename:
                            continue

                        changes.append({
                            "path": rel_path,
                            "status": "added",
                            "severity": "medium",
                            "details": {
                                "current_hash": calculate_file_hash(full_path)
                            }
                        })

        log_forensic_operation(
            operation="detect_file_changes",
            success=True,
            details={
                "baseline_path": baseline_path,
                "verify_dir": verify_dir,
                "changes_detected": len(changes)
            }
        )

        return changes

    except Exception as e:
        logger.error(f"Error detecting file changes: {e}", exc_info=True)
        log_forensic_operation(
            operation="detect_file_changes",
            success=False,
            details={
                "baseline_path": baseline_path,
                "verify_dir": verify_dir,
                "error": str(e)
            }
        )
        return [{"path": "system", "status": "error", "severity": "high", "details": {"error": str(e)}}]

def update_integrity_baseline(
    baseline_path: str,
    updates: List[Dict[str, Any]],
    remove_missing: bool = False
) -> Tuple[bool, str]:
    """
    Update a file integrity baseline with new or modified files.

    Args:
        baseline_path: Path to the baseline JSON file
        updates: List of updates to apply, each update should have:
            {
                "path": str,  # Relative path from baseline directory
                "hash": str,  # New hash value
                "action": str  # "add", "update" or "remove"
            }
        remove_missing: Whether to remove entries for missing files

    Returns:
        Tuple containing:
        - bool: True if update was successful
        - str: Message describing the result
    """
    try:
        # Check if baseline exists
        if not os.path.exists(baseline_path):
            return False, f"Baseline file not found: {baseline_path}"

        # Load current baseline
        try:
            with open(baseline_path, 'r') as f:
                baseline = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            return False, f"Failed to read baseline: {str(e)}"

        # Create backup of baseline
        backup_path = f"{baseline_path}.bak"
        try:
            with open(backup_path, 'w') as f:
                json.dump(baseline, f, indent=2)
        except IOError as e:
            logger.warning(f"Could not create baseline backup: {e}")

        # Track changes
        applied_changes = 0
        removed = 0
        verify_dir = os.path.dirname(baseline_path)

        # Process updates
        for update in updates:
            path = update.get("path")
            if not path:
                logger.warning("Update missing required 'path' field")
                continue

            action = update.get("action", "update")

            if action == "remove":
                if path in baseline:
                    del baseline[path]
                    removed += 1
                    applied_changes += 1
            else:  # add or update
                hash_value = update.get("hash")
                if not hash_value:
                    # If hash not provided, calculate it
                    file_path = os.path.join(verify_dir, path)
                    if not os.path.exists(file_path):
                        logger.warning(f"Cannot add/update non-existent file: {file_path}")
                        continue
                    hash_value = calculate_file_hash(file_path)

                baseline[path] = hash_value
                applied_changes += 1

        # Remove missing files if requested
        if remove_missing:
            to_remove = []
            for path in baseline:
                file_path = os.path.join(verify_dir, path)
                if not os.path.exists(file_path):
                    to_remove.append(path)

            for path in to_remove:
                del baseline[path]
                removed += 1

        # Save updated baseline
        with open(baseline_path, 'w') as f:
            json.dump(baseline, f, indent=2)

        msg = f"Baseline updated: {applied_changes} changes applied, {removed} entries removed"
        log_forensic_operation(
            operation="update_integrity_baseline",
            success=True,
            details={
                "baseline_path": baseline_path,
                "changes_applied": applied_changes,
                "entries_removed": removed
            }
        )

        return True, msg

    except Exception as e:
        logger.error(f"Error updating integrity baseline: {e}", exc_info=True)
        log_forensic_operation(
            operation="update_integrity_baseline",
            success=False,
            details={
                "baseline_path": baseline_path,
                "error": str(e)
            }
        )
        return False, f"Error updating baseline: {str(e)}"

def verify_chain_of_custody(
    evidence_path: str,
    coc_file: Optional[str] = None
) -> Dict[str, Any]:
    """
    Verify the chain of custody for evidence files.

    Args:
        evidence_path: Path to the evidence file or directory
        coc_file: Path to the chain of custody file (default: evidence_path + '.coc.json')

    Returns:
        Dictionary with verification results
    """
    result = {
        "verified": False,
        "evidence_path": evidence_path,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "chain_complete": False
    }

    try:
        # Determine chain of custody file if not provided
        if coc_file is None:
            coc_file = f"{evidence_path}.coc.json"

        # Check if evidence exists
        if not os.path.exists(evidence_path):
            result["error"] = "Evidence not found"
            return result

        # Check if chain of custody file exists
        if not os.path.exists(coc_file):
            result["error"] = "Chain of custody file not found"
            return result

        # Load chain of custody file
        try:
            with open(coc_file, 'r') as f:
                coc_data = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            result["error"] = f"Failed to read chain of custody file: {str(e)}"
            return result

        # Get the chain entries
        chain = coc_data.get("chain", [])
        if not chain:
            result["error"] = "Chain of custody is empty"
            return result

        # Verify each entry in the chain
        prev_hash = None
        prev_timestamp = None
        broken_links = []

        for i, entry in enumerate(chain):
            current_hash = entry.get("hash")
            timestamp = entry.get("timestamp")
            action = entry.get("action")
            analyst = entry.get("analyst")

            # Basic validation of entry
            if not all([current_hash, timestamp, action, analyst]):
                broken_links.append({
                    "index": i,
                    "reason": "Missing required fields"
                })
                continue

            # For first entry, check against current file
            if i == 0:
                if os.path.isfile(evidence_path):
                    # For file, verify hash
                    try:
                        file_hash = calculate_file_hash(evidence_path)
                        if file_hash != current_hash:
                            broken_links.append({
                                "index": i,
                                "reason": "Initial hash mismatch",
                                "expected": current_hash,
                                "found": file_hash
                            })
                    except Exception as e:
                        broken_links.append({
                            "index": i,
                            "reason": f"Failed to hash evidence: {str(e)}"
                        })
                else:
                    # For directory, look for manifest
                    manifest_path = os.path.join(evidence_path, "manifest.json")
                    if os.path.exists(manifest_path):
                        try:
                            manifest_hash = calculate_file_hash(manifest_path)
                            # In this case hash should be of manifest
                            if manifest_hash != current_hash:
                                broken_links.append({
                                    "index": i,
                                    "reason": "Initial manifest hash mismatch",
                                    "expected": current_hash,
                                    "found": manifest_hash
                                })
                        except Exception as e:
                            broken_links.append({
                                "index": i,
                                "reason": f"Failed to hash manifest: {str(e)}"
                            })
                    else:
                        # No manifest to verify
                        broken_links.append({
                            "index": i,
                            "reason": "No manifest.json found for directory evidence"
                        })

            # For subsequent entries, check that timestamps are sequential
            if prev_timestamp and timestamp:
                try:
                    prev_dt = datetime.fromisoformat(prev_timestamp.replace('Z', '+00:00'))
                    current_dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    if current_dt < prev_dt:
                        broken_links.append({
                            "index": i,
                            "reason": "Non-sequential timestamp",
                            "prev_timestamp": prev_timestamp,
                            "current_timestamp": timestamp
                        })
                except (ValueError, TypeError) as e:
                    broken_links.append({
                        "index": i,
                        "reason": f"Invalid timestamp format: {str(e)}"
                    })

            prev_hash = current_hash
            prev_timestamp = timestamp

        # Add results
        result["chain_entries"] = len(chain)
        result["chain_complete"] = len(broken_links) == 0
        result["broken_links"] = broken_links
        result["verified"] = result["chain_complete"]

        log_forensic_operation(
            operation="verify_chain_of_custody",
            success=result["verified"],
            details={
                "evidence_path": evidence_path,
                "coc_file": coc_file,
                "chain_entries": len(chain),
                "broken_links": len(broken_links)
            }
        )

        return result

    except Exception as e:
        logger.error(f"Error verifying chain of custody: {e}", exc_info=True)
        result["error"] = f"Error verifying chain of custody: {str(e)}"
        log_forensic_operation(
            operation="verify_chain_of_custody",
            success=False,
            details={
                "evidence_path": evidence_path,
                "coc_file": coc_file,
                "error": str(e)
            }
        )
        return result
