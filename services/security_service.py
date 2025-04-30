"""
Security Service for Cloud Infrastructure Platform.

This service provides security-related functionalities such as file integrity
monitoring, security baseline management, and potentially other security operations.
It integrates with core security utilities for logging and configuration.
"""

import logging
import os
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

# Attempt to import core security utilities and extensions
try:
    from core.security import log_security_event, generate_secure_hash
    from core.security.cs_utils import get_security_config
    from extensions import metrics
    CORE_SECURITY_AVAILABLE = True
except ImportError:
    CORE_SECURITY_AVAILABLE = False
    # Define dummy functions/classes if core components are missing
    def log_security_event(*args, **kwargs):
        logger.warning("Core security module not available. Skipping security event logging.")
    def generate_secure_hash(filepath: Path, algorithm: str) -> Optional[str]:
        logger.warning("Core security module not available. Using basic hash calculation.")
        try:
            hasher = hashlib.new(algorithm)
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except FileNotFoundError:
            logger.error("File not found during basic hash calculation: %s", filepath)
            return None
        except Exception as e:
            logger.error("Error during basic hash calculation for %s: %s", filepath, e)
            return None
    def get_security_config(key: str, default: Any = None) -> Any:
        logger.warning("Core security module not available. Using default config for %s.", key)
        # Provide minimal defaults based on expected keys
        defaults = {
            'SECURITY_BASELINE_FILE': "instance/security/baseline.json",
            'FILE_HASH_ALGORITHM': "sha256",
            'CRITICAL_FILES_PATTERN': [], # Cannot determine defaults without config
            'FILE_INTEGRITY_CHECK_ENABLED': True,
        }
        return defaults.get(key, default)
    class DummyMetrics:
        def increment(self, *args, **kwargs): pass
    metrics = DummyMetrics()
    # Define AuditLog constants used in logging if not available
    class AuditLog:
        EVENT_FILE_INTEGRITY_FAILED = "file_integrity_failed"
        EVENT_FILE_INTEGRITY_BASELINE_UPDATED = "file_integrity_baseline_updated"
        EVENT_FILE_INTEGRITY_ERROR = "file_integrity_error"


logger = logging.getLogger(__name__)

# Configuration fetched via core utility or defaults
DEFAULT_BASELINE_FILE_PATH = Path(get_security_config('SECURITY_BASELINE_FILE', "instance/security/baseline.json"))
DEFAULT_HASH_ALGORITHM = get_security_config('FILE_HASH_ALGORITHM', "sha256")
FILE_INTEGRITY_ENABLED = get_security_config('FILE_INTEGRITY_CHECK_ENABLED', True)


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
        """Saves the baseline data to the specified JSON file with secure permissions."""
        try:
            # Ensure parent directory exists
            baseline_file.parent.mkdir(parents=True, exist_ok=True)
            # Set secure permissions on directory if newly created (best effort)
            if not baseline_file.parent.exists():
                 try:
                     os.chmod(baseline_file.parent, 0o700) # Owner only access
                 except OSError as chmod_err:
                     logger.warning("Could not set secure permissions on baseline directory %s: %s", baseline_file.parent, chmod_err)

            # Write baseline file
            with open(baseline_file, 'w') as f:
                json.dump(data, f, indent=2)

            # Set secure file permissions (owner read/write only)
            os.chmod(baseline_file, 0o600)
            logger.info("Successfully saved baseline file: %s", baseline_file)
            metrics.increment('security.baseline.save_success')
            return True
        except IOError as e:
            logger.error("Failed to write baseline file %s: %s", baseline_file, e)
            metrics.increment('security.baseline.save_error')
            return False
        except Exception as e:
            logger.error("Unexpected error saving baseline file %s: %s", baseline_file, e)
            metrics.increment('security.baseline.save_error')
            return False

    @staticmethod
    def _calculate_hash(filepath: Path, algorithm: str = DEFAULT_HASH_ALGORITHM) -> Optional[str]:
        """Calculates the hash of a file using the specified algorithm."""
        if not filepath.is_file():
            logger.warning("Cannot calculate hash, path is not a file: %s", filepath)
            return None
        try:
            # Use core utility if available, otherwise fallback
            return generate_secure_hash(filepath, algorithm)
        except Exception as e:
            logger.error("Error calculating hash for %s using %s: %s", filepath, algorithm, e)
            metrics.increment('security.file_integrity.hash_error')
            return None

    @staticmethod
    def check_file_integrity(paths: Optional[List[str]] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Check file integrity against a stored baseline.

        Args:
            paths: Optional list of file paths to check. If None, checks files listed in the baseline.

        Returns:
            Tuple of (integrity_status, changes)
            - integrity_status: True if all checked files match baseline, False otherwise.
            - changes: List of dictionaries detailing discrepancies.
        """
        if not FILE_INTEGRITY_ENABLED:
            logger.info("File integrity check is disabled via configuration.")
            return True, [] # Return as compliant if disabled

        logger.info("Starting file integrity check...")
        baseline_data = SecurityService._load_baseline()
        baseline_files = baseline_data.get("files", {})
        changes: List[Dict[str, Any]] = []
        overall_status = True

        files_to_check: Dict[str, str]
        if paths:
            # Check only specified paths, ensure they exist in baseline
            files_to_check = {p: baseline_files[p] for p in paths if p in baseline_files}
            missing_in_baseline = [p for p in paths if p not in baseline_files]
            if missing_in_baseline:
                logger.warning("Some specified paths not found in baseline: %s", missing_in_baseline)
                # Optionally report these as changes/errors
                for p in missing_in_baseline:
                     changes.append({"path": p, "status": "error", "reason": "Path not found in baseline"})
                     overall_status = False # Consider this a failure
        else:
            # Check all files listed in the baseline
            files_to_check = baseline_files

        if not files_to_check:
             logger.warning("No files specified or found in baseline to check.")
             # If paths were specified but none were in baseline, status is already False
             # If no paths specified and baseline empty, return True (nothing to fail)
             return overall_status, changes

        checked_paths = set()
        for path_str, expected_hash in files_to_check.items():
            filepath = Path(path_str)
            checked_paths.add(path_str)
            current_hash = SecurityService._calculate_hash(filepath)

            if current_hash is None:
                # File might be missing or inaccessible
                if not filepath.exists():
                    logger.warning("File missing: %s", filepath)
                    changes.append({"path": path_str, "status": "missing", "expected_hash": expected_hash})
                    overall_status = False
                    metrics.increment('security.file_integrity.missing')
                else:
                    logger.error("Could not calculate hash for existing file: %s", filepath)
                    changes.append({"path": path_str, "status": "error", "reason": "Hashing failed"})
                    overall_status = False
                    metrics.increment('security.file_integrity.error')
            elif current_hash != expected_hash:
                logger.warning("File changed: %s", filepath)
                changes.append({
                    "path": path_str,
                    "status": "changed",
                    "expected_hash": expected_hash,
                    "actual_hash": current_hash
                })
                overall_status = False
                metrics.increment('security.file_integrity.changed')
            # else: File hash matches, no change needed

        # Check for files in baseline that were expected but not checked (only relevant if 'paths' was specified)
        if paths:
             not_checked = set(baseline_files.keys()) - checked_paths
             # These were implicitly skipped, log if necessary but don't mark as failure unless required
             if not_checked:
                  logger.debug("Files in baseline but not checked (due to specific path request): %s", not_checked)


        if not overall_status:
            logger.warning("File integrity check failed. Changes detected: %d", len(changes))
            metrics.increment('security.file_integrity.failed')
            # Log a security event for the overall failure
            log_security_event(
                event_type=getattr(AuditLog, 'EVENT_FILE_INTEGRITY_FAILED', 'file_integrity_failed'),
                description="File integrity check detected changes or errors.",
                severity="high",
                details={"changes_count": len(changes), "changes_summary": changes[:5]} # Log first 5 changes
            )
        else:
            logger.info("File integrity check passed successfully.")
            metrics.increment('security.file_integrity.success')

        return overall_status, changes

    @staticmethod
    def update_baseline(paths_to_update: Optional[List[str]] = None, remove_missing: bool = False) -> Tuple[bool, str]:
        """
        Update the security baseline file.

        Args:
            paths_to_update: Optional list of file paths to calculate hashes for and update/add.
                             If None, re-scans all files currently in the baseline.
            remove_missing: If True and paths_to_update is None, remove entries from the
                            baseline for files that no longer exist.

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

    # Potential future methods:
    # @staticmethod
    # def get_security_posture() -> Dict[str, Any]:
    #     """Returns an overall security posture summary."""
    #     # Combine results from integrity checks, vulnerability scans, etc.
    #     pass

    # @staticmethod
    # def run_vulnerability_scan(targets: List[str]) -> str:
    #     """Initiates a vulnerability scan."""
    #     # Integrate with scanning tools/APIs
    #     pass


# Example usage (for testing purposes, remove or guard in production)
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger.info("Running SecurityService standalone tests...")

    # Create dummy files for testing
    TEST_DIR = Path("instance/security_test")
    TEST_DIR.mkdir(parents=True, exist_ok=True)
    FILE1 = TEST_DIR / "file1.txt"
    FILE2 = TEST_DIR / "file2.bin"
    FILE_MISSING = TEST_DIR / "missing.txt"
    BASELINE_FILE = TEST_DIR / "test_baseline.json"

    # Override defaults for testing
    DEFAULT_BASELINE_FILE_PATH = BASELINE_FILE
    FILE_INTEGRITY_ENABLED = True

    logger.info("--- Test 1: Initial Baseline Creation ---")
    with open(FILE1, "w") as f: f.write("Initial content")
    with open(FILE2, "wb") as f: f.write(os.urandom(10))
    success, msg = SecurityService.update_baseline(paths_to_update=[str(FILE1), str(FILE2)])
    print(f"Baseline Creation Status: {success}, Message: {msg}")
    if BASELINE_FILE.exists():
        print(f"Baseline content:\n{BASELINE_FILE.read_text()}")
    else:
        print("ERROR: Baseline file was not created.")

    logger.info("\n--- Test 2: Integrity Check (No Changes) ---")
    status, changes = SecurityService.check_file_integrity()
    print(f"Integrity Check Status: {status}")
    print(f"Changes: {changes}")

    logger.info("\n--- Test 3: Integrity Check (File Changed) ---")
    with open(FILE1, "w") as f: f.write("Modified content")
    status, changes = SecurityService.check_file_integrity()
    print(f"Integrity Check Status (Changed): {status}")
    print(f"Changes: {changes}")

    logger.info("\n--- Test 4: Integrity Check (File Missing) ---")
    if FILE2.exists(): FILE2.unlink()
    status, changes = SecurityService.check_file_integrity()
    print(f"Integrity Check Status (Missing): {status}")
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

    logger.info("\n--- Test 8: Final Integrity Check ---")
    status, changes = SecurityService.check_file_integrity() # Should pass now
    print(f"Integrity Check Status (Final): {status}")
    print(f"Changes: {changes}")

    # Cleanup
    # import shutil
    # shutil.rmtree(TEST_DIR)
    # logger.info("Cleanup complete.")
