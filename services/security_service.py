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
import fnmatch
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple, Callable

# Add imports for service constants
from .service_constants import (
    DEFAULT_HASH_ALGORITHM,
    DEFAULT_BASELINE_FILE_PATH,
    AUTO_UPDATE_LIMIT,
    INTEGRITY_SEVERITY_CRITICAL,
    INTEGRITY_SEVERITY_HIGH,
    INTEGRITY_SEVERITY_MEDIUM,
    INTEGRITY_SEVERITY_LOW,
    FILE_CHANGE_SEVERITY_MAP,
    CRITICAL_FILE_PATTERNS,
    FILE_INTEGRITY_CONSTANTS,
    SCAN_STATUS_PENDING,
    SCAN_TYPE_VULNERABILITY,
    MAX_CONCURRENT_SCANS,
    DEFAULT_SCAN_TIMEOUT
)

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

# Use service constants instead of get_security_config
DEFAULT_BASELINE_FILE_PATH = Path(DEFAULT_BASELINE_FILE_PATH)
FILE_INTEGRITY_ENABLED = True


class SecurityError(Exception):
    """Custom exception for security-related errors."""
    pass


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
            # Use buffer size from constants
            hasher = hashlib.new(algorithm)
            buffer_size = FILE_INTEGRITY_CONSTANTS.get('HASH_BUFFER_SIZE', 65536)

            with open(filepath, 'rb') as f:
                while chunk := f.read(buffer_size):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error("Error calculating hash for %s using %s: %s", filepath, algorithm, e)
            metrics.increment('security.file_integrity.hash_error')
            return None

    @staticmethod
    def verify_file_hash(filepath: str, expected_hash: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Verify the hash of a specific file against baseline or provided hash.

        This method checks the integrity of a specific file by comparing its current
        hash with either a provided hash value or the value stored in the security baseline.

        Args:
            filepath: Path to the file to verify
            expected_hash: Optional expected hash. If None, uses hash from baseline

        Returns:
            Tuple of (match_status, details)
            - match_status: True if hash matches, False otherwise
            - details: Dictionary with verification details
        """
        details = {
            "path": filepath,
            "exists": os.path.exists(filepath),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # If file doesn't exist, return immediately
        if not details["exists"]:
            logger.warning(f"File not found for hash verification: {filepath}")
            details["status"] = "missing"
            metrics.increment('security.file_integrity.missing_file')
            return False, details

        # Calculate current hash of the file
        current_hash = SecurityService._calculate_hash(filepath)
        details["current_hash"] = current_hash

        if current_hash is None:
            details["status"] = "error"
            details["error"] = "Failed to calculate file hash"
            logger.error(f"Failed to calculate hash for file: {filepath}")
            metrics.increment('security.file_integrity.hash_error')
            return False, details

        # If expected hash is not provided, try to get it from baseline
        if expected_hash is None:
            baseline_data = SecurityService._load_baseline()
            baseline_files = baseline_data.get("files", {})

            # Try both absolute and relative paths in baseline
            if filepath in baseline_files:
                expected_hash = baseline_files[filepath]
                details["source"] = "baseline"
            elif os.path.basename(filepath) in baseline_files:
                expected_hash = baseline_files[os.path.basename(filepath)]
                details["source"] = "baseline_basename"
            else:
                details["status"] = "unknown"
                details["error"] = "No baseline entry found for file"
                logger.warning(f"No baseline hash found for file: {filepath}")
                metrics.increment('security.file_integrity.no_baseline')
                return False, details

        details["expected_hash"] = expected_hash
        match_status = current_hash == expected_hash

        if match_status:
            details["status"] = "verified"
            metrics.increment('security.file_integrity.verified')
            logger.debug(f"File integrity verified: {filepath}")
        else:
            details["status"] = "modified"
            logger.warning(f"File integrity check failed for {filepath}: hash mismatch")
            metrics.increment('security.file_integrity.modified')

            # Use service constants for severity mapping
            status = details.get("status", "changed")
            details["severity"] = FILE_CHANGE_SEVERITY_MAP.get(status, INTEGRITY_SEVERITY_MEDIUM)

            # Check critical patterns from service constants
            is_critical = False
            for pattern in CRITICAL_FILE_PATTERNS:
                if fnmatch.fnmatch(filepath, pattern):
                    is_critical = True
                    details["severity"] = INTEGRITY_SEVERITY_CRITICAL
                    break

            # Log security event for critical files
            if is_critical:
                try:
                    log_security_event(
                        event_type=getattr(AuditLog, 'EVENT_FILE_INTEGRITY_FAILED', 'file_integrity_failed'),
                        description=f"Critical file modified: {os.path.basename(filepath)}",
                        severity="high",
                        details={
                            "path": filepath,
                            "expected_hash": expected_hash,
                            "current_hash": current_hash
                        }
                    )
                except Exception as e:
                    logger.error(f"Failed to log security event: {e}")

        return match_status, details

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
    def update_baseline(paths_to_update: Optional[List[str]] = None, remove_missing: bool = False, max_updates: int = AUTO_UPDATE_LIMIT) -> Tuple[bool, str]:
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
        Schedule periodic integrity checks to run at specified intervals.

        This method sets up automated file integrity monitoring by configuring a
        recurring check that runs in the background. It can use either the
        Flask scheduler if available, or fall back to other scheduling mechanisms.

        Args:
            interval_seconds: Time between integrity checks in seconds (default: 1 hour)
            callback: Optional callback function to receive integrity check results.
                     Called with (integrity_status: bool, changes: List[Dict[str, Any]])

        Returns:
            bool: True if scheduling was successful, False otherwise
        """
        logger.info(f"Setting up scheduled integrity check every {interval_seconds} seconds")

        try:
            # Try to access Flask app context if available
            from flask import current_app
            if current_app and hasattr(current_app, 'scheduler'):
                # Use Flask's APScheduler if available
                try:
                    job_id = 'file_integrity_check'

                    # Custom wrapper function to handle the callback
                    def check_and_report():
                        integrity_status, changes = SecurityService.check_file_integrity()
                        if callback and callable(callback):
                            try:
                                callback(integrity_status, changes)
                            except Exception as e:
                                logger.error(f"Error in integrity check callback: {e}")
                        return integrity_status, changes

                    # Add job to scheduler
                    current_app.scheduler.add_job(
                        func=check_and_report,
                        trigger='interval',
                        seconds=interval_seconds,
                        id=job_id,
                        replace_existing=True
                    )

                    logger.info(f"Scheduled integrity check job '{job_id}' successfully")
                    metrics.increment('security.integrity_check.scheduled')
                    return True

                except Exception as e:
                    logger.error(f"Failed to schedule integrity check with Flask scheduler: {e}")
                    metrics.increment('security.integrity_check.schedule_error')

            # If Flask scheduler is not available, try alternate scheduling methods
            try:
                # Try to use APScheduler directly if available
                from apscheduler.schedulers.background import BackgroundScheduler

                # Create a singleton scheduler if it doesn't exist
                if not hasattr(SecurityService, '_integrity_scheduler'):
                    SecurityService._integrity_scheduler = BackgroundScheduler()
                    SecurityService._integrity_scheduler.start()

                # Define the job
                def check_and_report_job():
                    integrity_status, changes = SecurityService.check_file_integrity()
                    if callback and callable(callback):
                        try:
                            callback(integrity_status, changes)
                        except Exception as e:
                            logger.error(f"Error in integrity check callback: {e}")

                # Schedule the job
                job = SecurityService._integrity_scheduler.add_job(
                    check_and_report_job,
                    'interval',
                    seconds=interval_seconds,
                    id='security_integrity_check',
                    replace_existing=True
                )

                logger.info("Scheduled integrity check with background scheduler")
                metrics.increment('security.integrity_check.scheduled')
                return True

            except ImportError:
                logger.warning("Could not schedule integrity check: APScheduler not available")
                return False

        except ImportError:
            logger.warning("Could not access Flask application context for scheduling")
            # Try to use alternate scheduling methods as above
            return False

        except Exception as e:
            logger.error(f"Unexpected error setting up integrity check schedule: {e}")
            metrics.increment('security.integrity_check.schedule_error')
            return False

    @staticmethod
    def get_integrity_status() -> Dict[str, Any]:
        """
        Get the current integrity status of the system.

        Provides comprehensive information about the file integrity monitoring
        system, including last check time, baseline status, monitored files count,
        and any detected changes or security violations.

        Returns:
            Dictionary with integrity status information:
            - last_check_time: DateTime of the last integrity check
            - baseline_status: Status of the baseline file
            - file_count: Number of files monitored
            - changes_detected: Number of changes since last baseline update
            - critical_changes: List of critical file changes
            - baseline_path: Path to the current baseline file
            - monitoring_enabled: Whether file integrity monitoring is enabled
        """
        status = {
            'last_check_time': None,
            'baseline_status': 'unknown',
            'file_count': 0,
            'changes_detected': 0,
            'critical_changes': [],
            'baseline_path': str(DEFAULT_BASELINE_FILE_PATH),
            'monitoring_enabled': FILE_INTEGRITY_ENABLED
        }

        try:
            # Get baseline data to determine file count
            baseline_data = SecurityService._load_baseline()
            baseline_files = baseline_data.get("files", {})
            status['file_count'] = len(baseline_files)

            # Check if baseline file exists and has valid format
            if baseline_files:
                status['baseline_status'] = 'valid'
            elif Path(DEFAULT_BASELINE_FILE_PATH).exists():
                status['baseline_status'] = 'empty'
            else:
                status['baseline_status'] = 'missing'

            # Try to get last check time from metadata
            metadata = baseline_data.get("metadata", {})
            if "last_checked_at" in metadata:
                status['last_check_time'] = metadata.get("last_checked_at")
            elif "last_updated_at" in metadata:
                # Fall back to last update time if check time isn't available
                status['last_check_time'] = metadata.get("last_updated_at")

            # Try to get information about recent changes
            # First check if we can access Redis for more detailed/recent info
            try:
                from extensions import get_redis_client
                redis_client = get_redis_client()
                if redis_client:
                    # Try to get recent integrity check results from cache
                    violations_data = redis_client.get('security:integrity_violations')
                    if violations_data:
                        violations = json.loads(violations_data.decode('utf-8'))
                        status['changes_detected'] = violations.get('total', 0)

                        # Get detailed changes if available
                        changes_data = redis_client.get('security:integrity_changes')
                        if changes_data:
                            changes = json.loads(changes_data.decode('utf-8'))
                            status['critical_changes'] = [c for c in changes if c.get('severity') == 'critical']
            except (ImportError, Exception) as e:
                logger.debug(f"Could not access Redis for integrity status: {e}")

            # If no Redis info, try to do a quick check for changes
            if status['changes_detected'] == 0 and len(status['critical_changes']) == 0:
                # Do a lightweight check (up to 10 critical files only)
                critical_paths = list(baseline_files.keys())[:10]
                _, changes = SecurityService.check_file_integrity(critical_paths)
                if changes:
                    status['changes_detected'] = len(changes)
                    status['critical_changes'] = [c for c in changes if c.get('severity', 'medium') == 'critical']

            return status

        except Exception as e:
            logger.error(f"Error getting integrity status: {e}")
            status['baseline_status'] = 'error'
            status['error_message'] = str(e)
            return status

    @staticmethod
    def get_security_posture() -> Dict[str, Any]:
        """
        Returns an overall security posture summary combining various security metrics.

        Aggregates information from file integrity monitoring, vulnerability scans,
        and other security controls to provide a comprehensive security status.

        Returns:
            Dictionary containing:
            - overall_status: Overall security status (healthy/degraded/critical)
            - integrity_status: File integrity monitoring status
            - vulnerability_status: Latest vulnerability scan results
            - critical_issues: List of critical security issues
            - last_assessment: Timestamp of last full security assessment
            - metrics: Key security metrics and scores
        """
        posture = {
            'overall_status': 'unknown',
            'integrity_status': {},
            'vulnerability_status': {},
            'critical_issues': [],
            'last_assessment': None,
            'metrics': {
                'critical_vulnerabilities': 0,
                'high_vulnerabilities': 0,
                'integrity_violations': 0,
                'security_score': 100
            }
        }

        try:
            # Get file integrity status
            integrity_status = SecurityService.get_integrity_status()
            posture['integrity_status'] = integrity_status

            if integrity_status.get('critical_changes'):
                posture['critical_issues'].extend([
                    {
                        'type': 'integrity_violation',
                        'severity': 'critical',
                        'description': f"Critical file changes detected: {len(integrity_status['critical_changes'])}",
                        'details': integrity_status['critical_changes']
                    }
                ])
                posture['metrics']['integrity_violations'] = len(integrity_status['critical_changes'])

            # Try to get vulnerability data from cache/database
            try:
                from extensions import get_redis_client
                redis_client = get_redis_client()
                if redis_client:
                    vuln_data = redis_client.get('security:vulnerability_summary')
                    if vuln_data:
                        vuln_summary = json.loads(vuln_data.decode('utf-8'))
                        posture['vulnerability_status'] = vuln_summary
                        posture['metrics']['critical_vulnerabilities'] = vuln_summary.get('critical_count', 0)
                        posture['metrics']['high_vulnerabilities'] = vuln_summary.get('high_count', 0)
                        posture['last_assessment'] = vuln_summary.get('last_scan_time')
            except (ImportError, Exception) as e:
                logger.debug(f"Could not access vulnerability data: {e}")

            # Calculate overall security score and status
            score_deductions = {
                'critical_vulnerability': 20,  # -20 points per critical vulnerability
                'high_vulnerability': 10,      # -10 points per high vulnerability
                'integrity_violation': 15      # -15 points per critical integrity violation
            }

            score = 100
            score -= (posture['metrics']['critical_vulnerabilities'] * score_deductions['critical_vulnerability'])
            score -= (posture['metrics']['high_vulnerabilities'] * score_deductions['high_vulnerability'])
            score -= (posture['metrics']['integrity_violations'] * score_deductions['integrity_violation'])
            posture['metrics']['security_score'] = max(0, score)

            # Determine overall status
            if score < 40:
                posture['overall_status'] = 'critical'
            elif score < 70:
                posture['overall_status'] = 'degraded'
            else:
                posture['overall_status'] = 'healthy'

            # Track metrics
            metrics.gauge('security.posture.score', score)
            metrics.gauge('security.critical_issues', len(posture['critical_issues']))

            return posture

        except Exception as e:
            logger.error(f"Error getting security posture: {e}")
            posture['overall_status'] = 'error'
            posture['error_message'] = str(e)
            return posture

    @staticmethod
    def run_vulnerability_scan(targets: List[str]) -> str:
        """
        Initiates a vulnerability scan on specified targets.

        Args:
            targets: List of targets to scan (URLs, IPs, or file paths)

        Returns:
            Scan ID that can be used to track scan progress

        Raises:
            ValueError: If targets list is empty or invalid
            SecurityError: If scan cannot be initiated
        """
        if not targets:
            raise ValueError("No scan targets specified")

        try:
            # Generate unique scan ID
            scan_id = f"scan_{int(datetime.now(timezone.utc).timestamp())}_{os.urandom(4).hex()}"

            # Validate scan limits
            active_scans = 0
            try:
                from extensions import get_redis_client
                redis_client = get_redis_client()
                if redis_client:
                    active_scans = int(redis_client.get('security:active_scans') or 0)
                    if active_scans >= MAX_CONCURRENT_SCANS:
                        raise SecurityError("Maximum concurrent scan limit reached")
                    redis_client.incr('security:active_scans')
            except (ImportError, Exception) as e:
                logger.warning(f"Could not check scan limits: {e}")

            # Log scan initiation
            logger.info(f"Initiating vulnerability scan {scan_id} for {len(targets)} targets")
            metrics.increment('security.scan.initiated')

            # Store scan metadata
            scan_data = {
                'id': scan_id,
                'status': SCAN_STATUS_PENDING,
                'targets': targets,
                'start_time': datetime.now(timezone.utc).isoformat(),
                'scan_type': SCAN_TYPE_VULNERABILITY,
                'profile': 'standard'
            }

            # Store scan data in cache
            if redis_client:
                redis_client.setex(
                    f"scan:{scan_id}",
                    DEFAULT_SCAN_TIMEOUT,
                    json.dumps(scan_data)
                )

            # Log security event
            log_security_event(
                event_type='vulnerability_scan_initiated',
                description=f"Vulnerability scan initiated for {len(targets)} targets",
                severity="info",
                details={'scan_id': scan_id, 'targets': targets}
            )

            # Schedule actual scan execution (implementation depends on scanning infrastructure)
            # This is a placeholder - actual implementation would integrate with scanning tools
            from core.tasks import schedule_task
            schedule_task(
                'security.tasks.run_vulnerability_scan',
                scan_id=scan_id,
                targets=targets,
                timeout=DEFAULT_SCAN_TIMEOUT
            )

            return scan_id

        except Exception as e:
            logger.error(f"Failed to initiate vulnerability scan: {e}")
            metrics.increment('security.scan.failed')
            raise SecurityError(f"Failed to initiate scan: {str(e)}")


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
