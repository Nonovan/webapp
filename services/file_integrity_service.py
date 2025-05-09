"""
File Integrity Service for Cloud Infrastructure Platform.

This module provides comprehensive functionality for file integrity baseline management,
including creating, updating, verifying, and exporting baselines with proper security
controls, notifications, and audit logging.
"""

import logging
import os
import shutil
import json
import yaml
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from datetime import datetime, timezone

# Logger setup
logger = logging.getLogger(__name__)

# Try importing required dependencies
try:
    from .service_constants import (
        DEFAULT_HASH_ALGORITHM,
        DEFAULT_BASELINE_FILE_PATH,
        AUTO_UPDATE_LIMIT,
        DEFAULT_BASELINE_BACKUP_COUNT,
        FILE_INTEGRITY_CONSTANTS,
        DEFAULT_BACKUP_PATH_TEMPLATE,
        NOTIFICATION_CATEGORY_INTEGRITY
    )
except ImportError:
    # Set fallback defaults if constants are not available
    logger.warning("Service constants not available, using fallback values")
    DEFAULT_HASH_ALGORITHM = 'sha256'
    DEFAULT_BASELINE_FILE_PATH = 'instance/security/baseline.json'
    AUTO_UPDATE_LIMIT = 10
    DEFAULT_BASELINE_BACKUP_COUNT = 5
    FILE_INTEGRITY_CONSTANTS = {
        'MAX_FILE_SIZE': 50 * 1024 * 1024  # 50 MB
    }
    DEFAULT_BACKUP_PATH_TEMPLATE = 'instance/security/backups/baseline_{timestamp}.json'
    NOTIFICATION_CATEGORY_INTEGRITY = 'integrity'

try:
    from core.metrics import metrics
except ImportError:
    # Create dummy metrics object if unavailable
    logger.debug("Metrics module not available, using dummy implementation")
    class DummyMetrics:
        def increment(self, *args, **kwargs): pass
        def decrement(self, *args, **kwargs): pass
        def gauge(self, *args, **kwargs): pass
    metrics = DummyMetrics()

# Track feature availability
try:
    from .security_service import SecurityService
    SECURITY_SERVICE_AVAILABLE = True
except ImportError:
    logger.warning("SecurityService not available")
    SECURITY_SERVICE_AVAILABLE = False

try:
    from .notification import notification_manager
    NOTIFICATION_MODULE_AVAILABLE = True
except ImportError:
    logger.warning("Notification module not available")
    NOTIFICATION_MODULE_AVAILABLE = False

try:
    from .audit_service import AuditService
    AUDIT_SERVICE_AVAILABLE = True
except ImportError:
    logger.warning("AuditService not available")
    AUDIT_SERVICE_AVAILABLE = False


def update_file_integrity_baseline(
    baseline_path: str,
    updates: List[Dict[str, Any]],
    remove_missing: bool = False,
    notify_stakeholders: bool = True
) -> Tuple[bool, str]:
    """
    Update the file integrity baseline with the specified changes.

    Args:
        baseline_path: Path to baseline file
        updates: List of update dictionaries with path, hash info
        remove_missing: Whether to remove entries for missing files
        notify_stakeholders: Whether to send notifications about the update

    Returns:
        Tuple containing (success, message)
    """
    # Validate inputs
    if not baseline_path or not isinstance(baseline_path, str):
        return False, "Invalid baseline path provided"

    if not updates or not isinstance(updates, list):
        return False, "No updates provided or invalid update format"

    try:
        # Extract paths from update dictionaries
        update_paths = []
        for update in updates:
            if 'path' in update:
                update_paths.append(update['path'])

        # Apply updates to baseline
        baseline_file = Path(baseline_path)

        # Get AuditService if available to log the changes
        audit_service = None
        if AUDIT_SERVICE_AVAILABLE:
            audit_service = AuditService

        # Use SecurityService to update baseline
        if not SECURITY_SERVICE_AVAILABLE:
            return False, "SecurityService not available"

        result = SecurityService.update_baseline(
            paths_to_update=update_paths,
            remove_missing=remove_missing
        )

        success, message = result

        # Send notification if enabled and the operation was successful
        if success and notify_stakeholders and NOTIFICATION_MODULE_AVAILABLE:
            try:
                # Count severities for notification
                severities = {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0
                }

                update_details = {
                    'baseline_path': baseline_path,
                    'update_count': len(updates),
                    'remove_missing': remove_missing
                }

                # Count severity levels
                for update in updates:
                    severity = update.get('severity', 'low')
                    severities[severity] += 1

                update_details['severities'] = severities

                if audit_service:
                    audit_service.log_file_integrity_event(
                        status='success',
                        action='update',
                        changes=updates,
                        details=update_details,
                        severity='info'
                    )

                # Send notification if enabled and there are significant updates
                critical_updates = [u for u in updates if u.get('severity') == 'critical']
                high_severity_updates = [u for u in updates if u.get('severity') == 'high']

                if critical_updates or len(high_severity_updates) >= 3:
                    notification_severity = 'warning' if critical_updates else 'info'

                    notification_manager.send_to_stakeholders(
                        subject="File Integrity Baseline Updated",
                        message=(
                            f"The file integrity baseline has been updated with {len(updates)} changes. "
                            f"This includes {len(critical_updates)} critical and "
                            f"{len(high_severity_updates)} high severity changes."
                        ),
                        category=NOTIFICATION_CATEGORY_INTEGRITY,
                        level=notification_severity,
                        data=update_details
                    )
            except Exception as e:
                logger.warning(f"Failed to send notification for baseline update: {e}")

        return success, message

    except Exception as e:
        logger.error(f"Unexpected error updating file baseline: {str(e)}")
        return False, f"Error: {str(e)}"


def update_file_baseline(
    baseline_path: str,
    updates: Dict[str, str],
    remove_missing: bool = False,
    create_if_missing: bool = False
) -> Tuple[bool, str]:
    """
    Update a file baseline with hash values directly.

    Args:
        baseline_path: Path to the baseline file
        updates: Dictionary mapping file paths to hash values
        remove_missing: Whether to remove entries for missing files
        create_if_missing: Whether to create the baseline if it doesn't exist

    Returns:
        Tuple containing (success, message)
    """
    if not SECURITY_SERVICE_AVAILABLE:
        return False, "SecurityService not available"

    try:
        baseline_file = Path(baseline_path)

        # Handle case where baseline doesn't exist but create_if_missing is True
        if create_if_missing and not baseline_file.exists():
            logger.info(f"Creating new baseline at {baseline_path}")
            baseline_dir = baseline_file.parent
            if not baseline_dir.exists():
                baseline_dir.mkdir(parents=True, exist_ok=True)
                # Set secure permissions on Unix systems
                if os.name == 'posix':
                    try:
                        os.chmod(baseline_dir, 0o750)  # rwxr-x---
                    except OSError:
                        logger.warning(f"Could not set permissions on directory: {baseline_dir}")

            # Create a new baseline with the provided updates
            baseline_data = {
                "files": updates,
                "metadata": {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "last_updated_at": datetime.now(timezone.utc).isoformat(),
                    "hash_algorithm": DEFAULT_HASH_ALGORITHM
                }
            }
            SecurityService._save_baseline(baseline_data, baseline_file)
            return True, f"Created baseline with {len(updates)} entries"

        # Format updates for SecurityService
        paths = list(updates.keys())

        # First update the baseline with the specified paths
        success, message = SecurityService.update_baseline(
            paths_to_update=paths,
            remove_missing=remove_missing
        )

        # If successful and we need to verify hashes match exactly what was provided
        if success and paths:
            # Load the baseline again to ensure consistency
            baseline_data = SecurityService._load_baseline(baseline_file)
            files = baseline_data.get("files", {})

            # Check if hashes match what was requested
            mismatched = [p for p in paths if p in files and files[p] != updates.get(p)]
            if mismatched:
                logger.warning(f"Paths updated but hashes don't match requested values: {mismatched}")

                # Force update hashes to match exactly what was provided
                baseline_data["files"].update(updates)
                save_success = SecurityService._save_baseline(baseline_data, baseline_file)

                if save_success:
                    return True, f"Baseline updated with exact hash values for {len(updates)} files."
                else:
                    return False, "Failed to save baseline with exact hash values."

        return success, message

    except Exception as e:
        logger.error(f"Unexpected error updating file baseline: {str(e)}")
        return False, f"Error: {str(e)}"


def update_file_integrity_baseline_with_notifications(
    baseline_path: str,
    changes: List[Dict[str, Any]],
    remove_missing: bool = False,
    notify: bool = True,
    audit: bool = True,
    severity_threshold: str = 'high',
    update_limit: int = AUTO_UPDATE_LIMIT,
    message: Optional[str] = None
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Update file integrity baseline with enhanced notification and audit capabilities.

    Args:
        baseline_path: Path to baseline file
        changes: List of changes to apply to baseline
        remove_missing: Whether to remove missing files from baseline
        notify: Whether to send notifications about this update
        audit: Whether to log to audit trail
        severity_threshold: Minimum severity to trigger notifications ('low', 'medium', 'high', 'critical')
        update_limit: Maximum number of files to update at once
        message: Optional message to include in notifications and audit logs

    Returns:
        Tuple containing (success, message, stats)
    """
    success = False
    result_message = "Operation not completed"

    # Initialize stats dictionary for tracking operation details
    stats = {
        "baseline_path": baseline_path,
        "changes_requested": len(changes),
        "changes_applied": 0,
        "removed_entries": 0,
        "changes_rejected": 0,
        "critical_changes": 0,
        "high_severity_changes": 0,
        "medium_severity_changes": 0,
        "low_severity_changes": 0,
        "success": False,
        "notification_sent": False,
        "audit_logged": False,
        "duration_ms": 0
    }

    start_time = datetime.now(timezone.utc)

    # Security check: Enforce update limit
    if len(changes) > update_limit:
        result_message = f"Too many changes requested ({len(changes)}). Maximum allowed: {update_limit}"
        logger.warning(result_message)
        stats["changes_rejected"] = len(changes)
        return False, result_message, stats

    try:
        # Validate and categorize the changes by severity
        validated_changes = []
        for change in changes:
            if 'path' not in change:
                logger.warning(f"Skipping change without path: {change}")
                stats["changes_rejected"] += 1
                continue

            # Store severity data for reporting
            severity = change.get('severity', 'low')
            if severity == 'critical':
                stats["critical_changes"] += 1
            elif severity == 'high':
                stats["high_severity_changes"] += 1
            elif severity == 'medium':
                stats["medium_severity_changes"] += 1
            else:
                stats["low_severity_changes"] += 1

            validated_changes.append(change)

        # Log the operation start to audit trail if enabled
        if audit and AUDIT_SERVICE_AVAILABLE:
            try:
                # Determine appropriate audit severity based on change severities
                if stats["critical_changes"] > 0:
                    audit_severity = 'critical'
                elif stats["high_severity_changes"] > 0:
                    audit_severity = 'high'
                else:
                    audit_severity = 'info'

                AuditService.log_file_integrity_event(
                    status='pending',
                    action='update',
                    changes=validated_changes[:5],  # Only include the first 5 to avoid excessive logging
                    details={
                        'baseline_path': baseline_path,
                        'update_count': len(validated_changes),
                        'critical_count': stats["critical_changes"],
                        'high_severity_count': stats["high_severity_changes"],
                        'remove_missing': remove_missing,
                        'message': message
                    },
                    severity=audit_severity
                )
                stats["audit_logged"] = True
            except Exception as e:
                logger.warning(f"Failed to log baseline update start event: {e}")

        # Check if SecurityService is available
        if not SECURITY_SERVICE_AVAILABLE:
            result_message = "SecurityService not available"
            logger.error(result_message)
            return False, result_message, stats

        # First attempt the update using the SecurityService
        result = SecurityService.update_baseline(
            paths_to_update=[change.get('path') for change in validated_changes if 'path' in change],
            remove_missing=remove_missing
        )
        success, result_message = result

        # Update stats based on result
        if success:
            stats["success"] = True
            stats["changes_applied"] = len(validated_changes)

            # If we're removing missing files, try to estimate how many were removed
            if remove_missing:
                # Get the new baseline to compare
                try:
                    baseline_data = SecurityService._load_baseline(Path(baseline_path))
                    new_files = baseline_data.get("files", {})

                    # Estimate by counting paths that were in changes but not in new baseline
                    valid_paths = {change.get('path') for change in validated_changes if 'path' in change}
                    missing = sum(1 for path in valid_paths if path not in new_files)
                    stats["removed_entries"] = missing
                except Exception:
                    # If we can't determine, just use 0
                    pass

            metrics.increment('security.baseline.update_success')

            # Log completion to audit trail
            if audit and AUDIT_SERVICE_AVAILABLE:
                try:
                    AuditService.log_file_integrity_event(
                        status='success',
                        action='update',
                        changes=None,  # Don't duplicate the changes in the completion log
                        details={
                            'baseline_path': baseline_path,
                            'update_count': len(validated_changes),
                            'applied_count': stats["changes_applied"],
                            'removed_count': stats["removed_entries"],
                            'message': message or result_message
                        },
                        severity='info'
                    )
                    stats["audit_logged"] = True
                except Exception as e:
                    logger.warning(f"Failed to log baseline update completion: {e}")

            # Send notification if enabled and there are important changes
            if notify and NOTIFICATION_MODULE_AVAILABLE and callable(getattr(notification_manager, 'send_to_stakeholders', None)):
                # Only notify for changes at or above the severity threshold
                notify_changes = {
                    'critical': stats["critical_changes"] > 0,
                    'high': stats["critical_changes"] > 0 or stats["high_severity_changes"] > 0,
                    'medium': stats["critical_changes"] > 0 or stats["high_severity_changes"] > 0 or stats["medium_severity_changes"] > 0,
                    'low': True  # Always notify on 'low' threshold
                }

                should_notify = notify_changes.get(severity_threshold.lower(), False)

                if should_notify:
                    try:
                        # Determine notification level based on most severe change
                        if stats["critical_changes"] > 0:
                            level = 'critical'
                        elif stats["high_severity_changes"] > 0:
                            level = 'warning'
                        else:
                            level = 'info'

                        notification_manager.send_to_stakeholders(
                            subject="File Integrity Baseline Updated",
                            message=(
                                f"The file integrity baseline has been updated with {stats['changes_applied']} changes. "
                                f"This includes {stats['critical_changes']} critical, {stats['high_severity_changes']} high, "
                                f"and {stats['medium_severity_changes']} medium severity changes."
                                f"{f' {message}' if message else ''}"
                            ),
                            category=NOTIFICATION_CATEGORY_INTEGRITY,
                            level=level,
                            data={
                                'baseline_path': baseline_path,
                                'changes_applied': stats['changes_applied'],
                                'removed_entries': stats['removed_entries'],
                                'critical_changes': stats['critical_changes'],
                                'high_severity_changes': stats['high_severity_changes'],
                                'operation': 'baseline_update'
                            }
                        )
                        stats["notification_sent"] = True
                    except Exception as e:
                        logger.warning(f"Failed to send notification: {e}")
        else:
            # Handle failure case
            metrics.increment('security.baseline.update_error')

            # Log failure to audit trail
            if audit and AUDIT_SERVICE_AVAILABLE:
                try:
                    AuditService.log_file_integrity_event(
                        status='error',
                        action='update',
                        changes=None,
                        details={
                            'baseline_path': baseline_path,
                            'error': result_message,
                            'message': message
                        },
                        severity='warning'
                    )
                    stats["audit_logged"] = True
                except Exception as e:
                    logger.warning(f"Failed to log baseline update failure: {e}")

    except Exception as e:
        result_message = f"Error updating file integrity baseline: {str(e)}"
        logger.error(result_message)
        metrics.increment('security.baseline.update_error')
        success = False

    finally:
        # Calculate duration
        end_time = datetime.now(timezone.utc)
        stats["duration_ms"] = (end_time - start_time).total_seconds() * 1000

    return success, result_message, stats


def verify_baseline_consistency(baseline_path: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
    """
    Verify that a baseline file is consistent and valid.

    Args:
        baseline_path: Path to baseline file, if None uses default

    Returns:
        Tuple containing (is_consistent, details)
    """
    baseline_file = Path(baseline_path) if baseline_path else Path(DEFAULT_BASELINE_FILE_PATH)
    result = {
        'is_consistent': False,
        'errors': [],
        'warnings': [],
        'message': '',
        'baseline_path': str(baseline_file)
    }

    # Check if file exists
    if not baseline_file.exists():
        result['message'] = f"Baseline file not found: {baseline_file}"
        result['errors'].append("Baseline file not found")
        logger.warning(result['message'])
        return False, result

    try:
        # Check if file is readable
        with open(baseline_file, 'r') as f:
            try:
                # Check if content is valid JSON
                data = json.load(f)

                # Check for required keys
                if 'files' not in data:
                    result['errors'].append("Missing 'files' key in baseline")
                    result['message'] = "Invalid baseline format: missing 'files' key"
                    logger.error(result['message'])
                    return False, result

                # Check files section structure
                files = data.get('files', {})
                if not isinstance(files, dict):
                    result['errors'].append("'files' section should be a dictionary")
                    result['message'] = "Invalid baseline format: 'files' should be a dictionary"
                    logger.error(result['message'])
                    return False, result

                # Check file hash entries
                invalid_entries = []
                for file_path, file_hash in files.items():
                    if not isinstance(file_path, str) or not file_path:
                        invalid_entries.append(f"Invalid file path: {file_path}")
                    elif not isinstance(file_hash, str) or not file_hash:
                        invalid_entries.append(f"Invalid hash for {file_path}: {file_hash}")

                if invalid_entries:
                    result['errors'].extend(invalid_entries)
                    result['message'] = f"Invalid entries in baseline file: {len(invalid_entries)} issues found"
                    logger.error(result['message'])
                    return False, result

                # Check metadata section
                metadata = data.get('metadata', {})
                if not isinstance(metadata, dict):
                    result['warnings'].append("'metadata' section should be a dictionary")
                    logger.warning("Baseline metadata section is not a dictionary")
                else:
                    # Check for recommended metadata
                    if 'last_updated_at' not in metadata:
                        result['warnings'].append("Missing 'last_updated_at' in metadata")
                        logger.debug("Baseline is missing 'last_updated_at' timestamp")

                    if 'hash_algorithm' not in metadata:
                        result['warnings'].append("Missing 'hash_algorithm' in metadata")
                        logger.debug("Baseline is missing 'hash_algorithm' information")

                # Check file sizes
                if len(files) == 0:
                    result['warnings'].append("Baseline contains no file entries")
                    logger.warning("Baseline file is empty (contains no file entries)")

                # If we got this far with no errors, it's consistent
                if not result['errors']:
                    result['is_consistent'] = True
                    result['message'] = (
                        f"Baseline is consistent with {len(files)} files"
                        f"{' (warnings: ' + str(len(result['warnings'])) + ')' if result['warnings'] else ''}"
                    )
                    return True, result

                return False, result

            except json.JSONDecodeError as e:
                result['errors'].append(f"Invalid JSON format: {str(e)}")
                result['message'] = f"Baseline file is not valid JSON: {str(e)}"
                logger.error(result['message'])
                return False, result

    except IOError as e:
        result['errors'].append(f"IO Error: {str(e)}")
        result['message'] = f"Cannot read baseline file: {str(e)}"
        logger.error(result['message'])
        return False, result
    except Exception as e:
        result['errors'].append(f"Unexpected error: {str(e)}")
        result['message'] = f"Error verifying baseline consistency: {str(e)}"
        logger.error(result['message'])
        return False, result


def export_baseline(
    baseline_path: Optional[str] = None,
    destination: Optional[str] = None,
    format_type: str = "json"
) -> Tuple[bool, str]:
    """
    Export a baseline file to a specific format.

    Args:
        baseline_path: Source baseline path (uses default if None)
        destination: Destination file path (auto-generated if None)
        format_type: Output format ("json" or "yaml")

    Returns:
        Tuple containing (success, message)
    """
    try:
        # Determine source path
        source_file = Path(baseline_path) if baseline_path else Path(DEFAULT_BASELINE_FILE_PATH)

        if not source_file.exists():
            return False, f"Source baseline file does not exist: {source_file}"

        # Generate destination if not provided
        if destination is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if format_type == "json":
                destination = str(source_file.with_name(f"{source_file.stem}_{timestamp}.json"))
            elif format_type == "yaml":
                destination = str(source_file.with_name(f"{source_file.stem}_{timestamp}.yaml"))
            else:
                return False, f"Unsupported format: {format_type}"

        # Ensure destination directory exists
        dest_path = Path(destination)
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        # Load baseline data
        if not SECURITY_SERVICE_AVAILABLE:
            try:
                # Simple fallback if SecurityService is not available
                with open(source_file, 'r') as f:
                    baseline_data = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                return False, f"Failed to read baseline: {str(e)}"
        else:
            baseline_data = SecurityService._load_baseline(source_file)

        # Handle different export formats
        if format_type == "json":
            with open(dest_path, 'w') as f:
                json.dump(baseline_data, f, indent=2)
            return True, f"Baseline exported to JSON: {destination}"
        elif format_type == "yaml":
            try:
                with open(dest_path, 'w') as f:
                    yaml.safe_dump(baseline_data, f, default_flow_style=False)
                return True, f"Baseline exported to YAML: {destination}"
            except ImportError:
                return False, "YAML module not available. Install PyYAML to use this format."
            except Exception as e:
                return False, f"Failed to export to YAML: {str(e)}"
        else:
            return False, f"Unsupported export format: {format_type}"

    except Exception as e:
        logger.error(f"Error exporting baseline: {str(e)}")
        return False, f"Export failed: {str(e)}"


# Alias for backward compatibility
validate_baseline_consistency = verify_baseline_consistency


__all__ = [
    'update_file_integrity_baseline',
    'update_file_baseline',
    'update_file_integrity_baseline_with_notifications',
    'verify_baseline_consistency',
    'validate_baseline_consistency',
    'export_baseline',
]

# Module initialization
logger.debug(
    f"File integrity service initialized, "
    f"SecurityService available: {SECURITY_SERVICE_AVAILABLE}, "
    f"Notification module available: {NOTIFICATION_MODULE_AVAILABLE}, "
    f"AuditService available: {AUDIT_SERVICE_AVAILABLE}"
)
