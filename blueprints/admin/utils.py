"""
Administrative utilities for the admin blueprint.

This module provides utility functions for administrative operations including
file integrity baseline management, audit logging, configuration validation,
and security operations. These utilities support the secure administrative
interface of the Cloud Infrastructure Platform.

Key features:
- File integrity baseline management
- Configuration validation
- Administrative audit logging
- Secure file operations
- Permission verification
- Backup and recovery utilities
"""

import logging
import os
import json
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Union, Set, Callable

from flask import current_app, g, request, session
from werkzeug.local import LocalProxy

from extensions import db, cache, metrics
from models.security import AuditLog
from core.security import log_security_event

# Initialize logger
logger = logging.getLogger(__name__)

# Constants for file operations
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit for baseline files
BASELINE_UPDATE_BATCH_SIZE = 100
DEFAULT_HASH_ALGORITHM = 'sha256'
AUDIT_RETENTION_DAYS = 90
BASELINE_BACKUP_COUNT = 5

# File integrity functions availability flags
FILE_INTEGRITY_AVAILABLE = False
CORE_SECURITY_AVAILABLE = False

# Try to import core security functions for file integrity
try:
    from core.security.cs_file_integrity import (
        update_file_integrity_baseline as core_update_baseline,
        check_integrity,
        verify_file_integrity,
        calculate_file_hash,
        get_integrity_summary,
        verify_baseline_update
    )
    FILE_INTEGRITY_AVAILABLE = True
    CORE_SECURITY_AVAILABLE = True
    logger.debug("Core security file integrity functions loaded")
except ImportError:
    logger.debug("Core security file integrity functions not available, will use fallbacks")

# Try to import from services if core isn't available
if not FILE_INTEGRITY_AVAILABLE:
    try:
        from services.file_integrity import (
            update_file_integrity_baseline as service_update_baseline,
            check_file_integrity as service_check_integrity,
            calculate_hash as service_calculate_hash
        )
        FILE_INTEGRITY_AVAILABLE = True
        logger.debug("Service-level file integrity functions loaded")
    except ImportError:
        logger.debug("Service-level file integrity functions not available")


def update_file_integrity_baseline(
        paths: Optional[List[str]] = None,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
        reason: Optional[str] = None,
        app=None,
        baseline_path: Optional[str] = None,
        remove_missing: bool = False,
        analyst: Optional[str] = None
) -> Dict[str, Any]:
    """
    Update the file integrity baseline with new file hashes.

    This function updates the file integrity baseline by calculating new hashes
    for the specified files or patterns. It supports both updating existing entries
    and adding new files to the baseline.

    Args:
        paths: List of file or directory paths to process
        include_patterns: List of glob patterns to include
        exclude_patterns: List of glob patterns to exclude
        reason: Reason for the baseline update (for audit)
        app: Flask application instance
        baseline_path: Path to the baseline file (defaults to app config)
        remove_missing: Whether to remove entries for missing files
        analyst: Name of the person performing the update (for audit)

    Returns:
        Dict[str, Any]: Results of the baseline update operation
            {
                'success': bool,
                'message': str,
                'files_processed': int,
                'files_added': int,
                'files_updated': int,
                'files_removed': int,
                'timestamp': str
            }
    """
    if app is None:
        app = current_app

    if baseline_path is None:
        baseline_path = app.config.get('FILE_BASELINE_PATH')
        if not baseline_path:
            error_msg = "No baseline path specified and FILE_BASELINE_PATH not set in app config"
            logger.error(error_msg)
            return {
                'success': False,
                'message': error_msg,
                'files_processed': 0,
                'files_added': 0,
                'files_updated': 0,
                'files_removed': 0,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

    # Generate audit context
    user_id = getattr(g, 'user', {}).get('id') or session.get('user_id')
    ip_address = request.remote_addr if hasattr(request, 'remote_addr') else None
    audit_context = {
        'user_id': user_id,
        'ip_address': ip_address,
        'reason': reason,
        'analyst': analyst,
        'paths': paths,
        'include_patterns': include_patterns,
        'exclude_patterns': exclude_patterns,
        'baseline_path': baseline_path,
        'remove_missing': remove_missing
    }

    # Start metrics timer for baseline update operation
    start_time = time.time()
    metrics.info('admin_file_integrity_baseline_update_start', 1)

    try:
        # Process paths and patterns to generate file list
        file_list = []
        updates = []

        # First try to use core security module if available
        if CORE_SECURITY_AVAILABLE:
            try:
                logger.info(f"Updating file integrity baseline using core security module")

                # Convert paths and patterns to updates format expected by core module
                if paths:
                    for path in paths:
                        # Handle directory vs file
                        if os.path.isdir(path):
                            for root, _, files in os.walk(path):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    if _should_include_file(file_path, include_patterns, exclude_patterns):
                                        file_list.append(file_path)
                        elif os.path.isfile(path):
                            if _should_include_file(path, include_patterns, exclude_patterns):
                                file_list.append(path)

                # Calculate hashes and prepare updates
                for file_path in file_list:
                    try:
                        # Get file hash
                        current_hash = calculate_file_hash(file_path)

                        # Get relative path for the baseline
                        rel_path = os.path.relpath(file_path, os.path.dirname(app.root_path))

                        # Set severity based on file path and type
                        severity = 'medium'  # Default severity
                        if '__init__.py' in file_path or 'routes.py' in file_path:
                            severity = 'high'  # Higher severity for route definitions
                        if any(sec_path in file_path for sec_path in ['security', 'auth', 'admin']):
                            severity = 'high'  # Security-critical files

                        # Add to updates list
                        updates.append({
                            'path': rel_path,
                            'current_hash': current_hash,
                            'severity': severity
                        })
                    except (IOError, OSError) as e:
                        logger.warning(f"Error calculating hash for {file_path}: {e}")

                # Create backup before updating
                _create_baseline_backup(baseline_path)

                # Update baseline
                is_updated = core_update_baseline(
                    app=app,
                    baseline_path=baseline_path,
                    updates=updates,
                    remove_missing=remove_missing
                )

                # Get summary information
                summary = get_integrity_summary()
                result = {
                    'success': bool(is_updated),
                    'message': "Baseline updated successfully" if is_updated else "Failed to update baseline",
                    'files_processed': len(updates),
                    'files_added': summary.get('files_added', 0),
                    'files_updated': summary.get('files_updated', 0),
                    'files_removed': summary.get('files_removed', 0),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }

                # Log the operation
                _log_baseline_operation(result, audit_context)
                return result

            except Exception as e:
                logger.error(f"Error updating baseline with core security module: {e}")
                # Fall through to next method

        # Try service-level update if available
        if not CORE_SECURITY_AVAILABLE and FILE_INTEGRITY_AVAILABLE:
            try:
                logger.info(f"Updating file integrity baseline using service module")

                # Create backup before updating
                _create_baseline_backup(baseline_path)

                # Use the service layer function
                service_result = service_update_baseline(
                    paths=paths or [],
                    include_patterns=include_patterns or [],
                    exclude_patterns=exclude_patterns or [],
                    baseline_path=baseline_path,
                    remove_missing=remove_missing
                )

                # Map to our result format
                result = {
                    'success': service_result.get('success', False),
                    'message': service_result.get('message', ''),
                    'files_processed': service_result.get('files_processed', 0),
                    'files_added': service_result.get('files_added', 0),
                    'files_updated': service_result.get('files_updated', 0),
                    'files_removed': service_result.get('files_removed', 0),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }

                # Log the operation
                _log_baseline_operation(result, audit_context)
                return result

            except Exception as e:
                logger.error(f"Error updating baseline with service module: {e}")
                # Fall through to fallback implementation

        # Fallback implementation (minimal functionality)
        return _fallback_update_baseline(
            paths=paths,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
            baseline_path=baseline_path,
            remove_missing=remove_missing,
            audit_context=audit_context
        )

    except Exception as e:
        error_msg = f"Unexpected error during baseline update: {str(e)}"
        logger.error(error_msg, exc_info=True)

        # Track metrics
        metrics.info('admin_file_integrity_baseline_update_error', 1)

        # Log security event
        log_security_event(
            event_type='file_integrity_baseline_update_error',
            description=f"Error updating file integrity baseline: {str(e)}",
            severity='error',
            user_id=audit_context.get('user_id'),
            ip_address=audit_context.get('ip_address'),
            details={
                'baseline_path': audit_context.get('baseline_path'),
                'error': str(e)
            }
        )

        return {
            'success': False,
            'message': error_msg,
            'files_processed': 0,
            'files_added': 0,
            'files_updated': 0,
            'files_removed': 0,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    finally:
        # Record operation duration
        duration = time.time() - start_time
        metrics.info('admin_file_integrity_baseline_update_duration_seconds', duration)


def check_baseline_status(baseline_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Check the status of the file integrity baseline.

    Args:
        baseline_path: Path to the baseline file (defaults to app config)

    Returns:
        Dict[str, Any]: Status of the baseline
    """
    if baseline_path is None:
        baseline_path = current_app.config.get('FILE_BASELINE_PATH')

    if not baseline_path or not os.path.exists(baseline_path):
        return {
            'status': 'not_found',
            'message': f"Baseline file not found: {baseline_path}",
            'last_modified': None,
            'file_count': 0,
            'size_bytes': 0,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

    try:
        # Get file stats
        stats = os.stat(baseline_path)
        modified_time = datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc)
        size_bytes = stats.st_size

        # Load baseline file to count entries
        with open(baseline_path, 'r') as f:
            baseline = json.load(f)
            file_count = len(baseline)

        # Check for backup files
        backup_path = _get_backup_directory(baseline_path)
        backup_files = []

        if os.path.exists(backup_path):
            for f in os.listdir(backup_path):
                if f.endswith('.json') and 'baseline' in f:
                    backup_file = os.path.join(backup_path, f)
                    backup_files.append({
                        'name': f,
                        'path': backup_file,
                        'size': os.path.getsize(backup_file),
                        'date': datetime.fromtimestamp(os.path.getmtime(backup_file), tz=timezone.utc).isoformat()
                    })

        return {
            'status': 'ok',
            'message': "Baseline file found",
            'last_modified': modified_time.isoformat(),
            'file_count': file_count,
            'size_bytes': size_bytes,
            'backup_count': len(backup_files),
            'backups': backup_files[:5],  # Limit to 5 most recent
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    except (IOError, ValueError, json.JSONDecodeError) as e:
        return {
            'status': 'error',
            'message': f"Error reading baseline file: {str(e)}",
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


def verify_file_integrity(
        paths: Optional[List[str]] = None,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Verify the integrity of files against the baseline.

    Args:
        paths: List of file or directory paths to verify
        include_patterns: List of glob patterns to include
        exclude_patterns: List of glob patterns to exclude

    Returns:
        Dict[str, Any]: Results of the verification
    """
    start_time = time.time()
    metrics.info('admin_file_integrity_verify_start', 1)

    try:
        if CORE_SECURITY_AVAILABLE:
            # Use core security module
            result, violations = check_integrity(
                paths=paths,
                include_patterns=include_patterns,
                exclude_patterns=exclude_patterns
            )

            # Format the response
            return {
                'success': True,
                'status': result,
                'violations_count': len(violations),
                'violations': violations[:10],  # Limit to first 10 violations
                'execution_time': time.time() - start_time,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        elif FILE_INTEGRITY_AVAILABLE:
            # Use service layer function
            service_result = service_check_integrity(
                paths=paths or [],
                include_patterns=include_patterns or [],
                exclude_patterns=exclude_patterns or []
            )

            return {
                'success': True,
                'status': service_result.get('status', False),
                'violations_count': service_result.get('violation_count', 0),
                'violations': service_result.get('violations', [])[:10],
                'execution_time': time.time() - start_time,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        else:
            # Fallback is very limited - just check baseline exists
            baseline_path = current_app.config.get('FILE_BASELINE_PATH')
            if not baseline_path or not os.path.exists(baseline_path):
                return {
                    'success': False,
                    'message': "Baseline file not found",
                    'status': False,
                    'violations_count': 0,
                    'violations': [],
                    'execution_time': time.time() - start_time,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }

            return {
                'success': False,
                'message': "File integrity verification not available",
                'status': None,
                'violations_count': 0,
                'violations': [],
                'execution_time': time.time() - start_time,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    except Exception as e:
        logger.error(f"Error verifying file integrity: {e}", exc_info=True)

        # Track error metric
        metrics.info('admin_file_integrity_verify_error', 1)

        return {
            'success': False,
            'message': f"Error verifying file integrity: {str(e)}",
            'status': False,
            'violations_count': 0,
            'violations': [],
            'execution_time': time.time() - start_time,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    finally:
        # Record operation duration
        duration = time.time() - start_time
        metrics.info('admin_file_integrity_verify_duration_seconds', duration)


def restore_baseline_from_backup(backup_id: str) -> Dict[str, Any]:
    """
    Restore a file integrity baseline from a backup.

    Args:
        backup_id: ID or filename of the backup to restore

    Returns:
        Dict[str, Any]: Result of the restoration
    """
    baseline_path = current_app.config.get('FILE_BASELINE_PATH')
    if not baseline_path:
        return {
            'success': False,
            'message': "No baseline path configured"
        }

    backup_dir = _get_backup_directory(baseline_path)
    backup_file = os.path.join(backup_dir, backup_id)

    if not os.path.exists(backup_file):
        return {
            'success': False,
            'message': f"Backup file not found: {backup_id}"
        }

    try:
        # First, validate backup file
        with open(backup_file, 'r') as f:
            backup_data = json.load(f)

        # Create backup of current baseline before restoring
        _create_baseline_backup(baseline_path, suffix="pre_restore")

        # Copy backup to baseline location
        with open(baseline_path, 'w') as f:
            json.dump(backup_data, f, indent=2)

        # Log the action
        user_id = getattr(g, 'user', {}).get('id') or session.get('user_id')
        log_security_event(
            event_type='file_integrity_baseline_restore',
            description=f"File integrity baseline restored from backup: {backup_id}",
            severity='warning',
            user_id=user_id,
            details={
                'backup_id': backup_id,
                'baseline_path': baseline_path,
                'entry_count': len(backup_data)
            }
        )

        return {
            'success': True,
            'message': f"Baseline restored from backup: {backup_id}",
            'entry_count': len(backup_data),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    except (IOError, ValueError, json.JSONDecodeError) as e:
        logger.error(f"Error restoring baseline from backup: {e}", exc_info=True)
        return {
            'success': False,
            'message': f"Error restoring baseline: {str(e)}",
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


def log_admin_action(
        action: str,
        description: str,
        status: str = 'success',
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log an administrative action with audit trail.

    This function logs administrative actions to both the application log
    and the security audit log for compliance purposes.

    Args:
        action: Type of action being performed (e.g., 'user_create')
        description: Human-readable description of the action
        status: Status of the action ('success' or 'failed')
        user_id: ID of the user performing the action
        details: Additional details about the action
    """
    if user_id is None:
        user_id = getattr(g, 'user', {}).get('id') or session.get('user_id')

    if details is None:
        details = {}

    # Add contextual information
    context = {
        'ip_address': request.remote_addr if hasattr(request, 'remote_addr') else None,
        'user_agent': request.user_agent.string if hasattr(request, 'user_agent') else None,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'request_id': getattr(g, 'request_id', None)
    }

    # Merge details with context
    audit_details = {**details, **context}

    # Determine severity based on status
    severity = 'info' if status == 'success' else 'warning'

    # Log to security event log
    try:
        log_security_event(
            event_type=f"admin_{action}",
            description=description,
            severity=severity,
            user_id=user_id,
            details=audit_details
        )
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")

    # Log to application log
    if status == 'success':
        logger.info(f"Admin action: {description}",
                   extra={'action': action, 'user_id': user_id})
    else:
        logger.warning(f"Admin action failed: {description}",
                      extra={'action': action, 'user_id': user_id})

    # Track metric
    metrics.info('admin_action_total', 1, labels={
        'action': action,
        'status': status
    })


# Helper functions

def _should_include_file(file_path: str, include_patterns: Optional[List[str]],
                        exclude_patterns: Optional[List[str]]) -> bool:
    """
    Check if a file should be included based on patterns.

    Args:
        file_path: Path to the file
        include_patterns: List of glob patterns to include
        exclude_patterns: List of glob patterns to exclude

    Returns:
        bool: True if the file should be included
    """
    import fnmatch

    # Always exclude certain file types
    if any(file_path.endswith(ext) for ext in ['.pyc', '.pyo', '.pyd', '.git', '.svn', '.idea']):
        return False

    # Check exclude patterns first
    if exclude_patterns:
        for pattern in exclude_patterns:
            if pattern and fnmatch.fnmatch(file_path, pattern):
                return False

    # If include patterns specified, file must match at least one
    if include_patterns:
        return any(pattern and fnmatch.fnmatch(file_path, pattern) for pattern in include_patterns)

    # If no include patterns, include all files not excluded
    return True


def _create_baseline_backup(baseline_path: str, suffix: str = None) -> Optional[str]:
    """
    Create a backup of the baseline file.

    Args:
        baseline_path: Path to the baseline file
        suffix: Optional suffix for the backup file name

    Returns:
        Optional[str]: Path to the backup file, or None if backup failed
    """
    if not os.path.exists(baseline_path):
        return None

    # Create backup directory if it doesn't exist
    backup_dir = _get_backup_directory(baseline_path)
    os.makedirs(backup_dir, exist_ok=True)

    # Generate backup filename with timestamp
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    suffix_str = f"_{suffix}" if suffix else ""
    backup_filename = f"baseline_backup_{timestamp}{suffix_str}.json"
    backup_path = os.path.join(backup_dir, backup_filename)

    try:
        # Copy baseline to backup
        with open(baseline_path, 'r') as src, open(backup_path, 'w') as dst:
            dst.write(src.read())

        logger.debug(f"Created baseline backup: {backup_path}")

        # Clean up old backups
        _cleanup_old_backups(backup_dir)

        return backup_path
    except (IOError, OSError) as e:
        logger.error(f"Failed to create baseline backup: {e}")
        return None


def _get_backup_directory(baseline_path: str) -> str:
    """
    Get the backup directory for a baseline file.

    Args:
        baseline_path: Path to the baseline file

    Returns:
        str: Path to the backup directory
    """
    baseline_dir = os.path.dirname(baseline_path)
    backup_dir = os.path.join(baseline_dir, 'backups')
    return backup_dir


def _cleanup_old_backups(backup_dir: str, max_backups: int = BASELINE_BACKUP_COUNT) -> None:
    """
    Clean up old baseline backups, keeping only the most recent ones.

    Args:
        backup_dir: Directory containing backups
        max_backups: Maximum number of backups to keep
    """
    if not os.path.exists(backup_dir):
        return

    # Get all backup files
    backups = []
    for filename in os.listdir(backup_dir):
        if filename.startswith('baseline_backup_') and filename.endswith('.json'):
            full_path = os.path.join(backup_dir, filename)
            backups.append((full_path, os.path.getmtime(full_path)))

    # Sort by modification time (newest first)
    backups.sort(key=lambda x: x[1], reverse=True)

    # Delete older backups beyond the limit
    for backup_path, _ in backups[max_backups:]:
        try:
            os.remove(backup_path)
            logger.debug(f"Deleted old baseline backup: {backup_path}")
        except (IOError, OSError) as e:
            logger.warning(f"Failed to delete old backup {backup_path}: {e}")


def _log_baseline_operation(result: Dict[str, Any], audit_context: Dict[str, Any]) -> None:
    """
    Log a baseline update operation to security logs.

    Args:
        result: Result of the baseline update
        audit_context: Audit context information
    """
    success = result.get('success', False)
    event_type = 'file_integrity_baseline_updated' if success else 'file_integrity_baseline_update_failed'
    description = "File integrity baseline updated successfully" if success else "File integrity baseline update failed"
    severity = 'info' if success else 'warning'

    # Track metrics
    metric_name = 'admin_file_integrity_baseline_update_success' if success else 'admin_file_integrity_baseline_update_failure'
    metrics.info(metric_name, 1)
    metrics.info('admin_file_integrity_baseline_files_processed', result.get('files_processed', 0))

    # Log to security event log
    try:
        log_security_event(
            event_type=event_type,
            description=description,
            severity=severity,
            user_id=audit_context.get('user_id'),
            ip_address=audit_context.get('ip_address'),
            details={
                'baseline_path': audit_context.get('baseline_path'),
                'files_processed': result.get('files_processed', 0),
                'files_added': result.get('files_added', 0),
                'files_updated': result.get('files_updated', 0),
                'files_removed': result.get('files_removed', 0),
                'reason': audit_context.get('reason'),
                'message': result.get('message', '')
            }
        )
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")


def _fallback_update_baseline(
        paths: Optional[List[str]],
        include_patterns: Optional[List[str]],
        exclude_patterns: Optional[List[str]],
        baseline_path: str,
        remove_missing: bool,
        audit_context: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Fallback implementation for baseline updates when core security is unavailable.

    Args:
        paths: List of file or directory paths to process
        include_patterns: List of glob patterns to include
        exclude_patterns: List of glob patterns to exclude
        baseline_path: Path to the baseline file
        remove_missing: Whether to remove entries for missing files
        audit_context: Audit context information

    Returns:
        Dict[str, Any]: Results of the baseline update operation
    """
    logger.info("Using fallback implementation for baseline update")

    # Start with empty result structure
    result = {
        'success': False,
        'message': "",
        'files_processed': 0,
        'files_added': 0,
        'files_updated': 0,
        'files_removed': 0,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }

    try:
        # Try to create backup
        _create_baseline_backup(baseline_path)

        # Load existing baseline or create new one
        baseline = {}
        if os.path.exists(baseline_path):
            try:
                with open(baseline_path, 'r') as f:
                    baseline = json.load(f)
            except (json.JSONDecodeError, IOError, OSError) as e:
                logger.error(f"Error reading baseline file: {e}")
                result['message'] = f"Error reading baseline file: {str(e)}"
                return result

        # Process file list
        file_list = []

        # Process paths
        if paths:
            for path in paths:
                # Handle directory vs file
                if os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            if _should_include_file(file_path, include_patterns, exclude_patterns):
                                file_list.append(file_path)
                elif os.path.isfile(path):
                    if _should_include_file(path, include_patterns, exclude_patterns):
                        file_list.append(path)
                else:
                    logger.warning(f"Path not found: {path}")

        # Process files
        files_added = 0
        files_updated = 0

        for file_path in file_list:
            try:
                # Use basic hash calculation as fallback
                with open(file_path, 'rb') as f:
                    import hashlib
                    file_hash = hashlib.sha256(f.read()).hexdigest()

                # Get relative path for the baseline
                rel_path = os.path.relpath(file_path, os.path.dirname(current_app.root_path))

                # Check if this is an update or add
                if rel_path in baseline:
                    if baseline[rel_path] != file_hash:
                        baseline[rel_path] = file_hash
                        files_updated += 1
                else:
                    baseline[rel_path] = file_hash
                    files_added += 1

                result['files_processed'] += 1
            except (IOError, OSError) as e:
                logger.warning(f"Error processing file {file_path}: {e}")

        # Handle removing missing files
        files_removed = 0
        if remove_missing:
            to_remove = []
            for path in baseline:
                abs_path = os.path.join(os.path.dirname(current_app.root_path), path)
                if not os.path.exists(abs_path):
                    to_remove.append(path)

            for path in to_remove:
                del baseline[path]
                files_removed += 1

        # Save updated baseline
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(baseline_path), exist_ok=True)

            with open(baseline_path, 'w') as f:
                json.dump(baseline, f, indent=2)

            result['success'] = True
            result['message'] = "Baseline updated successfully"
            result['files_added'] = files_added
            result['files_updated'] = files_updated
            result['files_removed'] = files_removed

            logger.info(f"Baseline updated: {files_added} added, {files_updated} updated, {files_removed} removed")
        except (IOError, OSError) as e:
            logger.error(f"Error writing baseline file: {e}")
            result['message'] = f"Error writing baseline file: {str(e)}"

        # Log the operation
        _log_baseline_operation(result, audit_context)
        return result

    except Exception as e:
        logger.error(f"Error in fallback baseline update: {e}", exc_info=True)
        result['message'] = f"Error updating baseline: {str(e)}"
        return result
