"""
File integrity verification functionality.

This module provides functions to verify the integrity of critical files
by comparing current file hashes with reference values, checking for
unauthorized modifications, and validating digital signatures.

Key features:
- File hash verification against known baselines
- Configuration file integrity monitoring
- Critical file integrity checks
- File permission security validation
- Digital signature verification
- Comprehensive change detection
- Security event logging for violations
"""

import os
import glob
import hashlib
import json
import time
import stat
import pwd
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple, Union, Set, Callable

# Flask imports
from flask import current_app, has_app_context

# Cryptography imports
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Internal imports
from models.security import AuditLog
from extensions import db, metrics, get_redis_client
from .cs_audit import log_security_event, log_error, log_warning, log_info, log_debug
from .cs_constants import SECURITY_CONFIG
from services import calculate_file_hash
from core.utils.date_time import utcnow, format_timestamp

# Type definitions
FileMetadata = Dict[str, Any]
ResourceMetrics = Dict[str, Any]
FileChangeInfo = Dict[str, Any]

# Constants
DEFAULT_HASH_ALGORITHM = 'sha256'
SMALL_FILE_THRESHOLD = 10240  # 10KB
EXECUTABLE_PATTERNS = ['*.so', '*.dll', '*.exe', '*.bin', '*.sh']
CRITICAL_FILE_PATTERNS = ['*.py', 'config.*', '.env*', '*.ini', 'requirements.txt', '*.sh', '*.key', '*.pem']
ALLOWED_HIDDEN_FILES = ['.env', '.gitignore', '.dockerignore']
DEFAULT_READ_CHUNK_SIZE = 4096  # 4KB chunks for file reading
SUSPICIOUS_PATTERNS = ['backdoor', 'hack', 'exploit', 'rootkit', 'trojan', 'payload', 'malware']
SENSITIVE_EXTENSIONS = ['.key', '.pem', '.p12', '.pfx', '.keystore', '.jks', '.env', '.secret']

import logging
# Setup module-level logger
logger = logging.getLogger(__name__)

# Missing log_critical function - adding definition for completeness
def log_critical(message: str, *args, **kwargs) -> None:
    """Log a critical message."""
    logger.critical(message, *args, **kwargs)


def detect_file_changes(
        basedir: str,
        reference_hashes: Dict[str, str],
        critical_patterns: Optional[List[str]] = None,
        detect_permissions: bool = True,
        check_signatures: bool = False) -> List[FileChangeInfo]:
    """
    Detect changes in critical files by comparing current hashes with reference hashes.

    This function performs comprehensive file integrity monitoring by:
    1. Checking hash values against known good reference hashes
    2. Detecting recently modified files matching critical patterns
    3. Optionally checking for permission changes on critical files
    4. Optionally verifying digital signatures on executable files

    Args:
        basedir: Base directory to check files in
        reference_hashes: Dictionary mapping paths to expected hash values
        critical_patterns: List of glob patterns to match critical files
        detect_permissions: Whether to check for permission changes
        check_signatures: Whether to verify digital signatures on executables

    Returns:
        List of dictionaries containing information about modified files

    Example:
        changes = detect_file_changes('/app', config['CRITICAL_FILE_HASHES'])
        if changes:
            log_security_event('file_integrity_violation', f"Detected {len(changes)} modified files")
    """
    # Try to use enhanced file integrity module if available
    try:
        from core.security.cs_file_integrity import _detect_file_changes
        return _detect_file_changes(basedir, reference_hashes, critical_patterns, detect_permissions, check_signatures)
    except ImportError:
        # Fall back to local implementation
        pass

    if not os.path.isdir(basedir):
        log_error(f"Base directory does not exist or is not a directory: {basedir}")
        return [{'error': 'Invalid base directory', 'path': basedir, 'timestamp': format_timestamp()}]

    critical_patterns = critical_patterns or CRITICAL_FILE_PATTERNS
    modified_files = []
    permission_cache = {}

    # Start performance tracking
    start_time = time.monotonic()

    # Check files with known hashes
    _check_known_files(reference_hashes, modified_files, permission_cache, detect_permissions)

    # Check modification times of critical files
    _check_critical_files(basedir, critical_patterns, reference_hashes, modified_files)

    # Check digital signatures if requested
    if check_signatures:
        _check_file_signatures(basedir, modified_files)

    # Log performance metrics if monitoring enabled
    elapsed_ms = (time.monotonic() - start_time) * 1000
    if has_app_context() and hasattr(current_app, 'metrics'):
        try:
            current_app.metrics.gauge('file_integrity.check_duration_ms', elapsed_ms)
            current_app.metrics.gauge('file_integrity.files_checked', len(reference_hashes))
            current_app.metrics.gauge('file_integrity.violations', len(modified_files))
        except Exception:
            pass

    return modified_files


def _check_known_files(
        reference_hashes: Dict[str, str],
        modified_files: List[Dict[str, Any]],
        permission_cache: Dict[str, int],
        detect_permissions: bool) -> None:
    """
    Check known files against their reference hashes and permissions.

    Args:
        reference_hashes: Dictionary mapping paths to expected hash values
        modified_files: List to add detected changes to
        permission_cache: Dictionary to store file permissions
        detect_permissions: Whether to check for permission changes
    """
    for filepath, expected_hash in reference_hashes.items():
        if not os.path.exists(filepath):
            modified_files.append({
                'path': filepath,
                'status': 'missing',
                'severity': 'high',
                'timestamp': format_timestamp()
            })
            continue

        try:
            current_hash = calculate_file_hash(filepath)
            if current_hash != expected_hash:
                modified_files.append({
                    'path': filepath,
                    'status': 'modified',
                    'severity': 'high',
                    'old_hash': expected_hash,
                    'new_hash': current_hash,
                    'timestamp': format_timestamp()
                })

            # Check for permission changes if requested
            if detect_permissions:
                _check_file_permissions(filepath, permission_cache, modified_files)

        except (IOError, ValueError, OSError) as e:
            modified_files.append({
                'path': filepath,
                'status': 'access_error',
                'severity': 'medium',
                'error': str(e),
                'timestamp': format_timestamp()
            })


def _check_file_permissions(
        filepath: str,
        permission_cache: Dict[str, int],
        modified_files: List[Dict[str, Any]]) -> None:
    """
    Check file permissions for security issues.

    Args:
        filepath: Path to check
        permission_cache: Dictionary to store file permissions
        modified_files: List to add detected issues to
    """
    try:
        current_mode = os.stat(filepath).st_mode
        # Store permission mode to track changes
        permission_cache[filepath] = current_mode

        # Check if file has unusual permissions
        is_executable = bool(current_mode & stat.S_IXUSR)
        is_world_writable = bool(current_mode & stat.S_IWOTH)
        is_world_readable = bool(current_mode & stat.S_IROTH)
        is_setuid = bool(current_mode & stat.S_ISUID)
        is_setgid = bool(current_mode & stat.S_ISGID)

        # Check for Python scripts with execute permissions
        if filepath.endswith('.py') and is_executable:
            modified_files.append({
                'path': filepath,
                'status': 'executable_script',
                'severity': 'medium',
                'current_mode': oct(current_mode),
                'timestamp': format_timestamp()
            })

        # Check for world-writable files (severe security risk)
        if is_world_writable:
            modified_files.append({
                'path': filepath,
                'status': 'world_writable',
                'severity': 'critical',
                'current_mode': oct(current_mode),
                'timestamp': format_timestamp()
            })

        # Check for setuid/setgid binaries
        if is_setuid or is_setgid:
            modified_files.append({
                'path': filepath,
                'status': 'setuid_setgid',
                'severity': 'high',
                'setuid': is_setuid,
                'setgid': is_setgid,
                'current_mode': oct(current_mode),
                'timestamp': format_timestamp()
            })

        # Check for sensitive files that are world-readable
        if any(filepath.endswith(ext) for ext in SENSITIVE_EXTENSIONS) and is_world_readable:
            modified_files.append({
                'path': filepath,
                'status': 'world_readable_sensitive',
                'severity': 'high',
                'current_mode': oct(current_mode),
                'timestamp': format_timestamp()
            })

    except (IOError, OSError) as e:
        log_error(f"Error checking file permissions for {filepath}: {e}")
        # No need to add to modified_files as the calling function will handle this


def _check_critical_files(
        basedir: str,
        critical_patterns: List[str],
        reference_hashes: Dict[str, str],
        modified_files: List[Dict[str, Any]]) -> None:
    """
    Check critical files for modifications.

    Args:
        basedir: Base directory to check
        critical_patterns: List of glob patterns to match critical files
        reference_hashes: Dictionary of known file hashes
        modified_files: List to add detected changes to
    """
    for pattern in critical_patterns:
        try:
            # Safely join paths and handle path traversal attempts
            pattern_path = os.path.normpath(os.path.join(basedir, pattern))
            if not pattern_path.startswith(os.path.normpath(basedir)):
                log_warning(f"Skipping potentially dangerous path pattern: {pattern}")
                continue

            for filepath in glob.glob(pattern_path, recursive=True):
                # Skip files we've already hashed
                if filepath in reference_hashes:
                    continue

                # Only check files (not directories)
                if os.path.isfile(filepath):
                    _check_critical_file(filepath, modified_files)

        except (IOError, ValueError, OSError) as e:
            log_error(f"Error checking critical files with pattern {pattern}: {e}")


def _check_critical_file(filepath: str, modified_files: List[Dict[str, Any]]) -> None:
    """
    Check a single critical file for security concerns.

    Args:
        filepath: Path to the file to check
        modified_files: List to add detected issues to
    """
    try:
        mtime = os.path.getmtime(filepath)
        mtime_dt = datetime.fromtimestamp(mtime, tz=timezone.utc)

        # Check if modified in last 24 hours
        if (utcnow() - mtime_dt).total_seconds() < 86400:
            # Calculate hash for new/changed file
            current_hash = calculate_file_hash(filepath)

            modified_files.append({
                'path': filepath,
                'status': 'recent_change',
                'severity': 'medium',
                'modified_time': mtime_dt.isoformat(),
                'current_hash': current_hash,
                'timestamp': format_timestamp()
            })

        # Check for hidden files that match our patterns
        basename = os.path.basename(filepath)
        if basename.startswith('.') and basename not in ALLOWED_HIDDEN_FILES:
            modified_files.append({
                'path': filepath,
                'status': 'hidden_file',
                'severity': 'medium',
                'modified_time': mtime_dt.isoformat(),
                'timestamp': format_timestamp()
            })

        # Check for unusual file ownership
        _check_file_ownership(filepath, modified_files)

        # Check for suspicious filenames
        file_name = os.path.basename(filepath).lower()
        if any(pattern in file_name for pattern in SUSPICIOUS_PATTERNS):
            modified_files.append({
                'path': filepath,
                'status': 'suspicious_filename',
                'severity': 'high',
                'modified_time': mtime_dt.isoformat(),
                'timestamp': format_timestamp()
            })

    except (IOError, ValueError, OSError) as e:
        modified_files.append({
            'path': filepath,
            'status': 'access_error',
            'error': str(e),
            'timestamp': format_timestamp()
        })


def _check_file_ownership(filepath: str, modified_files: List[Dict[str, Any]]) -> None:
    """
    Check file ownership for security concerns.

    Args:
        filepath: Path to the file to check
        modified_files: List to add detected issues to
    """
    try:
        stat_info = os.stat(filepath)
        try:
            # Try to get the owner name (Unix-specific)
            owner = pwd.getpwuid(stat_info.st_uid).pw_name

            # Get expected owner from environment or config
            expected_owner = None
            if has_app_context():
                expected_owner = current_app.config.get('EXPECTED_FILE_OWNER')
            if not expected_owner:
                expected_owner = os.environ.get('EXPECTED_FILE_OWNER')

            # Check for unexpected ownership on security-sensitive files
            security_sensitive = any(filepath.endswith(ext) for ext in
                                    ['.py', '.env', 'config.py', '.sh'] + SENSITIVE_EXTENSIONS)
            if expected_owner and owner != expected_owner and security_sensitive:
                modified_files.append({
                    'path': filepath,
                    'status': 'unexpected_owner',
                    'severity': 'medium',
                    'owner': owner,
                    'expected_owner': expected_owner,
                    'timestamp': format_timestamp()
                })
        except (KeyError, ImportError):
            # pwd module not available or owner lookup failed
            pass

    except (IOError, OSError) as e:
        log_error(f"Error checking file ownership for {filepath}: {e}")


def _check_file_signatures(basedir: str, modified_files: List[Dict[str, Any]]) -> None:
    """
    Check digital signatures of executable files.

    Args:
        basedir: Base directory to check
        modified_files: List to add detected issues to
    """
    for pattern in EXECUTABLE_PATTERNS:
        try:
            # Use recursive glob to find all matching files in subdirectories
            for filepath in glob.glob(os.path.join(basedir, '**', pattern), recursive=True):
                if not verify_file_signature(filepath):
                    modified_files.append({
                        'path': filepath,
                        'status': 'invalid_signature',
                        'severity': 'critical',
                        'timestamp': format_timestamp()
                    })
        except (IOError, ValueError, OSError) as e:
            log_error(f"Error checking file signatures for pattern {pattern}: {e}")


def verify_file_signature(filepath: str) -> bool:
    """
    Verify the digital signature of a file if supported on the platform.

    Args:
        filepath: Path to the file to verify

    Returns:
        bool: True if signature is valid or verification not supported,
              False if signature is invalid
    """
    # Try using enhanced file signature verification if available
    try:
        from core.security.cs_file_integrity import verify_file_signature as verify_signature
        return verify_signature(filepath)
    except ImportError:
        # Fall back to basic implementation
        pass

    log_info(f"Verifying file signature for: {filepath}")

    # This is a placeholder implementation that should be replaced with
    # platform-specific signature verification code.
    try:
        # Platform-specific signature checking
        import platform
        system = platform.system()

        if system == 'Windows':
            # Windows signature verification - would use ctypes to call WinVerifyTrust
            # Example implementation would go here
            return True
        elif system == 'Darwin':  # macOS
            # macOS signature verification - would use Security framework
            # Example implementation would go here
            return True
        else:  # Linux or other platforms
            # Could use GPG or other verification methods
            # Example implementation would go here
            return True
    except (OSError, ValueError, ImportError):
        # If verification fails or is not supported, assume valid
        # to prevent false positives in environments without signature verification
        return True


def verify_file_integrity(file_path: str, expected_hash: str, algorithm: str = None) -> Dict[str, Any]:
    """
    Verify the integrity of a file by comparing its hash with an expected value.

    Extended version of check_file_integrity that returns more detailed results
    for compatibility with incident response toolkit.

    Args:
        file_path: Path to the file to verify
        expected_hash: Expected hash value to compare against
        algorithm: Hash algorithm to use (default: based on security config)

    Returns:
        Dict with verification results containing:
        - verified: bool - True if integrity check passed
        - file_path: str - Path that was checked
        - current_hash: str - Calculated hash of the file
        - expected_hash: str - Hash that was expected
        - algorithm: str - Algorithm that was used
        - timestamp: str - ISO format timestamp when check was performed
        - error: str - Any error that occurred (only present if there was an error)
    """
    result = {
        "verified": False,
        "file_path": file_path,
        "expected_hash": expected_hash,
        "timestamp": format_timestamp()
    }

    if not os.path.exists(file_path):
        result["error"] = "File does not exist"
        log_warning(f"File does not exist: {file_path}")
        return result

    try:
        # Use default hash algorithm from SECURITY_CONFIG if none specified
        if algorithm is None and has_app_context():
            algorithm = current_app.config.get(
                'FILE_HASH_ALGORITHM',
                SECURITY_CONFIG.get('FILE_HASH_ALGORITHM', 'sha256')
            )
        elif algorithm is None:
            algorithm = DEFAULT_HASH_ALGORITHM

        result["algorithm"] = algorithm
        current_hash = calculate_file_hash(file_path, algorithm)
        result["current_hash"] = current_hash
        result["verified"] = current_hash == expected_hash

        if not result["verified"]:
            log_warning(f"File integrity check failed for {file_path}")
            metrics.increment('security.file_integrity.failed')
        else:
            log_info(f"File integrity verified for {file_path}")
            metrics.increment('security.file_integrity.passed')

        return result

    except (IOError, OSError) as e:
        result["error"] = f"Error reading file: {str(e)}"
        log_error(f"Error checking file integrity for {file_path}: {e}")
        metrics.increment('security.file_integrity.error')
        return result

    except ValueError as e:
        result["error"] = f"Invalid hash algorithm '{algorithm}': {str(e)}"
        log_error(f"Invalid hash algorithm '{algorithm}' for {file_path}: {e}")
        metrics.increment('security.file_integrity.algorithm_error')
        return result

    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
        log_error(f"Unexpected error in verify_file_integrity for {file_path}: {e}")
        return result


def log_file_integrity_event(changes: List[Dict[str, Any]]) -> None:
    """
    Log file integrity violations to both the application log and audit log.

    Args:
        changes: List of detected file changes from detect_file_changes()
    """
    if not changes:
        return

    # Try to use the enhanced security module
    try:
        from core.security.cs_audit import log_security_event
        from core.security.cs_file_integrity import log_integrity_violations

        # Use the new centralized function if available
        log_integrity_violations(changes)
        return
    except ImportError:
        # Fall back to legacy implementation
        pass

    try:
        from models.audit_log import AuditLog
        from core.cs_audit import log_security_event
    except ImportError:
        try:
            from models.security.audit_log import AuditLog
            from core.security_utils import log_security_event
        except ImportError:
            # Define constants if imports fail
            class AuditLog:
                EVENT_FILE_INTEGRITY = 'file_integrity'
                SEVERITY_CRITICAL = 'critical'
                SEVERITY_ERROR = 'error'
                SEVERITY_WARNING = 'warning'
                SEVERITY_INFO = 'info'

            # Define a local function if needed
            def log_security_event(event_type, description, severity, **kwargs):
                log_info(f"Security event: {description}")

    # Group changes by severity
    critical = [c for c in changes if c.get('severity') == 'critical']
    high = [c for c in changes if c.get('severity') == 'high']
    medium = [c for c in changes if c.get('severity') == 'medium']
    low = [c for c in changes if c.get('severity', '').lower() not in ('critical', 'high', 'medium')]

    # Determine overall severity
    if critical:
        severity = AuditLog.SEVERITY_CRITICAL
        log_level = 'critical'
    elif high:
        severity = AuditLog.SEVERITY_ERROR
        log_level = 'error'
    elif medium:
        severity = AuditLog.SEVERITY_WARNING
        log_level = 'warning'
    else:
        severity = AuditLog.SEVERITY_INFO
        log_level = 'info'

    # Create summary
    summary = f"File integrity violations detected: {len(critical)} critical, {len(high)} high, {len(medium)} medium, {len(low)} low"

    # Log to application log
    if log_level == 'critical':
        log_critical(summary)
    elif log_level == 'error':
        log_error(summary)
    elif log_level == 'warning':
        log_warning(summary)
    else:
        log_info(summary)

    # Track metrics if available
    if has_app_context() and hasattr(current_app, 'metrics'):
        try:
            current_app.metrics.gauge('security.integrity_violations.total', len(changes))
            current_app.metrics.gauge('security.integrity_violations.critical', len(critical))
            current_app.metrics.gauge('security.integrity_violations.high', len(high))
            current_app.metrics.gauge('security.integrity_violations.medium', len(medium))
        except Exception:
            pass

    # Log detailed information for each changed file
    for change in changes:
        path = change.get('path', 'unknown')
        status = change.get('status', 'unknown')
        change_severity = change.get('severity', 'unknown')

        # Create audit log entry
        try:
            log_security_event(
                event_type=AuditLog.EVENT_FILE_INTEGRITY,
                description=f"File integrity violation: {path} ({status})",
                severity=severity,
                details={
                    "file": path,
                    "status": status,
                    "severity": change_severity,
                    "timestamp": change.get('timestamp', format_timestamp())
                }
            )
        except Exception as e:
            log_error(f"Failed to create audit log for file integrity event: {e}")


def get_critical_file_hashes(files: List[str], algorithm: str = DEFAULT_HASH_ALGORITHM) -> Dict[str, str]:
    """
    Generate hash dictionary for critical application files.

    Used to create reference hashes for integrity checking.

    Args:
        files: List of file paths to hash
        algorithm: Hash algorithm to use (default: sha256)

    Returns:
        Dictionary mapping file paths to their hash values
    """
    try:
        # Try importing from the enhanced security module first
        from core.security.cs_audit import log_security_event
    except ImportError:
        # Fall back to legacy import if needed
        # Define a local function if neither is available
        def log_security_event(event_type, description, severity, **kwargs):
                log_info(f"Security event: {description}")

    # Try to import AuditLog class for event constants
    try:
        from models.security import AuditLog
        EVENT_FILE_INTEGRITY = getattr(AuditLog, 'EVENT_FILE_INTEGRITY', 'file_integrity')
        SEVERITY_INFO = getattr(AuditLog, 'SEVERITY_INFO', 'info')
        SEVERITY_WARNING = getattr(AuditLog, 'SEVERITY_WARNING', 'warning')
    except ImportError:
        # Define constants if class not available
        EVENT_FILE_INTEGRITY = 'file_integrity'
        SEVERITY_INFO = 'info'
        SEVERITY_WARNING = 'warning'

    hashes = {}

    # Track any errors for comprehensive reporting
    errors = []

    for file_path in files:
        # Normalize the path for consistency
        normalized_path = os.path.normpath(file_path)

        if not os.path.exists(normalized_path):
            log_warning(f"File not found for hashing: {normalized_path}")
            errors.append(f"File not found: {normalized_path}")
            continue

        try:
            file_hash = calculate_file_hash(normalized_path, algorithm)
            hashes[normalized_path] = file_hash

            # Check if this is a security-critical file
            if has_app_context() and current_app.config.get('SECURITY_CHECK_FILE_INTEGRITY'):
                critical_files = current_app.config.get('SECURITY_CRITICAL_FILES', [])
                if normalized_path in critical_files:
                    # Log the hash calculation for audit purposes
                    log_security_event(
                        event_type=EVENT_FILE_INTEGRITY,
                        description=f"Integrity hash calculated for critical file: {normalized_path}",
                        severity=SEVERITY_INFO,
                        details={
                            "algorithm": algorithm,
                            "hash": file_hash[:8] + "...",
                            "timestamp": format_timestamp(),
                            "path": normalized_path
                        }
                    )
        except (IOError, ValueError, PermissionError) as e:
            error_msg = f"Failed to hash {normalized_path}: {str(e)}"
            log_error(error_msg)
            errors.append(error_msg)
            hashes[normalized_path] = None

            # Log file access errors for security-critical files
            if has_app_context() and current_app.config.get('SECURITY_CHECK_FILE_INTEGRITY'):
                critical_files = current_app.config.get('SECURITY_CRITICAL_FILES', [])
                if normalized_path in critical_files:
                    log_security_event(
                        event_type=EVENT_FILE_INTEGRITY,
                        description=f"Failed to verify integrity of critical file: {normalized_path}",
                        severity=SEVERITY_WARNING,
                        details={
                            "error": str(e),
                            "path": normalized_path,
                            "timestamp": format_timestamp()
                        }
                    )

    # Log a summary if there were errors
    if errors and len(errors) > 0:
        log_warning(f"Completed file hash generation with {len(errors)} errors")

        # Record metrics if available
        if has_app_context() and hasattr(current_app, 'metrics'):
            try:
                current_app.metrics.gauge('security.file_hash_errors', len(errors))
            except Exception:
                pass

    return hashes


def update_file_integrity_baseline(
    reference_file: str,
    updates: Dict[str, str],
    remove_missing: bool = False
) -> Tuple[bool, str]:
    """
    Update file integrity baseline with new hashes.

    Args:
        reference_file: Path to the baseline JSON file
        updates: Dictionary mapping file paths to new hashes
        remove_missing: Whether to remove missing files from baseline

    Returns:
        Tuple of (success, message)
    """
    if not os.path.isfile(reference_file):
        return False, f"Baseline file not found: {reference_file}"

    try:
        # Read current baseline
        with open(reference_file, 'r') as f:
            baseline = json.load(f)

        # Create backup first
        backup_file = f"{reference_file}.bak.{int(time.time())}"
        with open(backup_file, 'w') as f:
            json.dump(baseline, f, indent=2)

        # Update entries
        for path, hash_value in updates.items():
            baseline[path] = hash_value

        # Remove missing files if requested
        if remove_missing:
            to_remove = [path for path in baseline if not os.path.exists(path)]
            for path in to_remove:
                del baseline[path]

        # Write back the updated baseline
        with open(reference_file, 'w') as f:
            json.dump(baseline, f, indent=2)

        return True, f"Updated baseline with {len(updates)} files"

    except (IOError, ValueError, json.JSONDecodeError) as e:
        return False, f"Failed to update baseline: {str(e)}"


def check_file_integrity(file_path: str, expected_hash: str, algorithm: str = None) -> bool:
    """
    Verify integrity of a file by comparing its hash with expected value.

    Args:
        file_path: Path to the file to check
        expected_hash: Expected hash value to compare against
        algorithm: Hash algorithm to use ('sha256', 'sha384', 'sha512')
                  If None, uses SECURITY_CONFIG['FILE_HASH_ALGORITHM']

    Returns:
        bool: True if file hash matches expected hash, False otherwise
    """
    if not os.path.exists(file_path):
        log_warning(f"File does not exist: {file_path}")
        metrics.increment('security.file_integrity.missing_file')
        return False

    try:
        # Use default hash algorithm from SECURITY_CONFIG if none specified
        if algorithm is None and has_app_context():
            algorithm = current_app.config.get(
                'FILE_HASH_ALGORITHM',
                SECURITY_CONFIG.get('FILE_HASH_ALGORITHM', 'sha256')
            )
        elif algorithm is None:
            algorithm = SECURITY_CONFIG.get('FILE_HASH_ALGORITHM', 'sha256')

        current_hash = calculate_file_hash(file_path, algorithm)
        result = current_hash == expected_hash

        if not result:
            log_warning(f"File integrity check failed for {file_path}")
            metrics.increment('security.file_integrity.failed')

            # Track the specific file type for metrics
            if '.' in os.path.basename(file_path):
                ext = os.path.basename(file_path).split('.')[-1].lower()
                metrics.increment(f'security.file_integrity.failed.{ext}')
        else:
            metrics.increment('security.file_integrity.passed')

        return result
    except (IOError, OSError) as e:
        log_error(f"Error checking file integrity for {file_path}: {e}")
        metrics.increment('security.file_integrity.error')
        return False
    except ValueError as e:
        log_error(f"Invalid hash algorithm '{algorithm}' for {file_path}: {e}")
        metrics.increment('security.file_integrity.algorithm_error')
        return False


def check_config_integrity(app=None) -> bool:
    """
    Verify integrity of critical configuration files.

    This function verifies that all configuration files match their expected hash values,
    detecting any unauthorized modifications that could compromise system security.

    Args:
        app: Optional Flask app instance (uses current_app if None)

    Returns:
        bool: True if all files match their reference hashes, False otherwise
    """
    try:
        app = app or current_app

        # Get expected hashes from application configuration
        expected_hashes = app.config.get('CONFIG_FILE_HASHES', {})
        if not expected_hashes:
            log_warning("No reference hashes found for config files")
            return False

        # Record start time for performance metrics
        start_time = time.time()
        failed_files = []

        # Check each file against its expected hash
        for file_path, expected_hash in expected_hashes.items():
            if not os.path.isabs(file_path):
                # If not absolute path, make relative to app root
                base_path = os.path.dirname(app.root_path)
                file_path = os.path.join(base_path, file_path)

            if not os.path.exists(file_path):
                log_warning(f"Configuration file not found: {file_path}")
                failed_files.append(file_path)
                continue

            try:
                if not check_file_integrity(file_path, expected_hash):
                    log_warning(f"Configuration file integrity check failed: {file_path}")
                    failed_files.append(file_path)

                    # Record security event with detailed context
                    log_security_event(
                        event_type=AuditLog.EVENT_FILE_INTEGRITY,
                        description=f"Configuration file modified: {file_path}",
                        severity='error',
                        details={
                            'file_path': file_path,
                            'file_type': 'configuration',
                            'timestamp': format_timestamp()
                        }
                    )
            except Exception as e:
                log_error(f"Error checking integrity for {file_path}: {e}")
                failed_files.append(file_path)

        # Track metrics
        metrics.gauge('security.failed_config_files', len(failed_files))
        metrics.timing('security.config_integrity_check_time', time.time() - start_time)

        # If no failures, update last check time in metrics
        if len(failed_files) == 0:
            metrics.gauge('security.last_config_check', int(time.time()))

            # Cache successful check timestamp in Redis for monitoring
            redis_client = get_redis_client()
            if redis_client:
                try:
                    redis_client.setex(
                        'security:last_successful_config_check',
                        86400, # 24 hour TTL
                        str(int(time.time()))
                    )
                except Exception:
                    # Redis error shouldn't affect main functionality
                    pass
        else:
            # Cache failed file information
            redis_client = get_redis_client()
            if redis_client and failed_files:
                try:
                    redis_client.setex(
                        'security:failed_config_files',
                        3600, # 1 hour TTL
                        json.dumps(failed_files)
                    )
                except Exception:
                    pass

        return len(failed_files) == 0
    except Exception as e:
        log_error(f"Error in check_config_integrity: {e}")
        metrics.increment('security.config_integrity.error')
        return False


def check_critical_file_integrity(app=None) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Verify integrity of critical application files.

    This function checks the integrity of critical system files by comparing
    their current hash values against known good reference values. It can detect
    unauthorized modifications, file permission changes, and missing files.

    Args:
        app: Optional Flask app instance (uses current_app if None)

    Returns:
        Tuple of:
            bool: True if all files match their reference hashes, False otherwise
            List[Dict[str, Any]]: List of changes detected, each containing path, status, and severity
    """
    try:
        app = app or current_app

        # Get expected hashes from application configuration
        expected_hashes = app.config.get('CRITICAL_FILE_HASHES', {})
        if not expected_hashes:
            log_warning("No reference hashes found for critical files")
            return False, [{"path": "configuration", "status": "missing_hashes", "severity": "high"}]

        # Get monitoring settings
        basedir = os.path.dirname(os.path.abspath(app.root_path))
        critical_patterns = app.config.get(
            'CRITICAL_FILE_PATTERNS',
            SECURITY_CONFIG.get('CRITICAL_FILES_PATTERN', ['*.py', 'config.*', '.env*'])
        )
        detect_permissions = app.config.get('DETECT_FILE_PERMISSIONS', True)
        check_signatures = app.config.get('CHECK_FILE_SIGNATURES', False)
        periodic_baseline_update = app.config.get('PERIODIC_BASELINE_UPDATE', False)

        # Record start time for performance metrics
        start_time = time.time()

        # Detect file changes
        changes = _detect_file_changes(
            basedir,
            expected_hashes,
            critical_patterns=critical_patterns,
            detect_permissions=detect_permissions,
            check_signatures=check_signatures
        )

        # Update metrics for performance
        metrics.timing('security.file_integrity_check_time', time.time() - start_time)

        if changes:
            # Log each detected change
            total_changes = len(changes)
            high_severity = 0
            critical_severity = 0

            for change in changes:
                path = change.get('path', 'unknown')
                status = change.get('status', 'unknown')
                severity = change.get('severity', 'medium')

                # Count by severity
                if severity == 'critical':
                    critical_severity += 1
                elif severity == 'high':
                    high_severity += 1

                log_warning(f"File integrity violation: {path} ({status}) - {severity}")

                # Record security event for high severity changes
                if severity in ('high', 'critical'):
                    try:
                        log_security_event(
                            event_type=AuditLog.EVENT_FILE_INTEGRITY,
                            description=f"Critical file modified: {os.path.basename(path)}",
                            severity='error',
                            details={
                                'path': path,
                                'status': status,
                                'severity': severity,
                                'timestamp': change.get('timestamp', format_timestamp())
                            }
                        )
                    except Exception as e:
                        log_error(f"Failed to record file integrity event: {e}")

            # Track metrics
            metrics.gauge('security.modified_critical_files', total_changes)
            metrics.gauge('security.high_severity_changes', high_severity)
            metrics.gauge('security.critical_severity_changes', critical_severity)

            # Enhanced metrics by modification type
            status_counts = {}
            for change in changes:
                status = change.get('status', 'unknown')
                status_counts[status] = status_counts.get(status, 0) + 1

            for status, count in status_counts.items():
                metrics.gauge(f'security.modifications.{status}', count)

            # Cache information about changes in Redis for monitoring
            redis_client = get_redis_client()
            if redis_client:
                try:
                    # Store summary of current changes
                    summary = {
                        'total': total_changes,
                        'high_severity': high_severity,
                        'critical_severity': critical_severity,
                        'timestamp': int(time.time())
                    }
                    redis_client.setex('security:integrity_violations', 3600, json.dumps(summary))

                    # Store limited details of changes
                    changes_subset = [
                        {k: v for k, v in change.items()
                         if k in ('path', 'status', 'severity', 'timestamp')}
                        for change in changes[:20]  # Limit to first 20 for space
                    ]
                    redis_client.setex('security:integrity_changes', 3600, json.dumps(changes_subset))
                except Exception as e:
                    # Redis errors shouldn't affect main functionality
                    log_error(f"Error caching integrity violations: {e}")

            # If enabled, consider updating the baseline for non-critical changes
            # This helps adapt to authorized changes while still alerting on them
            if periodic_baseline_update and not any(
                c.get('severity') == 'critical' for c in changes
            ):
                _consider_baseline_update(app, changes, expected_hashes)

            return False, changes

        # No changes detected - successful check
        metrics.gauge('security.last_integrity_check', int(time.time()))

        # Cache successful check timestamp
        redis_client = get_redis_client()
        if redis_client:
            try:
                redis_client.setex(
                    'security:last_successful_integrity_check',
                    86400,  # 24 hour TTL
                    str(int(time.time()))
                )
            except Exception:
                pass

        return True, []
    except Exception as e:
        log_error(f"Error in check_critical_file_integrity: {e}")
        metrics.increment('security.integrity_check.error')
        return False, [{"path": "system", "status": "error", "severity": "high", "details": str(e)}]


def verify_file_signature(file_path: str, signature_path: Optional[str] = None,
                         public_key_path: Optional[str] = None) -> bool:
    """
    Verify the cryptographic signature of a file.

    This function verifies that a file matches its cryptographic signature,
    ensuring the file has not been tampered with and comes from a trusted source.

    Args:
        file_path: Path to the file to verify
        signature_path: Path to signature file (defaults to file_path + '.sig')
        public_key_path: Path to public key file (defaults to app config or SECURITY_CONFIG)

    Returns:
        bool: True if signature is valid, False otherwise
    """
    if not os.path.exists(file_path):
        log_warning(f"File does not exist: {file_path}")
        metrics.increment('security.signature_verification.missing_file')
        return False

    # Determine signature path if not specified
    if signature_path is None:
        signature_path = file_path + '.sig'
        # Check alternate extensions if main one doesn't exist
        if not os.path.exists(signature_path):
            for ext in ['.signature', '.sign', '.asc']:
                alt_path = file_path + ext
                if os.path.exists(alt_path):
                    signature_path = alt_path
                    break

    if not os.path.exists(signature_path):
        log_warning(f"Signature file not found: {signature_path}")
        metrics.increment('security.signature_verification.missing_signature')
        return False

    try:
        # Read the signature file
        with open(signature_path, 'rb') as f:
            signature = f.read()

        # Get public key from parameters, app config, or security config
        if public_key_path is None and has_app_context():
            public_key_path = current_app.config.get('SIGNATURE_PUBLIC_KEY_PATH')

        if public_key_path is None:
            public_key_path = SECURITY_CONFIG.get('SIGNATURE_PUBLIC_KEY_PATH')

        if not public_key_path or not os.path.exists(public_key_path):
            log_warning("Public key for signature verification not available")
            metrics.increment('security.signature_verification.missing_key')
            return False

        # Load the public key
        with open(public_key_path, 'rb') as f:
            public_key = load_pem_public_key(f.read())

        # Read the file content
        with open(file_path, 'rb') as f:
            file_data = f.read()

        # Verify the signature
        hash_algorithm = SECURITY_CONFIG.get('SIGNATURE_HASH_ALGORITHM', 'sha256')

        if hash_algorithm == 'sha384':
            hash_func = hashes.SHA384()
        elif hash_algorithm == 'sha512':
            hash_func = hashes.SHA512()
        else:
            hash_func = hashes.SHA256()

        public_key.verify(
            signature,
            file_data,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hash_func),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hash_func
        )

        # If we get here, verification succeeded
        log_info(f"Signature verification successful for {file_path}")
        metrics.increment('security.signature_verification.success')
        return True

    except InvalidSignature:
        log_warning(f"Invalid signature for file: {file_path}")
        metrics.increment('security.signature_verification.invalid')

        # Log security event for invalid signatures
        try:
            log_security_event(
                event_type='invalid_signature',
                description=f"Invalid signature detected: {os.path.basename(file_path)}",
                severity='warning',
                details={
                    'file_path': file_path,
                    'signature_path': signature_path
                }
            )
        except Exception:
            pass

        return False
    except Exception as e:
        log_error(f"Error verifying file signature {file_path}: {e}")
        metrics.increment('security.signature_verification.error')
        return False


def create_file_hash_baseline(directory: str, patterns: List[str] = None,
                             output_file: Optional[str] = None,
                             algorithm: str = 'sha256') -> Dict[str, str]:
    """
    Create a baseline of file hashes for integrity monitoring.

    This function generates hash values for files matching the specified patterns
    within the given directory, creating a baseline for future integrity checks.

    Args:
        directory: Base directory to scan
        patterns: List of file patterns to include (e.g., ['*.py', 'config/*.json'])
        output_file: Optional path to save the baseline to
        algorithm: Hash algorithm to use

    Returns:
        Dict[str, str]: Dictionary mapping file paths to hash values
    """
    if not os.path.isdir(directory):
        log_error(f"Directory not found: {directory}")
        return {}

    if patterns is None:
        if has_app_context():
            patterns = current_app.config.get(
                'CRITICAL_FILE_PATTERNS',
                SECURITY_CONFIG.get('CRITICAL_FILES_PATTERN', ['*.py', 'config/*'])
            )
        else:
            patterns = ['*.py', 'config/*', '*.ini', '*.json', '*.yaml', '*.yml', 'requirements.txt']

    try:
        baseline = {}
        files_processed = 0
        files_skipped = 0

        # Process each pattern
        for pattern in patterns:
            pattern_path = os.path.join(directory, pattern)
            # Safely handle the pattern to prevent path traversal
            norm_dir = os.path.normpath(directory)

            for file_path in glob.glob(pattern_path, recursive=True):
                # Security check: ensure file path is within the intended directory
                norm_path = os.path.normpath(file_path)
                if not norm_path.startswith(norm_dir):
                    log_warning(f"Skipping path outside target directory: {file_path}")
                    files_skipped += 1
                    continue

                # Skip if not a regular file
                if not os.path.isfile(file_path):
                    continue

                # Skip large files
                try:
                    file_size = os.path.getsize(file_path)
                    max_size = SECURITY_CONFIG.get('MAX_BASELINE_FILE_SIZE', 10 * 1024 * 1024)  # Default 10MB
                    if file_size > max_size:
                        log_info(f"Skipping large file: {file_path} ({file_size} bytes)")
                        files_skipped += 1
                        continue
                except OSError:
                    # Can't get file size, skip
                    files_skipped += 1
                    continue

                try:
                    file_hash = calculate_file_hash(file_path, algorithm)
                    baseline[file_path] = file_hash
                    files_processed += 1

                    # Log progress for large directories
                    if files_processed % 100 == 0:
                        log_debug(f"Processed {files_processed} files for baseline...")
                except (IOError, OSError) as e:
                    log_warning(f"Could not hash file {file_path}: {e}")
                    files_skipped += 1

        # Save to output file if specified
        if output_file and baseline:
            try:
                # Make sure the directory exists
                output_dir = os.path.dirname(output_file)
                if output_dir and not os.path.exists(output_dir):
                    os.makedirs(output_dir)

                with open(output_file, 'w') as f:
                    json.dump(baseline, f, indent=2)

                # Set secure permissions
                try:
                    os.chmod(output_file, 0o600)  # Read/write for owner only
                except OSError:
                    log_warning(f"Could not set secure permissions on {output_file}")

                log_info(f"File hash baseline saved to {output_file}")
            except (IOError, OSError) as e:
                log_error(f"Error saving baseline to {output_file}: {e}")

        log_info(f"Created hash baseline with {len(baseline)} files (processed: {files_processed}, skipped: {files_skipped})")
        metrics.gauge('security.baseline.files_processed', files_processed)
        metrics.gauge('security.baseline.files_skipped', files_skipped)

        return baseline

    except Exception as e:
        log_error(f"Error creating file hash baseline: {e}")
        metrics.increment('security.baseline.error')
        return {}


def verify_baseline_update(file_path: str, current_hash: str,
                          expected_hash: str, max_age: int = 86400) -> bool:
    """
    Verify if a baseline update for a modified file should be authorized.

    This function implements security checks to determine if an automatic
    baseline update should be allowed for a file that has changed.

    Args:
        file_path: Path of the modified file
        current_hash: Current hash of the file
        expected_hash: Previously expected hash
        max_age: Maximum age in seconds for file modifications to be considered

    Returns:
        bool: True if baseline update is safe, False otherwise
    """
    try:
        # Don't update for certain critical files
        file_name = os.path.basename(file_path).lower()
        critical_prefixes = ['security', 'auth', 'crypto', 'password', 'secret', 'key']
        critical_extensions = ['.key', '.pem', '.crt', '.pub', '.env']

        # Check filename patterns
        if any(file_name.startswith(prefix) for prefix in critical_prefixes):
            return False

        if any(file_name.endswith(ext) for ext in critical_extensions):
            return False

        # Check file modification time
        try:
            mtime = os.path.getmtime(file_path)
            if (time.time() - mtime) > max_age:
                # File was modified more than max_age ago, don't update automatically
                return False
        except OSError:
            # If we can't get the modification time, be cautious
            return False

        # Additional checks could be added here:
        # - Check if file is under version control (git)
        # - Verify if app deployed from CI/CD pipeline recently
        # - Check if file is owned by expected user

        return True
    except Exception as e:
        log_error(f"Error verifying baseline update for {file_path}: {e}")
        return False


def initialize_file_monitoring(app, basedir: str = None,
                              patterns: List[str] = None,
                              interval: int = 3600) -> bool:
    """
    Initialize file integrity monitoring for the application.

    This function sets up scheduled file integrity checks and creates
    a baseline if one doesn't exist.

    Args:
        app: Flask application instance
        basedir: Base directory to monitor
        patterns: List of file patterns to monitor
        interval: Check interval in seconds

    Returns:
        bool: True if initialization was successful
    """
    try:
        if not app:
            log_error("Cannot initialize file monitoring: No app provided")
            return False

        log_info("Initializing file integrity monitoring")

        # Set default base directory if not provided
        if not basedir:
            basedir = os.path.dirname(os.path.abspath(app.root_path))

        # Set default patterns if not provided
        if not patterns:
            patterns = SECURITY_CONFIG.get(
                'CRITICAL_FILES_PATTERN',
                ['*.py', 'config/*', '*.ini', '*.json', 'requirements.txt']
            )

        # Check if baseline exists, create if not
        baseline_path = app.config.get('FILE_BASELINE_PATH')
        if not baseline_path:
            baseline_path = os.path.join(app.instance_path, 'file_baseline.json')
            app.config['FILE_BASELINE_PATH'] = baseline_path

        # Create baseline directory if needed
        os.makedirs(os.path.dirname(baseline_path), exist_ok=True)

        # Create baseline if it doesn't exist
        if not os.path.exists(baseline_path):
            log_info("Creating initial file integrity baseline")
            baseline = create_file_hash_baseline(basedir, patterns, baseline_path)

            if not baseline:
                log_error("Failed to create initial file integrity baseline")
                return False

            # Load baseline into app config for future checks
            app.config['CRITICAL_FILE_HASHES'] = baseline
        else:
            # Load existing baseline
            try:
                with open(baseline_path, 'r') as f:
                    baseline = json.load(f)
                app.config['CRITICAL_FILE_HASHES'] = baseline
                log_info(f"Loaded file integrity baseline with {len(baseline)} entries")
            except (IOError, json.JSONDecodeError) as e:
                log_error(f"Failed to load file integrity baseline: {e}")
                return False

        # Set up scheduling if available
        if hasattr(app, 'scheduler'):
            try:
                # Register jobs with scheduler
                app.scheduler.add_job(
                    func=lambda: check_critical_file_integrity(app),
                    trigger='interval',
                    seconds=interval,
                    id='file_integrity_check',
                    replace_existing=True
                )

                log_info(f"Scheduled file integrity checks every {interval} seconds")
            except Exception as e:
                log_error(f"Failed to schedule file integrity checks: {e}")
                return False

        return True
    except Exception as e:
        log_error(f"Error initializing file monitoring: {e}")
        return False


def update_file_integrity_baseline(
        app=None,
        baseline_path: Optional[str] = None,
        updates: Optional[List[Dict[str, Any]]] = None,
        remove_missing: bool = False) -> bool:
    """
    Update the file integrity baseline with new hash values.

    This function updates the baseline file with new hash values from detected changes
    or explicitly provided updates. It can also optionally remove entries for missing files.

    Args:
        app: Flask application instance (uses current_app if None)
        baseline_path: Path to the baseline file (uses app config if None)
        updates: List of change dictionaries to incorporate into baseline
        remove_missing: Whether to remove entries for files that no longer exist

    Returns:
        bool: True if the baseline was successfully updated, False otherwise
    """
    try:
        app = app or current_app

        # Determine baseline path
        if not baseline_path:
            baseline_path = app.config.get('FILE_BASELINE_PATH')
            if not baseline_path:
                baseline_path = os.path.join(app.instance_path, 'file_baseline.json')

        # Load existing baseline
        if os.path.exists(baseline_path):
            with open(baseline_path, 'r') as f:
                baseline = json.load(f)
        else:
            baseline = {}

        # Create a backup of the current baseline
        backup_path = f"{baseline_path}.bak.{int(time.time())}"
        try:
            with open(backup_path, 'w') as f:
                json.dump(baseline, f, indent=2)
            log_info(f"Created baseline backup at {backup_path}")
        except (IOError, OSError) as e:
            log_warning(f"Failed to create baseline backup: {e}")

        # Process updates
        changes_applied = 0
        if updates:
            for change in updates:
                path = change.get('path')
                current_hash = change.get('current_hash')

                # Skip entries without necessary information
                if not path or not current_hash:
                    continue

                # Ensure path is relative to project root if needed
                if not os.path.isabs(path) and app:
                    basedir = os.path.dirname(os.path.abspath(app.root_path))
                    abs_path = os.path.join(basedir, path)
                else:
                    abs_path = path

                # Only update if file exists
                if os.path.exists(abs_path):
                    baseline[path] = current_hash
                    changes_applied += 1

        # Remove missing files if requested
        removed = 0
        if remove_missing:
            to_remove = []
            for path in baseline.keys():
                if not os.path.isabs(path) and app:
                    basedir = os.path.dirname(os.path.abspath(app.root_path))
                    abs_path = os.path.join(basedir, path)
                else:
                    abs_path = path

                if not os.path.exists(abs_path):
                    to_remove.append(path)

            for path in to_remove:
                del baseline[path]
                removed += 1

        # Save updated baseline
        os.makedirs(os.path.dirname(baseline_path), exist_ok=True)
        with open(baseline_path, 'w') as f:
            json.dump(baseline, f, indent=2)

        # Update application config
        app.config['CRITICAL_FILE_HASHES'] = baseline

        # Log the update operation
        log_info(f"Updated file integrity baseline: {changes_applied} changes applied, {removed} entries removed")
        metrics.gauge('security.baseline.files_updated', changes_applied)
        if removed > 0:
            metrics.gauge('security.baseline.files_removed', removed)

        # Log security event
        if changes_applied > 0 or removed > 0:
            try:
                log_security_event(
                    event_type='baseline_updated',
                    description=f"File integrity baseline updated: {changes_applied} new/changed files, {removed} removed",
                    severity='info',
                    details={
                        'changes_applied': changes_applied,
                        'entries_removed': removed,
                        'timestamp': format_timestamp()
                    }
                )
            except Exception as e:
                log_error(f"Failed to log baseline update event: {e}")

        return True

    except (IOError, OSError) as e:
        log_error(f"Error updating file integrity baseline: {e}")
        metrics.increment('security.baseline.update_error')
        return False
    except Exception as e:
        log_error(f"Unexpected error updating file integrity baseline: {e}")
        metrics.increment('security.baseline.update_error')
        return False


def _detect_file_changes(
        basedir: str,
        reference_hashes: Dict[str, str],
        critical_patterns: Optional[List[str]] = None,
        detect_permissions: bool = True,
        check_signatures: bool = False) -> List[Dict[str, Any]]:
    """
    Detect changes in critical files by comparing current hashes with reference hashes.

    This function performs comprehensive file integrity monitoring by:
    1. Checking hash values against known good reference hashes
    2. Detecting recently modified files matching critical patterns
    3. Optionally checking for permission changes on critical files
    4. Optionally verifying digital signatures on executable files

    Args:
        basedir: Base directory to check files in
        reference_hashes: Dictionary mapping paths to expected hash values
        critical_patterns: List of glob patterns to match critical files
        detect_permissions: Whether to check for permission changes
        check_signatures: Whether to verify digital signatures on executables

    Returns:
        List of dictionaries containing information about modified files
    """
    modified_files = []
    algorithm = SECURITY_CONFIG.get('FILE_HASH_ALGORITHM', 'sha256')

    try:
        # Check existing files against reference hashes
        for file_path, expected_hash in reference_hashes.items():
            if not os.path.isabs(file_path):
                file_path = os.path.join(basedir, file_path)

            if not os.path.exists(file_path):
                modified_files.append({
                    'path': file_path,
                    'status': 'missing',
                    'severity': 'high',
                    'timestamp': format_timestamp()
                })
                continue

            try:
                current_hash = calculate_file_hash(file_path, algorithm)

                if current_hash != expected_hash:
                    modified_files.append({
                        'path': file_path,
                        'status': 'modified',
                        'severity': 'high',
                        'expected_hash': expected_hash,
                        'current_hash': current_hash,
                        'timestamp': format_timestamp()
                    })

                    # Check signature if enabled and file doesn't match hash
                    if check_signatures and file_path.endswith(('.sh', '.py', '.exe', '.bin', '.js')):
                        sig_valid = verify_file_signature(file_path)
                        if not sig_valid:
                            modified_files[-1]['signature_valid'] = False
                            modified_files[-1]['severity'] = 'critical'

            except (IOError, OSError) as e:
                modified_files.append({
                    'path': file_path,
                    'status': 'error',
                    'severity': 'medium',
                    'error': str(e),
                    'timestamp': format_timestamp()
                })

        # Check for permission changes if enabled
        if detect_permissions:
            _check_for_permission_changes(
                basedir, reference_hashes, modified_files)

        # Search for additional files matching critical patterns
        if critical_patterns:
            _check_additional_critical_files(
                basedir, critical_patterns, reference_hashes, modified_files)

        return modified_files

    except Exception as e:
        log_error(f"Error during file integrity check: {e}")
        return [{
            'path': 'system',
            'status': 'error',
            'severity': 'high',
            'error': str(e),
            'timestamp': format_timestamp()
        }]


def _check_for_permission_changes(
        basedir: str,
        reference_hashes: Dict[str, str],
        modified_files: List[Dict[str, Any]]) -> None:
    """
    Check for permission changes on critical files.

    Args:
        basedir: Base directory to check files in
        reference_hashes: Dictionary mapping paths to expected hash values
        modified_files: List to add detected changes to
    """
    # Permission check implementation
    try:
        import stat

        for file_path in reference_hashes:
            if not os.path.isabs(file_path):
                file_path = os.path.join(basedir, file_path)

            if not os.path.exists(file_path):
                continue

            # Check if file is world-writable (unsafe)
            file_stat = os.stat(file_path)
            if file_stat.st_mode & stat.S_IWOTH:
                modified_files.append({
                    'path': file_path,
                    'status': 'world_writable',
                    'severity': 'high',
                    'mode': oct(file_stat.st_mode),
                    'timestamp': format_timestamp()
                })

            # Check if file is world-executable (potentially unsafe)
            elif file_stat.st_mode & stat.S_IXOTH and file_path.endswith(('.py', '.sh', '.exe', '.bin')):
                modified_files.append({
                    'path': file_path,
                    'status': 'world_executable',
                    'severity': 'medium',
                    'mode': oct(file_stat.st_mode),
                    'timestamp': format_timestamp()
                })

            # Check if file has setuid/setgid bits (highly suspicious)
            elif file_stat.st_mode & (stat.S_ISUID | stat.S_ISGID):
                modified_files.append({
                    'path': file_path,
                    'status': 'setuid_setgid',
                    'severity': 'critical',
                    'mode': oct(file_stat.st_mode),
                    'timestamp': format_timestamp()
                })

            # Check if directory permissions are too open
            elif os.path.isdir(file_path) and file_stat.st_mode & (stat.S_IWOTH | stat.S_IWGRP):
                modified_files.append({
                    'path': file_path,
                    'status': 'insecure_directory',
                    'severity': 'high',
                    'mode': oct(file_stat.st_mode),
                    'timestamp': format_timestamp()
                })
    except Exception as e:
        log_error(f"Error checking file permissions: {e}")


def _check_additional_critical_files(
        basedir: str,
        critical_patterns: List[str],
        reference_hashes: Dict[str, str],
        modified_files: List[Dict[str, Any]]) -> None:
    """
    Check additional files matching critical patterns.

    Args:
        basedir: Base directory to check files in
        critical_patterns: List of glob patterns to match critical files
        reference_hashes: Dictionary mapping paths to expected hash values
        modified_files: List to add detected changes to
    """
    # Check for new files that match critical patterns
    for pattern in critical_patterns:
        try:
            # Safely join paths and handle path traversal attempts
            pattern_path = os.path.normpath(os.path.join(basedir, pattern))
            if not pattern_path.startswith(os.path.normpath(basedir)):
                log_warning(f"Skipping potentially dangerous path pattern: {pattern}")
                continue

            for filepath in glob.glob(pattern_path, recursive=True):
                # Skip if not a file or if already in reference hashes
                if not os.path.isfile(filepath) or filepath in reference_hashes:
                    continue

                # Mark as new critical file
                modified_files.append({
                    'path': filepath,
                    'status': 'new_critical_file',
                    'severity': 'medium',
                    'timestamp': format_timestamp()
                })

                # Additional check for suspicious file names/extensions
                file_name = os.path.basename(filepath).lower()
                suspicious_patterns = ['backdoor', 'hack', 'exploit', 'rootkit', 'trojan', 'payload']
                suspicious_extensions = ['.so', '.dll', '.exe', '.bin', '.sh', '.cmd', '.bat']

                if any(pattern in file_name for pattern in suspicious_patterns) or \
                   any(file_name.endswith(ext) for ext in suspicious_extensions):
                    # Update the severity of the previously added entry
                    modified_files[-1]['severity'] = 'high'
                    modified_files[-1]['status'] = 'suspicious_new_file'
        except (IOError, ValueError, OSError) as e:
            log_error(f"Error checking critical files with pattern {pattern}: {e}")


def _consider_baseline_update(app, changes: List[Dict[str, Any]],
                            expected_hashes: Dict[str, str]) -> None:
    """
    Consider updating the baseline for non-critical changes.

    Args:
        app: Flask application
        changes: List of detected changes
        expected_hashes: Current hash baseline
    """
    try:
        # Only proceed if auto-updates are enabled
        if not app.config.get('AUTO_UPDATE_BASELINE', False):
            return

        # Only update for low or medium severity changes
        safe_changes = [c for c in changes if c.get('severity') in ('low', 'medium')]
        if not safe_changes:
            return

        # Copy current baseline
        updated_hashes = expected_hashes.copy()
        files_updated = 0

        for change in safe_changes:
            path = change.get('path')
            status = change.get('status')
            current_hash = change.get('current_hash')

            # Only update for modified files with a current hash
            if status == 'modified' and current_hash and path:
                # Verify it's safe to update
                if verify_baseline_update(path, current_hash, expected_hashes.get(path, '')):
                    updated_hashes[path] = current_hash
                    files_updated += 1
                    log_info(f"Auto-updated baseline for: {path}")

        # If any files were updated, save the new baseline
        if files_updated > 0:
            baseline_path = app.config.get('FILE_BASELINE_PATH')
            if baseline_path:
                with open(baseline_path, 'w') as f:
                    json.dump(updated_hashes, f, indent=2)

                # Update the config
                app.config['CRITICAL_FILE_HASHES'] = updated_hashes

                log_info(f"Auto-updated file baseline with {files_updated} changes")

                # Log security event
                try:
                    log_security_event(
                        event_type='baseline_updated',
                        description=f"File integrity baseline auto-updated with {files_updated} changes",
                        severity='info',
                        details={
                            'files_updated': files_updated,
                            'timestamp': format_timestamp()
                        }
                    )
                except Exception:
                    pass
    except Exception as e:
        log_error(f"Error updating baseline: {e}")


def get_last_integrity_status() -> Dict[str, Any]:
    """
    Get the most recent integrity checking status.

    Returns:
        Dict with integrity status information
    """
    status_info = {
        'last_check': None,
        'last_successful_check': None,
        'recent_violations': 0,
        'has_critical_violations': False,
        'status': 'unknown'
    }

    try:
        redis_client = get_redis_client()
        if not redis_client:
            return status_info

        # Get last check timestamps
        last_check = redis_client.get('security:last_integrity_check')
        if last_check:
            status_info['last_check'] = int(last_check)

        last_successful = redis_client.get('security:last_successful_integrity_check')
        if last_successful:
            status_info['last_successful_check'] = int(last_successful)

        # Get recent violations
        violations_data = redis_client.get('security:integrity_violations')
        if violations_data:
            try:
                violations = json.loads(violations_data)
                status_info['recent_violations'] = violations.get('total', 0)
                status_info['has_critical_violations'] = violations.get('critical_severity', 0) > 0
            except json.JSONDecodeError:
                pass

        # Determine overall status
        if status_info['last_successful_check'] is not None:
            if status_info['recent_violations'] > 0:
                if status_info['has_critical_violations']:
                    status_info['status'] = 'critical'
                else:
                    status_info['status'] = 'warning'
            else:
                status_info['status'] = 'ok'
        else:
            status_info['status'] = 'unknown'

        return status_info
    except Exception as e:
        log_error(f"Error getting integrity status: {e}")
        return status_info
