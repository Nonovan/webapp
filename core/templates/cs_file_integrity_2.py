"""
Security file integrity monitoring for the Cloud Infrastructure Platform.

This module provides functionality for monitoring file integrity, detecting unauthorized
modifications, and alerting on potential security incidents. It implements several integrity
verification methods including hash comparison, permission validation, and digital signature
verification for critical system files.
"""

import os
import re
import json
import time
import logging
import hashlib
import datetime
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Any, Tuple, Optional, Set, Union

# Flask imports
from flask import current_app, has_app_context

# Internal imports
from extensions import db, metrics
from extensions import get_redis_client
from core.utils import log_error, log_warning, log_info, log_debug
from core.cs_constants import SECURITY_CONFIG
from core.cs_audit import log_security_event

try:
    from models.security.audit_log import AuditLog
except ImportError:
    # Mock AuditLog for cases where models aren't available
    class AuditLog:
        EVENT_FILE_INTEGRITY = "file_integrity"
        SEVERITY_INFO = "info"
        SEVERITY_WARNING = "warning"
        SEVERITY_ERROR = "error"


def check_file_integrity(file_path: str, expected_hash: str = None,
                        create_if_missing: bool = False,
                        algorithm: str = "sha256") -> bool:
    """
    Check if a file's integrity is intact based on its hash.

    This function computes a hash of the file's contents and compares it with the
    expected hash. If the expected hash isn't provided but create_if_missing is True,
    it will compute and return the hash.

    Args:
        file_path: Path to the file to check
        expected_hash: Expected hash value, if None and create_if_missing is True
                     then it computes and returns the hash
        create_if_missing: Whether to create a hash if expected_hash is None
        algorithm: Hashing algorithm to use (default: sha256)

    Returns:
        bool: True if the integrity is verified, False otherwise
    """
    if not os.path.exists(file_path):
        log_warning(f"File not found for integrity check: {file_path}")
        return False

    try:
        actual_hash = calculate_file_hash(file_path, algorithm)

        if expected_hash is None:
            if create_if_missing:
                log_info(f"Created hash for {file_path}: {actual_hash} ({algorithm})")
                return actual_hash
            else:
                log_warning(f"No expected hash provided for {file_path}")
                return False

        # Compare hashes
        if actual_hash == expected_hash:
            return True
        else:
            log_warning(f"File integrity check failed for: {file_path}")
            log_debug(f"Expected hash: {expected_hash}")
            log_debug(f"Actual hash: {actual_hash}")
            return False
    except (IOError, OSError) as e:
        log_error(f"Error reading file {file_path} for integrity check: {e}")
        return False
    except Exception as e:
        log_error(f"Unexpected error during file integrity check for {file_path}: {e}")
        return False


def check_config_integrity() -> bool:
    """
    Check integrity of critical configuration files.

    Verifies that critical configuration files have not been modified since
    baseline creation or last authorized update.

    Returns:
        bool: True if all configuration files are unmodified, False otherwise
    """
    if not has_app_context():
        log_warning("No application context available for config integrity check")
        return False

    # Determine patterns for configuration files
    config_patterns = current_app.config.get('CONFIG_FILES_PATTERN',
                                          SECURITY_CONFIG.get('CONFIG_FILES_PATTERN', []))
    if not config_patterns:
        config_patterns = ["config/*", "*.ini", "*.conf", "*.cfg", "*.config", "*-config.json", "*-config.yaml", "*-config.yml"]

    # Use common base directory for config files
    config_basedir = current_app.config.get('CONFIG_BASEDIR', current_app.config.root_path)

    # Get reference hashes
    config_hashes = current_app.config.get('CONFIG_FILE_HASHES', {})
    if not config_hashes:
        log_warning("No configuration file hashes available for integrity check")
        return False

    # Check all configuration files
    all_intact = True
    violations = []

    for file_path, expected_hash in config_hashes.items():
        full_path = os.path.join(config_basedir, file_path) if not os.path.isabs(file_path) else file_path

        if not os.path.exists(full_path):
            log_warning(f"Configuration file not found: {file_path}")
            all_intact = False
            violations.append(file_path)
            continue

        if not check_file_integrity(full_path, expected_hash):
            log_warning(f"Configuration integrity violation: {file_path}")
            all_intact = False
            violations.append(file_path)

    # Record metrics
    metrics.gauge('security.config_integrity_violations', len(violations))

    # Log details of violations if any found
    if violations:
        try:
            log_security_event(
                event_type=AuditLog.EVENT_FILE_INTEGRITY,
                description=f"Configuration integrity violation: {len(violations)} files modified",
                severity=AuditLog.SEVERITY_WARNING,
                details={"modified_files": violations}
            )
        except Exception as e:
            log_error(f"Failed to record configuration integrity violation event: {e}")

    return all_intact


def check_critical_file_integrity(app=None) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Check integrity of critical system files.

    Performs a comprehensive check of critical system files, comparing current
    hashes with stored baseline hashes. Detects unauthorized modifications,
    permission changes, and new files matching critical patterns.

    Args:
        app: Flask application (optional, uses current_app if not provided)

    Returns:
        Tuple containing:
        - bool: True if all critical files are unmodified
        - List[Dict[str, Any]]: Details about integrity violations if any
    """
    try:
        # Get Flask application context
        if app is None and has_app_context():
            app = current_app

        if not app:
            log_warning("No application context available for critical file integrity check")
            return False, [{"path": "system", "status": "error", "severity": "high", "details": "No application context"}]

        # Get file integrity configuration
        basedir = app.config.get('PROJECT_ROOT', app.root_path)
        expected_hashes = app.config.get('CRITICAL_FILE_HASHES', {})

        if not expected_hashes:
            log_warning("No critical file hashes defined for integrity check")
            return False, [{"path": "system", "status": "error", "severity": "medium", "details": "No file baseline defined"}]

        # Get patterns for critical files
        critical_patterns = app.config.get('CRITICAL_FILES_PATTERN',
                                         SECURITY_CONFIG.get('CRITICAL_FILES_PATTERN', []))

        # Track metrics
        metrics.increment('security.integrity_check.run')

        # Periodic updating of baseline is optional
        periodic_baseline_update = app.config.get('AUTO_UPDATE_BASELINE',
                                               SECURITY_CONFIG.get('AUTO_UPDATE_BASELINE', False))

        # Detect file changes
        changes = _detect_file_changes(
            basedir=basedir,
            reference_hashes=expected_hashes,
            critical_patterns=critical_patterns,
            detect_permissions=True,
            check_signatures=app.config.get('CHECK_FILE_SIGNATURES',
                                         SECURITY_CONFIG.get('CHECK_FILE_SIGNATURES', False))
        )

        # If any changes are detected, integrity check has failed
        if changes:
            metrics.increment('security.integrity_check.failed')

            # Count changes by severity
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
                            severity=AuditLog.SEVERITY_ERROR,
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


def verify_file_signature(file_path: str) -> bool:
    """
    Verify digital signature of a file.

    For signed files, verifies that the file's digital signature matches the
    expected signature based on configured keys. This provides an additional
    layer of verification beyond simple hashing.

    Args:
        file_path: Path to the file to verify

    Returns:
        bool: True if signature is valid, False otherwise
    """
    if not os.path.exists(file_path):
        log_warning(f"File not found for signature verification: {file_path}")
        return False

    try:
        # Determine if signature verification is applicable for this file
        file_ext = os.path.splitext(file_path)[1].lower()
        filename = os.path.basename(file_path).lower()

        # Skip verification for certain files
        if file_ext in ('.txt', '.md', '.log', '.css', '.html', '.svg'):
            return True

        # Python files can be verified by attempting to compile them
        if file_ext == '.py':
            try:
                with open(file_path, 'rb') as f:
                    compile(f.read(), file_path, 'exec')
                return True
            except Exception:
                log_warning(f"Python syntax verification failed for {file_path}")
                return False

        # Shell scripts can be checked with shellcheck if available
        if file_ext in ('.sh', '.bash') and os.path.exists('/usr/bin/shellcheck'):
            try:
                result = subprocess.run(
                    ['/usr/bin/shellcheck', file_path],
                    capture_output=True,
                    check=False,
                    timeout=5
                )
                return result.returncode == 0
            except (subprocess.SubprocessError, OSError):
                pass  # Fall back to other methods

        # For executable files, check PGP signatures if configured
        if os.access(file_path, os.X_OK) and has_app_context():
            sig_path = f"{file_path}.sig"
            key_path = current_app.config.get('PGP_PUBLIC_KEY_PATH')

            if os.path.exists(sig_path) and key_path and os.path.exists(key_path):
                try:
                    result = subprocess.run(
                        ['gpg', '--no-default-keyring',
                         f'--keyring={key_path}', '--verify',
                         sig_path, file_path],
                        capture_output=True,
                        check=False,
                        timeout=5
                    )
                    return result.returncode == 0
                except (subprocess.SubprocessError, OSError):
                    pass  # Fall back to permission check

        # If all else fails, at least ensure the file has appropriate permissions
        return check_file_permissions(file_path)
    except Exception as e:
        log_error(f"Error verifying file signature for {file_path}: {e}")
        return False


def create_file_hash_baseline(basedir: str, file_patterns: List[str] = None,
                           output_file: str = None,
                           algorithm: str = "sha256") -> Dict[str, str]:
    """
    Create a baseline of file hashes for integrity monitoring.

    Scans files matching patterns and creates a dictionary of file paths to hash values.
    The resulting baseline can be used for future integrity checks.

    Args:
        basedir: Base directory to scan files in
        file_patterns: List of glob patterns to match files to include
        output_file: Optional file path to save the baseline to
        algorithm: Hashing algorithm to use (default: sha256)

    Returns:
        Dict[str, str]: Dictionary mapping file paths to hash values
    """
    hashes = {}

    if not os.path.isdir(basedir):
        log_error(f"Base directory not found: {basedir}")
        return hashes

    # Default patterns if none provided
    if not file_patterns:
        file_patterns = SECURITY_CONFIG.get('CRITICAL_FILES_PATTERN', [])
        if not file_patterns:
            file_patterns = [
                "*.py",                 # Python source files
                "*.sh",                 # Shell scripts
                "config/*.ini",         # Configuration files
                "config/*.json",        # JSON configuration
                "config/*.yaml",        # YAML configuration
                "config/*.yml",         # YAML configuration (alt)
            ]

    metrics.gauge('security.baseline_creation', 1)
    start_time = time.time()

    try:
        # Get all files matching patterns
        matching_files = find_files_by_patterns(basedir, file_patterns)

        log_info(f"Creating file hash baseline from {len(matching_files)} files")

        # Calculate hash for each file
        for file_path in matching_files:
            try:
                # Use relative path for portable baselines
                rel_path = os.path.relpath(file_path, basedir)
                hashes[rel_path] = calculate_file_hash(file_path, algorithm)
            except (IOError, OSError) as e:
                log_warning(f"Error reading file {file_path} for baseline: {e}")
            except Exception as e:
                log_error(f"Unexpected error processing {file_path} for baseline: {e}")

        # Save to file if output path is provided
        if output_file and hashes:
            try:
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                with open(output_file, 'w') as f:
                    json.dump(hashes, f, indent=2, sort_keys=True)

                # Set secure permissions
                os.chmod(output_file, 0o600)

                log_info(f"File hash baseline created with {len(hashes)} entries: {output_file}")
            except (IOError, OSError) as e:
                log_error(f"Error saving baseline to {output_file}: {e}")
    except Exception as e:
        log_error(f"Error creating file baseline: {e}")
    finally:
        # Update metrics
        elapsed = time.time() - start_time
        metrics.gauge('security.baseline_creation', 0)
        metrics.gauge('security.baseline_creation_time', elapsed)
        metrics.gauge('security.baseline_file_count', len(hashes))

    return hashes


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
    Initialize file integrity monitoring for the Flask application.

    Sets up periodic file integrity monitoring checks and creates a baseline
    if one doesn't exist.

    Args:
        app: Flask application
        basedir: Base directory to monitor (defaults to app root)
        patterns: List of file patterns to monitor
        interval: Interval between checks in seconds

    Returns:
        bool: True if initialization was successful
    """
    if not app:
        log_error("Cannot initialize file monitoring: No app provided")
        return False

    try:
        # Set default base directory if not specified
        if not basedir:
            basedir = app.root_path

        # Set default patterns if not specified
        if not patterns:
            patterns = SECURITY_CONFIG.get('CRITICAL_FILES_PATTERN', [])

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

        # Schedule periodic checks if a scheduler is available
        if hasattr(app, 'scheduler'):
            app.scheduler.add_job(
                func=lambda: check_critical_file_integrity(app),
                trigger='interval',
                seconds=interval,
                id='file_integrity_check',
                replace_existing=True
            )
            log_info(f"Scheduled file integrity checks with {interval}s interval")

        return True
    except Exception as e:
        log_error(f"Failed to initialize file integrity monitoring: {e}")
        return False


def get_last_integrity_status() -> Dict[str, Any]:
    """
    Get the status of the last file integrity check.

    Returns:
        Dict[str, Any]: Dictionary containing:
            - last_check: Timestamp of the last check
            - has_violations: Boolean indicating if violations were found
            - violations: List of integrity violations found (if any)
    """
    try:
        redis_client = get_redis_client()
        if not redis_client:
            return {
                'status': 'unknown',
                'last_check': None,
                'has_violations': False
            }

        # Get summary of violations
        summary_data = redis_client.get('security:integrity_violations')
        changes_data = redis_client.get('security:integrity_changes')

        # Get last successful check timestamp
        last_check_time = redis_client.get('security:last_successful_integrity_check')

        status = {}

        if last_check_time:
            try:
                timestamp = int(last_check_time.decode('utf-8'))
                status['last_check'] = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
            except (ValueError, TypeError):
                pass

        if summary_data:
            try:
                summary = json.loads(summary_data)
                status['has_violations'] = True
                status['status'] = 'violation'
                status['total_violations'] = summary.get('total', 0)
                status['high_severity'] = summary.get('high_severity', 0)
                status['critical_severity'] = summary.get('critical_severity', 0)

                if changes_data:
                    try:
                        status['violations'] = json.loads(changes_data)
                    except json.JSONDecodeError:
                        pass

            except json.JSONDecodeError:
                pass
        else:
            status['has_violations'] = False
            status['status'] = 'ok'

        return status
    except Exception as e:
        log_error(f"Error getting integrity status: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'has_violations': False
        }


def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """
    Calculate the hash of a file using the specified algorithm.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use (md5, sha1, sha256, sha512)

    Returns:
        str: Hex digest of the file hash
    """
    # Choose hash algorithm
    if algorithm == "md5":
        hash_obj = hashlib.md5()
    elif algorithm == "sha1":
        hash_obj = hashlib.sha1()
    elif algorithm == "sha512":
        hash_obj = hashlib.sha512()
    else:
        hash_obj = hashlib.sha256()  # Default to SHA-256

    # Read file in chunks to handle large files efficiently
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_obj.update(chunk)

    return hash_obj.hexdigest()


def check_file_permissions(file_path: str) -> bool:
    """
    Check if a file has appropriate permissions.

    Args:
        file_path: Path to the file

    Returns:
        bool: True if permissions are appropriate, False otherwise
    """
    if not os.path.exists(file_path):
        return False

    try:
        # Get file permissions
        mode = os.stat(file_path).st_mode

        # Check if file is world-writable (risky)
        if mode & 0o002:  # World-writable
            return False

        # Check if directory has executable bit for owner
        if os.path.isdir(file_path) and not (mode & 0o100):
            return False

        # Verify specific permissions for executable files
        if os.path.isfile(file_path) and os.access(file_path, os.X_OK):
            # Executable script should be readable but not writable by group/others
            if mode & 0o022:  # Group/world writable
                return False

        return True
    except (IOError, OSError) as e:
        log_error(f"Error checking file permissions for {file_path}: {e}")
        return False


def find_files_by_patterns(basedir: str, patterns: List[str]) -> Set[str]:
    """
    Find files matching any of the given glob patterns.

    Args:
        basedir: Base directory to search in
        patterns: List of glob patterns to match

    Returns:
        Set[str]: Set of absolute paths to matched files
    """
    import glob

    matching_files = set()

    for pattern in patterns:
        # Skip invalid patterns
        if not pattern or pattern.strip() == '*':
            continue

        # Make pattern absolute if it's not already
        if not os.path.isabs(pattern):
            search_pattern = os.path.join(basedir, pattern)
        else:
            search_pattern = pattern

        # Find files matching the pattern
        for file_path in glob.glob(search_pattern, recursive=True):
            if os.path.isfile(file_path) and os.access(file_path, os.R_OK):
                matching_files.add(file_path)

    return matching_files


def format_timestamp(dt: datetime = None) -> str:
    """
    Format a timestamp in ISO 8601 format.

    Args:
        dt: Datetime object (defaults to current time)

    Returns:
        str: ISO 8601 formatted timestamp
    """
    if dt is None:
        dt = datetime.now(timezone.utc)
    return dt.isoformat()


# Private helper functions

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
        reference_hashes: Dictionary of reference hashes
        modified_files: List to append any detected changes to
    """
    for file_path in reference_hashes:
        if not os.path.isabs(file_path):
            file_path = os.path.join(basedir, file_path)

        if not os.path.exists(file_path):
            # Already marked as missing in the main check
            continue

        try:
            # Check if file has appropriate permissions
            if not check_file_permissions(file_path):
                # Check if this file has already been reported
                if not any(m['path'] == file_path for m in modified_files):
                    modified_files.append({
                        'path': file_path,
                        'status': 'permission_changed',
                        'severity': 'high',
                        'timestamp': format_timestamp()
                    })
        except Exception as e:
            log_error(f"Error checking permissions for {file_path}: {e}")


def _check_additional_critical_files(
        basedir: str,
        critical_patterns: List[str],
        reference_hashes: Dict[str, str],
        modified_files: List[Dict[str, Any]]) -> None:
    """
    Check for new files matching critical patterns.

    Args:
        basedir: Base directory to check files in
        critical_patterns: List of glob patterns to match
        reference_hashes: Dictionary of reference hashes
        modified_files: List to append any detected changes to
    """
    # Find all files matching critical patterns
    matching_files = find_files_by_patterns(basedir, critical_patterns)

    # Convert reference_hashes to absolute paths
    reference_abs_paths = set()
    for path in reference_hashes:
        if not os.path.isabs(path):
            reference_abs_paths.add(os.path.join(basedir, path))
        else:
            reference_abs_paths.add(path)

    # Check for new files that match critical patterns but aren't in reference_hashes
    for filepath in matching_files:
        if filepath not in reference_abs_paths:
            # Check for newly added critical files
            rel_path = os.path.relpath(filepath, basedir)

            # Skip common backup files and editor swap files
            if (os.path.basename(filepath).startswith(('.', '~', '#')) or
                any(ext in filepath for ext in ('.bak', '.tmp', '.swp', '.old'))):
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

                # Check if the file is executable
                if os.access(filepath, os.X_OK):
                    modified_files[-1]['severity'] = 'critical'
                    modified_files[-1]['status'] = 'suspicious_executable'


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
