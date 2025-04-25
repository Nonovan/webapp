"""
File integrity verification functionality.

This module provides functions to verify the integrity of critical files
by comparing current file hashes with reference values, checking for
unauthorized modifications, and validating digital signatures.
"""

import os
import glob
import hashlib
from typing import List, Dict, Any, Optional, Tuple, Union, Set

# Flask imports
from flask import current_app, has_app_context

# Cryptography imports
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Internal imports
from models.audit_log import AuditLog
from extensions import metrics
from .cs_audit import log_security_event
from .cs_constants import SECURITY_CONFIG
from core.utils import (
    calculate_file_hash, format_timestamp,
    log_error, log_warning, log_info, log_debug
)


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
        return False

    try:
        # Use default hash algorithm from SECURITY_CONFIG if none specified
        if algorithm is None and has_app_context():
            algorithm = SECURITY_CONFIG.get('FILE_HASH_ALGORITHM', 'sha256')
        elif algorithm is None:
            algorithm = 'sha256'

        current_hash = calculate_file_hash(file_path, algorithm)
        result = current_hash == expected_hash

        if not result:
            log_warning(f"File integrity check failed for {file_path}")
            metrics.increment('security.file_integrity_failed')

        return result
    except (IOError, OSError) as e:
        log_error(f"Error checking file integrity for {file_path}: {e}")
        return False
    except ValueError as e:
        log_error(f"Invalid hash algorithm '{algorithm}' for {file_path}: {e}")
        return False


def check_config_integrity(app=None) -> bool:
    """
    Verify integrity of critical configuration files.

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

        failed_files = []

        # Check each file against its expected hash
        for file_path, expected_hash in expected_hashes.items():
            if not os.path.exists(file_path):
                log_warning(f"Configuration file not found: {file_path}")
                failed_files.append(file_path)
                continue

            try:
                if not check_file_integrity(file_path, expected_hash):
                    log_warning(f"Configuration file integrity check failed: {file_path}")
                    failed_files.append(file_path)

                    # Record security event
                    log_security_event(
                        event_type=AuditLog.EVENT_FILE_INTEGRITY,
                        description=f"Configuration file modified: {file_path}",
                        severity='error'
                    )
            except Exception as e:
                log_error(f"Error checking integrity for {file_path}: {e}")
                failed_files.append(file_path)

        # Track metrics
        metrics.gauge('security.failed_config_files', len(failed_files))

        # If no failures, update last check time in metrics
        if len(failed_files) == 0:
            metrics.gauge('security.last_config_check', format_timestamp(as_unix_time=True))

        return len(failed_files) == 0
    except Exception as e:
        log_error(f"Error in check_config_integrity: {e}")
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
            return False, [{"path": "configuration", "status": "missing", "severity": "high"}]

        # Get monitoring settings
        basedir = os.path.dirname(os.path.abspath(app.root_path))
        critical_patterns = app.config.get(
            'CRITICAL_FILE_PATTERNS',
            SECURITY_CONFIG.get('CRITICAL_FILES_PATTERN', ['*.py', 'config.*', '.env*'])
        )
        detect_permissions = app.config.get('DETECT_FILE_PERMISSIONS', True)
        check_signatures = app.config.get('CHECK_FILE_SIGNATURES', False)

        # Detect file changes
        changes = _detect_file_changes(
            basedir,
            expected_hashes,
            critical_patterns=critical_patterns,
            detect_permissions=detect_permissions,
            check_signatures=check_signatures
        )

        if changes:
            # Log each detected change
            for change in changes:
                path = change.get('path', 'unknown')
                status = change.get('status', 'unknown')
                severity = change.get('severity', 'medium')

                log_warning(f"File integrity violation: {path} ({status})")

                # Record security event for high severity changes
                if severity in ('high', 'critical'):
                    try:
                        log_security_event(
                            event_type=AuditLog.EVENT_FILE_INTEGRITY,
                            description=f"Critical file modified: {path}",
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
            high_severity = sum(1 for c in changes if c.get('severity', '') in ('high', 'critical'))
            metrics.gauge('security.modified_critical_files', len(changes))
            metrics.gauge('security.high_severity_changes', high_severity)

            return False, changes

        # Update last check time in metrics
        metrics.gauge('security.last_integrity_check', format_timestamp(as_unix_time=True))
        return True, []
    except Exception as e:
        log_error(f"Error in check_critical_file_integrity: {e}")
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
        return False

    if signature_path is None:
        signature_path = file_path + '.sig'

    if not os.path.exists(signature_path):
        log_warning(f"Signature file not found: {signature_path}")
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
            return False

        # Load the public key
        with open(public_key_path, 'rb') as f:
            public_key = load_pem_public_key(f.read())

        # Read the file content
        with open(file_path, 'rb') as f:
            file_data = f.read()

        # Verify the signature
        public_key.verify(
            signature,
            file_data,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # If we get here, verification succeeded
        log_info(f"Signature verification successful for {file_path}")
        return True

    except InvalidSignature:
        log_warning(f"Invalid signature for file: {file_path}")
        metrics.increment('security.invalid_signature')
        return False
    except Exception as e:
        log_error(f"Error verifying file signature {file_path}: {e}")
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
            patterns = ['*.py', 'config/*', '*.ini', '*.json', '*.yaml', '*.yml']

    try:
        baseline = {}

        # Process each pattern
        for pattern in patterns:
            pattern_path = os.path.join(directory, pattern)
            # Safely handle the pattern to prevent path traversal
            for file_path in glob.glob(pattern_path, recursive=True):
                if os.path.isfile(file_path):
                    try:
                        file_hash = calculate_file_hash(file_path, algorithm)
                        baseline[file_path] = file_hash
                    except (IOError, OSError) as e:
                        log_warning(f"Could not hash file {file_path}: {e}")

        # Save to output file if specified
        if output_file and baseline:
            try:
                import json
                with open(output_file, 'w') as f:
                    json.dump(baseline, f, indent=2)
                log_info(f"File hash baseline saved to {output_file}")
            except (IOError, OSError) as e:
                log_error(f"Error saving baseline to {output_file}: {e}")

        log_info(f"Created hash baseline with {len(baseline)} files")
        return baseline

    except Exception as e:
        log_error(f"Error creating file hash baseline: {e}")
        return {}


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
                    if check_signatures and file_path.endswith(('.sh', '.py', '.exe', '.bin')):
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
    # This is a placeholder for actual permission checking logic
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
            pattern_path = os.path.join(basedir, pattern)
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
        except (IOError, ValueError, OSError) as e:
            log_error(f"Error checking critical files with pattern {pattern}: {e}")
