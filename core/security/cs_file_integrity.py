#
# File Integrity and Security Functions
#
import os
from typing import List, Dict, Any, Optional, Tuple, Union, Set, TypeVar, cast

# Flask imports
from flask import current_app, request, g, has_request_context, session, has_app_context

# Cryptography imports
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Internal imports
from models.audit_log import AuditLog
from extensions import db, metrics
from cs_audit import log_security_event
from core.utils import (
    detect_file_changes, calculate_file_hash, format_timestamp,
    log_error, log_warning, log_info, log_debug
)





def _initialize_file_integrity_monitoring():
    """
    Initialize file integrity monitoring.
    """
    if not has_app_context():
        return

    # Check if file integrity monitoring is enabled
    if not current_app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
        return

    # Get file paths to monitor from configuration
    critical_files = current_app.config.get('SECURITY_CRITICAL_FILES', [])
    if not critical_files:
        return

    # Calculate and store reference hashes
    try:
        from core.utils import get_critical_file_hashes
        hashes = get_critical_file_hashes(critical_files)
        current_app.config['CRITICAL_FILE_HASHES'] = hashes
        log_info(f"Initialized file integrity monitoring for {len(hashes)} files")
    except Exception as e:
        log_error(f"Failed to initialize file integrity monitoring: {e}")


def check_file_integrity(file_path: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
    """
    Verify integrity of a file by comparing its hash with expected value.

    Args:
        file_path: Path to the file to check
        expected_hash: Expected hash value to compare against
        algorithm: Hash algorithm to use ('sha256', 'sha384', 'sha512')

    Returns:
        bool: True if file hash matches expected hash, False otherwise
    """
    if not os.path.exists(file_path):
        log_warning(f"File does not exist: {file_path}")
        return False

    try:
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

        return len(failed_files) == 0
    except Exception as e:
        log_error(f"Error in check_config_integrity: {e}")
        return False


def check_critical_file_integrity(app=None) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Verify integrity of critical application files.

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
        critical_patterns = app.config.get('CRITICAL_FILE_PATTERNS', ['*.py', 'config.*', '.env*'])
        detect_permissions = app.config.get('DETECT_FILE_PERMISSIONS', True)
        check_signatures = app.config.get('CHECK_FILE_SIGNATURES', False)

        # Use the more comprehensive detection function
        changes = detect_file_changes(
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
            high_severity = sum(1 for c in changes if c.get('severity') in ('high', 'critical'))
            metrics.gauge('security.modified_critical_files', len(changes))
            metrics.gauge('security.high_severity_changes', high_severity)

            return False, changes

        return True, []
    except Exception as e:
        log_error(f"Error in check_critical_file_integrity: {e}")
        return False, [{"path": "system", "status": "error", "severity": "high", "details": str(e)}]


def verify_file_signature(file_path: str, signature_path: Optional[str] = None) -> bool:
    """
    Verify the cryptographic signature of a file.

    This function verifies that a file matches its cryptographic signature,
    ensuring the file has not been tampered with and comes from a trusted source.

    Args:
        file_path: Path to the file to verify
        signature_path: Path to signature file (defaults to file_path + '.sig')

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

        # Get public key from configuration
        public_key_path = None
        if has_app_context():
            public_key_path = current_app.config.get('SIGNATURE_PUBLIC_KEY_PATH')

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
        return True

    except InvalidSignature:
        log_warning(f"Invalid signature for file: {file_path}")
        metrics.increment('security.invalid_signature')
        return False
    except Exception as e:
        log_error(f"Error verifying file signature {file_path}: {e}")
        return False
