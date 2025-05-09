"""
Services Package for Cloud Infrastructure Platform.

This package provides service-layer functionality that encapsulates business logic
and complex operations independently from presentation concerns. Services are designed
to be reusable across different presentation layers (API, CLI, web interface).
"""

import logging
import os
from typing import Dict, Any, List, Optional, Callable, Tuple, Union
from pathlib import Path
from datetime import datetime, timezone
import json
import sys
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Track feature availability
AUTH_SERVICE_AVAILABLE = False
EMAIL_SERVICE_AVAILABLE = False
NEWSLETTER_SERVICE_AVAILABLE = False
SECURITY_SERVICE_AVAILABLE = False
SCANNING_SERVICE_AVAILABLE = False
WEBHOOK_SERVICE_AVAILABLE = False
NOTIFICATION_SERVICE_AVAILABLE = False
NOTIFICATION_MODULE_AVAILABLE = False
SMS_SERVICE_AVAILABLE = False
HAS_INTEGRITY_NOTIFICATIONS = False
HAS_SCAN_NOTIFICATIONS = False

# Import service constants
try:
    from .service_constants import (
        # Version info
        __version__, __author__,

        # Notification channels
        CHANNEL_IN_APP, CHANNEL_EMAIL, CHANNEL_SMS, CHANNEL_WEBHOOK,

        # File integrity constants
        DEFAULT_HASH_ALGORITHM, DEFAULT_BASELINE_FILE_PATH,
        AUTO_UPDATE_LIMIT, DEFAULT_BASELINE_BACKUP_COUNT,

        # Scanning constants
        DEFAULT_SCAN_PROFILES, MAX_CONCURRENT_SCANS,
        SCAN_STATUS_PENDING, SCAN_STATUS_RUNNING, SCAN_STATUS_COMPLETED,
        SCAN_STATUS_FAILED, SCAN_STATUS_CANCELLED, SCAN_STATUS_TIMEOUT,

        # Notification categories
        NOTIFICATION_CATEGORY_SYSTEM, NOTIFICATION_CATEGORY_SECURITY,
        NOTIFICATION_CATEGORY_USER, NOTIFICATION_CATEGORY_ADMIN,
        NOTIFICATION_CATEGORY_MAINTENANCE, NOTIFICATION_CATEGORY_MONITORING,
        NOTIFICATION_CATEGORY_COMPLIANCE, NOTIFICATION_CATEGORY_INTEGRITY,
        NOTIFICATION_CATEGORY_AUDIT, NOTIFICATION_CATEGORY_SCAN,
        NOTIFICATION_CATEGORY_VULNERABILITY, NOTIFICATION_CATEGORY_INCIDENT,

        # SMS Service Constants
        SMS_DEFAULT_REGION,
        SMS_MAX_LENGTH,
        SMS_RETRY_COUNT,
        SMS_CRITICAL_PRIORITY,
        SMS_HIGH_PRIORITY,
        SMS_MEDIUM_PRIORITY,
        SMS_LOW_PRIORITY,
        SMS_RATE_LIMIT_WINDOW,
        SMS_RATE_LIMIT_MAX_PER_USER,
        SMS_ALLOWED_DOMAINS,
        SMS_STATUS_QUEUED,
        SMS_STATUS_SENDING,
        SMS_STATUS_SENT,
        SMS_STATUS_DELIVERED,
        SMS_STATUS_FAILED,
        SMS_STATUS_UNDELIVERABLE,
        SMS_STATUS_UNKNOWN,
        SMS_PROVIDER_SETTINGS
    )
    SERVICE_CONSTANTS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Service constants not available: {e}")
    SERVICE_CONSTANTS_AVAILABLE = False
    # Set fallback defaults
    __version__ = '0.2.0'
    __author__ = 'Cloud Infrastructure Platform Team'

    # Notification channels - fallback definitions
    CHANNEL_IN_APP = 'in_app'
    CHANNEL_EMAIL = 'email'
    CHANNEL_SMS = 'sms'
    CHANNEL_WEBHOOK = 'webhook'

    # File integrity constants - fallback definitions
    DEFAULT_HASH_ALGORITHM = 'sha256'
    DEFAULT_BASELINE_FILE_PATH = 'instance/security/baseline.json'
    AUTO_UPDATE_LIMIT = 10
    DEFAULT_BASELINE_BACKUP_COUNT = 5

    # Scanning constants - fallback definitions
    DEFAULT_SCAN_PROFILES = {}
    MAX_CONCURRENT_SCANS = 5
    SCAN_STATUS_PENDING = 'pending'
    SCAN_STATUS_RUNNING = 'running'
    SCAN_STATUS_COMPLETED = 'completed'
    SCAN_STATUS_FAILED = 'failed'
    SCAN_STATUS_CANCELLED = 'cancelled'
    SCAN_STATUS_TIMEOUT = 'timeout'

    # Notification categories - fallback definitions
    NOTIFICATION_CATEGORY_SYSTEM = 'system'
    NOTIFICATION_CATEGORY_SECURITY = 'security'
    NOTIFICATION_CATEGORY_USER = 'user'
    NOTIFICATION_CATEGORY_ADMIN = 'admin'
    NOTIFICATION_CATEGORY_MAINTENANCE = 'maintenance'
    NOTIFICATION_CATEGORY_MONITORING = 'monitoring'
    NOTIFICATION_CATEGORY_COMPLIANCE = 'compliance'
    NOTIFICATION_CATEGORY_INTEGRITY = 'integrity'
    NOTIFICATION_CATEGORY_AUDIT = 'audit'
    NOTIFICATION_CATEGORY_SCAN = 'scan'
    NOTIFICATION_CATEGORY_VULNERABILITY = 'vulnerability'
    NOTIFICATION_CATEGORY_INCIDENT = 'incident'

    # SMS Service fallback constants
    SMS_DEFAULT_REGION = 'US'
    SMS_MAX_LENGTH = 160
    SMS_RETRY_COUNT = 3
    SMS_CRITICAL_PRIORITY = 'critical'
    SMS_HIGH_PRIORITY = 'high'
    SMS_MEDIUM_PRIORITY = 'medium'
    SMS_LOW_PRIORITY = 'low'
    SMS_RATE_LIMIT_WINDOW = 300  # 5 minutes
    SMS_RATE_LIMIT_MAX_PER_USER = 5  # 5 messages per window
    SMS_ALLOWED_DOMAINS = []
    SMS_STATUS_QUEUED = 'queued'
    SMS_STATUS_SENDING = 'sending'
    SMS_STATUS_SENT = 'sent'
    SMS_STATUS_DELIVERED = 'delivered'
    SMS_STATUS_FAILED = 'failed'
    SMS_STATUS_UNDELIVERABLE = 'undeliverable'
    SMS_STATUS_UNKNOWN = 'unknown'
    SMS_PROVIDER_SETTINGS = {
        'twilio': {},
        'aws_sns': {},
        'messagebird': {},
        'vonage': {}
    }

# Try importing metrics
try:
    from core.metrics import metrics
    METRICS_AVAILABLE = True
except ImportError:
    logger.debug("Metrics module not available")
    METRICS_AVAILABLE = False
    # Create dummy metrics object
    class DummyMetrics:
        def increment(self, *args, **kwargs):
            pass

        def decrement(self, *args, **kwargs):
            pass

        def gauge(self, *args, **kwargs):
            pass

        def histogram(self, *args, **kwargs):
            pass

        def timing(self, *args, **kwargs):
            pass

    metrics = DummyMetrics()

# Import and expose NotificationManager from the notification package
try:
    from .notification import (
        NotificationManager,
        notification_manager,
        notify_stakeholders,
        NOTIFICATION_CATEGORY_SYSTEM,
        NOTIFICATION_CATEGORY_SECURITY,
        NOTIFICATION_CATEGORY_USER,
        NOTIFICATION_CATEGORY_ADMIN,
        NOTIFICATION_CATEGORY_MAINTENANCE,
        NOTIFICATION_CATEGORY_MONITORING,
        NOTIFICATION_CATEGORY_COMPLIANCE,
        NOTIFICATION_CATEGORY_INTEGRITY,
        NOTIFICATION_CATEGORY_AUDIT,
        NOTIFICATION_CATEGORY_SCAN,
        NOTIFICATION_CATEGORY_VULNERABILITY,
        NOTIFICATION_CATEGORY_INCIDENT
    )

    # Import convenience functions if available
    try:
        from .notification import send_integrity_notification
        HAS_INTEGRITY_NOTIFICATIONS = True
    except ImportError:
        HAS_INTEGRITY_NOTIFICATIONS = False

    try:
        from .notification import send_scan_notification
        HAS_SCAN_NOTIFICATIONS = True
    except ImportError:
        HAS_SCAN_NOTIFICATIONS = False

    NOTIFICATION_MODULE_AVAILABLE = True
    logger.debug("Notification module available")
except ImportError as e:
    logger.warning(f"Notification module not available: {e}")
    HAS_INTEGRITY_NOTIFICATIONS = False
    HAS_SCAN_NOTIFICATIONS = False
    NOTIFICATION_MODULE_AVAILABLE = False

# Try to import original NotificationService (for backward compatibility)
try:
    from .notification_service import (
        NotificationService,
        send_system_notification,
        send_security_alert,
        send_success_notification,
        send_warning_notification,
        send_user_notification
    )
    NOTIFICATION_SERVICE_AVAILABLE = True
except ImportError:
    NOTIFICATION_SERVICE_AVAILABLE = False
    if not NOTIFICATION_MODULE_AVAILABLE:
        logger.warning("NotificationService functionality may be limited or unavailable")

# Import other services if available
try:
    from .auth_service import AuthService
    AUTH_SERVICE_AVAILABLE = True
except ImportError:
    logger.warning("AuthService not available")

# Import AuditService if available
try:
    from .audit_service import AuditService
except ImportError:
    logger.warning("AuditService not available")

try:
    from .email_service import EmailService, send_email, send_template_email, validate_email_address, test_email_configuration
    EMAIL_SERVICE_AVAILABLE = True
except ImportError:
    logger.warning("EmailService not available")

try:
    from .newsletter_service import NewsletterService
    NEWSLETTER_SERVICE_AVAILABLE = True
except ImportError:
    logger.warning("NewsletterService not available")

try:
    from .security_service import SecurityService
    SECURITY_SERVICE_AVAILABLE = True
except ImportError:
    logger.warning("SecurityService not available")

try:
    from .scanning_service import ScanningService
    SCANNING_SERVICE_AVAILABLE = True
except ImportError:
    logger.warning("ScanningService not available")

try:
    from .webhook_service import WebhookService
    WEBHOOK_SERVICE_AVAILABLE = True
except ImportError:
    logger.warning("WebhookService not available")

# Try to import SMS Service
try:
    from .sms_service import (
        SMSService,
        SMSProvider,
        send_sms,
        send_bulk_sms,
        verify_phone_number,
        test_sms_configuration
    )
    SMS_SERVICE_AVAILABLE = True
except ImportError:
    logger.warning("SMSService not available")
    SMS_SERVICE_AVAILABLE = False

# Export classes and functions to make them available when importing this package
__all__ = [
    # Service classes
    'AuthService',
    'EmailService',
    'NewsletterService',
    'ScanningService',
    'SecurityService',
    'WebhookService',
    'NotificationManager',
    'NotificationService',

    # Email utility functions
    'send_email',
    'send_template_email',
    'validate_email_address',
    'test_email_configuration',

    # Notification functions
    'send_system_notification',
    'send_security_alert',
    'send_success_notification',
    'send_warning_notification',
    'send_user_notification',
    'notify_stakeholders',

    # Notification channels
    'CHANNEL_IN_APP',
    'CHANNEL_EMAIL',
    'CHANNEL_SMS',
    'CHANNEL_WEBHOOK',

    # Notification categories
    'NOTIFICATION_CATEGORY_SYSTEM',
    'NOTIFICATION_CATEGORY_SECURITY',
    'NOTIFICATION_CATEGORY_USER',
    'NOTIFICATION_CATEGORY_ADMIN',
    'NOTIFICATION_CATEGORY_MAINTENANCE',
    'NOTIFICATION_CATEGORY_MONITORING',
    'NOTIFICATION_CATEGORY_COMPLIANCE',
    'NOTIFICATION_CATEGORY_INTEGRITY',
    'NOTIFICATION_CATEGORY_AUDIT',
    'NOTIFICATION_CATEGORY_SCAN',
    'NOTIFICATION_CATEGORY_VULNERABILITY',
    'NOTIFICATION_CATEGORY_INCIDENT',

    # SMS functions
    'send_sms',
    'send_bulk_sms',
    'verify_phone_number',
    'test_sms_configuration',

    # Security functions
    'check_integrity',
    'update_security_baseline',
    'verify_file_hash',
    'calculate_file_hash',
    'get_integrity_status',
    'schedule_integrity_check',
    'update_file_integrity_baseline',
    'update_file_baseline',
    'verify_baseline_consistency',
    'export_baseline',
    'validate_baseline_consistency',

    # Scanning functions
    'run_security_scan',
    'get_scan_status',
    'get_scan_results',
    'get_scan_history',
    'get_scan_profiles',
    'start_security_scan',
    'cancel_security_scan',
    'get_scan_health_metrics',
    'estimate_scan_duration',

    # Webhook functions
    'trigger_webhook_event',
    'create_webhook_subscription',
    'get_webhook_subscription',
    'update_webhook_subscription',
    'delete_webhook_subscription',
    'check_subscription_health',

    # Feature availability flags
    'SECURITY_SERVICE_AVAILABLE',
    'SCANNING_SERVICE_AVAILABLE',
    'EMAIL_SERVICE_AVAILABLE',
    'NOTIFICATION_SERVICE_AVAILABLE',
    'NOTIFICATION_MODULE_AVAILABLE',
    'AUTH_SERVICE_AVAILABLE',
    'NEWSLETTER_SERVICE_AVAILABLE',
    'WEBHOOK_SERVICE_AVAILABLE',
    'SMS_SERVICE_AVAILABLE',

    # Version info
    '__version__'
]

# Conditionally add notification integration functions if available
if HAS_INTEGRITY_NOTIFICATIONS:
    __all__.append('send_integrity_notification')

if HAS_SCAN_NOTIFICATIONS:
    __all__.append('send_scan_notification')

# Conditionally add SMS service components if available
if SMS_SERVICE_AVAILABLE:
    __all__.extend([
        'SMSService',
        'SMSProvider'
    ])

# Conditionally add security functions if SecurityService is available
if SECURITY_SERVICE_AVAILABLE:
    # Helper functions from SecurityService
    def check_integrity(paths: Optional[List[str]] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Check file integrity against the stored baseline.

        Args:
            paths: Optional list of paths to check, if None all baseline files are checked

        Returns:
            Tuple of (integrity_status, changes)
            - integrity_status: True if all files match baseline, False otherwise
            - changes: List of dictionaries detailing any changes found
        """
        return SecurityService.check_file_integrity(paths)

    def update_security_baseline(paths_to_update: Optional[List[str]] = None,
                               remove_missing: bool = False) -> Tuple[bool, str]:
        """
        Update the security baseline.

        Args:
            paths_to_update: Optional list of paths to update. If None, updates all baseline files.
            remove_missing: Whether to remove entries for files that no longer exist

        Returns:
            Tuple containing (success, message)
        """
        return SecurityService.update_baseline(paths_to_update, remove_missing)

    def verify_file_hash(filepath: str, expected_hash: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Verify the hash of a file against an expected value or baseline.

        Args:
            filepath: Path to the file to verify
            expected_hash: Optional hash to check against, if None gets from baseline

        Returns:
            Tuple containing (match_status, details)
        """
        return SecurityService.verify_file_hash(filepath, expected_hash)

    def calculate_file_hash(filepath: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> Optional[str]:
        """
        Calculate the hash of a file using the specified algorithm.

        Args:
            filepath: Path to the file to hash
            algorithm: Hash algorithm to use (default: from service constants)

        Returns:
            String hash of the file or None if hashing fails
        """
        return SecurityService._calculate_hash(Path(filepath), algorithm)

    def schedule_integrity_check(interval_seconds: int = 3600,
                               callback: Optional[Callable[[bool, List[Dict[str, Any]]], None]] = None) -> bool:
        """
        Schedule periodic file integrity checks.

        Args:
            interval_seconds: Interval between checks in seconds
            callback: Optional callable invoked with check results

        Returns:
            True if scheduling succeeded, False otherwise
        """
        return SecurityService.schedule_integrity_check(interval_seconds, callback)

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
            try:
                if 'AuditService' in globals():
                    audit_service = AuditService
            except Exception as e:
                logger.debug(f"Could not access AuditService: {e}")

            # Use SecurityService to update baseline
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

    def update_file_baseline(baseline_path: str,
                            updates: Dict[str, str],
                            remove_missing: bool = False,
                            create_if_missing: bool = False) -> Tuple[bool, str]:
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
            success, message = SecurityService.update_baseline(paths_to_update=paths,
                                                             remove_missing=remove_missing)

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

    # Add alias to match the name imported in main __init__.py
    validate_baseline_consistency = verify_baseline_consistency

    # Add to __all__ to expose the function
    __all__.extend([
        'verify_baseline_consistency',
        'validate_baseline_consistency'
    ])

    def export_baseline(baseline_path: Optional[str] = None, destination: Optional[str] = None,
                       format_type: str = "json") -> Tuple[bool, str]:
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

            # Handle different export formats
            baseline_data = SecurityService._load_baseline(source_file)

            if format_type == "json":
                with open(dest_path, 'w') as f:
                    json.dump(baseline_data, f, indent=2)
                return True, f"Baseline exported to JSON: {destination}"

            elif format_type == "yaml":
                try:
                    with open(dest_path, 'w') as f:
                        yaml.safe_dump(baseline_data, f, default_flow_style=False)
                    return True, f"Baseline exported to YAML: {destination}"
                except Exception as e:
                    return False, f"Failed to export to YAML: {str(e)}"
            else:
                return False, f"Unsupported export format: {format_type}"

        except Exception as e:
            logger.error(f"Error exporting baseline: {str(e)}")
            return False, f"Export failed: {str(e)}"

    def get_integrity_status() -> Dict[str, Any]:
        """
        Get the current file integrity monitoring status.

        Returns:
            Dictionary containing status information
        """
        return SecurityService.get_integrity_status()

    # Implement the enhanced version of update_file_integrity_baseline_with_notifications
    def update_file_integrity_baseline_with_notifications(
        baseline_path: str,
        changes: List[Dict[str, Any]],
        remove_missing: bool = False,
        notify: bool = True,
        audit: bool = True,
        severity_threshold: str = 'high',
        update_limit: int = AUTO_UPDATE_LIMIT
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

        Returns:
            Tuple containing (success, message, stats)
        """
        success = False
        message = "Operation not completed"

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
            message = f"Too many changes requested ({len(changes)}). Maximum allowed: {update_limit}"
            logger.warning(message)
            stats["changes_rejected"] = len(changes)
            return False, message, stats

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
            if audit and 'AuditService' in globals() and hasattr(AuditService, 'log_file_integrity_event'):
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
                            'remove_missing': remove_missing
                        },
                        severity=audit_severity
                    )
                except Exception as e:
                    logger.warning(f"Failed to log baseline update start event: {e}")

            # First attempt the update using the SecurityService
            result = SecurityService.update_baseline(
                paths_to_update=[change.get('path') for change in validated_changes if 'path' in change],
                remove_missing=remove_missing
            )
            success, message = result

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
                if audit and 'AuditService' in globals() and hasattr(AuditService, 'log_file_integrity_event'):
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
                                'message': message
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
                if audit and 'AuditService' in globals() and hasattr(AuditService, 'log_file_integrity_event'):
                    try:
                        AuditService.log_file_integrity_event(
                            status='error',
                            action='update',
                            changes=None,
                            details={
                                'baseline_path': baseline_path,
                                'error': message
                            },
                            severity='warning'
                        )
                        stats["audit_logged"] = True
                    except Exception as e:
                        logger.warning(f"Failed to log baseline update failure: {e}")

        except Exception as e:
            message = f"Error updating file integrity baseline: {str(e)}"
            logger.error(message)
            metrics.increment('security.baseline.update_error')
            success = False

        finally:
            # Calculate duration
            end_time = datetime.now(timezone.utc)
            stats["duration_ms"] = (end_time - start_time).total_seconds() * 1000

        return success, message, stats

    __all__.append('update_file_integrity_baseline_with_notifications')

if not HAS_SCAN_NOTIFICATIONS and SCANNING_SERVICE_AVAILABLE and NOTIFICATION_MODULE_AVAILABLE:
    def send_scan_notification(scan_id: str, scan_type: str, status: str,
                             findings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Send notifications about scan results.

        Args:
            scan_id: Unique identifier for the scan
            scan_type: Type of scan performed
            status: Current scan status
            findings: Optional scan findings

        Returns:
            Dictionary with notification results
        """
        result = {
            'success': False,
            'notifications_sent': 0,
            'error': None
        }

        try:
            if not NOTIFICATION_MODULE_AVAILABLE:
                result['error'] = 'Notification module not available'
                return result

            # Determine notification level based on findings
            level = 'info'
            if findings:
                critical_findings = findings.get('critical_count', 0)
                high_findings = findings.get('high_count', 0)

                if critical_findings > 0:
                    level = 'critical'
                elif high_findings > 0:
                    level = 'warning'

            # Create appropriate message based on status
            if status == 'completed':
                if findings:
                    message = (
                        f"Scan {scan_id} completed. "
                        f"Found: {findings.get('critical_count', 0)} critical, "
                        f"{findings.get('high_count', 0)} high, "
                        f"{findings.get('medium_count', 0)} medium, "
                        f"{findings.get('low_count', 0)} low severity issues."
                    )
                else:
                    message = f"Scan {scan_id} completed successfully."
            elif status == 'failed':
                message = f"Scan {scan_id} failed. Please check logs for details."
                level = 'warning'
            else:
                message = f"Scan {scan_id} status changed to: {status}"

            # Send notification
            notification_manager.send_to_stakeholders(
                subject=f"Security Scan {status.capitalize()}: {scan_type}",
                message=message,
                category=NOTIFICATION_CATEGORY_SCAN,
                level=level,
                data={
                    'scan_id': scan_id,
                    'scan_type': scan_type,
                    'status': status,
                    'findings': findings
                }
            )

            result['success'] = True
            result['notifications_sent'] = 1  # We could track actual count from the notification manager if needed

            return result

        except Exception as e:
            logger.error(f"Error sending scan notification: {str(e)}")
            result['error'] = str(e)
            return result

    __all__.append('send_scan_notification')

# Log package initialization
logger.debug(f"Services package initialized (version: {__version__}), " +
            f"Security service available: {SECURITY_SERVICE_AVAILABLE}, " +
            f"Scanning service available: {SCANNING_SERVICE_AVAILABLE}, " +
            f"Notification module available: {NOTIFICATION_MODULE_AVAILABLE}, " +
            f"SMS service available: {SMS_SERVICE_AVAILABLE}, " +
            f"Auth service available: {AUTH_SERVICE_AVAILABLE}")
