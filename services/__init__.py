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
        def increment(self, *args, **kwargs): pass
        def gauge(self, *args, **kwargs): pass
        def timing(self, *args, **kwargs): pass
    metrics = DummyMetrics()

# Import and expose NotificationManager from the notification package
try:
    from .notification import (
        NotificationManager,
        notification_manager,
        notify_stakeholders
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
        Check file integrity against the baseline.

        Args:
            paths: Optional list of file paths to check. If None, checks all files in baseline.

        Returns:
            Tuple containing (integrity_status, list_of_changes)
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
        Verify a file's hash against an expected value or calculate it.

        Args:
            filepath: Path to the file to check
            expected_hash: Expected hash value (if None, just returns the calculated hash)

        Returns:
            Tuple containing (match_status, details_dict)
        """
        calculated = SecurityService._calculate_hash(Path(filepath))
        if calculated is None:
            return False, {"error": "Failed to calculate hash", "file": filepath}

        if expected_hash is None:
            return True, {"hash": calculated, "file": filepath}

        match = calculated == expected_hash
        return match, {
            "match": match,
            "file": filepath,
            "calculated": calculated,
            "expected": expected_hash
        }

    def calculate_file_hash(filepath: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> Optional[str]:
        """
        Calculate a file's hash using the specified algorithm.

        Args:
            filepath: Path to the file
            algorithm: Hash algorithm to use (default: sha256)

        Returns:
            Hash value as string, or None if calculation failed
        """
        # Use SecurityService._calculate_hash but enforce the algorithm choice
        orig_algo = SecurityService.DEFAULT_HASH_ALGORITHM
        try:
            SecurityService.DEFAULT_HASH_ALGORITHM = algorithm
            return SecurityService._calculate_hash(Path(filepath))
        finally:
            SecurityService.DEFAULT_HASH_ALGORITHM = orig_algo

    def schedule_integrity_check(interval_seconds: int = 3600,
                               callback: Optional[Callable[[bool, List[Dict[str, Any]]], None]] = None) -> bool:
        """
        Schedule periodic file integrity checks.

        Args:
            interval_seconds: Time between checks in seconds
            callback: Function to call with integrity check results

        Returns:
            bool: True if scheduled successfully, False otherwise
        """
        return SecurityService.schedule_integrity_check(interval_seconds, callback)

    def update_file_integrity_baseline(
        baseline_path: str,
        updates: List[Dict[str, Any]],
        remove_missing: bool = False,
        notify_stakeholders: bool = True
    ) -> Tuple[bool, str]:
        """
        Update the file integrity baseline with changes.

        This function integrates with notification and audit services to ensure
        that baseline updates are properly tracked and relevant parties are notified.

        Args:
            baseline_path: Path to the baseline file
            updates: List of updates to apply, each containing path, hash, and status
            remove_missing: Whether to remove baseline entries for missing files
            notify_stakeholders: Whether to send notifications about major changes

        Returns:
            Tuple containing (success, message)
        """
        if not SECURITY_SERVICE_AVAILABLE:
            logger.warning("Security service not available for baseline update")
            return False, "Security service not available"

        try:
            # First attempt the update using the SecurityService
            result = SecurityService.update_baseline(
                paths_to_update=[u['path'] for u in updates if 'path' in u],
                remove_missing=remove_missing
            )
            success, message = result

            if not success:
                logger.error(f"Failed to update baseline: {message}")
                metrics.increment('security.baseline.update_failed')
                return result

            # Success - log to audit trail if available
            if 'AuditService' in globals() and hasattr(AuditService, 'log_file_integrity_event'):
                update_details = {
                    'baseline_path': baseline_path,
                    'update_count': len(updates),
                    'removed_missing': remove_missing,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }

                # Count updates by severity
                severities = {}
                for update in updates:
                    severity = update.get('severity', 'medium')
                    if severity not in severities:
                        severities[severity] = 0
                    severities[severity] += 1

                update_details['severities'] = severities

                AuditService.log_file_integrity_event(
                    status='success',
                    action='update',
                    changes=updates,
                    details=update_details,
                    severity='info'
                )

            # Send notification if enabled and there are significant updates
            if notify_stakeholders and NOTIFICATION_MODULE_AVAILABLE:
                critical_updates = [u for u in updates if u.get('severity') == 'critical']
                high_severity_updates = [u for u in updates if u.get('severity') == 'high']

                if critical_updates or len(high_severity_updates) >= 3:
                    notification_severity = 'warning' if critical_updates else 'info'

                    try:
                        notification_manager.send_to_stakeholders(
                            subject="File Integrity Baseline Updated",
                            message=f"File integrity baseline has been updated with {len(updates)} changes " +
                                    f"({len(critical_updates)} critical, {len(high_severity_updates)} high severity).",
                            level=notification_severity,
                            category=NOTIFICATION_CATEGORY_INTEGRITY,
                            data={
                                'baseline_path': baseline_path,
                                'total_changes': len(updates),
                                'critical_changes': len(critical_updates),
                                'high_severity_changes': len(high_severity_updates)
                            }
                        )
                    except Exception as e:
                        logger.warning(f"Failed to send baseline update notification: {e}")

            metrics.increment('security.baseline.update_success')
            return success, message

        except Exception as e:
            logger.error(f"Error updating file integrity baseline: {e}")
            metrics.increment('security.baseline.update_error')
            return False, f"Error updating baseline: {str(e)}"

    def update_file_baseline(baseline_path: str,
                            updates: Dict[str, str],
                            remove_missing: bool = False,
                            create_if_missing: bool = False) -> Tuple[bool, str]:
        """
        Update file integrity baseline with new hashes.

        This function provides a direct way to update the file baseline with explicit
        hash values without requiring a Flask application context.

        Args:
            baseline_path: Path to the baseline JSON file
            updates: Dictionary mapping file paths to new hashes
            remove_missing: Whether to remove entries for files that no longer exist
            create_if_missing: Whether to create the baseline file if it doesn't exist

        Returns:
            Tuple of (success, message)
        """
        try:
            # Try to use the utility from core
            try:
                from core.utils import update_file_integrity_baseline as core_update_baseline
                return core_update_baseline(baseline_path, updates, remove_missing)
            except ImportError:
                logger.debug("Core utility not available, using SecurityService directly")

            # Convert baseline_path to Path object for consistency
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
                    logger.warning(f"Hash mismatch after baseline update for: {mismatched}")

                    # Force update the file directly with exact hashes if mismatches found
                    try:
                        # Make a copy of the baseline data and update it with the exact hashes
                        updated_baseline = baseline_data.copy()
                        for path, hash_value in updates.items():
                            if path in updated_baseline["files"]:
                                updated_baseline["files"][path] = hash_value

                        # Write the updated baseline back to file
                        SecurityService._save_baseline(updated_baseline, baseline_file)
                        logger.info(f"Forced update of {len(mismatched)} hash values to match exactly")
                        return True, f"{message} (with {len(mismatched)} forced hash updates)"
                    except Exception as e:
                        logger.error(f"Failed to force hash updates: {e}")

            return success, message

        except Exception as e:
            logger.error(f"Unexpected error updating file baseline: {str(e)}")
            return False, f"Error: {str(e)}"

    def verify_baseline_consistency(baseline_path: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Verify the consistency and integrity of a file integrity baseline.

        Args:
            baseline_path: Path to the baseline file (uses default if None)

        Returns:
            Tuple containing (consistency_status, details_dict)
        """
        result = {
            "exists": False,
            "readable": False,
            "valid_format": False,
            "has_required_fields": False,
            "has_metadata": False,
            "file_count": 0,
            "metadata_keys": [],
            "errors": [],
            "size": 0,
            "last_modified": None,
            "permissions": None,
        }

        try:
            # Determine baseline path
            if baseline_path is None:
                baseline_path = SecurityService.get_baseline_path()
                if baseline_path is None:
                    baseline_path = str(DEFAULT_BASELINE_FILE_PATH)

            # Check if file exists and is readable
            baseline_file = Path(baseline_path)
            result["exists"] = baseline_file.exists()
            result["readable"] = baseline_file.exists() and os.access(baseline_file, os.R_OK)

            if not result["exists"]:
                result["errors"].append("Baseline file does not exist")
                return False, result

            if not result["readable"]:
                result["errors"].append("Baseline file is not readable")
                return False, result

            # Get file stats
            try:
                stats = baseline_file.stat()
                result["last_modified"] = datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc).isoformat()
                result["size"] = stats.st_size
            except OSError as e:
                result["errors"].append(f"Error getting file stats: {e}")

            # Check file permissions
            if os.name == 'posix':
                permissions = stats.st_mode & 0o777
                result["permissions"] = oct(permissions)[2:]

                if permissions & 0o077:  # Check if world or group has any access
                    result["errors"].append(f"Insecure permissions: {result['permissions']}")

            # Try to load baseline and validate content
            try:
                baseline_data = SecurityService._load_baseline(baseline_file)

                # Check required fields
                if "files" in baseline_data:
                    result["has_required_fields"] = True
                    result["file_count"] = len(baseline_data["files"])
                else:
                    result["errors"].append("Missing 'files' in baseline data")

                # Check metadata
                if "metadata" in baseline_data:
                    result["has_metadata"] = True
                    result["metadata_keys"] = list(baseline_data["metadata"].keys())
                else:
                    result["metadata_keys"] = []

                # Passed all checks
                result["valid_format"] = result["has_required_fields"]

            except Exception as e:
                result["errors"].append(f"Error parsing baseline content: {e}")
                result["valid_format"] = False

            # Overall consistency status
            is_consistent = (
                result["exists"] and
                result["readable"] and
                result["valid_format"] and
                result["has_required_fields"]
            )

            return is_consistent, result

        except Exception as e:
            result["errors"].append(f"Unexpected error: {str(e)}")
            return False, result

    def export_baseline(baseline_path: Optional[str] = None, destination: Optional[str] = None,
                       format_type: str = "json") -> Tuple[bool, str]:
        """
        Export the file integrity baseline to a different location or format.

        Args:
            baseline_path: Path to source baseline file (uses default if None)
            destination: Path for exported baseline (auto-generated if None)
            format_type: Format for export ("json" or "yaml")

        Returns:
            Tuple of (success, message)
        """
        try:
            # Determine source baseline path
            if baseline_path is None:
                baseline_path = SecurityService.get_baseline_path()
                if baseline_path is None:
                    baseline_path = str(DEFAULT_BASELINE_FILE_PATH)

            source_file = Path(baseline_path)
            if not source_file.exists():
                return False, f"Baseline file not found: {baseline_path}"

            # Auto-generate destination path if not provided
            if not destination:
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
                except ImportError:
                    return False, "YAML library not available, install PyYAML"

            else:
                return False, f"Unsupported format: {format_type}"

        except Exception as e:
            logger.error(f"Error exporting baseline: {e}")
            return False, f"Export failed: {str(e)}"

    def get_integrity_status() -> Dict[str, Any]:
        """
        Get the current status of file integrity monitoring.

        Returns:
            Dictionary with integrity status information
        """
        return SecurityService.get_integrity_status()

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
        Update file integrity baseline with comprehensive notification and auditing.

        This function provides a unified approach to file integrity baseline updates,
        ensuring proper notification, auditing, security checks, and rate limiting.
        It centralizes these security operations while maintaining expected behavior.

        Args:
            baseline_path: Path to the baseline file
            changes: List of changes to apply to the baseline, each containing at minimum:
                    - 'path': The file path
                    - 'current_hash' or 'hash': The hash value to set
                    - 'severity' (optional): Severity level ('critical', 'high', 'medium', 'low')
            remove_missing: Whether to remove entries for missing files
            notify: Whether to send notifications about significant changes
            audit: Whether to record the update in the audit log
            severity_threshold: Minimum severity to trigger notifications ('critical', 'high', 'medium', 'low')
            update_limit: Maximum number of changes to apply at once (safety limit)

        Returns:
            Tuple containing:
            - bool: Success indicator
            - str: Status message
            - Dict[str, Any]: Detailed statistics about the update operation
        """
        if not SECURITY_SERVICE_AVAILABLE:
            logger.warning("Security service not available for baseline update")
            return False, "Security service not available", {"changes_applied": 0, "error": "Service unavailable"}

        stats = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
            logger.warning(f"Too many changes requested ({len(changes)}), exceeding limit of {update_limit}")
            stats["changes_rejected"] = len(changes) - update_limit

            # Prioritize changes by severity for safety
            def get_severity_priority(change):
                severity = change.get('severity', 'medium').lower()
                priority_map = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
                return priority_map.get(severity, 2)

            changes = sorted(changes, key=get_severity_priority)[:update_limit]

        # Validate and count changes by severity
        validated_changes = []
        for change in changes:
            # Skip invalid entries
            if not isinstance(change, dict) or 'path' not in change:
                stats["changes_rejected"] += 1
                continue

            # Get hash (support both 'current_hash' and 'hash' keys)
            hash_value = change.get('current_hash') or change.get('hash')
            if not hash_value:
                stats["changes_rejected"] += 1
                continue

            # Add to validated list
            validated_changes.append(change)

            # Count by severity
            severity = change.get('severity', 'medium').lower()
            if severity == 'critical':
                stats["critical_changes"] += 1
            elif severity == 'high':
                stats["high_severity_changes"] += 1
            elif severity == 'medium':
                stats["medium_severity_changes"] += 1
            else:
                stats["low_severity_changes"] += 1

        # Early return if no valid changes
        if not validated_changes:
            return False, "No valid changes to apply", stats

        try:
            # Log the baseline update attempt
            if audit and 'AuditService' in globals() and hasattr(AuditService, 'log_file_integrity_event'):
                try:
                    # Determine proper severity for audit
                    audit_severity = 'info'
                    if stats["critical_changes"] > 0:
                        audit_severity = 'critical'
                    elif stats["high_severity_changes"] > 0:
                        audit_severity = 'warning'

                    AuditService.log_file_integrity_event(
                        status='started',
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
                                'changes_applied': stats["changes_applied"],
                                'removed_entries': stats["removed_entries"],
                                'message': message
                            },
                            severity='info'
                        )
                        stats["audit_logged"] = True
                    except Exception as e:
                        logger.warning(f"Failed to log baseline update completion: {e}")

                # Send notification if requested and significant changes detected
                if (notify and NOTIFICATION_MODULE_AVAILABLE and
                    (stats["critical_changes"] > 0 or stats["high_severity_changes"] > 0)):

                    try:
                        # Determine notification level
                        notification_level = 'info'
                        if stats["critical_changes"] > 0:
                            notification_level = 'warning'
                        elif stats["high_severity_changes"] >= 3:  # Multiple high severity changes
                            notification_level = 'warning'

                        # Build the notification message
                        subject = "File Integrity Baseline Updated"

                        # Add severity indicators for critical updates
                        if stats["critical_changes"] > 0:
                            subject = f"[IMPORTANT] {subject} - Critical Files Modified"

                        message = (
                            f"The file integrity baseline has been updated with {stats['changes_applied']} changes. "
                            f"This update includes:\n\n"
                            f"• {stats['critical_changes']} critical file changes\n"
                            f"• {stats['high_severity_changes']} high severity changes\n"
                            f"• {stats['medium_severity_changes']} medium severity changes\n"
                            f"• {stats['low_severity_changes']} low severity changes"
                        )

                        if stats["removed_entries"] > 0:
                            message += f"\n\nAdditionally, {stats['removed_entries']} missing files were removed from baseline."

                        # Send using notification manager
                        notification_manager.send_to_stakeholders(
                            subject=subject,
                            message=message,
                            level=notification_level,
                            category=NOTIFICATION_CATEGORY_INTEGRITY,
                            tags={
                                'category': NOTIFICATION_CATEGORY_INTEGRITY,
                                'event_type': 'baseline_update',
                                'baseline_path': baseline_path,
                                'critical_files': stats["critical_changes"] > 0
                            }
                        )
                        stats["notification_sent"] = True

                    except Exception as e:
                        logger.warning(f"Failed to send baseline update notification: {e}")
            else:
                # Update failed
                metrics.increment('security.baseline.update_failed')

                # Log failure to audit trail
                if audit and 'AuditService' in globals() and hasattr(AuditService, 'log_file_integrity_event'):
                    try:
                        AuditService.log_file_integrity_event(
                            status='failure',
                            action='update',
                            details={
                                'baseline_path': baseline_path,
                                'error': message,
                            },
                            severity='error'
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
        Send notification about security scan results.

        Args:
            scan_id: ID of the scan
            scan_type: Type of scan performed
            status: Status of the scan (completed, failed, etc.)
            findings: Optional findings from the scan

        Returns:
            Dictionary containing delivery results
        """
        return notification_manager.send_scan_notification(scan_id, scan_type, status, findings)

    __all__.append('send_scan_notification')

# Log package initialization
logger.debug(f"Services package initialized (version: {__version__}), " +
            f"Security service available: {SECURITY_SERVICE_AVAILABLE}, " +
            f"Scanning service available: {SCANNING_SERVICE_AVAILABLE}, " +
            f"Notification module available: {NOTIFICATION_MODULE_AVAILABLE}, " +
            f"SMS service available: {SMS_SERVICE_AVAILABLE}, " +
            f"Auth service available: {AUTH_SERVICE_AVAILABLE}")
