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
        NOTIFICATION_CATEGORY_VULNERABILITY, NOTIFICATION_CATEGORY_INCIDENT
    )
    SERVICE_CONSTANTS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Service constants not available: {e}")
    SERVICE_CONSTANTS_AVAILABLE = False
    # Set fallback defaults
    __version__ = '0.2.0'
    __author__ = 'Cloud Infrastructure Platform Team'
    CHANNEL_IN_APP = 'in_app'
    CHANNEL_EMAIL = 'email'
    CHANNEL_SMS = 'sms'
    CHANNEL_WEBHOOK = 'webhook'
    DEFAULT_HASH_ALGORITHM = 'sha256'
    DEFAULT_BASELINE_FILE_PATH = 'instance/security/baseline.json'
    AUTO_UPDATE_LIMIT = 10
    DEFAULT_BASELINE_BACKUP_COUNT = 5
    DEFAULT_SCAN_PROFILES = {}
    MAX_CONCURRENT_SCANS = 5
    SCAN_STATUS_PENDING = 'pending'
    SCAN_STATUS_RUNNING = 'running'
    SCAN_STATUS_COMPLETED = 'completed'
    SCAN_STATUS_FAILED = 'failed'
    SCAN_STATUS_CANCELLED = 'cancelled'
    SCAN_STATUS_TIMEOUT = 'timeout'
    # Notification categories
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
        notify_stakeholders,
        CHANNEL_IN_APP,
        CHANNEL_EMAIL,
        CHANNEL_SMS,
        CHANNEL_WEBHOOK,
        # Notification categories
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

# Try to import original NotificationService (for backward compatibility)
try:
    from .notification_service import (
        NotificationService,
        send_system_notification,
        send_security_alert,
        send_success_notification,
        send_warning_notification,
        send_user_notification,
        CHANNEL_IN_APP,
        CHANNEL_EMAIL,
        CHANNEL_SMS,
        CHANNEL_WEBHOOK
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

    # Notification instances
    'notification_manager',

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

    # Version info
    '__version__'
]

# Conditionally add notification integration functions if available
if HAS_INTEGRITY_NOTIFICATIONS:
    __all__.append('send_integrity_notification')

if HAS_SCAN_NOTIFICATIONS:
    __all__.append('send_scan_notification')

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

    def update_file_integrity_baseline(app, baseline_path: str, changes: List[Dict[str, Any]],
                                     auto_update_limit: int = 10,
                                     bypass_critical_check: bool = False) -> Tuple[bool, str]:
        """
        Update the file integrity baseline with changes.

        This function is used to update the baseline when changes are detected.
        It incorporates new file hashes into the baseline, typically used in development
        or controlled update scenarios.

        Args:
            app: Flask application instance
            baseline_path: Path to the baseline JSON file
            changes: List of change dictionaries from integrity check
            auto_update_limit: Maximum number of files to auto-update (safety limit)
            bypass_critical_check: If True, allows updating critical files (use with caution)

        Returns:
            Tuple containing (success, message)
        """
        try:
            # Import required security functions
            from core.security.cs_file_integrity import update_file_integrity_baseline as core_update_baseline

            # Filter changes to include only those that should be updated
            if bypass_critical_check:
                non_critical = changes
            else:
                # Exclude critical/high severity changes
                non_critical = [c for c in changes if c.get('severity') not in ('critical', 'high')]

            # Safety check - don't update if too many files changed
            if len(non_critical) > auto_update_limit and not app.config.get('BYPASS_UPDATE_LIMITS', False):
                logger.warning(f"Too many files to update: {len(non_critical)} exceeds limit of {auto_update_limit}")
                return False, f"Too many files to update: {len(non_critical)} exceeds safety limit"

            if not non_critical:
                return True, "No changes to update"

            # Format the changes for the core function
            # The core function expects updates with 'path' and 'current_hash' keys
            formatted_updates = []
            for change in non_critical:
                if 'path' in change and 'actual_hash' in change:
                    formatted_updates.append({
                        'path': change['path'],
                        'current_hash': change['actual_hash']
                    })
                # Support alternate key names for backward compatibility
                elif 'path' in change and 'current_hash' in change:
                    formatted_updates.append({
                        'path': change['path'],
                        'current_hash': change['current_hash']
                    })

            if not formatted_updates:
                logger.warning("No valid changes found to update baseline")
                return False, "No valid changes to update"

            # Log the update details
            logger.info(f"Updating baseline at {baseline_path} with {len(formatted_updates)} changes")

            # Update the baseline with these changes
            result = core_update_baseline(app, baseline_path, formatted_updates)

            if result:
                logger.info("File integrity baseline updated successfully")
                return True, f"Updated baseline with {len(formatted_updates)} changes"
            else:
                logger.error("Failed to update file integrity baseline")
                return False, "Failed to update baseline"

        except ImportError as e:
            logger.warning(f"Could not update baseline: cs_file_integrity module not available - {e}")
            return False, "File integrity module not available"
        except PermissionError as e:
            logger.error(f"Permission error updating baseline: {str(e)}")
            return False, f"Permission denied: {str(e)}"
        except Exception as e:
            logger.error(f"Error updating baseline: {str(e)}")
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

# Conditionally add scanning functions if ScanningService is available
if SCANNING_SERVICE_AVAILABLE:
    def run_security_scan(target: str, scan_type: str = "standard",
                        parameters: Optional[Dict[str, Any]] = None,
                        callback_url: Optional[str] = None) -> str:
        """
        Run a security scan with the specified parameters.

        Args:
            target: The target to scan (can be a URL, path, container image, etc.)
            scan_type: Type of scan to run ("standard", "quick", "full", etc.)
            parameters: Optional parameters to customize the scan
            callback_url: Optional URL to call when scan completes

        Returns:
            Scan ID that can be used to check status and retrieve results
        """
        profile = ScanningService.get_profile(scan_type)

        scan = {
            "id": f"scan_{int(datetime.now().timestamp())}",
            "target": target,
            "profile_id": scan_type,
            "parameters": parameters or {},
            "callback_url": callback_url,
            "status": SCAN_STATUS_PENDING,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        success = ScanningService.start_scan(scan)
        if success:
            return scan["id"]
        else:
            raise RuntimeError("Failed to start security scan")

    def get_scan_status(scan_id: str) -> Dict[str, Any]:
        """
        Get the current status of a security scan.

        Args:
            scan_id: ID of the scan to check

        Returns:
            Dictionary with scan status information
        """
        return ScanningService.get_scan_status(scan_id)

    def get_scan_results(scan_id: str) -> Dict[str, Any]:
        """
        Get the results of a completed security scan.

        Args:
            scan_id: ID of the scan

        Returns:
            Dictionary with scan results
        """
        return ScanningService.get_scan_results(scan_id)

    def get_scan_history(limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get history of recent security scans.

        Args:
            limit: Maximum number of results to return

        Returns:
            List of scan history entries
        """
        return ScanningService.get_scan_history(limit)

    def get_scan_profiles() -> List[Dict[str, Any]]:
        """
        Get available security scan profiles.

        Returns:
            List of scan profile configurations
        """
        return ScanningService.get_available_scan_profiles()

    def start_security_scan(scan_config: Dict[str, Any]) -> str:
        """
        Start a security scan with custom configuration.

        Args:
            scan_config: Complete scan configuration

        Returns:
            Scan ID
        """
        success = ScanningService.start_scan(scan_config)
        if success:
            return scan_config.get("id", "unknown")
        else:
            raise RuntimeError("Failed to start security scan")

    def cancel_security_scan(scan_id: str) -> bool:
        """
        Cancel a running security scan.

        Args:
            scan_id: ID of the scan to cancel

        Returns:
            True if successfully cancelled, False otherwise
        """
        return ScanningService.cancel_scan(scan_id)

    def get_scan_health_metrics() -> Dict[str, Any]:
        """
        Get health metrics for the scanning service.

        Returns:
            Dictionary with health metrics
        """
        return {
            "active_scans": ScanningService.get_active_scan_count(),
            "queue_depth": ScanningService.get_queue_length(),
            "available_workers": MAX_CONCURRENT_SCANS - ScanningService.get_active_scan_count()
        }

    def estimate_scan_duration(scan_type: str, target_size: Optional[int] = None) -> int:
        """
        Estimate the duration of a security scan.

        Args:
            scan_type: Type of scan to run
            target_size: Size of the target in bytes (if applicable)

        Returns:
            Estimated duration in seconds
        """
        # Basic estimation algorithm - this would be enhanced in a real implementation
        profile = ScanningService.get_profile(scan_type)
        base_time = profile.get("parameters", {}).get("timeout", 3600)

        if target_size:
            # Adjust time based on size (very naive approach)
            size_factor = max(1.0, min(3.0, target_size / (50 * 1024 * 1024)))
            return int(base_time * size_factor)

        return base_time

# Conditionally add webhook functions if WebhookService is available
if WEBHOOK_SERVICE_AVAILABLE:
    def trigger_webhook_event(event_type: str, data: Dict[str, Any],
                            subscriptions: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Trigger a webhook event to notify external systems.

        Args:
            event_type: Type of event (e.g., "security.scan.completed")
            data: Event data to include in the payload
            subscriptions: Optional list of subscription IDs to target (if None, matches by event type)

        Returns:
            Dictionary with delivery results
        """
        return WebhookService.trigger_event(event_type, data, subscriptions)

    def create_webhook_subscription(callback_url: str, event_types: List[str],
                                  secret: Optional[str] = None,
                                  description: Optional[str] = None) -> str:
        """
        Create a new webhook subscription.

        Args:
            callback_url: URL to call when events occur
            event_types: List of event types to subscribe to
            secret: Optional secret for signature verification
            description: Optional description of subscription

        Returns:
            Subscription ID
        """
        return WebhookService.create_subscription(callback_url, event_types, secret, description)

    def get_webhook_subscription(subscription_id: str) -> Dict[str, Any]:
        """
        Get information about a webhook subscription.

        Args:
            subscription_id: ID of the subscription

        Returns:
            Subscription information dictionary
        """
        return WebhookService.get_subscription(subscription_id)

    def update_webhook_subscription(subscription_id: str,
                                 updates: Dict[str, Any]) -> bool:
        """
        Update an existing webhook subscription.

        Args:
            subscription_id: ID of the subscription to update
            updates: Dictionary of fields to update

        Returns:
            True if successful, False otherwise
        """
        return WebhookService.update_subscription(subscription_id, updates)

    def delete_webhook_subscription(subscription_id: str) -> bool:
        """
        Delete a webhook subscription.

        Args:
            subscription_id: ID of the subscription to delete

        Returns:
            True if successful, False otherwise
        """
        return WebhookService.delete_subscription(subscription_id)

    def check_subscription_health(subscription_id: str) -> Dict[str, Any]:
        """
        Check the health of a webhook subscription.

        Args:
            subscription_id: ID of the subscription to check

        Returns:
            Health status dictionary
        """
        return WebhookService.check_health(subscription_id)

# Directly provide notification convenience functions if not available from the notification module
if not HAS_INTEGRITY_NOTIFICATIONS and SECURITY_SERVICE_AVAILABLE and NOTIFICATION_MODULE_AVAILABLE:
    def send_integrity_notification(changes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Send notification about file integrity changes.

        Args:
            changes: List of file changes detected

        Returns:
            Dictionary containing delivery results
        """
        return notification_manager.send_file_integrity_notification(changes)

    __all__.append('send_integrity_notification')

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
            f"Notification service available: {NOTIFICATION_SERVICE_AVAILABLE}")
