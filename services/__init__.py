"""
Services Package for Cloud Infrastructure Platform.

This package provides service layer functionality for various aspects of the
cloud infrastructure platform, including authentication, security, monitoring,
notifications, and more.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple, Callable

# Set up package logger
logger = logging.getLogger(__name__)

# Feature availability tracking
SECURITY_SERVICE_AVAILABLE = False
SCANNING_SERVICE_AVAILABLE = False
EMAIL_SERVICE_AVAILABLE = False
NOTIFICATION_SERVICE_AVAILABLE = False
NOTIFICATION_MODULE_AVAILABLE = False
AUTH_SERVICE_AVAILABLE = False
NEWSLETTER_SERVICE_AVAILABLE = False
WEBHOOK_SERVICE_AVAILABLE = False
SMS_SERVICE_AVAILABLE = False
FILE_INTEGRITY_SERVICE_AVAILABLE = False
SERVICE_CONSTANTS_AVAILABLE = False

# Try to import constants
try:
    from .service_constants import (
        __version__,
        __author__,

        # Notification channels
        CHANNEL_IN_APP, CHANNEL_EMAIL, CHANNEL_SMS, CHANNEL_WEBHOOK,

        # File integrity constants
        DEFAULT_HASH_ALGORITHM, DEFAULT_BASELINE_FILE_PATH,
        AUTO_UPDATE_LIMIT, DEFAULT_BASELINE_BACKUP_COUNT,
        FILE_INTEGRITY_CONSTANTS, DEFAULT_BACKUP_PATH_TEMPLATE,

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
        SMS_PROVIDER_SETTINGS,

        # File integrity baseline constants
        BASELINE_EXPORT_FORMATS,
        BASELINE_ACTION_EXPORT,
        BASELINE_ACTION_IMPORT
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
    NOTIFICATION_CATEGORY_COMPLIANCE = 'compliance'
    NOTIFICATION_CATEGORY_INTEGRITY = 'integrity'
    NOTIFICATION_CATEGORY_SCAN = 'scan'
    NOTIFICATION_CATEGORY_VULNERABILITY = 'vulnerability'
    NOTIFICATION_CATEGORY_INCIDENT = 'incident'

    # Baseline export constants
    BASELINE_EXPORT_FORMATS = ['json', 'yaml']
    BASELINE_ACTION_EXPORT = 'export'
    BASELINE_ACTION_IMPORT = 'import'

# Try to import notification service
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
    logger.warning("NotificationService not available")

# Try to import Email Service
try:
    from .email_service import (
        EmailService,
        send_email,
        send_template_email,
        validate_email_address,
        test_email_configuration
    )
    EMAIL_SERVICE_AVAILABLE = True
except ImportError:
    logger.warning("EmailService not available")

# Try to import Auth Service
try:
    from .auth_service import AuthService
    AUTH_SERVICE_AVAILABLE = True
except ImportError:
    logger.warning("AuthService not available")

# Try to import Newsletter Service
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

# Try to import File Integrity Service
try:
    from .file_integrity_service import (
        update_file_integrity_baseline,
        update_file_baseline,
        update_file_integrity_baseline_with_notifications,
        verify_baseline_consistency,
        validate_baseline_consistency,
        export_baseline
    )
    FILE_INTEGRITY_SERVICE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"File integrity service not available: {e}")
    FILE_INTEGRITY_SERVICE_AVAILABLE = False

# Try to import notification module and NotificationManager
try:
    from .notification import (
        NotificationManager,
        notification_manager
    )
    # Import notify_stakeholders specifically - this only exists in notification module
    from .notification import notify_stakeholders
    NOTIFICATION_MODULE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Notification module not available: {e}")
    NOTIFICATION_MODULE_AVAILABLE = False
    # Need to set this to None so it can be referenced safely later
    notify_stakeholders = None

# Check availability of notification integration functions
HAS_INTEGRITY_NOTIFICATIONS = False
HAS_SCAN_NOTIFICATIONS = False

# Only try to import specialized notification functions if the base module is available
if NOTIFICATION_MODULE_AVAILABLE:
    # Check for integrity notification integration
    if SECURITY_SERVICE_AVAILABLE and FILE_INTEGRITY_SERVICE_AVAILABLE:
        try:
            from .notification import send_integrity_notification
            HAS_INTEGRITY_NOTIFICATIONS = True
        except (ImportError, AttributeError) as e:
            logger.debug(f"File integrity notification integration not available: {e}")

    # Check for scan notification integration
    if SCANNING_SERVICE_AVAILABLE:
        try:
            from .notification import send_scan_notification
            HAS_SCAN_NOTIFICATIONS = True
        except (ImportError, AttributeError) as e:
            logger.debug(f"Scan notification integration not available: {e}")

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
    'notify_stakeholders',  # This now comes from notification package

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
    'update_file_integrity_baseline_with_notifications',
    'verify_baseline_consistency',
    'validate_baseline_consistency',
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
    'FILE_INTEGRITY_SERVICE_AVAILABLE',

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
        Check file integrity against baseline.

        Args:
            paths: Optional list of paths to check. If None, checks all baseline files.

        Returns:
            Tuple containing (status, changes)
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
        Calculate the hash of a file.

        Args:
            filepath: Path to the file to hash
            algorithm: Hash algorithm to use (default: sha256)

        Returns:
            Hex digest of file hash or None if file cannot be read
        """
        from pathlib import Path
        return SecurityService._calculate_hash(Path(filepath))

    def schedule_integrity_check(interval_seconds: int = 3600,
                               callback: Optional[Callable[[bool, List[Dict[str, Any]]], None]] = None) -> bool:
        """
        Schedule periodic integrity checks.

        Args:
            interval_seconds: Time between integrity checks in seconds
            callback: Optional function to call with check results

        Returns:
            bool: True if scheduling was successful
        """
        return SecurityService.schedule_integrity_check(interval_seconds, callback)

    def get_integrity_status() -> Dict[str, Any]:
        """
        Get the current status of the baseline and recent integrity checks.

        Returns:
            Dictionary with integrity status information
        """
        return SecurityService.get_integrity_status()

# Conditionally add scanning functions if ScanningService is available
if SCANNING_SERVICE_AVAILABLE:
    def run_security_scan(scan_type: str = 'standard', targets: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run a security scan with the specified parameters.

        Args:
            scan_type: Type of scan to run (standard, quick, full, or compliance)
            targets: Optional list of targets to scan

        Returns:
            Dictionary containing scan details including ID and status
        """
        return ScanningService.run_scan(scan_type, targets)

# Log package initialization
logger.debug(f"Services package initialized (version: {__version__}), " +
            f"Security service available: {SECURITY_SERVICE_AVAILABLE}, " +
            f"Scanning service available: {SCANNING_SERVICE_AVAILABLE}, " +
            f"Notification module available: {NOTIFICATION_MODULE_AVAILABLE}, " +
            f"SMS service available: {SMS_SERVICE_AVAILABLE}, " +
            f"Auth service available: {AUTH_SERVICE_AVAILABLE}, " +
            f"File integrity service available: {FILE_INTEGRITY_SERVICE_AVAILABLE}")
