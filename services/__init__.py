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

# Log package initialization
logger.debug(f"Services package initialized (version: {__version__}), " +
            f"Security service available: {SECURITY_SERVICE_AVAILABLE}, " +
            f"Scanning service available: {SCANNING_SERVICE_AVAILABLE}, " +
            f"Notification module available: {NOTIFICATION_MODULE_AVAILABLE}, " +
            f"SMS service available: {SMS_SERVICE_AVAILABLE}, " +
            f"Auth service available: {AUTH_SERVICE_AVAILABLE}")
