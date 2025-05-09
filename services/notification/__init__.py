"""
Notification package for the Cloud Infrastructure Platform.

This package provides a centralized notification management system with multiple delivery
channels and standardized interfaces. It supports various notification levels,
recipient targeting, flexible message formatting, and integration with security
features including file integrity monitoring and security scanning.
"""

import logging
from typing import Dict, Any, Optional, List, Union, Set, Tuple

# Import notification channels from core service for consistency
from services.notification_service import (
    CHANNEL_IN_APP,
    CHANNEL_EMAIL,
    CHANNEL_SMS,
    CHANNEL_WEBHOOK
)

# Import NotificationManager from note_manager
from .note_manager import (
    NotificationManager,
    notification_manager,
    notify_stakeholders
)

# Setup package logger
logger = logging.getLogger(__name__)

# Check if metrics module is available
try:
    from core.metrics import metrics
    METRICS_AVAILABLE = True
    logger.debug("Metrics functionality available for notification tracking")
except ImportError:
    METRICS_AVAILABLE = False
    logger.debug("Metrics functionality not available")

# Check if security service is available for integration
try:
    from services import SECURITY_SERVICE_AVAILABLE
except ImportError:
    SECURITY_SERVICE_AVAILABLE = False

# Check if scanning service is available for integration
try:
    from services import SCANNING_SERVICE_AVAILABLE
except ImportError:
    SCANNING_SERVICE_AVAILABLE = False

# Define notification categories
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

# Export symbols that should be available when importing the package
__all__ = [
    # Classes
    'NotificationManager',

    # Functions
    'notify_stakeholders',

    # Constants - Channels
    'CHANNEL_IN_APP',
    'CHANNEL_EMAIL',
    'CHANNEL_SMS',
    'CHANNEL_WEBHOOK',

    # Constants - Categories
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

    # Instances
    'notification_manager',

    # Feature flags
    'METRICS_AVAILABLE'
]

# Enhanced wrapper for notification functions related to security features
if SECURITY_SERVICE_AVAILABLE:
    def send_integrity_notification(changes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Send notification about file integrity changes.

        This is a convenience function that wraps NotificationManager.send_file_integrity_notification.

        Args:
            changes: List of file changes detected

        Returns:
            Dictionary containing delivery results
        """
        return notification_manager.send_file_integrity_notification(changes)

    __all__.append('send_integrity_notification')

# Enhanced wrapper for notification functions related to scanning features
if SCANNING_SERVICE_AVAILABLE:
    def send_scan_notification(scan_id: str, scan_type: str, status: str,
                              findings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Send notification about security scan results.

        This is a convenience function that wraps NotificationManager.send_scan_notification.

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

# Version information
__version__ = '0.2.0'

# Log package initialization with feature availability
logger.debug(
    f"Notification package initialized (version: {__version__}), "
    f"Metrics available: {METRICS_AVAILABLE}, "
    f"Security integration: {SECURITY_SERVICE_AVAILABLE}, "
    f"Scanning integration: {SCANNING_SERVICE_AVAILABLE}"
)
