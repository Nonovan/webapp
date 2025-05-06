"""
Notification package for the Cloud Infrastructure Platform.

This package provides a centralized notification system with multiple delivery
channels and standardized interfaces. It supports various notification levels,
recipient targeting, and flexible message formatting.
"""

import logging
from typing import Dict, Any, Optional, List, Union

# Import core notification components
from services.notification_service import (
    CHANNEL_IN_APP,
    CHANNEL_EMAIL,
    CHANNEL_SMS,
    CHANNEL_WEBHOOK
)

# Import the NotificationManager from note_manager
from .note_manager import (
    NotificationManager,
    notification_manager,
    notify_stakeholders
)

# Setup package logger
logger = logging.getLogger(__name__)

# Export symbols that should be available when importing the package
__all__ = [
    # Classes
    'NotificationManager',

    # Functions
    'notify_stakeholders',

    # Constants
    'CHANNEL_IN_APP',
    'CHANNEL_EMAIL',
    'CHANNEL_SMS',
    'CHANNEL_WEBHOOK',

    # Instances
    'notification_manager'
]

# Log package initialization
logger.debug("Notification package initialized")
