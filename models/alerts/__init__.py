"""
Alert models package for tracking and managing system alerts.

This package provides models and utilities for managing system alerts
including creation, acknowledgment, resolution, and correlation.

The package contains the following core components:
- Alert: Model for tracking alerts across the platform
- AlertCorrelation: Functionality for detecting related alerts
- AlertNotification: Model for managing alert notifications
- AlertEscalation: Model for managing alert escalation policies
- AlertSuppression: Model for managing alert suppression rules
- AlertMetrics: Model for tracking alert statistics and trends

These components work together to provide a comprehensive alert management
system with support for alert correlation, prioritization, escalation,
and integration with the notification system.
"""

import logging

# Initialize package logger
logger = logging.getLogger(__name__)

# Import core models explicitly to avoid circular imports
from models.alerts.alert import Alert
from models.alerts.alert_correlation import AlertCorrelation
from models.alerts.alert_notification import AlertNotification
from models.alerts.alert_escalation import AlertEscalation
from models.alerts.alert_suppression import AlertSuppression
from models.alerts.alert_metrics import AlertMetrics

# Define package version for tracking
__version__ = '0.1.1'

# Define exports explicitly for better control over the public API
__all__ = [
    'Alert',
    'AlertCorrelation',
    'AlertNotification',
    'AlertEscalation',
    'AlertSuppression',
    'AlertMetrics',
]

# Track initialization state for logging purposes
logger.debug("Alert models package initialized successfully")
