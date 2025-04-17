"""
Webhook handling package for Cloud Infrastructure Platform.

This package implements webhook event dispatching, subscription management,
and delivery retry logic for integration with external systems. Webhooks allow
external applications to receive real-time notifications about events within
the cloud platform.

Each webhook subscription can filter for specific event types and
includes authentication via a shared secret for payload verification.
"""

from typing import Dict, List, Optional, Any
from enum import Enum, auto
import hmac
import hashlib
import json
from datetime import datetime

# Available webhook event types
class EventType:
    """Supported webhook event types."""
    
    # Cloud resource events
    RESOURCE_CREATED = "resource.created"
    RESOURCE_UPDATED = "resource.updated"
    RESOURCE_DELETED = "resource.deleted"
    RESOURCE_STARTED = "resource.started"
    RESOURCE_STOPPED = "resource.stopped"
    RESOURCE_ERROR = "resource.error"
    RESOURCE_SCALED = "resource.scaled"
    
    # Alert events
    ALERT_TRIGGERED = "alert.triggered"
    ALERT_ACKNOWLEDGED = "alert.acknowledged"
    ALERT_RESOLVED = "alert.resolved"
    ALERT_ESCALATED = "alert.escalated"
    ALERT_COMMENT = "alert.comment"
    
    # Security events
    SECURITY_INCIDENT = "security.incident"
    SECURITY_SCAN_COMPLETED = "security.scan.completed"
    SECURITY_VULNERABILITY = "security.vulnerability"
    SECURITY_BRUTE_FORCE = "security.brute_force"
    SECURITY_FILE_INTEGRITY = "security.file_integrity"
    SECURITY_AUDIT = "security.audit"
    
    # ICS events
    ICS_READING = "ics.reading"
    ICS_STATE_CHANGE = "ics.state.change"
    ICS_ALARM = "ics.alarm"
    ICS_MAINTENANCE_REQUIRED = "ics.maintenance_required"
    ICS_CALIBRATION = "ics.calibration"
    
    # System events
    SYSTEM_BACKUP_COMPLETED = "system.backup.completed"
    MAINTENANCE_SCHEDULED = "system.maintenance.scheduled"
    SYSTEM_UPGRADED = "system.upgraded"
    SYSTEM_HIGH_LOAD = "system.high_load"
    SYSTEM_LOW_DISK_SPACE = "system.low_disk_space"
    
    # User events
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_LOGGED_IN = "user.logged_in"
    USER_LOGIN_FAILED = "user.login_failed"
    USER_MFA_ENABLED = "user.mfa_enabled"
    
    # Cost events
    COST_THRESHOLD_EXCEEDED = "cost.threshold_exceeded"
    COST_ANOMALY = "cost.anomaly"
    COST_REPORT = "cost.report"


# Filter categories for easier subscription management
EVENT_CATEGORIES = {
    "all": [getattr(EventType, event) for event in dir(EventType) 
            if not event.startswith("_") and event.isupper()],
    
    "resources": [
        EventType.RESOURCE_CREATED, EventType.RESOURCE_UPDATED, EventType.RESOURCE_DELETED,
        EventType.RESOURCE_STARTED, EventType.RESOURCE_STOPPED, EventType.RESOURCE_ERROR,
        EventType.RESOURCE_SCALED
    ],
    
    "alerts": [
        EventType.ALERT_TRIGGERED, EventType.ALERT_ACKNOWLEDGED, 
        EventType.ALERT_RESOLVED, EventType.ALERT_ESCALATED, EventType.ALERT_COMMENT
    ],
    
    "security": [
        EventType.SECURITY_INCIDENT, EventType.SECURITY_SCAN_COMPLETED,
        EventType.SECURITY_VULNERABILITY, EventType.SECURITY_BRUTE_FORCE,
        EventType.SECURITY_FILE_INTEGRITY, EventType.SECURITY_AUDIT
    ],
    
    "ics": [
        EventType.ICS_READING, EventType.ICS_STATE_CHANGE, EventType.ICS_ALARM,
        EventType.ICS_MAINTENANCE_REQUIRED, EventType.ICS_CALIBRATION
    ],
    
    "system": [
        EventType.SYSTEM_BACKUP_COMPLETED, EventType.MAINTENANCE_SCHEDULED,
        EventType.SYSTEM_UPGRADED, EventType.SYSTEM_HIGH_LOAD, 
        EventType.SYSTEM_LOW_DISK_SPACE
    ],
    
    "users": [
        EventType.USER_CREATED, EventType.USER_UPDATED, EventType.USER_LOGGED_IN,
        EventType.USER_LOGIN_FAILED, EventType.USER_MFA_ENABLED
    ],
    
    "cost": [
        EventType.COST_THRESHOLD_EXCEEDED, EventType.COST_ANOMALY, EventType.COST_REPORT
    ],
    
    "critical": [
        EventType.SECURITY_INCIDENT, EventType.RESOURCE_ERROR, EventType.ICS_ALARM,
        EventType.SYSTEM_LOW_DISK_SPACE, EventType.SECURITY_VULNERABILITY
    ]
}

# Generate list of all event types for backwards compatibility
EVENT_TYPES = [getattr(EventType, event) for event in dir(EventType) 
               if not event.startswith("_") and event.isupper()]

# Webhook delivery status constants
class DeliveryStatus:
    """Webhook delivery status codes."""
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELED = "canceled"


def generate_webhook_signature(payload: str, secret: str) -> str:
    """
    Generate HMAC signature for webhook payload verification.
    
    Args:
        payload: The webhook payload as a string
        secret: The shared secret for the webhook subscription
        
    Returns:
        str: Hexadecimal signature for the payload
    """
    return hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def verify_webhook_signature(payload: str, signature: str, secret: str) -> bool:
    """
    Verify the signature of a webhook payload.
    
    Args:
        payload: The webhook payload as a string
        signature: The signature provided with the webhook
        secret: The shared secret for the webhook subscription
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    expected = generate_webhook_signature(payload, secret)
    return hmac.compare_digest(expected, signature)


def format_webhook_payload(event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format a standard webhook payload.
    
    Args:
        event_type: The type of event
        data: Event-specific data
        
    Returns:
        Dict: Formatted webhook payload with standard fields
    """
    return {
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat(),
        "data": data
    }


__all__ = [
    "EventType",
    "EVENT_TYPES",
    "EVENT_CATEGORIES",
    "DeliveryStatus",
    "generate_webhook_signature",
    "verify_webhook_signature",
    "format_webhook_payload"
]
