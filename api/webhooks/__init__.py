"""
Webhook handling package for Cloud Infrastructure Platform.

This package implements webhook event dispatching, subscription management,
and delivery retry logic for integration with external systems. Webhooks allow
external applications to receive real-time notifications about events within
the cloud platform.

Each webhook subscription can filter for specific event types and
includes authentication via a shared secret for payload verification.
"""

from typing import Dict, List, Optional
from enum import Enum, auto

# Available webhook event types
class EventType:
    """Supported webhook event types."""
    
    # Cloud resource events
    RESOURCE_CREATED = "resource.created"
    RESOURCE_UPDATED = "resource.updated"
    RESOURCE_DELETED = "resource.deleted"
    
    # Alert events
    ALERT_TRIGGERED = "alert.triggered"
    ALERT_ACKNOWLEDGED = "alert.acknowledged"
    ALERT_RESOLVED = "alert.resolved"
    
    # Security events
    SECURITY_INCIDENT = "security.incident"
    SECURITY_SCAN_COMPLETED = "security.scan.completed"
    
    # ICS events
    ICS_READING = "ics.reading"
    ICS_STATE_CHANGE = "ics.state.change"
    
    # System events
    SYSTEM_BACKUP_COMPLETED = "system.backup.completed"
    MAINTENANCE_SCHEDULED = "maintenance.scheduled"


# Filter categories for easier subscription management
EVENT_CATEGORIES = {
    "all": [event for event in dir(EventType) if not event.startswith("_") and event.isupper()],
    "resources": [EventType.RESOURCE_CREATED, EventType.RESOURCE_UPDATED, EventType.RESOURCE_DELETED],
    "alerts": [EventType.ALERT_TRIGGERED, EventType.ALERT_ACKNOWLEDGED, EventType.ALERT_RESOLVED],
    "security": [EventType.SECURITY_INCIDENT, EventType.SECURITY_SCAN_COMPLETED],
    "ics": [EventType.ICS_READING, EventType.ICS_STATE_CHANGE],
    "system": [EventType.SYSTEM_BACKUP_COMPLETED, EventType.MAINTENANCE_SCHEDULED]
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
    import hmac
    import hashlib
    
    return hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


__all__ = [
    "EventType",
    "EVENT_TYPES",
    "EVENT_CATEGORIES",
    "DeliveryStatus",
    "generate_webhook_signature"
]
