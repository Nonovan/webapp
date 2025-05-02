"""
Webhook handling package for Cloud Infrastructure Platform.

This package implements webhook event dispatching, subscription management,
and delivery retry logic for integration with external systems. Webhooks allow
external applications to receive real-time notifications about events within
the cloud platform.

Each webhook subscription can filter for specific event types and
includes authentication via a shared secret for payload verification.
"""

import hmac
import hashlib
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from flask import Blueprint, current_app, Flask

# Initialize logger for this package
logger = logging.getLogger(__name__)

# Flag to track initialization state
_initialized = False

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
    ALERT_SUPPRESSED = "alert.suppressed"
    ALERT_CORRELATED = "alert.correlated"
    ALERT_METRIC_THRESHOLD = "alert.metric_threshold"
    ALERT_NOTIFICATION_SENT = "alert.notification_sent"
    ALERT_NOTIFICATION_FAILED = "alert.notification_failed"

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
        EventType.ALERT_RESOLVED, EventType.ALERT_ESCALATED, EventType.ALERT_COMMENT,
        EventType.ALERT_SUPPRESSED, EventType.ALERT_CORRELATED, EventType.ALERT_METRIC_THRESHOLD,
        EventType.ALERT_NOTIFICATION_SENT, EventType.ALERT_NOTIFICATION_FAILED
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
        EventType.SYSTEM_LOW_DISK_SPACE, EventType.SECURITY_VULNERABILITY,
        EventType.ALERT_ESCALATED
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

    This function creates a secure HMAC-SHA256 signature from the payload
    and a shared secret, allowing recipients to verify the authenticity
    of the webhook.

    Args:
        payload: The webhook payload as a string
        secret: The shared secret for the webhook subscription

    Returns:
        str: Hexadecimal signature for the payload
    """
    if not payload or not secret:
        raise ValueError("Payload and secret are required")

    return hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def verify_webhook_signature(payload: str, signature: str, secret: str) -> bool:
    """
    Verify the signature of a webhook payload.

    This function implements constant-time comparison to prevent timing attacks
    when verifying webhook signatures.

    Args:
        payload: The webhook payload as a string
        signature: The signature provided with the webhook
        secret: The shared secret for the webhook subscription

    Returns:
        bool: True if signature is valid, False otherwise
    """
    if not payload or not signature or not secret:
        return False

    expected = generate_webhook_signature(payload, secret)
    return hmac.compare_digest(expected, signature)


def format_webhook_payload(event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format a standard webhook payload.

    Creates a consistently structured webhook payload with standard metadata
    fields like event_type, timestamp, and request_id for traceability.

    Args:
        event_type: The type of event
        data: Event-specific data

    Returns:
        Dict: Formatted webhook payload with standard fields
    """
    return {
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": str(uuid.uuid4()),
        "data": data
    }


def validate_event_type(event_type: str) -> bool:
    """
    Validate if an event type is supported.

    Args:
        event_type: The event type to validate

    Returns:
        bool: True if valid, False otherwise
    """
    return event_type in EVENT_TYPES


def filter_events_by_category(category: str) -> List[str]:
    """
    Get event types belonging to a specific category.

    Args:
        category: The event category name

    Returns:
        List[str]: List of event types in the category

    Raises:
        ValueError: If category doesn't exist
    """
    if category not in EVENT_CATEGORIES:
        raise ValueError(f"Unknown event category: {category}")

    return EVENT_CATEGORIES[category]


# Create blueprint for webhook API routes
webhooks_api = Blueprint('webhooks', __name__, url_prefix='/webhooks')


# Register webhook-related metrics
def register_webhook_metrics(metrics):
    """
    Register webhook-related metrics with the metrics system.

    Args:
        metrics: The metrics registry
    """
    try:
        metrics.counter(
            'webhook_events_total',
            'Total number of webhook events',
            ['event_type']
        )

        metrics.counter(
            'webhook_delivery_failures_total',
            'Total number of webhook delivery failures',
            ['event_type', 'status_code']
        )

        metrics.histogram(
            'webhook_delivery_duration_milliseconds',
            'Webhook delivery duration in milliseconds',
            ['event_type']
        )

        metrics.gauge(
            'webhook_subscriptions_active',
            'Number of active webhook subscriptions',
            []
        )

        # Add alert-specific webhook metrics
        metrics.counter(
            'webhook_alert_events_total',
            'Total number of alert-related webhook events',
            ['alert_type', 'severity']
        )

        metrics.gauge(
            'webhook_alert_delivery_success_rate',
            'Success rate percentage for alert webhook deliveries',
            ['alert_type']
        )
    except Exception as e:
        current_app.logger.warning(f"Failed to register webhook metrics: {e}")


def init_app(app: Flask) -> None:
    """
    Initialize the webhooks module with the Flask application.

    This function:
    - Registers the webhook blueprint with the application
    - Configures rate limits for webhook endpoints
    - Sets up periodic background tasks for delivery monitoring
    - Registers necessary metrics
    - Initializes circuit breakers for external webhook targets

    Args:
        app: Flask application instance
    """
    global _initialized

    if _initialized:
        logger.debug("Webhooks system already initialized, skipping")
        return

    logger.info("Initializing webhooks system")

    # Register the blueprint with the application
    if not app.blueprints.get('webhooks_api'):
        app.register_blueprint(webhooks_api)

    # Configure rate limits if limiter is available
    if hasattr(app, 'extensions') and 'limiter' in app.extensions:
        limiter = app.extensions['limiter']
        limits = {
            'create': app.config.get('WEBHOOK_RATE_LIMIT_CREATE', '30/minute'),
            'test': app.config.get('WEBHOOK_RATE_LIMIT_TEST', '10/minute'),
            'list': app.config.get('WEBHOOK_RATE_LIMIT_LIST', '60/minute')
        }

        # Apply rate limits to webhook endpoints
        try:
            limiter.limit(limits['create'])(webhooks_api)
            logger.debug(f"Applied rate limit {limits['create']} to webhook creation")
        except Exception as e:
            logger.warning(f"Failed to apply rate limit to webhook creation: {e}")

    # Setup metrics if available
    try:
        from extensions import metrics
        register_webhook_metrics(metrics)
        logger.debug("Webhook metrics registered")
    except (ImportError, AttributeError) as e:
        logger.warning(f"Could not register webhook metrics: {e}")

    # Initialize circuit breakers for webhook delivery targets
    try:
        from core.security.cs_general_sec import CircuitBreaker

        delivery_breaker = CircuitBreaker(
            name="webhook.delivery",
            failure_threshold=app.config.get('WEBHOOK_CIRCUIT_THRESHOLD', 5),
            reset_timeout=app.config.get('WEBHOOK_CIRCUIT_RESET', 300),
            half_open_after=app.config.get('WEBHOOK_CIRCUIT_HALFOPEN', 60)
        )
        delivery_breaker.initialize()

        logger.debug("Webhook delivery circuit breaker initialized")
    except ImportError:
        logger.info("Circuit breaker not available for webhook delivery")

    # Set up background tasks for retrying failed deliveries if applicable
    if app.config.get('WEBHOOK_ENABLE_BACKGROUND_RETRY', True):
        try:
            from .delivery import setup_retry_task
            setup_retry_task(app)
            logger.debug("Webhook retry background task initialized")
        except (ImportError, AttributeError) as e:
            logger.warning(f"Could not set up webhook retry background task: {e}")

    _initialized = True
    logger.info("Webhooks system initialized successfully")


# Import routes and models at the end to avoid circular imports
from . import routes


# Version information
__version__ = '0.1.1'


__all__ = [
    "EventType",
    "EVENT_TYPES",
    "EVENT_CATEGORIES",
    "DeliveryStatus",
    "generate_webhook_signature",
    "verify_webhook_signature",
    "format_webhook_payload",
    "validate_event_type",
    "filter_events_by_category",
    "webhooks_api",
    "register_webhook_metrics",
    "init_app",
    "__version__"
]
