"""
Webhook subscription management for Cloud Infrastructure Platform.

This module provides functionality for creating, updating, and deleting
webhook subscription configurations, including validation and security.
"""

from typing import Dict, List, Optional, Tuple, Union, Any
from flask import current_app
import uuid
import secrets
import ipaddress
from datetime import datetime, timedelta
from urllib.parse import urlparse

from models import db, WebhookSubscription
from core.security.cs_audit import log_security_event
from extensions import metrics
from . import EventType, EVENT_TYPES, EVENT_CATEGORIES, generate_webhook_signature

# Default circuit breaker settings
DEFAULT_FAILURE_THRESHOLD = 5
DEFAULT_RESET_TIMEOUT = 300  # seconds


def create_subscription(
    target_url: str,
    event_types: List[str],
    description: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    user_id: Optional[int] = None,
    max_retries: int = 3,
    failure_threshold: Optional[int] = None,
    reset_timeout: Optional[int] = None,
    group_id: Optional[int] = None
) -> Dict:
    """
    Create a new webhook subscription.

    Args:
        target_url: URL to send webhook events to
        event_types: List of event types to subscribe to
        description: Optional description of the subscription
        headers: Optional custom headers to include with webhook requests
        user_id: ID of user creating the subscription
        max_retries: Maximum number of retries for failed deliveries
        failure_threshold: Number of failures before circuit breaker trips (default: 5)
        reset_timeout: Seconds before circuit breaker resets to half-open (default: 300)
        group_id: Optional group ID to associate subscription with

    Returns:
        Dict containing the created subscription information
    """
    # Validate event types
    invalid_events = [e for e in event_types if e not in EVENT_TYPES]
    if invalid_events:
        raise ValueError(f"Invalid event types: {', '.join(invalid_events)}")

    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        raise ValueError("Target URL must use HTTP or HTTPS protocol")

    # Additional security validation for URL
    security_error = _validate_security_constraints(target_url)
    if security_error:
        metrics.increment('webhook.subscription.security_rejection')
        raise ValueError(f"Security constraint violation: {security_error}")

    # Apply default circuit breaker settings if not provided
    if failure_threshold is None:
        failure_threshold = current_app.config.get('WEBHOOK_CIRCUIT_THRESHOLD', DEFAULT_FAILURE_THRESHOLD)
    if reset_timeout is None:
        reset_timeout = current_app.config.get('WEBHOOK_CIRCUIT_TIMEOUT', DEFAULT_RESET_TIMEOUT)

    # Validate circuit breaker parameters
    if not (1 <= failure_threshold <= 20):
        raise ValueError("failure_threshold must be between 1 and 20")
    if not (30 <= reset_timeout <= 86400):
        raise ValueError("reset_timeout must be between 30 and 86400 seconds")

    # Generate subscription ID and secret
    subscription_id = str(uuid.uuid4())
    secret = secrets.token_hex(32)

    # Create subscription with circuit breaker settings
    subscription = WebhookSubscription(
        id=subscription_id,
        user_id=user_id,
        target_url=target_url,
        event_types=event_types,
        description=description or "",
        headers=headers or {},
        secret=secret,
        max_retries=max_retries,
        created_at=datetime.utcnow(),
        is_active=True,
        group_id=group_id,
        # Circuit breaker fields
        circuit_status='closed',
        failure_count=0,
        failure_threshold=failure_threshold,
        reset_timeout=reset_timeout
    )

    try:
        db.session.add(subscription)
        db.session.commit()

        # Log creation event
        metrics.increment('webhook.subscription.created')
        if user_id:
            log_security_event(
                event_type='webhook_subscription_created',
                description=f"Webhook subscription created: {subscription_id}",
                user_id=user_id,
                object_type='WebhookSubscription',
                object_id=subscription_id,
                severity='info'
            )

        # Don't return the secret in the response, only show it once
        return {
            "id": subscription.id,
            "target_url": subscription.target_url,
            "event_types": subscription.event_types,
            "created_at": subscription.created_at.isoformat(),
            "circuit_status": subscription.circuit_status,
            "failure_threshold": subscription.failure_threshold,
            "reset_timeout": subscription.reset_timeout,
            "secret": secret  # Only returned upon creation
        }
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to create webhook subscription: {e}")
        metrics.increment('webhook.subscription.error')
        raise


def update_subscription_circuit_breaker(
    subscription_id: str,
    user_id: int,
    failure_threshold: Optional[int] = None,
    reset_timeout: Optional[int] = None,
    circuit_status: Optional[str] = None
) -> Tuple[bool, Optional[str]]:
    """
    Update circuit breaker settings for a webhook subscription.

    Args:
        subscription_id: The ID of the subscription to update
        user_id: The ID of the user requesting the update
        failure_threshold: Number of failures before tripping circuit breaker
        reset_timeout: Time in seconds before trying again after circuit trips
        circuit_status: Manually set circuit status ('closed', 'open', 'half-open')

    Returns:
        Tuple of (success, error_message)
    """
    try:
        subscription = WebhookSubscription.query.filter_by(id=subscription_id, user_id=user_id).first()
        if not subscription:
            return False, "Webhook subscription not found or access denied"

        # Update parameters if provided
        if failure_threshold is not None:
            if not (1 <= failure_threshold <= 20):
                return False, "failure_threshold must be between 1 and 20"
            subscription.failure_threshold = failure_threshold

        if reset_timeout is not None:
            if not (30 <= reset_timeout <= 86400):  # Between 30 seconds and 24 hours
                return False, "reset_timeout must be between 30 and 86400 seconds"
            subscription.reset_timeout = reset_timeout

        if circuit_status is not None:
            if circuit_status not in ('closed', 'open', 'half-open'):
                return False, "circuit_status must be one of: closed, open, half-open"

            # Reset related fields based on status change
            if circuit_status == 'closed':
                subscription.failure_count = 0
                subscription.circuit_tripped_at = None
                subscription.next_attempt_at = None
            elif circuit_status == 'open':
                subscription.circuit_tripped_at = datetime.utcnow()
                subscription.next_attempt_at = datetime.utcnow().replace(
                    second=0, microsecond=0
                ) + timedelta(seconds=subscription.reset_timeout)

            subscription.circuit_status = circuit_status

        subscription.updated_at = datetime.utcnow()
        db.session.commit()

        # Log configuration change
        metrics.increment('webhook.subscription.circuit_breaker_configured')
        log_security_event(
            event_type='webhook_circuit_breaker_configured',
            description=f"Webhook circuit breaker configured for subscription {subscription_id}",
            user_id=user_id,
            object_type='WebhookSubscription',
            object_id=subscription_id,
            severity='info',
            details={
                'failure_threshold': subscription.failure_threshold,
                'reset_timeout': subscription.reset_timeout,
                'circuit_status': subscription.circuit_status
            }
        )

        return True, None
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error configuring webhook circuit breaker: {e}")
        metrics.increment('webhook.subscription.error')
        return False, f"Failed to update circuit breaker settings: {str(e)}"


def get_subscription_circuit_status(
    subscription_id: str,
    user_id: int
) -> Dict[str, Any]:
    """
    Get current circuit breaker status for a webhook subscription.

    Args:
        subscription_id: The ID of the subscription
        user_id: The ID of the user requesting the status

    Returns:
        Dictionary with circuit breaker state information
    """
    try:
        subscription = WebhookSubscription.query.filter_by(id=subscription_id, user_id=user_id).first()
        if not subscription:
            return {"error": "Webhook subscription not found or access denied"}

        # Calculate time remaining if circuit is open
        time_remaining_seconds = None
        if subscription.circuit_status == 'open' and subscription.next_attempt_at:
            time_remaining_seconds = max(0,
                (subscription.next_attempt_at - datetime.utcnow()).total_seconds()
            )

        return {
            "subscription_id": subscription_id,
            "target_url": subscription.target_url,
            "circuit_status": subscription.circuit_status,
            "failure_count": subscription.failure_count,
            "failure_threshold": subscription.failure_threshold,
            "reset_timeout_seconds": subscription.reset_timeout,
            "last_failure_at": subscription.last_failure_at.isoformat() if subscription.last_failure_at else None,
            "circuit_tripped_at": subscription.circuit_tripped_at.isoformat() if subscription.circuit_tripped_at else None,
            "next_attempt_at": subscription.next_attempt_at.isoformat() if subscription.next_attempt_at else None,
            "time_remaining_seconds": time_remaining_seconds,
            "health_status": _get_circuit_health_status(subscription)
        }
    except Exception as e:
        current_app.logger.error(f"Error getting webhook circuit breaker status: {e}")
        return {"error": str(e)}


def _validate_security_constraints(url: str) -> Optional[str]:
    """
    Validate URL against security constraints.

    Args:
        url: URL to validate

    Returns:
        Error message if validation fails, None if valid
    """
    try:
        parsed_url = urlparse(url)

        # Check for localhost/internal addresses
        hostname = parsed_url.hostname
        if hostname:
            # Check for localhost
            if hostname == 'localhost' or hostname.startswith('127.'):
                return "Localhost URLs are not allowed"

            # Check for internal IP addresses
            try:
                if hostname.replace('.', '').isdigit():  # Only check if it looks like an IP
                    ip = ipaddress.ip_address(hostname)
                    if ip.is_private or ip.is_loopback or ip.is_link_local:
                        return "Internal IP addresses are not allowed"
            except ValueError:
                # Not a valid IP address, continue with other checks
                pass

            # Check for internal hostnames (optional)
            restricted_hostnames = current_app.config.get('WEBHOOK_RESTRICTED_HOSTNAMES', [])
            for restricted in restricted_hostnames:
                if hostname.endswith(restricted):
                    return f"Hostname ending with {restricted} is restricted"

        # Check for restricted ports
        if parsed_url.port:
            restricted_ports = current_app.config.get('WEBHOOK_RESTRICTED_PORTS', [22, 23, 25, 3389])
            if parsed_url.port in restricted_ports:
                return f"Port {parsed_url.port} is restricted"

        return None
    except Exception as e:
        current_app.logger.error(f"Error validating URL security constraints: {e}")
        return "URL validation error"


def _get_circuit_health_status(subscription: WebhookSubscription) -> str:
    """
    Get a descriptive health status based on circuit breaker state.

    Args:
        subscription: WebhookSubscription object

    Returns:
        String describing the health status
    """
    if subscription.circuit_status == 'open':
        return "degraded"
    elif subscription.circuit_status == 'half-open':
        return "recovering"
    elif subscription.failure_count > 0:
        failure_ratio = subscription.failure_count / subscription.failure_threshold
        if failure_ratio > 0.7:
            return "warning"
        elif failure_ratio > 0.3:
            return "fair"
        else:
            return "good"
    else:
        return "healthy"
