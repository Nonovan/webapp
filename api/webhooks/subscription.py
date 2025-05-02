"""
Webhook subscription management for Cloud Infrastructure Platform.

This module provides functionality for creating, updating, and deleting
webhook subscription configurations, including validation and security.
"""

from typing import Dict, List, Optional
from flask import current_app
import uuid
import secrets
from datetime import datetime

from models import db, WebhookSubscription
from . import EventType, EVENT_TYPES, EVENT_CATEGORIES, generate_webhook_signature

def create_subscription(
    target_url: str,
    event_types: List[str],
    description: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    user_id: Optional[int] = None,
    max_retries: int = 3
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

    # Generate subscription ID and secret
    subscription_id = str(uuid.uuid4())
    secret = secrets.token_hex(32)

    # Create subscription
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
        is_active=True
    )

    try:
        db.session.add(subscription)
        db.session.commit()

        # Don't return the secret in the response, only show it once
        return {
            "id": subscription.id,
            "target_url": subscription.target_url,
            "event_types": subscription.event_types,
            "created_at": subscription.created_at.isoformat(),
            "secret": secret  # Only returned upon creation
        }
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to create webhook subscription: {e}")
        raise
