"""
Test fixtures for webhook tests.

This module provides common fixtures used across webhook tests.
"""

import pytest
import uuid
from datetime import datetime

from api.webhooks import EventType, DeliveryStatus
from models.webhook import WebhookSubscription, WebhookDelivery

@pytest.fixture
def webhook_subscription(db, test_user):
    """Create a test webhook subscription"""
    subscription = WebhookSubscription(
        id=str(uuid.uuid4()),
        user_id=test_user.id,
        target_url="https://example.com/webhook-receiver",
        event_types=[EventType.RESOURCE_CREATED, EventType.ALERT_TRIGGERED],
        description="Test webhook subscription",
        headers={"X-Test-Header": "test-value"},
        secret="test-webhook-secret",
        max_retries=3,
        is_active=True
    )
    
    db.session.add(subscription)
    db.session.commit()
    
    yield subscription
    
    # Clean up
    db.session.delete(subscription)
    db.session.commit()

@pytest.fixture
def webhook_delivery(db, webhook_subscription):
    """Create a test webhook delivery"""
    delivery = WebhookDelivery(
        subscription_id=webhook_subscription.id,
        event_type=EventType.RESOURCE_CREATED,
        payload={
            "event_type": EventType.RESOURCE_CREATED,
            "timestamp": datetime.utcnow().isoformat(),
            "data": {"resource_id": 123, "name": "Test Resource"}
        },
        status=DeliveryStatus.DELIVERED,
        attempts=1,
        response_code=200,
        response_body='{"status": "received"}',
        duration_ms=125,
        created_at=datetime.utcnow()
    )
    
    db.session.add(delivery)
    db.session.commit()
    
    yield delivery
    
    # Clean up
    db.session.delete(delivery)
    db.session.commit()
