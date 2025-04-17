"""
Tests for webhook subscription management.

This module tests creation, validation, and management of webhook subscriptions.
"""

import pytest
import uuid
from unittest.mock import patch

from api.webhooks import EventType
from api.webhooks.subscription import create_subscription
from models.webhook import WebhookSubscription

class TestWebhookSubscription:

    def test_create_subscription_valid(self, app, db, test_user):
        """Test creating a valid webhook subscription"""
        with app.app_context():
            subscription = create_subscription(
                target_url="https://example.com/webhook",
                event_types=[EventType.RESOURCE_CREATED, EventType.ALERT_TRIGGERED],
                description="Test subscription",
                headers={"X-Custom-Header": "value"},
                user_id=test_user.id
            )
            
            assert subscription["id"] is not None
            assert "secret" in subscription
            assert len(subscription["secret"]) > 32  # Should be long enough to be secure
            
            # Verify it was saved to the database
            db_subscription = WebhookSubscription.query.get(subscription["id"])
            assert db_subscription is not None
            assert db_subscription.target_url == "https://example.com/webhook"
            assert db_subscription.user_id == test_user.id
    
    def test_create_subscription_invalid_url(self, app, db, test_user):
        """Test creating a subscription with invalid URL"""
        with app.app_context():
            with pytest.raises(ValueError) as excinfo:
                create_subscription(
                    target_url="not-a-url",
                    event_types=[EventType.RESOURCE_CREATED],
                    user_id=test_user.id
                )
            assert "URL" in str(excinfo.value)
    
    def test_create_subscription_invalid_events(self, app, db, test_user):
        """Test creating a subscription with invalid event types"""
        with app.app_context():
            with pytest.raises(ValueError) as excinfo:
                create_subscription(
                    target_url="https://example.com/webhook",
                    event_types=["not-a-valid-event"],
                    user_id=test_user.id
                )
            assert "event types" in str(excinfo.value).lower()
    
    @patch('api.webhooks.subscription.secrets.token_hex')
    def test_subscription_secret_generation(self, mock_token, app, db, test_user):
        """Test that subscription secrets are securely generated"""
        mock_token.return_value = "test-secure-secret"
        
        with app.app_context():
            subscription = create_subscription(
                target_url="https://example.com/webhook",
                event_types=[EventType.RESOURCE_CREATED],
                user_id=test_user.id
            )
            
            assert subscription["secret"] == "test-secure-secret"
            mock_token.assert_called_once_with(32)  # Should generate a 32-byte hex token
