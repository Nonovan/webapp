"""
Tests for webhook API routes.

This module tests the webhook HTTP endpoints to ensure they function correctly,
handle authentication properly, and enforce appropriate rate limits.
"""

import json
import uuid
from unittest.mock import patch, MagicMock
from flask import url_for

from api.webhooks import EventType, DeliveryStatus
from api.webhooks.routes import webhooks_api
from tests.conftest import login_user, logout_user

class TestWebhookRoutes:

    def test_create_webhook_subscription(self, client, db, test_user):
        """Test creating a webhook subscription"""
        # Login required
        login_user(client, test_user)
        
        # Create subscription
        data = {
            "target_url": "https://example.com/webhook-receiver",
            "event_types": [EventType.RESOURCE_CREATED, EventType.ALERT_TRIGGERED],
            "description": "Test webhook subscription",
            "headers": {"X-Test-Header": "test-value"}
        }
        
        response = client.post(
            url_for('api.webhooks.create_webhook_subscription'),
            json=data,
            content_type='application/json'
        )
        
        assert response.status_code == 201
        result = json.loads(response.data)
        
        # Verify response structure
        assert "id" in result
        assert "target_url" in result
        assert "event_types" in result
        assert "secret" in result  # Secret should be in initial response only
        assert result["target_url"] == data["target_url"]
    
    def test_list_webhook_subscriptions(self, client, db, test_user, webhook_subscription):
        """Test listing webhook subscriptions"""
        login_user(client, test_user)
        
        response = client.get(url_for('api.webhooks.list_webhook_subscriptions'))
        assert response.status_code == 200
        
        result = json.loads(response.data)
        assert "items" in result
        assert isinstance(result["items"], list)
        assert len(result["items"]) >= 1
    
    def test_get_webhook_subscription(self, client, db, test_user, webhook_subscription):
        """Test getting a specific webhook subscription"""
        login_user(client, test_user)
        
        response = client.get(
            url_for('api.webhooks.get_webhook_subscription', 
                   subscription_id=webhook_subscription.id)
        )
        
        assert response.status_code == 200
        result = json.loads(response.data)
        assert result["id"] == webhook_subscription.id
        assert "secret" not in result  # Secret should not be exposed after creation
    
    def test_delete_webhook_subscription(self, client, db, test_user, webhook_subscription):
        """Test deleting a webhook subscription"""
        login_user(client, test_user)
        
        response = client.delete(
            url_for('api.webhooks.delete_webhook_subscription',
                   subscription_id=webhook_subscription.id)
        )
        
        assert response.status_code == 200
        result = json.loads(response.data)
        assert result["success"] is True
        
        # Verify it's actually deleted
        response = client.get(
            url_for('api.webhooks.get_webhook_subscription',
                   subscription_id=webhook_subscription.id)
        )
        assert response.status_code == 404
    
    def test_list_webhook_deliveries(self, client, db, test_user, webhook_subscription, webhook_delivery):
        """Test listing webhook delivery history"""
        login_user(client, test_user)
        
        response = client.get(
            url_for('api.webhooks.list_webhook_deliveries',
                   subscription_id=webhook_subscription.id)
        )
        
        assert response.status_code == 200
        result = json.loads(response.data)
        assert "items" in result
        assert len(result["items"]) >= 1
    
    @patch('api.webhooks.routes.deliver_webhook')
    def test_test_webhook(self, mock_deliver, client, db, test_user, webhook_subscription):
        """Test the test webhook endpoint"""
        login_user(client, test_user)
        
        # Mock the deliver_webhook function
        mock_deliver.return_value = [{
            "delivery_id": 123,
            "subscription_id": webhook_subscription.id,
            "event_type": "test.event",
            "status": DeliveryStatus.PENDING
        }]
        
        payload = {"message": "Test webhook"}
        data = {
            "subscription_id": webhook_subscription.id,
            "payload": payload
        }
        
        response = client.post(
            url_for('api.webhooks.test_webhook'),
            json=data,
            content_type='application/json'
        )
        
        assert response.status_code == 200
        result = json.loads(response.data)
        assert result["success"] is True
        assert "delivery" in result
        
        # Verify deliver_webhook was called correctly
        mock_deliver.assert_called_once_with(
            event_type="test.event",
            payload=payload,
            subscription_id=webhook_subscription.id
        )
    
    def test_list_webhook_events(self, client, db, test_user):
        """Test listing available webhook event types"""
        login_user(client, test_user)
        
        response = client.get(url_for('api.webhooks.list_webhook_events'))
        assert response.status_code == 200
        
        result = json.loads(response.data)
        assert "event_types" in result
        assert "categories" in result
        assert isinstance(result["event_types"], list)
        assert isinstance(result["categories"], dict)
