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
from api.webhooks.subscription import _validate_security_constraints
from models.communication.webhook import WebhookSubscription
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

    def test_get_circuit_status(self, client, db, test_user, webhook_subscription):
        """Test getting circuit breaker status"""
        login_user(client, test_user)

        response = client.get(
            url_for('api.webhooks.get_circuit_status',
                   subscription_id=webhook_subscription.id)
        )

        assert response.status_code == 200
        result = json.loads(response.data)

        # Verify status structure
        assert "circuit_status" in result
        assert "failure_count" in result
        assert "failure_threshold" in result
        assert "health_status" in result
        assert result["circuit_status"] == "closed"  # Default should be closed

    @patch('api.webhooks.routes.configure_circuit_breaker')
    def test_configure_circuit_breaker(self, mock_configure, client, db, test_user, webhook_subscription):
        """Test configuring circuit breaker parameters"""
        login_user(client, test_user)

        # Mock the configure function to return success
        mock_configure.return_value = (True, None)

        data = {
            "failure_threshold": 10,
            "reset_timeout": 120
        }

        response = client.post(
            url_for('api.webhooks.manage_circuit_breaker',
                   subscription_id=webhook_subscription.id),
            json=data,
            content_type='application/json'
        )

        assert response.status_code == 200
        result = json.loads(response.data)
        assert result["success"] is True

        # Verify configure_circuit_breaker was called correctly
        mock_configure.assert_called_once_with(
            subscription_id=webhook_subscription.id,
            user_id=test_user.id,
            failure_threshold=10,
            reset_timeout=120,
            circuit_status=None  # Not changing status
        )

    @patch('api.webhooks.routes.reset_circuit_breaker')
    def test_reset_circuit_breaker(self, mock_reset, client, db, test_user, open_circuit_subscription):
        """Test resetting circuit breaker state"""
        login_user(client, test_user)
        subscription, _ = open_circuit_subscription

        # Mock the reset function to return success
        mock_reset.return_value = True

        data = {
            "action": "reset"
        }

        response = client.post(
            url_for('api.webhooks.manage_circuit_breaker',
                   subscription_id=subscription.id),
            json=data,
            content_type='application/json'
        )

        assert response.status_code == 200
        result = json.loads(response.data)
        assert result["success"] is True

        # Verify reset_circuit_breaker was called correctly
        mock_reset.assert_called_once_with(
            subscription_id=subscription.id,
            user_id=test_user.id
        )

    def test_authentication_required(self, client, webhook_subscription):
        """Test authentication requirements for webhook endpoints"""
        # Ensure user is logged out
        logout_user(client)

        # Test each endpoint that requires authentication
        endpoints = [
            (url_for('api.webhooks.create_webhook_subscription'), 'POST'),
            (url_for('api.webhooks.list_webhook_subscriptions'), 'GET'),
            (url_for('api.webhooks.get_webhook_subscription', subscription_id=webhook_subscription.id), 'GET'),
            (url_for('api.webhooks.delete_webhook_subscription', subscription_id=webhook_subscription.id), 'DELETE'),
            (url_for('api.webhooks.list_webhook_deliveries', subscription_id=webhook_subscription.id), 'GET'),
            (url_for('api.webhooks.test_webhook'), 'POST'),
            (url_for('api.webhooks.list_webhook_events'), 'GET'),
            (url_for('api.webhooks.get_circuit_status', subscription_id=webhook_subscription.id), 'GET'),
            (url_for('api.webhooks.manage_circuit_breaker', subscription_id=webhook_subscription.id), 'POST'),
        ]

        for endpoint, method in endpoints:
            if method == 'GET':
                response = client.get(endpoint)
            elif method == 'POST':
                response = client.post(endpoint, json={})
            elif method == 'DELETE':
                response = client.delete(endpoint)

            assert response.status_code in [401, 302], f"Expected 401/302 for {method} {endpoint}, got {response.status_code}"

    def test_subscription_access_control(self, client, db, test_user, test_admin_user, webhook_subscription):
        """Test that users can only access their own subscriptions"""
        # Create subscription owned by test_user
        test_user_sub = webhook_subscription

        # Login as admin user (different from owner)
        login_user(client, test_admin_user)

        # Try to access test_user's subscription
        response = client.get(
            url_for('api.webhooks.get_webhook_subscription',
                   subscription_id=test_user_sub.id)
        )

        # Should get 404 (not 403) for security reasons (not revealing existence)
        assert response.status_code == 404

    def test_create_subscription_with_circuit_breaker_params(self, client, db, test_user):
        """Test creating a subscription with circuit breaker parameters"""
        login_user(client, test_user)

        data = {
            "target_url": "https://example.com/webhook-receiver",
            "event_types": [EventType.RESOURCE_CREATED],
            "description": "Test subscription with circuit breaker",
            "failure_threshold": 8,
            "reset_timeout": 180
        }

        response = client.post(
            url_for('api.webhooks.create_webhook_subscription'),
            json=data,
            content_type='application/json'
        )

        assert response.status_code == 201
        result = json.loads(response.data)

        # Verify circuit breaker parameters
        assert result["failure_threshold"] == 8
        assert result["reset_timeout"] == 180

    def test_create_subscription_invalid_url(self, client, db, test_user):
        """Test creating subscription with invalid URL"""
        login_user(client, test_user)

        data = {
            "target_url": "not-a-url",
            "event_types": [EventType.RESOURCE_CREATED]
        }

        response = client.post(
            url_for('api.webhooks.create_webhook_subscription'),
            json=data,
            content_type='application/json'
        )

        assert response.status_code == 400
        result = json.loads(response.data)
        assert "error" in result

    @patch('api.webhooks.routes._validate_security_constraints')
    def test_create_subscription_security_check(self, mock_validate, client, db, test_user):
        """Test URL security validation during subscription creation"""
        login_user(client, test_user)

        # Mock validation to fail for specific URL
        mock_validate.return_value = "Internal network addresses not allowed"

        data = {
            "target_url": "http://10.0.0.1:8080/webhook",  # Internal IP
            "event_types": [EventType.RESOURCE_CREATED]
        }

        response = client.post(
            url_for('api.webhooks.create_webhook_subscription'),
            json=data,
            content_type='application/json'
        )

        assert response.status_code == 400
        result = json.loads(response.data)
        assert "error" in result
        assert "Internal network" in result["error"]

    @patch('api.webhooks.routes.deliver_webhook')
    def test_test_webhook_blocked_by_circuit_breaker(self, mock_deliver, client, db, test_user, open_circuit_subscription):
        """Test that test webhook endpoint respects circuit breaker state"""
        login_user(client, test_user)
        subscription, _ = open_circuit_subscription

        # Mock the deliver_webhook function to return empty list (blocked by circuit)
        mock_deliver.return_value = []

        data = {
            "subscription_id": subscription.id
        }

        response = client.post(
            url_for('api.webhooks.test_webhook'),
            json=data,
            content_type='application/json'
        )

        # Should fail due to circuit breaker
        assert response.status_code == 500
        result = json.loads(response.data)
        assert "error" in result

    def test_empty_event_types(self, client, db, test_user):
        """Test creating subscription with empty event types"""
        login_user(client, test_user)

        data = {
            "target_url": "https://example.com/webhook",
            "event_types": []  # Empty event types
        }

        response = client.post(
            url_for('api.webhooks.create_webhook_subscription'),
            json=data,
            content_type='application/json'
        )

        assert response.status_code == 400
        result = json.loads(response.data)
        assert "error" in result

    def test_invalid_content_type(self, client, db, test_user):
        """Test API protection against non-JSON requests"""
        login_user(client, test_user)

        # Try to use form data instead of JSON
        response = client.post(
            url_for('api.webhooks.create_webhook_subscription'),
            data="target_url=https://example.com",
            content_type='application/x-www-form-urlencoded'
        )

        assert response.status_code == 400
        assert b"Invalid request format" in response.data

    @patch('api.webhooks.routes.metrics.increment')
    def test_metrics_tracking(self, mock_increment, client, db, test_user, webhook_subscription):
        """Test that API endpoints track metrics"""
        login_user(client, test_user)

        # Test deletion for metrics tracking
        response = client.delete(
            url_for('api.webhooks.delete_webhook_subscription',
                   subscription_id=webhook_subscription.id)
        )

        assert response.status_code == 200
        mock_increment.assert_called_with('webhook.subscription.deleted')

    @patch('api.webhooks.routes.rate_limit_exceeded')
    def test_rate_limiting(self, mock_rate_limit, client, db, test_user):
        """Test rate limiting on webhook endpoints"""
        login_user(client, test_user)

        # Configure the rate limit exceeded mock to return True (limit exceeded)
        mock_rate_limit.return_value = True

        # Try to access a rate-limited endpoint
        response = client.get(url_for('api.webhooks.list_webhook_subscriptions'))

        # Should get a 429 Too Many Requests
        assert response.status_code == 429

    def test_filter_subscriptions_by_event(self, client, db, test_user, multiple_webhook_subscriptions):
        """Test filtering webhook subscriptions by event type"""
        login_user(client, test_user)

        # Filter by event type
        response = client.get(
            url_for('api.webhooks.list_webhook_subscriptions') +
            f'?event_type={EventType.ALERT_TRIGGERED}'
        )

        assert response.status_code == 200
        result = json.loads(response.data)

        # Should only include subscriptions for this event type
        for subscription in result["items"]:
            assert EventType.ALERT_TRIGGERED in subscription["event_types"]

    def test_pagination(self, client, db, test_user, multiple_webhook_subscriptions):
        """Test pagination for webhook subscription listing"""
        login_user(client, test_user)

        # Request with pagination params
        response = client.get(
            url_for('api.webhooks.list_webhook_subscriptions') + '?page=1&per_page=2'
        )

        assert response.status_code == 200
        result = json.loads(response.data)

        # Verify pagination fields
        assert "page" in result
        assert "per_page" in result
        assert "total" in result
        assert "pages" in result
        assert len(result["items"]) <= 2  # Should respect per_page

    def test_filter_deliveries_by_status(self, client, db, test_user, webhook_with_deliveries):
        """Test filtering webhook deliveries by status"""
        login_user(client, test_user)

        subscription, _ = webhook_with_deliveries

        # Filter by failed status
        response = client.get(
            url_for('api.webhooks.list_webhook_deliveries',
                   subscription_id=subscription.id) + f'?status={DeliveryStatus.FAILED}'
        )

        assert response.status_code == 200
        result = json.loads(response.data)

        # Should only include failed deliveries
        for delivery in result["items"]:
            assert delivery["status"] == DeliveryStatus.FAILED

    @patch('api.webhooks.routes.get_circuit_breaker_stats')
    def test_get_circuit_breaker_stats(self, mock_get_stats, client, db, test_user, webhook_subscription):
        """Test getting circuit breaker statistics"""
        login_user(client, test_user)

        # Mock the stats endpoint
        mock_get_stats.return_value = {
            "total_webhooks": 100,
            "open_circuits": 5,
            "half_open_circuits": 2,
            "failing_webhooks": 10
        }

        response = client.get(url_for('api.webhooks.circuit_breaker_stats'))

        assert response.status_code == 200
        result = json.loads(response.data)

        # Verify stats structure
        assert "total_webhooks" in result
        assert "open_circuits" in result
        assert "half_open_circuits" in result
        assert "failing_webhooks" in result

    def test_nonexistent_subscription(self, client, db, test_user):
        """Test handling of non-existent subscription IDs"""
        login_user(client, test_user)

        fake_id = str(uuid.uuid4())

        response = client.get(
            url_for('api.webhooks.get_webhook_subscription',
                   subscription_id=fake_id)
        )

        assert response.status_code == 404
        result = json.loads(response.data)
        assert "error" in result

    def test_invalid_subscription_id_format(self, client, db, test_user):
        """Test handling of invalid subscription ID format"""
        login_user(client, test_user)

        invalid_id = "not-a-uuid"

        response = client.get(
            url_for('api.webhooks.get_webhook_subscription',
                   subscription_id=invalid_id)
        )

        assert response.status_code == 400
        result = json.loads(response.data)
        assert "error" in result
