"""
Tests for webhook security features.

This module tests webhook signature generation, verification, and other
security features of the webhook system.
"""

import json
import hmac
import hashlib
import pytest
from unittest.mock import patch, MagicMock
from flask import url_for

from api.webhooks import generate_webhook_signature, verify_webhook_signature, EventType
from api.webhooks.testing import MockWebhookServer
from api.webhooks.subscription import create_subscription, _validate_security_constraints
from models.communication.webhook import WebhookSubscription
from tests.conftest import login_user, logout_user

class TestWebhookSecurity:

    def test_signature_generation(self):
        """Test webhook signature generation"""
        payload = json.dumps({"test": "data"})
        secret = "webhook-secret-key"

        signature = generate_webhook_signature(payload, secret)

        # Verify signature format
        assert isinstance(signature, str)
        assert len(signature) == 64  # SHA-256 hex digest is 64 chars

        # Verify signature matches expected
        expected = hmac.new(
            secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        assert signature == expected

    def test_signature_verification(self):
        """Test webhook signature verification"""
        payload = json.dumps({"test": "data"})
        secret = "webhook-secret-key"

        # Generate signature
        signature = generate_webhook_signature(payload, secret)

        # Verify correct signature passes
        assert verify_webhook_signature(payload, signature, secret) is True

        # Verify incorrect signature fails
        assert verify_webhook_signature(payload, "invalid-signature", secret) is False
        assert verify_webhook_signature(payload, signature, "wrong-secret") is False

        # Verify tampered payload fails
        tampered = json.dumps({"test": "tampered"})
        assert verify_webhook_signature(tampered, signature, secret) is False

    def test_mock_webhook_server_signature_verification(self):
        """Test that MockWebhookServer correctly verifies signatures"""
        payload = {"event_type": "test.event", "data": {"test": "data"}}
        secret = "webhook-secret-key"

        # Create mock server
        server = MockWebhookServer()

        # Generate signature
        payload_str = json.dumps(payload)
        signature = generate_webhook_signature(payload_str, secret)

        # Deliver to mock server
        headers = {
            "Content-Type": "application/json",
            "X-Webhook-Signature": signature
        }

        server.receive(payload, headers)

        # Verify signature checking works
        assert server.verify_signature(0, secret) is True
        assert server.verify_signature(0, "wrong-secret") is False

    def test_authentication_required_for_endpoints(self, client):
        """
        Test that all webhook endpoints require authentication.

        This ensures that unauthenticated users cannot access webhook functionality.
        """
        # List of endpoints to test with their methods
        endpoints = [
            (url_for('api.webhooks.list_webhook_subscriptions'), 'GET'),
            (url_for('api.webhooks.create_webhook_subscription'), 'POST'),
            (url_for('api.webhooks.test_webhook'), 'POST'),
            # Assuming we have a subscription ID
            (url_for('api.webhooks.get_webhook_subscription', subscription_id='test-id'), 'GET'),
            (url_for('api.webhooks.delete_webhook_subscription', subscription_id='test-id'), 'DELETE'),
            (url_for('api.webhooks.list_webhook_deliveries', subscription_id='test-id'), 'GET')
        ]

        # Test each endpoint
        for endpoint, method in endpoints:
            if method == 'GET':
                response = client.get(endpoint)
            elif method == 'POST':
                response = client.post(endpoint, json={})
            elif method == 'DELETE':
                response = client.delete(endpoint)

            # All should return 401 Unauthorized or 403 Forbidden for unauthenticated users
            assert response.status_code in (401, 403), f"Expected 401/403 for {method} {endpoint}, got {response.status_code}"

    def test_url_security_constraints(self):
        """
        Test that URL security constraints prevent dangerous webhook URLs.

        Ensures that restricted URLs like internal networks, localhost, and
        sensitive ports are rejected.
        """
        # Test internal/private network addresses
        internal_addresses = [
            "http://10.0.0.1/webhook",           # Class A private
            "http://172.16.0.5/webhook",         # Class B private
            "http://192.168.1.1/webhook",        # Class C private
            "http://127.0.0.1/webhook",          # Localhost
            "http://localhost/webhook",          # Localhost name
            "http://0.0.0.0/webhook",            # All interfaces
            "http://169.254.169.254/metadata",   # AWS metadata service
            "http://webhook.internal/webhook"    # Assumed internal DNS
        ]

        for url in internal_addresses:
            error = _validate_security_constraints(url)
            assert error is not None, f"Expected URL rejection for {url}"

        # Test dangerous ports
        dangerous_ports = [
            "http://example.com:22/webhook",    # SSH
            "http://example.com:23/webhook",    # Telnet
            "http://example.com:25/webhook",    # SMTP
            "http://example.com:3389/webhook",  # RDP
        ]

        for url in dangerous_ports:
            error = _validate_security_constraints(url)
            assert error is not None, f"Expected port rejection for {url}"

        # Valid URLs should pass
        valid_urls = [
            "https://api.example.com/webhook",
            "https://webhook.customer-domain.com/endpoint",
            "https://example.com:443/webhook",
            "https://example.com:8080/webhook"
        ]

        for url in valid_urls:
            error = _validate_security_constraints(url)
            assert error is None, f"Expected valid URL to be accepted: {url}, got error: {error}"

    @patch('models.communication.webhook.WebhookSubscription.rotate_secret')
    def test_secret_rotation(self, mock_rotate, app, client, db, test_user, webhook_subscription):
        """
        Test that webhook secrets can be securely rotated.

        This ensures that secret rotation functionality works correctly and
        logs security events appropriately.
        """
        # Configure mock
        mock_rotate.return_value = True

        # Login as the subscription owner
        login_user(client, test_user)

        # Request secret rotation
        rotation_url = url_for('api.webhooks.rotate_webhook_secret', subscription_id=webhook_subscription.id)
        response = client.post(rotation_url)

        # Verify response
        assert response.status_code == 200
        result = json.loads(response.data)

        # Should return success message
        assert result.get("success") is True
        assert "new_secret" in result
        assert result["new_secret"] != webhook_subscription.secret

        # Verify that rotate_secret was called
        mock_rotate.assert_called_once()

    @patch('api.webhooks.routes.metrics')
    @patch('api.webhooks.routes.log_security_event')
    def test_endpoint_security_logging(self, mock_security_log, mock_metrics, app, client, db, test_user, webhook_subscription):
        """
        Test that security-relevant webhook actions are properly logged.

        Ensures that sensitive operations like secret rotation and subscription
        management are logged for security auditing.
        """
        login_user(client, test_user)

        # Set up mocks
        mock_metrics.increment = MagicMock()

        # Test deletion - should log a security event
        delete_url = url_for('api.webhooks.delete_webhook_subscription', subscription_id=webhook_subscription.id)
        response = client.delete(delete_url)

        assert response.status_code == 200

        # Verify security logging
        mock_security_log.assert_called()
        mock_metrics.increment.assert_called_with('webhook.subscription.deleted')

    def test_secure_secret_storage(self, app, db, test_user):
        """
        Test that webhook secrets are securely stored and not exposed.

        Ensures that secrets are properly generated and not exposed in API responses
        after initial creation.
        """
        with app.app_context():
            # Create a subscription
            subscription_data = create_subscription(
                target_url="https://example.com/webhook",
                event_types=[EventType.RESOURCE_CREATED],
                user_id=test_user.id
            )

            # Secret should be in the initial response
            assert "secret" in subscription_data
            assert len(subscription_data["secret"]) >= 32

            # Get the subscription from database
            db_subscription = WebhookSubscription.query.get(subscription_data["id"])

            # Secret should be stored in the database
            assert db_subscription.secret is not None
            assert db_subscription.secret == subscription_data["secret"]

            # Now test that the secret is not exposed in subscription details
            to_dict_result = db_subscription.to_dict(exclude_secret=True)
            assert "secret" not in to_dict_result

    @patch('api.webhooks.routes.deliver_webhook')
    def test_csrf_protection_for_webhooks(self, mock_deliver, client, db, test_user, webhook_subscription):
        """
        Test that webhook endpoints are protected against CSRF attacks.

        Ensures that state-changing operations require proper CSRF protection.
        """
        login_user(client, test_user)

        # Test endpoint without CSRF protection would be vulnerable
        mock_deliver.return_value = [{
            "delivery_id": 123,
            "subscription_id": webhook_subscription.id,
            "event_type": "test.event",
            "status": "pending"
        }]

        # Attempt without proper content type (simulating CSRF)
        response = client.post(
            url_for('api.webhooks.test_webhook'),
            data="subscription_id=" + webhook_subscription.id
        )

        # Should get a 400 Bad Request because JSON is expected
        assert response.status_code == 400, "API endpoint should reject non-JSON requests"

        # Now try with proper JSON content type
        response = client.post(
            url_for('api.webhooks.test_webhook'),
            json={"subscription_id": webhook_subscription.id},
            content_type='application/json'
        )

        # Should succeed
        assert response.status_code == 200

    def test_no_secret_exposure_in_logs(self, app, caplog):
        """
        Test that webhook secrets are not exposed in logs.

        Ensures that sensitive secrets are not accidentally logged.
        """
        secret = "super-secret-webhook-key-12345"
        payload = json.dumps({"data": "test"})

        # Generate signature with the secret
        with caplog.at_level('DEBUG'):
            signature = generate_webhook_signature(payload, secret)
            # Verify the signature
            verify_webhook_signature(payload, signature, secret)

        # Check that the secret isn't in logs
        assert secret not in caplog.text, "Secret should not be exposed in logs"

    def test_rate_limiting(self, client, db, test_user):
        """
        Test that webhook endpoints are rate limited.

        Ensures that the rate limits configured for webhook endpoints are enforced.
        """
        login_user(client, test_user)

        # Test rate limiting on test webhook endpoint (10/minute)
        for i in range(12):  # Try 12 times, should be limited after 10
            response = client.post(
                url_for('api.webhooks.test_webhook'),
                json={"subscription_id": "test-id"},
                content_type='application/json'
            )

            if i < 10:
                # First 10 requests should return 400 (bad request) due to invalid ID but not be rate limited
                assert response.status_code == 400, f"Expected 400 for request {i+1}, got {response.status_code}"
            else:
                # Requests after rate limit should return 429
                assert response.status_code == 429, f"Expected 429 for request {i+1}, got {response.status_code}"
                break
