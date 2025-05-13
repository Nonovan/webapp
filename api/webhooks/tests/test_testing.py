"""
Tests for webhook testing utilities.

This module tests the MockWebhookServer and other testing utilities
for the webhook system.
"""

import json
import time
import threading
import requests
from datetime import datetime
from unittest.mock import patch, MagicMock

from api.webhooks import generate_webhook_signature
from api.webhooks.testing import MockWebhookServer

class TestWebhookTestingUtilities:

    def test_mock_webhook_server_receive(self):
        """Test that MockWebhookServer correctly receives webhooks"""
        server = MockWebhookServer()

        # Test payload and headers
        payload = {
            "event_type": "resource.created",
            "data": {"resource_id": 123}
        }
        headers = {"Content-Type": "application/json"}

        # Receive webhook
        response = server.receive(payload, headers)

        # Verify response
        assert response["status_code"] == 200
        assert response["body"] == '{"status": "received"}'

        # Verify webhook was stored
        assert len(server.deliveries) == 1
        assert server.deliveries[0]["payload"] == payload
        assert server.deliveries[0]["headers"] == headers
        assert "received_at" in server.deliveries[0]

    def test_mock_webhook_server_custom_response(self):
        """Test that MockWebhookServer can return custom responses"""
        server = MockWebhookServer()

        # Set custom response
        server.set_response(429, '{"error": "Rate limit exceeded"}')

        # Receive webhook
        response = server.receive({"test": "data"}, {})

        # Verify custom response
        assert response["status_code"] == 429
        assert response["body"] == '{"error": "Rate limit exceeded"}'

    def test_mock_webhook_server_clear(self):
        """Test that MockWebhookServer can clear deliveries"""
        server = MockWebhookServer()

        # Add some deliveries
        server.receive({"test": "data1"}, {})
        server.receive({"test": "data2"}, {})
        assert len(server.deliveries) == 2

        # Clear deliveries
        server.clear()
        assert len(server.deliveries) == 0

    def test_mock_webhook_server_verify_delivery(self):
        """Test that MockWebhookServer can verify deliveries"""
        server = MockWebhookServer()

        # Add deliveries with different event types
        server.receive({"event_type": "resource.created", "data": {}}, {})
        server.receive({"event_type": "resource.updated", "data": {}}, {})
        server.receive({"event_type": "resource.created", "data": {}}, {})

        # Verify counts
        assert server.verify_delivery("resource.created", count=2) is True
        assert server.verify_delivery("resource.updated", count=1) is True
        assert server.verify_delivery("resource.deleted", count=0) is False
        assert server.verify_delivery("resource.created", count=3) is False

    def test_mock_webhook_server_get_deliveries_for_event(self):
        """Test retrieving deliveries for a specific event"""
        server = MockWebhookServer()

        # Add deliveries with different event types
        server.receive({"event_type": "resource.created", "data": {"id": "1"}}, {})
        server.receive({"event_type": "resource.updated", "data": {"id": "2"}}, {})
        server.receive({"event_type": "resource.created", "data": {"id": "3"}}, {})

        # Retrieve deliveries for specific event type
        created_deliveries = server.get_deliveries_for_event("resource.created")

        # Verify filtered deliveries
        assert len(created_deliveries) == 2
        assert created_deliveries[0]["payload"]["data"]["id"] == "1"
        assert created_deliveries[1]["payload"]["data"]["id"] == "3"

    def test_mock_webhook_server_signature_verification(self):
        """Test signature verification in MockWebhookServer"""
        # Create server with secret
        secret = "test-webhook-secret"
        server = MockWebhookServer(secret=secret)

        # Create payload and generate signature
        payload = json.dumps({"event_type": "resource.created", "data": {"id": "123"}})
        signature = generate_webhook_signature(payload, secret)

        # Receive webhook with signature
        headers = {
            "Content-Type": "application/json",
            "X-Webhook-Signature": signature
        }

        server.receive(json.loads(payload), headers)

        # Verify signature check succeeded
        assert server.verify_signature(0, secret) is True

    def test_mock_webhook_server_invalid_signature(self):
        """Test invalid signature detection in MockWebhookServer"""
        # Create server with secret
        secret = "test-webhook-secret"
        server = MockWebhookServer(secret=secret)

        # Create payload with invalid signature
        payload = json.dumps({"event_type": "resource.created", "data": {"id": "123"}})
        invalid_signature = "invalid-signature-value"

        # Receive webhook with invalid signature
        headers = {
            "Content-Type": "application/json",
            "X-Webhook-Signature": invalid_signature
        }

        server.receive(json.loads(payload), headers)

        # Verify signature check fails
        assert server.verify_signature(0, secret) is False

    def test_mock_webhook_server_failure_sequence(self):
        """Test failure sequence in MockWebhookServer"""
        server = MockWebhookServer()

        # Set failure sequence
        server.set_failure_sequence([200, 500, 429, 200])

        # Make multiple requests and verify responses follow the sequence
        responses = []
        for _ in range(5):  # Test past the end to verify cycling
            response = server.receive({"test": "data"}, {})
            responses.append(response["status_code"])

        assert responses == [200, 500, 429, 200, 200]  # Last one cycles back

    def test_mock_webhook_server_assert_payload_matches(self):
        """Test payload matching assertions in MockWebhookServer"""
        server = MockWebhookServer()

        # Add a delivery with nested payload
        server.receive({
            "event_type": "resource.created",
            "data": {
                "id": "123",
                "attributes": {
                    "name": "Test Resource",
                    "status": "active"
                }
            }
        }, {})

        # Test exact match
        assert server.assert_payload_matches(0, {"id": "123"}, "data") is True

        # Test nested match
        assert server.assert_payload_matches(0, {"name": "Test Resource"}, "data.attributes") is True

        # Test mismatched data
        try:
            server.assert_payload_matches(0, {"id": "456"}, "data")
            assert False, "Should have raised AssertionError on mismatch"
        except AssertionError:
            pass  # Expected behavior

    def test_mock_webhook_server_response_delay(self):
        """Test response delay functionality"""
        server = MockWebhookServer()

        # Set delay
        delay_time = 0.1  # Short delay for testing
        server.set_response_delay(delay_time)

        # Measure response time
        start_time = time.time()
        server.receive({"test": "data"}, {})
        end_time = time.time()

        # Verify delay was applied
        assert end_time - start_time >= delay_time

    @patch('time.sleep')
    def test_mock_webhook_server_simulate_circuit_breaker(self, mock_sleep):
        """Test circuit breaker simulation in MockWebhookServer"""
        server = MockWebhookServer()

        # Configure for circuit breaker testing
        server.simulate_circuit_breaker_scenario(num_failures=3)

        # First 3 requests should fail
        for i in range(3):
            response = server.receive({"test": f"attempt-{i}"}, {})
            assert response["status_code"] >= 500

        # Fourth request should succeed
        response = server.receive({"test": "attempt-4"}, {})
        assert response["status_code"] == 200

        # Verify the server tracked requests as expected
        assert len(server.deliveries) == 4
        assert server.get_delivery_count() == 4

    def test_mock_webhook_server_custom_response_handler(self):
        """Test custom response handler in MockWebhookServer"""
        server = MockWebhookServer()

        # Define custom handler
        def custom_handler(payload, headers):
            if payload.get("priority") == "high":
                return {"status_code": 200, "body": '{"status":"prioritized"}'}
            else:
                return {"status_code": 202, "body": '{"status":"queued"}'}

        # Set custom handler
        server.set_response_handler(custom_handler)

        # Test with different payloads
        high_response = server.receive({"priority": "high"}, {})
        low_response = server.receive({"priority": "low"}, {})

        assert high_response["status_code"] == 200
        assert json.loads(high_response["body"])["status"] == "prioritized"

        assert low_response["status_code"] == 202
        assert json.loads(low_response["body"])["status"] == "queued"

    def test_get_delivery_count(self):
        """Test delivery count tracking"""
        server = MockWebhookServer()

        assert server.get_delivery_count() == 0

        server.receive({"test": "data1"}, {})
        assert server.get_delivery_count() == 1

        server.receive({"test": "data2"}, {})
        assert server.get_delivery_count() == 2

        server.clear()
        assert server.get_delivery_count() == 0

    @patch('requests.post')
    def test_mock_server_url_property(self, mock_post):
        """Test the url property generates a valid URL"""
        server = MockWebhookServer()

        # Verify URL format
        assert server.url.startswith("https://") or server.url.startswith("http://")
        assert "webhook" in server.url

    @patch('threading.Thread')
    @patch('flask.Flask')
    def test_start_capture_server(self, mock_flask, mock_thread):
        """Test starting a capture server"""
        server = MockWebhookServer()

        # Mock the thread to avoid actually starting a server
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        # Start server
        result = server.start_capture_server(port=8099)

        # Verify thread was created and started
        assert mock_thread.called
        assert mock_thread_instance.daemon is True
        assert mock_thread_instance.start.called

        # Verify URL was updated
        assert server.url == "http://localhost:8099"

        # Verify thread was returned
        assert result == mock_thread_instance

    def test_mock_server_event_type_extraction(self):
        """Test that event types are properly extracted from payloads"""
        server = MockWebhookServer()

        # Add deliveries with event types in different formats
        server.receive({"event_type": "resource.created"}, {})
        server.receive({"eventType": "resource.updated"}, {})
        server.receive({"event": "resource.deleted"}, {})
        server.receive({"type": "notification.sent"}, {})

        # Check event type extraction for each format
        assert server.deliveries[0].get("extracted_event_type") == "resource.created"
        assert server.deliveries[1].get("extracted_event_type") == "resource.updated"
        assert server.deliveries[2].get("extracted_event_type") == "resource.deleted"
        assert server.deliveries[3].get("extracted_event_type") == "notification.sent"

        # Verify count by extracted event type
        assert server.verify_delivery("resource.created", count=1) is True
        assert server.verify_delivery("resource.updated", count=1) is True
        assert server.verify_delivery("resource.deleted", count=1) is True
        assert server.verify_delivery("notification.sent", count=1) is True

    def test_webhook_server_default_parameters(self):
        """Test default parameters of MockWebhookServer"""
        server = MockWebhookServer()

        # Verify defaults
        assert server.response_code == 200
        assert server.response_body == '{"status": "received"}'
        assert server.response_delay == 0
        assert server.response_handler is None
        assert server.deliveries == []
        assert server._failure_sequence == []
        assert server._failure_index == 0
