"""
Tests for webhook testing utilities.

This module tests the MockWebhookServer and other testing utilities
for the webhook system.
"""

import json
from datetime import datetime

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
