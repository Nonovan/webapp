"""
Tests for webhook security features.

This module tests webhook signature generation, verification, and other 
security features of the webhook system.
"""

import json
import hmac
import hashlib
from unittest.mock import patch

from api.webhooks import generate_webhook_signature, verify_webhook_signature
from api.webhooks.testing import MockWebhookServer

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
