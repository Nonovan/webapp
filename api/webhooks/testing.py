"""
Testing utilities for webhooks.

This module provides tools for testing webhook delivery and subscription
management without making actual HTTP requests.
"""

from typing import Dict, Any, List, Optional
import json
from datetime import datetime

from models.webhook import WebhookSubscription, WebhookDelivery
from . import DeliveryStatus, generate_webhook_signature

class MockWebhookServer:
    """
    Mock webhook receiver for testing webhook delivery.
    
    This class simulates an external webhook server for testing.
    It captures webhook deliveries for verification in tests.
    """
    
    def __init__(self):
        """Initialize a new mock webhook server."""
        self.deliveries = []
        self.response_code = 200
        self.response_body = '{"status": "received"}'
    
    def receive(self, payload: Dict[str, Any], headers: Dict[str, str]) -> Dict:
        """
        Receive a webhook delivery.
        
        Args:
            payload: Webhook event payload
            headers: HTTP request headers
            
        Returns:
            Dict with response status
        """
        self.deliveries.append({
            'payload': payload,
            'headers': headers,
            'received_at': datetime.utcnow().isoformat()
        })
        
        return {
            'status_code': self.response_code,
            'body': self.response_body
        }
    
    def set_response(self, status_code: int = 200, body: str = '{"status": "received"}'):
        """
        Set the response for future webhook deliveries.
        
        Args:
            status_code: HTTP status code to return
            body: Response body to return
        """
        self.response_code = status_code
        self.response_body = body
    
    def clear(self):
        """Clear all received deliveries."""
        self.deliveries = []
    
    def verify_delivery(self, event_type: str, count: int = 1) -> bool:
        """
        Verify that a specific event type was delivered.
        
        Args:
            event_type: Event type to check for
            count: Expected number of deliveries (default: 1)
            
        Returns:
            bool: True if expected deliveries were received
        """
        matching = [
            d for d in self.deliveries 
            if d['payload'].get('event_type') == event_type
        ]
        return len(matching) == count
    
    def verify_signature(self, index: int, secret: str) -> bool:
        """
        Verify the signature of a specific delivery.
        
        Args:
            index: Index of delivery to verify
            secret: Secret to verify with
            
        Returns:
            bool: True if signature is valid
        """
        if index >= len(self.deliveries):
            return False
            
        delivery = self.deliveries[index]
        payload_str = json.dumps(delivery['payload'])
        expected = generate_webhook_signature(payload_str, secret)
        actual = delivery['headers'].get('X-Webhook-Signature')
        
        return expected == actual
