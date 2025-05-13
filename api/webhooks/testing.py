"""
Testing utilities for webhooks.

This module provides tools for testing webhook delivery and subscription
management without making actual HTTP requests.
"""

from typing import Dict, Any, List, Optional, Union, Callable
import json
import time
import threading
import uuid
from datetime import datetime, timezone

from models import WebhookSubscription, WebhookDelivery
from . import DeliveryStatus, generate_webhook_signature

class MockWebhookServer:
    """
    Mock webhook receiver for testing webhook delivery.

    This class simulates an external webhook server for testing.
    It captures webhook deliveries for verification in tests and supports
    configurable responses including circuit breaker testing scenarios.
    """

    def __init__(self, url: str = "https://mock-webhook-server.example.com/webhook", secret: Optional[str] = None):
        """
        Initialize a new mock webhook server.

        Args:
            url: The URL to use for this mock server
            secret: Optional webhook secret for signature validation
        """
        self.deliveries = []
        self.response_code = 200
        self.response_body = '{"status": "received"}'
        self.url = url
        self.secret = secret or str(uuid.uuid4())
        self.response_delay = 0.0  # seconds
        self._response_handler = None
        self._failure_sequence = []
        self._failure_index = 0

    def receive(self, payload: Dict[str, Any], headers: Dict[str, str]) -> Dict:
        """
        Receive a webhook delivery.

        Args:
            payload: Webhook event payload
            headers: HTTP request headers

        Returns:
            Dict with response status
        """
        delivery = {
            'payload': payload,
            'headers': headers,
            'received_at': datetime.now(timezone.utc).isoformat(),
            'request_id': headers.get('X-Request-ID') or headers.get('X-Webhook-ID') or str(uuid.uuid4())
        }

        self.deliveries.append(delivery)

        # Add artificial delay if configured
        if self.response_delay > 0:
            time.sleep(self.response_delay)

        # Use dynamic response handler if set
        if self._response_handler:
            return self._response_handler(payload, headers, delivery)

        # Use failure sequence if configured
        if self._failure_sequence:
            code = self._failure_sequence[self._failure_index]
            self._failure_index = (self._failure_index + 1) % len(self._failure_sequence)

            if code >= 400:
                return {
                    'status_code': code,
                    'body': json.dumps({"error": f"Simulated error {code}"})
                }

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

    def set_response_delay(self, delay_seconds: float):
        """
        Set a delay for all responses to simulate slow servers.

        Args:
            delay_seconds: Delay in seconds before responding
        """
        self.response_delay = max(0.0, delay_seconds)

    def set_response_handler(self, handler: Optional[Callable]):
        """
        Set a custom response handler function for dynamic responses.

        The handler receives (payload, headers, delivery) and should return
        a dict with 'status_code' and 'body'.

        Args:
            handler: Function to handle responses or None to reset
        """
        self._response_handler = handler

    def set_failure_sequence(self, status_codes: List[int]):
        """
        Configure a repeating sequence of status codes for testing retry logic.

        Example: [200, 500, 503, 200] will alternate between success and failures.

        Args:
            status_codes: List of status codes to cycle through
        """
        self._failure_sequence = status_codes
        self._failure_index = 0

    def simulate_circuit_breaker_scenario(self, num_failures: int = 5):
        """
        Configure server to simulate a circuit breaker scenario.

        This sets up a sequence that will fail enough times to typically
        trip a circuit breaker, then return to normal.

        Args:
            num_failures: Number of consecutive failures before recovery
        """
        # Create a sequence of errors followed by successes
        self.set_failure_sequence([500] * num_failures + [200])

    def clear(self):
        """Clear all received deliveries."""
        self.deliveries = []
        self._failure_index = 0

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

    def get_deliveries_for_event(self, event_type: str) -> List[Dict]:
        """
        Get all deliveries for a specific event type.

        Args:
            event_type: Event type to filter by

        Returns:
            List of delivery records
        """
        return [
            d for d in self.deliveries
            if d['payload'].get('event_type') == event_type
        ]

    def verify_signature(self, index: int, secret: Optional[str] = None) -> bool:
        """
        Verify the signature of a specific delivery.

        Args:
            index: Index of delivery to verify
            secret: Secret to verify with (defaults to server's secret)

        Returns:
            bool: True if signature is valid
        """
        if index >= len(self.deliveries):
            return False

        delivery = self.deliveries[index]
        payload_str = json.dumps(delivery['payload'])
        expected = generate_webhook_signature(payload_str, secret or self.secret)
        actual = delivery['headers'].get('X-Webhook-Signature')

        return expected == actual

    def get_delivery_count(self) -> int:
        """
        Get the total number of deliveries received.

        Returns:
            int: Number of deliveries
        """
        return len(self.deliveries)

    def assert_payload_matches(self, index: int, expected_data: Dict, path: str = 'data') -> bool:
        """
        Assert that a delivery's payload matches expected data.

        Args:
            index: Index of delivery to check
            expected_data: Expected data to match against
            path: JSON path within payload to check (default: 'data')

        Returns:
            bool: True if data matches

        Raises:
            AssertionError: If data doesn't match
        """
        if index >= len(self.deliveries):
            raise AssertionError(f"No delivery at index {index}, only {len(self.deliveries)} deliveries received")

        delivery = self.deliveries[index]
        payload = delivery['payload']

        # Navigate to the specified path
        actual_data = payload
        if path:
            for part in path.split('.'):
                if part in actual_data:
                    actual_data = actual_data[part]
                else:
                    raise AssertionError(f"Path '{path}' not found in payload: {json.dumps(payload)}")

        if actual_data != expected_data:
            raise AssertionError(
                f"Payload data doesn't match at path '{path}'.\n"
                f"Expected: {json.dumps(expected_data)}\n"
                f"Actual: {json.dumps(actual_data)}"
            )

        return True

    def start_capture_server(self, port: int = 8088) -> threading.Thread:
        """
        Start an actual HTTP server to capture webhooks for integration tests.

        This method starts a local HTTP server on the specified port for
        testing with real HTTP requests instead of mocked functions.

        Args:
            port: Port to listen on

        Returns:
            threading.Thread: Thread running the server (call join() to wait for it)

        Note: Requires Flask to be installed
        """
        try:
            from flask import Flask, request, jsonify
        except ImportError:
            raise ImportError("Flask is required for start_capture_server. Install with 'pip install flask'")

        app = Flask("MockWebhookServer")
        server_self = self

        @app.route('/', methods=['POST'])
        def handle_webhook():
            """Handle incoming webhooks and pass to the mock server logic."""
            payload = request.json
            headers = {k: v for k, v in request.headers.items()}

            # Process with existing logic
            response = server_self.receive(payload, headers)

            return jsonify(json.loads(response['body'])), response['status_code']

        def run_server():
            app.run(host='localhost', port=port)

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()

        # Give server time to start
        time.sleep(0.5)

        # Update URL to point to the local server
        self.url = f"http://localhost:{port}"

        return thread
