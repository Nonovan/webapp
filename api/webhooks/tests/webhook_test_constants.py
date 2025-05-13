"""
Webhook Test Constants

This module defines constants and configuration values used across the webhook test suite.
It centralizes test values to ensure consistency across all webhook-related tests.
"""

import uuid
from typing import Dict, List, Any
from datetime import datetime, timedelta

from api.webhooks import EventType

# Base test URLs
TEST_WEBHOOK_URL = "https://webhook-test.example.com/endpoint"
TEST_INVALID_URL = "not-a-valid-url"
TEST_LOCALHOST_URL = "http://localhost:8080/webhook"
TEST_INTERNAL_IP_URL = "http://192.168.1.1/webhook"
TEST_PUBLIC_URL = "https://api.example.com/webhooks"

# Test secrets
TEST_WEBHOOK_SECRET = "test-webhook-secret-a1b2c3d4e5f6"
TEST_INVALID_SECRET = "too-short"
TEST_ROTATED_SECRET = "rotated-webhook-secret-g7h8i9j0k1l2"

# Standard test event types
TEST_EVENT_TYPES = [EventType.RESOURCE_CREATED, EventType.ALERT_TRIGGERED]
TEST_EVENT_TYPE_SINGLE = EventType.RESOURCE_CREATED
TEST_INVALID_EVENT_TYPE = "not.a.valid.event"

# Test data for different event types
TEST_EVENT_PAYLOADS = {
    EventType.RESOURCE_CREATED: {
        "resource_id": "res-12345",
        "name": "Test Resource",
        "type": "vm",
        "status": "creating"
    },
    EventType.RESOURCE_UPDATED: {
        "resource_id": "res-12345",
        "name": "Test Resource",
        "type": "vm",
        "status": "running",
        "changes": ["size", "tags"]
    },
    EventType.ALERT_TRIGGERED: {
        "alert_id": "alert-67890",
        "severity": "critical",
        "resource_id": "res-12345",
        "message": "CPU usage exceeded 90%"
    },
    EventType.SECURITY_INCIDENT: {
        "incident_id": "sec-13579",
        "severity": "high",
        "type": "brute_force_attempt",
        "target": "login_endpoint",
        "source_ip": "198.51.100.1"
    }
}

# Test request headers
TEST_REQUEST_HEADERS = {
    "Content-Type": "application/json",
    "X-Request-ID": "test-req-" + str(uuid.uuid4()),
    "X-Test-Header": "test-header-value"
}

# Test webhook subscription parameters
TEST_SUBSCRIPTION_PARAMS = {
    "name": "Test Subscription",
    "description": "Subscription for testing webhook delivery",
    "headers": {"X-Custom-Header": "custom-value"},
    "max_retries": 3,
    "retry_interval": 60
}

# Circuit breaker test parameters
TEST_CIRCUIT_PARAMS = {
    "failure_threshold": 5,
    "reset_timeout": 60,
    "success_threshold": 2
}

# Failure sequence patterns for testing various scenarios
TEST_FAILURE_SEQUENCES = {
    "all_success": [200, 200, 200, 200, 200],
    "all_failure": [500, 500, 500, 500, 500],
    "intermittent": [200, 500, 200, 500, 200],
    "transient": [500, 500, 200, 200, 200],
    "degrading": [200, 200, 200, 500, 500],
    "circuit_trip": [500, 500, 500, 500, 500, 200],  # Should trip circuit before last request
    "timeout": [408, 408, 408, 408, 408],
    "rate_limited": [429, 429, 429, 429, 429],
    "auth_failure": [401, 401, 401, 401, 401],
    "client_errors": [400, 403, 404, 422, 429],
    "server_errors": [500, 502, 503, 504, 500]
}

# Test response bodies
TEST_RESPONSE_BODIES = {
    "success": '{"status": "received", "message": "Webhook delivery successful", "id": "delivery-123"}',
    "validation_error": '{"error": "Invalid payload format", "code": "VALIDATION_ERROR"}',
    "auth_error": '{"error": "Invalid signature", "code": "AUTHENTICATION_ERROR"}',
    "rate_limited": '{"error": "Rate limit exceeded", "code": "RATE_LIMITED", "retry_after": 60}',
    "server_error": '{"error": "Internal server error", "code": "SERVER_ERROR"}',
    "empty": ""
}

# Webhook delivery statuses for testing status transitions
TEST_DELIVERY_STATUSES = {
    "pending": "pending",
    "delivered": "delivered",
    "failed": "failed",
    "retrying": "retrying",
    "cancelled": "cancelled"
}

# Testing time constants
TEST_TIMES = {
    "now": datetime.utcnow(),
    "one_minute_ago": datetime.utcnow() - timedelta(minutes=1),
    "one_hour_ago": datetime.utcnow() - timedelta(hours=1),
    "one_day_ago": datetime.utcnow() - timedelta(days=1),
    "one_minute_later": datetime.utcnow() + timedelta(minutes=1),
    "circuit_reset_time": datetime.utcnow() + timedelta(minutes=5)
}

# Mock server configurations
TEST_MOCK_SERVER_CONFIGS = {
    "standard": {
        "url": TEST_WEBHOOK_URL,
        "response_code": 200,
        "response_body": TEST_RESPONSE_BODIES["success"],
        "response_delay": 0.0
    },
    "slow_server": {
        "url": TEST_WEBHOOK_URL,
        "response_code": 200,
        "response_body": TEST_RESPONSE_BODIES["success"],
        "response_delay": 2.0  # 2-second delay
    },
    "failing_server": {
        "url": TEST_WEBHOOK_URL,
        "response_code": 500,
        "response_body": TEST_RESPONSE_BODIES["server_error"],
        "response_delay": 0.0
    },
    "auth_failing_server": {
        "url": TEST_WEBHOOK_URL,
        "response_code": 401,
        "response_body": TEST_RESPONSE_BODIES["auth_error"],
        "response_delay": 0.0
    },
    "rate_limited_server": {
        "url": TEST_WEBHOOK_URL,
        "response_code": 429,
        "response_body": TEST_RESPONSE_BODIES["rate_limited"],
        "response_delay": 0.0
    }
}

# Test scenarios for circuit breaker state transitions
TEST_CIRCUIT_SCENARIOS = {
    "normal": {
        "state": "closed",
        "failure_count": 0,
        "time_since_failure": None
    },
    "at_risk": {
        "state": "closed",
        "failure_count": 3,  # A few failures but not enough to trip
        "time_since_failure": 30  # Seconds since last failure
    },
    "just_tripped": {
        "state": "open",
        "failure_count": 5,
        "time_since_failure": 10  # Recently tripped
    },
    "open_long_time": {
        "state": "open",
        "failure_count": 10,
        "time_since_failure": 300  # Open for a while
    },
    "ready_for_retry": {
        "state": "open",
        "failure_count": 5,
        "time_since_failure": 70  # Past retry timeout
    },
    "half_open_testing": {
        "state": "half-open",
        "failure_count": 5,
        "time_since_failure": 70,
        "half_open_successes": 1  # One success in half-open state
    }
}

# Request identifiers for correlation tracking
TEST_REQUEST_IDS = {
    "standard": f"test-req-{uuid.uuid4()}",
    "circuit_breaker": f"circuit-test-{uuid.uuid4()}",
    "security": f"security-test-{uuid.uuid4()}",
    "delivery": f"delivery-test-{uuid.uuid4()}",
}

# Internal references for test assertions
MAX_VERIFY_ATTEMPTS = 3  # Maximum attempts to check for asynchronous test results
RESPONSE_CODE_SUCCESS_MIN = 200
RESPONSE_CODE_SUCCESS_MAX = 299
ASSERTION_TIMEOUT = 5.0  # Maximum time to wait for async assertions

# Security testing constants
VALID_URL_PATTERNS = [
    "https://api.example.com/webhook",
    "https://webhook.customer-domain.com/endpoint",
    "https://example.com:443/webhook",
    "https://example.com:8080/webhook"
]

INVALID_URL_PATTERNS = [
    # Local/internal addresses
    "http://10.0.0.1/webhook",           # Class A private
    "http://172.16.0.5/webhook",         # Class B private
    "http://192.168.1.1/webhook",        # Class C private
    "http://127.0.0.1/webhook",          # Localhost
    "http://localhost/webhook",          # Localhost name
    "http://0.0.0.0/webhook",            # All interfaces
    "http://169.254.169.254/metadata",   # AWS metadata service
    "http://webhook.internal/webhook",   # Assumed internal DNS

    # Dangerous ports
    "http://example.com:22/webhook",     # SSH
    "http://example.com:23/webhook",     # Telnet
    "http://example.com:25/webhook",     # SMTP
    "http://example.com:3389/webhook"    # RDP
]

# Test subscription permissions
TEST_USER_PERMISSIONS = {
    "standard": ["webhook:read", "webhook:create", "webhook:update", "webhook:delete"],
    "readonly": ["webhook:read"],
    "admin": ["webhook:read", "webhook:create", "webhook:update", "webhook:delete", "webhook:admin"]
}

# API endpoint rate limits for testing
TEST_RATE_LIMITS = {
    "create": 30,
    "read": 60,
    "update": 30,
    "delete": 30,
    "test": 10,
}

# Circuit breaker health status values for testing
CIRCUIT_HEALTH_STATUSES = {
    "healthy": "healthy",
    "degraded": "degraded",
    "tripped": "tripped",
    "recovering": "recovering",
    "unknown": "unknown"
}

# Circuit breaker state values
CIRCUIT_STATES = {
    "closed": "closed",
    "open": "open",
    "half-open": "half-open"
}

# Exponential backoff parameters for retry testing
RETRY_BACKOFF_PARAMS = {
    "base_delay": 10,  # Base delay in seconds
    "max_delay": 300,  # Maximum delay in seconds
    "factor": 2,       # Multiplication factor for each retry
    "jitter": 0.1      # Random jitter factor (0.1 = 10%)
}

# MockWebhookServer test parameters
MOCK_SERVER_PARAMS = {
    "default_port": 8088,
    "default_host": "localhost",
    "default_url": "https://mock-webhook-server.example.com/webhook",
    "default_response_code": 200,
    "default_response_body": '{"status": "received"}',
    "default_headers": {"Content-Type": "application/json"},
    "default_delay": 0.0
}

# Test scenarios for verifying metric tracking
METRICS_TEST_SCENARIOS = {
    "delivery_success": {
        "metrics": ["webhook.delivery.success", "webhook.delivery.total"],
        "tags": ["status:delivered"]
    },
    "delivery_failure": {
        "metrics": ["webhook.delivery.failure", "webhook.delivery.total"],
        "tags": ["status:failed", "error:server_error"]
    },
    "circuit_open": {
        "metrics": ["webhook.circuit.open", "webhook.circuit.transition"],
        "tags": ["from:closed", "to:open"]
    },
    "circuit_half_open": {
        "metrics": ["webhook.circuit.half_open", "webhook.circuit.transition"],
        "tags": ["from:open", "to:half-open"]
    },
    "circuit_close": {
        "metrics": ["webhook.circuit.closed", "webhook.circuit.transition"],
        "tags": ["from:half-open", "to:closed"]
    }
}

# Common HTTP error scenarios with expected error codes and messages
HTTP_ERROR_SCENARIOS = {
    "connection_timeout": {
        "exception": "requests.exceptions.ConnectTimeout",
        "status_code": None,
        "error_message": "Connection timeout"
    },
    "dns_failure": {
        "exception": "requests.exceptions.ConnectionError",
        "status_code": None,
        "error_message": "Failed to resolve hostname"
    },
    "ssl_error": {
        "exception": "requests.exceptions.SSLError",
        "status_code": None,
        "error_message": "SSL verification failed"
    },
    "read_timeout": {
        "exception": "requests.exceptions.ReadTimeout",
        "status_code": None,
        "error_message": "Read timeout"
    },
    "bad_request": {
        "exception": None,
        "status_code": 400,
        "error_message": "Bad request format"
    },
    "unauthorized": {
        "exception": None,
        "status_code": 401,
        "error_message": "Unauthorized"
    },
    "forbidden": {
        "exception": None,
        "status_code": 403,
        "error_message": "Forbidden"
    },
    "not_found": {
        "exception": None,
        "status_code": 404,
        "error_message": "Resource not found"
    },
    "rate_limited": {
        "exception": None,
        "status_code": 429,
        "error_message": "Rate limit exceeded"
    },
    "server_error": {
        "exception": None,
        "status_code": 500,
        "error_message": "Internal server error"
    }
}

# Threshold values for circuit breaker test scenarios
CIRCUIT_BREAKER_THRESHOLDS = {
    "min_threshold": 2,     # Minimum acceptable threshold
    "default_threshold": 5, # Default threshold from config
    "high_threshold": 10,   # High threshold for less sensitive circuits
    "invalid_threshold": 0  # Invalid threshold that should be rejected
}

# Reset timeout values for circuit breaker test scenarios
CIRCUIT_BREAKER_TIMEOUTS = {
    "min_timeout": 10,       # Minimum acceptable timeout in seconds
    "default_timeout": 60,   # Default timeout from config
    "high_timeout": 300,     # High timeout for longer recovery periods
    "invalid_timeout": -10   # Invalid timeout that should be rejected
}

# Success threshold values for half-open state testing
CIRCUIT_SUCCESS_THRESHOLDS = {
    "min_threshold": 1,      # Minimum acceptable threshold
    "default_threshold": 2,  # Default threshold from config
    "high_threshold": 5,     # High threshold for more cautious recovery
    "invalid_threshold": 0   # Invalid threshold that should be rejected
}

# Export constants - Define what should be accessible when importing
__all__ = [
    "TEST_WEBHOOK_URL",
    "TEST_INVALID_URL",
    "TEST_WEBHOOK_SECRET",
    "TEST_EVENT_TYPES",
    "TEST_EVENT_TYPE_SINGLE",
    "TEST_EVENT_PAYLOADS",
    "TEST_REQUEST_HEADERS",
    "TEST_SUBSCRIPTION_PARAMS",
    "TEST_CIRCUIT_PARAMS",
    "TEST_FAILURE_SEQUENCES",
    "TEST_RESPONSE_BODIES",
    "TEST_DELIVERY_STATUSES",
    "TEST_TIMES",
    "TEST_MOCK_SERVER_CONFIGS",
    "TEST_CIRCUIT_SCENARIOS",
    "TEST_REQUEST_IDS",
    "VALID_URL_PATTERNS",
    "INVALID_URL_PATTERNS",
    "TEST_USER_PERMISSIONS",
    "TEST_RATE_LIMITS",
    "MAX_VERIFY_ATTEMPTS",
    "RESPONSE_CODE_SUCCESS_MIN",
    "RESPONSE_CODE_SUCCESS_MAX",
    "ASSERTION_TIMEOUT",
    "CIRCUIT_HEALTH_STATUSES",
    "CIRCUIT_STATES",
    "RETRY_BACKOFF_PARAMS",
    "MOCK_SERVER_PARAMS",
    "METRICS_TEST_SCENARIOS",
    "HTTP_ERROR_SCENARIOS",
    "CIRCUIT_BREAKER_THRESHOLDS",
    "CIRCUIT_BREAKER_TIMEOUTS",
    "CIRCUIT_SUCCESS_THRESHOLDS"
]
