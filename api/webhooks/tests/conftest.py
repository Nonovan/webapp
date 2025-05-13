"""
Test fixtures for webhook tests.

This module provides common fixtures used across webhook tests.
"""

import pytest
import uuid
import time
from datetime import datetime, timedelta
from unittest.mock import patch
from flask import session

from flask import Flask
from api.webhooks import EventType, DeliveryStatus
from api.webhooks.testing import MockWebhookServer
from models.communication.webhook import WebhookSubscription, WebhookDelivery
from api.webhooks.tests.webhook_test_constants import (
    TEST_WEBHOOK_URL,
    TEST_WEBHOOK_SECRET,
    TEST_EVENT_TYPES
)
from api.webhooks.tests import (
    setup_test_subscription,
    setup_circuit_breaker_test_scenario,
    setup_test_delivery
)

# Authentication utility functions
def login_user(client, user):
    """
    Login a user for testing purposes.

    This function simulates a user login by adding the user ID to the session
    and performing any necessary authentication steps.

    Args:
        client: Flask test client
        user: User object to log in

    Returns:
        Response object from the login request
    """
    with client.session_transaction() as sess:
        sess['user_id'] = user.id
        sess['authenticated'] = True
        sess['auth_method'] = 'password'
        sess['login_time'] = datetime.utcnow().isoformat()

    return client.get('/')  # Just a request to ensure session is applied

def logout_user(client):
    """
    Logout a user for testing purposes.

    This function simulates a user logout by clearing the session
    and performing any necessary authentication cleanup.

    Args:
        client: Flask test client

    Returns:
        Response object from the logout request
    """
    with client.session_transaction() as sess:
        sess.clear()

    return client.get('/')  # Just a request to ensure session is cleared

@pytest.fixture
def auth_client(client, test_user):
    """
    Create a pre-authenticated client for testing endpoints that require login.

    This fixture provides a logged-in client to simplify testing protected routes.

    Args:
        client: Flask test client
        test_user: User fixture to authenticate

    Returns:
        Authenticated Flask test client
    """
    login_user(client, test_user)
    yield client
    logout_user(client)

@pytest.fixture
def admin_auth_client(client, test_admin_user):
    """
    Create a pre-authenticated client with admin privileges.

    This fixture provides a logged-in client with admin permissions
    for testing admin-only routes.

    Args:
        client: Flask test client
        test_admin_user: Admin user fixture to authenticate

    Returns:
        Admin-authenticated Flask test client
    """
    login_user(client, test_admin_user)
    yield client
    logout_user(client)

@pytest.fixture
def csrf_token(auth_client):
    """
    Generate a valid CSRF token for form submissions.

    Returns:
        Valid CSRF token
    """
    response = auth_client.get('/api/csrf-token')
    data = response.get_json()
    return data['csrf_token']

@pytest.fixture
def webhook_subscription(db, test_user):
    """Create a test webhook subscription"""
    subscription = WebhookSubscription(
        id=str(uuid.uuid4()),
        user_id=test_user.id,
        target_url="https://example.com/webhook-receiver",
        event_types=[EventType.RESOURCE_CREATED, EventType.ALERT_TRIGGERED],
        description="Test webhook subscription",
        headers={"X-Test-Header": "test-value"},
        secret="test-webhook-secret",
        max_retries=3,
        is_active=True,
        failure_threshold=5,
        reset_timeout=60,
        success_threshold=2
    )

    db.session.add(subscription)
    db.session.commit()

    yield subscription

    # Clean up
    db.session.delete(subscription)
    db.session.commit()

@pytest.fixture
def webhook_delivery(db, webhook_subscription):
    """Create a test webhook delivery"""
    delivery = WebhookDelivery(
        subscription_id=webhook_subscription.id,
        event_type=EventType.RESOURCE_CREATED,
        payload={
            "event_type": EventType.RESOURCE_CREATED,
            "timestamp": datetime.utcnow().isoformat(),
            "data": {"resource_id": 123, "name": "Test Resource"}
        },
        status=DeliveryStatus.DELIVERED,
        attempts=1,
        response_code=200,
        response_body='{"status": "received"}',
        duration_ms=125,
        created_at=datetime.utcnow()
    )

    db.session.add(delivery)
    db.session.commit()

    yield delivery

    # Clean up
    db.session.delete(delivery)
    db.session.commit()

@pytest.fixture
def mock_webhook_server():
    """Create a mock webhook server"""
    server = MockWebhookServer(secret=TEST_WEBHOOK_SECRET)
    yield server

@pytest.fixture
def failed_webhook_delivery(db, webhook_subscription):
    """Create a failed webhook delivery"""
    delivery = WebhookDelivery(
        subscription_id=webhook_subscription.id,
        event_type=EventType.RESOURCE_CREATED,
        payload={
            "event_type": EventType.RESOURCE_CREATED,
            "timestamp": datetime.utcnow().isoformat(),
            "data": {"resource_id": 123, "name": "Test Resource"}
        },
        status=DeliveryStatus.FAILED,
        attempts=3,
        response_code=500,
        response_body='{"error": "Server error"}',
        error_message="Failed after 3 attempts",
        created_at=datetime.utcnow()
    )

    db.session.add(delivery)
    db.session.commit()

    yield delivery

    # Clean up
    db.session.delete(delivery)
    db.session.commit()

@pytest.fixture
def request_with_auth_headers(test_user):
    """
    Create standard authentication headers for API requests.

    This is useful for testing API endpoints that use header-based authentication.

    Args:
        test_user: User fixture to generate tokens for

    Returns:
        Dictionary with standard auth headers
    """
    return {
        'Authorization': f'Bearer test-token-{test_user.id}',
        'X-API-Key': f'api-key-{test_user.id}',
        'Content-Type': 'application/json'
    }

@pytest.fixture
def with_rate_limits_disabled():
    """
    Temporarily disable rate limits for testing.

    This fixture patches the rate limiter to allow tests to run
    without being affected by rate limiting.
    """
    with patch('api.webhooks.routes.rate_limit_exceeded', return_value=False):
        yield

@pytest.fixture
def webhook_api_client(client, test_user, request_with_auth_headers):
    """
    Create a client with webhook API authentication headers.

    This combines a client with the necessary auth headers for webhook API calls.

    Returns:
        Client with API authentication headers
    """
    def _make_request(method, endpoint, json_data=None):
        """Helper function to make authenticated requests"""
        if method.lower() == 'get':
            return client.get(endpoint, headers=request_with_auth_headers)
        elif method.lower() == 'post':
            return client.post(endpoint, json=json_data, headers=request_with_auth_headers)
        elif method.lower() == 'put':
            return client.put(endpoint, json=json_data, headers=request_with_auth_headers)
        elif method.lower() == 'delete':
            return client.delete(endpoint, headers=request_with_auth_headers)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

    # Login the user through the session as well, for endpoints that use session auth
    login_user(client, test_user)

    # Add the request helper to the client object
    client.api_request = _make_request

    yield client

    # Clean up
    logout_user(client)

@pytest.fixture
def open_circuit_subscription(app, db, test_user):
    """Create a webhook subscription with an open circuit breaker"""
    subscription, mock_server = setup_circuit_breaker_test_scenario(
        app=app,
        db_session=db,
        user_id=test_user.id,
        state='open',
        failure_count=5,
        failure_threshold=5,
        reset_timeout=60,
        time_since_failure=10  # Failed 10 seconds ago
    )

    yield subscription, mock_server

    # Clean up
    db.session.delete(subscription)
    db.session.commit()

@pytest.fixture
def half_open_circuit_subscription(app, db, test_user):
    """Create a webhook subscription with a half-open circuit breaker"""
    subscription, mock_server = setup_circuit_breaker_test_scenario(
        app=app,
        db_session=db,
        user_id=test_user.id,
        state='half-open',
        failure_count=5,
        failure_threshold=5,
        reset_timeout=60,
        time_since_failure=70  # Failed 70 seconds ago (beyond reset_timeout)
    )

    yield subscription, mock_server

    # Clean up
    db.session.delete(subscription)
    db.session.commit()

@pytest.fixture
def multiple_webhook_subscriptions(app, db, test_user, test_admin_user):
    """Create multiple webhook subscriptions for different users and event types"""
    # First user's subscription for resource events
    sub1 = setup_test_subscription(
        app=app,
        db_session=db,
        user_id=test_user.id,
        event_types=[EventType.RESOURCE_CREATED, EventType.RESOURCE_UPDATED]
    )

    # First user's subscription for alert events
    sub2 = setup_test_subscription(
        app=app,
        db_session=db,
        user_id=test_user.id,
        event_types=[EventType.ALERT_TRIGGERED, EventType.SECURITY_INCIDENT]
    )

    # Second user's subscription for all event types
    sub3 = setup_test_subscription(
        app=app,
        db_session=db,
        user_id=test_admin_user.id,
        event_types=TEST_EVENT_TYPES
    )

    yield [sub1, sub2, sub3]

    # Clean up
    for subscription in [sub1, sub2, sub3]:
        db.session.delete(subscription)
    db.session.commit()

@pytest.fixture
def webhook_with_deliveries(app, db, test_user):
    """Create a webhook subscription with multiple deliveries in various states"""
    # Create subscription
    subscription = setup_test_subscription(
        app=app,
        db_session=db,
        user_id=test_user.id
    )

    # Create deliveries in different states
    deliveries = []

    # Successful delivery
    deliveries.append(setup_test_delivery(
        app=app,
        db_session=db,
        subscription_id=subscription.id,
        status=DeliveryStatus.DELIVERED,
        response_code=200
    ))

    # Failed delivery
    deliveries.append(setup_test_delivery(
        app=app,
        db_session=db,
        subscription_id=subscription.id,
        status=DeliveryStatus.FAILED,
        response_code=500,
        attempts=3
    ))

    # Pending delivery
    deliveries.append(setup_test_delivery(
        app=app,
        db_session=db,
        subscription_id=subscription.id,
        status=DeliveryStatus.PENDING,
        response_code=None,
        attempts=0
    ))

    yield subscription, deliveries

    # Clean up
    for delivery in deliveries:
        db.session.delete(delivery)
    db.session.delete(subscription)
    db.session.commit()

@pytest.fixture
def mocked_timeouts():
    """
    Patch time-related functions to enable faster testing of timeouts

    This fixture mocks time.sleep to avoid waiting during tests
    """
    with patch('time.sleep') as mock_sleep:
        mock_sleep.return_value = None
        yield mock_sleep

@pytest.fixture
def failing_mock_server():
    """Create a mock webhook server configured to fail with 500 errors"""
    server = MockWebhookServer()
    server.set_response(500, '{"error": "Internal Server Error"}')
    yield server

@pytest.fixture
def flaky_mock_server():
    """Create a mock webhook server with intermittent failures"""
    server = MockWebhookServer()
    server.set_failure_sequence([200, 500, 200, 500, 200])
    yield server

@pytest.fixture
def slow_mock_server():
    """Create a mock webhook server with slow responses for timeout testing"""
    server = MockWebhookServer()
    server.set_response(200, '{"status": "delayed"}')
    server.set_response_delay(1.0)  # 1 second delay
    yield server
