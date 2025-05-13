"""
Initialization utilities for webhook tests.

This module provides setup and utility functions for webhook system tests.
It includes functions to create test environments, mock servers, and reset
the system state between tests.
"""

import pytest
import uuid
import time
from unittest.mock import patch, MagicMock
from flask import Flask, current_app
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union, Callable
import contextlib

from api.webhooks import EventType, DeliveryStatus
from api.webhooks.testing import MockWebhookServer
from api.webhooks.subscription import create_subscription
from models.communication.webhook import WebhookSubscription, WebhookDelivery
from extensions import db

# Importing test constants from __init__.py
from . import TEST_WEBHOOK_URL, TEST_WEBHOOK_SECRET, TEST_EVENT_TYPES

def setup_test_subscription(
    app: Flask,
    db_session,
    user_id: int,
    target_url: str = None,
    event_types: List[str] = None,
    secret: str = None,
    description: str = "Test webhook subscription",
    headers: Dict[str, str] = None,
    is_active: bool = True,
    failure_threshold: int = 5,
    reset_timeout: int = 60,
    success_threshold: int = 2
) -> WebhookSubscription:
    """
    Create a test webhook subscription in the database.

    Args:
        app: Flask application context
        db_session: Database session
        user_id: User ID to associate with the subscription
        target_url: URL to deliver webhooks to (defaults to TEST_WEBHOOK_URL)
        event_types: List of event types to subscribe to (defaults to TEST_EVENT_TYPES)
        secret: Webhook secret for signature generation (defaults to TEST_WEBHOOK_SECRET)
        description: Subscription description
        headers: Custom headers to include with webhook requests
        is_active: Whether the subscription is active
        failure_threshold: Number of failures before circuit trips
        reset_timeout: Seconds before auto-resetting circuit
        success_threshold: Successful requests needed in half-open state

    Returns:
        WebhookSubscription object
    """
    with app.app_context():
        subscription = WebhookSubscription(
            id=str(uuid.uuid4()),
            user_id=user_id,
            target_url=target_url or TEST_WEBHOOK_URL,
            event_types=event_types or TEST_EVENT_TYPES,
            description=description,
            headers=headers or {"X-Test-Header": "test-value"},
            secret=secret or TEST_WEBHOOK_SECRET,
            is_active=is_active,
            failure_threshold=failure_threshold,
            reset_timeout=reset_timeout,
            success_threshold=success_threshold,
            max_retries=3
        )

        db_session.add(subscription)
        db_session.commit()

        return subscription

def setup_test_delivery(
    app: Flask,
    db_session,
    subscription_id: str,
    event_type: str = None,
    status: str = DeliveryStatus.DELIVERED,
    response_code: int = 200,
    attempts: int = 1,
    request_id: str = None,
    payload: Dict[str, Any] = None
) -> WebhookDelivery:
    """
    Create a test webhook delivery in the database.

    Args:
        app: Flask application context
        db_session: Database session
        subscription_id: ID of subscription this delivery belongs to
        event_type: Type of event for this delivery
        status: Delivery status
        response_code: HTTP response code
        attempts: Number of delivery attempts
        request_id: Optional unique request ID
        payload: Custom payload data

    Returns:
        WebhookDelivery object
    """
    with app.app_context():
        # Create default payload if none provided
        if payload is None:
            payload = {
                "event_type": event_type or EventType.RESOURCE_CREATED,
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"resource_id": 123, "name": "Test Resource"}
            }

        delivery = WebhookDelivery(
            subscription_id=subscription_id,
            event_type=event_type or EventType.RESOURCE_CREATED,
            payload=payload,
            status=status,
            attempts=attempts,
            request_id=request_id or f"test-{uuid.uuid4()}",
            response_code=response_code,
            response_body='{"status": "received"}' if status == DeliveryStatus.DELIVERED else None,
            duration_ms=125 if status == DeliveryStatus.DELIVERED else None,
            created_at=datetime.utcnow()
        )

        db_session.add(delivery)
        db_session.commit()

        return delivery

def setup_circuit_breaker_test_scenario(
    app: Flask,
    db_session,
    user_id: int,
    state: str = 'closed',
    failure_count: int = 0,
    failure_threshold: int = 5,
    reset_timeout: int = 60,
    time_since_failure: Optional[int] = None,  # seconds
    success_threshold: int = 2
) -> Tuple[WebhookSubscription, MockWebhookServer]:
    """
    Create a test environment for circuit breaker testing.

    This function sets up a subscription with specific circuit breaker state
    and a corresponding mock server for testing webhook deliveries.

    Args:
        app: Flask application context
        db_session: Database session
        user_id: User ID to associate with the subscription
        state: Circuit breaker state ('closed', 'open', or 'half-open')
        failure_count: Current failure count
        failure_threshold: Number of failures before circuit trips
        reset_timeout: Seconds before auto-resetting circuit
        time_since_failure: Seconds since last failure (None for no failure)
        success_threshold: Number of successes needed in half-open state to close the circuit

    Returns:
        Tuple of (WebhookSubscription, MockWebhookServer)
    """
    with app.app_context():
        # Create mock server
        mock_server = MockWebhookServer(secret=TEST_WEBHOOK_SECRET)

        # Create subscription
        subscription = setup_test_subscription(
            app=app,
            db_session=db_session,
            user_id=user_id,
            target_url=mock_server.url,
            failure_threshold=failure_threshold,
            reset_timeout=reset_timeout,
            success_threshold=success_threshold
        )

        # Set up the circuit breaker state
        subscription.circuit_status = state
        subscription.failure_count = failure_count

        if state == 'open':
            subscription.circuit_tripped_at = datetime.utcnow()
            subscription.next_attempt_at = datetime.utcnow() + timedelta(seconds=reset_timeout)

        if failure_count > 0 or time_since_failure is not None:
            last_failure = datetime.utcnow()
            if time_since_failure is not None:
                last_failure = last_failure - timedelta(seconds=time_since_failure)
            subscription.last_failure_at = last_failure

        if state == 'half-open':
            subscription.half_open_successes = 0

        db_session.add(subscription)
        db_session.commit()

        # Configure mock server response based on state
        if state == 'open':
            # Configure to continue failing
            mock_server.set_response(500, '{"error": "Still failing"}')
        elif state == 'half-open':
            # Configure to succeed to allow closing the circuit
            mock_server.set_response(200, '{"status": "recovered"}')

        return subscription, mock_server

def simulate_webhook_failures(
    app: Flask,
    subscription: WebhookSubscription,
    mock_server: MockWebhookServer,
    num_failures: int
) -> List[WebhookDelivery]:
    """
    Simulate a series of webhook delivery failures.

    This function creates delivery records with failed status
    to simulate a failing webhook endpoint.

    Args:
        app: Flask application context
        subscription: WebhookSubscription to use
        mock_server: MockWebhookServer to record deliveries
        num_failures: Number of failures to simulate

    Returns:
        List of created WebhookDelivery objects
    """
    with app.app_context():
        mock_server.set_response(500, '{"error": "Server error"}')
        deliveries = []

        for i in range(num_failures):
            # Record a failure in the subscription
            subscription.record_failure()

            # Create a delivery record
            delivery = WebhookDelivery(
                subscription_id=subscription.id,
                event_type=EventType.RESOURCE_CREATED,
                payload={
                    "event_type": EventType.RESOURCE_CREATED,
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {"resource_id": 123, "attempt": i + 1}
                },
                status=DeliveryStatus.FAILED,
                attempts=1,
                request_id=f"test-failure-{i+1}-{uuid.uuid4()}",
                response_code=500,
                response_body='{"error": "Server error"}',
                error_message="Simulated server error",
                created_at=datetime.utcnow()
            )
            db.session.add(delivery)
            deliveries.append(delivery)

            # Add a small delay to ensure timestamps are different
            time.sleep(0.01)

        db.session.commit()
        return deliveries

def reset_test_state(app: Flask, db_session) -> None:
    """
    Reset test state by cleaning up test data.

    Args:
        app: Flask application context
        db_session: Database session
    """
    with app.app_context():
        # Delete all test webhook deliveries
        WebhookDelivery.query.delete()

        # Delete all test webhook subscriptions
        WebhookSubscription.query.delete()

        # Commit the changes
        db_session.commit()

def assert_circuit_state(subscription: WebhookSubscription, expected_state: str) -> None:
    """
    Assert that a subscription's circuit breaker is in the expected state.

    Args:
        subscription: WebhookSubscription to check
        expected_state: Expected circuit status ('closed', 'open', or 'half-open')

    Raises:
        AssertionError: If circuit state doesn't match expected state
    """
    assert subscription.circuit_status == expected_state, \
        f"Expected circuit state to be '{expected_state}', got '{subscription.circuit_status}'"

    # Additional state-specific assertions
    if expected_state == 'open':
        assert subscription.circuit_tripped_at is not None, "Missing circuit_tripped_at timestamp"
        assert subscription.next_attempt_at is not None, "Missing next_attempt_at timestamp"
    elif expected_state == 'closed':
        assert subscription.half_open_successes == 0, "half_open_successes should be 0 in closed state"

def patch_retry_task():
    """
    Return a patch decorator for the retry task to prevent background tasks during tests.

    Returns:
        patch decorator
    """
    return patch('api.webhooks.delivery.setup_retry_task')

def patch_circuit_maintenance():
    """
    Return a patch decorator for the circuit maintenance task to prevent background tasks during tests.

    Returns:
        patch decorator
    """
    return patch('api.webhooks.init.setup_circuit_maintenance')

def trigger_circuit_breaker_transition(
    app: Flask,
    subscription: WebhookSubscription,
    transition_to: str
) -> None:
    """
    Trigger a specific circuit breaker transition for testing.

    Args:
        app: Flask application context
        subscription: WebhookSubscription to modify
        transition_to: Target state ('open', 'half-open', or 'closed')
    """
    with app.app_context():
        if transition_to == 'open':
            # Force circuit to open state
            subscription.failure_count = subscription.failure_threshold
            subscription.circuit_status = 'open'
            subscription.circuit_tripped_at = datetime.utcnow()
            subscription.next_attempt_at = datetime.utcnow() + timedelta(seconds=subscription.reset_timeout)

        elif transition_to == 'half-open':
            # Force circuit to half-open state
            subscription.circuit_status = 'half-open'
            subscription.half_open_successes = 0

        elif transition_to == 'closed':
            # Force circuit to closed state
            subscription.circuit_status = 'closed'
            subscription.failure_count = 0
            subscription.half_open_successes = 0
            subscription.circuit_tripped_at = None
            subscription.next_attempt_at = None

        db.session.add(subscription)
        db.session.commit()

@contextlib.contextmanager
def wait_for_background_tasks(min_wait: float = 0.1, max_wait: float = 1.0):
    """
    Context manager that waits for background tasks to complete.

    This ensures that asynchronous webhook deliveries have time to process.

    Args:
        min_wait: Minimum time to wait in seconds
        max_wait: Maximum time to wait in seconds

    Returns:
        Context manager
    """
    try:
        yield
    finally:
        # Sleep to allow background tasks to complete
        time.sleep(min_wait)

def setup_multi_step_test(app: Flask, steps: List[Callable]) -> None:
    """
    Run a sequence of setup steps inside the application context.

    Useful for complex test scenarios that require multiple state changes.

    Args:
        app: Flask application context
        steps: List of callables to execute in order
    """
    with app.app_context():
        for step in steps:
            step()

def create_test_scenario_with_mock_responses(
    app: Flask,
    db_session,
    user_id: int,
    mock_server: MockWebhookServer = None,
    response_sequence: List[int] = None
) -> Tuple[WebhookSubscription, MockWebhookServer]:
    """
    Create a test scenario with preconfigured mock responses.

    Args:
        app: Flask application context
        db_session: Database session
        user_id: User ID for the subscription
        mock_server: Optional existing mock server to configure
        response_sequence: List of status codes to return in sequence

    Returns:
        Tuple of (WebhookSubscription, MockWebhookServer)
    """
    with app.app_context():
        # Create or use provided mock server
        if mock_server is None:
            mock_server = MockWebhookServer(secret=TEST_WEBHOOK_SECRET)

        # Configure mock server response sequence if provided
        if response_sequence:
            mock_server.set_failure_sequence(response_sequence)

        # Create subscription pointing to mock server
        subscription = setup_test_subscription(
            app=app,
            db_session=db_session,
            user_id=user_id,
            target_url=mock_server.url,
            secret=mock_server.secret
        )

        return subscription, mock_server

def setup_recovery_test_scenario(
    app: Flask,
    db_session,
    user_id: int,
    num_failures: int = 5,
    failure_threshold: int = 5,
    reset_timeout: int = 60
) -> Tuple[WebhookSubscription, MockWebhookServer]:
    """
    Set up a test scenario for recovery testing.

    Creates a subscription that has just enough failures to trigger circuit opening,
    then configures the mock server to recover on the next attempt.

    Args:
        app: Flask application context
        db_session: Database session
        user_id: User ID for the subscription
        num_failures: Number of failures to simulate
        failure_threshold: Threshold for circuit to open
        reset_timeout: Circuit reset timeout in seconds

    Returns:
        Tuple of (WebhookSubscription, MockWebhookServer)
    """
    with app.app_context():
        # Create mock server
        mock_server = MockWebhookServer(secret=TEST_WEBHOOK_SECRET)

        # Create subscription
        subscription = setup_test_subscription(
            app=app,
            db_session=db_session,
            user_id=user_id,
            target_url=mock_server.url,
            failure_threshold=failure_threshold,
            reset_timeout=reset_timeout
        )

        # Simulate failures up to threshold
        simulate_webhook_failures(app, subscription, mock_server, num_failures)

        # Now configure the mock server to start succeeding
        mock_server.set_response(200, '{"status": "recovered"}')

        return subscription, mock_server

def assert_delivery_metrics(deliveries: List[WebhookDelivery], expected_stats: Dict[str, int]) -> None:
    """
    Assert that delivery metrics match expected statistics.

    Args:
        deliveries: List of WebhookDelivery objects to check
        expected_stats: Dictionary of expected statistics
            (e.g., {'delivered': 2, 'failed': 1})

    Raises:
        AssertionError: If metrics don't match expectations
    """
    actual_stats = {}
    for delivery in deliveries:
        if delivery.status not in actual_stats:
            actual_stats[delivery.status] = 0
        actual_stats[delivery.status] += 1

    for status, count in expected_stats.items():
        assert status in actual_stats, f"Expected status '{status}' not found in deliveries"
        assert actual_stats[status] == count, \
            f"Expected {count} deliveries with status '{status}', got {actual_stats.get(status, 0)}"

def wait_for_condition(condition_func: Callable[[], bool], timeout: float = 2.0, interval: float = 0.1) -> bool:
    """
    Wait for a condition to become true within a timeout.

    Useful for testing asynchronous behavior like webhook deliveries.

    Args:
        condition_func: Function that returns True when condition is met
        timeout: Maximum time to wait in seconds
        interval: Time between checks in seconds

    Returns:
        bool: True if condition was met within timeout, False otherwise
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        if condition_func():
            return True
        time.sleep(interval)
    return False
