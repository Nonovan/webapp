"""
Tests for webhook subscription management.

This module tests creation, validation, and management of webhook subscriptions.
"""

import pytest
import uuid
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

from api.webhooks import EventType
from api.webhooks.subscription import (
    create_subscription,
    update_subscription_circuit_breaker,
    get_subscription_circuit_status,
    _validate_security_constraints,
    _get_circuit_health_status
)
from api.webhooks.tests import (
    setup_circuit_breaker_test_scenario,
    simulate_webhook_failures,
    assert_circuit_state,
    trigger_circuit_breaker_transition
)
from api.webhooks.tests.webhook_test_constants import (
    TEST_CIRCUIT_PARAMS,
    TEST_SUBSCRIPTION_PARAMS,
    INVALID_URL_PATTERNS
)
from models.communication.webhook import WebhookSubscription

class TestWebhookSubscription:

    def test_create_subscription_valid(self, app, db, test_user):
        """Test creating a valid webhook subscription"""
        with app.app_context():
            subscription = create_subscription(
                target_url="https://example.com/webhook",
                event_types=[EventType.RESOURCE_CREATED, EventType.ALERT_TRIGGERED],
                description="Test subscription",
                headers={"X-Custom-Header": "value"},
                user_id=test_user.id
            )

            assert subscription["id"] is not None
            assert "secret" in subscription
            assert len(subscription["secret"]) > 32  # Should be long enough to be secure

            # Verify it was saved to the database
            db_subscription = WebhookSubscription.query.get(subscription["id"])
            assert db_subscription is not None
            assert db_subscription.target_url == "https://example.com/webhook"
            assert db_subscription.user_id == test_user.id

    def test_create_subscription_invalid_url(self, app, db, test_user):
        """Test creating a subscription with invalid URL"""
        with app.app_context():
            with pytest.raises(ValueError) as excinfo:
                create_subscription(
                    target_url="not-a-url",
                    event_types=[EventType.RESOURCE_CREATED],
                    user_id=test_user.id
                )
            assert "URL" in str(excinfo.value)

    def test_create_subscription_invalid_events(self, app, db, test_user):
        """Test creating a subscription with invalid event types"""
        with app.app_context():
            with pytest.raises(ValueError) as excinfo:
                create_subscription(
                    target_url="https://example.com/webhook",
                    event_types=["not-a-valid-event"],
                    user_id=test_user.id
                )
            assert "event types" in str(excinfo.value).lower()

    @patch('api.webhooks.subscription.secrets.token_hex')
    def test_subscription_secret_generation(self, mock_token, app, db, test_user):
        """Test that subscription secrets are securely generated"""
        mock_token.return_value = "test-secure-secret"

        with app.app_context():
            subscription = create_subscription(
                target_url="https://example.com/webhook",
                event_types=[EventType.RESOURCE_CREATED],
                user_id=test_user.id
            )

            assert subscription["secret"] == "test-secure-secret"
            mock_token.assert_called_once_with(32)  # Should generate a 32-byte hex token

    def test_create_subscription_with_circuit_breaker_params(self, app, db, test_user):
        """Test creating a subscription with custom circuit breaker parameters"""
        with app.app_context():
            custom_failure_threshold = 10
            custom_reset_timeout = 600

            subscription = create_subscription(
                target_url="https://example.com/webhook",
                event_types=[EventType.RESOURCE_CREATED],
                user_id=test_user.id,
                failure_threshold=custom_failure_threshold,
                reset_timeout=custom_reset_timeout
            )

            # Verify the circuit breaker parameters were set correctly
            db_subscription = WebhookSubscription.query.get(subscription["id"])
            assert db_subscription.failure_threshold == custom_failure_threshold
            assert db_subscription.reset_timeout == custom_reset_timeout
            assert db_subscription.circuit_status == 'closed'
            assert db_subscription.failure_count == 0

    def test_subscription_circuit_breaker_defaults(self, app, db, test_user):
        """Test that circuit breaker settings have proper defaults"""
        with app.app_context():
            # First, configure app defaults to ensure they're picked up
            app.config['WEBHOOK_CIRCUIT_THRESHOLD'] = 7  # Non-standard value for testing
            app.config['WEBHOOK_CIRCUIT_TIMEOUT'] = 450  # Non-standard value for testing

            # Create without explicit circuit breaker params
            subscription = create_subscription(
                target_url="https://example.com/webhook",
                event_types=[EventType.RESOURCE_CREATED],
                user_id=test_user.id
            )

            # Verify default values were applied from app config
            db_subscription = WebhookSubscription.query.get(subscription["id"])
            assert db_subscription.failure_threshold == 7
            assert db_subscription.reset_timeout == 450

    def test_create_subscription_with_invalid_circuit_params(self, app, db, test_user):
        """Test creating a subscription with invalid circuit breaker parameters"""
        with app.app_context():
            # Test with threshold too low
            with pytest.raises(ValueError) as excinfo:
                create_subscription(
                    target_url="https://example.com/webhook",
                    event_types=[EventType.RESOURCE_CREATED],
                    user_id=test_user.id,
                    failure_threshold=0  # Invalid: must be >= 1
                )
            assert "failure_threshold" in str(excinfo.value)

            # Test with threshold too high
            with pytest.raises(ValueError) as excinfo:
                create_subscription(
                    target_url="https://example.com/webhook",
                    event_types=[EventType.RESOURCE_CREATED],
                    user_id=test_user.id,
                    failure_threshold=21  # Invalid: must be <= 20
                )
            assert "failure_threshold" in str(excinfo.value)

            # Test with reset timeout too short
            with pytest.raises(ValueError) as excinfo:
                create_subscription(
                    target_url="https://example.com/webhook",
                    event_types=[EventType.RESOURCE_CREATED],
                    user_id=test_user.id,
                    reset_timeout=29  # Invalid: must be >= 30
                )
            assert "reset_timeout" in str(excinfo.value)

            # Test with reset timeout too long
            with pytest.raises(ValueError) as excinfo:
                create_subscription(
                    target_url="https://example.com/webhook",
                    event_types=[EventType.RESOURCE_CREATED],
                    user_id=test_user.id,
                    reset_timeout=86401  # Invalid: must be <= 86400 (24 hours)
                )
            assert "reset_timeout" in str(excinfo.value)

    @patch('api.webhooks.subscription.log_security_event')
    def test_update_circuit_breaker_parameters(self, mock_log, app, db, test_user):
        """Test updating circuit breaker parameters"""
        with app.app_context():
            # Create subscription with default circuit breaker settings
            subscription = create_subscription(
                target_url="https://example.com/webhook",
                event_types=[EventType.RESOURCE_CREATED],
                user_id=test_user.id
            )

            # Update circuit breaker parameters
            new_threshold = 8
            new_timeout = 120
            success, error = update_subscription_circuit_breaker(
                subscription_id=subscription["id"],
                user_id=test_user.id,
                failure_threshold=new_threshold,
                reset_timeout=new_timeout
            )

            assert success is True
            assert error is None

            # Verify changes were saved
            db_subscription = WebhookSubscription.query.get(subscription["id"])
            assert db_subscription.failure_threshold == new_threshold
            assert db_subscription.reset_timeout == new_timeout

            # Verify security logging
            mock_log.assert_called_once()

    def test_update_circuit_breaker_invalid_params(self, app, db, test_user):
        """Test updating circuit breaker with invalid parameters"""
        with app.app_context():
            # Create subscription
            subscription = create_subscription(
                target_url="https://example.com/webhook",
                event_types=[EventType.RESOURCE_CREATED],
                user_id=test_user.id
            )

            # Try to update with invalid failure threshold
            success, error = update_subscription_circuit_breaker(
                subscription_id=subscription["id"],
                user_id=test_user.id,
                failure_threshold=-5
            )

            assert success is False
            assert "failure_threshold" in error

            # Try to update with invalid reset timeout
            success, error = update_subscription_circuit_breaker(
                subscription_id=subscription["id"],
                user_id=test_user.id,
                reset_timeout=100000  # > 24 hours
            )

            assert success is False
            assert "reset_timeout" in error

            # Try to update with invalid circuit status
            success, error = update_subscription_circuit_breaker(
                subscription_id=subscription["id"],
                user_id=test_user.id,
                circuit_status="invalid-state"
            )

            assert success is False
            assert "circuit_status" in error

    def test_circuit_breaker_state_transitions(self, app, db, test_user):
        """Test circuit breaker state transitions through update_subscription_circuit_breaker"""
        with app.app_context():
            # Create subscription
            subscription_data = create_subscription(
                target_url="https://example.com/webhook",
                event_types=[EventType.RESOURCE_CREATED],
                user_id=test_user.id
            )
            subscription_id = subscription_data["id"]

            # Transition to open state
            success, error = update_subscription_circuit_breaker(
                subscription_id=subscription_id,
                user_id=test_user.id,
                circuit_status="open"
            )

            assert success is True

            # Verify state changed and timestamps set
            subscription = WebhookSubscription.query.get(subscription_id)
            assert subscription.circuit_status == "open"
            assert subscription.circuit_tripped_at is not None
            assert subscription.next_attempt_at is not None

            # Transition to half-open state
            success, error = update_subscription_circuit_breaker(
                subscription_id=subscription_id,
                user_id=test_user.id,
                circuit_status="half-open"
            )

            assert success is True

            # Verify state changed
            subscription = WebhookSubscription.query.get(subscription_id)
            assert subscription.circuit_status == "half-open"
            assert subscription.half_open_successes == 0

            # Transition back to closed state
            success, error = update_subscription_circuit_breaker(
                subscription_id=subscription_id,
                user_id=test_user.id,
                circuit_status="closed"
            )

            assert success is True

            # Verify state changed and counters/timestamps reset
            subscription = WebhookSubscription.query.get(subscription_id)
            assert subscription.circuit_status == "closed"
            assert subscription.failure_count == 0
            assert subscription.circuit_tripped_at is None
            assert subscription.next_attempt_at is None

    def test_get_subscription_circuit_status(self, app, db, test_user):
        """Test retrieving circuit breaker status information"""
        with app.app_context():
            # Create a subscription and trigger circuit breaker
            subscription, mock_server = setup_circuit_breaker_test_scenario(
                app=app,
                db_session=db,
                user_id=test_user.id,
                state='open',
                failure_count=5,
                failure_threshold=5,
                reset_timeout=300,
                time_since_failure=60  # Failed 60 seconds ago
            )

            # Get circuit status
            status = get_subscription_circuit_status(
                subscription_id=subscription.id,
                user_id=test_user.id
            )

            # Verify status information
            assert status["circuit_status"] == "open"
            assert status["failure_count"] == 5
            assert status["failure_threshold"] == 5
            assert "time_remaining_seconds" in status
            assert status["time_remaining_seconds"] <= 240  # 300 - 60 seconds elapsed
            assert "last_failure_at" in status
            assert "circuit_tripped_at" in status
            assert "next_attempt_at" in status
            assert "health_status" in status

    def test_security_constraints_validation(self, app):
        """Test URL security constraints validation"""
        with app.app_context():
            # Test allowed URLs
            assert _validate_security_constraints("https://api.example.com/webhooks") is None
            assert _validate_security_constraints("https://webhook.customer-domain.com/endpoint") is None

            # Test localhost/internal URLs
            for url in INVALID_URL_PATTERNS:
                error = _validate_security_constraints(url)
                assert error is not None, f"Expected security violation for URL: {url}"

    def test_circuit_health_status_calculation(self, app, db, test_user):
        """Test circuit breaker health status calculation"""
        with app.app_context():
            # Test healthy state
            subscription, _ = setup_circuit_breaker_test_scenario(
                app=app,
                db_session=db,
                user_id=test_user.id,
                state='closed',
                failure_count=0
            )
            assert _get_circuit_health_status(subscription) == "healthy"

            # Test at-risk state
            subscription, _ = setup_circuit_breaker_test_scenario(
                app=app,
                db_session=db,
                user_id=test_user.id,
                state='closed',
                failure_count=3,  # Some failures but not enough to trip
                failure_threshold=5
            )
            assert _get_circuit_health_status(subscription) == "at_risk"

            # Test tripped state
            subscription, _ = setup_circuit_breaker_test_scenario(
                app=app,
                db_session=db,
                user_id=test_user.id,
                state='open',
                failure_count=5
            )
            assert _get_circuit_health_status(subscription) == "tripped"

            # Test recovering state
            subscription, _ = setup_circuit_breaker_test_scenario(
                app=app,
                db_session=db,
                user_id=test_user.id,
                state='half-open',
                failure_count=5
            )
            assert _get_circuit_health_status(subscription) == "recovering"

    def test_record_failure_triggers_circuit_breaker(self, app, db, test_user):
        """Test that record_failure() trips the circuit breaker when threshold is reached"""
        with app.app_context():
            # Create subscription with failure_threshold=3
            subscription, mock_server = setup_circuit_breaker_test_scenario(
                app=app,
                db_session=db,
                user_id=test_user.id,
                failure_threshold=3
            )
            assert subscription.circuit_status == 'closed'

            # Record 3 failures (should trip the circuit)
            for _ in range(3):
                subscription.record_failure()

            # Verify circuit has tripped
            assert_circuit_state(subscription, 'open')
            assert subscription.circuit_tripped_at is not None
            assert subscription.next_attempt_at is not None

    def test_record_success_in_closed_state(self, app, db, test_user):
        """Test that record_success() clears failure count in closed state"""
        with app.app_context():
            # Create subscription with some failures but not enough to trip
            subscription, mock_server = setup_circuit_breaker_test_scenario(
                app=app,
                db_session=db,
                user_id=test_user.id,
                state='closed',
                failure_count=2,
                failure_threshold=5
            )

            # Record a success
            subscription.record_success()

            # Verify failure count was reset
            assert subscription.failure_count == 0

    def test_record_success_in_half_open_state(self, app, db, test_user):
        """Test that record_success() in half-open state transitions to closed after threshold"""
        with app.app_context():
            # Create subscription in half-open state
            subscription, mock_server = setup_circuit_breaker_test_scenario(
                app=app,
                db_session=db,
                user_id=test_user.id,
                state='half-open',
                failure_count=5,
                failure_threshold=5,
                success_threshold=2  # Need 2 successes to close circuit
            )

            # Record first success
            subscription.record_success()

            # Circuit should still be half-open
            assert_circuit_state(subscription, 'half-open')
            assert subscription.half_open_successes == 1

            # Record second success
            subscription.record_success()

            # Circuit should now be closed
            assert_circuit_state(subscription, 'closed')
            assert subscription.failure_count == 0
            assert subscription.half_open_successes == 0
            assert subscription.circuit_tripped_at is None

    def test_manual_reset_circuit(self, app, db, test_user):
        """Test manually resetting the circuit breaker"""
        with app.app_context():
            # Create subscription in open state
            subscription, _ = setup_circuit_breaker_test_scenario(
                app=app,
                db_session=db,
                user_id=test_user.id,
                state='open',
                failure_count=5
            )

            # Reset circuit
            success = subscription.manual_reset_circuit()

            # Verify circuit was reset successfully
            assert success is True
            assert_circuit_state(subscription, 'closed')
            assert subscription.failure_count == 0

    def test_is_circuit_open_function(self, app, db, test_user):
        """Test the is_circuit_open helper function"""
        with app.app_context():
            # Test with closed circuit
            subscription, _ = setup_circuit_breaker_test_scenario(
                app=app,
                db_session=db,
                user_id=test_user.id,
                state='closed'
            )
            assert subscription.is_circuit_open() is False

            # Test with open circuit
            subscription, _ = setup_circuit_breaker_test_scenario(
                app=app,
                db_session=db,
                user_id=test_user.id,
                state='open'
            )
            assert subscription.is_circuit_open() is True

            # Test with half-open circuit
            subscription, _ = setup_circuit_breaker_test_scenario(
                app=app,
                db_session=db,
                user_id=test_user.id,
                state='half-open'
            )
            # Half-open should return False since we want to allow test requests
            assert subscription.is_circuit_open() is False
