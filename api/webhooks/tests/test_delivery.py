"""
Tests for webhook delivery functionality.

This module tests the delivery of webhooks, including retry mechanisms,
circuit breaker behavior, and delivery tracking.
"""

import json
import pytest
import time
from unittest.mock import patch, MagicMock, call

from api.webhooks import EventType, DeliveryStatus
from api.webhooks.delivery import deliver_webhook, _process_delivery, setup_retry_task
from api.webhooks.testing import MockWebhookServer
from api.webhooks.subscription import create_subscription
from models.communication.webhook import WebhookSubscription, WebhookDelivery
from api.webhooks.tests import (
    setup_test_subscription,
    setup_test_delivery,
    setup_circuit_breaker_test_scenario,
    assert_circuit_state,
    patch_retry_task
)
from api.webhooks.tests.webhook_test_constants import (
    TEST_WEBHOOK_URL,
    TEST_EVENT_PAYLOADS,
    TEST_FAILURE_SEQUENCES,
    TEST_CIRCUIT_SCENARIOS
)


class TestWebhookDelivery:
    """Tests for webhook delivery functionality."""

    @patch('api.webhooks.delivery.requests.post')
    def test_basic_webhook_delivery(self, mock_post, app, db, test_user):
        """Test basic webhook delivery functionality"""
        mock_post.return_value = MagicMock(
            status_code=200,
            text='{"status":"received"}',
            headers={}
        )

        with app.app_context():
            # Create a subscription
            subscription = setup_test_subscription(
                app=app,
                db_session=db,
                user_id=test_user.id
            )

            # Trigger webhook delivery
            event_type = EventType.RESOURCE_CREATED
            payload = {"id": "res-123", "name": "test-resource"}

            results = deliver_webhook(event_type, payload, subscription_id=subscription.id)

            # Verify results
            assert len(results) == 1
            assert results[0]["subscription_id"] == subscription.id
            assert results[0]["event_type"] == event_type
            assert results[0]["status"] == DeliveryStatus.PENDING

            # Let background task complete
            time.sleep(0.1)

            # Verify the request was made with correct data
            mock_post.assert_called_once()

            # Check the payload was formatted properly
            call_args = mock_post.call_args
            sent_payload = json.loads(call_args[1]['data'])
            assert sent_payload["event_type"] == event_type
            assert "timestamp" in sent_payload
            assert sent_payload["data"] == payload

            # Verify headers
            headers = call_args[1]['headers']
            assert headers["Content-Type"] == "application/json"
            assert "X-Webhook-Signature" in headers
            assert headers["X-Webhook-ID"] == subscription.id

            # Check delivery was recorded
            delivery = WebhookDelivery.query.filter_by(subscription_id=subscription.id).first()
            assert delivery is not None
            assert delivery.status == DeliveryStatus.DELIVERED
            assert delivery.response_code == 200

    @patch('api.webhooks.delivery.requests.post')
    def test_webhook_delivery_failure(self, mock_post, app, db, test_user):
        """Test webhook delivery failure handling"""
        mock_post.return_value = MagicMock(
            status_code=500,
            text='{"error":"server error"}',
            headers={}
        )

        with app.app_context():
            # Create a subscription with only 1 retry
            subscription = setup_test_subscription(
                app=app,
                db_session=db,
                user_id=test_user.id,
                max_retries=1
            )

            # Trigger webhook delivery
            event_type = EventType.RESOURCE_CREATED
            payload = {"id": "res-123", "name": "test-resource"}

            results = deliver_webhook(event_type, payload, subscription_id=subscription.id)

            # Let background task complete
            time.sleep(0.2)

            # Verify the request was attempted twice (initial + 1 retry)
            assert mock_post.call_count == 2

            # Check delivery was recorded with failed status
            delivery = WebhookDelivery.query.filter_by(subscription_id=subscription.id).first()
            assert delivery is not None
            assert delivery.status == DeliveryStatus.FAILED
            assert delivery.response_code == 500
            assert delivery.attempts == 2

            # Verify subscription failure count was incremented
            subscription = WebhookSubscription.query.get(subscription.id)
            assert subscription.failure_count == 2

    @patch('api.webhooks.delivery.requests.post')
    def test_circuit_breaker_opens_after_failures(self, mock_post, app, db, test_user):
        """Test that circuit breaker opens after multiple failures"""
        mock_post.return_value = MagicMock(
            status_code=500,
            text='{"error":"server error"}',
            headers={}
        )

        with app.app_context():
            # Create a subscription with low failure threshold
            subscription = setup_test_subscription(
                app=app,
                db_session=db,
                user_id=test_user.id,
                failure_threshold=3,
                max_retries=0  # No retries to make test faster
            )

            # Deliver three webhooks to trigger circuit breaker
            event_type = EventType.RESOURCE_CREATED
            payload = {"id": "res-123", "name": "test-resource"}

            for i in range(3):
                deliver_webhook(event_type, payload, subscription_id=subscription.id)
                time.sleep(0.1)  # Let background task complete

            # Verify circuit breaker opened
            subscription = WebhookSubscription.query.get(subscription.id)
            assert_circuit_state(subscription, 'open')
            assert subscription.circuit_tripped_at is not None
            assert subscription.next_attempt_at is not None

            # Attempt another delivery - should be blocked by circuit breaker
            mock_post.reset_mock()
            deliver_webhook(event_type, payload, subscription_id=subscription.id)
            time.sleep(0.1)

            # Verify no HTTP request was made
            mock_post.assert_not_called()

            # Check last delivery was marked as cancelled due to circuit breaker
            delivery = WebhookDelivery.query.order_by(WebhookDelivery.created_at.desc()).first()
            assert delivery.status == DeliveryStatus.CANCELED
            assert "Circuit breaker" in delivery.error_message

    def test_circuit_breaker_with_mock_server(self, app, db, test_user):
        """Test circuit breaker using MockWebhookServer"""
        with app.app_context():
            # Create mock server with failure sequence
            mock_server = MockWebhookServer(secret="test-secret")
            mock_server.set_failure_sequence([500, 500, 500, 200])

            # Create subscription pointing to mock server
            subscription = setup_test_subscription(
                app=app,
                db_session=db,
                user_id=test_user.id,
                target_url=mock_server.url,
                secret=mock_server.secret,
                failure_threshold=3,
                max_retries=0  # No retries to simplify test
            )

            # Deliver webhooks until circuit trips
            event_type = EventType.RESOURCE_CREATED
            payload = {"id": "res-123", "name": "test-resource"}

            for i in range(3):
                deliver_webhook(event_type, payload, subscription_id=subscription.id)
                time.sleep(0.1)

            # Verify circuit is now open
            subscription = WebhookSubscription.query.get(subscription.id)
            assert_circuit_state(subscription, 'open')

            # Try one more delivery which should be blocked
            deliver_webhook(event_type, payload, subscription_id=subscription.id)
            time.sleep(0.1)

            # Only 3 deliveries should have reached the mock server
            assert mock_server.get_delivery_count() == 3

    def test_circuit_half_open_state(self, app, db, test_user):
        """Test circuit breaker half-open state behavior"""
        with app.app_context():
            # Create a subscription in half-open state
            subscription, mock_server = setup_circuit_breaker_test_scenario(
                app=app,
                db_session=db,
                user_id=test_user.id,
                state='half-open',
                failure_count=5,
                success_threshold=2
            )

            # Configure server to succeed
            mock_server.set_response(200, '{"status":"success"}')

            # Deliver first webhook - should be allowed in half-open state
            event_type = EventType.RESOURCE_CREATED
            payload = {"id": "res-123", "name": "test-resource"}

            deliver_webhook(event_type, payload, subscription_id=subscription.id)
            time.sleep(0.1)

            # Verify delivery succeeded and half_open_successes was incremented
            subscription = WebhookSubscription.query.get(subscription.id)
            assert_circuit_state(subscription, 'half-open')
            assert subscription.half_open_successes == 1

            # Deliver second webhook - should close the circuit after success
            deliver_webhook(event_type, payload, subscription_id=subscription.id)
            time.sleep(0.1)

            # Verify circuit closed after second success
            subscription = WebhookSubscription.query.get(subscription.id)
            assert_circuit_state(subscription, 'closed')
            assert subscription.failure_count == 0

    def test_circuit_remains_open_on_half_open_failure(self, app, db, test_user):
        """Test circuit breaker remains open if half-open delivery fails"""
        with app.app_context():
            # Create a subscription in half-open state
            subscription, mock_server = setup_circuit_breaker_test_scenario(
                app=app,
                db_session=db,
                user_id=test_user.id,
                state='half-open',
                failure_count=5,
                success_threshold=2
            )

            # Configure server to fail
            mock_server.set_response(500, '{"error":"still failing"}')

            # Deliver webhook - should be allowed but will fail
            event_type = EventType.RESOURCE_CREATED
            payload = {"id": "res-123", "name": "test-resource"}

            deliver_webhook(event_type, payload, subscription_id=subscription.id)
            time.sleep(0.1)

            # Verify circuit returned to open state
            subscription = WebhookSubscription.query.get(subscription.id)
            assert_circuit_state(subscription, 'open')
            assert subscription.half_open_successes == 0

    @patch('api.webhooks.delivery._process_delivery')
    def test_retry_scheduled_task(self, mock_process, app, db, test_user):
        """Test webhook retry scheduled task functionality"""
        with app.app_context():
            # Create test subscription
            subscription = setup_test_subscription(
                app=app,
                db_session=db,
                user_id=test_user.id
            )

            # Create failed deliveries that need retry
            failed_delivery = setup_test_delivery(
                app=app,
                db_session=db,
                subscription_id=subscription.id,
                status=DeliveryStatus.FAILED,
                response_code=500,
                attempts=1
            )

            # Create pending delivery that's stalled
            pending_delivery = setup_test_delivery(
                app=app,
                db_session=db,
                subscription_id=subscription.id,
                status=DeliveryStatus.PENDING,
                response_code=None,
                attempts=1
            )

            # Set updated_at to be old enough for retry
            five_mins_ago = time.time() - 300
            pending_delivery.updated_at = five_mins_ago
            failed_delivery.updated_at = five_mins_ago
            db.session.commit()

            # Run retry task
            retry_task = setup_retry_task(app)
            retry_job = getattr(retry_task, 'scheduled_job', None)
            retry_job.func()  # Call the scheduled function directly

            # Verify _process_delivery was called for both deliveries
            assert mock_process.call_count == 2
            mock_process.assert_has_calls(
                [
                    call(pending_delivery.id, subscription.id, pending_delivery.payload),
                    call(failed_delivery.id, subscription.id, failed_delivery.payload)
                ],
                any_order=True
            )

    @patch_retry_task()
    @patch('api.webhooks.delivery.requests.post')
    def test_webhook_exponential_backoff(self, mock_post, mock_retry_task, app, db, test_user):
        """Test webhook delivery exponential backoff for retries"""
        responses = [
            MagicMock(status_code=500, text='{"error":"error1"}', headers={}),
            MagicMock(status_code=500, text='{"error":"error2"}', headers={}),
            MagicMock(status_code=200, text='{"status":"success"}', headers={})
        ]
        mock_post.side_effect = responses

        with app.app_context():
            # Create a subscription with 2 retries
            subscription = setup_test_subscription(
                app=app,
                db_session=db,
                user_id=test_user.id,
                max_retries=2
            )

            start_time = time.time()

            # Process a delivery directly (not in background thread)
            delivery = setup_test_delivery(
                app=app,
                db_session=db,
                subscription_id=subscription.id,
                status=DeliveryStatus.PENDING
            )

            _process_delivery(delivery.id, subscription.id, delivery.payload)

            end_time = time.time()
            duration = end_time - start_time

            # Verify all attempts were made
            assert mock_post.call_count == 3

            # Verify backoff delay - should be at least 10 seconds
            # First failure: immediate
            # Second failure: 10 second backoff (2^0 * 10)
            # Third attempt: after backoff
            assert duration >= 10

            # Check delivery succeeded after retries
            delivery = WebhookDelivery.query.get(delivery.id)
            assert delivery.status == DeliveryStatus.DELIVERED
            assert delivery.attempts == 3

    def test_delivery_with_circuit_breaker_opening_during_retries(self, app, db, test_user):
        """Test webhook delivery when circuit breaker opens during retry attempts"""
        with app.app_context():
            # Create mock server with failure sequence
            mock_server = MockWebhookServer()

            # Create subscription with threshold=2, so circuit will open during retries
            subscription = setup_test_subscription(
                app=app,
                db_session=db,
                user_id=test_user.id,
                target_url=mock_server.url,
                failure_threshold=2,
                max_retries=3
            )

            # Configure server to always fail
            mock_server.set_response(500, '{"error":"always failing"}')

            # Trigger webhook delivery
            event_type = EventType.RESOURCE_CREATED
            payload = {"id": "res-123", "name": "test-resource"}

            results = deliver_webhook(event_type, payload, subscription_id=subscription.id)
            time.sleep(0.2)  # Let background task complete

            # Verify circuit opened during delivery
            subscription = WebhookSubscription.query.get(subscription.id)
            assert_circuit_state(subscription, 'open')

            # Check delivery was aborted after circuit opened
            delivery = WebhookDelivery.query.get(results[0]["delivery_id"])
            assert "Circuit breaker opened" in delivery.error_message
            assert delivery.attempts < 4  # Should not do all attempts

    def test_delivery_filtering_by_subscription_id(self, app, db, test_user):
        """Test webhook delivery filtering by subscription_id"""
        with app.app_context():
            # Create two subscriptions
            sub1 = setup_test_subscription(
                app=app,
                db_session=db,
                user_id=test_user.id
            )

            sub2 = setup_test_subscription(
                app=app,
                db_session=db,
                user_id=test_user.id
            )

            # Patch the delivery process to avoid actual HTTP requests
            with patch('api.webhooks.delivery._process_delivery'):
                # Deliver webhook only to sub1
                results = deliver_webhook(
                    EventType.RESOURCE_CREATED,
                    {"id": "res-123"},
                    subscription_id=sub1.id
                )

                # Verify only one result for sub1
                assert len(results) == 1
                assert results[0]["subscription_id"] == sub1.id

                # Check database records
                deliveries = WebhookDelivery.query.all()
                assert len(deliveries) == 1
                assert deliveries[0].subscription_id == sub1.id

    def test_delivery_multiple_subscribers(self, app, db, test_user, test_admin_user):
        """Test webhook delivery to multiple subscribers for the same event"""
        with app.app_context():
            # Create two subscriptions for different users
            sub1 = setup_test_subscription(
                app=app,
                db_session=db,
                user_id=test_user.id,
                event_types=[EventType.RESOURCE_CREATED]
            )

            sub2 = setup_test_subscription(
                app=app,
                db_session=db,
                user_id=test_admin_user.id,
                event_types=[EventType.RESOURCE_CREATED, EventType.RESOURCE_UPDATED]
            )

            # Create a subscription for a different event type
            sub3 = setup_test_subscription(
                app=app,
                db_session=db,
                user_id=test_user.id,
                event_types=[EventType.ALERT_TRIGGERED]
            )

            # Patch the delivery process to avoid actual HTTP requests
            with patch('api.webhooks.delivery._process_delivery'):
                # Deliver resource.created webhook
                results = deliver_webhook(EventType.RESOURCE_CREATED, {"id": "res-123"})

                # Verify both relevant subscriptions got the event
                assert len(results) == 2
                sub_ids = [r["subscription_id"] for r in results]
                assert sub1.id in sub_ids
                assert sub2.id in sub_ids
                assert sub3.id not in sub_ids

    def test_delivery_with_circuit_breaker_already_open(self, app, db, test_user):
        """Test webhook delivery when circuit breaker is already open"""
        with app.app_context():
            # Create subscription with circuit already open
            subscription, _ = setup_circuit_breaker_test_scenario(
                app=app,
                db_session=db,
                user_id=test_user.id,
                state='open',
                failure_count=5
            )

            # Patch the delivery process to verify it's not called
            with patch('api.webhooks.delivery._process_delivery') as mock_process:
                # Try to deliver webhook
                results = deliver_webhook(
                    EventType.RESOURCE_CREATED,
                    {"id": "res-123"},
                    subscription_id=subscription.id
                )

                # Should be empty results - delivery blocked by circuit breaker
                assert len(results) == 0

                # Verify no attempt was made
                mock_process.assert_not_called()
