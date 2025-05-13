"""
Webhook service functions for webhook delivery and management.
"""

from typing import Dict, Any, List, Tuple, Optional, Union
from datetime import datetime, timedelta
import json
import time
import asyncio
import httpx
import uuid
from flask import current_app

from extensions import db, metrics
from api.webhooks.models import WebhookSubscription, WebhookDeliveryAttempt
from api.webhooks import EventType, DeliveryStatus, generate_webhook_signature

def validate_subscription_data(data: Dict[str, Any]) -> Optional[str]:
    """
    Validate webhook subscription data.

    Args:
        data: Dictionary containing subscription data

    Returns:
        Error message string if validation fails, None if valid
    """
    required_fields = ['name', 'url', 'event_types']
    for field in required_fields:
        if field not in data:
            return f"Missing required field: {field}"

    # Validate URL format
    url = data['url']
    if not url.startswith(('http://', 'https://')):
        return "URL must start with http:// or https://"

    # Validate event types
    if not isinstance(data['event_types'], list) or not data['event_types']:
        return "event_types must be a non-empty list"

    # Check if event types are valid
    valid_events = set(EventType.__dict__.values())
    for event in data['event_types']:
        if not isinstance(event, str):
            return f"Event type must be a string: {event}"
        if event not in valid_events and event != 'test':
            return f"Invalid event type: {event}"

    return None

def enqueue_webhook_event(event_type: str, payload: Dict[str, Any]) -> int:
    """
    Enqueue a webhook event for delivery to all subscribed endpoints.

    Args:
        event_type: Type of event
        payload: Event payload

    Returns:
        Number of webhooks triggered
    """
    try:
        # Find subscriptions for this event
        subscriptions = WebhookSubscription.find_by_event_type(event_type)

        # Track metrics
        metrics.counter(
            'webhook_events_total',
            'Total number of webhook events',
            labels={'event_type': event_type}
        ).inc()

        count = 0
        for subscription in subscriptions:
            # Skip if circuit is open (WebhookSubscription.find_by_event_type already filters these,
            # but we check again in case circuit status changed between query and processing)
            if subscription.is_circuit_open():
                metrics.counter(
                    'webhook_circuit_breaker_blocks_total',
                    'Total number of webhook deliveries blocked by circuit breaker',
                    labels={'subscription_id': str(subscription.id)}
                ).inc()
                continue

            # Create delivery attempt record
            delivery = WebhookDeliveryAttempt(
                subscription_id=subscription.id,
                event_type=event_type,
                payload=payload,
                status=DeliveryStatus.PENDING,
                request_id=str(uuid.uuid4())
            )
            db.session.add(delivery)
            count += 1

        if count > 0:
            db.session.commit()
            current_app.logger.info(f"Enqueued {count} webhook deliveries for event: {event_type}")

        return count
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error enqueueing webhook event: {e}")
        metrics.counter(
            'webhook_errors_total',
            'Total number of webhook errors',
            labels={'operation': 'enqueue'}
        ).inc()
        raise

def trigger_webhook(
    subscription: WebhookSubscription,
    event_type: str,
    payload: Dict[str, Any],
    is_test: bool = False
) -> Tuple[bool, Dict[str, Any]]:
    """
    Trigger a webhook delivery immediately.

    Args:
        subscription: Webhook subscription
        event_type: Event type
        payload: Event data
        is_test: Whether this is a test event

    Returns:
        Tuple of (success, result details)
    """
    # Check circuit breaker status unless this is a test event
    if not is_test and subscription.is_circuit_open():
        metrics.counter(
            'webhook_circuit_breaker_blocks_total',
            'Total number of webhook deliveries blocked by circuit breaker',
            labels={'subscription_id': str(subscription.id)}
        ).inc()
        return False, {
            "error": "Circuit breaker is open",
            "circuit_status": subscription.circuit_status,
            "next_attempt_at": subscription.next_attempt_at.isoformat() if subscription.next_attempt_at else None
        }

    # Add standard properties to payload
    enriched_payload = {
        'event_type': event_type,
        'timestamp': datetime.utcnow().isoformat(),
        'subscription_id': subscription.id,
        'test': is_test,
        'data': payload
    }

    # Serialize and sign payload
    payload_json = json.dumps(enriched_payload)
    signature = generate_webhook_signature(payload_json, subscription.secret)

    # Set up headers
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Cloud-Platform-Webhook-Service',
        'X-Webhook-Signature': signature,
        'X-Event-Type': event_type,
        'X-Webhook-ID': str(uuid.uuid4())
    }

    # Add custom headers from subscription
    if subscription.headers:
        headers.update(subscription.headers)

    start_time = time.time()

    try:
        # Create a delivery attempt record for tracking
        delivery_attempt = WebhookDeliveryAttempt(
            subscription_id=subscription.id,
            event_type=event_type,
            payload=enriched_payload,
            status=DeliveryStatus.PENDING,
            attempts=1,
            request_id=headers.get('X-Webhook-ID')
        )
        db.session.add(delivery_attempt)
        db.session.commit()

        # Send the webhook
        with httpx.Client(timeout=10.0) as client:
            response = client.post(
                subscription.url,
                headers=headers,
                json=enriched_payload
            )

        # Calculate request duration
        duration_ms = (time.time() - start_time) * 1000

        # Update delivery attempt record
        delivery_attempt.response_code = response.status_code
        delivery_attempt.response_body = response.text[:1000]  # Limit size
        delivery_attempt.request_duration = duration_ms
        delivery_attempt.updated_at = datetime.utcnow()

        # Consider success for 2xx status codes
        success = 200 <= response.status_code < 300

        if success:
            # Update circuit breaker state on success
            subscription.record_success()

            delivery_attempt.status = DeliveryStatus.DELIVERED
            delivery_attempt.completed_at = datetime.utcnow()
            metrics.histogram(
                'webhook_delivery_duration_milliseconds',
                'Webhook delivery duration in milliseconds',
                labels={'event_type': event_type}
            ).observe(duration_ms)

            # Track circuit breaker transitions
            if subscription.circuit_status == 'closed':
                metrics.counter(
                    'webhook_circuit_breaker_close_total',
                    'Total number of circuit breaker closes',
                    labels={'subscription_id': str(subscription.id)}
                ).inc()
        else:
            # Update circuit breaker state on failure
            subscription.record_failure()

            delivery_attempt.status = DeliveryStatus.FAILED
            delivery_attempt.error_message = f"HTTP {response.status_code}: {response.text[:100]}"
            metrics.counter(
                'webhook_delivery_failures_total',
                'Total number of webhook delivery failures',
                labels={'event_type': event_type, 'status_code': str(response.status_code)}
            ).inc()

            # Track circuit breaker trips
            if subscription.circuit_status == 'open':
                metrics.counter(
                    'webhook_circuit_breaker_trip_total',
                    'Total number of circuit breaker trips',
                    labels={'subscription_id': str(subscription.id)}
                ).inc()
                current_app.logger.warning(
                    f"Circuit breaker tripped for webhook subscription {subscription.id} to {subscription.url}"
                )

        db.session.commit()

        return success, {
            "delivery_id": delivery_attempt.id,
            "status_code": response.status_code,
            "success": success,
            "duration_ms": duration_ms,
            "circuit_status": subscription.circuit_status
        }
    except Exception as e:
        current_app.logger.error(f"Error triggering webhook {subscription.id}: {str(e)}")

        # Try to update delivery attempt if it was created
        try:
            if 'delivery_attempt' in locals() and delivery_attempt.id:
                delivery_attempt.status = DeliveryStatus.FAILED
                delivery_attempt.error_message = f"Exception: {str(e)[:500]}"
                delivery_attempt.updated_at = datetime.utcnow()

                # Update circuit breaker on failure
                subscription.record_failure()

                # Track circuit breaker trips
                if subscription.circuit_status == 'open':
                    metrics.counter(
                        'webhook_circuit_breaker_trip_total',
                        'Total number of circuit breaker trips',
                        labels={'subscription_id': str(subscription.id)}
                    ).inc()
                    current_app.logger.warning(
                        f"Circuit breaker tripped for webhook subscription {subscription.id} to {subscription.url}"
                    )

                db.session.commit()
        except Exception as inner_e:
            db.session.rollback()
            current_app.logger.error(f"Failed to update delivery attempt status: {str(inner_e)}")

        metrics.counter(
            'webhook_delivery_failures_total',
            'Total number of webhook delivery failures',
            labels={'event_type': event_type, 'status_code': 'exception'}
        ).inc()

        return False, {"error": str(e), "circuit_status": subscription.circuit_status}

def reset_circuit_breaker(subscription_id: str) -> Tuple[bool, Optional[str]]:
    """
    Manually reset a circuit breaker to closed state.

    Args:
        subscription_id: ID of the subscription to reset

    Returns:
        Tuple of (success, error_message)
    """
    try:
        subscription = WebhookSubscription.query.get(subscription_id)
        if not subscription:
            return False, "Subscription not found"

        # Reset failure count and circuit status
        subscription.failure_count = 0
        subscription.circuit_status = 'closed'
        subscription.circuit_tripped_at = None
        subscription.next_attempt_at = None

        db.session.commit()

        # Log and track metrics
        current_app.logger.info(f"Circuit breaker manually reset for subscription {subscription_id}")
        metrics.counter(
            'webhook_circuit_breaker_manual_reset_total',
            'Total number of manual circuit breaker resets',
            labels={'subscription_id': str(subscription_id)}
        ).inc()

        return True, None
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error resetting circuit breaker for subscription {subscription_id}: {e}")
        return False, str(e)

def get_circuit_breaker_stats(subscription_id: str) -> Dict[str, Any]:
    """
    Get circuit breaker statistics for a webhook subscription.

    Args:
        subscription_id: ID of the subscription

    Returns:
        Dictionary with circuit breaker statistics
    """
    try:
        subscription = WebhookSubscription.query.get(subscription_id)
        if not subscription:
            return {"error": "Subscription not found"}

        # Calculate time remaining if circuit is open
        time_remaining = None
        if subscription.circuit_status == 'open' and subscription.next_attempt_at:
            time_remaining = max(0, (subscription.next_attempt_at - datetime.utcnow()).total_seconds())

        # Get recent delivery statistics
        recent_deliveries = WebhookDeliveryAttempt.query.filter(
            WebhookDeliveryAttempt.subscription_id == subscription_id,
            WebhookDeliveryAttempt.created_at >= datetime.utcnow() - timedelta(hours=24)
        ).all()

        success_count = len([d for d in recent_deliveries if d.status == DeliveryStatus.DELIVERED])
        failure_count = len([d for d in recent_deliveries if d.status == DeliveryStatus.FAILED])
        pending_count = len([d for d in recent_deliveries if d.status == DeliveryStatus.PENDING])

        # Calculate success rate
        total_completed = success_count + failure_count
        success_rate = (success_count / total_completed) * 100 if total_completed > 0 else None

        return {
            "subscription_id": subscription_id,
            "circuit_status": subscription.circuit_status,
            "failure_count": subscription.failure_count,
            "failure_threshold": subscription.failure_threshold,
            "last_failure_at": subscription.last_failure_at.isoformat() if subscription.last_failure_at else None,
            "circuit_tripped_at": subscription.circuit_tripped_at.isoformat() if subscription.circuit_tripped_at else None,
            "next_attempt_at": subscription.next_attempt_at.isoformat() if subscription.next_attempt_at else None,
            "reset_timeout_seconds": subscription.reset_timeout,
            "time_remaining_seconds": time_remaining,
            "recent_delivery_stats": {
                "success_count": success_count,
                "failure_count": failure_count,
                "pending_count": pending_count,
                "success_rate_percent": success_rate,
                "period_hours": 24
            }
        }
    except Exception as e:
        current_app.logger.error(f"Error getting circuit breaker stats for subscription {subscription_id}: {e}")
        return {"error": str(e)}

def configure_circuit_breaker(
    subscription_id: str,
    failure_threshold: Optional[int] = None,
    reset_timeout: Optional[int] = None
) -> Tuple[bool, Optional[str]]:
    """
    Configure circuit breaker parameters for a webhook subscription.

    Args:
        subscription_id: ID of the subscription to configure
        failure_threshold: Number of failures before tripping circuit breaker
        reset_timeout: Time in seconds before trying again after circuit trips

    Returns:
        Tuple of (success, error_message)
    """
    try:
        subscription = WebhookSubscription.query.get(subscription_id)
        if not subscription:
            return False, "Subscription not found"

        # Update parameters if provided
        if failure_threshold is not None:
            if not (1 <= failure_threshold <= 20):
                return False, "failure_threshold must be between 1 and 20"
            subscription.failure_threshold = failure_threshold

        if reset_timeout is not None:
            if not (30 <= reset_timeout <= 86400):  # Between 30 seconds and 24 hours
                return False, "reset_timeout must be between 30 and 86400 seconds"
            subscription.reset_timeout = reset_timeout

        db.session.commit()

        # Log configuration change
        current_app.logger.info(
            f"Circuit breaker configured for subscription {subscription_id}: "
            f"threshold={subscription.failure_threshold}, "
            f"timeout={subscription.reset_timeout}s"
        )

        return True, None
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error configuring circuit breaker for subscription {subscription_id}: {e}")
        return False, str(e)
