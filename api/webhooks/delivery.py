"""
Webhook delivery processing for Cloud Infrastructure Platform.

This module handles the actual sending of webhook payloads to subscribers,
including retry logic and delivery status tracking.
"""

from typing import Dict, Any, List, Optional
import json
import time
from datetime import datetime, timedelta
import requests
from requests.exceptions import RequestException
import threading
from flask import current_app

from models import AuditLog, db, WebhookSubscription, WebhookDelivery
from . import DeliveryStatus, generate_webhook_signature
from extensions import metrics

def deliver_webhook(
    event_type: str,
    payload: Dict[str, Any],
    subscription_id: Optional[str] = None,
    filtered_subscribers: Optional[List[int]] = None
) -> List[Dict]:
    """
    Deliver a webhook event to all matching subscriptions.

    Args:
        event_type: Type of event to deliver
        payload: Event payload data
        subscription_id: Optional specific subscription to deliver to
        filtered_subscribers: Optional list of user IDs to filter subscriptions by

    Returns:
        List of delivery results with status information
    """
    # Query for matching subscriptions
    query = WebhookSubscription.query.filter_by(is_active=True)

    # Filter by specific subscription if provided
    if subscription_id:
        query = query.filter_by(id=subscription_id)
    else:
        # Otherwise, filter by event type
        query = query.filter(WebhookSubscription.event_types.contains([event_type]))

    # Apply circuit breaker filter - don't deliver to subscriptions with open circuits
    query = query.filter(db.or_(
        WebhookSubscription.circuit_status != 'open',
        WebhookSubscription.circuit_status == None
    ))

    # Apply user filter if specified
    if filtered_subscribers:
        query = query.filter(WebhookSubscription.user_id.in_(filtered_subscribers))

    subscriptions = query.all()
    results = []

    # Format the payload with standard fields
    formatted_payload = {
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat(),
        "data": payload
    }

    # Deliver to each subscription asynchronously
    for subscription in subscriptions:
        # Double-check circuit breaker status (in case it changed between query and processing)
        if hasattr(subscription, 'is_circuit_open') and subscription.is_circuit_open():
            current_app.logger.info(
                f"Skipping delivery for subscription {subscription.id} due to open circuit breaker"
            )
            if hasattr(metrics, 'increment'):
                metrics.increment('webhook.delivery.circuit_breaker.blocked')
            continue

        # Create a delivery record
        delivery = WebhookDelivery(
            subscription_id=subscription.id,
            event_type=event_type,
            payload=formatted_payload,
            status=DeliveryStatus.PENDING,
            created_at=datetime.utcnow()
        )

        db.session.add(delivery)
        db.session.commit()

        # Start delivery in background thread
        thread = threading.Thread(
            target=_process_delivery,
            args=(delivery.id, subscription.id, formatted_payload),
            daemon=True
        )
        thread.start()

        results.append({
            "delivery_id": delivery.id,
            "subscription_id": subscription.id,
            "event_type": event_type,
            "status": DeliveryStatus.PENDING
        })

    return results

def _process_delivery(delivery_id: int, subscription_id: str, payload: Dict[str, Any]) -> None:
    """
    Process webhook delivery with retries and status tracking.

    Args:
        delivery_id: ID of delivery record
        subscription_id: ID of webhook subscription
        payload: Formatted payload to deliver
    """
    with current_app.app_context():
        try:
            # Fetch delivery and subscription
            delivery = WebhookDelivery.query.get(delivery_id)
            subscription = WebhookSubscription.query.get(subscription_id)

            if not delivery or not subscription:
                current_app.logger.error(f"Delivery {delivery_id} or subscription {subscription_id} not found")
                return

            # Check circuit breaker before attempting delivery
            if hasattr(subscription, 'is_circuit_open') and subscription.is_circuit_open():
                current_app.logger.info(
                    f"Circuit breaker open for subscription {subscription.id}, skipping delivery"
                )
                delivery.status = DeliveryStatus.CANCELED
                delivery.error_message = "Delivery canceled: Circuit breaker open"
                db.session.add(delivery)
                db.session.commit()

                if hasattr(metrics, 'increment'):
                    metrics.increment('webhook.delivery.circuit_breaker.canceled')
                return

            # Prepare request with signature
            payload_str = json.dumps(payload)
            signature = generate_webhook_signature(payload_str, subscription.secret)

            # Request ID for tracing
            request_id = f"whk-{int(time.time())}-{delivery_id}"

            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'Cloud-Platform-Webhook-Service/1.0',
                'X-Webhook-Signature': signature,
                'X-Webhook-ID': subscription.id,
                'X-Request-ID': request_id,
                'X-Webhook-Event': payload.get('event_type', ''),
                **subscription.headers
            }

            # Delivery attempt logic with retries
            max_attempts = subscription.max_retries + 1  # +1 for initial attempt
            attempt = 0
            success = False

            while attempt < max_attempts and not success:
                attempt += 1

                # Check circuit breaker status before each attempt
                if attempt > 1 and hasattr(subscription, 'is_circuit_open') and subscription.is_circuit_open():
                    current_app.logger.info(
                        f"Circuit breaker opened during retries for subscription {subscription.id}"
                    )
                    delivery.error_message = "Delivery aborted: Circuit breaker opened"
                    break

                try:
                    # Update status to retrying if not first attempt
                    if attempt > 1:
                        delivery.status = DeliveryStatus.RETRYING
                        delivery.attempts = attempt
                        db.session.add(delivery)
                        db.session.commit()

                    # Make the request with timeout
                    start_time = time.time()
                    response = requests.post(
                        subscription.target_url,
                        data=payload_str,
                        headers=headers,
                        timeout=10  # 10 second timeout
                    )
                    duration_ms = int((time.time() - start_time) * 1000)

                    # Check for success (2xx status code)
                    if 200 <= response.status_code < 300:
                        success = True
                        delivery.status = DeliveryStatus.DELIVERED
                        delivery.response_code = response.status_code
                        delivery.response_body = response.text[:1000]  # Limit size
                        delivery.duration_ms = duration_ms
                        delivery.delivered_at = datetime.utcnow()

                        # Update circuit breaker state on success
                        if hasattr(subscription, 'record_success'):
                            subscription.record_success()
                            if hasattr(metrics, 'increment'):
                                metrics.increment('webhook.delivery.circuit_breaker.success')
                    else:
                        # Failed delivery
                        delivery.response_code = response.status_code
                        delivery.response_body = response.text[:1000]
                        delivery.duration_ms = duration_ms
                        delivery.last_attempt_at = datetime.utcnow()

                        # Update circuit breaker state on failure
                        if hasattr(subscription, 'record_failure'):
                            subscription.record_failure()
                            if hasattr(metrics, 'increment'):
                                metrics.increment('webhook.delivery.circuit_breaker.failure')

                            # Log if circuit breaker tripped
                            if subscription.circuit_status == 'open':
                                current_app.logger.warning(
                                    f"Circuit breaker tripped for subscription {subscription.id} "
                                    f"to {subscription.target_url}"
                                )
                                if hasattr(metrics, 'increment'):
                                    metrics.increment('webhook.delivery.circuit_breaker.tripped')

                        # Exponential backoff
                        if attempt < max_attempts:
                            backoff_seconds = min(2 ** (attempt - 1) * 10, 300)  # Max 5 minutes
                            time.sleep(backoff_seconds)

                except RequestException as e:
                    # Connection error
                    delivery.response_body = str(e)[:500]
                    delivery.last_attempt_at = datetime.utcnow()

                    # Update circuit breaker state on connection failure
                    if hasattr(subscription, 'record_failure'):
                        subscription.record_failure()
                        if hasattr(metrics, 'increment'):
                            metrics.increment('webhook.delivery.circuit_breaker.failure')

                        # Log if circuit breaker tripped
                        if subscription.circuit_status == 'open':
                            current_app.logger.warning(
                                f"Circuit breaker tripped for subscription {subscription.id} "
                                f"due to connection error: {str(e)}"
                            )
                            if hasattr(metrics, 'increment'):
                                metrics.increment('webhook.delivery.circuit_breaker.tripped')

                    if attempt < max_attempts:
                        backoff_seconds = min(2 ** (attempt - 1) * 10, 300)
                        time.sleep(backoff_seconds)

            # Final update after all attempts
            if not success:
                delivery.status = DeliveryStatus.FAILED

                # Log security event for webhook failure
                AuditLog.create(
                    event_type='webhook_delivery_failed',
                    description=f"Webhook delivery failed after {attempt} attempts",
                    user_id=subscription.user_id,
                    object_type='WebhookDelivery',
                    object_id=delivery.id,
                    details=json.dumps({
                        "subscription_id": subscription.id,
                        "event_type": payload.get('event_type', ''),
                        "target_url": subscription.target_url,
                        "attempts": attempt,
                        "circuit_status": getattr(subscription, 'circuit_status', None)
                    }),
                    severity=AuditLog.SEVERITY_WARNING
                )

            db.session.add(delivery)
            db.session.commit()

        except Exception as e:
            current_app.logger.error(f"Error processing webhook delivery {delivery_id}: {str(e)}")
            try:
                db.session.rollback()

                # Update delivery status to failed
                delivery = WebhookDelivery.query.get(delivery_id)
                subscription = WebhookSubscription.query.get(subscription_id)

                if delivery:
                    delivery.status = DeliveryStatus.FAILED
                    delivery.error_message = f"Internal error: {str(e)[:500]}"
                    delivery.last_attempt_at = datetime.utcnow()
                    db.session.add(delivery)

                # Update circuit breaker on internal errors
                if subscription and hasattr(subscription, 'record_failure'):
                    subscription.record_failure()
                    if hasattr(metrics, 'increment'):
                        metrics.increment('webhook.delivery.circuit_breaker.failure')

                    # Log if circuit breaker tripped
                    if subscription.circuit_status == 'open':
                        current_app.logger.warning(
                            f"Circuit breaker tripped for subscription {subscription.id} "
                            f"due to internal error: {str(e)}"
                        )
                        if hasattr(metrics, 'increment'):
                            metrics.increment('webhook.delivery.circuit_breaker.tripped')

                db.session.commit()
            except Exception as inner_e:
                current_app.logger.error(f"Failed to update delivery status: {str(inner_e)}")


def setup_retry_task(app) -> None:
    """
    Set up background task for retrying failed deliveries.

    Args:
        app: Flask application instance
    """
    # Only import if we need it (to avoid circular imports)
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger

    scheduler = BackgroundScheduler()

    # Add retry job that runs every minute
    @scheduler.scheduled_job(
        IntervalTrigger(minutes=1),
        id='webhook_retry_job',
        max_instances=1
    )
    def retry_failed_deliveries():
        """Retry failed webhook deliveries that still have retries available."""
        with app.app_context():
            try:
                # Find deliveries that should be retried
                one_hour_ago = datetime.utcnow() - timedelta(hours=1)

                # Get pending deliveries that haven't been updated in the last 5 minutes
                pending_deliveries = WebhookDelivery.query.filter(
                    WebhookDelivery.status == DeliveryStatus.PENDING,
                    WebhookDelivery.updated_at <= datetime.utcnow() - timedelta(minutes=5),
                    WebhookDelivery.created_at >= one_hour_ago
                ).limit(100).all()

                # Get failed deliveries with retries remaining
                failed_deliveries = WebhookDelivery.query.join(WebhookSubscription).filter(
                    WebhookDelivery.status == DeliveryStatus.FAILED,
                    WebhookDelivery.attempts < WebhookSubscription.max_retries,
                    WebhookDelivery.created_at >= one_hour_ago
                ).limit(100).all()

                # Process all deliveries that need retrying
                for delivery in pending_deliveries + failed_deliveries:
                    # Get subscription and check circuit breaker
                    subscription = WebhookSubscription.query.get(delivery.subscription_id)
                    if not subscription or not subscription.is_active:
                        continue

                    # Skip if circuit breaker is open
                    if hasattr(subscription, 'is_circuit_open') and subscription.is_circuit_open():
                        app.logger.info(
                            f"Skipping retry for delivery {delivery.id} due to open circuit breaker"
                        )
                        continue

                    # Re-deliver the webhook
                    thread = threading.Thread(
                        target=_process_delivery,
                        args=(delivery.id, subscription.id, delivery.payload),
                        daemon=True
                    )
                    thread.start()

                    if hasattr(metrics, 'increment'):
                        metrics.increment('webhook.delivery.retry')

                app.logger.info(f"Webhook retry job processed {len(pending_deliveries)} pending and "
                               f"{len(failed_deliveries)} failed deliveries")

            except Exception as e:
                app.logger.error(f"Error in webhook retry task: {str(e)}")

    # Start the scheduler
    scheduler.start()
    app.logger.info("Webhook retry scheduler started")
