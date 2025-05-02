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

def deliver_webhook(
    event_type: str,
    payload: Dict[str, Any],
    subscription_id: Optional[str] = None
) -> List[Dict]:
    """
    Deliver a webhook event to all matching subscriptions.

    Args:
        event_type: Type of event to deliver
        payload: Event payload data
        subscription_id: Optional specific subscription to deliver to

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

            # Prepare request with signature
            payload_str = json.dumps(payload)
            signature = generate_webhook_signature(payload_str, subscription.secret)

            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'Cloud-Platform-Webhook-Service/1.0',
                'X-Webhook-Signature': signature,
                'X-Webhook-ID': subscription.id,
                'X-Webhook-Event': payload.get('event_type', ''),
                **subscription.headers
            }

            # Delivery attempt logic with retries
            max_attempts = subscription.max_retries + 1  # +1 for initial attempt
            attempt = 0
            success = False

            while attempt < max_attempts and not success:
                attempt += 1

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
                    else:
                        # Failed delivery
                        delivery.response_code = response.status_code
                        delivery.response_body = response.text[:1000]
                        delivery.duration_ms = duration_ms
                        delivery.last_attempt_at = datetime.utcnow()

                        # Exponential backoff
                        if attempt < max_attempts:
                            backoff_seconds = min(2 ** (attempt - 1) * 10, 300)  # Max 5 minutes
                            time.sleep(backoff_seconds)

                except RequestException as e:
                    # Connection error
                    delivery.response_body = str(e)[:500]
                    delivery.last_attempt_at = datetime.utcnow()

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
                        "attempts": attempt
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
                if delivery:
                    delivery.status = DeliveryStatus.FAILED
                    delivery.response_body = f"Internal error: {str(e)[:500]}"
                    delivery.last_attempt_at = datetime.utcnow()
                    db.session.add(delivery)
                    db.session.commit()
            except Exception as inner_e:
                current_app.logger.error(f"Failed to update delivery status: {str(inner_e)}")
