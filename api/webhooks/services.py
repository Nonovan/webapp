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
            delivery_attempt.status = DeliveryStatus.DELIVERED
            delivery_attempt.completed_at = datetime.utcnow()
            metrics.histogram(
                'webhook_delivery_duration_milliseconds',
                'Webhook delivery duration in milliseconds',
                labels={'event_type': event_type}
            ).observe(duration_ms)
        else:
            delivery_attempt.status = DeliveryStatus.FAILED
            delivery_attempt.error_message = f"HTTP {response.status_code}: {response.text[:100]}"
            metrics.counter(
                'webhook_delivery_failures_total',
                'Total number of webhook delivery failures',
                labels={'event_type': event_type, 'status_code': str(response.status_code)}
            ).inc()
        
        db.session.commit()
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
            delivery_attempt.status = DeliveryStatus.DELIVERED
            delivery_attempt.completed_at = datetime.utcnow()
            metrics.histogram(
                'webhook_delivery_duration_milliseconds',
                'Webhook delivery duration in milliseconds',
                labels={'event_type': event_type}
            ).observe(duration_ms)
        else:
            delivery_attempt.status = DeliveryStatus.FAILED
            delivery_attempt.error_message = f"HTTP {response.status_code}: {response.text[:100]}"
            metrics.counter(
                'webhook_delivery_failures_total',
                'Total number of webhook delivery failures',
                labels={'event_type': event_type, 'status_code': str(response.status_code)}
            ).inc()
        
        db.session.commit()
