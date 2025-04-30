"""
Webhook Service for the Cloud Infrastructure Platform.

This service centralizes the business logic for managing webhook subscriptions,
triggering webhook deliveries, and handling related tasks. It interacts with
webhook models and potentially other services like notification or audit logging.
"""

import logging
import secrets
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Union

from flask import current_app, g
from sqlalchemy.exc import SQLAlchemyError

from extensions import db, metrics
from models.communication.webhook import WebhookSubscription, WebhookDelivery
from api.webhooks import EventType, DeliveryStatus, EVENT_TYPES, generate_webhook_signature
# Assuming delivery logic might be moved here or called from here
from api.webhooks.delivery import deliver_webhook as trigger_delivery_process
from core.security import log_security_event # Assuming a security logging function exists

logger = logging.getLogger(__name__)

class WebhookService:
    """
    Provides methods for managing and interacting with webhooks.
    """

    @staticmethod
    def create_subscription(
        user_id: int,
        target_url: str,
        event_types: List[str],
        description: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        is_active: bool = True,
        max_retries: int = 3
    ) -> Tuple[Optional[WebhookSubscription], Optional[str], Optional[str]]:
        """
        Creates a new webhook subscription for a user.

        Args:
            user_id: The ID of the user creating the subscription.
            target_url: The URL to send webhook events to.
            event_types: A list of event types to subscribe to.
            description: An optional description for the subscription.
            headers: Optional custom headers to include with webhook requests.
            is_active: Whether the subscription should be active initially.
            max_retries: Maximum number of retries for failed deliveries.

        Returns:
            A tuple containing:
            - The created WebhookSubscription object (or None on failure).
            - The generated secret (only returned on successful creation).
            - An error message string (or None on success).
        """
        validation_error = WebhookService.validate_subscription_data(target_url, event_types)
        if validation_error:
            return None, None, validation_error

        secret = secrets.token_hex(32)
        subscription_id = str(uuid.uuid4())

        try:
            subscription = WebhookSubscription(
                id=subscription_id,
                user_id=user_id,
                target_url=target_url,
                event_types=event_types,
                description=description or "",
                headers=headers or {},
                secret=secret, # Store the hashed secret if implementing secure storage
                max_retries=max_retries,
                is_active=is_active,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.session.add(subscription)
            db.session.commit()
            logger.info(f"Webhook subscription created: {subscription.id} for user {user_id}")
            metrics.increment('webhook.subscription.created')
            log_security_event(
                event_type='webhook_subscription_created',
                description=f"Webhook subscription created: {subscription.id}",
                user_id=user_id,
                object_type='WebhookSubscription',
                object_id=subscription.id,
                severity='info'
            )
            # Return the subscription object and the raw secret
            return subscription, secret, None
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error creating webhook subscription for user {user_id}: {str(e)}")
            metrics.increment('webhook.subscription.db_error')
            return None, None, "Database error occurred while creating subscription."
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error creating webhook subscription for user {user_id}: {str(e)}")
            metrics.increment('webhook.subscription.error')
            return None, None, "An unexpected error occurred."

    @staticmethod
    def update_subscription(
        subscription_id: str,
        user_id: int, # Ensure user owns the subscription
        **kwargs: Any
    ) -> Tuple[Optional[WebhookSubscription], Optional[str]]:
        """
        Updates an existing webhook subscription.

        Args:
            subscription_id: The ID of the subscription to update.
            user_id: The ID of the user requesting the update.
            **kwargs: Fields to update (e.g., target_url, event_types, description, headers, is_active).

        Returns:
            A tuple containing the updated subscription object (or None) and an error message (or None).
        """
        try:
            subscription = WebhookSubscription.query.filter_by(id=subscription_id, user_id=user_id).first()
            if not subscription:
                return None, "Webhook subscription not found or access denied."

            # Validate potential changes
            if 'target_url' in kwargs or 'event_types' in kwargs:
                 validation_error = WebhookService.validate_subscription_data(
                     kwargs.get('target_url', subscription.target_url),
                     kwargs.get('event_types', subscription.event_types)
                 )
                 if validation_error:
                     return None, validation_error

            allowed_updates = ['target_url', 'event_types', 'description', 'headers', 'is_active', 'max_retries']
            update_applied = False
            for key, value in kwargs.items():
                if key in allowed_updates and hasattr(subscription, key):
                    setattr(subscription, key, value)
                    update_applied = True

            if update_applied:
                subscription.updated_at = datetime.utcnow()
                db.session.commit()
                logger.info(f"Webhook subscription updated: {subscription.id} by user {user_id}")
                metrics.increment('webhook.subscription.updated')
                log_security_event(
                    event_type='webhook_subscription_updated',
                    description=f"Webhook subscription updated: {subscription.id}",
                    user_id=user_id,
                    object_type='WebhookSubscription',
                    object_id=subscription.id,
                    details=json.dumps({k: v for k, v in kwargs.items() if k in allowed_updates}),
                    severity='info'
                )
            else:
                 logger.debug(f"No valid fields provided for webhook subscription update: {subscription_id}")
                 # Not necessarily an error, but no changes made.

            return subscription, None
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error updating webhook subscription {subscription_id}: {str(e)}")
            metrics.increment('webhook.subscription.db_error')
            return None, "Database error occurred while updating subscription."
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error updating webhook subscription {subscription_id}: {str(e)}")
            metrics.increment('webhook.subscription.error')
            return None, "An unexpected error occurred."

    @staticmethod
    def delete_subscription(subscription_id: str, user_id: int) -> Tuple[bool, Optional[str]]:
        """
        Deletes a webhook subscription.

        Args:
            subscription_id: The ID of the subscription to delete.
            user_id: The ID of the user requesting the deletion.

        Returns:
            A tuple containing success status (bool) and an error message (or None).
        """
        try:
            subscription = WebhookSubscription.query.filter_by(id=subscription_id, user_id=user_id).first()
            if not subscription:
                return False, "Webhook subscription not found or access denied."

            db.session.delete(subscription)
            db.session.commit()
            logger.info(f"Webhook subscription deleted: {subscription_id} by user {user_id}")
            metrics.increment('webhook.subscription.deleted')
            log_security_event(
                event_type='webhook_subscription_deleted',
                description=f"Webhook subscription deleted: {subscription_id}",
                user_id=user_id,
                object_type='WebhookSubscription',
                object_id=subscription_id,
                severity='warning' # Deletion is often a significant action
            )
            return True, None
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error deleting webhook subscription {subscription_id}: {str(e)}")
            metrics.increment('webhook.subscription.db_error')
            return False, "Database error occurred while deleting subscription."
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error deleting webhook subscription {subscription_id}: {str(e)}")
            metrics.increment('webhook.subscription.error')
            return False, "An unexpected error occurred."

    @staticmethod
    def get_subscription_by_id(subscription_id: str, user_id: int) -> Optional[WebhookSubscription]:
        """
        Retrieves a specific webhook subscription by its ID, ensuring user ownership.

        Args:
            subscription_id: The ID of the subscription.
            user_id: The ID of the user requesting the subscription.

        Returns:
            The WebhookSubscription object or None if not found or not owned by the user.
        """
        try:
            subscription = WebhookSubscription.query.filter_by(id=subscription_id, user_id=user_id).first()
            return subscription
        except Exception as e:
            logger.error(f"Error retrieving webhook subscription {subscription_id} for user {user_id}: {str(e)}")
            return None

    @staticmethod
    def list_subscriptions_for_user(user_id: int, page: int = 1, per_page: int = 20) -> Optional[Any]:
        """
        Lists webhook subscriptions for a specific user with pagination.

        Args:
            user_id: The ID of the user.
            page: Page number for pagination.
            per_page: Number of items per page.

        Returns:
            A Flask-SQLAlchemy Pagination object or None on error.
        """
        try:
            pagination = WebhookSubscription.query.filter_by(user_id=user_id)\
                .order_by(WebhookSubscription.created_at.desc())\
                .paginate(page=page, per_page=per_page, error_out=False)
            return pagination
        except Exception as e:
            logger.error(f"Error listing webhook subscriptions for user {user_id}: {str(e)}")
            return None

    @staticmethod
    def trigger_event(event_type: str, payload: Dict[str, Any]) -> int:
        """
        Triggers the delivery process for a specific event type to all relevant subscribers.

        Args:
            event_type: The type of event that occurred (e.g., 'resource.created').
            payload: The data associated with the event.

        Returns:
            The number of webhook deliveries initiated.
        """
        try:
            # This might call the function currently in api/webhooks/delivery.py
            # or contain the logic directly. Let's assume it calls the existing function for now.
            results = trigger_delivery_process(event_type=event_type, payload=payload)
            count = len(results)
            if count > 0:
                logger.info(f"Triggered {count} webhook deliveries for event: {event_type}")
                metrics.increment('webhook.delivery.triggered', count)
            return count
        except Exception as e:
            logger.error(f"Error triggering webhook event {event_type}: {str(e)}")
            metrics.increment('webhook.delivery.trigger_error')
            return 0

    @staticmethod
    def test_webhook_delivery(subscription_id: str, user_id: int, custom_payload: Optional[Dict[str, Any]] = None) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Sends a test event to a specific webhook subscription.

        Args:
            subscription_id: The ID of the subscription to test.
            user_id: The ID of the user initiating the test.
            custom_payload: Optional custom payload for the test event.

        Returns:
            A tuple containing:
            - Success status (bool).
            - An error message (or None).
            - Delivery result details (or None).
        """
        subscription = WebhookService.get_subscription_by_id(subscription_id, user_id)
        if not subscription:
            return False, "Webhook subscription not found or access denied.", None

        test_event_type = "test.event"
        payload = custom_payload or {
            "message": "This is a test webhook event from the Cloud Infrastructure Platform.",
            "timestamp": datetime.utcnow().isoformat(),
            "subscription_id": subscription_id
        }

        try:
            # Trigger delivery specifically for this subscription and event type
            results = trigger_delivery_process(
                event_type=test_event_type,
                payload=payload,
                subscription_id=subscription_id # Target only this subscription
            )

            if not results:
                metrics.increment('webhook.test_delivery.failed')
                return False, "Failed to initiate test webhook delivery.", None

            metrics.increment('webhook.test_delivery.success')
            logger.info(f"Test webhook sent for subscription {subscription_id} by user {user_id}")
            return True, None, results[0] # Return details of the first (only) delivery attempt initiated

        except Exception as e:
            logger.error(f"Error sending test webhook for subscription {subscription_id}: {str(e)}")
            metrics.increment('webhook.test_delivery.error')
            return False, "An unexpected error occurred during the test delivery.", None


    @staticmethod
    def list_deliveries_for_subscription(subscription_id: str, user_id: int, page: int = 1, per_page: int = 20, status: Optional[str] = None) -> Optional[Any]:
        """
        Lists delivery history for a specific webhook subscription with pagination.

        Args:
            subscription_id: The ID of the subscription.
            user_id: The ID of the user requesting the history.
            page: Page number for pagination.
            per_page: Number of items per page.
            status: Optional filter by delivery status.

        Returns:
            A Flask-SQLAlchemy Pagination object or None on error.
        """
        # First, verify ownership
        subscription = WebhookService.get_subscription_by_id(subscription_id, user_id)
        if not subscription:
            logger.warning(f"User {user_id} attempted to list deliveries for inaccessible subscription {subscription_id}")
            return None # Or raise an exception/return specific error

        try:
            query = WebhookDelivery.query.filter_by(subscription_id=subscription_id)
            if status and hasattr(DeliveryStatus, status.upper()):
                 query = query.filter_by(status=getattr(DeliveryStatus, status.upper()))

            pagination = query.order_by(WebhookDelivery.created_at.desc())\
                .paginate(page=page, per_page=per_page, error_out=False)
            return pagination
        except Exception as e:
            logger.error(f"Error listing deliveries for subscription {subscription_id}: {str(e)}")
            return None

    @staticmethod
    def validate_subscription_data(target_url: str, event_types: List[str]) -> Optional[str]:
        """
        Validates webhook subscription data (URL and event types).

        Args:
            target_url: The target URL.
            event_types: List of event types.

        Returns:
            Error message string if validation fails, None otherwise.
        """
        if not target_url.startswith(('http://', 'https://')):
            # Add more robust URL validation if needed (e.g., using libraries like `validators`)
            # Also consider disallowing localhost or internal IPs depending on security policy
            return "Target URL must start with http:// or https://"

        if not isinstance(event_types, list) or not event_types:
            return "Event types must be provided as a non-empty list."

        # Check against defined event types
        valid_events = set(EVENT_TYPES)
        # Allow 'test.event' specifically for testing purposes if desired
        valid_events.add('test.event')

        for event in event_types:
            if not isinstance(event, str):
                return f"Invalid event type format: {event}. Must be a string."
            if event not in valid_events:
                return f"Unsupported event type: {event}."

        return None


# Define what is exported when using 'from services import *'
__all__ = [
    'WebhookService'
]
