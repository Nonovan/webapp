"""
Webhook Service for the Cloud Infrastructure Platform.

This service centralizes the business logic for managing webhook subscriptions,
triggering webhook deliveries, and handling related tasks. It interacts with
webhook models and potentially other services like notification or audit logging.
"""

import logging
import secrets
import uuid
import json
import time
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Tuple, Union, Set
from urllib.parse import urlparse

from flask import current_app, g, request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func, and_, or_

from extensions import db, metrics, cache
from models.communication.webhook import WebhookSubscription, WebhookDelivery, WebhookSubscriptionGroup
from api.webhooks import EventType, DeliveryStatus, EVENT_TYPES, EVENT_CATEGORIES, generate_webhook_signature
# Assuming delivery logic might be moved here or called from here
from api.webhooks.delivery import deliver_webhook as trigger_delivery_process
from core.security import log_security_event, validate_url # Assuming security functions exist
from services.notification_service import send_system_notification

logger = logging.getLogger(__name__)

# Rate limiting constants
DEFAULT_RATE_LIMIT_WINDOW = 60  # seconds
DEFAULT_RATE_LIMIT_MAX_CALLS = 100  # per window

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
        max_retries: int = 3,
        group_id: Optional[int] = None,
        rate_limit: Optional[Dict[str, int]] = None
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
            group_id: Optional ID of a subscription group to associate with.
            rate_limit: Optional dictionary with rate limiting settings (max_calls, window_seconds).

        Returns:
            A tuple containing:
            - The created WebhookSubscription object (or None on failure).
            - The generated secret (only returned on successful creation).
            - An error message string (or None on success).
        """
        validation_error = WebhookService.validate_subscription_data(target_url, event_types)
        if validation_error:
            return None, None, validation_error

        # Enhanced security validation
        security_error = WebhookService._validate_security_constraints(target_url)
        if security_error:
            metrics.increment('webhook.subscription.security_rejection')
            log_security_event(
                event_type='webhook_subscription_security_rejected',
                description=f"Webhook subscription rejected due to security constraints: {security_error}",
                user_id=user_id,
                severity='warning',
                details={'target_url': target_url, 'reason': security_error}
            )
            return None, None, f"Security constraint violation: {security_error}"

        secret = secrets.token_hex(32)
        subscription_id = str(uuid.uuid4())

        # Process rate limit settings
        rate_limit_settings = None
        if rate_limit:
            max_calls = rate_limit.get('max_calls', DEFAULT_RATE_LIMIT_MAX_CALLS)
            window_seconds = rate_limit.get('window_seconds', DEFAULT_RATE_LIMIT_WINDOW)
            rate_limit_settings = {
                'max_calls': max(1, min(max_calls, 1000)),  # Ensure between 1-1000
                'window_seconds': max(1, min(window_seconds, 3600))  # Ensure between 1-3600 seconds
            }

        try:
            subscription = WebhookSubscription(
                id=subscription_id,
                user_id=user_id,
                target_url=target_url,
                event_types=event_types,
                description=description or "",
                headers=headers or {},
                secret=secret,  # Store the hashed secret if implementing secure storage
                max_retries=max_retries,
                is_active=is_active,
                group_id=group_id,
                rate_limit=rate_limit_settings,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
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

            # Additional security check for target_url changes
            if 'target_url' in kwargs and kwargs['target_url'] != subscription.target_url:
                security_error = WebhookService._validate_security_constraints(kwargs['target_url'])
                if security_error:
                    metrics.increment('webhook.subscription.security_rejection')
                    return None, f"Security constraint violation: {security_error}"

            # Process rate limit settings if provided
            if 'rate_limit' in kwargs and kwargs['rate_limit']:
                rate_limit = kwargs['rate_limit']
                max_calls = rate_limit.get('max_calls', DEFAULT_RATE_LIMIT_MAX_CALLS)
                window_seconds = rate_limit.get('window_seconds', DEFAULT_RATE_LIMIT_WINDOW)
                kwargs['rate_limit'] = {
                    'max_calls': max(1, min(max_calls, 1000)),
                    'window_seconds': max(1, min(window_seconds, 3600))
                }

            allowed_updates = [
                'target_url', 'event_types', 'description', 'headers',
                'is_active', 'max_retries', 'group_id', 'rate_limit'
            ]
            update_applied = False
            for key, value in kwargs.items():
                if key in allowed_updates and hasattr(subscription, key):
                    setattr(subscription, key, value)
                    update_applied = True

            if update_applied:
                subscription.updated_at = datetime.now(timezone.utc)
                db.session.commit()
                logger.info(f"Webhook subscription updated: {subscription.id} by user {user_id}")
                metrics.increment('webhook.subscription.updated')

                # Clear any cached information related to this subscription
                cache_key = f"webhook:sub:{subscription_id}"
                if hasattr(current_app, 'cache'):
                    current_app.cache.delete(cache_key)

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

            # Keep track of stats for auditing
            target_url = subscription.target_url
            event_types = subscription.event_types

            # Clear any cached information for this subscription
            cache_key = f"webhook:sub:{subscription_id}"
            if hasattr(current_app, 'cache'):
                current_app.cache.delete(cache_key)

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
                severity='warning',  # Deletion is often a significant action
                details={'target_url': target_url, 'event_types': event_types}
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
            # First try getting from cache
            cache_key = f"webhook:sub:{subscription_id}"
            if hasattr(current_app, 'cache'):
                cached_sub = current_app.cache.get(cache_key)
                if cached_sub:
                    # Verify ownership before returning cached data
                    if cached_sub.user_id == user_id:
                        return cached_sub

            # Get from database and cache the result
            subscription = WebhookSubscription.query.filter_by(id=subscription_id, user_id=user_id).first()
            if subscription and hasattr(current_app, 'cache'):
                current_app.cache.set(cache_key, subscription, timeout=300)  # Cache for 5 minutes

            return subscription
        except Exception as e:
            logger.error(f"Error retrieving webhook subscription {subscription_id} for user {user_id}: {str(e)}")
            return None

    @staticmethod
    def list_subscriptions_for_user(user_id: int, page: int = 1, per_page: int = 20,
                                  group_id: Optional[int] = None,
                                  is_active: Optional[bool] = None,
                                  event_type: Optional[str] = None) -> Optional[Any]:
        """
        Lists webhook subscriptions for a specific user with pagination and filtering.

        Args:
            user_id: The ID of the user.
            page: Page number for pagination.
            per_page: Number of items per page.
            group_id: Optional filter by subscription group ID.
            is_active: Optional filter by active status.
            event_type: Optional filter by event type.

        Returns:
            A Flask-SQLAlchemy Pagination object or None on error.
        """
        try:
            query = WebhookSubscription.query.filter_by(user_id=user_id)

            # Apply filters if provided
            if group_id is not None:
                query = query.filter(WebhookSubscription.group_id == group_id)

            if is_active is not None:
                query = query.filter(WebhookSubscription.is_active == is_active)

            if event_type:
                # Filter for subscriptions that include this event type
                query = query.filter(WebhookSubscription.event_types.contains([event_type]))

            pagination = query.order_by(WebhookSubscription.created_at.desc())\
                .paginate(page=page, per_page=per_page, error_out=False)
            return pagination
        except Exception as e:
            logger.error(f"Error listing webhook subscriptions for user {user_id}: {str(e)}")
            return None

    @staticmethod
    def trigger_event(event_type: str, payload: Dict[str, Any],
                     user_id: Optional[int] = None,
                     tags: Optional[List[str]] = None) -> int:
        """
        Triggers the delivery process for a specific event type to all relevant subscribers.

        Args:
            event_type: The type of event that occurred (e.g., 'resource.created').
            payload: The data associated with the event.
            user_id: Optional user ID associated with the event.
            tags: Optional list of tags to include with the event.

        Returns:
            The number of webhook deliveries initiated.
        """
        try:
            # Enhance payload with metadata
            enriched_payload = payload.copy()

            # Add context information that might be useful to subscribers
            enriched_payload.setdefault('meta', {})
            enriched_payload['meta']['timestamp'] = datetime.now(timezone.utc).isoformat()
            enriched_payload['meta']['event_type'] = event_type

            if user_id is not None:
                enriched_payload['meta']['user_id'] = user_id

            if tags:
                enriched_payload['meta']['tags'] = tags

            # Generate unique event ID
            event_id = str(uuid.uuid4())
            enriched_payload['meta']['event_id'] = event_id

            # Track event for metrics
            category = WebhookService._get_event_category(event_type)
            metrics.increment(f'webhook.event.{category}')

            # This might call the function currently in api/webhooks/delivery.py
            # or contain the logic directly. We'll call the imported function.
            results = trigger_delivery_process(event_type=event_type, payload=enriched_payload)
            count = len(results)
            if count > 0:
                logger.info(f"Triggered {count} webhook deliveries for event: {event_type} (id: {event_id})")
                metrics.increment('webhook.delivery.triggered', count)

                # Record event in high-volume delivery log
                WebhookService._record_event_delivery(
                    event_type=event_type,
                    event_id=event_id,
                    success_count=count,
                    user_id=user_id
                )
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

        # Check if we're at the rate limit
        if WebhookService._is_rate_limited(subscription):
            metrics.increment('webhook.test_delivery.rate_limited')
            return False, "Rate limit exceeded for this webhook endpoint. Please try again later.", None

        test_event_type = "test.event"
        payload = custom_payload or {
            "message": "This is a test webhook event from the Cloud Infrastructure Platform.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "subscription_id": subscription_id
        }

        try:
            # Trigger delivery specifically for this subscription and event type
            results = trigger_delivery_process(
                event_type=test_event_type,
                payload=payload,
                subscription_id=subscription_id  # Target only this subscription
            )

            if not results:
                metrics.increment('webhook.test_delivery.failed')
                return False, "Failed to initiate test webhook delivery.", None

            metrics.increment('webhook.test_delivery.success')
            logger.info(f"Test webhook sent for subscription {subscription_id} by user {user_id}")

            # Track this test for rate limiting purposes
            WebhookService._record_delivery_attempt(subscription)

            return True, None, results[0]  # Return details of the first (only) delivery attempt initiated
        except Exception as e:
            logger.error(f"Error sending test webhook for subscription {subscription_id}: {str(e)}")
            metrics.increment('webhook.test_delivery.error')
            return False, "An unexpected error occurred during the test delivery.", None

    @staticmethod
    def list_deliveries_for_subscription(subscription_id: str, user_id: int, page: int = 1,
                                        per_page: int = 20, status: Optional[str] = None,
                                        start_time: Optional[datetime] = None,
                                        end_time: Optional[datetime] = None) -> Optional[Any]:
        """
        Lists delivery history for a specific webhook subscription with pagination.

        Args:
            subscription_id: The ID of the subscription.
            user_id: The ID of the user requesting the history.
            page: Page number for pagination.
            per_page: Number of items per page.
            status: Optional filter by delivery status.
            start_time: Optional filter for deliveries after this time.
            end_time: Optional filter for deliveries before this time.

        Returns:
            A Flask-SQLAlchemy Pagination object or None on error.
        """
        # First, verify ownership
        subscription = WebhookService.get_subscription_by_id(subscription_id, user_id)
        if not subscription:
            logger.warning(f"User {user_id} attempted to list deliveries for inaccessible subscription {subscription_id}")
            return None  # Or raise an exception/return specific error

        try:
            query = WebhookDelivery.query.filter_by(subscription_id=subscription_id)

            # Apply optional filters
            if status and hasattr(DeliveryStatus, status.upper()):
                query = query.filter_by(status=getattr(DeliveryStatus, status.upper()))

            if start_time:
                query = query.filter(WebhookDelivery.created_at >= start_time)

            if end_time:
                query = query.filter(WebhookDelivery.created_at <= end_time)

            pagination = query.order_by(WebhookDelivery.created_at.desc())\
                .paginate(page=page, per_page=per_page, error_out=False)
            return pagination
        except Exception as e:
            logger.error(f"Error listing deliveries for subscription {subscription_id}: {str(e)}")
            return None

    @staticmethod
    def create_subscription_group(
        user_id: int,
        name: str,
        description: Optional[str] = None
    ) -> Tuple[Optional[WebhookSubscriptionGroup], Optional[str]]:
        """
        Creates a new webhook subscription group.

        Args:
            user_id: The ID of the user creating the group.
            name: Name of the subscription group.
            description: Optional description of the purpose of this group.

        Returns:
            Tuple containing the created group (or None) and an error message (or None).
        """
        try:
            # Check if name already exists for this user
            existing = WebhookSubscriptionGroup.query.filter_by(
                user_id=user_id, name=name
            ).first()

            if existing:
                return None, "A subscription group with this name already exists."

            group = WebhookSubscriptionGroup(
                user_id=user_id,
                name=name,
                description=description or "",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )

            db.session.add(group)
            db.session.commit()

            logger.info(f"Webhook subscription group created: {group.id} for user {user_id}")
            metrics.increment('webhook.subscription_group.created')

            return group, None

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error creating webhook subscription group for user {user_id}: {str(e)}")
            metrics.increment('webhook.subscription_group.db_error')
            return None, "Database error occurred while creating subscription group."
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error creating webhook subscription group for user {user_id}: {str(e)}")
            metrics.increment('webhook.subscription_group.error')
            return None, "An unexpected error occurred."

    @staticmethod
    def list_subscription_groups(user_id: int) -> List[WebhookSubscriptionGroup]:
        """
        List all webhook subscription groups for a user.

        Args:
            user_id: The ID of the user.

        Returns:
            List of webhook subscription groups.
        """
        try:
            groups = WebhookSubscriptionGroup.query.filter_by(user_id=user_id)\
                .order_by(WebhookSubscriptionGroup.name).all()
            return groups
        except Exception as e:
            logger.error(f"Error listing webhook subscription groups for user {user_id}: {str(e)}")
            return []

    @staticmethod
    def delete_subscription_group(group_id: int, user_id: int,
                               delete_subscriptions: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Deletes a webhook subscription group.

        Args:
            group_id: ID of the group to delete.
            user_id: User ID requesting the deletion.
            delete_subscriptions: Whether to delete all subscriptions in the group.

        Returns:
            Tuple of (success, error_message).
        """
        try:
            group = WebhookSubscriptionGroup.query.filter_by(
                id=group_id, user_id=user_id
            ).first()

            if not group:
                return False, "Subscription group not found or access denied."

            # Handle subscriptions in this group
            if delete_subscriptions:
                # Delete all subscriptions in this group
                subscriptions = WebhookSubscription.query.filter_by(group_id=group_id).all()
                for subscription in subscriptions:
                    db.session.delete(subscription)
                logger.info(f"Deleted {len(subscriptions)} webhooks in group {group_id}")
            else:
                # Update subscriptions to remove the group association
                WebhookSubscription.query.filter_by(group_id=group_id)\
                    .update({WebhookSubscription.group_id: None})

            # Delete the group
            db.session.delete(group)
            db.session.commit()

            logger.info(f"Webhook subscription group {group_id} deleted by user {user_id}")
            metrics.increment('webhook.subscription_group.deleted')

            return True, None

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error deleting webhook subscription group {group_id}: {str(e)}")
            metrics.increment('webhook.subscription_group.db_error')
            return False, "Database error occurred while deleting subscription group."
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error deleting webhook subscription group {group_id}: {str(e)}")
            metrics.increment('webhook.subscription_group.error')
            return False, "An unexpected error occurred."

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

        # Use URL validation from core security if available
        if validate_url:
            url_validation_result = validate_url(target_url)
            if url_validation_result:
                return f"URL validation failed: {url_validation_result}"

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

    @staticmethod
    def replay_failed_delivery(delivery_id: int, user_id: int) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Retry a previously failed webhook delivery.

        Args:
            delivery_id: ID of the failed delivery to retry.
            user_id: ID of the user requesting the retry.

        Returns:
            Tuple containing (success status, error message, result details).
        """
        try:
            # Get the delivery record
            delivery = WebhookDelivery.query.get(delivery_id)
            if not delivery:
                return False, "Delivery record not found.", None

            # Check ownership of the associated subscription
            subscription = WebhookService.get_subscription_by_id(
                delivery.subscription_id, user_id
            )
            if not subscription:
                logger.warning(f"User {user_id} attempted to replay delivery {delivery_id} for inaccessible subscription")
                return False, "Access denied: You don't have permission to replay this delivery.", None

            # Check if delivery is in a failed state
            if delivery.status != DeliveryStatus.FAILED:
                return False, f"Delivery is not in a failed state. Current status: {delivery.status}", None

            # Check rate limiting
            if WebhookService._is_rate_limited(subscription):
                metrics.increment('webhook.replay_delivery.rate_limited')
                return False, "Rate limit exceeded for this webhook endpoint. Please try again later.", None

            # Create a new delivery based on the failed one
            event_type = delivery.event_type
            payload = delivery.payload

            # Add replay information to payload
            if isinstance(payload, dict):
                payload.setdefault('meta', {})
                payload['meta']['is_replay'] = True
                payload['meta']['original_delivery_id'] = delivery_id
                payload['meta']['replay_time'] = datetime.now(timezone.utc).isoformat()

            # Trigger a new delivery
            results = trigger_delivery_process(
                event_type=event_type,
                payload=payload,
                subscription_id=delivery.subscription_id
            )

            if not results:
                metrics.increment('webhook.replay_delivery.failed')
                return False, "Failed to initiate delivery retry.", None

            metrics.increment('webhook.replay_delivery.success')
            logger.info(f"Webhook delivery {delivery_id} replayed by user {user_id}")

            # Track this attempt for rate limiting purposes
            WebhookService._record_delivery_attempt(subscription)

            # Return the new delivery details
            return True, None, results[0]

        except Exception as e:
            logger.error(f"Error replaying webhook delivery {delivery_id}: {str(e)}")
            metrics.increment('webhook.replay_delivery.error')
            return False, "An unexpected error occurred while replaying the delivery.", None

    @staticmethod
    def get_subscription_health(
        subscription_id: str,
        user_id: int,
        lookback_hours: int = 24
    ) -> Optional[Dict[str, Any]]:
        """
        Get health metrics for a specific webhook subscription.

        Args:
            subscription_id: ID of the subscription.
            user_id: ID of the user requesting the health data.
            lookback_hours: How many hours of history to analyze.

        Returns:
            Dictionary with health metrics or None if access denied.
        """
        # Verify ownership
        subscription = WebhookService.get_subscription_by_id(subscription_id, user_id)
        if not subscription:
            return None

        try:
            # Define time range
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=lookback_hours)

            # Get delivery stats
            deliveries = WebhookDelivery.query.filter(
                WebhookDelivery.subscription_id == subscription_id,
                WebhookDelivery.created_at >= start_time
            ).all()

            if not deliveries:
                return {
                    'subscription_id': subscription_id,
                    'period_hours': lookback_hours,
                    'total_deliveries': 0,
                    'status': 'unknown',
                    'message': f"No deliveries in the past {lookback_hours} hours"
                }

            # Calculate statistics
            total = len(deliveries)
            succeeded = sum(1 for d in deliveries if d.status == DeliveryStatus.DELIVERED)
            failed = sum(1 for d in deliveries if d.status == DeliveryStatus.FAILED)
            pending = total - succeeded - failed

            # Calculate success rate
            success_rate = (succeeded / total) * 100 if total > 0 else 0

            # Determine health status
            status = 'healthy'  # Default
            message = "Webhook endpoint is operating normally."

            if success_rate < 50:
                status = 'critical'
                message = "Critical failure rate - most webhook deliveries are failing."
            elif success_rate < 80:
                status = 'warning'
                message = "High failure rate - webhook deliveries are frequently failing."
            elif success_rate < 95:
                status = 'degraded'
                message = "Some webhook deliveries are failing."

            # Calculate average response time for successful deliveries
            response_times = [d.duration_ms for d in deliveries if d.status == DeliveryStatus.DELIVERED and d.duration_ms]
            avg_response_time = sum(response_times) / len(response_times) if response_times else None

            # Return the health report
            return {
                'subscription_id': subscription_id,
                'status': status,
                'message': message,
                'period_hours': lookback_hours,
                'total_deliveries': total,
                'successful_deliveries': succeeded,
                'failed_deliveries': failed,
                'pending_deliveries': pending,
                'success_rate': round(success_rate, 1),
                'average_response_time_ms': round(avg_response_time, 2) if avg_response_time else None,
                'is_active': subscription.is_active,
                'target_url': subscription.target_url
            }

        except Exception as e:
            logger.error(f"Error calculating webhook health for subscription {subscription_id}: {str(e)}")
            return {
                'subscription_id': subscription_id,
                'status': 'error',
                'message': "Error calculating webhook health metrics",
                'error': str(e)
            }

    @staticmethod
    def rotate_subscription_secret(subscription_id: str, user_id: int) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Rotates the webhook subscription secret.

        Args:
            subscription_id: ID of the subscription.
            user_id: ID of the user requesting the rotation.

        Returns:
            Tuple containing (success status, error message, new secret).
        """
        try:
            # Verify ownership
            subscription = WebhookSubscription.query.filter_by(
                id=subscription_id, user_id=user_id
            ).first()

            if not subscription:
                return False, "Webhook subscription not found or access denied.", None

            # Generate new secret
            new_secret = secrets.token_hex(32)

            # Update subscription
            subscription.secret = new_secret
            subscription.updated_at = datetime.now(timezone.utc)
            db.session.commit()

            logger.info(f"Webhook subscription secret rotated: {subscription_id} by user {user_id}")
            metrics.increment('webhook.subscription.secret_rotated')

            # Log security event
            log_security_event(
                event_type='webhook_subscription_secret_rotated',
                description=f"Webhook subscription secret rotated: {subscription_id}",
                user_id=user_id,
                object_type='WebhookSubscription',
                object_id=subscription_id,
                severity='info'
            )

            # Clear cache for this subscription
            cache_key = f"webhook:sub:{subscription_id}"
            if hasattr(current_app, 'cache'):
                current_app.cache.delete(cache_key)

            return True, None, new_secret

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error rotating webhook subscription secret {subscription_id}: {str(e)}")
            metrics.increment('webhook.subscription.db_error')
            return False, "Database error occurred while rotating subscription secret.", None
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error rotating webhook subscription secret {subscription_id}: {str(e)}")
            metrics.increment('webhook.subscription.error')
            return False, "An unexpected error occurred.", None

    @staticmethod
    def bulk_update_subscriptions(
        user_id: int,
        filters: Dict[str, Any],
        updates: Dict[str, Any]
    ) -> Tuple[int, List[str]]:
        """
        Update multiple webhook subscriptions in bulk.

        Args:
            user_id: ID of the user performing the update.
            filters: Dictionary of filters to select subscriptions.
            updates: Dictionary of fields to update.

        Returns:
            Tuple containing (count of updated subscriptions, list of errors).
        """
        errors = []

        try:
            # Start with user's subscriptions
            query = WebhookSubscription.query.filter_by(user_id=user_id)

            # Apply filters
            if 'group_id' in filters:
                query = query.filter(WebhookSubscription.group_id == filters['group_id'])

            if 'is_active' in filters:
                query = query.filter(WebhookSubscription.is_active == filters['is_active'])

            if 'event_type' in filters:
                query = query.filter(WebhookSubscription.event_types.contains([filters['event_type']]))

            if 'target_url_contains' in filters:
                query = query.filter(WebhookSubscription.target_url.ilike(f"%{filters['target_url_contains']}%"))

            # Validate update fields
            allowed_updates = ['is_active', 'max_retries', 'group_id', 'rate_limit']
            update_data = {k: v for k, v in updates.items() if k in allowed_updates}

            if not update_data:
                return 0, ["No valid update fields provided"]

            # If changing URL, validate it for each subscription separately
            if 'target_url' in updates:
                # We can't do this in bulk due to validation requirements
                url = updates['target_url']
                validation_error = WebhookService.validate_subscription_data(url, ['test.event'])
                if validation_error:
                    return 0, [f"Invalid target URL: {validation_error}"]

                security_error = WebhookService._validate_security_constraints(url)
                if security_error:
                    return 0, [f"Security constraint violation: {security_error}"]

                update_data['target_url'] = url

            # Get the subscriptions to update
            subscriptions = query.all()
            if not subscriptions:
                return 0, ["No subscriptions match the provided filters"]

            # Update each subscription
            updated_count = 0
            for subscription in subscriptions:
                try:
                    # Apply updates
                    for key, value in update_data.items():
                        setattr(subscription, key, value)

                    subscription.updated_at = datetime.now(timezone.utc)

                    # Clear cache for this subscription
                    cache_key = f"webhook:sub:{subscription.id}"
                    if hasattr(current_app, 'cache'):
                        current_app.cache.delete(cache_key)

                    updated_count += 1
                except Exception as e:
                    errors.append(f"Error updating subscription {subscription.id}: {str(e)}")

            # Commit changes if any were made
            if updated_count > 0:
                db.session.commit()
                logger.info(f"Bulk updated {updated_count} webhook subscriptions for user {user_id}")
                metrics.increment('webhook.subscription.bulk_updated', updated_count)

                # Log security event
                log_security_event(
                    event_type='webhook_subscriptions_bulk_updated',
                    description=f"Bulk updated {updated_count} webhook subscriptions",
                    user_id=user_id,
                    severity='info',
                    details={'filters': filters, 'updates': updates}
                )

            return updated_count, errors

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error during bulk webhook subscription update for user {user_id}: {str(e)}")
            metrics.increment('webhook.subscription.db_error')
            errors.append(f"Database error: {str(e)}")
            return 0, errors
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error during bulk webhook subscription update for user {user_id}: {str(e)}")
            metrics.increment('webhook.subscription.error')
            errors.append(f"Unexpected error: {str(e)}")
            return 0, errors

    @staticmethod
    def _is_rate_limited(subscription) -> bool:
        """
        Check if a subscription is currently rate limited.

        Args:
            subscription: The WebhookSubscription object to check.

        Returns:
            True if rate limited, False otherwise.
        """
        # If no rate limit set on the subscription, apply default
        if not hasattr(subscription, 'rate_limit') or not subscription.rate_limit:
            max_calls = DEFAULT_RATE_LIMIT_MAX_CALLS
            window_seconds = DEFAULT_RATE_LIMIT_WINDOW
        else:
            max_calls = subscription.rate_limit.get('max_calls', DEFAULT_RATE_LIMIT_MAX_CALLS)
            window_seconds = subscription.rate_limit.get('window_seconds', DEFAULT_RATE_LIMIT_WINDOW)

        # Get the rate limiting key
        rate_key = f"webhook:rate:{subscription.id}"

        if not hasattr(current_app, 'cache'):
            # Can't enforce rate limiting without a cache
            return False

        # Check current count
        current_count = current_app.cache.get(rate_key) or 0

        # If we're under the limit, we're not rate limited
        return current_count >= max_calls

    @staticmethod
    def _record_delivery_attempt(subscription) -> None:
        """
        Record a delivery attempt for rate limiting purposes.

        Args:
            subscription: The WebhookSubscription object.
        """
        if not hasattr(current_app, 'cache'):
            return

        # If no rate limit set on the subscription, apply default
        if not hasattr(subscription, 'rate_limit') or not subscription.rate_limit:
            window_seconds = DEFAULT_RATE_LIMIT_WINDOW
        else:
            window_seconds = subscription.rate_limit.get('window_seconds', DEFAULT_RATE_LIMIT_WINDOW)

        # Get the rate limiting key
        rate_key = f"webhook:rate:{subscription.id}"

        # Get current count and increment
        current_count = current_app.cache.get(rate_key) or 0
        current_app.cache.set(rate_key, current_count + 1, timeout=window_seconds)

    @staticmethod
    def _validate_security_constraints(url: str) -> Optional[str]:
        """
        Validate URL against security constraints.

        Args:
            url: The URL to validate.

        Returns:
            Error message if validation fails, None if passed.
        """
        try:
            parsed = urlparse(url)

            # Check against blocked hosts if configured
            blocked_hosts = current_app.config.get('WEBHOOK_BLOCKED_HOSTS', []) if hasattr(current_app, 'config') else []
            if parsed.netloc in blocked_hosts:
                return "Target host is not allowed."

            # Local IPs or localhost are often disallowed in production
            if parsed.netloc.lower() in ('localhost', '127.0.0.1', '::1'):
                return "Local addresses are not allowed as webhook targets."

            # Block internal IP ranges if configured to do so
            if hasattr(current_app, 'config') and current_app.config.get('BLOCK_INTERNAL_IPS', True):
                try:
                    # Look up the hostname to get IP
                    import socket
                    host = parsed.netloc.split(':')[0]  # Remove port if present

                    # Try to resolve the hostname to an IP address
                    ip_str = socket.gethostbyname(host)
                    ip = ipaddress.ip_address(ip_str)

                    # Check if it's a private IP address
                    if ip.is_private:
                        return "Private IP addresses are not allowed as webhook targets."
                except socket.gaierror:
                    # Could not resolve host, let it pass since this might be temporary
                    pass
                except Exception:
                    # Any other error, let it pass
                    pass

            # Validate port if specified (block uncommon ports)
            if parsed.port and parsed.port not in (80, 443, 8080, 8443):
                allowed_ports = current_app.config.get('WEBHOOK_ALLOWED_PORTS', []) if hasattr(current_app, 'config') else []
                if parsed.port not in allowed_ports:
                    return f"Port {parsed.port} is not allowed for webhook targets."

            # Always require HTTPS in production
            if hasattr(current_app, 'config') and current_app.config.get('ENV') == 'production':
                if parsed.scheme != 'https':
                    return "Only HTTPS URLs are allowed in production."

        except Exception as e:
            logger.error(f"Error validating webhook URL security constraints: {str(e)}")
            return "Error validating URL security constraints."

        return None

    @staticmethod
    def _get_event_category(event_type: str) -> str:
        """
        Get the category for an event type.

        Args:
            event_type: Event type string.

        Returns:
            Category name or 'other'.
        """
        for category, events in EVENT_CATEGORIES.items():
            if event_type in events:
                return category
        return "other"

    @staticmethod
    def _record_event_delivery(event_type: str, event_id: str, success_count: int, user_id: Optional[int] = None) -> None:
        """
        Record high-level information about event delivery for auditing.

        This is separate from individual delivery records and allows for efficient tracking
        of large numbers of webhook events without DB overhead.

        Args:
            event_type: Type of event delivered.
            event_id: Unique ID for the event.
            success_count: Number of successful deliveries.
            user_id: Optional ID of the user who triggered the event.
        """
        try:
            # Record in high-frequency log
            logger.info(
                f"WEBHOOK_DELIVERY event_id={event_id} event_type={event_type} "
                f"deliveries={success_count} user_id={user_id or 'system'}"
            )

            # Optionally, if configured, send to external monitoring system
            if hasattr(current_app, 'config') and current_app.config.get('WEBHOOK_MONITORING_ENABLED'):
                # This could publish to a queue, stream, or monitoring service
                try:
                    monitoring_data = {
                        'event_id': event_id,
                        'event_type': event_type,
                        'delivery_count': success_count,
                        'user_id': user_id,
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    }
                    # Publish to monitoring system
                    # (Implementation depends on monitoring infrastructure)
                    pass
                except Exception as mon_err:
                    logger.warning(f"Failed to send webhook event to monitoring system: {mon_err}")
        except Exception as e:
            # Best effort, don't fail if this doesn't work
            logger.warning(f"Failed to record webhook delivery event: {e}")


# Define what is exported when using 'from services import *'
__all__ = [
    'WebhookService'
]
