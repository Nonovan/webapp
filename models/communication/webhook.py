"""
Database models for webhooks feature.

These models store webhook subscriptions and delivery tracking information for the
Cloud Infrastructure Platform's event notification system.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Set, Union, Tuple
import json
import uuid

from sqlalchemy import func, and_, or_
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app

from models import db, BaseModel, TimestampMixin, AuditableMixin
from core.security_utils import log_security_event
from extensions import cache, metrics


class WebhookSubscriptionGroup(BaseModel, TimestampMixin):
    """
    Webhook subscription group for organizing subscriptions.

    Groups allow users to organize and manage related webhook subscriptions together.

    Attributes:
        id: Unique identifier for the group
        user_id: ID of user who created the group
        name: Display name of the group
        description: Optional description of the group's purpose
    """
    __tablename__ = 'webhook_subscription_groups'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)

    # Relationships
    user = db.relationship('User', backref=db.backref('webhook_groups', lazy='dynamic'))
    subscriptions = db.relationship('WebhookSubscription', back_populates='group', lazy='dynamic')

    def __init__(self, user_id: int, name: str, description: Optional[str] = None):
        self.user_id = user_id
        self.name = name
        self.description = description

    def to_dict(self) -> Dict[str, Any]:
        """Convert group to dictionary for API responses."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'subscription_count': self.subscriptions.count()
        }


class WebhookSubscription(BaseModel, TimestampMixin, AuditableMixin):
    """
    Webhook subscription configuration.

    Represents an external endpoint registration to receive webhook events.

    Attributes:
        id: Unique subscription identifier (UUID string)
        user_id: ID of user who created the subscription
        target_url: URL to send webhook payloads to
        event_types: List of event types to notify about
        description: Optional description of the subscription
        headers: Custom HTTP headers to send with webhook requests
        secret: Secret key used to sign webhook payloads
        max_retries: Maximum number of retry attempts for failed deliveries
        is_active: Whether the subscription is currently active
        rate_limit: Optional rate limiting configuration
        group_id: Optional group this subscription belongs to
    """
    __tablename__ = 'webhook_subscriptions'

    # Fields that trigger security auditing when changed
    SECURITY_CRITICAL_FIELDS = ['target_url', 'secret', 'headers']

    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target_url = db.Column(db.String(512), nullable=False)
    event_types = db.Column(db.JSON, nullable=False, default=list)
    description = db.Column(db.String(255), nullable=True)
    headers = db.Column(db.JSON, nullable=False, default=dict)
    secret = db.Column(db.String(128), nullable=False)
    max_retries = db.Column(db.Integer, nullable=False, default=3)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    rate_limit = db.Column(db.JSON, nullable=True)
    group_id = db.Column(db.Integer, db.ForeignKey('webhook_subscription_groups.id', ondelete='SET NULL'), nullable=True)

    # Relationships
    user = db.relationship('User', backref=db.backref('webhook_subscriptions', lazy='dynamic'))
    deliveries = db.relationship(
        'WebhookDelivery',
        back_populates='subscription',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    group = db.relationship('WebhookSubscriptionGroup', back_populates='subscriptions')

    def __init__(self, id: str, user_id: int, target_url: str, event_types: List[str],
                 secret: str, description: Optional[str] = None, headers: Optional[Dict[str, str]] = None,
                 max_retries: int = 3, is_active: bool = True, group_id: Optional[int] = None,
                 rate_limit: Optional[Dict[str, int]] = None):
        """
        Initialize a new webhook subscription.

        Args:
            id: UUID string for this subscription
            user_id: ID of user creating this subscription
            target_url: URL where webhooks will be sent
            event_types: List of event types to subscribe to
            secret: Secret key for signing webhooks
            description: Optional description
            headers: Optional custom headers to include
            max_retries: Maximum delivery attempts
            is_active: Whether subscription is active initially
            group_id: Optional ID of a subscription group
            rate_limit: Optional rate limiting settings
        """
        self.id = id
        self.user_id = user_id
        self.target_url = target_url
        self.event_types = event_types
        self.secret = secret
        self.description = description
        self.headers = headers or {}
        self.max_retries = max_retries
        self.is_active = is_active
        self.group_id = group_id
        self.rate_limit = rate_limit

    def to_dict(self, exclude_secret: bool = True) -> Dict[str, Any]:
        """
        Convert subscription to dictionary for API responses.

        Args:
            exclude_secret: Whether to exclude the secret key

        Returns:
            Dictionary representation of the subscription
        """
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'target_url': self.target_url,
            'event_types': self.event_types,
            'description': self.description,
            'headers': self.headers,
            'max_retries': self.max_retries,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'group_id': self.group_id,
            'rate_limit': self.rate_limit
        }

        if not exclude_secret:
            data['secret'] = self.secret

        return data

    def update(self, **kwargs) -> bool:
        """
        Update subscription attributes with proper security auditing.

        Args:
            **kwargs: Attributes to update

        Returns:
            bool: True if update was successful
        """
        try:
            original_url = self.target_url

            # Track if target URL is being changed (security critical)
            url_changed = 'target_url' in kwargs and kwargs['target_url'] != self.target_url

            # Apply updates
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, value)

            self.updated_at = datetime.now(timezone.utc)
            db.session.commit()

            # Clear cache for this subscription
            self._clear_cache()

            # Log security event if target URL changed
            if url_changed and hasattr(log_security_event, '__call__'):
                log_security_event(
                    event_type='webhook_target_url_changed',
                    description=f"Webhook target URL changed for subscription {self.id}",
                    user_id=self.user_id,
                    severity='warning',
                    details={
                        'old_url': original_url,
                        'new_url': self.target_url
                    }
                )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to update webhook subscription: {str(e)}")
            return False

    def rotate_secret(self, new_secret: str) -> bool:
        """
        Rotate the webhook secret with security auditing.

        Args:
            new_secret: The new secret key

        Returns:
            bool: True if rotation was successful
        """
        try:
            self.secret = new_secret
            self.updated_at = datetime.now(timezone.utc)
            db.session.commit()

            # Clear cache
            self._clear_cache()

            # Log security event
            if hasattr(log_security_event, '__call__'):
                log_security_event(
                    event_type='webhook_secret_rotated',
                    description=f"Secret key rotated for webhook subscription {self.id}",
                    user_id=self.user_id,
                    severity='info',
                    object_type='WebhookSubscription',
                    object_id=self.id
                )

            # Track metrics
            if hasattr(metrics, 'increment'):
                metrics.increment('webhook.secret_rotated')

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to rotate webhook secret: {str(e)}")
            return False

    def get_health_metrics(self, lookback_hours: int = 24) -> Dict[str, Any]:
        """
        Get delivery health metrics for this subscription.

        Args:
            lookback_hours: Number of hours to analyze

        Returns:
            Dictionary with health metrics
        """
        from datetime import timedelta

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=lookback_hours)

        # Get recent deliveries
        recent_deliveries = self.deliveries.filter(
            WebhookDelivery.created_at >= start_time,
            WebhookDelivery.created_at <= end_time
        ).all()

        if not recent_deliveries:
            return {
                'status': 'unknown',
                'message': f"No deliveries in the past {lookback_hours} hours",
                'delivery_count': 0,
                'success_rate': None,
                'success_count': 0,
                'failure_count': 0,
                'avg_duration_ms': None
            }

        # Calculate metrics
        total = len(recent_deliveries)
        successful = sum(1 for d in recent_deliveries if d.status == 'delivered')
        failed = sum(1 for d in recent_deliveries if d.status == 'failed')

        success_rate = (successful / total) * 100 if total > 0 else 0

        # Calculate health status
        status = 'healthy'
        message = "Webhook endpoint is operating normally"

        if success_rate < 50:
            status = 'critical'
            message = "Critical failure rate - most webhook deliveries are failing"
        elif success_rate < 80:
            status = 'warning'
            message = "High failure rate - webhook deliveries are frequently failing"
        elif success_rate < 95:
            status = 'degraded'
            message = "Some webhook deliveries are failing"

        # Calculate average response time
        durations = [d.duration_ms for d in recent_deliveries
                    if d.status == 'delivered' and d.duration_ms is not None]
        avg_duration = sum(durations) / len(durations) if durations else None

        return {
            'status': status,
            'message': message,
            'delivery_count': total,
            'success_rate': round(success_rate, 1),
            'success_count': successful,
            'failure_count': failed,
            'avg_duration_ms': round(avg_duration, 2) if avg_duration is not None else None
        }

    def _clear_cache(self) -> None:
        """Clear cached data for this subscription."""
        if hasattr(cache, 'delete'):
            try:
                cache.delete(f"webhook:sub:{self.id}")
                cache.delete(f"webhook:user:{self.user_id}:subs")
            except Exception as e:
                if hasattr(current_app, 'logger'):
                    current_app.logger.warning(f"Failed to clear webhook cache: {str(e)}")

    @classmethod
    def get_by_id(cls, subscription_id: str) -> Optional['WebhookSubscription']:
        """
        Get a subscription by ID with caching.

        Args:
            subscription_id: The ID to look up

        Returns:
            WebhookSubscription or None if not found
        """
        # Try cache first
        cache_key = f"webhook:sub:{subscription_id}"
        if hasattr(cache, 'get'):
            cached = cache.get(cache_key)
            if cached:
                return cached

        # Query database
        subscription = cls.query.filter_by(id=subscription_id).first()

        # Cache result if found
        if subscription and hasattr(cache, 'set'):
            try:
                cache.set(cache_key, subscription, timeout=300)  # 5 minute cache
            except Exception:
                pass

        return subscription

    @classmethod
    def find_by_event_type(cls, event_type: str) -> List['WebhookSubscription']:
        """
        Find active subscriptions for a specific event type.

        Args:
            event_type: The event type to match

        Returns:
            List of matching subscriptions
        """
        return cls.query.filter(
            cls.is_active == True,
            cls.event_types.contains([event_type])
        ).all()


class WebhookDelivery(BaseModel):
    """
    Webhook delivery tracking record.

    Tracks the delivery attempt history and outcomes for webhook events.

    Attributes:
        id: Unique delivery identifier
        subscription_id: ID of the webhook subscription
        event_type: Type of event delivered
        payload: Event payload data
        status: Current delivery status
        attempts: Number of delivery attempts made
        response_code: HTTP status code from the most recent attempt
        response_body: Response body from the most recent attempt
        duration_ms: Request duration in milliseconds
        created_at: When the delivery was first attempted
        delivered_at: When the delivery was successfully completed
        last_attempt_at: Timestamp of the most recent delivery attempt
        error_message: Error details if delivery failed
    """
    __tablename__ = 'webhook_deliveries'

    id = db.Column(db.Integer, primary_key=True)
    subscription_id = db.Column(db.String(36), db.ForeignKey('webhook_subscriptions.id'), nullable=False)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    payload = db.Column(db.JSON, nullable=False)
    status = db.Column(db.String(20), nullable=False, index=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    response_code = db.Column(db.Integer, nullable=True)
    response_body = db.Column(db.Text, nullable=True)
    duration_ms = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    delivered_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_attempt_at = db.Column(db.DateTime(timezone=True), nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    # Define relationship back to subscription
    subscription = db.relationship('WebhookSubscription', back_populates='deliveries')

    def __init__(self, subscription_id: str, event_type: str, payload: Dict[str, Any],
                status: str = 'pending', created_at: Optional[datetime] = None):
        """
        Initialize a new webhook delivery record.

        Args:
            subscription_id: ID of the webhook subscription
            event_type: Type of event being delivered
            payload: Event data to deliver
            status: Initial delivery status
            created_at: Creation timestamp (default: now)
        """
        self.subscription_id = subscription_id
        self.event_type = event_type
        self.payload = payload
        self.status = status
        if created_at:
            self.created_at = created_at

    def update_status(self, status: str, response_code: Optional[int] = None,
                     response_body: Optional[str] = None, duration_ms: Optional[int] = None,
                     error_message: Optional[str] = None) -> bool:
        """
        Update delivery status and response details.

        Args:
            status: New delivery status
            response_code: HTTP status code from attempt
            response_body: Response body from attempt
            duration_ms: Request duration in milliseconds
            error_message: Error details if failed

        Returns:
            bool: True if update was successful
        """
        try:
            self.status = status
            self.last_attempt_at = datetime.now(timezone.utc)
            self.attempts += 1

            if response_code is not None:
                self.response_code = response_code

            if response_body is not None:
                # Limit response body size
                self.response_body = response_body[:10000]

            if duration_ms is not None:
                self.duration_ms = duration_ms

            if error_message is not None:
                self.error_message = error_message

            # Set delivered_at timestamp if status is 'delivered'
            if status == 'delivered' and not self.delivered_at:
                self.delivered_at = datetime.now(timezone.utc)

            db.session.commit()

            # Track metrics
            if hasattr(metrics, 'increment'):
                metrics.increment(f'webhook.delivery.{status}')
                if status == 'delivered' and duration_ms:
                    metrics.histogram('webhook.delivery.duration', duration_ms)

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to update webhook delivery status: {str(e)}")
            return False

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert delivery to dictionary for API responses.

        Returns:
            Dictionary representation of the delivery
        """
        return {
            'id': self.id,
            'subscription_id': self.subscription_id,
            'event_type': self.event_type,
            'payload': self.payload,
            'status': self.status,
            'attempts': self.attempts,
            'response_code': self.response_code,
            'response_body': self.response_body,
            'duration_ms': self.duration_ms,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'delivered_at': self.delivered_at.isoformat() if self.delivered_at else None,
            'last_attempt_at': self.last_attempt_at.isoformat() if self.last_attempt_at else None,
            'error_message': self.error_message
        }

    @classmethod
    def get_stats(cls, user_id: Optional[int] = None, days: int = 30) -> Dict[str, Any]:
        """
        Get webhook delivery statistics.

        Args:
            user_id: Optional user ID to filter by
            days: Number of days to include in stats

        Returns:
            Dictionary with delivery statistics
        """
        from datetime import timedelta

        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)

            # Build query
            query = cls.query.filter(cls.created_at >= start_time)

            # Filter by user if provided
            if user_id:
                query = query.join(WebhookSubscription).filter(WebhookSubscription.user_id == user_id)

            # Get total count
            total = query.count()

            # Get counts by status
            status_counts = db.session.query(
                cls.status, func.count(cls.id)
            ).filter(
                cls.created_at >= start_time
            ).group_by(cls.status).all()

            # Get counts by event type (top 10)
            event_counts = db.session.query(
                cls.event_type, func.count(cls.id)
            ).filter(
                cls.created_at >= start_time
            ).group_by(cls.event_type).order_by(func.count(cls.id).desc()).limit(10).all()

            # Calculate success rate
            delivered = next((count for status, count in status_counts if status == 'delivered'), 0)
            success_rate = (delivered / total) * 100 if total > 0 else 0

            return {
                'total_deliveries': total,
                'success_rate': round(success_rate, 2),
                'by_status': {status: count for status, count in status_counts},
                'top_events': {event_type: count for event_type, count in event_counts},
                'period_days': days
            }

        except SQLAlchemyError as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error calculating webhook delivery stats: {str(e)}")
            return {
                'total_deliveries': 0,
                'success_rate': 0,
                'by_status': {},
                'top_events': {},
                'period_days': days,
                'error': str(e)
            }


# Create indexes on commonly queried columns
db.Index('ix_webhook_deliveries_status_created_at',
        WebhookDelivery.status, WebhookDelivery.created_at)
db.Index('ix_webhook_subscriptions_user_event',
        WebhookSubscription.user_id, WebhookSubscription.is_active)
