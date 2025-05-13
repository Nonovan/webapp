"""
Webhook models for the Cloud Infrastructure Platform.

This module defines the database models for webhook subscriptions, delivery
attempts, event logs, and their corresponding schemas for API validation.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from marshmallow import Schema, fields, validate, validates, ValidationError
import re

from extensions import db
from api.webhooks import EventType, DeliveryStatus, EVENT_TYPES

class WebhookSubscription(db.Model):
    """Model representing a webhook subscription."""

    __tablename__ = 'webhook_subscriptions'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    url = db.Column(db.String(512), nullable=False)
    description = db.Column(db.String(512), nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    active = db.Column(db.Boolean, default=True, nullable=False)
    secret = db.Column(db.String(128), nullable=False)
    event_types = db.Column(db.JSON, default=list, nullable=False)
    headers = db.Column(db.JSON, default=dict, nullable=False)
    max_retries = db.Column(db.Integer, default=3, nullable=False)
    retry_interval = db.Column(db.Integer, default=60, nullable=False)  # seconds

    # Circuit breaker fields
    circuit_status = db.Column(db.String(10), default='closed', nullable=False)  # closed, open, half-open
    failure_count = db.Column(db.Integer, default=0, nullable=False)
    last_failure_at = db.Column(db.DateTime, nullable=True)
    circuit_tripped_at = db.Column(db.DateTime, nullable=True)
    next_attempt_at = db.Column(db.DateTime, nullable=True)
    failure_threshold = db.Column(db.Integer, default=5, nullable=False)
    reset_timeout = db.Column(db.Integer, default=300, nullable=False)  # seconds
    success_threshold = db.Column(db.Integer, default=2, nullable=False)  # Successful requests needed in half-open state
    half_open_successes = db.Column(db.Integer, default=0, nullable=False)  # Counter for successes in half-open state

    # Relationships
    created_by = db.relationship('User', backref=db.backref('webhook_subscriptions', lazy='dynamic'))
    delivery_attempts = db.relationship('WebhookDeliveryAttempt',
                                       backref='subscription',
                                       lazy='dynamic',
                                       cascade='all, delete-orphan')

    def __repr__(self) -> str:
        return f'<WebhookSubscription {self.id}: {self.name}>'

    def to_dict(self) -> Dict[str, Any]:
        """Convert subscription to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'url': self.url,
            'description': self.description,
            'created_by_id': self.created_by_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'active': self.active,
            'event_types': self.event_types,
            'headers': self.headers,
            'max_retries': self.max_retries,
            'retry_interval': self.retry_interval,
            'circuit_status': self.circuit_status,
            'failure_count': self.failure_count,
            'failure_threshold': self.failure_threshold,
            'reset_timeout': self.reset_timeout,
            'next_attempt_at': self.next_attempt_at.isoformat() if self.next_attempt_at else None
        }

    @classmethod
    def find_by_event_type(cls, event_type: str) -> List['WebhookSubscription']:
        """Find all active subscriptions for a specific event type."""
        return cls.query.filter(
            cls.active == True,
            cls.event_types.contains(event_type),
            # Don't deliver to subscriptions with open circuit, but allow half-open for testing
            db.or_(
                cls.circuit_status == 'closed',
                cls.circuit_status == 'half-open',
                cls.circuit_status == None
            )
        ).all()

    def record_failure(self) -> None:
        """Record delivery failure and potentially trip circuit breaker."""
        self.failure_count += 1
        self.last_failure_at = datetime.utcnow()

        # Handle different circuit states
        if self.circuit_status == 'closed':
            # Trip circuit breaker if failures exceed threshold
            if self.failure_count >= self.failure_threshold:
                self.trip_circuit_breaker()
        elif self.circuit_status == 'half-open':
            # Any failure in half-open state trips the circuit again
            self.trip_circuit_breaker()

        db.session.commit()

    def record_success(self) -> None:
        """Record successful delivery and update circuit breaker state."""
        if self.circuit_status == 'closed':
            # Reset failure count on success in closed state
            if self.failure_count > 0:
                self.failure_count = 0
                db.session.commit()
        elif self.circuit_status == 'half-open':
            # In half-open state, we need consecutive successes to close the circuit
            self.half_open_successes += 1

            if self.half_open_successes >= self.success_threshold:
                # Reset circuit breaker after enough successful requests
                self.circuit_status = 'closed'
                self.failure_count = 0
                self.half_open_successes = 0
                self.circuit_tripped_at = None
                self.next_attempt_at = None
                db.session.commit()
            else:
                # Still collecting successes in half-open state
                db.session.commit()

    def trip_circuit_breaker(self) -> None:
        """Trip the circuit breaker to open state."""
        self.circuit_status = 'open'
        self.circuit_tripped_at = datetime.utcnow()
        self.next_attempt_at = datetime.utcnow() + timedelta(seconds=self.reset_timeout)
        self.half_open_successes = 0  # Reset success counter

    def is_circuit_open(self) -> bool:
        """
        Check if circuit breaker is open (preventing deliveries).

        This method also handles the transition from open to half-open state
        when the reset timeout has elapsed.

        Returns:
            bool: True if circuit is open and blocking requests, False otherwise
        """
        if self.circuit_status == 'open':
            # Check if it's time to try again (transition to half-open state)
            if self.next_attempt_at and datetime.utcnow() >= self.next_attempt_at:
                self.circuit_status = 'half-open'
                self.half_open_successes = 0  # Reset success counter for half-open state
                db.session.commit()
                return False  # Allow one request through in half-open state
            return True  # Still in open state, block requests
        return False  # Circuit is closed or half-open

    def get_health_status(self) -> Dict[str, Any]:
        """
        Get detailed health status information for this webhook subscription.

        Returns:
            Dict containing health metrics and circuit breaker status
        """
        # Calculate failure rate
        attempts = self.delivery_attempts.filter(
            WebhookDeliveryAttempt.created_at >= datetime.utcnow() - timedelta(hours=24)
        ).count()

        failures = self.delivery_attempts.filter(
            WebhookDeliveryAttempt.status == DeliveryStatus.FAILED,
            WebhookDeliveryAttempt.created_at >= datetime.utcnow() - timedelta(hours=24)
        ).count()

        failure_rate = (failures / attempts) * 100 if attempts > 0 else 0
        time_since_last_failure = None

        if self.last_failure_at:
            time_since_last_failure = (datetime.utcnow() - self.last_failure_at).total_seconds()

        # Determine if circuit breaker is going to be reset soon
        reset_remaining = None
        if self.circuit_status == 'open' and self.next_attempt_at:
            reset_remaining = max(0, (self.next_attempt_at - datetime.utcnow()).total_seconds())

        return {
            'circuit_status': self.circuit_status,
            'failure_count': self.failure_count,
            'failure_threshold': self.failure_threshold,
            'failure_rate_24h': round(failure_rate, 2),
            'attempts_24h': attempts,
            'failures_24h': failures,
            'last_failure_at': self.last_failure_at.isoformat() if self.last_failure_at else None,
            'time_since_failure_seconds': round(time_since_last_failure) if time_since_last_failure else None,
            'reset_timeout': self.reset_timeout,
            'reset_remaining_seconds': round(reset_remaining) if reset_remaining else None,
            'half_open_successes': self.half_open_successes,
            'success_threshold': self.success_threshold
        }

    def manual_reset_circuit(self) -> bool:
        """
        Manually reset the circuit breaker to closed state.

        Returns:
            bool: True if circuit was reset, False if it was already closed
        """
        if self.circuit_status != 'closed':
            self.circuit_status = 'closed'
            self.failure_count = 0
            self.half_open_successes = 0
            self.circuit_tripped_at = None
            self.next_attempt_at = None
            db.session.commit()
            return True
        return False


class WebhookDeliveryAttempt(db.Model):
    """Model representing a webhook delivery attempt."""

    __tablename__ = 'webhook_delivery_attempts'

    id = db.Column(db.Integer, primary_key=True)
    subscription_id = db.Column(db.Integer, db.ForeignKey('webhook_subscriptions.id'), nullable=False)
    event_type = db.Column(db.String(64), nullable=False)
    payload = db.Column(db.JSON, nullable=False)
    status = db.Column(db.String(16), nullable=False, default=DeliveryStatus.PENDING)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    response_code = db.Column(db.Integer, nullable=True)
    response_body = db.Column(db.Text, nullable=True)
    attempts = db.Column(db.Integer, default=0, nullable=False)
    next_attempt_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    request_duration = db.Column(db.Float, nullable=True)  # milliseconds
    request_id = db.Column(db.String(64), nullable=True)

    def __repr__(self) -> str:
        return f'<WebhookDeliveryAttempt {self.id}: {self.event_type} ({self.status})>'

    def to_dict(self) -> Dict[str, Any]:
        """Convert delivery attempt to dictionary."""
        return {
            'id': self.id,
            'subscription_id': self.subscription_id,
            'event_type': self.event_type,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'response_code': self.response_code,
            'attempts': self.attempts,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'error_message': self.error_message,
            'request_duration': self.request_duration,
            'request_id': self.request_id
        }

    @classmethod
    def get_recent_failures(cls, subscription_id: int, hours: int = 24) -> List['WebhookDeliveryAttempt']:
        """Get recent delivery failures for a subscription."""
        return cls.query.filter(
            cls.subscription_id == subscription_id,
            cls.status == DeliveryStatus.FAILED,
            cls.created_at >= datetime.utcnow() - timedelta(hours=hours)
        ).order_by(cls.created_at.desc()).all()


# Schema classes for API validation
class BaseSchema(Schema):
    """Base schema with common functionality."""

    class Meta:
        ordered = True

    @staticmethod
    def clean_url(url: str) -> str:
        """Remove any potential trailing slashes from URLs."""
        return url.rstrip('/') if url else url


class WebhookSubscriptionSchema(BaseSchema):
    """Schema for webhook subscription validation."""

    id = fields.Integer(dump_only=True)
    name = fields.String(required=True, validate=validate.Length(min=1, max=128))
    url = fields.URL(required=True, validate=validate.Length(max=512))
    description = fields.String(allow_none=True, validate=validate.Length(max=512))
    created_by_id = fields.Integer(dump_only=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)
    active = fields.Boolean(missing=True)
    event_types = fields.List(fields.String(), required=True, validate=validate.Length(min=1))
    headers = fields.Dict(keys=fields.String(), values=fields.String(), missing=dict)
    max_retries = fields.Integer(missing=3, validate=validate.Range(min=0, max=10))
    retry_interval = fields.Integer(missing=60, validate=validate.Range(min=10, max=3600))
    failure_threshold = fields.Integer(missing=5, validate=validate.Range(min=1, max=20))
    reset_timeout = fields.Integer(missing=300, validate=validate.Range(min=30, max=86400))
    success_threshold = fields.Integer(missing=2, validate=validate.Range(min=1, max=5))
    circuit_status = fields.String(dump_only=True)

    @validates('url')
    def validate_url(self, url):
        """Validate URL contains valid scheme."""
        if not url.startswith(('http://', 'https://')):
            raise ValidationError("URL must start with http:// or https://")

        # Clean URL by removing trailing slashes
        return self.clean_url(url)

    @validates('event_types')
    def validate_event_types(self, event_types):
        """Validate that all event types are supported."""
        if not event_types:
            raise ValidationError("At least one event type must be specified")

        for event_type in event_types:
            if event_type not in EVENT_TYPES and event_type != 'test.event':
                raise ValidationError(f"Event type '{event_type}' is not supported")

        return event_types


class WebhookDeliveryAttemptSchema(BaseSchema):
    """Schema for webhook delivery attempt validation."""

    id = fields.Integer(dump_only=True)
    subscription_id = fields.Integer(required=True)
    event_type = fields.String(required=True)
    payload = fields.Dict(dump_only=True)
    status = fields.String(dump_only=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)
    response_code = fields.Integer(dump_only=True)
    attempts = fields.Integer(dump_only=True)
    completed_at = fields.DateTime(dump_only=True)
    error_message = fields.String(dump_only=True)
    request_duration = fields.Float(dump_only=True)
    request_id = fields.String(dump_only=True)


class WebhookTestSchema(BaseSchema):
    """Schema for webhook test request validation."""

    subscription_id = fields.String(required=True)
    custom_payload = fields.Dict(keys=fields.String(), values=fields.Raw(), missing=None)


class WebhookQuerySchema(BaseSchema):
    """Schema for webhook query parameters."""

    page = fields.Integer(missing=1, validate=validate.Range(min=1))
    per_page = fields.Integer(missing=20, validate=validate.Range(min=1, max=100))
    active = fields.Boolean(missing=None)
    event_type = fields.String(missing=None)

    @validates('event_type')
    def validate_event_type(self, event_type):
        """Validate that event type is supported if specified."""
        if event_type and event_type not in EVENT_TYPES and event_type != 'test.event':
            raise ValidationError(f"Event type '{event_type}' is not supported")

        return event_type


class WebhookDeliveryQuerySchema(BaseSchema):
    """Schema for webhook delivery query parameters."""

    page = fields.Integer(missing=1, validate=validate.Range(min=1))
    per_page = fields.Integer(missing=20, validate=validate.Range(min=1, max=100))
    status = fields.String(missing=None, validate=validate.OneOf([
        DeliveryStatus.PENDING, DeliveryStatus.DELIVERED, DeliveryStatus.FAILED, None
    ]))
    start_date = fields.DateTime(missing=None)
    end_date = fields.DateTime(missing=None)

    @validates('end_date')
    def validate_date_range(self, end_date, **kwargs):
        """Validate that end_date is after start_date if both provided."""
        start_date = kwargs.get('start_date')
        if start_date and end_date and end_date < start_date:
            raise ValidationError("end_date must be after start_date")

        return end_date


class CircuitBreakerActionSchema(BaseSchema):
    """Schema for circuit breaker actions."""

    action = fields.String(required=True, validate=validate.OneOf(['reset', 'trip', 'configure']))
    failure_threshold = fields.Integer(validate=validate.Range(min=1, max=20), missing=None)
    reset_timeout = fields.Integer(validate=validate.Range(min=30, max=86400), missing=None)
    success_threshold = fields.Integer(validate=validate.Range(min=1, max=5), missing=None)
