"""
Database models for webhooks feature.

These models store webhook subscriptions and delivery tracking information.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
import json

from models import db, BaseModel, TimestampMixin

class WebhookSubscription(BaseModel, TimestampMixin):
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
    """
    __tablename__ = 'webhook_subscriptions'

    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    target_url = db.Column(db.String(512), nullable=False)
    event_types = db.Column(db.JSON, nullable=False, default=list)
    description = db.Column(db.String(255), nullable=True)
    headers = db.Column(db.JSON, nullable=False, default=dict)
    secret = db.Column(db.String(128), nullable=False)
    max_retries = db.Column(db.Integer, nullable=False, default=3)
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    # Relationships
    user = db.relationship('User', backref=db.backref('webhook_subscriptions', lazy='dynamic'))
    deliveries = db.relationship(
        'WebhookDelivery',
        backref='subscription',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )

    def to_dict(self, exclude_secret: bool = True) -> Dict:
        """Convert subscription to dictionary for API responses."""
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
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        
        if not exclude_secret:
            data['secret'] = self.secret
            
        return data

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
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    delivered_at = db.Column(db.DateTime, nullable=True)
    last_attempt_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self) -> Dict:
        """Convert delivery to dictionary for API responses."""
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
            'last_attempt_at': self.last_attempt_at.isoformat() if self.last_attempt_at else None
        }
