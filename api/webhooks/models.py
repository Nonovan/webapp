"""
Webhook models for the Cloud Infrastructure Platform.

This module defines the database models for webhook subscriptions, delivery
attempts, and event logs.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional

from extensions import db
from api.webhooks import EventType, DeliveryStatus

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
            'retry_interval': self.retry_interval
        }
    
    @classmethod
    def find_by_event_type(cls, event_type: str) -> List['WebhookSubscription']:
        """Find all active subscriptions for a specific event type."""
        return cls.query.filter(
            cls.active == True,
            cls.event_types.contains(event_type)
        ).all()


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
