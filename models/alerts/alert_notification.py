"""
Alert notification model for managing alert delivery across channels.

This module provides the AlertNotification model for tracking and managing
alert notifications across multiple channels (email, SMS, webhooks, etc.).
It handles notification templates, delivery status tracking, and retry logic.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy import desc, asc, and_, or_, func
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app

from extensions import db
from models.base import BaseModel
from core.security import log_security_event
from models.alerts.alert import Alert

class AlertNotification(BaseModel):
    """
    Model for tracking alert notifications.

    This model tracks notifications sent for alerts across various channels,
    supports retry logic, and maintains delivery status.

    Attributes:
        id (int): Notification unique identifier
        alert_id (int): Associated alert ID
        channel (str): Notification channel (email, sms, webhook, etc.)
        recipient (str): Notification recipient (email, phone, URL, etc.)
        status (str): Delivery status (pending, sent, delivered, failed)
        content (dict): JSON content of the notification
        attempts (int): Number of delivery attempts
        last_attempt (datetime): Timestamp of last delivery attempt
        delivered_at (datetime): Timestamp when notification was delivered
        error (str): Error message if delivery failed
    """

    __tablename__ = 'alert_notifications'

    # Notification channels
    CHANNEL_EMAIL = 'email'
    CHANNEL_SMS = 'sms'
    CHANNEL_WEBHOOK = 'webhook'
    CHANNEL_SLACK = 'slack'
    CHANNEL_TEAMS = 'teams'
    CHANNEL_PAGERDUTY = 'pagerduty'
    CHANNEL_INAPP = 'inapp'

    CHANNELS = [
        CHANNEL_EMAIL, CHANNEL_SMS, CHANNEL_WEBHOOK,
        CHANNEL_SLACK, CHANNEL_TEAMS, CHANNEL_PAGERDUTY,
        CHANNEL_INAPP
    ]

    # Notification statuses
    STATUS_PENDING = 'pending'
    STATUS_SENT = 'sent'
    STATUS_DELIVERED = 'delivered'
    STATUS_FAILED = 'failed'

    STATUSES = [STATUS_PENDING, STATUS_SENT, STATUS_DELIVERED, STATUS_FAILED]

    # Column definitions
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id', ondelete='CASCADE'), nullable=False, index=True)
    channel = db.Column(db.String(32), nullable=False, index=True)
    recipient = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(32), nullable=False, default=STATUS_PENDING, index=True)
    content = db.Column(MutableDict.as_mutable(db.JSON), default=dict, nullable=False)
    attempts = db.Column(db.Integer, default=0, nullable=False)
    last_attempt = db.Column(db.DateTime(timezone=True), nullable=True)
    delivered_at = db.Column(db.DateTime(timezone=True), nullable=True)
    error = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    alert = db.relationship('Alert', backref=db.backref('notifications', lazy='dynamic', cascade='all, delete-orphan'))

    def __init__(self, alert_id: int, channel: str, recipient: str, content: Dict[str, Any] = None):
        """
        Initialize a new notification.

        Args:
            alert_id: ID of the associated alert
            channel: Notification channel (email, sms, etc.)
            recipient: Notification recipient
            content: JSON content of the notification
        """
        self.alert_id = alert_id
        self.channel = channel
        self.recipient = recipient
        self.content = content or {}
        self.status = self.STATUS_PENDING
        self.attempts = 0

    def mark_sent(self) -> None:
        """Mark the notification as sent."""
        self.status = self.STATUS_SENT
        self.last_attempt = datetime.now(timezone.utc)
        self.attempts += 1
        db.session.add(self)
        db.session.commit()

    def mark_delivered(self) -> None:
        """Mark the notification as delivered."""
        self.status = self.STATUS_DELIVERED
        self.delivered_at = datetime.now(timezone.utc)
        db.session.add(self)
        db.session.commit()

    def mark_failed(self, error: str) -> None:
        """
        Mark the notification as failed.

        Args:
            error: Error message
        """
        self.status = self.STATUS_FAILED
        self.last_attempt = datetime.now(timezone.utc)
        self.attempts += 1
        self.error = error
        db.session.add(self)
        db.session.commit()

    @classmethod
    def create_notification(cls,
                          alert: Alert,
                          channel: str,
                          recipient: str,
                          template: str = 'default',
                          extra_context: Dict[str, Any] = None) -> Optional['AlertNotification']:
        """
        Create a notification for an alert.

        Args:
            alert: Alert object to notify about
            channel: Notification channel
            recipient: Notification recipient
            template: Template name to use
            extra_context: Additional context for template rendering

        Returns:
            Created notification or None if creation failed
        """
        try:
            # Validate channel
            if channel not in cls.CHANNELS:
                current_app.logger.error(f"Invalid notification channel: {channel}")
                return None

            # Format notification content based on channel and template
            content = cls._format_content(alert, channel, template, extra_context)

            # Create notification
            notification = cls(
                alert_id=alert.id,
                channel=channel,
                recipient=recipient,
                content=content
            )

            db.session.add(notification)
            db.session.commit()

            return notification
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to create notification: {e}")
            return None

    @classmethod
    def _format_content(cls, alert: Alert,
                       channel: str,
                       template: str,
                       extra_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Format notification content based on channel and template.

        Args:
            alert: Alert object
            channel: Notification channel
            template: Template name
            extra_context: Additional context

        Returns:
            Formatted content dictionary
        """
        context = {
            'alert_id': alert.id,
            'alert_type': alert.alert_type,
            'resource_id': alert.resource_id,
            'service_name': alert.service_name,
            'severity': alert.severity,
            'message': alert.message,
            'environment': alert.environment,
            'region': alert.region,
            'created_at': alert.created_at.isoformat() if alert.created_at else None,
            'status': alert.status
        }

        # Add extra context if provided
        if extra_context:
            context.update(extra_context)

        # Use different formatting based on channel
        if channel == cls.CHANNEL_EMAIL:
            subject = f"[{alert.severity.upper()}] Alert: {alert.message[:50]}..."
            body = cls._render_template(f"email/{template}.html", context)
            return {'subject': subject, 'body': body, 'format': 'html'}

        elif channel == cls.CHANNEL_SMS:
            text = f"{alert.severity.upper()}: {alert.message[:160]}"
            return {'text': text}

        elif channel in [cls.CHANNEL_SLACK, cls.CHANNEL_TEAMS]:
            return cls._format_chat_message(alert, channel, context)

        elif channel == cls.CHANNEL_WEBHOOK:
            return alert.to_dict()

        else:
            return context

    @staticmethod
    def _render_template(template_path: str, context: Dict[str, Any]) -> str:
        """
        Render a template with the given context.

        Args:
            template_path: Path to the template
            context: Template context

        Returns:
            Rendered template as string
        """
        try:
            from flask import render_template
            return render_template(f"alerts/notifications/{template_path}", **context)
        except Exception as e:
            current_app.logger.error(f"Failed to render template {template_path}: {e}")
            # Fallback to basic formatting
            return f"""
            Alert ID: {context.get('alert_id')}
            Type: {context.get('alert_type')}
            Severity: {context.get('severity')}
            Message: {context.get('message')}
            """

    @staticmethod
    def _format_chat_message(alert: Alert, channel: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format a message for chat platforms (Slack, Teams).

        Args:
            alert: Alert object
            channel: Chat channel
            context: Template context

        Returns:
            Formatted chat message
        """
        # Set color based on severity
        color_map = {
            'critical': '#FF0000',  # Red
            'high': '#FFA500',      # Orange
            'warning': '#FFFF00',   # Yellow
            'info': '#0000FF'       # Blue
        }
        color = color_map.get(alert.severity.lower(), '#808080')  # Default gray

        if channel == AlertNotification.CHANNEL_SLACK:
            return {
                'blocks': [
                    {
                        'type': 'header',
                        'text': {
                            'type': 'plain_text',
                            'text': f"Alert: {alert.message[:50]}...",
                            'emoji': True
                        }
                    },
                    {
                        'type': 'section',
                        'fields': [
                            {'type': 'mrkdwn', 'text': f"*ID:* {alert.id}"},
                            {'type': 'mrkdwn', 'text': f"*Type:* {alert.alert_type}"},
                            {'type': 'mrkdwn', 'text': f"*Severity:* {alert.severity}"},
                            {'type': 'mrkdwn', 'text': f"*Service:* {alert.service_name}"},
                            {'type': 'mrkdwn', 'text': f"*Environment:* {alert.environment}"},
                            {'type': 'mrkdwn', 'text': f"*Created:* {alert.created_at.strftime('%Y-%m-%d %H:%M:%S')}"}
                        ]
                    },
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': f"*Message:* {alert.message}"
                        }
                    },
                    {
                        'type': 'actions',
                        'elements': [
                            {
                                'type': 'button',
                                'text': {
                                    'type': 'plain_text',
                                    'text': 'View Details',
                                    'emoji': True
                                },
                                'url': f"{context.get('base_url', '')}/alerts/{alert.id}"
                            },
                            {
                                'type': 'button',
                                'text': {
                                    'type': 'plain_text',
                                    'text': 'Acknowledge',
                                    'emoji': True
                                },
                                'url': f"{context.get('base_url', '')}/alerts/{alert.id}/acknowledge"
                            }
                        ]
                    }
                ],
                'attachments': [
                    {
                        'color': color,
                        'blocks': []
                    }
                ]
            }
        else:  # Teams
            return {
                '@type': 'MessageCard',
                '@context': 'http://schema.org/extensions',
                'themeColor': color.replace('#', ''),
                'summary': f"Alert: {alert.message[:50]}...",
                'sections': [
                    {
                        'activityTitle': f"Alert: {alert.message[:50]}...",
                        'facts': [
                            {'name': 'ID', 'value': str(alert.id)},
                            {'name': 'Type', 'value': alert.alert_type},
                            {'name': 'Severity', 'value': alert.severity},
                            {'name': 'Service', 'value': alert.service_name},
                            {'name': 'Environment', 'value': alert.environment},
                            {'name': 'Created', 'value': alert.created_at.strftime('%Y-%m-%d %H:%M:%S')}
                        ],
                        'text': alert.message
                    }
                ],
                'potentialAction': [
                    {
                        '@type': 'OpenUri',
                        'name': 'View Details',
                        'targets': [
                            {'os': 'default', 'uri': f"{context.get('base_url', '')}/alerts/{alert.id}"}
                        ]
                    }
                ]
            }

    @classmethod
    def get_pending_notifications(cls, limit: int = 100) -> List['AlertNotification']:
        """
        Get pending notifications ready for sending.

        Args:
            limit: Maximum number of notifications to retrieve

        Returns:
            List of pending notifications
        """
        return cls.query.filter_by(
            status=cls.STATUS_PENDING
        ).order_by(
            asc(cls.created_at)
        ).limit(limit).all()

    @classmethod
    def get_failed_notifications_for_retry(cls, max_attempts: int = 3, limit: int = 100) -> List['AlertNotification']:
        """
        Get failed notifications eligible for retry.

        Args:
            max_attempts: Maximum number of retry attempts
            limit: Maximum number of notifications to retrieve

        Returns:
            List of failed notifications eligible for retry
        """
        one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
        return cls.query.filter(
            cls.status == cls.STATUS_FAILED,
            cls.attempts < max_attempts,
            cls.last_attempt < one_hour_ago
        ).order_by(
            asc(cls.last_attempt)
        ).limit(limit).all()

    @classmethod
    def get_notification_stats(cls) -> Dict[str, Any]:
        """
        Get notification statistics.

        Returns:
            Dictionary with notification statistics
        """
        try:
            stats = {
                'total': 0,
                'by_channel': {},
                'by_status': {
                    cls.STATUS_PENDING: 0,
                    cls.STATUS_SENT: 0,
                    cls.STATUS_DELIVERED: 0,
                    cls.STATUS_FAILED: 0
                }
            }

            # Total count
            stats['total'] = cls.query.count()

            # Count by channel
            channel_counts = db.session.query(
                cls.channel, func.count(cls.id)
            ).group_by(cls.channel).all()

            for channel, count in channel_counts:
                stats['by_channel'][channel] = count

            # Count by status
            status_counts = db.session.query(
                cls.status, func.count(cls.id)
            ).group_by(cls.status).all()

            for status, count in status_counts:
                stats['by_status'][status] = count

            return stats

        except SQLAlchemyError as e:
            current_app.logger.error(f"Error getting notification stats: {e}")
            return {
                'total': 0,
                'by_channel': {},
                'by_status': {
                    cls.STATUS_PENDING: 0,
                    cls.STATUS_SENT: 0,
                    cls.STATUS_DELIVERED: 0,
                    cls.STATUS_FAILED: 0
                },
                'error': str(e)
            }
