"""
Communication models package for the Cloud Infrastructure Platform.

This package contains models related to various communication systems including:
- Newsletter subscribers and mailing list management
- User notifications for system alerts and events
- Webhooks for integration with external services
- Communication logging and auditing
- Scheduled communications and campaign management
- Communication channels and provider integrations
- User preference management for notifications and communications

These models enable comprehensive communication capabilities throughout the application
while maintaining proper separation of concerns and providing robust validation and
error handling.
"""

import logging
import json
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Union, Set

from flask import current_app, has_request_context, g, request
from extensions import db

# Create package-level logger
logger = logging.getLogger(__name__)

# Import models for external access
from .newsletter import Subscriber, MailingList, SubscriberList
from .notification import Notification
from .webhook import WebhookSubscription, WebhookDelivery
from .subscriber import Subscriber as SubscriberModel, SubscriberCategory
from .comm_log import CommunicationLog
from .comm_scheduler import CommunicationScheduler
from .comm_channel import CommunicationChannel
from .user_preference import (
    UserPreference,
    NotificationPreference,
    CommunicationPreference
)

# Define exports explicitly for better control over the public API
__all__ = [
    # Newsletter models
    "Subscriber",
    "MailingList",
    "SubscriberList",

    # Notification model
    "Notification",

    # Webhook models
    "WebhookSubscription",
    "WebhookDelivery",

    # Subscriber models (from subscriber.py)
    "SubscriberModel",
    "SubscriberCategory",

    # Communication logging
    "CommunicationLog",

    # Communication scheduling
    "CommunicationScheduler",

    # Communication channels
    "CommunicationChannel",

    # User preference models
    "UserPreference",
    "NotificationPreference",
    "CommunicationPreference",

    # Helper functions
    "get_default_channel",
    "get_notification_preferences",
    "send_notification",
    "log_communication",
    "get_active_channels"
]

# Package version information
__version__ = '0.1.1'

# Package initialization timestamp
__initialized_at__ = datetime.now(timezone.utc).isoformat()

def get_default_channel(channel_type: str = 'email') -> Optional[CommunicationChannel]:
    """Get the default communication channel for a given type."""
    try:
        # First try to get active default channel
        channel = CommunicationChannel.query.filter_by(
            channel_type=channel_type,
            is_active=True
        ).first()

        return channel
    except Exception as e:
        logger.error(f"Failed to get default channel for {channel_type}: {str(e)}")
        return None

def get_active_channels(security_level: Optional[str] = None) -> List[CommunicationChannel]:
    """
    Get all active communication channels, optionally filtered by security level.

    Args:
        security_level: Optional security level filter

    Returns:
        List of active communication channel objects
    """
    try:
        query = CommunicationChannel.query.filter_by(is_active=True)

        if security_level:
            query = query.filter_by(security_level=security_level)

        return query.all()
    except Exception as e:
        logger.error(f"Failed to get active channels: {str(e)}")
        return []

def get_notification_preferences(user_id: int) -> Dict[str, Any]:
    """
    Get notification preferences for a given user.

    Args:
        user_id: User ID to get preferences for

    Returns:
        Dictionary of notification preferences
    """
    try:
        # Try to get user preferences from the new model first
        pref = NotificationPreference.get_or_create(user_id)
        if pref:
            return pref.to_dict()

        # Return default preferences if not found
        return {
            'email_enabled': True,
            'sms_enabled': False,
            'push_enabled': False,
            'in_app_enabled': True,
            'webhook_enabled': False,
            'priority_threshold': 'low',
            'subscribed_categories': [
                'security',
                'system',
                'user'
            ],
            'disabled_types': [],
            'quiet_hours': {
                'enabled': False,
                'start': '22:00',
                'end': '07:00',
                'timezone': 'UTC'
            }
        }
    except Exception as e:
        logger.error(f"Failed to get notification preferences: {str(e)}")
        # Return default preferences on error
        return {
            'email_enabled': True,
            'in_app_enabled': True
        }

def send_notification(
    user_id: int,
    message: str,
    notification_type: str = "info",
    priority: str = "medium",
    title: Optional[str] = None,
    action_url: Optional[str] = None,
    expires_at: Optional[datetime] = None,
    data: Optional[Dict[str, Any]] = None,
    channels: Optional[List[str]] = None
) -> Optional[Notification]:
    """
    Send a notification to a user.

    Args:
        user_id: ID of the recipient user
        message: Notification message content
        notification_type: Type of notification
        priority: Priority level
        title: Optional notification title
        action_url: Optional URL for notification action
        expires_at: Optional expiration time
        data: Additional structured data for the notification
        channels: Optional list of delivery channels

    Returns:
        Created notification object or None if failed
    """
    try:
        # Get user notification preferences
        user_prefs = NotificationPreference.get_or_create(user_id)

        # Check if user should receive this notification based on preferences
        if not _should_send_notification(user_prefs, notification_type, priority):
            logger.debug(f"Notification skipped due to user preferences: user_id={user_id}, type={notification_type}")
            return None

        # Create notification object
        notification = Notification(
            user_id=user_id,
            message=message,
            notification_type=notification_type,
            priority=priority,
            title=title,
            action_url=action_url,
            expires_at=expires_at,
            data=data
        )

        # Determine delivery channels
        if not channels:
            channels = ["in_app"]
            if user_prefs.email_enabled:
                channels.append("email")
            if user_prefs.sms_enabled and priority in ('high', 'critical'):
                channels.append("sms")

        # Additional processing for delivery tracking
        if data is None:
            notification.data = {}

        # Save the notification
        db.session.add(notification)
        db.session.commit()

        # Process additional delivery channels
        _process_delivery_channels(notification, channels, user_id, message, notification_type, title)

        return notification

    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to create notification: {str(e)}")
        return None

def _should_send_notification(
    user_prefs: NotificationPreference,
    notification_type: str,
    priority: str
) -> bool:
    """
    Determine if notification should be sent based on user preferences.

    Args:
        user_prefs: User notification preferences
        notification_type: Type of notification
        priority: Priority level

    Returns:
        True if notification should be sent, False otherwise
    """
    # Skip if notification type is in disabled types
    disabled_types = user_prefs.disabled_types or []
    if notification_type in disabled_types:
        return False

    # Check priority threshold
    priority_levels = {
        'low': 0,
        'medium': 1,
        'high': 2,
        'critical': 3
    }

    user_threshold = user_prefs.priority_threshold or 'low'
    if priority_levels.get(priority, 0) < priority_levels.get(user_threshold, 0):
        return False

    # All checks passed
    return True

def _process_delivery_channels(
    notification: Notification,
    channels: List[str],
    user_id: int,
    message: str,
    notification_type: str,
    title: Optional[str]
) -> None:
    """Process additional delivery channels for a notification."""
    from models.auth import User

    # Only process if we have additional channels
    if not channels or 'in_app' == channels:
        return

    # Get user
    user = User.query.get(user_id)
    if not user:
        logger.warning(f"Cannot deliver notification: User ID {user_id} not found")
        return

    # Track delivery attempts
    delivery_info = {}

    # Handle email delivery
    if 'email' in channels and user.email:
        try:
            _handle_email_delivery(user, notification, message, notification_type, title, delivery_info)
        except Exception as e:
            logger.error(f"Failed to queue email notification: {str(e)}")

    # Handle SMS delivery
    if 'sms' in channels and hasattr(user, 'phone_number') and user.phone_number:
        try:
            _handle_sms_delivery(user, notification, message, notification_type, delivery_info)
        except Exception as e:
            logger.error(f"Failed to queue SMS notification: {str(e)}")

    # Handle push notification
    if 'push' in channels:
        try:
            _handle_push_delivery(user, notification, message, notification_type, title, delivery_info)
        except Exception as e:
            logger.error(f"Failed to queue push notification: {str(e)}")

    # Update notification with delivery information
    if delivery_info:
        notification.data = notification.data or {}
        notification.data['delivery'] = delivery_info
        db.session.commit()

def _handle_email_delivery(user, notification, message, notification_type, title, delivery_info):
    """Handle email delivery for a notification."""
    email_channel = get_default_channel('email')
    if email_channel:
        # Log email communication attempt
        log_communication(
            channel_type='email',
            recipient_address=user.email,
            recipient_id=user.id,
            message_type=notification_type,
            subject=title or f"{notification_type.capitalize()} Notification",
            content_snippet=message[:100] + ('...' if len(message) > 100 else '')
        )

        delivery_info['email'] = {
            'status': 'queued',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'channel_id': email_channel.id
        }

def _handle_sms_delivery(user, notification, message, notification_type, delivery_info):
    """Handle SMS delivery for a notification."""
    sms_channel = get_default_channel('sms')
    if sms_channel:
        # Log SMS communication attempt
        log_communication(
            channel_type='sms',
            recipient_address=user.phone_number,
            recipient_id=user.id,
            message_type=notification_type,
            content_snippet=message[:50] + ('...' if len(message) > 50 else '')
        )

        delivery_info['sms'] = {
            'status': 'queued',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'channel_id': sms_channel.id
        }

def _handle_push_delivery(user, notification, message, notification_type, title, delivery_info):
    """Handle push notification delivery."""
    push_channel = get_default_channel('push')
    if push_channel:
        # Log push communication attempt
        log_communication(
            channel_type='push',
            recipient_address=f'user:{user.id}',
            recipient_id=user.id,
            message_type=notification_type,
            subject=title,
            content_snippet=message[:50] + ('...' if len(message) > 50 else '')
        )

        delivery_info['push'] = {
            'status': 'queued',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'channel_id': push_channel.id
        }

def log_communication(
    channel_type: str,
    recipient_address: str,
    message_type: str,
    recipient_id: Optional[int] = None,
    subject: Optional[str] = None,
    content_snippet: Optional[str] = None,
    sender_id: Optional[int] = None,
    template_id: Optional[int] = None,
    message_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Optional[CommunicationLog]:
    """
    Log a communication attempt.

    Args:
        channel_type: Communication channel type
        recipient_address: Address where message is sent
        message_type: Type of message
        recipient_id: Optional recipient user ID
        subject: Optional message subject
        content_snippet: Optional content preview
        sender_id: Optional sender user ID
        template_id: Optional template ID
        message_id: Optional external message ID
        metadata: Additional metadata

    Returns:
        Created log entry or None if failed
    """
    try:
        # Determine recipient type
        recipient_type = 'user' if recipient_id else 'custom'

        # Create log entry
        log = CommunicationLog(
            channel_type=channel_type,
            recipient_type=recipient_type,
            recipient_address=recipient_address,
            recipient_id=recipient_id,
            message_type=message_type,
            subject=subject,
            content_snippet=content_snippet,
            sender_id=sender_id,
            template_id=template_id,
            message_id=message_id,
            metadata=metadata
        )

        db.session.add(log)
        db.session.commit()
        return log

    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to log communication: {str(e)}")
        return None

# Log package initialization
logger.debug(f"Communication models package {__version__} initialized - {len(__all__)} models available")
