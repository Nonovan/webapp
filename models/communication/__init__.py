"""
Communication models package for the Cloud Infrastructure Platform.

This package contains models related to various communication systems including:
- Newsletter subscribers and mailing list management
- User notifications for system alerts and events
- Webhooks for integration with external services
- Communication logging and auditing
- Scheduled communications and campaign management
- Communication channels and provider integrations

These models enable comprehensive communication capabilities throughout the application
while maintaining proper separation of concerns and providing robust validation and
error handling.
"""

import logging
import json
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Union, Set

from flask import current_app, has_request_context

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
    """
    Get the default communication channel for a specific type.

    Args:
        channel_type: Type of channel to retrieve (email, sms, etc.)

    Returns:
        CommunicationChannel: Default channel for the specified type or None if not found
    """
    try:
        return CommunicationChannel.query.filter_by(
            channel_type=channel_type,
            is_active=True
        ).order_by(CommunicationChannel.priority.desc()).first()
    except Exception as e:
        logger.error(f"Failed to get default channel: {str(e)}")
        return None

def get_active_channels(security_level: str = None) -> List[CommunicationChannel]:
    """
    Get all active communication channels, optionally filtered by security level.

    Args:
        security_level: Minimum security level required (low, medium, high, critical)

    Returns:
        List of active communication channels
    """
    try:
        query = CommunicationChannel.query.filter_by(is_active=True)

        if security_level:
            # Map security levels to their priorities for comparison
            security_levels = {
                'low': 0,
                'medium': 1,
                'high': 2,
                'critical': 3
            }

            level_value = security_levels.get(security_level.lower(), 1)
            # Filter channels with equal or higher security level
            eligible_levels = [k for k, v in security_levels.items() if v >= level_value]
            query = query.filter(CommunicationChannel.security_level.in_(eligible_levels))

        return query.order_by(CommunicationChannel.channel_type).all()
    except Exception as e:
        logger.error(f"Failed to get active channels: {str(e)}")
        return []

def get_notification_preferences(user_id: int) -> Dict[str, Any]:
    """
    Get notification preferences for a user.

    Args:
        user_id: User ID to retrieve preferences for

    Returns:
        dict: User's notification preferences or default preferences if not set
    """
    try:
        from models.auth import User
        user = User.query.get(user_id)
        if not user:
            logger.warning(f"User not found: {user_id}")
            return {}

        # Get preferences from user model or preferences table
        if hasattr(user, 'notification_preferences'):
            if user.notification_preferences:
                return user.notification_preferences

        # Check system config for default preferences
        if has_request_context() or current_app:
            from models.security import SystemConfig
            default_prefs = SystemConfig.get('default_notification_preferences')
            if default_prefs:
                return default_prefs

        # Return basic default preferences
        return {
            'email': True,
            'in_app': True,
            'push': False,
            'sms': False
        }

    except Exception as e:
        logger.error(f"Failed to get notification preferences: {str(e)}")
        return {}

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
    Send a notification to a user through appropriate channels.

    This is a convenience function that creates a notification and handles
    delivery through the configured channels based on user preferences.

    Args:
        user_id: ID of the recipient user
        message: Notification message content
        notification_type: Type of notification (info, warning, error, etc.)
        priority: Priority level (low, medium, high, critical)
        title: Optional notification title
        action_url: Optional URL for notification action
        expires_at: Optional expiration datetime
        data: Additional structured data for the notification
        channels: Optional list of delivery channels to use

    Returns:
        Created notification object or None if creation failed
    """
    try:
        from extensions import db

        # Create notification record
        notification = Notification(
            user_id=user_id,
            message=message,
            notification_type=notification_type,
            priority=priority,
            title=title,
            action_url=action_url,
            expires_at=expires_at,
            data=data or {}
        )

        # Get user preferences for channels if not explicitly provided
        user_preferences = None
        if not channels:
            user_preferences = get_notification_preferences(user_id)
            channels = [channel for channel, enabled in user_preferences.items() if enabled]

        # Save the notification (creates in-app notification)
        db.session.add(notification)
        db.session.commit()

        # Process additional delivery channels if needed
        if channels and any(channel != 'in_app' for channel in channels):
            from models.auth import User
            user = User.query.get(user_id)
            if not user:
                logger.warning(f"Cannot deliver notification: User ID {user_id} not found")
                return notification

            # Track delivery attempts
            delivery_info = {}

            # Handle email delivery if enabled
            if 'email' in channels and user.email:
                try:
                    email_channel = get_default_channel('email')
                    if email_channel:
                        # Log email communication attempt
                        log_communication(
                            channel_type='email',
                            recipient_address=user.email,
                            recipient_id=user_id,
                            message_type=notification_type,
                            subject=title or f"{notification_type.capitalize()} Notification",
                            content_snippet=message[:100] + ('...' if len(message) > 100 else '')
                        )

                        delivery_info['email'] = {
                            'status': 'queued',
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                            'channel_id': email_channel.id
                        }
                except Exception as e:
                    logger.error(f"Failed to queue email notification: {str(e)}")

            # Handle SMS delivery if enabled
            if 'sms' in channels and hasattr(user, 'phone_number') and user.phone_number:
                try:
                    sms_channel = get_default_channel('sms')
                    if sms_channel:
                        # Log SMS communication attempt
                        log_communication(
                            channel_type='sms',
                            recipient_address=user.phone_number,
                            recipient_id=user_id,
                            message_type=notification_type,
                            content_snippet=message[:50] + ('...' if len(message) > 50 else '')
                        )

                        delivery_info['sms'] = {
                            'status': 'queued',
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                            'channel_id': sms_channel.id
                        }
                except Exception as e:
                    logger.error(f"Failed to queue SMS notification: {str(e)}")

            # Handle push notification if enabled
            if 'push' in channels and hasattr(user, 'push_token') and user.push_token:
                try:
                    push_channel = get_default_channel('push')
                    if push_channel:
                        # Log push communication attempt
                        log_communication(
                            channel_type='push',
                            recipient_address=f"user:{user_id}",
                            recipient_id=user_id,
                            message_type=notification_type,
                            subject=title or f"{notification_type.capitalize()} Notification",
                            content_snippet=message[:50] + ('...' if len(message) > 50 else '')
                        )

                        delivery_info['push'] = {
                            'status': 'queued',
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                            'channel_id': push_channel.id
                        }
                except Exception as e:
                    logger.error(f"Failed to queue push notification: {str(e)}")

            # Update notification with delivery information
            if delivery_info:
                notification.data = notification.data or {}
                notification.data['delivery'] = delivery_info
                db.session.commit()

        return notification

    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")
        if 'db' in locals() and hasattr(db, 'session'):
            db.session.rollback()
        return None

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
    Log a communication record for audit and tracking purposes.

    This is a convenience wrapper around CommunicationLog.log_communication.

    Args:
        channel_type: Type of communication channel used
        recipient_address: Address the message was sent to
        message_type: Type of message sent
        recipient_id: Optional ID of the recipient user
        subject: Optional message subject or title
        content_snippet: Optional brief excerpt of the content
        sender_id: Optional ID of the sender user
        template_id: Optional ID of the template used
        message_id: Optional external message ID from provider
        metadata: Optional additional tracking metadata

    Returns:
        Created communication log entry or None if creation failed
    """
    try:
        # Determine recipient type from address format
        if recipient_id is not None:
            recipient_type = CommunicationLog.RECIPIENT_USER
        elif '@' in recipient_address:
            recipient_type = CommunicationLog.RECIPIENT_USER
        elif recipient_address.startswith('+') or recipient_address.isdigit():
            recipient_type = CommunicationLog.RECIPIENT_CONTACT
        else:
            recipient_type = CommunicationLog.RECIPIENT_CUSTOM

        return CommunicationLog.log_communication(
            channel_type=channel_type,
            recipient_type=recipient_type,
            recipient_address=recipient_address,
            message_type=message_type,
            recipient_id=recipient_id,
            subject=subject,
            content_snippet=content_snippet,
            sender_id=sender_id,
            template_id=template_id,
            message_id=message_id,
            metadata=metadata
        )
    except Exception as e:
        logger.error(f"Failed to log communication: {str(e)}")
        return None

# Log package initialization
logger.debug(f"Communication models package {__version__} initialized")
