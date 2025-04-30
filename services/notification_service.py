"""
Notification Service for the Cloud Infrastructure Platform.

This service centralizes the sending of various types of notifications,
including in-app messages, emails, SMS messages, and potentially other channels like webhooks.
It integrates with the Notification model and EmailService to provide a unified notification system
with proper error handling and delivery tracking.
"""

import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Union, Set, Tuple

from flask import current_app, has_app_context
from sqlalchemy.exc import SQLAlchemyError

from extensions import db, metrics, cache
from models.communication.notification import Notification
from services.email_service import EmailService, send_email, send_template_email
from models.user import User  # Assuming User model exists for fetching recipients
from core.security import sanitize_url, log_security_event

logger = logging.getLogger(__name__)

# Constants for delivery channels
CHANNEL_IN_APP = "in_app"
CHANNEL_EMAIL = "email"
CHANNEL_SMS = "sms"  # SMS delivery functionality
CHANNEL_WEBHOOK = "webhook"  # For future webhook integration

class NotificationService:
    """
    Provides methods for sending notifications through various channels.
    """

    @staticmethod
    def send_notification(
        user_ids: Union[int, List[int]],
        message: str,
        title: Optional[str] = None,
        notification_type: str = Notification.TYPE_INFO,
        priority: str = Notification.PRIORITY_MEDIUM,
        action_url: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        send_email: bool = False,
        email_subject: Optional[str] = None,
        email_template: Optional[str] = None,
        email_template_data: Optional[Dict[str, Any]] = None,
        email_content: Optional[str] = None,
        send_sms: bool = False,
        sms_message: Optional[str] = None,
        respect_preferences: bool = True,
        delivery_tracking_id: Optional[str] = None,
        expiry: Optional[int] = None  # Expiry in hours
    ) -> Dict[str, Any]:
        """
        Sends a notification, potentially via multiple channels (in-app, email, SMS).

        Args:
            user_ids: A single user ID or a list of user IDs to notify.
            message: The main content of the notification.
            title: Optional title for the notification (defaults based on type).
            notification_type: Type of notification (e.g., 'info', 'warning').
            priority: Priority level ('low', 'medium', 'high', 'critical').
            action_url: Optional URL for an action related to the notification.
            data: Optional dictionary for additional structured data.
            send_email: If True, also attempt to send an email notification.
            email_subject: Subject for the email notification. Required if send_email is True.
            email_template: Name of the email template to use.
            email_template_data: Data for the email template.
            email_content: Raw HTML or text content for the email (alternative to template).
            send_sms: If True, also attempt to send an SMS notification.
            sms_message: Optional SMS message content (defaults to truncated version of message).
            respect_preferences: If True, respects user notification preferences.
            delivery_tracking_id: Optional ID to track notification delivery across systems.
            expiry: Optional time in hours after which the notification expires.

        Returns:
            A dictionary containing the delivery status for each channel and overall success.
        """
        if isinstance(user_ids, int):
            user_ids = [user_ids]

        if not user_ids:
            logger.warning("No user IDs provided for notification.")
            return {
                'success': False,
                'in_app_success': False,
                'email_success': False,
                'sms_success': False,
                'error': 'No user IDs provided'
            }

        # Sanitize action URL if provided
        if action_url:
            action_url = sanitize_url(action_url)

        # Prepare expiration timestamp if provided
        expires_at = None
        if expiry is not None and expiry > 0:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=expiry)

        # Generate delivery tracking ID if not provided
        if delivery_tracking_id is None and hasattr(current_app, 'config'):
            import uuid
            delivery_tracking_id = f"notif-{uuid.uuid4().hex[:12]}"

        # Add delivery tracking ID to data if not already present
        if delivery_tracking_id:
            data = data or {}
            if 'delivery_tracking_id' not in data:
                data['delivery_tracking_id'] = delivery_tracking_id

        # If preferences should be respected, get eligible users
        if respect_preferences:
            try:
                user_ids = NotificationService._filter_by_preferences(
                    user_ids, notification_type, priority,
                    send_email, send_sms
                )
            except Exception as e:
                logger.error(f"Failed to filter users by preferences: {str(e)}")
                # Continue with original user list as fallback

        # Track results across channels
        results = {
            'success': False,
            'in_app_success': False,
            'email_success': False,
            'sms_success': False,
            'users': {
                'total': len(user_ids),
                'notified': 0
            }
        }

        # In-app notifications
        in_app_success = NotificationService.send_in_app_notification(
            user_ids=user_ids,
            message=message,
            title=title,
            notification_type=notification_type,
            priority=priority,
            action_url=action_url,
            data=data,
            expires_at=expires_at
        )
        results['in_app_success'] = in_app_success

        # Email notifications
        email_success = False
        if send_email and user_ids:
            if not email_subject:
                logger.warning("Email subject is required when send_email is True.")
            else:
                # Fetch user emails
                users = User.query.filter(User.id.in_(user_ids)).all()
                recipients = [user.email for user in users if user.email]

                if not recipients:
                    logger.warning("No valid email recipients found for the given user IDs.")
                else:
                    try:
                        if email_template and email_template_data is not None:
                            email_success = send_template_email(
                                to=recipients,
                                subject=email_subject,
                                template_name=email_template,
                                template_data=email_template_data,
                                priority=priority, # Pass priority to email service
                                tracking_id=delivery_tracking_id
                            )
                        elif email_content:
                            email_success = send_email(
                                to=recipients,
                                subject=email_subject,
                                html_content=email_content, # Assuming HTML, adjust if needed
                                priority=priority,
                                tracking_id=delivery_tracking_id
                            )
                        else:
                            # Fallback to sending the basic message as text content
                            email_success = send_email(
                                to=recipients,
                                subject=email_subject,
                                text_content=message,
                                priority=priority,
                                tracking_id=delivery_tracking_id
                            )
                        metrics.increment(f'notification.email.sent.{priority}')
                    except Exception as e:
                        logger.error(f"Failed to send email notification: {str(e)}")
                        metrics.increment(f'notification.email.failed.{priority}')

        results['email_success'] = email_success

        # SMS notifications
        sms_success = False
        if send_sms and user_ids:
            sms_success = NotificationService._send_sms_notification(
                user_ids=user_ids,
                message=sms_message or NotificationService._create_sms_content(message, title),
                priority=priority,
                tracking_id=delivery_tracking_id
            )
        results['sms_success'] = sms_success

        # Calculate overall success and user notification stats
        results['success'] = in_app_success or email_success or sms_success
        results['users']['notified'] = NotificationService._calculate_notified_users(
            user_ids, in_app_success, email_success, sms_success
        )

        # Log the overall notification result
        if results['success']:
            logger.info(
                f"Notification sent successfully via one or more channels. "
                f"Type: {notification_type}, Priority: {priority}, "
                f"Users: {results['users']['notified']}/{results['users']['total']}"
            )
            if delivery_tracking_id:
                logger.info(f"Notification tracking ID: {delivery_tracking_id}")
        else:
            logger.error(
                f"Failed to send notification via any channel. "
                f"Type: {notification_type}, Priority: {priority}"
            )

        return results

    @staticmethod
    def send_in_app_notification(
        user_ids: List[int],
        message: str,
        title: Optional[str] = None,
        notification_type: str = Notification.TYPE_INFO,
        priority: str = Notification.PRIORITY_MEDIUM,
        action_url: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        expires_at: Optional[datetime] = None
    ) -> bool:
        """
        Creates and saves in-app notifications for multiple users.

        Args:
            user_ids: List of user IDs to notify.
            message: The notification message content.
            title: Optional title.
            notification_type: Type of notification.
            priority: Priority level.
            action_url: Optional action URL.
            data: Optional structured data.
            expires_at: Optional expiration datetime.

        Returns:
            True if notifications were created successfully for at least one user, False otherwise.
        """
        success_count = 0
        for user_id in user_ids:
            try:
                notification = Notification.create_notification(
                    user_id=user_id,
                    message=message,
                    title=title,
                    notification_type=notification_type,
                    priority=priority,
                    action_url=action_url,
                    data=data,
                    expires_at=expires_at
                )
                if notification:
                    success_count += 1
                else:
                    logger.warning(f"Failed to create in-app notification for user {user_id} (returned None).")

            except SQLAlchemyError as e:
                db.session.rollback()
                logger.error(f"Database error creating in-app notification for user {user_id}: {str(e)}")
                metrics.increment('notification.in_app.db_error')
            except Exception as e:
                logger.error(f"Unexpected error creating in-app notification for user {user_id}: {str(e)}")
                metrics.increment('notification.in_app.error')

        if success_count > 0:
            logger.info(f"Successfully created {success_count}/{len(user_ids)} in-app notifications.")
            metrics.increment('notification.in_app.sent', success_count)
            return True
        else:
            logger.error(f"Failed to create any in-app notifications for user IDs: {user_ids}")
            return False

    @staticmethod
    def mark_notifications_as_read(user_id: int, notification_ids: Optional[List[int]] = None) -> int:
        """
        Marks specific notifications or all unread notifications as read for a user.

        Args:
            user_id: The ID of the user.
            notification_ids: A list of specific notification IDs to mark as read.
                              If None, marks all unread notifications for the user.

        Returns:
            The number of notifications marked as read.
        """
        try:
            query = Notification.query.filter_by(user_id=user_id, is_read=False)
            if notification_ids:
                query = query.filter(Notification.id.in_(notification_ids))

            updated_count = query.update(
                {Notification.is_read: True, Notification.read_at: datetime.now(timezone.utc)},
                synchronize_session=False
            )
            db.session.commit()
            logger.debug(f"Marked {updated_count} notifications as read for user {user_id}.")
            metrics.increment('notification.marked_read', updated_count)
            return updated_count
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error marking notifications as read for user {user_id}: {str(e)}")
            metrics.increment('notification.mark_read.db_error')
            return 0
        except Exception as e:
            logger.error(f"Unexpected error marking notifications as read for user {user_id}: {str(e)}")
            metrics.increment('notification.mark_read.error')
            return 0

    @staticmethod
    def send_batch_notification(
        user_groups: Dict[str, List[int]],
        base_message: str,
        notification_type: str = Notification.TYPE_INFO,
        priority: str = Notification.PRIORITY_MEDIUM,
        channels: Optional[List[str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Sends customized batch notifications to different user groups.

        Args:
            user_groups: Dictionary mapping group names to lists of user IDs
            base_message: Base message template to customize for each group
            notification_type: Type of notification
            priority: Priority level
            channels: List of delivery channels to use ('in_app', 'email', 'sms')
            **kwargs: Additional arguments to pass to send_notification

        Returns:
            Dictionary containing results for each batch
        """
        channels = channels or [CHANNEL_IN_APP]
        results = {}
        total_users = 0
        successful_deliveries = 0

        # Configure delivery channels
        send_email = CHANNEL_EMAIL in channels
        send_sms = CHANNEL_SMS in channels

        # Process each group
        for group_name, user_ids in user_groups.items():
            if not user_ids:
                continue

            total_users += len(user_ids)

            # Customize message for group if needed
            message = base_message
            if "{group}" in base_message:
                message = base_message.replace("{group}", group_name)

            # Prepare data with group information
            data = kwargs.get('data', {}) or {}
            data['user_group'] = group_name

            # Send notification to this group
            group_result = NotificationService.send_notification(
                user_ids=user_ids,
                message=message,
                notification_type=notification_type,
                priority=priority,
                send_email=send_email,
                send_sms=send_sms,
                data=data,
                **kwargs
            )

            results[group_name] = group_result
            if group_result.get('success', False):
                successful_deliveries += group_result.get('users', {}).get('notified', 0)

        # Aggregate results
        aggregate_results = {
            'total_groups': len(user_groups),
            'total_users': total_users,
            'successful_deliveries': successful_deliveries,
            'success_rate': (successful_deliveries / total_users * 100) if total_users > 0 else 0,
            'group_results': results
        }

        return aggregate_results

    @staticmethod
    def get_unread_count(user_id: int) -> int:
        """
        Get the count of unread notifications for a user.

        Args:
            user_id: The ID of the user

        Returns:
            Count of unread notifications
        """
        # Try to get from cache first for performance
        cache_key = f"notification:unread_count:{user_id}"

        if hasattr(current_app, 'cache'):
            cached_count = current_app.cache.get(cache_key)
            if cached_count is not None:
                return cached_count

        # If not in cache or no cache available, query the database
        try:
            count = Notification.get_unread_count(user_id)

            # Cache the result
            if hasattr(current_app, 'cache'):
                current_app.cache.set(cache_key, count, timeout=60)  # Cache for 1 minute

            return count
        except Exception as e:
            logger.error(f"Error getting unread notification count for user {user_id}: {str(e)}")
            return 0

    @staticmethod
    def clear_expired_notifications(days_threshold: int = 30) -> int:
        """
        Clear expired notifications from the database.

        Args:
            days_threshold: Age in days for notifications to be considered expired

        Returns:
            Number of notifications cleared
        """
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_threshold)

            # Delete expired notifications (those with explicit expiry)
            explicit_expired = Notification.query.filter(
                Notification.expires_at.isnot(None),
                Notification.expires_at < datetime.now(timezone.utc)
            ).delete(synchronize_session=False)

            # Delete old notifications
            old_notifications = Notification.query.filter(
                Notification.created_at < cutoff_date,
                Notification.is_read == True  # Only delete read notifications
            ).delete(synchronize_session=False)

            db.session.commit()

            cleared_count = explicit_expired + old_notifications
            logger.info(f"Cleared {cleared_count} expired notifications (explicit: {explicit_expired}, old: {old_notifications})")
            return cleared_count

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error clearing expired notifications: {str(e)}")
            return 0
        except Exception as e:
            logger.error(f"Unexpected error clearing expired notifications: {str(e)}")
            return 0

    @staticmethod
    def get_user_notification_history(
        user_id: int,
        page: int = 1,
        per_page: int = 20,
        include_read: bool = True
    ) -> Dict[str, Any]:
        """
        Get paginated notification history for a user.

        Args:
            user_id: The ID of the user
            page: Page number
            per_page: Number of items per page
            include_read: Whether to include read notifications

        Returns:
            Dictionary with notifications and pagination info
        """
        try:
            return Notification.get_all_for_user(
                user_id=user_id,
                page=page,
                per_page=per_page,
                include_read=include_read
            )
        except Exception as e:
            logger.error(f"Error getting notification history for user {user_id}: {str(e)}")
            return {
                'notifications': [],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': 0,
                    'total_pages': 0,
                    'has_next': False,
                    'has_prev': False
                },
                'error': str(e)
            }

    @staticmethod
    def _send_sms_notification(
        user_ids: List[int],
        message: str,
        priority: str,
        tracking_id: Optional[str] = None
    ) -> bool:
        """
        Sends SMS notifications to users.

        Args:
            user_ids: List of user IDs to notify
            message: SMS message content
            priority: Priority level
            tracking_id: Optional delivery tracking ID

        Returns:
            True if sent successfully to any user, False otherwise
        """
        if not user_ids:
            return False

        # Check if SMS service is configured
        sms_enabled = current_app.config.get('SMS_ENABLED', False) if has_app_context() else False
        if not sms_enabled:
            logger.warning("SMS notifications are not enabled in configuration")
            return False

        try:
            # Get phone numbers for the users
            users = User.query.filter(User.id.in_(user_ids)).all()
            recipients = []

            for user in users:
                # This assumes the User model has a phone_number field
                # Adjust according to your actual data model
                phone = getattr(user, 'phone_number', None)
                if phone and phone.strip():
                    recipients.append(phone)

            if not recipients:
                logger.warning("No valid phone numbers found for the given user IDs")
                return False

            # Import the SMS service (assumed to exist)
            try:
                from services.sms_service import send_sms

                # Send SMS to each recipient
                success_count = 0

                for recipient in recipients:
                    try:
                        result = send_sms(
                            to=recipient,
                            message=message,
                            priority=priority,
                            tracking_id=tracking_id
                        )
                        if result:
                            success_count += 1
                    except Exception as e:
                        logger.error(f"Failed to send SMS to {recipient}: {str(e)}")

                if success_count > 0:
                    logger.info(f"Successfully sent {success_count}/{len(recipients)} SMS notifications")
                    metrics.increment(f'notification.sms.sent.{priority}', success_count)
                    return True
                else:
                    logger.error("Failed to send any SMS notifications")
                    metrics.increment('notification.sms.failed')
                    return False

            except ImportError:
                logger.error("SMS service not available")
                return False

        except Exception as e:
            logger.error(f"Error sending SMS notifications: {str(e)}")
            metrics.increment('notification.sms.error')
            return False

    @staticmethod
    def _create_sms_content(message: str, title: Optional[str] = None) -> str:
        """
        Creates SMS-friendly content from notification message.

        Args:
            message: Original notification message
            title: Optional notification title

        Returns:
            SMS-friendly content
        """
        # Maximum SMS length (standard limit minus some buffer)
        MAX_SMS_LENGTH = 150

        content = ""
        if title:
            content = f"{title}: "

        content += message

        # Truncate if too long
        if len(content) > MAX_SMS_LENGTH:
            content = content[:MAX_SMS_LENGTH - 3] + "..."

        return content

    @staticmethod
    def _filter_by_preferences(
        user_ids: List[int],
        notification_type: str,
        priority: str,
        send_email: bool,
        send_sms: bool
    ) -> List[int]:
        """
        Filters users based on their notification preferences.

        Args:
            user_ids: List of user IDs to filter
            notification_type: Type of notification
            priority: Priority level
            send_email: Whether email is requested
            send_sms: Whether SMS is requested

        Returns:
            Filtered list of user IDs
        """
        # If notification preferences are not implemented yet, return all users
        try:
            from models.user_preference import NotificationPreference
        except ImportError:
            return user_ids

        filtered_user_ids = []

        try:
            # Get relevant preferences
            preferences = NotificationPreference.query.filter(
                NotificationPreference.user_id.in_(user_ids)
            ).all()

            # Group preferences by user ID
            preferences_by_user = {}
            for pref in preferences:
                if pref.user_id not in preferences_by_user:
                    preferences_by_user[pref.user_id] = pref

            # Check preferences for each user
            for user_id in user_ids:
                should_include = True

                # If user has preferences, check them
                if user_id in preferences_by_user:
                    pref = preferences_by_user[user_id]

                    # Check if this notification type is disabled
                    disabled_types = getattr(pref, 'disabled_types', []) or []
                    if notification_type in disabled_types:
                        should_include = False

                    # Check if this priority level is below user's threshold
                    priority_threshold = getattr(pref, 'priority_threshold', None)
                    if priority_threshold:
                        priority_level = {
                            Notification.PRIORITY_LOW: 0,
                            Notification.PRIORITY_MEDIUM: 1,
                            Notification.PRIORITY_HIGH: 2,
                            Notification.PRIORITY_CRITICAL: 3
                        }
                        if priority_level.get(priority, 0) < priority_level.get(priority_threshold, 0):
                            should_include = False

                    # Check if requested channels match user preferences
                    if send_email and not getattr(pref, 'email_enabled', True):
                        send_email = False

                    if send_sms and not getattr(pref, 'sms_enabled', False):
                        send_sms = False

                if should_include:
                    filtered_user_ids.append(user_id)

            return filtered_user_ids

        except Exception as e:
            logger.error(f"Error filtering users by notification preferences: {str(e)}")
            return user_ids  # Return original list on error

    @staticmethod
    def _calculate_notified_users(
        user_ids: List[int],
        in_app_success: bool,
        email_success: bool,
        sms_success: bool
    ) -> int:
        """
        Calculates how many users were successfully notified through any channel.

        This is an approximation since we can't easily determine per-user success rates.

        Args:
            user_ids: List of user IDs
            in_app_success: Whether in-app notifications succeeded
            email_success: Whether email notifications succeeded
            sms_success: Whether SMS notifications succeeded

        Returns:
            Estimated number of users notified
        """
        if not user_ids:
            return 0

        total = len(user_ids)

        # If all channels failed, no users were notified
        if not in_app_success and not email_success and not sms_success:
            return 0

        # If all channels succeeded, all users were notified
        if in_app_success and (not email_success and not sms_success):
            return total

        # Conservative estimate: at least half the users were likely notified
        # if one or more channels were successful
        return total // 2


# Helper functions for common notification types
def send_system_notification(user_ids: Union[int, List[int]], message: str, **kwargs) -> Dict[str, Any]:
    """
    Helper function to send a system notification.

    Args:
        user_ids: User ID or list of user IDs to notify
        message: Notification message
        **kwargs: Additional arguments for NotificationService.send_notification

    Returns:
        Dictionary containing delivery results
    """
    return NotificationService.send_notification(
        user_ids=user_ids,
        message=message,
        notification_type=Notification.TYPE_SYSTEM,
        **kwargs
    )


def send_security_alert(user_ids: Union[int, List[int]], message: str, **kwargs) -> Dict[str, Any]:
    """
    Helper function to send a security alert notification.

    Args:
        user_ids: User ID or list of user IDs to notify
        message: Alert message
        **kwargs: Additional arguments for NotificationService.send_notification

    Returns:
        Dictionary containing delivery results
    """
    # Ensure priority is high or critical for security alerts
    priority = kwargs.pop('priority', Notification.PRIORITY_HIGH)
    if priority not in [Notification.PRIORITY_HIGH, Notification.PRIORITY_CRITICAL]:
        priority = Notification.PRIORITY_HIGH

    # Ensure email notification for security alerts by default
    send_email = kwargs.pop('send_email', True)

    # Generate tracking ID if not provided
    if 'delivery_tracking_id' not in kwargs:
        import uuid
        kwargs['delivery_tracking_id'] = f"sec-alert-{uuid.uuid4().hex[:8]}"

    # Log security event
    try:
        log_security_event(
            event_type='security_alert_notification',
            description=message,
            severity=priority,
            details={'tracking_id': kwargs.get('delivery_tracking_id')}
        )
    except Exception as e:
        logger.warning(f"Failed to log security event: {e}")

    return NotificationService.send_notification(
        user_ids=user_ids,
        message=message,
        notification_type=Notification.TYPE_SECURITY_ALERT,
        priority=priority,
        send_email=send_email,
        **kwargs
    )


def send_success_notification(user_ids: Union[int, List[int]], message: str, **kwargs) -> Dict[str, Any]:
    """
    Helper function to send a success notification.

    Args:
        user_ids: User ID or list of user IDs to notify
        message: Success message
        **kwargs: Additional arguments for NotificationService.send_notification

    Returns:
        Dictionary containing delivery results
    """
    return NotificationService.send_notification(
        user_ids=user_ids,
        message=message,
        notification_type=Notification.TYPE_SUCCESS,
        priority=kwargs.pop('priority', Notification.PRIORITY_LOW),
        **kwargs
    )


def send_warning_notification(user_ids: Union[int, List[int]], message: str, **kwargs) -> Dict[str, Any]:
    """
    Helper function to send a warning notification.

    Args:
        user_ids: User ID or list of user IDs to notify
        message: Warning message
        **kwargs: Additional arguments for NotificationService.send_notification

    Returns:
        Dictionary containing delivery results
    """
    return NotificationService.send_notification(
        user_ids=user_ids,
        message=message,
        notification_type=Notification.TYPE_WARNING,
        priority=kwargs.pop('priority', Notification.PRIORITY_MEDIUM),
        **kwargs
    )


# Define what's exported from this module
__all__ = [
    'NotificationService',
    'send_system_notification',
    'send_security_alert',
    'send_success_notification',
    'send_warning_notification',
    'CHANNEL_IN_APP',
    'CHANNEL_EMAIL',
    'CHANNEL_SMS',
    'CHANNEL_WEBHOOK'
]
