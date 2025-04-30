"""
Notification Service for the Cloud Infrastructure Platform.

This service centralizes the sending of various types of notifications,
including in-app messages, emails, and potentially other channels like SMS or webhooks.
It integrates with the Notification model and EmailService.
"""

import logging
from typing import Dict, Any, Optional, List, Union

from flask import current_app
from sqlalchemy.exc import SQLAlchemyError

from extensions import db, metrics
from models.communication.notification import Notification
from services.email_service import EmailService, send_email, send_template_email
from models.user import User  # Assuming User model exists for fetching recipients

logger = logging.getLogger(__name__)

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
        email_content: Optional[str] = None
    ) -> bool:
        """
        Sends a notification, potentially via multiple channels (in-app, email).

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

        Returns:
            True if at least one notification channel succeeded, False otherwise.
        """
        if isinstance(user_ids, int):
            user_ids = [user_ids]

        if not user_ids:
            logger.warning("No user IDs provided for notification.")
            return False

        in_app_success = NotificationService.send_in_app_notification(
            user_ids=user_ids,
            message=message,
            title=title,
            notification_type=notification_type,
            priority=priority,
            action_url=action_url,
            data=data
        )

        email_success = False
        if send_email:
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
                                priority=priority # Pass priority to email service
                            )
                        elif email_content:
                            email_success = send_email(
                                to=recipients,
                                subject=email_subject,
                                html_content=email_content, # Assuming HTML, adjust if needed
                                priority=priority
                            )
                        else:
                            # Fallback to sending the basic message as text content
                             email_success = send_email(
                                to=recipients,
                                subject=email_subject,
                                text_content=message,
                                priority=priority
                            )
                        metrics.increment(f'notification.email.sent.{priority}')
                    except Exception as e:
                        logger.error(f"Failed to send email notification: {str(e)}")
                        metrics.increment(f'notification.email.failed.{priority}')

        return in_app_success or email_success

    @staticmethod
    def send_in_app_notification(
        user_ids: List[int],
        message: str,
        title: Optional[str] = None,
        notification_type: str = Notification.TYPE_INFO,
        priority: str = Notification.PRIORITY_MEDIUM,
        action_url: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None
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
                    data=data
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

# Example usage (for testing or direct calls if needed)
def send_system_notification(user_ids: Union[int, List[int]], message: str, **kwargs):
    """Helper function to send a system notification."""
    return NotificationService.send_notification(
        user_ids=user_ids,
        message=message,
        notification_type=Notification.TYPE_SYSTEM,
        **kwargs
    )

def send_security_alert(user_ids: Union[int, List[int]], message: str, **kwargs):
    """Helper function to send a security alert notification."""
    # Ensure priority is high or critical for security alerts
    priority = kwargs.pop('priority', Notification.PRIORITY_HIGH)
    if priority not in [Notification.PRIORITY_HIGH, Notification.PRIORITY_CRITICAL]:
        priority = Notification.PRIORITY_HIGH

    return NotificationService.send_notification(
        user_ids=user_ids,
        message=message,
        notification_type=Notification.TYPE_SECURITY_ALERT,
        priority=priority,
        send_email=True, # Often good to email security alerts
        **kwargs
    )

# Add __all__ if this becomes part of the services package export
__all__ = [
    'NotificationService',
    'send_system_notification',
    'send_security_alert'
]
