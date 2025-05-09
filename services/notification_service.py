"""
Notification Service for the Cloud Infrastructure Platform.

This service centralizes the sending of various types of notifications,
including in-app messages, emails, SMS messages, and potentially other channels like webhooks.
It integrates with the Notification model and EmailService to provide a unified notification system
with proper error handling and delivery tracking.
"""

import logging
import json
import uuid
import pytz
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Union, Set, Tuple

from flask import current_app, has_app_context
from sqlalchemy.exc import SQLAlchemyError

from extensions import db, metrics, cache
from models.communication.notification import Notification
from models.communication.user_preference import NotificationPreference, UserPreference
from services.email_service import EmailService, send_email, send_template_email
from models import User
from core.security import sanitize_url, log_security_event

# Import service constants if available
try:
    from services.service_constants import (
        NOTIFICATION_CATEGORY_SYSTEM,
        NOTIFICATION_CATEGORY_SECURITY,
        NOTIFICATION_CATEGORY_USER,
        NOTIFICATION_CATEGORY_ADMIN,
        NOTIFICATION_CATEGORY_MAINTENANCE,
        NOTIFICATION_CATEGORY_MONITORING,
        NOTIFICATION_CATEGORY_COMPLIANCE,
        NOTIFICATION_CATEGORY_INTEGRITY,
        NOTIFICATION_CATEGORY_AUDIT,
        NOTIFICATION_CATEGORY_SCAN,
        NOTIFICATION_CATEGORY_VULNERABILITY,
        NOTIFICATION_CATEGORY_INCIDENT,
        NOTIFICATION_EXPIRY_DAYS,
    )
    SERVICE_CONSTANTS_AVAILABLE = True
except ImportError:
    # Default values if service_constants not available
    NOTIFICATION_CATEGORY_SYSTEM = 'system'
    NOTIFICATION_CATEGORY_SECURITY = 'security'
    NOTIFICATION_CATEGORY_USER = 'user'
    NOTIFICATION_CATEGORY_ADMIN = 'admin'
    NOTIFICATION_CATEGORY_MAINTENANCE = 'maintenance'
    NOTIFICATION_CATEGORY_MONITORING = 'monitoring'
    NOTIFICATION_CATEGORY_COMPLIANCE = 'compliance'
    NOTIFICATION_CATEGORY_INTEGRITY = 'integrity'
    NOTIFICATION_CATEGORY_AUDIT = 'audit'
    NOTIFICATION_CATEGORY_SCAN = 'scan'
    NOTIFICATION_CATEGORY_VULNERABILITY = 'vulnerability'
    NOTIFICATION_CATEGORY_INCIDENT = 'incident'
    NOTIFICATION_EXPIRY_DAYS = 30
    SERVICE_CONSTANTS_AVAILABLE = False

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
        expiry: Optional[int] = None,  # Expiry in hours
        category: Optional[str] = None  # Notification category for organization
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
            category: Notification category for organization and routing.

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
        elif hasattr(current_app, 'config'):
            # Use system default if configured
            default_expiry = current_app.config.get('NOTIFICATION_EXPIRY_DAYS', NOTIFICATION_EXPIRY_DAYS)
            if default_expiry > 0:
                expires_at = datetime.now(timezone.utc) + timedelta(days=default_expiry)

        # Generate delivery tracking ID if not provided
        if delivery_tracking_id is None:
            delivery_tracking_id = f"notif-{uuid.uuid4().hex[:12]}"

        # Add delivery tracking ID and category to data
        data = data or {}
        data['delivery_tracking_id'] = delivery_tracking_id

        # Add category information if provided
        if category:
            data['category'] = category

        # If preferences should be respected, get eligible users and their channel preferences
        eligible_user_ids = user_ids
        user_channel_prefs = {}

        if respect_preferences:
            try:
                eligible_user_ids, user_channel_prefs = NotificationService._filter_by_preferences(
                    user_ids, notification_type, priority, category,
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
            'webhook_success': False,
            'users': {
                'total': len(user_ids),
                'eligible': len(eligible_user_ids),
                'notified': 0
            },
            'tracking_id': delivery_tracking_id
        }

        if not eligible_user_ids:
            logger.info("No eligible users to notify based on preferences.")
            results['message'] = 'No eligible users based on preferences'
            return results

        # In-app notifications - only send to users whose preferences allow in-app
        in_app_user_ids = [uid for uid in eligible_user_ids
                          if uid not in user_channel_prefs or user_channel_prefs.get(uid, {}).get('in_app', True)]

        in_app_success = False
        if in_app_user_ids:
            in_app_success = NotificationService.send_in_app_notification(
                user_ids=in_app_user_ids,
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
        if send_email and eligible_user_ids:
            if not email_subject:
                logger.warning("Email subject is required when send_email is True.")
            else:
                # Filter users that allow email notifications
                email_user_ids = [uid for uid in eligible_user_ids
                                 if uid not in user_channel_prefs or user_channel_prefs.get(uid, {}).get('email', True)]

                if email_user_ids:
                    # Fetch user emails
                    users = User.query.filter(User.id.in_(email_user_ids)).all()
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
                                    priority=priority,  # Pass priority to email service
                                    tracking_id=delivery_tracking_id,
                                    category=category
                                )
                            elif email_content:
                                email_success = send_email(
                                    to=recipients,
                                    subject=email_subject,
                                    html_content=email_content,  # Assuming HTML, adjust if needed
                                    priority=priority,
                                    tracking_id=delivery_tracking_id,
                                    category=category
                                )
                            else:
                                # Fallback to sending the basic message as text content
                                email_success = send_email(
                                    to=recipients,
                                    subject=email_subject,
                                    text_content=message,
                                    priority=priority,
                                    tracking_id=delivery_tracking_id,
                                    category=category
                                )
                            metrics.increment(f'notification.email.sent.{priority}')
                        except Exception as e:
                            logger.error(f"Failed to send email notification: {str(e)}")
                            metrics.increment(f'notification.email.failed.{priority}')

        results['email_success'] = email_success

        # SMS notifications
        sms_success = False
        if send_sms and eligible_user_ids:
            # Filter users that have SMS enabled in their preferences
            sms_user_ids = [uid for uid in eligible_user_ids
                           if uid in user_channel_prefs and user_channel_prefs.get(uid, {}).get('sms', False)]

            if sms_user_ids:
                sms_success = NotificationService._send_sms_notification(
                    user_ids=sms_user_ids,
                    message=sms_message or NotificationService._create_sms_content(message, title),
                    priority=priority,
                    tracking_id=delivery_tracking_id,
                    category=category
                )
        results['sms_success'] = sms_success

        # Calculate overall success and user notification stats
        results['success'] = in_app_success or email_success or sms_success
        results['users']['notified'] = NotificationService._calculate_notified_users(
            eligible_user_ids, in_app_success, email_success, sms_success
        )

        # Log the overall notification result
        if results['success']:
            logger.info(
                f"Notification sent successfully via one or more channels. "
                f"Type: {notification_type}, Priority: {priority}, "
                f"Users: {results['users']['notified']}/{results['users']['eligible']} eligible "
                f"(of {results['users']['total']} total), "
                f"Category: {category or 'none'}"
            )
            logger.debug(f"Notification tracking ID: {delivery_tracking_id}")
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
    def get_user_preferences(user_id: int, create_if_missing: bool = True) -> Optional[Dict[str, Any]]:
        """
        Get notification preferences for a user.

        Args:
            user_id: The user ID
            create_if_missing: Whether to create default preferences if none exist

        Returns:
            Dictionary of user preferences or None if not found and not created
        """
        try:
            if create_if_missing:
                prefs = NotificationPreference.get_or_create(user_id)
            else:
                prefs = NotificationPreference.query.filter_by(user_id=user_id).first()

            if prefs:
                return prefs.to_dict()
            return None

        except Exception as e:
            logger.error(f"Error getting notification preferences for user {user_id}: {str(e)}")
            return None

    @staticmethod
    def update_user_preferences(
        user_id: int,
        preferences: Dict[str, Any],
        create_if_missing: bool = True
    ) -> bool:
        """
        Update notification preferences for a user.

        Args:
            user_id: The user ID
            preferences: Dictionary of preference updates
            create_if_missing: Whether to create preferences if none exist

        Returns:
            True if successful, False otherwise
        """
        try:
            if create_if_missing:
                prefs = NotificationPreference.get_or_create(user_id)
            else:
                prefs = NotificationPreference.query.filter_by(user_id=user_id).first()

            if not prefs:
                logger.warning(f"No notification preferences found for user {user_id}")
                return False

            result = prefs.update(preferences)

            if result:
                # Clear any cached unread counts
                cache_key = f"notification:unread_count:{user_id}"
                if hasattr(current_app, 'cache'):
                    current_app.cache.delete(cache_key)

            return result

        except Exception as e:
            logger.error(f"Error updating notification preferences for user {user_id}: {str(e)}")
            return False

    @staticmethod
    def get_subscribers_for_category(category: str) -> List[int]:
        """
        Get users subscribed to a specific notification category.

        Args:
            category: The notification category

        Returns:
            List of user IDs subscribed to the category
        """
        try:
            return NotificationPreference.get_subscribers_for_category(category)
        except Exception as e:
            logger.error(f"Error getting subscribers for category '{category}': {str(e)}")
            return []

    @staticmethod
    def _send_sms_notification(
        user_ids: List[int],
        message: str,
        priority: str,
        tracking_id: Optional[str] = None,
        category: Optional[str] = None
    ) -> bool:
        """
        Sends SMS notifications to users.

        Args:
            user_ids: List of user IDs to notify
            message: SMS message content
            priority: Priority level
            tracking_id: Optional delivery tracking ID
            category: Notification category for routing

        Returns:
            True if sent successfully to any user, False otherwise
        """
        # Implementation remains the same with added category parameter
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
                            tracking_id=tracking_id,
                            category=category
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
        category: Optional[str],
        send_email: bool,
        send_sms: bool
    ) -> Tuple[List[int], Dict[int, Dict[str, bool]]]:
        """
        Filters users based on their notification preferences and returns channel preferences.

        Args:
            user_ids: List of user IDs to filter
            notification_type: Type of notification
            priority: Priority level
            category: Notification category (optional)
            send_email: Whether email is requested
            send_sms: Whether SMS is requested

        Returns:
            Tuple containing:
            - List of filtered user IDs
            - Dictionary mapping user_id to channel preferences
        """
        # Initialize return values
        filtered_user_ids = []
        user_channel_prefs = {}

        try:
            # Get all notification preferences for the users
            preferences = NotificationPreference.query.filter(
                NotificationPreference.user_id.in_(user_ids)
            ).all()

            # Group preferences by user ID
            preferences_by_user = {}
            for pref in preferences:
                preferences_by_user[pref.user_id] = pref

            # Check preferences for each user
            for user_id in user_ids:
                should_include = True
                channel_prefs = {'in_app': True, 'email': send_email, 'sms': send_sms}

                # If user has preferences, check them
                if user_id in preferences_by_user:
                    pref = preferences_by_user[user_id]

                    # Check if this notification type is disabled
                    disabled_types = getattr(pref, 'disabled_types', []) or []
                    if notification_type in disabled_types:
                        should_include = False

                    # Check if category is in subscribed categories (if category is specified)
                    if category and (not pref.subscribed_categories or
                                    category not in pref.subscribed_categories):
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

                    # Check quiet hours
                    if should_include and getattr(pref, 'quiet_hours_enabled', False):
                        if NotificationService._is_quiet_hour(pref):
                            # During quiet hours, only include critical notifications
                            if priority != Notification.PRIORITY_CRITICAL:
                                should_include = False

                    # Check channel preferences
                    if should_include:
                        # Set channel preferences based on user's settings
                        channel_prefs['in_app'] = getattr(pref, 'in_app_enabled', True)
                        channel_prefs['email'] = getattr(pref, 'email_enabled', send_email)
                        channel_prefs['sms'] = getattr(pref, 'sms_enabled', send_sms)

                        # If all channels are disabled but the user should be included,
                        # at least enable in-app notifications as a fallback
                        if not any(channel_prefs.values()):
                            channel_prefs['in_app'] = True
                            logger.debug(f"All notification channels disabled for user {user_id}, "
                                         "enabling in-app notifications as fallback")

                if should_include:
                    filtered_user_ids.append(user_id)
                    user_channel_prefs[user_id] = channel_prefs

            return filtered_user_ids, user_channel_prefs

        except Exception as e:
            logger.error(f"Error filtering users by notification preferences: {str(e)}")
            # Return original list on error, with default channel preferences
            return user_ids, {uid: {'in_app': True, 'email': send_email, 'sms': send_sms} for uid in user_ids}

    @staticmethod
    def _is_quiet_hour(pref: NotificationPreference) -> bool:
        """
        Determine if current time is within a user's configured quiet hours.

        Args:
            pref: User's notification preference object

        Returns:
            True if current time is within quiet hours, False otherwise
        """
        if not getattr(pref, 'quiet_hours_enabled', False):
            return False

        try:
            from datetime import datetime, time

            # Get current time in user's timezone
            user_tz = pytz.timezone(getattr(pref, 'quiet_hours_timezone', 'UTC'))
            now = datetime.now(user_tz).time()

            # Parse quiet hours start/end times
            start_str = getattr(pref, 'quiet_hours_start', '22:00')
            end_str = getattr(pref, 'quiet_hours_end', '07:00')

            start_hour, start_min = map(int, start_str.split(':'))
            end_hour, end_min = map(int, end_str.split(':'))

            start_time = time(start_hour, start_min)
            end_time = time(end_hour, end_min)

            # Check if current time is in quiet hours
            if start_time <= end_time:
                # Simple case: quiet hours within same day
                return start_time <= now <= end_time
            else:
                # Complex case: quiet hours span midnight
                return now >= start_time or now <= end_time

        except Exception as e:
            logger.error(f"Error checking quiet hours: {str(e)}")
            return False

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

        # If all in-app notifications succeeded, we likely reached everyone
        if in_app_success:
            return total

        # If only email or SMS was successful, we likely reached a subset of users
        # Conservative estimate: about 75% for email, 50% for SMS
        if email_success and not sms_success:
            return int(total * 0.75)
        elif sms_success and not email_success:
            return int(total * 0.5)
        elif email_success and sms_success:
            return int(total * 0.9)  # Higher likelihood with multiple channels

        # Conservative fallback estimate
        return max(1, total // 3)


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
    # Set the category if not provided
    if 'category' not in kwargs:
        kwargs['category'] = NOTIFICATION_CATEGORY_SYSTEM

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

    # Set the category if not provided
    if 'category' not in kwargs:
        kwargs['category'] = NOTIFICATION_CATEGORY_SECURITY

    # Generate tracking ID if not provided
    if 'delivery_tracking_id' not in kwargs:
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
    """Helper function to send a success notification."""
    return NotificationService.send_notification(
        user_ids=user_ids,
        message=message,
        notification_type=Notification.TYPE_SUCCESS,
        priority=kwargs.pop('priority', Notification.PRIORITY_LOW),
        **kwargs
    )


def send_warning_notification(user_ids: Union[int, List[int]], message: str, **kwargs) -> Dict[str, Any]:
    """Helper function to send a warning notification."""
    return NotificationService.send_notification(
        user_ids=user_ids,
        message=message,
        notification_type=Notification.TYPE_WARNING,
        priority=kwargs.pop('priority', Notification.PRIORITY_MEDIUM),
        **kwargs
    )


def send_integrity_notification(user_ids: Union[int, List[int]], message: str, changes: List[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
    """
    Helper function to send a file integrity notification.

    Args:
        user_ids: User ID or list of user IDs to notify
        message: Notification message
        changes: Optional details of file integrity changes
        **kwargs: Additional arguments for NotificationService.send_notification

    Returns:
        Dictionary containing delivery results
    """
    # Set appropriate priority based on changes if possible
    priority = kwargs.pop('priority', None)
    if changes and not priority:
        # Determine priority based on severity of changes
        has_critical = any(change.get('severity') == 'critical' for change in changes if isinstance(change, dict))
        has_high = any(change.get('severity') == 'high' for change in changes if isinstance(change, dict))

        if has_critical:
            priority = Notification.PRIORITY_CRITICAL
        elif has_high:
            priority = Notification.PRIORITY_HIGH
        else:
            priority = Notification.PRIORITY_MEDIUM

    if not priority:
        priority = Notification.PRIORITY_MEDIUM

    # Set the category if not provided
    if 'category' not in kwargs:
        kwargs['category'] = NOTIFICATION_CATEGORY_INTEGRITY

    # Add changes to data if not already present
    data = kwargs.pop('data', {}) or {}
    if changes and 'changes' not in data:
        data['changes'] = changes

    if data:
        kwargs['data'] = data

    return NotificationService.send_notification(
        user_ids=user_ids,
        message=message,
        notification_type=Notification.TYPE_SECURITY_ALERT,
        priority=priority,
        send_email=kwargs.pop('send_email', True),
        **kwargs
    )


def send_user_notification(
    user_id: int,
    notification_type: str,
    data: Optional[Dict[str, Any]] = None,
    priority: str = Notification.PRIORITY_MEDIUM,
    send_email: bool = True
) -> bool:
    """
    Send a user account-related notification through appropriate channels.

    This is a specialized wrapper around the general notification system
    for user account management notifications such as account creation,
    password resets, and other user-specific events.
    """
    try:
        data = data or {}
        user = User.query.get(user_id)

        if not user:
            logger.error(f"Cannot send notification: User ID {user_id} not found")
            return False

        # Configure notification params based on notification_type
        if notification_type == "account_created":
            title = "Welcome to the Platform"
            message = f"Your account has been created successfully."
            email_subject = "Welcome - Your Account Has Been Created"
            email_template = "emails/account_created"

        elif notification_type == "password_reset":
            title = "Password Reset"
            message = "Your password has been reset by an administrator."
            email_subject = "Your Password Has Been Reset"
            email_template = "emails/password_reset"

        elif notification_type == "role_changed":
            title = "Role Assignment"
            message = f"Your role has been updated to {data.get('new_role', 'a new role')}."
            email_subject = "Your User Role Has Changed"
            email_template = "emails/role_changed"

        elif notification_type == "account_locked":
            title = "Account Locked"
            message = "Your account has been locked. Please contact an administrator."
            email_subject = "Your Account Has Been Locked"
            email_template = "emails/account_locked"
            priority = Notification.PRIORITY_HIGH

        elif notification_type == "account_unlocked":
            title = "Account Unlocked"
            message = "Your account has been unlocked and is now accessible."
            email_subject = "Your Account Has Been Unlocked"
            email_template = "emails/account_unlocked"

        else:
            # Generic user notification
            title = "Account Notification"
            message = "There's a new notification regarding your account."
            email_subject = "Account Notification"
            email_template = "emails/account_notification"

        # Add username and other standard fields to template data
        template_data = {
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name or user.username,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Merge with provided data
        template_data.update(data or {})

        # Send notification using the service
        result = NotificationService.send_notification(
            user_ids=user_id,
            message=message,
            title=title,
            notification_type=Notification.TYPE_USER_ACCOUNT,
            priority=priority,
            data=data,
            send_email=send_email,
            email_subject=email_subject,
            email_template=email_template,
            email_template_data=template_data,
            category=NOTIFICATION_CATEGORY_USER
        )

        # Log the notification
        logger.info(
            f"User notification sent: type={notification_type}, user_id={user_id}, "
            f"success={result.get('success', False)}"
        )

        # Return overall success status
        return result.get('success', False)

    except Exception as e:
        logger.error(f"Failed to send user notification: {str(e)}")
        metrics.increment('notification.user_notification_error')
        return False


# Define what's exported from this module
__all__ = [
    'NotificationService',
    'send_system_notification',
    'send_security_alert',
    'send_success_notification',
    'send_warning_notification',
    'send_user_notification',
    'send_integrity_notification',
    'CHANNEL_IN_APP',
    'CHANNEL_EMAIL',
    'CHANNEL_SMS',
    'CHANNEL_WEBHOOK',

    # Notification categories
    'NOTIFICATION_CATEGORY_SYSTEM',
    'NOTIFICATION_CATEGORY_SECURITY',
    'NOTIFICATION_CATEGORY_USER',
    'NOTIFICATION_CATEGORY_ADMIN',
    'NOTIFICATION_CATEGORY_MAINTENANCE',
    'NOTIFICATION_CATEGORY_MONITORING',
    'NOTIFICATION_CATEGORY_COMPLIANCE',
    'NOTIFICATION_CATEGORY_INTEGRITY',
    'NOTIFICATION_CATEGORY_AUDIT',
    'NOTIFICATION_CATEGORY_SCAN',
    'NOTIFICATION_CATEGORY_VULNERABILITY',
    'NOTIFICATION_CATEGORY_INCIDENT'
]
