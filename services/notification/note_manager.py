"""
Notification Manager for the Cloud Infrastructure Platform.

This module provides a centralized notification management system that abstracts
the underlying notification delivery mechanisms and provides a simpler interface
for sending notifications across various channels.

The NotificationManager integrates with the core NotificationService while adding
additional features like category-based routing, enhanced tagging, and simplified
interfaces for common notification patterns.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Union, Set

from flask import current_app

from services.notification_service import (
    NotificationService,
    send_system_notification,
    send_security_alert,
    send_success_notification,
    send_warning_notification,
    CHANNEL_IN_APP,
    CHANNEL_EMAIL,
    CHANNEL_SMS
)
from models.communication.notification import Notification


logger = logging.getLogger(__name__)


class NotificationManager:
    """
    Manages notifications across multiple channels and provides simplified interfaces
    for common notification patterns.

    This class acts as a facade for the underlying NotificationService, adding
    additional functionality like notification categorization, recipient group
    management, and standardized formatting.
    """

    # Level to notification type mapping
    LEVEL_TYPE_MAP = {
        'info': Notification.TYPE_INFO,
        'success': Notification.TYPE_SUCCESS,
        'warning': Notification.TYPE_WARNING,
        'error': Notification.TYPE_ERROR,
        'critical': Notification.TYPE_SECURITY_ALERT,
        'system': Notification.TYPE_SYSTEM,
        'security': Notification.TYPE_SECURITY_ALERT,
    }

    # Level to priority mapping
    LEVEL_PRIORITY_MAP = {
        'info': Notification.PRIORITY_LOW,
        'success': Notification.PRIORITY_LOW,
        'warning': Notification.PRIORITY_MEDIUM,
        'error': Notification.PRIORITY_HIGH,
        'critical': Notification.PRIORITY_CRITICAL,
        'system': Notification.PRIORITY_MEDIUM,
        'security': Notification.PRIORITY_HIGH,
    }

    # Level to helper function mapping
    LEVEL_FUNCTION_MAP = {
        'info': NotificationService.send_notification,
        'success': send_success_notification,
        'warning': send_warning_notification,
        'error': send_security_alert,
        'critical': send_security_alert,
        'system': send_system_notification,
        'security': send_security_alert,
    }

    def __init__(self):
        """Initialize the NotificationManager."""
        self.default_channels = [CHANNEL_IN_APP, CHANNEL_EMAIL]
        self._load_config()

    def _load_config(self):
        """Load notification configuration from app config if available."""
        if not current_app:
            return

        config = current_app.config.get('NOTIFICATION_MANAGER', {})
        self.default_channels = config.get('default_channels', self.default_channels)
        self.default_expiry = config.get('default_expiry_hours', 72)

        # Log initialization
        if hasattr(current_app, 'logger'):
            current_app.logger.debug("NotificationManager initialized")

    def send(self, subject: str, body: str, level: str = 'info',
             recipients: Optional[Union[int, str, List[Union[int, str]]]] = None,
             channels: Optional[List[str]] = None,
             tags: Optional[Dict[str, Any]] = None,
             expiry_hours: Optional[int] = None,
             action_url: Optional[str] = None,
             send_email: Optional[bool] = None) -> Dict[str, Any]:
        """
        Send a notification to one or more recipients.

        Args:
            subject: The notification subject/title
            body: The notification message
            level: Notification level (info, success, warning, error, critical, system, security)
            recipients: User ID(s), email address(es), or other identifiers for recipients
            channels: List of delivery channels to use
            tags: Dictionary of tags to attach to the notification for categorization
            expiry_hours: Hours until the notification expires
            action_url: URL for action buttons
            send_email: Override to explicitly enable/disable email

        Returns:
            Dictionary containing delivery results
        """
        # Normalize level
        level = level.lower() if level else 'info'
        if level not in self.LEVEL_TYPE_MAP:
            level = 'info'

        # Map level to notification type and priority
        notification_type = self.LEVEL_TYPE_MAP.get(level, Notification.TYPE_INFO)
        priority = self.LEVEL_PRIORITY_MAP.get(level, Notification.PRIORITY_MEDIUM)

        # Normalize recipients
        user_ids = self._normalize_recipients(recipients)
        if not user_ids:
            logger.warning("No valid recipients specified for notification")
            return {"success": False, "error": "No valid recipients"}

        # Handle channels
        if channels is None:
            channels = self.default_channels

        # Handle expiry
        if expiry_hours is None:
            expiry_hours = self.default_expiry

        expires_at = None
        if expiry_hours:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=expiry_hours)

        # Prepare data including tags
        data = tags or {}

        # Prepare email parameters
        email_subject = subject
        email_template = None
        email_template_data = None

        # Determine if we should send email
        should_send_email = send_email if send_email is not None else (CHANNEL_EMAIL in channels)

        # Use the appropriate helper function based on level
        notification_function = self.LEVEL_FUNCTION_MAP.get(level, NotificationService.send_notification)

        # Send notification
        try:
            result = notification_function(
                user_ids=user_ids,
                message=body,
                title=subject,
                notification_type=notification_type,
                priority=priority,
                action_url=action_url,
                data=data,
                send_email=should_send_email,
                email_subject=email_subject,
                email_template=email_template,
                email_template_data=email_template_data,
                expiry=expiry_hours
            )

            logger.debug(f"Notification sent with level {level}, success: {result.get('success', False)}")
            return result
        except Exception as e:
            logger.error(f"Error sending notification: {str(e)}")
            return {"success": False, "error": str(e)}

    def send_to_stakeholders(self, subject: str, message: str, level: str = 'info',
                            incident_id: Optional[str] = None,
                            category: Optional[str] = None) -> Dict[str, Any]:
        """
        Send notification to incident stakeholders or category subscribers.

        This is particularly useful for incident response communications.

        Args:
            subject: Notification subject/title
            message: Notification message
            level: Notification level
            incident_id: Optional incident ID for tracking
            category: Optional category to determine appropriate stakeholders

        Returns:
            Dictionary containing delivery results
        """
        tags = {}
        if incident_id:
            tags["incident_id"] = incident_id
        if category:
            tags["category"] = category

        # Try to get stakeholders based on incident ID or category
        recipients = self._get_stakeholders(incident_id, category)

        return self.send(
            subject=subject,
            body=message,
            level=level,
            recipients=recipients,
            tags=tags
        )

    def _normalize_recipients(self, recipients: Optional[Union[int, str, List[Union[int, str]]]]) -> List[int]:
        """
        Normalize recipients to a list of user IDs.

        Args:
            recipients: User ID(s), email address(es), or other identifiers

        Returns:
            List of user IDs
        """
        if recipients is None:
            # Default to empty list
            return []

        # Handle single recipient
        if isinstance(recipients, (int, str)):
            recipients = [recipients]

        # Convert to list of user IDs
        user_ids = []
        for recipient in recipients:
            if isinstance(recipient, int):
                # Already a user ID
                user_ids.append(recipient)
            elif isinstance(recipient, str):
                # Could be an email or username, try to resolve
                user = self._resolve_user_from_identifier(recipient)
                if user:
                    user_ids.append(user)
                else:
                    logger.warning(f"Could not resolve recipient: {recipient}")

        return user_ids

    def _resolve_user_from_identifier(self, identifier: str) -> Optional[int]:
        """
        Resolve a user ID from an identifier like email, username, etc.

        Args:
            identifier: Email, username or other identifier

        Returns:
            User ID if found, None otherwise
        """
        try:
            # Try to look up by email first
            from models.auth.user import User

            # Check if the identifier looks like an email
            if '@' in identifier:
                user = User.query.filter_by(email=identifier).first()
                if user:
                    return user.id

            # Next, try by username
            user = User.query.filter_by(username=identifier).first()
            if user:
                return user.id

            # If still not found but it's an integer string, try direct ID
            if identifier.isdigit():
                user_id = int(identifier)
                user = User.query.get(user_id)
                if user:
                    return user.id

            return None
        except Exception as e:
            logger.error(f"Error resolving user from identifier '{identifier}': {e}")
            return None

    def _get_stakeholders(self, incident_id: Optional[str] = None,
                         category: Optional[str] = None) -> List[int]:
        """
        Get appropriate stakeholders based on incident ID or category.

        Args:
            incident_id: Optional incident ID to find stakeholders for
            category: Optional category of notification to find subscribers

        Returns:
            List of user IDs for stakeholders/subscribers
        """
        stakeholders = set()

        # Try to find stakeholders for the incident
        if incident_id:
            try:
                # Try to find incident stakeholders from security models
                from models.security import SecurityIncident

                incident = SecurityIncident.query.filter_by(external_id=incident_id).first()
                if incident:
                    # Add assignee
                    if incident.assigned_to:
                        stakeholders.add(incident.assigned_to)

                    # Add creator
                    if incident.user_id:
                        stakeholders.add(incident.user_id)

                    # Add resolver if exists
                    if incident.resolved_by:
                        stakeholders.add(incident.resolved_by)
            except ImportError:
                logger.debug("Security models not available, can't find incident stakeholders")

        # Try to find subscribers for the category
        if category:
            try:
                # This would depend on your notification preferences model
                # For now, this is a placeholder
                pass
            except Exception as e:
                logger.debug(f"Error finding category subscribers: {e}")

        # If we don't have specific stakeholders, get admins/security team
        if not stakeholders:
            try:
                # Find users with security or admin roles
                from models.auth.user import User
                from models.auth.role import Role

                security_roles = Role.query.filter(
                    Role.name.in_(['security', 'admin', 'incident_responder'])
                ).all()

                if security_roles:
                    role_ids = [role.id for role in security_roles]
                    users = User.query.filter(
                        User.roles.any(Role.id.in_(role_ids))
                    ).all()

                    for user in users:
                        stakeholders.add(user.id)
            except Exception as e:
                logger.debug(f"Error finding security team: {e}")

        return list(stakeholders)


# Singleton instance for easy import
notification_manager = NotificationManager()


# Helper function for backward compatibility with old response coordination module
def notify_stakeholders(subject: str, message: str, level: str = 'info',
                       recipients: Optional[List[str]] = None,
                       incident_id: Optional[str] = None):
    """
    Send notification to incident stakeholders.

    This function maintains compatibility with the older notification system
    used in the incident response toolkit.

    Args:
        subject: Notification subject
        message: Notification message
        level: Notification level
        recipients: Optional list of recipient emails
        incident_id: Optional incident ID
    """
    return notification_manager.send(
        subject=subject,
        body=message,
        level=level,
        recipients=recipients,
        tags={"incident_id": incident_id} if incident_id else None
    )
