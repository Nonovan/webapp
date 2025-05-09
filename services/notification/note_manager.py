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
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Union, Set, Tuple

from flask import current_app

from services.notification_service import (
    NotificationService,
    send_system_notification,
    send_security_alert,
    send_success_notification,
    send_warning_notification,
    CHANNEL_IN_APP,
    CHANNEL_EMAIL,
    CHANNEL_SMS,
    CHANNEL_WEBHOOK
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

    # Category to notification level mapping
    CATEGORY_LEVEL_MAP = {
        'system': 'system',
        'security': 'security',
        'maintenance': 'info',
        'user': 'info',
        'admin': 'info',
        'monitoring': 'info',
        'compliance': 'warning',
        'integrity': 'security',
        'audit': 'info',
        'scan': 'info',
        'vulnerability': 'warning',
        'incident': 'critical'
    }

    def __init__(self):
        """Initialize the NotificationManager."""
        self.default_channels = [CHANNEL_IN_APP, CHANNEL_EMAIL]
        self.default_expiry = 72  # Default expiry in hours
        self.category_subscribers = {}  # Cache for category subscribers
        self._load_config()

    def _load_config(self):
        """Load notification configuration from app config if available."""
        if current_app:
            config = current_app.config.get('NOTIFICATION_MANAGER', {})
            self.default_channels = config.get('default_channels', self.default_channels)
            self.default_expiry = config.get('default_expiry_hours', 72)

            # Load any predefined category subscribers
            self.category_subscribers = config.get('category_subscribers', {})

            # Configure additional settings
            self.enable_webhooks = config.get('enable_webhooks', True)
            self.notification_retention = config.get('notification_retention_days', 30)

            # Log initialization
            if hasattr(current_app, 'logger'):
                current_app.logger.debug("NotificationManager initialized")

    def send(self, subject: str, body: str, level: str = 'info',
             recipients: Optional[Union[int, str, List[Union[int, str]]]] = None,
             channels: Optional[List[str]] = None,
             tags: Optional[Dict[str, Any]] = None,
             expiry_hours: Optional[int] = None,
             action_url: Optional[str] = None,
             send_email: Optional[bool] = None,
             email_template: Optional[str] = None,
             email_template_data: Optional[Dict[str, Any]] = None,
             webhook_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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
            email_template: Optional specific email template to use
            email_template_data: Optional template data for email rendering
            webhook_data: Optional additional data for webhook notifications

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

        # Add standard metadata
        data.update({
            "notification_timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "notification_type": notification_type
        })

        # Include severity mapping for security events if level indicates a security event
        if level in ('security', 'critical', 'error'):
            data["security_context"] = {
                "priority": priority,
                "timestamp_iso": datetime.now(timezone.utc).isoformat(),
                "environment": os.environ.get('ENVIRONMENT', 'unknown')
            }

        # Prepare email parameters
        email_subject = subject

        # Add category/level information to subject for certain notification types
        if level in ('warning', 'error', 'critical', 'security'):
            if not email_subject.startswith(f"[{level.upper()}]"):
                email_subject = f"[{level.upper()}] {email_subject}"

        # Prepare webhook data if needed
        if CHANNEL_WEBHOOK in channels and webhook_data:
            data.update({"webhook_data": webhook_data})

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

            # Log metrics for the notification
            self._log_notification_metrics(level, channels, result)

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

            # If level not specified but category is, use category's default level
            if level == 'info' and category in self.CATEGORY_LEVEL_MAP:
                level = self.CATEGORY_LEVEL_MAP[category]

        # Try to get stakeholders based on incident ID or category
        recipients = self._get_stakeholders(incident_id, category)

        # Select appropriate email template based on category
        email_template = None
        if category:
            if category == 'security':
                email_template = 'emails/security_alert'
            elif category == 'incident':
                email_template = 'emails/incident_notification'
            elif category == 'integrity':
                email_template = 'emails/integrity_violation'

        # For security-related categories, add webhook channel
        channels = None
        if category in ('security', 'incident', 'integrity', 'compliance'):
            channels = self.default_channels.copy()
            if CHANNEL_WEBHOOK not in channels and self.enable_webhooks:
                channels.append(CHANNEL_WEBHOOK)

        return self.send(
            subject=subject,
            body=message,
            level=level,
            recipients=recipients,
            tags=tags,
            channels=channels,
            email_template=email_template
        )

    def send_file_integrity_notification(self, changes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Send notification about file integrity changes.

        Args:
            changes: List of file changes detected

        Returns:
            Dictionary containing delivery results
        """
        if not changes:
            return {"success": True, "message": "No changes to notify"}

        # Count changes by severity
        severity_counts = {}
        for change in changes:
            severity = change.get('severity', 'medium')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Determine overall notification level based on highest severity
        level = 'info'
        if any(s == 'critical' for s in severity_counts.keys()):
            level = 'critical'
        elif any(s == 'high' for s in severity_counts.keys()):
            level = 'security'
        elif any(s == 'medium' for s in severity_counts.keys()):
            level = 'warning'

        # Create message and subject
        total_changes = sum(severity_counts.values())
        subject = f"File Integrity Alert: {total_changes} changes detected"

        # Create message body with summary
        message = f"File integrity monitoring has detected {total_changes} changes:\n\n"
        for severity, count in sorted(severity_counts.items(), key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x[0], 4)):
            message += f"- {count} {severity} severity changes\n"

        # Send to security stakeholders
        return self.send_to_stakeholders(
            subject=subject,
            message=message,
            level=level,
            category='integrity',
            tags={
                'category': 'integrity',
                'changes': changes,
                'file_count': total_changes
            }
        )

    def send_scan_notification(self, scan_id: str, scan_type: str, status: str,
                             findings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Send notification about security scan results.

        Args:
            scan_id: ID of the scan
            scan_type: Type of scan performed
            status: Status of the scan (completed, failed, etc.)
            findings: Optional findings from the scan

        Returns:
            Dictionary containing delivery results
        """
        # Determine level based on findings
        level = 'info'
        if status != 'completed':
            level = 'warning'
        elif findings:
            critical_count = findings.get('critical', 0)
            high_count = findings.get('high', 0)

            if critical_count > 0:
                level = 'critical'
            elif high_count > 0:
                level = 'security'

        # Create subject
        subject = f"Security Scan {status.capitalize()}: {scan_type}"

        # Create message
        message = f"Security scan {scan_id} ({scan_type}) has {status}.\n\n"

        if findings:
            message += "Findings summary:\n"
            for severity, count in findings.items():
                if count > 0:
                    message += f"- {count} {severity} findings\n"

        # Send notification
        return self.send_to_stakeholders(
            subject=subject,
            message=message,
            level=level,
            category='scan',
            tags={
                'category': 'scan',
                'scan_id': scan_id,
                'scan_type': scan_type,
                'scan_status': status,
                'findings': findings
            }
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
                user_id = self._resolve_user_from_identifier(recipient)
                if user_id:
                    user_ids.append(user_id)
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

                    # Add watchers/subscribers if the model supports it
                    if hasattr(incident, 'subscribers') and incident.subscribers:
                        for subscriber_id in incident.subscribers:
                            stakeholders.add(subscriber_id)

                    # Add responders if the model supports it
                    if hasattr(incident, 'responders') and incident.responders:
                        for responder_id in incident.responders:
                            stakeholders.add(responder_id)
            except ImportError:
                logger.debug("Security models not available, can't find incident stakeholders")

        # Try to find subscribers for the category
        if category:
            # First check for any category subscribers in config
            if category in self.category_subscribers:
                preconfigured_subscribers = self.category_subscribers.get(category, [])
                for subscriber in preconfigured_subscribers:
                    user_id = self._resolve_user_from_identifier(subscriber)
                    if user_id:
                        stakeholders.add(user_id)

            try:
                # Try to find subscribers in notification preferences
                from models.communication.notification_preference import NotificationPreference

                prefs = NotificationPreference.query.filter(
                    NotificationPreference.subscribed_categories.contains(category)
                ).all()

                for pref in prefs:
                    stakeholders.add(pref.user_id)
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

    def _log_notification_metrics(self, level: str, channels: List[str], result: Dict[str, Any]) -> None:
        """
        Log metrics about notification delivery.

        Args:
            level: Notification level
            channels: Channels used
            result: Delivery results
        """
        try:
            if not METRICS_AVAILABLE:
                return

            # Import metrics
            from core.metrics import metrics

            # Log basic success/failure
            if result.get('success', False):
                metrics.increment('notification.sent.success', tags={'level': level})
            else:
                metrics.increment('notification.sent.failure', tags={'level': level})

            # Log by channel
            for channel in channels:
                channel_success = False
                if channel == CHANNEL_IN_APP:
                    channel_success = result.get('in_app_success', False)
                elif channel == CHANNEL_EMAIL:
                    channel_success = result.get('email_success', False)
                elif channel == CHANNEL_SMS:
                    channel_success = result.get('sms_success', False)

                metrics.increment(f'notification.channel.{channel}',
                           tags={'success': channel_success, 'level': level})

            # Log notification count
            notified_users = result.get('users', {}).get('notified', 0)
            metrics.gauge('notification.recipients', notified_users)

        except Exception as e:
            logger.debug(f"Error logging notification metrics: {e}")


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

__all__ = [
    'NotificationManager',
    'notification_manager',
    'notify_stakeholders'
]

# Check if metrics module is available
try:
    from core.metrics import metrics
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False
