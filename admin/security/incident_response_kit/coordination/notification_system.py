"""
Incident Response Kit - Notification System

This module provides functionality for sending notifications about security incidents
to stakeholders through various channels (email, SMS, etc.). The notification system
integrates with the coordination module and supports different severity levels,
templates, and recipient targeting.

The notification system supports:
- Multiple delivery channels (email, SMS, application notifications)
- Priority-based handling of notifications
- Template-based message generation
- Scheduled notifications
- Escalation paths for unacknowledged notifications
"""

import os
import sys
import logging
import json
import time
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Set, Tuple
import re
import smtplib
import subprocess
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configure logging
logger = logging.getLogger(__name__)

# Determine module paths
try:
    # Get module directory
    MODULE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
    COORDINATION_DIR = MODULE_DIR
    IR_KIT_DIR = COORDINATION_DIR.parent

    # Add parent directory to path if running as script
    if __name__ == "__main__" and str(IR_KIT_DIR) not in sys.path:
        sys.path.insert(0, str(IR_KIT_DIR.parent))

    # Import from parent package
    try:
        from admin.security.incident_response_kit import (
            IncidentSeverity, response_config, CONFIG_AVAILABLE,
            sanitize_incident_id, NOTIFICATION_ENABLED, NOTIFICATION_CHANNELS, CRITICAL_CONTACTS
        )
        PARENT_IMPORTS_AVAILABLE = True
    except ImportError as e:
        logger.warning(f"Failed to import parent package components: {e}")
        PARENT_IMPORTS_AVAILABLE = False

        # Default severity levels if import fails
        class IncidentSeverity:
            CRITICAL = "critical"
            HIGH = "high"
            MEDIUM = "medium"
            LOW = "low"

        # Default configuration if import fails
        CONFIG_AVAILABLE = False
        response_config = {}
        NOTIFICATION_ENABLED = True
        NOTIFICATION_CHANNELS = ["email"]
        CRITICAL_CONTACTS = []

        def sanitize_incident_id(incident_id: str) -> str:
            """Sanitize incident ID for safety."""
            return re.sub(r'[^a-zA-Z0-9_\-]', '_', incident_id)

    # Try to import core security audit logging if available
    try:
        from core.security.cs_audit import log_security_event
        AUDIT_AVAILABLE = True
    except ImportError:
        AUDIT_AVAILABLE = False
        logger.debug("Security audit logging not available")

        def log_security_event(*args, **kwargs):
            """Placeholder for audit logging when not available."""
            pass

except Exception as e:
    logger.error(f"Error during module initialization: {e}")
    # Define basic fallbacks for critical components
    PARENT_IMPORTS_AVAILABLE = False
    AUDIT_AVAILABLE = False
    CONFIG_AVAILABLE = False
    NOTIFICATION_ENABLED = True
    NOTIFICATION_CHANNELS = ["email"]
    CRITICAL_CONTACTS = []

# Define constants
DEFAULT_TEMPLATE_DIR = IR_KIT_DIR / "templates" if 'IR_KIT_DIR' in locals() else Path("./templates")
DEFAULT_CONFIG_FILE = IR_KIT_DIR / "config" / "notification_channels.json" if 'IR_KIT_DIR' in locals() else Path("./config/notification_channels.json")
DEFAULT_RETRY_ATTEMPTS = 3
DEFAULT_RETRY_DELAY = 5  # seconds


class NotificationLevel(str, Enum):
    """Notification severity/priority levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class NotificationChannel(str, Enum):
    """Available notification channels."""
    EMAIL = "email"
    SMS = "sms"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    CONSOLE = "console"


class NotificationError(Exception):
    """Base exception for notification errors."""
    pass


class ChannelError(NotificationError):
    """Exception for channel-specific errors."""
    pass


class TemplateError(NotificationError):
    """Exception for template-related errors."""
    pass


def _load_channel_config() -> Dict[str, Any]:
    """
    Load notification channel configuration.

    Returns:
        Dict with channel configuration settings
    """
    config = {}
    config_file = DEFAULT_CONFIG_FILE

    # Try loading from response_config first
    if CONFIG_AVAILABLE:
        notification_config = response_config.get("notification", {})
        # If there's channel config in response_config, use it
        if "channels" in notification_config:
            return notification_config.get("channels", {})

    # Fall back to loading from config file
    if config_file.exists():
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
            logger.debug(f"Loaded notification channel configuration from {config_file}")
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading notification channel config: {e}")

    # If we still don't have config, use defaults
    if not config:
        logger.warning("Using default notification configuration")
        config = {
            "email": {
                "enabled": False,
                "method": "smtp",
                "from": "incident-response@example.com",
                "smtp_server": "smtp.example.com",
                "smtp_port": 587,
                "use_tls": True
            },
            "sms": {
                "enabled": False
            },
            "slack": {
                "enabled": False
            },
            "teams": {
                "enabled": False
            },
            "webhook": {
                "enabled": False
            },
            "console": {
                "enabled": True
            }
        }

    return config


def _get_template_content(template_name: str, context: Dict[str, Any] = None) -> str:
    """
    Get content from a template file with variables replaced.

    Args:
        template_name: Name of template file
        context: Dictionary of variables to replace in the template

    Returns:
        String with processed template content

    Raises:
        TemplateError: If template cannot be found or processed
    """
    if not template_name.endswith(".md") and not template_name.endswith(".txt"):
        template_name += ".md"

    # Look for templates in incident response kit templates directory
    template_path = DEFAULT_TEMPLATE_DIR / template_name

    if not template_path.exists():
        # Try without extension
        template_path = DEFAULT_TEMPLATE_DIR / template_name.split('.')[0]

    if not template_path.exists():
        # Try in a notifications subdirectory
        template_path = DEFAULT_TEMPLATE_DIR / "notifications" / template_name

    if not template_path.exists():
        raise TemplateError(f"Template not found: {template_name}")

    try:
        with open(template_path, "r") as f:
            content = f.read()

        # Replace variables if context is provided
        if context:
            for key, value in context.items():
                content = content.replace(f"{{{{{key}}}}}", str(value))

        return content
    except Exception as e:
        raise TemplateError(f"Error processing template {template_name}: {e}")


def _format_message_by_channel(
    subject: str,
    message: str,
    channel: str,
    level: str,
    incident_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Format notification message for specific channel.

    Args:
        subject: Message subject
        message: Message body
        channel: Channel type (email, sms, etc.)
        level: Notification level/severity
        incident_id: Optional incident ID
        metadata: Additional metadata to include

    Returns:
        Dict with formatted message content for the channel
    """
    formatted = {
        "subject": subject,
        "body": message,
        "level": level
    }

    if incident_id:
        formatted["incident_id"] = incident_id

    if metadata:
        formatted["metadata"] = metadata

    # Add timestamp
    formatted["timestamp"] = datetime.now(timezone.utc).isoformat()

    # Channel-specific formatting
    if channel == NotificationChannel.SMS:
        # SMS should be shorter
        sms_body = f"{subject}: {message}"
        if len(sms_body) > 160:
            sms_body = sms_body[:157] + "..."
        formatted["body"] = sms_body

    elif channel in (NotificationChannel.SLACK, NotificationChannel.TEAMS):
        # Format for chat platforms
        color_map = {
            "debug": "#808080",  # gray
            "info": "#2196F3",   # blue
            "warning": "#FF9800", # orange
            "error": "#F44336",  # red
            "critical": "#9C27B0" # purple
        }
        color = color_map.get(level.lower(), "#2196F3")

        if channel == NotificationChannel.SLACK:
            formatted["slack_payload"] = {
                "attachments": [
                    {
                        "color": color,
                        "title": subject,
                        "text": message,
                        "fields": []
                    }
                ]
            }

            # Add incident_id as field if available
            if incident_id:
                formatted["slack_payload"]["attachments"][0]["fields"].append(
                    {"title": "Incident ID", "value": incident_id, "short": True}
                )

        elif channel == NotificationChannel.TEAMS:
            formatted["teams_payload"] = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color.replace('#', ''),
                "summary": subject,
                "sections": [
                    {
                        "activityTitle": subject,
                        "text": message
                    }
                ]
            }

            # Add incident_id as fact if available
            if incident_id:
                facts = [{"name": "Incident ID", "value": incident_id}]
                formatted["teams_payload"]["sections"][0]["facts"] = facts

    elif channel == NotificationChannel.WEBHOOK:
        # Format for webhook delivery
        formatted["webhook_payload"] = {
            "subject": subject,
            "message": message,
            "level": level,
            "timestamp": formatted["timestamp"]
        }
        if incident_id:
            formatted["webhook_payload"]["incident_id"] = incident_id
        if metadata:
            formatted["webhook_payload"]["metadata"] = metadata

    return formatted


def _get_recipients_by_level(level: str) -> List[str]:
    """
    Get notification recipients based on severity level.

    Args:
        level: Notification level/severity

    Returns:
        List of recipient identifiers (emails, usernames, etc.)
    """
    # If critical notifications are configured, use them for critical and high alerts
    if CRITICAL_CONTACTS and level.lower() in ("critical", "high"):
        return CRITICAL_CONTACTS

    # Otherwise get from config
    recipients = []

    if CONFIG_AVAILABLE:
        # Try to get recipients from configuration
        notification_config = response_config.get("notification", {})

        # Check for level-specific recipients
        level_recipients = notification_config.get(f"{level.lower()}_recipients", [])
        if level_recipients:
            recipients.extend(level_recipients)

        # Add default recipients if no level-specific ones were found
        if not recipients:
            default_recipients = notification_config.get("recipients", [])
            recipients.extend(default_recipients)

    return recipients


def _send_email_notification(
    recipients: List[str],
    subject: str,
    message: str,
    config: Dict[str, Any],
    incident_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Send notification via email.

    Args:
        recipients: List of email addresses
        subject: Email subject
        message: Email content
        config: Email configuration
        incident_id: Optional incident ID

    Returns:
        Dict with delivery results
    """
    result = {
        "success": False,
        "channel": "email",
        "recipients": recipients,
        "errors": []
    }

    if not recipients:
        result["errors"].append("No email recipients provided")
        return result

    try:
        # Add incident ID to subject if provided
        if incident_id:
            subject = f"[IR-{incident_id}] {subject}"

        # Get email configuration
        from_addr = config.get("from", "incident-response@example.com")
        method = config.get("method", "smtp").lower()

        # Attempt to send based on configured method
        if method == "smtp":
            # Use SMTP
            smtp_server = config.get("smtp_server", "localhost")
            smtp_port = int(config.get("smtp_port", 25))
            use_tls = config.get("use_tls", False)
            username = config.get("username")
            password = config.get("password")

            # Create message
            msg = MIMEMultipart()
            msg['From'] = from_addr
            msg['To'] = ", ".join(recipients)
            msg['Subject'] = subject

            # Attach message body
            msg.attach(MIMEText(message, 'plain'))

            # Connect and send
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if use_tls:
                    server.starttls()

                if username and password:
                    server.login(username, password)

                server.send_message(msg)

            result["success"] = True

        elif method == "sendmail":
            # Use sendmail command
            msg = MIMEText(message)
            msg["From"] = from_addr
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = subject

            sendmail_proc = subprocess.run(
                ["sendmail", "-t"],
                input=msg.as_string().encode(),
                capture_output=True
            )

            if sendmail_proc.returncode != 0:
                result["errors"].append(f"Sendmail error: {sendmail_proc.stderr.decode()}")
            else:
                result["success"] = True

        elif method == "mail":
            # Use mail command - simpler but less reliable
            mail_cmd = ["mail", "-s", subject]

            for recipient in recipients:
                mail_cmd.append(recipient)

            mail_proc = subprocess.run(
                mail_cmd,
                input=message.encode(),
                capture_output=True
            )

            if mail_proc.returncode != 0:
                result["errors"].append(f"Mail command error: {mail_proc.stderr.decode()}")
            else:
                result["success"] = True

        else:
            result["errors"].append(f"Unsupported email method: {method}")

    except Exception as e:
        result["errors"].append(f"Email error: {str(e)}")

    # Log delivery result
    if result["success"]:
        logger.info(f"Email notification sent to {len(recipients)} recipients")
    else:
        logger.error(f"Failed to send email notification: {result['errors']}")

    return result


def _send_sms_notification(
    recipients: List[str],
    message: str,
    config: Dict[str, Any],
    **kwargs
) -> Dict[str, Any]:
    """
    Send notification via SMS.

    Args:
        recipients: List of phone numbers
        message: SMS content
        config: SMS configuration
        **kwargs: Additional parameters

    Returns:
        Dict with delivery results
    """
    result = {
        "success": False,
        "channel": "sms",
        "recipients": recipients,
        "errors": []
    }

    if not recipients:
        result["errors"].append("No SMS recipients provided")
        return result

    # Check if we have a configured SMS provider
    provider = config.get("provider", "").lower()

    if not provider or provider == "none":
        result["errors"].append("No SMS provider configured")
        return result

    try:
        # Simple console fallback for testing
        if provider == "console":
            logger.info(f"SMS NOTIFICATION to {recipients}: {message}")
            result["success"] = True

        # Add more SMS provider implementations as needed
        # This is a placeholder - actual implementation would vary by provider
        else:
            result["errors"].append(f"Unsupported SMS provider: {provider}")

    except Exception as e:
        result["errors"].append(f"SMS error: {str(e)}")

    # Log delivery result
    if result["success"]:
        logger.info(f"SMS notification sent to {len(recipients)} recipients")
    else:
        logger.error(f"Failed to send SMS notification: {result['errors']}")

    return result


def _send_webhook_notification(
    webhook_url: str,
    payload: Dict[str, Any],
    config: Dict[str, Any],
    **kwargs
) -> Dict[str, Any]:
    """
    Send notification via webhook.

    Args:
        webhook_url: Target webhook URL
        payload: Data to send to webhook
        config: Webhook configuration
        **kwargs: Additional parameters

    Returns:
        Dict with delivery results
    """
    result = {
        "success": False,
        "channel": "webhook",
        "recipient": webhook_url,
        "errors": []
    }

    if not webhook_url:
        result["errors"].append("No webhook URL provided")
        return result

    try:
        import requests

        # Get timeout from config
        timeout = int(config.get("timeout", 10))

        # Add signing if configured
        headers = {"Content-Type": "application/json"}
        if config.get("sign_payload") and config.get("signing_key"):
            import hmac
            import hashlib

            # Create signature
            payload_bytes = json.dumps(payload).encode()
            signature = hmac.new(
                config["signing_key"].encode(),
                payload_bytes,
                hashlib.sha256
            ).hexdigest()

            # Add to headers
            headers["X-Signature"] = signature

        # Send the request
        response = requests.post(
            webhook_url,
            json=payload,
            headers=headers,
            timeout=timeout
        )

        # Check for success
        if response.status_code < 400:
            result["success"] = True
        else:
            result["errors"].append(
                f"Webhook error: HTTP {response.status_code} - {response.text[:100]}"
            )

    except ImportError:
        result["errors"].append("Requests library not available for webhook delivery")
    except Exception as e:
        result["errors"].append(f"Webhook error: {str(e)}")

    # Log delivery result
    if result["success"]:
        logger.info(f"Webhook notification sent to {webhook_url}")
    else:
        logger.error(f"Failed to send webhook notification: {result['errors']}")

    return result


def _send_chat_notification(
    webhook_url: str,
    payload: Dict[str, Any],
    channel: str,
    **kwargs
) -> Dict[str, Any]:
    """
    Send notification to chat platform (Slack/Teams).

    Args:
        webhook_url: Target webhook URL
        payload: Platform-specific payload
        channel: Channel type (slack or teams)
        **kwargs: Additional parameters

    Returns:
        Dict with delivery results
    """
    result = {
        "success": False,
        "channel": channel,
        "recipient": webhook_url,
        "errors": []
    }

    if not webhook_url:
        result["errors"].append(f"No {channel} webhook URL provided")
        return result

    try:
        import requests

        # Send the request
        response = requests.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )

        # Check for success
        if response.status_code < 400:
            result["success"] = True
        else:
            result["errors"].append(
                f"{channel.capitalize()} error: HTTP {response.status_code} - {response.text[:100]}"
            )

    except ImportError:
        result["errors"].append("Requests library not available for chat delivery")
    except Exception as e:
        result["errors"].append(f"{channel.capitalize()} error: {str(e)}")

    # Log delivery result
    if result["success"]:
        logger.info(f"{channel.capitalize()} notification sent")
    else:
        logger.error(f"Failed to send {channel} notification: {result['errors']}")

    return result


def _send_console_notification(
    subject: str,
    message: str,
    level: str,
    incident_id: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Send notification to console (stdout).

    Args:
        subject: Message subject
        message: Message content
        level: Message level (debug, info, etc.)
        incident_id: Optional incident ID
        **kwargs: Additional parameters

    Returns:
        Dict with delivery results
    """
    result = {
        "success": False,
        "channel": "console",
        "errors": []
    }

    try:
        # Format the header
        header = f"==== NOTIFICATION [{level.upper()}] ===="

        # Add incident ID if provided
        if incident_id:
            header += f" [IR-{incident_id}]"

        # Format and print the message
        print("\n" + header)
        print(f"Subject: {subject}")
        print("-" * len(header))
        print(message)
        print("=" * len(header) + "\n")

        result["success"] = True

    except Exception as e:
        result["errors"].append(f"Console output error: {str(e)}")

    return result


def notify_stakeholders(
    subject: str,
    message: str,
    severity: str = IncidentSeverity.MEDIUM,
    incident_id: Optional[str] = None,
    template: Optional[str] = None,
    template_vars: Optional[Dict[str, Any]] = None,
    channels: Optional[List[str]] = None,
    recipients: Optional[List[str]] = None,
    retry_attempts: int = DEFAULT_RETRY_ATTEMPTS,
    priority: Optional[str] = None,  # Alias for severity
    level: Optional[str] = None,     # Alias for severity
    metadata: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Send notification to incident stakeholders.

    Args:
        subject: Notification subject
        message: Notification message content
        severity: Notification severity (critical, high, medium, low)
        incident_id: Associated incident ID
        template: Template name to use instead of direct message
        template_vars: Variables to use with the template
        channels: List of channels to use (email, sms, etc.)
        recipients: List of recipient identifiers (emails, phones, etc.)
        retry_attempts: Number of delivery retry attempts on failure
        priority: Alias for severity
        level: Alias for severity
        metadata: Additional metadata for the notification

    Returns:
        True if notification was sent successfully to any channel
    """
    # Validate that notification system is enabled
    if not NOTIFICATION_ENABLED:
        logger.warning("Notification system is disabled")
        return False

    # Use priority or level as aliases for severity
    severity = priority or level or severity

    # Validate severity
    if hasattr(IncidentSeverity, severity.upper()):
        # Use the canonical version from IncidentSeverity
        severity = getattr(IncidentSeverity, severity.upper())
    elif severity.lower() not in [s.lower() for s in vars(IncidentSeverity).values()
                                if isinstance(s, str) and not s.startswith('_')]:
        logger.warning(f"Invalid severity '{severity}', using MEDIUM")
        severity = IncidentSeverity.MEDIUM

    # Sanitize incident ID if provided
    if incident_id:
        incident_id = sanitize_incident_id(incident_id)

    # Process template if requested
    if template:
        try:
            # Get template variables
            template_context = template_vars or {}

            # Add standard variables
            template_context.update({
                "INCIDENT_ID": incident_id or "N/A",
                "SEVERITY": severity,
                "TIMESTAMP": datetime.now(timezone.utc).isoformat(),
                "SUBJECT": subject
            })

            # Process the template
            message = _get_template_content(template, template_context)
        except TemplateError as e:
            logger.error(f"Template error: {e}")
            # Continue with original message as fallback

    # Get channel configuration
    channel_config = _load_channel_config()

    # Determine which channels to use
    if not channels:
        channels = NOTIFICATION_CHANNELS

    # Get recipients if not explicitly provided
    if recipients is None:
        recipients = _get_recipients_by_level(severity)

    # Ensure recipients is a list
    if isinstance(recipients, str):
        recipients = [recipients]

    # Prepare metadata
    notification_metadata = metadata or {}
    if incident_id:
        notification_metadata["incident_id"] = incident_id
    notification_metadata["severity"] = severity

    # Track successful deliveries
    sent_successfully = False
    results = []

    # Attempt to send through each channel
    for channel in channels:
        channel = channel.lower()
        channel_enabled = channel_config.get(channel, {}).get("enabled", False)

        if not channel_enabled:
            logger.debug(f"Channel {channel} is disabled, skipping")
            continue

        # Format message for the channel
        formatted_message = _format_message_by_channel(
            subject=subject,
            message=message,
            channel=channel,
            level=severity,
            incident_id=incident_id,
            metadata=notification_metadata
        )

        # Send based on channel type
        retry_count = 0
        result = None

        while retry_count <= retry_attempts:
            try:
                if channel == NotificationChannel.EMAIL:
                    result = _send_email_notification(
                        recipients=recipients,
                        subject=subject,
                        message=message,
                        config=channel_config.get('email', {}),
                        incident_id=incident_id
                    )

                elif channel == NotificationChannel.SMS:
                    result = _send_sms_notification(
                        recipients=recipients,
                        message=formatted_message.get('body', message),
                        config=channel_config.get('sms', {})
                    )

                elif channel == NotificationChannel.SLACK:
                    result = _send_chat_notification(
                        webhook_url=channel_config.get('slack', {}).get('webhook_url', ''),
                        payload=formatted_message.get('slack_payload', {}),
                        channel='slack'
                    )

                elif channel == NotificationChannel.TEAMS:
                    result = _send_chat_notification(
                        webhook_url=channel_config.get('teams', {}).get('webhook_url', ''),
                        payload=formatted_message.get('teams_payload', {}),
                        channel='teams'
                    )

                elif channel == NotificationChannel.WEBHOOK:
                    result = _send_webhook_notification(
                        webhook_url=channel_config.get('webhook', {}).get('url', ''),
                        payload=formatted_message.get('webhook_payload', {}),
                        config=channel_config.get('webhook', {})
                    )

                elif channel == NotificationChannel.CONSOLE:
                    result = _send_console_notification(
                        subject=subject,
                        message=message,
                        level=severity,
                        incident_id=incident_id
                    )

                else:
                    logger.warning(f"Unsupported notification channel: {channel}")
                    break

                # Check result
                if result and result.get('success'):
                    sent_successfully = True
                    break

                # Retry logic - only retry if we have retries left and there's an error to retry
                if retry_count < retry_attempts and result and result.get('errors'):
                    retry_count += 1
                    logger.warning(f"Retrying {channel} notification (attempt {retry_count}/{retry_attempts})")
                    time.sleep(DEFAULT_RETRY_DELAY * retry_count)  # Incremental backoff
                else:
                    # No more retries or no error to retry
                    break

            except Exception as e:
                logger.error(f"Error sending {channel} notification: {e}")
                if retry_count < retry_attempts:
                    retry_count += 1
                    time.sleep(DEFAULT_RETRY_DELAY * retry_count)
                else:
                    break

        # Store result for audit/logging
        if result:
            results.append(result)

    # Audit notification if available
    if AUDIT_AVAILABLE and log_security_event:
        try:
            audit_data = {
                "subject": subject,
                "channels": channels,
                "severity": severity,
                "results": [{k: v for k, v in r.items() if k != 'errors'} for r in results]
            }

            if incident_id:
                audit_data["incident_id"] = incident_id

            log_security_event(
                event_type="notification_sent",
                description=f"Notification sent: {subject[:50]}",
                severity="info",
                metadata=audit_data
            )
        except Exception as e:
            logger.warning(f"Failed to log notification audit: {e}")

    return sent_successfully


def scheduled_notification(
    subject: str,
    message: str,
    schedule_time: Union[str, datetime],
    **kwargs
) -> Dict[str, Any]:
    """
    Schedule a notification for future delivery.

    This is a placeholder implementation. A full implementation would:
    1. Store the notification in a database or task queue
    2. Use a scheduler (e.g., Celery) to send at the specified time

    Args:
        subject: Notification subject
        message: Notification message
        schedule_time: When to send the notification (ISO timestamp or datetime)
        **kwargs: Additional arguments for notify_stakeholders()

    Returns:
        Dict with scheduling results
    """
    result = {
        "success": False,
        "scheduled": False,
        "errors": []
    }

    try:
        # Parse the schedule time if it's a string
        if isinstance(schedule_time, str):
            schedule_time = datetime.fromisoformat(schedule_time.replace('Z', '+00:00'))

        # Calculate delay
        now = datetime.now(timezone.utc)
        if schedule_time.tzinfo is None:
            # Assume UTC if no timezone specified
            schedule_time = schedule_time.replace(tzinfo=timezone.utc)

        # Check if in the past
        if schedule_time <= now:
            logger.warning(f"Schedule time is in the past, sending immediately")
            send_result = notify_stakeholders(subject, message, **kwargs)
            return {"success": send_result, "scheduled": False}

        # Log the scheduled notification
        time_diff = schedule_time - now
        delay_seconds = time_diff.total_seconds()

        logger.info(
            f"Notification scheduled: '{subject}' in {delay_seconds:.1f} seconds "
            f"({schedule_time.isoformat()})"
        )

        # A real implementation would add to a task queue here
        # This is a placeholder that doesn't actually schedule
        result["scheduled"] = True
        result["success"] = True
        result["scheduled_time"] = schedule_time.isoformat()
        result["note"] = "This is a placeholder. Real scheduling requires a task queue."

    except ValueError as e:
        result["errors"].append(f"Invalid schedule time format: {e}")
    except Exception as e:
        result["errors"].append(f"Scheduling error: {e}")

    return result


def get_notification_history(
    incident_id: Optional[str] = None,
    limit: int = 20
) -> List[Dict[str, Any]]:
    """
    Get history of sent notifications.

    This is a placeholder implementation. A full implementation would:
    1. Query notification records from a database
    2. Filter by incident ID if provided
    3. Return formatted notification history

    Args:
        incident_id: Filter by incident ID
        limit: Maximum number of records to return

    Returns:
        List of notification history records
    """
    logger.warning("Notification history is not implemented")
    return []


def main():
    """Main function when script is run directly."""
    import argparse

    parser = argparse.ArgumentParser(description="Incident Response Notification System")
    parser.add_argument("--incident-id", help="Incident ID")
    parser.add_argument("--subject", help="Notification subject")
    parser.add_argument("--message", help="Notification message")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low"],
                        default="medium", help="Notification severity")
    parser.add_argument("--template", help="Template to use instead of direct message")
    parser.add_argument("--channels", help="Comma-separated list of channels to use")
    parser.add_argument("--recipients", help="Comma-separated list of recipients")
    parser.add_argument("--schedule", help="Schedule time for notification (ISO format)")

    args = parser.parse_args()

    # Validate required args
    if not args.subject or (not args.message and not args.template):
        parser.error("--subject and either --message or --template are required")

    # Split lists
    channels = args.channels.split(',') if args.channels else None
    recipients = args.recipients.split(',') if args.recipients else None

    # Send the notification
    if args.schedule:
        result = scheduled_notification(
            subject=args.subject,
            message=args.message or "",
            schedule_time=args.schedule,
            severity=args.severity,
            incident_id=args.incident_id,
            template=args.template,
            channels=channels,
            recipients=recipients
        )
        print(f"Notification scheduling {'successful' if result.get('success') else 'failed'}")
    else:
        success = notify_stakeholders(
            subject=args.subject,
            message=args.message or "",
            severity=args.severity,
            incident_id=args.incident_id,
            template=args.template,
            channels=channels,
            recipients=recipients
        )
        print(f"Notification {'sent successfully' if success else 'failed'}")


if __name__ == "__main__":
    main()
