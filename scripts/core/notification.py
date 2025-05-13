#!/usr/bin/env python3
# filepath: scripts/core/notification.py
"""
Notification Service for the Cloud Infrastructure Platform.

This module provides a flexible notification system that can send alerts and messages
through various channels such as email, SMS, chat applications, and more. It supports
templated notifications, priority levels, rate limiting, and delivery verification.

Key features:
- Multiple notification channels (email, SMS, chat platforms)
- Templated notifications
- Priority-based handling
- Rate limiting to prevent notification flooding
- Delivery status tracking and verification
- Retry mechanisms for failed notifications
"""

import os
import sys
import json
import time
import smtplib
import logging
import socket
import uuid
import subprocess
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union, Any, Tuple, Set
from pathlib import Path
import threading
import queue

# Try to import internal modules
try:
    from scripts.core.logger import Logger
    from scripts.core.config_loader import ConfigLoader
    INTERNAL_MODULES_AVAILABLE = True
except ImportError:
    INTERNAL_MODULES_AVAILABLE = False

# Constants
CHANNEL_EMAIL = "email"
CHANNEL_SMS = "sms"
CHANNEL_SLACK = "slack"
CHANNEL_TEAMS = "teams"
CHANNEL_WEBHOOK = "webhook"
CHANNEL_CONSOLE = "console"

PRIORITY_LOW = "low"
PRIORITY_MEDIUM = "medium"
PRIORITY_HIGH = "high"
PRIORITY_CRITICAL = "critical"

STATUS_PENDING = "pending"
STATUS_SENT = "sent"
STATUS_DELIVERED = "delivered"
STATUS_FAILED = "failed"

# Setup logging
if INTERNAL_MODULES_AVAILABLE:
    logger = Logger.get_logger(__name__)
else:
    logging.basicConfig(
        format='[%(asctime)s] %(levelname)s in %(name)s: %(message)s',
        level=logging.INFO
    )
    logger = logging.getLogger(__name__)

# Default template directory
TEMPLATE_DIR = Path(__file__).parent.parent.parent / "templates" / "notifications"

# Cache for templates
_template_cache = {}

class NotificationError(Exception):
    """Base exception for notification errors."""
    pass

class ChannelError(NotificationError):
    """Exception for channel-specific errors."""
    pass

class TemplateError(NotificationError):
    """Exception for template-related errors."""
    pass

class RateLimitError(NotificationError):
    """Exception for rate limiting errors."""
    pass

class NotificationManager:
    """
    Manages rate limiting and notification queuing.
    This is a singleton used internally by NotificationService.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(NotificationManager, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Initialize the notification manager."""
        self.rate_limits = {
            CHANNEL_EMAIL: {"count": 0, "reset_time": datetime.now(), "limit": 50, "period": 3600},
            CHANNEL_SMS: {"count": 0, "reset_time": datetime.now(), "limit": 10, "period": 3600},
            CHANNEL_SLACK: {"count": 0, "reset_time": datetime.now(), "limit": 30, "period": 60},
            CHANNEL_TEAMS: {"count": 0, "reset_time": datetime.now(), "limit": 30, "period": 60},
            CHANNEL_WEBHOOK: {"count": 0, "reset_time": datetime.now(), "limit": 100, "period": 3600},
        }

        # Notification history - store recent notifications to avoid duplicates
        self.recent_notifications = {}

        # Queue for background notifications
        self.notification_queue = queue.Queue()
        self.worker_thread = threading.Thread(
            target=self._process_queue,
            daemon=True,
            name="NotificationWorker"
        )
        self.worker_running = True
        self.worker_thread.start()

    def check_rate_limit(self, channel: str) -> bool:
        """
        Check if sending a notification would exceed rate limits.

        Args:
            channel: The notification channel

        Returns:
            True if within rate limits, False if would exceed
        """
        if channel not in self.rate_limits:
            return True

        rate_info = self.rate_limits[channel]

        # Reset counter if period has elapsed
        now = datetime.now()
        if (now - rate_info["reset_time"]).total_seconds() > rate_info["period"]:
            rate_info["count"] = 0
            rate_info["reset_time"] = now

        # Check if we're at the limit
        return rate_info["count"] < rate_info["limit"]

    def increment_rate_counter(self, channel: str) -> None:
        """
        Increment the rate counter for a channel.

        Args:
            channel: The notification channel
        """
        if channel in self.rate_limits:
            self.rate_limits[channel]["count"] += 1

    def check_duplicate(self, recipient: str, message: str, channel: str) -> bool:
        """
        Check if a notification is a duplicate of a recent one.

        Args:
            recipient: Notification recipient
            message: Notification message
            channel: Notification channel

        Returns:
            True if it's a duplicate, False otherwise
        """
        key = f"{recipient}:{channel}:{hash(message)}"
        if key in self.recent_notifications:
            last_time = self.recent_notifications[key]
            # Consider a duplicate if sent in the last 5 minutes
            if (datetime.now() - last_time).total_seconds() < 300:
                return True

        # Update last send time
        self.recent_notifications[key] = datetime.now()

        # Clean up old entries
        self._cleanup_recent_notifications()
        return False

    def _cleanup_recent_notifications(self) -> None:
        """Periodically clean up old notification records."""
        now = datetime.now()
        cutoff = now - timedelta(minutes=15)

        # Remove entries older than cutoff
        keys_to_remove = [
            key for key, timestamp in self.recent_notifications.items()
            if timestamp < cutoff
        ]

        for key in keys_to_remove:
            del self.recent_notifications[key]

    def add_to_queue(self, params: Dict[str, Any]) -> None:
        """
        Add a notification to the background processing queue.

        Args:
            params: Notification parameters
        """
        self.notification_queue.put(params)

    def _process_queue(self) -> None:
        """Process notifications in the background queue."""
        while self.worker_running:
            try:
                # Wait for an item with timeout to allow checking worker_running
                try:
                    params = self.notification_queue.get(timeout=1.0)
                except queue.Empty:
                    continue

                # Initialize notification service within the thread
                notifier = NotificationService()

                # Extract parameters
                message = params.get("message", "")
                subject = params.get("subject", "Notification")
                recipients = params.get("recipients", [])
                channels = params.get("channels", ["email"])
                template = params.get("template")
                template_data = params.get("template_data", {})
                priority = params.get("priority", PRIORITY_MEDIUM)

                # Send the notification based on parameters
                if template:
                    notifier.send_template(
                        template=template,
                        template_data=template_data,
                        recipients=recipients,
                        subject=subject,
                        channels=channels,
                        priority=priority,
                        tracking_id=params.get("tracking_id")
                    )
                else:
                    notifier.send(
                        message=message,
                        recipients=recipients,
                        subject=subject,
                        channels=channels,
                        priority=priority,
                        tracking_id=params.get("tracking_id")
                    )

                # Mark task as done
                self.notification_queue.task_done()

            except Exception as e:
                logger.error(f"Error processing queued notification: {str(e)}")
                try:
                    # Try to mark the task as done even if it failed
                    self.notification_queue.task_done()
                except Exception:
                    pass

class NotificationService:
    """
    Main service for sending notifications through various channels.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the notification service.

        Args:
            config_path: Optional path to a configuration file
        """
        # Initialize the notification manager singleton
        self.manager = NotificationManager()

        # Load configuration
        self.config = self._load_config(config_path)

        # Set up delivery tracking
        self.delivery_status = {}

    def _load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Load configuration for notification channels.

        Args:
            config_path: Path to configuration file

        Returns:
            Configuration dictionary
        """
        config = {
            "channels": {
                CHANNEL_EMAIL: {
                    "enabled": True,
                    "method": "smtp",  # smtp, sendmail, or mail
                    "from": "notifications@example.com",
                    "smtp_server": "localhost",
                    "smtp_port": 25,
                    "use_tls": False,
                    "username": None,
                    "password": None,
                },
                CHANNEL_SMS: {
                    "enabled": False,
                    "provider": "none",  # none, twilio, sns
                    "from_number": "",
                },
                CHANNEL_SLACK: {
                    "enabled": False,
                    "webhook_url": "",
                    "default_channel": "#general",
                },
                CHANNEL_TEAMS: {
                    "enabled": False,
                    "webhook_url": "",
                },
                CHANNEL_WEBHOOK: {
                    "enabled": False,
                    "url": "",
                    "method": "POST",
                    "headers": {},
                },
                CHANNEL_CONSOLE: {
                    "enabled": True,
                },
            },
            "templates_dir": str(TEMPLATE_DIR),
            "default_channels": [CHANNEL_EMAIL, CHANNEL_CONSOLE],
            "retry": {
                "max_attempts": 3,
                "backoff_factor": 2,
                "initial_delay": 1,
            }
        }

        # If config_loader is available, try to use it
        if config_path and INTERNAL_MODULES_AVAILABLE:
            try:
                loaded_config = ConfigLoader.load(config_path)

                # Update our default config with loaded values
                if "notification" in loaded_config:
                    notification_config = loaded_config.get("notification", {})

                    # Update channels configuration
                    if "channels" in notification_config:
                        for channel, settings in notification_config["channels"].items():
                            if channel in config["channels"]:
                                config["channels"][channel].update(settings)

                    # Update other settings
                    for key in ["templates_dir", "default_channels"]:
                        if key in notification_config:
                            config[key] = notification_config[key]

                    # Update retry configuration
                    if "retry" in notification_config:
                        config["retry"].update(notification_config["retry"])

                logger.debug(f"Loaded notification configuration from {config_path}")

            except Exception as e:
                logger.error(f"Error loading notification config from {config_path}: {str(e)}")

        # Check for environment variable overrides
        smtp_server = os.environ.get("NOTIFICATION_SMTP_SERVER")
        if smtp_server:
            config["channels"][CHANNEL_EMAIL]["smtp_server"] = smtp_server

        smtp_port = os.environ.get("NOTIFICATION_SMTP_PORT")
        if smtp_port:
            try:
                config["channels"][CHANNEL_EMAIL]["smtp_port"] = int(smtp_port)
            except ValueError:
                logger.warning(f"Invalid SMTP port: {smtp_port}")

        smtp_user = os.environ.get("NOTIFICATION_SMTP_USER")
        if smtp_user:
            config["channels"][CHANNEL_EMAIL]["username"] = smtp_user

        smtp_pass = os.environ.get("NOTIFICATION_SMTP_PASSWORD")
        if smtp_pass:
            config["channels"][CHANNEL_EMAIL]["password"] = smtp_pass

        smtp_tls = os.environ.get("NOTIFICATION_SMTP_TLS")
        if smtp_tls:
            config["channels"][CHANNEL_EMAIL]["use_tls"] = smtp_tls.lower() in ["true", "yes", "1"]

        slack_webhook = os.environ.get("NOTIFICATION_SLACK_WEBHOOK")
        if slack_webhook:
            config["channels"][CHANNEL_SLACK]["webhook_url"] = slack_webhook
            config["channels"][CHANNEL_SLACK]["enabled"] = True

        teams_webhook = os.environ.get("NOTIFICATION_TEAMS_WEBHOOK")
        if teams_webhook:
            config["channels"][CHANNEL_TEAMS]["webhook_url"] = teams_webhook
            config["channels"][CHANNEL_TEAMS]["enabled"] = True

        # Return the configuration
        return config

    def send(self,
             message: str,
             recipients: Optional[Union[str, List[str]]] = None,
             subject: str = "Notification",
             channels: Optional[List[str]] = None,
             priority: str = PRIORITY_MEDIUM,
             tracking_id: Optional[str] = None,
             async_send: bool = False,
             channel_options: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Send a notification through specified channels.

        Args:
            message: The notification message
            recipients: Recipient(s) for the notification
            subject: Subject line for email/notification title
            channels: List of channels to use
            priority: Notification priority
            tracking_id: Optional tracking ID for status updates
            async_send: Whether to send asynchronously
            channel_options: Channel-specific options

        Returns:
            Dictionary with delivery results
        """
        # Validate inputs
        if not message:
            raise ValueError("Message cannot be empty")

        # Normalize recipients to list
        if recipients is None:
            recipients = []
        elif isinstance(recipients, str):
            recipients = [recipients]

        # Set default channels if not specified
        if not channels:
            channels = self.config.get("default_channels", [CHANNEL_EMAIL, CHANNEL_CONSOLE])

        # Generate tracking ID if not provided
        if not tracking_id:
            tracking_id = f"notif-{uuid.uuid4().hex[:12]}"

        # If async requested, queue the notification and return
        if async_send:
            self.manager.add_to_queue({
                "message": message,
                "recipients": recipients,
                "subject": subject,
                "channels": channels,
                "priority": priority,
                "tracking_id": tracking_id,
                "channel_options": channel_options
            })
            return {
                "success": True,
                "async": True,
                "tracking_id": tracking_id
            }

        # Initialize results
        results = {
            "success": False,
            "tracking_id": tracking_id,
            "channels": {},
            "timestamp": datetime.now().isoformat()
        }

        # Try each channel in order
        any_success = False

        for channel in channels:
            # Check if channel is enabled in config
            channel_config = self.config.get("channels", {}).get(channel, {})
            if not channel_config.get("enabled", False) and channel != CHANNEL_CONSOLE:
                logger.debug(f"Channel {channel} is disabled, skipping")
                results["channels"][channel] = {"status": "skipped", "reason": "disabled"}
                continue

            # Check rate limits
            if not self.manager.check_rate_limit(channel):
                logger.warning(f"Rate limit exceeded for channel: {channel}")
                results["channels"][channel] = {"status": "skipped", "reason": "rate_limit"}
                continue

            # Check for duplicate notifications (except console)
            if channel != CHANNEL_CONSOLE:
                recipient_key = ",".join(recipients) if recipients else "default"
                if self.manager.check_duplicate(recipient_key, message, channel):
                    logger.debug(f"Duplicate notification suppressed for {channel}")
                    results["channels"][channel] = {"status": "skipped", "reason": "duplicate"}
                    continue

            # Apply channel-specific options
            options = {}
            if channel_options and channel in channel_options:
                options = channel_options[channel]

            # Send through the channel
            try:
                channel_result = self._send_via_channel(
                    channel=channel,
                    subject=subject,
                    message=message,
                    recipients=recipients,
                    priority=priority,
                    tracking_id=tracking_id,
                    options=options
                )

                # Update results
                results["channels"][channel] = channel_result

                # Increment the rate counter
                self.manager.increment_rate_counter(channel)

                # Track successful delivery
                if channel_result.get("status") == "sent":
                    any_success = True

            except Exception as e:
                logger.error(f"Error sending notification via {channel}: {str(e)}")
                results["channels"][channel] = {
                    "status": "error",
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }

        # Update overall success
        results["success"] = any_success

        # Store delivery status for tracking
        self.delivery_status[tracking_id] = results

        return results

    def send_template(self,
                      template: str,
                      template_data: Dict[str, Any],
                      recipients: Optional[Union[str, List[str]]] = None,
                      subject: Optional[str] = None,
                      channels: Optional[List[str]] = None,
                      priority: str = PRIORITY_MEDIUM,
                      tracking_id: Optional[str] = None,
                      async_send: bool = False) -> Dict[str, Any]:
        """
        Send a notification using a template.

        Args:
            template: Template name or path
            template_data: Data to render the template with
            recipients: Recipient(s) for the notification
            subject: Optional subject override (otherwise from template)
            channels: List of channels to use
            priority: Notification priority
            tracking_id: Optional tracking ID for status updates
            async_send: Whether to send asynchronously

        Returns:
            Dictionary with delivery results
        """
        try:
            # Render template
            template_content = self._render_template(template, template_data)

            # Extract subject from template if not provided
            if not subject and isinstance(template_content, dict) and "subject" in template_content:
                subject = template_content["subject"]
            elif not subject:
                subject = f"Notification: {template}"

            # Get message content
            if isinstance(template_content, dict) and "body" in template_content:
                message = template_content["body"]
            else:
                message = template_content

            # Send the notification
            return self.send(
                message=message,
                recipients=recipients,
                subject=subject,
                channels=channels,
                priority=priority,
                tracking_id=tracking_id,
                async_send=async_send,
                channel_options=template_content.get("channel_options") if isinstance(template_content, dict) else None
            )

        except Exception as e:
            logger.error(f"Error sending template notification: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "template": template,
                "tracking_id": tracking_id or f"notif-{uuid.uuid4().hex[:12]}"
            }

    def get_delivery_status(self, tracking_id: str) -> Dict[str, Any]:
        """
        Get the delivery status of a notification.

        Args:
            tracking_id: The tracking ID of the notification

        Returns:
            Status information or empty dict if not found
        """
        return self.delivery_status.get(tracking_id, {})

    def verify_delivery(self, tracking_id: str) -> bool:
        """
        Verify if a notification was successfully delivered.

        Args:
            tracking_id: The tracking ID of the notification

        Returns:
            True if confirmed delivered, False otherwise
        """
        status = self.get_delivery_status(tracking_id)
        return status.get("success", False)

    def _send_via_channel(self,
                         channel: str,
                         subject: str,
                         message: str,
                         recipients: List[str],
                         priority: str,
                         tracking_id: str,
                         options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Send notification through a specific channel.

        Args:
            channel: The channel to use
            subject: Notification subject/title
            message: Notification message
            recipients: List of recipients
            priority: Notification priority
            tracking_id: Tracking ID
            options: Channel-specific options

        Returns:
            Dictionary with channel-specific results
        """
        options = options or {}
        channel_config = self.config.get("channels", {}).get(channel, {})

        # Configure retry parameters
        retry_config = self.config.get("retry", {})
        max_attempts = retry_config.get("max_attempts", 3)
        backoff_factor = retry_config.get("backoff_factor", 2)
        initial_delay = retry_config.get("initial_delay", 1)

        # Track attempts
        attempt = 0
        last_error = None

        # Try sending with retry logic
        while attempt < max_attempts:
            try:
                if channel == CHANNEL_EMAIL:
                    return self._send_email(subject, message, recipients, priority, options)

                elif channel == CHANNEL_SMS:
                    return self._send_sms(message, recipients, priority, options)

                elif channel == CHANNEL_SLACK:
                    return self._send_slack(subject, message, recipients, priority, options)

                elif channel == CHANNEL_TEAMS:
                    return self._send_teams(subject, message, recipients, priority, options)

                elif channel == CHANNEL_WEBHOOK:
                    return self._send_webhook(subject, message, recipients, priority, options)

                elif channel == CHANNEL_CONSOLE:
                    return self._send_console(subject, message, priority)

                else:
                    raise ChannelError(f"Unsupported channel: {channel}")

            except Exception as e:
                last_error = str(e)
                attempt += 1

                if attempt < max_attempts:
                    # Calculate delay with exponential backoff
                    delay = initial_delay * (backoff_factor ** (attempt - 1))
                    logger.debug(f"Retry {attempt}/{max_attempts} for {channel} in {delay}s: {last_error}")
                    time.sleep(delay)
                else:
                    logger.error(f"Failed to send via {channel} after {max_attempts} attempts: {last_error}")

        # If we got here, all attempts failed
        return {
            "status": "error",
            "error": last_error,
            "timestamp": datetime.now().isoformat(),
            "attempts": attempt
        }

    def _send_email(self,
                   subject: str,
                   message: str,
                   recipients: List[str],
                   priority: str,
                   options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send notification via email.

        Args:
            subject: Email subject
            message: Email body
            recipients: List of email recipients
            priority: Notification priority
            options: Email-specific options

        Returns:
            Dictionary with email delivery results
        """
        # Check if we have recipients
        if not recipients:
            return {"status": "error", "error": "No recipients specified", "timestamp": datetime.now().isoformat()}

        # Get email configuration
        email_config = self.config.get("channels", {}).get(CHANNEL_EMAIL, {})
        method = options.get("method", email_config.get("method", "smtp"))
        from_addr = options.get("from", email_config.get("from", "notifications@example.com"))

        # Create message
        if options.get("format", "html").lower() == "html":
            msg = MIMEMultipart()
            msg.attach(MIMEText(message, 'html'))
        else:
            msg = MIMEText(message)

        # Set headers
        msg['Subject'] = subject
        msg['From'] = from_addr
        msg['To'] = ", ".join(recipients)

        # Set priority headers
        if priority == PRIORITY_HIGH or priority == PRIORITY_CRITICAL:
            msg['X-Priority'] = '1'  # High priority
            msg['X-MSMail-Priority'] = 'High'

        # Try sending using the configured method
        if method == "smtp":
            # Get SMTP configuration
            smtp_server = options.get("smtp_server", email_config.get("smtp_server", "localhost"))
            smtp_port = int(options.get("smtp_port", email_config.get("smtp_port", 25)))
            use_tls = options.get("use_tls", email_config.get("use_tls", False))
            username = options.get("username", email_config.get("username"))
            password = options.get("password", email_config.get("password"))

            # Send via SMTP
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if use_tls:
                    server.starttls()

                if username and password:
                    server.login(username, password)

                server.send_message(msg)

        elif method == "sendmail":
            # Use sendmail command
            sendmail_proc = subprocess.run(
                ["sendmail", "-t"],
                input=msg.as_string().encode(),
                capture_output=True
            )

            if sendmail_proc.returncode != 0:
                raise ChannelError(f"Sendmail error: {sendmail_proc.stderr.decode()}")

        elif method == "mail":
            # Use mail command
            mail_cmd = ["mail", "-s", subject]

            # Add From header if specified
            if from_addr:
                mail_cmd.extend(["-r", from_addr])

            # Add recipients
            mail_cmd.extend(recipients)

            mail_proc = subprocess.run(
                mail_cmd,
                input=message.encode(),
                capture_output=True
            )

            if mail_proc.returncode != 0:
                raise ChannelError(f"Mail command error: {mail_proc.stderr.decode()}")

        else:
            raise ChannelError(f"Unsupported email method: {method}")

        # Return success
        return {
            "status": "sent",
            "recipients": len(recipients),
            "timestamp": datetime.now().isoformat(),
            "method": method
        }

    def _send_sms(self,
                 message: str,
                 recipients: List[str],
                 priority: str,
                 options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send notification via SMS.

        Args:
            message: SMS message
            recipients: List of phone numbers
            priority: Notification priority
            options: SMS-specific options

        Returns:
            Dictionary with SMS delivery results
        """
        # Check if we have recipients
        if not recipients:
            return {"status": "error", "error": "No recipients specified", "timestamp": datetime.now().isoformat()}

        # Get SMS configuration
        sms_config = self.config.get("channels", {}).get(CHANNEL_SMS, {})
        provider = options.get("provider", sms_config.get("provider", "none"))

        # Limit message length
        max_length = options.get("max_length", 160)
        if len(message) > max_length:
            message = message[:max_length-3] + "..."

        if provider == "none":
            logger.warning("SMS provider not configured")
            return {
                "status": "error",
                "error": "SMS provider not configured",
                "timestamp": datetime.now().isoformat()
            }

        elif provider == "twilio":
            try:
                # Check for twilio module
                import importlib
                if importlib.util.find_spec("twilio") is None:
                    raise ChannelError("Twilio module not available. Install with: pip install twilio")

                from twilio.rest import Client

                # Get Twilio configuration
                account_sid = options.get("account_sid", os.environ.get("TWILIO_ACCOUNT_SID"))
                auth_token = options.get("auth_token", os.environ.get("TWILIO_AUTH_TOKEN"))
                from_number = options.get("from_number", sms_config.get("from_number"))

                if not account_sid or not auth_token:
                    raise ChannelError("Twilio account credentials not configured")

                if not from_number:
                    raise ChannelError("Twilio from number not configured")

                # Initialize Twilio client
                client = Client(account_sid, auth_token)

                # Send messages
                sent_count = 0
                for recipient in recipients:
                    client.messages.create(
                        body=message,
                        from_=from_number,
                        to=recipient
                    )
                    sent_count += 1

                return {
                    "status": "sent",
                    "recipients": sent_count,
                    "timestamp": datetime.now().isoformat(),
                    "provider": "twilio"
                }

            except Exception as e:
                raise ChannelError(f"Twilio SMS error: {str(e)}")

        elif provider == "sns":
            try:
                # Check for boto3 module
                import importlib
                if importlib.util.find_spec("boto3") is None:
                    raise ChannelError("boto3 module not available. Install with: pip install boto3")

                import boto3

                # Initialize SNS client
                sns = boto3.client('sns')

                # Send messages
                sent_count = 0
                for recipient in recipients:
                    sns.publish(
                        PhoneNumber=recipient,
                        Message=message,
                        MessageAttributes={
                            'AWS.SNS.SMS.SenderID': {
                                'DataType': 'String',
                                'StringValue': options.get("sender_id", "NOTIFY")
                            }
                        }
                    )
                    sent_count += 1

                return {
                    "status": "sent",
                    "recipients": sent_count,
                    "timestamp": datetime.now().isoformat(),
                    "provider": "sns"
                }

            except Exception as e:
                raise ChannelError(f"AWS SNS SMS error: {str(e)}")

        else:
            raise ChannelError(f"Unsupported SMS provider: {provider}")

    def _send_slack(self,
                   subject: str,
                   message: str,
                   recipients: List[str],
                   priority: str,
                   options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send notification via Slack.

        Args:
            subject: Message title
            message: Message body
            recipients: List of channels (optional)
            priority: Notification priority
            options: Slack-specific options

        Returns:
            Dictionary with Slack delivery results
        """
        # Get Slack configuration
        slack_config = self.config.get("channels", {}).get(CHANNEL_SLACK, {})
        webhook_url = options.get("webhook_url", slack_config.get("webhook_url"))

        if not webhook_url:
            return {
                "status": "error",
                "error": "Slack webhook URL not configured",
                "timestamp": datetime.now().isoformat()
            }

        # Determine channels to send to
        channels = []
        if recipients:
            channels = recipients
        elif "channel" in options:
            channels = [options["channel"]]
        elif slack_config.get("default_channel"):
            channels = [slack_config["default_channel"]]

        # If no channels specified, send to webhook default
        if not channels:
            channels = ["default"]

        # Map priority to color
        color_map = {
            PRIORITY_LOW: "#2196F3",      # Blue
            PRIORITY_MEDIUM: "#FF9800",   # Orange
            PRIORITY_HIGH: "#F44336",     # Red
            PRIORITY_CRITICAL: "#9C27B0"  # Purple
        }
        color = color_map.get(priority, "#2196F3")

        # Format message for Slack
        payload = {
            "text": subject,
            "attachments": [
                {
                    "color": color,
                    "title": subject,
                    "text": message,
                    "fallback": subject,
                    "fields": []
                }
            ]
        }

        # Add custom fields if provided
        if "fields" in options and isinstance(options["fields"], list):
            payload["attachments"][0]["fields"] = options["fields"]

        # Add footer if provided
        if "footer" in options:
            payload["attachments"][0]["footer"] = options["footer"]

        # Send to each channel
        sent_count = 0
        for channel in channels:
            try:
                # Add channel if not default
                if channel != "default":
                    payload["channel"] = channel

                # Send the message
                response = requests.post(
                    webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code != 200:
                    logger.warning(f"Slack API error: HTTP {response.status_code} - {response.text}")
                else:
                    sent_count += 1

            except Exception as e:
                logger.error(f"Error sending to Slack channel {channel}: {str(e)}")

        return {
            "status": "sent" if sent_count > 0 else "error",
            "channels_sent": sent_count,
            "channels_total": len(channels),
            "timestamp": datetime.now().isoformat()
        }

    def _send_teams(self,
                   subject: str,
                   message: str,
                   recipients: List[str],
                   priority: str,
                   options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send notification via Microsoft Teams.

        Args:
            subject: Message title
            message: Message body
            recipients: Not used for Teams
            priority: Notification priority
            options: Teams-specific options

        Returns:
            Dictionary with Teams delivery results
        """
        # Get Teams configuration
        teams_config = self.config.get("channels", {}).get(CHANNEL_TEAMS, {})
        webhook_url = options.get("webhook_url", teams_config.get("webhook_url"))

        if not webhook_url:
            return {
                "status": "error",
                "error": "Teams webhook URL not configured",
                "timestamp": datetime.now().isoformat()
            }

        # Map priority to color
        color_map = {
            PRIORITY_LOW: "2196F3",      # Blue
            PRIORITY_MEDIUM: "FF9800",   # Orange
            PRIORITY_HIGH: "F44336",     # Red
            PRIORITY_CRITICAL: "9C27B0"  # Purple
        }
        color = color_map.get(priority, "2196F3")

        # Format message for Teams
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": subject,
            "title": subject,
            "sections": [
                {
                    "text": message
                }
            ]
        }

        # Add potential actions if provided
        if "actions" in options and isinstance(options["actions"], list):
            payload["potentialAction"] = options["actions"]

        # Send the message
        try:
            response = requests.post(
                webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code != 200:
                raise ChannelError(f"Teams API error: HTTP {response.status_code} - {response.text}")

            return {
                "status": "sent",
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            raise ChannelError(f"Teams notification error: {str(e)}")

    def _send_webhook(self,
                     subject: str,
                     message: str,
                     recipients: List[str],
                     priority: str,
                     options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send notification via webhook.

        Args:
            subject: Message title
            message: Message body
            recipients: Not used for webhook
            priority: Notification priority
            options: Webhook-specific options

        Returns:
            Dictionary with webhook delivery results
        """
        # Get webhook configuration
        webhook_config = self.config.get("channels", {}).get(CHANNEL_WEBHOOK, {})
        url = options.get("url", webhook_config.get("url"))
        method = options.get("method", webhook_config.get("method", "POST"))
        headers = options.get("headers", webhook_config.get("headers", {}))

        if not url:
            return {
                "status": "error",
                "error": "Webhook URL not configured",
                "timestamp": datetime.now().isoformat()
            }

        # Prepare payload
        payload = {
            "subject": subject,
            "message": message,
            "priority": priority,
            "timestamp": datetime.now().isoformat()
        }

        # Add custom data if provided
        if "data" in options:
            payload["data"] = options["data"]

        # Default headers if not provided
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"

        # Send the request
        try:
            response = requests.request(
                method=method,
                url=url,
                json=payload,
                headers=headers
            )

            if response.status_code < 200 or response.status_code >= 300:
                raise ChannelError(f"Webhook error: HTTP {response.status_code} - {response.text}")

            return {
                "status": "sent",
                "response_code": response.status_code,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            raise ChannelError(f"Webhook notification error: {str(e)}")

    def _send_console(self, subject: str, message: str, priority: str) -> Dict[str, Any]:
        """
        Send notification to console.

        Args:
            subject: Message title
            message: Message body
            priority: Notification priority

        Returns:
            Dictionary with console output results
        """
        # Map priority to color
        color_map = {
            PRIORITY_LOW: "\033[34m",     # Blue
            PRIORITY_MEDIUM: "\033[33m",  # Yellow
            PRIORITY_HIGH: "\033[31m",    # Red
            PRIORITY_CRITICAL: "\033[35m" # Purple
        }
        reset_color = "\033[0m"
        color = color_map.get(priority, "\033[0m")

        # Format message for console
        formatted_message = f"{color}[{subject}]{reset_color}\n{message}"

        # Print to stderr for higher visibility
        print(formatted_message, file=sys.stderr)

        return {
            "status": "sent",
            "timestamp": datetime.now().isoformat()
        }

    def _render_template(self, template: str, data: Dict[str, Any]) -> Union[str, Dict[str, Any]]:
        """
        Render a template with the provided data.

        Args:
            template: Template name or path
            data: Data to render the template with

        Returns:
            Rendered template content or dict with rendered content
        """
        # First check if it's a template file path
        template_path = Path(template)

        # If not an absolute path, check in the configured templates directory
        if not template_path.is_absolute():
            templates_dir = Path(self.config.get("templates_dir", TEMPLATE_DIR))
            template_path = templates_dir / template

        # Try different extensions if no extension provided
        if not template_path.suffix:
            for ext in [".txt", ".html", ".md", ".json"]:
                if (template_path.with_suffix(ext)).exists():
                    template_path = template_path.with_suffix(ext)
                    break

        # Check if the template file exists
        if template_path.exists():
            # Check cache first
            cache_key = str(template_path)
            if cache_key in _template_cache:
                template_content = _template_cache[cache_key]
            else:
                with open(template_path, 'r') as f:
                    template_content = f.read()
                    # Cache the template
                    _template_cache[cache_key] = template_content

            # If it's a JSON template, parse it
            if template_path.suffix.lower() == '.json':
                try:
                    template_data = json.loads(template_content)
                    # Replace placeholders in all strings recursively
                    return self._replace_placeholders_in_dict(template_data, data)
                except json.JSONDecodeError as e:
                    raise TemplateError(f"Invalid JSON template: {str(e)}")

            # Otherwise render as text template
            return self._replace_placeholders(template_content, data)
        else:
            # If not a file, treat it as an inline template
            return self._replace_placeholders(template, data)

    def _replace_placeholders(self, content: str, data: Dict[str, Any]) -> str:
        """
        Replace placeholders in template content with values from data.

        Args:
            content: Template content with placeholders
            data: Data to populate placeholders

        Returns:
            Content with placeholders replaced
        """
        # Replace placeholders with format {key}
        result = content

        # Simple placeholder replacement
        for key, value in data.items():
            placeholder = f"{{{key}}}"
            if isinstance(value, (str, int, float, bool)):
                result = result.replace(placeholder, str(value))

        # Handle conditional blocks
        result = self._process_conditional_blocks(result, data)

        return result

    def _process_conditional_blocks(self, content: str, data: Dict[str, Any]) -> str:
        """
        Process conditional blocks in template content.

        Args:
            content: Template content with conditional blocks
            data: Data to evaluate conditions

        Returns:
            Processed content
        """
        # Match conditional blocks
        import re
        pattern = r'{if\s+([^}]+)}(.*?){else}(.*?){endif}'

        def replace_conditional(match):
            condition = match.group(1).strip()
            if_content = match.group(2)
            else_content = match.group(3)

            # Evaluate condition
            try:
                # Simple equality check
                if '==' in condition:
                    left, right = condition.split('==', 1)
                    left = left.strip()
                    right = right.strip().strip('"\'')

                    # Get value from data
                    left_val = data.get(left)
                    is_true = left_val == right
                # Simple presence check
                else:
                    key = condition
                    is_true = key in data and data[key]

                return if_content if is_true else else_content
            except Exception:
                # On any error, return else content
                return else_content

        # Process all conditional blocks
        result = re.sub(pattern, replace_conditional, content, flags=re.DOTALL)
        return result

    def _replace_placeholders_in_dict(self, d: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Replace placeholders in all string values of a dictionary.

        Args:
            d: Dictionary with placeholders in string values
            data: Data to populate placeholders

        Returns:
            Dictionary with placeholders replaced
        """
        result = {}

        for key, value in d.items():
            if isinstance(value, str):
                result[key] = self._replace_placeholders(value, data)
            elif isinstance(value, dict):
                result[key] = self._replace_placeholders_in_dict(value, data)
            elif isinstance(value, list):
                result[key] = [
                    self._replace_placeholders_in_dict(item, data) if isinstance(item, dict)
                    else (self._replace_placeholders(item, data) if isinstance(item, str) else item)
                    for item in value
                ]
            else:
                result[key] = value

        return result


def send_notification(
    message: str,
    recipients: Optional[Union[str, List[str]]] = None,
    subject: str = "Notification",
    channels: Optional[List[str]] = None,
    priority: str = PRIORITY_MEDIUM,
    **kwargs
) -> Dict[str, Any]:
    """
    Send a notification using the default service configuration.
    This is a convenience wrapper around NotificationService.send().

    Args:
        message: The notification message
        recipients: Recipient(s) for the notification
        subject: Subject line for email/notification title
        channels: List of channels to use
        priority: Notification priority
        **kwargs: Additional options to pass to NotificationService.send()

    Returns:
        Dictionary with delivery results
    """
    service = NotificationService()
    return service.send(message, recipients, subject, channels, priority, **kwargs)


def send_template_notification(
    template: str,
    template_data: Dict[str, Any],
    recipients: Optional[Union[str, List[str]]] = None,
    subject: Optional[str] = None,
    channels: Optional[List[str]] = None,
    priority: str = PRIORITY_MEDIUM,
    **kwargs
) -> Dict[str, Any]:
    """
    Send a templated notification using the default service configuration.
    This is a convenience wrapper around NotificationService.send_template().

    Args:
        template: Template name or path
        template_data: Data to render the template with
        recipients: Recipient(s) for the notification
        subject: Optional subject override (otherwise from template)
        channels: List of channels to use
        priority: Notification priority
        **kwargs: Additional options to pass to NotificationService.send_template()

    Returns:
        Dictionary with delivery results
    """
    service = NotificationService()
    return service.send_template(template, template_data, recipients, subject, channels, priority, **kwargs)


# Command line interface
def main():
    """
    Command line interface for sending notifications.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Send notifications through various channels")
    parser.add_argument("--subject", required=True, help="Notification subject/title")
    parser.add_argument("--message", help="Notification message body")
    parser.add_argument("--priority", choices=["low", "medium", "high", "critical"], default="medium", help="Notification priority")
    parser.add_argument("--channel", action="append", help="Notification channel (can be specified multiple times)")
    parser.add_argument("--recipient", action="append", help="Recipient (can be specified multiple times)")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--template", help="Path to notification template")
    parser.add_argument("--template-var", action="append", help="Template variable in KEY=VALUE format")
    parser.add_argument("--attachment", help="Path to file attachment")
    parser.add_argument("--tracking-id", help="Custom tracking ID for the notification")
    parser.add_argument("--async", action="store_true", help="Send notification asynchronously")

    args = parser.parse_args()

    # Initialize notification service
    notifier = NotificationService(args.config)

    # Process channels
    channels = args.channel if args.channel else None

    # Process recipients
    recipients = args.recipient if args.recipient else None

    # Process template variables
    template_data = {}
    if args.template_var:
        for var in args.template_var:
            if "=" in var:
                key, value = var.split("=", 1)
                template_data[key] = value

    # Set tracking ID
    tracking_id = args.tracking_id

    # If template specified, use template notification
    if args.template:
        # Ensure we have a message in template data
        if args.message:
            template_data["message"] = args.message

        result = notifier.send_template(
            template=args.template,
            template_data=template_data,
            recipients=recipients,
            subject=args.subject,
            channels=channels,
            priority=args.priority,
            tracking_id=tracking_id,
            async_send=getattr(args, "async", False)
        )
    else:
        # Regular notification
        if not args.message:
            parser.error("--message is required when not using a template")

        result = notifier.send(
            message=args.message,
            recipients=recipients,
            subject=args.subject,
            channels=channels,
            priority=args.priority,
            tracking_id=tracking_id,
            async_send=getattr(args, "async", False)
        )

    # Print result
    if result.get("success"):
        print(f"Notification sent successfully. Tracking ID: {result.get('tracking_id')}")
        sys.exit(0)
    else:
        print(f"Error sending notification: {result.get('error', 'unknown error')}")
        sys.exit(1)


if __name__ == "__main__":
    main()
