"""
Email service for sending and managing email delivery.

This module provides a service class that handles email operations such as
template rendering, sending transactional emails, and email delivery tracking.
It abstracts away the details of email server configuration and provides a
clean interface for sending emails throughout the application.
"""

import logging
import os
import re
import smtplib
import uuid
import time
from datetime import datetime, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple, Set
from urllib.parse import urlparse

from flask import current_app, render_template, has_request_context, request
from jinja2 import Template

from core.security import sanitize_url, log_security_event
from extensions import db, metrics, cache

logger = logging.getLogger(__name__)

# Email validation constants
EMAIL_MAX_LENGTH = 254
EMAIL_PATTERN = r"^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"

# Dangerous file extensions that should not be attached
DANGEROUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.msi', '.vbs', '.js', '.jar', '.dll',
    '.scr', '.pif', '.com', '.reg', '.ps1', '.hta', '.msc', '.wsf'
}

# Security-sensitive words/patterns for email content moderation
SENSITIVE_CONTENT_PATTERNS = [
    r'password', r'credit.?card', r'secret', r'credentials',
    r'social.?security', r'ssn', r'bank.?account'
]


class EmailDeliveryException(Exception):
    """Exception raised for email delivery failures."""
    pass


class EmailRenderException(Exception):
    """Exception raised for template rendering failures."""
    pass


class EmailValidationException(Exception):
    """Exception raised for email validation failures."""
    pass


class EmailService:
    """
    Service for handling email sending and delivery.

    This class provides methods for sending emails with various configurations
    and can be extended to support different email providers.
    """

    def __init__(self,
                smtp_server: Optional[str] = None,
                port: int = 587,
                username: Optional[str] = None,
                password: Optional[str] = None,
                use_tls: bool = True,
                from_email: Optional[str] = None,
                from_name: Optional[str] = None,
                max_retries: int = 2,
                timeout: int = 30):
        """
        Initialize the email service.

        Args:
            smtp_server: SMTP server address
            port: SMTP server port
            username: SMTP username
            password: SMTP password
            use_tls: Whether to use TLS encryption
            from_email: Default sender email address
            from_name: Default sender name
            max_retries: Maximum number of retry attempts for failed sends
            timeout: Timeout in seconds for SMTP operations
        """
        self.smtp_server = smtp_server
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.from_email = from_email
        self.from_name = from_name
        self.max_retries = max_retries
        self.timeout = timeout

        # Generate instance ID for tracking
        self._instance_id = str(uuid.uuid4())[:8]
        logger.debug("EmailService instance created with ID: %s", self._instance_id)

    def send_email(self,
                   to: Union[str, List[str]],
                   subject: str,
                   text_content: Optional[str] = None,
                   html_content: Optional[str] = None,
                   from_email: Optional[str] = None,
                   from_name: Optional[str] = None,
                   cc: Optional[Union[str, List[str]]] = None,
                   bcc: Optional[Union[str, List[str]]] = None,
                   reply_to: Optional[str] = None,
                   attachments: Optional[List[Dict[str, Any]]] = None,
                   categories: Optional[List[str]] = None,
                   headers: Optional[Dict[str, str]] = None,
                   track_clicks: bool = False,
                   track_opens: bool = False,
                   message_id: Optional[str] = None,
                   priority: str = "normal",
                   tracking_id: Optional[str] = None,
                   category: Optional[str] = None,
                   respect_preferences: bool = True) -> bool:
        """
        Send an email with the configured settings.

        Args:
            to: Recipient email address or list of addresses
            subject: Email subject line
            text_content: Plain text email content
            html_content: HTML email content
            from_email: Sender email address (overrides default)
            from_name: Sender name (overrides default)
            cc: Carbon copy recipients
            bcc: Blind carbon copy recipients
            reply_to: Reply-to email address
            attachments: List of attachment dictionaries with 'content', 'filename',
                         and optional 'content_type' keys
            categories: Email categories for analytics and filtering
            headers: Additional email headers to include
            track_clicks: Whether to track link clicks
            track_opens: Whether to track email opens
            message_id: Custom message ID for tracking
            priority: Email priority (low, normal, high)
            tracking_id: External tracking ID for cross-system correlation
            category: Email category for filtering and preference management
            respect_preferences: Whether to respect user communication preferences

        Returns:
            Boolean indicating if the email was sent successfully

        Raises:
            ValueError: If neither text_content nor html_content is provided or if
                      required configuration is missing
            EmailValidationException: If email addresses are invalid
        """
        # Generate message ID if not provided
        message_id = message_id or f"msg_{uuid.uuid4().hex}"

        try:
            if not text_content and not html_content:
                raise ValueError("Either text_content or html_content must be provided")

            # Validate recipients
            if isinstance(to, str):
                if not self._is_valid_email(to):
                    raise EmailValidationException(f"Invalid recipient email address: {to}")
                recipients = [to]
            else:
                if not to:
                    raise EmailValidationException("At least one recipient is required")
                recipients = []
                for email in to:
                    if self._is_valid_email(email):
                        recipients.append(email)
                    else:
                        logger.warning("Invalid recipient email skipped: %s", email)
                        metrics.increment('email.invalid_recipient')

                if not recipients:
                    raise EmailValidationException("No valid recipient email addresses provided")

            # Filter recipients based on communication preferences if requested
            if respect_preferences:
                recipients = self._filter_by_preferences(recipients, category)
                if not recipients:
                    logger.info("No recipients remaining after preference filtering")
                    metrics.increment('email.skipped_by_preferences')
                    return True  # Consider this a success since we respected preferences

            # Get sender information
            sender_email = from_email or self.from_email or current_app.config.get('MAIL_DEFAULT_SENDER')
            sender_name = from_name or self.from_name or current_app.config.get('MAIL_DEFAULT_SENDER_NAME')

            if not sender_email:
                raise ValueError("Sender email is required")

            if not self._is_valid_email(sender_email):
                raise EmailValidationException(f"Invalid sender email address: {sender_email}")

            # Validate and prepare CC and BCC lists
            validated_cc = self._validate_email_list(cc) if cc else None
            validated_bcc = self._validate_email_list(bcc) if bcc else None

            # Validate reply_to if present
            if reply_to and not self._is_valid_email(reply_to):
                logger.warning("Invalid reply-to email address: %s", reply_to)
                reply_to = None

            # Check for sensitive content patterns
            if self._contains_sensitive_content(subject, text_content, html_content):
                logger.warning("Email with potentially sensitive content detected (msgid: %s)", message_id)
                metrics.increment('email.sensitive_content_detected')

            # Create message and recipient list
            msg, all_recipients = self._create_message(
                sender_email=sender_email,
                sender_name=sender_name,
                recipients=recipients,
                subject=subject,
                cc=validated_cc,
                bcc=validated_bcc,
                reply_to=reply_to,
                message_id=message_id,
                priority=priority,
                headers=headers,
                tracking_id=tracking_id,
                category=category
            )

            # Add content
            if text_content:
                # Ensure text content is properly sanitized
                clean_text = self._sanitize_content(text_content)
                msg.attach(MIMEText(clean_text, 'plain', 'utf-8'))

            if html_content:
                # Validate and sanitize HTML content
                clean_html = self._sanitize_html(html_content)

                # Add tracking pixels if needed
                if track_opens and 'DISABLE_EMAIL_TRACKING' not in current_app.config.get('SECURITY_SETTINGS', {}):
                    clean_html = self._add_tracking_pixel(clean_html, message_id)

                # Add link tracking if needed
                if track_clicks and 'DISABLE_EMAIL_TRACKING' not in current_app.config.get('SECURITY_SETTINGS', {}):
                    clean_html = self._add_link_tracking(clean_html, message_id)

                msg.attach(MIMEText(clean_html, 'html', 'utf-8'))

            # Add attachments if present
            if attachments:
                for attachment in attachments:
                    try:
                        self._add_attachment(msg, attachment)
                    except ValueError as e:
                        logger.warning("Skipping invalid attachment: %s", str(e))
                        metrics.increment('email.invalid_attachment')

            # Track custom categories if provided
            if categories:
                categories_str = ','.join(categories[:5])  # Limit to 5 categories
                msg['X-Categories'] = categories_str

            # Log email attempt
            self._log_email_attempt(
                message_id=message_id,
                to=recipients,
                subject=subject,
                categories=categories,
                tracking_id=tracking_id,
                category=category
            )

            # Send email with retry logic
            return self._send_message_with_retry(msg, sender_email, all_recipients, message_id)

        except (ValueError, EmailValidationException) as e:
            logger.error("Email validation error: %s", str(e))
            metrics.increment('email.validation_error')
            raise

        except Exception as e:
            logger.error("Unexpected error in send_email: %s", str(e), exc_info=True)
            metrics.increment('email.unexpected_error')
            return False

    def send_template_email(self,
                          to: Union[str, List[str]],
                          subject: str,
                          template_name: str,
                          template_data: Dict[str, Any],
                          **kwargs) -> bool:
        """
        Send an email using a template.

        This method renders a template with the provided data and sends it as an email.

        Args:
            to: Recipient email address or list of addresses
            subject: Email subject line
            template_name: Name of the template to render (without extension)
            template_data: Dictionary of data to pass to the template
            **kwargs: Additional parameters to pass to send_email()

        Returns:
            Boolean indicating if the email was sent successfully

        Raises:
            EmailRenderException: If the template cannot be found or rendered
            EmailDeliveryException: If sending the email fails
        """
        try:
            # Generate message ID
            message_id = kwargs.pop('message_id', None) or f"template_{uuid.uuid4().hex}"

            # Add tracking ID to template data if provided in kwargs
            if 'tracking_id' in kwargs and 'tracking_id' not in template_data:
                template_data['tracking_id'] = kwargs['tracking_id']

            # Add standard template data
            enriched_data = self._enrich_template_data(template_data)

            # Try to load both HTML and text templates
            html_content = None
            text_content = None

            try:
                html_content = render_template(f"emails/{template_name}.html", **enriched_data)
            except Exception as e:
                logger.warning("Failed to render HTML template %s: %s", template_name, str(e))
                metrics.increment('email.template_render_error_html')

            try:
                text_content = render_template(f"emails/{template_name}.txt", **enriched_data)
            except Exception as e:
                logger.warning("Failed to render text template %s: %s", template_name, str(e))
                metrics.increment('email.template_render_error_text')

            # Ensure at least one template was loaded
            if not html_content and not text_content:
                raise EmailRenderException(f"Failed to render both HTML and text templates for {template_name}")

            # Check template rendering succeeded
            metrics.increment('email.template_render_success')

            # Send the email with the rendered templates
            success = self.send_email(
                to=to,
                subject=subject,
                html_content=html_content,
                text_content=text_content,
                message_id=message_id,
                **kwargs
            )

            if not success:
                raise EmailDeliveryException(f"Failed to send template email: {template_name}")

            return success

        except EmailRenderException as e:
            logger.error("Template rendering error: %s", str(e))
            metrics.increment('email.template_error')
            raise

        except Exception as e:
            logger.error("Failed to send template email: %s", str(e), exc_info=True)
            metrics.increment('email.template_send_error')
            return False

    def send_bulk_emails(self,
                         recipients: List[Dict[str, Any]],
                         subject: str,
                         template_name: Optional[str] = None,
                         text_content: Optional[str] = None,
                         html_content: Optional[str] = None,
                         delay_between_sends: float = 0.1,
                         batch_id: Optional[str] = None,
                         respect_preferences: bool = True,
                         category: Optional[str] = None) -> Dict[str, Any]:
        """
        Send emails to multiple recipients with personalized content.

        Args:
            recipients: List of recipient dictionaries with 'email' key and any template variables
            subject: Email subject line
            template_name: Name of the template to render (optional)
            text_content: Plain text content template (optional)
            html_content: HTML content template (optional)
            delay_between_sends: Delay between sends in seconds to avoid rate limiting
            batch_id: Unique identifier for this batch of emails
            respect_preferences: Whether to respect user communication preferences
            category: Email category for filtering and preference management

        Returns:
            Dictionary with counts of successful and failed emails and batch statistics

        Raises:
            ValueError: If no content is provided or if required parameters are missing
        """
        import time  # Import here to avoid top-level import

        if not template_name and not text_content and not html_content:
            raise ValueError("Either template_name, text_content, or html_content must be provided")

        if not recipients:
            return {
                'successful': 0,
                'failed': 0,
                'total': 0,
                'skipped': 0,
                'batch_id': None
            }

        # Generate a batch ID if not provided
        batch_id = batch_id or f"batch_{uuid.uuid4().hex}"

        # Extract just the email addresses for duplicate checking
        email_addresses = [r.get('email', '').lower().strip() for r in recipients if r.get('email')]
        unique_emails = set(email_addresses)

        # Track duplicates
        duplicate_count = len(email_addresses) - len(unique_emails)

        # Start with empty results
        results = {
            'successful': 0,
            'failed': 0,
            'total': len(recipients),
            'skipped': 0,
            'duplicates': duplicate_count,
            'preference_filtered': 0,
            'batch_id': batch_id,
            'start_time': str(datetime.now()),
            'category': category
        }

        # Track unique emails to avoid duplicates in the same batch
        processed_emails = set()

        # Log batch start
        logger.info("Starting bulk email batch %s with %d recipients (category: %s)",
                   batch_id, len(recipients), category or "none")

        # Create a database record for the batch if available
        self._record_email_batch(batch_id, results['total'], category=category)

        for recipient in recipients:
            email = recipient.get('email', '').lower().strip()

            # Skip invalid or missing emails
            if not email or not self._is_valid_email(email):
                results['skipped'] += 1
                continue

            # Skip duplicates if already processed in this batch
            if email in processed_emails:
                results['skipped'] += 1
                continue

            # Check communication preferences if requested
            if respect_preferences:
                if not self._check_recipient_preference(email, category):
                    results['preference_filtered'] += 1
                    continue

            processed_emails.add(email)

            # Generate a message ID for tracking
            message_id = f"{batch_id}_{uuid.uuid4().hex[:8]}"
            recipient['message_id'] = message_id

            try:
                # If using a template
                if template_name:
                    success = self.send_template_email(
                        to=email,
                        subject=subject,
                        template_name=template_name,
                        template_data=recipient,
                        message_id=message_id,
                        category=category
                    )
                else:
                    # Replace placeholders in content using recipient data
                    final_text = self._personalize_content(text_content, recipient) if text_content else None
                    final_html = self._personalize_content(html_content, recipient) if html_content else None

                    success = self.send_email(
                        to=email,
                        subject=subject,
                        text_content=final_text,
                        html_content=final_html,
                        message_id=message_id,
                        category=category
                    )

                if success:
                    results['successful'] += 1
                    self._update_email_batch(batch_id, sent=1)
                else:
                    results['failed'] += 1
                    self._update_email_batch(batch_id, failed=1)

            except Exception as e:
                logger.error("Failed to send email to %s: %s", email, str(e))
                results['failed'] += 1
                self._update_email_batch(batch_id, failed=1)
                metrics.increment('email.bulk_send_error')

            # Add delay between sends to avoid rate limiting
            if delay_between_sends > 0 and results['successful'] + results['failed'] < len(recipients):
                time.sleep(delay_between_sends)

        # Update final batch status
        self._update_email_batch(batch_id, completed=True)

        # Calculate success rate
        processed = results['successful'] + results['failed']
        if processed > 0:
            results['success_rate'] = round(results['successful'] / processed * 100, 1)
        else:
            results['success_rate'] = 0

        results['end_time'] = str(datetime.now())

        # Log batch completion
        logger.info("Completed bulk email batch %s: %d sent, %d failed, %d skipped (%d preference filtered)",
                   batch_id, results['successful'], results['failed'], results['skipped'], results['preference_filtered'])

        return results

    def verify_connection(self) -> Dict[str, Any]:
        """
        Verify that the SMTP connection is working.

        Returns:
            Dict with connection test results
        """
        result = {
            'success': False,
            'server': self.smtp_server or current_app.config.get('SMTP_SERVER'),
            'port': self.port or current_app.config.get('SMTP_PORT', 587),
            'use_tls': self.use_tls if self.use_tls is not None else current_app.config.get('SMTP_USE_TLS', True),
            'has_auth': bool(self.username or current_app.config.get('SMTP_USERNAME'))
        }

        try:
            # Verify SMTP configuration
            smtp_server = result['server']
            port = result['port']

            if not smtp_server:
                result['error'] = "SMTP server not configured"
                return result

            # Test SMTP connection
            with smtplib.SMTP(smtp_server, port, timeout=10) as smtp:
                result['connect'] = True

                # Try EHLO
                ehlo_response = smtp.ehlo()
                result['ehlo'] = ehlo_response[0] == 250

                # Try TLS if enabled
                if result['use_tls']:
                    starttls_response = smtp.starttls()
                    result['tls'] = starttls_response[0] == 220

                    # Second EHLO after TLS
                    ehlo2_response = smtp.ehlo()
                    result['ehlo_tls'] = ehlo2_response[0] == 250

                # Check authentication if provided
                username = self.username or current_app.config.get('SMTP_USERNAME')
                password = self.password or current_app.config.get('SMTP_PASSWORD')

                if username and password:
                    try:
                        login_response = smtp.login(username, password)
                        result['auth'] = login_response[0] == 235
                    except (smtplib.SMTPAuthenticationError, smtplib.SMTPException) as e:
                        result['auth'] = False
                        result['auth_error'] = str(e)

            # Overall success
            result['success'] = result.get('connect', False) and (
                not result['use_tls'] or result.get('tls', False)
            ) and (
                not result['has_auth'] or result.get('auth', False)
            )

            return result

        except (smtplib.SMTPException, ConnectionError, TimeoutError) as e:
            result['error'] = str(e)
            result['success'] = False
            return result

    def _create_message(self,
                      sender_email: str,
                      sender_name: Optional[str],
                      recipients: List[str],
                      subject: str,
                      cc: Optional[Union[str, List[str]]] = None,
                      bcc: Optional[Union[str, List[str]]] = None,
                      reply_to: Optional[str] = None,
                      message_id: Optional[str] = None,
                      priority: str = "normal",
                      headers: Optional[Dict[str, str]] = None,
                      tracking_id: Optional[str] = None,
                      category: Optional[str] = None) -> Tuple[MIMEMultipart, List[str]]:
        """
        Create an email message with the specified headers.

        Args:
            sender_email: Sender's email address
            sender_name: Sender's name (optional)
            recipients: List of primary recipient email addresses
            subject: Email subject line
            cc: Carbon copy recipients
            bcc: Blind carbon copy recipients
            reply_to: Reply-to email address
            message_id: Custom message ID
            priority: Email priority (low, normal, high)
            headers: Additional email headers
            tracking_id: External tracking ID for cross-system correlation
            category: Email category for filtering

        Returns:
            Tuple containing:
            - The created MIMEMultipart message object
            - List of all recipient addresses (To + CC + BCC)
        """
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject

        # Add default security headers
        msg['X-Content-Type-Options'] = 'nosniff'
        msg['X-XSS-Protection'] = '1; mode=block'

        # Set message ID
        if message_id:
            domain = sender_email.split('@')[-1]
            msg['Message-ID'] = f"<{message_id}@{domain}>"

        # Set priority
        if priority == "high":
            msg['X-Priority'] = '1'
            msg['X-MSMail-Priority'] = 'High'
            msg['Importance'] = 'High'  # RFC 1327 header
        elif priority == "low":
            msg['X-Priority'] = '5'
            msg['X-MSMail-Priority'] = 'Low'
            msg['Importance'] = 'Low'   # RFC 1327 header
        else:  # normal priority
            msg['X-Priority'] = '3'
            msg['X-MSMail-Priority'] = 'Normal'
            msg['Importance'] = 'Normal'  # RFC 1327 header

        # Set headers
        if sender_name:
            msg['From'] = f"{sender_name} <{sender_email}>"
        else:
            msg['From'] = sender_email

        msg['To'] = ', '.join(recipients)

        # Track all recipients for SMTP sendmail
        all_recipients = recipients.copy()

        # Add CC recipients if specified
        if cc:
            cc_list = [cc] if isinstance(cc, str) else list(cc)
            msg['Cc'] = ', '.join(cc_list)
            all_recipients.extend(cc_list)

        # Add BCC recipients to the delivery list but not to headers
        if bcc:
            bcc_list = [bcc] if isinstance(bcc, str) else list(bcc)
            all_recipients.extend(bcc_list)

        # Set reply-to if specified
        if reply_to:
            msg['Reply-To'] = reply_to

        # Add tracking ID if provided
        if tracking_id:
            msg['X-Tracking-ID'] = tracking_id

        # Add category if provided
        if category:
            msg['X-Category'] = category

        # Add custom headers if provided
        if headers:
            for header_name, header_value in headers.items():
                # Filter out any potentially dangerous headers
                if header_name.lower() not in {'content-type', 'mime-version',
                                              'from', 'to', 'cc', 'bcc',
                                              'message-id', 'sender'}:
                    msg[header_name] = header_value

        # Add date header
        msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')

        # Add application information
        app_name = current_app.config.get('APPLICATION_NAME', 'Cloud Infrastructure Platform')
        app_version = current_app.config.get('VERSION', '1.0.0')
        msg['X-Mailer'] = f"{app_name}/{app_version}"

        return msg, all_recipients

    def _send_message(self, msg: MIMEMultipart, sender_email: str, recipients: List[str],
                     message_id: Optional[str] = None) -> bool:
        """
        Send an email message via SMTP.

        Args:
            msg: The prepared email message
            sender_email: Sender's email address
            recipients: List of all recipients
            message_id: Message identifier for tracking

        Returns:
            Boolean indicating if the email was sent successfully
        """
        try:
            # Get SMTP settings
            smtp_server = self.smtp_server or current_app.config.get('SMTP_SERVER')
            port = self.port or current_app.config.get('SMTP_PORT', 587)
            username = self.username or current_app.config.get('SMTP_USERNAME')
            password = self.password or current_app.config.get('SMTP_PASSWORD')
            use_tls = self.use_tls if self.use_tls is not None else current_app.config.get('SMTP_USE_TLS', True)
            timeout = self.timeout

            if not smtp_server:
                raise ValueError("SMTP server is required")

            # Connect and send with context manager for automatic cleanup
            with smtplib.SMTP(smtp_server, port, timeout=timeout) as smtp:
                # SMTP debugging if in development mode
                if current_app.config.get('DEBUG', False):
                    smtp.set_debuglevel(1)

                # Use TLS if enabled
                if use_tls:
                    smtp.starttls()

                # Authenticate if credentials are provided
                if username and password:
                    smtp.login(username, password)

                # Send the email
                smtp.sendmail(
                    sender_email,
                    recipients,
                    msg.as_string()
                )

                if message_id:
                    logger.info("Email [%s] sent successfully to %d recipients",
                              message_id, len(recipients))
                else:
                    logger.info("Email sent successfully to %d recipients", len(recipients))

                metrics.increment('email.send_success')
                return True

        except (smtplib.SMTPException, ValueError, ConnectionError, TimeoutError) as e:
            if message_id:
                logger.error("Failed to send email [%s]: %s", message_id, str(e))
            else:
                logger.error("Failed to send email: %s", str(e))

            metrics.increment('email.send_error')

            # Track specific error types
            if isinstance(e, smtplib.SMTPRecipientsRefused):
                metrics.increment('email.recipient_refused')
            elif isinstance(e, smtplib.SMTPAuthenticationError):
                metrics.increment('email.authentication_error')
            elif isinstance(e, TimeoutError):
                metrics.increment('email.timeout')

            return False

    def _send_message_with_retry(self, msg: MIMEMultipart, sender_email: str, recipients: List[str],
                                message_id: Optional[str] = None) -> bool:
        """
        Send an email message with retry logic.

        Args:
            msg: The prepared email message
            sender_email: Sender's email address
            recipients: List of all recipients
            message_id: Message identifier for tracking

        Returns:
            Boolean indicating if the email was sent successfully
        """
        retries = 0
        max_retries = self.max_retries

        while retries <= max_retries:
            if retries > 0:
                logger.info("Retry %d/%d for email [%s]",
                          retries, max_retries, message_id or "unknown")
                metrics.increment('email.retry')

            success = self._send_message(msg, sender_email, recipients, message_id)

            if success:
                if retries > 0:
                    metrics.increment('email.retry_success')
                return True

            retries += 1

            if retries <= max_retries:
                # Exponential backoff: 1s, 2s, 4s, etc.
                backoff = 2 ** (retries - 1)
                time.sleep(backoff)

        # If we get here, all retries failed
        logger.error("All %d send attempts failed for email [%s]",
                   max_retries + 1, message_id or "unknown")

        # Record failure details
        self._record_delivery_failure(
            message_id=message_id or "unknown",
            recipient_count=len(recipients),
            error="Maximum retry attempts reached"
        )

        return False

    def _add_attachment(self, msg: MIMEMultipart, attachment: Dict[str, Any]) -> None:
        """
        Add an attachment to the email message.

        Args:
            msg: The email message to add the attachment to
            attachment: Attachment information dictionary with:
                      - 'content': file content as bytes or file-like object
                      - 'filename': name of the file
                      - 'content_type': MIME type (optional)

        Raises:
            ValueError: If required attachment information is missing or if attachment is invalid
        """
        if not attachment.get('content') or not attachment.get('filename'):
            raise ValueError("Attachment must contain 'content' and 'filename'")

        content = attachment['content']
        filename = attachment['filename'].strip()
        content_type = attachment.get('content_type', 'application/octet-stream')

        # Security checks for attachments

        # Check for potentially dangerous file extensions
        _, file_ext = os.path.splitext(filename.lower())
        if file_ext in DANGEROUS_EXTENSIONS:
            raise ValueError(f"Potentially dangerous file type not allowed: {file_ext}")

        # Limit attachment size (10MB by default or configurable)
        max_size = current_app.config.get('MAX_EMAIL_ATTACHMENT_SIZE', 10 * 1024 * 1024)

        if hasattr(content, 'read'):  # File-like object
            content_bytes = content.read()
            if hasattr(content, 'seek'):
                content.seek(0)  # Reset file pointer for future reads
        elif isinstance(content, str):
            content_bytes = content.encode('utf-8')
        else:
            content_bytes = content  # Assume it's already bytes

        if len(content_bytes) > max_size:
            raise ValueError(f"Attachment exceeds maximum allowed size ({max_size} bytes)")

        # Create attachment part
        attachment_part = MIMEApplication(content_bytes)
        attachment_part.add_header(
            'Content-Disposition',
            f'attachment; filename="{filename}"'
        )
        attachment_part.add_header('Content-Type', content_type)

        # Add the attachment to the message
        msg.attach(attachment_part)

        # Track metrics
        metrics.increment('email.attachment_sent')


    def _personalize_content(self, content: str, data: Dict[str, Any]) -> str:
        """
        Replace placeholders in content with values from data dictionary using Jinja2 templates.

        Args:
            content: Content string with placeholders in Jinja2 format {{ variable }}
            data: Dictionary with variable values

        Returns:
            Personalized content string
        """
        if not content:
            return ""

        try:
            # Use Jinja2 template for more robust variable replacement
            template = Template(content)
            return template.render(**data)
        except Exception as e:
            logger.warning("Error personalizing content: %s", str(e))

            # Fallback to simple replacement for robustness
            personalized = content
            for key, value in data.items():
                try:
                    personalized = personalized.replace(f"{{{{{key}}}}}", str(value))
                except Exception:
                    pass

            return personalized

    def _is_valid_email(self, email: str) -> bool:
        """
        Validate an email address format.

        Args:
            email: The email address to validate

        Returns:
            Boolean indicating if the email address has a valid format
        """
        if not email or not isinstance(email, str):
            return False

        # Trim whitespace
        email = email.strip()

        # Check length constraints
        if len(email) > EMAIL_MAX_LENGTH:
            return False

        # Match RFC 5322 compatible pattern
        return bool(re.match(EMAIL_PATTERN, email))

    def _validate_email_list(self, emails: Union[str, List[str]]) -> List[str]:
        """
        Validate a list of email addresses and return only the valid ones.

        Args:
            emails: Email address or list of email addresses

        Returns:
            List of valid email addresses
        """
        if isinstance(emails, str):
            emails = [emails]

        valid_emails = []
        for email in emails:
            if self._is_valid_email(email):
                valid_emails.append(email)

        return valid_emails

    def _sanitize_content(self, content: str) -> str:
        """
        Sanitize plain text content by removing potentially harmful content.

        Args:
            content: Plain text content

        Returns:
            Sanitized content
        """
        if not content:
            return ""

        # Remove null bytes and control characters (except newlines and tabs)
        return re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', content)

    def _sanitize_html(self, html_content: str) -> str:
        """
        Sanitize HTML content to remove potentially dangerous elements.

        Args:
            html_content: HTML content to sanitize

        Returns:
            Sanitized HTML content
        """
        if not html_content:
            return ""

        # For comprehensive HTML sanitization, consider using bleach or html_sanitizer
        # Here we'll do basic sanitization

        # Replace null bytes, they can be used for obfuscation
        sanitized = re.sub(r'[\x00]', '', html_content)

        # Remove potentially dangerous scripts, frames, etc.
        dangerous_patterns = [
            r'<script.*?>.*?</script>',
            r'<iframe.*?>.*?</iframe>',
            r'<object.*?>.*?</object>',
            r'<embed.*?>.*?</embed>',
            r'javascript:',
            r'vbscript:',
            r'data:text/html',
            r'expression\(',
        ]

        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)

        # Sanitize URLs in href and src attributes
        sanitized = re.sub(r'(href|src)="([^"]*)"', self._sanitize_url_match, sanitized)
        sanitized = re.sub(r"(href|src)='([^']*)'", self._sanitize_url_match, sanitized)

        return sanitized

    def _sanitize_url_match(self, match) -> str:
        """
        Sanitize a URL in an HTML attribute match.

        Args:
            match: Regex match object with the HTML attribute

        Returns:
            Sanitized HTML attribute
        """
        attribute = match.group(1)
        url = match.group(2)

        # Use the security utility for URL sanitization
        safe_url = sanitize_url(url)

        # Return the sanitized attribute
        return f'{attribute}="{safe_url}"'

    def _add_tracking_pixel(self, html_content: str, message_id: str) -> str:
        """
        Add a tracking pixel to HTML content for open tracking.

        Args:
            html_content: HTML content
            message_id: Message ID for tracking

        Returns:
            HTML content with tracking pixel
        """
        # Create tracking URL
        site_url = current_app.config.get('SITE_URL', '')
        tracking_url = f"{site_url}/email/track/open/{message_id}"

        # Create tracking pixel HTML
        pixel_html = f'<img src="{tracking_url}" width="1" height="1" alt="" style="display:none;width:1px;height:1px;"/>'

        # Add pixel before the closing body tag
        if '</body>' in html_content.lower():
            html_content = html_content.replace('</body>', f'{pixel_html}</body>', 1)
        else:
            html_content += pixel_html

        return html_content

    def _add_link_tracking(self, html_content: str, message_id: str) -> str:
        """
        Add link tracking to HTML content.

        Args:
            html_content: HTML content
            message_id: Message ID for tracking

        Returns:
            HTML content with tracked links
        """
        # Create base tracking URL
        site_url = current_app.config.get('SITE_URL', '')
        tracking_base = f"{site_url}/email/track/click/{message_id}"

        def _replace_link(match):
            href = match.group(1)
            rest = match.group(2)

            # Skip tracking for special links
            if href.startswith('#') or href.startswith('mailto:') or href.startswith('tel:'):
                return match.group(0)

            # Encode the URL
            import urllib.parse
            encoded_url = urllib.parse.quote_plus(href)

            # Create tracking URL
            tracking_url = f"{tracking_base}?url={encoded_url}"

            return f'href="{tracking_url}"{rest}'

        # Replace all href attributes
        return re.sub(r'href="([^"]*)"(.*?)', _replace_link, html_content)

    def _contains_sensitive_content(self, subject: str, text_content: Optional[str],
                                  html_content: Optional[str]) -> bool:
        """
        Check if content contains potentially sensitive information.

        Args:
            subject: Email subject
            text_content: Plain text content
            html_content: HTML content

        Returns:
            Boolean indicating if sensitive content was detected
        """
        # Combine all text to check
        all_text = subject + " " + (text_content or "")
        if html_content:
            # Extract text from HTML for checking
            text_from_html = re.sub(r'<[^>]*>', ' ', html_content)
            all_text += " " + text_from_html

        all_text = all_text.lower()

        # Check for sensitive patterns
        for pattern in SENSITIVE_CONTENT_PATTERNS:
            if re.search(pattern, all_text):
                return True

        return False

    def _enrich_template_data(self, template_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add standard data to template variables.

        Args:
            template_data: Original template data

        Returns:
            Enriched template data dictionary
        """
        from datetime import datetime

        # Create a copy to avoid modifying the original
        data = template_data.copy()

        # Add standard variables if they don't exist
        defaults = {
            'site_name': current_app.config.get('SITE_NAME', 'Cloud Infrastructure Platform'),
            'site_url': current_app.config.get('SITE_URL', ''),
            'current_year': datetime.now().year,
            'company_name': current_app.config.get('COMPANY_NAME', 'Your Company'),
            'contact_email': current_app.config.get('CONTACT_EMAIL', 'support@example.com'),
            'unsubscribe_url': current_app.config.get('UNSUBSCRIBE_URL', '#'),
        }

        # Only add if not already present
        for key, value in defaults.items():
            if key not in data:
                data[key] = value

        return data

    def _log_email_attempt(self, message_id: str, to: List[str],
                          subject: str, categories: Optional[List[str]] = None,
                          tracking_id: Optional[str] = None,
                          category: Optional[str] = None) -> None:
        """
        Log email sending attempt for audit and metrics.

        Args:
            message_id: Email message ID
            to: Recipient list
            subject: Email subject
            categories: Email categories
            tracking_id: External tracking ID
            category: Email category
        """
        # Log to application logs
        logger.info("Sending email [%s] to %d recipients, subject: %s, category: %s",
                   message_id, len(to), subject, category or "none")

        # Track metrics
        metrics.increment('email.send_attempt')

        # Track by category if provided
        if category:
            metrics.increment(f'email.category.{category}')

        if categories:
            for cat in categories[:5]:  # Limit to 5 categories
                metrics.increment(f'email.category.{cat}')

        # If we're in a request context, record user info for audit
        if has_request_context():
            try:
                # Record who sent the email for audit purposes
                details = {
                    'message_id': message_id,
                    'recipient_count': len(to),
                    'subject': subject
                }

                if categories:
                    details['categories'] = categories

                if tracking_id:
                    details['tracking_id'] = tracking_id

                if category:
                    details['category'] = category

                log_security_event(
                    event_type="email_sent",
                    description=f"Email sent to {len(to)} recipients",
                    severity="info",
                    details=details
                )
            except Exception as e:
                logger.warning("Failed to log email security event: %s", str(e))

    def _record_email_batch(self, batch_id: str, total: int, category: Optional[str] = None) -> bool:
        """
        Record email batch in the database if available.

        Args:
            batch_id: Batch identifier
            total: Total number of emails in batch
            category: Email category

        Returns:
            Boolean indicating if recording was successful
        """
        try:
            # We'll check if the EmailBatch model is available
            try:
                from models.communication.email import EmailBatch

                # Create record
                batch = EmailBatch(
                    batch_id=batch_id,
                    total_count=total,
                    sent_count=0,
                    failed_count=0,
                    status='started',
                    category=category
                )

                db.session.add(batch)
                db.session.commit()
                return True

            except ImportError:
                # Model not available, this is optional functionality
                return False

        except Exception as e:
            logger.warning("Failed to record email batch: %s", str(e))
            return False

    def _update_email_batch(self, batch_id: str, sent: int = 0,
                           failed: int = 0, completed: bool = False) -> bool:
        """
        Update email batch status in the database if available.

        Args:
            batch_id: Batch identifier
            sent: Number of newly sent emails
            failed: Number of newly failed emails
            completed: Whether the batch is completed

        Returns:
            Boolean indicating if update was successful
        """
        try:
            # Try to update the email batch record
            try:
                from models.communication.email import EmailBatch

                # Find and update record
                batch = EmailBatch.query.filter_by(batch_id=batch_id).first()
                if batch:
                    batch.sent_count += sent
                    batch.failed_count += failed

                    if completed:
                        batch.status = 'completed'
                        batch.completed_at = datetime.now(timezone.utc)

                    db.session.commit()
                    return True

                return False

            except ImportError:
                # Model not available, this is optional functionality
                return False

        except Exception as e:
            logger.warning("Failed to update email batch: %s", str(e))
            return False

    def _filter_by_preferences(self, recipients: List[str], category: Optional[str] = None) -> List[str]:
        """
        Filter recipients based on their communication preferences.

        Args:
            recipients: List of recipient email addresses
            category: Email category for preference matching

        Returns:
            Filtered list of recipient email addresses
        """
        # If no integration with preference models, return all recipients
        try:
            from models.communication.user_preference import CommunicationPreference
            from models import User
        except ImportError:
            return recipients

        filtered_recipients = []

        # Group users by their preferences to minimize database queries
        users = User.query.filter(User.email.in_(recipients)).all()

        if not users:
            return recipients  # No users found, return original list

        user_emails = {user.email.lower(): user for user in users if user.email}

        for email in recipients:
            user = user_emails.get(email.lower())
            if not user:
                # Email doesn't match a user, include it anyway
                filtered_recipients.append(email)
                continue

            # Check communication preferences
            include_email = True

            try:
                pref = CommunicationPreference.get_for_user(user.id)
                if pref:
                    # Apply preference rules based on category
                    if category == 'newsletter' and not pref.newsletter_enabled:
                        include_email = False
                    elif category == 'marketing' and not pref.marketing_enabled:
                        include_email = False
                    elif category == 'announcement' and not pref.announcement_enabled:
                        include_email = False
            except Exception as e:
                logger.warning(f"Error checking communication preferences for user {user.id}: {e}")

            if include_email:
                filtered_recipients.append(email)

        # Log how many recipients were filtered out
        filtered_count = len(recipients) - len(filtered_recipients)
        if filtered_count > 0:
            logger.info(f"Filtered out {filtered_count} recipients based on communication preferences")
            metrics.increment('email.preference_filtered', filtered_count)

        return filtered_recipients

    def _check_recipient_preference(self, email: str, category: Optional[str] = None) -> bool:
        """
        Check if a single recipient has opted in to receive emails of the specified category.

        Args:
            email: Recipient email address
            category: Email category for preference matching

        Returns:
            Boolean indicating if recipient has opted in
        """
        # If no integration with preference models, assume opt-in
        try:
            from models.communication.user_preference import CommunicationPreference
            from models import User
        except ImportError:
            return True

        # Find user by email
        user = User.query.filter(User.email.ilike(email)).first()
        if not user:
            return True  # No user found, assume opt-in

        try:
            # Check communication preferences
            pref = CommunicationPreference.get_for_user(user.id)
            if pref:
                # Apply preference rules based on category
                if category == 'newsletter' and not pref.newsletter_enabled:
                    return False
                elif category == 'marketing' and not pref.marketing_enabled:
                    return False
                elif category == 'announcement' and not pref.announcement_enabled:
                    return False
        except Exception as e:
            logger.warning(f"Error checking communication preference for {email}: {e}")

        return True

    def _record_delivery_failure(self, message_id: str, recipient_count: int, error: str) -> None:
        """
        Record details about an email delivery failure.

        Args:
            message_id: Email message ID
            recipient_count: Number of intended recipients
            error: Error message
        """
        try:
            # Check if we have access to the delivery failure model
            try:
                from models.communication.email import EmailDeliveryFailure

                failure = EmailDeliveryFailure(
                    message_id=message_id,
                    recipient_count=recipient_count,
                    error_message=error,
                    occurred_at=datetime.now(timezone.utc)
                )

                db.session.add(failure)
                db.session.commit()

            except ImportError:
                # Model not available, just log the failure
                logger.error(f"Email delivery failure for ID {message_id}: {error}")

        except Exception as e:
            logger.warning(f"Failed to record email delivery failure: {e}")


def send_email(to: Union[str, List[str]],
              subject: str,
              text_content: Optional[str] = None,
              html_content: Optional[str] = None,
              **kwargs: Any) -> bool:
    """
    Send an email using application configuration.

    This is a module-level convenience function that uses Flask's
    current_app to get email configuration and send an email.

    Args:
        to: Recipient email address(es)
        subject: Email subject line
        text_content: Plain text content (optional if html_content is provided)
        html_content: HTML content (optional if text_content is provided)
        **kwargs: Additional parameters to pass to EmailService.send_email

    Returns:
        Boolean indicating if the email was sent successfully

    Example:
        from services.email_service import send_email

        send_email(
            to='user@example.com',
            subject='Welcome to our service',
            html_content='<h1>Welcome!</h1><p>Thank you for signing up.</p>'
        )
    """
    try:
        config = current_app.config

        service = EmailService(
            smtp_server=config.get('SMTP_SERVER'),
            port=config.get('SMTP_PORT', 587),
            username=config.get('SMTP_USERNAME'),
            password=config.get('SMTP_PASSWORD'),
            use_tls=config.get('SMTP_USE_TLS', True),
            from_email=config.get('MAIL_DEFAULT_SENDER'),
            from_name=config.get('MAIL_DEFAULT_SENDER_NAME')
        )

        return service.send_email(
            to=to,
            subject=subject,
            text_content=text_content,
            html_content=html_content,
            **kwargs
        )

    except (ValueError, KeyError, RuntimeError, Exception) as e:
        logger.error("Failed to send email: %s", str(e))
        metrics.increment('email.utility_error')
        return False


def send_template_email(to: Union[str, List[str]],
                      subject: str,
                      template_name: str,
                      template_data: Dict[str, Any],
                      **kwargs: Any) -> bool:
    """
    Send a templated email using application configuration.

    This is a module-level convenience function that renders a template
    and sends it as an email.

    Args:
        to: Recipient email address(es)
        subject: Email subject line
        template_name: Name of the template to render (without extension)
        template_data: Dictionary of data to pass to the template
        **kwargs: Additional parameters to pass to EmailService.send_email

    Returns:
        Boolean indicating if the email was sent successfully

    Example:
        from services.email_service import send_template_email

        send_template_email(
            to='user@example.com',
            subject='Welcome to our service',
            template_name='welcome_email',
            template_data={'username': 'john_doe', 'activation_link': 'https://example.com/activate/123'}
        )
    """
    try:
        config = current_app.config

        service = EmailService(
            smtp_server=config.get('SMTP_SERVER'),
            port=config.get('SMTP_PORT', 587),
            username=config.get('SMTP_USERNAME'),
            password=config.get('SMTP_PASSWORD'),
            use_tls=config.get('SMTP_USE_TLS', True),
            from_email=config.get('MAIL_DEFAULT_SENDER'),
            from_name=config.get('MAIL_DEFAULT_SENDER_NAME')
        )

        return service.send_template_email(
            to=to,
            subject=subject,
            template_name=template_name,
            template_data=template_data,
            **kwargs
        )

    except (ValueError, KeyError, RuntimeError, Exception) as e:
        logger.error("Failed to send template email: %s", str(e))
        metrics.increment('email.template_utility_error')
        return False


def validate_email_address(email: str) -> bool:
    """
    Validate an email address format without sending a verification email.

    Args:
        email: Email address to validate

    Returns:
        Boolean indicating if the email format is valid
    """
    if not email or not isinstance(email, str):
        return False

    # Trim whitespace
    email = email.strip()

    # Check length constraints
    if len(email) > EMAIL_MAX_LENGTH:
        return False

    # Match RFC 5322 compatible pattern
    return bool(re.match(EMAIL_PATTERN, email))


def test_email_configuration() -> Dict[str, Any]:
    """
    Test if the email configuration is correctly set up.

    Returns:
        Dictionary with configuration test results
    """
    try:
        config = current_app.config

        # Check required configuration
        required_configs = ['SMTP_SERVER', 'SMTP_PORT', 'MAIL_DEFAULT_SENDER']
        missing_configs = [key for key in required_configs if not config.get(key)]

        if missing_configs:
            return {
                'success': False,
                'status': 'missing_config',
                'missing': missing_configs,
                'message': f"Missing required configurations: {', '.join(missing_configs)}"
            }

        # Create service
        service = EmailService(
            smtp_server=config.get('SMTP_SERVER'),
            port=config.get('SMTP_PORT', 587),
            username=config.get('SMTP_USERNAME'),
            password=config.get('SMTP_PASSWORD'),
            use_tls=config.get('SMTP_USE_TLS', True),
            from_email=config.get('MAIL_DEFAULT_SENDER'),
            from_name=config.get('MAIL_DEFAULT_SENDER_NAME')
        )

        # Test connection
        return service.verify_connection()

    except Exception as e:
        return {
            'success': False,
            'status': 'error',
            'message': str(e)
        }


def get_email_stats(period: str = 'last_24h') -> Dict[str, Any]:
    """
    Get email sending statistics for the specified period.

    Args:
        period: Time period for statistics ('today', 'last_24h', 'last_7d', 'last_30d')

    Returns:
        Dictionary with email statistics
    """
    try:
        # This is a placeholder for implementing email stats collection
        # In a real implementation, we'd query the database for metrics

        # For now, return mock data
        return {
            'period': period,
            'sent_count': 0,
            'failed_count': 0,
            'delivery_rate': 0,
            'open_rate': 0,
            'click_rate': 0,
            'categories': {},
            'status': 'success'
        }
    except Exception as e:
        logger.error(f"Failed to retrieve email stats: {str(e)}")
        return {
            'period': period,
            'error': str(e),
            'status': 'error'
        }


# Add to exports
__all__ = [
    'EmailService',
    'EmailDeliveryException',
    'EmailRenderException',
    'EmailValidationException',
    'send_email',
    'send_template_email',
    'validate_email_address',
    'test_email_configuration',
    'get_email_stats'
]
