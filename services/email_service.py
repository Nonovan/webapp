# services/email_service.py

"""
Email service for sending and managing email delivery.

This module provides a service class that handles email operations such as
template rendering, sending transactional emails, and email delivery tracking.
It abstracts away the details of email server configuration and provides a
clean interface for sending emails throughout the application.
"""

import logging
import os
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple

from flask import current_app, render_template

logger = logging.getLogger(__name__)


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
                from_name: Optional[str] = None):
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
        """
        self.smtp_server = smtp_server
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.from_email = from_email
        self.from_name = from_name

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
                   attachments: Optional[List[Dict[str, Any]]] = None) -> bool:
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

        Returns:
            Boolean indicating if the email was sent successfully

        Raises:
            ValueError: If neither text_content nor html_content is provided or if
                       required configuration is missing
        """
        if not text_content and not html_content:
            raise ValueError("Either text_content or html_content must be provided")

        # Ensure recipient is a list
        recipients = [to] if isinstance(to, str) else list(to)

        # Get sender information
        sender_email = from_email or self.from_email or current_app.config.get('MAIL_DEFAULT_SENDER')
        sender_name = from_name or self.from_name or current_app.config.get('MAIL_DEFAULT_SENDER_NAME')

        if not sender_email:
            raise ValueError("Sender email is required")

        # Create message and recipient list
        msg, all_recipients = self._create_message(
            sender_email=sender_email,
            sender_name=sender_name,
            recipients=recipients,
            subject=subject,
            cc=cc,
            bcc=bcc,
            reply_to=reply_to
        )

        # Add content
        if text_content:
            msg.attach(MIMEText(text_content, 'plain'))

        if html_content:
            msg.attach(MIMEText(html_content, 'html'))

        # Add attachments if present
        if attachments:
            for attachment in attachments:
                self._add_attachment(msg, attachment)

        # Send email
        return self._send_message(msg, sender_email, all_recipients)

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
            ValueError: If the template cannot be found or rendered
        """
        try:
            # Try to load both HTML and text templates
            html_content = None
            text_content = None

            try:
                html_content = render_template(f"emails/{template_name}.html", **template_data)
            except Exception as e:
                logger.warning("Failed to render HTML template %s: %s", template_name, str(e))

            try:
                text_content = render_template(f"emails/{template_name}.txt", **template_data)
            except Exception as e:
                logger.warning("Failed to render text template %s: %s", template_name, str(e))

            # Ensure at least one template was loaded
            if not html_content and not text_content:
                raise ValueError(f"Failed to render both HTML and text templates for {template_name}")

            # Send the email with the rendered templates
            return self.send_email(
                to=to,
                subject=subject,
                html_content=html_content,
                text_content=text_content,
                **kwargs
            )

        except Exception as e:
            logger.error("Failed to send template email: %s", str(e))
            return False

    def _create_message(self,
                      sender_email: str,
                      sender_name: Optional[str],
                      recipients: List[str],
                      subject: str,
                      cc: Optional[Union[str, List[str]]] = None,
                      bcc: Optional[Union[str, List[str]]] = None,
                      reply_to: Optional[str] = None) -> Tuple[MIMEMultipart, List[str]]:
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

        Returns:
            Tuple containing:
            - The created MIMEMultipart message object
            - List of all recipient addresses (To + CC + BCC)
        """
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject

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

        return msg, all_recipients

    def _send_message(self, msg: MIMEMultipart, sender_email: str, recipients: List[str]) -> bool:
        """
        Send an email message via SMTP.

        Args:
            msg: The prepared email message
            sender_email: Sender's email address
            recipients: List of all recipients

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

            if not smtp_server:
                raise ValueError("SMTP server is required")

            # Connect and send with context manager for automatic cleanup
            with smtplib.SMTP(smtp_server, port, timeout=30) as smtp:
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

                logger.info("Email sent successfully to %s", recipients)
                return True

        except (smtplib.SMTPException, ValueError, ConnectionError) as e:
            logger.error("Failed to send email: %s", str(e))
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
            ValueError: If required attachment information is missing
        """
        if not attachment.get('content') or not attachment.get('filename'):
            raise ValueError("Attachment must contain 'content' and 'filename'")

        content = attachment['content']
        filename = attachment['filename']
        content_type = attachment.get('content_type', 'application/octet-stream')

        # Create attachment part
        attachment_part = MIMEApplication(content)
        attachment_part.add_header(
            'Content-Disposition',
            f'attachment; filename="{filename}"'
        )
        attachment_part.add_header('Content-Type', content_type)

        # Add the attachment to the message
        msg.attach(attachment_part)

    def send_bulk_emails(self,
                         recipients: List[Dict[str, Any]],
                         subject: str,
                         template_name: Optional[str] = None,
                         text_content: Optional[str] = None,
                         html_content: Optional[str] = None) -> Dict[str, Any]:
        """
        Send emails to multiple recipients with personalized content.

        Args:
            recipients: List of recipient dictionaries with 'email' key and any template variables
            subject: Email subject line
            template_name: Name of the template to render (optional)
            text_content: Plain text content template (optional)
            html_content: HTML content template (optional)

        Returns:
            Dictionary with counts of successful and failed emails

        Raises:
            ValueError: If no content is provided or if required parameters are missing
        """
        if not template_name and not text_content and not html_content:
            raise ValueError("Either template_name, text_content, or html_content must be provided")

        results = {
            'successful': 0,
            'failed': 0,
            'total': len(recipients)
        }

        for recipient in recipients:
            email = recipient.get('email')
            if not email:
                results['failed'] += 1
                continue

            try:
                # If using a template
                if template_name:
                    success = self.send_template_email(
                        to=email,
                        subject=subject,
                        template_name=template_name,
                        template_data=recipient
                    )
                else:
                    # Replace placeholders in content using recipient data
                    final_text = self._personalize_content(text_content, recipient) if text_content else None
                    final_html = self._personalize_content(html_content, recipient) if html_content else None

                    success = self.send_email(
                        to=email,
                        subject=subject,
                        text_content=final_text,
                        html_content=final_html
                    )

                if success:
                    results['successful'] += 1
                else:
                    results['failed'] += 1

            except Exception as e:
                logger.error("Failed to send email to %s: %s", email, str(e))
                results['failed'] += 1

        return results

    def _personalize_content(self, content: str, data: Dict[str, Any]) -> str:
        """
        Replace placeholders in content with values from data dictionary.

        Args:
            content: Content string with placeholders in format {{variable}}
            data: Dictionary with variable values

        Returns:
            Personalized content string
        """
        if not content:
            return ""

        personalized = content
        for key, value in data.items():
            personalized = personalized.replace(f"{{{{{key}}}}}", str(value))

        return personalized


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

    except (ValueError, KeyError, RuntimeError) as e:
        logger.error("Failed to send email: %s", str(e))
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

    except (ValueError, KeyError, RuntimeError) as e:
        logger.error("Failed to send template email: %s", str(e))
        return False
