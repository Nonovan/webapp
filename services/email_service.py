# services/email_service.py

"""
Email service for sending and managing email delivery.

This module provides a service class that handles email operations such as
template rendering, sending transactional emails, and email delivery tracking.
It abstracts away the details of email server configuration and provides a
clean interface for sending emails throughout the application.
"""

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional, Union, Any
from flask import current_app

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
            attachments: List of attachment dictionaries
            
        Returns:
            Boolean indicating if the email was sent successfully
        """
        if not text_content and not html_content:
            raise ValueError("Either text_content or html_content must be provided")
            
        # Ensure to is a list
        recipients = [to] if isinstance(to, str) else to
        
        # Get sender information
        sender_email = from_email or self.from_email or current_app.config.get('MAIL_DEFAULT_SENDER')
        sender_name = from_name or self.from_name or current_app.config.get('MAIL_DEFAULT_SENDER_NAME')
        
        if not sender_email:
            raise ValueError("Sender email is required")
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        
        # Set headers
        if sender_name:
            msg['From'] = f"{sender_name} <{sender_email}>"
        else:
            msg['From'] = sender_email
            
        msg['To'] = ', '.join(recipients)
        
        if cc:
            cc_list = [cc] if isinstance(cc, str) else cc
            msg['Cc'] = ', '.join(cc_list)
            recipients.extend(cc_list)
            
        if bcc:
            bcc_list = [bcc] if isinstance(bcc, str) else bcc
            recipients.extend(bcc_list)
            
        if reply_to:
            msg['Reply-To'] = reply_to
        
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
        try:
            # Get SMTP settings
            smtp_server = self.smtp_server or current_app.config.get('SMTP_SERVER')
            port = self.port or current_app.config.get('SMTP_PORT', 587)
            username = self.username or current_app.config.get('SMTP_USERNAME')
            password = self.password or current_app.config.get('SMTP_PASSWORD')
            use_tls = self.use_tls if self.use_tls is not None else current_app.config.get('SMTP_USE_TLS', True)
            
            if not smtp_server:
                raise ValueError("SMTP server is required")
                
            # Connect and send
            smtp = smtplib.SMTP(smtp_server, port)
            
            if use_tls:
                smtp.starttls()
                
            if username and password:
                smtp.login(username, password)
                
            smtp.sendmail(
                sender_email,
                recipients,
                msg.as_string()
            )
            
            smtp.quit()
            
            return True
            
        except (smtplib.SMTPException, ValueError) as e:
            logger = logging.getLogger(__name__)
            logger.error("Failed to send email: %s", str(e))
            return False
    
    def _add_attachment(self, msg: MIMEMultipart, attachment: Dict[str, Any]) -> None:
        """
        Add an attachment to the email message.
        
        Args:
            msg: The email message to add the attachment to
            attachment: Attachment information dictionary
        """
        # This is a placeholder for attachment handling
        # The implementation depends on your specific needs
        
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
            use_tls=config.get('SMTP_USE_TLS', True)
        )
        
        return service.send_email(
            to=to,
            subject=subject,
            text_content=text_content,
            html_content=html_content,
            **kwargs
        )
        
    except (ValueError, KeyError, RuntimeError) as e:
        logging.getLogger(__name__).error("Failed to send email: %s", str(e))
        return False