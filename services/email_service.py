# services/newsletter_service.py

"""
Newsletter service for managing subscriptions and sending newsletters.

This module provides a service class that handles newsletter operations such as
subscribing, unsubscribing, and sending newsletters to subscribers. It follows
best practices for email validation, duplicate prevention, and error handling.
"""

from datetime import datetime, timedelta
import re
from typing import Dict, List, Optional, Union
import uuid
from flask import current_app, render_template
from sqlalchemy.exc import SQLAlchemyError

from extensions import db
from models.newsletter import Subscriber
from services.email_service import EmailService

class NewsletterService:
    """
    A service class for managing newsletter-related operations.
    
    This class provides methods for managing newsletter subscriptions
    and sending newsletters to subscribers.
    """

    @staticmethod
    def subscribe_email(email: str) -> Dict[str, Union[bool, str]]:
        """
        Subscribe an email address to the newsletter.
        
        Args:
            email: The email address to subscribe
            
        Returns:
            A dictionary with success flag and optional error message
        """
        try:
            # Validate email format
            if not NewsletterService._validate_email(email):
                return {
                    'success': False,
                    'error': 'Invalid email format'
                }
                
            # Check if already subscribed
            existing = Subscriber.query.filter_by(email=email).first()
            if existing:
                if existing.confirmed:
                    return {
                        'success': True,
                        'message': 'Email already subscribed'
                    }
                else:
                    # Resend confirmation email for unconfirmed subscribers
                    NewsletterService._send_confirmation_email(email, existing.confirmation_token)
                    return {
                        'success': True,
                        'message': 'Confirmation email resent'
                    }
                    
            # Generate confirmation token
            confirmation_token = str(uuid.uuid4())
                    
            # Create new subscriber
            new_subscriber = Subscriber(
                email=email,
                subscribed_at=datetime.utcnow(),
                confirmed=False,
                confirmation_token=confirmation_token
            )
            
            db.session.add(new_subscriber)
            db.session.commit()
            
            # Send confirmation email
            NewsletterService._send_confirmation_email(email, confirmation_token)
            
            current_app.logger.info(f"New newsletter subscription request: {email}")
            return {
                'success': True,
                'message': 'Subscription confirmation email sent'
            }
            
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Database error in subscribe_email: {str(e)}")
            return {
                'success': False,
                'error': 'Database error occurred'
            }
        except ValueError as e:
            current_app.logger.error(f"Value error in subscribe_email: {str(e)}")
            return {
                'success': False,
                'error': 'Invalid input provided'
            }
        except RuntimeError as e:
            current_app.logger.error(f"Runtime error in subscribe_email: {str(e)}")
            return {
                'success': False,
                'error': 'A runtime error occurred'
            }
    
    @staticmethod
    def confirm_subscription(token: str) -> Dict[str, Union[bool, str]]:
        """
        Confirm a newsletter subscription using a confirmation token.
        
        Args:
            token: The confirmation token sent to the subscriber
            
        Returns:
            A dictionary with success flag and message
        """
        try:
            subscriber = Subscriber.query.filter_by(confirmation_token=token).first()
            
            if not subscriber:
                return {
                    'success': False,
                    'error': 'Invalid or expired confirmation token'
                }
                
            subscriber.confirmed = True
            subscriber.confirmed_at = datetime.utcnow()
            db.session.commit()
            
            current_app.logger.info(f"Confirmed newsletter subscription: {subscriber.email}")
            return {
                'success': True,
                'message': 'Subscription confirmed successfully'
            }
            
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Database error in confirm_subscription: {str(e)}")
            return {
                'success': False,
                'error': 'Database error occurred'
            }
        except ValueError as e:
            current_app.logger.error(f"Value error in confirm_subscription: {str(e)}")
            return {
                'success': False,
                'error': 'Invalid input provided'
            }
            current_app.logger.error(f"Error in confirm_subscription: {str(e)}")
            return {
                'success': False,
                'error': 'An unexpected error occurred'
            }
        except (SQLAlchemyError, ValueError, RuntimeError) as e:
            current_app.logger.error(f"Error in confirm_subscription: {str(e)}")
            return {
                'success': False,
                'error': 'An unexpected error occurred'
            }
        
        # Ensure a return statement in case no exception is raised
        return {
            'success': False,
            'error': 'An unknown error occurred'
        }
            
    @staticmethod
    def unsubscribe(email_or_token: str) -> Dict[str, Union[bool, str]]:
        """
        Unsubscribe from the newsletter.
        
        Args:
            email_or_token: Either the subscriber's email or unsubscribe token
            
        Returns:
            A dictionary with success flag and message
        """
        try:
            # Try to find by unsubscribe token first
            subscriber = Subscriber.query.filter_by(unsubscribe_token=email_or_token).first()
            
            # If not found by token, try email
            if not subscriber and '@' in email_or_token:
                subscriber = Subscriber.query.filter_by(email=email_or_token).first()
                
            if not subscriber:
                return {
                    'success': False,
                    'error': 'No subscription found for this email or token'
                }
                
            email = subscriber.email
            db.session.delete(subscriber)
            db.session.commit()
            
            current_app.logger.info(f"Unsubscribed from newsletter: {email}")
            return {
                'success': True,
                'message': f'Successfully unsubscribed: {email}'
            }
        except ValueError as e:
            current_app.logger.error(f"Value error in unsubscribe: {str(e)}")
            return {
                'success': False,
                'error': 'Invalid input provided'
            }
        except RuntimeError as e:
            current_app.logger.error(f"Runtime error in unsubscribe: {str(e)}")
            return {
                'success': False,
                'error': 'A runtime error occurred'
            }
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Database error in unsubscribe: {str(e)}")
            return {
                'success': False,
                'error': 'Database error occurred'
            }
        # Ensure a default return in case no exception is raised
        return {
            'success': False,
            'error': 'An unknown error occurred'
        }
    
    @staticmethod
    def send_newsletter(subject: str, content: str, test_emails: Optional[List[str]] = None) -> Dict[str, Union[bool, str, int]]:
        """
        Send a newsletter to all confirmed subscribers or test emails.
        
        Args:
            subject: The newsletter subject
            content: The newsletter content (HTML)
            test_emails: Optional list of test emails to send to instead of subscribers
            
        Returns:
            A dictionary with success flag, message and count of recipients
        """
        try:
            if test_emails:
                # Send only to test emails
                recipients = test_emails
                recipient_count = len(test_emails)
            else:
                # Get all confirmed subscribers
                subscribers = Subscriber.query.filter_by(confirmed=True).all()
                recipients = [sub.email for sub in subscribers]
                recipient_count = len(recipients)
                
            if recipient_count == 0:
                return {
                    'success': False,
                    'error': 'No recipients found'
                }
                
            # Send emails in batches to avoid timeouts
            batch_size = 50
            for i in range(0, recipient_count, batch_size):
                batch = recipients[i:i + batch_size]
                
                for email in batch:
                    # Find subscriber to include unsubscribe token
                    subscriber = Subscriber.query.filter_by(email=email).first()
                    unsubscribe_token = subscriber.unsubscribe_token if subscriber else None
                    
                    # Prepare newsletter content with unsubscribe link
                    context = {
                        'content': content,
                        'unsubscribe_url': f"{current_app.config['BASE_URL']}/newsletter/unsubscribe/{unsubscribe_token}" if unsubscribe_token else None
                    }
                    html = render_template('emails/newsletter.html', **context)
                    EmailService.send_email(
                        to=email,
                        subject=subject,
                        html_content=html
                    )
        except ValueError as e:
            current_app.logger.error(f"Value error in send_newsletter: {str(e)}")
            return {
                'success': False,
                'error': 'Invalid input provided'
            }
        except RuntimeError as e:
            current_app.logger.error(f"Runtime error in send_newsletter: {str(e)}")
            return {
                'success': False,
                'error': f'Failed to send newsletter due to runtime error: {str(e)}'
            }
            
            current_app.logger.info(f"Newsletter sent to {recipient_count} recipients")
            return {
                'success': True,
                'message': f'Newsletter sent successfully to {recipient_count} recipients',
                'count': recipient_count
            }
            
        except SQLAlchemyError as e:
            current_app.logger.error(f"Error in send_newsletter: {str(e)}")
            return {
                'success': False,
                'error': f'Failed to send newsletter: {str(e)}'
            }
    
    @staticmethod
    def get_stats() -> Dict[str, int]:
        """
        Get newsletter subscription statistics.
        
        Returns:
            A dictionary with various statistics
        """
        try:
            total_subscribers = Subscriber.query.count()
            confirmed_subscribers = Subscriber.query.filter_by(confirmed=True).count()
            pending_subscribers = total_subscribers - confirmed_subscribers
            
            # Get subscribers in the last 30 days
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            new_subscribers = Subscriber.query.filter(Subscriber.subscribed_at >= thirty_days_ago).count()
            
            return {
                'total': total_subscribers,
                'confirmed': confirmed_subscribers,
                'pending': pending_subscribers,
                'new_30d': new_subscribers
            }
            
        except SQLAlchemyError as e:
            current_app.logger.error(f"Database error in get_stats: {str(e)}")
            return {
                'total': 0,
                'confirmed': 0,
                'pending': 0,
                'new_30d': 0
            }
    
    # Private methods
    
    @staticmethod
    def _validate_email(email: str) -> bool:
        """
        Validate an email address format.
        
        Args:
            email: The email address to validate
            
        Returns:
            Boolean indicating if the email format is valid
        """
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(pattern, email) is not None
    
    @staticmethod
    def _send_confirmation_email(email: str, token: str) -> bool:
        """
        Send a confirmation email to a subscriber.
        
        Args:
            email: The recipient email address
            token: The confirmation token
            
        Returns:
            Boolean indicating if the email was sent successfully
        """
        try:
            confirmation_url = f"{current_app.config['BASE_URL']}/newsletter/confirm/{token}"
            
            context = {
                'confirmation_url': confirmation_url,
                'email': email,
                'support_email': current_app.config.get('SUPPORT_EMAIL', 'support@example.com'),
                'company_name': current_app.config.get('COMPANY_NAME', 'Our Company')
            }
            
            html = render_template('emails/confirm_subscription.html', **context)
            
            # Import directly here to avoid circular imports
            from services.email_service import send_email
            
            # Use the module-level function
            result = send_email(
                to=email,
                subject="Please confirm your newsletter subscription",
                html_content=html
            )
            
            if not result:
                raise RuntimeError("Email service returned failure")
                
            return True
        except (RuntimeError, ValueError, KeyError) as e:
            current_app.logger.error(f"Failed to send confirmation email: {str(e)}")
            return False