# services/newsletter_service.py

"""
Newsletter service for managing subscriptions and sending newsletters.

This module provides a service class that handles newsletter operations such as
subscribing, unsubscribing, and sending newsletters to subscribers. It follows
best practices for email validation, duplicate prevention, and error handling.
"""

from datetime import datetime, timedelta
import logging
import re
from typing import Dict, List, Optional, Union, Any
import uuid

from flask import current_app, render_template
from sqlalchemy.exc import SQLAlchemyError

from extensions import db
from models.subscriber import Subscriber
from services.email_service import EmailService, send_template_email


class NewsletterService:
    """
    Service for handling newsletter subscriptions and management.

    This class provides methods for subscribing to newsletters, confirming
    subscriptions, unsubscribing, and sending newsletters to subscribers.
    """

    @staticmethod
    def subscribe_email(email: str) -> Dict[str, Union[bool, str]]:
        """
        Subscribe an email to the newsletter.

        Args:
            email: Email address to subscribe

        Returns:
            dict: Result with success flag and message or error
        """
        try:
            # Sanitize email before validation
            email = email.strip().lower()

            # Validate email format
            if not NewsletterService._validate_email(email):
                current_app.logger.info("Newsletter subscription rejected: Invalid email format: %s", email)
                return {
                    'success': False,
                    'error': 'Invalid email format'
                }

            # Check if already subscribed
            existing = Subscriber.query.filter_by(email=email).first()
            if existing:
                # Check if confirmed or just return success to avoid email enumeration
                if existing.confirmed:
                    current_app.logger.debug("Already subscribed to newsletter: %s", email)
                    return {'success': True}
                else:
                    # Resend confirmation email logic
                    # Generate new token for security if last attempt was a while ago
                    if existing.subscribed_at < datetime.utcnow() - timedelta(days=1):
                        existing.confirmation_token = str(uuid.uuid4())
                        db.session.commit()

                    NewsletterService._send_confirmation_email(email, existing.confirmation_token)
                    current_app.logger.info("Resent confirmation email to: %s", email)
                    return {'success': True}

            # Generate confirmation token
            confirmation_token = str(uuid.uuid4())

            # Also generate unsubscribe token now to avoid need for updates later
            unsubscribe_token = str(uuid.uuid4())

            # Create new subscriber
            new_subscriber = Subscriber(
                email=email,
                subscribed_at=datetime.utcnow(),
                confirmed=False,  # Requires confirmation via email
                confirmation_token=confirmation_token,
                unsubscribe_token=unsubscribe_token
            )

            db.session.add(new_subscriber)
            db.session.commit()

            # Send confirmation email
            NewsletterService._send_confirmation_email(email, confirmation_token)

            current_app.logger.info("New newsletter subscription request: %s", email)
            return {
                'success': True,
                'message': 'Subscription confirmation email sent'
            }

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error("Database error in subscribe_email: %s", str(e))
            return {
                'success': False,
                'error': 'Database error occurred'
            }
        except Exception as e:
            current_app.logger.error("Error in subscribe_email: %s", str(e))
            return {
                'success': False,
                'error': 'An unexpected error occurred'
            }

    @staticmethod
    def confirm_subscription(token: str) -> Dict[str, Union[bool, str]]:
        """
        Confirm a subscription using a token.

        Args:
            token: The confirmation token sent to the subscriber

        Returns:
            dict: Result with success flag and message or error
        """
        try:
            # Validate token format
            if not token or not isinstance(token, str) or len(token) < 10:
                return {
                    'success': False,
                    'error': 'Invalid confirmation token'
                }

            subscriber = Subscriber.query.filter_by(confirmation_token=token).first()

            if not subscriber:
                current_app.logger.warning("Invalid confirmation token used: %s", token)
                return {
                    'success': False,
                    'error': 'Invalid or expired confirmation token'
                }

            # Check if token is too old (expired)
            token_age = datetime.utcnow() - subscriber.subscribed_at
            if token_age > timedelta(days=7):  # Tokens expire after 7 days
                current_app.logger.info("Expired confirmation token: %s", token)
                return {
                    'success': False,
                    'error': 'This confirmation link has expired'
                }

            # Mark as confirmed
            subscriber.confirmed = True
            subscriber.confirmed_at = datetime.utcnow()

            # Invalidate the confirmation token for security
            subscriber.confirmation_token = None

            db.session.commit()

            current_app.logger.info("Confirmed newsletter subscription: %s", subscriber.email)
            return {
                'success': True,
                'message': 'Subscription confirmed successfully'
            }

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error("Database error in confirm_subscription: %s", str(e))
            return {
                'success': False,
                'error': 'Database error occurred'
            }
        except Exception as e:
            current_app.logger.error("Error in confirm_subscription: %s", str(e))
            return {
                'success': False,
                'error': 'An unexpected error occurred'
            }

    @staticmethod
    def unsubscribe(email_or_token: str) -> Dict[str, Union[bool, str]]:
        """
        Unsubscribe a user from the newsletter.

        Args:
            email_or_token: Either an email address or unsubscribe token

        Returns:
            dict: Result with success flag and message or error
        """
        try:
            if not email_or_token:
                return {
                    'success': False,
                    'error': 'No email or token provided'
                }

            subscriber = None

            # Try to find by unsubscribe token first (preferred method)
            if not '@' in email_or_token:
                subscriber = Subscriber.query.filter_by(unsubscribe_token=email_or_token).first()

            # If not found by token, try email (less secure but more user-friendly)
            if not subscriber and '@' in email_or_token:
                email = email_or_token.strip().lower()
                if NewsletterService._validate_email(email):
                    subscriber = Subscriber.query.filter_by(email=email).first()

            if not subscriber:
                current_app.logger.info("Unsubscribe attempt failed: subscription not found for %s", email_or_token)
                return {
                    'success': False,
                    'error': 'No subscription found for this email or token'
                }

            email = subscriber.email

            # Soft delete approach - maintain record but mark as unsubscribed
            # This prevents enumeration attacks and preserves history
            if current_app.config.get('NEWSLETTER_HARD_DELETE', False):
                # Hard delete if specifically configured
                db.session.delete(subscriber)
            else:
                # Soft delete (default)
                subscriber.unsubscribed = True
                subscriber.unsubscribed_at = datetime.utcnow()
                subscriber.confirmed = False

            db.session.commit()

            current_app.logger.info("Unsubscribed from newsletter: %s", email)
            return {
                'success': True,
                'message': 'Successfully unsubscribed from newsletter'
            }

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error("Database error in unsubscribe: %s", str(e))
            return {
                'success': False,
                'error': 'Database error occurred'
            }
        except Exception as e:
            current_app.logger.error("Error in unsubscribe: %s", str(e))
            return {
                'success': False,
                'error': 'An unexpected error occurred'
            }

    @staticmethod
    def send_newsletter(
        subject: str,
        content: str,
        test_emails: Optional[List[str]] = None
    ) -> Dict[str, Union[bool, str, int]]:
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
            if not subject or not content:
                return {
                    'success': False,
                    'error': 'Subject and content are required'
                }

            # Determine recipients
            recipients_list = []

            if test_emails:
                # Send only to test emails
                recipients_list = [{'email': email.strip()} for email in test_emails if email.strip()]
                recipient_count = len(recipients_list)
                current_app.logger.info("Sending test newsletter to %d recipients", recipient_count)
            else:
                # Get all confirmed subscribers that haven't unsubscribed
                subscribers = Subscriber.query.filter_by(confirmed=True).filter_by(unsubscribed=False).all()
                recipients_list = [
                    {
                        'email': sub.email,
                        'unsubscribe_token': sub.unsubscribe_token
                    } for sub in subscribers
                ]
                recipient_count = len(recipients_list)
                current_app.logger.info("Sending newsletter to %d subscribers", recipient_count)

            if recipient_count == 0:
                return {
                    'success': False,
                    'error': 'No recipients found'
                }

            # Get email service
            email_service = EmailService()

            # Send emails in batches to avoid timeouts
            batch_size = current_app.config.get('NEWSLETTER_BATCH_SIZE', 50)
            sent_count = 0
            failed_count = 0

            for i in range(0, recipient_count, batch_size):
                batch = recipients_list[i:i + batch_size]

                for recipient_data in batch:
                    email = recipient_data['email']

                    try:
                        # Prepare newsletter content with unsubscribe link
                        unsubscribe_token = recipient_data.get('unsubscribe_token')

                        context = {
                            'content': content,
                            'email': email,
                            'unsubscribe_url': f"{current_app.config['BASE_URL']}/newsletter/unsubscribe/{unsubscribe_token}" if unsubscribe_token else None
                        }

                        # Send email using template
                        success = send_template_email(
                            to=email,
                            subject=subject,
                            template_name='emails/newsletter',
                            template_data=context
                        )

                        if success:
                            sent_count += 1
                        else:
                            failed_count += 1
                            current_app.logger.warning("Failed to send newsletter to: %s", email)

                    except Exception as e:
                        failed_count += 1
                        current_app.logger.error("Error sending newsletter to %s: %s", email, str(e))

            # Log successful newsletter sending
            if failed_count == 0:
                current_app.logger.info("Newsletter sent successfully to %d recipients", sent_count)
            else:
                current_app.logger.warning(
                    "Newsletter sent with some failures: %d successful, %d failed",
                    sent_count, failed_count
                )

            return {
                'success': sent_count > 0,
                'message': f'Newsletter sent to {sent_count} recipients ({failed_count} failed)',
                'count': sent_count,
                'failed': failed_count
            }

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error("Database error in send_newsletter: %s", str(e))
            return {
                'success': False,
                'error': f'Failed to send newsletter: Database error'
            }
        except Exception as e:
            current_app.logger.error("Error in send_newsletter: %s", str(e))
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
            # Add unsubscribed filter to ensure accurate counts
            total_subscribers = Subscriber.query.filter_by(unsubscribed=False).count()
            confirmed_subscribers = Subscriber.query.filter_by(confirmed=True, unsubscribed=False).count()
            pending_subscribers = total_subscribers - confirmed_subscribers

            # Get subscribers in the last 30 days
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            new_subscribers = Subscriber.query.filter(
                Subscriber.subscribed_at >= thirty_days_ago,
                Subscriber.unsubscribed == False
            ).count()

            # Get unsubscribe rate for the last 30 days
            unsubscribed_30d = Subscriber.query.filter(
                Subscriber.unsubscribed == True,
                Subscriber.unsubscribed_at >= thirty_days_ago
            ).count()

            return {
                'total': total_subscribers,
                'confirmed': confirmed_subscribers,
                'pending': pending_subscribers,
                'new_30d': new_subscribers,
                'unsubscribed_30d': unsubscribed_30d
            }

        except SQLAlchemyError as e:
            current_app.logger.error("Database error in get_stats: %s", str(e))
            return {
                'total': 0,
                'confirmed': 0,
                'pending': 0,
                'new_30d': 0,
                'unsubscribed_30d': 0
            }

    @staticmethod
    def get_subscribers(
        page: int = 1,
        per_page: int = 20,
        confirmed_only: bool = True
    ) -> Dict[str, Any]:
        """
        Get a paginated list of subscribers.

        Args:
            page: Page number (starting from 1)
            per_page: Number of items per page
            confirmed_only: If True, only return confirmed subscribers

        Returns:
            A dictionary with subscribers and pagination metadata
        """
        try:
            query = Subscriber.query.filter_by(unsubscribed=False)

            if confirmed_only:
                query = query.filter_by(confirmed=True)

            # Order by subscription date, newest first
            query = query.order_by(Subscriber.subscribed_at.desc())

            # Apply pagination
            pagination = query.paginate(page=page, per_page=per_page)

            subscribers = [
                {
                    'email': s.email,
                    'subscribed_at': s.subscribed_at.isoformat(),
                    'confirmed': s.confirmed,
                    'confirmed_at': s.confirmed_at.isoformat() if s.confirmed_at else None
                }
                for s in pagination.items
            ]

            return {
                'subscribers': subscribers,
                'pagination': {
                    'total': pagination.total,
                    'pages': pagination.pages,
                    'current_page': page,
                    'per_page': per_page,
                    'has_next': pagination.has_next,
                    'has_prev': pagination.has_prev
                }
            }

        except SQLAlchemyError as e:
            current_app.logger.error("Database error in get_subscribers: %s", str(e))
            return {
                'subscribers': [],
                'pagination': {
                    'total': 0,
                    'pages': 0,
                    'current_page': page,
                    'per_page': per_page,
                    'has_next': False,
                    'has_prev': False
                }
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
        if not email or not isinstance(email, str):
            return False

        # More comprehensive RFC 5322 compatible pattern
        pattern = r"^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"

        # Check length constraints
        if len(email) > 254:
            return False

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
            base_url = current_app.config.get('BASE_URL', '')
            confirmation_url = f"{base_url}/newsletter/confirm/{token}"

            context = {
                'email': email,
                'confirmation_url': confirmation_url,
                'expire_days': 7  # Match the expiration logic in confirm_subscription
            }

            return send_template_email(
                to=email,
                subject="Please confirm your newsletter subscription",
                template_name='emails/confirm_subscription',
                template_data=context
            )

        except Exception as e:
            current_app.logger.error("Failed to send confirmation email: %s", str(e))
            return False
