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

from extensions import db, metrics
from models.communication import Subscriber, MailingList
from services.email_service import EmailService, send_template_email
from core.security import sanitize_url


class NewsletterService:
    """
    Service for handling newsletter subscriptions and management.

    This class provides methods for subscribing to newsletters, confirming
    subscriptions, unsubscribing, and sending newsletters to subscribers.
    """

    @staticmethod
    def subscribe_email(email: str, source: str = 'website',
                      first_name: Optional[str] = None,
                      last_name: Optional[str] = None,
                      preferences: Optional[Dict[str, Any]] = None) -> Dict[str, Union[bool, str]]:
        """
        Subscribe an email to the newsletter.

        Args:
            email: Email address to subscribe
            source: Source of subscription (website, api, import)
            first_name: Subscriber's first name (optional)
            last_name: Subscriber's last name (optional)
            preferences: Subscription preferences (optional)

        Returns:
            dict: Result with success flag and message or error
        """
        try:
            # Sanitize email before validation
            email = email.strip().lower()

            # Validate email format
            if not NewsletterService._validate_email(email):
                current_app.logger.info("Newsletter subscription rejected: Invalid email format: %s", email)
                metrics.increment('newsletter.invalid_email')
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
                    return {'success': True, 'message': 'Already subscribed'}
                else:
                    # Resend confirmation email logic
                    # Generate new token for security if last attempt was a while ago
                    if existing.subscribed_at < datetime.utcnow() - timedelta(days=1):
                        existing.confirmation_token = str(uuid.uuid4())
                        db.session.commit()

                    NewsletterService._send_confirmation_email(email, existing.confirmation_token)
                    current_app.logger.info("Resent confirmation email to: %s", email)
                    metrics.increment('newsletter.confirmation_resent')
                    return {'success': True, 'message': 'Confirmation email resent'}

            # Generate confirmation token
            confirmation_token = str(uuid.uuid4())

            # Also generate unsubscribe token now to avoid need for updates later
            unsubscribe_token = str(uuid.uuid4())

            # Create new subscriber
            new_subscriber = Subscriber(
                email=email,
                first_name=first_name,
                last_name=last_name,
                source=source,
                preferences=preferences or {},
                subscribed_at=datetime.utcnow(),
                confirmed=False,  # Requires confirmation via email
                confirmation_token=confirmation_token,
                unsubscribe_token=unsubscribe_token
            )

            db.session.add(new_subscriber)
            db.session.commit()

            # Send confirmation email
            sent = NewsletterService._send_confirmation_email(email, confirmation_token)

            if not sent:
                current_app.logger.error("Failed to send confirmation email to: %s", email)
                metrics.increment('newsletter.confirmation_email_failed')
            else:
                metrics.increment('newsletter.subscription_requested')

            current_app.logger.info("New newsletter subscription request: %s", email)
            return {
                'success': True,
                'message': 'Subscription confirmation email sent'
            }

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error("Database error in subscribe_email: %s", str(e))
            metrics.increment('newsletter.db_error')
            return {
                'success': False,
                'error': 'Database error occurred'
            }
        except Exception as e:
            current_app.logger.error("Error in subscribe_email: %s", str(e))
            metrics.increment('newsletter.error')
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
                metrics.increment('newsletter.invalid_token')
                return {
                    'success': False,
                    'error': 'Invalid confirmation token'
                }

            subscriber = Subscriber.query.filter_by(confirmation_token=token).first()

            if not subscriber:
                current_app.logger.warning("Invalid confirmation token used: %s", token)
                metrics.increment('newsletter.token_not_found')
                return {
                    'success': False,
                    'error': 'Invalid or expired confirmation token'
                }

            # Check if token is too old (expired)
            token_age = datetime.utcnow() - subscriber.subscribed_at
            if token_age > timedelta(days=7):  # Tokens expire after 7 days
                current_app.logger.info("Expired confirmation token: %s", token)
                metrics.increment('newsletter.token_expired')
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

            # Track metrics for confirmed subscriptions
            metrics.increment('newsletter.subscription_confirmed')

            # Clear any cached subscriber data
            if hasattr(subscriber, '_clear_cache'):
                subscriber._clear_cache()

            current_app.logger.info("Confirmed newsletter subscription: %s", subscriber.email)
            return {
                'success': True,
                'message': 'Subscription confirmed successfully'
            }

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error("Database error in confirm_subscription: %s", str(e))
            metrics.increment('newsletter.db_error')
            return {
                'success': False,
                'error': 'Database error occurred'
            }
        except Exception as e:
            current_app.logger.error("Error in confirm_subscription: %s", str(e))
            metrics.increment('newsletter.error')
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
                metrics.increment('newsletter.unsubscribe_not_found')
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
                metrics.increment('newsletter.hard_delete')
            else:
                # Soft delete (default)
                subscriber.unsubscribed = True
                subscriber.unsubscribed_at = datetime.utcnow()
                subscriber.confirmed = False
                metrics.increment('newsletter.soft_delete')

            db.session.commit()

            # Clear any cached subscriber data
            if hasattr(subscriber, '_clear_cache'):
                subscriber._clear_cache()

            current_app.logger.info("Unsubscribed from newsletter: %s", email)
            return {
                'success': True,
                'message': 'Successfully unsubscribed from newsletter'
            }

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error("Database error in unsubscribe: %s", str(e))
            metrics.increment('newsletter.db_error')
            return {
                'success': False,
                'error': 'Database error occurred'
            }
        except Exception as e:
            current_app.logger.error("Error in unsubscribe: %s", str(e))
            metrics.increment('newsletter.error')
            return {
                'success': False,
                'error': 'An unexpected error occurred'
            }

    @staticmethod
    def send_newsletter(
        subject: str,
        content: str,
        test_emails: Optional[List[str]] = None,
        list_id: Optional[int] = None,
        track_opens: bool = True,
        track_clicks: bool = True
    ) -> Dict[str, Union[bool, str, int]]:
        """
        Send a newsletter to all confirmed subscribers or test emails.

        Args:
            subject: The newsletter subject
            content: The newsletter content (HTML)
            test_emails: Optional list of test emails to send to instead of subscribers
            list_id: Optional mailing list ID to filter recipients
            track_opens: Whether to track email opens
            track_clicks: Whether to track link clicks

        Returns:
            A dictionary with success flag, message and count of recipients
        """
        try:
            if not subject or not content:
                return {
                    'success': False,
                    'error': 'Subject and content are required'
                }

            # Create a batch ID for tracking
            batch_id = f"newsletter_{uuid.uuid4().hex}"

            # Determine recipients
            recipients_list = []

            if test_emails:
                # Send only to test emails
                recipients_list = [{'email': email.strip()} for email in test_emails if email.strip()]
                recipient_count = len(recipients_list)
                current_app.logger.info("Sending test newsletter to %d recipients", recipient_count)
                metrics.info('newsletter.test_send', recipient_count)
            else:
                # Query base: confirmed subscribers that haven't unsubscribed
                query = Subscriber.query.filter_by(confirmed=True).filter_by(unsubscribed=False)

                # Apply mailing list filter if specified
                if list_id:
                    try:
                        mailing_list = MailingList.query.get(list_id)
                        if not mailing_list:
                            return {
                                'success': False,
                                'error': f'Mailing list with ID {list_id} not found'
                            }

                        # Get subscribers through the relationship
                        subscribers = mailing_list.get_subscribers(active_only=True, confirmed_only=True)
                    except SQLAlchemyError as e:
                        current_app.logger.error("Error fetching mailing list: %s", str(e))
                        return {
                            'success': False,
                            'error': 'Failed to fetch mailing list subscribers'
                        }
                else:
                    subscribers = query.all()

                recipients_list = [
                    {
                        'email': sub.email,
                        'unsubscribe_token': sub.unsubscribe_token,
                        'first_name': sub.first_name,
                        'last_name': sub.last_name
                    } for sub in subscribers
                ]
                recipient_count = len(recipients_list)
                current_app.logger.info("Sending newsletter to %d subscribers", recipient_count)
                metrics.info('newsletter.production_send', recipient_count)

            if recipient_count == 0:
                return {
                    'success': False,
                    'error': 'No recipients found'
                }

            # Get email service
            email_service = EmailService()

            # Use bulk email sending for efficiency
            results = email_service.send_bulk_emails(
                recipients=recipients_list,
                subject=subject,
                template_name='emails/newsletter',
                delay_between_sends=0.2,
                batch_id=batch_id
            )

            sent_count = results.get('successful', 0)
            failed_count = results.get('failed', 0)

            # Log results
            if failed_count == 0:
                current_app.logger.info("Newsletter sent successfully to %d recipients", sent_count)
            else:
                current_app.logger.warning(
                    "Newsletter sent with some failures: %d successful, %d failed",
                    sent_count, failed_count
                )

            # Track success rate
            if recipient_count > 0:
                success_rate = (sent_count / recipient_count) * 100
                metrics.info('newsletter.delivery_rate', success_rate)

            return {
                'success': sent_count > 0,
                'message': f'Newsletter sent to {sent_count} recipients ({failed_count} failed)',
                'count': sent_count,
                'failed': failed_count,
                'batch_id': batch_id
            }

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error("Database error in send_newsletter: %s", str(e))
            metrics.increment('newsletter.db_error')
            return {
                'success': False,
                'error': f'Failed to send newsletter: Database error'
            }
        except Exception as e:
            current_app.logger.error("Error in send_newsletter: %s", str(e))
            metrics.increment('newsletter.error')
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
            # Try to get from cache first
            cache_key = 'newsletter:stats:summary'
            if hasattr(current_app, 'cache'):
                cached = current_app.cache.get(cache_key)
                if cached:
                    return cached

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

            # Get count of subscribers by source
            source_counts = {}
            sources = db.session.query(
                Subscriber.source,
                db.func.count(Subscriber.id)
            ).filter(
                Subscriber.unsubscribed == False
            ).group_by(
                Subscriber.source
            ).all()

            for source, count in sources:
                if source:
                    source_counts[source] = count

            # Calculate conversion rate (confirmed / total)
            conversion_rate = 0
            if total_subscribers > 0:
                conversion_rate = round((confirmed_subscribers / total_subscribers) * 100, 1)

            result = {
                'total': total_subscribers,
                'confirmed': confirmed_subscribers,
                'pending': pending_subscribers,
                'new_30d': new_subscribers,
                'unsubscribed_30d': unsubscribed_30d,
                'conversion_rate': conversion_rate,
                'sources': source_counts,
                'generated_at': datetime.utcnow().isoformat()
            }

            # Cache the results for 30 minutes
            if hasattr(current_app, 'cache'):
                current_app.cache.set(cache_key, result, timeout=1800)

            return result

        except SQLAlchemyError as e:
            current_app.logger.error("Database error in get_stats: %s", str(e))
            metrics.increment('newsletter.db_error')
            return {
                'total': 0,
                'confirmed': 0,
                'pending': 0,
                'new_30d': 0,
                'unsubscribed_30d': 0,
                'conversion_rate': 0,
                'sources': {},
                'error': 'Database error'
            }

    @staticmethod
    def get_subscribers(
        page: int = 1,
        per_page: int = 20,
        confirmed_only: bool = True,
        search: Optional[str] = None,
        sort_by: Optional[str] = 'subscribed_at',
        sort_dir: Optional[str] = 'desc'
    ) -> Dict[str, Any]:
        """
        Get a paginated list of subscribers.

        Args:
            page: Page number (starting from 1)
            per_page: Number of items per page
            confirmed_only: If True, only return confirmed subscribers
            search: Optional search term for filtering results
            sort_by: Field to sort by ('subscribed_at', 'email', etc.)
            sort_dir: Sort direction ('asc' or 'desc')

        Returns:
            A dictionary with subscribers and pagination metadata
        """
        try:
            query = Subscriber.query.filter_by(unsubscribed=False)

            if confirmed_only:
                query = query.filter_by(confirmed=True)

            # Apply search filter if provided
            if search:
                search_term = f"%{search}%"
                query = query.filter(
                    db.or_(
                        Subscriber.email.ilike(search_term),
                        Subscriber.first_name.ilike(search_term),
                        Subscriber.last_name.ilike(search_term)
                    )
                )

            # Apply sorting
            valid_sort_fields = {
                'subscribed_at': Subscriber.subscribed_at,
                'email': Subscriber.email,
                'confirmed_at': Subscriber.confirmed_at
            }

            sort_field = valid_sort_fields.get(sort_by, Subscriber.subscribed_at)

            if sort_dir.lower() == 'asc':
                query = query.order_by(sort_field.asc())
            else:
                query = query.order_by(sort_field.desc())

            # Apply pagination
            pagination = query.paginate(page=page, per_page=per_page)

            subscribers = [
                {
                    'id': s.id,
                    'email': s.email,
                    'first_name': s.first_name,
                    'last_name': s.last_name,
                    'full_name': s.get_full_name() if hasattr(s, 'get_full_name') else None,
                    'subscribed_at': s.subscribed_at.isoformat() if s.subscribed_at else None,
                    'confirmed': s.confirmed,
                    'confirmed_at': s.confirmed_at.isoformat() if s.confirmed_at else None,
                    'source': s.source,
                    'status': s.get_subscription_status() if hasattr(s, 'get_subscription_status') else None
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
            metrics.increment('newsletter.db_error')
            return {
                'subscribers': [],
                'pagination': {
                    'total': 0,
                    'pages': 0,
                    'current_page': page,
                    'per_page': per_page,
                    'has_next': False,
                    'has_prev': False
                },
                'error': 'Database error occurred'
            }

    @staticmethod
    def add_subscriber_to_list(email: str, list_name_or_id: Union[str, int]) -> Dict[str, Union[bool, str]]:
        """
        Add a subscriber to a mailing list.

        Args:
            email: The subscriber's email address
            list_name_or_id: The list name or ID to add the subscriber to

        Returns:
            Dict with success flag and message
        """
        try:
            # Find the subscriber
            subscriber = Subscriber.query.filter_by(email=email.lower().strip()).first()
            if not subscriber:
                return {
                    'success': False,
                    'error': 'Subscriber not found'
                }

            # Find the mailing list
            mailing_list = None
            if isinstance(list_name_or_id, int) or list_name_or_id.isdigit():
                mailing_list = MailingList.query.get(int(list_name_or_id))
            else:
                mailing_list = MailingList.query.filter_by(name=list_name_or_id).first()

            if not mailing_list:
                return {
                    'success': False,
                    'error': 'Mailing list not found'
                }

            # Add subscriber to list
            if subscriber.add_to_list(mailing_list):
                metrics.increment('newsletter.list_subscription')
                return {
                    'success': True,
                    'message': f'Subscriber added to list: {mailing_list.name}'
                }
            else:
                return {
                    'success': False,
                    'error': 'Failed to add subscriber to list'
                }

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error("Database error adding subscriber to list: %s", str(e))
            metrics.increment('newsletter.db_error')
            return {
                'success': False,
                'error': 'Database error occurred'
            }
        except Exception as e:
            current_app.logger.error("Error adding subscriber to list: %s", str(e))
            metrics.increment('newsletter.error')
            return {
                'success': False,
                'error': 'An unexpected error occurred'
            }

    @staticmethod
    def create_mailing_list(name: str, description: Optional[str] = None) -> Dict[str, Union[bool, str, int]]:
        """
        Create a new mailing list.

        Args:
            name: The name of the mailing list
            description: Optional description for the mailing list

        Returns:
            Dict with success flag, message, and list ID
        """
        try:
            # Check if list with same name already exists
            existing = MailingList.query.filter_by(name=name).first()
            if existing:
                return {
                    'success': False,
                    'error': 'A mailing list with this name already exists'
                }

            # Create new mailing list
            mailing_list = MailingList(
                name=name,
                description=description,
                is_active=True
            )

            db.session.add(mailing_list)
            db.session.commit()

            metrics.increment('newsletter.list_created')

            return {
                'success': True,
                'message': 'Mailing list created successfully',
                'list_id': mailing_list.id
            }

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error("Database error creating mailing list: %s", str(e))
            metrics.increment('newsletter.db_error')
            return {
                'success': False,
                'error': 'Database error occurred'
            }
        except Exception as e:
            current_app.logger.error("Error creating mailing list: %s", str(e))
            metrics.increment('newsletter.error')
            return {
                'success': False,
                'error': 'An unexpected error occurred'
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

            # Ensure URL is properly sanitized for security
            confirmation_url = sanitize_url(confirmation_url)

            context = {
                'email': email,
                'confirmation_url': confirmation_url,
                'expire_days': 7,  # Match the expiration logic in confirm_subscription
                'site_name': current_app.config.get('SITE_NAME', 'Our Site'),
                'contact_email': current_app.config.get('CONTACT_EMAIL', 'support@example.com')
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
