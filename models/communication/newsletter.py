"""
Newsletter subscription model for cloud infrastructure platform.

This module provides models for managing newsletter subscribers and mailing lists.
It handles subscription status tracking, email validation, confirmation workflows,
and unsubscribe mechanisms while adhering to email marketing best practices.
"""

from datetime import datetime, timezone
import uuid
import re
from typing import Optional, Dict, Any, List, Union, Tuple
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.orm import relationship
from flask import current_app

from extensions import db, cache
from models.base import BaseModel
from core.security_utils import generate_secure_token


class Subscriber(BaseModel):
    """
    Model representing a newsletter subscriber.

    This model tracks newsletter subscribers with their subscription status,
    confirmation tokens, and subscription preferences. It provides methods
    for managing the subscription lifecycle.

    Attributes:
        id: Primary key
        email: Subscriber's email address (unique)
        first_name: Subscriber's first name (optional)
        last_name: Subscriber's last name (optional)
        subscribed_at: When the subscription was initiated
        confirmed: Whether the subscription has been confirmed
        confirmed_at: When the subscription was confirmed
        confirmation_token: Token for confirming subscription
        unsubscribe_token: Token for unsubscribing
        preferences: JSON data with subscriber preferences
        source: How the subscriber was acquired
        is_active: Whether the subscription is currently active
        lists: Relationship to mailing lists through SubscriberList
    """
    __tablename__ = 'newsletter_subscribers'

    # Subscription sources
    SOURCE_WEBSITE = 'website'
    SOURCE_IMPORT = 'import'
    SOURCE_API = 'api'
    SOURCE_MANUAL = 'manual'
    SOURCE_FORM = 'form'

    # Subscription status constants
    STATUS_PENDING = 'pending'
    STATUS_CONFIRMED = 'confirmed'
    STATUS_UNSUBSCRIBED = 'unsubscribed'

    # Cache timeout in seconds (5 minutes)
    CACHE_TIMEOUT = 300

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)

    # Status fields
    subscribed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    confirmed = db.Column(db.Boolean, default=False)
    confirmed_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)

    # Security tokens
    confirmation_token = db.Column(db.String(64), default=lambda: generate_secure_token(), unique=True)
    unsubscribe_token = db.Column(db.String(64), default=lambda: generate_secure_token(), unique=True)

    # Additional fields
    preferences = db.Column(db.JSON, default=dict, nullable=True)
    source = db.Column(db.String(50), nullable=True)

    # Relationships
    lists = relationship("MailingList", secondary="subscriber_lists", back_populates="subscribers")

    def __init__(self, email: str, first_name: Optional[str] = None,
                 last_name: Optional[str] = None, source: Optional[str] = None,
                 preferences: Optional[Dict[str, Any]] = None):
        """
        Initialize a new subscriber instance.

        Args:
            email: Subscriber's email address
            first_name: Subscriber's first name (optional)
            last_name: Subscriber's last name (optional)
            source: Where the subscriber came from (optional)
            preferences: Initial preferences as dictionary (optional)

        Raises:
            ValueError: If email is not provided or invalid format
        """
        if not email:
            raise ValueError("Email address is required")

        # More comprehensive email validation
        email = email.lower().strip()
        if not self.is_valid_email(email):
            raise ValueError("Invalid email address format")

        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.source = source
        self.preferences = preferences or {}

        # Generate tokens using secure utility function
        self.confirmation_token = generate_secure_token()
        self.unsubscribe_token = generate_secure_token()

        # Set timestamp in UTC
        self.subscribed_at = datetime.now(timezone.utc)

    @staticmethod
    def is_valid_email(email: str) -> bool:
        """
        Validate email format using a more comprehensive regex pattern.

        Args:
            email: Email address to validate

        Returns:
            bool: True if email format is valid
        """
        # Simple regex for email validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def confirm_subscription(self) -> bool:
        """
        Confirm subscriber's email address.

        Returns:
            bool: True if confirmation was successful
        """
        if self.confirmed:
            return True  # Already confirmed

        try:
            self.confirmed = True
            self.confirmed_at = datetime.now(timezone.utc)
            db.session.commit()

            # Invalidate cache
            self._clear_cache()

            if hasattr(current_app, 'logger'):
                current_app.logger.info(f"Subscription confirmed for {self.email}")

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error confirming subscription: {str(e)}")
            return False

    def unsubscribe(self) -> bool:
        """
        Unsubscribe a user from all newsletters.

        Returns:
            bool: True if unsubscribe was successful
        """
        try:
            self.is_active = False
            db.session.commit()

            # Invalidate cache
            self._clear_cache()

            if hasattr(current_app, 'logger'):
                current_app.logger.info(f"User unsubscribed: {self.email}")

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error unsubscribing: {str(e)}")
            return False

    def regenerate_tokens(self) -> bool:
        """
        Regenerate the confirmation and unsubscribe tokens.

        Returns:
            bool: True if token regeneration was successful
        """
        try:
            # Use secure token generation
            self.confirmation_token = generate_secure_token()
            self.unsubscribe_token = generate_secure_token()
            db.session.commit()

            # Invalidate cache
            self._clear_cache()

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error regenerating tokens: {str(e)}")
            return False

    def update_preferences(self, preferences: Dict[str, Any]) -> bool:
        """
        Update subscriber preferences.

        Args:
            preferences: Dictionary of preferences to update

        Returns:
            bool: True if update was successful
        """
        if not preferences or not isinstance(preferences, dict):
            if hasattr(current_app, 'logger'):
                current_app.logger.warning(f"Invalid preferences format for {self.email}")
            return False

        try:
            # Merge with existing preferences
            current_prefs = self.preferences or {}
            current_prefs.update(preferences)
            self.preferences = current_prefs
            db.session.commit()

            # Invalidate cache
            self._clear_cache()

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error updating preferences: {str(e)}")
            return False

    def add_to_list(self, mailing_list: 'MailingList') -> bool:
        """
        Add subscriber to a mailing list.

        Args:
            mailing_list: MailingList object to add subscriber to

        Returns:
            bool: True if successful
        """
        # Check if list is active
        if not mailing_list.is_active:
            if hasattr(current_app, 'logger'):
                current_app.logger.warning(f"Cannot add subscriber to inactive list: {mailing_list.name}")
            return False

        # Check if subscriber is already in this list
        if mailing_list in self.lists:
            return True  # Already in list

        try:
            subscriber_list = SubscriberList(
                subscriber_id=self.id,
                list_id=mailing_list.id
            )
            db.session.add(subscriber_list)
            db.session.commit()

            # Invalidate cache
            self._clear_cache()
            mailing_list._clear_cache()

            return True
        except IntegrityError:
            # Duplicate entry - subscriber already in this list
            db.session.rollback()
            return True  # Consider this a success since the end state is what was requested
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error adding to list: {str(e)}")
            return False

    def remove_from_list(self, mailing_list: 'MailingList') -> bool:
        """
        Remove subscriber from a mailing list.

        Args:
            mailing_list: MailingList object to remove subscriber from

        Returns:
            bool: True if successful
        """
        try:
            # Check if association exists before attempting deletion
            association = SubscriberList.query.filter_by(
                subscriber_id=self.id,
                list_id=mailing_list.id
            ).first()

            if not association:
                return True  # Already not in the list

            db.session.delete(association)
            db.session.commit()

            # Invalidate cache
            self._clear_cache()
            mailing_list._clear_cache()

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error removing from list: {str(e)}")
            return False

    def get_subscription_status(self) -> str:
        """
        Get the current subscription status.

        Returns:
            str: Status - pending, confirmed, or unsubscribed
        """
        if not self.is_active:
            return self.STATUS_UNSUBSCRIBED
        elif self.confirmed:
            return self.STATUS_CONFIRMED
        else:
            return self.STATUS_PENDING

    def get_full_name(self) -> str:
        """
        Get subscriber's full name if available.

        Returns:
            str: Full name or email if name not available
        """
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        elif self.last_name:
            return self.last_name
        return self.email

    def _clear_cache(self) -> None:
        """Clear cached data for this subscriber."""
        if hasattr(cache, 'delete'):
            try:
                # Clear subscriber-specific cache entries
                cache.delete(f"subscriber:{self.id}")
                cache.delete(f"subscriber_email:{self.email}")
            except Exception as e:
                if hasattr(current_app, 'logger'):
                    current_app.logger.warning(f"Failed to clear subscriber cache: {str(e)}")

    @classmethod
    def get_active_subscribers(cls, page: int = 1, per_page: int = 50) -> Union[List['Subscriber'], Tuple[List['Subscriber'], int]]:
        """
        Get all active subscribers with optional pagination.

        Args:
            page: Page number (1-indexed, default: 1)
            per_page: Number of subscribers per page (default: 50)

        Returns:
            List of active subscriber objects if page is None, otherwise tuple of (items, total)
        """
        query = cls.query.filter_by(confirmed=True, is_active=True).order_by(cls.email)

        if page is None:
            return query.all()

        # Return paginated results and total count for pagination controls
        paginated = query.paginate(page=page, per_page=per_page, error_out=False)
        return paginated.items, paginated.total

    @classmethod
    def get_by_email(cls, email: str) -> Optional['Subscriber']:
        """
        Find a subscriber by email.

        Args:
            email: Email address to search for

        Returns:
            Subscriber object or None if not found
        """
        if not email:
            return None

        email = email.lower().strip()

        # Check cache first
        cache_key = f"subscriber_email:{email}"
        if hasattr(cache, 'get'):
            cached_id = cache.get(cache_key)
            if cached_id is not None:
                return cls.query.get(cached_id)

        # Query database
        subscriber = cls.query.filter_by(email=email).first()

        # Cache result if found
        if subscriber and hasattr(cache, 'set'):
            try:
                cache.set(cache_key, subscriber.id, timeout=cls.CACHE_TIMEOUT)
            except Exception:
                pass

        return subscriber

    @classmethod
    def get_by_confirmation_token(cls, token: str) -> Optional['Subscriber']:
        """
        Find a subscriber by confirmation token.

        Args:
            token: Confirmation token to search for

        Returns:
            Subscriber object or None if not found
        """
        if not token:
            return None

        return cls.query.filter_by(confirmation_token=token).first()

    @classmethod
    def get_by_unsubscribe_token(cls, token: str) -> Optional['Subscriber']:
        """
        Find a subscriber by unsubscribe token.

        Args:
            token: Unsubscribe token to search for

        Returns:
            Subscriber object or None if not found
        """
        if not token:
            return None

        return cls.query.filter_by(unsubscribe_token=token).first()

    @classmethod
    def search(cls, query: str, limit: int = 50) -> List['Subscriber']:
        """
        Search for subscribers by email or name.

        Args:
            query: Search string
            limit: Maximum number of results to return

        Returns:
            List of matching subscribers
        """
        if not query:
            return []

        search_term = f"%{query}%"
        return cls.query.filter(
            db.or_(
                cls.email.ilike(search_term),
                cls.first_name.ilike(search_term),
                cls.last_name.ilike(search_term)
            )
        ).limit(limit).all()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert subscriber to dictionary for API responses.

        Returns:
            Dictionary representation of subscriber
        """
        return {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'full_name': self.get_full_name(),
            'subscribed_at': self.subscribed_at.isoformat() if self.subscribed_at else None,
            'status': self.get_subscription_status(),
            'confirmed': self.confirmed,
            'confirmed_at': self.confirmed_at.isoformat() if self.confirmed_at else None,
            'is_active': self.is_active,
            'preferences': self.preferences or {},
            'source': self.source,
            'lists': [lst.name for lst in self.lists] if self.lists else []
        }

    def __repr__(self) -> str:
        """String representation of subscriber."""
        status = self.get_subscription_status()
        return f"<Subscriber {self.email} ({status})>"


class MailingList(BaseModel):
    """
    Model representing a mailing list for newsletters.

    This model tracks mailing lists that subscribers can join, with
    attributes for list name, description, and configuration settings.

    Attributes:
        id: Primary key
        name: Unique list name
        description: List description
        is_active: Whether the list is currently active
        config: JSON configuration data
        subscribers: Relationship to subscribers through SubscriberList
    """
    __tablename__ = 'mailing_lists'

    # Cache timeout in seconds (5 minutes)
    CACHE_TIMEOUT = 300

    # List type constants
    TYPE_GENERAL = 'general'
    TYPE_MARKETING = 'marketing'
    TYPE_TRANSACTIONAL = 'transactional'
    TYPE_ANNOUNCEMENT = 'announcement'

    LIST_TYPES = [TYPE_GENERAL, TYPE_MARKETING, TYPE_TRANSACTIONAL, TYPE_ANNOUNCEMENT]

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    list_type = db.Column(db.String(20), default=TYPE_GENERAL, nullable=False)
    config = db.Column(db.JSON, default=dict, nullable=True)

    # Relationships
    subscribers = relationship("Subscriber", secondary="subscriber_lists", back_populates="lists")

    def __init__(self, name: str, description: Optional[str] = None,
                 is_active: bool = True, list_type: str = TYPE_GENERAL,
                 config: Optional[Dict[str, Any]] = None):
        """
        Initialize a new mailing list.

        Args:
            name: List name
            description: List description
            is_active: Whether the list is active
            list_type: Type of mailing list (default: general)
            config: Configuration settings

        Raises:
            ValueError: If list_type is not valid
        """
        if list_type and list_type not in self.LIST_TYPES:
            raise ValueError(f"Invalid list type. Must be one of: {', '.join(self.LIST_TYPES)}")

        self.name = name
        self.description = description
        self.is_active = is_active
        self.list_type = list_type
        self.config = config or {}

    def add_subscriber(self, subscriber: Subscriber) -> bool:
        """
        Add a subscriber to this mailing list.

        Args:
            subscriber: Subscriber to add

        Returns:
            bool: True if successful
        """
        if not self.is_active:
            if hasattr(current_app, 'logger'):
                current_app.logger.warning(f"Cannot add subscriber to inactive list: {self.name}")
            return False

        return subscriber.add_to_list(self)

    def remove_subscriber(self, subscriber: Subscriber) -> bool:
        """
        Remove a subscriber from this mailing list.

        Args:
            subscriber: Subscriber to remove

        Returns:
            bool: True if successful
        """
        return subscriber.remove_from_list(self)

    def add_subscribers(self, subscribers: List[Subscriber]) -> Tuple[int, int]:
        """
        Add multiple subscribers to this mailing list.

        Args:
            subscribers: List of Subscriber objects

        Returns:
            Tuple of (success_count, error_count)
        """
        if not self.is_active:
            if hasattr(current_app, 'logger'):
                current_app.logger.warning(f"Cannot add subscribers to inactive list: {self.name}")
            return 0, len(subscribers)

        success_count = 0
        error_count = 0

        for subscriber in subscribers:
            if subscriber.add_to_list(self):
                success_count += 1
            else:
                error_count += 1

        # Clear cache after bulk operation
        self._clear_cache()

        return success_count, error_count

    def get_subscribers(self, active_only: bool = True, confirmed_only: bool = True) -> List[Subscriber]:
        """
        Get all subscribers for this mailing list with optional filtering.

        Args:
            active_only: Only include active subscribers
            confirmed_only: Only include confirmed subscribers

        Returns:
            List of Subscriber objects
        """
        query = db.session.query(Subscriber).join(
            SubscriberList, Subscriber.id == SubscriberList.subscriber_id
        ).filter(
            SubscriberList.list_id == self.id
        )

        if active_only:
            query = query.filter(Subscriber.is_active == True)

        if confirmed_only:
            query = query.filter(Subscriber.confirmed == True)

        return query.all()

    @property
    def subscriber_count(self) -> int:
        """
        Get the number of subscribers on this list.

        Returns:
            int: Number of subscribers
        """
        # Check cache first
        cache_key = f"mailing_list_count:{self.id}"
        if hasattr(cache, 'get'):
            cached_count = cache.get(cache_key)
            if cached_count is not None:
                return cached_count

        # Query database
        count = SubscriberList.query.filter_by(list_id=self.id).count()

        # Cache result
        if hasattr(cache, 'set'):
            try:
                cache.set(cache_key, count, timeout=self.CACHE_TIMEOUT)
            except Exception:
                pass

        return count

    @property
    def active_subscriber_count(self) -> int:
        """
        Get the number of active and confirmed subscribers on this list.

        Returns:
            int: Number of active subscribers
        """
        return db.session.query(SubscriberList).join(
            Subscriber, SubscriberList.subscriber_id == Subscriber.id
        ).filter(
            SubscriberList.list_id == self.id,
            Subscriber.is_active == True,
            Subscriber.confirmed == True
        ).count()

    def _clear_cache(self) -> None:
        """Clear cached data for this mailing list."""
        if hasattr(cache, 'delete'):
            try:
                # Clear list-specific cache entries
                cache.delete(f"mailing_list:{self.id}")
                cache.delete(f"mailing_list_count:{self.id}")
            except Exception as e:
                if hasattr(current_app, 'logger'):
                    current_app.logger.warning(f"Failed to clear mailing list cache: {str(e)}")

    @classmethod
    def get_by_name(cls, name: str) -> Optional['MailingList']:
        """
        Get a mailing list by name.

        Args:
            name: Name of the mailing list

        Returns:
            MailingList object or None if not found
        """
        if not name:
            return None

        return cls.query.filter_by(name=name).first()

    @classmethod
    def get_active_lists(cls) -> List['MailingList']:
        """
        Get all active mailing lists.

        Returns:
            List of active MailingList objects
        """
        return cls.query.filter_by(is_active=True).order_by(cls.name).all()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert mailing list to dictionary for API responses.

        Returns:
            Dictionary representation of mailing list
        """
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'is_active': self.is_active,
            'list_type': self.list_type,
            'subscriber_count': self.subscriber_count,
            'active_subscriber_count': self.active_subscriber_count,
            'config': self.config or {}
        }

    def __repr__(self) -> str:
        """String representation of mailing list."""
        return f"<MailingList {self.name}>"


class SubscriberList(db.Model):
    """
    Association model for many-to-many relationship between subscribers and mailing lists.

    Attributes:
        id: Primary key
        subscriber_id: Foreign key to subscriber
        list_id: Foreign key to mailing list
        subscribed_at: When the subscriber was added to the list
    """
    __tablename__ = 'subscriber_lists'

    id = db.Column(db.Integer, primary_key=True)
    subscriber_id = db.Column(db.Integer, db.ForeignKey('newsletter_subscribers.id', ondelete='CASCADE'), nullable=False)
    list_id = db.Column(db.Integer, db.ForeignKey('mailing_lists.id', ondelete='CASCADE'), nullable=False)
    subscribed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Define unique constraint to prevent duplicate subscriptions
    __table_args__ = (
        db.UniqueConstraint('subscriber_id', 'list_id', name='uq_subscriber_list'),
    )

    # Add index for faster lookups
    __table_args__ = (
        db.UniqueConstraint('subscriber_id', 'list_id', name='uq_subscriber_list'),
        db.Index('idx_subscriber_lists_ids', 'subscriber_id', 'list_id'),
    )

    # Relationships for easier access
    subscriber = db.relationship('Subscriber', backref=db.backref('list_associations', cascade='all, delete-orphan'))
    mailing_list = db.relationship('MailingList', backref=db.backref('subscriber_associations', cascade='all, delete-orphan'))

    def __repr__(self) -> str:
        """String representation of subscriber-list association."""
        return f"<SubscriberList subscriber_id={self.subscriber_id} list_id={self.list_id}>"
