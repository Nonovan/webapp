"""
Subscriber model for email marketing and notifications in myproject.

This module defines the Subscriber model which serves as the foundation for
the application's email marketing and notification system. It provides:

- Proper tracking of subscriber email addresses
- Management of subscription status (active/inactive)
- Auditing of subscriber creation and modification dates
- Support for tracking subscriber preferences and categories
- Communication opt-in controls and channel preferences
- Metadata tracking for analytics and compliance
"""

from datetime import datetime, timezone
import re
from typing import Dict, Any, Optional, List, Tuple, Union

from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON, ForeignKey, Table, func, and_, or_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import relationship
from flask import current_app

from extensions import db, cache, metrics
from models.base import BaseModel
from core.security_utils import generate_secure_token


class Subscriber(BaseModel):
    """
    Subscriber model representing users who opted in to receive communications.

    This model tracks subscribers to various notification channels and services,
    maintaining their subscription status, preferences, and metadata for proper
    communication management.

    Attributes:
        id (int): Primary key, unique identifier for the subscriber
        email (str): Email address of the subscriber (required, unique)
        name (str): Full name of the subscriber (optional)
        is_active (bool): Whether the subscription is currently active
        preferences (dict): JSON field storing subscriber preferences
        subscription_date (datetime): When the user initially subscribed
        unsubscribe_date (datetime): When the user unsubscribed (if applicable)
        created_at (datetime): Timestamp when the subscriber record was created
        updated_at (datetime): Timestamp when the subscriber record was last updated
        categories (list): Categories this subscriber belongs to
        confirmed (bool): Whether the email address has been confirmed
        confirmed_at (datetime): When the email was confirmed
        confirmation_token (str): Token used for email confirmation
        unsubscribe_token (str): Token used for one-click unsubscribes
        metadata (dict): Additional tracking metadata for analytics
        communication_channels (dict): Channel-specific subscription preferences
    """
    __tablename__ = 'subscribers'

    # Cache timeout in seconds (5 minutes)
    CACHE_TIMEOUT = 300

    # Status constants
    STATUS_ACTIVE = 'active'
    STATUS_INACTIVE = 'inactive'
    STATUS_PENDING = 'pending'
    STATUS_UNSUBSCRIBED = 'unsubscribed'
    STATUS_BOUNCED = 'bounced'

    # Channel constants
    CHANNEL_EMAIL = 'email'
    CHANNEL_SMS = 'sms'
    CHANNEL_PUSH = 'push'
    CHANNEL_IN_APP = 'in_app'

    # Valid channels for opt-in settings
    VALID_CHANNELS = [CHANNEL_EMAIL, CHANNEL_SMS, CHANNEL_PUSH, CHANNEL_IN_APP]

    # Core fields
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), nullable=False, unique=True, index=True)
    name = Column(String(255), nullable=True)

    # Subscription status
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    subscription_date = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    unsubscribe_date = Column(DateTime(timezone=True), nullable=True)

    # Email confirmation
    confirmed = Column(Boolean, default=False, nullable=False, index=True)
    confirmed_at = Column(DateTime(timezone=True), nullable=True)
    confirmation_token = Column(String(64), nullable=True, unique=True)
    unsubscribe_token = Column(String(64), default=lambda: generate_secure_token(), unique=True)

    # Preferences and communication settings
    preferences = Column(JSON, nullable=True)
    communication_channels = Column(JSON, nullable=True)

    # Metadata for analytics and tracking
    metadata = Column(JSON, nullable=True)
    source = Column(String(50), nullable=True)
    last_engagement = Column(DateTime(timezone=True), nullable=True)
    bounce_count = Column(Integer, default=0, nullable=False)

    # Tracking fields with timezone awareness
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True),
                      default=lambda: datetime.now(timezone.utc),
                      onupdate=lambda: datetime.now(timezone.utc),
                      nullable=False)

    # Relationships
    categories = relationship('SubscriberCategory',
                             secondary='subscriber_categories',
                             back_populates='subscribers',
                             lazy='joined')

    def __init__(self, email: str, name: Optional[str] = None,
                is_active: bool = True, preferences: Optional[Dict[str, Any]] = None,
                confirmed: bool = False, source: Optional[str] = None,
                metadata: Optional[Dict[str, Any]] = None,
                communication_channels: Optional[Dict[str, bool]] = None) -> None:
        """
        Initialize a new Subscriber instance.

        Args:
            email (str): Email address of the subscriber (required)
            name (Optional[str]): Name of the subscriber (optional)
            is_active (bool): Whether the subscription is active (defaults to True)
            preferences (Optional[Dict[str, Any]]): Subscriber preferences (optional)
            confirmed (bool): Whether the email is confirmed (defaults to False)
            source (Optional[str]): Source of the subscription (optional)
            metadata (Optional[Dict[str, Any]]): Additional tracking metadata (optional)
            communication_channels (Optional[Dict[str, bool]]): Channel preferences (optional)
        """
        # Validate and normalize email
        if not email:
            raise ValueError("Email address is required")

        email = email.lower().strip()
        if not self.is_valid_email(email):
            raise ValueError(f"Invalid email address format: {email}")

        self.email = email
        self.name = name
        self.is_active = is_active
        self.preferences = preferences or {}
        self.source = source
        self.metadata = metadata or {}
        self.communication_channels = communication_channels or self._default_channel_preferences()
        self.confirmed = confirmed

        # Generate tokens for confirmation and unsubscribe
        if not confirmed:
            self.confirmation_token = generate_secure_token()

        # Set timestamps
        now = datetime.now(timezone.utc)
        self.subscription_date = now if is_active else None
        self.confirmed_at = now if confirmed else None

    def deactivate(self) -> None:
        """
        Deactivate this subscription and record the unsubscribe date.
        """
        if self.is_active:
            self.is_active = False
            self.unsubscribe_date = datetime.now(timezone.utc)
            self._clear_cache()

            # Track metrics
            if hasattr(metrics, 'increment'):
                metrics.increment('subscribers.deactivated')

    def reactivate(self) -> None:
        """
        Reactivate a previously deactivated subscription.
        """
        if not self.is_active:
            self.is_active = True
            self.subscription_date = datetime.now(timezone.utc)
            self.unsubscribe_date = None
            self._clear_cache()

            # Track metrics
            if hasattr(metrics, 'increment'):
                metrics.increment('subscribers.reactivated')

    def add_category(self, category: 'SubscriberCategory') -> bool:
        """
        Add subscriber to a category.

        Args:
            category (SubscriberCategory): Category to add the subscriber to

        Returns:
            bool: True if successful, False if already in category
        """
        if category not in self.categories:
            self.categories.append(category)
            self._clear_cache()
            return True
        return False

    def remove_category(self, category: 'SubscriberCategory') -> bool:
        """
        Remove subscriber from a category.

        Args:
            category (SubscriberCategory): Category to remove the subscriber from

        Returns:
            bool: True if successful, False if not in category
        """
        if category in self.categories:
            self.categories.remove(category)
            self._clear_cache()
            return True
        return False

    def update_preferences(self, new_preferences: Dict[str, Any]) -> None:
        """
        Update subscriber preferences.

        Args:
            new_preferences (Dict[str, Any]): Dictionary of preference settings to update
        """
        current_prefs = self.preferences or {}
        current_prefs.update(new_preferences)
        self.preferences = current_prefs
        self._clear_cache()

    def update_channel_preferences(self, channel: str, enabled: bool) -> bool:
        """
        Update communication channel preferences.

        Args:
            channel (str): The channel to update (email, sms, push, etc.)
            enabled (bool): Whether communication via this channel is enabled

        Returns:
            bool: True if successful, False if invalid channel
        """
        if channel not in self.VALID_CHANNELS:
            return False

        channels = self.communication_channels or self._default_channel_preferences()
        channels[channel] = enabled
        self.communication_channels = channels
        self._clear_cache()
        return True

    def confirm(self) -> bool:
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
            self.confirmation_token = None  # Invalidate token after use
            db.session.commit()
            self._clear_cache()

            # Track metrics
            if hasattr(metrics, 'increment'):
                metrics.increment('subscribers.confirmed')

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error confirming subscriber: {str(e)}")
            return False

    def record_engagement(self) -> None:
        """
        Record subscriber engagement (email open, click, etc.)
        """
        self.last_engagement = datetime.now(timezone.utc)
        self._clear_cache()

    def record_bounce(self) -> None:
        """
        Record an email bounce for this subscriber. Multiple bounces may lead to automatic deactivation.
        """
        self.bounce_count += 1

        # Auto-disable after multiple bounces
        if self.bounce_count >= 3:
            self.deactivate()
            if hasattr(current_app, 'logger'):
                current_app.logger.info(f"Deactivated subscriber after multiple bounces: {self.email}")

        self._clear_cache()

        # Track metrics
        if hasattr(metrics, 'increment'):
            metrics.increment('subscribers.bounce')

    def regenerate_confirmation_token(self) -> str:
        """
        Generate a new confirmation token.

        Returns:
            str: The new confirmation token
        """
        self.confirmation_token = generate_secure_token()
        self._clear_cache()
        return self.confirmation_token

    def regenerate_unsubscribe_token(self) -> str:
        """
        Generate a new unsubscribe token.

        Returns:
            str: The new unsubscribe token
        """
        self.unsubscribe_token = generate_secure_token()
        self._clear_cache()
        return self.unsubscribe_token

    def get_subscription_status(self) -> str:
        """
        Get the current subscription status.

        Returns:
            str: Status string (active, inactive, pending, unsubscribed, bounced)
        """
        if not self.is_active:
            return self.STATUS_UNSUBSCRIBED
        if self.bounce_count >= 3:
            return self.STATUS_BOUNCED
        if not self.confirmed:
            return self.STATUS_PENDING
        return self.STATUS_ACTIVE

    @staticmethod
    def is_valid_email(email: str) -> bool:
        """
        Validate email format using regex pattern.

        Args:
            email (str): Email address to validate

        Returns:
            bool: True if email format is valid
        """
        # RFC 5322 compliant email regex
        pattern = r"^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
        return re.match(pattern, email) is not None

    def _default_channel_preferences(self) -> Dict[str, bool]:
        """
        Get default communication channel preferences.

        Returns:
            Dict[str, bool]: Dictionary with default channel preferences
        """
        return {
            self.CHANNEL_EMAIL: True,
            self.CHANNEL_SMS: False,
            self.CHANNEL_PUSH: False,
            self.CHANNEL_IN_APP: True
        }

    def _clear_cache(self) -> None:
        """
        Clear cached data for this subscriber.
        """
        if hasattr(cache, 'delete'):
            try:
                cache.delete(f"subscriber:{self.id}")
                cache.delete(f"subscriber_email:{self.email}")
                if self.confirmation_token:
                    cache.delete(f"subscriber_token:{self.confirmation_token}")
                if self.unsubscribe_token:
                    cache.delete(f"subscriber_unsubscribe:{self.unsubscribe_token}")
            except Exception as e:
                if hasattr(current_app, 'logger'):
                    current_app.logger.warning(f"Failed to clear subscriber cache: {str(e)}")

    @classmethod
    def get_by_email(cls, email: str) -> Optional['Subscriber']:
        """
        Find a subscriber by email address.

        Args:
            email (str): Email address to search for

        Returns:
            Optional[Subscriber]: Subscriber if found, None otherwise
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
            token (str): Confirmation token

        Returns:
            Optional[Subscriber]: Subscriber if found, None otherwise
        """
        if not token:
            return None

        # Check cache first
        cache_key = f"subscriber_token:{token}"
        if hasattr(cache, 'get'):
            cached_id = cache.get(cache_key)
            if cached_id is not None:
                return cls.query.get(cached_id)

        # Query database
        subscriber = cls.query.filter_by(confirmation_token=token).first()

        # Cache result if found
        if subscriber and hasattr(cache, 'set'):
            try:
                cache.set(cache_key, subscriber.id, timeout=cls.CACHE_TIMEOUT)
            except Exception:
                pass

        return subscriber

    @classmethod
    def get_by_unsubscribe_token(cls, token: str) -> Optional['Subscriber']:
        """
        Find a subscriber by unsubscribe token.

        Args:
            token (str): Unsubscribe token

        Returns:
            Optional[Subscriber]: Subscriber if found, None otherwise
        """
        if not token:
            return None

        # Check cache first
        cache_key = f"subscriber_unsubscribe:{token}"
        if hasattr(cache, 'get'):
            cached_id = cache.get(cache_key)
            if cached_id is not None:
                return cls.query.get(cached_id)

        # Query database
        subscriber = cls.query.filter_by(unsubscribe_token=token).first()

        # Cache result if found
        if subscriber and hasattr(cache, 'set'):
            try:
                cache.set(cache_key, subscriber.id, timeout=cls.CACHE_TIMEOUT)
            except Exception:
                pass

        return subscriber

    @classmethod
    def get_active_subscribers(cls, page: int = 1, per_page: int = 50) -> Union[List['Subscriber'], Tuple[List['Subscriber'], int]]:
        """
        Get all active and confirmed subscribers with pagination.

        Args:
            page (int): Page number (1-indexed)
            per_page (int): Number of items per page

        Returns:
            Union[List[Subscriber], Tuple[List[Subscriber], int]]:
            List of subscribers or tuple of (subscribers, total)
        """
        query = cls.query.filter(
            cls.is_active == True,
            cls.confirmed == True
        ).order_by(cls.email)

        # Return paginated results
        paginated = query.paginate(page=page, per_page=per_page, error_out=False)
        return paginated.items, paginated.total

    @classmethod
    def search(cls, query_str: str, status: Optional[str] = None,
              categories: Optional[List[int]] = None, limit: int = 50) -> List['Subscriber']:
        """
        Search for subscribers with filters.

        Args:
            query_str (str): Search string for email or name
            status (Optional[str]): Filter by subscription status
            categories (Optional[List[int]]): List of category IDs to filter by
            limit (int): Maximum number of results to return

        Returns:
            List[Subscriber]: List of matching subscribers
        """
        # Start with base query
        query = cls.query

        # Apply search filter if provided
        if query_str:
            search_term = f"%{query_str}%"
            query = query.filter(
                or_(
                    cls.email.ilike(search_term),
                    cls.name.ilike(search_term)
                )
            )

        # Filter by status
        if status:
            if status == cls.STATUS_ACTIVE:
                query = query.filter(cls.is_active == True, cls.confirmed == True)
            elif status == cls.STATUS_INACTIVE:
                query = query.filter(cls.is_active == False)
            elif status == cls.STATUS_PENDING:
                query = query.filter(cls.is_active == True, cls.confirmed == False)

        # Filter by categories
        if categories:
            from sqlalchemy import exists
            for cat_id in categories:
                subquery = exists().where(and_(
                    subscriber_categories.c.subscriber_id == cls.id,
                    subscriber_categories.c.category_id == cat_id
                ))
                query = query.filter(subquery)

        # Apply limit and return results
        return query.limit(limit).all()

    @classmethod
    def get_stats(cls) -> Dict[str, Any]:
        """
        Get subscriber statistics.

        Returns:
            Dict[str, Any]: Dictionary with subscriber statistics
        """
        try:
            # Get total counts
            total = cls.query.count()
            active = cls.query.filter(cls.is_active == True).count()
            confirmed = cls.query.filter(cls.is_active == True, cls.confirmed == True).count()
            pending = cls.query.filter(cls.is_active == True, cls.confirmed == False).count()
            inactive = cls.query.filter(cls.is_active == False).count()

            # Get count by source (if available)
            sources = {}
            if hasattr(cls, 'source'):
                source_counts = db.session.query(
                    cls.source, func.count(cls.id)
                ).group_by(cls.source).all()

                for source, count in source_counts:
                    if source:
                        sources[source] = count

            # Return stats dictionary
            return {
                'total': total,
                'active': active,
                'confirmed': confirmed,
                'pending': pending,
                'inactive': inactive,
                'sources': sources
            }
        except SQLAlchemyError as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error getting subscriber stats: {str(e)}")
            return {
                'total': 0,
                'active': 0,
                'confirmed': 0,
                'pending': 0,
                'inactive': 0,
                'sources': {}
            }

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the subscriber to a dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary with subscriber data
        """
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'is_active': self.is_active,
            'status': self.get_subscription_status(),
            'preferences': self.preferences or {},
            'communication_channels': self.communication_channels or self._default_channel_preferences(),
            'confirmed': getattr(self, 'confirmed', False),
            'confirmed_at': self.confirmed_at.isoformat() if getattr(self, 'confirmed_at', None) else None,
            'subscription_date': self.subscription_date.isoformat() if self.subscription_date else None,
            'unsubscribe_date': self.unsubscribe_date.isoformat() if self.unsubscribe_date else None,
            'last_engagement': self.last_engagement.isoformat() if getattr(self, 'last_engagement', None) else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'categories': [c.name for c in self.categories] if self.categories else [],
            'source': getattr(self, 'source', None),
            'metadata': self.metadata or {}
        }

    def __repr__(self) -> str:
        """
        String representation of the Subscriber instance.

        Returns:
            str: String representation of the subscriber
        """
        status = self.get_subscription_status()
        return f"<Subscriber(id={self.id}, email='{self.email}', status='{status}')>"


# Association table for many-to-many relationship between subscribers and categories
subscriber_categories = Table(
    'subscriber_categories',
    BaseModel.metadata,
    Column('subscriber_id', Integer, ForeignKey('subscribers.id', ondelete='CASCADE'), primary_key=True),
    Column('category_id', Integer, ForeignKey('subscriber_categories.id', ondelete='CASCADE'), primary_key=True)
)


class SubscriberCategory(BaseModel):
    """
    Categories for organizing subscribers.

    Attributes:
        id (int): Primary key, unique identifier for the category
        name (str): Name of the category
        description (str): Description of the category
        subscribers (list): List of subscribers in this category
    """
    __tablename__ = 'subscriber_categories'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    parent_id = Column(Integer, ForeignKey('subscriber_categories.id'), nullable=True)

    # Relationships
    subscribers = relationship('Subscriber',
                             secondary='subscriber_categories',
                             back_populates='categories',
                             lazy='dynamic')
    # Self-referential relationship for hierarchical categories
    parent = relationship('SubscriberCategory', remote_side=[id], backref='subcategories')

    def __init__(self, name: str, description: Optional[str] = None,
                parent: Optional['SubscriberCategory'] = None) -> None:
        """
        Initialize a new SubscriberCategory.

        Args:
            name (str): Name of the category
            description (Optional[str]): Description of the category
            parent (Optional[SubscriberCategory]): Parent category for hierarchical organization
        """
        self.name = name
        self.description = description
        self.parent = parent

    def get_active_subscribers(self) -> List['Subscriber']:
        """
        Get active subscribers in this category.

        Returns:
            List[Subscriber]: List of active subscribers in this category
        """
        return self.subscribers.filter(Subscriber.is_active == True, Subscriber.confirmed == True).all()

    def get_subscriber_count(self) -> int:
        """
        Get count of active subscribers in this category.

        Returns:
            int: Number of active subscribers
        """
        return self.subscribers.filter(Subscriber.is_active == True, Subscriber.confirmed == True).count()

    def get_all_subscribers(self, include_subcategories: bool = False) -> List['Subscriber']:
        """
        Get all subscribers in this category, optionally including subcategories.

        Args:
            include_subcategories (bool): Whether to include subscribers from subcategories

        Returns:
            List[Subscriber]: List of all subscribers
        """
        all_subscribers = set(self.subscribers.all())

        if include_subcategories:
            for subcategory in self.subcategories:
                all_subscribers.update(subcategory.get_all_subscribers(include_subcategories=True))

        return list(all_subscribers)

    @classmethod
    def get_by_name(cls, name: str) -> Optional['SubscriberCategory']:
        """
        Get category by name.

        Args:
            name (str): Category name

        Returns:
            Optional[SubscriberCategory]: Category object or None if not found
        """
        return cls.query.filter(func.lower(cls.name) == name.lower()).first()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert category to dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary with category data
        """
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'parent_id': self.parent_id,
            'subscriber_count': self.get_subscriber_count(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'subcategories': [s.id for s in self.subcategories] if hasattr(self, 'subcategories') else []
        }

    def __repr__(self) -> str:
        """
        String representation of the category.

        Returns:
            str: String representation of the category
        """
        return f"<SubscriberCategory(id={self.id}, name='{self.name}')>"
