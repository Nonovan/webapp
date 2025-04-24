"""
Subscriber model for email marketing and notifications in myproject.

This module defines the Subscriber model which serves as the foundation for
the application's email marketing and notification system. It provides:

- Proper tracking of subscriber email addresses
- Management of subscription status (active/inactive)
- Auditing of subscriber creation and modification dates
- Support for tracking subscriber preferences and categories
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON, ForeignKey, Table
from sqlalchemy.orm import relationship

from extensions import db
from models.base import BaseModel


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
    """
    __tablename__ = 'subscribers'

    # Core fields
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), nullable=False, unique=True, index=True)
    name = Column(String(255), nullable=True)

    # Subscription status
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    subscription_date = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    unsubscribe_date = Column(DateTime(timezone=True), nullable=True)

    # Preferences
    preferences = Column(JSON, nullable=True)

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
                is_active: bool = True, preferences: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize a new Subscriber instance.

        Args:
            email (str): Email address of the subscriber (required)
            name (Optional[str]): Name of the subscriber (optional)
            is_active (bool): Whether the subscription is active (defaults to True)
            preferences (Optional[Dict[str, Any]]): Subscriber preferences (optional)
        """
        self.email = email
        self.name = name
        self.is_active = is_active
        self.preferences = preferences or {}
        self.subscription_date = datetime.now(timezone.utc) if is_active else None

    def deactivate(self) -> None:
        """
        Deactivate this subscription and record the unsubscribe date.
        """
        if self.is_active:
            self.is_active = False
            self.unsubscribe_date = datetime.now(timezone.utc)

    def reactivate(self) -> None:
        """
        Reactivate a previously deactivated subscription.
        """
        if not self.is_active:
            self.is_active = True
            self.subscription_date = datetime.now(timezone.utc)
            self.unsubscribe_date = None

    def add_category(self, category: 'SubscriberCategory') -> None:
        """
        Add subscriber to a category.

        Args:
            category (SubscriberCategory): Category to add the subscriber to
        """
        if category not in self.categories:
            self.categories.append(category)

    def remove_category(self, category: 'SubscriberCategory') -> None:
        """
        Remove subscriber from a category.

        Args:
            category (SubscriberCategory): Category to remove the subscriber from
        """
        if category in self.categories:
            self.categories.remove(category)

    def update_preferences(self, new_preferences: Dict[str, Any]) -> None:
        """
        Update subscriber preferences.

        Args:
            new_preferences (Dict[str, Any]): Dictionary of preference settings to update
        """
        current_prefs = self.preferences or {}
        current_prefs.update(new_preferences)
        self.preferences = current_prefs

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
            'preferences': self.preferences or {},
            'subscription_date': self.subscription_date.isoformat() if self.subscription_date else None,
            'unsubscribe_date': self.unsubscribe_date.isoformat() if self.unsubscribe_date else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'categories': [c.name for c in self.categories] if self.categories else []
        }

    def __repr__(self) -> str:
        """
        String representation of the Subscriber instance.

        Returns:
            str: String representation of the subscriber
        """
        status = "active" if self.is_active else "inactive"
        return f"<Subscriber(id={self.id}, email='{self.email}', status={status})>"


# Association table for many-to-many relationship between subscribers and categories
subscriber_categories = Table(
    'subscriber_categories',
    BaseModel.metadata,
    Column('subscriber_id', Integer, ForeignKey('subscribers.id'), primary_key=True),
    Column('category_id', Integer, ForeignKey('subscriber_categories.id'), primary_key=True)
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

    # Relationships
    subscribers = relationship('Subscriber',
                             secondary='subscriber_categories',
                             back_populates='categories',
                             lazy='dynamic')

    def __init__(self, name: str, description: Optional[str] = None) -> None:
        """
        Initialize a new SubscriberCategory.

        Args:
            name (str): Name of the category
            description (Optional[str]): Description of the category
        """
        self.name = name
        self.description = description

    def get_active_subscribers(self) -> List['Subscriber']:
        """
        Get active subscribers in this category.

        Returns:
            List[Subscriber]: List of active subscribers in this category
        """
        return self.subscribers.filter(Subscriber.is_active == True).all()

    def __repr__(self) -> str:
        """
        String representation of the category.

        Returns:
            str: String representation of the category
        """
        return f"<SubscriberCategory(id={self.id}, name='{self.name}')>"
