"""
User preference models for the Cloud Infrastructure Platform.

This module defines preference models for users across the platform,
including notification preferences, communication channel preferences,
and general preference handling capabilities.

It provides a base UserPreference class that can be extended for
different preference types, ensuring consistent implementation patterns.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Set, Type, TypeVar, Generic
from sqlalchemy import Column, Integer, String, Boolean, JSON, ForeignKey, Text
from sqlalchemy.orm import relationship
from flask import current_app
import json

from extensions import db, cache
from models.base import BaseModel, AuditableMixin

# Import notification categories from service_constants if available
try:
    from services.service_constants import (
        NOTIFICATION_CATEGORY_SYSTEM,
        NOTIFICATION_CATEGORY_SECURITY,
        NOTIFICATION_CATEGORY_USER,
        NOTIFICATION_CATEGORY_ADMIN,
        NOTIFICATION_CATEGORY_MAINTENANCE,
        NOTIFICATION_CATEGORY_MONITORING,
        NOTIFICATION_CATEGORY_COMPLIANCE,
        NOTIFICATION_CATEGORY_INTEGRITY,
        NOTIFICATION_CATEGORY_AUDIT,
        NOTIFICATION_CATEGORY_SCAN,
        NOTIFICATION_CATEGORY_VULNERABILITY,
        NOTIFICATION_CATEGORY_INCIDENT,
    )
    SERVICE_CONSTANTS_AVAILABLE = True
except ImportError:
    # Default values if service_constants not available
    NOTIFICATION_CATEGORY_SYSTEM = 'system'
    NOTIFICATION_CATEGORY_SECURITY = 'security'
    NOTIFICATION_CATEGORY_USER = 'user'
    NOTIFICATION_CATEGORY_ADMIN = 'admin'
    NOTIFICATION_CATEGORY_MAINTENANCE = 'maintenance'
    NOTIFICATION_CATEGORY_MONITORING = 'monitoring'
    NOTIFICATION_CATEGORY_COMPLIANCE = 'compliance'
    NOTIFICATION_CATEGORY_INTEGRITY = 'integrity'
    NOTIFICATION_CATEGORY_AUDIT = 'audit'
    NOTIFICATION_CATEGORY_SCAN = 'scan'
    NOTIFICATION_CATEGORY_VULNERABILITY = 'vulnerability'
    NOTIFICATION_CATEGORY_INCIDENT = 'incident'
    SERVICE_CONSTANTS_AVAILABLE = False


class UserPreference(BaseModel, AuditableMixin):
    """
    Base user preference model.

    This abstract model provides common functionality for all user preference types
    including audit logging, cache management, and standard CRUD operations.
    This should not be directly instantiated but rather used as a parent class.

    Attributes:
        id: Primary key
        user_id: User ID this preference belongs to
        additional_settings: JSON field for additional custom settings
    """
    __abstract__ = True

    # Cache timeout (in seconds)
    CACHE_TIMEOUT = 300  # 5 minutes

    # Auditing settings
    SECURITY_CRITICAL_FIELDS = []
    AUDIT_ACCESS = True

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                       nullable=False, index=True)
    additional_settings = db.Column(db.JSON, default=dict)

    def update(self, preferences: Dict[str, Any]) -> bool:
        """
        Update user preferences with new values.

        Args:
            preferences: Dictionary of preferences to update

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            for key, value in preferences.items():
                if hasattr(self, key):
                    # Special handling for JSON fields
                    if isinstance(getattr(self.__class__, key).type, db.JSON):
                        if isinstance(value, (dict, list)):
                            # Validate if needed
                            self._validate_json_field(key, value)
                        else:
                            # Skip invalid JSON types
                            continue

                    setattr(self, key, value)

            db.session.add(self)
            db.session.commit()

            # Clear cache
            self._clear_cache()

            return True
        except Exception as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to update {self.__class__.__name__}: {str(e)}")
            return False

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert preferences to dictionary.

        Returns:
            Dict: Dictionary representation of preferences
        """
        # Base implementation - should be extended by subclasses
        return {
            'user_id': self.user_id,
            'additional_settings': self.additional_settings or {}
        }

    def _validate_json_field(self, field_name: str, value: Any) -> bool:
        """
        Validate JSON fields for specific preference types.
        Meant to be overridden by subclasses for specific validation rules.

        Args:
            field_name: Name of field to validate
            value: Value to validate

        Returns:
            bool: True if valid, False otherwise
        """
        return True

    def _clear_cache(self) -> None:
        """Clear cache entries for this preference."""
        try:
            if hasattr(cache, 'delete'):
                cache.delete(f"user_pref:{self.__class__.__name__}:{self.user_id}")
        except Exception as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.debug(f"Failed to clear preference cache: {str(e)}")

    @classmethod
    def get_for_user(cls, user_id: int) -> Optional[Any]:
        """
        Get preferences for a specific user.

        Args:
            user_id: ID of the user

        Returns:
            Optional[Any]: Preference object if found, None otherwise
        """
        try:
            # Try to get from cache first
            if hasattr(cache, 'get'):
                cached = cache.get(f"user_pref:{cls.__name__}:{user_id}")
                if cached:
                    return cls.from_cache(cached)

            # If not in cache, get from database
            pref = cls.query.filter_by(user_id=user_id).first()

            # Cache result if found
            if pref and hasattr(cache, 'set'):
                cache.set(f"user_pref:{cls.__name__}:{user_id}",
                         json.dumps(pref.to_dict()),
                         timeout=cls.CACHE_TIMEOUT)

            return pref
        except Exception as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to get preference: {str(e)}")
            return None

    @classmethod
    def from_cache(cls, cached_data: str) -> Any:
        """
        Create instance from cached data.

        Args:
            cached_data: JSON string of cached preference

        Returns:
            Instance of preference class
        """
        try:
            data = json.loads(cached_data)
            instance = cls()
            for key, value in data.items():
                if hasattr(instance, key):
                    setattr(instance, key, value)
            return instance
        except Exception as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to parse cached preference: {str(e)}")
            return None


class NotificationPreference(UserPreference):
    """
    User notification preferences.

    This model stores user preferences for receiving notifications, including:
    - Which notification types they want to receive
    - Through which channels (email, SMS, in-app, etc.)
    - Priority threshold (only receive notifications above a certain priority)
    - Category subscriptions (which notification categories to receive)
    - Quiet hours (when not to send notifications)

    Attributes:
        id: Primary key (inherited from UserPreference)
        user_id: User ID this preference belongs to (inherited from UserPreference)
        email_enabled: Whether email notifications are enabled
        sms_enabled: Whether SMS notifications are enabled
        push_enabled: Whether push notifications are enabled
        in_app_enabled: Whether in-app notifications are enabled
        webhook_enabled: Whether webhook notifications are enabled
        priority_threshold: Minimum priority level to receive notifications
        subscribed_categories: List of notification categories to receive
        disabled_types: List of notification types to not receive
        quiet_hours_start: Start time for quiet hours (no notifications)
        quiet_hours_end: End time for quiet hours
        quiet_hours_timezone: Timezone for quiet hours
        additional_settings: JSON field for additional custom settings (inherited)
    """
    __tablename__ = 'notification_preferences'

    # Override security critical fields
    SECURITY_CRITICAL_FIELDS = ['email_enabled', 'sms_enabled', 'subscribed_categories']

    # Priority threshold constants for reuse
    PRIORITY_THRESHOLD_LOW = 'low'        # Receive all notifications
    PRIORITY_THRESHOLD_MEDIUM = 'medium'  # Receive medium, high, critical
    PRIORITY_THRESHOLD_HIGH = 'high'      # Receive high and critical
    PRIORITY_THRESHOLD_CRITICAL = 'critical'  # Receive only critical

    VALID_PRIORITY_THRESHOLDS = [
        PRIORITY_THRESHOLD_LOW,
        PRIORITY_THRESHOLD_MEDIUM,
        PRIORITY_THRESHOLD_HIGH,
        PRIORITY_THRESHOLD_CRITICAL
    ]

    # Channel preferences - not using db.Column here since it's already defined in parent class
    email_enabled = db.Column(db.Boolean, default=True)
    sms_enabled = db.Column(db.Boolean, default=False)
    push_enabled = db.Column(db.Boolean, default=False)
    in_app_enabled = db.Column(db.Boolean, default=True)
    webhook_enabled = db.Column(db.Boolean, default=False)

    # Notification content preferences
    priority_threshold = db.Column(db.String(20), default=PRIORITY_THRESHOLD_LOW)
    subscribed_categories = db.Column(db.JSON, default=list)
    disabled_types = db.Column(db.JSON, default=list)

    # Quiet hours settings
    quiet_hours_enabled = db.Column(db.Boolean, default=False)
    quiet_hours_start = db.Column(db.String(5), default='22:00')  # Format: HH:MM in 24h
    quiet_hours_end = db.Column(db.String(5), default='07:00')    # Format: HH:MM in 24h
    quiet_hours_timezone = db.Column(db.String(50), default='UTC')

    # Relationships
    user = relationship('User', backref=db.backref('notification_preference',
                                                  uselist=False,
                                                  cascade='all, delete-orphan'))

    def __init__(self, user_id: int, **kwargs):
        """
        Initialize notification preferences for a user.

        Args:
            user_id: ID of the user these preferences belong to
            **kwargs: Additional preference settings
        """
        super().__init__()
        self.user_id = user_id

        # Set default subscribed categories if not provided
        if 'subscribed_categories' not in kwargs:
            # By default, subscribe to security and system categories
            kwargs['subscribed_categories'] = [
                NOTIFICATION_CATEGORY_SECURITY,
                NOTIFICATION_CATEGORY_SYSTEM,
                NOTIFICATION_CATEGORY_USER
            ]

        # Apply any other provided settings
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def set_quiet_hours(self, enabled: bool, start_time: Optional[str] = None,
                       end_time: Optional[str] = None, timezone: Optional[str] = None) -> bool:
        """
        Set quiet hours when notifications shouldn't be sent.

        Args:
            enabled: Whether quiet hours are enabled
            start_time: Start time in format HH:MM (24h)
            end_time: End time in format HH:MM (24h)
            timezone: Timezone name (e.g., 'America/New_York')

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.quiet_hours_enabled = enabled

            if start_time:
                # Validate time format (HH:MM)
                if not self._is_valid_time_format(start_time):
                    return False
                self.quiet_hours_start = start_time

            if end_time:
                # Validate time format (HH:MM)
                if not self._is_valid_time_format(end_time):
                    return False
                self.quiet_hours_end = end_time

            if timezone:
                self.quiet_hours_timezone = timezone

            db.session.add(self)
            db.session.commit()

            # Clear cache
            self._clear_cache()

            return True
        except Exception as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to update quiet hours: {str(e)}")
            return False

    def subscribe_to_category(self, category: str) -> bool:
        """
        Subscribe to a notification category.

        Args:
            category: Category to subscribe to

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get current subscribed categories
            subscribed = self.subscribed_categories or []

            # Check if valid category
            valid_categories = self.get_valid_categories()
            if category not in valid_categories:
                if hasattr(current_app, 'logger'):
                    current_app.logger.warning(f"Invalid notification category: {category}")
                return False

            # Add category if not already subscribed
            if category not in subscribed:
                subscribed.append(category)
                self.subscribed_categories = subscribed
                db.session.add(self)
                db.session.commit()

                # Clear cache
                self._clear_cache()

            return True
        except Exception as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to subscribe to category: {str(e)}")
            return False

    def unsubscribe_from_category(self, category: str) -> bool:
        """
        Unsubscribe from a notification category.

        Args:
            category: Category to unsubscribe from

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get current subscribed categories
            subscribed = self.subscribed_categories or []

            # Remove category if subscribed
            if category in subscribed:
                subscribed.remove(category)
                self.subscribed_categories = subscribed
                db.session.add(self)
                db.session.commit()

                # Clear cache
                self._clear_cache()

            return True
        except Exception as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to unsubscribe from category: {str(e)}")
            return False

    def is_subscribed_to_category(self, category: str) -> bool:
        """
        Check if user is subscribed to a notification category.

        Args:
            category: Category to check

        Returns:
            bool: True if subscribed, False otherwise
        """
        subscribed = self.subscribed_categories or []
        return category in subscribed

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert notification preferences to dictionary.

        Returns:
            Dict: Dictionary representation of preferences
        """
        # Include base class fields and extend with notification-specific fields
        base_dict = super().to_dict()
        notification_dict = {
            'email_enabled': self.email_enabled,
            'sms_enabled': self.sms_enabled,
            'push_enabled': self.push_enabled,
            'in_app_enabled': self.in_app_enabled,
            'webhook_enabled': self.webhook_enabled,
            'priority_threshold': self.priority_threshold,
            'subscribed_categories': self.subscribed_categories or [],
            'disabled_types': self.disabled_types or [],
            'quiet_hours': {
                'enabled': self.quiet_hours_enabled,
                'start': self.quiet_hours_start,
                'end': self.quiet_hours_end,
                'timezone': self.quiet_hours_timezone
            }
        }

        # Merge dictionaries
        return {**base_dict, **notification_dict}

    def _validate_json_field(self, field_name: str, value: Any) -> bool:
        """
        Validate JSON fields for notification preferences.

        Args:
            field_name: Name of field to validate
            value: Value to validate

        Returns:
            bool: True if valid, False otherwise
        """
        if field_name == 'subscribed_categories' and isinstance(value, list):
            # Validate categories
            valid_categories = self.get_valid_categories()
            for cat in value:
                if cat not in valid_categories:
                    return False
        return True

    @staticmethod
    def get_valid_categories() -> List[str]:
        """
        Get list of valid notification categories.

        Returns:
            List[str]: List of valid category names
        """
        return [
            NOTIFICATION_CATEGORY_SYSTEM,
            NOTIFICATION_CATEGORY_SECURITY,
            NOTIFICATION_CATEGORY_USER,
            NOTIFICATION_CATEGORY_ADMIN,
            NOTIFICATION_CATEGORY_MAINTENANCE,
            NOTIFICATION_CATEGORY_MONITORING,
            NOTIFICATION_CATEGORY_COMPLIANCE,
            NOTIFICATION_CATEGORY_INTEGRITY,
            NOTIFICATION_CATEGORY_AUDIT,
            NOTIFICATION_CATEGORY_SCAN,
            NOTIFICATION_CATEGORY_VULNERABILITY,
            NOTIFICATION_CATEGORY_INCIDENT,
        ]

    @classmethod
    def get_or_create(cls, user_id: int) -> 'NotificationPreference':
        """
        Get existing preferences for user or create new defaults.

        Args:
            user_id: ID of the user

        Returns:
            NotificationPreference: User's preference object
        """
        pref = cls.query.filter_by(user_id=user_id).first()
        if not pref:
            pref = cls(user_id=user_id)
            db.session.add(pref)
            db.session.commit()
        return pref

    @classmethod
    def get_subscribers_for_category(cls, category: str) -> List[int]:
        """
        Get IDs of users subscribed to a specific category.

        Args:
            category: Category name

        Returns:
            List[int]: List of user IDs
        """
        # Try to get from cache first
        cache_key = f"subscribers_for_category:{category}"
        if hasattr(cache, 'get'):
            cached = cache.get(cache_key)
            if cached:
                try:
                    return json.loads(cached)
                except:
                    pass

        try:
            # Implement with a direct query for better performance in SQL
            if hasattr(db, 'session') and hasattr(db.session, 'execute'):
                # For PostgreSQL JSON querying
                try:
                    query = """
                    SELECT user_id FROM notification_preferences
                    WHERE subscribed_categories @> :category
                    """
                    result = db.session.execute(query, {"category": json.dumps([category])})
                    subscribers = [row[0] for row in result]

                    # Cache the result
                    if hasattr(cache, 'set'):
                        cache.set(cache_key, json.dumps(subscribers), timeout=300)

                    return subscribers
                except Exception:
                    # Fallback to Python filtering if SQL JSON query fails
                    pass

            # Python-based filtering fallback
            result = []
            prefs = cls.query.all()

            for pref in prefs:
                subscribed = pref.subscribed_categories or []
                if category in subscribed:
                    result.append(pref.user_id)

            # Cache the result
            if hasattr(cache, 'set'):
                cache.set(cache_key, json.dumps(result), timeout=300)

            return result
        except Exception as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error getting subscribers for category: {str(e)}")
            return []

    def _is_valid_time_format(self, time_str: str) -> bool:
        """
        Validate time string format (HH:MM in 24-hour format).

        Args:
            time_str: Time string to validate

        Returns:
            bool: True if valid, False otherwise
        """
        try:
            # Check format
            if len(time_str) != 5 or time_str[2] != ':':
                return False

            # Check hours and minutes
            hours, minutes = time_str.split(':')
            hours = int(hours)
            minutes = int(minutes)

            return 0 <= hours < 24 and 0 <= minutes < 60
        except Exception:
            return False

    def __repr__(self) -> str:
        """String representation of preferences."""
        return f'<NotificationPreference user_id={self.user_id}>'


class CommunicationPreference(UserPreference):
    """
    User communication preferences.

    This model stores user preferences for general communications,
    including marketing communications, newsletters, and system announcements.

    Attributes:
        id: Primary key (inherited from UserPreference)
        user_id: User ID this preference belongs to (inherited)
        marketing_enabled: Whether marketing emails are allowed
        newsletter_enabled: Whether newsletter emails are allowed
        announcement_enabled: Whether system announcement emails are allowed
        digest_frequency: Frequency of digest emails (daily, weekly, monthly, never)
        preferred_format: Preferred email format (html, text)
        language: Preferred language for communications
    """
    __tablename__ = 'communication_preferences'

    # Validation constants
    DIGEST_FREQUENCY_DAILY = 'daily'
    DIGEST_FREQUENCY_WEEKLY = 'weekly'
    DIGEST_FREQUENCY_MONTHLY = 'monthly'
    DIGEST_FREQUENCY_NEVER = 'never'

    VALID_DIGEST_FREQUENCIES = [
        DIGEST_FREQUENCY_DAILY,
        DIGEST_FREQUENCY_WEEKLY,
        DIGEST_FREQUENCY_MONTHLY,
        DIGEST_FREQUENCY_NEVER
    ]

    FORMAT_HTML = 'html'
    FORMAT_TEXT = 'text'

    VALID_FORMATS = [FORMAT_HTML, FORMAT_TEXT]

    # Communication preferences
    marketing_enabled = db.Column(db.Boolean, default=False)
    newsletter_enabled = db.Column(db.Boolean, default=True)
    announcement_enabled = db.Column(db.Boolean, default=True)
    digest_frequency = db.Column(db.String(10), default=DIGEST_FREQUENCY_WEEKLY)
    preferred_format = db.Column(db.String(10), default=FORMAT_HTML)
    language = db.Column(db.String(10), default='en')

    # Relationships
    user = relationship('User', backref=db.backref('communication_preference',
                                                  uselist=False,
                                                  cascade='all, delete-orphan'))

    def __init__(self, user_id: int, **kwargs):
        """
        Initialize communication preferences for a user.

        Args:
            user_id: ID of the user these preferences belong to
            **kwargs: Additional preference settings
        """
        super().__init__()
        self.user_id = user_id

        # Apply provided settings
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert communication preferences to dictionary.

        Returns:
            Dict: Dictionary representation of preferences
        """
        # Include base fields and extend with communication-specific fields
        base_dict = super().to_dict()
        comm_dict = {
            'marketing_enabled': self.marketing_enabled,
            'newsletter_enabled': self.newsletter_enabled,
            'announcement_enabled': self.announcement_enabled,
            'digest_frequency': self.digest_frequency,
            'preferred_format': self.preferred_format,
            'language': self.language
        }

        # Merge dictionaries
        return {**base_dict, **comm_dict}

    def _validate_json_field(self, field_name: str, value: Any) -> bool:
        """Nothing to validate for this preference type."""
        return True

    @classmethod
    def get_or_create(cls, user_id: int) -> 'CommunicationPreference':
        """
        Get existing preferences for user or create new defaults.

        Args:
            user_id: ID of the user

        Returns:
            CommunicationPreference: User's preference object
        """
        pref = cls.query.filter_by(user_id=user_id).first()
        if not pref:
            pref = cls(user_id=user_id)
            db.session.add(pref)
            db.session.commit()
        return pref

    def __repr__(self) -> str:
        """String representation of preferences."""
        return f'<CommunicationPreference user_id={self.user_id}>'


# Make classes available for import
__all__ = [
    'UserPreference',
    'NotificationPreference',
    'CommunicationPreference'
]
