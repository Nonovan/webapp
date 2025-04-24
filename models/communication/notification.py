"""
Notification model for the application.

This module provides the Notification model for storing and managing system notifications
to users. Notifications can be used for system alerts, user messages, and event notifications.
The model supports different notification types and priority levels.
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Union
from sqlalchemy import desc, and_, or_
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app

from extensions import db
from models import BaseModel


class Notification(BaseModel):
    """
    Notification model for storing user notifications.

    This class represents a notification sent to a specific user with
    configurable type, priority, and read status tracking.

    Attributes:
        id: Primary key
        user_id: ID of recipient user
        title: Notification title
        message: Notification message content
        notification_type: Type of notification (e.g., 'security_alert', 'info', etc.)
        priority: Priority level ('low', 'medium', 'high', 'critical')
        is_read: Whether the notification has been read by the user
        read_at: Timestamp when notification was read
        created_at: Timestamp when notification was created (from BaseModel)
        updated_at: Timestamp when notification was updated (from BaseModel)
    """

    __tablename__ = 'notifications'

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), nullable=False, default='info', index=True)
    priority = db.Column(db.String(20), nullable=False, default='medium', index=True)
    is_read = db.Column(db.Boolean, default=False, nullable=False, index=True)
    read_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Add metadata fields if not provided by BaseModel
    if not hasattr(BaseModel, 'created_at'):
        created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    if not hasattr(BaseModel, 'updated_at'):
        updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                               onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Additional fields for more advanced notifications
    action_url = db.Column(db.String(255), nullable=True)  # Optional URL for notification action
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)  # Optional expiration time
    data = db.Column(db.JSON, nullable=True)  # Additional structured data

    # Constants for notification types
    TYPE_INFO = 'info'
    TYPE_WARNING = 'warning'
    TYPE_SUCCESS = 'success'
    TYPE_ERROR = 'error'
    TYPE_SECURITY_ALERT = 'security_alert'
    TYPE_SYSTEM = 'system'

    # Constants for priority levels
    PRIORITY_LOW = 'low'
    PRIORITY_MEDIUM = 'medium'
    PRIORITY_HIGH = 'high'
    PRIORITY_CRITICAL = 'critical'

    # Valid notification types and priorities
    VALID_TYPES = [TYPE_INFO, TYPE_WARNING, TYPE_SUCCESS, TYPE_ERROR,
                  TYPE_SECURITY_ALERT, TYPE_SYSTEM]
    VALID_PRIORITIES = [PRIORITY_LOW, PRIORITY_MEDIUM, PRIORITY_HIGH, PRIORITY_CRITICAL]

    # Type title mappings
    TYPE_TITLES = {
        TYPE_SECURITY_ALERT: 'Security Alert',
        TYPE_SYSTEM: 'System Notification',
        TYPE_INFO: 'Information',
        TYPE_WARNING: 'Warning',
        TYPE_SUCCESS: 'Success',
        TYPE_ERROR: 'Error'
    }

    # Relationships
    user = db.relationship('User', backref=db.backref('notifications', lazy='dynamic', cascade='all, delete-orphan'))

    def __init__(self, user_id: int, message: str,
                notification_type: str = TYPE_INFO,
                priority: str = PRIORITY_MEDIUM,
                title: Optional[str] = None,
                action_url: Optional[str] = None,
                expires_at: Optional[datetime] = None,
                data: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize a new notification.

        Args:
            user_id: ID of the recipient user
            message: Notification message content
            notification_type: Type of notification
            priority: Priority level ('low', 'medium', 'high', 'critical')
            title: Notification title (optional, will be auto-generated if not provided)
            action_url: Optional URL for notification action
            expires_at: Optional expiration time
            data: Additional structured data for the notification
        """
        self.user_id = user_id
        self.message = message

        # Validate notification type
        if notification_type not in self.VALID_TYPES:
            if current_app and current_app.logger:
                current_app.logger.warning(f"Invalid notification type: {notification_type}. Using default.")
            notification_type = self.TYPE_INFO
        self.notification_type = notification_type

        # Validate priority
        if priority not in self.VALID_PRIORITIES:
            if current_app and current_app.logger:
                current_app.logger.warning(f"Invalid priority: {priority}. Using default.")
            priority = self.PRIORITY_MEDIUM
        self.priority = priority

        # Generate title from notification type if not provided
        if title:
            self.title = title
        else:
            self.title = self.TYPE_TITLES.get(notification_type, 'Notification')

        # Set additional fields
        self.action_url = action_url
        self.expires_at = expires_at
        self.data = data or {}

    def mark_as_read(self) -> bool:
        """
        Mark the notification as read with current timestamp.

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_read:
            try:
                self.is_read = True
                self.read_at = datetime.now(timezone.utc)
                db.session.add(self)
                db.session.commit()
                return True
            except SQLAlchemyError as e:
                if current_app and current_app.logger:
                    current_app.logger.error(f"Failed to mark notification as read: {str(e)}")
                db.session.rollback()
                return False
        return True

    def mark_as_unread(self) -> bool:
        """
        Mark the notification as unread.

        Returns:
            bool: True if successful, False otherwise
        """
        if self.is_read:
            try:
                self.is_read = False
                self.read_at = None
                db.session.add(self)
                db.session.commit()
                return True
            except SQLAlchemyError as e:
                if current_app and current_app.logger:
                    current_app.logger.error(f"Failed to mark notification as unread: {str(e)}")
                db.session.rollback()
                return False
        return True

    def is_expired(self) -> bool:
        """
        Check if the notification has expired.

        Returns:
            bool: True if expired, False otherwise
        """
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert notification to dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the notification
        """
        created_at = self.created_at
        if callable(self.created_at):
            created_at = self.created_at()

        result = {
            'id': self.id,
            'title': self.title,
            'message': self.message,
            'notification_type': self.notification_type,
            'priority': self.priority,
            'is_read': self.is_read,
            'read_at': self.read_at.isoformat() if self.read_at else None,
            'created_at': created_at.isoformat() if created_at else None,
        }

        # Add optional fields if they exist
        if self.action_url:
            result['action_url'] = self.action_url
        if self.expires_at:
            result['expires_at'] = self.expires_at.isoformat()
            result['is_expired'] = self.is_expired()
        if self.data:
            result['data'] = self.data

        return result

    @classmethod
    def get_unread_count(cls, user_id: int) -> int:
        """
        Get count of unread notifications for a user.

        Args:
            user_id: ID of the user

        Returns:
            int: Count of unread notifications
        """
        try:
            # Exclude expired notifications
            query = cls.query.filter(cls.user_id == user_id, cls.is_read == False)
            query = cls._exclude_expired(query)
            return query.count()
        except SQLAlchemyError as e:
            if current_app and current_app.logger:
                current_app.logger.error(f"Error counting unread notifications: {str(e)}")
            return 0

    @classmethod
    def get_unread(cls, user_id: int, limit: int = 10) -> List['Notification']:
        """
        Get unread notifications for a user.

        Args:
            user_id: ID of the user
            limit: Maximum number of notifications to return

        Returns:
            List[Notification]: List of unread notifications
        """
        try:
            query = cls.query.filter(cls.user_id == user_id, cls.is_read == False)
            query = cls._exclude_expired(query)
            return query.order_by(desc(cls.created_at)).limit(limit).all()
        except SQLAlchemyError as e:
            if current_app and current_app.logger:
                current_app.logger.error(f"Error retrieving unread notifications: {str(e)}")
            return []

    @classmethod
    def get_all_for_user(cls, user_id: int, page: int = 1, per_page: int = 20,
                       include_read: bool = True, types: Optional[List[str]] = None,
                       priorities: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Get paginated notifications for a user with filtering options.

        Args:
            user_id: ID of the user
            page: Page number (1-indexed)
            per_page: Number of items per page
            include_read: Whether to include read notifications
            types: Filter by notification types
            priorities: Filter by priorities

        Returns:
            Dict[str, Any]: Dictionary with notifications and pagination metadata
        """
        try:
            # Start with base query for user
            query = cls.query.filter(cls.user_id == user_id)

            # Apply filters
            if not include_read:
                query = query.filter(cls.is_read == False)

            if types:
                valid_types = [t for t in types if t in cls.VALID_TYPES]
                if valid_types:
                    query = query.filter(cls.notification_type.in_(valid_types))

            if priorities:
                valid_priorities = [p for p in priorities if p in cls.VALID_PRIORITIES]
                if valid_priorities:
                    query = query.filter(cls.priority.in_(valid_priorities))

            # Exclude expired notifications
            query = cls._exclude_expired(query)

            # Paginate results
            total = query.count()
            query = query.order_by(desc(cls.created_at))

            # Adjust page if needed
            if page < 1:
                page = 1

            # Get paginated results
            offset = (page - 1) * per_page
            notifications = query.offset(offset).limit(per_page).all()

            # Calculate pagination metadata
            total_pages = (total + per_page - 1) // per_page  # Ceiling division

            return {
                'notifications': notifications,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'total_pages': total_pages,
                    'has_next': page < total_pages,
                    'has_prev': page > 1
                }
            }
        except SQLAlchemyError as e:
            if current_app and current_app.logger:
                current_app.logger.error(f"Error retrieving notifications: {str(e)}")
            return {
                'notifications': [],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': 0,
                    'total_pages': 0,
                    'has_next': False,
                    'has_prev': False
                }
            }

    @classmethod
    def create_notification(cls, user_id: int, message: str, **kwargs) -> Optional['Notification']:
        """
        Create and save a new notification.

        This is a convenience method that creates a notification,
        adds it to the session, and commits it in one step.

        Args:
            user_id: ID of the recipient user
            message: Notification message
            **kwargs: Additional notification parameters

        Returns:
            Optional[Notification]: The created notification object or None if error
        """
        try:
            notification = cls(user_id=user_id, message=message, **kwargs)
            db.session.add(notification)
            db.session.commit()
            return notification
        except SQLAlchemyError as e:
            if current_app and current_app.logger:
                current_app.logger.error(f"Failed to create notification: {str(e)}")
            db.session.rollback()
            return None

    @classmethod
    def mark_all_as_read(cls, user_id: int, notification_type: Optional[str] = None) -> int:
        """
        Mark all notifications for a user as read.

        Args:
            user_id: ID of the user
            notification_type: Optional type to filter by

        Returns:
            int: Number of notifications marked as read
        """
        try:
            query = cls.query.filter(cls.user_id == user_id, cls.is_read == False)
            if notification_type:
                query = query.filter(cls.notification_type == notification_type)

            now = datetime.now(timezone.utc)
            count = query.update({
                'is_read': True,
                'read_at': now
            }, synchronize_session=False)

            db.session.commit()
            return count
        except SQLAlchemyError as e:
            if current_app and current_app.logger:
                current_app.logger.error(f"Error marking notifications as read: {str(e)}")
            db.session.rollback()
            return 0

    @classmethod
    def _exclude_expired(cls, query):
        """
        Helper method to exclude expired notifications from a query.

        Args:
            query: SQLAlchemy query object

        Returns:
            Modified query excluding expired notifications
        """
        now = datetime.now(timezone.utc)
        return query.filter(or_(
            cls.expires_at == None,  # No expiration
            cls.expires_at > now     # Not yet expired
        ))

    @classmethod
    def cleanup_expired(cls) -> int:
        """
        Delete expired notifications.

        Returns:
            int: Number of deleted notifications
        """
        try:
            now = datetime.now(timezone.utc)
            result = cls.query.filter(
                cls.expires_at.isnot(None),
                cls.expires_at < now
            ).delete(synchronize_session=False)

            db.session.commit()
            return result
        except SQLAlchemyError as e:
            if current_app and current_app.logger:
                current_app.logger.error(f"Error cleaning up expired notifications: {str(e)}")
            db.session.rollback()
            return 0

    def __repr__(self) -> str:
        """String representation of the notification."""
        return f'<Notification {self.id}: {self.title} ({self.priority})>'
