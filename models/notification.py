"""
Notification model for the application.

This module provides the Notification model for storing and managing system notifications
to users. Notifications can be used for system alerts, user messages, and event notifications.
The model supports different notification types and priority levels.
"""

from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import desc

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
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), nullable=False, default='info')  
    priority = db.Column(db.String(20), nullable=False, default='medium')
    is_read = db.Column(db.Boolean, default=False)
    read_at = db.Column(db.DateTime(timezone=True), nullable=True)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('notifications', lazy='dynamic'))
    
    def __init__(self, user_id: int, message: str, 
                notification_type: str = 'info', 
                priority: str = 'medium',
                title: Optional[str] = None):
        """
        Initialize a new notification.
        
        Args:
            user_id: ID of the recipient user
            message: Notification message content
            notification_type: Type of notification
            priority: Priority level ('low', 'medium', 'high', 'critical')
            title: Notification title (optional, will be auto-generated if not provided)
        """
        self.user_id = user_id
        self.message = message
        self.notification_type = notification_type
        self.priority = priority
        
        # Generate title from notification type if not provided
        if title:
            self.title = title
        else:
            # Generate title based on notification type
            type_titles = {
                'security_alert': 'Security Alert',
                'system': 'System Notification',
                'info': 'Information',
                'warning': 'Warning',
                'success': 'Success'
            }
            self.title = type_titles.get(notification_type, 'Notification')
    
    def mark_as_read(self) -> None:
        """Mark the notification as read with current timestamp."""
        if not self.is_read:
            self.is_read = True
            self.read_at = datetime.utcnow()
            db.session.commit()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert notification to dictionary.
        
        Returns:
            Dictionary representation of the notification
        """
        return {
            'id': self.id,
            'title': self.title,
            'message': self.message,
            'notification_type': self.notification_type,
            'priority': self.priority,
            'is_read': self.is_read,
            'read_at': self.read_at.isoformat() if self.read_at else None,
            'created_at': self.created_at().isoformat() if callable(self.created_at) else self.created_at.isoformat(),
        }
    
    @classmethod
    def get_unread_count(cls, user_id: int) -> int:
        """
        Get count of unread notifications for a user.
        
        Args:
            user_id: ID of the user
            
        Returns:
            Count of unread notifications
        """
        return cls.query.filter_by(user_id=user_id, is_read=False).count()
    
    @classmethod
    def get_unread(cls, user_id: int, limit: int = 10) -> list:
        """
        Get unread notifications for a user.
        
        Args:
            user_id: ID of the user
            limit: Maximum number of notifications to return
            
        Returns:
            List of unread notifications
        """
        return cls.query.filter_by(user_id=user_id, is_read=False)\
                    .order_by(desc(cls.created_at))\
                    .limit(limit).all()

    @classmethod
    def create_notification(cls, user_id: int, message: str, **kwargs) -> 'Notification':
        """
        Create and save a new notification.
        
        This is a convenience method that creates a notification,
        adds it to the session, and commits it in one step.
        
        Args:
            user_id: ID of the recipient user
            message: Notification message
            **kwargs: Additional notification parameters
            
        Returns:
            The created notification object
        """
        notification = cls(user_id=user_id, message=message, **kwargs)
        db.session.add(notification)
        db.session.commit()
        return notification

    def __repr__(self) -> str:
        """String representation of the notification."""
        return f'<Notification {self.id}: {self.title} ({self.priority})>'