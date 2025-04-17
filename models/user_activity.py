"""
User activity model for tracking user actions and system interactions.

This module provides a model for detailed tracking of user activities across 
the application, supporting security auditing, user behavior analytics, 
and compliance reporting for cloud infrastructure management.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from flask import current_app, g
from sqlalchemy.exc import SQLAlchemyError

from extensions import db, metrics
from models.base import BaseModel

class UserActivity(BaseModel):
    """
    Model representing user activity in the cloud infrastructure platform.
    
    Tracks detailed information about user interactions with the system including
    the type of activity, affected resources, contextual data, and geographic information
    to support security monitoring, user behavior analysis, and compliance reporting.
    
    Activity types include:
    - login: User authentication
    - resource_access: User accessing a protected resource
    - configuration_change: User modifying system settings
    - api_access: API endpoint usage
    - infrastructure_operation: Cloud resource creation/modification/deletion
    - security_event: Security-related actions
    - ics_control: Industrial Control System interactions
    """

    __tablename__ = 'user_activities'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    session_id = db.Column(db.String(64), db.ForeignKey('user_sessions.session_id', ondelete='CASCADE'), nullable=True, index=True)
    activity_type = db.Column(db.String(32), nullable=False, index=True)

    # Activity details
    resource_type = db.Column(db.String(32), nullable=True, index=True)
    resource_id = db.Column(db.String(64), nullable=True, index=True)
    action = db.Column(db.String(32), nullable=True)
    status = db.Column(db.String(16), default='success', nullable=False)

    # Request details
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    path = db.Column(db.String(255), nullable=True)
    method = db.Column(db.String(16), nullable=True)

    # Contextual data
    data = db.Column(db.JSON, nullable=True)
    geo_location = db.Column(db.String(128), nullable=True)
    cloud_region = db.Column(db.String(32), nullable=True)
    device_type = db.Column(db.String(32), nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    duration_ms = db.Column(db.Integer, nullable=True)  # Duration of activity in milliseconds

    # Define relationships
    user = db.relationship('User', backref=db.backref('activities', lazy='dynamic'))
    session = db.relationship('UserSession', backref=db.backref('activities', lazy='dynamic'))

    def __init__(self, user_id: Optional[int] = None, activity_type: Optional[str] = None, **kwargs):
        """
        Initialize a UserActivity instance.

        Args:
            user_id: ID of the user performing the activity (optional if from system)
            activity_type: Type of activity being performed
            **kwargs: Additional attributes to set
        """
        self.user_id = user_id
        self.activity_type = activity_type

        # Set attributes from kwargs
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

        # Get session_id from global context if available
        if hasattr(g, 'session_id') and not self.session_id:
            self.session_id = g.session_id

        # Default created_at if not provided
        if not self.created_at:
            self.created_at = datetime.utcnow()

    def __repr__(self):
        """Return a string representation of the UserActivity instance."""
        return f"UserActivity(id={self.id}, user_id={self.user_id}, type={self.activity_type}, resource={self.resource_type}:{self.resource_id})"

    def to_dict(self) -> Dict[str, Any]:
        """Convert activity to dictionary for API responses and logging."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'activity_type': self.activity_type,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'action': self.action,
            'status': self.status,
            'ip_address': self.ip_address,
            'path': self.path,
            'method': self.method,
            'cloud_region': self.cloud_region,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'duration_ms': self.duration_ms,
        }

    @classmethod
    def log_activity(cls, activity_type: str, user_id: Optional[int] = None, 
                    resource_type: Optional[str] = None, resource_id: Optional[str] = None,
                    action: Optional[str] = None, status: str = 'success',
                    data: Optional[Dict[str, Any]] = None, **kwargs) -> Optional['UserActivity']:
        """
        Create and save a new user activity record.
        
        Args:
            activity_type: Type of activity (login, resource_access, etc.)
            user_id: ID of the user performing the action
            resource_type: Type of resource affected (user, instance, config, etc.)
            resource_id: ID of the specific resource
            action: Action performed (create, read, update, delete)
            status: Outcome status (success, failure, error)
            data: Additional contextual data
            **kwargs: Additional attributes to set
            
        Returns:
            The created UserActivity instance or None if creation failed
        """
        try:
            # Get current user from context if not provided
            if user_id is None and hasattr(g, 'user_id'):
                user_id = g.user_id

            # Create activity instance
            activity = cls(
                user_id=user_id,
                activity_type=activity_type,
                resource_type=resource_type,
                resource_id=resource_id,
                action=action,
                status=status,
                data=data,
                **kwargs
            )

            # Record metrics
            metrics.counter(
                'user_activity_total',
                1,
                labels={
                    'activity_type': activity_type,
                    'resource_type': resource_type or 'none',
                    'status': status
                }
            )

            # Save to database
            db.session.add(activity)
            db.session.commit()

            return activity

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to log user activity: {str(e)}")
            return None

    @classmethod
    def get_recent_activities(cls, user_id: Optional[int] = None, 
                             activity_type: Optional[str] = None,
                             limit: int = 100) -> List['UserActivity']:
        """
        Retrieve recent user activities with optional filtering.
        
        Args:
            user_id: Filter by specific user ID
            activity_type: Filter by activity type
            limit: Maximum number of activities to return
            
        Returns:
            List of UserActivity objects
        """
        query = cls.query.order_by(db.desc(cls.created_at))

        if user_id is not None:
            query = query.filter(cls.user_id == user_id)

        if activity_type is not None:
            query = query.filter(cls.activity_type == activity_type)

        return query.limit(limit).all()

    @classmethod
    def get_user_activity_summary(cls, user_id: int, days: int = 30) -> Dict[str, int]:
        """
        Get summary of user activity by type for a specific period.
        
        Args:
            user_id: User ID to get summary for
            days: Number of days to look back
            
        Returns:
            Dictionary with activity types and counts
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)

        result = db.session.query(
            cls.activity_type, 
            db.func.count(cls.id)
        ).filter(
            cls.user_id == user_id,
            cls.created_at >= cutoff_date
        ).group_by(cls.activity_type).all()

        return {activity_type: count for activity_type, count in result}

    @classmethod
    def get_resource_access_history(cls, resource_type: str, resource_id: str, limit: int = 50) -> List['UserActivity']:
        """
        Get history of access to a specific resource.
        
        Args:
            resource_type: Type of resource (e.g., 'instance', 'storage', 'config')
            resource_id: Identifier for the specific resource
            limit: Maximum number of records to return
            
        Returns:
            List of activity records for the resource
        """
        return cls.query.filter(
            cls.resource_type == resource_type,
            cls.resource_id == resource_id
        ).order_by(db.desc(cls.created_at)).limit(limit).all()
