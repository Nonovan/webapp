"""
User activity model for tracking user actions and system interactions.

This module provides a model for detailed tracking of user activities across
the application, supporting security auditing, user behavior analytics,
and compliance reporting for cloud infrastructure management.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List, Union, Tuple
from flask import current_app, g, request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func, desc, text

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
    - logout: User logout
    - resource_access: User accessing a protected resource
    - configuration_change: User modifying system settings
    - api_access: API endpoint usage
    - infrastructure_operation: Cloud resource creation/modification/deletion
    - security_event: Security-related actions
    - ics_control: Industrial Control System interactions
    """

    __tablename__ = 'user_activities'

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'),
                      nullable=True, index=True)
    session_id = db.Column(db.String(64), db.ForeignKey('user_sessions.session_id', ondelete='CASCADE'),
                         nullable=True, index=True)
    activity_type = db.Column(db.String(32), nullable=False, index=True)

    # Activity details
    resource_type = db.Column(db.String(32), nullable=True, index=True)
    resource_id = db.Column(db.String(64), nullable=True, index=True)
    action = db.Column(db.String(32), nullable=True)
    status = db.Column(db.String(16), default='success', nullable=False)

    # Request details
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 can be up to 45 chars
    user_agent = db.Column(db.String(255), nullable=True)
    path = db.Column(db.String(255), nullable=True)
    method = db.Column(db.String(16), nullable=True)

    # Contextual data
    data = db.Column(db.JSON, nullable=True)
    geo_location = db.Column(db.String(128), nullable=True)
    cloud_region = db.Column(db.String(32), nullable=True)
    device_type = db.Column(db.String(32), nullable=True)

    # Timestamps with timezone awareness
    created_at = db.Column(db.DateTime(timezone=True),
                        default=lambda: datetime.now(timezone.utc),
                        nullable=False, index=True)
    duration_ms = db.Column(db.Integer, nullable=True)  # Duration of activity in milliseconds

    # Define relationships
    user = db.relationship('User', backref=db.backref('activities', lazy='dynamic', cascade='all, delete-orphan'))
    session = db.relationship('UserSession', backref=db.backref('activities', lazy='dynamic'))

    # Constants for activity types
    ACTIVITY_LOGIN = 'login'
    ACTIVITY_LOGOUT = 'logout'
    ACTIVITY_RESOURCE_ACCESS = 'resource_access'
    ACTIVITY_CONFIG_CHANGE = 'configuration_change'
    ACTIVITY_API_ACCESS = 'api_access'
    ACTIVITY_INFRA_OPERATION = 'infrastructure_operation'
    ACTIVITY_SECURITY_EVENT = 'security_event'
    ACTIVITY_ICS_CONTROL = 'ics_control'

    # Constants for status values
    STATUS_SUCCESS = 'success'
    STATUS_FAILURE = 'failure'
    STATUS_ERROR = 'error'
    STATUS_WARNING = 'warning'
    STATUS_UNAUTHORIZED = 'unauthorized'

    # Valid activity types and statuses
    VALID_ACTIVITY_TYPES = [
        ACTIVITY_LOGIN, ACTIVITY_LOGOUT, ACTIVITY_RESOURCE_ACCESS,
        ACTIVITY_CONFIG_CHANGE, ACTIVITY_API_ACCESS, ACTIVITY_INFRA_OPERATION,
        ACTIVITY_SECURITY_EVENT, ACTIVITY_ICS_CONTROL
    ]

    VALID_STATUSES = [
        STATUS_SUCCESS, STATUS_FAILURE, STATUS_ERROR,
        STATUS_WARNING, STATUS_UNAUTHORIZED
    ]

    def __init__(self, user_id: Optional[int] = None, activity_type: Optional[str] = None, **kwargs: Any) -> None:
        """
        Initialize a UserActivity instance.

        Args:
            user_id: ID of the user performing the activity (optional if from system)
            activity_type: Type of activity being performed
            **kwargs: Additional attributes to set
        """
        self.user_id = user_id

        # Validate activity type
        if activity_type and activity_type not in self.VALID_ACTIVITY_TYPES:
            if current_app:
                current_app.logger.warning(f"Invalid activity type: {activity_type}. Using {self.ACTIVITY_RESOURCE_ACCESS} instead.")
            activity_type = self.ACTIVITY_RESOURCE_ACCESS
        self.activity_type = activity_type

        # Set attributes from kwargs
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

        # Validate status value if provided
        if hasattr(self, 'status') and self.status and self.status not in self.VALID_STATUSES:
            if current_app:
                current_app.logger.warning(f"Invalid status: {self.status}. Using {self.STATUS_SUCCESS} instead.")
            self.status = self.STATUS_SUCCESS

        # Get session_id from global context if available and not already set
        if hasattr(g, 'session_id') and not self.session_id and g.get('session_id'):
            self.session_id = g.session_id

        # Get request info if available and not already set
        if request and not self.path:
            self.path = request.path[:255] if request.path else None
            self.method = request.method[:16] if request.method else None
            self.ip_address = request.remote_addr[:45] if request.remote_addr else None
            self.user_agent = request.user_agent.string[:255] if request.user_agent.string else None

        # Default created_at if not provided
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc)

    def __repr__(self) -> str:
        """Return a string representation of the UserActivity instance."""
        return f"<UserActivity id={self.id} user_id={self.user_id} type={self.activity_type} resource={self.resource_type}:{self.resource_id}>"

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert activity to dictionary for API responses and logging.

        Returns:
            Dict[str, Any]: Dictionary representation of the activity
        """
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
            'geo_location': self.geo_location,
            'device_type': self.device_type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'duration_ms': self.duration_ms,
            # Only include non-sensitive data
            'data': self.filter_sensitive_data(self.data) if self.data else None
        }

    @staticmethod
    def filter_sensitive_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Filter out sensitive information from data dictionary.

        Args:
            data: Dictionary containing activity data

        Returns:
            Dict[str, Any]: Filtered data dictionary
        """
        if not data or not isinstance(data, dict):
            return {}

        # Create a copy to avoid modifying the original
        filtered = data.copy()

        # List of sensitive keys to remove
        sensitive_keys = [
            'password', 'token', 'secret', 'key', 'auth',
            'credential', 'apikey', 'api_key', 'access_key',
            'private_key'
        ]

        # Remove or mask sensitive information
        for key in list(filtered.keys()):
            lower_key = key.lower()
            if any(sensitive in lower_key for sensitive in sensitive_keys):
                filtered[key] = '******'
            elif isinstance(filtered[key], dict):
                # Recursively filter nested dictionaries
                filtered[key] = UserActivity.filter_sensitive_data(filtered[key])

        return filtered

    @classmethod
    def log_activity(cls, activity_type: str, user_id: Optional[int] = None,
                    resource_type: Optional[str] = None, resource_id: Optional[str] = None,
                    action: Optional[str] = None, status: str = 'success',
                    data: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Optional['UserActivity']:
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
            Optional[UserActivity]: The created UserActivity instance or None if creation failed
        """
        try:
            # Get current user from context if not provided
            if user_id is None and hasattr(g, 'user_id'):
                user_id = g.get('user_id')

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

            # Record metrics if available
            try:
                metrics.counter(
                    'user_activity_total',
                    1,
                    labels={
                        'activity_type': activity_type,
                        'resource_type': resource_type or 'none',
                        'status': status
                    }
                )
            except Exception as e:
                # Don't fail the activity logging if metrics fail
                if current_app:
                    current_app.logger.warning(f"Failed to record activity metrics: {str(e)}")

            # Save to database
            db.session.add(activity)
            db.session.commit()

            return activity

        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Failed to log user activity: {str(e)}")
            return None
        except Exception as e:
            # Catch-all for any other errors
            if current_app:
                current_app.logger.error(f"Unexpected error logging user activity: {str(e)}")
            return None

    @classmethod
    def get_recent_activities(cls, user_id: Optional[int] = None,
                             activity_type: Optional[str] = None,
                             resource_type: Optional[str] = None,
                             status: Optional[str] = None,
                             limit: int = 100) -> List['UserActivity']:
        """
        Retrieve recent user activities with optional filtering.

        Args:
            user_id: Filter by specific user ID
            activity_type: Filter by activity type
            resource_type: Filter by resource type
            status: Filter by status
            limit: Maximum number of activities to return

        Returns:
            List[UserActivity]: List of UserActivity objects
        """
        try:
            query = cls.query.order_by(desc(cls.created_at))

            if user_id is not None:
                query = query.filter(cls.user_id == user_id)

            if activity_type is not None:
                query = query.filter(cls.activity_type == activity_type)

            if resource_type is not None:
                query = query.filter(cls.resource_type == resource_type)

            if status is not None:
                query = query.filter(cls.status == status)

            # Ensure limit is reasonable
            if limit <= 0 or limit > 1000:
                limit = 100

            return query.limit(limit).all()
        except SQLAlchemyError as e:
            if current_app:
                current_app.logger.error(f"Error retrieving recent activities: {str(e)}")
            return []

    @classmethod
    def get_user_activity_summary(cls, user_id: int, days: int = 30) -> Dict[str, int]:
        """
        Get summary of user activity by type for a specific period.

        Args:
            user_id: User ID to get summary for
            days: Number of days to look back

        Returns:
            Dict[str, int]: Dictionary with activity types and counts
        """
        try:
            # Validate days parameter
            if days <= 0 or days > 365:
                days = 30

            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

            result = db.session.query(
                cls.activity_type,
                func.count(cls.id).label('count')
            ).filter(
                cls.user_id == user_id,
                cls.created_at >= cutoff_date
            ).group_by(cls.activity_type).all()

            return {activity_type: count for activity_type, count in result}

        except SQLAlchemyError as e:
            if current_app:
                current_app.logger.error(f"Error getting activity summary for user {user_id}: {str(e)}")
            return {}

    @classmethod
    def get_resource_access_history(cls, resource_type: str, resource_id: str,
                                  limit: int = 50,
                                  include_users: bool = False) -> List[Union['UserActivity', Dict[str, Any]]]:
        """
        Get history of access to a specific resource.

        Args:
            resource_type: Type of resource (e.g., 'instance', 'storage', 'config')
            resource_id: Identifier for the specific resource
            limit: Maximum number of records to return
            include_users: If True, include user information in the result

        Returns:
            List[Union[UserActivity, Dict[str, Any]]]: List of activity records for the resource
        """
        try:
            # Ensure limit is reasonable
            if limit <= 0 or limit > 1000:
                limit = 50

            if include_users:
                # Join with users table to include user information
                query = db.session.query(cls, db.models.User).outerjoin(
                    db.models.User, cls.user_id == db.models.User.id
                ).filter(
                    cls.resource_type == resource_type,
                    cls.resource_id == resource_id
                ).order_by(desc(cls.created_at)).limit(limit)

                result = []
                for activity, user in query.all():
                    activity_dict = activity.to_dict()
                    if user:
                        activity_dict['user'] = {
                            'id': user.id,
                            'username': user.username,
                            'email': user.email,
                            'full_name': getattr(user, 'full_name', user.username)
                        }
                    else:
                        activity_dict['user'] = None
                    result.append(activity_dict)

                return result
            else:
                # Just return activity records without user details
                return cls.query.filter(
                    cls.resource_type == resource_type,
                    cls.resource_id == resource_id
                ).order_by(desc(cls.created_at)).limit(limit).all()

        except SQLAlchemyError as e:
            if current_app:
                current_app.logger.error(
                    f"Error retrieving access history for {resource_type}:{resource_id}: {str(e)}"
                )
            return []

    @classmethod
    def get_activity_trend(cls, days: int = 30, interval: str = 'day') -> List[Dict[str, Any]]:
        """
        Get activity trend data for charts and analytics.

        Args:
            days: Number of days to include in the trend
            interval: Time interval for grouping ('hour', 'day', 'week', 'month')

        Returns:
            List[Dict[str, Any]]: List of data points with date and count
        """
        try:
            # Validate parameters
            if days <= 0 or days > 366:
                days = 30

            valid_intervals = ['hour', 'day', 'week', 'month']
            if interval not in valid_intervals:
                interval = 'day'

            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

            # Define date trunc function based on dialect
            if db.engine.dialect.name == 'postgresql':
                # PostgreSQL syntax
                date_trunc = func.date_trunc(interval, cls.created_at).label('time_period')
            elif db.engine.dialect.name == 'mysql':
                # MySQL syntax
                if interval == 'hour':
                    date_format = '%Y-%m-%d %H:00:00'
                elif interval == 'day':
                    date_format = '%Y-%m-%d'
                elif interval == 'week':
                    date_format = '%Y-%U'
                else:  # month
                    date_format = '%Y-%m'
                date_trunc = func.date_format(cls.created_at, date_format).label('time_period')
            else:
                # SQLite syntax (fallback)
                if interval == 'hour':
                    date_trunc = func.strftime('%Y-%m-%d %H:00:00', cls.created_at).label('time_period')
                elif interval == 'day':
                    date_trunc = func.strftime('%Y-%m-%d', cls.created_at).label('time_period')
                elif interval == 'week':
                    date_trunc = func.strftime('%Y-%W', cls.created_at).label('time_period')
                else:  # month
                    date_trunc = func.strftime('%Y-%m', cls.created_at).label('time_period')

            # Query for trend data
            result = db.session.query(
                date_trunc,
                func.count(cls.id).label('count'),
                func.count(func.distinct(cls.user_id)).label('user_count')
            ).filter(
                cls.created_at >= cutoff_date
            ).group_by(date_trunc).order_by(date_trunc).all()

            # Format the result
            trend_data = []
            for period, count, user_count in result:
                if isinstance(period, str):
                    # Already formatted by database
                    time_str = period
                else:
                    # Format datetime object
                    time_str = period.strftime('%Y-%m-%d %H:%M:%S')

                trend_data.append({
                    'period': time_str,
                    'count': count,
                    'user_count': user_count
                })

            return trend_data

        except SQLAlchemyError as e:
            if current_app:
                current_app.logger.error(f"Error generating activity trend: {str(e)}")
            return []

    @classmethod
    def cleanup_old_activities(cls, days_to_keep: int = 90) -> Tuple[bool, int]:
        """
        Clean up old activity logs to manage database size.

        Args:
            days_to_keep: Number of days of activity logs to retain

        Returns:
            Tuple[bool, int]: Success status and number of records deleted
        """
        try:
            if days_to_keep <= 0:
                days_to_keep = 90

            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_to_keep)

            # Use efficient bulk deletion
            count = cls.query.filter(cls.created_at < cutoff_date).delete()
            db.session.commit()

            if current_app:
                current_app.logger.info(f"Cleaned up {count} activity records older than {days_to_keep} days")

            return True, count

        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Error cleaning up old activity logs: {str(e)}")
            return False, 0
