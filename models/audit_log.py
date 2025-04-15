"""
Audit log model for security monitoring and activity tracking.

This module defines the AuditLog model which records security-relevant events
throughout the application. It provides a centralized log of user actions,
system events, and security incidents for compliance, troubleshooting, and
security forensics purposes.

The audit log captures detailed information including:
- Who performed an action (user identification)
- What action was performed (event type and description)
- When the action occurred (timestamp)
- Where the action originated from (IP address, user agent)
- Additional context about the action (details)

This model is used extensively by the security monitoring system to detect
anomalies, track suspicious activities, and provide audit trails for
security investigations.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, ClassVar

from flask import current_app
from sqlalchemy import desc, or_
from sqlalchemy.exc import SQLAlchemyError

from extensions import db
from models.base import BaseModel


class AuditLog(BaseModel):
    """
    A model representing security-relevant events for auditing and monitoring.
    
    This model stores comprehensive information about system and user actions
    for security auditing, compliance reporting, and anomaly detection. Each
    record represents a discrete event that may be relevant for security
    monitoring or regulatory compliance.

    Attributes:
        id: Primary key ID for the log entry
        event_type: Type of event being logged (e.g., login_failed, api_access)
        user_id: ID of user who performed the action (if applicable)
        ip_address: Source IP address of the event
        user_agent: User agent string from the request
        details: Additional context or details about the event
        severity: Importance level of the event (info, warning, error, critical)
        created_at: When the event occurred (inherited from BaseModel)
        updated_at: When the log entry was last updated (inherited from BaseModel)
    """

    __tablename__ = 'audit_logs'

    # Define severity levels as class variables for consistency
    SEVERITY_INFO: ClassVar[str] = 'info'
    SEVERITY_WARNING: ClassVar[str] = 'warning'
    SEVERITY_ERROR: ClassVar[str] = 'error'
    SEVERITY_CRITICAL: ClassVar[str] = 'critical'

    # Event types as class variables
    EVENT_LOGIN_SUCCESS: ClassVar[str] = 'login_success'
    EVENT_LOGIN_FAILED: ClassVar[str] = 'login_failed'
    EVENT_ACCOUNT_LOCKOUT: ClassVar[str] = 'account_lockout'
    EVENT_PASSWORD_RESET: ClassVar[str] = 'password_reset'
    EVENT_PERMISSION_DENIED: ClassVar[str] = 'permission_denied'
    EVENT_API_ACCESS: ClassVar[str] = 'api_access'
    EVENT_FILE_ACCESS: ClassVar[str] = 'file_access'
    EVENT_FILE_MODIFIED: ClassVar[str] = 'file_modified'
    EVENT_DATABASE_ACCESS: ClassVar[str] = 'database_access'
    EVENT_SESSION_START: ClassVar[str] = 'session_start'
    EVENT_SESSION_END: ClassVar[str] = 'session_end'
    EVENT_SECURITY_BREACH_ATTEMPT: ClassVar[str] = 'security_breach_attempt'
    EVENT_SECURITY_COUNTERMEASURE: ClassVar[str] = 'security_countermeasure'

    # Column definitions
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    ip_address = db.Column(db.String(45), nullable=True, index=True)
    user_agent = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), default='info', index=True)

    # Define relationship to User model
    user = db.relationship('User', backref=db.backref('audit_logs', lazy='dynamic'))

    def __init__(self, event_type: str, user_id: Optional[int] = None,
                ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                details: Optional[str] = None, severity: str = 'info'):
        """
        Initialize a new AuditLog entry.

        Args:
            event_type: Type of event being logged (e.g., login_failed, api_access)
            user_id: ID of user who performed the action (if applicable)
            ip_address: Source IP address of the event
            user_agent: User agent string from the request
            details: Additional context or details about the event
            severity: Importance level of the event (info, warning, error, critical)
        """
        self.event_type = event_type
        self.user_id = user_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.details = details
        self.severity = severity

    @classmethod
    def create(cls, event_type: str, description: str, user_id: Optional[int] = None, 
              ip_address: Optional[str] = None, user_agent: Optional[str] = None,
              severity: str = 'info') -> 'AuditLog':
        """
        Create a new audit log entry and save it to the database.

        This class method provides a convenient way to create and save an audit
        log entry in a single operation, with proper error handling.

        Args:
            event_type: Type of event being logged (e.g., login_failed, api_access)
            description: Description of the event (stored in details)
            user_id: ID of user who performed the action (if applicable)
            ip_address: Source IP address of the event
            user_agent: User agent string from the request
            severity: Importance level of the event (info, warning, error, critical)
            
        Returns:
            AuditLog: The created audit log entry

        Example:
            AuditLog.create(
                'login_failed', 
                'Failed login attempt for user bob',
                user_id=None,
                ip_address='192.168.1.1',
                severity='warning'
            )
        """
        log = cls(
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=description,
            severity=severity
        )
        
        try:
            db.session.add(log)
            db.session.commit()
            current_app.logger.debug(f"Audit log created: {event_type}")
            return log
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating audit log: {str(e)}")
            # Still return the log object even if it couldn't be saved
            return log

    @classmethod
    def get_by_ip(cls, ip_address: str, limit: int = 100) -> List['AuditLog']:
        """
        Get audit logs for a specific IP address.
        
        Args:
            ip_address: IP address to filter by
            limit: Maximum number of logs to return
            
        Returns:
            List[AuditLog]: List of audit logs from the IP address
        """
        return cls.query.filter_by(ip_address=ip_address).order_by(
            desc(cls.created_at)
        ).limit(limit).all()

    @classmethod
    def get_by_user(cls, user_id: int, limit: int = 100) -> List['AuditLog']:
        """
        Get audit logs for a specific user.
        
        Args:
            user_id: User ID to filter by
            limit: Maximum number of logs to return
            
        Returns:
            List[AuditLog]: List of audit logs for the user
        """
        return cls.query.filter_by(user_id=user_id).order_by(
            desc(cls.created_at)
        ).limit(limit).all()

    @classmethod
    def get_security_events(cls, hours: int = 24, limit: int = 100) -> List['AuditLog']:
        """
        Get security-related events from the past specified hours.
        
        Args:
            hours: Number of hours to look back
            limit: Maximum number of logs to return
            
        Returns:
            List[AuditLog]: List of security-related audit logs
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        security_events = [
            cls.EVENT_LOGIN_FAILED, cls.EVENT_ACCOUNT_LOCKOUT,
            cls.EVENT_PERMISSION_DENIED, cls.EVENT_SECURITY_BREACH_ATTEMPT,
            cls.EVENT_SECURITY_COUNTERMEASURE
        ]
        
        return cls.query.filter(
            cls.__table__.c.event_type.in_(security_events),
            cls.__table__.c.created_at >= cutoff,
            or_(cls.severity == cls.SEVERITY_WARNING, 
                cls.severity == cls.SEVERITY_ERROR,
                cls.severity == cls.SEVERITY_CRITICAL)
        ).order_by(desc(cls.created_at)).limit(limit).all()

    @classmethod
    def count_by_event_type(cls, event_type: str, hours: int = 24) -> int:
        """
        Count occurrences of a specific event type in the past specified hours.
        
        Args:
            event_type: Event type to count
            hours: Number of hours to look back
            
        Returns:
            int: Count of matching audit logs
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return cls.query.filter(
            cls.event_type == event_type,
            cls.__table__.c.created_at >= cutoff
        ).count()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the audit log entry to a dictionary.

        Extends the base to_dict method with additional formatted data.

        Returns:
            Dict[str, Any]: Dictionary representation of the audit log entry
        """
        data = super().to_dict()
        
        # Add formatted timestamp for display purposes
        if isinstance(self.created_at, datetime):
            data['created_at_formatted'] = self.created_at.strftime('%Y-%m-%d %H:%M:%S')
            
        # Add username if available and not already included by the base method
        if self.user and 'username' not in data.get('user', {}):
            data['username'] = self.user.username
            
        return data

    def __repr__(self) -> str:
        """String representation of the audit log entry."""
        return (f"<AuditLog(id={self.id}, event_type='{self.event_type}', "
                f"user_id={self.user_id}, severity='{self.severity}')>")