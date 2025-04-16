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
- Additional context about the action (description)

This model is used extensively by the security monitoring system to detect
anomalies, track suspicious activities, and provide audit trails for
security investigations.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple, ClassVar

from flask import current_app
from sqlalchemy import desc, func
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
        description: Text description of the event
        details: Additional context or details about the event (JSON or text)
        severity: Importance level of the event (info, warning, error, critical)
        created_at: When the event occurred (inherited from BaseModel)
        updated_at: When the log entry was last updated (inherited from BaseModel)
    """
    
    __tablename__ = 'audit_logs'
    
    # Event type constants
    EVENT_LOGIN_SUCCESS: ClassVar[str] = 'login_success'
    EVENT_LOGIN_FAILED: ClassVar[str] = 'login_failed'
    EVENT_LOGOUT: ClassVar[str] = 'logout'
    EVENT_ACCOUNT_CREATED: ClassVar[str] = 'account_created'
    EVENT_ACCOUNT_MODIFIED: ClassVar[str] = 'account_modified'
    EVENT_ACCOUNT_LOCKOUT: ClassVar[str] = 'account_lockout'
    EVENT_PASSWORD_RESET: ClassVar[str] = 'password_reset'
    EVENT_PASSWORD_CHANGED: ClassVar[str] = 'password_changed'
    EVENT_PERMISSION_DENIED: ClassVar[str] = 'permission_denied'
    EVENT_API_ACCESS: ClassVar[str] = 'api_access'
    EVENT_ADMIN_ACTION: ClassVar[str] = 'admin_action'
    EVENT_FILE_UPLOAD: ClassVar[str] = 'file_upload'
    EVENT_FILE_DOWNLOAD: ClassVar[str] = 'file_download'
    EVENT_FILE_INTEGRITY: ClassVar[str] = 'file_integrity'
    EVENT_CONFIG_CHANGE: ClassVar[str] = 'config_change'
    EVENT_SECURITY_BREACH_ATTEMPT: ClassVar[str] = 'security_breach_attempt'
    EVENT_SECURITY_COUNTERMEASURE: ClassVar[str] = 'security_countermeasure'
    EVENT_DATABASE_ACCESS: ClassVar[str] = 'database_access'
    EVENT_RATE_LIMIT_EXCEEDED: ClassVar[str] = 'rate_limit_exceeded'
    EVENT_API_ABUSE: ClassVar[str] = 'api_abuse'
    
    # Severity constants
    SEVERITY_INFO: ClassVar[str] = 'info'
    SEVERITY_WARNING: ClassVar[str] = 'warning'
    SEVERITY_ERROR: ClassVar[str] = 'error'
    SEVERITY_CRITICAL: ClassVar[str] = 'critical'
    
    # Column definitions
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    ip_address = db.Column(db.String(45), nullable=True, index=True)  # IPv6 can be up to 45 chars
    user_agent = db.Column(db.String(255), nullable=True)
    description = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), nullable=False, default='info', index=True)
    
    def __init__(self, event_type: str, description: str, user_id: Optional[int] = None, 
                ip_address: Optional[str] = None, user_agent: Optional[str] = None, 
                details: Optional[str] = None, severity: str = 'info', 
                created_at: Optional[datetime] = None):
        """
        Initialize a new AuditLog entry.
        
        Args:
            event_type: Type of event (use EVENT_* constants)
            description: Human-readable description of the event
            user_id: ID of user associated with the event (if applicable)
            ip_address: Source IP address for the event
            user_agent: User agent string from the request
            details: Additional context information (may be JSON or text)
            severity: Event importance (info, warning, error, critical)
            created_at: Override the event timestamp (defaults to now)
        """
        self.event_type = event_type
        self.description = description
        self.user_id = user_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.details = details
        self.severity = severity
        
        if created_at:
            if created_at:
                super().__init__(created_at=created_at)
    
    @classmethod
    def create(cls, event_type: str, description: str, user_id: Optional[int] = None, 
              ip_address: Optional[str] = None, user_agent: Optional[str] = None,
              details: Optional[str] = None, severity: str = 'info') -> 'AuditLog':
        """
        Create and save a new audit log entry.
        
        This is a convenience method that creates a new AuditLog instance,
        adds it to the session, and commits it in one step.
        
        Args:
            event_type: Type of event (use EVENT_* constants)
            description: Human-readable description of the event
            user_id: ID of user associated with the event (if applicable)
            ip_address: Source IP address for the event
            user_agent: User agent string from the request
            details: Additional context information (may be JSON or text)
            severity: Event importance (info, warning, error, critical)
            
        Returns:
            AuditLog: The created audit log entry
            
        Raises:
            SQLAlchemyError: If the database operation fails
        """
        try:
            log = cls(
                event_type=event_type,
                description=description,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details,
                severity=severity
            )
            db.session.add(log)
            db.session.commit()
            return log
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to create audit log: {e}")
            # Re-raise or handle as needed by your application
            raise
    
    @classmethod
    def get_by_ip(cls, ip_address: str, limit: int = 100) -> List['AuditLog']:
        """
        Get audit log entries from a specific IP address.
        
        Args:
            ip_address: IP address to filter by
            limit: Maximum number of entries to return
            
        Returns:
            List[AuditLog]: List of matching audit log entries
        """
        return cls.query.filter_by(ip_address=ip_address)\
                       .order_by(desc(cls.created_at))\
                       .limit(limit).all()
    
    @classmethod
    def get_by_user(cls, user_id: int, limit: int = 100) -> List['AuditLog']:
        """
        Get audit log entries for a specific user.
        
        Args:
            user_id: User ID to filter by
            limit: Maximum number of entries to return
            
        Returns:
            List[AuditLog]: List of matching audit log entries
        """
        return cls.query.filter_by(user_id=user_id)\
                       .order_by(desc(cls.created_at))\
                       .limit(limit).all()
    
    @classmethod
    def get_security_events(cls, hours: int = 24, limit: int = 100) -> List['AuditLog']:
        """
        Get recent security-related events.
        
        Args:
            hours: How many hours back to look
            limit: Maximum number of entries to return
            
        Returns:
            List[AuditLog]: List of matching security events
        """
        # Define the security-related event types
        security_events = [
            cls.EVENT_LOGIN_FAILED,
            cls.EVENT_ACCOUNT_LOCKOUT,
            cls.EVENT_PERMISSION_DENIED,
            cls.EVENT_SECURITY_BREACH_ATTEMPT,
            cls.EVENT_SECURITY_COUNTERMEASURE,
            cls.EVENT_FILE_INTEGRITY,
            cls.EVENT_RATE_LIMIT_EXCEEDED,
            cls.EVENT_CONFIG_CHANGE,        # Track configuration changes
            cls.EVENT_ADMIN_ACTION,         # Track administrative actions
            cls.EVENT_PASSWORD_RESET,       # Track password resets
            cls.EVENT_API_ABUSE             # Track API abuse
        ]
        
        # Calculate the cutoff time
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        # Query the database
        return cls.query.filter(
                cls.event_type.in_(security_events),
                cls.created_at >= cutoff
            ).order_by(desc(cls.created_at)).limit(limit).all()
    
    @classmethod
    def count_by_event_type(cls, event_type: str, hours: int = 24) -> int:
        """
        Count occurrences of a specific event type within a time period.
        
        Args:
            event_type: Event type to count
            hours: How many hours back to look
            
        Returns:
            int: Count of matching events
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return cls.query.filter(
                cls.event_type == event_type,
                cls.created_at >= cutoff
            ).count()
            
    @classmethod
    def get_login_failures_by_ip(cls, hours: int = 24, min_count: int = 5) -> List[Tuple[str, int]]:
        """
        Get IPs with multiple failed login attempts.
        
        This method finds IP addresses with suspicious login activity
        that might indicate brute force attacks.
        
        Args:
            hours: How many hours back to look
            min_count: Minimum number of failures to be considered suspicious
            
        Returns:
            List[Tuple[str, int]]: List of (ip_address, failure_count) tuples
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        # Use SQLAlchemy to count failed logins grouped by IP
        result = db.session.query(
                cls.ip_address, 
                func.count(cls.id).label('count')
            ).filter(
                cls.event_type == cls.EVENT_LOGIN_FAILED,
                cls.created_at >= cutoff,
                cls.ip_address != None  # Ensure IP is not null
            ).group_by(
                cls.ip_address
            ).having(
                func.count(cls.id) >= min_count
            ).order_by(
                desc('count')
            ).all()
            
        return result
        
    @classmethod
    def get_security_timeline(cls, user_id: Optional[int] = None, hours: int = 24) -> List['AuditLog']:
        """
        Get a timeline of security-relevant events for analysis.
        
        This method provides a chronological sequence of security events
        for a specific user or system-wide if no user is specified.
        
        Args:
            user_id: Optional user ID to filter by
            hours: How many hours back to look
            
        Returns:
            List['AuditLog']: List of audit log entries in chronological order
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        query = cls.query.filter(cls.created_at >= cutoff)
        
        # Filter by security-relevant events
        query = query.filter(cls.event_type.in_([
            cls.EVENT_LOGIN_SUCCESS,
            cls.EVENT_LOGIN_FAILED,
            cls.EVENT_PERMISSION_DENIED,
            cls.EVENT_PASSWORD_RESET,
            cls.EVENT_SECURITY_BREACH_ATTEMPT,
            cls.EVENT_SECURITY_COUNTERMEASURE,
            cls.EVENT_ADMIN_ACTION,
            cls.EVENT_CONFIG_CHANGE,
            cls.EVENT_API_ACCESS
        ]))
        
        # Filter by user if specified
        if user_id is not None:
            query = query.filter(cls.user_id == user_id)
        
        # Order chronologically
        return query.order_by(cls.created_at).all()
    
    @classmethod
    def get_critical_events(cls, hours: int = 24) -> List['AuditLog']:
        """
        Get high-severity security events that require attention.
        
        This method finds critical security events that may indicate
        a breach or require immediate response.
        
        Args:
            hours: How many hours back to look
            
        Returns:
            List['AuditLog']: List of critical audit log entries
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return cls.query.filter(
            cls.severity.in_([cls.SEVERITY_CRITICAL, cls.SEVERITY_ERROR]),
            cls.created_at >= cutoff
        ).order_by(desc(cls.created_at)).all()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the audit log entry to a dictionary for serialization.
        
        Returns:
            Dict[str, Any]: Dictionary representation of the audit log entry
        """
        return {
            'id': self.id,
            'event_type': self.event_type,
            'user_id': self.user_id,
            'description': self.description,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'details': self.details,
            'severity': self.severity,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'timestamp': self.created_at.timestamp() if self.created_at else None,
            'related_id': self.related_id,
            'related_type': self.related_type
        }