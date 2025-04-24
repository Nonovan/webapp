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
from typing import Dict, Any, Optional, List, Tuple, ClassVar, Union

from flask import current_app, request, g
from sqlalchemy import desc, func, and_, or_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.postgresql import JSONB

from extensions import db, metrics
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
        related_id: ID of related entity (optional)
        related_type: Type of related entity (optional)
        object_id: ID of the object being acted upon (optional)
        object_type: Type of the object being acted upon (optional)
        created_at: When the event occurred (inherited from BaseModel)
        updated_at: When the log entry was last updated (inherited from BaseModel)
    """

    __tablename__ = 'audit_logs'

    # Event type constants for authentication events
    EVENT_LOGIN_SUCCESS: ClassVar[str] = 'login_success'
    EVENT_LOGIN_FAILED: ClassVar[str] = 'login_failed'
    EVENT_LOGOUT: ClassVar[str] = 'logout'
    EVENT_ACCOUNT_CREATED: ClassVar[str] = 'account_created'
    EVENT_ACCOUNT_MODIFIED: ClassVar[str] = 'account_modified'
    EVENT_ACCOUNT_LOCKOUT: ClassVar[str] = 'account_lockout'
    EVENT_PASSWORD_RESET: ClassVar[str] = 'password_reset'
    EVENT_PASSWORD_CHANGED: ClassVar[str] = 'password_changed'
    EVENT_MFA_ENABLED: ClassVar[str] = 'mfa_enabled'
    EVENT_MFA_DISABLED: ClassVar[str] = 'mfa_disabled'
    EVENT_MFA_CHALLENGE: ClassVar[str] = 'mfa_challenge'

    # Event type constants for authorization events
    EVENT_PERMISSION_DENIED: ClassVar[str] = 'permission_denied'
    EVENT_ROLE_ASSIGNED: ClassVar[str] = 'role_assigned'
    EVENT_ROLE_REMOVED: ClassVar[str] = 'role_removed'
    EVENT_PERMISSION_GRANTED: ClassVar[str] = 'permission_granted'
    EVENT_PERMISSION_REVOKED: ClassVar[str] = 'permission_revoked'

    # Event type constants for system events
    EVENT_API_ACCESS: ClassVar[str] = 'api_access'
    EVENT_ADMIN_ACTION: ClassVar[str] = 'admin_action'
    EVENT_FILE_UPLOAD: ClassVar[str] = 'file_upload'
    EVENT_FILE_DOWNLOAD: ClassVar[str] = 'file_download'
    EVENT_FILE_INTEGRITY: ClassVar[str] = 'file_integrity'
    EVENT_CONFIG_CHANGE: ClassVar[str] = 'config_change'
    EVENT_OBJECT_CREATED: ClassVar[str] = 'object_created'
    EVENT_OBJECT_UPDATED: ClassVar[str] = 'object_updated'
    EVENT_OBJECT_DELETED: ClassVar[str] = 'object_deleted'

    # Event type constants for security events
    EVENT_SECURITY_BREACH_ATTEMPT: ClassVar[str] = 'security_breach_attempt'
    EVENT_SECURITY_COUNTERMEASURE: ClassVar[str] = 'security_countermeasure'
    EVENT_SECURITY_INCIDENT_UPDATE: ClassVar[str] = 'security_incident_update'
    EVENT_DATABASE_ACCESS: ClassVar[str] = 'database_access'
    EVENT_RATE_LIMIT_EXCEEDED: ClassVar[str] = 'rate_limit_exceeded'
    EVENT_API_ABUSE: ClassVar[str] = 'api_abuse'

    # Event categories
    EVENT_CATEGORY_AUTH: ClassVar[str] = 'authentication'
    EVENT_CATEGORY_ACCESS: ClassVar[str] = 'access_control'
    EVENT_CATEGORY_DATA: ClassVar[str] = 'data_access'
    EVENT_CATEGORY_ADMIN: ClassVar[str] = 'administrative'
    EVENT_CATEGORY_SECURITY: ClassVar[str] = 'security'
    EVENT_CATEGORY_SYSTEM: ClassVar[str] = 'system'

    # Severity constants
    SEVERITY_INFO: ClassVar[str] = 'info'
    SEVERITY_WARNING: ClassVar[str] = 'warning'
    SEVERITY_ERROR: ClassVar[str] = 'error'
    SEVERITY_CRITICAL: ClassVar[str] = 'critical'

    # Valid severity levels
    VALID_SEVERITIES = [SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_ERROR, SEVERITY_CRITICAL]

    # Column definitions
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    ip_address = db.Column(db.String(45), nullable=True, index=True)  # IPv6 can be up to 45 chars
    user_agent = db.Column(db.String(255), nullable=True)
    description = db.Column(db.String(255), nullable=False)
    details = db.Column(db.JSON, nullable=True)  # Use native JSON type where supported
    severity = db.Column(db.String(20), nullable=False, default=SEVERITY_INFO, index=True)
    related_id = db.Column(db.Integer, nullable=True, index=True)  # For linking to other entities
    related_type = db.Column(db.String(50), nullable=True, index=True)  # Type of the related entity
    object_id = db.Column(db.Integer, nullable=True, index=True)  # Object being acted upon
    object_type = db.Column(db.String(50), nullable=True, index=True)  # Type of object
    category = db.Column(db.String(50), nullable=True, index=True)  # Event category

    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], lazy='joined',
                          backref=db.backref('audit_logs', lazy='dynamic'))

    def __init__(self, event_type: str, description: str, user_id: Optional[int] = None,
                ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                details: Optional[Union[Dict, str]] = None, severity: str = SEVERITY_INFO,
                created_at: Optional[datetime] = None,
                related_id: Optional[int] = None, related_type: Optional[str] = None,
                object_id: Optional[int] = None, object_type: Optional[str] = None,
                category: Optional[str] = None):
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
            related_id: ID of a related entity (e.g., for linking to specific resources)
            related_type: Type of the related entity
            object_id: ID of the object being acted upon
            object_type: Type of the object being acted upon
            category: Category of the event (auth, access, data, etc.)
        """
        # Validate severity
        if severity not in self.VALID_SEVERITIES:
            if current_app:
                current_app.logger.warning(f"Invalid severity: {severity}. Using {self.SEVERITY_INFO} instead.")
            severity = self.SEVERITY_INFO

        self.event_type = event_type
        self.description = description
        self.user_id = user_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.details = details
        self.severity = severity
        self.related_id = related_id
        self.related_type = related_type
        self.object_id = object_id
        self.object_type = object_type
        self.category = category

        # Automatically determine category if not provided
        if not category:
            self.category = self._determine_category(event_type)

        # Only pass created_at to the parent class if it's provided
        if created_at:
            super().__init__(created_at=created_at)
        else:
            super().__init__()

    def _determine_category(self, event_type: str) -> str:
        """
        Determine the event category based on event type.

        Args:
            event_type: The type of event

        Returns:
            str: The event category
        """
        # Authentication events
        if event_type in [self.EVENT_LOGIN_SUCCESS, self.EVENT_LOGIN_FAILED,
                         self.EVENT_LOGOUT, self.EVENT_ACCOUNT_CREATED,
                         self.EVENT_ACCOUNT_MODIFIED, self.EVENT_ACCOUNT_LOCKOUT,
                         self.EVENT_PASSWORD_RESET, self.EVENT_PASSWORD_CHANGED,
                         self.EVENT_MFA_ENABLED, self.EVENT_MFA_DISABLED,
                         self.EVENT_MFA_CHALLENGE]:
            return self.EVENT_CATEGORY_AUTH

        # Access control events
        elif event_type in [self.EVENT_PERMISSION_DENIED, self.EVENT_ROLE_ASSIGNED,
                           self.EVENT_ROLE_REMOVED, self.EVENT_PERMISSION_GRANTED,
                           self.EVENT_PERMISSION_REVOKED]:
            return self.EVENT_CATEGORY_ACCESS

        # Security events
        elif event_type in [self.EVENT_SECURITY_BREACH_ATTEMPT, self.EVENT_SECURITY_COUNTERMEASURE,
                           self.EVENT_SECURITY_INCIDENT_UPDATE, self.EVENT_RATE_LIMIT_EXCEEDED,
                           self.EVENT_API_ABUSE]:
            return self.EVENT_CATEGORY_SECURITY

        # Administrative events
        elif event_type in [self.EVENT_ADMIN_ACTION, self.EVENT_CONFIG_CHANGE]:
            return self.EVENT_CATEGORY_ADMIN

        # Data access events
        elif event_type in [self.EVENT_FILE_UPLOAD, self.EVENT_FILE_DOWNLOAD,
                           self.EVENT_DATABASE_ACCESS, self.EVENT_FILE_INTEGRITY,
                           self.EVENT_OBJECT_CREATED, self.EVENT_OBJECT_UPDATED,
                           self.EVENT_OBJECT_DELETED]:
            return self.EVENT_CATEGORY_DATA

        # Default to system
        else:
            return self.EVENT_CATEGORY_SYSTEM

    @classmethod
    def create(cls, event_type: str, description: str, user_id: Optional[int] = None,
              ip_address: Optional[str] = None, user_agent: Optional[str] = None,
              details: Optional[Union[Dict, str]] = None, severity: str = SEVERITY_INFO,
              related_id: Optional[int] = None, related_type: Optional[str] = None,
              object_id: Optional[int] = None, object_type: Optional[str] = None) -> 'AuditLog':
        """
        Create and save a new audit log entry.

        This is a convenience method that creates a new AuditLog instance,
        adds it to the session, and commits it in one step. It also collects
        request information if not explicitly provided.

        Args:
            event_type: Type of event (use EVENT_* constants)
            description: Human-readable description of the event
            user_id: ID of user associated with the event (if applicable)
            ip_address: Source IP address for the event
            user_agent: User agent string from the request
            details: Additional context information (may be JSON or text)
            severity: Event importance (info, warning, error, critical)
            related_id: ID of a related entity (e.g., for linking to specific resources)
            related_type: Type of the related entity
            object_id: ID of the object being acted upon
            object_type: Type of the object being acted upon

        Returns:
            AuditLog: The created audit log entry

        Raises:
            SQLAlchemyError: If the database operation fails
        """
        try:
            # Auto-populate user_id from Flask g if available and not provided
            if user_id is None and hasattr(g, 'user_id'):
                user_id = g.get('user_id')

            # Auto-populate IP address and user agent from Flask request if available
            if request:
                if not ip_address:
                    ip_address = request.remote_addr

                if not user_agent and hasattr(request, 'user_agent'):
                    user_agent = str(request.user_agent)

            log = cls(
                event_type=event_type,
                description=description,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details,
                severity=severity,
                related_id=related_id,
                related_type=related_type,
                object_id=object_id,
                object_type=object_type
            )

            db.session.add(log)
            db.session.commit()

            # Record metrics if available
            try:
                metrics.counter(
                    'audit_log_events_total',
                    1,
                    labels={
                        'event_type': event_type,
                        'severity': severity,
                        'category': log.category
                    }
                )
            except Exception as e:
                # Don't fail logging if metrics fail
                if current_app:
                    current_app.logger.debug(f"Failed to record audit log metrics: {e}")

            return log
        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error("Failed to create audit log: %s", str(e))
            # Re-raise to allow caller to handle
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
            cls.EVENT_SECURITY_INCIDENT_UPDATE,
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
    def get_by_category(cls, category: str, hours: int = 24, limit: int = 100) -> List['AuditLog']:
        """
        Get audit log entries by category.

        Args:
            category: Category to filter by (use EVENT_CATEGORY_* constants)
            hours: How many hours back to look
            limit: Maximum number of entries to return

        Returns:
            List[AuditLog]: List of matching audit log entries
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return cls.query.filter(
                cls.category == category,
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
                cls.ip_address.isnot(None)  # Ensure IP is not null
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
            List[AuditLog]: List of audit log entries in chronological order
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
            cls.EVENT_SECURITY_INCIDENT_UPDATE,
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
            List[AuditLog]: List of critical audit log entries
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return cls.query.filter(
            cls.severity.in_([cls.SEVERITY_CRITICAL, cls.SEVERITY_ERROR]),
            cls.created_at >= cutoff
        ).order_by(desc(cls.created_at)).all()

    @classmethod
    def get_events_by_related_entity(cls, related_type: str, related_id: int, limit: int = 100) -> List['AuditLog']:
        """
        Get audit log entries related to a specific entity.

        Args:
            related_type: Type of the related entity
            related_id: ID of the related entity
            limit: Maximum number of entries to return

        Returns:
            List[AuditLog]: List of audit log entries for the entity
        """
        return cls.query.filter_by(
                related_type=related_type,
                related_id=related_id
            ).order_by(desc(cls.created_at)).limit(limit).all()

    @classmethod
    def get_events_by_object(cls, object_type: str, object_id: int, limit: int = 100) -> List['AuditLog']:
        """
        Get audit trail for a specific object.

        Args:
            object_type: Type of the object
            object_id: ID of the object
            limit: Maximum number of entries to return

        Returns:
            List[AuditLog]: List of audit log entries for the object
        """
        return cls.query.filter_by(
                object_type=object_type,
                object_id=object_id
            ).order_by(desc(cls.created_at)).limit(limit).all()

    @classmethod
    def search(cls, query_params: Dict[str, Any], start_date: Optional[datetime] = None,
              end_date: Optional[datetime] = None, limit: int = 100) -> List['AuditLog']:
        """
        Search audit logs with flexible filtering.

        Args:
            query_params: Dictionary of search parameters
            start_date: Start date for search range
            end_date: End date for search range
            limit: Maximum number of results to return

        Returns:
            List[AuditLog]: Matching audit log entries
        """
        search_query = cls.query

        # Apply date range filter
        if start_date:
            search_query = search_query.filter(cls.created_at >= start_date)
        if end_date:
            search_query = search_query.filter(cls.created_at <= end_date)

        # Apply filters based on query parameters
        for key, value in query_params.items():
            if hasattr(cls, key) and value is not None:
                if isinstance(value, list):
                    search_query = search_query.filter(getattr(cls, key).in_(value))
                else:
                    search_query = search_query.filter(getattr(cls, key) == value)

        # Order by creation date descending
        return search_query.order_by(desc(cls.created_at)).limit(limit).all()

    @classmethod
    def get_statistics(cls, days: int = 30) -> Dict[str, Any]:
        """
        Get statistical summary of audit log entries.

        Args:
            days: Number of days to include in statistics

        Returns:
            Dict: Dictionary with statistical information
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        # Total events
        total_events = cls.query.filter(cls.created_at >= cutoff).count()

        # Events by severity
        severity_counts = {}
        for severity in cls.VALID_SEVERITIES:
            count = cls.query.filter(cls.created_at >= cutoff, cls.severity == severity).count()
            severity_counts[severity] = count

        # Events by category
        category_counts = db.session.query(
            cls.category, func.count(cls.id)
        ).filter(
            cls.created_at >= cutoff
        ).group_by(cls.category).all()

        # Most common event types
        event_type_counts = db.session.query(
            cls.event_type, func.count(cls.id)
        ).filter(
            cls.created_at >= cutoff
        ).group_by(cls.event_type).order_by(desc(func.count(cls.id))).limit(10).all()

        return {
            'total_events': total_events,
            'severity_counts': dict(severity_counts),
            'category_counts': dict(category_counts),
            'event_type_counts': dict(event_type_counts),
            'period_days': days
        }

    @classmethod
    def cleanup_old_logs(cls, retention_days: int = 365) -> Tuple[bool, int]:
        """
        Delete audit logs older than the retention period.

        Args:
            retention_days: Number of days to retain logs

        Returns:
            Tuple[bool, int]: Success status and number of logs deleted
        """
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

            # Use bulk delete for efficiency
            count = cls.query.filter(cls.created_at < cutoff).delete()
            db.session.commit()

            if current_app:
                current_app.logger.info(f"Cleaned up {count} audit logs older than {retention_days} days")

            return True, count
        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Error cleaning up old audit logs: {str(e)}")
            return False, 0

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
            'related_type': self.related_type,
            'object_id': self.object_id,
            'object_type': self.object_type,
            'category': self.category
        }
