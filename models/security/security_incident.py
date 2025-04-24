"""
Security incident model for tracking and responding to security events.

This module provides the SecurityIncident model which represents security events
that require investigation or response. It tracks incidents detected through the
application's monitoring systems including suspicious access patterns, breach attempts,
and other security-related events requiring attention.

The model supports the complete incident lifecycle from detection through investigation,
remediation, and resolution, providing a comprehensive audit trail of security responses.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy import desc, func
from extensions import db
from models.audit_log import AuditLog
from models.base import BaseModel, AuditableMixin
from core.security_utils import log_security_event


class SecurityIncident(BaseModel, AuditableMixin):
    """
    A model representing a detected security incident requiring attention.

    This model tracks security incidents detected by the application's
    monitoring systems, including breach detection, login anomalies,
    and other security-related events that require investigation and response.
    It provides a full audit trail of incident detection, investigation,
    and resolution.

    Attributes:
        id: Primary key
        title: Short descriptive title of the incident
        incident_type: Type classification (e.g., brute_force, data_leak)
        description: Brief summary description of the incident
        details: Detailed information including technical specifics
        severity: Criticality level (critical, high, medium, low)
        status: Current status (open, investigating, resolved, closed)
        user_id: User associated with the incident (if applicable)
        ip_address: IP address associated with the incident
        source: How the incident was detected (system, user_report, etc.)
        assigned_to: User ID of staff member handling the incident
        resolution: Description of how the incident was resolved
        resolved_at: When the incident was marked as resolved
        created_at: When the incident was detected/created
        updated_at: Last update timestamp
    """
    __tablename__ = 'security_incidents'

    # Define security-critical fields for AuditableMixin
    SECURITY_CRITICAL_FIELDS = ['status', 'severity', 'resolution', 'assigned_to']
    AUDIT_ACCESS = True

    # Status constants
    STATUS_OPEN = 'open'
    STATUS_INVESTIGATING = 'investigating'
    STATUS_RESOLVED = 'resolved'
    STATUS_CLOSED = 'closed'

    # Severity constants
    SEVERITY_CRITICAL = 'critical'
    SEVERITY_HIGH = 'high'
    SEVERITY_MEDIUM = 'medium'
    SEVERITY_LOW = 'low'

    # Source constants
    SOURCE_SYSTEM = 'system'
    SOURCE_USER_REPORT = 'user_report'
    SOURCE_SECURITY_SCAN = 'security_scan'
    SOURCE_ALERT = 'alert'
    SOURCE_MONITORING = 'monitoring'

    # Primary columns
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    incident_type = db.Column(db.String(50), nullable=False, index=True)
    description = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), nullable=False, index=True)
    status = db.Column(db.String(20), default=STATUS_OPEN, index=True)

    # Relations and references
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    source = db.Column(db.String(50), default=SOURCE_SYSTEM)
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    # Resolution information
    resolution = db.Column(db.Text, nullable=True)
    resolved_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Metadata
    notes = db.Column(db.Text, nullable=True)  # Internal notes on investigation
    external_references = db.Column(db.String(255), nullable=True)  # External tracking IDs

    # Relationships
    user = db.relationship('User', foreign_keys=[user_id],
                          backref=db.backref('security_incidents', lazy='dynamic'))
    assignee = db.relationship('User', foreign_keys=[assigned_to],
                              backref=db.backref('assigned_incidents', lazy='dynamic'))

    def __init__(self, title: str, incident_type: str, description: str,
                severity: str = SEVERITY_MEDIUM, details: Optional[str] = None,
                status: str = STATUS_OPEN, user_id: Optional[int] = None,
                ip_address: Optional[str] = None, source: str = SOURCE_SYSTEM,
                assigned_to: Optional[int] = None, notes: Optional[str] = None,
                resolution: Optional[str] = None, resolved_at: Optional[datetime] = None,
                external_references: Optional[str] = None, **kwargs):
        """
        Initialize a SecurityIncident instance.

        Args:
            title: Short descriptive title of the incident
            incident_type: Classification of incident type
            description: Brief summary description
            severity: Criticality level (critical, high, medium, low)
            details: Detailed information including technical specifics
            status: Current status (open, investigating, resolved, closed)
            user_id: User associated with the incident (if applicable)
            ip_address: IP address associated with the incident
            source: How the incident was detected (system, user_report, etc.)
            assigned_to: User ID of staff member handling the incident
            notes: Internal notes on investigation progress
            resolution: Description of how the incident was resolved
            resolved_at: When the incident was marked as resolved
            external_references: References to external tracking systems
            **kwargs: Additional keyword arguments
        """
        super().__init__(**kwargs)  # Call the base class __init__ method
        self.title = title
        self.incident_type = incident_type
        self.description = description
        self.details = details
        self.severity = severity
        self.status = status
        self.user_id = user_id
        self.ip_address = ip_address
        self.source = source
        self.assigned_to = assigned_to
        self.notes = notes
        self.resolution = resolution
        self.resolved_at = resolved_at
        self.external_references = external_references

    @hybrid_property
    def is_resolved(self) -> bool:
        """
        Check if the incident has been resolved.

        Returns:
            bool: True if status is resolved or closed, False otherwise
        """
        return self.status in (self.STATUS_RESOLVED, self.STATUS_CLOSED)

    @hybrid_property
    def time_to_resolution(self) -> Optional[int]:
        """
        Calculate time to resolution in hours, if resolved.

        Returns:
            Optional[int]: Hours to resolution or None if not resolved
        """
        if self.resolved_at and self.created_at:
            delta = self.resolved_at - self.created_at
            return int(delta.total_seconds() / 3600)
        return None

    @hybrid_property
    def age_hours(self) -> int:
        """
        Calculate the age of the incident in hours.

        Returns:
            int: Age in hours
        """
        if self.created_at:
            delta = datetime.now(timezone.utc) - self.created_at
            return int(delta.total_seconds() / 3600)
        return 0

    def assign_to(self, user_id: int, assigned_by: Optional[int] = None) -> None:
        """
        Assign the incident to a user for investigation.

        Args:
            user_id: ID of the user to assign the incident to
            assigned_by: ID of the user making the assignment
        """
        previous_assignee = self.assigned_to
        self.assigned_to = user_id

        if self.status == self.STATUS_OPEN:
            self.status = self.STATUS_INVESTIGATING

        # Record the change
        fields_changed = ['assigned_to']
        if previous_assignee != user_id:
            fields_changed.append('status')

        # Log the change
        self.log_change(fields_changed, f"Assigned to user ID {user_id}")

        # Record security event
        if assigned_by:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_INCIDENT_UPDATE,
                description=f"Security incident #{self.id} assigned to user ID {user_id}",
                user_id=assigned_by,
                severity='info'
            )

    def add_note(self, note: str, user_id: Optional[int] = None) -> None:
        """
        Add an investigation note to the incident.

        Args:
            note: The note text to add
            user_id: ID of the user adding the note
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        note_with_timestamp = f"[{timestamp}] {note}"

        if self.notes:
            self.notes = f"{self.notes}\n\n{note_with_timestamp}"
        else:
            self.notes = note_with_timestamp

        # Record the change
        self.log_change(['notes'], f"Note added by user ID {user_id}" if user_id else "Note added")

    def escalate(self, new_severity: str, reason: str, user_id: Optional[int] = None) -> None:
        """
        Escalate the incident to a higher severity level.

        Args:
            new_severity: The new severity level
            reason: Reason for escalation
            user_id: ID of the user performing the escalation
        """
        # Validate severity
        valid_severities = [self.SEVERITY_LOW, self.SEVERITY_MEDIUM, self.SEVERITY_HIGH, self.SEVERITY_CRITICAL]
        if new_severity not in valid_severities:
            raise ValueError(f"Invalid severity: {new_severity}")

        # Check if this is an actual escalation
        old_severity = self.severity
        old_severity_index = valid_severities.index(old_severity) if old_severity in valid_severities else 0
        new_severity_index = valid_severities.index(new_severity)

        if new_severity_index <= old_severity_index:
            raise ValueError(f"New severity {new_severity} is not an escalation from {old_severity}")

        self.severity = new_severity
        escalation_note = f"Escalated from {old_severity} to {new_severity}. Reason: {reason}"
        self.add_note(escalation_note, user_id)

        # Record security event
        if user_id:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_INCIDENT_UPDATE,
                description=f"Security incident #{self.id} escalated to {new_severity}",
                user_id=user_id,
                severity='warning'
            )

    def resolve(self, resolution: str, user_id: Optional[int] = None) -> None:
        """
        Mark the incident as resolved.

        Args:
            resolution: Description of how the incident was resolved
            user_id: ID of the user who resolved the incident
        """
        old_status = self.status
        self.status = self.STATUS_RESOLVED
        self.resolution = resolution
        self.resolved_at = datetime.now(timezone.utc)

        # Record the change
        fields_changed = ['status', 'resolution', 'resolved_at']
        self.log_change(
            fields_changed,
            f"Resolved by user ID {user_id}" if user_id else "Resolved"
        )

        # Track who resolved it if provided
        if user_id:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_COUNTERMEASURE,
                description=f"Security incident #{self.id} resolved",
                user_id=user_id,
                severity='info',
                details=f"Status change: {old_status} → {self.STATUS_RESOLVED}. Resolution: {resolution[:100]}..."
            )

    def reopen(self, reason: str, user_id: Optional[int] = None) -> None:
        """
        Reopen a resolved or closed incident.

        Args:
            reason: Reason for reopening
            user_id: ID of the user reopening the incident
        """
        if self.status not in (self.STATUS_RESOLVED, self.STATUS_CLOSED):
            raise ValueError(f"Cannot reopen incident with status: {self.status}")

        old_status = self.status
        self.status = self.STATUS_INVESTIGATING
        self.resolved_at = None
        reopen_note = f"Incident reopened. Reason: {reason}"
        self.add_note(reopen_note, user_id)

        # Record the change
        fields_changed = ['status', 'resolved_at']
        self.log_change(
            fields_changed,
            f"Reopened by user ID {user_id}" if user_id else "Reopened"
        )

        # Track who reopened it if provided
        if user_id:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_INCIDENT_UPDATE,
                description=f"Security incident #{self.id} reopened",
                user_id=user_id,
                severity='warning',
                details=f"Status change: {old_status} → {self.STATUS_INVESTIGATING}. Reason: {reason[:100]}..."
            )

    def close(self, reason: Optional[str] = None, user_id: Optional[int] = None) -> None:
        """
        Close the incident (final state).

        Args:
            reason: Optional reason for closure
            user_id: ID of the user closing the incident
        """
        old_status = self.status
        self.status = self.STATUS_CLOSED

        # Add closure reason to notes if provided
        if reason:
            closure_note = f"Incident closed. Reason: {reason}"
            self.add_note(closure_note, user_id)

        # Record the change
        self.log_change(
            ['status'],
            f"Closed by user ID {user_id}" if user_id else "Closed"
        )

        # Track who closed it if provided
        if user_id:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_INCIDENT_UPDATE,
                description=f"Security incident #{self.id} closed",
                user_id=user_id,
                severity='info',
                details=f"Status change: {old_status} → {self.STATUS_CLOSED}"
            )

    @classmethod
    def get_active_incidents(cls) -> List['SecurityIncident']:
        """
        Get all active (non-closed) security incidents.

        Returns:
            List[SecurityIncident]: List of active incidents sorted by severity and time
        """
        return cls.query.filter(
            cls.status.in_([cls.STATUS_OPEN, cls.STATUS_INVESTIGATING])
        ).order_by(desc(cls.severity), desc(cls.created_at)).all()

    @classmethod
    def get_incidents_by_severity(cls, severity: str) -> List['SecurityIncident']:
        """
        Get incidents with the specified severity level.

        Args:
            severity: Severity level to filter by

        Returns:
            List[SecurityIncident]: List of incidents with the specified severity
        """
        return cls.query.filter_by(severity=severity).order_by(desc(cls.created_at)).all()

    @classmethod
    def get_incidents_by_type(cls, incident_type: str) -> List['SecurityIncident']:
        """
        Get incidents of the specified type.

        Args:
            incident_type: Incident type to filter by

        Returns:
            List[SecurityIncident]: List of incidents of the specified type
        """
        return cls.query.filter_by(incident_type=incident_type).order_by(
            desc(cls.severity), desc(cls.created_at)
        ).all()

    @classmethod
    def get_incidents_by_ip(cls, ip_address: str) -> List['SecurityIncident']:
        """
        Get incidents associated with the specified IP address.

        Args:
            ip_address: IP address to search for

        Returns:
            List[SecurityIncident]: List of incidents associated with the IP
        """
        return cls.query.filter_by(ip_address=ip_address).order_by(
            desc(cls.created_at)
        ).all()

    @classmethod
    def count_by_status(cls) -> Dict[str, int]:
        """
        Count incidents by status.

        Returns:
            Dict[str, int]: Dictionary mapping status to count
        """
        result = db.session.query(
            cls.status,
            func.count(cls.id)
        ).group_by(cls.status).all()

        return {status: count for status, count in result}

    @classmethod
    def count_by_severity(cls) -> Dict[str, int]:
        """
        Count incidents by severity.

        Returns:
            Dict[str, int]: Dictionary mapping severity to count
        """
        result = db.session.query(
            cls.severity,
            func.count(cls.id)
        ).group_by(cls.severity).all()

        return {severity: count for severity, count in result}

    @classmethod
    def get_recent_incidents(cls, days: int = 7, limit: int = 100) -> List['SecurityIncident']:
        """
        Get recent security incidents within the specified timeframe.

        Args:
            days: Number of days to look back
            limit: Maximum number of incidents to return

        Returns:
            List[SecurityIncident]: List of recent incidents
        """
        cutoff = datetime.now(timezone.utc) - datetime.timedelta(days=days)
        return cls.query.filter(cls.created_at >= cutoff).order_by(
            desc(cls.created_at)
        ).limit(limit).all()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the incident to a dictionary for API responses.

        Returns:
            Dict[str, Any]: Dictionary representation of the incident
        """
        # Get the base dictionary from the parent class
        data = super().to_dict()

        # Add SecurityIncident specific fields
        data.update({
            'is_resolved': self.is_resolved,
            'time_to_resolution': self.time_to_resolution,
            'age_hours': self.age_hours
        })

        # Ensure datetime fields are properly serialized
        for field in ['resolved_at']:
            if hasattr(self, field) and getattr(self, field):
                data[field] = getattr(self, field).isoformat()

        return data
