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
from sqlalchemy import desc
from extensions import db
from models.audit_log import AuditLog
from models.base import BaseModel
from core.security_utils import log_security_event


class SecurityIncident(BaseModel):
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

    # Primary columns
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    incident_type = db.Column(db.String(50), nullable=False, index=True)
    description = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), nullable=False, index=True) 
    status = db.Column(db.String(20), default='open', index=True)

    # Relations and references
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    source = db.Column(db.String(50), default='system')  # system, user_report, security_scan
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
                severity: str = 'medium', details: Optional[str] = None,
                status: str = 'open', user_id: Optional[int] = None, 
                ip_address: Optional[str] = None, source: str = 'system',
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

        # Handle any legacy fields from kwargs
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    @hybrid_property
    def is_resolved(self) -> bool:
        """Check if the incident has been resolved."""
        return self.status in ('resolved', 'closed')

    @hybrid_property
    def time_to_resolution(self) -> Optional[int]:
        """Calculate time to resolution in hours, if resolved."""
        if self.resolved_at and self.created_at:
            # No need to check if callable - these are datetime attributes
            delta = self.resolved_at - self.created_at
            return int(delta.total_seconds() / 3600)
        return None

    def assign_to(self, user_id: int) -> None:
        """
        Assign the incident to a user for investigation.
        
        Args:
            user_id: ID of the user to assign the incident to
        """
        self.assigned_to = user_id
        self.status = 'investigating' if self.status == 'open' else self.status
        self.updated_at = datetime.now(timezone.utc)

    def resolve(self, resolution: str, user_id: Optional[int] = None) -> None:
        """
        Mark the incident as resolved.
        
        Args:
            resolution: Description of how the incident was resolved
            user_id: ID of the user who resolved the incident
        """
        self.status = 'resolved'
        self.resolution = resolution
        self.resolved_at = datetime.now(timezone.utc)
        self.updated_at = self.resolved_at

        if user_id:
            # Track who resolved it if provided
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_COUNTERMEASURE,
                description=f"Security incident #{self.id} resolved",
                user_id=user_id,
                details=f"Resolution: {resolution[:50]}..."
            )

    def close(self, reason: Optional[str] = None) -> None:
        """
        Close the incident (final state).
        
        Args:
            reason: Optional reason for closure
        """
        self.status = 'closed'
        if reason:
            self.notes = f"{self.notes or ''}\nClosure reason: {reason}"
        self.updated_at = datetime.now(timezone.utc)

    @classmethod
    def get_active_incidents(cls) -> List['SecurityIncident']:
        """Get all active (non-closed) security incidents."""
        return cls.query.filter(
            cls.status.in_(['open', 'investigating'])
        ).order_by(desc(cls.severity), desc(cls.created_at)).all()

    @classmethod
    def get_incidents_by_severity(cls, severity: str) -> List['SecurityIncident']:
        """Get incidents with the specified severity level."""
        return cls.query.filter_by(severity=severity).order_by(desc(cls.created_at)).all()

    @classmethod
    def count_by_status(cls) -> Dict[str, int]:
        """Count incidents by status."""
        result = db.session.query(
            cls.status, 
            db.func.count(cls.id)
        ).group_by(cls.status).all()

        return {status: count for status, count in result}

    def to_dict(self) -> Dict[str, Any]:
        """Convert the incident to a dictionary for API responses."""
        return {
            'id': self.id,
            'title': self.title,
            'incident_type': self.incident_type,
            'description': self.description,
            'details': self.details,
            'severity': self.severity,
            'status': self.status,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'source': self.source,
            'assigned_to': self.assigned_to,
            'resolution': self.resolution,
            'notes': self.notes,
            'external_references': self.external_references,
            'created_at': (self.created_at() if callable(self.created_at) else self.created_at).isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'is_resolved': self.is_resolved,
            'time_to_resolution': self.time_to_resolution
        }
