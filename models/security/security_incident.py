"""
Security incident model for tracking and responding to security events.

This module provides the SecurityIncident model which represents security events
that require investigation or response. It tracks incidents detected through the
application's monitoring systems including suspicious access patterns, breach attempts,
and other security-related events requiring attention.

The model supports the complete incident lifecycle from detection through investigation,
remediation, and resolution, providing a comprehensive audit trail of security responses.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List, Tuple, Union
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy import desc, func, and_, or_, not_, case
from extensions import db, metrics
from models.base import BaseModel, AuditableMixin
from models.security.audit_log import AuditLog
from core.security.cs_audit import log_security_event


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
        notes: Internal investigation notes with timestamps
        external_references: External tracking IDs or references
        last_activity_at: Timestamp of last activity on this incident
        priority_score: Calculated priority score based on severity and age
        affected_resources: JSON array of resources affected by the incident
        related_incidents: JSON array of related incident IDs
        tags: List of tags for categorization
    """
    __tablename__ = 'security_incidents'

    # Define security-critical fields for AuditableMixin
    SECURITY_CRITICAL_FIELDS = ['status', 'severity', 'resolution', 'assigned_to', 'details', 'notes']
    AUDIT_ACCESS = True

    # Status constants
    STATUS_OPEN = 'open'
    STATUS_INVESTIGATING = 'investigating'
    STATUS_RESOLVED = 'resolved'
    STATUS_CLOSED = 'closed'
    STATUS_MERGED = 'merged'  # New status for merged incidents

    VALID_STATUSES = [STATUS_OPEN, STATUS_INVESTIGATING, STATUS_RESOLVED, STATUS_CLOSED, STATUS_MERGED]

    # Severity constants
    SEVERITY_CRITICAL = 'critical'
    SEVERITY_HIGH = 'high'
    SEVERITY_MEDIUM = 'medium'
    SEVERITY_LOW = 'low'

    VALID_SEVERITIES = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW]

    # Source constants
    SOURCE_SYSTEM = 'system'
    SOURCE_USER_REPORT = 'user_report'
    SOURCE_SECURITY_SCAN = 'security_scan'
    SOURCE_ALERT = 'alert'
    SOURCE_MONITORING = 'monitoring'
    SOURCE_SIEM = 'siem'
    SOURCE_THREAT_INTELLIGENCE = 'threat_intelligence'
    SOURCE_VULNERABILITY_SCAN = 'vulnerability_scan'

    VALID_SOURCES = [
        SOURCE_SYSTEM, SOURCE_USER_REPORT, SOURCE_SECURITY_SCAN, SOURCE_ALERT,
        SOURCE_MONITORING, SOURCE_SIEM, SOURCE_THREAT_INTELLIGENCE, SOURCE_VULNERABILITY_SCAN
    ]

    # Incident type constants
    TYPE_UNAUTHORIZED_ACCESS = 'unauthorized_access'
    TYPE_BRUTE_FORCE = 'brute_force'
    TYPE_MALWARE = 'malware'
    TYPE_DATA_LEAK = 'data_leak'
    TYPE_PRIVILEGE_ESCALATION = 'privilege_escalation'
    TYPE_SUSPICIOUS_ACTIVITY = 'suspicious_activity'
    TYPE_CONFIGURATION_ERROR = 'configuration_error'
    TYPE_ACCOUNT_COMPROMISE = 'account_compromise'
    TYPE_DOS = 'denial_of_service'
    TYPE_SYSTEM_COMPROMISE = 'system_compromise'
    TYPE_NETWORK_ANOMALY = 'network_anomaly'
    TYPE_POLICY_VIOLATION = 'policy_violation'
    TYPE_INSIDER_THREAT = 'insider_threat'

    VALID_INCIDENT_TYPES = [
        TYPE_UNAUTHORIZED_ACCESS, TYPE_BRUTE_FORCE, TYPE_MALWARE, TYPE_DATA_LEAK,
        TYPE_PRIVILEGE_ESCALATION, TYPE_SUSPICIOUS_ACTIVITY, TYPE_CONFIGURATION_ERROR,
        TYPE_ACCOUNT_COMPROMISE, TYPE_DOS, TYPE_SYSTEM_COMPROMISE, TYPE_NETWORK_ANOMALY,
        TYPE_POLICY_VIOLATION, TYPE_INSIDER_THREAT
    ]

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
    ip_address = db.Column(db.String(45), nullable=True, index=True)
    source = db.Column(db.String(50), default=SOURCE_SYSTEM)
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)

    # Resolution information
    resolution = db.Column(db.Text, nullable=True)
    resolved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    # Metadata
    notes = db.Column(db.Text, nullable=True)  # Internal notes on investigation
    external_references = db.Column(db.String(255), nullable=True)  # External tracking IDs
    last_activity_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    priority_score = db.Column(db.Integer, nullable=True, index=True)
    affected_resources = db.Column(db.JSON, nullable=True)
    related_incidents = db.Column(db.JSON, nullable=True)
    tags = db.Column(db.JSON, nullable=True)
    parent_incident_id = db.Column(db.Integer, db.ForeignKey('security_incidents.id'), nullable=True)

    # Relationships
    user = db.relationship('User', foreign_keys=[user_id],
                          backref=db.backref('security_incidents', lazy='dynamic'))
    assignee = db.relationship('User', foreign_keys=[assigned_to],
                              backref=db.backref('assigned_incidents', lazy='dynamic'))
    resolver = db.relationship('User', foreign_keys=[resolved_by],
                             backref=db.backref('resolved_incidents', lazy='dynamic'))
    parent_incident = db.relationship('SecurityIncident', remote_side=[id],
                                     backref=db.backref('child_incidents', lazy='dynamic'))

    def __init__(self, title: str, incident_type: str, description: str,
                severity: str = SEVERITY_MEDIUM, details: Optional[str] = None,
                status: str = STATUS_OPEN, user_id: Optional[int] = None,
                ip_address: Optional[str] = None, source: str = SOURCE_SYSTEM,
                assigned_to: Optional[int] = None, notes: Optional[str] = None,
                resolution: Optional[str] = None, resolved_at: Optional[datetime] = None,
                external_references: Optional[str] = None,
                affected_resources: Optional[List[Dict[str, Any]]] = None,
                related_incidents: Optional[List[int]] = None,
                tags: Optional[List[str]] = None,
                **kwargs):
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
            affected_resources: List of resources affected by the incident
            related_incidents: List of related incident IDs
            tags: List of tags for categorization
            **kwargs: Additional keyword arguments
        """
        super().__init__(**kwargs)  # Call the base class __init__ method

        # Validate inputs
        if incident_type not in self.VALID_INCIDENT_TYPES:
            raise ValueError(f"Invalid incident type: {incident_type}")

        if severity not in self.VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        if status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}")

        if source and source not in self.VALID_SOURCES:
            raise ValueError(f"Invalid source: {source}")

        # Set core fields
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
        self.resolution = resolution
        self.resolved_at = resolved_at
        self.external_references = external_references

        # Set metadata fields
        self.last_activity_at = datetime.now(timezone.utc)
        self.affected_resources = affected_resources or []
        self.related_incidents = related_incidents or []
        self.tags = tags or []

        # Set notes with timestamp if provided
        if notes:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            self.notes = f"[{timestamp}] {notes}"

        # Calculate priority score
        self._update_priority_score()

    @hybrid_property
    def is_resolved(self) -> bool:
        """
        Check if the incident has been resolved.

        Returns:
            bool: True if status is resolved or closed, False otherwise
        """
        return self.status in (self.STATUS_RESOLVED, self.STATUS_CLOSED)

    @hybrid_property
    def is_active(self) -> bool:
        """
        Check if the incident is active and needs attention.

        Returns:
            bool: True if status is open or investigating, False otherwise
        """
        return self.status in (self.STATUS_OPEN, self.STATUS_INVESTIGATING)

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

    @hybrid_property
    def sla_status(self) -> str:
        """
        Calculate SLA status based on incident age and severity.

        Returns:
            str: "within_sla", "at_risk", or "breached"
        """
        if not self.is_active:
            return "within_sla"

        age_hours = self.age_hours

        # Define SLA thresholds by severity
        if self.severity == self.SEVERITY_CRITICAL:
            if age_hours <= 2:
                return "within_sla"
            elif age_hours <= 4:
                return "at_risk"
            else:
                return "breached"
        elif self.severity == self.SEVERITY_HIGH:
            if age_hours <= 8:
                return "within_sla"
            elif age_hours <= 12:
                return "at_risk"
            else:
                return "breached"
        elif self.severity == self.SEVERITY_MEDIUM:
            if age_hours <= 24:
                return "within_sla"
            elif age_hours <= 36:
                return "at_risk"
            else:
                return "breached"
        else:  # LOW
            if age_hours <= 72:
                return "within_sla"
            elif age_hours <= 96:
                return "at_risk"
            else:
                return "breached"

    def _update_priority_score(self) -> None:
        """
        Update the incident's priority score based on severity, age, and status.

        The priority score is used for sorting and prioritization.
        Higher scores indicate higher priority.
        """
        # Base scores by severity
        severity_scores = {
            self.SEVERITY_CRITICAL: 1000,
            self.SEVERITY_HIGH: 750,
            self.SEVERITY_MEDIUM: 500,
            self.SEVERITY_LOW: 250,
        }

        # Get base score from severity
        base_score = severity_scores.get(self.severity, 0)

        # Adjust based on status
        if self.status == self.STATUS_OPEN:
            status_multiplier = 1.0
        elif self.status == self.STATUS_INVESTIGATING:
            status_multiplier = 0.8
        elif self.status == self.STATUS_RESOLVED:
            status_multiplier = 0.2
        else:  # CLOSED or MERGED
            status_multiplier = 0.1

        # Adjust based on age (newer incidents get higher priority within same severity)
        if self.created_at:
            # Calculate age factor that decreases over time but stays positive
            # More recent incidents have a higher age_factor
            age_hours = self.age_hours
            if age_hours < 24:  # Less than a day old
                age_factor = 100 - (age_hours * 2)  # Starts at 100, decreases by 2 per hour
            elif age_hours < 168:  # Less than a week old
                age_factor = 50 - ((age_hours - 24) / 4)  # Continues decreasing but more slowly
            else:
                age_factor = 15  # Minimum age factor for old incidents
        else:
            age_factor = 0

        # Calculate final score
        self.priority_score = int(base_score * status_multiplier + age_factor)

    def _record_activity(self) -> None:
        """
        Update last activity timestamp and recalculate priority score.
        """
        self.last_activity_at = datetime.now(timezone.utc)
        self._update_priority_score()

        # Record metrics for activity
        try:
            metrics.counter(
                'security_incident_activity',
                1,
                labels={
                    'incident_id': str(self.id),
                    'severity': self.severity,
                    'status': self.status,
                    'type': self.incident_type
                }
            )
        except Exception:
            # Don't let metrics failures affect core functionality
            pass

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
        if previous_assignee != user_id and self.status == self.STATUS_INVESTIGATING:
            fields_changed.append('status')

        # Log the change
        self.log_change(fields_changed, f"Assigned to user ID {user_id}")

        # Update activity timestamp
        self._record_activity()

        # Record security event
        if assigned_by:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_INCIDENT_UPDATE,
                description=f"Security incident #{self.id} assigned to user ID {user_id}",
                user_id=assigned_by,
                severity='info',
                object_id=self.id,
                object_type='SecurityIncident'
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

        # Update activity timestamp
        self._record_activity()

    def escalate(self, new_severity: str, reason: str, user_id: Optional[int] = None) -> None:
        """
        Escalate the incident to a higher severity level.

        Args:
            new_severity: The new severity level
            reason: Reason for escalation
            user_id: ID of the user performing the escalation

        Raises:
            ValueError: If the severity is invalid or not higher than current
        """
        # Validate severity
        if new_severity not in self.VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {new_severity}")

        # Check if this is an actual escalation
        old_severity = self.severity
        old_severity_index = self.VALID_SEVERITIES.index(old_severity) if old_severity in self.VALID_SEVERITIES else 0
        new_severity_index = self.VALID_SEVERITIES.index(new_severity)

        if new_severity_index <= old_severity_index:
            raise ValueError(f"New severity {new_severity} is not an escalation from {old_severity}")

        self.severity = new_severity
        escalation_note = f"Escalated from {old_severity} to {new_severity}. Reason: {reason}"
        self.add_note(escalation_note, user_id)

        # Update activity timestamp and priority score
        self._record_activity()

        # Record security event
        if user_id:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_INCIDENT_UPDATE,
                description=f"Security incident #{self.id} escalated to {new_severity}",
                user_id=user_id,
                severity='warning',
                object_id=self.id,
                object_type='SecurityIncident',
                details={
                    'old_severity': old_severity,
                    'new_severity': new_severity,
                    'reason': reason[:100] + '...' if len(reason) > 100 else reason
                }
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
        self.resolved_by = user_id

        # Record the change
        fields_changed = ['status', 'resolution', 'resolved_at', 'resolved_by']
        self.log_change(
            fields_changed,
            f"Resolved by user ID {user_id}" if user_id else "Resolved"
        )

        # Update activity timestamp and priority score
        self._record_activity()

        # Track who resolved it if provided
        if user_id:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_COUNTERMEASURE,
                description=f"Security incident #{self.id} resolved",
                user_id=user_id,
                severity='info',
                object_id=self.id,
                object_type='SecurityIncident',
                details={
                    'old_status': old_status,
                    'new_status': self.STATUS_RESOLVED,
                    'resolution': resolution[:100] + '...' if len(resolution) > 100 else resolution
                }
            )

    def reopen(self, reason: str, user_id: Optional[int] = None) -> None:
        """
        Reopen a resolved or closed incident.

        Args:
            reason: Reason for reopening
            user_id: ID of the user reopening the incident

        Raises:
            ValueError: If the incident is not in a resolved or closed state
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

        # Update activity timestamp and priority score
        self._record_activity()

        # Track who reopened it if provided
        if user_id:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_INCIDENT_UPDATE,
                description=f"Security incident #{self.id} reopened",
                user_id=user_id,
                severity='warning',
                object_id=self.id,
                object_type='SecurityIncident',
                details={
                    'old_status': old_status,
                    'new_status': self.STATUS_INVESTIGATING,
                    'reason': reason[:100] + '...' if len(reason) > 100 else reason
                }
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

        # Update activity timestamp and priority score
        self._record_activity()

        # Track who closed it if provided
        if user_id:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_INCIDENT_UPDATE,
                description=f"Security incident #{self.id} closed",
                user_id=user_id,
                severity='info',
                object_id=self.id,
                object_type='SecurityIncident',
                details={
                    'old_status': old_status,
                    'new_status': self.STATUS_CLOSED,
                    'reason': reason[:100] + '...' if reason and len(reason) > 100 else reason
                }
            )

    def merge_into(self, parent_incident_id: int, reason: str, user_id: Optional[int] = None) -> None:
        """
        Merge this incident into another (parent) incident.

        Args:
            parent_incident_id: ID of the parent incident
            reason: Reason for merging
            user_id: ID of the user performing the merge

        Raises:
            ValueError: If parent incident ID is invalid or same as this incident
        """
        if parent_incident_id == self.id:
            raise ValueError("Cannot merge incident into itself")

        # Check if parent incident exists
        parent = SecurityIncident.query.get(parent_incident_id)
        if not parent:
            raise ValueError(f"Parent incident with ID {parent_incident_id} not found")

        old_status = self.status
        self.status = self.STATUS_MERGED
        self.parent_incident_id = parent_incident_id

        # Add merge note
        merge_note = f"Incident merged into #{parent_incident_id}. Reason: {reason}"
        self.add_note(merge_note, user_id)

        # Also add note to parent
        parent_note = f"Incident #{self.id} was merged into this incident. Reason: {reason}"
        parent.add_note(parent_note, user_id)

        # Add this incident's ID to parent's related incidents if not already there
        if parent.related_incidents is None:
            parent.related_incidents = []

        if self.id not in parent.related_incidents:
            parent.related_incidents.append(self.id)

        # Record the change
        fields_changed = ['status', 'parent_incident_id']
        self.log_change(
            fields_changed,
            f"Merged into incident #{parent_incident_id} by user ID {user_id}" if user_id else f"Merged into incident #{parent_incident_id}"
        )

        # Update activity timestamps on both incidents
        self._record_activity()
        parent._record_activity()

        # Track merge action
        if user_id:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_INCIDENT_UPDATE,
                description=f"Security incident #{self.id} merged into #{parent_incident_id}",
                user_id=user_id,
                severity='info',
                object_id=self.id,
                object_type='SecurityIncident',
                details={
                    'old_status': old_status,
                    'new_status': self.STATUS_MERGED,
                    'parent_incident_id': parent_incident_id,
                    'reason': reason[:100] + '...' if len(reason) > 100 else reason
                }
            )

    def add_tag(self, tag: str) -> None:
        """
        Add a tag to the incident for categorization.

        Args:
            tag: Tag to add
        """
        if not self.tags:
            self.tags = []

        # Convert to lowercase for consistency
        tag = tag.strip().lower()

        # Avoid duplicates
        if tag not in self.tags:
            self.tags.append(tag)
            self._record_activity()

    def remove_tag(self, tag: str) -> None:
        """
        Remove a tag from the incident.

        Args:
            tag: Tag to remove
        """
        if not self.tags:
            return

        # Convert to lowercase for consistency
        tag = tag.strip().lower()

        if tag in self.tags:
            self.tags.remove(tag)
            self._record_activity()

    def add_related_incident(self, related_incident_id: int) -> None:
        """
        Add a related incident ID.

        Args:
            related_incident_id: ID of the related incident

        Raises:
            ValueError: If incident ID is invalid or same as this incident
        """
        if related_incident_id == self.id:
            raise ValueError("Cannot add incident as related to itself")

        # Check if related incident exists
        related = SecurityIncident.query.get(related_incident_id)
        if not related:
            raise ValueError(f"Related incident with ID {related_incident_id} not found")

        if not self.related_incidents:
            self.related_incidents = []

        if related_incident_id not in self.related_incidents:
            self.related_incidents.append(related_incident_id)
            self._record_activity()

            # Also add this incident to the related incident's related list
            if not related.related_incidents:
                related.related_incidents = []

            if self.id not in related.related_incidents:
                related.related_incidents.append(self.id)
                related._record_activity()

    def add_affected_resource(self, resource_type: str, resource_id: str,
                            details: Optional[Dict[str, Any]] = None) -> None:
        """
        Add an affected resource to the incident.

        Args:
            resource_type: Type of resource (e.g., 'instance', 'user', 'network')
            resource_id: Identifier for the resource
            details: Additional details about the impact
        """
        if not self.affected_resources:
            self.affected_resources = []

        # Create resource entry
        resource = {
            'resource_type': resource_type,
            'resource_id': resource_id,
            'added_at': datetime.now(timezone.utc).isoformat()
        }

        if details:
            resource['details'] = details

        # Check if resource already exists
        for existing in self.affected_resources:
            if (existing.get('resource_type') == resource_type and
                existing.get('resource_id') == resource_id):
                # Update existing resource
                existing.update(resource)
                self._record_activity()
                return

        # Add new resource
        self.affected_resources.append(resource)
        self._record_activity()

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
    def get_incidents_by_tag(cls, tag: str) -> List['SecurityIncident']:
        """
        Get incidents with the specified tag.

        Args:
            tag: Tag to search for

        Returns:
            List[SecurityIncident]: List of incidents with the tag
        """
        # Lowercase tag for consistency
        tag = tag.strip().lower()

        # Use JSON contains operator based on database dialect
        if db.engine.dialect.name == 'postgresql':
            return cls.query.filter(cls.tags.cast(db.JSON).contains([tag])).order_by(
                desc(cls.created_at)
            ).all()
        elif db.engine.dialect.name == 'mysql':
            # MySQL JSON_CONTAINS requires slightly different syntax
            return cls.query.filter(func.json_contains(cls.tags, func.json_quote(tag))).order_by(
                desc(cls.created_at)
            ).all()
        else:
            # SQLite or others - use string LIKE as fallback
            # This is less accurate but provides basic functionality
            return cls.query.filter(cls.tags.cast(db.String).like(f'%"{tag}"%')).order_by(
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
    def count_by_type(cls) -> Dict[str, int]:
        """
        Count incidents by type.

        Returns:
            Dict[str, int]: Dictionary mapping incident type to count
        """
        result = db.session.query(
            cls.incident_type,
            func.count(cls.id)
        ).group_by(cls.incident_type).all()

        return {incident_type: count for incident_type, count in result}

    @classmethod
    def get_recent_incidents(cls, days: int = 7, limit: int = 100,
                          status: Optional[str] = None,
                          severity: Optional[str] = None) -> List['SecurityIncident']:
        """
        Get recent security incidents within the specified timeframe.

        Args:
            days: Number of days to look back
            limit: Maximum number of incidents to return
            status: Filter by specific status
            severity: Filter by specific severity

        Returns:
            List[SecurityIncident]: List of recent incidents
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        query = cls.query.filter(cls.created_at >= cutoff)

        if status:
            query = query.filter(cls.status == status)

        if severity:
            query = query.filter(cls.severity == severity)

        return query.order_by(desc(cls.created_at)).limit(limit).all()

    @classmethod
    def get_breached_sla_incidents(cls) -> List['SecurityIncident']:
        """
        Get all active incidents that have breached their SLA based on severity.

        Returns:
            List[SecurityIncident]: List of incidents that breached SLA
        """
        current_time = datetime.now(timezone.utc)

        # Build a complex query using case statements to check SLA breaches
        # based on severity and response time requirements
        query = cls.query.filter(
            # Only active incidents
            cls.status.in_([cls.STATUS_OPEN, cls.STATUS_INVESTIGATING]),

            # Check SLA breach based on severity and age
            or_(
                # Critical: > 4 hours
                and_(
                    cls.severity == cls.SEVERITY_CRITICAL,
                    cls.created_at <= current_time - timedelta(hours=4)
                ),
                # High: > 12 hours
                and_(
                    cls.severity == cls.SEVERITY_HIGH,
                    cls.created_at <= current_time - timedelta(hours=12)
                ),
                # Medium: > 36 hours
                and_(
                    cls.severity == cls.SEVERITY_MEDIUM,
                    cls.created_at <= current_time - timedelta(hours=36)
                ),
                # Low: > 96 hours
                and_(
                    cls.severity == cls.SEVERITY_LOW,
                    cls.created_at <= current_time - timedelta(hours=96)
                )
            )
        )

        # Order by severity (most severe first) and then by age (oldest first)
        return query.order_by(
            case({
                cls.SEVERITY_CRITICAL: 0,
                cls.SEVERITY_HIGH: 1,
                cls.SEVERITY_MEDIUM: 2,
                cls.SEVERITY_LOW: 3
            }, value=cls.severity),
            cls.created_at
        ).all()

    @classmethod
    def get_sla_metrics(cls, days: int = 30) -> Dict[str, Any]:
        """
        Calculate SLA metrics for incidents over the specified period.

        Args:
            days: Number of days to analyze

        Returns:
            Dict: Dictionary with SLA metrics
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        # Get all incidents resolved in the time period
        resolved_incidents = cls.query.filter(
            cls.resolved_at >= cutoff
        ).all()

        # Calculate metrics
        total_resolved = len(resolved_incidents)

        sla_met = 0
        resolution_times = []

        for incident in resolved_incidents:
            if incident.time_to_resolution is not None:
                resolution_times.append(incident.time_to_resolution)

                # Check if resolution time was within SLA
                if incident.severity == cls.SEVERITY_CRITICAL and incident.time_to_resolution <= 4:
                    sla_met += 1
                elif incident.severity == cls.SEVERITY_HIGH and incident.time_to_resolution <= 12:
                    sla_met += 1
                elif incident.severity == cls.SEVERITY_MEDIUM and incident.time_to_resolution <= 36:
                    sla_met += 1
                elif incident.severity == cls.SEVERITY_LOW and incident.time_to_resolution <= 96:
                    sla_met += 1

        # Calculate average resolution time
        avg_resolution_time = sum(resolution_times) / len(resolution_times) if resolution_times else 0

        # Calculate SLA compliance percentage
        sla_compliance = (sla_met / total_resolved * 100) if total_resolved > 0 else 100

        return {
            'total_incidents': total_resolved,
            'sla_met': sla_met,
            'sla_breached': total_resolved - sla_met,
            'sla_compliance_percentage': round(sla_compliance, 2),
            'avg_resolution_time_hours': round(avg_resolution_time, 2),
            'period_days': days
        }

    @classmethod
    def search(cls, query: str,
              status: Optional[List[str]] = None,
              severity: Optional[List[str]] = None,
              incident_type: Optional[List[str]] = None,
              days: int = 90,
              limit: int = 100) -> List['SecurityIncident']:
        """
        Search for incidents based on specified criteria.

        Args:
            query: Search text to find in title, description, or details
            status: List of statuses to filter by
            severity: List of severities to filter by
            incident_type: List of incident types to filter by
            days: Number of days to look back
            limit: Maximum number of results to return

        Returns:
            List[SecurityIncident]: Matching incidents
        """
        search_query = cls.query

        # Apply text search if provided
        if query:
            search_query = search_query.filter(
                or_(
                    cls.title.ilike(f'%{query}%'),
                    cls.description.ilike(f'%{query}%'),
                    cls.details.ilike(f'%{query}%'),
                    cls.notes.ilike(f'%{query}%')
                )
            )

        # Apply date filter
        if days > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            search_query = search_query.filter(cls.created_at >= cutoff)

        # Apply status filter
        if status:
            search_query = search_query.filter(cls.status.in_(status))

        # Apply severity filter
        if severity:
            search_query = search_query.filter(cls.severity.in_(severity))

        # Apply incident type filter
        if incident_type:
            search_query = search_query.filter(cls.incident_type.in_(incident_type))

        # Order by relevance (if search query), then by priority
        if query:
            # For complex ranking in PostgreSQL
            if db.engine.dialect.name == 'postgresql':
                # Calculate relevance score
                search_query = search_query.order_by(
                    # Title match is highest priority
                    case([(cls.title.ilike(f'%{query}%'), 3)], else_=0) +
                    # Description match is medium priority
                    case([(cls.description.ilike(f'%{query}%'), 2)], else_=0) +
                    # Details/notes match is lowest priority
                    case([(cls.details.ilike(f'%{query}%'), 1)], else_=0) +
                    case([(cls.notes.ilike(f'%{query}%'), 1)], else_=0),
                    # Then by standard priority factors
                    desc(cls.priority_score),
                    desc(cls.created_at)
                )
            else:
                # For other databases, use simpler sorting
                search_query = search_query.order_by(
                    desc(cls.priority_score),
                    desc(cls.created_at)
                )
        else:
            # Without search query, sort by priority score and recency
            search_query = search_query.order_by(
                desc(cls.priority_score),
                desc(cls.created_at)
            )

        return search_query.limit(limit).all()

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
            'is_active': self.is_active,
            'time_to_resolution': self.time_to_resolution,
            'age_hours': self.age_hours,
            'sla_status': self.sla_status,
            'priority_score': self.priority_score,
            'tags': self.tags or []
        })

        # Ensure datetime fields are properly serialized
        for field in ['resolved_at', 'last_activity_at']:
            if hasattr(self, field) and getattr(self, field):
                data[field] = getattr(self, field).isoformat()

        # Add user information if available
        if self.user:
            data['user'] = {
                'id': self.user.id,
                'username': getattr(self.user, 'username', f'User #{self.user_id}')
            }

        # Add assignee information if available
        if self.assignee:
            data['assignee'] = {
                'id': self.assignee.id,
                'username': getattr(self.assignee, 'username', f'User #{self.assigned_to}')
            }

        # Add resolver information if available
        if self.resolver:
            data['resolver'] = {
                'id': self.resolver.id,
                'username': getattr(self.resolver, 'username', f'User #{self.resolved_by}')
            }

        return data
