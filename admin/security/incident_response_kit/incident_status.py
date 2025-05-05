"""
Security Incident Response Models

This module provides data models and constants for security incident response management,
defining the structure for incident tracking across the incident response lifecycle.
The models follow the NIST SP 800-61 incident handling framework and provide a foundation
for managing incidents from identification through resolution.

Key components:
- Status and phase constants for incident lifecycle tracking
- Severity level definitions for incident prioritization
- Incident type categorization for proper response selection
- Incident model for core incident data storage and management

These models integrate with the incident response toolkit to provide consistent structure
and typing across all incident response activities and maintain a single source of truth
for incident metadata.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum, auto
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey, Boolean, JSON
from sqlalchemy.ext.hybrid import hybrid_property
from extensions import db
from models.base import BaseModel, AuditableMixin


# ======= Status and Phase Constants =======

class IncidentStatus:
    """Constants defining the possible status values for a security incident."""
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERING = "recovering"
    RESOLVED = "resolved"
    CLOSED = "closed"
    MERGED = "merged"

    # All valid statuses
    VALID_STATUSES = [OPEN, INVESTIGATING, CONTAINED, ERADICATED,
                      RECOVERING, RESOLVED, CLOSED, MERGED]

    # Status categories
    ACTIVE_STATUSES = [OPEN, INVESTIGATING, CONTAINED, ERADICATED, RECOVERING]
    TERMINAL_STATUSES = [RESOLVED, CLOSED, MERGED]


class IncidentPhase:
    """Constants defining the phases of the security incident response lifecycle."""
    IDENTIFICATION = "identification"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    LESSONS_LEARNED = "lessons_learned"

    # All valid phases
    VALID_PHASES = [IDENTIFICATION, CONTAINMENT, ERADICATION, RECOVERY, LESSONS_LEARNED]


class IncidentSeverity:
    """Constants defining the severity levels for security incidents."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    # All valid severity levels
    VALID_SEVERITIES = [CRITICAL, HIGH, MEDIUM, LOW]

    # SLA hours by severity
    SLA_HOURS = {
        CRITICAL: 1,    # 1 hour
        HIGH: 4,        # 4 hours
        MEDIUM: 24,     # 24 hours
        LOW: 72         # 72 hours
    }


class IncidentType:
    """Constants defining the types of security incidents."""
    MALWARE = "malware"
    DATA_BREACH = "data_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DENIAL_OF_SERVICE = "denial_of_service"
    WEB_APPLICATION_ATTACK = "web_application_attack"
    ACCOUNT_COMPROMISE = "account_compromise"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INSIDER_THREAT = "insider_threat"
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"

    # All valid incident types
    VALID_TYPES = [
        MALWARE, DATA_BREACH, UNAUTHORIZED_ACCESS, DENIAL_OF_SERVICE,
        WEB_APPLICATION_ATTACK, ACCOUNT_COMPROMISE, PRIVILEGE_ESCALATION,
        INSIDER_THREAT, RANSOMWARE, PHISHING
    ]

    # Categorization of incident types
    CATEGORIES = {
        "malicious_code": [MALWARE, RANSOMWARE],
        "unauthorized_access": [UNAUTHORIZED_ACCESS, ACCOUNT_COMPROMISE, PRIVILEGE_ESCALATION],
        "availability": [DENIAL_OF_SERVICE],
        "web_attacks": [WEB_APPLICATION_ATTACK],
        "data_security": [DATA_BREACH],
        "internal_threats": [INSIDER_THREAT],
        "social_engineering": [PHISHING]
    }


# ======= Phase-Status Mapping =======

# Mapping between incident phases and allowed statuses
PHASE_STATUS_MAPPING = {
    IncidentPhase.IDENTIFICATION: [IncidentStatus.OPEN, IncidentStatus.INVESTIGATING],
    IncidentPhase.CONTAINMENT: [IncidentStatus.CONTAINED, IncidentStatus.INVESTIGATING],
    IncidentPhase.ERADICATION: [IncidentStatus.ERADICATED, IncidentStatus.CONTAINED],
    IncidentPhase.RECOVERY: [IncidentStatus.RECOVERING, IncidentStatus.RESOLVED],
    IncidentPhase.LESSONS_LEARNED: [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]
}

# Status progression (allowed transitions)
STATUS_TRANSITIONS = {
    IncidentStatus.OPEN: [IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED, IncidentStatus.MERGED],
    IncidentStatus.INVESTIGATING: [IncidentStatus.CONTAINED, IncidentStatus.OPEN, IncidentStatus.CLOSED, IncidentStatus.MERGED],
    IncidentStatus.CONTAINED: [IncidentStatus.ERADICATED, IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED, IncidentStatus.MERGED],
    IncidentStatus.ERADICATED: [IncidentStatus.RECOVERING, IncidentStatus.CONTAINED, IncidentStatus.CLOSED, IncidentStatus.MERGED],
    IncidentStatus.RECOVERING: [IncidentStatus.RESOLVED, IncidentStatus.ERADICATED, IncidentStatus.CLOSED, IncidentStatus.MERGED],
    IncidentStatus.RESOLVED: [IncidentStatus.CLOSED, IncidentStatus.INVESTIGATING, IncidentStatus.MERGED],
    IncidentStatus.CLOSED: [IncidentStatus.INVESTIGATING],  # Can be reopened if needed
    IncidentStatus.MERGED: []  # Terminal state, cannot transition out
}


# ======= Incident Model =======

class Incident(BaseModel, AuditableMixin):
    """
    Model representing a security incident within the organization.

    This model tracks security incidents through their lifecycle from detection to resolution,
    following the NIST SP 800-61 incident handling process. It maintains a detailed audit trail
    of all incident-related actions and state changes.
    """
    __tablename__ = 'security_incidents'

    # Define security-critical fields for AuditableMixin
    SECURITY_CRITICAL_FIELDS = ['status', 'severity', 'phase', 'resolution']
    AUDIT_ACCESS = True

    # Primary key
    id = Column(Integer, primary_key=True)

    # Core incident fields
    incident_id = Column(String(50), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    incident_type = Column(String(50), nullable=False, index=True)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default=IncidentSeverity.MEDIUM, index=True)
    status = Column(String(20), nullable=False, default=IncidentStatus.OPEN, index=True)
    phase = Column(String(20), nullable=False, default=IncidentPhase.IDENTIFICATION, index=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    closed_at = Column(DateTime(timezone=True), nullable=True)

    # Attribution and assignment
    reported_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    lead_responder = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    assigned_team = Column(String(50), nullable=True)

    # Resolution details
    resolution = Column(Text, nullable=True)
    root_cause = Column(Text, nullable=True)
    resolved_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    # Additional details
    affected_systems = Column(JSON, nullable=True)
    affected_users = Column(JSON, nullable=True)
    related_incidents = Column(JSON, nullable=True)
    parent_incident_id = Column(Integer, ForeignKey('security_incidents.id'), nullable=True)
    tags = Column(JSON, nullable=True)

    # Tracking data
    action_history = Column(JSON, nullable=True)
    sla_breach = Column(Boolean, default=False)
    priority_score = Column(Integer, default=0)

    # Relationships
    reporter = db.relationship('User', foreign_keys=[reported_by],
                              backref=db.backref('reported_incidents', lazy='dynamic'))
    responder = db.relationship('User', foreign_keys=[lead_responder],
                               backref=db.backref('assigned_incidents', lazy='dynamic'))
    resolver = db.relationship('User', foreign_keys=[resolved_by],
                              backref=db.backref('resolved_incidents', lazy='dynamic'))
    parent_incident = db.relationship('Incident', remote_side=[id],
                                    backref=db.backref('child_incidents', lazy='dynamic'))

    def __init__(self, incident_id: str, title: str, incident_type: str,
                severity: str = IncidentSeverity.MEDIUM,
                status: str = IncidentStatus.OPEN, phase: str = IncidentPhase.IDENTIFICATION,
                description: Optional[str] = None, reported_by: Optional[int] = None,
                lead_responder: Optional[int] = None, **kwargs):
        """
        Initialize a new security incident.

        Args:
            incident_id: Unique tracking identifier for the incident
            title: Brief title summarizing the incident
            incident_type: Type of incident (see IncidentType constants)
            severity: Severity level (critical, high, medium, low)
            status: Current status (open, investigating, etc.)
            phase: Current phase in the incident lifecycle
            description: Detailed description of the incident
            reported_by: User ID of the person who reported the incident
            lead_responder: User ID of the person leading the response
            **kwargs: Additional incident attributes
        """
        # Validate inputs
        if not incident_id:
            raise ValueError("Incident ID is required")
        if not title:
            raise ValueError("Title is required")
        if incident_type not in IncidentType.VALID_TYPES:
            raise ValueError(f"Invalid incident type: {incident_type}")
        if severity not in IncidentSeverity.VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")
        if status not in IncidentStatus.VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}")
        if phase not in IncidentPhase.VALID_PHASES:
            raise ValueError(f"Invalid phase: {phase}")

        # Set core attributes
        self.incident_id = incident_id
        self.title = title
        self.incident_type = incident_type
        self.severity = severity
        self.status = status
        self.phase = phase
        self.description = description
        self.reported_by = reported_by
        self.lead_responder = lead_responder

        # Initialize tracking
        now = datetime.now(timezone.utc)
        self.created_at = now
        self.updated_at = now
        self.action_history = [{
            "timestamp": now.isoformat(),
            "action": "created",
            "user_id": reported_by,
            "details": {
                "type": incident_type,
                "severity": severity
            }
        }]

        # Set additional attributes
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

        # Calculate initial priority score
        self._update_priority_score()

    @hybrid_property
    def is_active(self) -> bool:
        """Check if the incident is currently active."""
        return self.status in IncidentStatus.ACTIVE_STATUSES

    @hybrid_property
    def is_resolved(self) -> bool:
        """Check if the incident has been marked as resolved."""
        return self.status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]

    @hybrid_property
    def age_hours(self) -> int:
        """Calculate the age of the incident in hours."""
        if self.created_at:
            delta = datetime.now(timezone.utc) - self.created_at
            return int(delta.total_seconds() / 3600)
        return 0

    @hybrid_property
    def time_to_resolution(self) -> Optional[int]:
        """Calculate the time to resolution in hours if the incident is resolved."""
        if self.resolved_at and self.created_at:
            delta = self.resolved_at - self.created_at
            return int(delta.total_seconds() / 3600)
        return None

    @hybrid_property
    def sla_status(self) -> str:
        """
        Get the SLA status for this incident based on severity and age.

        Returns:
            'within_sla', 'at_risk', or 'breached'
        """
        if not self.is_active:
            return "within_sla"

        age = self.age_hours
        sla_hours = IncidentSeverity.SLA_HOURS.get(self.severity, 72)

        if age <= sla_hours * 0.75:  # Within 75% of SLA
            return "within_sla"
        elif age <= sla_hours:  # Between 75% and 100% of SLA
            return "at_risk"
        else:  # Beyond SLA
            # Update SLA breach flag if not already set
            if not self.sla_breach:
                self.sla_breach = True
                self._add_to_history("sla_breached", None, {
                    "severity": self.severity,
                    "age_hours": age,
                    "sla_hours": sla_hours
                })
            return "breached"

    def _update_priority_score(self) -> None:
        """
        Calculate a priority score based on severity, age, and status.

        This score is used for sorting incidents by priority with higher numbers
        indicating higher priority incidents.
        """
        # Base score from severity
        severity_scores = {
            IncidentSeverity.CRITICAL: 1000,
            IncidentSeverity.HIGH: 750,
            IncidentSeverity.MEDIUM: 500,
            IncidentSeverity.LOW: 250
        }
        base_score = severity_scores.get(self.severity, 500)

        # Factor in status
        status_multipliers = {
            IncidentStatus.OPEN: 1.0,
            IncidentStatus.INVESTIGATING: 0.9,
            IncidentStatus.CONTAINED: 0.8,
            IncidentStatus.ERADICATED: 0.7,
            IncidentStatus.RECOVERING: 0.6,
            IncidentStatus.RESOLVED: 0.3,
            IncidentStatus.CLOSED: 0.1,
            IncidentStatus.MERGED: 0.1
        }
        status_multiplier = status_multipliers.get(self.status, 1.0)

        # Factor in age for active incidents (newer = higher priority within same severity)
        age_factor = 0
        if self.is_active and self.created_at:
            age_hours = self.age_hours
            # SLA-based urgency factor
            sla_hours = IncidentSeverity.SLA_HOURS.get(self.severity, 72)

            if age_hours >= sla_hours:  # Beyond SLA
                age_factor = 200
            elif age_hours >= sla_hours * 0.75:  # Approaching SLA
                age_factor = 150
            elif age_hours >= sla_hours * 0.5:  # Halfway to SLA
                age_factor = 100
            else:
                age_factor = 50

        self.priority_score = int((base_score * status_multiplier) + age_factor)

    def _add_to_history(self, action: str, user_id: Optional[int], details: Dict) -> None:
        """Add an action to the incident history."""
        if self.action_history is None:
            self.action_history = []

        self.action_history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "user_id": user_id,
            "details": details
        })

        # Update modified timestamp
        self.updated_at = datetime.now(timezone.utc)

        # Recalculate priority after changes
        self._update_priority_score()

    def assign(self, responder_id: int, assigner_id: Optional[int] = None, team: Optional[str] = None) -> None:
        """
        Assign the incident to a lead responder and optionally a team.

        Args:
            responder_id: User ID of the assigned responder
            assigner_id: User ID making the assignment
            team: Team being assigned to the incident
        """
        old_responder = self.lead_responder
        old_team = self.assigned_team

        self.lead_responder = responder_id
        if team:
            self.assigned_team = team

        # Add to history
        self._add_to_history("assigned", assigner_id, {
            "old_responder": old_responder,
            "new_responder": responder_id,
            "old_team": old_team,
            "new_team": team
        })

        # If incident is newly opened, move it to investigating
        if self.status == IncidentStatus.OPEN:
            self.change_status(IncidentStatus.INVESTIGATING, "Auto-updated on assignment", assigner_id)

    def change_status(self, new_status: str, reason: str, user_id: Optional[int] = None) -> None:
        """
        Change the incident status.

        Args:
            new_status: New status to set
            reason: Reason for the status change
            user_id: ID of the user making the change

        Raises:
            ValueError: If the status transition is invalid
        """
        if new_status not in IncidentStatus.VALID_STATUSES:
            raise ValueError(f"Invalid status: {new_status}")

        # Prevent invalid transitions
        if new_status != self.status and self.status != IncidentStatus.MERGED:
            allowed_transitions = STATUS_TRANSITIONS.get(self.status, [])
            if new_status not in allowed_transitions:
                raise ValueError(
                    f"Invalid status transition from '{self.status}' to '{new_status}'. "
                    f"Allowed transitions: {', '.join(allowed_transitions)}"
                )

        old_status = self.status
        self.status = new_status

        # Update special timestamps
        now = datetime.now(timezone.utc)
        if new_status == IncidentStatus.RESOLVED:
            self.resolved_at = now
        elif new_status == IncidentStatus.CLOSED:
            self.closed_at = now

        # Update history
        self._add_to_history("status_change", user_id, {
            "old_status": old_status,
            "new_status": new_status,
            "reason": reason
        })

    def change_phase(self, new_phase: str, reason: str, user_id: Optional[int] = None) -> None:
        """
        Change the incident response phase.

        Args:
            new_phase: New phase to set
            reason: Reason for the phase change
            user_id: ID of the user making the change

        Raises:
            ValueError: If the phase is invalid
        """
        if new_phase not in IncidentPhase.VALID_PHASES:
            raise ValueError(f"Invalid phase: {new_phase}")

        old_phase = self.phase
        self.phase = new_phase

        # Update history
        self._add_to_history("phase_change", user_id, {
            "old_phase": old_phase,
            "new_phase": new_phase,
            "reason": reason
        })

        # Suggest status change based on phase if still in earlier status
        recommended_statuses = PHASE_STATUS_MAPPING.get(new_phase, [])
        if recommended_statuses and self.status not in recommended_statuses:
            # Only suggest if current status is earlier in the lifecycle
            current_idx = IncidentStatus.VALID_STATUSES.index(self.status) if self.status in IncidentStatus.VALID_STATUSES else -1
            for status in recommended_statuses:
                new_idx = IncidentStatus.VALID_STATUSES.index(status) if status in IncidentStatus.VALID_STATUSES else -1
                if new_idx > current_idx:
                    # Higher index = later in lifecycle
                    self._add_to_history("status_recommendation", None, {
                        "recommended_status": status,
                        "current_status": self.status,
                        "based_on_phase": new_phase
                    })
                    break

    def escalate(self, new_severity: str, reason: str, user_id: Optional[int] = None) -> None:
        """
        Escalate the incident to a higher severity level.

        Args:
            new_severity: New severity level
            reason: Reason for escalation
            user_id: ID of the user performing the escalation

        Raises:
            ValueError: If the severity is invalid or not an escalation
        """
        if new_severity not in IncidentSeverity.VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {new_severity}")

        # Ensure this is actually an escalation
        sev_ranks = {
            IncidentSeverity.LOW: 1,
            IncidentSeverity.MEDIUM: 2,
            IncidentSeverity.HIGH: 3,
            IncidentSeverity.CRITICAL: 4
        }

        current_rank = sev_ranks.get(self.severity, 0)
        new_rank = sev_ranks.get(new_severity, 0)

        if new_rank <= current_rank:
            raise ValueError(f"New severity '{new_severity}' is not an escalation from '{self.severity}'")

        old_severity = self.severity
        self.severity = new_severity

        # Update history
        self._add_to_history("escalated", user_id, {
            "old_severity": old_severity,
            "new_severity": new_severity,
            "reason": reason
        })

        # Re-evaluate priority score after escalation
        self._update_priority_score()

    def add_note(self, note: str, user_id: Optional[int] = None) -> None:
        """
        Add a note to the incident history.

        Args:
            note: The note text to add
            user_id: ID of the user adding the note
        """
        self._add_to_history("note_added", user_id, {
            "note": note
        })

    def resolve(self, resolution: str, root_cause: Optional[str] = None, user_id: Optional[int] = None) -> None:
        """
        Mark the incident as resolved with resolution details.

        Args:
            resolution: Description of how the incident was resolved
            root_cause: Identified root cause of the incident
            user_id: ID of the user resolving the incident
        """
        if not resolution:
            raise ValueError("Resolution description is required")

        self.resolution = resolution
        if root_cause:
            self.root_cause = root_cause
        self.resolved_at = datetime.now(timezone.utc)
        self.resolved_by = user_id

        # Change status if not already resolved/closed
        if self.status not in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
            self.change_status(IncidentStatus.RESOLVED, f"Resolved: {resolution}", user_id)

        # Add resolution to history
        self._add_to_history("resolved", user_id, {
            "resolution": resolution,
            "root_cause": root_cause
        })

    def reopen(self, reason: str, user_id: Optional[int] = None) -> None:
        """
        Reopen a previously resolved or closed incident.

        Args:
            reason: Reason for reopening the incident
            user_id: ID of the user reopening the incident

        Raises:
            ValueError: If incident is not in a resolved or closed state
        """
        if self.status not in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
            raise ValueError(f"Cannot reopen incident with status {self.status}")

        old_status = self.status

        # Reset resolution fields
        self.resolved_at = None

        # Set to investigating status
        self.change_status(IncidentStatus.INVESTIGATING, f"Reopened: {reason}", user_id)

        # Add reopen action to history
        self._add_to_history("reopened", user_id, {
            "old_status": old_status,
            "reason": reason
        })

    def close(self, reason: Optional[str] = None, user_id: Optional[int] = None) -> None:
        """
        Close the incident (final state).

        Args:
            reason: Optional reason for closure
            user_id: ID of the user closing the incident

        Raises:
            ValueError: If the incident is not in a resolved state
        """
        # Typically incidents should be resolved before closing
        if self.status != IncidentStatus.RESOLVED and self.status != IncidentStatus.CLOSED:
            raise ValueError(f"Incident should be resolved before closing (current status: {self.status})")

        close_reason = reason or "Incident review complete"
        self.change_status(IncidentStatus.CLOSED, close_reason, user_id)
        self.closed_at = datetime.now(timezone.utc)

        # Add close action to history
        self._add_to_history("closed", user_id, {
            "reason": close_reason
        })

    def add_affected_system(self, system_id: str, system_name: Optional[str] = None, impact: Optional[str] = None) -> None:
        """
        Add an affected system to the incident.

        Args:
            system_id: Identifier of the affected system
            system_name: Descriptive name of the system
            impact: Description of the impact on this system
        """
        if self.affected_systems is None:
            self.affected_systems = []

        # Check for existing entry
        for system in self.affected_systems:
            if system.get('id') == system_id:
                # Update existing entry
                system.update({
                    'name': system_name or system.get('name'),
                    'impact': impact or system.get('impact'),
                    'updated_at': datetime.now(timezone.utc).isoformat()
                })
                return

        # Add new system
        self.affected_systems.append({
            'id': system_id,
            'name': system_name,
            'impact': impact,
            'added_at': datetime.now(timezone.utc).isoformat()
        })

        self._add_to_history("system_added", None, {
            "system_id": system_id,
            "system_name": system_name
        })

    def relate_to(self, related_incident_id: int, relationship_type: str = "related") -> None:
        """
        Create a relationship with another incident.

        Args:
            related_incident_id: ID of the related incident
            relationship_type: Type of relationship (related, parent, child, duplicate)

        Raises:
            ValueError: If the relationship is invalid
        """
        if related_incident_id == self.id:
            raise ValueError("Cannot relate an incident to itself")

        valid_types = ["related", "parent", "child", "duplicate", "supersedes", "superseded_by"]
        if relationship_type not in valid_types:
            raise ValueError(f"Invalid relationship type: {relationship_type}")

        if self.related_incidents is None:
            self.related_incidents = []

        # Check if relationship already exists
        for rel in self.related_incidents:
            if rel.get('incident_id') == related_incident_id:
                rel['relationship_type'] = relationship_type
                rel['updated_at'] = datetime.now(timezone.utc).isoformat()
                return

        # Add new relationship
        self.related_incidents.append({
            'incident_id': related_incident_id,
            'relationship_type': relationship_type,
            'created_at': datetime.now(timezone.utc).isoformat()
        })

        self._add_to_history("relationship_added", None, {
            "related_incident_id": related_incident_id,
            "relationship_type": relationship_type
        })

    def merge_into(self, parent_incident_id: int, reason: str, user_id: Optional[int] = None) -> None:
        """
        Merge this incident into another parent incident.

        Args:
            parent_incident_id: ID of the parent incident
            reason: Reason for merging
            user_id: ID of the user performing the merge

        Raises:
            ValueError: If the parent incident ID is invalid
        """
        if parent_incident_id == self.id:
            raise ValueError("Cannot merge incident into itself")

        # Change status to merged
        self.parent_incident_id = parent_incident_id
        self.change_status(IncidentStatus.MERGED, f"Merged into incident #{parent_incident_id}: {reason}", user_id)

        # Create relationship
        self.relate_to(parent_incident_id, "merged_into")

        self._add_to_history("merged", user_id, {
            "parent_incident_id": parent_incident_id,
            "reason": reason
        })

    def add_tag(self, tag: str) -> None:
        """
        Add a tag to the incident.

        Args:
            tag: Tag to add (will be normalized)
        """
        if self.tags is None:
            self.tags = []

        # Normalize tag
        tag = tag.strip().lower()

        # Check if tag already exists
        if tag not in self.tags:
            self.tags.append(tag)
            self._add_to_history("tag_added", None, {"tag": tag})

    def remove_tag(self, tag: str) -> None:
        """
        Remove a tag from the incident.

        Args:
            tag: Tag to remove
        """
        if self.tags is None:
            return

        tag = tag.strip().lower()
        if tag in self.tags:
            self.tags.remove(tag)
            self._add_to_history("tag_removed", None, {"tag": tag})

    def to_dict(self) -> Dict[str, Any]:
        """Convert the incident to a dictionary representation."""
        data = {
            'id': self.id,
            'incident_id': self.incident_id,
            'title': self.title,
            'description': self.description,
            'incident_type': self.incident_type,
            'severity': self.severity,
            'status': self.status,
            'phase': self.phase,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'closed_at': self.closed_at.isoformat() if self.closed_at else None,
            'reported_by': self.reported_by,
            'lead_responder': self.lead_responder,
            'assigned_team': self.assigned_team,
            'resolution': self.resolution,
            'root_cause': self.root_cause,
            'resolved_by': self.resolved_by,
            'affected_systems': self.affected_systems,
            'affected_users': self.affected_users,
            'related_incidents': self.related_incidents,
            'parent_incident_id': self.parent_incident_id,
            'tags': self.tags,
            'is_active': self.is_active,
            'is_resolved': self.is_resolved,
            'age_hours': self.age_hours,
            'time_to_resolution': self.time_to_resolution,
            'sla_status': self.sla_status,
            'sla_breach': self.sla_breach,
            'priority_score': self.priority_score
        }

        # Add history if present
        if self.action_history:
            data['action_history'] = self.action_history

        # Add user info for related users
        if hasattr(self, 'reporter') and self.reporter:
            data['reporter_name'] = self.reporter.username

        if hasattr(self, 'responder') and self.responder:
            data['responder_name'] = self.responder.username

        if hasattr(self, 'resolver') and self.resolver:
            data['resolver_name'] = self.resolver.username

        return data

    @classmethod
    def get_open_incidents(cls) -> List['Incident']:
        """Get all currently open incidents."""
        return cls.query.filter(
            cls.status.in_(IncidentStatus.ACTIVE_STATUSES)
        ).order_by(
            cls.priority_score.desc()
        ).all()

    @classmethod
    def get_incidents_by_severity(cls, severity: str) -> List['Incident']:
        """Get incidents with the specified severity."""
        return cls.query.filter_by(severity=severity).order_by(
            cls.priority_score.desc()
        ).all()

    @classmethod
    def get_incidents_by_type(cls, incident_type: str) -> List['Incident']:
        """Get incidents of the specified type."""
        return cls.query.filter_by(incident_type=incident_type).order_by(
            cls.priority_score.desc()
        ).all()

    @classmethod
    def get_sla_breached_incidents(cls) -> List['Incident']:
        """Get incidents that have breached their SLA."""
        return cls.query.filter(
            cls.status.in_(IncidentStatus.ACTIVE_STATUSES),
            cls.sla_breach == True
        ).order_by(
            cls.severity.desc(),
            cls.created_at.asc()
        ).all()

    @classmethod
    def get_recent_incidents(cls, days: int = 30) -> List['Incident']:
        """Get incidents updated in the past specified number of days."""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        return cls.query.filter(
            cls.updated_at >= cutoff_date
        ).order_by(
            cls.updated_at.desc()
        ).all()

    @classmethod
    def search(cls, query: str, **filters) -> List['Incident']:
        """
        Search for incidents by text and filters.

        Args:
            query: Text to search for
            **filters: Additional filter parameters

        Returns:
            List of matching incidents
        """
        search_query = cls.query

        # Text search across multiple fields
        if query:
            search_query = search_query.filter(
                db.or_(
                    cls.incident_id.ilike(f'%{query}%'),
                    cls.title.ilike(f'%{query}%'),
                    cls.description.ilike(f'%{query}%')
                )
            )

        # Apply filters
        for field, value in filters.items():
            if hasattr(cls, field) and value is not None:
                if isinstance(value, list):
                    search_query = search_query.filter(getattr(cls, field).in_(value))
                else:
                    search_query = search_query.filter(getattr(cls, field) == value)

        # Time-based filters
        if 'since' in filters and filters['since']:
            days = int(filters['since'])
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            search_query = search_query.filter(cls.created_at >= cutoff)

        # Order by priority and recency
        return search_query.order_by(
            cls.priority_score.desc(),
            cls.updated_at.desc()
        ).all()

# Module exports
__all__ = [
    'IncidentStatus',
    'IncidentPhase',
    'IncidentSeverity',
    'IncidentType',
    'PHASE_STATUS_MAPPING',
    'STATUS_TRANSITIONS',
    'Incident'
]
