"""
Incident Response Toolkit - Incident Model

This module provides a lightweight incident model for use in the incident response toolkit.
Unlike the full database model in models.security.security_incident, this model is designed
for toolkit operations and doesn't require a database connection.

The model follows the NIST SP 800-61 incident handling framework and provides basic
functionality for tracking incident details and actions throughout the response process.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from .incident_constants import (
    IncidentStatus,
    IncidentPhase,
    IncidentSeverity,
    IncidentType,
    PHASE_STATUS_MAPPING,
    STATUS_TRANSITIONS
)


class Incident:
    """
    Represents a security incident for tracking purposes within the toolkit.

    This is a lightweight version of the incident model that doesn't rely on
    database connectivity, designed for use in the incident response toolkit.
    """

    def __init__(
        self,
        incident_id: str,
        incident_type: str,
        severity: str = IncidentSeverity.MEDIUM,
        status: str = IncidentStatus.OPEN,
        lead_responder: Optional[str] = None,
        description: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize a new incident.

        Args:
            incident_id: Unique identifier for the incident
            incident_type: Type of incident (see IncidentType constants)
            severity: Severity level (critical, high, medium, low)
            status: Current status (open, investigating, etc.)
            lead_responder: Email or identifier for the lead responder
            description: Brief description of the incident
            **kwargs: Additional metadata for the incident
        """
        # Validate inputs
        if incident_type not in IncidentType.VALID_TYPES:
            raise ValueError(f"Invalid incident type: {incident_type}")
        if severity not in IncidentSeverity.VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")
        if status not in IncidentStatus.VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}")

        # Set core attributes
        self.id = incident_id
        self.incident_type = incident_type
        self.severity = severity
        self.status = status
        self.lead_responder = lead_responder
        self.description = description
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = self.created_at
        self.current_phase = IncidentPhase.IDENTIFICATION

        # Additional metadata
        self.metadata = kwargs

        # Action tracking
        self.actions = []

    def add_action(self, action: str, user: str, details: Optional[Dict[str, Any]] = None):
        """
        Record an action taken during the incident response.

        Args:
            action: Description of the action taken
            user: User who performed the action
            details: Additional details about the action
        """
        self.actions.append({
            'timestamp': datetime.now(timezone.utc),
            'action': action,
            'user': user,
            'details': details or {}
        })
        self.updated_at = datetime.now(timezone.utc)

    def update_status(self, status: str, user: str, notes: Optional[str] = None):
        """
        Update the incident status.

        Args:
            status: New status for the incident
            user: User making the status change
            notes: Optional notes about the status change

        Raises:
            ValueError: If status is invalid
            ValueError: If transition is not allowed
        """
        # Validate status
        if status not in IncidentStatus.VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}")

        # Check if transition is allowed
        if status != self.status:
            allowed_transitions = STATUS_TRANSITIONS.get(self.status, [])
            if status not in allowed_transitions:
                raise ValueError(
                    f"Invalid status transition from '{self.status}' to '{status}'. "
                    f"Allowed transitions: {', '.join(allowed_transitions)}"
                )

        old_status = self.status
        self.status = status
        self.updated_at = datetime.now(timezone.utc)

        # Record the action
        self.add_action(
            action="status_change",
            user=user,
            details={
                'old_status': old_status,
                'new_status': status,
                'notes': notes
            }
        )

    def update_phase(self, phase: str, user: str, notes: Optional[str] = None):
        """
        Update the incident phase.

        Args:
            phase: New phase for the incident
            user: User making the phase change
            notes: Optional notes about the phase change

        Raises:
            ValueError: If phase is invalid
        """
        # Validate phase
        if phase not in IncidentPhase.VALID_PHASES:
            raise ValueError(f"Invalid phase: {phase}")

        old_phase = self.current_phase
        self.current_phase = phase
        self.updated_at = datetime.now(timezone.utc)

        # Record the action
        self.add_action(
            action="phase_change",
            user=user,
            details={
                'old_phase': old_phase,
                'new_phase': phase,
                'notes': notes
            }
        )

        # Suggest status change based on phase if applicable
        recommended_statuses = PHASE_STATUS_MAPPING.get(phase, [])
        if recommended_statuses and self.status not in recommended_statuses:
            self.add_action(
                action="status_recommendation",
                user="system",
                details={
                    'recommended_statuses': recommended_statuses,
                    'current_status': self.status,
                    'reason': f"Based on phase change to {phase}"
                }
            )

    def add_note(self, note: str, user: str):
        """
        Add a note to the incident.

        Args:
            note: Content of the note
            user: User adding the note
        """
        self.add_action(
            action="note_added",
            user=user,
            details={'note': note}
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the incident to a dictionary representation.

        Returns:
            Dictionary with incident data
        """
        return {
            'id': self.id,
            'incident_type': self.incident_type,
            'severity': self.severity,
            'status': self.status,
            'current_phase': self.current_phase,
            'lead_responder': self.lead_responder,
            'description': self.description,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'actions': self.actions,
            'metadata': self.metadata
        }
