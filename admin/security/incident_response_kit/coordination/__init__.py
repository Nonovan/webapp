"""
Incident Response Kit - Coordination Module

This module provides functionality for coordinating incident response activities,
including status tracking, task management, notification systems, and war room coordination.
It serves as a central integration point for various incident response activities.

The coordination module follows the NIST SP 800-61 framework for incident handling
and integrates with other components of the incident response toolkit.
"""

import os
import sys
import logging
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Set, Callable

# Configure logging
logger = logging.getLogger(__name__)

# Import from parent package
try:
    from .. import (
        IncidentStatus, IncidentPhase, IncidentSeverity, IncidentType,
        STATUS_TRANSITIONS, IncidentStatusError, ValidationError,
        CONFIG_AVAILABLE, response_config, sanitize_incident_id
    )
    PARENT_IMPORTS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Failed to import parent package components: {e}")
    PARENT_IMPORTS_AVAILABLE = False

    # Define fallback classes/constants if imports fail
    class IncidentStatus:
        OPEN = "open"
        INVESTIGATING = "investigating"
        CONTAINED = "contained"
        ERADICATED = "eradicated"
        RECOVERING = "recovering"
        RESOLVED = "resolved"
        CLOSED = "closed"
        MERGED = "merged"

    class IncidentPhase:
        IDENTIFICATION = "identification"
        CONTAINMENT = "containment"
        ERADICATION = "eradication"
        RECOVERY = "recovery"
        LESSONS_LEARNED = "lessons_learned"

    class IncidentSeverity:
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"

    class IncidentType:
        MALWARE = "malware"
        DATA_BREACH = "data_breach"
        UNAUTHORIZED_ACCESS = "unauthorized_access"
        DENIAL_OF_SERVICE = "denial_of_service"

    class IncidentStatusError(Exception):
        """Error updating incident status."""
        pass

    class ValidationError(Exception):
        """Error validating incident data."""
        pass

    STATUS_TRANSITIONS = {}
    CONFIG_AVAILABLE = False
    response_config = {}

    def sanitize_incident_id(incident_id: str) -> str:
        """Sanitize incident ID for safety."""
        import re
        return re.sub(r'[^a-zA-Z0-9_\-]', '_', incident_id)

# Determine module base path
MODULE_PATH = Path(os.path.dirname(os.path.abspath(__file__)))

# Import core coordination functions
try:
    from .status_tracker import (
        initialize_incident_status,
        update_incident_status as update_status,
        get_incident_status,
        list_incidents,
        generate_report,
        add_related_incident
    )
    STATUS_TRACKER_AVAILABLE = True
    logger.debug("Status tracker module loaded successfully")
except ImportError as e:
    logger.warning(f"Failed to import status_tracker module: {e}")
    STATUS_TRACKER_AVAILABLE = False

    # Define fallback functions
    def initialize_incident_status(*args, **kwargs):
        raise NotImplementedError("Status tracking not available")

    def update_status(*args, **kwargs):
        raise NotImplementedError("Status tracking not available")

    def get_incident_status(*args, **kwargs):
        raise NotImplementedError("Status tracking not available")

    def list_incidents(*args, **kwargs):
        raise NotImplementedError("Status tracking not available")

    def generate_report(*args, **kwargs):
        raise NotImplementedError("Report generation not available")

    def add_related_incident(*args, **kwargs):
        raise NotImplementedError("Relationship management not available")

try:
    from .notification_system import notify_stakeholders
    NOTIFICATION_SYSTEM_AVAILABLE = True
    logger.debug("Notification system loaded successfully")
except ImportError as e:
    logger.warning(f"Failed to import notification_system module: {e}")
    NOTIFICATION_SYSTEM_AVAILABLE = False

    def notify_stakeholders(*args, **kwargs):
        raise NotImplementedError("Notification system not available")

try:
    from .task_manager import (
        create_task,
        assign_task,
        update_task_status,
        get_task_list
    )
    TASK_MANAGER_AVAILABLE = True
    logger.debug("Task manager loaded successfully")
except ImportError as e:
    logger.warning(f"Failed to import task_manager module: {e}")
    TASK_MANAGER_AVAILABLE = False

    def create_task(*args, **kwargs):
        raise NotImplementedError("Task management not available")

    def assign_task(*args, **kwargs):
        raise NotImplementedError("Task management not available")

    def update_task_status(*args, **kwargs):
        raise NotImplementedError("Task management not available")

    def get_task_list(*args, **kwargs):
        raise NotImplementedError("Task management not available")

try:
    from .war_room import (
        setup_war_room,
        add_participants,
        add_resource,
        archive_war_room
    )
    WAR_ROOM_AVAILABLE = True
    logger.debug("War room module loaded successfully")
except ImportError as e:
    logger.warning(f"Failed to import war_room module: {e}")
    WAR_ROOM_AVAILABLE = False

    def setup_war_room(*args, **kwargs):
        raise NotImplementedError("War room management not available")

    def add_participants(*args, **kwargs):
        raise NotImplementedError("War room management not available")

    def add_resource(*args, **kwargs):
        raise NotImplementedError("War room management not available")

    def archive_war_room(*args, **kwargs):
        raise NotImplementedError("War room management not available")

def track_incident_status(*args, **kwargs):
    """
    Alias for initialize_incident_status to maintain compatibility with parent module.

    This function maintains backward compatibility with code that might call
    track_incident_status from the parent module.
    """
    return initialize_incident_status(*args, **kwargs)

def reopen_incident(
    incident_id: str,
    reason: str,
    user_id: Optional[str] = None,
    phase: str = IncidentPhase.IDENTIFICATION
) -> Dict[str, Any]:
    """
    Reopen a previously closed or resolved security incident.

    This function:
    - Changes the incident status to INVESTIGATING
    - Resets the incident phase (default: IDENTIFICATION)
    - Records the reason for reopening
    - Creates an audit trail entry

    Args:
        incident_id: Unique identifier for the incident to reopen
        reason: Reason for reopening the incident
        user_id: ID or name of user reopening the incident (optional)
        phase: New phase for the incident (defaults to IDENTIFICATION)

    Returns:
        Dict containing results of the reopening operation

    Raises:
        ValidationError: If incident_id or reason is invalid
        IncidentStatusError: If incident status can't be changed (not resolved/closed)
    """
    if not incident_id:
        raise ValidationError("Incident ID is required")

    if not reason:
        raise ValidationError("Reason for reopening is required")

    if not STATUS_TRACKER_AVAILABLE:
        raise NotImplementedError("Status tracker not available for reopening incidents")

    try:
        # Get current incident status
        incident_data = get_incident_status(incident_id)

        if not incident_data:
            raise IncidentStatusError(f"Incident {incident_id} not found")

        current_status = incident_data.get("status")

        # Check if incident can be reopened (must be resolved or closed)
        if current_status not in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
            raise IncidentStatusError(
                f"Cannot reopen incident with status '{current_status}'. "
                f"Only incidents with status '{IncidentStatus.RESOLVED}' or '{IncidentStatus.CLOSED}' can be reopened."
            )

        # Update the incident status to investigating
        status_updated = update_status(
            incident_id=incident_id,
            status=IncidentStatus.INVESTIGATING,
            phase=phase,
            notes=f"Incident reopened: {reason}",
            user=user_id
        )

        if not status_updated:
            raise IncidentStatusError(f"Failed to update status for incident {incident_id}")

        logger.info(f"Successfully reopened incident {incident_id}")

        return {
            "success": True,
            "incident_id": incident_id,
            "new_status": IncidentStatus.INVESTIGATING,
            "new_phase": phase,
            "reason": reason,
            "reopened_by": user_id
        }

    except Exception as e:
        if isinstance(e, (ValidationError, IncidentStatusError)):
            # Re-raise these specific exceptions
            raise
        else:
            # Convert other exceptions to IncidentStatusError
            logger.error(f"Error reopening incident {incident_id}: {e}", exc_info=True)
            raise IncidentStatusError(f"Failed to reopen incident: {str(e)}")

# Check available components
def get_available_components() -> Dict[str, bool]:
    """Return a dictionary indicating which coordination components are available."""
    return {
        "status_tracker": STATUS_TRACKER_AVAILABLE,
        "notification_system": NOTIFICATION_SYSTEM_AVAILABLE,
        "task_manager": TASK_MANAGER_AVAILABLE,
        "war_room": WAR_ROOM_AVAILABLE
    }

# Public exports
__all__ = [
    # Status tracking functions
    'initialize_incident_status',
    'update_status',
    'get_incident_status',
    'list_incidents',
    'generate_report',
    'add_related_incident',
    'track_incident_status',

    # Incident management functions
    'reopen_incident',

    # Notification functions
    'notify_stakeholders',

    # Task management functions
    'create_task',
    'assign_task',
    'update_task_status',
    'get_task_list',

    # War room functions
    'setup_war_room',
    'add_participants',
    'add_resource',
    'archive_war_room',

    # Utility functions
    'get_available_components',
]

# Log initialization status
available_components = get_available_components()
logger.info(f"Incident Response Coordination module loaded")
logger.debug(f"Available components: {', '.join([k for k, v in available_components.items() if v])}")
