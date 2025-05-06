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
        generate_report as generate_status_report,
        add_related_incident,
        reopen_incident
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

    def generate_status_report(*args, **kwargs):
        raise NotImplementedError("Report generation not available")

    def add_related_incident(*args, **kwargs):
        raise NotImplementedError("Relationship management not available")

    def reopen_incident(*args, **kwargs):
        raise NotImplementedError("Incident reopening not available")

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
        get_task_list,
        get_task,
        add_task_comment,
        delete_task,
        create_subtask,
        generate_tasks_report,
        TaskPriority,
        TaskStatus,
        TaskManagementError,
        TaskNotFoundError
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

    def get_task(*args, **kwargs):
        raise NotImplementedError("Task management not available")

    def add_task_comment(*args, **kwargs):
        raise NotImplementedError("Task management not available")

    def delete_task(*args, **kwargs):
        raise NotImplementedError("Task management not available")

    def create_subtask(*args, **kwargs):
        raise NotImplementedError("Task management not available")

    def generate_tasks_report(*args, **kwargs):
        raise NotImplementedError("Task management not available")

    class TaskPriority:
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"

    class TaskStatus:
        NEW = "new"
        ASSIGNED = "assigned"
        IN_PROGRESS = "in_progress"
        BLOCKED = "blocked"
        COMPLETED = "completed"
        CANCELLED = "cancelled"

    class TaskManagementError(Exception):
        """Base exception for task management errors."""
        pass

    class TaskNotFoundError(TaskManagementError):
        """Exception raised when a task is not found."""
        pass

try:
    from .war_room import (
        setup_war_room,
        add_participants,
        add_resource,
        archive_war_room,
        list_war_rooms,
        get_war_room_details
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

    def list_war_rooms(*args, **kwargs):
        raise NotImplementedError("War room management not available")

    def get_war_room_details(*args, **kwargs):
        raise NotImplementedError("War room management not available")

# Import report generator functionality
try:
    from .report_generator import (
        generate_report,
        generate_status_report,
        generate_full_report,
        generate_timeline_report,
        REPORT_FORMATS
    )
    REPORT_GENERATOR_AVAILABLE = True
    logger.debug("Report generator module loaded successfully")
except ImportError as e:
    logger.warning(f"Failed to import report_generator module: {e}")
    REPORT_GENERATOR_AVAILABLE = False

    def generate_report(*args, **kwargs):
        raise NotImplementedError("Report generation not available")

    def generate_full_report(*args, **kwargs):
        raise NotImplementedError("Full report generation not available")

    def generate_timeline_report(*args, **kwargs):
        raise NotImplementedError("Timeline report generation not available")

    REPORT_FORMATS = ["text", "markdown", "json", "html", "pdf"]

def track_incident_status(*args, **kwargs):
    """
    Alias for initialize_incident_status to maintain compatibility with parent module.

    This function maintains backward compatibility with code that might call
    track_incident_status from the parent module.
    """
    return initialize_incident_status(*args, **kwargs)

# Helper function to check available components
def get_available_components():
    """Returns status of available coordination components."""
    return {
        'status_tracker': STATUS_TRACKER_AVAILABLE,
        'notification_system': NOTIFICATION_SYSTEM_AVAILABLE,
        'task_manager': TASK_MANAGER_AVAILABLE,
        'war_room': WAR_ROOM_AVAILABLE,
        'report_generator': REPORT_GENERATOR_AVAILABLE
    }

# Export public API
__all__ = [
    # Status tracking
    'initialize_incident_status',
    'update_status',
    'get_incident_status',
    'list_incidents',
    'add_related_incident',
    'reopen_incident',
    'track_incident_status',

    # Notification
    'notify_stakeholders',

    # Task management
    'create_task',
    'assign_task',
    'update_task_status',
    'get_task_list',
    'get_task',
    'add_task_comment',
    'delete_task',
    'create_subtask',
    'generate_tasks_report',
    'TaskPriority',
    'TaskStatus',
    'TaskManagementError',
    'TaskNotFoundError',

    # War room
    'setup_war_room',
    'add_participants',
    'add_resource',
    'archive_war_room',
    'list_war_rooms',
    'get_war_room_details',

    # Report generation
    'generate_report',
    'generate_status_report',
    'generate_full_report',
    'generate_timeline_report',
    'REPORT_FORMATS',

    # Utility
    'get_available_components'
]

# Check and log available components
available_components = get_available_components()
logger.info(f"Incident Response Coordination module loaded")
logger.debug(f"Available components: {', '.join([k for k, v in available_components.items() if v])}")
