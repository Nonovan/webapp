"""
Incident Response Toolkit - Incident Initialization Module

This module provides functionality for initializing a new security incident response,
creating the necessary directory structure, performing initial documentation,
and setting up tracking for the incident response process.

It follows the NIST SP 800-61 framework for incident handling and integrates
with other components of the incident response toolkit.
"""

import os
import sys
import logging
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple, Set

# Import shared components from the toolkit
from . import (
    Incident, IncidentStatus, IncidentPhase, IncidentSeverity, IncidentType,
    InitializationError, IncidentResponseError, ValidationError,
    MODULE_PATH, CONFIG_AVAILABLE, response_config, tool_paths,
    DEFAULT_EVIDENCE_DIR, create_evidence_directory, sanitize_incident_id,
    track_incident_status, notify_stakeholders, EvidenceCollectionError,
    get_incident_status, IncidentStatusError
)
from .coordination import update_incident_status

# Configure module logging
logger = logging.getLogger(__name__)

# Constants
TEMPLATE_DIR = MODULE_PATH / "templates"
DEFAULT_INCIDENT_DIR = Path(DEFAULT_EVIDENCE_DIR)
DEFAULT_INCIDENT_TEMPLATE = "incident_report.md"
DEFAULT_TIMELINE_TEMPLATE = "incident_timeline.md"

# Check if documentation templates are available
DOCUMENTATION_AVAILABLE = (TEMPLATE_DIR / DEFAULT_INCIDENT_TEMPLATE).exists() and \
                          (TEMPLATE_DIR / DEFAULT_TIMELINE_TEMPLATE).exists()

# Check if notifications are enabled (default: True)
NOTIFICATION_ENABLED = os.getenv("NOTIFICATION_ENABLED", "true").lower() in ("true", "1", "yes")

# Constants
TEMPLATE_DIR = MODULE_PATH / "templates"
DEFAULT_INCIDENT_DIR = Path(DEFAULT_EVIDENCE_DIR)
DEFAULT_INCIDENT_TEMPLATE = "incident_report.md"
DEFAULT_TIMELINE_TEMPLATE = "incident_timeline.md"


def initialize_incident(
    incident_id: str,
    incident_type: str,
    severity: str = IncidentSeverity.MEDIUM,
    description: Optional[str] = None,
    lead_responder: Optional[str] = None,
    evidence_dir: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    documentation: bool = True,
    tracking: bool = True,
    notify: bool = True
) -> Dict[str, Any]:
    """
    Initialize a new security incident response environment.

    This function sets up all necessary components for a new security incident:
    - Creates directory structure for evidence collection
    - Initializes incident tracking
    - Creates initial documentation
    - Notifies stakeholders (if enabled)

    Args:
        incident_id: Unique identifier for the incident
        incident_type: Type of incident (malware, phishing, etc.)
        severity: Severity level (critical, high, medium, low)
        description: Brief description of the incident
        lead_responder: Email/name of the lead responder
        evidence_dir: Custom evidence directory (optional)
        metadata: Additional incident metadata (optional)
        documentation: Whether to create initial documentation
        tracking: Whether to initialize incident tracking
        notify: Whether to send notifications

    Returns:
        Dict containing initialization results and paths

    Raises:
        InitializationError: If initialization fails
        ValidationError: If incident parameters are invalid
    """
    # Verify inputs
    if not incident_id:
        raise ValidationError("Incident ID is required")

    if incident_type not in IncidentType.VALID_TYPES:
        raise ValidationError(f"Invalid incident type: {incident_type}")

    if severity not in IncidentSeverity.VALID_SEVERITIES:
        raise ValidationError(f"Invalid severity: {severity}")

    # Result dictionary to track initialization progress
    result = {
        "incident_id": incident_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "success": False,
        "evidence_dir": None,
        "documentation_paths": [],
        "tracking_initialized": False,
        "notifications_sent": False,
        "errors": []
    }

    try:
        # Create evidence directory
        if evidence_dir:
            incident_dir = Path(evidence_dir)
            try:
                incident_dir.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                raise InitializationError(f"Failed to create custom evidence directory: {e}")
        else:
            try:
                incident_dir = create_evidence_directory(incident_id)
            except EvidenceCollectionError as e:
                raise InitializationError(f"Failed to create evidence directory: {e}")

        result["evidence_dir"] = str(incident_dir)
        logger.info(f"Created evidence directory: {incident_dir}")

        # Initialize incident tracking if enabled
        if tracking:
            try:
                tracking_success = track_incident_status(
                    incident_id=incident_id,
                    incident_type=incident_type,
                    severity=severity,
                    lead_responder=lead_responder,
                    description=description
                )

                if tracking_success:
                    result["tracking_initialized"] = True
                    logger.info(f"Initialized tracking for incident: {incident_id}")
                else:
                    result["errors"].append("Failed to initialize incident tracking")
            except Exception as e:
                logger.error(f"Error initializing incident tracking: {e}", exc_info=True)
                result["errors"].append(f"Tracking error: {str(e)}")

        # Create documentation if enabled and templates are available
        if documentation and DOCUMENTATION_AVAILABLE:
            docs_dir = incident_dir / "documentation"
            docs_dir.mkdir(exist_ok=True)

            # Create initial incident report
            try:
                incident_report_path = create_incident_report(
                    docs_dir,
                    incident_id=incident_id,
                    incident_type=incident_type,
                    severity=severity,
                    description=description,
                    lead_responder=lead_responder,
                    metadata=metadata
                )

                if incident_report_path:
                    result["documentation_paths"].append(str(incident_report_path))
                    logger.info(f"Created incident report: {incident_report_path}")
            except Exception as e:
                logger.error(f"Error creating incident report: {e}", exc_info=True)
                result["errors"].append(f"Documentation error: {str(e)}")

            # Create initial timeline
            try:
                timeline_path = create_timeline_template(
                    docs_dir,
                    incident_id=incident_id,
                    incident_type=incident_type
                )

                if timeline_path:
                    result["documentation_paths"].append(str(timeline_path))
                    logger.info(f"Created incident timeline: {timeline_path}")
            except Exception as e:
                logger.error(f"Error creating timeline: {e}", exc_info=True)
                result["errors"].append(f"Timeline error: {str(e)}")

        # Send notifications if enabled
        if notify and NOTIFICATION_ENABLED:
            try:
                # Determine who to notify based on severity
                notification_sent = notify_stakeholders(
                    subject=f"Security Incident Initiated: {incident_id}",
                    message=f"A new security incident has been initialized.\n\n"
                            f"ID: {incident_id}\n"
                            f"Type: {incident_type}\n"
                            f"Severity: {severity}\n"
                            f"Description: {description or 'N/A'}\n"
                            f"Lead: {lead_responder or 'Unassigned'}",
                    severity=severity
                )

                result["notifications_sent"] = notification_sent
                if notification_sent:
                    logger.info(f"Sent notifications for incident: {incident_id}")
            except Exception as e:
                logger.error(f"Error sending notifications: {e}", exc_info=True)
                result["errors"].append(f"Notification error: {str(e)}")

        # Create incident object instance for potential further use
        incident_obj = Incident(
            incident_id=incident_id,
            incident_type=incident_type,
            severity=severity,
            status=IncidentStatus.OPEN,
            lead_responder=lead_responder,
            description=description,
            **(metadata or {})
        )

        # Record the initial action in the incident history
        incident_obj.add_action(
            action="initialization",
            user=lead_responder or "system",
            details={
                "type": incident_type,
                "severity": severity,
                "description": description
            }
        )

        # Set success flag
        result["success"] = True
        logger.info(f"Successfully initialized incident: {incident_id}")

        return result

    except (InitializationError, ValidationError) as e:
        # Re-raise these specific exceptions
        raise
    except Exception as e:
        logger.error(f"Unexpected error initializing incident: {e}", exc_info=True)
        raise InitializationError(f"Failed to initialize incident: {str(e)}")


def create_incident_report(
    output_dir: Path,
    incident_id: str,
    incident_type: str,
    severity: str,
    description: Optional[str] = None,
    lead_responder: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Optional[Path]:
    """
    Create an initial incident report document.

    Args:
        output_dir: Directory to save the report
        incident_id: Unique identifier for the incident
        incident_type: Type of incident
        severity: Severity level
        description: Brief description of the incident
        lead_responder: Lead responder name/email
        metadata: Additional incident metadata

    Returns:
        Path to the created report file, or None if creation failed
    """
    template_path = TEMPLATE_DIR / DEFAULT_INCIDENT_TEMPLATE
    if not template_path.exists():
        logger.warning(f"Incident report template not found: {template_path}")
        return None

    # Create a filename for the incident report
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    report_filename = f"incident_report_{sanitize_incident_id(incident_id)}_{timestamp}.md"
    report_path = output_dir / report_filename

    try:
        # Load the template
        with open(template_path, 'r') as f:
            template_content = f.read()

        # Prepare template variables
        template_vars = {
            "INCIDENT_ID": incident_id,
            "INCIDENT_TYPE": incident_type,
            "SEVERITY": severity,
            "DESCRIPTION": description or "No description provided",
            "LEAD_RESPONDER": lead_responder or "Unassigned",
            "DATE": datetime.now(timezone.utc).strftime('%Y-%m-%d'),
            "TIME": datetime.now(timezone.utc).strftime('%H:%M:%S UTC'),
            "STATUS": IncidentStatus.OPEN,
            "PHASE": IncidentPhase.IDENTIFICATION
        }

        # Add metadata if provided
        if metadata:
            for key, value in metadata.items():
                template_vars[f"META_{key.upper()}"] = str(value)

        # Replace template variables
        report_content = template_content
        for key, value in template_vars.items():
            report_content = report_content.replace(f"{{{{{key}}}}}", str(value))

        # Write the report file
        with open(report_path, 'w') as f:
            f.write(report_content)

        return report_path
    except Exception as e:
        logger.error(f"Error creating incident report: {e}", exc_info=True)
        return None


def create_timeline_template(
    output_dir: Path,
    incident_id: str,
    incident_type: str
) -> Optional[Path]:
    """
    Create an initial timeline document.

    Args:
        output_dir: Directory to save the timeline
        incident_id: Unique identifier for the incident
        incident_type: Type of incident

    Returns:
        Path to the created timeline file, or None if creation failed
    """
    template_path = TEMPLATE_DIR / DEFAULT_TIMELINE_TEMPLATE
    if not template_path.exists():
        logger.warning(f"Timeline template not found: {template_path}")
        return None

    # Create a filename for the timeline
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    timeline_filename = f"incident_timeline_{sanitize_incident_id(incident_id)}_{timestamp}.md"
    timeline_path = output_dir / timeline_filename

    try:
        # Load the template
        with open(template_path, 'r') as f:
            template_content = f.read()

        # Prepare template variables
        template_vars = {
            "INCIDENT_ID": incident_id,
            "INCIDENT_TYPE": incident_type,
            "DATE": datetime.now(timezone.utc).strftime('%Y-%m-%d'),
            "TIME": datetime.now(timezone.utc).strftime('%H:%M:%S UTC'),
            "INITIAL_ENTRY": f"Incident initialized ({datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')})"
        }

        # Replace template variables
        timeline_content = template_content
        for key, value in template_vars.items():
            timeline_content = timeline_content.replace(f"{{{{{key}}}}}", str(value))

        # Write the timeline file
        with open(timeline_path, 'w') as f:
            f.write(timeline_content)

        return timeline_path
    except Exception as e:
        logger.error(f"Error creating timeline template: {e}", exc_info=True)
        return None


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
    - Notifies stakeholders if notifications are enabled
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

    # Sanitize the incident ID
    incident_id = sanitize_incident_id(incident_id)

    # Result dictionary to track progress
    result = {
        "incident_id": incident_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "success": False,
        "status_updated": False,
        "notifications_sent": False,
        "errors": []
    }

    try:
        # Get current incident status using coordination module
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

        # Use status_tracker's update_incident_status to change status
        status_updated = update_incident_status(
            incident_id=incident_id,
            status=IncidentStatus.INVESTIGATING,
            phase=phase,
            notes=f"Incident reopened: {reason}",
            user=user_id
        )

        result["status_updated"] = status_updated

        if not status_updated:
            result["errors"].append("Failed to update incident status")
            return result

        # Send notifications if enabled
        if NOTIFICATION_ENABLED:
            try:
                severity = incident_data.get("severity", IncidentSeverity.MEDIUM)
                notification_sent = notify_stakeholders(
                    subject=f"Security Incident Reopened: {incident_id}",
                    message=(
                        f"A security incident has been reopened.\n\n"
                        f"ID: {incident_id}\n"
                        f"Reason: {reason}\n"
                        f"Reopened by: {user_id or 'System'}\n"
                        f"New status: {IncidentStatus.INVESTIGATING}\n"
                        f"New phase: {phase}"
                    ),
                    severity=severity
                )

                result["notifications_sent"] = notification_sent
                if notification_sent:
                    logger.info(f"Sent notifications for reopened incident: {incident_id}")
            except Exception as e:
                logger.error(f"Error sending notifications for reopened incident: {e}", exc_info=True)
                result["errors"].append(f"Notification error: {str(e)}")

        # Set success flag if we got this far
        result["success"] = True
        logger.info(f"Successfully reopened incident: {incident_id}")

        return result

    except (ValidationError, IncidentStatusError) as e:
        # Re-raise these specific exceptions
        raise
    except Exception as e:
        logger.error(f"Unexpected error reopening incident: {e}", exc_info=True)
        result["errors"].append(str(e))
        return result


# Only expose the main initialization function and needed constants
__all__ = [
    'initialize_incident',
    'DEFAULT_INCIDENT_TEMPLATE',
    'DEFAULT_TIMELINE_TEMPLATE',
    'reopen_incident'
]
