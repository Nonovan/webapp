"""
Incident Response Kit - War Room Management

This module provides functionality for setting up and managing virtual war rooms
for security incident response coordination. War rooms serve as centralized collaboration
environments where incident response team members can share information, coordinate
activities, and maintain situational awareness during security incidents.

The war room management follows the NIST SP 800-61 framework for incident handling
and integrates with other components of the incident response toolkit.
"""

import os
import sys
import json
import logging
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Set, Tuple

# Configure logging
logger = logging.getLogger(__name__)

# Import from parent package
try:
    # Attempt to import parent package components
    from .. import (
        IncidentStatus, IncidentPhase, response_config, sanitize_incident_id,
        CONFIG_AVAILABLE, MODULE_PATH
    )

    # Import coordination components
    from .status_tracker import get_incident_status
    from .notification_system import notify_stakeholders

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

    response_config = {}
    CONFIG_AVAILABLE = False
    MODULE_PATH = Path(__file__).resolve().parent

    def sanitize_incident_id(incident_id: str) -> str:
        """Sanitize incident ID for safety."""
        import re
        return re.sub(r'[^a-zA-Z0-9_\-]', '_', incident_id)

    def get_incident_status(incident_id: str) -> Optional[Dict[str, Any]]:
        """Placeholder for get_incident_status when not available."""
        return None

# --- War Room Configuration ---

# Configure logging
LOG_LEVEL = response_config.get("logging", {}).get("level", "INFO").upper()
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)

# War room configuration settings
WAR_ROOM_CONFIG = response_config.get("war_room", {})
STORAGE_DIR = WAR_ROOM_CONFIG.get("storage_dir")
if not STORAGE_DIR:
    # Default to a war_rooms directory next to storage_dir
    STORAGE_DIR = Path(response_config.get("storage_dir", "/secure/incident_response/war_rooms"))
else:
    STORAGE_DIR = Path(STORAGE_DIR)

# File and directory permissions
FILE_PERMISSIONS = 0o600  # Owner read/write only
DIR_PERMISSIONS = 0o700   # Owner read/write/execute only

# Integration settings
CHAT_INTEGRATION_ENABLED = WAR_ROOM_CONFIG.get("chat_integration", {}).get("enabled", False)
VIDEO_CONF_INTEGRATION_ENABLED = WAR_ROOM_CONFIG.get("video_conference", {}).get("enabled", False)
RECORDING_ENABLED = WAR_ROOM_CONFIG.get("recording", {}).get("enabled", False)
COLLABORATION_TOOL = WAR_ROOM_CONFIG.get("collaboration_tool", "default")

# Default war room settings
DEFAULT_LIFECYCLE = {
    "expiration_days": WAR_ROOM_CONFIG.get("defaults", {}).get("expiration_days", 30),
    "auto_archive": WAR_ROOM_CONFIG.get("defaults", {}).get("auto_archive", True),
    "reminder_before_expiration": WAR_ROOM_CONFIG.get("defaults", {}).get("reminder_days", 7)
}

# Attempt to import secure communications module if available
try:
    from ..secure_comms import create_secure_room as create_secure_channel
    SECURE_COMMS_AVAILABLE = True
except ImportError:
    SECURE_COMMS_AVAILABLE = False
    logger.warning("Secure communications module not available - using basic war room functionality")

# Try to import core security audit logging if available
try:
    from core.security.cs_audit import log_security_event
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False
    logger.debug("Security audit logging not available")

    def log_security_event(*args, **kwargs):
        """Placeholder for audit logging when not available."""
        pass

# --- Helper Functions ---

def get_current_timestamp() -> str:
    """Return current timestamp in ISO format with timezone."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def get_user_identity() -> str:
    """Get current user identity for attribution."""
    # In an actual implementation, this would integrate with an auth system
    # This is a fallback implementation
    import getpass
    return os.environ.get("USER_ID", getpass.getuser())

def create_war_room_id(incident_id: str) -> str:
    """Create a unique war room ID based on incident ID."""
    timestamp = int(time.time())
    return f"{sanitize_incident_id(incident_id)}_war_room_{timestamp}"

def get_war_room_path(incident_id: str, war_room_id: Optional[str] = None) -> Path:
    """Get the path to the war room data file."""
    incident_id = sanitize_incident_id(incident_id)
    incident_dir = STORAGE_DIR / incident_id

    # Create directories if they don't exist
    if not incident_dir.exists():
        incident_dir.mkdir(parents=True, mode=DIR_PERMISSIONS)

    if war_room_id:
        return incident_dir / f"{war_room_id}.json"
    else:
        # Return the latest war room if none specified
        war_rooms = list(incident_dir.glob("*_war_room_*.json"))
        if war_rooms:
            return max(war_rooms, key=lambda p: p.stat().st_mtime)
        return None

def save_war_room_data(incident_id: str, war_room_id: str, data: Dict[str, Any]) -> bool:
    """Save war room data to storage."""
    try:
        file_path = get_war_room_path(incident_id, war_room_id)

        # Ensure directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True, mode=DIR_PERMISSIONS)

        # Create a temporary file first for atomic writing
        temp_path = file_path.with_suffix('.tmp')
        with open(temp_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        # Set proper permissions
        os.chmod(temp_path, FILE_PERMISSIONS)

        # Rename to final path (atomic operation)
        temp_path.replace(file_path)

        logger.debug(f"Saved war room data for {incident_id}/{war_room_id}")
        return True

    except Exception as e:
        logger.error(f"Failed to save war room data: {e}")
        return False

def load_war_room_data(incident_id: str, war_room_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Load war room data from storage."""
    try:
        file_path = get_war_room_path(incident_id, war_room_id)
        if not file_path or not file_path.exists():
            logger.warning(f"War room data not found for incident {incident_id}")
            return None

        with open(file_path, 'r') as f:
            data = json.load(f)

        return data

    except Exception as e:
        logger.error(f"Failed to load war room data: {e}")
        return None

def create_collaboration_workspace(name: str, description: str, participants: List[str]) -> Dict[str, Any]:
    """Create a collaboration workspace in the configured collaboration tool."""
    if SECURE_COMMS_AVAILABLE:
        try:
            # Use secure communications module if available
            result = create_secure_channel(
                name=name,
                members=participants,
                description=description,
                expires_in=f"{DEFAULT_LIFECYCLE['expiration_days']}d"
            )
            return {
                "tool": "secure_comms",
                "workspace_id": result.get("room_id"),
                "access_token": result.get("access_token"),
                "url": result.get("url", ""),
            }
        except Exception as e:
            logger.error(f"Failed to create secure communication channel: {e}")

    # Default implementation - simulated workspace
    workspace_id = str(uuid.uuid4())
    return {
        "tool": COLLABORATION_TOOL,
        "workspace_id": workspace_id,
        "url": f"https://collaboration.example.com/war-room/{workspace_id}",
        "access_info": "Contact the incident response team for access details"
    }

def get_resource_path(resource_name: str) -> Optional[str]:
    """Get path to incident response resource."""
    resource_name = resource_name.lower().replace(' ', '_')

    # In a real implementation, this would be a lookup to a resource database
    resource_map = {
        "incident_playbook": "/secure/playbooks/incident_response_plan.md",
        "network_diagram": "/secure/documentation/network/network_diagram.pdf",
        "employee_investigation_procedure": "/secure/hr/procedures/employee_investigation.pdf",
        "interview_templates": "/secure/hr/templates/investigation_interview.docx",
    }

    return resource_map.get(resource_name)

# --- Core Functions ---

def setup_war_room(
    incident_id: str,
    name: Optional[str] = None,
    participants: Optional[List[str]] = None,
    resources: Optional[List[str]] = None,
    description: Optional[str] = None,
    lifecycle: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Set up a virtual war room for incident response coordination.

    Args:
        incident_id: The ID of the incident
        name: Name for the war room (defaults to "<Incident ID> War Room")
        participants: List of participant user IDs to add initially
        resources: List of resource names to add to the war room
        description: Description of the war room
        lifecycle: Dictionary with lifecycle settings (expiration_days, auto_archive)

    Returns:
        Dictionary with war room details
    """
    # Get current user
    user = get_user_identity()
    incident_id = sanitize_incident_id(incident_id)

    # Create war room ID
    war_room_id = create_war_room_id(incident_id)

    # Set default name if not provided
    if not name:
        incident_data = get_incident_status(incident_id)
        if incident_data:
            incident_type = incident_data.get('incident_type', 'General')
            name = f"{incident_id} - {incident_type} Response War Room"
        else:
            name = f"{incident_id} War Room"

    # Set default participants if not provided
    if not participants:
        participants = [user]
    elif user not in participants:
        participants.append(user)

    # Set default resources if not provided
    if not resources:
        resources = []

    # Set default description if not provided
    if not description:
        description = f"Incident response war room for {incident_id}"

    # Set default lifecycle if not provided
    if not lifecycle:
        lifecycle = DEFAULT_LIFECYCLE

    # Create the collaboration workspace
    workspace_info = create_collaboration_workspace(
        name=name,
        description=description,
        participants=participants
    )

    # Create war room data
    war_room_data = {
        "incident_id": incident_id,
        "war_room_id": war_room_id,
        "name": name,
        "description": description,
        "created_at": get_current_timestamp(),
        "created_by": user,
        "updated_at": get_current_timestamp(),
        "status": "active",
        "participants": participants,
        "resources": [],
        "workspace": workspace_info,
        "lifecycle": {
            "expiration_date": (datetime.now(timezone.utc) +
                               timedelta(days=lifecycle.get("expiration_days",
                                                          DEFAULT_LIFECYCLE["expiration_days"]))).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "auto_archive": lifecycle.get("auto_archive", DEFAULT_LIFECYCLE["auto_archive"]),
            "reminder_before_expiration": lifecycle.get("reminder_before_expiration",
                                                      DEFAULT_LIFECYCLE["reminder_before_expiration"])
        },
        "activity": [
            {
                "timestamp": get_current_timestamp(),
                "action": "created",
                "user": user,
                "details": {
                    "name": name,
                    "participants": participants
                }
            }
        ]
    }

    # Add resources if provided
    if resources:
        for resource in resources:
            resource_path = get_resource_path(resource)
            if resource_path:
                war_room_data["resources"].append({
                    "name": resource,
                    "path": resource_path,
                    "added_at": get_current_timestamp(),
                    "added_by": user
                })
            else:
                logger.warning(f"Resource not found: {resource}")

    # Save war room data
    save_success = save_war_room_data(incident_id, war_room_id, war_room_data)

    if not save_success:
        logger.error(f"Failed to save war room data for {incident_id}/{war_room_id}")
        return {
            "status": "error",
            "message": "Failed to save war room data",
            "incident_id": incident_id
        }

    # Audit the war room creation
    if AUDIT_AVAILABLE:
        log_security_event(
            event_type="war_room_created",
            description=f"War room {war_room_id} created for incident {incident_id}",
            severity="info",
            user_id=user,
            details={
                "incident_id": incident_id,
                "war_room_id": war_room_id,
                "participants": participants
            }
        )

    # Update incident status to reflect war room creation
    try:
        from .status_tracker import update_incident_status
        update_incident_status(
            incident_id=incident_id,
            notes=f"War room created: {name}",
            user=user
        )
    except Exception as e:
        logger.warning(f"Failed to update incident status: {e}")

    # Notify participants
    if PARENT_IMPORTS_AVAILABLE:
        try:
            notify_participants = [p for p in participants if p != user]
            if notify_participants:
                notify_stakeholders(
                    recipients=notify_participants,
                    subject=f"War Room Created for Incident {incident_id}",
                    message=(
                        f"You have been added to the war room for incident {incident_id}.\n\n"
                        f"War Room: {name}\n"
                        f"Description: {description}\n\n"
                        f"Access Details:\n{workspace_info.get('access_info', '')}\n"
                        f"URL: {workspace_info.get('url', 'Not available')}"
                    ),
                    incident_id=incident_id
                )
        except Exception as e:
            logger.warning(f"Failed to notify participants: {e}")

    # Return war room information
    return {
        "status": "success",
        "incident_id": incident_id,
        "war_room_id": war_room_id,
        "name": name,
        "description": description,
        "created_at": war_room_data["created_at"],
        "participants": participants,
        "resources": [r["name"] for r in war_room_data["resources"]],
        "workspace_url": workspace_info.get("url", ""),
        "workspace_id": workspace_info.get("workspace_id", ""),
        "access_info": workspace_info.get("access_info", "")
    }

def add_participants(
    incident_id: str,
    participants: List[str],
    war_room_id: Optional[str] = None,
    notify: bool = True
) -> Dict[str, Any]:
    """
    Add participants to an existing war room.

    Args:
        incident_id: The ID of the incident
        participants: List of participant user IDs to add
        war_room_id: Specific war room ID (optional)
        notify: Whether to notify new participants

    Returns:
        Dictionary with updated war room details
    """
    # Get current user
    user = get_user_identity()
    incident_id = sanitize_incident_id(incident_id)

    # Load existing war room data
    war_room_data = load_war_room_data(incident_id, war_room_id)
    if not war_room_data:
        logger.error(f"War room not found for incident {incident_id}")
        return {
            "status": "error",
            "message": "War room not found",
            "incident_id": incident_id
        }

    # Check if war room is active
    if war_room_data.get("status") != "active":
        logger.error(f"War room is not active: {war_room_data.get('status')}")
        return {
            "status": "error",
            "message": f"War room is {war_room_data.get('status')}",
            "incident_id": incident_id
        }

    # Get current participants
    current_participants = war_room_data.get("participants", [])

    # Identify new participants
    new_participants = [p for p in participants if p not in current_participants]
    if not new_participants:
        logger.info("No new participants to add")
        return {
            "status": "success",
            "message": "No new participants to add",
            "incident_id": incident_id,
            "war_room_id": war_room_data.get("war_room_id"),
            "participants": current_participants
        }

    # Update participant list
    war_room_data["participants"].extend(new_participants)
    war_room_data["updated_at"] = get_current_timestamp()

    # Record the action
    war_room_data["activity"].append({
        "timestamp": get_current_timestamp(),
        "action": "participants_added",
        "user": user,
        "details": {
            "added": new_participants
        }
    })

    # Save updated war room data
    save_success = save_war_room_data(
        incident_id,
        war_room_data["war_room_id"],
        war_room_data
    )

    if not save_success:
        logger.error(f"Failed to save war room data after adding participants")
        return {
            "status": "error",
            "message": "Failed to save war room data",
            "incident_id": incident_id
        }

    # Update collaboration workspace
    workspace_info = war_room_data.get("workspace", {})
    if SECURE_COMMS_AVAILABLE and workspace_info.get("tool") == "secure_comms":
        try:
            # In a real implementation, this would call an API to add members
            logger.info(f"Would add participants to secure comms workspace: {new_participants}")
        except Exception as e:
            logger.warning(f"Failed to update collaboration workspace participants: {e}")

    # Notify new participants
    if notify and PARENT_IMPORTS_AVAILABLE:
        try:
            notify_stakeholders(
                recipients=new_participants,
                subject=f"Added to War Room for Incident {incident_id}",
                message=(
                    f"You have been added to the war room for incident {incident_id}.\n\n"
                    f"War Room: {war_room_data.get('name')}\n"
                    f"Description: {war_room_data.get('description')}\n\n"
                    f"Access Details:\n{workspace_info.get('access_info', '')}\n"
                    f"URL: {workspace_info.get('url', 'Not available')}"
                ),
                incident_id=incident_id
            )
        except Exception as e:
            logger.warning(f"Failed to notify new participants: {e}")

    # Return updated war room information
    return {
        "status": "success",
        "incident_id": incident_id,
        "war_room_id": war_room_data["war_room_id"],
        "added_participants": new_participants,
        "participants": war_room_data["participants"]
    }

def add_resource(
    incident_id: str,
    resource: str,
    resource_path: Optional[str] = None,
    war_room_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Add a resource to a war room.

    Args:
        incident_id: The ID of the incident
        resource: Resource name to add
        resource_path: Custom path to the resource (optional)
        war_room_id: Specific war room ID (optional)

    Returns:
        Dictionary with updated war room details
    """
    # Get current user
    user = get_user_identity()
    incident_id = sanitize_incident_id(incident_id)

    # Load existing war room data
    war_room_data = load_war_room_data(incident_id, war_room_id)
    if not war_room_data:
        logger.error(f"War room not found for incident {incident_id}")
        return {
            "status": "error",
            "message": "War room not found",
            "incident_id": incident_id
        }

    # Check if war room is active
    if war_room_data.get("status") != "active":
        logger.error(f"War room is not active: {war_room_data.get('status')}")
        return {
            "status": "error",
            "message": f"War room is {war_room_data.get('status')}",
            "incident_id": incident_id
        }

    # Get the resource path if not provided
    if not resource_path:
        resource_path = get_resource_path(resource)
        if not resource_path:
            logger.warning(f"Resource not found: {resource}")
            resource_path = f"custom/{resource}"

    # Check if resource already exists
    current_resources = war_room_data.get("resources", [])
    for existing_resource in current_resources:
        if existing_resource["name"].lower() == resource.lower():
            logger.info(f"Resource already exists: {resource}")
            return {
                "status": "success",
                "message": "Resource already exists",
                "incident_id": incident_id,
                "war_room_id": war_room_data["war_room_id"],
                "resource": existing_resource
            }

    # Add the new resource
    new_resource = {
        "name": resource,
        "path": resource_path,
        "added_at": get_current_timestamp(),
        "added_by": user
    }

    war_room_data["resources"].append(new_resource)
    war_room_data["updated_at"] = get_current_timestamp()

    # Record the action
    war_room_data["activity"].append({
        "timestamp": get_current_timestamp(),
        "action": "resource_added",
        "user": user,
        "details": {
            "resource": resource,
            "path": resource_path
        }
    })

    # Save updated war room data
    save_success = save_war_room_data(
        incident_id,
        war_room_data["war_room_id"],
        war_room_data
    )

    if not save_success:
        logger.error(f"Failed to save war room data after adding resource")
        return {
            "status": "error",
            "message": "Failed to save war room data",
            "incident_id": incident_id
        }

    # Return updated war room information
    return {
        "status": "success",
        "incident_id": incident_id,
        "war_room_id": war_room_data["war_room_id"],
        "resource_added": new_resource
    }

def archive_war_room(
    incident_id: str,
    war_room_id: Optional[str] = None,
    output_path: Optional[str] = None,
    archive_workspace: bool = True
) -> Dict[str, Any]:
    """
    Archive a war room and its contents.

    Args:
        incident_id: The ID of the incident
        war_room_id: Specific war room ID (optional)
        output_path: Path to save the archive (optional)
        archive_workspace: Whether to archive the collaboration workspace

    Returns:
        Dictionary with archive details
    """
    # Get current user
    user = get_user_identity()
    incident_id = sanitize_incident_id(incident_id)

    # Load existing war room data
    war_room_data = load_war_room_data(incident_id, war_room_id)
    if not war_room_data:
        logger.error(f"War room not found for incident {incident_id}")
        return {
            "status": "error",
            "message": "War room not found",
            "incident_id": incident_id
        }

    # Get the war room ID from the data
    war_room_id = war_room_data["war_room_id"]

    # If war room is already archived, return info
    if war_room_data.get("status") == "archived":
        logger.info(f"War room already archived: {war_room_id}")
        return {
            "status": "success",
            "message": "War room already archived",
            "incident_id": incident_id,
            "war_room_id": war_room_id,
            "archive_path": war_room_data.get("archive_info", {}).get("path")
        }

    # Determine archive path
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_archive_path = str(STORAGE_DIR / "archives" / f"{incident_id}_{war_room_id}_{timestamp}.zip")
    archive_path = output_path or default_archive_path

    # Create archive directory if it doesn't exist
    archive_dir = Path(archive_path).parent
    if not archive_dir.exists():
        archive_dir.mkdir(parents=True, exist_ok=True, mode=DIR_PERMISSIONS)

    # Archive collaboration workspace
    workspace_archive_info = {}
    if archive_workspace:
        workspace_info = war_room_data.get("workspace", {})
        if SECURE_COMMS_AVAILABLE and workspace_info.get("tool") == "secure_comms":
            try:
                # In a real implementation, this would call an API to archive the workspace
                logger.info(f"Would archive secure comms workspace: {workspace_info.get('workspace_id')}")
                workspace_archive_info = {
                    "archive_id": f"archive_{workspace_info.get('workspace_id')}",
                    "status": "archived"
                }
            except Exception as e:
                logger.warning(f"Failed to archive collaboration workspace: {e}")

    # Update war room status
    war_room_data["status"] = "archived"
    war_room_data["updated_at"] = get_current_timestamp()

    # Add archive information
    war_room_data["archive_info"] = {
        "archived_at": get_current_timestamp(),
        "archived_by": user,
        "path": archive_path,
        "workspace_archive": workspace_archive_info
    }

    # Record the action
    war_room_data["activity"].append({
        "timestamp": get_current_timestamp(),
        "action": "archived",
        "user": user,
        "details": {
            "path": archive_path,
            "workspace_archived": archive_workspace
        }
    })

    # Save updated war room data
    save_success = save_war_room_data(incident_id, war_room_id, war_room_data)

    if not save_success:
        logger.error(f"Failed to save war room data after archiving")
        return {
            "status": "error",
            "message": "Failed to save war room data",
            "incident_id": incident_id
        }

    # Save war room data to archive path
    try:
        # In a real implementation, this would create a ZIP archive with all relevant data
        import shutil
        import tempfile
        from pathlib import Path

        # Create a temporary directory for archive contents
        with tempfile.TemporaryDirectory() as temp_dir:
            # Save war room data to temp directory
            temp_path = Path(temp_dir) / f"{war_room_id}_data.json"
            with open(temp_path, 'w') as f:
                json.dump(war_room_data, f, indent=2, default=str)

            # Create the archive
            archive_path_obj = Path(archive_path)
            if archive_path_obj.suffix != '.zip':
                archive_path = f"{archive_path}.zip"
                archive_path_obj = Path(archive_path)

            # Create parent directory if it doesn't exist
            archive_path_obj.parent.mkdir(parents=True, exist_ok=True)

            # Create the archive (in reality would include more files)
            shutil.make_archive(
                str(archive_path_obj.with_suffix('')),
                'zip',
                temp_dir
            )

        # Set proper permissions on the archive file
        os.chmod(archive_path, FILE_PERMISSIONS)
        logger.info(f"War room archived to: {archive_path}")

    except Exception as e:
        logger.error(f"Failed to create war room archive: {e}")
        return {
            "status": "error",
            "message": f"Failed to create archive: {str(e)}",
            "incident_id": incident_id,
            "war_room_id": war_room_id
        }

    # Audit the war room archival
    if AUDIT_AVAILABLE:
        log_security_event(
            event_type="war_room_archived",
            description=f"War room {war_room_id} archived for incident {incident_id}",
            severity="info",
            user_id=user,
            details={
                "incident_id": incident_id,
                "war_room_id": war_room_id,
                "archive_path": archive_path
            }
        )

    # Update incident status to reflect war room archival
    try:
        from .status_tracker import update_incident_status
        update_incident_status(
            incident_id=incident_id,
            notes=f"War room archived: {war_room_data.get('name')}",
            user=user
        )
    except Exception as e:
        logger.warning(f"Failed to update incident status: {e}")

    # Return archive information
    return {
        "status": "success",
        "incident_id": incident_id,
        "war_room_id": war_room_id,
        "name": war_room_data.get("name"),
        "archive_path": archive_path,
        "archived_at": war_room_data["archive_info"]["archived_at"],
        "workspace_archived": bool(workspace_archive_info)
    }

def list_war_rooms(incident_id: Optional[str] = None) -> Dict[str, Any]:
    """
    List war rooms, optionally filtering by incident ID.

    Args:
        incident_id: Optional incident ID to filter by

    Returns:
        Dictionary with list of war rooms
    """
    try:
        war_rooms = []

        if incident_id:
            # List war rooms for a specific incident
            incident_id = sanitize_incident_id(incident_id)
            incident_dir = STORAGE_DIR / incident_id
            if incident_dir.exists():
                for file_path in incident_dir.glob("*_war_room_*.json"):
                    try:
                        with open(file_path, 'r') as f:
                            data = json.load(f)
                            war_rooms.append({
                                "incident_id": data.get("incident_id"),
                                "war_room_id": data.get("war_room_id"),
                                "name": data.get("name"),
                                "status": data.get("status"),
                                "created_at": data.get("created_at"),
                                "participants": len(data.get("participants", [])),
                                "resources": len(data.get("resources", []))
                            })
                    except Exception as e:
                        logger.warning(f"Failed to load war room data from {file_path}: {e}")
        else:
            # List all war rooms
            for incident_dir in STORAGE_DIR.glob("*"):
                if incident_dir.is_dir():
                    for file_path in incident_dir.glob("*_war_room_*.json"):
                        try:
                            with open(file_path, 'r') as f:
                                data = json.load(f)
                                war_rooms.append({
                                    "incident_id": data.get("incident_id"),
                                    "war_room_id": data.get("war_room_id"),
                                    "name": data.get("name"),
                                    "status": data.get("status"),
                                    "created_at": data.get("created_at"),
                                    "participants": len(data.get("participants", [])),
                                    "resources": len(data.get("resources", []))
                                })
                        except Exception as e:
                            logger.warning(f"Failed to load war room data from {file_path}: {e}")

        # Sort by creation timestamp (newest first)
        war_rooms.sort(key=lambda x: x.get("created_at", ""), reverse=True)

        return {
            "status": "success",
            "count": len(war_rooms),
            "war_rooms": war_rooms
        }

    except Exception as e:
        logger.error(f"Failed to list war rooms: {e}")
        return {
            "status": "error",
            "message": f"Failed to list war rooms: {str(e)}",
            "war_rooms": []
        }

def get_war_room_details(incident_id: str, war_room_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Get detailed information about a war room.

    Args:
        incident_id: The ID of the incident
        war_room_id: Specific war room ID (optional)

    Returns:
        Dictionary with war room details
    """
    incident_id = sanitize_incident_id(incident_id)

    # Load war room data
    war_room_data = load_war_room_data(incident_id, war_room_id)
    if not war_room_data:
        logger.error(f"War room not found for incident {incident_id}")
        return {
            "status": "error",
            "message": "War room not found",
            "incident_id": incident_id
        }

    # Extract relevant details
    return {
        "status": "success",
        "incident_id": incident_id,
        "war_room_id": war_room_data["war_room_id"],
        "name": war_room_data.get("name"),
        "description": war_room_data.get("description"),
        "created_at": war_room_data.get("created_at"),
        "created_by": war_room_data.get("created_by"),
        "updated_at": war_room_data.get("updated_at"),
        "status": war_room_data.get("status"),
        "participants": war_room_data.get("participants", []),
        "resources": [
            {
                "name": r.get("name"),
                "path": r.get("path"),
                "added_at": r.get("added_at"),
                "added_by": r.get("added_by")
            }
            for r in war_room_data.get("resources", [])
        ],
        "workspace": {
            "tool": war_room_data.get("workspace", {}).get("tool"),
            "url": war_room_data.get("workspace", {}).get("url"),
            "access_info": war_room_data.get("workspace", {}).get("access_info")
        },
        "lifecycle": war_room_data.get("lifecycle", {}),
        "activity_count": len(war_room_data.get("activity", []))
    }

# --- Main Execution ---

def main() -> int:
    """Main function when script is run directly."""
    import argparse

    parser = argparse.ArgumentParser(description="Manage virtual war rooms for incident response")
    parser.add_argument("--incident-id", required=True, help="Unique identifier for the incident")

    # War room management commands
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("--setup", action="store_true", help="Set up a new war room")
    action_group.add_argument("--add-participants", help="Add participants to existing war room (comma-separated)")
    action_group.add_argument("--add-resource", help="Add a resource to existing war room")
    action_group.add_argument("--archive", action="store_true", help="Archive a war room")
    action_group.add_argument("--list", action="store_true", help="List war rooms for the incident")
    action_group.add_argument("--details", action="store_true", help="Get detailed information about a war room")

    # Setup parameters
    parser.add_argument("--name", help="Name for the war room")
    parser.add_argument("--description", help="Description of the war room")
    parser.add_argument("--participants", help="Initial participants (comma-separated)")
    parser.add_argument("--resources", help="Resources to add (comma-separated)")

    # Additional parameters
    parser.add_argument("--war-room-id", help="Specific war room ID (if multiple exist)")
    parser.add_argument("--resource-path", help="Custom path to a resource")
    parser.add_argument("--output", help="Output path for archive")
    parser.add_argument("--no-workspace-archive", action="store_true", help="Don't archive the workspace")

    args = parser.parse_args()

    try:
        if args.setup:
            # Set up a new war room
            participants = args.participants.split(",") if args.participants else None
            resources = args.resources.split(",") if args.resources else None

            result = setup_war_room(
                incident_id=args.incident_id,
                name=args.name,
                participants=participants,
                resources=resources,
                description=args.description
            )

            if result["status"] == "success":
                print(f"War room created successfully:")
                print(f"  ID: {result['war_room_id']}")
                print(f"  Name: {result['name']}")
                print(f"  Participants: {', '.join(result['participants'])}")
                print(f"  Workspace URL: {result['workspace_url']}")
                return 0
            else:
                print(f"Error: {result['message']}")
                return 1

        elif args.add_participants:
            # Add participants to existing war room
            participants = args.add_participants.split(",")

            result = add_participants(
                incident_id=args.incident_id,
                participants=participants,
                war_room_id=args.war_room_id
            )

            if result["status"] == "success":
                print(f"Added participants to war room:")
                print(f"  Added: {', '.join(result.get('added_participants', []))}")
                print(f"  Total participants: {len(result['participants'])}")
                return 0
            else:
                print(f"Error: {result['message']}")
                return 1

        elif args.add_resource:
            # Add a resource to existing war room
            result = add_resource(
                incident_id=args.incident_id,
                resource=args.add_resource,
                resource_path=args.resource_path,
                war_room_id=args.war_room_id
            )

            if result["status"] == "success":
                resource_added = result.get('resource_added', {})
                print(f"Resource added to war room:")
                print(f"  Name: {resource_added.get('name')}")
                print(f"  Path: {resource_added.get('path')}")
                return 0
            else:
                print(f"Error: {result['message']}")
                return 1

        elif args.archive:
            # Archive a war room
            result = archive_war_room(
                incident_id=args.incident_id,
                war_room_id=args.war_room_id,
                output_path=args.output,
                archive_workspace=not args.no_workspace_archive
            )

            if result["status"] == "success":
                print(f"War room archived successfully:")
                print(f"  Name: {result['name']}")
                print(f"  Archive path: {result['archive_path']}")
                print(f"  Archived at: {result['archived_at']}")
                return 0
            else:
                print(f"Error: {result['message']}")
                return 1

        elif args.list:
            # List war rooms
            result = list_war_rooms(args.incident_id)

            if result["status"] == "success":
                print(f"War Rooms for incident {args.incident_id}:")
                for idx, war_room in enumerate(result["war_rooms"], 1):
                    print(f"  {idx}. {war_room['name']} (ID: {war_room['war_room_id']})")
                    print(f"     Status: {war_room['status']}")
                    print(f"     Created: {war_room['created_at']}")
                    print(f"     Participants: {war_room['participants']}")
                    print(f"     Resources: {war_room['resources']}")
                    print()
                return 0
            else:
                print(f"Error: {result['message']}")
                return 1

        elif args.details:
            # Get war room details
            result = get_war_room_details(
                incident_id=args.incident_id,
                war_room_id=args.war_room_id
            )

            if result["status"] == "success":
                print(f"War Room Details:")
                print(f"  Name: {result['name']}")
                print(f"  ID: {result['war_room_id']}")
                print(f"  Description: {result['description']}")
                print(f"  Status: {result['status']}")
                print(f"  Created: {result['created_at']} by {result['created_by']}")
                print(f"  Updated: {result['updated_at']}")
                print(f"  Participants: {', '.join(result['participants'])}")
                print(f"  Resources: {len(result['resources'])}")
                print(f"  Workspace: {result['workspace']['tool']} - {result['workspace']['url']}")
                return 0
            else:
                print(f"Error: {result['message']}")
                return 1

    except Exception as e:
        print(f"An error occurred: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
