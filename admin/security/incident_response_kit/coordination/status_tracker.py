"""
Incident Response Status Tracker

This script manages the status and phase tracking for security incidents
within the Incident Response Kit. It allows initializing, updating, querying,
and reporting on incident progress.

Follows the phases defined in NIST SP 800-61:
Preparation, Detection & Analysis, Containment, Eradication, Recovery, Post-Incident Activity.
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Union, Set

# Determine project root and add to sys.path if necessary
# This allows importing modules from the broader project structure
try:
    # Assumes this script is in admin/security/incident_response_kit/coordination
    ADMIN_DIR = Path(__file__).resolve().parents[3]
    if str(ADMIN_DIR) not in sys.path:
        sys.path.insert(0, str(ADMIN_DIR))

    # Import constants and potentially the Incident class if needed for structure validation
    from admin.security.incident_response_kit import (
        IncidentStatus, IncidentPhase, IncidentSeverity, IncidentType,
        response_config, tool_paths, CONFIG_AVAILABLE, MODULE_PATH
    )
    # Import core security utilities for audit logging
    try:
        from core.security.cs_audit import log_security_event
        from core.security.cs_file_integrity import calculate_file_hash
        AUDIT_AVAILABLE = True
    except ImportError:
        AUDIT_AVAILABLE = False

except ImportError as e:
    print(f"Error importing project modules: {e}", file=sys.stderr)
    print("Ensure the script is run from within the project structure or PYTHONPATH is set correctly.", file=sys.stderr)
    # Define fallback constants if import fails, allowing basic operation
    class IncidentStatus:
        OPEN = "open"; INVESTIGATING = "investigating"; CONTAINED = "contained"; ERADICATED = "eradicated"
        RECOVERING = "recovering"; RESOLVED = "resolved"; CLOSED = "closed"; MERGED = "merged"
    class IncidentPhase:
        IDENTIFICATION = "identification"; CONTAINMENT = "containment"; ERADICATION = "eradication"
        RECOVERY = "recovery"; LESSONS_LEARNED = "lessons_learned"
    class IncidentSeverity:
        CRITICAL = "critical"; HIGH = "high"; MEDIUM = "medium"; LOW = "low"
    class IncidentType:
        MALWARE = "malware"; DATA_BREACH = "data_breach"; UNAUTHORIZED_ACCESS = "unauthorized_access"
        DENIAL_OF_SERVICE = "denial_of_service"; WEB_APPLICATION_ATTACK = "web_application_attack"
        ACCOUNT_COMPROMISE = "account_compromise"; PRIVILEGE_ESCALATION = "privilege_escalation"
        INSIDER_THREAT = "insider_threat"; RANSOMWARE = "ransomware"; PHISHING = "phishing"
        UNKNOWN = "unknown"
    response_config = {}
    tool_paths = {}
    CONFIG_AVAILABLE = False
    MODULE_PATH = Path(__file__).resolve().parent
    AUDIT_AVAILABLE = False

# --- Configuration ---
DEFAULT_STORAGE_DIR = "/secure/incidents"  # Default, should be overridden by config
DEFAULT_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_HISTORY_ITEMS = 100  # Maximum number of history items to keep
MAX_NOTES_ITEMS = 200    # Maximum number of notes to keep
LOCKFILE_TIMEOUT = 30    # Seconds to wait for a lockfile before giving up
FILE_PERMISSIONS = 0o600  # Owner read/write only
CACHE_DURATION = 300     # Cache incident data for 5 minutes

# Configure logging
LOG_LEVEL = response_config.get("logging", {}).get("level", "INFO").upper()
LOG_FILE_PATH = response_config.get("logging", {}).get("file")  # Use path from config if available

logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename=LOG_FILE_PATH,  # Log to file if configured
    filemode='a'
)
logger = logging.getLogger(__name__)
# Add console handler if not logging to file or if verbose needed
if not LOG_FILE_PATH or LOG_LEVEL == "DEBUG":
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(LOG_LEVEL)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    if not logger.hasHandlers():  # Avoid duplicate console logs if root logger already has one
        logger.addHandler(console_handler)

# Determine storage path from config or use default
if CONFIG_AVAILABLE and response_config.get("evidence_collection", {}).get("base_dir"):
    # Store incident status data within a subdirectory of the evidence base dir
    STORAGE_DIR = Path(response_config["evidence_collection"]["base_dir"]) / "incident_status"
else:
    STORAGE_DIR = Path(DEFAULT_STORAGE_DIR)

# In-memory cache for incident data to reduce disk I/O
INCIDENT_CACHE = {}
INCIDENT_CACHE_TIMESTAMPS = {}

# --- Helper Functions ---

def sanitize_incident_id(incident_id: str) -> str:
    """
    Sanitize incident ID to ensure it only contains safe characters.

    Args:
        incident_id: The incident ID to sanitize

    Returns:
        Sanitized incident ID string
    """
    if not incident_id:
        raise ValueError("Incident ID cannot be empty")

    # Only allow alphanumeric characters, hyphens and underscores
    return re.sub(r'[^a-zA-Z0-9\-_]', '_', incident_id)

def get_incident_file_path(incident_id: str) -> Path:
    """
    Constructs the file path for a given incident ID.

    Args:
        incident_id: The incident ID to get a file path for

    Returns:
        Path object for the incident's JSON file
    """
    safe_incident_id = sanitize_incident_id(incident_id)
    filename = f"{safe_incident_id}_status.json"
    return STORAGE_DIR / filename

def get_incident_lock_path(incident_id: str) -> Path:
    """
    Constructs the lock file path for a given incident ID.

    Args:
        incident_id: The incident ID to get a lock file path for

    Returns:
        Path object for the incident's lock file
    """
    safe_incident_id = sanitize_incident_id(incident_id)
    filename = f"{safe_incident_id}.lock"
    return STORAGE_DIR / filename

def acquire_lock(incident_id: str) -> bool:
    """
    Acquires a lock on the incident file to prevent concurrent modifications.

    Args:
        incident_id: The incident ID to lock

    Returns:
        True if lock was acquired, False otherwise
    """
    lock_file = get_incident_lock_path(incident_id)

    # Create directory if it doesn't exist
    lock_file.parent.mkdir(parents=True, exist_ok=True)

    start_time = time.time()
    while time.time() - start_time < LOCKFILE_TIMEOUT:
        try:
            # Try to create the lock file exclusively
            with open(lock_file, 'x') as f:
                # Write process ID and timestamp to the lock file
                f.write(f"{os.getpid()},{datetime.now(timezone.utc).isoformat()}")
            return True
        except FileExistsError:
            # Check if the lock file is stale (older than 5 minutes)
            try:
                if lock_file.exists() and (time.time() - lock_file.stat().st_mtime > 300):
                    logger.warning(f"Removing stale lock file for incident {incident_id}")
                    os.unlink(lock_file)
                    continue
            except OSError:
                pass  # Ignore errors checking lock file

            # Wait a bit before retrying
            time.sleep(0.5)

    logger.error(f"Failed to acquire lock for incident {incident_id}")
    return False

def release_lock(incident_id: str) -> None:
    """
    Releases the lock on the incident file.

    Args:
        incident_id: The incident ID to unlock
    """
    lock_file = get_incident_lock_path(incident_id)
    try:
        if lock_file.exists():
            os.unlink(lock_file)
    except OSError as e:
        logger.warning(f"Error releasing lock for incident {incident_id}: {e}")

def load_incident_data(incident_id: str, bypass_cache: bool = False) -> Optional[Dict[str, Any]]:
    """
    Loads incident status data from its JSON file or cache.

    Args:
        incident_id: The incident ID to load data for
        bypass_cache: If True, bypass the cache and read directly from disk

    Returns:
        Dictionary with incident data or None if not found
    """
    # Check in-memory cache first unless bypass_cache is True
    if not bypass_cache and incident_id in INCIDENT_CACHE:
        # Check if cache is still valid
        cache_time = INCIDENT_CACHE_TIMESTAMPS.get(incident_id, 0)
        if time.time() - cache_time < CACHE_DURATION:
            return INCIDENT_CACHE[incident_id]

    file_path = get_incident_file_path(incident_id)
    if not file_path.exists():
        logger.warning(f"Incident status file not found for ID: {incident_id}")
        return None

    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            logger.debug(f"Loaded incident data for {incident_id} from {file_path}")

            # Update cache
            INCIDENT_CACHE[incident_id] = data
            INCIDENT_CACHE_TIMESTAMPS[incident_id] = time.time()

            return data
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON from file: {file_path}")
        return None
    except IOError as e:
        logger.error(f"Error reading incident file {file_path}: {e}")
        return None

def save_incident_data(incident_id: str, data: Dict[str, Any], verify: bool = True) -> bool:
    """
    Saves incident status data to its JSON file with proper locking.

    Args:
        incident_id: The incident ID to save data for
        data: The incident data to save
        verify: If True, verify the saved file integrity

    Returns:
        True if save was successful, False otherwise
    """
    file_path = get_incident_file_path(incident_id)

    # Acquire lock first
    if not acquire_lock(incident_id):
        logger.error(f"Failed to acquire lock for incident {incident_id}, cannot save")
        return False

    try:
        # Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Write to a temporary file first
        temp_file = file_path.with_suffix('.tmp')
        with open(temp_file, 'w') as f:
            json.dump(data, f, indent=4, default=str)  # Use default=str for datetime etc.

        # Set secure permissions
        os.chmod(temp_file, FILE_PERMISSIONS)

        # Verify the file can be read correctly
        if verify:
            try:
                with open(temp_file, 'r') as f:
                    json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Verification of temporary file failed: {e}")
                os.unlink(temp_file)
                return False

        # Calculate hash for audit purposes
        file_hash = None
        if AUDIT_AVAILABLE and 'calculate_file_hash' in globals():
            try:
                file_hash = calculate_file_hash(str(temp_file))
            except Exception as e:
                logger.warning(f"Failed to calculate file hash: {e}")

        # Replace the real file with the temporary one
        if os.path.exists(file_path):
            backup_path = file_path.with_suffix('.bak')
            os.replace(file_path, backup_path)

        os.replace(temp_file, file_path)

        logger.info(f"Saved incident data for {incident_id} to {file_path}")

        # Audit the file modification if available
        if AUDIT_AVAILABLE and 'log_security_event' in globals():
            try:
                log_security_event(
                    event_type="incident_status_update",
                    description=f"Updated incident status for {incident_id}",
                    severity="info",
                    source_file=str(file_path),
                    file_hash=file_hash
                )
            except Exception as e:
                logger.warning(f"Failed to audit incident update: {e}")

        # Update cache
        INCIDENT_CACHE[incident_id] = data
        INCIDENT_CACHE_TIMESTAMPS[incident_id] = time.time()

        return True

    except IOError as e:
        logger.error(f"Error writing incident file {file_path}: {e}")
        return False
    except TypeError as e:
        logger.error(f"Error serializing incident data for {incident_id}: {e}")
        return False
    finally:
        # Always release the lock
        release_lock(incident_id)

def get_current_timestamp() -> str:
    """Returns the current time in UTC ISO format."""
    return datetime.now(timezone.utc).strftime(DEFAULT_TIMESTAMP_FORMAT)

def get_user_identity() -> str:
    """
    Gets the current user identity, trying multiple methods.

    Returns:
        String identifying the current user
    """
    # Try different environment variables
    for env_var in ["USER", "USERNAME", "LOGNAME"]:
        if env_var in os.environ:
            return os.environ[env_var]

    # Fallback
    try:
        import getpass
        return getpass.getuser()
    except:
        return "unknown"

def validate_incident_type(incident_type: str) -> str:
    """
    Validates an incident type against known types.

    Args:
        incident_type: String incident type to validate

    Returns:
        Valid incident type string
    """
    # Get all valid incident types from the IncidentType class
    valid_types = [
        attr for attr in dir(IncidentType)
        if not attr.startswith('_') and isinstance(getattr(IncidentType, attr), str)
    ]

    # First, check for exact match
    if incident_type in valid_types:
        return incident_type

    # Then, check for case-insensitive match
    for valid_type in valid_types:
        if incident_type.lower() == valid_type.lower():
            return valid_type

    # If it's an attribute of IncidentType class, use that
    if hasattr(IncidentType, incident_type.upper()):
        return getattr(IncidentType, incident_type.upper())

    # Fallback to unknown
    logger.warning(f"Unknown incident type: {incident_type}, using default")
    return IncidentType.UNKNOWN

def validate_incident_severity(severity: str) -> str:
    """
    Validates an incident severity level.

    Args:
        severity: String severity level to validate

    Returns:
        Valid severity string
    """
    # Get all valid severity levels from the IncidentSeverity class
    valid_levels = [
        attr for attr in dir(IncidentSeverity)
        if not attr.startswith('_') and isinstance(getattr(IncidentSeverity, attr), str)
    ]

    # First, check for exact match
    if severity in valid_levels:
        return severity

    # Then, check for case-insensitive match
    for valid_level in valid_levels:
        if severity.lower() == valid_level.lower():
            return valid_level

    # If it's an attribute of IncidentSeverity class, use that
    if hasattr(IncidentSeverity, severity.upper()):
        return getattr(IncidentSeverity, severity.upper())

    # Fallback to medium
    logger.warning(f"Unknown severity level: {severity}, using default")
    return IncidentSeverity.MEDIUM

def prune_history(data: Dict[str, Any], max_items: int = MAX_HISTORY_ITEMS) -> Dict[str, Any]:
    """
    Prunes history and notes lists to prevent unlimited growth.

    Args:
        data: Incident data dictionary
        max_items: Maximum number of items to keep

    Returns:
        Updated incident data dictionary
    """
    # Sort history by timestamp (newest first) and keep only the newest entries
    if 'history' in data and isinstance(data['history'], list) and len(data['history']) > max_items:
        data['history'] = sorted(
            data['history'],
            key=lambda x: x.get('timestamp', ''),
            reverse=True
        )[:max_items]

    # Sort notes by timestamp (newest first) and keep only the newest entries
    if 'notes' in data and isinstance(data['notes'], list) and len(data['notes']) > MAX_NOTES_ITEMS:
        data['notes'] = sorted(
            data['notes'],
            key=lambda x: x.get('timestamp', ''),
            reverse=True
        )[:MAX_NOTES_ITEMS]

    return data

def list_incidents(status: Optional[str] = None, since: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    List incidents with optional filtering.

    Args:
        status: Filter by incident status
        since: List incidents created or updated in the last N days

    Returns:
        List of incident summary dictionaries
    """
    result = []
    cutoff = None

    if since is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=since)

    try:
        # Ensure storage directory exists
        STORAGE_DIR.mkdir(parents=True, exist_ok=True)

        # Find all incident JSON files
        for file_path in STORAGE_DIR.glob("*_status.json"):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)

                # Apply filters
                if status is not None and data.get('status') != status:
                    continue

                if cutoff is not None:
                    # Parse timestamps
                    created_at = data.get('created_at')
                    updated_at = data.get('updated_at')

                    if not created_at and not updated_at:
                        continue

                    # Parse timestamps to datetime objects
                    try:
                        if created_at:
                            created_dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                        else:
                            created_dt = None

                        if updated_at:
                            updated_dt = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
                        else:
                            updated_dt = None

                        # Skip if both timestamps are before cutoff
                        if (not created_dt or created_dt < cutoff) and (not updated_dt or updated_dt < cutoff):
                            continue
                    except (ValueError, TypeError):
                        # If we can't parse the dates, include the incident just to be safe
                        pass

                # Create summary item with key fields
                summary = {
                    'incident_id': data.get('incident_id'),
                    'status': data.get('status'),
                    'phase': data.get('current_phase'),
                    'severity': data.get('severity'),
                    'type': data.get('incident_type'),
                    'created_at': data.get('created_at'),
                    'updated_at': data.get('updated_at'),
                    'lead_responder': data.get('lead_responder'),
                    'description': data.get('description')
                }

                result.append(summary)
            except (json.JSONDecodeError, IOError) as e:
                logger.error(f"Error reading incident file {file_path}: {e}")

        # Sort by updated_at (newest first)
        result.sort(key=lambda x: x.get('updated_at', ''), reverse=True)

        return result

    except Exception as e:
        logger.error(f"Error listing incidents: {e}")
        return []

# --- Core Functions ---

def initialize_incident_status(incident_id: str, incident_type: str, severity: str,
                              lead_responder: Optional[str] = None, description: Optional[str] = None) -> bool:
    """
    Initializes the status tracking file for a new incident.

    Args:
        incident_id: Unique identifier for the incident
        incident_type: Type of incident (malware, phishing, etc.)
        severity: Severity level (critical, high, medium, low)
        lead_responder: Name/email of the lead responder
        description: Brief description of the incident

    Returns:
        True if initialization was successful, False otherwise
    """
    # Verify incident ID is valid
    incident_id = sanitize_incident_id(incident_id)

    # Validate incident doesn't already exist
    if load_incident_data(incident_id) is not None:
        logger.warning(f"Incident {incident_id} status file already exists. Cannot re-initialize.")
        return False

    # Validate and normalize incident type
    incident_type = validate_incident_type(incident_type)

    # Validate and normalize severity
    severity = validate_incident_severity(severity)

    # Get current user
    user = get_user_identity()

    # Get current timestamp
    timestamp = get_current_timestamp()

    data = {
        "incident_id": incident_id,
        "incident_type": incident_type,
        "severity": severity,
        "status": IncidentStatus.OPEN,
        "current_phase": IncidentPhase.IDENTIFICATION,
        "lead_responder": lead_responder,
        "description": description,
        "created_at": timestamp,
        "updated_at": timestamp,
        "created_by": user,
        "history": [
            {
                "timestamp": timestamp,
                "action": "Initialized",
                "user": user,
                "details": {
                    "type": incident_type,
                    "severity": severity,
                    "lead": lead_responder,
                    "description": description
                }
            }
        ],
        "notes": []
    }

    logger.info(f"Initializing status tracking for incident {incident_id}")

    # Audit the creation if available
    if AUDIT_AVAILABLE and 'log_security_event' in globals():
        try:
            log_security_event(
                event_type="incident_created",
                description=f"Incident {incident_id} created with type {incident_type}, severity {severity}",
                severity="info",
                user_id=user
            )
        except Exception as e:
            logger.warning(f"Failed to audit incident creation: {e}")

    return save_incident_data(incident_id, data)

def update_incident_status(incident_id: str, phase: Optional[str] = None, status: Optional[str] = None,
                          notes: Optional[str] = None, user: Optional[str] = None,
                          escalation: Optional[bool] = None) -> bool:
    """
    Updates the phase, status, or adds notes to an incident.

    Args:
        incident_id: Unique identifier for the incident
        phase: New phase for the incident (containment, eradication, etc.)
        status: New status for the incident (investigating, contained, etc.)
        notes: Notes to add to the incident log
        user: User making the update (defaults to current system user)
        escalation: Whether this update represents an escalation

    Returns:
        True if update was successful, False otherwise
    """
    # Verify incident ID is valid
    incident_id = sanitize_incident_id(incident_id)

    # Try to load the incident data
    data = load_incident_data(incident_id)
    if data is None:
        logger.error(f"Cannot update status for non-existent incident: {incident_id}")
        return False

    updated = False
    timestamp = get_current_timestamp()
    user = user or get_user_identity()
    action_details = {}

    # Update phase if provided
    if phase:
        # Validate phase
        valid_phases = [
            attr for attr in dir(IncidentPhase)
            if not attr.startswith('_') and isinstance(getattr(IncidentPhase, attr), str)
        ]

        # Try case-insensitive match
        matched_phase = None
        for valid_phase in valid_phases:
            if phase.lower() == valid_phase.lower() or phase.lower() == getattr(IncidentPhase, valid_phase).lower():
                matched_phase = getattr(IncidentPhase, valid_phase)
                break

        if not matched_phase and hasattr(IncidentPhase, phase.upper()):
            matched_phase = getattr(IncidentPhase, phase.upper())

        if matched_phase:
            phase = matched_phase
        else:
            logger.warning(f"Invalid phase: {phase}, ignoring")
            phase = None

        if phase and phase != data.get("current_phase"):
            old_phase = data.get("current_phase")
            data["current_phase"] = phase
            action_details['phase_change'] = {'old': old_phase, 'new': phase}
            updated = True
            logger.info(f"Incident {incident_id}: Phase updated to {phase} by {user}")

    # Update status if provided
    if status:
        # Validate status
        valid_statuses = [
            attr for attr in dir(IncidentStatus)
            if not attr.startswith('_') and isinstance(getattr(IncidentStatus, attr), str)
        ]

        # Try case-insensitive match
        matched_status = None
        for valid_status in valid_statuses:
            if status.lower() == valid_status.lower() or status.lower() == getattr(IncidentStatus, valid_status).lower():
                matched_status = getattr(IncidentStatus, valid_status)
                break

        if not matched_status and hasattr(IncidentStatus, status.upper()):
            matched_status = getattr(IncidentStatus, status.upper())

        if matched_status:
            status = matched_status
        else:
            logger.warning(f"Invalid status: {status}, ignoring")
            status = None

        if status and status != data.get("status"):
            old_status = data.get("status")
            data["status"] = status
            action_details['status_change'] = {'old': old_status, 'new': status}
            updated = True
            logger.info(f"Incident {incident_id}: Status updated to {status} by {user}")

    # Handle escalation flag
    if escalation is not None:
        # Update severity if escalating
        if escalation and data.get("severity") != IncidentSeverity.CRITICAL:
            old_severity = data.get("severity")
            data["severity"] = IncidentSeverity.CRITICAL
            action_details['severity_change'] = {'old': old_severity, 'new': IncidentSeverity.CRITICAL}
            action_details['escalated'] = True
            updated = True
            logger.info(f"Incident {incident_id}: Escalated to CRITICAL by {user}")

    # Add notes if provided
    if notes:
        note_entry = {
            "timestamp": timestamp,
            "user": user,
            "note": notes
        }
        if "notes" not in data:
            data["notes"] = []
        data["notes"].append(note_entry)
        action_details['note_added'] = notes[:100] + ('...' if len(notes) > 100 else '')  # Log truncated note
        updated = True
        logger.info(f"Incident {incident_id}: Note added by {user}")

    # If any updates were made, update metadata and history
    if updated:
        # Update timestamp
        data["updated_at"] = timestamp

        # Add history entry
        history_entry = {
            "timestamp": timestamp,
            "action": "Update",
            "user": user,
            "details": action_details
        }
        if "history" not in data:
            data["history"] = []
        data["history"].append(history_entry)

        # Prune history to prevent unlimited growth
        data = prune_history(data)

        # Audit the update if available
        if AUDIT_AVAILABLE and 'log_security_event' in globals():
            try:
                log_security_event(
                    event_type="incident_updated",
                    description=f"Incident {incident_id} updated by {user}",
                    severity="info",
                    user_id=user,
                    metadata=action_details
                )
            except Exception as e:
                logger.warning(f"Failed to audit incident update: {e}")

        # Save the updated data
        return save_incident_data(incident_id, data)
    else:
        logger.info(f"No status/phase changes or notes provided for incident {incident_id}. No update performed.")
        return True  # No error, just no change

def get_incident_status(incident_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves the current status data for an incident.

    Args:
        incident_id: Unique identifier for the incident

    Returns:
        Dictionary with incident status data or None if not found
    """
    # Verify incident ID is valid
    incident_id = sanitize_incident_id(incident_id)

    # Load incident data
    data = load_incident_data(incident_id)
    if data is None:
        logger.error(f"Incident status file not found for ID: {incident_id}")
        return None

    return data

def generate_report(incident_id: str, output_format: str = 'text', include_all: bool = False) -> Optional[str]:
    """
    Generates a status report for the incident.

    Args:
        incident_id: Unique identifier for the incident
        output_format: Format to generate ('text' or 'json')
        include_all: Whether to include all history and notes (vs. latest 10)

    Returns:
        Report string in the requested format or None if error
    """
    # Verify incident ID is valid
    incident_id = sanitize_incident_id(incident_id)

    # Get incident data
    data = get_incident_status(incident_id)
    if data is None:
        return None

    # Generate report in the requested format
    if output_format == 'json':
        return json.dumps(data, indent=4, default=str)

    elif output_format == 'text':
        report_lines = [
            f"Incident Status Report: {data.get('incident_id', 'N/A')}",
            f"========================================",
            f"Type:         {data.get('incident_type', 'N/A')}",
            f"Severity:     {data.get('severity', 'N/A')}",
            f"Status:       {data.get('status', 'N/A')}",
            f"Phase:        {data.get('current_phase', 'N/A')}",
            f"Lead:         {data.get('lead_responder', 'N/A')}",
            f"Created:      {data.get('created_at', 'N/A')}",
            f"Last Updated: {data.get('updated_at', 'N/A')}",
            f"Description:  {data.get('description', 'N/A')}",
        ]

        # Add metrics if available
        if "metrics" in data:
            report_lines.append("\n--- Metrics ---")
            metrics = data["metrics"]
            for key, value in metrics.items():
                report_lines.append(f"  {key}: {value}")

        # Add history section
        report_lines.append("\n--- History ---")
        history = data.get('history', [])

        # Sort by timestamp (newest first) and limit unless include_all is True
        history_to_show = sorted(
            history,
            key=lambda x: x.get('timestamp', ''),
            reverse=True
        )

        if not include_all:
            history_to_show = history_to_show[:10]  # Show last 10 history items by default

        if not history_to_show:
            report_lines.append("  No history available")
        else:
            for entry in history_to_show:
                # Format details for cleaner display
                details = entry.get('details', {})
                details_formatted = []

                for key, value in details.items():
                    if key == 'phase_change' and isinstance(value, dict):
                        details_formatted.append(f"phase changed from '{value.get('old')}' to '{value.get('new')}'")
                    elif key == 'status_change' and isinstance(value, dict):
                        details_formatted.append(f"status changed from '{value.get('old')}' to '{value.get('new')}'")
                    elif key == 'severity_change' and isinstance(value, dict):
                        details_formatted.append(f"severity changed from '{value.get('old')}' to '{value.get('new')}'")
                    elif key == 'note_added':
                        details_formatted.append(f"note added")
                    elif key == 'escalated' and value:
                        details_formatted.append("incident escalated")
                    else:
                        details_formatted.append(f"{key}: {value}")

                details_str = ", ".join(details_formatted) if details_formatted else ""
                report_lines.append(f"  [{entry.get('timestamp')}] {entry.get('action')} by {entry.get('user')}: {details_str}")

        # Add notes section
        report_lines.append("\n--- Notes ---")
        notes = data.get('notes', [])

        # Sort by timestamp (newest first) and limit unless include_all is True
        notes_to_show = sorted(
            notes,
            key=lambda x: x.get('timestamp', ''),
            reverse=True
        )

        if not include_all:
            notes_to_show = notes_to_show[:10]  # Show last 10 notes by default

        if not notes_to_show:
            report_lines.append("  No notes available")
        else:
            for entry in notes_to_show:
                report_lines.append(f"  [{entry.get('timestamp')}] by {entry.get('user')}:")
                note_text = entry.get('note', '')

                # Format multi-line notes with proper indentation
                if '\n' in note_text:
                    note_lines = note_text.split('\n')
                    report_lines.append(f"    {note_lines[0]}")
                    for line in note_lines[1:]:
                        report_lines.append(f"    {line}")
                else:
                    report_lines.append(f"    {note_text}")

        return "\n".join(report_lines)

    else:
        logger.error(f"Unsupported report format: {output_format}")
        return None

def update_incident_metrics(incident_id: str, metrics: Dict[str, Any]) -> bool:
    """
    Updates metrics associated with an incident.

    Args:
        incident_id: Unique identifier for the incident
        metrics: Dictionary of metrics to update

    Returns:
        True if update was successful, False otherwise
    """
    # Verify incident ID is valid
    incident_id = sanitize_incident_id(incident_id)

    # Get incident data
    data = load_incident_data(incident_id)
    if data is None:
        logger.error(f"Cannot update metrics for non-existent incident: {incident_id}")
        return False

    # Update or create metrics
    if "metrics" not in data:
        data["metrics"] = {}

    # Merge the provided metrics with existing metrics
    for key, value in metrics.items():
        data["metrics"][key] = value

    # Update timestamp
    data["updated_at"] = get_current_timestamp()

    # Save the updated data
    return save_incident_data(incident_id, data)

def add_related_incident(incident_id: str, related_id: str, relationship_type: str = "related",
                        user: Optional[str] = None) -> bool:
    """
    Adds a relationship between incidents.

    Args:
        incident_id: Primary incident ID to update
        related_id: Related incident ID
        relationship_type: Type of relationship (related, parent, child, etc.)
        user: User creating the relationship

    Returns:
        True if update was successful, False otherwise
    """
    # Verify incident IDs are valid
    incident_id = sanitize_incident_id(incident_id)
    related_id = sanitize_incident_id(related_id)

    if incident_id == related_id:
        logger.error(f"Cannot relate an incident to itself: {incident_id}")
        return False

    # Load incident data
    data = load_incident_data(incident_id)
    if data is None:
        logger.error(f"Cannot update non-existent incident: {incident_id}")
        return False

    # Verify related incident exists
    related_data = load_incident_data(related_id)
    if related_data is None:
        logger.error(f"Related incident does not exist: {related_id}")
        return False

    # Initialize relationships if needed
    if "relationships" not in data:
        data["relationships"] = []

    # Avoid duplicates
    for rel in data["relationships"]:
        if rel.get("incident_id") == related_id:
            # Relationship already exists, possibly update type
            if rel.get("relationship_type") != relationship_type:
                rel["relationship_type"] = relationship_type
                rel["updated_at"] = get_current_timestamp()
                rel["updated_by"] = user or get_user_identity()

                # Update timestamp and history
                timestamp = get_current_timestamp()
                data["updated_at"] = timestamp

                if "history" not in data:
                    data["history"] = []

                data["history"].append({
                    "timestamp": timestamp,
                    "action": "Update Relationship",
                    "user": user or get_user_identity(),
                    "details": {
                        "related_incident": related_id,
                        "relationship_type": relationship_type,
                        "previous_relationship_type": rel.get("relationship_type")
                    }
                })

                # Save the updated data
                return save_incident_data(incident_id, data)

            # No change needed
            return True

    # Add new relationship
    timestamp = get_current_timestamp()
    username = user or get_user_identity()

    data["relationships"].append({
        "incident_id": related_id,
        "relationship_type": relationship_type,
        "created_at": timestamp,
        "created_by": username
    })

    # Update timestamp and history
    data["updated_at"] = timestamp

    if "history" not in data:
        data["history"] = []

    data["history"].append({
        "timestamp": timestamp,
        "action": "Add Relationship",
        "user": username,
        "details": {
            "related_incident": related_id,
            "relationship_type": relationship_type
        }
    })

    # Prune history to prevent unlimited growth
    data = prune_history(data)

    # Save the updated data
    return save_incident_data(incident_id, data)

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="Track and update security incident status.")
    parser.add_argument("--incident-id", required=False, help="Unique identifier for the incident.")

    # Actions
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("--initialize", action="store_true", help="Initialize status tracking for a new incident.")
    action_group.add_argument("--update", action="store_true", help="Update the status, phase, or add notes.")
    action_group.add_argument("--query", action="store_true", help="Query the current status of the incident.")
    action_group.add_argument("--generate-report", action="store_true", help="Generate a status report.")
    action_group.add_argument("--list", action="store_true", help="List incidents with optional filtering.")
    action_group.add_argument("--add-relationship", action="store_true", help="Add a relationship to another incident.")

    # Initialization arguments (used with --initialize)
    parser.add_argument("--type", help="Incident type (e.g., malware, phishing). Required for --initialize.")
    parser.add_argument("--severity", help="Incident severity (e.g., critical, high). Required for --initialize.")
    parser.add_argument("--lead-responder", help="Lead responder identifier.")
    parser.add_argument("--description", help="Brief description of the incident.")

    # Update arguments (used with --update)
    parser.add_argument("--update-phase", dest="phase", help="New phase for the incident (e.g., containment).")
    parser.add_argument("--status", dest="status_update", help="New status for the incident (e.g., investigating).")
    parser.add_argument("--notes", help="Add notes to the incident log.")
    parser.add_argument("--user", help="User performing the update (defaults to current system user).")
    parser.add_argument("--escalate", action="store_true", help="Escalate the incident to critical severity.")

    # List arguments
    parser.add_argument("--filter-status", help="Filter incidents by status.")
    parser.add_argument("--since", type=int, help="List incidents updated in the last N days.")

    # Relationship arguments
    parser.add_argument("--related-id", help="ID of related incident for relationship management.")
    parser.add_argument("--relationship-type", default="related",
                       choices=["related", "parent", "child", "duplicate", "superseded"],
                       help="Type of relationship between incidents.")

    # Reporting arguments (used with --generate-report)
    parser.add_argument("--format", default="text", choices=["text", "json"], help="Report output format.")
    parser.add_argument("--all", action="store_true", help="Include all history and notes in the report.")
    parser.add_argument("--output-file", help="Save report to the specified file.")

    args = parser.parse_args()

    try:
        # Ensure directory exists
        STORAGE_DIR.mkdir(parents=True, exist_ok=True)

        # List incidents
        if args.list:
            incidents = list_incidents(
                status=args.filter_status,
                since=args.since
            )

            if not incidents:
                print("No incidents found.")
                return

            if args.format == "json":
                print(json.dumps(incidents, indent=4, default=str))
            else:
                # Text format table
                print(f"{'ID':<20} {'Type':<15} {'Severity':<10} {'Status':<15} {'Phase':<15} {'Last Updated':<25}")
                print("=" * 100)

                for incident in incidents:
                    print(f"{incident.get('incident_id', 'N/A'):<20} "
                          f"{incident.get('type', 'N/A'):<15} "
                          f"{incident.get('severity', 'N/A'):<10} "
                          f"{incident.get('status', 'N/A'):<15} "
                          f"{incident.get('phase', 'N/A'):<15} "
                          f"{incident.get('updated_at', 'N/A'):<25}")
            return

        # All other options require an incident ID
        if not args.incident_id:
            parser.error("--incident-id is required for this operation.")

        incident_id = args.incident_id

        if args.initialize:
            if not args.type or not args.severity:
                parser.error("--type and --severity are required for --initialize.")

            logger.info(f"Action: Initialize incident {incident_id}")
            success = initialize_incident_status(
                incident_id,
                args.type,
                args.severity,
                args.lead_responder,
                args.description
            )

            if success:
                print(f"Successfully initialized incident: {incident_id}")
            else:
                print(f"Failed to initialize incident: {incident_id}")
                sys.exit(1)

        elif args.update:
            if not args.phase and not args.status_update and not args.notes and not args.escalate:
                parser.error("At least one of --update-phase, --status, --notes, or --escalate must be provided for --update.")

            logger.info(f"Action: Update incident {incident_id}")
            success = update_incident_status(
                incident_id,
                args.phase,
                args.status_update,
                args.notes,
                args.user,
                args.escalate
            )

            if success:
                print(f"Successfully updated incident: {incident_id}")
            else:
                print(f"Failed to update incident: {incident_id}")
                sys.exit(1)

        elif args.query:
            logger.info(f"Action: Query incident {incident_id}")
            data = get_incident_status(incident_id)

            if data:
                print(json.dumps(data, indent=4, default=str))
            else:
                print(f"Error: Incident not found: {incident_id}")
                sys.exit(1)

        elif args.generate_report:
            logger.info(f"Action: Generate report for incident {incident_id} (Format: {args.format})")
            report = generate_report(incident_id, args.format, args.all)

            if report:
                # Save to file if specified
                if args.output_file:
                    try:
                        with open(args.output_file, 'w') as f:
                            f.write(report)
                        print(f"Report saved to: {args.output_file}")
                    except IOError as e:
                        print(f"Error saving report to file: {e}")
                        sys.exit(1)
                else:
                    # Print to stdout
                    print(report)
            else:
                print(f"Error: Failed to generate report for incident: {incident_id}")
                sys.exit(1)

        elif args.add_relationship:
            if not args.related_id:
                parser.error("--related-id is required when adding a relationship.")

            logger.info(f"Action: Add relationship between {incident_id} and {args.related_id}")
            success = add_related_incident(
                incident_id,
                args.related_id,
                args.relationship_type,
                args.user
            )

            if success:
                print(f"Successfully added relationship: {incident_id} -> {args.relationship_type} -> {args.related_id}")
            else:
                print(f"Failed to add relationship between incidents.")
                sys.exit(1)

    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Basic check for storage directory writability
    try:
        # Ensure directory exists
        STORAGE_DIR.mkdir(parents=True, exist_ok=True)

        # Check if writable
        test_path = STORAGE_DIR / ".write_test"
        try:
            with open(test_path, 'w') as f:
                f.write("test")
            os.unlink(test_path)
        except IOError:
            logger.critical(f"Error: Storage directory '{STORAGE_DIR}' is not writable. Cannot proceed.")
            sys.exit(1)
    except Exception as e:
        logger.critical(f"Error accessing storage directory '{STORAGE_DIR}': {e}")
        sys.exit(1)

    main()
