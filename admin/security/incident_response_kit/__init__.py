"""
Incident Response Toolkit Package

This package provides tools and utilities for coordinating and executing security incident
response activities, following the NIST SP 800-61 incident handling framework. The toolkit
covers the complete incident lifecycle: preparation, detection and analysis, containment,
eradication, recovery, and post-incident activities.

The toolkit integrates multiple components including coordination tools, documentation templates,
forensic tools, recovery tools, and reference materials to provide a comprehensive platform for
security incident response.
"""

import os
import sys
import logging
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple, Set, Callable

# Package versioning
__version__ = '0.1.1'
__author__ = 'Security Team'
__email__ = 'security-team@example.com'

# Initialize package logging
logger = logging.getLogger(__name__)

# Determine module base path
MODULE_PATH = Path(os.path.dirname(os.path.abspath(__file__)))

# Load module availability flags
COORDINATION_AVAILABLE = os.path.exists(MODULE_PATH / "coordination")
DOCUMENTATION_AVAILABLE = os.path.exists(MODULE_PATH / "templates")
FORENSIC_TOOLS_AVAILABLE = os.path.exists(MODULE_PATH / "forensic_tools")
PLAYBOOKS_AVAILABLE = os.path.exists(MODULE_PATH / "playbooks")
RECOVERY_AVAILABLE = os.path.exists(MODULE_PATH / "recovery")
REFERENCES_AVAILABLE = os.path.exists(MODULE_PATH / "references")
CONFIG_AVAILABLE = os.path.exists(MODULE_PATH / "config")
VOLATILE_DATA_CAPTURE_AVAILABLE = os.path.exists(MODULE_PATH / "volatile_data_capture.py")

# Import constants from dedicated constants file

from .incident_constants import (
    IncidentStatus, IncidentPhase, IncidentSeverity, IncidentType,
    PHASE_STATUS_MAPPING, STATUS_TRANSITIONS, IncidentSource, EvidenceType,
    ActionType, PHASE_REQUIRED_ACTIONS, INCIDENT_TYPE_RECOMMENDED_EVIDENCE,
    SEVERITY_REQUIRED_NOTIFICATIONS
)
# Import the Incident class
try:
    from .incident import Incident
except ImportError as e:
    logger.error(f"Error importing Incident class: {e}")
    # Define basic fallback class
    class Incident:
        def __init__(self, incident_id, **kwargs):
            self.id = incident_id
            for key, value in kwargs.items():
                setattr(self, key, value)

        def update_status(self, status, user, notes=None):
            raise NotImplementedError("Incident class not properly imported")

        def update_phase(self, phase, user, notes=None):
            raise NotImplementedError("Incident class not properly imported")

        def add_note(self, note, user):
            raise NotImplementedError("Incident class not properly imported")

        def reopen(self, reason, user):
            raise NotImplementedError("Incident class not properly imported")

        def to_dict(self):
            return vars(self)

# Import the VolatileDataCapture class
try:
    from .volatile_data_capture import VolatileDataCapture
    logger.debug("Loaded VolatileDataCapture class")
    VOLATILE_DATA_CAPTURE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Failed to import volatile_data_capture module: {e}")
    VOLATILE_DATA_CAPTURE_AVAILABLE = False
    class VolatileDataCapture:
        def __init__(self, *args, **kwargs):
            raise NotImplementedError("VolatileDataCapture module not available")

# Load configurations
try:
    if CONFIG_AVAILABLE:
        with open(MODULE_PATH / "config" / "response_config.json", "r") as f:
            response_config = json.load(f)
        with open(MODULE_PATH / "config" / "tool_paths.json", "r") as f:
            tool_paths = json.load(f)

        # Set defaults from config
        DEFAULT_EVIDENCE_DIR = tool_paths.get("directories", {}).get("evidence", "/secure/evidence")
        DEFAULT_LOG_DIR = tool_paths.get("directories", {}).get("logs", "/var/log")
        DEFAULT_TEMP_DIR = tool_paths.get("directories", {}).get("temp", "/tmp/ir-toolkit")

        # Load notification settings
        NOTIFICATION_ENABLED = response_config.get("notification", {}).get("enabled", False)
        NOTIFICATION_CHANNELS = response_config.get("notification", {}).get("methods", [])
        CRITICAL_CONTACTS = response_config.get("notification", {}).get("critical_contacts", [])

        # Load evidence settings
        EVIDENCE_ENCRYPTION = response_config.get("evidence_collection", {}).get("encrypt", True)
        EVIDENCE_COMPRESSION = response_config.get("evidence_collection", {}).get("compress", True)
        EVIDENCE_RETENTION_DAYS = response_config.get("evidence_collection", {}).get("retention_days", 180)

        CONFIG_LOADED = True
    else:
        # Set reasonable defaults if config files aren't available
        DEFAULT_EVIDENCE_DIR = "/secure/evidence"
        DEFAULT_LOG_DIR = "/var/log"
        DEFAULT_TEMP_DIR = "/tmp/ir-toolkit"
        NOTIFICATION_ENABLED = False
        NOTIFICATION_CHANNELS = ["email"]
        CRITICAL_CONTACTS = []
        EVIDENCE_ENCRYPTION = True
        EVIDENCE_COMPRESSION = True
        EVIDENCE_RETENTION_DAYS = 180
        CONFIG_LOADED = False

except (FileNotFoundError, json.JSONDecodeError) as e:
    logger.warning(f"Failed to load configuration files: {e}")
    # Fall back to defaults
    DEFAULT_EVIDENCE_DIR = "/secure/evidence"
    DEFAULT_LOG_DIR = "/var/log"
    DEFAULT_TEMP_DIR = "/tmp/ir-toolkit"
    NOTIFICATION_ENABLED = False
    NOTIFICATION_CHANNELS = ["email"]
    CRITICAL_CONTACTS = []
    EVIDENCE_ENCRYPTION = True
    EVIDENCE_COMPRESSION = True
    EVIDENCE_RETENTION_DAYS = 180
    CONFIG_LOADED = False

# Exception classes
class IncidentResponseError(Exception):
    """Base exception for all incident response errors."""
    pass

class ConfigurationError(IncidentResponseError):
    """Error in configuration parameters."""
    pass

class InitializationError(IncidentResponseError):
    """Error initializing an incident."""
    pass

class EvidenceCollectionError(IncidentResponseError):
    """Error during evidence collection."""
    pass

class IsolationError(IncidentResponseError):
    """Error during system isolation."""
    pass

class NotificationError(IncidentResponseError):
    """Error sending notifications."""
    pass

class IncidentStatusError(IncidentResponseError):
    """Error updating incident status."""
    pass

class PlaybookExecutionError(IncidentResponseError):
    """Error running playbook steps."""
    pass

class RecoveryError(IncidentResponseError):
    """Error during recovery operations."""
    pass

class ValidationError(IncidentResponseError):
    """Error validating incident data."""
    pass

# Dynamically import and expose main functionality
def import_core_functions():
    global initialize_incident, collect_evidence, isolate_system, notify_stakeholders
    global update_status, run_playbook, restore_service, harden_system
    global track_incident_status, verify_file_integrity, build_timeline
    global get_incident_status, list_incidents, generate_report
    global capture_volatile_data, reopen_incident

    try:
        # Import primary functions from module scripts
        from .initialize import initialize_incident
        logger.debug("Loaded initialize_incident function")
    except ImportError as e:
        logger.warning(f"Failed to import initialize module: {e}")
        def initialize_incident(*args, **kwargs):
            raise NotImplementedError("Initialize module not available")

    try:
        from .collect_evidence import collect_evidence
        logger.debug("Loaded collect_evidence function")
    except ImportError as e:
        logger.warning(f"Failed to import collect_evidence module: {e}")
        def collect_evidence(*args, **kwargs):
            raise NotImplementedError("Evidence collection module not available")

    try:
        from .network_isolation import isolate_system
        logger.debug("Loaded isolate_system function")
    except ImportError as e:
        logger.warning(f"Failed to import network_isolation module: {e}")
        def isolate_system(*args, **kwargs):
            raise NotImplementedError("Network isolation module not available")

    # Import volatile data capture function if available
    try:
        from .volatile_data_capture import VolatileDataCapture

        def capture_volatile_data(incident_id=None, output_dir=None, analyst=None,
                                target=None, categories=None, minimal=False, **kwargs):
            capture = VolatileDataCapture(
                incident_id=incident_id,
                output_dir=output_dir,
                analyst=analyst,
                **kwargs
            )
            return capture.collect_data(target=target, categories=categories, minimal=minimal)
        logger.debug("Loaded capture_volatile_data function")
    except ImportError as e:
        logger.warning(f"Failed to import volatile_data_capture module: {e}")
        def capture_volatile_data(*args, **kwargs):
            raise NotImplementedError("Volatile data capture module not available")

    # Conditionally import coordination functions if available
    if COORDINATION_AVAILABLE:
        try:
            from .coordination.notification_system import notify_stakeholders
            logger.debug("Loaded notify_stakeholders function")
        except ImportError as e:
            logger.warning(f"Failed to import notification_system module: {e}")
            def notify_stakeholders(*args, **kwargs):
                raise NotImplementedError("Notification system not available")

        try:
            from .coordination.status_tracker import update_status, get_incident_status, list_incidents
            logger.debug("Loaded status_tracker functions")

            # Define reopen_incident function that uses update_status for reopening
            def reopen_incident(incident_id: str, reason: str, user: Optional[str] = None):
                """
                Reopen a previously closed or resolved incident.

                Args:
                    incident_id: The ID of the incident to reopen
                    reason: Reason for reopening the incident
                    user: User who is reopening the incident

                Returns:
                    bool: True if successful, False otherwise
                """
                try:
                    # Get current status
                    incident_data = get_incident_status(incident_id)
                    if not incident_data:
                        logger.error(f"Cannot reopen non-existent incident: {incident_id}")
                        return False

                    current_status = incident_data.get("status")

                    # Check if incident can be reopened
                    if current_status not in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
                        logger.warning(f"Incident {incident_id} has status {current_status} and cannot be reopened")
                        return False

                    # Use update_status to set status back to investigating
                    status_updated = update_status(
                        incident_id=incident_id,
                        status=IncidentStatus.INVESTIGATING,
                        notes=f"Incident reopened: {reason}",
                        user=user,
                        phase=IncidentPhase.IDENTIFICATION  # Reset phase to identification
                    )

                    if status_updated:
                        logger.info(f"Successfully reopened incident {incident_id}")
                    else:
                        logger.error(f"Failed to reopen incident {incident_id}")

                    return status_updated

                except Exception as e:
                    logger.error(f"Error reopening incident {incident_id}: {e}", exc_info=True)
                    return False

            logger.debug("Created reopen_incident function")

        except ImportError as e:
            logger.warning(f"Failed to import status_tracker module: {e}")
            def update_status(*args, **kwargs):
                raise NotImplementedError("Status tracker not available")
            def get_incident_status(*args, **kwargs):
                raise NotImplementedError("Status tracker not available")
            def list_incidents(*args, **kwargs):
                raise NotImplementedError("Status tracker not available")
            def reopen_incident(*args, **kwargs):
                raise NotImplementedError("Reopen incident function not available")

        try:
            from .coordination.status_tracker import initialize_incident_status as track_incident_status
            logger.debug("Loaded track_incident_status function")
        except ImportError as e:
            logger.warning(f"Failed to import track_incident_status function: {e}")
            def track_incident_status(*args, **kwargs):
                raise NotImplementedError("Status tracking not available")

        try:
            from .coordination.report_generator import generate_report
            logger.debug("Loaded generate_report function")
        except ImportError as e:
            logger.warning(f"Failed to import report_generator module: {e}")
            def generate_report(*args, **kwargs):
                raise NotImplementedError("Report generation not available")
    else:
        def notify_stakeholders(*args, **kwargs):
            raise NotImplementedError("Coordination modules not available")
        def update_status(*args, **kwargs):
            raise NotImplementedError("Coordination modules not available")
        def track_incident_status(*args, **kwargs):
            raise NotImplementedError("Status tracking not available")
        def get_incident_status(*args, **kwargs):
            raise NotImplementedError("Status tracking not available")
        def list_incidents(*args, **kwargs):
            raise NotImplementedError("Status tracking not available")
        def generate_report(*args, **kwargs):
            raise NotImplementedError("Report generation not available")
        def reopen_incident(*args, **kwargs):
            raise NotImplementedError("Reopen incident function not available")

    # Import playbook functions if available
    if PLAYBOOKS_AVAILABLE:
        try:
            from .run_playbook import run_playbook
            logger.debug("Loaded run_playbook function")
        except ImportError as e:
            logger.warning(f"Failed to import run_playbook module: {e}")
            def run_playbook(*args, **kwargs):
                raise NotImplementedError("Playbook module not available")
    else:
        def run_playbook(*args, **kwargs):
            raise NotImplementedError("Playbooks not available")

    # Import forensic tool functions if available
    if FORENSIC_TOOLS_AVAILABLE:
        try:
            from .forensic_tools.file_integrity import verify_file_integrity
            logger.debug("Loaded verify_file_integrity function")
        except ImportError as e:
            logger.warning(f"Failed to import file_integrity module: {e}")
            def verify_file_integrity(*args, **kwargs):
                raise NotImplementedError("File integrity verification not available")

        try:
            from .forensic_tools.timeline_builder import build_timeline
            logger.debug("Loaded build_timeline function")
        except ImportError as e:
            logger.warning(f"Failed to import timeline_builder module: {e}")
            def build_timeline(*args, **kwargs):
                raise NotImplementedError("Timeline building not available")
    else:
        def verify_file_integrity(*args, **kwargs):
            raise NotImplementedError("Forensic tools not available")
        def build_timeline(*args, **kwargs):
            raise NotImplementedError("Forensic tools not available")

    # Import recovery functions if available
    if RECOVERY_AVAILABLE:
        try:
            from .recovery.service_restoration import restore_service
            logger.debug("Loaded restore_service function")
        except ImportError as e:
            logger.warning(f"Failed to import service_restoration module: {e}")
            def restore_service(*args, **kwargs):
                raise NotImplementedError("Service restoration module not available")

        try:
            from .recovery.security_hardening import harden_system
            logger.debug("Loaded harden_system function")
        except ImportError as e:
            logger.warning(f"Failed to import security_hardening module: {e}")
            def harden_system(*args, **kwargs):
                raise NotImplementedError("Security hardening module not available")
    else:
        def restore_service(*args, **kwargs):
            raise NotImplementedError("Recovery modules not available")
        def harden_system(*args, **kwargs):
            raise NotImplementedError("Recovery modules not available")

# Import functions
import_core_functions()

# Check which components of the toolkit are available
def get_available_components() -> Dict[str, bool]:
    """Return a dictionary indicating which components of the toolkit are available."""
    return {
        "coordination": COORDINATION_AVAILABLE,
        "volatile_data_capture": VOLATILE_DATA_CAPTURE_AVAILABLE,
        "documentation": DOCUMENTATION_AVAILABLE,
        "playbooks": PLAYBOOKS_AVAILABLE,
        "forensic_tools": FORENSIC_TOOLS_AVAILABLE,
        "recovery": RECOVERY_AVAILABLE,
        "file_integrity": hasattr(verify_file_integrity, "__call__") and not isinstance(verify_file_integrity.__call__, type(NotImplementedError)),
        "timeline_building": hasattr(build_timeline, "__call__") and not isinstance(build_timeline.__call__, type(NotImplementedError)),
        "configuration": CONFIG_LOADED,
        "templates": DOCUMENTATION_AVAILABLE,
        "references": REFERENCES_AVAILABLE
    }

# Create evidence directory safely if it doesn't exist
def create_evidence_directory(incident_id: str) -> Path:
    """Create a directory for evidence collection based on incident ID."""
    incident_id = sanitize_incident_id(incident_id)
    evidence_dir = Path(DEFAULT_EVIDENCE_DIR) / incident_id

    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        return evidence_dir
    except (OSError, PermissionError) as e:
        logger.error(f"Failed to create evidence directory for incident {incident_id}: {e}")
        raise EvidenceCollectionError(f"Failed to create evidence directory: {e}")

# Sanitize incident ID to ensure it's safe for file operations
def sanitize_incident_id(incident_id: str) -> str:
    """Sanitize incident ID to ensure it's safe for file operations."""
    # Replace any characters that are not alphanumeric, dash, or underscore
    import re
    return re.sub(r'[^a-zA-Z0-9_\-]', '_', incident_id)

# Check file integrity
def check_file_integrity(
    file_path: Union[str, Path],
    expected_hash: Optional[str] = None,
    hash_algorithm: str = 'sha256',
    verify_permissions: bool = True
) -> Dict[str, Any]:
    """
    Check the integrity of a file by verifying its hash and permissions.

    Args:
        file_path: Path to the file
        expected_hash: Expected hash value to compare against
        hash_algorithm: Hash algorithm to use (sha256, sha512, etc.)
        verify_permissions: Whether to verify file permissions

    Returns:
        Dict containing integrity check results
    """
    try:
        import hashlib
        import os

        result = {
            'file_exists': False,
            'hash_match': False,
            'permissions_ok': False,
            'file_hash': None,
            'errors': []
        }

        file_path = Path(file_path)

        # Check if file exists
        if not file_path.exists():
            result['errors'].append("File does not exist")
            return result

        result['file_exists'] = True

        # Calculate hash
        hash_func = getattr(hashlib, hash_algorithm, None)
        if not hash_func:
            result['errors'].append(f"Invalid hash algorithm: {hash_algorithm}")
            return result

        try:
            with open(file_path, 'rb') as f:
                file_hash = hash_func(f.read()).hexdigest()
                result['file_hash'] = file_hash

            if expected_hash:
                result['hash_match'] = file_hash == expected_hash
                if not result['hash_match']:
                    result['errors'].append("Hash mismatch")
        except (IOError, PermissionError) as e:
            result['errors'].append(f"Error reading file: {e}")

        # Check permissions if requested
        if verify_permissions:
            try:
                # Check if file is world-writable
                mode = os.stat(file_path).st_mode
                is_world_writable = bool(mode & 0o002)
                result['permissions_ok'] = not is_world_writable
                if is_world_writable:
                    result['errors'].append("File is world-writable")
            except OSError as e:
                result['errors'].append(f"Error checking permissions: {e}")

        return result
    except Exception as e:
        logger.error(f"Error checking file integrity: {e}")
        return {
            'file_exists': False,
            'hash_match': False,
            'permissions_ok': False,
            'file_hash': None,
            'errors': [f"Unexpected error: {str(e)}"]
        }

# Log initialization status
logger.info(f"Incident Response Toolkit initialized, version {__version__}")
available = get_available_components()
logger.debug(f"Available components: {', '.join([k for k, v in available.items() if v])}")

# Public exports
__all__ = [
    # Version info
    '__version__',
    '__author__',
    '__email__',

    # Constants
    'IncidentStatus',
    'IncidentPhase',
    'IncidentSeverity',
    'IncidentType',
    'IncidentSource',
    'EvidenceType',
    'ActionType',
    'PHASE_STATUS_MAPPING',
    'STATUS_TRANSITIONS',
    'PHASE_REQUIRED_ACTIONS',
    'INCIDENT_TYPE_RECOMMENDED_EVIDENCE',
    'SEVERITY_REQUIRED_NOTIFICATIONS',

    # Classes
    'Incident',
    'VolatileDataCapture',
    'IncidentResponseError',
    'ConfigurationError',
    'InitializationError',
    'EvidenceCollectionError',
    'IsolationError',
    'NotificationError',
    'IncidentStatusError',
    'PlaybookExecutionError',
    'RecoveryError',
    'ValidationError',

    # Functions
    'initialize_incident',
    'collect_evidence',
    'isolate_system',
    'notify_stakeholders',
    'update_status',
    'get_incident_status',
    'list_incidents',
    'run_playbook',
    'restore_service',
    'harden_system',
    'verify_file_integrity',
    'build_timeline',
    'generate_report',
    'get_available_components',
    'create_evidence_directory',
    'sanitize_incident_id',
    'capture_volatile_data',
    'check_file_integrity',
    'reopen_incident',
    'track_incident_status',

    # Module configuration
    'CONFIG_AVAILABLE',
    'MODULE_PATH',
    'response_config',
    'tool_paths'
]
