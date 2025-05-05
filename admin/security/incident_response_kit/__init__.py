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
try:
    from .incident_constants import (
        IncidentStatus, IncidentPhase, IncidentSeverity, IncidentType,
        PHASE_STATUS_MAPPING, STATUS_TRANSITIONS
    )
except ImportError as e:
    logger.error(f"Error importing incident constants: {e}")
    # Define basic fallback constants
    class IncidentStatus:
        OPEN = "open"
        INVESTIGATING = "investigating"
        RESOLVED = "resolved"
        CLOSED = "closed"

    class IncidentPhase:
        IDENTIFICATION = "identification"
        CONTAINMENT = "containment"
        ERADICATION = "eradication"
        RECOVERY = "recovery"

    class IncidentSeverity:
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"

    class IncidentType:
        MALWARE = "malware"
        DATA_BREACH = "data_breach"

    PHASE_STATUS_MAPPING = {}
    STATUS_TRANSITIONS = {}

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
    """Base exception for incident response toolkit errors"""
    pass

class ConfigurationError(IncidentResponseError):
    """Error in configuration parameters"""
    pass

class InitializationError(IncidentResponseError):
    """Error initializing an incident"""
    pass

class EvidenceCollectionError(IncidentResponseError):
    """Error during evidence collection"""
    pass

class IsolationError(IncidentResponseError):
    """Error during system isolation"""
    pass

class NotificationError(IncidentResponseError):
    """Error sending notifications"""
    pass

class IncidentStatusError(IncidentResponseError):
    """Error updating incident status"""
    pass

class PlaybookExecutionError(IncidentResponseError):
    """Error running playbook steps"""
    pass

class RecoveryError(IncidentResponseError):
    """Error during recovery operations"""
    pass

class ValidationError(IncidentResponseError):
    """Error validating incident data"""
    pass

# Core functional imports - lazy loading with proper exception handling
def import_core_functions():
    global initialize_incident, collect_evidence, isolate_system, notify_stakeholders
    global update_status, run_playbook, restore_service, harden_system
    global track_incident_status, verify_file_integrity, build_timeline
    global get_incident_status, list_incidents, generate_report
    global capture_volatile_data

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
            """
            Capture volatile system data for incident response.

            Args:
                incident_id: Optional incident identifier
                output_dir: Directory to store collected evidence
                analyst: Name of the analyst performing the collection
                target: Target hostname or IP address (default: local system)
                categories: List of data categories to collect
                minimal: Perform minimal collection (faster but less comprehensive)
                **kwargs: Additional options to pass to VolatileDataCapture.capture()

            Returns:
                Tuple of (success, output_path)
            """
            capturer = VolatileDataCapture(
                incident_id=incident_id,
                output_dir=output_dir,
                analyst=analyst
            )
            return capturer.capture(
                target=target,
                categories=categories,
                minimal=minimal,
                **kwargs
            )

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
        except ImportError as e:
            logger.warning(f"Failed to import status_tracker module: {e}")
            def update_status(*args, **kwargs):
                raise NotImplementedError("Status tracker not available")
            def get_incident_status(*args, **kwargs):
                raise NotImplementedError("Status tracker not available")
            def list_incidents(*args, **kwargs):
                raise NotImplementedError("Status tracker not available")

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

# Import core functions
import_core_functions()

# Utility function for getting available components
def get_available_components() -> Dict[str, bool]:
    """
    Get the availability status of incident response toolkit components.

    Returns:
        Dictionary with availability status of each component
    """
    return {
        "coordination": COORDINATION_AVAILABLE,
        "documentation": DOCUMENTATION_AVAILABLE,
        "forensic_tools": FORENSIC_TOOLS_AVAILABLE,
        "playbooks": PLAYBOOKS_AVAILABLE,
        "recovery": RECOVERY_AVAILABLE,
        "references": REFERENCES_AVAILABLE,
        "configuration": CONFIG_LOADED,
        "volatile_data_capture": VOLATILE_DATA_CAPTURE_AVAILABLE
    }

# Create evidence directory safely if it doesn't exist
def create_evidence_directory(incident_id: str) -> Path:
    """
    Creates an evidence directory for the specified incident ID.

    Args:
        incident_id: Incident identifier

    Returns:
        Path to the created evidence directory

    Raises:
        OSError: If directory creation fails
    """
    evidence_dir = Path(DEFAULT_EVIDENCE_DIR) / incident_id
    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created evidence directory: {evidence_dir}")

        # Set secure permissions on Unix-like systems
        if os.name != 'nt':  # Not Windows
            os.chmod(evidence_dir, 0o700)  # Owner only

        return evidence_dir
    except OSError as e:
        logger.error(f"Failed to create evidence directory: {e}")
        raise

# Sanitize incident ID to ensure it's safe for file operations
def sanitize_incident_id(incident_id: str) -> str:
    """
    Sanitizes incident ID to ensure it's safe for file operations.

    Args:
        incident_id: Raw incident identifier

    Returns:
        Sanitized incident ID safe for file operations
    """
    # Remove or replace potentially dangerous characters
    safe_id = ''.join(c if c.isalnum() or c in '-_' else '_' for c in incident_id)
    return safe_id

# Check file integrity
def check_file_integrity(
    file_path: Union[str, Path],
    expected_hash: Optional[str] = None,
    hash_algorithm: str = 'sha256',
    verify_permissions: bool = True
) -> Dict[str, Any]:
    """
    Verifies the integrity of a file by checking its hash and optionally its permissions.

    This is a critical function during incident response to verify that evidence files
    haven't been tampered with and that secure permissions are properly set.

    Args:
        file_path: Path to the file to check
        expected_hash: If provided, the file's hash will be compared to this value
        hash_algorithm: Hash algorithm to use (sha256, sha512, etc.)
        verify_permissions: Whether to verify file permissions (Unix only)

    Returns:
        Dictionary with integrity check results including:
            - file_exists: Whether the file exists
            - file_hash: Computed hash of the file
            - hash_matches: Whether the hash matches the expected value
            - permissions_secure: Whether permissions are secure (Unix only)
            - is_valid: Overall validation result

    Raises:
        FileNotFoundError: If the file does not exist
        PermissionError: If the file cannot be read due to permissions
    """
    result = {
        "file_exists": False,
        "file_hash": None,
        "hash_matches": None,
        "permissions_secure": None,
        "is_valid": False
    }

    file_path = Path(file_path)

    # Check if the file exists
    if not file_path.exists():
        logger.error(f"File not found: {file_path}")
        return result

    result["file_exists"] = True

    try:
        # Calculate file hash
        if FORENSIC_TOOLS_AVAILABLE and 'verify_file_integrity' in globals():
            # Use the forensic toolkit's function if available
            integrity_result = verify_file_integrity(str(file_path), expected_hash, hash_algorithm)
            result["file_hash"] = integrity_result.get("hash")
            result["hash_matches"] = integrity_result.get("hash_matches")
        else:
            # Basic implementation if forensic tools aren't available
            import hashlib

            hash_obj = hashlib.new(hash_algorithm)
            with open(file_path, 'rb') as f:
                # Read in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)

            file_hash = hash_obj.hexdigest()
            result["file_hash"] = file_hash

            if expected_hash:
                result["hash_matches"] = file_hash.lower() == expected_hash.lower()

        # Check file permissions on Unix-like systems
        if verify_permissions and os.name != 'nt':
            import stat
            file_stat = os.stat(file_path)
            file_mode = file_stat.st_mode

            # Check if file is only readable/writable by owner
            is_secure = not (file_mode & (stat.S_IRWXG | stat.S_IRWXO))
            result["permissions_secure"] = is_secure

            if not is_secure:
                logger.warning(f"File has insecure permissions: {file_path}, mode: {oct(file_mode)}")

        # Overall validity check
        if expected_hash:
            result["is_valid"] = result["hash_matches"] and (not verify_permissions or result["permissions_secure"] is True)
        else:
            result["is_valid"] = True if not verify_permissions else result["permissions_secure"] is True

        return result

    except PermissionError as e:
        logger.error(f"Permission error checking file integrity: {e}")
        raise
    except Exception as e:
        logger.error(f"Error checking file integrity: {e}")
        result["error"] = str(e)
        return result

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
    'PHASE_STATUS_MAPPING',
    'STATUS_TRANSITIONS',

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
]
