"""
Incident Response Toolkit Package

This package provides tools and utilities for coordinating and executing security incident
response activities, following the NIST SP 800-61 incident handling framework. The toolkit
covers the complete incident lifecycle: preparation, detection and analysis, containment,
eradication, recovery, and post-incident activities.

The toolkit integrates multiple components including coordination tools, documentation templates,
forensic tools, recovery tools, and reference materials to provide a comprehensive platform for
security incident response.

Key capabilities include:
- Incident workflow management and coordination
- Evidence collection and preservation with chain of custody
- System isolation and containment
- Documentation and reporting
- Recovery and remediation guidance
- Secure communication channels
- Playbook-based response for different incident types

Usage:
    The toolkit can be used both through command-line scripts and programmatically
    through the provided Python modules.

Example:
    # Setup a new incident response environment
    from admin.security.incident_response_kit import initialize_incident, collect_evidence

    # Initialize a new incident
    incident = initialize_incident(
        incident_id="IR-2024-042",
        incident_type="malware",
        severity="high",
        lead_responder="security-analyst@example.com"
    )

    # Collect evidence
    collection_result = collect_evidence(
        incident_id=incident.id,
        target="compromised-host-01",
        evidence_types=["memory", "logs", "network"],
        output_dir="/secure/evidence/IR-2024-042/"
    )
"""

import os
import sys
import logging
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple, Set

# Package versioning
__version__ = '1.0.0'
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

# Define constants for incident status and phases
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
    WEB_APPLICATION_ATTACK = "web_application_attack"
    ACCOUNT_COMPROMISE = "account_compromise"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INSIDER_THREAT = "insider_threat"
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"

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

# Basic incident class
class Incident:
    """
    Represents a security incident for tracking purposes within the toolkit.
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
        """
        # Validate status
        if status not in vars(IncidentStatus).values():
            raise ValueError(f"Invalid status: {status}")

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
        """
        # Validate phase
        if phase not in vars(IncidentPhase).values():
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

# Core functional imports - lazy loading with proper exception handling
def import_core_functions():
    global initialize_incident, collect_evidence, isolate_system, notify_stakeholders
    global update_status, run_playbook, restore_service, harden_system

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
            from .coordination.status_tracker import update_status
            logger.debug("Loaded update_status function")
        except ImportError as e:
            logger.warning(f"Failed to import status_tracker module: {e}")
            def update_status(*args, **kwargs):
                raise NotImplementedError("Status tracker not available")
    else:
        def notify_stakeholders(*args, **kwargs):
            raise NotImplementedError("Coordination modules not available")

        def update_status(*args, **kwargs):
            raise NotImplementedError("Coordination modules not available")

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
        "configuration": CONFIG_LOADED
    }

# Create evidence directory safely if it doesn't exist
def create_evidence_directory(incident_id: str) -> str:
    """
    Creates an evidence directory for the specified incident ID.

    Args:
        incident_id: Incident identifier

    Returns:
        Path to the created evidence directory

    Raises:
        OSError: If directory creation fails
    """
    evidence_dir = os.path.join(DEFAULT_EVIDENCE_DIR, incident_id)
    try:
        os.makedirs(evidence_dir, exist_ok=True)
        logger.info(f"Created evidence directory: {evidence_dir}")

        # Set secure permissions on Unix-like systems
        if os.name != 'nt':  # Not Windows
            os.chmod(evidence_dir, 0o700)  # Owner only

        return evidence_dir
    except OSError as e:
        logger.error(f"Failed to create evidence directory: {e}")
        raise

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

    # Classes
    'Incident',
    'IncidentResponseError',
    'ConfigurationError',
    'InitializationError',
    'EvidenceCollectionError',
    'IsolationError',
    'NotificationError',
    'IncidentStatusError',
    'PlaybookExecutionError',
    'RecoveryError',

    # Functions
    'initialize_incident',
    'collect_evidence',
    'isolate_system',
    'notify_stakeholders',
    'update_status',
    'run_playbook',
    'restore_service',
    'harden_system',
    'get_available_components',
    'create_evidence_directory',
]
