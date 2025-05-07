"""
Forensic Tools for Incident Response Toolkit

This package provides tools for digital forensic acquisition, analysis, and investigation during
security incidents. These tools follow forensic best practices to preserve evidence integrity
and maintain proper chain of custody.

The forensic tools integrate with the broader incident response toolkit and can leverage
core security functionality when available.
"""

import os
import sys
import logging
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple

# Configure package logging
logger = logging.getLogger(__name__)

# Determine module paths
MODULE_PATH = Path(os.path.dirname(os.path.abspath(__file__)))
TOOLKIT_PATH = MODULE_PATH.parent

# Constants
DEFAULT_HASH_ALGORITHM = "sha256"
SUPPORTED_HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]
DEFAULT_CHUNK_SIZE = 65536  # 64KB chunks for efficient reading
DEFAULT_OUTPUT_FORMAT = "json"
SUPPORTED_FORMATS = ["json", "csv", "html", "markdown", "text"]

# Check availability of each tool
FILE_INTEGRITY_AVAILABLE = (MODULE_PATH / "file_integrity.py").exists()
TIMELINE_BUILDER_AVAILABLE = (MODULE_PATH / "timeline_builder.py").exists()
MEMORY_ACQUISITION_AVAILABLE = (MODULE_PATH / "memory_acquisition.sh").exists()
DISK_IMAGING_AVAILABLE = (MODULE_PATH / "disk_imaging.sh").exists()
NETWORK_CAPTURE_AVAILABLE = (MODULE_PATH / "network_capture.sh").exists()
USER_ACTIVITY_MONITOR_AVAILABLE = (MODULE_PATH / "user_activity_monitor.py").exists()

# Try to import parent package components
try:
    # Import config and utilities from parent package
    from .. import (
        response_config, tool_paths, CONFIG_AVAILABLE, MODULE_PATH as IR_KIT_PATH,
        DEFAULT_EVIDENCE_DIR, sanitize_incident_id, IncidentType, EvidenceType
    )
    PARENT_IMPORTS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Failed to import parent package components: {e}")
    PARENT_IMPORTS_AVAILABLE = False

    # Set defaults if imports fail
    CONFIG_AVAILABLE = False
    tool_paths = {}
    response_config = {}
    DEFAULT_EVIDENCE_DIR = "/secure/evidence"
    IR_KIT_PATH = MODULE_PATH.parent

    def sanitize_incident_id(incident_id: str) -> str:
        """Fallback sanitize function."""
        return incident_id.replace('/', '-').replace('\\', '-')

    # Define minimal enums for standalone operation
    class EvidenceType:
        """Evidence type constants."""
        MEMORY_DUMP = "memory_dump"
        DISK_IMAGE = "disk_image"
        NETWORK_CAPTURE = "network_capture"
        LOG_FILES = "log_files"
        REGISTRY_HIVE = "registry_hive"
        USER_ACTIVITY = "user_activity"

    class IncidentType:
        """Incident type constants."""
        MALWARE = "malware"
        COMPROMISE = "compromise"
        DATA_BREACH = "data_breach"
        DDOS = "ddos"
        INSIDER_THREAT = "insider_threat"
        PHISHING = "phishing"
        RANSOMWARE = "ransomware"

# Try to import core security utilities if available
try:
    from core.security.cs_audit import log_security_event
    from core.security.cs_file_integrity import (
        calculate_file_hash as core_calculate_hash,
        verify_file_integrity as core_verify_integrity
    )
    CORE_SECURITY_AVAILABLE = True
    logger.debug("Core security utilities available")
except ImportError as e:
    logger.debug(f"Core security utilities not available: {e}")
    CORE_SECURITY_AVAILABLE = False

# Try to import admin utilities if available
try:
    from admin.utils.file_integrity import (
        calculate_file_hash as admin_calculate_hash,
        verify_file_integrity as admin_verify_integrity,
        detect_file_changes as admin_detect_changes
    )
    ADMIN_UTILS_AVAILABLE = True
    logger.debug("Admin utilities available")
except ImportError as e:
    logger.debug(f"Admin utilities not available: {e}")
    ADMIN_UTILS_AVAILABLE = False

# Try to import forensics package utilities if available
try:
    from admin.security.forensics.utils import (
        calculate_file_hash as forensic_calculate_hash,
        verify_integrity as forensic_verify_integrity,
        log_forensic_operation
    )
    from admin.security.forensics.utils.timestamp_utils import normalize_timestamp
    FORENSICS_PACKAGE_AVAILABLE = True
    logger.debug("Forensics package available")
except ImportError as e:
    logger.debug(f"Forensics package not available: {e}")
    FORENSICS_PACKAGE_AVAILABLE = False

    # Define fallback for forensic logging if package not available
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict] = None, level: int = logging.INFO):
        """Fallback implementation of forensic logging."""
        if details is None:
            details = {}

        log_message = f"Forensic operation: {operation} - {'Success' if success else 'Failed'}"
        if details:
            log_message += f" - Details: {details}"

        logger.log(level, log_message)

# Import file integrity functions if available
if FILE_INTEGRITY_AVAILABLE:
    try:
        from .file_integrity import (
            calculate_file_hash,
            verify_file_integrity,
            create_file_hash_baseline,
            detect_file_changes,
            update_integrity_baseline,
            verify_chain_of_custody
        )
        logger.debug("File integrity tools loaded successfully")
    except ImportError as e:
        logger.warning(f"Failed to import file integrity tools: {e}")

        # Define fallbacks
        def calculate_file_hash(*args, **kwargs):
            """Fallback file hash calculation."""
            raise NotImplementedError("File integrity module not properly loaded")

        def verify_file_integrity(*args, **kwargs):
            """Fallback file integrity verification."""
            raise NotImplementedError("File integrity module not properly loaded")

        def create_file_hash_baseline(*args, **kwargs):
            """Fallback baseline creation."""
            raise NotImplementedError("File integrity module not properly loaded")

        def detect_file_changes(*args, **kwargs):
            """Fallback file change detection."""
            raise NotImplementedError("File integrity module not properly loaded")

        def update_integrity_baseline(*args, **kwargs):
            """Fallback baseline update."""
            raise NotImplementedError("File integrity module not properly loaded")

        def verify_chain_of_custody(*args, **kwargs):
            """Fallback chain of custody verification."""
            raise NotImplementedError("File integrity module not properly loaded")
else:
    # Define stubs if file_integrity.py doesn't exist
    def calculate_file_hash(*args, **kwargs):
        raise NotImplementedError("File integrity module not available")

    def verify_file_integrity(*args, **kwargs):
        raise NotImplementedError("File integrity module not available")

    def create_file_hash_baseline(*args, **kwargs):
        raise NotImplementedError("File integrity module not available")

    def detect_file_changes(*args, **kwargs):
        raise NotImplementedError("File integrity module not available")

    def update_integrity_baseline(*args, **kwargs):
        raise NotImplementedError("File integrity module not available")

    def verify_chain_of_custody(*args, **kwargs):
        raise NotImplementedError("File integrity module not available")

# Import timeline builder functions if available
if TIMELINE_BUILDER_AVAILABLE:
    try:
        from .timeline_builder import (
            build_timeline,
            extract_timeline_from_logs,
            merge_timelines,
            correlate_timelines,
            analyze_timeline,
            Timeline,
            Event,
            TimelineSource,
            CorrelationCluster
        )
        logger.debug("Timeline builder tools loaded successfully")
    except ImportError as e:
        logger.warning(f"Failed to import timeline builder tools: {e}")

        # Define fallbacks
        def build_timeline(*args, **kwargs):
            """Fallback timeline building."""
            raise NotImplementedError("Timeline builder module not properly loaded")

        def extract_timeline_from_logs(*args, **kwargs):
            """Fallback timeline extraction."""
            raise NotImplementedError("Timeline builder module not properly loaded")

        def merge_timelines(*args, **kwargs):
            """Fallback timeline merging."""
            raise NotImplementedError("Timeline builder module not properly loaded")

        def correlate_timelines(*args, **kwargs):
            """Fallback timeline correlation."""
            raise NotImplementedError("Timeline builder module not properly loaded")

        def analyze_timeline(*args, **kwargs):
            """Fallback timeline analysis."""
            raise NotImplementedError("Timeline builder module not properly loaded")

        # Fallback classes
        class Timeline:
            """Fallback Timeline class."""
            def __init__(self, *args, **kwargs):
                raise NotImplementedError("Timeline builder module not properly loaded")

        class Event:
            """Fallback Event class."""
            def __init__(self, *args, **kwargs):
                raise NotImplementedError("Timeline builder module not properly loaded")

        class TimelineSource:
            """Fallback TimelineSource class."""
            def __init__(self, *args, **kwargs):
                raise NotImplementedError("Timeline builder module not properly loaded")

        class CorrelationCluster:
            """Fallback CorrelationCluster class."""
            def __init__(self, *args, **kwargs):
                raise NotImplementedError("Timeline builder module not properly loaded")
else:
    # Define stubs if timeline_builder.py doesn't exist
    def build_timeline(*args, **kwargs):
        raise NotImplementedError("Timeline builder module not available")

    def extract_timeline_from_logs(*args, **kwargs):
        raise NotImplementedError("Timeline builder module not available")

    def merge_timelines(*args, **kwargs):
        raise NotImplementedError("Timeline builder module not available")

    def correlate_timelines(*args, **kwargs):
        raise NotImplementedError("Timeline builder module not available")

    def analyze_timeline(*args, **kwargs):
        raise NotImplementedError("Timeline builder module not available")

    # Stub classes
    class Timeline:
        def __init__(self, *args, **kwargs):
            raise NotImplementedError("Timeline builder module not available")

    class Event:
        def __init__(self, *args, **kwargs):
            raise NotImplementedError("Timeline builder module not available")

    class TimelineSource:
        def __init__(self, *args, **kwargs):
            raise NotImplementedError("Timeline builder module not available")

    class CorrelationCluster:
        def __init__(self, *args, **kwargs):
            raise NotImplementedError("Timeline builder module not available")

# Import user activity monitor functions if available
if USER_ACTIVITY_MONITOR_AVAILABLE:
    try:
        from .user_activity_monitor import (
            # Classes
            UserActivityCollection,
            UserBehaviorAnalysis,
            ActivityTimeline,

            # Constants
            ACTIVITY_TYPES,
            DETECTION_SENSITIVITY,
            ANALYSIS_FEATURES,
            EVIDENCE_FORMATS,

            # Core functions
            collect_user_activity,
            generate_activity_timeline,
            analyze_user_behavior,
            detect_access_anomalies,
            detect_authorization_anomalies,

            # Helper functions
            extract_login_patterns,
            find_concurrent_sessions,
            get_resource_access_summary,
            correlate_activities,
            export_activity_evidence
        )
        logger.debug("User activity monitor loaded successfully")
    except ImportError as e:
        logger.warning(f"Failed to import user activity monitor: {e}")

        # Define fallback constants and classes
        class ACTIVITY_TYPES:
            LOGIN = 'login'
            LOGOUT = 'logout'
            RESOURCE_ACCESS = 'resource_access'
            CONFIG_CHANGE = 'configuration_change'
            ADMIN_ACTION = 'admin_action'
            SECURITY_EVENT = 'security_event'
            ALL = ['login', 'logout', 'resource_access', 'configuration_change',
                'admin_action', 'security_event']

        class DETECTION_SENSITIVITY:
            LOW = 'low'
            MEDIUM = 'medium'
            HIGH = 'high'

        class ANALYSIS_FEATURES:
            TIME_PATTERN = 'time_pattern'
            RESOURCE_PATTERN = 'resource_pattern'
            VOLUME_PATTERN = 'volume_pattern'
            LOCATION_PATTERN = 'location_pattern'
            ALL = ['time_pattern', 'resource_pattern', 'volume_pattern', 'location_pattern']

        class EVIDENCE_FORMATS:
            JSON = 'json'
            CSV = 'csv'
            EVTX = 'evtx'
            MARKDOWN = 'markdown'
            ALL = ['json', 'csv', 'evtx', 'markdown']

        # Fallback classes
        class UserActivityCollection:
            def __init__(self, *args, **kwargs):
                raise NotImplementedError("User activity monitor module not properly loaded")

        class UserBehaviorAnalysis:
            def __init__(self, *args, **kwargs):
                raise NotImplementedError("User activity monitor module not properly loaded")

        class ActivityTimeline:
            def __init__(self, *args, **kwargs):
                raise NotImplementedError("User activity monitor module not properly loaded")

        # Fallback functions
        def collect_user_activity(*args, **kwargs):
            raise NotImplementedError("User activity monitor module not properly loaded")

        def generate_activity_timeline(*args, **kwargs):
            raise NotImplementedError("User activity monitor module not properly loaded")

        def analyze_user_behavior(*args, **kwargs):
            raise NotImplementedError("User activity monitor module not properly loaded")

        def detect_access_anomalies(*args, **kwargs):
            raise NotImplementedError("User activity monitor module not properly loaded")

        def detect_authorization_anomalies(*args, **kwargs):
            raise NotImplementedError("User activity monitor module not properly loaded")

        def extract_login_patterns(*args, **kwargs):
            raise NotImplementedError("User activity monitor module not properly loaded")

        def find_concurrent_sessions(*args, **kwargs):
            raise NotImplementedError("User activity monitor module not properly loaded")

        def get_resource_access_summary(*args, **kwargs):
            raise NotImplementedError("User activity monitor module not properly loaded")

        def correlate_activities(*args, **kwargs):
            raise NotImplementedError("User activity monitor module not properly loaded")

        def export_activity_evidence(*args, **kwargs):
            raise NotImplementedError("User activity monitor module not properly loaded")
else:
    # Define stubs if user_activity_monitor.py doesn't exist
    class ACTIVITY_TYPES:
        LOGIN = 'login'
        LOGOUT = 'logout'
        RESOURCE_ACCESS = 'resource_access'
        CONFIG_CHANGE = 'configuration_change'
        ADMIN_ACTION = 'admin_action'
        SECURITY_EVENT = 'security_event'
        ALL = ['login', 'logout', 'resource_access', 'configuration_change',
              'admin_action', 'security_event']

    class DETECTION_SENSITIVITY:
        LOW = 'low'
        MEDIUM = 'medium'
        HIGH = 'high'

    class ANALYSIS_FEATURES:
        TIME_PATTERN = 'time_pattern'
        RESOURCE_PATTERN = 'resource_pattern'
        VOLUME_PATTERN = 'volume_pattern'
        LOCATION_PATTERN = 'location_pattern'
        ALL = ['time_pattern', 'resource_pattern', 'volume_pattern', 'location_pattern']

    class EVIDENCE_FORMATS:
        JSON = 'json'
        CSV = 'csv'
        EVTX = 'evtx'
        MARKDOWN = 'markdown'
        ALL = ['json', 'csv', 'evtx', 'markdown']

    class UserActivityCollection:
        def __init__(self, *args, **kwargs):
            raise NotImplementedError("User activity monitor module not available")

    class UserBehaviorAnalysis:
        def __init__(self, *args, **kwargs):
            raise NotImplementedError("User activity monitor module not available")

    class ActivityTimeline:
        def __init__(self, *args, **kwargs):
            raise NotImplementedError("User activity monitor module not available")

    def collect_user_activity(*args, **kwargs):
        raise NotImplementedError("User activity monitor module not available")

    def generate_activity_timeline(*args, **kwargs):
        raise NotImplementedError("User activity monitor module not available")

    def analyze_user_behavior(*args, **kwargs):
        raise NotImplementedError("User activity monitor module not available")

    def detect_access_anomalies(*args, **kwargs):
        raise NotImplementedError("User activity monitor module not available")

    def detect_authorization_anomalies(*args, **kwargs):
        raise NotImplementedError("User activity monitor module not available")

    def extract_login_patterns(*args, **kwargs):
        raise NotImplementedError("User activity monitor module not available")

    def find_concurrent_sessions(*args, **kwargs):
        raise NotImplementedError("User activity monitor module not available")

    def get_resource_access_summary(*args, **kwargs):
        raise NotImplementedError("User activity monitor module not available")

    def correlate_activities(*args, **kwargs):
        raise NotImplementedError("User activity monitor module not available")

    def export_activity_evidence(*args, **kwargs):
        raise NotImplementedError("User activity monitor module not available")

# Helper function to check available tools
def get_available_tools() -> Dict[str, bool]:
    """
    Get available forensic tools in the package.

    Returns:
        Dict[str, bool]: Dictionary with tool availability flags
    """
    return {
        "file_integrity": FILE_INTEGRITY_AVAILABLE,
        "timeline_builder": TIMELINE_BUILDER_AVAILABLE,
        "memory_acquisition": MEMORY_ACQUISITION_AVAILABLE,
        "disk_imaging": DISK_IMAGING_AVAILABLE,
        "network_capture": NETWORK_CAPTURE_AVAILABLE,
        "user_activity_monitor": USER_ACTIVITY_MONITOR_AVAILABLE
    }

# Public exports
__all__ = [
    # Version info and package information
    'DEFAULT_HASH_ALGORITHM',
    'SUPPORTED_HASH_ALGORITHMS',
    'SUPPORTED_FORMATS',

    # Core utilities
    'get_available_tools',
    'log_forensic_operation',

    # Availability flags
    'FILE_INTEGRITY_AVAILABLE',
    'TIMELINE_BUILDER_AVAILABLE',
    'MEMORY_ACQUISITION_AVAILABLE',
    'DISK_IMAGING_AVAILABLE',
    'NETWORK_CAPTURE_AVAILABLE',
    'USER_ACTIVITY_MONITOR_AVAILABLE',

    # File integrity functions (if available)
    *(['calculate_file_hash', 'verify_file_integrity', 'create_file_hash_baseline',
       'detect_file_changes', 'update_integrity_baseline', 'verify_chain_of_custody']
      if FILE_INTEGRITY_AVAILABLE else []),

    # Timeline builder functions (if available)
    *(['build_timeline', 'extract_timeline_from_logs', 'merge_timelines',
       'correlate_timelines', 'analyze_timeline']
      if TIMELINE_BUILDER_AVAILABLE else []),

    # Timeline classes (if timeline_builder is available)
    *(['Timeline', 'Event', 'TimelineSource', 'CorrelationCluster']
      if TIMELINE_BUILDER_AVAILABLE else []),

    # User activity monitor exports (if available)
    *(['UserActivityCollection', 'UserBehaviorAnalysis', 'ActivityTimeline',
       'ACTIVITY_TYPES', 'DETECTION_SENSITIVITY', 'ANALYSIS_FEATURES', 'EVIDENCE_FORMATS',
       'collect_user_activity', 'generate_activity_timeline', 'analyze_user_behavior',
       'detect_access_anomalies', 'detect_authorization_anomalies', 'extract_login_patterns',
       'find_concurrent_sessions', 'get_resource_access_summary', 'correlate_activities',
       'export_activity_evidence']
      if USER_ACTIVITY_MONITOR_AVAILABLE else [])
]

# Log initialization status
available_tools = get_available_tools()
logger.info(f"Forensic tools module loaded")
logger.debug(f"Available tools: {', '.join([k for k, v in available_tools.items() if v])}")
