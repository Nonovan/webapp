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
        import re
        return re.sub(r'[^a-zA-Z0-9_\-]', '_', incident_id)

    # Define minimal enums for standalone operation
    class EvidenceType:
        """Evidence type constants."""
        LOG_FILE = "log_file"
        MEMORY_DUMP = "memory_dump"
        DISK_IMAGE = "disk_image"
        NETWORK_CAPTURE = "network_capture"
        CONFIGURATION = "configuration"
        TIMELINE = "timeline"
        FILE_SYSTEM = "file_system"
        HASH_LIST = "hash_list"

    class IncidentType:
        """Incident type constants."""
        MALWARE = "malware"
        DATA_BREACH = "data_breach"
        UNAUTHORIZED_ACCESS = "unauthorized_access"
        DENIAL_OF_SERVICE = "denial_of_service"
        INSIDER_THREAT = "insider_threat"
        PHISHING = "phishing"

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
        verify_file_integrity as admin_verify_integrity
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
        log_msg = f"Forensic Operation: {operation}, Success: {success}"
        if details:
            log_msg += f", Details: {details}"
        logger.log(level, log_msg)

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
            """Fallback log extraction."""
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

        class Timeline:
            """Fallback Timeline class."""
            def __init__(self, *args, **kwargs):
                raise NotImplementedError("Timeline class not properly loaded")

        class Event:
            """Fallback Event class."""
            def __init__(self, *args, **kwargs):
                raise NotImplementedError("Event class not properly loaded")

        class TimelineSource:
            """Fallback TimelineSource class."""
            def __init__(self, *args, **kwargs):
                raise NotImplementedError("TimelineSource class not properly loaded")

        class CorrelationCluster:
            """Fallback CorrelationCluster class."""
            def __init__(self, *args, **kwargs):
                raise NotImplementedError("CorrelationCluster class not properly loaded")
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

# Define helpers for shell-based tools
def get_shell_tool_path(tool_name: str, default_path: str) -> str:
    """Get the path for a shell-based tool from configuration or use default."""
    if CONFIG_AVAILABLE and tool_paths:
        return tool_paths.get('forensic_tools', {}).get(tool_name, default_path)
    return default_path

# Define utility function to check tool availability
def get_available_tools() -> Dict[str, bool]:
    """Return a dictionary of available forensic tools."""
    return {
        'file_integrity': FILE_INTEGRITY_AVAILABLE,
        'timeline_builder': TIMELINE_BUILDER_AVAILABLE,
        'memory_acquisition': MEMORY_ACQUISITION_AVAILABLE,
        'disk_imaging': DISK_IMAGING_AVAILABLE,
        'network_capture': NETWORK_CAPTURE_AVAILABLE,
        'core_security': CORE_SECURITY_AVAILABLE,
        'admin_utils': ADMIN_UTILS_AVAILABLE,
        'forensics_package': FORENSICS_PACKAGE_AVAILABLE
    }

# Define public exports
__all__ = [
    # Constants
    'DEFAULT_HASH_ALGORITHM',
    'SUPPORTED_HASH_ALGORITHMS',
    'DEFAULT_OUTPUT_FORMAT',
    'SUPPORTED_FORMATS',

    # File integrity functions
    'calculate_file_hash',
    'verify_file_integrity',
    'create_file_hash_baseline',
    'detect_file_changes',
    'update_integrity_baseline',
    'verify_chain_of_custody',

    # Timeline functions and classes
    'build_timeline',
    'extract_timeline_from_logs',
    'merge_timelines',
    'correlate_timelines',
    'analyze_timeline',

    # Timeline classes (if timeline_builder is available)
    *(['Timeline', 'Event', 'TimelineSource', 'CorrelationCluster']
      if TIMELINE_BUILDER_AVAILABLE else []),

    # Utility functions
    'get_available_tools',
    'log_forensic_operation',

    # Feature flags
    'FILE_INTEGRITY_AVAILABLE',
    'TIMELINE_BUILDER_AVAILABLE',
    'MEMORY_ACQUISITION_AVAILABLE',
    'DISK_IMAGING_AVAILABLE',
    'NETWORK_CAPTURE_AVAILABLE'
]

# Log initialization status
available_tools = get_available_tools()
logger.info(f"Forensic tools module loaded")
logger.debug(f"Available tools: {', '.join([k for k, v in available_tools.items() if v])}")
