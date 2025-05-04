"""
Common utilities for the Live Response Forensic Toolkit.

This module provides shared functionality for memory acquisition, volatile data collection,
network state analysis, and evidence packaging components of the live response toolkit.
It ensures consistent handling of evidence, logging, and chain of custody documentation
across all toolkit components.
"""

import os
import sys
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union

# Set up module-level logger
logger = logging.getLogger(__name__)

# Version information
__version__ = "1.0.0"
__author__ = "Security Forensics Team"

# Try importing core forensic utilities if available
try:
    from admin.security.forensics.utils.logging_utils import (
        log_forensic_operation,
        setup_forensic_logger
    )
    from admin.security.forensics.utils.validation_utils import validate_path
    from admin.security.forensics.utils.evidence_tracker import (
        register_evidence,
        track_access,
        track_analysis,
        get_evidence_details
    )
    FORENSIC_CORE_AVAILABLE = True
except ImportError:
    FORENSIC_CORE_AVAILABLE = False
    logger.warning("Core forensic utilities not available. Using fallback implementations.")

# Export artifact parser components
try:
    from .artifact_parser import (
        parse_artifacts,
        detect_suspicious_processes,
        detect_suspicious_connections,
        detect_suspicious_commands,
        detect_data_exfil,
        detect_privilege_escalation,
        extract_network_indicators,
        extract_file_indicators,
        analyze_artifact_timeline,
        generate_artifact_report,
        save_analysis_report,
        ARTIFACT_TYPES
    )

    __all__ = [
        # Version info
        '__version__',
        '__author__',

        # Core availability flag
        'FORENSIC_CORE_AVAILABLE',

        # Artifact parsing functions
        'parse_artifacts',
        'detect_suspicious_processes',
        'detect_suspicious_connections',
        'detect_suspicious_commands',
        'detect_data_exfil',
        'detect_privilege_escalation',

        # Indicator extraction
        'extract_network_indicators',
        'extract_file_indicators',

        # Timeline and reporting
        'analyze_artifact_timeline',
        'generate_artifact_report',
        'save_analysis_report',

        # Constants
        'ARTIFACT_TYPES'
    ]

    logger.debug(f"Live response common module initialized - {len(__all__)} components available")

except ImportError as e:
    logger.error(f"Error importing artifact parser components: {e}")
    __all__ = []
