"""
Static Analysis Tools for Forensic Analysis Toolkit.

This package provides tools for static analysis of files during digital forensic investigations,
enabling security analysts to examine suspicious files without execution. The tools support file
structure analysis, signature verification, hash comparison, and memory string analysis.

These components follow forensic best practices to ensure evidence integrity and maintain
proper chain of custody throughout the analysis process.
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Set, Optional, Tuple

# Initialize package-level logger
logger = logging.getLogger(__name__)

# Package version information
__version__ = '1.0.0'
__author__ = 'Security Team'
__email__ = 'security@example.com'
__status__ = 'Production'

# Package metadata
PACKAGE_ROOT = Path(__file__).parent
COMMON_DIR = PACKAGE_ROOT / "common"
RULES_DIR = COMMON_DIR / "yara_rules"
SIGNATURES_DIR = COMMON_DIR / "signature_db"

# Import primary tool entry points
try:
    # Import main tools as direct package exports
    from .file_analyzer import perform_analysis as analyze_file
    from .signature_checker import (
        check_malware_signatures,
        scan_with_yara,
        verify_code_signature
    )
    from .hash_compare import (
        calculate_multiple_file_hashes,
        compare_files,
        verify_file_hash,
        find_similar_files
    )
    from .memory_string_analyzer import perform_analysis as analyze_memory_strings

    # Expose key utility functions from common modules if available
    from .common import (
        # From common.__init__
        save_analysis_report,
        calculate_hash,
        calculate_multiple_hashes,
        calculate_fuzzy_hash
    )

    INITIALIZATION_SUCCESS = True
    logger.debug("Static analysis package initialized successfully")

except ImportError as e:
    logger.warning(f"Error initializing static analysis package: {e}")
    INITIALIZATION_SUCCESS = False

# Define public API for easier imports
__all__ = [
    # Main analysis tools
    'analyze_file',
    'check_malware_signatures',
    'scan_with_yara',
    'verify_code_signature',
    'calculate_multiple_file_hashes',
    'compare_files',
    'verify_file_hash',
    'find_similar_files',
    'analyze_memory_strings',

    # Common utilities
    'save_analysis_report',
    'calculate_hash',
    'calculate_multiple_hashes',
    'calculate_fuzzy_hash',

    # Constants and package information
    'PACKAGE_ROOT',
    'COMMON_DIR',
    'RULES_DIR',
    'SIGNATURES_DIR',
    'INITIALIZATION_SUCCESS'
]

def get_capabilities() -> Dict[str, Dict[str, Any]]:
    """
    Return information about available static analysis capabilities.

    Returns:
        Dictionary containing information about available tools, their
        dependencies, and status.
    """
    capabilities = {
        "file_analyzer": {
            "available": "analyze_file" in globals(),
            "description": "File structure and content analysis tool",
            "entry_point": "analyze_file" if "analyze_file" in globals() else None,
        },
        "signature_checker": {
            "available": "check_malware_signatures" in globals(),
            "description": "Signature verification and malware detection tool",
            "entry_point": "check_malware_signatures" if "check_malware_signatures" in globals() else None,
        },
        "hash_compare": {
            "available": "calculate_multiple_file_hashes" in globals(),
            "description": "Hash calculation and comparison tool",
            "entry_point": "calculate_multiple_file_hashes" if "calculate_multiple_file_hashes" in globals() else None,
        },
        "memory_string_analyzer": {
            "available": "analyze_memory_strings" in globals(),
            "description": "Memory-extracted string analysis tool",
            "entry_point": "analyze_memory_strings" if "analyze_memory_strings" in globals() else None,
        }
    }

    # Add common dependency information
    from .common import get_package_info
    capabilities["common"] = get_package_info() if "get_package_info" in dir() else {
        "available": INITIALIZATION_SUCCESS,
        "dependencies": {
            "yara_scanner": "Unknown",
            "signature_db": "Unknown",
            "fuzzy_hash": "Unknown"
        }
    }

    return capabilities

def init_logging(level: int = logging.INFO) -> None:
    """
    Initialize package-level logging with the specified level.

    Args:
        level: Logging level from the logging module
    """
    logger.setLevel(level)

    # Check for existing handlers to avoid duplicates
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.debug(f"Logging initialized at level {level}")
