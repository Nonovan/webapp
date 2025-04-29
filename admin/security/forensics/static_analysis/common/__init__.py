"""
Common components for static analysis in the Forensic Analysis Toolkit.

This package provides shared utilities and core components used by the static analysis
tools within the Forensic Analysis Toolkit. It includes file handling utilities, hash
computation functions, signature database systems, and YARA rule integration.

These components ensure consistent behavior across the toolkit while maintaining proper
security controls and providing optimized implementations of frequently used operations.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional, List

# Initialize package-level logger
logger = logging.getLogger(__name__)

# Import and expose core utilities for direct package-level imports
try:
    from .file_utils import (
        # Core file operations
        safe_analyze_file,
        isolated_file_access,
        identify_file_type,
        extract_embedded_files,
        extract_file_strings,
        calculate_file_entropy,

        # Analysis functions
        extract_metadata_by_format,
        analyze_script_file,
        detect_file_obfuscation,
        compare_files_forensically,
        save_analysis_report
    )

    from .hash_utils import (
        # Basic hash functions
        calculate_hash,
        calculate_multiple_hashes,
        calculate_fuzzy_hash,
        verify_hash,

        # Advanced hash functions
        compare_fuzzy_hashes,
        create_hash_database,
        check_hash_against_database,
        hash_directory,
        find_similar_files
    )

    # Check for optional modules
    try:
        from .signature_db import SignatureDBManager
        SIGNATURE_DB_AVAILABLE = True
    except ImportError:
        logger.debug("SignatureDBManager not available")
        SIGNATURE_DB_AVAILABLE = False

    try:
        from .yara_rules import YaraScanner
        YARA_SCANNER_AVAILABLE = True
    except ImportError:
        logger.debug("YaraScanner not available")
        YARA_SCANNER_AVAILABLE = False

    # Core module initialization success
    logger.debug("Static analysis common components initialized successfully")
    INITIALIZATION_SUCCESS = True

except ImportError as e:
    logger.warning(f"Error importing static analysis common components: {e}")
    INITIALIZATION_SUCCESS = False


# Module version information
__version__ = '1.0.0'

# Package metadata
__author__ = 'Security Team'
__email__ = 'security@example.com'
__status__ = 'Production'

# Define public API
__all__ = [
    # File utilities
    'safe_analyze_file',
    'isolated_file_access',
    'identify_file_type',
    'extract_embedded_files',
    'extract_file_strings',
    'calculate_file_entropy',
    'extract_metadata_by_format',
    'analyze_script_file',
    'detect_file_obfuscation',
    'compare_files_forensically',
    'save_analysis_report',

    # Hash utilities
    'calculate_hash',
    'calculate_multiple_hashes',
    'calculate_fuzzy_hash',
    'verify_hash',
    'compare_fuzzy_hashes',
    'create_hash_database',
    'check_hash_against_database',
    'hash_directory',
    'find_similar_files'
]

# Add optional components conditionally
if SIGNATURE_DB_AVAILABLE:
    __all__.append('SignatureDBManager')

if YARA_SCANNER_AVAILABLE:
    __all__.append('YaraScanner')

# Package path utilities
PACKAGE_PATH = Path(__file__).parent
YARA_RULES_PATH = PACKAGE_PATH / 'yara_rules'
SIGNATURE_DB_PATH = PACKAGE_PATH / 'signature_db'

def get_package_info() -> Dict[str, Any]:
    """
    Return package information and status.

    Returns:
        Dictionary with package version, initialization status,
        and component availability.
    """
    return {
        'version': __version__,
        'initialized': INITIALIZATION_SUCCESS,
        'components': {
            'file_utils': True,
            'hash_utils': True,
            'signature_db': SIGNATURE_DB_AVAILABLE,
            'yara_scanner': YARA_SCANNER_AVAILABLE
        },
        'paths': {
            'package': str(PACKAGE_PATH),
            'yara_rules': str(YARA_RULES_PATH),
            'signature_db': str(SIGNATURE_DB_PATH)
        }
    }

def check_dependencies() -> Dict[str, bool]:
    """
    Check availability of optional dependencies.

    Returns:
        Dictionary with dependency status.
    """
    dependencies = {}

    # Check for fuzzy hashing libraries
    try:
        import ssdeep
        dependencies['ssdeep'] = True
    except ImportError:
        dependencies['ssdeep'] = False

    try:
        import tlsh
        dependencies['tlsh'] = True
    except ImportError:
        dependencies['tlsh'] = False

    # Check for YARA
    try:
        import yara
        dependencies['yara'] = True
    except ImportError:
        dependencies['yara'] = False

    # Check for PE file parsing
    try:
        import pefile
        dependencies['pefile'] = True
    except ImportError:
        dependencies['pefile'] = False

    return dependencies
