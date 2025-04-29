"""
Common components for static analysis in the Forensic Analysis Toolkit.

This package provides shared utilities and core components used by the static analysis
tools within the Forensic Analysis Toolkit. It includes file handling utilities, hash
computation functions, signature database systems, and YARA rule integration.

These components ensure consistent behavior across the toolkit while maintaining proper
security controls and providing optimized implementations of frequently used operations.
"""

import logging
import importlib.util
from pathlib import Path
from typing import Dict, Any, Optional, List, Set, Tuple

# Initialize package-level logger
logger = logging.getLogger(__name__)

# Package version information
__version__ = '1.0.0'

# Package metadata
__author__ = 'Security Team'
__email__ = 'security@example.com'
__status__ = 'Production'

# Package path utilities
PACKAGE_PATH = Path(__file__).parent
YARA_RULES_PATH = PACKAGE_PATH / 'yara_rules'
SIGNATURE_DB_PATH = PACKAGE_PATH / 'signature_db'

# Initialize feature flags and availability trackers
INITIALIZATION_SUCCESS = False
SIGNATURE_DB_AVAILABLE = False
YARA_SCANNER_AVAILABLE = False
SSDEEP_AVAILABLE = False
TLSH_AVAILABLE = False
PEFILE_AVAILABLE = False
EMBEDDED_EXTRACTION_AVAILABLE = False

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

    # Check for optional dependencies first
    # Check for fuzzy hashing libraries
    try:
        import ssdeep
        SSDEEP_AVAILABLE = True
        logger.debug("ssdeep library available")
    except ImportError:
        logger.debug("ssdeep library not available")
        SSDEEP_AVAILABLE = False

    try:
        import tlsh
        TLSH_AVAILABLE = True
        logger.debug("tlsh library available")
    except ImportError:
        logger.debug("tlsh library not available")
        TLSH_AVAILABLE = False

    # Check for YARA
    try:
        import yara
        YARA_AVAILABLE = True
        logger.debug("yara-python library available")
    except ImportError:
        logger.debug("yara-python library not available")
        YARA_AVAILABLE = False

    # Check for PE file parsing
    try:
        import pefile
        PEFILE_AVAILABLE = True
        logger.debug("pefile library available")
    except ImportError:
        logger.debug("pefile library not available")
        PEFILE_AVAILABLE = False

    # Check for additional extraction tools
    try:
        # Check for common extraction libraries like python-magic, etc.
        magic_spec = importlib.util.find_spec("magic")
        EMBEDDED_EXTRACTION_AVAILABLE = magic_spec is not None
        if EMBEDDED_EXTRACTION_AVAILABLE:
            logger.debug("python-magic library available for enhanced file type detection")
    except ImportError:
        logger.debug("python-magic library not available")
        EMBEDDED_EXTRACTION_AVAILABLE = False

    # Try to import optional modules after checking their dependencies
    try:
        from .signature_db import SignatureDBManager
        SIGNATURE_DB_AVAILABLE = True
        logger.debug("SignatureDBManager available")
    except ImportError as e:
        logger.debug(f"SignatureDBManager not available: {e}")
        SIGNATURE_DB_AVAILABLE = False

    try:
        from .yara_rules import YaraScanner
        YARA_SCANNER_AVAILABLE = True
        logger.debug("YaraScanner available")
    except ImportError as e:
        logger.debug(f"YaraScanner not available: {e}")
        YARA_SCANNER_AVAILABLE = False

    # Core module initialization success
    INITIALIZATION_SUCCESS = True
    logger.debug("Static analysis common components initialized successfully")

except ImportError as e:
    logger.warning(f"Error importing static analysis common components: {e}")
    INITIALIZATION_SUCCESS = False

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
    'find_similar_files',

    # Package constants
    'PACKAGE_PATH',
    'YARA_RULES_PATH',
    'SIGNATURE_DB_PATH',
    'SSDEEP_AVAILABLE',
    'TLSH_AVAILABLE',
    'YARA_AVAILABLE',
    'PEFILE_AVAILABLE',
    'EMBEDDED_EXTRACTION_AVAILABLE',
    'INITIALIZATION_SUCCESS',

    # Information functions
    'get_package_info',
    'check_dependencies',
    'get_component_status',

    # Version info
    '__version__',
    '__author__',
    '__email__',
    '__status__'
]

# Add optional components conditionally
if SIGNATURE_DB_AVAILABLE:
    __all__.append('SignatureDBManager')

if YARA_SCANNER_AVAILABLE:
    __all__.append('YaraScanner')

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
            'yara_scanner': YARA_SCANNER_AVAILABLE,
            'ssdeep': SSDEEP_AVAILABLE,
            'tlsh': TLSH_AVAILABLE,
            'pefile': PEFILE_AVAILABLE,
            'embedded_extraction': EMBEDDED_EXTRACTION_AVAILABLE
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
    dependencies = {
        'ssdeep': SSDEEP_AVAILABLE,
        'tlsh': TLSH_AVAILABLE,
        'yara': YARA_AVAILABLE,
        'pefile': PEFILE_AVAILABLE,
        'python-magic': EMBEDDED_EXTRACTION_AVAILABLE
    }

    # Check for additional parsing libraries
    try:
        import olefile
        dependencies['olefile'] = True
    except ImportError:
        dependencies['olefile'] = False

    try:
        import PyPDF2
        dependencies['pypdf2'] = True
    except ImportError:
        dependencies['pypdf2'] = False

    try:
        import zipfile
        dependencies['zipfile'] = True
    except ImportError:
        dependencies['zipfile'] = False

    try:
        import tarfile
        dependencies['tarfile'] = True
    except ImportError:
        dependencies['tarfile'] = False

    return dependencies

def get_component_status() -> Dict[str, Dict[str, Any]]:
    """
    Get detailed status of each component including dependency information.

    Returns:
        Dictionary with detailed component status
    """
    status = {}

    # File utility component
    status["file_utils"] = {
        "available": True,
        "functions": [
            "safe_analyze_file", "isolated_file_access", "identify_file_type",
            "extract_embedded_files", "extract_file_strings", "calculate_file_entropy",
            "extract_metadata_by_format", "analyze_script_file",
            "detect_file_obfuscation", "compare_files_forensically", "save_analysis_report"
        ],
        "dependencies": {
            "pefile": PEFILE_AVAILABLE,
            "python-magic": EMBEDDED_EXTRACTION_AVAILABLE
        }
    }

    # Hash utility component
    status["hash_utils"] = {
        "available": True,
        "functions": [
            "calculate_hash", "calculate_multiple_hashes", "calculate_fuzzy_hash",
            "verify_hash", "compare_fuzzy_hashes", "create_hash_database",
            "check_hash_against_database", "hash_directory", "find_similar_files"
        ],
        "dependencies": {
            "ssdeep": SSDEEP_AVAILABLE,
            "tlsh": TLSH_AVAILABLE
        }
    }

    # Signature DB component
    status["signature_db"] = {
        "available": SIGNATURE_DB_AVAILABLE,
        "path": str(SIGNATURE_DB_PATH),
        "exists": SIGNATURE_DB_PATH.exists()
    }

    # YARA scanner component
    status["yara_scanner"] = {
        "available": YARA_SCANNER_AVAILABLE,
        "path": str(YARA_RULES_PATH),
        "exists": YARA_RULES_PATH.exists(),
        "dependencies": {
            "yara": YARA_AVAILABLE
        }
    }

    return status

# Initialize required directories if they don't exist
def _ensure_directories():
    """Ensure required directories exist."""
    try:
        # Create YARA rules directory if it doesn't exist
        if not YARA_RULES_PATH.exists():
            YARA_RULES_PATH.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created YARA rules directory at {YARA_RULES_PATH}")

        # Create signature database directory if it doesn't exist
        if not SIGNATURE_DB_PATH.exists():
            SIGNATURE_DB_PATH.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created signature database directory at {SIGNATURE_DB_PATH}")
    except (OSError, PermissionError) as e:
        logger.warning(f"Could not create required directories: {e}")

# Run directory initialization
_ensure_directories()
