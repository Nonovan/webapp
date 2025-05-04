"""
Static Analysis Tools for Forensic Analysis Toolkit.

This package provides tools for static analysis of files during digital forensic investigations,
enabling security analysts to examine suspicious files without execution. The tools support file
structure analysis, signature verification, hash comparison, and memory string analysis.

These components follow forensic best practices to ensure evidence integrity and maintain
proper chain of custody throughout the analysis process.
"""

import logging
import os
import sys
import importlib.util
from pathlib import Path
from typing import Dict, List, Any, Set, Optional, Tuple, Union

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

# Track initialization state
INITIALIZATION_SUCCESS = False
INITIALIZATION_ERROR = None
COMMON_MODULE_AVAILABLE = False
TOOL_AVAILABILITY = {
    "file_analyzer": False,
    "signature_checker": False,
    "hash_compare": False,
    "memory_string_analyzer": False
}

# Define required dependencies for proper operation
REQUIRED_PYTHON_PACKAGES = [
    "yara-python",  # For YARA rule scanning
    "pefile",       # For PE file analysis
    "ssdeep",       # For fuzzy hashing (optional)
]

def _ensure_directories():
    """Create necessary directories if they don't exist."""
    try:
        # Create YARA rules directory if it doesn't exist
        os.makedirs(RULES_DIR, exist_ok=True)

        # Create signature database directory if it doesn't exist
        os.makedirs(SIGNATURES_DIR, exist_ok=True)

        return True
    except (OSError, PermissionError) as e:
        logger.error(f"Could not create required directories: {e}")
        return False

# Create a function to check for required dependencies
def check_dependencies() -> Dict[str, bool]:
    """Check if required dependencies are available."""
    results = {}

    # Check for core dependencies
    for package in REQUIRED_PYTHON_PACKAGES:
        results[package] = importlib.util.find_spec(package) is not None

    # Check for forensic core modules
    try:
        import admin.security.forensics.utils.logging_utils
        results["forensic_utils"] = True
    except ImportError:
        results["forensic_utils"] = False

    return results

# Import primary tool entry points in a controlled manner
try:
    # First check if common module is available as most tools depend on it
    try:
        from .common import (
            # Core file operations
            save_analysis_report,
            calculate_hash,
            calculate_multiple_hashes,
            calculate_fuzzy_hash,

            # Package information function
            get_package_info,

            # Feature flags
            INITIALIZATION_SUCCESS as COMMON_INIT_SUCCESS,
            YARA_AVAILABLE,
            SSDEEP_AVAILABLE,
            TLSH_AVAILABLE,
            PEFILE_AVAILABLE,
            SIGNATURE_DB_AVAILABLE,
            YARA_SCANNER_AVAILABLE,
            FORENSIC_CORE_AVAILABLE
        )
        COMMON_MODULE_AVAILABLE = True
        logger.debug("Common module components loaded successfully")
    except ImportError as e:
        logger.warning(f"Error loading common module: {e}")
        COMMON_MODULE_AVAILABLE = False

    # Import main tools as direct package exports with individual error handling
    try:
        from .file_analyzer import perform_analysis as analyze_file
        TOOL_AVAILABILITY["file_analyzer"] = True
    except ImportError as e:
        logger.warning(f"File analyzer module not available: {e}")
        analyze_file = None

    try:
        from .signature_checker import (
            check_malware_signatures,
            scan_with_yara,
            verify_code_signature
        )
        TOOL_AVAILABILITY["signature_checker"] = True
    except ImportError as e:
        logger.warning(f"Signature checker module not available: {e}")
        check_malware_signatures = None
        scan_with_yara = None
        verify_code_signature = None

    try:
        from .hash_compare import (
            calculate_multiple_file_hashes,
            compare_files,
            verify_file_hash,
            find_similar_files
        )
        TOOL_AVAILABILITY["hash_compare"] = True
    except ImportError as e:
        logger.warning(f"Hash compare module not available: {e}")
        calculate_multiple_file_hashes = None
        compare_files = None
        verify_file_hash = None
        find_similar_files = None

    try:
        from .memory_string_analyzer import perform_analysis as analyze_memory_strings
        TOOL_AVAILABILITY["memory_string_analyzer"] = True
    except ImportError as e:
        logger.warning(f"Memory string analyzer module not available: {e}")
        analyze_memory_strings = None

    # Ensure necessary directories exist
    _ensure_directories()

    # Mark package as successfully initialized if at least one tool is available
    if any(TOOL_AVAILABILITY.values()):
        INITIALIZATION_SUCCESS = True
        logger.debug("Static analysis package initialized successfully")
    else:
        logger.warning("No static analysis tools were successfully initialized")
        INITIALIZATION_SUCCESS = False

except Exception as e:
    logger.error(f"Error initializing static analysis package: {e}", exc_info=True)
    INITIALIZATION_SUCCESS = False
    INITIALIZATION_ERROR = str(e)

# Define public API for easier imports
__all__ = [
    # Version and metadata
    '__version__',
    '__author__',
    '__email__',
    '__status__',
    'INITIALIZATION_SUCCESS',

    # Functions
    'get_capabilities',
    'init_logging',
    'check_dependencies',

    # Constants and package information
    'PACKAGE_ROOT',
    'COMMON_DIR',
    'RULES_DIR',
    'SIGNATURES_DIR',
]

# Add main analysis tools to exports if available
if analyze_file:
    __all__.append('analyze_file')

if check_malware_signatures:
    __all__.extend(['check_malware_signatures', 'scan_with_yara', 'verify_code_signature'])

if calculate_multiple_file_hashes:
    __all__.extend(['calculate_multiple_file_hashes', 'compare_files', 'verify_file_hash', 'find_similar_files'])

if analyze_memory_strings:
    __all__.append('analyze_memory_strings')

# Add common utilities to exports if available
if COMMON_MODULE_AVAILABLE:
    __all__.extend(['save_analysis_report', 'calculate_hash', 'calculate_multiple_hashes', 'calculate_fuzzy_hash'])

def get_capabilities() -> Dict[str, Dict[str, Any]]:
    """
    Return information about available static analysis capabilities.

    This function provides detailed information about which tools and features
    are available in the current installation, including their dependencies
    and initialization status.

    Returns:
        Dictionary containing information about available tools, their
        dependencies, and status.
    """
    capabilities = {
        "file_analyzer": {
            "available": "analyze_file" in globals() and analyze_file is not None,
            "description": "File structure and content analysis tool",
            "entry_point": "analyze_file" if "analyze_file" in globals() and analyze_file is not None else None,
        },
        "signature_checker": {
            "available": "check_malware_signatures" in globals() and check_malware_signatures is not None,
            "description": "Signature verification and malware detection tool",
            "entry_point": "check_malware_signatures" if "check_malware_signatures" in globals() and check_malware_signatures is not None else None,
        },
        "hash_compare": {
            "available": "calculate_multiple_file_hashes" in globals() and calculate_multiple_file_hashes is not None,
            "description": "Hash calculation and comparison tool",
            "entry_point": "calculate_multiple_file_hashes" if "calculate_multiple_file_hashes" in globals() and calculate_multiple_file_hashes is not None else None,
        },
        "memory_string_analyzer": {
            "available": "analyze_memory_strings" in globals() and analyze_memory_strings is not None,
            "description": "Memory-extracted string analysis tool",
            "entry_point": "analyze_memory_strings" if "analyze_memory_strings" in globals() and analyze_memory_strings is not None else None,
        }
    }

    # Add system-level environment information
    capabilities["environment"] = {
        "python_version": sys.version.split()[0],
        "platform": sys.platform,
        "initialization_success": INITIALIZATION_SUCCESS,
        "initialization_error": INITIALIZATION_ERROR
    }

    # Add common dependency information
    if COMMON_MODULE_AVAILABLE and "get_package_info" in globals():
        capabilities["common"] = get_package_info()
    else:
        dependencies = check_dependencies()
        capabilities["common"] = {
            "available": COMMON_MODULE_AVAILABLE,
            "dependencies": {
                "yara_python": dependencies.get("yara-python", False),
                "pefile": dependencies.get("pefile", False),
                "ssdeep": dependencies.get("ssdeep", False),
                "forensic_utils": dependencies.get("forensic_utils", False)
            }
        }

    return capabilities

def init_logging(level: int = logging.INFO) -> None:
    """
    Initialize package-level logging with the specified level.

    This function configures the logger for the static analysis package,
    setting up appropriate formatting and log level. It ensures handlers
    are not duplicated if called multiple times.

    Args:
        level: Logging level from the logging module
            (e.g., logging.INFO, logging.DEBUG, etc.)
    """
    logger.setLevel(level)

    # Check for existing handlers to avoid duplicates
    if not logger.handlers:
        # Create a console handler
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        # Try to add a file handler if forensic log directory is available
        try:
            from admin.security.forensics.utils.logging_utils import setup_forensic_logger
            setup_forensic_logger(module_name="static_analysis", log_level=level)
            logger.debug("Forensic logger initialized")
        except ImportError:
            # Fall back to basic file logging if possible
            try:
                log_dir = os.path.join(PACKAGE_ROOT.parent, "logs")
                os.makedirs(log_dir, exist_ok=True)
                file_handler = logging.FileHandler(os.path.join(log_dir, "static_analysis.log"))
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
                logger.debug("Basic file logging initialized")
            except (OSError, PermissionError):
                logger.debug("File logging not available, using console only")

    logger.debug(f"Logging initialized at level {logging.getLevelName(level)}")

    # Log initialization status
    if INITIALIZATION_SUCCESS:
        tools_available = [name for name, available in TOOL_AVAILABILITY.items() if available]
        logger.info(f"Static analysis toolkit initialized with: {', '.join(tools_available)}")
    else:
        logger.warning("Static analysis toolkit initialization incomplete")
        if INITIALIZATION_ERROR:
            logger.error(f"Initialization error: {INITIALIZATION_ERROR}")

# Initialize logging with default level if this is the main module
if __name__ == "__main__":
    init_logging()
