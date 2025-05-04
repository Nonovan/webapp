"""
YARA Rules Collection for Static Analysis.

This module provides YARA rule definitions and scanning capabilities for the
forensic analysis toolkit. It includes rules for detecting malware patterns,
suspicious code, and ransomware indicators during static analysis operations.

The rules are organized by category (malware, ransomware, suspicious) to allow
for focused scanning depending on investigation requirements.
"""

import logging
import os
from pathlib import Path
from typing import Dict, List, Any, Union, Optional, Set, Tuple

# Initialize module-level logger
logger = logging.getLogger(__name__)

# Package version information
__version__ = '1.0.0'
__author__ = 'Security Team'
__email__ = 'security@example.com'
__status__ = 'Production'

# Package path constants
PACKAGE_PATH = Path(__file__).parent
MALWARE_RULES_PATH = PACKAGE_PATH / "malware"
RANSOMWARE_RULES_PATH = PACKAGE_PATH / "ransomware"
SUSPICIOUS_RULES_PATH = PACKAGE_PATH / "suspicious"

# Feature availability flags
YARA_AVAILABLE = False
SCANNER_AVAILABLE = False

# Try to import YARA scanner
try:
    from .yara_scanner import YaraScanner, YARA_AVAILABLE
    SCANNER_AVAILABLE = True
    logger.debug("YaraScanner successfully imported")
except ImportError as e:
    logger.warning(f"Could not import YaraScanner: {e}")
    # Define stub class for interface compatibility
    class YaraScanner:
        """Stub class when YARA scanner is not available."""
        def __init__(self, *args, **kwargs):
            logger.error("YaraScanner not available - missing dependencies")
            raise ImportError("yara-python is required for YaraScanner")

# Validate rule directories
def _validate_rule_directories() -> Dict[str, bool]:
    """Check if rule directories exist and contain rules."""
    results = {
        "malware": False,
        "ransomware": False,
        "suspicious": False
    }

    try:
        # Check for malware rules
        if MALWARE_RULES_PATH.exists() and any(f.suffix in ('.yar', '.yara') for f in MALWARE_RULES_PATH.glob('*.ya*')):
            results["malware"] = True
            logger.debug("Malware YARA rules available")

        # Check for ransomware rules
        if RANSOMWARE_RULES_PATH.exists() and any(f.suffix in ('.yar', '.yara') for f in RANSOMWARE_RULES_PATH.glob('*.ya*')):
            results["ransomware"] = True
            logger.debug("Ransomware YARA rules available")

        # Check specific families directory
        families_path = RANSOMWARE_RULES_PATH / "specific_families"
        if families_path.exists() and any(f.suffix in ('.yar', '.yara') for f in families_path.glob('*.ya*')):
            logger.debug("Ransomware family-specific YARA rules available")

        # Check for suspicious rules
        if SUSPICIOUS_RULES_PATH.exists() and any(f.suffix in ('.yar', '.yara') for f in SUSPICIOUS_RULES_PATH.glob('*.ya*')):
            results["suspicious"] = True
            logger.debug("Suspicious patterns YARA rules available")

    except Exception as e:
        logger.error(f"Error validating YARA rule directories: {e}")

    return results

# Check for available rules
AVAILABLE_RULES = _validate_rule_directories()

# Package exports
__all__ = [
    # Constants
    'YARA_AVAILABLE',
    'SCANNER_AVAILABLE',
    'PACKAGE_PATH',
    'MALWARE_RULES_PATH',
    'RANSOMWARE_RULES_PATH',
    'SUSPICIOUS_RULES_PATH',

    # Classes
    'YaraScanner',

    # Package info
    '__version__',
    '__author__',
    '__email__',
    '__status__'
]

def get_available_rule_categories() -> Dict[str, bool]:
    """
    Return information about available YARA rule categories.

    Returns:
        Dictionary with availability status for each rule category
    """
    return AVAILABLE_RULES.copy()

def get_recommended_rule_paths(category: Optional[str] = None) -> List[str]:
    """
    Get recommended rule paths for scanning based on category.

    Args:
        category: Optional category filter ('malware', 'ransomware', 'suspicious')
                 If None, returns paths for all available categories

    Returns:
        List of recommended paths to YARA rule files/directories
    """
    paths = []

    if category == 'malware' or category is None:
        if AVAILABLE_RULES["malware"]:
            paths.append(str(MALWARE_RULES_PATH))

    if category == 'ransomware' or category is None:
        if AVAILABLE_RULES["ransomware"]:
            paths.append(str(RANSOMWARE_RULES_PATH))
            # Add specific families directory if it exists
            families_path = RANSOMWARE_RULES_PATH / "specific_families"
            if families_path.exists():
                paths.append(str(families_path))

    if category == 'suspicious' or category is None:
        if AVAILABLE_RULES["suspicious"]:
            paths.append(str(SUSPICIOUS_RULES_PATH))

    return paths

def create_scanner(category: Optional[str] = None,
                   custom_paths: Optional[List[str]] = None,
                   timeout: int = 60) -> Optional[YaraScanner]:
    """
    Create a YaraScanner instance with appropriate rule paths.

    This is a convenience function to create a scanner with rules from
    specified categories or custom paths.

    Args:
        category: Optional category filter ('malware', 'ransomware', 'suspicious')
                 If None, uses rules from all available categories
        custom_paths: Optional list of custom paths to YARA rules
        timeout: Scanning timeout in seconds

    Returns:
        Configured YaraScanner instance or None if scanner is not available

    Example:
        # Create scanner with all available rules
        scanner = create_scanner()

        # Create scanner with only ransomware rules
        scanner = create_scanner(category='ransomware')

        # Create scanner with custom rules
        scanner = create_scanner(custom_paths=['/path/to/rules.yar'])
    """
    if not SCANNER_AVAILABLE:
        logger.error("Cannot create scanner: YaraScanner not available")
        return None

    try:
        # Build rule paths list
        rule_paths = []

        # Add category-based paths if specified
        if category or category is None:
            rule_paths.extend(get_recommended_rule_paths(category))

        # Add custom paths if provided
        if custom_paths:
            rule_paths.extend(custom_paths)

        # If no paths available, warn and use default
        if not rule_paths:
            logger.warning("No rule paths provided or found, using scanner default")
            return YaraScanner(default_timeout=timeout)

        # Create scanner with specified paths
        logger.debug(f"Creating YARA scanner with paths: {rule_paths}")
        return YaraScanner(rule_paths=rule_paths, default_timeout=timeout)

    except Exception as e:
        logger.error(f"Error creating YARA scanner: {e}")
        return None

# Log initialization status
logger.info(f"YARA rules module initialized (version {__version__})")
if YARA_AVAILABLE:
    logger.info("YARA scanning capabilities available")
    logger.info(f"Available rule categories: {', '.join(k for k, v in AVAILABLE_RULES.items() if v)}")
else:
    logger.warning("YARA scanning capabilities not available - missing yara-python")
