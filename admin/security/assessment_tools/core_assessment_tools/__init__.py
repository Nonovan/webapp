"""
Core Assessment Tools package for security assessments.

This package provides a comprehensive set of security assessment tools for evaluating
different aspects of system and application security. Tools are designed with a common
framework and shared utilities to ensure consistent evaluation methodology, evidence
collection, and reporting.

Available assessment tools:
- configuration_analyzer: System configuration security baseline validation
- vulnerability_scanner: Automated vulnerability scanning for systems
- network_security_tester: Network security control validation
- access_control_auditor: Access control implementation verification
- code_security_analyzer: Static code analysis for security vulnerabilities
- password_strength_tester: Authentication security validation

Each tool follows standardized assessment workflows including initialization,
execution, finding analysis, and result reporting with proper evidence collection.
Tools support compliance mapping to frameworks like PCI-DSS, NIST, and CIS.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

# Initialize package logger
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Package version
__version__ = "1.0.0"

# Try to import from common module first to check availability
try:
    from .common import (
        AssessmentBase,
        AssessmentStatus,
        AssessmentTarget,
        Finding,
        FindingSeverity,
        initialize_common_components
    )
    HAS_COMMON_COMPONENTS = True
except ImportError as e:
    logger.warning(f"Could not import common components: {e}")
    HAS_COMMON_COMPONENTS = False

# Get available assessment tools
_available_tools = {}

# Try importing each tool, but don't fail if some are missing
try:
    from .configuration_analyzer import ConfigurationAnalyzer
    _available_tools["configuration_analyzer"] = ConfigurationAnalyzer
except ImportError as e:
    logger.debug(f"Configuration analyzer not available: {e}")

try:
    from .vulnerability_scanner import VulnerabilityScanner
    _available_tools["vulnerability_scanner"] = VulnerabilityScanner
except ImportError as e:
    logger.debug(f"Vulnerability scanner not available: {e}")

try:
    from .network_security_tester import NetworkSecurityTester
    _available_tools["network_security_tester"] = NetworkSecurityTester
except ImportError as e:
    logger.debug(f"Network security tester not available: {e}")

try:
    from .access_control_auditor import AccessControlAuditor
    _available_tools["access_control_auditor"] = AccessControlAuditor
except ImportError as e:
    logger.debug(f"Access control auditor not available: {e}")

try:
    from .code_security_analyzer import CodeSecurityAnalyzer
    _available_tools["code_security_analyzer"] = CodeSecurityAnalyzer
except ImportError as e:
    logger.debug(f"Code security analyzer not available: {e}")

try:
    from .password_strength_tester import PasswordStrengthTester
    _available_tools["password_strength_tester"] = PasswordStrengthTester
except ImportError as e:
    logger.debug(f"Password strength tester not available: {e}")


def get_available_tools() -> Dict[str, type]:
    """
    Get dictionary of available assessment tools.

    Returns:
        Dictionary mapping tool names to tool classes
    """
    return _available_tools.copy()


def initialize_tools(config_path: Optional[str] = None) -> bool:
    """
    Initialize all assessment tools with common configuration.

    Args:
        config_path: Optional path to configuration file

    Returns:
        True if initialization was successful, False otherwise
    """
    if not HAS_COMMON_COMPONENTS:
        logger.error("Cannot initialize tools: common components not available")
        return False

    try:
        # Initialize common components first
        if not initialize_common_components(config_path):
            logger.error("Failed to initialize common components")
            return False

        logger.info(f"Initialized {len(_available_tools)} assessment tools successfully")
        return True
    except Exception as e:
        logger.error(f"Error initializing assessment tools: {e}")
        return False


# Export public classes and functions
__all__ = [
    # Main tool classes
    "ConfigurationAnalyzer",
    "VulnerabilityScanner",
    "NetworkSecurityTester",
    "AccessControlAuditor",
    "CodeSecurityAnalyzer",
    "PasswordStrengthTester",

    # Utility functions
    "get_available_tools",
    "initialize_tools",

    # Package information
    "__version__",
]
