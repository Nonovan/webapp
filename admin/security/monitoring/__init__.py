"""
Security Monitoring Tools Package

This package contains specialized security monitoring tools for administrative use.
These tools provide enhanced visibility into security events, support incident
investigation, and enable proactive threat detection beyond what's available
in the standard monitoring system.

Key components include:
- Enhanced file integrity monitoring
- Administrative privilege monitoring and auditing
- Security anomaly detection
- Threat intelligence integration
- Security event correlation
- Security dashboard generation
"""

import os
import sys
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

# Package version
__version__ = '1.0.0'
__author__ = 'Security Team'
__description__ = 'Security monitoring tools for the Cloud Infrastructure Platform'

# Define package-level constants
PACKAGE_DIR = Path(__file__).parent.resolve()
CONFIG_DIR = PACKAGE_DIR / "config"
TEMPLATES_DIR = PACKAGE_DIR / "templates"
LOG_DIR = Path(os.environ.get("SECURITY_LOG_DIR", "/var/log/cloud-platform/security"))
REPORT_DIR = Path(os.environ.get("SECURITY_REPORT_DIR", "/var/www/reports/security"))

# Set up package-level logging
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Import utility functions if available
try:
    from .utils import get_capabilities
    UTILS_AVAILABLE = True
except ImportError:
    UTILS_AVAILABLE = False
    def get_capabilities() -> Dict[str, bool]:
        return {
            "alert_formatter": False,
            "event_normalizer": False,
            "indicator_matcher": False,
            "log_parser": False
        }

# Check for core dependencies
try:
    from core.security import SECURITY_CONFIG
    from core.metrics import register_component_status
    CORE_AVAILABLE = True
    METRICS_AVAILABLE = True
except ImportError:
    CORE_AVAILABLE = False
    METRICS_AVAILABLE = False
    logger.debug("Core security or metrics module not available")

# Define security severity levels
SEVERITY_INFO = "info"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

# Try to import monitoring constants
try:
    from .monitoring_constants import (
        SEVERITY,
        EVENT_TYPES,
        OUTPUT_FORMATS,
        DETECTION_SENSITIVITY,
        THREAT_INTEL,
        INTEGRITY_MONITORING
    )
    CONSTANTS_AVAILABLE = True
except ImportError:
    CONSTANTS_AVAILABLE = False
    logger.debug("Monitoring constants not available")

# Tool initialization functions - these create a clean API for tool use in other modules
def init_file_integrity_monitoring(config_path: Optional[str] = None) -> bool:
    """
    Initialize file integrity monitoring with optional custom configuration.

    Args:
        config_path: Optional path to configuration file

    Returns:
        bool: True if initialization was successful
    """
    try:
        # This is a Python function wrapper around the shell script
        from .integrity_monitor import initialize_monitoring
        success = initialize_monitoring(config_path)

        # Register component status with metrics system if available
        if METRICS_AVAILABLE:
            register_component_status(
                "security_file_integrity",
                success,
                version=__version__
            )

        return success
    except (ImportError, AttributeError):
        logger.warning("File integrity monitoring module not available")
        return False

def init_privilege_audit(app=None) -> bool:
    """
    Initialize privilege audit functionality with optional Flask app context.

    Args:
        app: Optional Flask application for context

    Returns:
        bool: True if initialization was successful
    """
    try:
        from .privilege_audit import initialize_audit
        success = initialize_audit(app)

        # Register component status with metrics system if available
        if METRICS_AVAILABLE:
            register_component_status(
                "security_privilege_audit",
                success,
                version=__version__
            )

        return success
    except (ImportError, AttributeError):
        logger.warning("Privilege audit module not available")
        return False

def init_threat_intelligence(config_path: Optional[str] = None) -> bool:
    """
    Initialize threat intelligence tools with optional custom configuration.

    Args:
        config_path: Optional path to custom configuration file

    Returns:
        bool: True if initialization was successful
    """
    try:
        from .threat_intelligence import initialize_threat_intel
        success = initialize_threat_intel(config_path)

        # Register component status with metrics system if available
        if METRICS_AVAILABLE:
            register_component_status(
                "security_threat_intel",
                success,
                version=__version__
            )

        return success
    except (ImportError, AttributeError):
        logger.warning("Threat intelligence module not available")
        return False

def init_security_dashboard(app=None, template_path: Optional[str] = None) -> bool:
    """
    Initialize security dashboard generator with optional Flask app context.

    Args:
        app: Optional Flask application for context
        template_path: Optional custom template path

    Returns:
        bool: True if initialization was successful
    """
    try:
        from .security_dashboard import initialize_dashboard
        success = initialize_dashboard(app, template_path)

        # Register component status with metrics system if available
        if METRICS_AVAILABLE and app:
            register_component_status(
                "security_dashboard",
                success,
                version=__version__
            )

        return success
    except (ImportError, AttributeError):
        logger.warning("Security dashboard module not available")
        return False

def init_event_correlation(rules_dir: Optional[str] = None) -> bool:
    """
    Initialize security event correlation engine.

    Args:
        rules_dir: Optional directory containing correlation rules

    Returns:
        bool: True if initialization was successful
    """
    try:
        from .security_event_correlator import initialize_correlation
        success = initialize_correlation(rules_dir)

        # Register component status with metrics system if available
        if METRICS_AVAILABLE:
            register_component_status(
                "security_event_correlation",
                success,
                version=__version__
            )

        return success
    except (ImportError, AttributeError):
        logger.warning("Security event correlator not available")
        return False

def init_anomaly_detection(baseline_path: Optional[str] = None) -> bool:
    """
    Initialize anomaly detection system.

    Args:
        baseline_path: Optional path to behavioral baseline file

    Returns:
        bool: True if initialization was successful
    """
    try:
        # This is a Python function wrapper around the shell script
        from .anomaly_detector import initialize_detection
        success = initialize_detection(baseline_path)

        # Register component status with metrics system if available
        if METRICS_AVAILABLE:
            register_component_status(
                "security_anomaly_detection",
                success,
                version=__version__
            )

        return success
    except (ImportError, AttributeError):
        logger.warning("Anomaly detection module not available")
        return False

def get_monitoring_capabilities() -> Dict[str, bool]:
    """
    Return a dictionary of available monitoring capabilities.

    This helps other modules determine which tools are available.

    Returns:
        Dict[str, bool]: Dictionary mapping capability names to availability status
    """
    capabilities = {
        "integrity_monitoring": os.path.exists(os.path.join(PACKAGE_DIR, "integrity_monitor.sh")),
        "privilege_audit": os.path.exists(os.path.join(PACKAGE_DIR, "privilege_audit.py")),
        "anomaly_detection": os.path.exists(os.path.join(PACKAGE_DIR, "anomaly_detector.sh")),
        "security_dashboard": os.path.exists(os.path.join(PACKAGE_DIR, "security_dashboard.py")),
        "event_correlation": os.path.exists(os.path.join(PACKAGE_DIR, "security_event_correlator.py")),
        "threat_intelligence": os.path.exists(os.path.join(PACKAGE_DIR, "threat_intelligence.py")),
        "utils": UTILS_AVAILABLE,
        "core_integration": CORE_AVAILABLE,
        "constants": CONSTANTS_AVAILABLE
    }
    return capabilities

def init_all_tools(app=None) -> Dict[str, bool]:
    """
    Initialize all available security monitoring tools.

    This is a convenience function that attempts to initialize all tools
    and returns their initialization status.

    Args:
        app: Optional Flask app context to pass to components that need it

    Returns:
        Dict[str, bool]: Dictionary mapping tool names to initialization status
    """
    results = {}

    # Initialize all available tools
    capabilities = get_monitoring_capabilities()

    if capabilities.get("integrity_monitoring"):
        results["integrity_monitoring"] = init_file_integrity_monitoring()

    if capabilities.get("privilege_audit"):
        results["privilege_audit"] = init_privilege_audit(app)

    if capabilities.get("threat_intelligence"):
        results["threat_intelligence"] = init_threat_intelligence()

    if capabilities.get("security_dashboard"):
        results["security_dashboard"] = init_security_dashboard(app)

    if capabilities.get("event_correlation"):
        results["event_correlation"] = init_event_correlation()

    if capabilities.get("anomaly_detection"):
        results["anomaly_detection"] = init_anomaly_detection()

    # Log initialization summary
    success_count = sum(1 for status in results.values() if status)
    total_count = len(results)
    logger.info(f"Initialized {success_count}/{total_count} monitoring tools")

    # Register overall package status
    if METRICS_AVAILABLE:
        register_component_status(
            "security_monitoring",
            success_count > 0,
            version=__version__,
            details={
                "tools_available": total_count,
                "tools_initialized": success_count
            }
        )

    return results

# Define public API
__all__ = [
    # Constants
    "SEVERITY_INFO",
    "SEVERITY_LOW",
    "SEVERITY_MEDIUM",
    "SEVERITY_HIGH",
    "SEVERITY_CRITICAL",

    # Package metadata
    "__version__",
    "__author__",
    "__description__",

    # Module paths
    "PACKAGE_DIR",
    "CONFIG_DIR",
    "TEMPLATES_DIR",
    "LOG_DIR",
    "REPORT_DIR",

    # Initialization functions
    "init_file_integrity_monitoring",
    "init_privilege_audit",
    "init_threat_intelligence",
    "init_security_dashboard",
    "init_event_correlation",
    "init_anomaly_detection",
    "init_all_tools",

    # Utility functions
    "get_monitoring_capabilities",
]

# Conditionally add monitoring constants to exports if available
if CONSTANTS_AVAILABLE:
    __all__.extend([
        "SEVERITY",
        "EVENT_TYPES",
        "OUTPUT_FORMATS",
        "DETECTION_SENSITIVITY",
        "THREAT_INTEL",
        "INTEGRITY_MONITORING"
    ])

# Log initialization
logger.debug(f"Security monitoring package initialized - {sum(get_monitoring_capabilities().values())} components available")
