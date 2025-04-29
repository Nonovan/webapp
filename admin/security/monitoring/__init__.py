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
    CORE_AVAILABLE = True
except ImportError:
    CORE_AVAILABLE = False
    logger.debug("Core security module not available")

# Define security severity levels
SEVERITY_INFO = "info"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

# Tool initialization functions - these create a clean API for tool use in other modules
def init_file_integrity_monitoring(config_path: Optional[str] = None) -> bool:
    """Initialize file integrity monitoring with optional custom configuration."""
    try:
        # This is a Python function wrapper around the shell script
        from .integrity_monitor import initialize_monitoring
        return initialize_monitoring(config_path)
    except (ImportError, AttributeError):
        logger.warning("File integrity monitoring module not available")
        return False

def init_privilege_audit(app=None) -> bool:
    """Initialize privilege audit functionality with optional Flask app context."""
    try:
        from .privilege_audit import initialize_audit
        return initialize_audit(app)
    except (ImportError, AttributeError):
        logger.warning("Privilege audit module not available")
        return False

def init_threat_intelligence(config_path: Optional[str] = None) -> bool:
    """Initialize threat intelligence tools with optional custom configuration."""
    try:
        from .threat_intelligence import initialize_threat_intel
        return initialize_threat_intel(config_path)
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
        return initialize_dashboard(app, template_path)
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
        return initialize_correlation(rules_dir)
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
        return initialize_detection(baseline_path)
    except (ImportError, AttributeError):
        logger.warning("Anomaly detection module not available")
        return False

def get_monitoring_capabilities() -> Dict[str, bool]:
    """
    Return a dictionary of available monitoring capabilities.

    This helps other modules determine which tools are available.
    """
    capabilities = {
        "integrity_monitoring": os.path.exists(os.path.join(PACKAGE_DIR, "integrity_monitor.sh")),
        "privilege_audit": os.path.exists(os.path.join(PACKAGE_DIR, "privilege_audit.py")),
        "anomaly_detection": os.path.exists(os.path.join(PACKAGE_DIR, "anomaly_detector.sh")),
        "security_dashboard": os.path.exists(os.path.join(PACKAGE_DIR, "security_dashboard.py")),
        "event_correlation": os.path.exists(os.path.join(PACKAGE_DIR, "security_event_correlator.py")),
        "threat_intelligence": os.path.exists(os.path.join(PACKAGE_DIR, "threat_intelligence.py")),
        "utils": UTILS_AVAILABLE,
        "core_integration": CORE_AVAILABLE
    }
    return capabilities

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

    # Utility functions
    "get_monitoring_capabilities",
]

# Log initialization
logger.debug(f"Security monitoring package initialized - {sum(get_monitoring_capabilities().values())} components available")
