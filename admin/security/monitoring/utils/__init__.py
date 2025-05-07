"""
Security Monitoring Utilities Package

This package provides utility functions and helper modules for handling security event data,
formatting alerts, normalizing events across different sources, and matching security indicators.
These utilities support the security monitoring tools in the Cloud Infrastructure Platform with
standardized functionality for log parsing, event processing, and indicator matching.

Key functionality includes:
- Security log parsing for multiple formats
- Event normalization and standardization
- Indicator of compromise matching
- Security alert formatting
- Performance-optimized data processing

These utilities ensure consistent data handling across security monitoring tools while
following security best practices for sensitive data management.
"""

import logging
import os
from typing import Dict, Any, List, Optional, Set, Tuple, Union
from pathlib import Path

# Package version
__version__ = '0.1.1'
__author__ = 'Security Team'
__email__ = 'security@example.com'
__status__ = 'Production'

# Setup package-level logger
logger = logging.getLogger(__name__)

# Determine availability of package components
ALERT_FORMATTER_AVAILABLE = False
EVENT_NORMALIZER_AVAILABLE = False
INDICATOR_MATCHER_AVAILABLE = False
LOG_PARSER_AVAILABLE = False

# Try importing the alert formatter utilities
try:
    from .alert_formatter import (
        format_security_alert,
        format_batch_alerts,
        get_alert_template,
        get_severity_color,
        get_severity_icon,
        sanitize_alert_data,
        render_alert_template,
        ALERT_FORMATTER_AVAILABLE
    )
    # Update the availability flag based on what the module reports
    ALERT_FORMATTER_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Alert formatter not available: {e}")

# Try importing the event normalizer utilities
try:
    from .event_normalizer import (
        normalize_event,
        normalize_batch,
        get_event_schema,
        map_vendor_fields,
        standardize_timestamp,
        enrich_event_data,
        validate_normalized_event,
        extract_event_fields,
        EVENT_NORMALIZER_AVAILABLE
    )
    EVENT_NORMALIZER_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Event normalizer not available: {e}")

# Try importing the indicator matching utilities
try:
    from .indicator_matcher import (
        match_indicators,
        load_indicator_set,
        match_ip_address,
        match_domain,
        match_file_hash,
        match_regex_pattern,
        calculate_match_confidence,
        update_indicator_cache,
        INDICATOR_MATCHER_AVAILABLE
    )
    INDICATOR_MATCHER_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Indicator matcher not available: {e}")

# Try importing the log parser utilities
try:
    from .log_parser import (
        parse_security_log,
        parse_log_line,
        detect_log_format,
        parse_syslog_format,
        parse_json_format,
        parse_cef_format,
        parse_leef_format,
        parse_apache_format,
        parse_fallback_format,
        extract_log_fields,
        get_log_parser_for_format,
        LOG_PARSER_AVAILABLE
    )
    LOG_PARSER_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Log parser not available: {e}")

def get_capabilities() -> Dict[str, bool]:
    """
    Get available utility capabilities in the current environment.

    Returns:
        Dict containing available utility components and their status
    """
    return {
        "alert_formatter": ALERT_FORMATTER_AVAILABLE,
        "event_normalizer": EVENT_NORMALIZER_AVAILABLE,
        "indicator_matcher": INDICATOR_MATCHER_AVAILABLE,
        "log_parser": LOG_PARSER_AVAILABLE
    }

def get_utility_version() -> str:
    """
    Get the version string of the security monitoring utilities.

    Returns:
        String containing version information
    """
    return __version__

# Export public API - core functionality that's always available
__all__ = [
    # Version and package information
    '__version__',
    '__author__',
    '__email__',
    '__status__',

    # Core functionality
    'get_capabilities',
    'get_utility_version'
]

# Conditionally add components to public API based on availability
if ALERT_FORMATTER_AVAILABLE:
    __all__.extend([
        'format_security_alert',
        'format_batch_alerts',
        'get_alert_template',
        'get_severity_color',
        'get_severity_icon',
        'sanitize_alert_data',
        'render_alert_template'
    ])

if EVENT_NORMALIZER_AVAILABLE:
    __all__.extend([
        'normalize_event',
        'normalize_batch',
        'get_event_schema',
        'map_vendor_fields',
        'standardize_timestamp',
        'enrich_event_data',
        'validate_normalized_event',
        'extract_event_fields'
    ])

if INDICATOR_MATCHER_AVAILABLE:
    __all__.extend([
        'match_indicators',
        'load_indicator_set',
        'match_ip_address',
        'match_domain',
        'match_file_hash',
        'match_regex_pattern',
        'calculate_match_confidence',
        'update_indicator_cache'
    ])

if LOG_PARSER_AVAILABLE:
    __all__.extend([
        'parse_security_log',
        'parse_log_line',
        'detect_log_format',
        'parse_syslog_format',
        'parse_json_format',
        'parse_cef_format',
        'parse_leef_format',
        'parse_apache_format',
        'parse_fallback_format',
        'extract_log_fields',
        'get_log_parser_for_format'
    ])

# Log package initialization with more detailed information
available_components = [k for k, v in get_capabilities().items() if v]
logger.debug(f"Security monitoring utilities initialized (v{__version__}): " +
             (", ".join(available_components) if available_components else "No components available"))

# Register initialization status for monitoring if metrics are available
try:
    from core.metrics import register_component_status
    register_component_status("security_monitoring_utils", bool(available_components), version=__version__)
except ImportError:
    pass  # Optional dependency, not critical if unavailable
