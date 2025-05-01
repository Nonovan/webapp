"""
Audit Views Package

This package contains specialized view helpers for generating reports, aggregating
dashboard data, and preparing compliance documentation from audit logs. These view
helpers transform raw audit data into structured formats suitable for presentation
in administrative dashboards and reports.

The views handle complex data transformation, aggregation, and formatting logic
while maintaining security best practices including proper access control, input
validation, output sanitization, and handling of sensitive information.
"""

import logging
from typing import Dict, Any, List, Optional, Union

# Initialize logger for the package
logger = logging.getLogger(__name__)

# Import view components to make them available when importing the package
try:
    from .dashboard import (
        get_dashboard_data,
        get_event_summary,
        get_severity_distribution,
        get_top_events,
        get_user_activity,
        generate_trend_data,
        get_security_metrics,
        clear_dashboard_cache
    )
except ImportError as e:
    logger.warning(f"Failed to import dashboard views: {e}")

try:
    from .reports import (
        generate_security_report,
        generate_audit_summary,
        generate_activity_report,
        format_report_data
    )
except ImportError as e:
    logger.warning(f"Failed to import report views: {e}")

try:
    from .compliance import (
        generate_compliance_report,
        get_compliance_status,
        get_control_evidence,
        validate_compliance_requirements
    )
except ImportError as e:
    logger.warning(f"Failed to import compliance views: {e}")

# Define package version
__version__ = '0.1.0'

# Define public exports explicitly
__all__ = [
    # Dashboard views
    'get_dashboard_data',
    'get_event_summary',
    'get_severity_distribution',
    'get_top_events',
    'get_user_activity',
    'generate_trend_data',
    'get_security_metrics',
    'clear_dashboard_cache',

    # Report views
    'generate_security_report',
    'generate_audit_summary',
    'generate_activity_report',
    'format_report_data',

    # Compliance views
    'generate_compliance_report',
    'get_compliance_status',
    'get_control_evidence',
    'validate_compliance_requirements'
]

# Log successful initialization
logger.debug("Audit views package initialized")
