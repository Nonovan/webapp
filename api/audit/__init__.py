"""
Audit API Package

This package provides endpoints for querying, analyzing, and exporting audit logs
for the Cloud Infrastructure Platform. It implements secure access controls,
comprehensive filtering, and multiple export formats for security event monitoring
and compliance reporting.

The audit API features:
- Secure filtering of audit logs by various criteria
- Exporting logs in multiple formats (JSON, CSV, PDF)
- Generating compliance and security reports
- Security event correlation and analysis
- Dashboard data aggregation for monitoring
"""

import logging
from flask import Blueprint, current_app

# Initialize logger
logger = logging.getLogger(__name__)

# Create blueprint
audit_bp = Blueprint('audit', __name__, url_prefix='/audit')

# Initialize metrics
try:
    from extensions import metrics
    # Define Prometheus metrics for the audit API
    audit_request_count = metrics.counter(
        'audit_api_requests_total',
        'Total number of audit API requests',
        labels=['endpoint', 'status']
    )

    audit_export_size = metrics.histogram(
        'audit_export_size_bytes',
        'Size of audit data exports in bytes',
        labels=['format'],
        buckets=(1024, 10240, 102400, 1048576, 10485760, 104857600)  # 1KB to 100MB
    )

    audit_query_time = metrics.histogram(
        'audit_query_time_seconds',
        'Time to execute audit queries',
        labels=['endpoint', 'complexity'],
        buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0)  # 10ms to 10s
    )

    audit_logs_count = metrics.gauge(
        'audit_logs_count',
        'Total number of audit logs',
        multiprocess_mode='livesum'
    )

    audit_errors = metrics.counter(
        'audit_api_errors_total',
        'Total number of audit API errors',
        labels=['endpoint', 'error_type']
    )
except (ImportError, AttributeError) as e:
    logger.warning(f"Failed to initialize audit metrics: {e}")
    # Create dummy metrics for graceful fallback
    from core.metrics.dummy import DummyMetric
    audit_request_count = DummyMetric()
    audit_export_size = DummyMetric()
    audit_query_time = DummyMetric()
    audit_logs_count = DummyMetric()
    audit_errors = DummyMetric()

# Load and register routes
from . import routes

# Register metrics
@audit_bp.before_app_first_request
def register_audit_metrics():
    """Register custom metrics for the audit module."""
    try:
        from extensions import metrics

        metrics.gauge(
            'audit_log_count_total',
            'Total number of audit log entries',
            multiprocess_mode='livesum'
        )

        metrics.gauge(
            'audit_critical_events_24h',
            'Number of critical audit events in the last 24 hours',
            multiprocess_mode='livesum'
        )

        metrics.gauge(
            'audit_query_result_count',
            'Count of results from audit queries',
            labels=['endpoint'],
            multiprocess_mode='livesum'
        )

        logger.info("Audit API metrics registered successfully")
    except Exception as e:
        logger.error(f"Failed to register audit metrics: {e}")

# Public exports
from .schemas import (
    audit_log_schema,
    audit_logs_schema,
    audit_filter_schema,
    export_schema,
    compliance_report_schema,
    security_report_schema,
    advanced_search_schema,
    event_correlation_schema,
    dashboard_schema
)

from .filters import build_audit_query, parse_time_range
from .exporters import export_audit_data
from .analyzers import analyze_security_events, correlate_events

# Expose specific view functions that might be needed elsewhere
from .views import (
    generate_compliance_report,
    generate_security_report,
    get_dashboard_data
)

# Define publicly available components from this package
__all__ = [
    'audit_bp',

    # Schemas
    'audit_log_schema',
    'audit_logs_schema',
    'audit_filter_schema',
    'export_schema',
    'compliance_report_schema',
    'security_report_schema',
    'advanced_search_schema',
    'event_correlation_schema',
    'dashboard_schema',

    # Core functionality
    'build_audit_query',
    'parse_time_range',
    'export_audit_data',
    'analyze_security_events',
    'correlate_events',

    # View functions
    'generate_compliance_report',
    'generate_security_report',
    'get_dashboard_data',
]

# Log successful initialization
logger.debug("Audit API package initialized")
