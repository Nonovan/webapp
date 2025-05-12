"""
API Metrics Module for Cloud Infrastructure Platform.

This module provides endpoints for collecting, querying, and exporting metrics
for application performance, system resources, and operational health. It serves
as a central gateway for monitoring and alerting systems.

The module follows security best practices including authentication, role-based
access control, rate limiting, and comprehensive logging. Metrics are collected
from multiple sources including system resources, application performance,
database operations, security events, and cloud resources.
"""

import logging
from flask import Blueprint, Flask
from typing import Optional, Dict, Any
from extensions import metrics as metrics_registry

# Create blueprint with URL prefix
metrics_bp = Blueprint('metrics', __name__, url_prefix='/metrics')

# Initialize logger
logger = logging.getLogger(__name__)

# Module version
__version__ = '0.1.1'

# Track initialization state
_initialized = False

def init_app(app: Flask) -> None:
    """
    Initialize the metrics module with the Flask application.

    Args:
        app: Flask application instance
    """
    global _initialized

    if _initialized:
        logger.debug("Metrics API already initialized, skipping")
        return

    # Import routes here to avoid circular imports
    from .routes import (
        get_current_metrics,
        get_historical_metrics,
        export_metrics,
        get_health_summary,
        get_system_metrics,
        get_application_metrics,
        get_database_metrics,
        get_security_metrics,
        get_cloud_metrics,
        get_metric_trends
    )

    # Register metrics collectors
    _register_custom_metrics(app)

    logger.info("Metrics API initialized successfully")
    _initialized = True

def _register_custom_metrics(app: Flask) -> None:
    """Register custom metrics collectors with the metrics registry."""
    try:
        # Configure default latency buckets
        default_latency_buckets = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
        latency_buckets = app.config.get('METRICS_API_LATENCY_BUCKETS', default_latency_buckets)

        # Request counters by endpoint
        metrics_registry.counter(
            'metrics_api_requests_total',
            'Total number of Metrics API requests',
            labels=['endpoint', 'status', 'method']
        )

        # Response time histogram
        metrics_registry.histogram(
            'metrics_api_latency_seconds',
            'Metrics API request latency in seconds',
            labels=['endpoint'],
            buckets=latency_buckets
        )

        # Export metrics counter
        metrics_registry.counter(
            'metrics_export_total',
            'Number of metrics exports by format',
            labels=['format']
        )

        # Health checks counter
        metrics_registry.counter(
            'health_checks_total',
            'Total number of health check calls',
            labels=['result']
        )

        # Data points counter
        metrics_registry.counter(
            'metrics_data_points_returned',
            'Number of metric data points returned',
            labels=['endpoint', 'metric_type']
        )

        logger.debug("Custom metrics registered successfully")
    except Exception as e:
        logger.error("Failed to register custom metrics: %s", e)

# Import public components from submodules
from .collectors import (
    collect_system_metrics,
    collect_database_metrics,
    collect_application_metrics,
    collect_security_metrics,
    collect_cloud_metrics
)

from .analyzers import (
    detect_anomalies,
    analyze_trends,
    calculate_statistics,
    forecast_metrics,
    anomaly_detection_count,
    forecasting_operation_count,
    trend_analysis_count
)

from .aggregators import (
    TimeSeriesConfig,
    DataPoint,
    validate_time_series_input,
    aggregate_time_series,
    calculate_percentiles,
    resample_time_series,
    process_large_dataset
)

from .exporters import (
    export_metrics_prometheus,
    export_metrics_csv,
    export_metrics_json,
    export_metrics_xml,
    format_help_text,
    flatten_metrics,
    sanitize_metric_name,
    filter_sensitive_metrics,
    detect_unit
)

# Define public API
__all__ = [
    # Blueprint and initialization
    'metrics_bp',
    'init_app',
    '__version__',

    # Collectors
    'collect_system_metrics',
    'collect_database_metrics',
    'collect_application_metrics',
    'collect_security_metrics',
    'collect_cloud_metrics',

    # Analyzers
    'detect_anomalies',
    'analyze_trends',
    'calculate_statistics',
    'forecast_metrics',
    'anomaly_detection_count',
    'forecasting_operation_count',
    'trend_analysis_count',

    # Aggregators
    'TimeSeriesConfig',
    'DataPoint',
    'validate_time_series_input',
    'aggregate_time_series',
    'calculate_percentiles',
    'resample_time_series',
    'process_large_dataset',

    # Exporters
    'export_metrics_prometheus',
    'export_metrics_csv',
    'export_metrics_json',
    'export_metrics_xml',
    'format_help_text',
    'flatten_metrics',
    'sanitize_metric_name',
    'filter_sensitive_metrics',
    'detect_unit'
]
