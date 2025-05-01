"""
API Metrics Module for Cloud Infrastructure Platform.

This module provides endpoints for collecting, querying, and exporting metrics
for application performance, system resources, and operational health. It serves
as a central gateway for monitoring and alerting systems.

The module follows security best practices including authentication, role-based
access control, rate limiting, and comprehensive logging. Metrics are collected
from multiple sources including system resources, application performance,
database operations, security events, and cloud resources.

Exports:
    metrics_bp: Flask Blueprint for metrics routes
    init_app: Function to initialize the metrics module with a Flask app
"""

import logging
from flask import Blueprint, Flask
from typing import Optional
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

    Registers all routes and sets up necessary configurations for the metrics API.

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

    # Log initialization
    logger.info("Metrics API initialized successfully")
    _initialized = True

def _register_custom_metrics(app: Flask) -> None:
    """
    Register custom metrics collectors with the metrics registry.

    Args:
        app: Flask application instance
    """
    try:
        # Request counters by endpoint
        metrics_registry.counter(
            'metrics_api_requests_total',
            'Total number of Metrics API requests',
            labels=['endpoint', 'status']
        )

        # Response time histogram
        metrics_registry.histogram(
            'metrics_api_latency_seconds',
            'Metrics API request latency in seconds',
            labels=['endpoint'],
            buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
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
        logger.error(f"Failed to register custom metrics: {e}")

# Explicitly define what is available for import
__all__ = ['metrics_bp', 'init_app']
