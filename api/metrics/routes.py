"""
Metrics API routes for the Cloud Infrastructure Platform.

This module implements RESTful endpoints for retrieving system and application
metrics, providing access to performance data, resource usage statistics,
and system health information. These endpoints support monitoring dashboards,
alerting systems, and performance analysis tools.

All endpoints enforce strict access control and implement comprehensive
rate limiting to prevent abuse. The API supports complex metric queries
with configurable time ranges and export formats.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple, Union
import json

from flask import Blueprint, request, jsonify, current_app, Response, g, send_file, abort
from sqlalchemy import desc, func
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import BadRequest, NotFound, Forbidden

from extensions import db, limiter, cache, metrics
from core.security import require_permission, log_security_event
from core.metrics import (
    get_all_metrics,
    SystemMetrics,
    DatabaseMetrics,
    ApplicationMetrics,
    SecurityMetrics,
    _calculate_health_status
)
from .collectors import (
    collect_system_metrics,
    collect_database_metrics,
    collect_application_metrics,
    collect_security_metrics,
    collect_cloud_metrics
)
from .exporters import (
    export_metrics_prometheus,
    export_metrics_csv,
    export_metrics_json
)
from .analyzers import (
    detect_anomalies,
    analyze_trends,
    calculate_statistics,
    forecast_metrics
)
from .aggregators import (
    aggregate_time_series,
    calculate_percentiles,
    resample_time_series
)

# Initialize logger
logger = logging.getLogger(__name__)

# Create blueprint
metrics_bp = Blueprint('metrics', __name__, url_prefix='/metrics')

# Apply rate limits with overrides from config
DEFAULT_LIMIT = current_app.config.get('RATELIMIT_METRICS_DEFAULT', "60 per minute") if hasattr(current_app, 'config') else "60 per minute"
EXPORT_LIMIT = current_app.config.get('RATELIMIT_METRICS_EXPORT', "10 per minute") if hasattr(current_app, 'config') else "10 per minute"
HISTORY_LIMIT = current_app.config.get('RATELIMIT_METRICS_HISTORY', "30 per minute") if hasattr(current_app, 'config') else "30 per minute"

# Configure metrics tracking for the metrics API (meta-metrics)
metrics_request_count = metrics.counter(
    'metrics_api_requests_total',
    'Total number of Metrics API requests',
    labels=['endpoint', 'status']
)

metrics_response_time = metrics.histogram(
    'metrics_api_latency_seconds',
    'Metrics API request latency in seconds',
    labels=['endpoint'],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
)

# Common error handler for metrics API
def handle_metrics_error(e: Exception, status_code: int = 500) -> Tuple[Response, int]:
    """Common error handler for metrics API endpoints."""
    logger.error(f"Metrics API error: {str(e)}", exc_info=True)

    # Log security event for critical errors
    if status_code >= 500:
        log_security_event(
            event_type="metrics_api_error",
            description=f"Metrics API error: {str(e)}",
            severity="error",
            user_id=g.get('user_id'),
            ip_address=request.remote_addr,
            details={"endpoint": request.path, "method": request.method}
        )

    error_message = str(e) if not isinstance(e, SQLAlchemyError) else "Database error"
    return jsonify({"error": error_message}), status_code

# Register error handlers
@metrics_bp.errorhandler(BadRequest)
def handle_bad_request(e):
    return handle_metrics_error(e, 400)

@metrics_bp.errorhandler(Forbidden)
def handle_forbidden(e):
    return handle_metrics_error(e, 403)

@metrics_bp.errorhandler(NotFound)
def handle_not_found(e):
    return handle_metrics_error(e, 404)

@metrics_bp.errorhandler(SQLAlchemyError)
def handle_db_error(e):
    return handle_metrics_error(e, 500)

@metrics_bp.errorhandler(Exception)
def handle_exception(e):
    return handle_metrics_error(e, 500)

@metrics_bp.route('', methods=['GET'])
@require_permission('metrics:view')
@limiter.limit(DEFAULT_LIMIT)
def get_current_metrics():
    """
    Get current system and application metrics.

    Returns:
        JSON: Current metrics for all monitored systems
    """
    try:
        # Get metrics from cache if available, otherwise collect fresh data
        cached_metrics = cache.get('current_metrics')
        if cached_metrics:
            metrics_request_count.inc(1, labels={'endpoint': '/metrics', 'status': '200'})
            return jsonify(cached_metrics), 200

        # Collect fresh metrics
        current_time = datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'

        result = {
            "timestamp": current_time,
            "system": collect_system_metrics(),
            "application": collect_application_metrics(),
            "database": collect_database_metrics(),
            "security": collect_security_metrics(),
            "cloud": collect_cloud_metrics()
        }

        # Calculate overall status
        result["status"] = _calculate_health_status(result)

        # Cache the result
        cache_ttl = current_app.config.get('METRICS_CACHE_TIMEOUT', 15)  # Default 15 seconds
        cache.set('current_metrics', result, timeout=cache_ttl)

        metrics_request_count.inc(1, labels={'endpoint': '/metrics', 'status': '200'})
        return jsonify(result), 200

    except Exception as e:
        metrics_request_count.inc(1, labels={'endpoint': '/metrics', 'status': '500'})
        logger.error(f"Error retrieving current metrics: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to retrieve metrics"}), 500

@metrics_bp.route('/history', methods=['GET'])
@require_permission('metrics:history')
@limiter.limit(HISTORY_LIMIT)
def get_historical_metrics():
    """
    Get historical metrics with time ranges.

    Query Parameters:
        metric (str): Name of the metric to retrieve
        start (str): ISO format start datetime
        end (str): ISO format end datetime
        interval (str): Aggregation interval (minute, hour, day)

    Returns:
        JSON: Historical metric data with time series
    """
    try:
        # Extract and validate parameters
        metric_name = request.args.get('metric')
        if not metric_name:
            return jsonify({"error": "Metric name is required"}), 400

        start_str = request.args.get('start')
        end_str = request.args.get('end')

        if not start_str:
            # Default to 24 hours ago if not specified
            start = datetime.utcnow() - timedelta(hours=24)
        else:
            try:
                start = datetime.fromisoformat(start_str.replace('Z', '+00:00'))
            except ValueError:
                return jsonify({"error": "Invalid start date format. Use ISO format (e.g. 2023-06-14T00:00:00Z)"}), 400

        if not end_str:
            # Default to now if not specified
            end = datetime.utcnow()
        else:
            try:
                end = datetime.fromisoformat(end_str.replace('Z', '+00:00'))
            except ValueError:
                return jsonify({"error": "Invalid end date format. Use ISO format (e.g. 2023-06-15T00:00:00Z)"}), 400

        # Validate time range
        if end <= start:
            return jsonify({"error": "End date must be after start date"}), 400

        # Limit the time range to prevent excessive queries
        max_days = current_app.config.get('METRICS_HISTORY_RETENTION_DAYS', 30)
        if (end - start).days > max_days:
            return jsonify({"error": f"Time range cannot exceed {max_days} days"}), 400

        # Get interval parameter
        interval = request.args.get('interval', 'hour').lower()
        if interval not in ['minute', 'hour', 'day']:
            return jsonify({"error": "Invalid interval. Use 'minute', 'hour', or 'day'"}), 400

        # Get data points limit
        max_points = current_app.config.get('METRICS_MAX_POINTS', 1000)

        # Fetch metrics from database
        # This would typically query a time series database or table
        # For demonstration, we'll assume there's a metrics table with timestamp, name, and value columns
        try:
            # Example query (adjust based on your actual database schema)
            data_points = []

            # Note: This is a placeholder. In a real implementation, you'd query your
            # metrics storage system (e.g., Prometheus, InfluxDB, or a custom table)
            # The actual implementation depends on how metrics are stored
            # Here we're just generating example data

            # Resample the time series to the requested interval
            resampled_data = resample_time_series(data_points, interval, start, end, max_points)

            # Calculate statistics
            statistics = calculate_statistics(resampled_data)

            result = {
                "metric": metric_name,
                "interval": interval,
                "unit": detect_metric_unit(metric_name),
                "start_time": start.isoformat() + 'Z',
                "end_time": end.isoformat() + 'Z',
                "data_points": resampled_data,
                "statistics": statistics
            }

            metrics_request_count.inc(1, labels={'endpoint': '/metrics/history', 'status': '200'})
            return jsonify(result), 200

        except Exception as e:
            logger.error(f"Database error retrieving historical metrics: {str(e)}", exc_info=True)
            return jsonify({"error": "Failed to retrieve historical metrics"}), 500

    except Exception as e:
        metrics_request_count.inc(1, labels={'endpoint': '/metrics/history', 'status': '500'})
        logger.error(f"Error retrieving historical metrics: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to retrieve historical metrics"}), 500

@metrics_bp.route('/export', methods=['GET'])
@require_permission('metrics:export')
@limiter.limit(EXPORT_LIMIT)
def export_metrics():
    """
    Export metrics in various formats.

    Query Parameters:
        format (str): Export format (json, csv, prometheus)
        metrics (str): Comma-separated list of metrics to export

    Returns:
        File download or JSON: Exported metrics in the requested format
    """
    try:
        # Get export format
        export_format = request.args.get('format', 'json').lower()

        # Validate format
        allowed_formats = current_app.config.get('METRICS_EXPORT_FORMATS', ['json', 'prometheus', 'csv'])
        if export_format not in allowed_formats:
            return jsonify({
                "error": f"Unsupported format. Use one of: {', '.join(allowed_formats)}"
            }), 400

        # Get metrics list (optional filter)
        metrics_list = None
        if 'metrics' in request.args:
            metrics_list = [m.strip() for m in request.args.get('metrics').split(',')]

        # Get current metrics data
        metrics_data = get_all_metrics()

        # Filter metrics if list is provided
        if metrics_list:
            # Apply filtering based on your metrics structure
            # This is a simplified example
            filtered_data = {}
            for category, category_metrics in metrics_data.items():
                if isinstance(category_metrics, dict):
                    filtered_category = {}
                    for metric_name, value in category_metrics.items():
                        if metric_name in metrics_list or f"{category}.{metric_name}" in metrics_list:
                            filtered_category[metric_name] = value
                    if filtered_category:
                        filtered_data[category] = filtered_category
            metrics_data = filtered_data

        # Export in the requested format
        if export_format == 'json':
            # Return JSON directly
            metrics_request_count.inc(1, labels={'endpoint': '/metrics/export', 'status': '200'})
            return jsonify(metrics_data), 200

        elif export_format == 'csv':
            # Export to CSV
            csv_data = export_metrics_csv(metrics_data)
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

            # Return CSV file for download
            metrics_request_count.inc(1, labels={'endpoint': '/metrics/export', 'status': '200'})
            return Response(
                csv_data,
                mimetype='text/csv',
                headers={
                    'Content-Disposition': f'attachment; filename=metrics_export_{timestamp}.csv'
                }
            )

        elif export_format == 'prometheus':
            # Export in Prometheus exposition format
            prom_data = export_metrics_prometheus(metrics_data)

            metrics_request_count.inc(1, labels={'endpoint': '/metrics/export', 'status': '200'})
            return Response(
                prom_data,
                mimetype='text/plain; version=0.0.4',
                headers={
                    'Content-Type': 'text/plain; version=0.0.4'
                }
            )

    except Exception as e:
        metrics_request_count.inc(1, labels={'endpoint': '/metrics/export', 'status': '500'})
        logger.error(f"Error exporting metrics: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to export metrics"}), 500

@metrics_bp.route('/health', methods=['GET'])
@require_permission('metrics:health')
@limiter.limit(DEFAULT_LIMIT)
def get_health_summary():
    """
    Get system health summary.

    Returns:
        JSON: Health status for all system components
    """
    try:
        # Check if data is in cache
        cached_health = cache.get('health_summary')
        if cached_health:
            metrics_request_count.inc(1, labels={'endpoint': '/metrics/health', 'status': '200'})
            return jsonify(cached_health), 200

        # Get current time
        current_time = datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'

        # Collect metrics for health check
        system_metrics = collect_system_metrics()
        app_metrics = collect_application_metrics()
        db_metrics = collect_database_metrics()
        security_metrics = collect_security_metrics()
        cloud_metrics = collect_cloud_metrics()

        # Calculate component health statuses
        components = {
            "application": check_application_health(app_metrics),
            "database": check_database_health(db_metrics),
            "storage": check_storage_health(system_metrics),
            "cache": check_cache_health(app_metrics),
            "security": check_security_health(security_metrics)
        }

        # Calculate overall status
        if any(c["status"] == "critical" for c in components.values()):
            overall_status = "critical"
        elif any(c["status"] == "warning" for c in components.values()):
            overall_status = "warning"
        else:
            overall_status = "healthy"

        # Generate alerts list
        alerts = []
        for component_name, component in components.items():
            if component["status"] != "healthy":
                alerts.append({
                    "component": component_name,
                    "severity": component["status"],
                    "message": component["message"]
                })

        # Assemble result
        result = {
            "timestamp": current_time,
            "status": overall_status,
            "components": components,
            "alerts": alerts
        }

        # Cache the result
        cache_ttl = current_app.config.get('HEALTH_CACHE_TIMEOUT', 30)  # Default 30 seconds
        cache.set('health_summary', result, timeout=cache_ttl)

        metrics_request_count.inc(1, labels={'endpoint': '/metrics/health', 'status': '200'})
        return jsonify(result), 200

    except Exception as e:
        metrics_request_count.inc(1, labels={'endpoint': '/metrics/health', 'status': '500'})
        logger.error(f"Error generating health summary: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to generate health summary"}), 500

@metrics_bp.route('/system', methods=['GET'])
@require_permission('metrics:system')
@limiter.limit(DEFAULT_LIMIT)
def get_system_metrics():
    """
    Get system-specific metrics.

    Returns:
        JSON: Detailed system metrics
    """
    try:
        # Collect detailed system metrics
        result = collect_system_metrics(detailed=True)

        metrics_request_count.inc(1, labels={'endpoint': '/metrics/system', 'status': '200'})
        return jsonify(result), 200

    except Exception as e:
        metrics_request_count.inc(1, labels={'endpoint': '/metrics/system', 'status': '500'})
        logger.error(f"Error retrieving system metrics: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to retrieve system metrics"}), 500

@metrics_bp.route('/application', methods=['GET'])
@require_permission('metrics:application')
@limiter.limit(DEFAULT_LIMIT)
def get_application_metrics():
    """
    Get application performance metrics.

    Returns:
        JSON: Detailed application metrics
    """
    try:
        # Collect detailed application metrics
        result = collect_application_metrics(detailed=True)

        metrics_request_count.inc(1, labels={'endpoint': '/metrics/application', 'status': '200'})
        return jsonify(result), 200

    except Exception as e:
        metrics_request_count.inc(1, labels={'endpoint': '/metrics/application', 'status': '500'})
        logger.error(f"Error retrieving application metrics: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to retrieve application metrics"}), 500

@metrics_bp.route('/database', methods=['GET'])
@require_permission('metrics:database')
@limiter.limit(DEFAULT_LIMIT)
def get_database_metrics():
    """
    Get database performance metrics.

    Returns:
        JSON: Detailed database metrics
    """
    try:
        # Collect detailed database metrics
        result = collect_database_metrics(detailed=True)

        metrics_request_count.inc(1, labels={'endpoint': '/metrics/database', 'status': '200'})
        return jsonify(result), 200

    except Exception as e:
        metrics_request_count.inc(1, labels={'endpoint': '/metrics/database', 'status': '500'})
        logger.error(f"Error retrieving database metrics: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to retrieve database metrics"}), 500

@metrics_bp.route('/security', methods=['GET'])
@require_permission('metrics:security')
@limiter.limit(DEFAULT_LIMIT)
def get_security_metrics():
    """
    Get security-related metrics.

    Returns:
        JSON: Detailed security metrics
    """
    try:
        # Collect detailed security metrics
        result = collect_security_metrics(detailed=True)

        metrics_request_count.inc(1, labels={'endpoint': '/metrics/security', 'status': '200'})
        return jsonify(result), 200

    except Exception as e:
        metrics_request_count.inc(1, labels={'endpoint': '/metrics/security', 'status': '500'})
        logger.error(f"Error retrieving security metrics: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to retrieve security metrics"}), 500

@metrics_bp.route('/cloud', methods=['GET'])
@require_permission('metrics:cloud')
@limiter.limit(DEFAULT_LIMIT)
def get_cloud_metrics():
    """
    Get cloud resource metrics.

    Returns:
        JSON: Detailed cloud resource metrics
    """
    try:
        # Collect detailed cloud metrics
        result = collect_cloud_metrics(detailed=True)

        metrics_request_count.inc(1, labels={'endpoint': '/metrics/cloud', 'status': '200'})
        return jsonify(result), 200

    except Exception as e:
        metrics_request_count.inc(1, labels={'endpoint': '/metrics/cloud', 'status': '500'})
        logger.error(f"Error retrieving cloud metrics: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to retrieve cloud metrics"}), 500

@metrics_bp.route('/trends', methods=['GET'])
@require_permission('metrics:trends')
@limiter.limit(DEFAULT_LIMIT)
def get_metric_trends():
    """
    Get metrics trend analysis.

    Query Parameters:
        metric (str): Name of the metric to analyze
        period (str): Time period for analysis (e.g., '24h', '7d', '30d')

    Returns:
        JSON: Trend analysis for the specified metric
    """
    try:
        # Extract parameters
        metric_name = request.args.get('metric')
        if not metric_name:
            return jsonify({"error": "Metric name is required"}), 400

        period = request.args.get('period', '7d')

        # Validate period
        valid_periods = ['24h', '7d', '30d', '90d']
        if period not in valid_periods:
            return jsonify({"error": f"Invalid period. Use one of: {', '.join(valid_periods)}"}), 400

        # Analyze metric trends
        trend_data = analyze_trends(metric_name, period)

        # Get forecast if requested
        forecast_data = None
        if request.args.get('forecast', 'false').lower() == 'true':
            forecast_data = forecast_metrics(metric_name, trend_data)

        # Assemble result
        result = {
            "metric": metric_name,
            "period": period,
            "trends": trend_data
        }

        if forecast_data:
            result["forecast"] = forecast_data

        metrics_request_count.inc(1, labels={'endpoint': '/metrics/trends', 'status': '200'})
        return jsonify(result), 200

    except ValueError as e:
        metrics_request_count.inc(1, labels={'endpoint': '/metrics/trends', 'status': '400'})
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        metrics_request_count.inc(1, labels={'endpoint': '/metrics/trends', 'status': '500'})
        logger.error(f"Error analyzing metric trends: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to analyze metric trends"}), 500

# --- Helper functions ---

def detect_metric_unit(metric_name: str) -> str:
    """Detect the appropriate unit for a metric based on its name."""
    if any(substr in metric_name for substr in ['_percent', 'usage', 'utilization']):
        return 'percent'
    elif any(substr in metric_name for substr in ['_time', 'latency', 'duration']):
        return 'seconds'
    elif any(substr in metric_name for substr in ['_count', 'requests', 'errors']):
        return 'count'
    elif any(substr in metric_name for substr in ['_rate', 'throughput']):
        return 'per_second'
    elif any(substr in metric_name for substr in ['_size', '_mb']):
        return 'megabytes'
    return 'unknown'

def check_application_health(metrics: Dict[str, Any]) -> Dict[str, str]:
    """Check application health based on metrics."""
    status = "healthy"
    message = "All services operational"

    # Example checks - adjust based on your application's metrics
    if metrics.get('error_rate', 0) > 0.05:  # >5% error rate
        status = "warning"
        message = "Elevated error rate detected"

    if metrics.get('error_rate', 0) > 0.15:  # >15% error rate
        status = "critical"
        message = "Critical error rate detected"

    return {"status": status, "message": message}

def check_database_health(metrics: Dict[str, Any]) -> Dict[str, str]:
    """Check database health based on metrics."""
    status = "healthy"
    message = "Connected, optimal performance"

    # Example checks - adjust based on your database metrics
    if metrics.get('query_time_avg', 0) > 5:  # >5s average query time
        status = "warning"
        message = "Slow query performance detected"

    if metrics.get('connections', 0) > 80:  # >80 connections (assuming 100 max)
        status = "warning"
        message = "High connection count"

    return {"status": status, "message": message}

def check_storage_health(metrics: Dict[str, Any]) -> Dict[str, str]:
    """Check storage health based on metrics."""
    status = "healthy"
    message = "Sufficient storage available"

    # Example checks
    disk_usage = metrics.get('disk_usage', 0)
    if disk_usage > 75:  # >75% disk usage
        status = "warning"
        message = f"{disk_usage}% capacity used, approaching threshold"

    if disk_usage > 90:  # >90% disk usage
        status = "critical"
        message = f"{disk_usage}% capacity used, critically low storage"

    return {"status": status, "message": message}

def check_cache_health(metrics: Dict[str, Any]) -> Dict[str, str]:
    """Check cache health based on metrics."""
    status = "healthy"
    hit_rate = metrics.get('cache_hit_rate', 0)
    message = f"Operational, hit rate {hit_rate}%"

    # Example checks
    if hit_rate < 70:  # <70% hit rate may indicate issues
        status = "warning"
        message = f"Low cache hit rate: {hit_rate}%"

    return {"status": status, "message": message}

def check_security_health(metrics: Dict[str, Any]) -> Dict[str, str]:
    """Check security health based on metrics."""
    status = "healthy"
    message = "No active incidents"

    # Example checks
    if metrics.get('security_score', 100) < 80:
        status = "warning"
        message = "Security posture needs improvement"

    incidents = metrics.get('incidents_active', 0)
    if incidents > 0:
        status = "warning" if incidents < 3 else "critical"
        message = f"{incidents} active security incidents"

    return {"status": status, "message": message}

__all__ = [
    'metrics_bp',
    'get_current_metrics',
    'get_historical_metrics',
    'export_metrics',
    'get_health_summary',
    'get_system_metrics',
    'get_application_metrics',
    'get_database_metrics',
    'get_security_metrics',
    'get_cloud_metrics',
    'get_metric_trends'
]
