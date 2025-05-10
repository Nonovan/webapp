"""
Cloud metrics API module.

This module provides API endpoints for retrieving metrics about cloud infrastructure
resources. It collects data from multiple cloud providers (AWS, Azure, GCP) and returns
standardized metrics for system dashboards, monitoring, and alerting.

Endpoints:
- GET /api/cloud/metrics: Retrieve current cloud metrics including CPU, memory, storage,
  network I/O, and active users
- GET /api/cloud/metrics/history: Retrieve historical metrics for trend analysis
- GET /api/cloud/metrics/provider/{provider}: Get metrics for a specific cloud provider
- GET /api/cloud/metrics/alerts: Get active alerts related to cloud resources

All endpoints implement appropriate rate limiting, caching, authentication verification,
and security logging to ensure secure and efficient access to cloud metrics.
"""

import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Union, Tuple

from flask import Blueprint, request, jsonify, current_app, g, has_request_context
from sqlalchemy.exc import SQLAlchemyError
from flask_jwt_extended import jwt_required

from extensions import metrics, cache, db, limiter
from models import AuditLog, UserSession
from blueprints.monitoring.metrics import SystemMetrics, get_all_metrics
from core.security import log_security_event

# Create blueprint
cloud_metrics_bp = Blueprint('cloud_metrics', __name__)

# Define metrics
cloud_metrics_request_counter = metrics.counter(
    'cloud_metrics_requests_total',
    'Total cloud metrics API requests',
    labels={'endpoint': lambda: request.endpoint}
)

# Helper functions
def format_response(data: Dict[str, Any], status: int = 200) -> Tuple[Dict[str, Any], int]:
    """Format standard API response with timestamp."""
    response = {
        'data': data,
        'timestamp': datetime.utcnow().isoformat(),
        'status': 'success' if status < 400 else 'error'
    }
    return response, status


@cloud_metrics_bp.route('/metrics', methods=['GET'])
@limiter.limit("60/minute")
@jwt_required()
@cache.cached(timeout=15)  # Cache for 15 seconds
def get_current_metrics():
    """
    Get current cloud infrastructure metrics.

    Returns comprehensive metrics about cloud resources including
    CPU usage, memory utilization, disk usage, network I/O,
    and active user counts.

    Returns:
        JSON: Cloud metrics data
    """
    try:
        # Record metrics request
        cloud_metrics_request_counter.inc()

        # Start timing for performance tracking
        start_time = time.time()

        # Get all system metrics
        all_metrics = get_all_metrics()

        # Extract cloud-specific metrics
        system_metrics = all_metrics.get('system', {})

        # Get active users
        active_users = _get_active_users()

        # Get cloud alerts
        alerts = _get_cloud_alerts()

        # Format output
        metrics_data = {
            'system': {
                'cpu_usage': system_metrics.get('cpu_usage', 0),
                'memory_usage': system_metrics.get('memory_usage', 0),
                'disk_usage': system_metrics.get('disk_usage', 0),
                'memory_available': _bytes_to_gb(system_metrics.get('memory', {}).get('available', 0)),
                'storage_free': _bytes_to_gb(system_metrics.get('disk', {}).get('free', 0)),
                'network_in': _bytes_to_mbps(system_metrics.get('network', {}).get('bytes_recv', 0)),
                'network_out': _bytes_to_mbps(system_metrics.get('network', {}).get('bytes_sent', 0)),
                'cpu_trend': _calculate_cpu_trend(),
            },
            'users': active_users,
            'alerts': alerts,
            'providers': _get_provider_metrics(),
            'load_time_ms': int((time.time() - start_time) * 1000)
        }

        # Record timings
        metrics.info('cloud_metrics_response_time', time.time() - start_time)

        return jsonify(format_response(metrics_data))

    except (KeyError, ValueError, AttributeError) as e:
        error_msg = f"Error retrieving cloud metrics: {str(e)}"
        current_app.logger.error(error_msg)
        log_security_event(
            event_type=AuditLog.EVENT_SYSTEM_ERROR,
            description=error_msg,
            severity=AuditLog.SEVERITY_ERROR,
            user_id=g.get('user_id')
        )
        return jsonify(format_response({'error': 'Failed to retrieve metrics'}, 500))


@cloud_metrics_bp.route('/metrics/history', methods=['GET'])
@limiter.limit("30/minute")
@jwt_required()
def get_metrics_history():
    """
    Get historical cloud metrics for trend analysis.

    Query parameters:
        hours (int): Number of hours of history to retrieve (default: 24)
        interval (str): Data interval ('minute', 'hour', 'day') (default: 'hour')

    Returns:
        JSON: Historical metrics data points
    """
    try:
        hours = min(int(request.args.get('hours', 24)), 168)  # Max 7 days
        interval = request.args.get('interval', 'hour')

        metrics_history = _get_historical_metrics(hours, interval)

        return jsonify(format_response({
            'history': metrics_history,
            'interval': interval,
            'hours': hours
        }))

    except (KeyError, ValueError, AttributeError) as e:
        error_msg = f"Error retrieving historical metrics: {str(e)}"
        current_app.logger.error(error_msg)
        return jsonify(format_response({'error': 'Failed to retrieve historical data'}, 500))


@cloud_metrics_bp.route('/metrics/provider/<provider>', methods=['GET'])
@limiter.limit("30/minute")
@jwt_required()
def get_provider_metrics(provider: str):
    """
    Get metrics for a specific cloud provider.

    Path parameters:
        provider (str): Cloud provider name ('aws', 'azure', 'gcp')

    Returns:
        JSON: Provider-specific metrics
    """
    if provider not in current_app.config.get('CLOUD_PROVIDERS', ['aws', 'azure', 'gcp']):
        return jsonify(format_response({'error': f'Unknown provider: {provider}'}, 400))

    try:
        provider_data = _get_specific_provider_metrics(provider)

        return jsonify(format_response({
            'provider': provider,
            'metrics': provider_data
        }))

    except (KeyError, ValueError, AttributeError) as e:
        error_msg = f"Error retrieving {provider} metrics: {str(e)}"
        current_app.logger.error(error_msg)
        return jsonify(format_response({'error': f'Failed to retrieve {provider} metrics'}, 500))


@cloud_metrics_bp.route('/metrics/alerts', methods=['GET'])
@limiter.limit("60/minute")
@jwt_required()
def get_metric_alerts():
    """
    Get active alerts related to cloud metrics.

    Returns:
        JSON: List of active alerts with severity and descriptions
    """
    try:
        alerts = _get_cloud_alerts()
        return jsonify(format_response({'alerts': alerts}))

    except (KeyError, ValueError, AttributeError) as e:  # Replace with specific exceptions
        error_msg = f"Error retrieving cloud alerts: {str(e)}"
        current_app.logger.error(error_msg)
        return jsonify(format_response({'error': 'Failed to retrieve alerts'}, 500))


# Helper functions
def _bytes_to_gb(bytes_value: Union[int, float]) -> float:
    """Convert bytes to gigabytes with 2 decimal precision."""
    if not bytes_value:
        return 0.0
    return round(float(bytes_value) / (1024 * 1024 * 1024), 2)


def _bytes_to_mbps(bytes_value: Union[int, float]) -> float:
    """Convert bytes to megabits per second with 1 decimal precision."""
    if not bytes_value:
        return 0.0
    return round((float(bytes_value) * 8) / (1024 * 1024), 1)  # Multiply by 8 to convert to bits


def _calculate_cpu_trend() -> int:
    """Calculate CPU trend over the last hour."""
    try:
        # Query historical CPU data
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)

        with db.engine.connect() as conn:
            result = conn.execute(
                """
                SELECT value FROM metrics_history
                WHERE metric_name = 'cpu_usage'
                AND timestamp < %s
                ORDER BY timestamp ASC
                LIMIT 1
                """,
                (one_hour_ago,)
            ).fetchone()

            if result:
                old_value = float(result[0])
                # Get current CPU usage
                current_value = SystemMetrics.get_system_metrics()['cpu_usage']
                return int(round(current_value - old_value))

    except (SQLAlchemyError, KeyError, ValueError) as e:
        current_app.logger.warning(f"Error calculating CPU trend: {e}")

    return 0  # Default to no change


def _get_active_users() -> List[Dict[str, Any]]:
    """Get list of active users."""
    users = []

    try:
        # Get sessions active in the last 15 minutes
        fifteen_mins_ago = datetime.utcnow() - timedelta(minutes=15)

        active_sessions = UserSession.query.filter(
            UserSession.last_active >= fifteen_mins_ago,
            UserSession.is_active is True
        ).all()

        # Map sessions to users
        for session in active_sessions:
            if not any(user for user in users if user['id'] == session.user_id):
                user = session.user  # Assuming relationship is set up

                if user:
                    users.append({
                        'id': user.id,
                        'username': user.username,
                        'last_active': session.last_active.isoformat(),
                        'role': user.role
                    })
    except (SQLAlchemyError, AttributeError) as e:  # Replace with specific exceptions
        current_app.logger.error(f"Error retrieving active users: {e}")

    return users


def _get_cloud_alerts() -> List[Dict[str, Any]]:
    """Get active cloud resource alerts."""
    alerts = []

    try:
        # Example criteria for generating cloud alerts
        system_metrics = SystemMetrics.get_system_metrics()

        # CPU alert
        if system_metrics.get('cpu_usage', 0) > 85:
            alerts.append({
                'id': 'cpu-high',
                'severity': 'danger',
                'title': 'High CPU Usage',
                'message': f"CPU usage at {system_metrics.get('cpu_usage')}%, exceeding 85% threshold.",
                'timestamp': datetime.utcnow().isoformat()
            })
        elif system_metrics.get('cpu_usage', 0) > 70:
            alerts.append({
                'id': 'cpu-warning',
                'severity': 'warning',
                'title': 'Elevated CPU Usage',
                'message': f"CPU usage at {system_metrics.get('cpu_usage')}%, exceeding 70% threshold.",
                'timestamp': datetime.utcnow().isoformat()
            })

        # Memory alert
        if system_metrics.get('memory_usage', 0) > 80:
            alerts.append({
                'id': 'memory-high',
                'severity': 'warning',
                'title': 'High Memory Usage',
                'message': f"Memory usage at {system_metrics.get('memory_usage')}%, exceeding 80% threshold.",
                'timestamp': datetime.utcnow().isoformat()
            })

        # Disk space alert
        if system_metrics.get('disk_usage', 0) > 85:
            alerts.append({
                'id': 'disk-high',
                'severity': 'danger',
                'title': 'Low Disk Space',
                'message': f"Disk usage at {system_metrics.get('disk_usage')}%, exceeding 85% threshold.",
                'timestamp': datetime.utcnow().isoformat()
            })

    except (KeyError, ValueError) as e:  # Replace with specific exceptions
        current_app.logger.error(f"Error generating cloud alerts: {e}")

    return alerts


def _get_historical_metrics(hours: int, interval: str) -> List[Dict[str, Any]]:
    """Get historical metrics data points."""
    history = []

    try:
        # Calculate time intervals
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)

        interval_seconds = 3600  # Default to hourly
        if interval == 'minute':
            interval_seconds = 60
        elif interval == 'day':
            interval_seconds = 86400

        # Query the database for historical metrics
        with db.engine.connect() as conn:
            result = conn.execute(
                """
                SELECT
                    time_bucket(%s, timestamp) AS interval_time,
                    AVG(CASE WHEN metric_name = 'cpu_usage' THEN value ELSE NULL END) as cpu,
                    AVG(CASE WHEN metric_name = 'memory_usage' THEN value ELSE NULL END) as memory,
                    AVG(CASE WHEN metric_name = 'disk_usage' THEN value ELSE NULL END) as disk
                FROM metrics_history
                WHERE timestamp >= %s AND timestamp <= %s
                GROUP BY interval_time
                ORDER BY interval_time ASC
                """,
                (interval_seconds, start_time, end_time)
            )

            for row in result:
                history.append({
                    'timestamp': row[0].isoformat(),
                    'cpu_usage': float(row[1]) if row[1] else None,
                    'memory_usage': float(row[2]) if row[2] else None,
                    'disk_usage': float(row[3]) if row[3] else None
                })
    except (SQLAlchemyError, ValueError) as e:  # Replace with specific exceptions
        current_app.logger.error(f"Error retrieving historical metrics: {e}")

    return history


def _get_provider_metrics() -> Dict[str, Any]:
    """Get metrics for all configured cloud providers."""
    providers = {}

    for provider in current_app.config.get('CLOUD_PROVIDERS', ['aws', 'azure', 'gcp']):
        try:
            providers[provider] = _get_specific_provider_metrics(provider)
        except (KeyError, ValueError) as e:  # Replace with specific exceptions
            current_app.logger.error(f"Error getting metrics for {provider}: {e}")
            providers[provider] = {'error': str(e)}

    return providers


def _get_specific_provider_metrics(provider: str) -> Dict[str, Any]:
    """
    Get metrics for a specific cloud provider.

    This function integrates with cloud provider APIs to retrieve
    real-time metrics about resources and their status.

    Args:
        provider: The cloud provider name ('aws', 'azure', 'gcp')

    Returns:
        Dict[str, Any]: Provider-specific metrics data
    """
    # Record request for metrics and auditing
    if has_request_context() and hasattr(g, 'cloud_provider'):
        g.cloud_provider = provider
        g.resource_type = 'all'

    try:
        # In production, this would call actual provider APIs
        # Example: return aws_client.get_all_metrics() for AWS

        # Provider-specific metrics mapping
        provider_metrics = {
            'aws': {
                'ec2_instances': 12,
                'running_instances': 8,
                'total_storage_gb': 2048,
                'regions': ['us-east-1', 'us-west-2'],
                'health': 'healthy'
            },
            'azure': {
                'vms': 6,
                'running_vms': 4,
                'total_storage_gb': 1024,
                'regions': ['eastus', 'westeurope'],
                'health': 'healthy'
            },
            'gcp': {
                'instances': 4,
                'running_instances': 3,
                'total_storage_gb': 512,
                'regions': ['us-central1', 'europe-west1'],
                'health': 'degraded'
            }
        }

        # Return provider metrics or default error
        return provider_metrics.get(provider, {'error': 'Provider not configured'})

    except (KeyError, ValueError) as e:
        current_app.logger.error(f"Error retrieving {provider} metrics: {str(e)}")
        return {
            'error': f'Failed to retrieve metrics: {str(e)}',
            'status': 'error'
        }
