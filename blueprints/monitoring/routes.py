"""
Monitoring routes module for myproject.

This module defines HTTP routes for system monitoring, metrics collection,
and health checks. It provides endpoints for both internal monitoring systems
and administrative interfaces to check system health and performance.

The routes include:
- Health check endpoint for infrastructure monitoring
- Metrics collection endpoints for dashboard display
- Database status information

All routes implement appropriate access controls, rate limiting, and caching
to ensure security and performance even under heavy load.
"""

from datetime import datetime
from flask import Blueprint, jsonify, current_app
from auth.utils import login_required, require_role
from extensions import db, limiter, cache
from .metrics import SystemMetrics, DatabaseMetrics, ApplicationMetrics

monitoring_bp = Blueprint('monitoring', __name__, url_prefix='/monitoring')

@monitoring_bp.route('/health')
@limiter.limit("60/minute")
@cache.cached(timeout=30)
def health() -> dict | tuple[dict, int]:
    """
    Health check endpoint for uptime monitoring.

    This endpoint provides a simple health check for monitoring systems to verify
    that the application is running and can connect to its database. It returns
    basic information including status, version, and uptime.

    Rate limited to 60 requests per minute and cached for 30 seconds to minimize
    resource impact under heavy monitoring.

    Returns:
        Union[dict, tuple[dict, int]]: Health status information on success,
                                       or error details with 500 status on failure

    Example response:
        {
            "status": "healthy",
            "version": "1.0.0",
            "database": true,
            "uptime": "3 days, 2:15:30",
            "timestamp": "2023-01-01T12:00:00"
        }
    """
    try:
        return {
            'status': 'healthy',
            'version': current_app.config.get('VERSION', '1.0.0'),
            'database': db.engine.execute('SELECT 1').scalar() == 1,
            'uptime': str(datetime.utcnow() - current_app.uptime),
            'timestamp': datetime.utcnow().isoformat()
        }
    except (db.exc.SQLAlchemyError, AttributeError) as e:
        current_app.logger.error(f'Health check failed: {e}')
        return {'status': 'unhealthy', 'error': str(e)}, 500

@monitoring_bp.route('/metrics')
@login_required
@require_role('admin')
@limiter.limit("30/minute")
@cache.cached(timeout=60)
def metrics() -> dict | tuple[dict, int]:
    """
    System metrics collection endpoint.

    This endpoint provides comprehensive system metrics for administrative dashboards,
    including system resource usage, database performance, and application statistics.
    It requires authentication and admin role for access.

    Rate limited to 30 requests per minute and cached for 60 seconds to balance
    freshness with server load.

    Returns:
        Union[dict, tuple[dict, int]]: Metrics data on success,
                                      or error details with 500 status on failure

    Example response:
        {
            "system": {
                "cpu_usage": 45.2,
                "memory_usage": 62.8,
                "disk_usage": 78.5,
                ...
            },
            "database": {
                "active_connections": 5,
                ...
            },
            "application": {
                "total_users": 1240,
                ...
            },
            "timestamp": "2023-01-01T12:00:00"
        }
    """
    try:
        return jsonify({
            'system': SystemMetrics.get_system_metrics(),
            'database': DatabaseMetrics.get_db_metrics(),
            'application': ApplicationMetrics.get_app_metrics(),
            'timestamp': datetime.utcnow().isoformat()
        })
    except (SystemMetrics.MetricsError, DatabaseMetrics.MetricsError, ApplicationMetrics.MetricsError) as e:
        current_app.logger.error(f'Metrics collection failed: {e}')
        return {'error': str(e)}, 500

@monitoring_bp.route('/db/status')
@login_required
@require_role('admin')
@limiter.limit("30/minute")
@cache.cached(timeout=60)
def db_status() -> dict | tuple[dict, int]:
    """
    Database status and performance endpoint.

    This endpoint provides detailed information about database performance,
    connection pool status, and query statistics. It requires authentication
    and admin role for access.

    Rate limited to 30 requests per minute and cached for 60 seconds to
    minimize database impact.

    Returns:
        Union[dict, tuple[dict, int]]: Database metrics on success,
                                       or error details with 500 status on failure

    Example response:
        {
            "active_connections": 5,
            "pool_size": 10,
            "database_size": "1.2 GB",
            "timestamp": "2023-01-01T12:00:00"
        }
    """
    try:
        db_metrics = DatabaseMetrics.get_db_metrics()
        db_metrics['timestamp'] = datetime.utcnow().isoformat()
        return db_metrics
    except db.exc.SQLAlchemyError as e:
        current_app.logger.error(f'Database status check failed: {e}')
        return {'error': str(e)}, 500
