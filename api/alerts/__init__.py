"""
API module for alert management in the Cloud Infrastructure Platform.

This module initializes the alerts Blueprint and registers security metrics, event
handlers, and rate limiting configurations. It provides RESTful endpoints for
creating, querying, acknowledging, and resolving alerts across the platform.

The alerts API enforces proper authentication, permission checks, and comprehensive
audit logging for all operations. It uses custom schemas for strict input validation
and implements rate limiting to prevent abuse.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from flask import Blueprint, current_app, g, request
from prometheus_client import Counter, Histogram

from core.security.cs_audit import log_security_event
from extensions import db, limiter, metrics
from models.alerts import Alert
from models.security import AuditLog

# Create blueprint for alerts API
alerts_api = Blueprint('alerts', __name__, url_prefix='/alerts')

# Initialize logger
logger = logging.getLogger(__name__)

# Define metrics
alert_creation_counter = Counter(
    'cloud_platform_alerts_created_total',
    'Number of alerts created',
    ['severity', 'environment', 'service']
)

alert_resolution_counter = Counter(
    'cloud_platform_alerts_resolved_total',
    'Number of alerts resolved',
    ['severity', 'environment', 'service']
)

alert_processing_time = Histogram(
    'cloud_platform_alert_processing_seconds',
    'Time spent processing alert operations',
    ['operation']
)

alert_active_gauge = metrics.gauge(
    'cloud_platform_alerts_active_total',
    'Number of active alerts',
    ['severity', 'environment']
)

# Define SLA compliance metrics
sla_compliance_gauge = metrics.gauge(
    'cloud_platform_alerts_sla_compliance',
    'SLA compliance ratio (0-1)',
    ['severity', 'environment', 'check_type']
)

sla_violation_counter = Counter(
    'cloud_platform_alerts_sla_violations_total',
    'Number of SLA violations',
    ['severity', 'environment', 'check_type']
)

sla_check_counter = Counter(
    'cloud_platform_alerts_sla_checks_total',
    'Number of SLA compliance checks performed',
    ['severity', 'environment', 'check_type']
)

# Register event handlers
@alerts_api.before_app_first_request
def initialize_alert_metrics():
    """Initialize alert metrics on application startup."""
    try:
        # Update active alerts gauge based on current database state
        environments = ['production', 'staging', 'development', 'dr-recovery']
        severities = ['critical', 'high', 'warning', 'info']

        for env in environments:
            for severity in severities:
                count = Alert.query.filter_by(
                    environment=env,
                    severity=severity,
                    status='active'
                ).count()
                alert_active_gauge.labels(severity=severity, environment=env).set(count)

        # Clean up old resolved alerts if configured
        retention_days = current_app.config.get('ALERT_RETENTION_DAYS', 90)
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

        deleted_count = Alert.query.filter(
            Alert.status == 'resolved',
            Alert.resolved_at < cutoff_date
        ).delete()

        if deleted_count:
            logger.info(f"Cleaned up {deleted_count} old resolved alerts during startup")
            db.session.commit()

        # Initialize SLA compliance metrics
        _update_sla_compliance_metrics()

    except Exception as e:
        logger.warning(f"Failed to initialize alert metrics: {e}")


@alerts_api.after_app_request
def update_alert_metrics(response):
    """Update alert metrics after each request."""
    if request.endpoint and 'alerts' in request.endpoint:
        # Only track alert-related endpoints
        path = request.path.split('/')
        operation = path[-1] if len(path) > 2 else 'unknown'

        # Track active alert counts periodically (not on every request)
        if operation in ['create', 'acknowledge', 'resolve', 'sla'] or operation.isdigit():
            try:
                for severity in ['critical', 'high', 'warning', 'info']:
                    for env in ['production', 'staging', 'development', 'dr-recovery']:
                        count = Alert.query.filter_by(
                            environment=env,
                            severity=severity,
                            status='active'
                        ).count()
                        alert_active_gauge.labels(severity=severity, environment=env).set(count)

                # Update SLA metrics when SLA endpoints are accessed
                if operation == 'sla':
                    _update_sla_compliance_metrics()
            except Exception as e:
                logger.debug(f"Error updating alert metrics: {e}")

    return response


def _update_sla_compliance_metrics():
    """Update SLA compliance metrics based on current alerts."""
    try:
        # Get counts for compliance check
        environments = ['production', 'staging', 'development', 'dr-recovery']
        severities = ['critical', 'high', 'warning', 'info']
        check_types = ['acknowledgement', 'resolution', 'both']

        for env in environments:
            for severity in severities:
                for check_type in check_types:
                    # Calculate percentage of alerts meeting SLA for each type
                    try:
                        # Get active alerts for this severity/environment
                        active_alerts = Alert.query.filter_by(
                            environment=env,
                            severity=severity,
                            status='active'
                        ).all()

                        acknowledged_alerts = Alert.query.filter_by(
                            environment=env,
                            severity=severity,
                            status='acknowledged'
                        ).all()

                        resolved_alerts = Alert.query.filter_by(
                            environment=env,
                            severity=severity,
                            status='resolved'
                        ).filter(Alert.resolved_at >= datetime.utcnow() - timedelta(days=7)).all()

                        # Calculate compliance for each alert group
                        from .helpers import check_sla_compliance

                        compliance_count = 0
                        total_count = 0

                        # Process active alerts
                        for alert in active_alerts:
                            compliance = check_sla_compliance(alert, check_type=check_type)
                            if compliance.get('sla_met', False):
                                compliance_count += 1
                            total_count += 1

                        # Process acknowledged alerts
                        for alert in acknowledged_alerts:
                            if check_type != 'resolution':  # They're already acknowledged
                                compliance_count += 1
                                total_count += 1

                        # Process resolved alerts
                        for alert in resolved_alerts:
                            if check_type == 'both' or check_type == 'resolution':
                                compliance = check_sla_compliance(alert, check_type=check_type)
                                if compliance.get('sla_met', False):
                                    compliance_count += 1
                                total_count += 1

                        # Update metrics
                        if total_count > 0:
                            compliance_ratio = compliance_count / total_count
                            sla_compliance_gauge.labels(
                                severity=severity,
                                environment=env,
                                check_type=check_type
                            ).set(compliance_ratio)

                    except Exception as inner_e:
                        logger.debug(f"Error calculating SLA metrics for {severity}/{env}/{check_type}: {inner_e}")

    except Exception as e:
        logger.warning(f"Failed to update SLA compliance metrics: {e}")


# Register error handlers
@alerts_api.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded errors with proper logging."""
    log_security_event(
        event_type=AuditLog.EVENT_API_LIMIT_EXCEEDED,
        description=f"Rate limit exceeded on alerts API: {request.endpoint}",
        severity="medium",
        user_id=g.get('user_id'),
        ip_address=request.remote_addr,
        details={
            'endpoint': request.endpoint,
            'method': request.method,
            'limit': str(e.description)
        }
    )

    return {
        'error': 'Rate limit exceeded',
        'message': f'Too many requests. {e.description}',
        'retry_after': e.retry_after
    }, 429


# Set custom rate limits for specific routes
limiter.limit("60/minute")(alerts_api)
limiter.limit("120/minute", key_func=lambda: request.endpoint)(alerts_api)
# Add specific rate limit for SLA endpoints - these can be resource-intensive
limiter.limit("30/minute")(alerts_api, "/<int:alert_id>/sla")
limiter.limit("10/minute")(alerts_api, "/sla/report")


# Import and register routes
# This is done after the blueprint setup to avoid circular imports
from .routes import *


# Export the blueprint
__all__ = ['alerts_api']
