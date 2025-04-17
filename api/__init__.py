"""
API package for the cloud infrastructure platform.

This package provides RESTful API endpoints for programmatic access to the application's
functionality. It defines the API structure, versioning, and documentation, while
implementing consistent patterns for authentication, error handling, and response formatting.

The API follows REST principles with JSON as the primary data interchange format.
Authentication is handled via JWT tokens, and all endpoints include appropriate
rate limiting and input validation.

Key API areas:
- Authentication: Login, registration, and token management
- Newsletter: Subscription management and delivery
- User Management: User CRUD operations
- System Monitoring: Metrics and health checks
- Cloud Resources: Cloud infrastructure management endpoints
- ICS Systems: Industrial Control Systems monitoring and control
- Security: Security incident tracking and response
- Audit: Comprehensive audit logging and compliance reporting

Each module in this package represents a distinct resource type with
the standard HTTP methods (GET, POST, PUT, DELETE) implemented as appropriate.
"""

import time
import logging
from typing import Any, Dict, List, Tuple, Optional, Union
from flask import Blueprint, Flask, jsonify, request, g, current_app
from werkzeug.exceptions import HTTPException
from functools import wraps

from extensions import db, metrics, cache
from models.audit_log import AuditLog
from models.user_activity import UserActivity
from core.utils import log_security_event

# Create main API blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Configure metrics for API endpoints
api_request_latency = metrics.histogram(
    'api_request_latency_seconds',
    'API request latency in seconds',
    labels={'endpoint': lambda: request.endpoint, 'method': lambda: request.method},
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
)

# API request counter
api_request_count = metrics.counter(
    'api_requests_total',
    'Total number of API requests',
    labels={'endpoint': lambda: request.endpoint, 'method': lambda: request.method,
            'status': lambda: g.get('response_status', 200)}
)

# Define API-wide error handlers
@api_bp.errorhandler(404)
def resource_not_found(_e):
    """Handle resources not found with a consistent JSON response"""
    return jsonify(error="Resource not found", status_code=404), 404

@api_bp.errorhandler(500)
def internal_server_error(_e):
    """Handle internal server errors with a consistent JSON response"""
    current_app.logger.error(f"Internal server error: {str(_e)}")
    metrics.counter(
        'api_errors_total',
        'Total number of API errors',
        labels={'type': '500', 'endpoint': request.endpoint}
    ).inc()
    return jsonify(error="Internal server error", status_code=500), 500

@api_bp.errorhandler(429)
def too_many_requests(_e):
    """Handle rate limiting with a consistent JSON response"""
    return jsonify(
        error="Too many requests",
        status_code=429,
        message="Rate limit exceeded. Please try again later."
    ), 429

@api_bp.errorhandler(403)
def forbidden(_e):
    """Handle forbidden access with a consistent JSON response"""
    # Log security event for potential unauthorized access attempts
    log_security_event(
        event_type=AuditLog.EVENT_ACCESS_DENIED,
        description="API access denied",
        severity=AuditLog.SEVERITY_WARNING
    )
    return jsonify(error="Forbidden", status_code=403), 403

@api_bp.errorhandler(401)
def unauthorized(_e):
    """Handle unauthorized access with a consistent JSON response"""
    return jsonify(
        error="Unauthorized",
        status_code=401,
        message="Authentication required"
    ), 401

@api_bp.before_request
def before_request():
    """Execute before each API request to set up request context"""
    g.request_start_time = time.time()
    g.user_id = getattr(g, 'user_id', None)

@api_bp.after_request
def after_request(response):
    """Execute after each API request for metrics and logging"""
    # Calculate request duration
    if hasattr(g, 'request_start_time'):
        duration = time.time() - g.request_start_time
        endpoint = request.endpoint or 'unknown'
        method = request.method
        
        # Record the response status code for metrics
        g.response_status = response.status_code
        
        # Record request latency
        api_request_latency.labels(endpoint=endpoint, method=method).observe(duration)
        
        # Increment request counter
        api_request_count.inc()
        
        # Log API activity for security monitoring
        if g.user_id:
            try:
                UserActivity.create(
                    user_id=g.user_id,
                    activity_type='api_access',
                    resource_type=endpoint.split('.')[-1] if endpoint else None,
                    path=request.path,
                    method=method,
                    status='success' if response.status_code < 400 else 'error',
                    ip_address=request.remote_addr
                )
            except (ValueError, TypeError, db.DatabaseError) as e:
                current_app.logger.error(f"Failed to log API activity: {e}")
    
    # Add security headers to all API responses
    response.headers['Content-Security-Policy'] = "default-src 'none'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    
    return response

# Import and register API modules
from api.auth import auth_routes
from api.cloud import cloud_routes
from api.metrics import metrics_routes
from api.alerts import alerts_routes
from api.ics import ics_routes
from api.security import security_routes
from api.audit import audit_routes
from api.newsletter import newsletter_routes

# Register all route blueprints
api_bp.register_blueprint(auth_routes)
api_bp.register_blueprint(cloud_routes)
api_bp.register_blueprint(metrics_routes)
api_bp.register_blueprint(alerts_routes)
api_bp.register_blueprint(ics_routes)
api_bp.register_blueprint(security_routes)
api_bp.register_blueprint(audit_routes)
api_bp.register_blueprint(newsletter_routes)
