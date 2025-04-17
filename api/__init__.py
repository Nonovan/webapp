"""
API package for the myproject application.

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
from typing import Any
from flask import Blueprint, Flask, jsonify, request

from extensions import metrics

# Create main API blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Configure metrics for API endpoints
api_request_latency = metrics.histogram(
    'api_request_latency_seconds',
    'API request latency in seconds',
    labels={'endpoint': lambda: request.endpoint, 'method': lambda: request.method},
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
)

# Define API-wide error handlers
@api_bp.errorhandler(404)
def resource_not_found(_e):
    """Handle resources not found with a consistent JSON response"""
    return jsonify(error="Resource not found", status_code=404), 404

@api_bp.errorhandler(500)
def internal_server_error(_):
    """Handle internal server errors with a consistent JSON response"""
    return jsonify(error="Internal server error", status_code=500), 500

@api_bp.errorhandler(429)
def rate_limit_exceeded(_):
    """Handle rate limit exceeded errors with a consistent JSON response"""
    return jsonify(error="Rate limit exceeded. Please try again later.", status_code=429), 429

@api_bp.route('/status')
def api_status():
    """API health check endpoint"""
    return jsonify({
        'status': 'operational',
        'version': '1.0',
        'timestamp': time.time()
    })

def register_api(app: Flask) -> None:
    """Register the API blueprint with the Flask application"""
    # Import blueprints here to avoid circular imports
    from .auth.routes import auth_api
    from .newsletter.routes import newsletter_api
    from .cloud.routes import cloud_api
    from .ics.routes import ics_api
    from .security.routes import security_api
    from .audit.routes import audit_api

    # Register blueprints with the main API blueprint
    api_bp.register_blueprint(auth_api)
    api_bp.register_blueprint(newsletter_api)
    api_bp.register_blueprint(cloud_api)
    api_bp.register_blueprint(ics_api)
    api_bp.register_blueprint(security_api)
    api_bp.register_blueprint(audit_api)

    # Register request timing middleware
    @api_bp.before_request
    def start_timer() -> None:
        """Start timer for request timing"""
        request.start_time = time.time()

    # Register the main API blueprint with the app
    app.register_blueprint(api_bp)

@api_bp.after_request
def record_request_metrics(response: Any) -> Any:
    """Record request timing metrics"""
    request_latency = time.time() - getattr(request, 'start_time', time.time())
    api_request_latency.observe(request_latency)

    # Add security headers to all API responses
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cache-Control'] = 'no-store'

    return response

# Export public interface
__all__ = ['api_bp', 'register_api']
