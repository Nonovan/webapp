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

Each module in this package represents a distinct resource type with
the standard HTTP methods (GET, POST, PUT, DELETE) implemented as appropriate.
"""

from flask import Blueprint, Flask, jsonify

# Create main API blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Define API-wide error handlers
@api_bp.errorhandler(404)
def resource_not_found(_e):
    """Handle resources not found with a consistent JSON response"""
    return jsonify(error="Resource not found"), 404

@api_bp.errorhandler(500)
def internal_server_error(_):
    """Handle internal server errors with a consistent JSON response"""
    return jsonify(error="Internal server error"), 500

@api_bp.route('/status')
def api_status():
    """API health check endpoint"""
    return jsonify({
        'status': 'operational',
        'version': '1.0'
    })

def register_api(app: Flask):
    """Register the API blueprint with the Flask application"""
    # Import blueprints here to avoid circular imports
    from .auth.routes import auth_api
    from .newsletter.routes import newsletter_api
    
    # Register blueprints with the main API blueprint
    api_bp.register_blueprint(auth_api)
    api_bp.register_blueprint(newsletter_api)
    
    # Register the main API blueprint with the app
    app.register_blueprint(api_bp)

__all__ = ['api_bp', 'register_api']