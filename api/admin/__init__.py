"""
Administrative API module for the Cloud Infrastructure Platform.

This module initializes the admin Blueprint and registers security metrics, event
handlers, and rate limiting configurations. It provides RESTful endpoints for managing
users, system configuration, audit logs, and system health for administrators
with appropriate permissions.

The admin API enforces strict access controls including role-based permissions,
multi-factor authentication requirements, comprehensive audit logging, and detailed
rate limiting to ensure secure administration of the platform.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple
from flask import Blueprint, current_app, g, request, jsonify, Flask

from extensions import metrics, limiter, cache
from core.security import log_security_event
from core.security.cs_authentication import is_request_secure, get_client_ip

# Create blueprint for admin API
admin_api = Blueprint('admin', __name__, url_prefix='/admin')

# Initialize logger
logger = logging.getLogger(__name__)

# Module version for tracking in security audit logs
__version__ = '0.1.1'

# Track initialization state
_initialized = False

# Define rate limits - these can be overridden in config
DEFAULT_LIMIT = "30 per minute"
USERS_LIMIT = "60 per minute"
CONFIG_LIMIT = "10 per minute"
USER_CREATE_LIMIT = "5 per minute"
SYSTEM_LIMIT = "20 per minute"
AUDIT_LIMIT = "60 per minute"
EXPORT_LIMIT = "10 per minute"

# Define metrics
admin_request_counter = metrics.counter(
    'admin_api_requests_total',
    'Total number of administrative API requests',
    labels=['endpoint', 'method', 'status']
)

admin_action_counter = metrics.counter(
    'admin_api_actions_total',
    'Total number of administrative actions taken',
    labels=['action', 'status']
)

admin_operation_duration = metrics.histogram(
    'admin_api_action_duration_seconds',
    'Duration of administrative operations in seconds',
    labels=['action'],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
)

admin_unauthorized_counter = metrics.counter(
    'admin_api_unauthorized_access_total',
    'Total number of unauthorized access attempts to admin API',
    labels=['endpoint', 'required_role']
)

admin_export_size = metrics.histogram(
    'admin_api_export_size_bytes',
    'Size of exported data in bytes',
    labels=['data_type', 'format'],
    buckets=[1024, 10240, 102400, 1048576, 5242880, 10485760]
)

admin_config_changes = metrics.counter(
    'admin_api_config_changes_total',
    'Total number of configuration changes',
    labels=['component', 'change_type']
)

admin_security_incident = metrics.counter(
    'admin_api_security_incidents_total',
    'Total number of security incidents detected in admin API',
    labels=['type', 'severity']
)

admin_session_management = metrics.counter(
    'admin_api_session_events_total',
    'Administrative session management events',
    labels=['event_type']
)

def init_app(app: Flask) -> None:
    """
    Initialize the admin API with the Flask application.

    This function registers rate limits, security event handlers,
    and error responses for the administrative API.

    Args:
        app: Flask application instance
    """
    global _initialized

    if _initialized:
        logger.debug("Admin API already initialized, skipping")
        return

    logger.info("Initializing admin API components")

    # Import middleware and error handlers first to ensure proper security setup
    from .middleware import init_admin_middleware
    from .errors import register_error_handlers as register_detailed_error_handlers

    # Import routes after middleware creation to avoid circular imports
    from .decorators import admin_required, super_admin_required, auditor_required, require_mfa
    from .routes import log_admin_action  # Ensure routes are registered

    # Apply rate limits from configuration or use defaults
    limiter.limit(app.config.get('RATELIMIT_ADMIN_DEFAULT', DEFAULT_LIMIT))(admin_api)
    limiter.limit(app.config.get('RATELIMIT_ADMIN_USER_CREATE', USER_CREATE_LIMIT),
                 per_method=True, methods=["POST"])(admin_api)
    limiter.limit(app.config.get('RATELIMIT_ADMIN_CONFIG', CONFIG_LIMIT),
                 per_method=True, methods=["PUT", "POST"])(admin_api)
    limiter.limit(app.config.get('RATELIMIT_ADMIN_SYSTEM', SYSTEM_LIMIT))(admin_api)
    limiter.limit(app.config.get('RATELIMIT_ADMIN_AUDIT', AUDIT_LIMIT))(admin_api)
    limiter.limit(app.config.get('RATELIMIT_ADMIN_EXPORT', EXPORT_LIMIT),
                 per_method=True, methods=["GET", "POST"])(admin_api)

    # Register the blueprint with the application if not already registered
    if 'admin' not in app.blueprints:
        app.register_blueprint(admin_api)

    # Initialize admin middleware with secure defaults
    init_admin_middleware(app)

    # Set up cache configuration for admin endpoints if available
    if hasattr(cache, 'init_app'):
        try:
            # Only cache GET requests for short periods
            cache_timeout = app.config.get('ADMIN_CACHE_TIMEOUT', 30)  # 30 seconds default
            cache.init_app(app, config={
                'CACHE_TYPE': app.config.get('ADMIN_CACHE_TYPE', 'simple'),
                'CACHE_DEFAULT_TIMEOUT': cache_timeout,
                'CACHE_KEY_PREFIX': 'admin_api_',
                'CACHE_THRESHOLD': 1000  # Maximum number of items to store
            })
        except Exception as e:
            logger.warning(f"Failed to initialize admin cache: {e}")

    # Register advanced error handlers from the errors module
    register_detailed_error_handlers(admin_api)

    # Also register basic error handlers for backward compatibility
    register_error_handlers(app)

    # Initialize file integrity monitoring for admin module if available
    if app.config.get('ADMIN_FILE_INTEGRITY_CHECK', True):
        try:
            from core.security.cs_file_integrity import register_directory_monitoring
            admin_dir = __file__.rsplit('/', 1)[0]
            register_directory_monitoring(
                path=admin_dir,
                name="admin_api",
                criticality="high",
                file_patterns=['*.py'],
                exclude_patterns=['__pycache__/*', '*.pyc'],
                scan_interval=app.config.get('ADMIN_INTEGRITY_SCAN_INTERVAL', 3600)
            )
            logger.debug("File integrity monitoring registered for admin API")
        except ImportError:
            logger.warning("File integrity monitoring not available for admin API")

    # Log initialization event
    try:
        log_security_event(
            event_type="admin_api_initialized",
            description="Administrative API components initialized",
            severity="info",
            details={
                "version": __version__,
                "endpoints": [
                    "users", "roles", "config",
                    "audit", "system", "maintenance",
                    "export", "import", "baseline"
                ],
                "security_features": [
                    "ip_restriction",
                    "mfa_requirement",
                    "strict_content_validation",
                    "audit_logging",
                    "permission_verification",
                    "secure_transport"
                ]
            }
        )
    except Exception as e:
        logger.warning(f"Failed to log admin API initialization: {e}")

    _initialized = True
    logger.debug("Admin API package initialized successfully")


def register_error_handlers(app: Flask) -> None:
    """
    Register basic error handlers for the admin API.

    Note: More comprehensive error handling is provided by errors.py

    Args:
        app: Flask application instance
    """
    from werkzeug.exceptions import Forbidden, Unauthorized, NotFound, BadRequest

    @admin_api.errorhandler(Forbidden)
    def handle_forbidden(error):
        """Handle 403 Forbidden errors with structured response."""
        admin_unauthorized_counter.inc(labels={
            'endpoint': request.endpoint,
            'required_role': getattr(error, 'description', 'unknown')
        })

        # Log security event with source IP information
        client_ip = get_client_ip()
        log_security_event(
            event_type="admin_access_denied",
            description=f"Access denied to admin endpoint: {request.endpoint}",
            severity="medium",
            user_id=getattr(g, 'user_id', None),
            ip_address=client_ip,
            details={
                "endpoint": request.endpoint,
                "method": request.method,
                "path": request.path,
                "user_agent": request.headers.get('User-Agent', 'Unknown'),
                "referer": request.headers.get('Referer', 'Unknown')
            }
        )

        return jsonify({
            "error": "Forbidden",
            "message": "You don't have permission to access this resource",
            "status_code": 403,
            "request_id": getattr(g, 'request_id', 'unknown')
        }), 403, {'Content-Type': 'application/json; charset=utf-8'}

    @admin_api.errorhandler(Unauthorized)
    def handle_unauthorized(error):
        """Handle 401 Unauthorized errors with structured response."""
        client_ip = get_client_ip()
        log_security_event(
            event_type="admin_authentication_failure",
            description=f"Authentication failure for admin endpoint: {request.endpoint}",
            severity="medium",
            ip_address=client_ip,
            details={
                "endpoint": request.endpoint,
                "method": request.method,
                "path": request.path,
                "user_agent": request.headers.get('User-Agent', 'Unknown')
            }
        )

        return jsonify({
            "error": "Unauthorized",
            "message": "Authentication required to access this resource",
            "status_code": 401,
            "request_id": getattr(g, 'request_id', 'unknown')
        }), 401, {'Content-Type': 'application/json; charset=utf-8'}

    @admin_api.errorhandler(NotFound)
    def handle_not_found(error):
        """Handle 404 Not Found errors with structured response."""
        return jsonify({
            "error": "Not Found",
            "message": "The requested resource could not be found",
            "status_code": 404,
            "request_id": getattr(g, 'request_id', 'unknown')
        }), 404, {'Content-Type': 'application/json; charset=utf-8'}

    @admin_api.errorhandler(BadRequest)
    def handle_bad_request(error):
        """Handle 400 Bad Request errors with structured response."""
        return jsonify({
            "error": "Bad Request",
            "message": str(error),
            "status_code": 400,
            "request_id": getattr(g, 'request_id', 'unknown')
        }), 400, {'Content-Type': 'application/json; charset=utf-8'}


# Import public objects from submodules to make them available at the package level
from .decorators import admin_required, super_admin_required, auditor_required, require_mfa, log_admin_action
from .user_management import create_user, update_user, delete_user, get_user_by_id, update_user_role, reset_user_password, list_users
from .system_config import (
    get_config_value,
    set_config_value,
    get_all_configs,
    validate_config_key,
    export_configuration,
    import_configuration
)
from .audit import (
    get_audit_logs,
    get_security_events,
    export_audit_data,
    generate_compliance_report
)

# Export publicly accessible components
__all__ = [
    'admin_api',
    'init_app',

    # Decorators
    'admin_required',
    'super_admin_required',
    'auditor_required',
    'require_mfa',
    'log_admin_action',

    # User management
    'create_user',
    'update_user',
    'delete_user',
    'get_user_by_id',
    'update_user_role',
    'reset_user_password',
    'list_users',

    # System configuration
    'get_config_value',
    'set_config_value',
    'get_all_configs',
    'validate_config_key',
    'export_configuration',
    'import_configuration',

    # Audit and reporting
    'get_audit_logs',
    'get_security_events',
    'export_audit_data',
    'generate_compliance_report',

    # Version
    '__version__'
]
