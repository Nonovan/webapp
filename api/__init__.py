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
- Webhooks: Event notification integration with external systems
- Audit: Comprehensive audit logging and compliance reporting
- Admin: Administrative operations and system configuration

Each module in this package represents a distinct resource type with
the standard HTTP methods (GET, POST, PUT, DELETE) implemented as appropriate.
"""

import time
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple, Optional, Union
from flask import Blueprint, Flask, jsonify, request, g, current_app
from werkzeug.exceptions import HTTPException
from functools import wraps

from extensions import db, metrics, cache
from models import AuditLog, UserActivity
from core.security.cs_audit import log_security_event

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

# API error counter
api_error_count = metrics.counter(
    'api_errors_total',
    'Total number of API errors',
    labels={'type': lambda: g.get('error_type', 'unknown'), 'endpoint': lambda: request.endpoint}
)

def _log_api_security_incident(error_type: str, description: str, severity: str = "medium",
                               additional_details: Optional[Dict[str, Any]] = None) -> None:
    """
    Centralized security incident logging for API errors.

    Logs security-relevant API errors as incidents with appropriate
    severity, description, and contextual information, providing
    consistent security monitoring across all API endpoints.

    Args:
        error_type: Type of error or security event
        description: Human-readable description of the incident
        severity: Severity level (low, medium, high, critical)
        additional_details: Any additional context to include in the log
    """
    try:
        details = {
            'path': request.path,
            'method': request.method,
            'endpoint': request.endpoint,
            'user_agent': request.user_agent.string if request.user_agent else 'Unknown',
            'referrer': request.referrer or 'Direct',
            'remote_ip': request.remote_addr,
            'error_type': error_type
        }

        # Add user information if available
        if hasattr(g, 'user') and g.user:
            details['user_id'] = g.user.id
            details['username'] = g.user.username
        elif hasattr(g, 'user_id') and g.user_id:
            details['user_id'] = g.user_id

        # Add request parameters with sensitive data filtering
        if request.args:
            filtered_args = {k: '******' if k.lower() in ('token', 'password', 'key', 'secret', 'auth')
                            else v for k, v in request.args.items()}
            details['request_args'] = filtered_args

        # Merge with any additional details provided
        if additional_details:
            details.update(additional_details)

        # Get appropriate event type from AuditLog
        event_type = AuditLog.EVENT_API_ERROR
        if error_type == '403':
            event_type = AuditLog.EVENT_ACCESS_DENIED
        elif error_type == '401':
            event_type = AuditLog.EVENT_AUTHENTICATION_FAILURE

        # Log the security event
        log_security_event(
            event_type=event_type,
            description=description,
            severity=severity,
            details=details
        )

        # Increment metrics counter
        if hasattr(metrics, 'counter'):
            try:
                metrics.increment('api.security_incidents', labels={
                    'type': error_type,
                    'severity': severity
                })
            except Exception:
                pass

    except Exception as e:
        # Fail gracefully if logging fails
        current_app.logger.error(f"Failed to log security incident: {e}")

def update_api_module_baseline(app=None, auto_update_limit: int = 20,
                              remove_missing: bool = False) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Update file integrity baseline for critical API module files.

    This function provides a centralized way to update the integrity baseline
    for critical API components. It calculates current hashes for key API files
    and updates the baseline accordingly, following security best practices.

    Args:
        app: Flask application instance (uses current_app if None)
        auto_update_limit: Maximum number of files to update (safety limit)
        remove_missing: Whether to remove missing files from baseline

    Returns:
        Tuple containing (success, message, update_stats)
        - success: True if the update was successful
        - message: A descriptive message about the operation
        - update_stats: Statistics about the update including files updated and skipped
    """
    from services import calculate_file_hash

    try:
        app = app or current_app
        start_time = time.time()
        logger = logging.getLogger(__name__)

        # Get baseline path from config
        baseline_path = app.config.get('FILE_BASELINE_PATH')
        if not baseline_path:
            logger.error("Baseline path not configured")
            return False, "Baseline path not configured", {'files_updated': 0, 'files_skipped': 0}

        # Stats tracking
        stats = {
            'files_processed': 0,
            'files_updated': 0,
            'files_skipped': 0,
            'critical_files': 0,
            'high_priority_files': 0,
            'errors': 0,
            'modules_processed': set()
        }

        # Define critical API directories to monitor
        api_root = os.path.dirname(os.path.abspath(__file__))
        api_dirs = [
            os.path.join(api_root, ''),           # API root
            os.path.join(api_root, 'auth'),       # Authentication API
            os.path.join(api_root, 'admin'),      # Admin API
            os.path.join(api_root, 'security'),   # Security API
            os.path.join(api_root, 'webhooks')    # Webhooks API
        ]

        # Critical file patterns to monitor with priority
        critical_patterns = [
            '__init__.py',                 # Module initialization
            'auth.py',                     # Authentication handling
            'security.py',                 # Security handling
            'routes.py',                   # Core routes
            'baseline.py',                 # Baseline management
            'schemas.py',                  # Data validation
            'incidents.py',                # Security incidents
            'decorators.py'                # Security decorators
        ]

        # Collect all files from API directories
        changes = []
        for directory in api_dirs:
            if os.path.exists(directory):
                stats['modules_processed'].add(os.path.basename(directory) or 'api_root')

                for filename in os.listdir(directory):
                    file_path = os.path.join(directory, filename)

                    if os.path.isfile(file_path) and file_path.endswith('.py'):
                        try:
                            # Get relative path for baseline
                            rel_path = os.path.relpath(file_path, os.path.dirname(app.root_path))

                            # Calculate current hash
                            current_hash = calculate_file_hash(file_path)

                            # Determine severity based on file criticality
                            if filename in critical_patterns:
                                severity = 'high' if 'security' in directory or 'auth' in directory else 'medium'
                                if severity == 'high':
                                    stats['high_priority_files'] += 1
                            else:
                                severity = 'medium' if filename.endswith('.py') else 'low'

                            # Mark truly critical files
                            if ('security' in directory or 'auth' in directory) and filename in critical_patterns:
                                stats['critical_files'] += 1

                            # Add to changes list for baseline update
                            changes.append({
                                'path': rel_path,
                                'current_hash': current_hash,
                                'severity': severity
                            })

                            stats['files_processed'] += 1

                        except Exception as e:
                            logger.error(f"Error processing file {file_path}: {e}")
                            stats['errors'] += 1

        # Check if we have too many changes
        if len(changes) > auto_update_limit:
            logger.warning(f"Too many files to update: {len(changes)} exceeds limit of {auto_update_limit}")
            stats['files_skipped'] = len(changes) - auto_update_limit

            # Prioritize critical and high severity files
            changes = sorted(
                changes,
                key=lambda c: (
                    0 if c.get('severity', 'medium') == 'high' else
                    1 if c.get('severity', 'medium') == 'medium' else 2
                )
            )[:auto_update_limit]

        # Import security function for baseline update
        from api.security import update_file_integrity_baseline

        # Log the baseline update attempt
        log_security_event(
            event_type="api_baseline_update_started",
            description=f"API integrity baseline update started with {len(changes)} changes",
            severity="info",
            details={
                "changes_count": len(changes),
                "remove_missing": remove_missing,
                "baseline_path": baseline_path,
                "critical_files": stats['critical_files'],
                "high_priority_files": stats['high_priority_files']
            }
        )

        # Update baseline
        success, message = update_file_integrity_baseline(
            app=app,
            baseline_path=baseline_path,
            changes=changes,
            auto_update_limit=auto_update_limit,
            remove_missing=remove_missing
        )

        stats['files_updated'] = len(changes)
        duration = time.time() - start_time

        # Log event based on outcome
        if success:
            log_security_event(
                event_type="api_baseline_updated",
                description=f"API integrity baseline updated successfully with {len(changes)} changes",
                severity="info",
                details={
                    "modules_processed": list(stats['modules_processed']),
                    "files_updated": stats['files_updated'],
                    "files_skipped": stats['files_skipped'],
                    "critical_files": stats['critical_files'],
                    "duration_seconds": round(duration, 2)
                }
            )

            # Track metrics
            if hasattr(metrics, 'increment'):
                metrics.increment('security.api_baseline_updated')
                metrics.gauge('security.api_baseline.files_updated', stats['files_updated'])
        else:
            log_security_event(
                event_type="api_baseline_update_failed",
                description=f"API integrity baseline update failed: {message}",
                severity="warning",
                details={
                    "modules_processed": list(stats['modules_processed']),
                    "files_attempted": stats['files_processed'],
                    "errors": stats['errors'],
                    "duration_seconds": round(duration, 2)
                }
            )

            if hasattr(metrics, 'increment'):
                metrics.increment('security.api_baseline_error')

        return success, message, stats

    except ImportError as e:
        logger.error(f"Required security modules not available: {e}")
        return False, "Required security modules not available", {
            'files_updated': 0,
            'error': str(e)
        }
    except Exception as e:
        logger.error(f"Error updating API module baseline: {e}")
        return False, f"Error updating baseline: {str(e)}", {
            'files_updated': 0,
            'error': str(e)
        }

# Define API-wide error handlers
@api_bp.errorhandler(404)
def resource_not_found(_e):
    """Handle resources not found with a consistent JSON response"""
    g.error_type = '404'
    api_error_count.inc()
    return jsonify(error="Resource not found", status_code=404), 404

@api_bp.errorhandler(500)
def internal_server_error(_e):
    """Handle internal server errors with a consistent JSON response"""
    error_message = str(_e)
    current_app.logger.error(f"Internal server error: {error_message}")
    g.error_type = '500'
    api_error_count.inc()

    # Log security incident for server errors
    _log_api_security_incident(
        error_type='500',
        description=f"API server error: {error_message[:100]}",
        severity="high"
    )

    return jsonify(error="Internal server error", status_code=500), 500

@api_bp.errorhandler(429)
def too_many_requests(_e):
    """Handle rate limiting with a consistent JSON response"""
    g.error_type = '429'
    api_error_count.inc()

    # Log potential DoS attempt
    _log_api_security_incident(
        error_type='429',
        description="Rate limit exceeded",
        severity="medium",
        additional_details={
            'rate_limiting': {
                'endpoint': request.endpoint,
                'client_ip': request.remote_addr
            }
        }
    )

    return jsonify(
        error="Too many requests",
        status_code=429,
        message="Rate limit exceeded. Please try again later."
    ), 429

@api_bp.errorhandler(403)
def forbidden(_e):
    """Handle forbidden access with a consistent JSON response"""
    g.error_type = '403'
    api_error_count.inc()

    # Log security incident for forbidden access
    _log_api_security_incident(
        error_type='403',
        description="API access forbidden",
        severity="medium"
    )

    return jsonify(error="Forbidden", status_code=403), 403

@api_bp.errorhandler(401)
def unauthorized(_e):
    """Handle unauthorized access with a consistent JSON response"""
    g.error_type = '401'
    api_error_count.inc()

    # Log security incident for authentication failure
    _log_api_security_incident(
        error_type='401',
        description="Authentication required for API access",
        severity="low"
    )

    return jsonify(
        error="Unauthorized",
        status_code=401,
        message="Authentication required"
    ), 401

@api_bp.errorhandler(400)
def bad_request(_e):
    """Handle bad request errors with a consistent JSON response"""
    g.error_type = '400'
    api_error_count.inc()

    # Extract error message if provided
    message = str(_e) if _e else "Invalid request parameters"

    return jsonify(
        error="Bad Request",
        status_code=400,
        message=message
    ), 400

@api_bp.before_request
def before_request():
    """Execute before each API request to set up request context"""
    g.request_start_time = time.time()
    g.user_id = getattr(g, 'user_id', None)

    # Mark request as API request for middleware detection
    g.is_api_request = True

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

    # Add cache control headers to prevent caching of API responses
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response

# Import and register API modules
from api.auth import auth_api
from api.cloud import cloud_routes
from api.metrics import metrics_routes
from api.alerts import alerts_api
from api.ics import ics_routes
from api.security import security_routes
from api.audit import audit_routes
from api.newsletter import newsletter_routes
from api.webhooks import webhooks_api
from api.admin import admin_api

# Register all route blueprints
api_bp.register_blueprint(auth_api)
api_bp.register_blueprint(cloud_routes)
api_bp.register_blueprint(metrics_routes)
api_bp.register_blueprint(alerts_api)
api_bp.register_blueprint(ics_routes)
api_bp.register_blueprint(security_routes)
api_bp.register_blueprint(audit_routes)
api_bp.register_blueprint(newsletter_routes)
api_bp.register_blueprint(webhooks_api)
api_bp.register_blueprint(admin_api)

# Initialize webhook metrics
if hasattr(metrics, 'register'):
    try:
        from api.webhooks import register_webhook_metrics
        register_webhook_metrics(metrics)
    except (ImportError, AttributeError) as e:
        current_app.logger.warning(f"Failed to register webhook metrics: {e}")

def register_api_routes(app: Flask) -> None:
    """
    Register all API routes with appropriate error handling.

    This function centralizes the registration of all API blueprints,
    providing consistent error handling and logging during the
    registration process. It ensures that a failure to register
    one blueprint doesn't prevent others from being registered.

    Args:
        app: The Flask application instance

    Returns:
        None
    """
    # Define all blueprints to register with their URL prefixes
    blueprint_configs = [
        (api_bp, None),  # None means use the blueprint's url_prefix
        (auth_api, None),
        (cloud_routes, None),
        (metrics_routes, None),
        (alerts_api, None),
        (ics_routes, None),
        (security_routes, None),
        (audit_routes, None),
        (newsletter_routes, None),
        (webhooks_api, None),
        (admin_api, None)
    ]

    # Track successful registrations for logging
    registered_count = 0
    failed_count = 0

    # Register each blueprint with error handling
    for blueprint, url_prefix in blueprint_configs:
        try:
            if url_prefix:
                app.register_blueprint(blueprint, url_prefix=url_prefix)
            else:
                app.register_blueprint(blueprint)

            app.logger.debug(f"Registered API blueprint: {blueprint.name}")
            registered_count += 1

        except Exception as e:
            app.logger.error(f"Failed to register API blueprint {getattr(blueprint, 'name', 'unknown')}: {str(e)}")
            failed_count += 1

            # Log security event for blueprint registration failure
            try:
                if hasattr(log_security_event, '__call__'):
                    log_security_event(
                        event_type="api_initialization_error",
                        description=f"Failed to register API blueprint: {getattr(blueprint, 'name', 'unknown')}",
                        severity="high",
                        details={"error": str(e)}
                    )
            except Exception as log_error:
                app.logger.error(f"Failed to log security event for blueprint registration failure: {str(log_error)}")

    # Register metrics if available
    if hasattr(metrics, 'register'):
        try:
            from api.webhooks import register_webhook_metrics
            register_webhook_metrics(metrics)
            app.logger.debug("Registered webhook metrics")
        except (ImportError, AttributeError) as e:
            app.logger.warning(f"Failed to register webhook metrics: {e}")

    # Log summary of registration
    total = len(blueprint_configs)
    if failed_count > 0:
        app.logger.warning(
            f"API initialization completed with issues: {registered_count}/{total} blueprints registered successfully, {failed_count} failed"
        )
    else:
        app.logger.info(f"API initialization completed: All {total} blueprints registered successfully")


def init_app(app: Flask) -> None:
    """
    Initialize the API module within the Flask application.

    Sets up API blueprints, security features, and performs initial file
    integrity verification if configured.

    Args:
        app: The Flask application instance
    """
    # Register the API blueprint with all routes
    register_api_routes(app)

    # Setup file integrity monitoring if enabled
    if app.config.get('API_INTEGRITY_CHECK_ON_STARTUP', True):
        try:
            # Verify file integrity at startup in development environments
            # In production, this is better handled by scheduled tasks
            if app.config.get('ENVIRONMENT') in ['development', 'testing']:
                logger = logging.getLogger(__name__)
                logger.info("Performing API module integrity verification")

                # Only update automatically in development mode
                auto_update = app.config.get('ENVIRONMENT') == 'development'

                if auto_update:
                    # Update the baseline automatically
                    success, message, stats = update_api_module_baseline(
                        app=app,
                        auto_update_limit=app.config.get('API_BASELINE_AUTO_UPDATE_LIMIT', 20),
                        remove_missing=False
                    )

                    if success:
                        logger.info(f"API baseline updated: {message} - {stats['files_updated']} files updated")
                    else:
                        logger.warning(f"API baseline update failed: {message}")
                else:
                    # Just check the integrity but don't update
                    from api.security import validate_baseline_integrity
                    result, violations = validate_baseline_integrity()

                    if not result and violations:
                        logger.warning(f"API integrity verification failed: {len(violations)} violations detected")
                    else:
                        logger.info("API integrity verification passed")
        except ImportError:
            app.logger.warning("File integrity module not available, skipping API validation")
        except Exception as e:
            app.logger.error(f"Error during API integrity verification: {e}")

    # Log successful initialization
    app.logger.info("API module initialized successfully")

# Package version
__version__ = '0.1.1'

# Define what is available for import from this package
__all__ = [
    'api_bp',
    'init_app',
    'register_api_routes',
    'update_api_module_baseline',
    '__version__'
]
