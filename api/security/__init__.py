"""
Security API Package.

This package contains the Flask Blueprint and API endpoint implementations
for security-related operations within the Cloud Infrastructure Platform.
It covers areas such as security incident management, vulnerability tracking,
security scanning, and threat intelligence.

Endpoints are consolidated under the '/api/security' prefix via the `security_bp` blueprint.
"""

import logging
from typing import Dict, Any, Optional
from flask import Flask, current_app, request

# Import the main blueprint for the security API
from .routes import security_bp

# Import endpoint modules to ensure routes are registered with the blueprint
from . import incidents
from . import scanning
from . import threats
from . import vulnerabilities
# Add imports for any other endpoint files here

# Initialize logger for the package
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())  # Avoid "No handler found" warnings

# Import security utilities conditionally to avoid hard dependency
try:
    from core.security import log_security_event, check_critical_file_integrity, get_last_integrity_status
    from core.security.cs_metrics import setup_security_metrics
    from extensions import metrics
    SECURITY_UTILS_AVAILABLE = True
except ImportError:
    logger.warning("Core security utilities not fully available; some features may be limited")
    SECURITY_UTILS_AVAILABLE = False

# Define what is available for import from this package
__all__ = [
    "security_bp",
    "init_app",
    "update_file_integrity_baseline"
]

# Package version
__version__ = '0.1.1'  # Updated version for baseline management feature

# Track initialized state to prevent duplicate initialization
_initialized = False

def init_app(app: Flask) -> None:
    """
    Initialize the security API with the Flask application.

    This function sets up:
    - Security metrics collection
    - Event handlers for security events
    - Rate limiting for security-sensitive endpoints
    - Security-specific request validation
    - File integrity monitoring integration

    Args:
        app: Flask application instance
    """
    global _initialized

    if _initialized:
        logger.debug("Security API already initialized, skipping")
        return

    logger.info("Initializing security API components")

    # Register blueprint if not already done at import time
    if not app.blueprints.get('security_api'):
        app.register_blueprint(security_bp, url_prefix='/api/security')

    # Set up metrics collection if available
    if SECURITY_UTILS_AVAILABLE and hasattr(metrics, 'counter'):
        try:
            # Register security-specific metrics
            metrics.counter(
                'security_incidents_total',
                'Total number of security incidents',
                labels=['severity', 'status', 'type']
            )

            metrics.counter(
                'security_vulnerabilities_total',
                'Total number of security vulnerabilities',
                labels=['severity', 'status']
            )

            metrics.counter(
                'security_scans_total',
                'Total number of security scans',
                labels=['type', 'status']
            )

            metrics.counter(
                'security_threats_total',
                'Total number of security threats',
                labels=['indicator_type', 'confidence']
            )

            metrics.histogram(
                'security_incident_resolution_time',
                'Time to resolve security incidents in hours',
                labels=['severity', 'type'],
                buckets=(1, 4, 12, 24, 72, 168)  # 1hr, 4hr, 12hr, 1d, 3d, 7d
            )

            # Add file integrity metrics
            metrics.counter(
                'security_file_integrity_violations',
                'Total number of file integrity violations detected',
                labels=['severity', 'status']
            )

            metrics.gauge(
                'security_baseline_update_status',
                'Status of the last baseline update (1=success, 0=failure)'
            )

            logger.info("Security metrics registered successfully")
        except Exception as e:
            logger.error(f"Failed to initialize security metrics: {e}")

    # Configure custom security headers for API endpoints
    @security_bp.after_request
    def add_security_headers(response):
        """Add security-specific headers to all security API responses."""
        # Add security headers specific to security endpoints
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'

        # Add cache control headers to prevent caching of sensitive security data
        if request.method != 'GET' or request.path.startswith('/api/security/incidents'):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '-1'

        return response

    # Log initialization event
    try:
        if SECURITY_UTILS_AVAILABLE:
            log_security_event(
                event_type="security_api_initialized",
                description="Security API components initialized",
                severity="info",
                details={
                    "version": __version__,
                    "endpoints": [
                        "incidents", "vulnerabilities",
                        "scanning", "threats"
                    ]
                }
            )
    except Exception as e:
        logger.warning(f"Could not log security initialization event: {e}")

    _initialized = True
    logger.debug("Security API package initialized successfully")


def update_file_integrity_baseline(app: Flask, baseline_path: str, changes: list,
                                 auto_update_limit: int = 10, remove_missing: bool = False) -> tuple:
    """
    Update the file integrity baseline with authorized changes.

    This function serves as a wrapper around the core security service's baseline update
    functionality, providing proper security event logging and validation.

    Args:
        app: Flask application instance
        baseline_path: Path to the baseline JSON file
        changes: List of change dictionaries from integrity check
        auto_update_limit: Maximum number of files to auto-update (safety limit)
        remove_missing: Whether to remove missing files from baseline

    Returns:
        Tuple containing (success, message)
    """
    try:
        # Import required security functions
        from services import update_file_integrity_baseline as service_update_baseline

        # Log the baseline update attempt
        log_security_event(
            event_type="security_baseline_update_started",
            description=f"File integrity baseline update started with {len(changes)} changes",
            severity="info",
            details={
                "changes_count": len(changes),
                "remove_missing": remove_missing,
                "baseline_path": baseline_path
            }
        )

        # Call the service function to handle the update
        success, message = service_update_baseline(
            app=app,
            baseline_path=baseline_path,
            changes=changes,
            auto_update_limit=auto_update_limit
        )

        # Log the result of the update
        if success:
            metrics.gauge('security_baseline_update_status', 1)  # Success
            log_security_event(
                event_type="security_baseline_updated",
                description=f"File integrity baseline updated successfully: {message}",
                severity="info",
                details={
                    "baseline_path": baseline_path,
                    "changes_count": len(changes),
                    "message": message
                }
            )
        else:
            metrics.gauge('security_baseline_update_status', 0)  # Failure
            log_security_event(
                event_type="security_baseline_update_failed",
                description=f"File integrity baseline update failed: {message}",
                severity="warning",
                details={
                    "baseline_path": baseline_path,
                    "changes_count": len(changes),
                    "error_message": message
                }
            )

        return success, message

    except ImportError:
        logger.error("Required security modules not available for baseline update")
        log_security_event(
            event_type="security_baseline_update_failed",
            description="File integrity baseline update failed: Required modules not available",
            severity="error"
        )
        return False, "Required security modules not available"
    except Exception as e:
        logger.error(f"Error updating file integrity baseline: {str(e)}")
        log_security_event(
            event_type="security_baseline_update_failed",
            description=f"File integrity baseline update failed with exception: {str(e)}",
            severity="error",
            details={"error": str(e)}
        )
        return False, f"Error updating baseline: {str(e)}"


# Import Flask request object only when needed in function scope to avoid circular imports
def _add_security_headers(response):
    from flask import request
    # Implementation from the after_request handler above
    # (Kept separate to avoid circular import issues with Flask's request object)
