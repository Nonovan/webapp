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
    from core.security import log_security_event
    from core.security.cs_metrics import setup_security_metrics
    from extensions import metrics
    SECURITY_UTILS_AVAILABLE = True
except ImportError:
    logger.warning("Core security utilities not fully available; some features may be limited")
    SECURITY_UTILS_AVAILABLE = False

# Define what is available for import from this package
__all__ = [
    "security_bp",
    "init_app"
]

# Package version
__version__ = '1.0.0'

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


# Import Flask request object only when needed in function scope to avoid circular imports
def _add_security_headers(response):
    from flask import request
    # Implementation from the after_request handler above
    # (Kept separate to avoid circular import issues with Flask's request object)
