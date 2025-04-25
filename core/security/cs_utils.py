"""
Security utilities and configuration for Cloud Infrastructure Platform.

This module centralizes security configuration parameters and provides utility
functions for initializing, configuring, and managing security components across
the platform. It includes settings for encryption, authentication, authorization,
monitoring, and file integrity verification.

The security utilities ensure proper initialization of security components
and integration between different security modules.
"""

import os
import logging
from typing import Dict, Any, List, Optional, Union, Callable
from flask import Flask, current_app, has_app_context

# Internal imports
from cs_constants import SECURITY_CONFIG

# Set up module-level logger
logger = logging.getLogger(__name__)

def initialize_security_components(app: Flask) -> None:
    """
    Initialize security components for the Flask application.

    This function sets up security components including:
    - Security headers
    - File integrity monitoring
    - Audit logging
    - Security metrics
    - Session security

    Args:
        app: Flask application instance
    """
    if not app:
        logger.error("Cannot initialize security components: No app provided")
        return

    logger.info("Initializing security components")

    try:
        # Set up security headers middleware
        _setup_security_headers(app)

        # Set up file integrity monitoring
        _setup_file_integrity_monitoring(app)

        # Initialize security metrics collection
        _initialize_security_metrics(app)

        # Configure audit logging
        _setup_audit_logging(app)

        # Configure session security
        _setup_session_security(app)

        # Register security request handlers
        _register_security_request_handlers(app)

        logger.info("Security components initialized successfully")

    except Exception as e:
        logger.error(f"Failed to initialize security components: {e}")
        # Don't raise exception - we want the app to start even if security initialization fails
        # but log it as a critical issue


def validate_security_config() -> List[str]:
    """
    Validate the security configuration for required and recommended settings.

    Returns:
        List of validation errors/warnings
    """
    validation_issues = []

    # Check required settings
    if not SECURITY_CONFIG.get('ENCRYPTION_KEY'):
        validation_issues.append("CRITICAL: ENCRYPTION_KEY is not set")

    # Check password policy
    min_length = SECURITY_CONFIG.get('MIN_PASSWORD_LENGTH', 0)
    if min_length < 12:
        validation_issues.append(f"WARNING: MIN_PASSWORD_LENGTH ({min_length}) should be at least 12")

    # Check session security
    session_timeout = SECURITY_CONFIG.get('SESSION_TIMEOUT', 0)
    if session_timeout > 24 * 3600:
        validation_issues.append(f"WARNING: SESSION_TIMEOUT ({session_timeout}s) exceeds recommended maximum of 24 hours")

    # Check for MFA enforcement
    if not SECURITY_CONFIG.get('REQUIRE_MFA_FOR_SENSITIVE', False):
        validation_issues.append("WARNING: REQUIRE_MFA_FOR_SENSITIVE is not enabled")

    # Validate JWT algorithm
    jwt_algorithm = SECURITY_CONFIG.get('JWT_ALGORITHM')
    if jwt_algorithm not in ['HS256', 'RS256', 'ES256']:
        validation_issues.append(f"WARNING: JWT_ALGORITHM '{jwt_algorithm}' should be HS256, RS256, or ES256")

    return validation_issues


def get_security_config(key: str, default: Any = None) -> Any:
    """
    Get a security configuration value with optional default.

    This function checks both the SECURITY_CONFIG and Flask application config
    if available, with Flask config taking precedence.

    Args:
        key: Configuration key to retrieve
        default: Default value if key is not found

    Returns:
        Configuration value or default
    """
    # Check Flask app config first if in application context
    if has_app_context():
        app_value = current_app.config.get(key)
        if app_value is not None:
            return app_value

    # Fall back to SECURITY_CONFIG
    return SECURITY_CONFIG.get(key, default)


def apply_security_headers(response) -> None:
    """
    Apply security headers to HTTP response.

    Args:
        response: Flask response object
    """
    security_headers = SECURITY_CONFIG.get('SECURITY_HEADERS', {})

    # Apply headers from configuration
    for header, value in security_headers.items():
        # Don't overwrite existing headers set by the application
        if header not in response.headers:
            response.headers[header] = value

    return response


def register_security_check_handler(app: Flask, handler: Callable) -> None:
    """
    Register a security check handler to run on each request.

    Args:
        app: Flask application instance
        handler: Function to call on each request
    """
    if not app:
        logger.error("Cannot register security handler: No app provided")
        return

    if not callable(handler):
        logger.error("Cannot register security handler: Handler is not callable")
        return

    app.before_request_funcs.setdefault(None, []).append(handler)
    logger.debug(f"Registered security check handler: {handler.__name__}")


# Private helper functions

def _setup_security_headers(app: Flask) -> None:
    """Configure security headers for all responses."""
    @app.after_request
    def add_security_headers(response):
        return apply_security_headers(response)


def _setup_file_integrity_monitoring(app: Flask) -> None:
    """Set up file integrity monitoring for the application."""
    try:
        # Only import when needed to avoid circular imports
        from .cs_file_integrity import initialize_file_monitoring

        # Get configuration from app config or fallback to SECURITY_CONFIG
        basedir = app.root_path
        patterns = app.config.get('CRITICAL_FILE_PATTERNS',
                                SECURITY_CONFIG.get('CRITICAL_FILES_PATTERN', []))
        interval = app.config.get('FILE_CHECK_INTERVAL',
                                SECURITY_CONFIG.get('FILE_CHECK_INTERVAL', 3600))

        # Initialize file monitoring
        initialize_file_monitoring(app, basedir, patterns, interval)

    except ImportError:
        logger.warning("File integrity monitoring module not available")
    except Exception as e:
        logger.error(f"Failed to setup file integrity monitoring: {e}")


def _initialize_security_metrics(app: Flask) -> None:
    """Initialize security metrics collection."""
    try:
        # Import here to avoid circular imports
        from .cs_metrics import initialize_metrics_collection

        # Schedule metrics collection
        initialize_metrics_collection(app)

    except ImportError:
        logger.warning("Security metrics module not available")
    except Exception as e:
        logger.error(f"Failed to initialize security metrics: {e}")


def _setup_audit_logging(app: Flask) -> None:
    """Configure audit logging for security events."""
    try:
        # Import here to avoid circular imports
        from .cs_audit import initialize_audit_logging

        # Initialize audit logging
        initialize_audit_logging(app)

    except ImportError:
        logger.warning("Audit logging module not available")
    except Exception as e:
        logger.error(f"Failed to setup audit logging: {e}")


def _setup_session_security(app: Flask) -> None:
    """Configure session security features."""
    try:
        # Import here to avoid circular imports
        from .cs_session import initialize_session_security

        # Initialize session security
        initialize_session_security(app)

    except ImportError:
        logger.warning("Session security module not available")
    except Exception as e:
        logger.error(f"Failed to setup session security: {e}")


def _register_security_request_handlers(app: Flask) -> None:
    """Register security handlers for processing requests."""
    try:
        # Import here to avoid circular imports
        from .cs_authentication import check_auth_security
        from .cs_monitoring import check_request_security

        # Register authentication checks
        register_security_check_handler(app, check_auth_security)

        # Register request security checks
        register_security_check_handler(app, check_request_security)

    except ImportError as e:
        logger.warning(f"Some security handler modules not available: {e}")
    except Exception as e:
        logger.error(f"Failed to register security request handlers: {e}")
