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
import json
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union, Callable, Tuple
from flask import Flask, current_app, has_app_context, Response, g

# Internal imports
from .cs_constants import SECURITY_CONFIG
from extensions import metrics, get_redis_client

# Set up module-level logger
logger = logging.getLogger(__name__)


def initialize_security_components(app: Flask) -> None:
    """
    Initialize security components for the Flask application.

    This function sets up security components including:
    - Security headers
    - File integrity monitoring
    - Security metrics
    - Audit logging
    - Session security
    - Request handlers

    Args:
        app: Flask application instance
    """
    if not app:
        logger.error("Cannot initialize security components: No app provided")
        return

    logger.info("Initializing security components")

    try:
        # Validate security configuration
        issues = validate_security_config()
        for issue in issues:
            if issue.startswith("CRITICAL"):
                logger.critical(issue)
            else:
                logger.warning(issue)

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

        # Report initialization metrics
        metrics.increment('security.components_initialized')

        logger.info("Security components initialized successfully")

    except Exception as e:
        logger.error(f"Failed to initialize security components: {e}")
        metrics.increment('security.initialization_failure')
        # Don't raise exception - we want the app to start even if security initialization fails
        # but log it as a critical issue


def validate_security_config() -> List[str]:
    """
    Validate the security configuration for required and recommended settings.

    Returns:
        List of validation errors/warnings
    """
    validation_issues = []

    # Check encryption settings
    if not SECURITY_CONFIG.get('ENCRYPTION_KEY'):
        validation_issues.append("CRITICAL: ENCRYPTION_KEY is not set")

    encryption_salt = SECURITY_CONFIG.get('ENCRYPTION_SALT')
    if not encryption_salt:
        validation_issues.append("WARNING: ENCRYPTION_SALT is not set")
    elif isinstance(encryption_salt, str) and len(encryption_salt) < 16:
        validation_issues.append("WARNING: ENCRYPTION_SALT should be at least 16 bytes")

    # Check key iterations
    key_iterations = SECURITY_CONFIG.get('DEFAULT_KEY_ITERATIONS', 0)
    if key_iterations < 100000:
        validation_issues.append(f"WARNING: DEFAULT_KEY_ITERATIONS ({key_iterations}) should be at least 100,000")

    # Check password policy
    min_length = SECURITY_CONFIG.get('MIN_PASSWORD_LENGTH', 0)
    if min_length < 12:
        validation_issues.append(f"WARNING: MIN_PASSWORD_LENGTH ({min_length}) should be at least 12")

    if not SECURITY_CONFIG.get('PASSWORD_COMPLEXITY_REQUIRED', False):
        validation_issues.append("WARNING: PASSWORD_COMPLEXITY_REQUIRED is not enabled")

    # Check session security
    session_timeout = SECURITY_CONFIG.get('SESSION_TIMEOUT', 0)
    if session_timeout > 24 * 3600:
        validation_issues.append(f"WARNING: SESSION_TIMEOUT ({session_timeout}s) exceeds recommended maximum of 24 hours")
    elif session_timeout <= 0:
        validation_issues.append("WARNING: SESSION_TIMEOUT is not properly set")

    # Check for MFA enforcement
    if not SECURITY_CONFIG.get('REQUIRE_MFA_FOR_SENSITIVE', False):
        validation_issues.append("WARNING: REQUIRE_MFA_FOR_SENSITIVE is not enabled")

    # Validate JWT algorithm
    jwt_algorithm = SECURITY_CONFIG.get('JWT_ALGORITHM')
    if jwt_algorithm not in ['HS256', 'RS256', 'ES256']:
        validation_issues.append(f"WARNING: JWT_ALGORITHM '{jwt_algorithm}' should be HS256, RS256, or ES256")

    # Check security headers
    security_headers = SECURITY_CONFIG.get('SECURITY_HEADERS', {})
    if 'Strict-Transport-Security' not in security_headers:
        validation_issues.append("WARNING: HSTS header not configured")
    if 'Content-Security-Policy' not in security_headers:
        validation_issues.append("WARNING: Content-Security-Policy header not configured")

    # Check file integrity settings
    file_check_interval = SECURITY_CONFIG.get('FILE_CHECK_INTERVAL', 0)
    if file_check_interval < 900:  # Minimum 15 minutes
        validation_issues.append(f"WARNING: FILE_CHECK_INTERVAL ({file_check_interval}s) is too frequent")

    critical_patterns = SECURITY_CONFIG.get('CRITICAL_FILES_PATTERN', [])
    if not critical_patterns:
        validation_issues.append("WARNING: No CRITICAL_FILES_PATTERN specified for file monitoring")

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


def apply_security_headers(response: Response) -> Response:
    """
    Apply security headers to HTTP response.

    Args:
        response: Flask response object

    Returns:
        Response with security headers applied
    """
    security_headers = SECURITY_CONFIG.get('SECURITY_HEADERS', {})

    # Convert CSP to nonce-based if available in request context
    csp = security_headers.get('Content-Security-Policy', '')
    if csp and hasattr(g, 'csp_nonce'):
        # Insert nonce where needed in CSP
        csp = csp.replace("'self'", f"'self' 'nonce-{g.csp_nonce}'")
        security_headers['Content-Security-Policy'] = csp

    # Apply headers from configuration
    for header, value in security_headers.items():
        # Don't overwrite existing headers set by the application
        if header not in response.headers:
            response.headers[header] = value

    # Set feature policy if not already set
    if 'Feature-Policy' not in response.headers and 'Permissions-Policy' not in response.headers:
        response.headers['Permissions-Policy'] = "camera=(), microphone=(), geolocation=(self)"

    return response


def register_security_check_handler(app: Flask, handler: Callable) -> bool:
    """
    Register a security check handler to run on each request.

    Args:
        app: Flask application instance
        handler: Function to call on each request

    Returns:
        bool: True if registration was successful
    """
    if not app:
        logger.error("Cannot register security handler: No app provided")
        return False

    if not callable(handler):
        logger.error("Cannot register security handler: Handler is not callable")
        return False

    # Ensure we have a before_request_funcs list for None (global handlers)
    if not hasattr(app, 'before_request_funcs') or app.before_request_funcs is None:
        app.before_request_funcs = {}

    app.before_request_funcs.setdefault(None, []).append(handler)
    logger.debug(f"Registered security check handler: {handler.__name__}")
    return True


def get_file_integrity_report() -> Dict[str, Any]:
    """
    Get a summary report of file integrity status.

    Returns:
        Dict containing status of file integrity checks
    """
    try:
        # Import here to avoid circular imports
        from .cs_file_integrity import get_last_integrity_status

        # Get integrity status
        integrity_status = get_last_integrity_status()
        if integrity_status:
            return integrity_status

        # If no status is available, check if we have the database version
        redis_client = get_redis_client()
        if not redis_client:
            return {
                'status': 'unknown',
                'last_check': None,
                'has_violations': False
            }

        last_check_time = redis_client.get('security:last_successful_integrity_check')
        if last_check_time:
            try:
                timestamp = int(last_check_time.decode('utf-8'))
                last_check = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
                return {
                    'status': 'ok',
                    'last_check': last_check,
                    'has_violations': False
                }
            except (ValueError, TypeError):
                pass

        # No information available
        return {
            'status': 'unknown',
            'last_check': None,
            'has_violations': False
        }
    except ImportError:
        logger.warning("File integrity module not available")
        return {
            'status': 'disabled',
            'last_check': None,
            'has_violations': False
        }
    except Exception as e:
        logger.error(f"Failed to get file integrity report: {e}")
        return {
            'status': 'error',
            'last_check': None,
            'has_violations': False,
            'error': str(e)
        }


def get_security_status_summary() -> Dict[str, Any]:
    """
    Get a summary of the current security status.

    Returns:
        Dict containing security status information
    """
    try:
        # Get file integrity status
        integrity = get_file_integrity_report()

        # Try to get other security metrics
        metrics_available = False
        risk_score = None
        metrics_data = {}

        try:
            # Import here to avoid circular imports
            from .cs_metrics import get_security_metrics
            metrics_data = get_security_metrics(hours=24)
            metrics_available = True
            risk_score = metrics_data.get('risk_score')
        except ImportError:
            logger.debug("Security metrics module not available")
        except Exception as e:
            logger.error(f"Failed to get security metrics: {e}")

        # Determine overall status
        if integrity.get('has_violations', False):
            status = 'critical'
        elif risk_score and risk_score >= 8:
            status = 'critical'
        elif risk_score and risk_score >= 6:
            status = 'warning'
        elif metrics_available:
            status = 'ok'
        else:
            status = 'unknown'

        # Build summary
        summary = {
            'status': status,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'components': {
                'file_integrity': integrity.get('status', 'unknown'),
            },
            'details': {}
        }

        # Add metrics data if available
        if metrics_available:
            summary['components']['metrics'] = 'active'
            summary['details']['risk_score'] = risk_score

            # Add key metrics
            if 'failed_logins_24h' in metrics_data:
                summary['details']['failed_logins_24h'] = metrics_data['failed_logins_24h']

            if 'suspicious_ips' in metrics_data:
                summary['details']['suspicious_ip_count'] = len(metrics_data['suspicious_ips'])

            if 'security_anomalies' in metrics_data:
                summary['details']['anomaly_count'] = len(metrics_data['security_anomalies'])

        return summary
    except Exception as e:
        logger.error(f"Failed to get security status summary: {e}")
        return {
            'status': 'error',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': str(e)
        }


def generate_csp_nonce() -> str:
    """
    Generate a secure nonce for Content Security Policy.

    Returns:
        str: A cryptographically secure random nonce
    """
    try:
        import secrets
        return secrets.token_hex(16)
    except ImportError:
        # Fall back to os.urandom for older Python versions
        import binascii
        return binascii.hexlify(os.urandom(16)).decode('ascii')


def check_security_dependencies() -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Check if all required security dependencies are installed with proper versions.

    Verifies that critical security-related packages are installed with minimum
    acceptable versions. This helps ensure the security framework has all the
    dependencies needed to operate correctly.

    Returns:
        Tuple[bool, List[Dict[str, Any]]]:
            - Success status (True if all critical deps are available)
            - List of dependency details with status and version info
    """
    dependency_results = []
    critical_failures = 0

    # Required dependencies with minimum versions
    required_deps = [
        {'name': 'cryptography', 'min_version': '36.0.0', 'critical': True},
        {'name': 'bcrypt', 'min_version': '3.2.0', 'critical': True},
        {'name': 'passlib', 'min_version': '1.7.4', 'critical': True},
        {'name': 'pyOpenSSL', 'min_version': '20.0.0', 'critical': True},
        {'name': 'certifi', 'min_version': '2021.10.8', 'critical': False},
        {'name': 'requests', 'min_version': '2.27.0', 'critical': True},
        {'name': 'urllib3', 'min_version': '1.26.9', 'critical': True},
        {'name': 'idna', 'min_version': '3.3', 'critical': False}
    ]

    for dep in required_deps:
        result = {
            'name': dep['name'],
            'required_version': dep['min_version'],
            'critical': dep['critical'],
            'installed': False,
            'version': None,
            'status': 'missing'
        }

        try:
            # Try to import the module
            module = __import__(dep['name'].replace('-', '_'))

            # Get version - try different attributes since packages vary
            version = None
            for attr in ['__version__', 'version', 'VERSION']:
                if hasattr(module, attr):
                    version = getattr(module, attr)
                    if callable(version):
                        version = version()
                    break

            # If we still don't have a version, try using pkg_resources
            if version is None:
                try:
                    import pkg_resources
                    version = pkg_resources.get_distribution(dep['name']).version
                except (ImportError, pkg_resources.DistributionNotFound):
                    version = "unknown"

            result['installed'] = True
            result['version'] = str(version) if version else "unknown"

            # Check if version meets minimum requirements
            if version and version != "unknown":
                try:
                    from packaging import version as packaging_version
                    meets_min = packaging_version.parse(version) >= packaging_version.parse(dep['min_version'])
                    result['status'] = 'ok' if meets_min else 'outdated'
                    if not meets_min and dep['critical']:
                        critical_failures += 1
                except ImportError:
                    # If packaging is not available, do a simple string comparison
                    result['status'] = 'unknown_version'
            else:
                result['status'] = 'unknown_version'

        except ImportError:
            if dep['critical']:
                critical_failures += 1
            result['status'] = 'missing'
        except Exception as e:
            logger.error(f"Error checking {dep['name']}: {e}")
            result['status'] = 'error'
            result['error'] = str(e)
            if dep['critical']:
                critical_failures += 1

        dependency_results.append(result)

    # Check for specific security-enhancing features
    try:
        # Verify SSL implementation is not the default
        import ssl
        result = {
            'name': 'ssl_implementation',
            'installed': True,
            'critical': True,
            'version': ssl.OPENSSL_VERSION,
            'status': 'ok' if not ssl.OPENSSL_VERSION.startswith('LibreSSL') else 'warning'
        }
        dependency_results.append(result)
    except Exception as e:
        logger.error(f"Error checking SSL implementation: {e}")
        dependency_results.append({
            'name': 'ssl_implementation',
            'installed': False,
            'critical': True,
            'status': 'error',
            'error': str(e)
        })
        critical_failures += 1

    # Track metrics
    success = critical_failures == 0
    metrics.gauge('security.dependencies.critical_failures', critical_failures)
    metrics.gauge('security.dependencies.total', len(dependency_results))
    metrics.gauge('security.dependencies.missing', sum(1 for d in dependency_results if d['status'] == 'missing'))
    metrics.gauge('security.dependencies.outdated', sum(1 for d in dependency_results if d['status'] == 'outdated'))

    if not success:
        metrics.increment('security.dependencies_check_failed')

    return success, dependency_results


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent directory traversal and other issues.

    Args:
        filename: Filename to sanitize

    Returns:
        Sanitized filename
    """
    # Remove directory traversal components and limit to basename
    sanitized = os.path.basename(filename)

    # Remove any null bytes or other control characters
    sanitized = re.sub(r'[\x00-\x1f]', '', sanitized)

    # Replace potentially dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', sanitized)

    # Ensure non-empty result
    if not sanitized:
        sanitized = "unnamed_file"

    return sanitized


def obfuscate_sensitive_data(
    data: str,
    prefix_visible: int = 0,
    suffix_visible: int = 4,
    mask_char: str = '*'
) -> str:
    """
    Obfuscate sensitive data like API keys or PII.

    Args:
        data: String to obfuscate
        prefix_visible: Number of characters to show at beginning
        suffix_visible: Number of characters to show at end
        mask_char: Character to use for masking

    Returns:
        Obfuscated string
    """
    if not data:
        return ""

    data_len = len(data)

    # Adjust visible parts if they exceed data length
    if prefix_visible + suffix_visible >= data_len:
        if data_len <= 4:
            # Very short string, mask it entirely
            return mask_char * data_len
        else:
            # Adjust to show at most half from each end
            total_visible = data_len // 2
            prefix_visible = total_visible // 2
            suffix_visible = total_visible - prefix_visible

    # Create masked string
    masked_length = data_len - prefix_visible - suffix_visible
    return data[:prefix_visible] + (mask_char * masked_length) + data[-suffix_visible:] if suffix_visible else data[:prefix_visible] + (mask_char * masked_length)


def format_time_period(period_seconds: int) -> str:
    """
    Format a time period in seconds into a human-readable string.

    Args:
        period_seconds: Period in seconds

    Returns:
        Human-readable time period (e.g., "2 hours", "3 days")
    """
    if period_seconds < 60:
        return f"{period_seconds} second{'s' if period_seconds != 1 else ''}"
    elif period_seconds < 3600:
        minutes = period_seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    elif period_seconds < 86400:
        hours = period_seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''}"
    elif period_seconds < 604800:
        days = period_seconds // 86400
        return f"{days} day{'s' if days != 1 else ''}"
    elif period_seconds < 2592000:
        weeks = period_seconds // 604800
        return f"{weeks} week{'s' if weeks != 1 else ''}"
    elif period_seconds < 31536000:
        months = period_seconds // 2592000
        return f"{months} month{'s' if months != 1 else ''}"
    else:
        years = period_seconds // 31536000
        return f"{years} year{'s' if years != 1 else ''}"


def parse_time_period(period_str: str) -> int:
    """
    Parse a human-readable time period into seconds.

    Args:
        period_str: Time period string (e.g., "2h", "3d", "1w")

    Returns:
        Time period in seconds

    Raises:
        ValueError: If the time period format is invalid
    """
    if not period_str:
        raise ValueError("Time period cannot be empty")

    # Get the numeric part and the unit
    period_str = period_str.lower().strip()

    # Check format first
    if not any(period_str.endswith(unit) for unit in ['s', 'm', 'h', 'd', 'w']):
        try:
            # Try to parse as an integer (assumed to be seconds)
            return int(period_str)
        except ValueError:
            raise ValueError(f"Invalid time period format: {period_str}. "
                             f"Expected format: <number><unit> (e.g., 30s, 5m, 2h, 7d, 1w)")

    try:
        value = int(period_str[:-1])
        unit = period_str[-1]

        if unit == 's':
            return value
        elif unit == 'm':
            return value * 60
        elif unit == 'h':
            return value * 3600
        elif unit == 'd':
            return value * 86400
        elif unit == 'w':
            return value * 604800
        else:
            raise ValueError(f"Invalid time unit: {unit}. Expected s, m, h, d, or w.")

    except (ValueError, IndexError) as e:
        raise ValueError(f"Invalid time period format: {period_str}. "
                         f"Expected format: <number><unit> (e.g., 30s, 5m, 2h, 7d, 1w)")


# Private helper functions

def _setup_security_headers(app: Flask) -> None:
    """Configure security headers for all responses."""
    @app.after_request
    def add_security_headers(response):
        return apply_security_headers(response)

    # Generate CSP nonce for each request
    @app.before_request
    def generate_csp_nonce_for_request():
        g.csp_nonce = generate_csp_nonce()


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
        success = initialize_file_monitoring(app, basedir, patterns, interval)
        if success:
            logger.info(f"File integrity monitoring initialized with {len(patterns)} patterns")
            metrics.increment('security.file_integrity_enabled')
        else:
            logger.warning("Failed to initialize file integrity monitoring")
            metrics.increment('security.file_integrity_failed')

    except ImportError:
        logger.warning("File integrity monitoring module not available")
    except Exception as e:
        logger.error(f"Failed to setup file integrity monitoring: {e}")
        metrics.increment('security.file_integrity_error')


def _initialize_security_metrics(app: Flask) -> None:
    """Initialize security metrics collection."""
    try:
        # Import here to avoid circular imports
        from .cs_metrics import initialize_metrics_collection

        # Schedule metrics collection
        initialize_metrics_collection(app)
        logger.info("Security metrics collection initialized")
        metrics.increment('security.metrics_enabled')

    except ImportError:
        logger.warning("Security metrics module not available")
    except Exception as e:
        logger.error(f"Failed to initialize security metrics: {e}")
        metrics.increment('security.metrics_failed')


def _setup_audit_logging(app: Flask) -> None:
    """Configure audit logging for security events."""
    try:
        # Import here to avoid circular imports
        from .cs_audit import initialize_audit_logging

        # Initialize audit logging
        initialize_audit_logging(app)
        logger.info("Security audit logging initialized")
        metrics.increment('security.audit_logging_enabled')

    except ImportError:
        logger.warning("Audit logging module not available")
    except Exception as e:
        logger.error(f"Failed to setup audit logging: {e}")
        metrics.increment('security.audit_logging_failed')


def _setup_session_security(app: Flask) -> None:
    """Configure session security features."""
    try:
        # Import here to avoid circular imports
        from .cs_session import initialize_session_security

        # Initialize session security
        success = initialize_session_security(app)
        if success:
            logger.info("Session security features initialized")
            metrics.increment('security.session_security_enabled')
        else:
            logger.warning("Failed to initialize session security")
            metrics.increment('security.session_security_failed')

    except ImportError:
        logger.warning("Session security module not available")
    except Exception as e:
        logger.error(f"Failed to setup session security: {e}")
        metrics.increment('security.session_security_error')


def _register_security_request_handlers(app: Flask) -> None:
    """Register security handlers for processing requests."""
    try:
        # Import here to avoid circular imports
        from .cs_authentication import check_auth_security
        from .cs_monitoring import check_request_security

        # Register authentication checks
        auth_success = register_security_check_handler(app, check_auth_security)
        if auth_success:
            logger.debug("Registered authentication security check handler")

        # Register request security checks
        req_success = register_security_check_handler(app, check_request_security)
        if req_success:
            logger.debug("Registered request security check handler")

        if auth_success and req_success:
            metrics.increment('security.handlers_registered')
        else:
            metrics.increment('security.handlers_partial')

    except ImportError as e:
        logger.warning(f"Some security handler modules not available: {e}")
        metrics.increment('security.handlers_missing')
    except Exception as e:
        logger.error(f"Failed to register security request handlers: {e}")
        metrics.increment('security.handlers_error')
