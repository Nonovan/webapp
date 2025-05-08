"""
Security API Package.

This package contains the Flask Blueprint and API endpoint implementations
for security-related operations within the Cloud Infrastructure Platform.
It covers areas such as security incident management, vulnerability tracking,
security scanning, threat intelligence, and file integrity monitoring.

Endpoints are consolidated under the '/api/security' prefix via the `security_bp` blueprint.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple, Union
from flask import Flask, current_app, request, g

# Import the main blueprint for the security API
from .routes import security_bp

# Import endpoint modules to ensure routes are registered with the blueprint
from . import incidents
from . import scanning
from . import threats
from . import vulnerabilities
from . import baseline
from . import schemas
from .api_sec_constants import *

# Initialize logger for the package
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())  # Avoid "No handler found" warnings

# Import security utilities conditionally to avoid hard dependency
try:
    from core.security import (
        log_security_event, check_critical_file_integrity,
        get_last_integrity_status, validate_security_config
    )
    from core.security.cs_metrics import setup_security_metrics
    from extensions import metrics, db, cache
    SECURITY_UTILS_AVAILABLE = True
except ImportError:
    logger.warning("Core security utilities not fully available; some features may be limited")
    SECURITY_UTILS_AVAILABLE = False

# Import models conditionally to avoid hard dependency
try:
    from models.security import (
        SecurityIncident, SecurityBaseline, SecurityScan,
        Vulnerability, AuditLog, SystemConfig, ThreatIndicator
    )
    from models import db
    MODELS_AVAILABLE = True
except ImportError:
    logger.warning("Security models not fully available; API functionality may be limited")
    MODELS_AVAILABLE = False

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
    - Security policy enforcement
    - Threat intelligence feed integration

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

            # Add threat intelligence metrics
            metrics.counter(
                'security_threat_intelligence_indicators',
                'Total number of threat intelligence indicators',
                labels=['type', 'confidence', 'source']
            )

            # Add security policy metrics
            metrics.counter(
                'security_policy_violations',
                'Security policy violations detected',
                labels=['policy', 'severity']
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
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Add CSP nonce if available in request context
        if hasattr(g, 'csp_nonce'):
            response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{g.csp_nonce}'"

        # Add cache control headers to prevent caching of sensitive security data
        if request.method != 'GET' or request.path.startswith('/api/security/incidents'):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '-1'

        return response

    # Add request tracking for security endpoints
    @security_bp.before_request
    def track_security_request():
        """Track security-related API requests for monitoring and auditing."""
        try:
            g.request_start_time = datetime.now(timezone.utc)

            # Track critical security endpoint access
            critical_endpoints = CRITICAL_ENDPOINTS

            endpoint = request.endpoint
            if endpoint and any(critical in endpoint for critical in critical_endpoints):
                user_id = getattr(g, 'user', {}).get('id', None) if hasattr(g, 'user') else None

                if SECURITY_UTILS_AVAILABLE:
                    log_security_event(
                        event_type=EVENT_CRITICAL_ENDPOINT_ACCESS,
                        description=f"Access to critical security endpoint: {endpoint}",
                        severity="medium",
                        user_id=user_id,
                        details={
                            "endpoint": endpoint,
                            "method": request.method,
                            "ip_address": request.remote_addr,
                            "user_agent": request.user_agent.string
                        }
                    )

        except Exception as e:
            logger.warning(f"Error in security request tracking: {e}")

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
                        "scanning", "threats", "baseline"
                    ]
                }
            )
    except Exception as e:
        logger.warning(f"Could not log security initialization event: {e}")

    _initialized = True
    logger.debug("Security API package initialized successfully")

def update_file_integrity_baseline(app: Flask, baseline_path: str, changes: list,
                                 auto_update_limit: int = AUTO_UPDATE_LIMIT,
                                 remove_missing: bool = False) -> Tuple[bool, str]:
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

        # Validate changes list safety (prevent too many changes at once)
        if len(changes) > auto_update_limit:
            filtered_changes = sorted(
                changes,
                key=lambda c: c.get('severity', 'medium') != 'critical'
            )[:auto_update_limit]
            skipped_count = len(changes) - len(filtered_changes)
            logger.warning(f"Limiting baseline updates to {auto_update_limit} changes (skipped {skipped_count})")
            changes = filtered_changes

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
                event_type=EVENT_FILE_INTEGRITY_BASELINE_UPDATED,
                description=f"File integrity baseline updated successfully: {message}",
                severity="info",
                details={
                    "baseline_path": baseline_path,
                    "changes_count": len(changes),
                    "message": message
                }
            )

            # Cache baseline status for performance
            if hasattr(cache, 'set'):
                cache.set(CACHE_KEY_BASELINE_STATUS, {
                    'status': 'updated',
                    'last_updated': datetime.now(timezone.utc).isoformat(),
                    'message': message
                }, timeout=CACHE_TIMEOUT_MEDIUM)  # 1 hour cache

        else:
            metrics.gauge('security_baseline_update_status', 0)  # Failure
            log_security_event(
                event_type=EVENT_FILE_INTEGRITY_BASELINE_UPDATE_FAILED,
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
            event_type=EVENT_FILE_INTEGRITY_BASELINE_UPDATE_FAILED,
            description="File integrity baseline update failed: Required modules not available",
            severity="error"
        )
        return False, "Required security modules not available"
    except Exception as e:
        logger.error(f"Error updating file integrity baseline: {str(e)}")
        log_security_event(
            event_type=EVENT_FILE_INTEGRITY_BASELINE_UPDATE_FAILED,
            description=f"File integrity baseline update failed with exception: {str(e)}",
            severity="error",
            details={"error": str(e)}
        )
        return False, f"Error updating baseline: {str(e)}"

def get_security_status() -> Dict[str, Any]:
    """
    Get the current security status of the system.

    Returns a comprehensive overview of the current security status including
    incident counts, vulnerability metrics, file integrity status, and
    threat intelligence summary.

    Returns:
        Dict with security status information
    """
    try:
        # Default status structure
        status = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_status": STATUS_HEALTHY,
            "components": {
                "incidents": {
                    "active_count": 0,
                    "critical_count": 0
                },
                "vulnerabilities": {
                    "critical_count": 0,
                    "high_count": 0,
                    "total_open": 0
                },
                "scans": {
                    "recent_count": 0,
                    "last_completed": None
                },
                "file_integrity": {
                    "status": STATUS_HEALTHY,
                    "last_check": None,
                    "violations_count": 0
                },
                "threat_intelligence": {
                    "active_threats": 0,
                    "last_updated": None
                }
            }
        }

        # Get incident stats if models available
        if MODELS_AVAILABLE:
            try:
                active_incidents = SecurityIncident.query.filter_by(status='open').count()
                critical_incidents = SecurityIncident.query.filter_by(status='open', severity='critical').count()

                status["components"]["incidents"] = {
                    "active_count": active_incidents,
                    "critical_count": critical_incidents
                }

                # Get vulnerability stats
                critical_vulns = Vulnerability.query.filter_by(status='open', severity='critical').count()
                high_vulns = Vulnerability.query.filter_by(status='open', severity='high').count()

                status["components"]["vulnerabilities"] = {
                    "critical_count": critical_vulns,
                    "high_count": high_vulns,
                    "total_open": Vulnerability.query.filter_by(status='open').count()
                }

                # Get scan stats
                recent_scans = SecurityScan.query.order_by(SecurityScan.created_at.desc()).limit(5).count()
                last_scan = SecurityScan.query.order_by(SecurityScan.created_at.desc()).first()

                status["components"]["scans"] = {
                    "recent_count": recent_scans,
                    "last_completed": last_scan.completed_at.isoformat() if last_scan and last_scan.completed_at else None
                }

            except Exception as e:
                logger.warning(f"Error getting security models data: {e}")

        # Get file integrity status using core security function
        if SECURITY_UTILS_AVAILABLE:
            try:
                integrity_status = get_last_integrity_status()
                status["components"]["file_integrity"] = {
                    "status": integrity_status.get("status", STATUS_HEALTHY),
                    "last_check": integrity_status.get("timestamp"),
                    "violations_count": integrity_status.get("violations_count", 0)
                }
            except Exception as e:
                logger.warning(f"Error getting file integrity status: {e}")

        # Determine overall status based on component statuses
        if status["components"]["incidents"]["critical_count"] > 0:
            status["overall_status"] = STATUS_CRITICAL
        elif status["components"]["vulnerabilities"]["critical_count"] > 0:
            status["overall_status"] = STATUS_ERROR
        elif status["components"]["incidents"]["active_count"] > 0 or \
             status["components"]["vulnerabilities"]["high_count"] > 0 or \
             status["components"]["file_integrity"]["status"] != STATUS_HEALTHY:
            status["overall_status"] = STATUS_WARNING

        # Cache the status if cache is available
        if hasattr(cache, 'set'):
            cache.set(CACHE_KEY_SECURITY_STATUS, status, timeout=CACHE_TIMEOUT_SHORT)

        return status

    except Exception as e:
        logger.error(f"Error generating security status: {e}")
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_status": STATUS_ERROR,
            "error": str(e)
        }

def validate_baseline_integrity(baseline_path: str = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Validate the integrity of the security baseline file itself.

    This is a meta-check to ensure the baseline file has not been tampered with.

    Args:
        baseline_path: Path to the baseline file (uses app config if None)

    Returns:
        Tuple of (integrity_valid, issues_found)
    """
    try:
        if not SECURITY_UTILS_AVAILABLE:
            return False, [{"severity": "error", "message": "Security utilities not available"}]

        # Get application instance from current context
        app = current_app._get_current_object() if current_app else None
        if not app:
            return False, [{"severity": "error", "message": "No application context available"}]

        # Get baseline path from app config if not provided
        if not baseline_path:
            baseline_path = app.config.get('FILE_BASELINE_PATH', DEFAULT_BASELINE_PATH)
            if not baseline_path:
                return False, [{"severity": "error", "message": "Baseline path not configured"}]

        # Check baseline file integrity
        integrity_status, changes = check_critical_file_integrity(
            app,
            specific_files=[baseline_path]
        )

        if not integrity_status and changes:
            return False, changes

        return True, []

    except Exception as e:
        logger.error(f"Error validating baseline integrity: {e}")
        return False, [{"severity": "critical", "message": f"Error validating baseline: {str(e)}"}]

# Define what is available for import from this package
__all__ = [
    "security_bp",
    "init_app",
    "update_file_integrity_baseline",
    "get_security_status",
    "validate_baseline_integrity"
]

# Package version
__version__ = '0.1.1'  # Updated version for enhanced baseline management
