"""
Main routing file for the Security API module.

This file defines the primary Flask Blueprint for the security API (`security_bp`)
and aggregates routes defined in other modules within the `api/security` package,
such as incident management, vulnerability tracking, scanning operations, and
threat intelligence.

The blueprint consolidates all security-related API endpoints under the `/api/security` prefix.
"""

import logging
from flask import Blueprint, jsonify, current_app
from core.security import require_permission, log_security_event

# Initialize module logger
logger = logging.getLogger(__name__)

# Create the main blueprint for the security API
# All routes registered in other files (incidents.py, vulnerabilities.py, etc.)
# should ideally use this blueprint instance.
security_bp = Blueprint('security_api', __name__, url_prefix='/security')

# Import routes from other modules within the security API package.
# These imports ensure that routes defined in these modules are registered with
# the security_bp blueprint and are available when the blueprint is registered with the app
from . import incidents
from . import vulnerabilities
from . import scanning
from . import threats

# Common security routes

@security_bp.route('/status', methods=['GET'])
@require_permission('security:status:read')
def get_security_status():
    """
    Get the overall security status of the system.

    Returns information about the current security posture including:
    - Security component availability
    - Active security incidents count
    - Recent vulnerability detections
    - Latest scan status
    - Threat intelligence updates

    Requires 'security:status:read' permission.

    Returns:
        JSON: Security status information
    """
    try:
        # In a real implementation, this would gather status from various security components
        # Query each subsystem for its status and combine into comprehensive response
        security_status = {
            "status": "healthy",
            "message": "Security systems operational",
            "components": {
                "incident_management": {"status": "operational"},
                "vulnerability_tracking": {"status": "operational"},
                "security_scanning": {"status": "operational"},
                "threat_intelligence": {"status": "operational"}
            },
            "metrics": {
                "active_incidents": current_app.config.get('MOCK_ACTIVE_INCIDENTS', 2),
                "critical_vulnerabilities": current_app.config.get('MOCK_CRITICAL_VULNERABILITIES', 1),
                "recent_scans": current_app.config.get('MOCK_RECENT_SCANS', 5),
                "blocked_threats": current_app.config.get('MOCK_BLOCKED_THREATS', 124)
            },
            "last_updated": current_app.config.get('MOCK_LAST_UPDATED', "2023-08-01T10:30:00Z")
        }

        logger.info("Security status endpoint accessed successfully")
        return jsonify(security_status), 200

    except Exception as e:
        logger.error("Error retrieving security status: %s", e, exc_info=True)
        log_security_event(
            event_type="security_api_error",
            description=f"Error retrieving security status: {str(e)}",
            severity="medium"
        )
        return jsonify({"status": "degraded", "message": "Unable to retrieve complete security status"}), 500

@security_bp.route('/health', methods=['GET'])
def health_check():
    """
    Basic health check endpoint for the security API module.

    This endpoint does not require authentication and is used by
    monitoring systems to verify that the security API is responding.

    Returns:
        JSON: Simple health status
    """
    return jsonify({"status": "ok"}), 200

# Error handlers for security-related errors
@security_bp.errorhandler(403)
def handle_forbidden_error(error):
    """Handle forbidden errors with proper logging."""
    log_security_event(
        event_type="unauthorized_access_attempt",
        description=f"Forbidden access attempt to security endpoint",
        severity="medium"
    )
    return jsonify({"error": "Insufficient permissions to access this resource"}), 403

# Note: This blueprint ('security_bp') needs to be registered with the main Flask app
# in the application factory (e.g., in core/factory.py or app.py).
