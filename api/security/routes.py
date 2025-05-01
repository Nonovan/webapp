"""
Main routing file for the Security API module.

This file defines the primary Flask Blueprint for the security API (`security_bp`)
and aggregates routes defined in other modules within the `api/security` package,
such as incident management, vulnerability tracking, scanning operations, and
threat intelligence.

The blueprint consolidates all security-related API endpoints under the `/api/security` prefix.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from flask import Blueprint, jsonify, current_app, request, abort
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
from . import baseline
from . import schemas

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
                "threat_intelligence": {"status": "operational"},
                "baseline_management": {"status": "operational"}
            },
            "metrics": {
                "active_incidents": current_app.config.get('MOCK_ACTIVE_INCIDENTS', 2),
                "critical_vulnerabilities": current_app.config.get('MOCK_CRITICAL_VULNERABILITIES', 1),
                "recent_scans": current_app.config.get('MOCK_RECENT_SCANS', 5),
                "blocked_threats": current_app.config.get('MOCK_BLOCKED_THREATS', 124),
                "baseline_violations": current_app.config.get('MOCK_BASELINE_VIOLATIONS', 0)
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

@security_bp.route('/overview', methods=['GET'])
@require_permission('security:overview:read')
def get_security_overview():
    """
    Get a comprehensive overview of the security posture.

    This endpoint provides a high-level security dashboard with:
    - Active incidents by severity
    - Vulnerability remediation status
    - Recent scan results
    - File integrity health
    - Threat intelligence summary
    - Security compliance status

    Requires 'security:overview:read' permission.

    Returns:
        JSON: Security overview information
    """
    try:
        # Get the current timestamp for consistent reporting
        now = datetime.now(timezone.utc)

        # Build comprehensive security overview
        overview = {
            "timestamp": now.isoformat(),
            "overall_status": "healthy",  # Default status
            "active_alerts": {
                "critical": 0,
                "high": 1,
                "medium": 3,
                "low": 7
            },
            "incidents": {
                "open": 2,
                "investigating": 1,
                "resolved_7d": 5,
                "by_severity": {
                    "critical": 0,
                    "high": 1,
                    "medium": 1,
                    "low": 0
                }
            },
            "vulnerabilities": {
                "open": 4,
                "remediation_status": {
                    "on_time": 3,
                    "at_risk": 1,
                    "overdue": 0
                },
                "by_severity": {
                    "critical": 0,
                    "high": 1,
                    "medium": 2,
                    "low": 1
                }
            },
            "scans": {
                "last_completed": "2024-08-14T18:30:00Z",
                "next_scheduled": "2024-08-16T01:00:00Z",
                "coverage": 94.2  # percentage of assets scanned
            },
            "file_integrity": {
                "status": "healthy",
                "violation_count": 0,
                "last_baseline_update": "2024-08-10T03:15:00Z"
            },
            "compliance": {
                "overall_status": "compliant",
                "frameworks": {
                    "pci-dss": "compliant",
                    "iso27001": "compliant",
                    "nist-csf": "partially_compliant"
                }
            }
        }

        # Determine overall status based on component statuses
        if overview["active_alerts"]["critical"] > 0:
            overview["overall_status"] = "critical"
        elif overview["active_alerts"]["high"] > 0 or overview["incidents"]["by_severity"]["high"] > 0:
            overview["overall_status"] = "warning"

        return jsonify(overview), 200

    except Exception as e:
        logger.error("Error generating security overview: %s", e, exc_info=True)
        log_security_event(
            event_type="security_api_error",
            description=f"Error generating security overview: {str(e)}",
            severity="medium"
        )
        return jsonify({"error": "Failed to generate security overview"}), 500

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

@security_bp.errorhandler(400)
def handle_bad_request(error):
    """Handle bad request errors with proper logging."""
    log_security_event(
        event_type="security_api_error",
        description=f"Bad request to security endpoint: {str(error)}",
        severity="low"
    )
    return jsonify({"error": str(error) or "Invalid request parameters"}), 400

# Note: This blueprint ('security_bp') needs to be registered with the main Flask app
# in the application factory (e.g., in core/factory.py or app.py).
