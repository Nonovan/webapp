"""
Security baseline management for the Cloud Infrastructure Platform.

This module provides API endpoints for managing security baselines, specifically
file integrity baselines. It enables retrieving baseline status, updating baselines
with changes, and validating baseline integrity.

The baseline operations enforce strict security controls including proper authentication,
authorization checks, rate limiting, and comprehensive audit logging.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from flask import request, jsonify, current_app, g
from marshmallow import ValidationError

from . import security_bp
from .decorators import require_permission
from .schemas import baseline_update_schema
from extensions import metrics, limiter, cache

from core.security.cs_audit import log_security_event
from core.security import (
    check_critical_file_integrity,
    get_last_integrity_status
)

# Import baseline update function
from api.security import update_file_integrity_baseline, validate_baseline_integrity

# Initialize logger
logger = logging.getLogger(__name__)

# Define metrics
baseline_update_counter = metrics.counter(
    'security_baseline_updates_total',
    'Number of file integrity baseline updates',
    labels=['status']
)

baseline_check_counter = metrics.counter(
    'security_baseline_checks_total',
    'Number of file integrity baseline checks',
    labels=['status']
)

# Set rate limits
BASELINE_UPDATE_LIMIT = current_app.config.get('RATELIMIT_SECURITY_BASELINE_UPDATE', "5 per hour")
BASELINE_CHECK_LIMIT = current_app.config.get('RATELIMIT_SECURITY_BASELINE_CHECK', "30 per minute")


@security_bp.route('/baseline', methods=['GET'])
@require_permission('security:baseline:read')
@limiter.limit(BASELINE_CHECK_LIMIT)
def get_baseline_status():
    """
    Get the current status of the file integrity baseline.

    Returns information about the baseline including the last check time,
    verification status, and any detected changes.

    Returns:
        JSON response with baseline status information
    """
    try:
        # Get baseline path from config
        baseline_path = current_app.config.get('FILE_BASELINE_PATH')
        if not baseline_path:
            return jsonify({
                "error": "Baseline path not configured",
                "status": "error"
            }), 500

        # Check baseline integrity
        integrity_valid, issues = validate_baseline_integrity(baseline_path)

        # Get last integrity check status
        last_check = get_last_integrity_status()

        # Prepare response data
        result = {
            "status": "valid" if integrity_valid else "invalid",
            "baseline_path": baseline_path,
            "last_check": {
                "timestamp": last_check.get("timestamp", datetime.now().isoformat()),
                "status": last_check.get("status", "unknown"),
                "changes_detected": last_check.get("changes_detected", 0),
                "critical_changes": last_check.get("critical_changes", 0)
            }
        }

        # Add issues if baseline integrity is invalid
        if not integrity_valid:
            result["issues"] = issues

        # Add metadata from cache if available
        if hasattr(cache, 'get'):
            cached_status = cache.get('security_baseline_status')
            if cached_status:
                result["metadata"] = {
                    "last_updated": cached_status.get("last_updated", "unknown"),
                    "status": cached_status.get("status", "unknown")
                }

        baseline_check_counter.inc(1, labels={"status": "success"})
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Error retrieving baseline status: {str(e)}", exc_info=True)
        baseline_check_counter.inc(1, labels={"status": "error"})
        return jsonify({
            "error": f"Failed to retrieve baseline status: {str(e)}",
            "status": "error"
        }), 500


@security_bp.route('/baseline', methods=['PUT'])
@require_permission('security:baseline:update')
@limiter.limit(BASELINE_UPDATE_LIMIT)
def update_baseline():
    """
    Update the file integrity baseline with approved changes.

    Accepts a list of changes to apply to the baseline, subject to authorization
    and security controls. Validates input, applies changes, and logs the operation.

    Returns:
        JSON response with update status and details
    """
    try:
        # Log the request for audit purposes
        log_security_event(
            event_type="security_baseline_update_requested",
            description="File integrity baseline update requested",
            severity="info",
            details={
                "user_id": g.user.id if hasattr(g, 'user') else "unknown",
                "remote_ip": request.remote_addr
            }
        )

        # Validate request data
        json_data = request.get_json()
        if not json_data:
            return jsonify({
                "error": "No JSON data provided",
                "status": "error"
            }), 400

        try:
            validated_data = baseline_update_schema.load(json_data)
        except ValidationError as err:
            logger.warning(f"Invalid baseline update data: {err.messages}")
            baseline_update_counter.inc(1, labels={"status": "validation_error"})
            return jsonify({
                "error": "Invalid data format",
                "details": err.messages,
                "status": "error"
            }), 400

        # Get baseline path from config
        baseline_path = current_app.config.get('FILE_BASELINE_PATH')
        if not baseline_path:
            return jsonify({
                "error": "Baseline path not configured",
                "status": "error"
            }), 500

        # Extract parameters from validated data
        changes = validated_data.get('changes', [])
        remove_missing = validated_data.get('remove_missing', False)
        auto_update_limit = validated_data.get('auto_update_limit',
            current_app.config.get('FILE_INTEGRITY_AUTO_UPDATE_LIMIT', 10)
        )

        # Verify changes are not excessive
        max_changes = current_app.config.get('BASELINE_MAX_CHANGES_PER_UPDATE', 100)
        if len(changes) > max_changes:
            baseline_update_counter.inc(1, labels={"status": "too_many_changes"})
            return jsonify({
                "error": f"Too many changes requested: {len(changes)}. Maximum allowed: {max_changes}",
                "status": "error"
            }), 400

        # Update baseline
        app = current_app._get_current_object()
        success, message = update_file_integrity_baseline(
            app=app,
            baseline_path=baseline_path,
            changes=changes,
            auto_update_limit=auto_update_limit,
            remove_missing=remove_missing
        )

        # Count successful/failed updates for metrics
        status = "success" if success else "failure"
        baseline_update_counter.inc(1, labels={"status": status})

        if success:
            # Parse update details from message
            updated_files = 0
            removed_files = 0
            try:
                if "updated" in message and "," in message:
                    parts = message.split(",")
                    for part in parts:
                        if "updated" in part:
                            updated_files = int(part.split(":")[1].strip().split(" ")[0])
                        elif "removed" in part:
                            removed_files = int(part.split(":")[1].strip().split(" ")[0])
            except (ValueError, IndexError):
                logger.debug("Couldn't parse exact update counts from message")

            return jsonify({
                "message": message,
                "status": "success",
                "updated_files": updated_files,
                "removed_files": removed_files,
                "baseline_version": datetime.now().isoformat()
            }), 200
        else:
            return jsonify({
                "error": message,
                "status": "error"
            }), 400

    except Exception as e:
        logger.error(f"Error updating baseline: {str(e)}", exc_info=True)
        baseline_update_counter.inc(1, labels={"status": "error"})

        log_security_event(
            event_type="security_baseline_update_error",
            description=f"File integrity baseline update failed with exception: {str(e)}",
            severity="error"
        )

        return jsonify({
            "error": f"Failed to update baseline: {str(e)}",
            "status": "error"
        }), 500


@security_bp.route('/baseline/verify', methods=['POST'])
@require_permission('security:baseline:verify')
@limiter.limit(BASELINE_CHECK_LIMIT)
def verify_baseline_integrity():
    """
    Trigger a verification of file integrity against the baseline.

    Performs an on-demand check of system files against the integrity baseline,
    returning any detected changes or issues.

    Returns:
        JSON response with verification results
    """
    try:
        # Get baseline path from config
        baseline_path = current_app.config.get('FILE_BASELINE_PATH')
        if not baseline_path:
            return jsonify({
                "error": "Baseline path not configured",
                "status": "error"
            }), 500

        # Get optional paths parameter (specific files to check)
        json_data = request.get_json() or {}
        paths_to_check = json_data.get('paths', None)

        # Verify file integrity
        app = current_app._get_current_object()
        integrity_status, changes = check_critical_file_integrity(
            app,
            specific_files=paths_to_check
        )

        # Prepare result data
        result = {
            "timestamp": datetime.now().isoformat(),
            "status": "passed" if integrity_status else "failed",
            "baseline_path": baseline_path,
            "changes_detected": len(changes),
            "changes": changes
        }

        status_label = "passed" if integrity_status else "failed"
        baseline_check_counter.inc(1, labels={"status": status_label})

        # Update last check status in cache for quicker retrieval
        if hasattr(cache, 'set'):
            cache.set('last_integrity_check', {
                "timestamp": result["timestamp"],
                "status": result["status"],
                "changes_detected": result["changes_detected"],
                "critical_changes": sum(1 for c in changes if c.get("severity") == "critical")
            }, timeout=86400)  # Cache for 1 day

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Error verifying baseline integrity: {str(e)}", exc_info=True)
        baseline_check_counter.inc(1, labels={"status": "error"})
        return jsonify({
            "error": f"Failed to verify baseline integrity: {str(e)}",
            "status": "error"
        }), 500
