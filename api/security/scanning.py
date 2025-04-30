"""
API Endpoints for Security Scanning Operations.

Provides endpoints for initiating, monitoring, and managing security scans
within the Cloud Infrastructure Platform.
"""

import logging
from flask import request, jsonify, current_app, abort
from marshmallow import ValidationError

# Import the central security blueprint from routes.py
from .routes import security_bp

# Core security components
from core.security import require_permission, log_security_event

# Schemas for validation and serialization
from .schemas import (
    scan_schema,
    scans_schema,
    scan_create_schema,
    scan_update_schema,
    scan_filter_schema
)

# Models (assuming a SecurityScan model exists)
# Adjust import path based on actual model location
try:
    # Use package-level imports
    from models.security import SecurityScan, AuditLog
    MODELS_AVAILABLE = True
except ImportError:
    MODELS_AVAILABLE = False
    # Define dummy classes if models are not available for drafting
    class SecurityScan:
        @staticmethod
        def find_by_id(scan_id): return None
        @staticmethod
        def create(**kwargs): return SecurityScan(**kwargs)
        @staticmethod
        def get_paginated(**kwargs): return [], 0
        def update(self, **kwargs): pass
        def delete(self): pass # Although delete endpoint is not defined, keep for consistency
        def save(self): pass
        def __init__(self, **kwargs):
            self.id = kwargs.get('id', 1)
            self.scan_type = kwargs.get('scan_type')
            self.targets = kwargs.get('targets')
            self.status = kwargs.get('status', 'queued')
            self.profile_id = kwargs.get('profile_id')
            self.options = kwargs.get('options', {})
            self.initiated_by_id = kwargs.get('initiated_by_id')
            self.start_time = kwargs.get('start_time')
            self.end_time = kwargs.get('end_time')
            self.findings_summary = kwargs.get('findings_summary', {})
            self.created_at = kwargs.get('created_at')
            self.updated_at = kwargs.get('updated_at')

    class AuditLog:
        EVENT_SECURITY_SCAN_INITIATED = "security_scan_initiated"
        EVENT_SECURITY_SCAN_STATUS_CHANGE = "security_scan_status_change"
        EVENT_SECURITY_SCAN_ERROR = "security_scan_error"

logger = logging.getLogger(__name__)

# --- Security Scan Endpoints ---

@security_bp.route('/scan', methods=['POST'])
@require_permission('security:scan:create')
def initiate_security_scan():
    """
    Initiate a new security scan.
    Requires 'security:scan:create' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityScan.")
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    if not json_data:
        logger.warning("Initiate scan request received with no JSON data.")
        abort(400, description="No input data provided.")

    try:
        data = scan_create_schema.load(json_data)
    except ValidationError as err:
        logger.warning("Validation error initiating scan: %s", err.messages)
        return jsonify(err.messages), 400

    # TODO: Add logic to interact with a scanning service or background task queue.
    # This might involve creating the scan record first, then triggering the actual scan.
    # For now, we'll just create the record with a 'queued' status.

    try:
        # Assuming user ID is available from the request context (e.g., g.user.id)
        # initiated_by_id = getattr(g, 'user', None).id if hasattr(g, 'user') else None
        initiated_by_id = 1 # Placeholder

        scan_data = {
            **data,
            'status': 'queued',
            'initiated_by_id': initiated_by_id
        }

        new_scan = SecurityScan.create(**scan_data)
        new_scan.save() # Persist to database

        # Log the security event
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_SCAN_INITIATED,
            description=f"Security scan initiated: Type '{data['scan_type']}' on targets {data['targets']}",
            severity="medium",
            details={"scan_id": new_scan.id, **data}
        )

        logger.info("Security scan initiated: ID %s, Type: %s", new_scan.id, data['scan_type'])
        # Return 202 Accepted as the scan is likely asynchronous
        return jsonify(scan_schema.dump(new_scan)), 202

    except Exception as e:
        logger.error("Error initiating security scan: %s", e, exc_info=True)
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_SCAN_ERROR,
            description=f"Failed to initiate security scan: {e}",
            severity="high",
            details=data
        )
        abort(500, description="Failed to initiate security scan.")

@security_bp.route('/scan', methods=['GET'])
@require_permission('security:scan:read')
def list_security_scans():
    """
    List security scans with filtering and pagination.
    Requires 'security:scan:read' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityScan.")
        return jsonify({"error": "Model layer not available"}), 500

    try:
        # Validate query parameters
        query_params = scan_filter_schema.load(request.args)
    except ValidationError as err:
        logger.warning("Validation error listing security scans: %s", err.messages)
        return jsonify(err.messages), 400

    try:
        page = query_params.pop('page', 1)
        per_page = query_params.pop('per_page', 20)
        sort_by = query_params.pop('sort_by', 'created_at')
        sort_direction = query_params.pop('sort_direction', 'desc')

        # Pass validated filters to the model/service layer
        scans, total = SecurityScan.get_paginated(
            page=page,
            per_page=per_page,
            sort_by=sort_by,
            sort_direction=sort_direction,
            filters=query_params # Pass remaining validated params as filters
        )

        logger.debug("Retrieved %d security scans (page %d)", len(scans), page)
        return jsonify({
            "scans": scans_schema.dump(scans),
            "total": total,
            "page": page,
            "per_page": per_page
        }), 200

    except Exception as e:
        logger.error("Error listing security scans: %s", e, exc_info=True)
        abort(500, description="Failed to retrieve security scans.")

@security_bp.route('/scan/<int:scan_id>', methods=['GET'])
@require_permission('security:scan:read')
def get_security_scan(scan_id):
    """
    Get details of a specific security scan.
    Requires 'security:scan:read' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityScan.")
        return jsonify({"error": "Model layer not available"}), 500

    scan = SecurityScan.find_by_id(scan_id)
    if not scan:
        logger.warning("Security scan with ID %s not found.", scan_id)
        abort(404, description="Security scan not found.")

    logger.debug("Retrieved security scan ID %s", scan_id)
    return jsonify(scan_schema.dump(scan)), 200

@security_bp.route('/scan/<int:scan_id>', methods=['PATCH'])
@require_permission('security:scan:update')
def update_security_scan(scan_id):
    """
    Update an existing security scan (e.g., cancel).
    Requires 'security:scan:update' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityScan.")
        return jsonify({"error": "Model layer not available"}), 500

    scan = SecurityScan.find_by_id(scan_id)
    if not scan:
        logger.warning("Attempt to update non-existent security scan ID %s", scan_id)
        abort(404, description="Security scan not found.")

    # Check if scan is in a state that allows update (e.g., cancellation)
    if scan.status not in ['queued', 'in_progress']:
         logger.warning("Attempt to update scan ID %s in non-updatable state: %s", scan_id, scan.status)
         abort(400, description=f"Scan cannot be updated in its current state: {scan.status}")

    json_data = request.get_json()
    if not json_data:
        logger.warning("Update scan request received with no JSON data for ID %s.", scan_id)
        abort(400, description="No input data provided.")

    try:
        # Validate only the fields provided for update (currently only 'status' for cancellation)
        data = scan_update_schema.load(json_data)
    except ValidationError as err:
        logger.warning("Validation error updating scan ID %s: %s", scan_id, err.messages)
        return jsonify(err.messages), 400

    # TODO: Add logic to interact with the scanning service/backend to actually cancel the scan.
    # This might be asynchronous.

    try:
        original_status = scan.status
        scan.update(**data) # Update the status field
        scan.save() # Persist changes

        # Log the status change
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_SCAN_STATUS_CHANGE,
            description=f"Security scan ID {scan_id} status changed from {original_status} to {data['status']}",
            severity="medium",
            details={"scan_id": scan_id, "old_status": original_status, "new_status": data['status']}
        )
        logger.info("Security scan updated: ID %s, Status: %s", scan_id, data['status'])
        return jsonify(scan_schema.dump(scan)), 200

    except Exception as e:
        logger.error("Error updating security scan ID %s: %s", scan_id, e, exc_info=True)
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_SCAN_ERROR,
            description=f"Failed to update security scan ID {scan_id}: {e}",
            severity="high",
            details={"scan_id": scan_id, "update_data": data}
        )
        abort(500, description="Failed to update security scan.")

# Note: The '/api/security/scan/status' endpoint mentioned in some READMEs is not implemented here.
# Getting status is typically handled by retrieving the specific scan details via GET /scan/{id}.
