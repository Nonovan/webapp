"""
API Endpoints for Vulnerability Management.

Provides endpoints for creating, viewing, updating, and managing security
vulnerabilities identified within the Cloud Infrastructure Platform.
"""

import logging
from flask import request, jsonify, current_app, abort
from marshmallow import ValidationError

# Import the central security blueprint
from .routes import security_bp

# Core security components
from core.security import require_permission, log_security_event

# Schemas for validation and serialization
from .schemas import (
    vulnerability_schema,
    vulnerabilities_schema,
    vulnerability_create_schema,
    vulnerability_update_schema,
    vulnerability_filter_schema
)

# Models (assuming a Vulnerability model exists)
# Adjust import path based on actual model location
try:
    from models.security.vulnerability import Vulnerability # Assuming this path
    from models.security.audit_log import AuditLog # For event types
    MODELS_AVAILABLE = True
except ImportError:
    MODELS_AVAILABLE = False
    # Define dummy classes if models are not available for drafting
    class Vulnerability:
        @staticmethod
        def find_by_id(vuln_id): return None
        @staticmethod
        def create(**kwargs): return Vulnerability(**kwargs)
        @staticmethod
        def get_paginated(**kwargs): return [], 0
        def update(self, **kwargs): pass
        def delete(self): pass # Or perhaps just mark as deleted/invalid
        def save(self): pass
        def __init__(self, **kwargs):
            self.id = kwargs.get('id', 1)
            self.title = kwargs.get('title')
            self.description = kwargs.get('description')
            self.cve_id = kwargs.get('cve_id')
            self.cvss_score = kwargs.get('cvss_score')
            self.severity = kwargs.get('severity')
            self.status = kwargs.get('status')
            self.affected_resources = kwargs.get('affected_resources', [])
            self.remediation_steps = kwargs.get('remediation_steps')
            self.discovered_at = kwargs.get('discovered_at')
            self.resolved_at = kwargs.get('resolved_at')
            self.created_at = kwargs.get('created_at')
            self.updated_at = kwargs.get('updated_at')

    class AuditLog:
        EVENT_SECURITY_CONFIG_CHANGE = "security_config_change"
        EVENT_SECURITY_INFO = "security_info"
        EVENT_SECURITY_VULNERABILITY = "security_vulnerability"

logger = logging.getLogger(__name__)

# --- Vulnerability Endpoints ---

# Use the imported security_bp
@security_bp.route('', methods=['POST'])
@require_permission('security:vulnerability:create')
def create_vulnerability():
    """
    Create a new Vulnerability record.
    Requires 'security:vulnerability:create' permission.
    """
    if not MODELS_AVAILABLE:
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    if not json_data:
        abort(400, description="No input data provided.")

    try:
        data = vulnerability_create_schema.load(json_data)
    except ValidationError as err:
        logger.warning(f"Validation error creating vulnerability: {err.messages}")
        return jsonify(err.messages), 400

    # Optional: Check for duplicates based on title, CVE, or other criteria if needed

    try:
        new_vulnerability = Vulnerability.create(**data)
        new_vulnerability.save() # Persist to database

        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_VULNERABILITY,
            description=f"Vulnerability created: {data.get('cve_id', data['title'])}",
            severity=data.get('severity', 'medium'), # Use severity from data
            details=data
        )
        logger.info(f"Vulnerability created: ID {new_vulnerability.id}")
        return jsonify(vulnerability_schema.dump(new_vulnerability)), 201

    except Exception as e:
        logger.error(f"Error creating vulnerability: {e}", exc_info=True)
        abort(500, description="Failed to create vulnerability.")

@security_bp.route('', methods=['GET'])
@require_permission('security:vulnerability:read')
def list_vulnerabilities():
    """
    List Vulnerabilities with filtering and pagination.
    Requires 'security:vulnerability:read' permission.
    """
    if not MODELS_AVAILABLE:
        return jsonify({"error": "Model layer not available"}), 500

    try:
        # Validate query parameters using the filter schema
        query_params = vulnerability_filter_schema.load(request.args)
    except ValidationError as err:
        logger.warning(f"Validation error listing vulnerabilities: {err.messages}")
        return jsonify(err.messages), 400

    try:
        page = query_params.pop('page', 1)
        per_page = query_params.pop('per_page', 20)
        sort_by = query_params.pop('sort_by', 'created_at')
        sort_direction = query_params.pop('sort_direction', 'desc')

        # Pass validated filters to the model/service layer
        vulnerabilities, total = Vulnerability.get_paginated(
            page=page,
            per_page=per_page,
            sort_by=sort_by,
            sort_direction=sort_direction,
            filters=query_params # Pass remaining validated params as filters
        )

        return jsonify({
            "vulnerabilities": vulnerabilities_schema.dump(vulnerabilities),
            "total": total,
            "page": page,
            "per_page": per_page
        }), 200

    except Exception as e:
        logger.error(f"Error listing vulnerabilities: {e}", exc_info=True)
        abort(500, description="Failed to retrieve vulnerabilities.")

@security_bp.route('/<int:vuln_id>', methods=['GET'])
@require_permission('security:vulnerability:read')
def get_vulnerability(vuln_id):
    """
    Get details of a specific Vulnerability.
    Requires 'security:vulnerability:read' permission.
    """
    if not MODELS_AVAILABLE:
        return jsonify({"error": "Model layer not available"}), 500

    vulnerability = Vulnerability.find_by_id(vuln_id)
    if not vulnerability:
        logger.warning(f"Vulnerability with ID {vuln_id} not found.")
        abort(404, description="Vulnerability not found.")

    return jsonify(vulnerability_schema.dump(vulnerability)), 200

@security_bp.route('/<int:vuln_id>', methods=['PATCH'])
@require_permission('security:vulnerability:update')
def update_vulnerability(vuln_id):
    """
    Update an existing Vulnerability.
    Requires 'security:vulnerability:update' permission.
    """
    if not MODELS_AVAILABLE:
        return jsonify({"error": "Model layer not available"}), 500

    vulnerability = Vulnerability.find_by_id(vuln_id)
    if not vulnerability:
        logger.warning(f"Attempt to update non-existent vulnerability ID {vuln_id}")
        abort(404, description="Vulnerability not found.")

    json_data = request.get_json()
    if not json_data:
        abort(400, description="No input data provided.")

    try:
        # Validate only the fields provided for update
        data = vulnerability_update_schema.load(json_data, partial=True)
    except ValidationError as err:
        logger.warning(f"Validation error updating vulnerability ID {vuln_id}: {err.messages}")
        return jsonify(err.messages), 400

    if not data:
         abort(400, description="No valid fields provided for update.")

    try:
        vulnerability.update(**data)
        vulnerability.save() # Persist changes

        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_VULNERABILITY,
            description=f"Vulnerability updated: ID {vuln_id}",
            severity=data.get('severity', vulnerability.severity), # Use new or existing severity
            details={"id": vuln_id, "changes": data}
        )
        logger.info(f"Vulnerability updated: ID {vuln_id}")
        return jsonify(vulnerability_schema.dump(vulnerability)), 200

    except Exception as e:
        logger.error(f"Error updating vulnerability ID {vuln_id}: {e}", exc_info=True)
        abort(500, description="Failed to update vulnerability.")

@security_bp.route('/<int:vuln_id>', methods=['DELETE'])
@require_permission('security:vulnerability:delete')
def delete_vulnerability(vuln_id):
    """
    Delete a Vulnerability.
    Requires 'security:vulnerability:delete' permission.
    Consider if vulnerabilities should be truly deleted or marked inactive/archived.
    """
    if not MODELS_AVAILABLE:
        return jsonify({"error": "Model layer not available"}), 500

    vulnerability = Vulnerability.find_by_id(vuln_id)
    if not vulnerability:
        logger.warning(f"Attempt to delete non-existent vulnerability ID {vuln_id}")
        abort(404, description="Vulnerability not found.")

    try:
        vuln_info = f"{vulnerability.cve_id or vulnerability.title}" # Get info before deleting
        vulnerability.delete() # Remove from database or mark inactive

        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_CONFIG_CHANGE, # Or a dedicated delete event
            description=f"Vulnerability deleted: {vuln_info}",
            severity="medium",
            details={"id": vuln_id, "title": vulnerability.title, "cve_id": vulnerability.cve_id}
        )
        logger.info(f"Vulnerability deleted: ID {vuln_id}")
        return '', 204 # No Content

    except Exception as e:
        logger.error(f"Error deleting vulnerability ID {vuln_id}: {e}", exc_info=True)
        abort(500, description="Failed to delete vulnerability.")
