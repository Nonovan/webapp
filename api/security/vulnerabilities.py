"""
API Endpoints for Vulnerability Management.

Provides endpoints for creating, viewing, updating, and managing security
vulnerabilities identified within the Cloud Infrastructure Platform.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from flask import request, jsonify, current_app, abort, g
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
    vulnerability_filter_schema,
    vulnerability_bulk_update_schema
)

# Models
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
        @staticmethod
        def find_by_cve(cve_id): return None
        @staticmethod
        def bulk_update(ids, data): return 0
        def update(self, **kwargs): pass
        def delete(self): pass # Or perhaps just mark as deleted/invalid
        def save(self): pass
        def get_risk_score(self): return self.cvss_score or 5.0
        def __init__(self, **kwargs):
            self.id = kwargs.get('id', 1)
            self.title = kwargs.get('title')
            self.description = kwargs.get('description')
            self.cve_id = kwargs.get('cve_id')
            self.cvss_score = kwargs.get('cvss_score')
            self.cvss_vector = kwargs.get('cvss_vector')
            self.severity = kwargs.get('severity')
            self.status = kwargs.get('status')
            self.affected_resources = kwargs.get('affected_resources', [])
            self.remediation_steps = kwargs.get('remediation_steps')
            self.exploit_available = kwargs.get('exploit_available', False)
            self.exploited_in_wild = kwargs.get('exploited_in_wild', False)
            self.discovered_at = kwargs.get('discovered_at')
            self.resolved_at = kwargs.get('resolved_at')
            self.remediation_deadline = kwargs.get('remediation_deadline')
            self.created_at = kwargs.get('created_at')
            self.updated_at = kwargs.get('updated_at')
            self.asset_criticality = kwargs.get('asset_criticality', 'medium')
            self.external_references = kwargs.get('external_references', [])

    class AuditLog:
        EVENT_SECURITY_CONFIG_CHANGE = "security_config_change"
        EVENT_SECURITY_INFO = "security_info"
        EVENT_SECURITY_VULNERABILITY = "security_vulnerability"
        EVENT_SECURITY_VULNERABILITY_BULK_UPDATE = "security_vulnerability_bulk_update"

logger = logging.getLogger(__name__)

# --- Helper Functions ---

def calculate_severity_from_cvss(cvss_score: float) -> str:
    """
    Calculate severity level based on CVSS score.

    Args:
        cvss_score: CVSS score (0.0 to 10.0)

    Returns:
        Severity level string (critical, high, medium, low, or info)
    """
    if not isinstance(cvss_score, (int, float)):
        return 'medium'

    if cvss_score >= 9.0:
        return 'critical'
    elif cvss_score >= 7.0:
        return 'high'
    elif cvss_score >= 4.0:
        return 'medium'
    elif cvss_score > 0.0:
        return 'low'
    else:
        return 'info'

def calculate_remediation_timeframe(severity: str,
                                  exploit_available: bool = False,
                                  exploited_in_wild: bool = False,
                                  asset_criticality: str = 'medium') -> int:
    """
    Calculate recommended remediation timeframe in days.

    Args:
        severity: Vulnerability severity level
        exploit_available: Whether exploit code is publicly available
        exploited_in_wild: Whether vulnerability is actively exploited
        asset_criticality: Criticality of affected assets

    Returns:
        Recommended timeframe in days
    """
    # Base timeframes by severity
    timeframes = {
        'critical': 7,  # 1 week
        'high': 30,     # 1 month
        'medium': 90,   # 3 months
        'low': 180,     # 6 months
        'info': 365     # 1 year
    }

    # Get base timeframe from severity
    base_days = timeframes.get(severity.lower(), 90)

    # Reduce timeframe for exploited vulnerabilities
    if exploited_in_wild:
        return min(3, base_days)  # Max 3 days for exploited vulnerabilities

    # Reduce timeframe if exploit is available
    if exploit_available:
        base_days = max(7, base_days // 2)  # At least 7 days, but half of original

    # Further adjust based on asset criticality
    if asset_criticality == 'critical':
        base_days = max(7, base_days // 2)  # At least 7 days, but half of original
    elif asset_criticality == 'high':
        base_days = max(14, int(base_days * 0.7))  # At least 14 days, but 70% of original

    return base_days

def validate_cvss_vector(vector: str) -> bool:
    """
    Validate CVSS vector string format.

    Args:
        vector: CVSS vector string to validate

    Returns:
        True if valid, False otherwise
    """
    # Simplified CVSS v3 vector validation
    cvss_v3_pattern = r'^CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]'

    # Simplified CVSS v2 vector validation
    cvss_v2_pattern = r'^(AV:[LAN]/AC:[LMH]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC])'

    if re.match(cvss_v3_pattern, vector) or re.match(cvss_v2_pattern, vector):
        return True
    return False

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

    # Check for CVE duplicates if CVE ID provided
    if 'cve_id' in data and data['cve_id']:
        existing = Vulnerability.find_by_cve(data['cve_id'])
        if existing:
            logger.info(f"Attempted to create duplicate CVE record: {data['cve_id']}")
            return jsonify({
                "error": "A vulnerability with this CVE ID already exists",
                "existing_id": existing.id
            }), 409

    # Auto-calculate severity from CVSS if provided but severity not specified
    if 'cvss_score' in data and data['cvss_score'] and 'severity' not in data:
        data['severity'] = calculate_severity_from_cvss(data['cvss_score'])

    # Validate CVSS vector if provided
    if 'cvss_vector' in data and data['cvss_vector'] and not validate_cvss_vector(data['cvss_vector']):
        logger.warning(f"Invalid CVSS vector format: {data['cvss_vector']}")
        return jsonify({
            "error": "Invalid CVSS vector format",
            "field": "cvss_vector"
        }), 400

    # Calculate remediation deadline if not provided
    if 'remediation_deadline' not in data:
        severity = data.get('severity', 'medium')
        exploit_available = data.get('exploit_available', False)
        exploited_in_wild = data.get('exploited_in_wild', False)
        asset_criticality = data.get('asset_criticality', 'medium')

        # Calculate days to remediate
        days = calculate_remediation_timeframe(
            severity,
            exploit_available,
            exploited_in_wild,
            asset_criticality
        )

        # Set remediation_deadline to N days from now
        data['remediation_deadline'] = datetime.now(timezone.utc).replace(
            hour=23, minute=59, second=59
        ) + timezone.timedelta(days=days)

    try:
        # Add user who created the vulnerability
        if hasattr(g, 'user') and g.user:
            data['created_by_id'] = g.user.id

        # Add current timestamp
        if 'discovered_at' not in data:
            data['discovered_at'] = datetime.now(timezone.utc)

        new_vulnerability = Vulnerability.create(**data)
        new_vulnerability.save() # Persist to database

        # Security event logging
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_VULNERABILITY,
            description=f"Vulnerability created: {data.get('cve_id', data['title'])}",
            severity=data.get('severity', 'medium'), # Use severity from data
            details={
                "id": new_vulnerability.id,
                "cve_id": data.get('cve_id'),
                "title": data.get('title'),
                "cvss_score": data.get('cvss_score'),
                "severity": data.get('severity'),
                "status": data.get('status', 'open'),
                "affected_resources": data.get('affected_resources', [])
            }
        )

        logger.info(f"Security vulnerability created: ID {new_vulnerability.id}, CVE: {data.get('cve_id', 'N/A')}")
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

@security_bp.route('/statistics', methods=['GET'])
@require_permission('security:vulnerability:read')
def get_vulnerability_statistics():
    """
    Get vulnerability statistics and metrics.
    Requires 'security:vulnerability:read' permission.
    """
    if not MODELS_AVAILABLE:
        return jsonify({"error": "Model layer not available"}), 500

    try:
        # This would query the database for actual statistics in a real implementation
        # For now, we'll return sample statistics

        # Get statistics from context if available, otherwise use mock data
        stats = getattr(g, 'vulnerability_statistics', {})
        if not stats:
            # Mock statistics for development
            stats = {
                "total": current_app.config.get('MOCK_TOTAL_VULNERABILITIES', 142),
                "by_severity": {
                    "critical": current_app.config.get('MOCK_CRITICAL_VULNERABILITIES', 8),
                    "high": current_app.config.get('MOCK_HIGH_VULNERABILITIES', 27),
                    "medium": current_app.config.get('MOCK_MEDIUM_VULNERABILITIES', 56),
                    "low": current_app.config.get('MOCK_LOW_VULNERABILITIES', 41),
                    "info": current_app.config.get('MOCK_INFO_VULNERABILITIES', 10)
                },
                "by_status": {
                    "open": 55,
                    "in_progress": 20,
                    "resolved": 57,
                    "accepted_risk": 5,
                    "false_positive": 5
                },
                "remediation_progress": {
                    "on_time": 72,
                    "at_risk": 18,
                    "overdue": 12
                },
                "recent_trend": "decreasing",
                "top_affected_resources": [
                    {"name": "api-server", "count": 12},
                    {"name": "database-cluster", "count": 9},
                    {"name": "web-app", "count": 7}
                ],
                "updated_at": datetime.now(timezone.utc).isoformat()
            }

        return jsonify(stats), 200

    except Exception as e:
        logger.error(f"Error retrieving vulnerability statistics: {e}", exc_info=True)
        abort(500, description="Failed to retrieve vulnerability statistics.")

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

    # Validate CVSS vector if provided
    if 'cvss_vector' in data and data['cvss_vector'] and not validate_cvss_vector(data['cvss_vector']):
        logger.warning(f"Invalid CVSS vector format: {data['cvss_vector']}")
        return jsonify({
            "error": "Invalid CVSS vector format",
            "field": "cvss_vector"
        }), 400

    # Auto-calculate severity from CVSS if CVSS changed but severity not specified
    if 'cvss_score' in data and data['cvss_score'] and 'severity' not in data:
        data['severity'] = calculate_severity_from_cvss(data['cvss_score'])

    # If status changed to 'resolved', set resolved_at if not provided
    if data.get('status') == 'resolved' and not data.get('resolved_at'):
        data['resolved_at'] = datetime.now(timezone.utc)

    try:
        # Track who last updated the vulnerability
        if hasattr(g, 'user') and g.user:
            data['updated_by_id'] = g.user.id

        # Update vulnerability
        vulnerability.update(**data)
        vulnerability.save() # Persist changes

        # Log the security event with appropriate detail
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_VULNERABILITY,
            description=f"Vulnerability updated: ID {vuln_id}, CVE: {vulnerability.cve_id or 'N/A'}",
            severity=data.get('severity', vulnerability.severity), # Use new or existing severity
            details={
                "id": vuln_id,
                "cve_id": vulnerability.cve_id,
                "title": vulnerability.title,
                "changes": data,
                "status": data.get('status', vulnerability.status)
            }
        )

        logger.info(f"Vulnerability updated: ID {vuln_id}, Fields: {', '.join(data.keys())}")
        return jsonify(vulnerability_schema.dump(vulnerability)), 200

    except Exception as e:
        logger.error(f"Error updating vulnerability ID {vuln_id}: {e}", exc_info=True)
        abort(500, description="Failed to update vulnerability.")

@security_bp.route('/bulk', methods=['PATCH'])
@require_permission('security:vulnerability:update')
def bulk_update_vulnerabilities():
    """
    Update multiple vulnerabilities at once.
    Requires 'security:vulnerability:update' permission.
    """
    if not MODELS_AVAILABLE:
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    if not json_data:
        abort(400, description="No input data provided.")

    try:
        # Validate the bulk update request
        data = vulnerability_bulk_update_schema.load(json_data)
    except ValidationError as err:
        logger.warning(f"Validation error for bulk vulnerability update: {err.messages}")
        return jsonify(err.messages), 400

    vulnerability_ids = data.get('ids', [])
    update_data = data.get('data', {})

    if not vulnerability_ids:
        abort(400, description="No vulnerability IDs provided for update.")

    if not update_data:
        abort(400, description="No update data provided.")

    try:
        # Update vulnerabilities in bulk
        updated_count = Vulnerability.bulk_update(vulnerability_ids, update_data)

        # Log the security event
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_VULNERABILITY_BULK_UPDATE,
            description=f"Bulk vulnerability update: {updated_count} vulnerabilities",
            severity="medium",
            details={
                "vulnerability_ids": vulnerability_ids,
                "update_data": update_data,
                "updated_count": updated_count
            }
        )

        logger.info(f"Bulk vulnerability update: {updated_count} vulnerabilities updated")
        return jsonify({
            "message": f"{updated_count} vulnerabilities updated successfully",
            "updated_count": updated_count
        }), 200

    except Exception as e:
        logger.error(f"Error performing bulk vulnerability update: {e}", exc_info=True)
        abort(500, description="Failed to perform bulk vulnerability update.")

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

        # Log the security event
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_CONFIG_CHANGE, # Or a dedicated delete event
            description=f"Vulnerability deleted: {vuln_info}",
            severity="medium",
            details={
                "id": vuln_id,
                "title": vulnerability.title,
                "cve_id": vulnerability.cve_id,
                "deleted_by": getattr(g.user, 'id', None) if hasattr(g, 'user') else None
            }
        )

        logger.info(f"Vulnerability deleted: ID {vuln_id}")
        return '', 204 # No Content

    except Exception as e:
        logger.error(f"Error deleting vulnerability ID {vuln_id}: {e}", exc_info=True)
        abort(500, description="Failed to delete vulnerability.")

@security_bp.route('/check-cve/<string:cve_id>', methods=['GET'])
@require_permission('security:vulnerability:read')
def check_cve_exists(cve_id):
    """
    Check if a vulnerability with the given CVE ID already exists.
    Requires 'security:vulnerability:read' permission.
    """
    if not MODELS_AVAILABLE:
        return jsonify({"error": "Model layer not available"}), 500

    # Normalize CVE ID format (e.g., convert cve-2023-1234 to CVE-2023-1234)
    normalized_cve = cve_id.upper()
    if not normalized_cve.startswith('CVE-'):
        normalized_cve = f"CVE-{normalized_cve}"

    # Check if the CVE exists
    vulnerability = Vulnerability.find_by_cve(normalized_cve)

    if vulnerability:
        return jsonify({
            "exists": True,
            "vulnerability_id": vulnerability.id,
            "title": vulnerability.title,
            "status": vulnerability.status
        }), 200
    else:
        return jsonify({"exists": False}), 200
