"""
API Endpoints for Security Incident Management.

Provides endpoints for creating, viewing, updating, and managing security incidents
within the Cloud Infrastructure Platform.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from flask import request, jsonify, current_app, abort, g
from marshmallow import ValidationError
from sqlalchemy.exc import SQLAlchemyError

# Import the central security blueprint from routes.py
from .routes import security_bp

# Core security components
from core.security import require_permission, log_security_event, check_critical_file_integrity
from core.security import get_last_integrity_status

# Schemas for validation and serialization
from .schemas import (
    incident_schema,
    incidents_schema,
    incident_create_schema,
    incident_update_schema,
    incident_filter_schema,
    incident_note_schema,
    incident_status_change_schema,
    incident_phase_change_schema,
    incident_metrics_schema
)

# Models
# Adjust import path based on actual model location
try:
    # Use package-level imports
    from models.security import SecurityIncident, AuditLog, User
    from extensions import db, metrics # Assuming db and metrics are initialized in extensions
    MODELS_AVAILABLE = True
except ImportError as e:
    MODELS_AVAILABLE = False
    db = None
    metrics = None
    # Define dummy classes if models are not available for drafting
    class SecurityIncident:
        # Status constants
        STATUS_OPEN = 'open'
        STATUS_INVESTIGATING = 'investigating'
        STATUS_CONTAINED = 'contained'
        STATUS_ERADICATED = 'eradicated'
        STATUS_RECOVERING = 'recovering'
        STATUS_RESOLVED = 'resolved'
        STATUS_CLOSED = 'closed'
        STATUS_MERGED = 'merged'

        # Phase constants
        PHASE_IDENTIFICATION = 'identification'
        PHASE_CONTAINMENT = 'containment'
        PHASE_ERADICATION = 'eradication'
        PHASE_RECOVERY = 'recovery'
        PHASE_LESSONS_LEARNED = 'lessons_learned'

        # Severity constants
        SEVERITY_CRITICAL = 'critical'
        SEVERITY_HIGH = 'high'
        SEVERITY_MEDIUM = 'medium'
        SEVERITY_LOW = 'low'

        @staticmethod
        def find_by_id(incident_id): return None
        @staticmethod
        def create(**kwargs): return SecurityIncident(**kwargs)
        @staticmethod
        def get_paginated(**kwargs): return [], 0
        @staticmethod
        def search(**kwargs): return [], 0
        @staticmethod
        def get_active_incidents(): return []
        @staticmethod
        def get_incidents_by_severity(severity): return []
        @staticmethod
        def get_breached_sla_incidents(): return []
        @staticmethod
        def get_unassigned_incidents(): return []
        def update(self, **kwargs): pass
        def add_note(self, note: str, user_id: int): pass
        def assign_to(self, user_id: int, assigned_by: Optional[int] = None): pass
        def change_status(self, new_status: str, reason: str, user_id: Optional[int] = None): pass
        def change_phase(self, new_phase: str, reason: str, user_id: Optional[int] = None): pass
        def escalate(self, new_severity: str, reason: str, user_id: Optional[int] = None): pass
        def resolve(self, resolution: str, user_id: Optional[int] = None): pass
        def reopen(self, reason: str, user_id: Optional[int] = None): pass
        def close(self, reason: Optional[str] = None, user_id: Optional[int] = None): pass
        def merge_into(self, parent_incident_id: int, reason: str, user_id: Optional[int] = None): pass
        def add_related_incident(self, related_incident_id: int): pass
        def add_affected_resource(self, resource_type: str, resource_id: str, details: Optional[Dict] = None): pass
        def save(self): pass
        def to_dict(self): return self.__dict__ # Basic representation
        def __init__(self, **kwargs):
            self.id = kwargs.get('id', 1)
            self.title = kwargs.get('title')
            self.incident_type = kwargs.get('incident_type')
            self.description = kwargs.get('description')
            self.severity = kwargs.get('severity', 'medium')
            self.status = kwargs.get('status', 'open')
            self.phase = kwargs.get('phase', 'identification')
            self.details = kwargs.get('details', {})
            self.user_id = kwargs.get('user_id')
            self.assigned_to = kwargs.get('assigned_to')
            self.created_at = kwargs.get('created_at')
            self.updated_at = kwargs.get('updated_at')
            self.resolved_at = kwargs.get('resolved_at')
            self.notes = kwargs.get('notes', [])
            self.affected_resources = kwargs.get('affected_resources', [])
            self.related_incidents = kwargs.get('related_incidents', [])
            self.tags = kwargs.get('tags', [])
            self.user = None # Placeholder for relationship
            self.assignee = None # Placeholder for relationship

    class AuditLog:
        EVENT_SECURITY_INCIDENT_CREATED = "security_incident_created"
        EVENT_SECURITY_INCIDENT_UPDATED = "security_incident_updated"
        EVENT_SECURITY_INCIDENT_NOTE_ADDED = "security_incident_note_added"
        EVENT_SECURITY_INCIDENT_STATUS_CHANGED = "security_incident_status_changed"
        EVENT_SECURITY_INCIDENT_PHASE_CHANGED = "security_incident_phase_changed"
        EVENT_SECURITY_INCIDENT_ESCALATED = "security_incident_escalated"
        EVENT_SECURITY_INCIDENT_ASSIGNED = "security_incident_assigned"
        EVENT_SECURITY_INCIDENT_RESOLVED = "security_incident_resolved"
        EVENT_SECURITY_INCIDENT_REOPENED = "security_incident_reopened"
        EVENT_SECURITY_INCIDENT_CLOSED = "security_incident_closed"
        EVENT_SECURITY_INCIDENT_MERGED = "security_incident_merged"
        EVENT_SECURITY_INCIDENT_ERROR = "security_incident_error"

    class User:
        @staticmethod
        def find_by_id(user_id): return None

logger = logging.getLogger(__name__)

# --- Helper Functions ---

def record_incident_metric(action: str, incident_data: Dict[str, Any]) -> None:
    """
    Record metrics for incident-related actions.

    Args:
        action: The action being performed (create, update, resolve, etc.)
        incident_data: Data about the incident
    """
    if metrics is None:
        return

    try:
        # Record count metrics
        metrics.increment(
            'security_incident_actions_total',
            tags={
                'action': action,
                'severity': incident_data.get('severity', 'unknown'),
                'type': incident_data.get('incident_type', 'unknown')
            }
        )

        # Record timing metrics for certain actions
        if action == 'resolve':
            if incident_data.get('created_at') and incident_data.get('resolved_at'):
                created = incident_data['created_at']
                resolved = incident_data['resolved_at']
                if isinstance(created, str):
                    created = datetime.fromisoformat(created.replace('Z', '+00:00'))
                if isinstance(resolved, str):
                    resolved = datetime.fromisoformat(resolved.replace('Z', '+00:00'))

                # Calculate time to resolution in seconds
                resolution_time = (resolved - created).total_seconds()
                metrics.timing(
                    'security_incident_resolution_time',
                    resolution_time,
                    tags={
                        'severity': incident_data.get('severity', 'unknown'),
                        'type': incident_data.get('incident_type', 'unknown')
                    }
                )
    except Exception as e:
        # Never let metrics recording failure affect core functionality
        logger.warning(f"Failed to record incident metrics: {e}")

def create_incident_from_integrity_violation(violation: Dict[str, Any], user_id: Optional[int] = None) -> Optional[int]:
    """
    Create a security incident from a file integrity violation.

    Args:
        violation: The violation data
        user_id: ID of the user creating the incident (if applicable)

    Returns:
        The ID of the created incident or None if creation failed
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return None

    try:
        # Extract information from the violation
        path = violation.get('path', 'Unknown file')
        status = violation.get('status', 'modified')
        severity_map = {
            'critical': SecurityIncident.SEVERITY_CRITICAL,
            'high': SecurityIncident.SEVERITY_HIGH,
            'medium': SecurityIncident.SEVERITY_MEDIUM,
            'low': SecurityIncident.SEVERITY_LOW
        }
        severity = severity_map.get(violation.get('severity', 'medium'), SecurityIncident.SEVERITY_MEDIUM)

        # Create incident data
        incident_data = {
            'title': f"File Integrity Violation: {path}",
            'incident_type': 'file_integrity_violation',
            'description': f"File integrity check detected {status} file: {path}",
            'severity': severity,
            'status': SecurityIncident.STATUS_OPEN,
            'phase': SecurityIncident.PHASE_IDENTIFICATION,
            'details': {
                'violation': violation,
                'detected_by': 'file_integrity_monitor'
            },
            'user_id': user_id,
            'tags': ['file_integrity', 'system_security']
        }

        # Create the incident
        new_incident = SecurityIncident.create(**incident_data)

        # Add the affected resource
        new_incident.add_affected_resource(
            resource_type='file',
            resource_id=path,
            details={
                'path': path,
                'status': status,
                'expected_hash': violation.get('expected_hash'),
                'current_hash': violation.get('current_hash'),
                'timestamp': violation.get('timestamp')
            }
        )

        db.session.add(new_incident)
        db.session.commit()

        # Log the security event
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_INCIDENT_CREATED,
            description=f"File integrity violation incident created: {path}",
            severity=severity,
            user_id=user_id,
            details={
                "incident_id": new_incident.id,
                "path": path,
                "status": status,
                "violation": violation
            }
        )

        logger.info(f"File integrity violation incident created: ID {new_incident.id}, Path: {path}")
        record_incident_metric('create', incident_data)

        return new_incident.id

    except Exception as e:
        if db:
            db.session.rollback()
        logger.error(f"Error creating incident from integrity violation: {e}", exc_info=True)
        return None

# --- Security Incident Endpoints ---

@security_bp.route('/incidents', methods=['POST'])
@require_permission('security:incident:create')
def create_security_incident():
    """
    Create a new security incident.
    Requires 'security:incident:create' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    if not json_data:
        logger.warning("Create incident request received with no JSON data.")
        abort(400, description="No input data provided.")

    try:
        data = incident_create_schema.load(json_data)
    except ValidationError as err:
        logger.warning("Validation error creating incident: %s", err.messages)
        return jsonify(err.messages), 400

    try:
        # Assuming user ID is available from the request context (e.g., g.user.id)
        user_id = getattr(g, 'user', None).id if hasattr(g, 'user') else None
        ip_address = request.remote_addr

        incident_data = {
            **data,
            'user_id': user_id,
            'ip_address': ip_address,
            'status': SecurityIncident.STATUS_OPEN, # Default status on creation
            'phase': SecurityIncident.PHASE_IDENTIFICATION # Default phase on creation
        }

        new_incident = SecurityIncident.create(**incident_data)

        # Add affected resources if provided
        if 'affected_resources' in data:
            for resource in data['affected_resources']:
                new_incident.add_affected_resource(
                    resource_type=resource.get('type'),
                    resource_id=resource.get('id'),
                    details=resource.get('details')
                )

        db.session.add(new_incident)
        db.session.commit()

        # Log the security event
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_INCIDENT_CREATED,
            description=f"Security incident created: '{data['title']}' (Severity: {data['severity']})",
            severity=data.get('severity', 'medium'), # Use incident severity for log
            user_id=user_id,
            ip_address=ip_address,
            details={"incident_id": new_incident.id, **data}
        )

        # Record metrics
        record_incident_metric('create', incident_data)

        logger.info("Security incident created: ID %s, Title: %s", new_incident.id, data['title'])
        return jsonify(incident_schema.dump(new_incident)), 201

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Database error creating security incident: %s", e, exc_info=True)
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_INCIDENT_ERROR,
            description=f"Database error creating incident '{data.get('title', 'N/A')}': {e}",
            severity="high",
            details=data
        )
        abort(500, description="Failed to create security incident due to database error.")
    except Exception as e:
        db.session.rollback()
        logger.error("Error creating security incident: %s", e, exc_info=True)
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_INCIDENT_ERROR,
            description=f"Failed to create security incident '{data.get('title', 'N/A')}': {e}",
            severity="high",
            details=data
        )
        abort(500, description="Failed to create security incident.")


@security_bp.route('/incidents', methods=['GET'])
@require_permission('security:incident:read')
def list_security_incidents():
    """
    List security incidents with filtering and pagination.
    Requires 'security:incident:read' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    try:
        # Validate query parameters
        query_params = incident_filter_schema.load(request.args)
    except ValidationError as err:
        logger.warning("Validation error listing security incidents: %s", err.messages)
        return jsonify(err.messages), 400

    try:
        page = query_params.pop('page', 1)
        per_page = query_params.pop('per_page', 20)
        sort_by = query_params.pop('sort_by', 'created_at')
        sort_direction = query_params.pop('sort_direction', 'desc')

        # Pass validated filters to the model/service layer
        incidents, total = SecurityIncident.get_paginated(
            page=page,
            per_page=per_page,
            sort_by=sort_by,
            sort_direction=sort_direction,
            filters=query_params # Pass remaining validated params as filters
        )

        logger.debug("Retrieved %d security incidents (page %d)", len(incidents), page)
        return jsonify({
            "incidents": incidents_schema.dump(incidents),
            "total": total,
            "page": page,
            "per_page": per_page
        }), 200

    except SQLAlchemyError as e:
        logger.error("Database error listing security incidents: %s", e, exc_info=True)
        abort(500, description="Failed to retrieve security incidents due to database error.")
    except Exception as e:
        logger.error("Error listing security incidents: %s", e, exc_info=True)
        abort(500, description="Failed to retrieve security incidents.")


@security_bp.route('/incidents/search', methods=['GET'])
@require_permission('security:incident:read')
def search_security_incidents():
    """
    Search security incidents by keyword with filtering.
    Requires 'security:incident:read' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    try:
        q = request.args.get('q', '')
        status = request.args.getlist('status')
        severity = request.args.getlist('severity')
        incident_type = request.args.getlist('incident_type')
        days = int(request.args.get('days', 90))
        limit = min(int(request.args.get('limit', 100)), 500)  # Cap at 500

        incidents, total = SecurityIncident.search(
            query=q,
            status=status,
            severity=severity,
            incident_type=incident_type,
            days=days,
            limit=limit
        )

        logger.debug("Search found %d incidents matching '%s'", total, q)
        return jsonify({
            "incidents": incidents_schema.dump(incidents),
            "total": total,
            "query": q
        }), 200

    except ValueError as e:
        logger.warning("Invalid search parameter: %s", str(e))
        abort(400, description=f"Invalid search parameter: {str(e)}")
    except Exception as e:
        logger.error("Error searching security incidents: %s", e, exc_info=True)
        abort(500, description="Failed to search security incidents.")


@security_bp.route('/incidents/<int:incident_id>', methods=['GET'])
@require_permission('security:incident:read')
def get_security_incident(incident_id):
    """
    Get details of a specific security incident.
    Requires 'security:incident:read' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    try:
        incident = SecurityIncident.find_by_id(incident_id)
        if not incident:
            logger.warning("Security incident with ID %s not found.", incident_id)
            abort(404, description="Security incident not found.")

        logger.debug("Retrieved security incident ID %s", incident_id)
        return jsonify(incident_schema.dump(incident)), 200

    except SQLAlchemyError as e:
        logger.error("Database error retrieving incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to retrieve security incident due to database error.")
    except Exception as e:
        logger.error("Error retrieving incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to retrieve security incident.")


@security_bp.route('/incidents/<int:incident_id>', methods=['PATCH'])
@require_permission('security:incident:update')
def update_security_incident(incident_id):
    """
    Update an existing security incident (e.g., description, severity, tags).
    Requires 'security:incident:update' permission.

    Note: For status changes, phase changes, assignments, etc. use their dedicated endpoints.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    if not json_data:
        logger.warning("Update incident request received with no JSON data for ID %s.", incident_id)
        abort(400, description="No input data provided.")

    try:
        data = incident_update_schema.load(json_data)
    except ValidationError as err:
        logger.warning("Validation error updating incident ID %s: %s", incident_id, err.messages)
        return jsonify(err.messages), 400

    if not data:
         logger.warning("Update incident request for ID %s contained no valid fields.", incident_id)
         abort(400, description="No valid fields provided for update.")

    try:
        incident = SecurityIncident.find_by_id(incident_id)
        if not incident:
            logger.warning("Attempt to update non-existent security incident ID %s", incident_id)
            abort(404, description="Security incident not found.")

        # Store original values for logging changes
        original_data = {field: getattr(incident, field) for field in data.keys()}

        # Update incident fields
        incident.update(**data) # Assuming model has an update method
        db.session.commit()

        # Log the security event
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_INCIDENT_UPDATED,
            description=f"Security incident updated: ID {incident_id}",
            severity="medium",
            user_id=getattr(g, 'user', None).id if hasattr(g, 'user') else None,
            ip_address=request.remote_addr,
            details={
                "incident_id": incident_id,
                "changes": data,
                "original_values": {k: str(v) for k, v in original_data.items()} # Basic serialization for log
            }
        )

        # Record metrics
        record_incident_metric('update', data)

        logger.info("Security incident updated: ID %s", incident_id)
        return jsonify(incident_schema.dump(incident)), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Database error updating incident ID %s: %s", incident_id, e, exc_info=True)
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_INCIDENT_ERROR,
            description=f"Database error updating incident ID {incident_id}: {e}",
            severity="high",
            details={"incident_id": incident_id, "update_data": data}
        )
        abort(500, description="Failed to update security incident due to database error.")
    except Exception as e:
        db.session.rollback()
        logger.error("Error updating security incident ID %s: %s", incident_id, e, exc_info=True)
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_INCIDENT_ERROR,
            description=f"Failed to update security incident ID {incident_id}: {e}",
            severity="high",
            details={"incident_id": incident_id, "update_data": data}
        )
        abort(500, description="Failed to update security incident.")


@security_bp.route('/incidents/<int:incident_id>/status', methods=['POST'])
@require_permission('security:incident:update')
def change_incident_status(incident_id):
    """
    Change the status of a security incident with required reason.
    Requires 'security:incident:update' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    if not json_data:
        logger.warning("Status change request received with no JSON data for ID %s.", incident_id)
        abort(400, description="No input data provided.")

    try:
        data = incident_status_change_schema.load(json_data)
    except ValidationError as err:
        logger.warning("Validation error changing incident status for ID %s: %s", incident_id, err.messages)
        return jsonify(err.messages), 400

    if 'status' not in data or 'reason' not in data:
        abort(400, description="Both 'status' and 'reason' fields are required.")

    try:
        incident = SecurityIncident.find_by_id(incident_id)
        if not incident:
            logger.warning("Attempt to change status of non-existent incident ID %s", incident_id)
            abort(404, description="Security incident not found.")

        user_id = getattr(g, 'user', None).id if hasattr(g, 'user') else None
        new_status = data['status']
        reason = data['reason']

        # Use the model's method to change status
        incident.change_status(new_status=new_status, reason=reason, user_id=user_id)
        db.session.commit()

        # Record metrics
        record_incident_metric('status_change', {'status': new_status, 'incident_id': incident_id})

        logger.info("Security incident status changed: ID %s, New Status: %s", incident_id, new_status)
        return jsonify(incident_schema.dump(incident)), 200

    except ValueError as e:
        db.session.rollback()
        logger.warning("Invalid status change for incident ID %s: %s", incident_id, str(e))
        abort(400, description=str(e))
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Database error changing status for incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to change incident status due to database error.")
    except Exception as e:
        db.session.rollback()
        logger.error("Error changing status for incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to change incident status.")


@security_bp.route('/incidents/<int:incident_id>/phase', methods=['POST'])
@require_permission('security:incident:update')
def change_incident_phase(incident_id):
    """
    Change the phase of a security incident with required notes.
    Requires 'security:incident:update' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    if not json_data:
        logger.warning("Phase change request received with no JSON data for ID %s.", incident_id)
        abort(400, description="No input data provided.")

    try:
        data = incident_phase_change_schema.load(json_data)
    except ValidationError as err:
        logger.warning("Validation error changing incident phase for ID %s: %s", incident_id, err.messages)
        return jsonify(err.messages), 400

    if 'phase' not in data or 'reason' not in data:
        abort(400, description="Both 'phase' and 'reason' fields are required.")

    try:
        incident = SecurityIncident.find_by_id(incident_id)
        if not incident:
            logger.warning("Attempt to change phase of non-existent incident ID %s", incident_id)
            abort(404, description="Security incident not found.")

        user_id = getattr(g, 'user', None).id if hasattr(g, 'user') else None
        new_phase = data['phase']
        reason = data['reason']

        # Use the model's method to change phase
        incident.change_phase(new_phase=new_phase, reason=reason, user_id=user_id)
        db.session.commit()

        # Record metrics
        record_incident_metric('phase_change', {'phase': new_phase, 'incident_id': incident_id})

        logger.info("Security incident phase changed: ID %s, New Phase: %s", incident_id, new_phase)
        return jsonify(incident_schema.dump(incident)), 200

    except ValueError as e:
        db.session.rollback()
        logger.warning("Invalid phase change for incident ID %s: %s", incident_id, str(e))
        abort(400, description=str(e))
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Database error changing phase for incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to change incident phase due to database error.")
    except Exception as e:
        db.session.rollback()
        logger.error("Error changing phase for incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to change incident phase.")


@security_bp.route('/incidents/<int:incident_id>/escalate', methods=['POST'])
@require_permission('security:incident:escalate')
def escalate_incident(incident_id):
    """
    Escalate the severity of a security incident with required reason.
    Requires 'security:incident:escalate' permission (higher than standard update).
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    if not json_data or 'severity' not in json_data or 'reason' not in json_data:
        abort(400, description="Both 'severity' and 'reason' fields are required.")

    try:
        incident = SecurityIncident.find_by_id(incident_id)
        if not incident:
            logger.warning("Attempt to escalate non-existent incident ID %s", incident_id)
            abort(404, description="Security incident not found.")

        user_id = getattr(g, 'user', None).id if hasattr(g, 'user') else None
        new_severity = json_data['severity']
        reason = json_data['reason']

        # Use the model's method to escalate
        incident.escalate(new_severity=new_severity, reason=reason, user_id=user_id)
        db.session.commit()

        # Record metrics
        record_incident_metric('escalate', {
            'severity': new_severity,
            'previous_severity': incident.severity,
            'incident_id': incident_id
        })

        logger.info("Security incident escalated: ID %s, New Severity: %s", incident_id, new_severity)
        return jsonify(incident_schema.dump(incident)), 200

    except ValueError as e:
        db.session.rollback()
        logger.warning("Invalid escalation for incident ID %s: %s", incident_id, str(e))
        abort(400, description=str(e))
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Database error escalating incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to escalate incident due to database error.")
    except Exception as e:
        db.session.rollback()
        logger.error("Error escalating incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to escalate incident.")


@security_bp.route('/incidents/<int:incident_id>/assign', methods=['POST'])
@require_permission('security:incident:assign')
def assign_incident(incident_id):
    """
    Assign a security incident to a user.
    Requires 'security:incident:assign' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    if not json_data or 'assigned_to_id' not in json_data:
        abort(400, description="'assigned_to_id' field is required.")

    try:
        incident = SecurityIncident.find_by_id(incident_id)
        if not incident:
            logger.warning("Attempt to assign non-existent incident ID %s", incident_id)
            abort(404, description="Security incident not found.")

        assignee_id = json_data['assigned_to_id']
        if assignee_id is not None:
            assignee = User.find_by_id(assignee_id)
            if not assignee:
                abort(400, description=f"Assignee user with ID {assignee_id} not found.")

        user_id = getattr(g, 'user', None).id if hasattr(g, 'user') else None

        # Use the model's method to assign
        incident.assign_to(user_id=assignee_id, assigned_by=user_id)
        db.session.commit()

        # Record metrics
        record_incident_metric('assign', {'incident_id': incident_id})

        logger.info("Security incident assigned: ID %s, Assigned To: %s", incident_id, assignee_id)
        return jsonify(incident_schema.dump(incident)), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Database error assigning incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to assign incident due to database error.")
    except Exception as e:
        db.session.rollback()
        logger.error("Error assigning incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to assign incident.")


@security_bp.route('/incidents/<int:incident_id>/resolve', methods=['POST'])
@require_permission('security:incident:update')
def resolve_incident(incident_id):
    """
    Resolve a security incident with required resolution notes.
    Requires 'security:incident:update' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    if not json_data or 'resolution' not in json_data:
        abort(400, description="'resolution' field is required.")

    try:
        incident = SecurityIncident.find_by_id(incident_id)
        if not incident:
            logger.warning("Attempt to resolve non-existent incident ID %s", incident_id)
            abort(404, description="Security incident not found.")

        resolution = json_data['resolution']
        user_id = getattr(g, 'user', None).id if hasattr(g, 'user') else None

        # Use the model's method to resolve
        incident.resolve(resolution=resolution, user_id=user_id)
        db.session.commit()

        # Record metrics
        record_incident_metric('resolve', {
            'incident_id': incident_id,
            'created_at': incident.created_at,
            'resolved_at': incident.resolved_at,
            'severity': incident.severity
        })

        logger.info("Security incident resolved: ID %s", incident_id)
        return jsonify(incident_schema.dump(incident)), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Database error resolving incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to resolve incident due to database error.")
    except Exception as e:
        db.session.rollback()
        logger.error("Error resolving incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to resolve incident.")


@security_bp.route('/incidents/<int:incident_id>/reopen', methods=['POST'])
@require_permission('security:incident:update')
def reopen_incident(incident_id):
    """
    Reopen a previously resolved or closed security incident with required reason.
    Requires 'security:incident:update' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    if not json_data or 'reason' not in json_data:
        abort(400, description="'reason' field is required.")

    try:
        incident = SecurityIncident.find_by_id(incident_id)
        if not incident:
            logger.warning("Attempt to reopen non-existent incident ID %s", incident_id)
            abort(404, description="Security incident not found.")

        reason = json_data['reason']
        user_id = getattr(g, 'user', None).id if hasattr(g, 'user') else None

        # Use the model's method to reopen
        incident.reopen(reason=reason, user_id=user_id)
        db.session.commit()

        # Record metrics
        record_incident_metric('reopen', {'incident_id': incident_id})

        logger.info("Security incident reopened: ID %s", incident_id)
        return jsonify(incident_schema.dump(incident)), 200

    except ValueError as e:
        db.session.rollback()
        logger.warning("Invalid reopen attempt for incident ID %s: %s", incident_id, str(e))
        abort(400, description=str(e))
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Database error reopening incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to reopen incident due to database error.")
    except Exception as e:
        db.session.rollback()
        logger.error("Error reopening incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to reopen incident.")


@security_bp.route('/incidents/<int:incident_id>/comments', methods=['POST'])
@require_permission('security:incident:comment') # Assuming a specific permission
def add_incident_comment(incident_id):
    """
    Add a comment (note) to a specific security incident.
    Requires 'security:incident:comment' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    if not json_data or 'note' not in json_data:
        logger.warning("Add comment request received with no note data for ID %s.", incident_id)
        abort(400, description="No comment data provided ('note' field required).")

    note_text = json_data['note']
    if not isinstance(note_text, str) or len(note_text.strip()) == 0:
         abort(400, description="Comment ('note') must be a non-empty string.")

    try:
        incident = SecurityIncident.find_by_id(incident_id)
        if not incident:
            logger.warning("Attempt to add comment to non-existent incident ID %s", incident_id)
            abort(404, description="Security incident not found.")

        user_id = getattr(g, 'user', None).id if hasattr(g, 'user') else None

        # Use the model's method to add a note
        incident.add_note(note=note_text, user_id=user_id)
        db.session.commit()

        # Log the security event
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_INCIDENT_NOTE_ADDED,
            description=f"Comment added to security incident ID {incident_id}",
            severity="low",
            user_id=user_id,
            ip_address=request.remote_addr,
            details={"incident_id": incident_id, "note_preview": note_text[:100] + ('...' if len(note_text) > 100 else '')}
        )

        # Record metrics
        record_incident_metric('add_note', {'incident_id': incident_id})

        logger.info("Comment added to security incident ID %s", incident_id)
        # Return the updated incident or just a success status
        return jsonify(incident_schema.dump(incident)), 200 # Or return 204 No Content

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Database error adding comment to incident ID %s: %s", incident_id, e, exc_info=True)
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_INCIDENT_ERROR,
            description=f"Database error adding comment to incident ID {incident_id}: {e}",
            severity="high",
            details={"incident_id": incident_id}
        )
        abort(500, description="Failed to add comment due to database error.")
    except Exception as e:
        db.session.rollback()
        logger.error("Error adding comment to incident ID %s: %s", incident_id, e, exc_info=True)
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_INCIDENT_ERROR,
            description=f"Failed to add comment to incident ID {incident_id}: {e}",
            severity="high",
            details={"incident_id": incident_id}
        )
        abort(500, description="Failed to add comment to security incident.")


@security_bp.route('/incidents/<int:incident_id>/close', methods=['POST'])
@require_permission('security:incident:close')
def close_incident(incident_id):
    """
    Close a resolved security incident with optional closing notes.
    Requires 'security:incident:close' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    reason = json_data.get('reason') if json_data else None

    try:
        incident = SecurityIncident.find_by_id(incident_id)
        if not incident:
            logger.warning("Attempt to close non-existent incident ID %s", incident_id)
            abort(404, description="Security incident not found.")

        user_id = getattr(g, 'user', None).id if hasattr(g, 'user') else None

        # Use the model's method to close
        incident.close(reason=reason, user_id=user_id)
        db.session.commit()

        # Record metrics
        record_incident_metric('close', {'incident_id': incident_id})

        logger.info("Security incident closed: ID %s", incident_id)
        return jsonify(incident_schema.dump(incident)), 200

    except ValueError as e:
        db.session.rollback()
        logger.warning("Invalid close attempt for incident ID %s: %s", incident_id, str(e))
        abort(400, description=str(e))
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Database error closing incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to close incident due to database error.")
    except Exception as e:
        db.session.rollback()
        logger.error("Error closing incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to close incident.")


@security_bp.route('/incidents/<int:incident_id>/merge', methods=['POST'])
@require_permission('security:incident:update')
def merge_incident(incident_id):
    """
    Merge this incident into another parent incident.
    Requires 'security:incident:update' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    if not json_data or 'parent_incident_id' not in json_data or 'reason' not in json_data:
        abort(400, description="'parent_incident_id' and 'reason' fields are required.")

    try:
        incident = SecurityIncident.find_by_id(incident_id)
        if not incident:
            logger.warning("Attempt to merge non-existent incident ID %s", incident_id)
            abort(404, description="Security incident not found.")

        parent_id = json_data['parent_incident_id']
        parent = SecurityIncident.find_by_id(parent_id)
        if not parent:
            abort(404, description=f"Parent incident ID {parent_id} not found.")

        if parent_id == incident_id:
            abort(400, description="Cannot merge an incident into itself.")

        reason = json_data['reason']
        user_id = getattr(g, 'user', None).id if hasattr(g, 'user') else None

        # Use the model's method to merge
        incident.merge_into(parent_incident_id=parent_id, reason=reason, user_id=user_id)
        db.session.commit()

        # Record metrics
        record_incident_metric('merge', {
            'incident_id': incident_id,
            'parent_id': parent_id
        })

        logger.info("Security incident merged: ID %s into ID %s", incident_id, parent_id)
        return jsonify({
            "message": f"Incident {incident_id} merged successfully into {parent_id}",
            "merged_incident": incident_schema.dump(incident),
            "parent_incident": incident_schema.dump(parent)
        }), 200

    except ValueError as e:
        db.session.rollback()
        logger.warning("Invalid merge attempt for incident ID %s: %s", incident_id, str(e))
        abort(400, description=str(e))
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error("Database error merging incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to merge incident due to database error.")
    except Exception as e:
        db.session.rollback()
        logger.error("Error merging incident ID %s: %s", incident_id, e, exc_info=True)
        abort(500, description="Failed to merge incident.")


@security_bp.route('/incidents/stats', methods=['GET'])
@require_permission('security:incident:read')
def get_incident_statistics():
    """
    Get statistics about security incidents.
    Requires 'security:incident:read' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    try:
        # Get time range from query parameters, default to 90 days
        days = request.args.get('days', 90, type=int)
        if days <= 0:
            days = 90  # Default if invalid

        # Calculate the cutoff date
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        # Get active incidents by severity
        active_incidents = SecurityIncident.get_active_incidents()

        # Count by severity and status
        open_critical = len([i for i in active_incidents
                          if i.severity == SecurityIncident.SEVERITY_CRITICAL])
        open_high = len([i for i in active_incidents
                      if i.severity == SecurityIncident.SEVERITY_HIGH])
        open_medium = len([i for i in active_incidents
                        if i.severity == SecurityIncident.SEVERITY_MEDIUM])
        open_low = len([i for i in active_incidents
                     if i.severity == SecurityIncident.SEVERITY_LOW])

        # Get breached SLA incidents
        sla_breached = SecurityIncident.get_breached_sla_incidents()

        # Get unassigned incidents
        unassigned = SecurityIncident.get_unassigned_incidents()

        # Build the statistics response
        stats = {
            "summary": {
                "active_incidents": len(active_incidents),
                "sla_breached": len(sla_breached),
                "unassigned": len(unassigned)
            },
            "by_severity": {
                "critical": open_critical,
                "high": open_high,
                "medium": open_medium,
                "low": open_low
            },
            "by_status": {
                # This would be populated from database in real implementation
                "open": len([i for i in active_incidents if i.status == SecurityIncident.STATUS_OPEN]),
                "investigating": len([i for i in active_incidents if i.status == SecurityIncident.STATUS_INVESTIGATING]),
                "contained": len([i for i in active_incidents if i.status == SecurityIncident.STATUS_CONTAINED]),
                "eradicated": len([i for i in active_incidents if i.status == SecurityIncident.STATUS_ERADICATED]),
                "recovering": len([i for i in active_incidents if i.status == SecurityIncident.STATUS_RECOVERING])
            },
            "by_phase": {
                # This would be populated from database in real implementation
                "identification": 0,
                "containment": 0,
                "eradication": 0,
                "recovery": 0,
                "lessons_learned": 0
            },
            "time_period": f"Last {days} days",
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

        return jsonify(stats), 200

    except Exception as e:
        logger.error("Error generating incident statistics: %s", e, exc_info=True)
        abort(500, description="Failed to generate incident statistics.")


@security_bp.route('/incidents/file-integrity-violations', methods=['GET'])
@require_permission('security:integrity:read')
def get_file_integrity_incidents():
    """
    Get all incidents related to file integrity violations.
    Requires 'security:integrity:read' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    try:
        # Filter for file integrity incidents using model's search functionality
        incidents, total = SecurityIncident.search(
            query='',
            incident_type=['file_integrity_violation'],
            limit=100
        )

        logger.debug("Retrieved %d file integrity violation incidents", total)
        return jsonify({
            "incidents": incidents_schema.dump(incidents),
            "total": total
        }), 200

    except Exception as e:
        logger.error("Error retrieving file integrity incidents: %s", e, exc_info=True)
        abort(500, description="Failed to retrieve file integrity incidents.")


@security_bp.route('/incidents/create-from-integrity', methods=['POST'])
@require_permission('security:integrity:create')
def create_from_integrity_violation():
    """
    Create a new security incident from current file integrity violations.
    Requires 'security:integrity:create' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityIncident.")
        return jsonify({"error": "Model layer not available"}), 500

    try:
        # Check for file integrity violations
        is_intact, violations = check_critical_file_integrity(current_app)

        if is_intact or not violations:
            return jsonify({
                "message": "No file integrity violations found. No incident created.",
                "status": "intact"
            }), 200

        # Filter for critical and high severity violations
        important_violations = [v for v in violations
                              if v.get('severity') in ('critical', 'high')]

        if not important_violations:
            return jsonify({
                "message": "No critical or high severity violations found. No incident created.",
                "status": "minor_violations",
                "violations_count": len(violations)
            }), 200

        # Create incidents from violations
        user_id = getattr(g, 'user', None).id if hasattr(g, 'user') else None
        created_incidents = []

        for violation in important_violations:
            incident_id = create_incident_from_integrity_violation(
                violation=violation,
                user_id=user_id
            )
            if incident_id:
                created_incidents.append(incident_id)

        if not created_incidents:
            logger.error("Failed to create any incidents from file integrity violations")
            abort(500, description="Failed to create incidents from file integrity violations.")

        # Get the created incidents for the response
        incidents = []
        for incident_id in created_incidents:
            incident = SecurityIncident.find_by_id(incident_id)
            if incident:
                incidents.append(incident_schema.dump(incident))

        return jsonify({
            "message": f"Created {len(created_incidents)} incidents from file integrity violations",
            "created_incidents": incidents,
            "violations_processed": len(important_violations),
            "total_violations": len(violations)
        }), 201

    except Exception as e:
        logger.error("Error creating incidents from integrity violations: %s", e, exc_info=True)
        abort(500, description="Failed to check file integrity or create incidents.")

# Note: A DELETE endpoint for incidents is generally discouraged.
# Incidents are usually marked as 'closed' or 'merged' rather than deleted.
