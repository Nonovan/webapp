"""
API Endpoints for Security Incident Management.

Provides endpoints for creating, viewing, updating, and managing security incidents
within the Cloud Infrastructure Platform.
"""

import logging
from flask import request, jsonify, current_app, abort, g
from marshmallow import ValidationError
from sqlalchemy.exc import SQLAlchemyError

# Import the central security blueprint from routes.py
from .routes import security_bp

# Core security components
from core.security import require_permission, log_security_event

# Schemas for validation and serialization
from .schemas import (
    incident_schema,
    incidents_schema,
    incident_create_schema,
    incident_update_schema,
    incident_filter_schema,
    # Assuming a schema for adding notes/comments exists or can be simple
    # incident_note_schema
)

# Models
# Adjust import path based on actual model location
try:
    # Use package-level imports
    from models.security import SecurityIncident, AuditLog, User
    from extensions import db # Assuming db is initialized in extensions
    MODELS_AVAILABLE = True
except ImportError as e:
    MODELS_AVAILABLE = False
    db = None
    # Define dummy classes if models are not available for drafting
    class SecurityIncident:
        @staticmethod
        def find_by_id(incident_id): return None
        @staticmethod
        def create(**kwargs): return SecurityIncident(**kwargs)
        @staticmethod
        def get_paginated(**kwargs): return [], 0
        def update(self, **kwargs): pass
        def add_note(self, note: str, user_id: int): pass
        def save(self): pass
        def to_dict(self): return self.__dict__ # Basic representation
        def __init__(self, **kwargs):
            self.id = kwargs.get('id', 1)
            self.title = kwargs.get('title')
            self.incident_type = kwargs.get('incident_type')
            self.description = kwargs.get('description')
            self.severity = kwargs.get('severity', 'medium')
            self.status = kwargs.get('status', 'new')
            self.details = kwargs.get('details', {})
            self.user_id = kwargs.get('user_id')
            self.assigned_to_id = kwargs.get('assigned_to_id')
            self.created_at = kwargs.get('created_at')
            self.updated_at = kwargs.get('updated_at')
            self.resolved_at = kwargs.get('resolved_at')
            self.notes = kwargs.get('notes', [])
            self.user = None # Placeholder for relationship
            self.assignee = None # Placeholder for relationship

    class AuditLog:
        EVENT_SECURITY_INCIDENT_CREATED = "security_incident_created"
        EVENT_SECURITY_INCIDENT_UPDATED = "security_incident_updated"
        EVENT_SECURITY_INCIDENT_NOTE_ADDED = "security_incident_note_added"
        EVENT_SECURITY_INCIDENT_ERROR = "security_incident_error"

    class User:
        @staticmethod
        def find_by_id(user_id): return None

logger = logging.getLogger(__name__)

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
            'status': SecurityIncident.STATUS_OPEN # Default status on creation
        }

        new_incident = SecurityIncident(**incident_data)
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
    Update an existing security incident (e.g., status, severity, assignment).
    Requires 'security:incident:update' permission.
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

        # Handle assignment separately if needed (e.g., check user existence)
        if 'assigned_to_id' in data:
            assignee_id = data['assigned_to_id']
            if assignee_id is not None:
                assignee = User.find_by_id(assignee_id)
                if not assignee:
                    abort(400, description=f"Assignee user with ID {assignee_id} not found.")
            # Model's update or assign_to method should handle this
            # incident.assign_to(assignee_id, assigned_by=getattr(g, 'user', None).id)
            # data.pop('assigned_to_id') # Remove if handled by specific method

        # Update incident fields
        incident.update(**data) # Assuming model has an update method
        db.session.commit()

        # Log the security event
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_INCIDENT_UPDATED,
            description=f"Security incident updated: ID {incident_id}",
            severity="medium",
            user_id=getattr(g, 'user', None).id,
            ip_address=request.remote_addr,
            details={
                "incident_id": incident_id,
                "changes": data,
                "original_values": {k: str(v) for k, v in original_data.items()} # Basic serialization for log
            }
        )
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

# Note: A DELETE endpoint for incidents is generally discouraged.
# Incidents are usually marked as 'closed' or 'merged' rather than deleted.
