"""
API Endpoints for Threat Intelligence and Detection.

Provides endpoints for managing Indicators of Compromise (IOCs) and viewing
threat detection events within the Cloud Infrastructure Platform.
"""

import logging
from flask import request, jsonify, current_app, abort # Removed Blueprint import as it's now imported
from marshmallow import ValidationError

# Import the central security blueprint from routes.py
from .routes import security_bp

# Core security components
# Use package-level import as per instructions
from core.security import require_permission, log_security_event

# Schemas for validation and serialization
from .schemas import (
    threat_indicator_schema,
    threat_indicators_schema,
    threat_indicator_create_schema,
    threat_indicator_update_schema,
    threat_indicator_filter_schema
)

# Models (assuming a ThreatIndicator model exists)
# Adjust import path based on actual model location
try:
    # Use package-level imports
    from models.security import ThreatIndicator, AuditLog
    MODELS_AVAILABLE = True
except ImportError:
    MODELS_AVAILABLE = False
    # Define dummy classes if models are not available for drafting
    class ThreatIndicator:
        @staticmethod
        def find_by_id(indicator_id): return None
        @staticmethod
        def create(**kwargs): return ThreatIndicator(**kwargs)
        @staticmethod
        def get_paginated(**kwargs): return [], 0
        def update(self, **kwargs): pass
        def delete(self): pass
        def save(self): pass
        def __init__(self, **kwargs):
            self.id = kwargs.get('id', 1)
            self.indicator_type = kwargs.get('indicator_type')
            self.value = kwargs.get('value')
            # Add other fields as needed for schema dump
            self.description = kwargs.get('description')
            self.source = kwargs.get('source')
            self.severity = kwargs.get('severity', 'medium')
            self.confidence = kwargs.get('confidence', 50)
            self.tags = kwargs.get('tags', [])
            self.first_seen = kwargs.get('first_seen')
            self.last_seen = kwargs.get('last_seen')
            self.is_active = kwargs.get('is_active', True)
            self.created_at = kwargs.get('created_at')
            self.updated_at = kwargs.get('updated_at')

    class AuditLog:
        EVENT_SECURITY_CONFIG_CHANGE = "security_config_change"
        EVENT_SECURITY_INFO = "security_info"

logger = logging.getLogger(__name__)

# --- Threat Indicator (IOC) Endpoints ---
# Routes are now registered on the imported security_bp

@security_bp.route('/threats/ioc', methods=['POST']) # Updated route prefix to match central blueprint
@require_permission('security:threat:create')
def create_threat_indicator():
    """
    Create a new Threat Indicator (IOC).
    Requires 'security:threat:create' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for ThreatIndicator.")
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    if not json_data:
        logger.warning("Create threat indicator request received with no JSON data.")
        abort(400, description="No input data provided.")

    try:
        data = threat_indicator_create_schema.load(json_data)
    except ValidationError as err:
        logger.warning("Validation error creating threat indicator: %s", err.messages)
        return jsonify(err.messages), 400

    # Check for duplicates (optional, based on requirements)
    # existing = ThreatIndicator.find_by_value_and_type(data['value'], data['indicator_type'])
    # if existing:
    #     logger.info("Attempted to create duplicate threat indicator: %s - %s", data['indicator_type'], data['value'])
    #     return jsonify({"error": "Threat indicator with this value and type already exists"}), 409

    try:
        new_indicator = ThreatIndicator.create(**data)
        new_indicator.save() # Persist to database

        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_CONFIG_CHANGE,
            description=f"Threat indicator created: {data['indicator_type']} - {data['value']}",
            severity="medium",
            details=data
        )
        logger.info("Threat indicator created: ID %s", new_indicator.id)
        return jsonify(threat_indicator_schema.dump(new_indicator)), 201

    except Exception as e:
        logger.error("Error creating threat indicator: %s", e, exc_info=True)
        abort(500, description="Failed to create threat indicator.")

@security_bp.route('/threats/ioc', methods=['GET']) # Updated route prefix
@require_permission('security:threat:read')
def list_threat_indicators():
    """
    List Threat Indicators (IOCs) with filtering and pagination.
    Requires 'security:threat:read' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for ThreatIndicator.")
        return jsonify({"error": "Model layer not available"}), 500

    try:
        # Validate query parameters
        query_params = threat_indicator_filter_schema.load(request.args)
    except ValidationError as err:
        logger.warning("Validation error listing threat indicators: %s", err.messages)
        return jsonify(err.messages), 400

    try:
        page = query_params.pop('page', 1)
        per_page = query_params.pop('per_page', 20)
        sort_by = query_params.pop('sort_by', 'created_at')
        sort_direction = query_params.pop('sort_direction', 'desc')

        # Pass validated filters to the model/service layer
        indicators, total = ThreatIndicator.get_paginated(
            page=page,
            per_page=per_page,
            sort_by=sort_by,
            sort_direction=sort_direction,
            filters=query_params # Pass remaining validated params as filters
        )

        logger.debug("Retrieved %d threat indicators (page %d)", len(indicators), page)
        return jsonify({
            "indicators": threat_indicators_schema.dump(indicators),
            "total": total,
            "page": page,
            "per_page": per_page
        }), 200

    except Exception as e:
        logger.error("Error listing threat indicators: %s", e, exc_info=True)
        abort(500, description="Failed to retrieve threat indicators.")

@security_bp.route('/threats/ioc/<int:indicator_id>', methods=['GET']) # Updated route prefix
@require_permission('security:threat:read')
def get_threat_indicator(indicator_id):
    """
    Get details of a specific Threat Indicator (IOC).
    Requires 'security:threat:read' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for ThreatIndicator.")
        return jsonify({"error": "Model layer not available"}), 500

    indicator = ThreatIndicator.find_by_id(indicator_id)
    if not indicator:
        logger.warning("Threat indicator with ID %s not found.", indicator_id)
        abort(404, description="Threat indicator not found.")

    logger.debug("Retrieved threat indicator ID %s", indicator_id)
    return jsonify(threat_indicator_schema.dump(indicator)), 200

@security_bp.route('/threats/ioc/<int:indicator_id>', methods=['PATCH']) # Updated route prefix
@require_permission('security:threat:update')
def update_threat_indicator(indicator_id):
    """
    Update an existing Threat Indicator (IOC).
    Requires 'security:threat:update' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for ThreatIndicator.")
        return jsonify({"error": "Model layer not available"}), 500

    indicator = ThreatIndicator.find_by_id(indicator_id)
    if not indicator:
        logger.warning("Attempt to update non-existent threat indicator ID %s", indicator_id)
        abort(404, description="Threat indicator not found.")

    json_data = request.get_json()
    if not json_data:
        logger.warning("Update threat indicator request received with no JSON data for ID %s.", indicator_id)
        abort(400, description="No input data provided.")

    try:
        # Validate only the fields provided for update
        data = threat_indicator_update_schema.load(json_data, partial=True)
    except ValidationError as err:
        logger.warning("Validation error updating threat indicator ID %s: %s", indicator_id, err.messages)
        return jsonify(err.messages), 400

    if not data:
         logger.warning("Update threat indicator request for ID %s contained no valid fields.", indicator_id)
         abort(400, description="No valid fields provided for update.")

    try:
        indicator.update(**data)
        indicator.save() # Persist changes

        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_CONFIG_CHANGE,
            description=f"Threat indicator updated: ID {indicator_id}",
            severity="medium",
            details={"id": indicator_id, "changes": data}
        )
        logger.info("Threat indicator updated: ID %s", indicator_id)
        return jsonify(threat_indicator_schema.dump(indicator)), 200

    except Exception as e:
        logger.error("Error updating threat indicator ID %s: %s", indicator_id, e, exc_info=True)
        abort(500, description="Failed to update threat indicator.")

@security_bp.route('/threats/ioc/<int:indicator_id>', methods=['DELETE']) # Updated route prefix
@require_permission('security:threat:delete')
def delete_threat_indicator(indicator_id):
    """
    Delete a Threat Indicator (IOC).
    Requires 'security:threat:delete' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for ThreatIndicator.")
        return jsonify({"error": "Model layer not available"}), 500

    indicator = ThreatIndicator.find_by_id(indicator_id)
    if not indicator:
        logger.warning("Attempt to delete non-existent threat indicator ID %s", indicator_id)
        abort(404, description="Threat indicator not found.")

    try:
        indicator_info = f"{indicator.indicator_type} - {indicator.value}" # Get info before deleting
        indicator.delete() # Remove from database

        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_CONFIG_CHANGE,
            description=f"Threat indicator deleted: {indicator_info}",
            severity="medium",
            details={"id": indicator_id, "type": indicator.indicator_type, "value": indicator.value}
        )
        logger.info("Threat indicator deleted: ID %s", indicator_id)
        return '', 204 # No Content

    except Exception as e:
        logger.error("Error deleting threat indicator ID %s: %s", indicator_id, e, exc_info=True)
        abort(500, description="Failed to delete threat indicator.")

# --- Threat Detection Endpoints ---

@security_bp.route('/threats/detection', methods=['GET']) # Updated route prefix
@require_permission('security:threat:read')
def list_threat_detections():
    """
    List Threat Detection events.
    Requires 'security:threat:read' permission.
    (Placeholder - Implementation depends on how detections are stored/logged)
    """
    # This endpoint would likely query a different model or log source
    # (e.g., AuditLog filtered by specific event types, or a dedicated DetectionEvent model)
    # Filtering and pagination should be added similar to list_threat_indicators.

    logger.info("Listing threat detections (placeholder implementation).")

    # Example placeholder response
    # TODO: Replace with actual implementation querying detection logs/events
    detections = [
        {"id": 1, "timestamp": "2024-07-26T10:00:00Z", "indicator_id": 5, "indicator_value": "198.51.100.10", "source_ip": "10.1.1.5", "severity": "high", "action_taken": "blocked"},
        {"id": 2, "timestamp": "2024-07-26T11:30:00Z", "indicator_id": 12, "indicator_value": "bad-domain.com", "source_ip": "10.1.2.8", "severity": "medium", "action_taken": "logged"}
    ]
    total = len(detections)
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    # Basic pagination for example
    start = (page - 1) * per_page
    end = start + per_page
    paginated_detections = detections[start:end]

    return jsonify({
        "detections": paginated_detections,
        "total": total,
        "page": page,
        "per_page": per_page
    }), 200

# Removed the note about registering the blueprint as it's handled centrally.
