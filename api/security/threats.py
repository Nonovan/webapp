"""
API Endpoints for Threat Intelligence and Detection.

Provides endpoints for managing Indicators of Compromise (IOCs) and viewing
threat detection events within the Cloud Infrastructure Platform.

The threat detection system integrates with file integrity monitoring to provide
comprehensive protection against both external and internal threats.
"""

import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple

from flask import request, jsonify, current_app, abort
from marshmallow import ValidationError

# Import the central security blueprint from routes.py
from .routes import security_bp

# Core security components
# Use package-level import as per instructions
from core.security import (
    require_permission,
    log_security_event,
    check_critical_file_integrity,
    get_last_integrity_status
)

# Schemas for validation and serialization
from .schemas import (
    threat_indicator_schema,
    threat_indicators_schema,
    threat_indicator_create_schema,
    threat_indicator_update_schema,
    threat_indicator_filter_schema,
    threat_detection_filter_schema
)

# Models (assuming a ThreatIndicator model exists)
# Adjust import path based on actual model location
try:
    # Use package-level imports
    from models.security import ThreatIndicator, AuditLog, SecurityEvent
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
        @staticmethod
        def check_for_matches(value, indicator_type=None): return []
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
        EVENT_FILE_INTEGRITY = "file_integrity"
        EVENT_THREAT_DETECTION = "threat_detection"

        @staticmethod
        def get_events_by_type(event_type, **kwargs): return []

    class SecurityEvent:
        @staticmethod
        def get_paginated(**kwargs): return [], 0
        @staticmethod
        def create(**kwargs): return SecurityEvent(**kwargs)

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

@security_bp.route('/threats/detection', methods=['GET'])
@require_permission('security:threat:read')
def list_threat_detections():
    """
    List Threat Detection events with filtering and pagination.

    This endpoint provides a unified view of both external threat detections
    (IOC matches) and internal threats (file integrity violations).

    Requires 'security:threat:read' permission.
    """
    try:
        # If available, attempt to validate query parameters
        if 'threat_detection_filter_schema' in globals():
            query_params = threat_detection_filter_schema.load(request.args)
        else:
            # Default parameters if schema isn't available
            query_params = {
                'page': request.args.get('page', 1, type=int),
                'per_page': request.args.get('per_page', 20, type=int),
                'event_type': request.args.get('event_type'),
                'severity': request.args.get('severity'),
                'start_date': request.args.get('start_date'),
                'end_date': request.args.get('end_date')
            }

        page = query_params.pop('page', 1)
        per_page = query_params.pop('per_page', 20)

        if MODELS_AVAILABLE:
            # Fetch events from database if models are available
            detections, total = SecurityEvent.get_paginated(
                page=page,
                per_page=per_page,
                filters=query_params
            )
        else:
            # Create example detections for API documentation/testing
            detections = [
                {
                    "id": 1,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "ioc_match",
                    "indicator_id": 5,
                    "indicator_value": "198.51.100.10",
                    "source_ip": "10.1.1.5",
                    "severity": "high",
                    "action_taken": "blocked"
                },
                {
                    "id": 2,
                    "timestamp": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
                    "event_type": "ioc_match",
                    "indicator_id": 12,
                    "indicator_value": "bad-domain.com",
                    "source_ip": "10.1.2.8",
                    "severity": "medium",
                    "action_taken": "logged"
                }
            ]

            # Add file integrity violations as threat detections (integrated approach)
            try:
                # Get file integrity status
                integrity_status = get_last_integrity_status()
                if integrity_status and integrity_status.get('has_violations'):
                    for idx, violation in enumerate(integrity_status.get('violations', [])[:3]):
                        # Only include critical and high severity file integrity violations
                        if violation.get('severity') in ('critical', 'high'):
                            detections.append({
                                "id": len(detections) + 1,
                                "timestamp": violation.get('timestamp', datetime.now(timezone.utc).isoformat()),
                                "event_type": "file_integrity_violation",
                                "path": violation.get('path', 'unknown'),
                                "status": violation.get('status', 'modified'),
                                "severity": violation.get('severity', 'high'),
                                "details": {
                                    "expected_hash": violation.get('expected_hash'),
                                    "current_hash": violation.get('current_hash')
                                },
                                "action_taken": "logged"
                            })
            except Exception as e:
                logger.warning(f"Unable to integrate file integrity status: {e}")

            total = len(detections)

        logger.info("Retrieved %d threat detections (page %d)", len(detections), page)
        return jsonify({
            "detections": detections,
            "total": total,
            "page": page,
            "per_page": per_page
        }), 200

    except Exception as e:
        logger.error("Error listing threat detections: %s", e, exc_info=True)
        abort(500, description="Failed to retrieve threat detections.")

@security_bp.route('/threats/check', methods=['POST'])
@require_permission('security:threat:read')
def check_ioc():
    """
    Check if a value matches any known threat indicators.

    This endpoint allows checking arbitrary values against the threat database
    to determine if they match known IOCs.

    Requires 'security:threat:read' permission.
    """
    json_data = request.get_json()
    if not json_data or 'value' not in json_data:
        abort(400, description="Missing required field 'value'")

    value = json_data.get('value')
    indicator_type = json_data.get('type')  # Optional indicator type for stronger matching

    try:
        if MODELS_AVAILABLE:
            matches = ThreatIndicator.check_for_matches(value, indicator_type)
        else:
            # Mock implementation for when models aren't available
            matches = []
            # For testing - simulate a match if the value looks like an IP or domain
            if '.' in value:
                if all(part.isdigit() and int(part) < 256 for part in value.split('.')[:4]):
                    # Looks like an IP
                    matches = [{"id": 999, "indicator_type": "ip", "value": value, "severity": "medium"}]
                elif len(value.split('.')) >= 2:
                    # Looks like a domain
                    matches = [{"id": 998, "indicator_type": "domain", "value": value, "severity": "low"}]

        # If matches were found, log this as a security event
        if matches:
            try:
                log_security_event(
                    event_type=AuditLog.EVENT_THREAT_DETECTION,
                    description=f"Threat indicator match found for {value}",
                    severity="medium" if len(matches) > 0 else "low",
                    details={
                        "value": value,
                        "indicator_type": indicator_type,
                        "matches_count": len(matches),
                        "source": "manual_check",
                        "user_agent": request.headers.get('User-Agent')
                    }
                )
            except Exception as log_error:
                logger.warning(f"Failed to log threat detection event: {log_error}")

        return jsonify({
            "value": value,
            "type": indicator_type,
            "matches": matches,
            "matches_found": len(matches) > 0
        }), 200

    except Exception as e:
        logger.error("Error checking IOC value: %s", e, exc_info=True)
        abort(500, description="Failed to check value against threat indicators.")

@security_bp.route('/threats/integrity', methods=['GET'])
@require_permission('security:integrity:read')
def get_file_integrity_status():
    """
    Get current file integrity status as part of the threat monitoring system.

    This endpoint provides information about the system's file integrity status,
    including any detected modifications to critical files that might indicate
    a security breach or malware.

    Requires 'security:integrity:read' permission.
    """
    try:
        # Perform an on-demand integrity check with current_app if available
        if current_app:
            is_intact, changes = check_critical_file_integrity(current_app)
        else:
            # Fall back to function without app context
            is_intact, changes = check_critical_file_integrity()

        # Filter changes by severity for the response
        critical_changes = [c for c in changes if c.get('severity') == 'critical']
        high_changes = [c for c in changes if c.get('severity') == 'high']
        other_changes = [c for c in changes if c.get('severity') not in ('critical', 'high')]

        # Get the timestamp from the last integrity check
        last_check = datetime.now(timezone.utc).isoformat()
        if changes and len(changes) > 0 and 'timestamp' in changes[0]:
            last_check = changes[0]['timestamp']

        return jsonify({
            "status": "intact" if is_intact else "compromised",
            "last_check": last_check,
            "changes_detected": len(changes),
            "critical_violations": len(critical_changes),
            "high_violations": len(high_changes),
            "other_violations": len(other_changes),
            "violations": {
                "critical": critical_changes,
                "high": high_changes,
                "other": other_changes[:10]  # Limit the number of lower priority changes
            } if not is_intact else {}
        }), 200

    except Exception as e:
        logger.error("Error checking file integrity: %s", e, exc_info=True)
        abort(500, description="Failed to retrieve file integrity status.")

@security_bp.route('/threats/status', methods=['GET'])
@require_permission('security:overview:read')
def get_threat_status_summary():
    """
    Get an overview of the system's current security posture.

    This endpoint provides a comprehensive summary of the security status,
    integrating both external threat intelligence and internal file integrity status.

    Requires 'security:overview:read' permission.
    """
    try:
        # Get recent threat detections (last 24 hours)
        recent_threats = []
        threat_count = 0

        if MODELS_AVAILABLE:
            # Get last 24 hours of threat events from database
            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
            events = AuditLog.get_events_by_type(
                event_type=AuditLog.EVENT_THREAT_DETECTION,
                since=cutoff.isoformat()
            )
            threat_count = len(events)
            recent_threats = events[:5]  # Just the 5 most recent

        # Get file integrity status
        try:
            integrity_status = get_last_integrity_status()
            integrity_ok = not integrity_status.get('has_violations', False)
            integrity_last_check = integrity_status.get('last_check', 'unknown')
            integrity_critical_count = 0
            integrity_high_count = 0

            for violation in integrity_status.get('violations', []):
                if violation.get('severity') == 'critical':
                    integrity_critical_count += 1
                elif violation.get('severity') == 'high':
                    integrity_high_count += 1
        except Exception:
            integrity_ok = False
            integrity_last_check = 'unknown'
            integrity_critical_count = 0
            integrity_high_count = 0

        # Calculate overall threat level based on combined factors
        threat_level = "low"
        if threat_count > 10 or integrity_critical_count > 0:
            threat_level = "critical"
        elif threat_count > 5 or integrity_high_count > 0:
            threat_level = "high"
        elif threat_count > 0 or not integrity_ok:
            threat_level = "medium"

        return jsonify({
            "status": "secure" if threat_level == "low" and integrity_ok else "at_risk",
            "threat_level": threat_level,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "external_threats": {
                "recent_count": threat_count,
                "recent_events": recent_threats
            },
            "internal_threats": {
                "file_integrity": integrity_ok,
                "last_integrity_check": integrity_last_check,
                "critical_violations": integrity_critical_count,
                "high_violations": integrity_high_count
            },
            "recommendations": _generate_security_recommendations(
                threat_level, integrity_ok, integrity_critical_count, integrity_high_count
            )
        }), 200

    except Exception as e:
        logger.error("Error generating threat status summary: %s", e, exc_info=True)
        abort(500, description="Failed to retrieve threat status.")

def _generate_security_recommendations(threat_level: str,
                                      integrity_ok: bool,
                                      critical_violations: int,
                                      high_violations: int) -> List[Dict[str, str]]:
    """
    Generate actionable security recommendations based on the current threat posture.

    Args:
        threat_level: Overall threat level (critical, high, medium, low)
        integrity_ok: Whether file integrity is intact
        critical_violations: Count of critical file integrity violations
        high_violations: Count of high severity file integrity violations

    Returns:
        List of recommendation dictionaries with priority and description
    """
    recommendations = []

    # Add recommendations based on file integrity
    if not integrity_ok:
        if critical_violations > 0:
            recommendations.append({
                "priority": "critical",
                "action": "Investigate critical file integrity violations immediately",
                "description": "Critical system files have been modified, which may indicate a compromise."
            })

        if high_violations > 0:
            recommendations.append({
                "priority": "high",
                "action": "Review high severity file changes",
                "description": "Important system files have been modified and should be verified."
            })

    # Add recommendations based on threat level
    if threat_level == "critical":
        recommendations.append({
            "priority": "critical",
            "action": "Activate incident response plan",
            "description": "Critical security threats detected - follow incident response procedures."
        })
    elif threat_level == "high":
        recommendations.append({
            "priority": "high",
            "action": "Investigate recent security events",
            "description": "Multiple security threats detected requiring investigation."
        })

    # Always include baseline recommendation
    if not recommendations:
        recommendations.append({
            "priority": "low",
            "action": "Continue regular monitoring",
            "description": "No immediate threats detected. Maintain regular security practices."
        })

    return recommendations
