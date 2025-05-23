"""
Alert API routes for the Cloud Infrastructure Platform.

This module defines RESTful endpoints for creating, retrieving, updating,
and managing alerts across the infrastructure. It provides functionality
for creating new alerts, filtering existing alerts, acknowledging and
resolving alerts, and retrieving alert statistics.

All endpoints implement:
- Input validation using schemas
- Rate limiting to prevent abuse
- Proper error handling and logging
- Authentication and authorization checks
- Comprehensive audit logging
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple

from flask import Blueprint, request, jsonify, current_app, g, abort
from sqlalchemy import desc, func
from sqlalchemy.exc import SQLAlchemyError

from extensions import db, limiter
from core.security import require_permission, log_security_event
from models.alerts import Alert
from models.security import AuditLog
from .schemas import (
    alert_schema,
    alerts_schema,
    alert_create_schema,
    alert_update_schema,
    alert_filter_schema,
    alert_statistics_schema,
    alert_sla_schema,
    alert_sla_response_schema
)
from .helpers import check_sla_compliance, update_sla_compliance_history

# Initialize logger
logger = logging.getLogger(__name__)

# Create blueprint for alert API routes
alerts_api = Blueprint('alerts', __name__, url_prefix='/alerts')

# Define common error handler
def handle_error(e: Exception, error_msg: str, status_code: int = 500) -> tuple:
    """
    Handle exceptions with consistent logging and response format.

    Args:
        e: The exception that was raised
        error_msg: Human-readable error message
        status_code: HTTP status code to return

    Returns:
        Tuple of response and status code
    """
    logger.error(f"{error_msg}: {str(e)}", exc_info=True)

    # Log security event for server errors
    if status_code >= 500:
        log_security_event(
            event_type="alert_api_error",
            description=f"Error in alerts API: {error_msg}",
            severity="medium",
            user_id=g.get('user_id'),
            ip_address=request.remote_addr
        )

    return jsonify({"error": error_msg}), status_code


@alerts_api.route('', methods=['GET'])
@require_permission('alerts:read')
@limiter.limit("60/minute")
def list_alerts():
    """
    Get alerts with filtering options.

    Query Parameters:
        status (str): Filter by alert status (active, acknowledged, resolved)
        severity (str): Filter by severity (critical, high, warning, info)
        service_name (str): Filter by service name
        resource_id (str): Filter by resource ID
        environment (str): Filter by environment
        region (str): Filter by region
        page (int): Page number (default: 1)
        per_page (int): Items per page (default: 20)
        sort_by (str): Field to sort by (default: created_at)
        sort_dir (str): Sort direction (asc, desc) (default: desc)

    Returns:
        JSON: List of alerts with pagination metadata
    """
    try:
        # Get and validate query parameters
        filter_data = {
            'status': request.args.get('status', 'active'),
            'severity': request.args.get('severity'),
            'service_name': request.args.get('service_name'),
            'resource_id': request.args.get('resource_id'),
            'environment': request.args.get('environment'),
            'region': request.args.get('region')
        }

        # Validate filter parameters
        errors = alert_filter_schema.validate({k: v for k, v in filter_data.items() if v is not None})
        if errors:
            return jsonify({"error": "Invalid filter parameters", "details": errors}), 400

        # Pagination parameters
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(int(request.args.get('per_page', 20)), 100)  # Limit to 100 max

        # Sorting parameters
        sort_by = request.args.get('sort_by', 'created_at')
        sort_dir = request.args.get('sort_dir', 'desc')

        if sort_by not in ['created_at', 'severity', 'status', 'service_name']:
            sort_by = 'created_at'
        if sort_dir not in ['asc', 'desc']:
            sort_dir = 'desc'

        # Build query
        query = Alert.query

        # Apply filters
        if filter_data['status']:
            query = query.filter(Alert.status == filter_data['status'])
        if filter_data['severity']:
            query = query.filter(Alert.severity == filter_data['severity'])
        if filter_data['service_name']:
            query = query.filter(Alert.service_name == filter_data['service_name'])
        if filter_data['resource_id']:
            query = query.filter(Alert.resource_id == filter_data['resource_id'])
        if filter_data['environment']:
            query = query.filter(Alert.environment == filter_data['environment'])
        if filter_data['region']:
            query = query.filter(Alert.region == filter_data['region'])

        # Apply sorting
        if sort_dir == 'asc':
            query = query.order_by(getattr(Alert, sort_by).asc())
        else:
            query = query.order_by(getattr(Alert, sort_by).desc())

        # Execute query with pagination
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        # Format results
        alerts = alerts_schema.dump(pagination.items)

        result = {
            'alerts': alerts,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page,
            'per_page': per_page
        }

        return jsonify(result), 200

    except ValueError as e:
        return handle_error(e, "Invalid parameter value", 400)
    except SQLAlchemyError as e:
        return handle_error(e, "Database error retrieving alerts", 500)
    except Exception as e:
        return handle_error(e, "Failed to retrieve alerts", 500)


@alerts_api.route('', methods=['POST'])
@require_permission('alerts:create')
@limiter.limit("120/minute")
def create_alert():
    """
    Create a new alert.

    Request Body:
        alert_type (str): Type of alert
        resource_id (str, optional): ID of affected resource
        service_name (str): Service that generated the alert
        severity (str): Alert severity (critical, high, warning, info)
        message (str): Alert message
        details (dict, optional): Additional alert details
        environment (str): Environment (production, staging, etc.)
        region (str, optional): Region where alert was generated

    Returns:
        JSON: Created alert details
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Validate input data
        errors = alert_create_schema.validate(data)
        if errors:
            return jsonify({"error": "Invalid input data", "details": errors}), 400

        # Add timestamp if not provided
        if 'created_at' not in data:
            data['created_at'] = datetime.utcnow()

        # Set default status to active
        if 'status' not in data:
            data['status'] = 'active'

        # Create new alert
        new_alert = Alert(**data)
        db.session.add(new_alert)
        db.session.commit()

        # Log the event
        log_security_event(
            event_type="alert_created",
            description=f"Alert created: {data.get('alert_type')} - {data.get('severity')}",
            severity=data.get('severity', 'info').lower(),
            user_id=g.get('user_id'),
            ip_address=request.remote_addr,
            details={
                'alert_id': new_alert.id,
                'alert_type': data.get('alert_type'),
                'service_name': data.get('service_name'),
                'resource_id': data.get('resource_id'),
                'environment': data.get('environment')
            }
        )

        logger.info(f"Alert created: ID {new_alert.id}, Type: {data.get('alert_type')}")

        return jsonify(alert_schema.dump(new_alert)), 201

    except SQLAlchemyError as e:
        db.session.rollback()
        return handle_error(e, "Database error creating alert", 500)
    except Exception as e:
        return handle_error(e, "Failed to create alert", 500)


@alerts_api.route('/<int:alert_id>', methods=['GET'])
@require_permission('alerts:read')
@limiter.limit("60/minute")
def get_alert(alert_id):
    """
    Get alert details by ID.

    Args:
        alert_id: ID of the alert to retrieve

    Returns:
        JSON: Alert details
    """
    try:
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({"error": "Alert not found"}), 404

        return jsonify(alert_schema.dump(alert)), 200

    except SQLAlchemyError as e:
        return handle_error(e, "Database error retrieving alert", 500)
    except Exception as e:
        return handle_error(e, f"Failed to retrieve alert {alert_id}", 500)


@alerts_api.route('/<int:alert_id>', methods=['PATCH'])
@require_permission('alerts:update')
@limiter.limit("30/minute")
def update_alert(alert_id):
    """
    Update an existing alert.

    Args:
        alert_id: ID of the alert to update

    Request Body:
        status (str, optional): New alert status
        severity (str, optional): Updated severity
        message (str, optional): Updated message
        details (dict, optional): Updated details

    Returns:
        JSON: Updated alert details
    """
    try:
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({"error": "Alert not found"}), 404

        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Validate input data
        errors = alert_update_schema.validate(data)
        if errors:
            return jsonify({"error": "Invalid input data", "details": errors}), 400

        # Update allowed fields
        allowed_fields = ['status', 'severity', 'message', 'details']
        for field in allowed_fields:
            if field in data:
                setattr(alert, field, data[field])

        # Update timestamps based on status changes
        if 'status' in data:
            if data['status'] == 'acknowledged' and alert.acknowledged_at is None:
                alert.acknowledged_at = datetime.utcnow()
                alert.acknowledged_by = g.get('user_id')
            elif data['status'] == 'resolved' and alert.resolved_at is None:
                alert.resolved_at = datetime.utcnow()
                alert.resolved_by = g.get('user_id')

        db.session.commit()

        # Log the event
        log_security_event(
            event_type="alert_updated",
            description=f"Alert updated: ID {alert_id}",
            severity=alert.severity.lower(),
            user_id=g.get('user_id'),
            ip_address=request.remote_addr,
            details={
                'alert_id': alert_id,
                'status': alert.status,
                'changes': data
            }
        )

        logger.info(f"Alert updated: ID {alert_id}, Status: {alert.status}")

        return jsonify(alert_schema.dump(alert)), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        return handle_error(e, "Database error updating alert", 500)
    except Exception as e:
        return handle_error(e, f"Failed to update alert {alert_id}", 500)


@alerts_api.route('/<int:alert_id>/acknowledge', methods=['POST'])
@require_permission('alerts:acknowledge')
@limiter.limit("30/minute")
def acknowledge_alert(alert_id):
    """
    Acknowledge an alert.

    Args:
        alert_id: ID of the alert to acknowledge

    Request Body:
        note (str, optional): Acknowledgement note

    Returns:
        JSON: Updated alert details
    """
    try:
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({"error": "Alert not found"}), 404

        data = request.get_json() or {}

        # Can only acknowledge active alerts
        if alert.status != 'active':
            return jsonify({"error": "Only active alerts can be acknowledged"}), 400

        # Update alert
        alert.status = 'acknowledged'
        alert.acknowledged_at = datetime.utcnow()
        alert.acknowledged_by = g.get('user_id')

        if 'note' in data:
            alert.acknowledgement_note = data['note']

        db.session.commit()

        # Log the event
        log_security_event(
            event_type="alert_acknowledged",
            description=f"Alert acknowledged: ID {alert_id}",
            severity=alert.severity.lower(),
            user_id=g.get('user_id'),
            ip_address=request.remote_addr,
            details={
                'alert_id': alert_id,
                'alert_type': alert.alert_type,
                'note': data.get('note', '')
            }
        )

        # Check and update SLA compliance after status change
        sla_compliance = check_sla_compliance(alert, check_type='both')
        update_sla_compliance_history(alert, sla_compliance)

        logger.info(f"Alert acknowledged: ID {alert_id}")

        return jsonify(alert_schema.dump(alert)), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        return handle_error(e, "Database error acknowledging alert", 500)
    except Exception as e:
        return handle_error(e, f"Failed to acknowledge alert {alert_id}", 500)


@alerts_api.route('/<int:alert_id>/resolve', methods=['POST'])
@require_permission('alerts:resolve')
@limiter.limit("30/minute")
def resolve_alert(alert_id):
    """
    Resolve an alert.

    Args:
        alert_id: ID of the alert to resolve

    Request Body:
        resolution (str, optional): Resolution details

    Returns:
        JSON: Updated alert details
    """
    try:
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({"error": "Alert not found"}), 404

        data = request.get_json() or {}

        # Can only resolve active or acknowledged alerts
        if alert.status == 'resolved':
            return jsonify({"error": "Alert is already resolved"}), 400

        # Update alert
        alert.status = 'resolved'
        alert.resolved_at = datetime.utcnow()
        alert.resolved_by = g.get('user_id')

        if 'resolution' in data:
            alert.resolution = data['resolution']

        db.session.commit()

        # Log the event
        log_security_event(
            event_type="alert_resolved",
            description=f"Alert resolved: ID {alert_id}",
            severity=alert.severity.lower(),
            user_id=g.get('user_id'),
            ip_address=request.remote_addr,
            details={
                'alert_id': alert_id,
                'alert_type': alert.alert_type,
                'resolution': data.get('resolution', '')
            }
        )

        # Check and update SLA compliance after status change
        sla_compliance = check_sla_compliance(alert, check_type='both')
        update_sla_compliance_history(alert, sla_compliance)

        logger.info(f"Alert resolved: ID {alert_id}")

        return jsonify(alert_schema.dump(alert)), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        return handle_error(e, "Database error resolving alert", 500)
    except Exception as e:
        return handle_error(e, f"Failed to resolve alert {alert_id}", 500)


@alerts_api.route('/<int:alert_id>/sla', methods=['GET'])
@require_permission('alerts:read')
@limiter.limit("30/minute")
def check_alert_sla(alert_id):
    """
    Check SLA compliance for a specific alert.

    Args:
        alert_id: ID of the alert to check

    Query Parameters:
        check_type (str): Type of SLA check to perform (acknowledgement, resolution, both)
        include_history (bool): Whether to include historical compliance data

    Returns:
        JSON: SLA compliance information
    """
    try:
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({"error": "Alert not found"}), 404

        # Parse query parameters
        check_type = request.args.get('check_type', 'both')
        if check_type not in ['acknowledgement', 'resolution', 'both']:
            check_type = 'both'

        include_history = request.args.get('include_history', '').lower() == 'true'

        # Calculate SLA compliance
        compliance_data = check_sla_compliance(
            alert,
            check_type=check_type,
            custom_sla_hours=None  # Use system defaults
        )

        # Format response using schema
        result = {
            'alert_id': alert.id,
            'severity': alert.severity,
            'status': alert.status,
            'created_at': alert.created_at.isoformat(),
            'acknowledged_at': alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
            'resolved_at': alert.resolved_at.isoformat() if alert.resolved_at else None,
            'sla_met': compliance_data.get('sla_met', False),
            'compliance': compliance_data.get('compliance', {}),
            'overall_health': compliance_data.get('overall_health', 0)
        }

        # Include history if requested and available
        if include_history and 'history' in compliance_data:
            result['history'] = compliance_data['history']

        # Log the event (lower level than security events)
        logger.info(f"SLA compliance checked for alert {alert_id}: {result['sla_met']}")

        return jsonify(result), 200

    except SQLAlchemyError as e:
        return handle_error(e, "Database error checking SLA compliance", 500)
    except Exception as e:
        return handle_error(e, f"Failed to check SLA compliance for alert {alert_id}", 500)


@alerts_api.route('/sla/report', methods=['POST'])
@require_permission('alerts:read')
@limiter.limit("10/minute")
def get_sla_compliance_report():
    """
    Generate a comprehensive SLA compliance report across multiple alerts.

    Request Body:
        start_date (str, optional): Start date for report (ISO format)
        end_date (str, optional): End date for report (ISO format)
        environment (str, optional): Filter by environment
        service_name (str, optional): Filter by service name
        severity (str, optional): Filter by severity

    Returns:
        JSON: SLA compliance report with statistics
    """
    try:
        # Parse request parameters
        data = request.get_json() or {}

        # Validate date inputs if provided
        start_date = None
        end_date = None

        if 'start_date' in data:
            try:
                start_date = datetime.fromisoformat(data['start_date'].replace('Z', '+00:00'))
            except ValueError:
                return jsonify({"error": "Invalid start_date format. Use ISO format (YYYY-MM-DDTHH:MM:SS)."}), 400

        if 'end_date' in data:
            try:
                end_date = datetime.fromisoformat(data['end_date'].replace('Z', '+00:00'))
            except ValueError:
                return jsonify({"error": "Invalid end_date format. Use ISO format (YYYY-MM-DDTHH:MM:SS)."}), 400

        # Set default date range if not provided (last 30 days)
        if end_date is None:
            end_date = datetime.utcnow()
        if start_date is None:
            start_date = end_date - timedelta(days=30)

        # Build query with filters
        query = Alert.query.filter(
            Alert.created_at >= start_date,
            Alert.created_at <= end_date
        )

        # Apply additional filters
        if data.get('environment'):
            query = query.filter(Alert.environment == data['environment'])
        if data.get('service_name'):
            query = query.filter(Alert.service_name == data['service_name'])
        if data.get('severity'):
            query = query.filter(Alert.severity == data['severity'])

        # Execute query
        alerts = query.all()

        # Initialize metrics
        total_count = len(alerts)
        acknowledged_count = 0
        resolved_count = 0
        sla_met_count = 0
        sla_missed_count = 0
        avg_acknowledgement_time = 0
        avg_resolution_time = 0

        # Collect alert-specific compliance data and calculate metrics
        compliance_details = []
        total_ack_time = 0
        total_resolve_time = 0

        for alert in alerts:
            # Skip alerts with no meaningful SLA data
            if not alert.created_at:
                continue

            # Check SLA compliance
            compliance_data = check_sla_compliance(alert, check_type='both')

            # Collect details for each alert
            detail = {
                'alert_id': alert.id,
                'severity': alert.severity,
                'service_name': alert.service_name,
                'created_at': alert.created_at.isoformat(),
                'status': alert.status,
                'sla_met': compliance_data.get('sla_met', False)
            }

            # Track metrics
            if compliance_data.get('sla_met', False):
                sla_met_count += 1
            else:
                sla_missed_count += 1

            if alert.status in ('acknowledged', 'resolved'):
                acknowledged_count += 1

            if alert.status == 'resolved':
                resolved_count += 1

            # Track acknowledgement time
            if alert.acknowledged_at:
                ack_time_seconds = (alert.acknowledged_at - alert.created_at).total_seconds()
                detail['acknowledgement_time_seconds'] = ack_time_seconds
                total_ack_time += ack_time_seconds

            # Track resolution time
            if alert.resolved_at:
                resolve_time_seconds = (alert.resolved_at - alert.created_at).total_seconds()
                detail['resolution_time_seconds'] = resolve_time_seconds
                total_resolve_time += resolve_time_seconds

            compliance_details.append(detail)

        # Calculate averages
        if acknowledged_count > 0:
            avg_acknowledgement_time = total_ack_time / acknowledged_count

        if resolved_count > 0:
            avg_resolution_time = total_resolve_time / resolved_count

        # Prepare response
        result = {
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'days': (end_date - start_date).days
            },
            'metrics': {
                'total_alerts': total_count,
                'acknowledged_alerts': acknowledged_count,
                'resolved_alerts': resolved_count,
                'sla_met_count': sla_met_count,
                'sla_missed_count': sla_missed_count,
                'sla_compliance_rate': round(sla_met_count / total_count, 4) if total_count > 0 else 0,
                'avg_acknowledgement_time_seconds': round(avg_acknowledgement_time, 2),
                'avg_resolution_time_seconds': round(avg_resolution_time, 2)
            },
            'filters': {
                'environment': data.get('environment'),
                'service_name': data.get('service_name'),
                'severity': data.get('severity')
            }
        }

        # Include individual alert details if requested and not too many
        if data.get('include_details', False) and total_count <= 1000:
            result['alerts'] = compliance_details

        # Log the event
        logger.info(f"SLA compliance report generated: {total_count} alerts analyzed")

        return jsonify(result), 200

    except SQLAlchemyError as e:
        return handle_error(e, "Database error generating SLA compliance report", 500)
    except Exception as e:
        return handle_error(e, "Failed to generate SLA compliance report", 500)


@alerts_api.route('/statistics', methods=['GET'])
@require_permission('alerts:read')
@limiter.limit("20/minute")
def get_alert_statistics():
    """
    Get alert statistics and metrics.

    Query Parameters:
        days (int): Number of days to include (default: 7)
        environment (str, optional): Filter by environment

    Returns:
        JSON: Alert statistics
    """
    try:
        # Get query parameters
        days = int(request.args.get('days', 7))
        days = max(1, min(days, 90))  # Limit range from 1 to 90 days
        environment = request.args.get('environment')

        # Calculate time period
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        # Base query
        query = db.session.query(Alert)

        # Apply environment filter if provided
        if environment:
            query = query.filter(Alert.environment == environment)

        # Filter by time range
        query = query.filter(Alert.created_at >= start_date, Alert.created_at <= end_date)

        # Group by severity
        severity_stats = (
            db.session.query(
                Alert.severity,
                func.count(Alert.id).label('count')
            )
            .filter(Alert.created_at >= start_date, Alert.created_at <= end_date)
        )
        if environment:
            severity_stats = severity_stats.filter(Alert.environment == environment)
        severity_stats = severity_stats.group_by(Alert.severity).all()

        # Group by status
        status_stats = (
            db.session.query(
                Alert.status,
                func.count(Alert.id).label('count')
            )
            .filter(Alert.created_at >= start_date, Alert.created_at <= end_date)
        )
        if environment:
            status_stats = status_stats.filter(Alert.environment == environment)
        status_stats = status_stats.group_by(Alert.status).all()

        # Group by service
        service_stats = (
            db.session.query(
                Alert.service_name,
                func.count(Alert.id).label('count')
            )
            .filter(Alert.created_at >= start_date, Alert.created_at <= end_date)
        )
        if environment:
            service_stats = service_stats.filter(Alert.environment == environment)
        service_stats = service_stats.group_by(Alert.service_name).all()

        # Time to acknowledgement (for acknowledged or resolved alerts)
        ack_time_query = (
            db.session.query(
                func.avg(func.extract('epoch', Alert.acknowledged_at) -
                         func.extract('epoch', Alert.created_at)).label('avg_time')
            )
            .filter(
                Alert.created_at >= start_date,
                Alert.created_at <= end_date,
                Alert.acknowledged_at.isnot(None)
            )
        )
        if environment:
            ack_time_query = ack_time_query.filter(Alert.environment == environment)
        avg_time_to_ack = ack_time_query.scalar() or 0

        # Time to resolution (for resolved alerts)
        resolve_time_query = (
            db.session.query(
                func.avg(func.extract('epoch', Alert.resolved_at) -
                         func.extract('epoch', Alert.created_at)).label('avg_time')
            )
            .filter(
                Alert.created_at >= start_date,
                Alert.created_at <= end_date,
                Alert.resolved_at.isnot(None)
            )
        )
        if environment:
            resolve_time_query = resolve_time_query.filter(Alert.environment == environment)
        avg_time_to_resolve = resolve_time_query.scalar() or 0

        # Calculate SLA compliance rates
        total_alerts = query.count()
        compliant_alerts = 0

        for alert in query.all():
            compliance_data = check_sla_compliance(alert, check_type='both')
            if compliance_data.get('sla_met', False):
                compliant_alerts += 1

        sla_compliance_rate = round(compliant_alerts / total_alerts, 4) if total_alerts > 0 else 0

        # Prepare statistics response
        statistics = {
            'total_alerts': total_alerts,
            'by_severity': {severity: count for severity, count in severity_stats},
            'by_status': {status: count for status, count in status_stats},
            'by_service': {service: count for service, count in service_stats},
            'avg_time_to_acknowledge': avg_time_to_ack,  # in seconds
            'avg_time_to_resolve': avg_time_to_resolve,  # in seconds
            'sla_compliance_rate': sla_compliance_rate,
            'sla_compliant_alerts': compliant_alerts,
            'time_period': {
                'days': days,
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            }
        }

        # Add environment info if filtered
        if environment:
            statistics['environment'] = environment

        return jsonify(statistics), 200

    except ValueError as e:
        return handle_error(e, "Invalid parameter value", 400)
    except SQLAlchemyError as e:
        return handle_error(e, "Database error retrieving alert statistics", 500)
    except Exception as e:
        return handle_error(e, "Failed to retrieve alert statistics", 500)


@alerts_api.route('/service/<service_name>', methods=['GET'])
@require_permission('alerts:read')
@limiter.limit("60/minute")
def get_service_alerts(service_name):
    """
    Get alerts for a specific service.

    Args:
        service_name: Name of the service

    Query Parameters:
        status (str, optional): Filter by status
        page (int): Page number (default: 1)
        per_page (int): Items per page (default: 20)

    Returns:
        JSON: List of alerts for the specified service
    """
    try:
        # Get query parameters
        status = request.args.get('status')
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(int(request.args.get('per_page', 20)), 100)

        # Build query
        query = Alert.query.filter(Alert.service_name == service_name)

        # Apply status filter if provided
        if status:
            query = query.filter(Alert.status == status)

        # Execute query with pagination
        pagination = query.order_by(desc(Alert.created_at)).paginate(
            page=page, per_page=per_page, error_out=False)

        # Format results
        alerts = alerts_schema.dump(pagination.items)

        result = {
            'service': service_name,
            'alerts': alerts,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page,
            'per_page': per_page
        }

        return jsonify(result), 200

    except ValueError as e:
        return handle_error(e, "Invalid parameter value", 400)
    except SQLAlchemyError as e:
        return handle_error(e, f"Database error retrieving alerts for service {service_name}", 500)
    except Exception as e:
        return handle_error(e, f"Failed to retrieve alerts for service {service_name}", 500)


@alerts_api.errorhandler(Exception)
def handle_exception(e):
    """Handle uncaught exceptions."""
    return handle_error(e, "An unexpected error occurred", 500)


@alerts_api.errorhandler(404)
def handle_not_found(e):
    """Handle not found errors."""
    return jsonify({"error": "Resource not found"}), 404


@alerts_api.errorhandler(405)
def handle_method_not_allowed(e):
    """Handle method not allowed errors."""
    return jsonify({"error": f"Method {request.method} not allowed"}), 405


# Export the blueprint for registration in __init__.py
__all__ = ['alerts_api']
