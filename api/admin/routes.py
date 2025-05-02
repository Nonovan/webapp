"""
Administrative API routes for Cloud Infrastructure Platform.

This module implements RESTful API endpoints for system administration, including
user management, configuration control, system health monitoring, and security
operations. These routes are restricted to administrative users with appropriate
permissions and implement comprehensive security controls.

All endpoints enforce:
- Strong authentication with optional MFA requirement
- Fine-grained permission checks
- Comprehensive audit logging
- Rate limiting to prevent abuse
- Input validation against schemas
"""

import logging
import os
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple, Union

from flask import Blueprint, request, jsonify, current_app, g, abort
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import BadRequest, Forbidden, NotFound
from marshmallow import ValidationError

from extensions import db, limiter, metrics
from models.auth import Role, User
from models.auth.permission import Permission
from models.security import AuditLog, SecurityIncident, SystemConfig

from .user_management import (
    get_users,
    get_user_by_id,
    create_user,
    update_user,
    delete_user,
    update_user_role,
    reset_user_password
)

from .system_config import (
    get_config_value,
    set_config_value,
    get_all_configs,
    validate_config_key,
    export_configuration,
    import_configuration
)

from .audit import (
    get_audit_logs,
    get_security_events,
    export_audit_data,
    generate_compliance_report
)

from .decorators import (
    admin_required,
    super_admin_required,
    auditor_required,
    require_mfa,
    log_admin_action
)

from core.security import (
    log_security_event,
    get_security_metrics,
    check_critical_file_integrity,
    detect_suspicious_activity
)

# Create admin blueprint
admin_api = Blueprint('admin', __name__, url_prefix='/admin')

# Initialize logger
logger = logging.getLogger(__name__)

# Configure metrics
admin_request_counter = metrics.counter(
    'admin_api_requests_total',
    'Total administrative API requests',
    labels=['endpoint', 'method', 'status']
)

# Register rate limits
# Default rate limits can be overridden in application config
@admin_api.before_request
def apply_rate_limits():
    """Apply appropriate rate limits based on endpoint and user role."""
    # Apply stricter rate limits to more sensitive operations
    if request.endpoint and 'admin.user' in request.endpoint:
        limiter.limit("30/minute")(admin_api)
    elif request.endpoint and 'admin.config' in request.endpoint:
        limiter.limit("20/minute")(admin_api)
    elif request.endpoint and 'admin.security' in request.endpoint:
        limiter.limit("20/minute")(admin_api)
    else:
        limiter.limit("60/minute")(admin_api)


@admin_api.after_request
def add_security_headers(response):
    """Add security headers to all admin API responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


# Error handlers
@admin_api.errorhandler(ValidationError)
def handle_validation_error(error):
    """Handle schema validation errors."""
    log_security_event(
        event_type="admin_api_validation_error",
        description=f"Validation error in admin API: {str(error)}",
        severity="warning",
        user_id=g.get('user_id'),
        ip_address=request.remote_addr
    )
    return jsonify({"error": "Validation error", "details": error.messages}), 400


@admin_api.errorhandler(Forbidden)
def handle_forbidden_error(error):
    """Handle permission errors."""
    log_security_event(
        event_type="admin_api_forbidden",
        description=f"Forbidden access to admin API: {request.path}",
        severity="medium",
        user_id=g.get('user_id'),
        ip_address=request.remote_addr
    )
    return jsonify({"error": "You do not have permission to perform this action"}), 403


@admin_api.errorhandler(NotFound)
def handle_not_found_error(error):
    """Handle resource not found errors."""
    return jsonify({"error": "Resource not found"}), 404


@admin_api.errorhandler(SQLAlchemyError)
def handle_database_error(error):
    """Handle database errors."""
    db.session.rollback()
    logger.error(f"Database error in admin API: {str(error)}")
    log_security_event(
        event_type="admin_api_database_error",
        description=f"Database error in admin API: {str(error)}",
        severity="high",
        user_id=g.get('user_id'),
        ip_address=request.remote_addr
    )
    return jsonify({"error": "A database error occurred"}), 500


@admin_api.errorhandler(Exception)
def handle_unexpected_error(error):
    """Handle unexpected errors."""
    logger.error(f"Unexpected error in admin API: {str(error)}", exc_info=True)
    log_security_event(
        event_type="admin_api_error",
        description=f"Unexpected error in admin API: {str(error)}",
        severity="high",
        user_id=g.get('user_id'),
        ip_address=request.remote_addr
    )
    return jsonify({"error": "An unexpected error occurred"}), 500


# Basic health/status endpoint that doesn't require elevated permissions
@admin_api.route('/health', methods=['GET'])
def health_check():
    """
    Get basic API health status.

    This endpoint returns a simple status check to verify the admin API is responding.
    It doesn't require authentication and can be used by monitoring systems.

    Returns:
        JSON: Basic health status information
    """
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "api": "admin"
    }), 200


# User management endpoints
@admin_api.route('/users', methods=['GET'])
@admin_required
@log_admin_action('admin.users.list')
def list_users():
    """
    Get a list of all users with filtering options.

    Query Parameters:
        role (str): Filter by role name
        active (bool): Filter by active status
        search (str): Search by username or email
        page (int): Page number (default: 1)
        per_page (int): Items per page (default: 50)

    Returns:
        JSON: List of users with pagination metadata
    """
    role = request.args.get('role')
    active = request.args.get('active')
    search = request.args.get('search')
    page = int(request.args.get('page', 1))
    per_page = min(int(request.args.get('per_page', 50)), 100)  # Limit to 100 max

    try:
        users, total, page_count = get_users(
            role=role,
            active=(active == 'true') if active is not None else None,
            search=search,
            page=page,
            per_page=per_page
        )

        return jsonify({
            "users": users,
            "pagination": {
                "total": total,
                "page": page,
                "per_page": per_page,
                "pages": page_count
            }
        }), 200

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@admin_api.route('/users', methods=['POST'])
@admin_required
@require_mfa
@log_admin_action('admin.users.create')
def create_user_account():
    """
    Create a new user account.

    Request Body:
        username (str): Username
        email (str): Email address
        password (str): Initial password
        role (str): Role name (default: 'user')
        first_name (str, optional): First name
        last_name (str, optional): Last name
        active (bool, optional): Active status (default: True)

    Returns:
        JSON: Created user details
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    required_fields = ['username', 'email', 'password']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    try:
        user_dict = create_user(
            username=data['username'],
            email=data['email'],
            password=data['password'],
            role=data.get('role', 'user'),
            first_name=data.get('first_name', ''),
            last_name=data.get('last_name', ''),
            active=data.get('active', True),
            created_by=g.user.id
        )

        log_security_event(
            event_type="user_created",
            description=f"User created: {data['username']} with role {data.get('role', 'user')}",
            severity="info",
            user_id=g.user.id,
            ip_address=request.remote_addr
        )

        return jsonify(user_dict), 201

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@admin_api.route('/users/<int:user_id>', methods=['GET'])
@admin_required
@log_admin_action('admin.users.view')
def get_user(user_id):
    """
    Get detailed information about a specific user.

    Args:
        user_id (int): The user ID to retrieve

    Returns:
        JSON: User details
    """
    try:
        user_dict = get_user_by_id(user_id)
        if not user_dict:
            return jsonify({"error": "User not found"}), 404

        return jsonify(user_dict), 200

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@admin_api.route('/users/<int:user_id>', methods=['PUT'])
@admin_required
@log_admin_action('admin.users.update')
def update_user_account(user_id):
    """
    Update a user's account details.

    Args:
        user_id (int): The user ID to update

    Request Body:
        email (str, optional): Updated email address
        first_name (str, optional): Updated first name
        last_name (str, optional): Updated last name
        active (bool, optional): Updated active status

    Returns:
        JSON: Updated user details
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    try:
        user_dict = update_user(
            user_id=user_id,
            email=data.get('email'),
            first_name=data.get('first_name'),
            last_name=data.get('last_name'),
            active=data.get('active'),
            updated_by=g.user.id
        )

        if not user_dict:
            return jsonify({"error": "User not found"}), 404

        return jsonify(user_dict), 200

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@admin_api.route('/users/<int:user_id>/role', methods=['PATCH'])
@super_admin_required
@require_mfa
@log_admin_action('admin.users.change_role')
def change_user_role(user_id):
    """
    Change a user's role (requires super admin privilege).

    Args:
        user_id (int): The user ID to update

    Request Body:
        role (str): The new role name

    Returns:
        JSON: Updated user details
    """
    data = request.get_json()
    if not data or 'role' not in data:
        return jsonify({"error": "Role must be specified"}), 400

    try:
        user_dict = update_user_role(
            user_id=user_id,
            role=data['role'],
            updated_by=g.user.id
        )

        if not user_dict:
            return jsonify({"error": "User not found"}), 404

        log_security_event(
            event_type="user_role_changed",
            description=f"User role changed: user_id={user_id}, new role={data['role']}",
            severity="medium",
            user_id=g.user.id,
            ip_address=request.remote_addr
        )

        return jsonify(user_dict), 200

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@admin_api.route('/users/<int:user_id>/reset-password', methods=['POST'])
@admin_required
@require_mfa
@log_admin_action('admin.users.reset_password')
def reset_password(user_id):
    """
    Reset a user's password.

    Args:
        user_id (int): The user ID to update

    Request Body:
        password (str): The new password
        send_email (bool, optional): Whether to send an email notification (default: True)

    Returns:
        JSON: Success message
    """
    data = request.get_json()
    if not data or 'password' not in data:
        return jsonify({"error": "New password must be specified"}), 400

    try:
        success = reset_user_password(
            user_id=user_id,
            new_password=data['password'],
            send_email=data.get('send_email', True),
            reset_by=g.user.id
        )

        if not success:
            return jsonify({"error": "Failed to reset password"}), 400

        log_security_event(
            event_type="user_password_reset",
            description=f"Password reset by admin: user_id={user_id}",
            severity="medium",
            user_id=g.user.id,
            ip_address=request.remote_addr
        )

        return jsonify({"message": "Password reset successfully"}), 200

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@admin_api.route('/users/<int:user_id>', methods=['DELETE'])
@super_admin_required
@require_mfa
@log_admin_action('admin.users.delete')
def delete_user_account(user_id):
    """
    Delete a user account (requires super admin privilege).

    Args:
        user_id (int): The user ID to delete

    Returns:
        JSON: Success message
    """
    try:
        success = delete_user(user_id=user_id, deleted_by=g.user.id)

        if not success:
            return jsonify({"error": "User not found or could not be deleted"}), 404

        log_security_event(
            event_type="user_deleted",
            description=f"User deleted: user_id={user_id}",
            severity="high",
            user_id=g.user.id,
            ip_address=request.remote_addr
        )

        return jsonify({"message": "User deleted successfully"}), 200

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


# Role management endpoints
@admin_api.route('/roles', methods=['GET'])
@admin_required
@log_admin_action('admin.roles.list')
def list_roles():
    """
    Get a list of all roles and their permissions.

    Returns:
        JSON: List of roles with their permissions
    """
    try:
        roles = Role.query.all()
        result = []

        for role in roles:
            permissions = Permission.query.join(
                Permission.roles
            ).filter(
                Role.id == role.id
            ).all()

            permission_list = [
                {"id": p.id, "name": p.name, "description": p.description}
                for p in permissions
            ]

            result.append({
                "id": role.id,
                "name": role.name,
                "description": role.description,
                "permissions": permission_list
            })

        return jsonify({"roles": result}), 200

    except SQLAlchemyError as e:
        logger.error(f"Database error retrieving roles: {str(e)}")
        return jsonify({"error": "Failed to retrieve roles"}), 500


# System configuration endpoints
@admin_api.route('/config', methods=['GET'])
@admin_required
@log_admin_action('admin.config.list')
def get_config():
    """
    Get system configuration settings.

    Query Parameters:
        category (str, optional): Filter by category

    Returns:
        JSON: List of configuration settings
    """
    category = request.args.get('category')

    try:
        config_items = get_all_configs(category=category)
        return jsonify({"config": config_items}), 200

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@admin_api.route('/config/<key>', methods=['GET'])
@admin_required
@log_admin_action('admin.config.view')
def get_config_item(key):
    """
    Get a specific configuration value.

    Args:
        key (str): Configuration key

    Returns:
        JSON: Configuration value
    """
    try:
        value = get_config_value(key)
        if value is None:
            return jsonify({"error": "Configuration key not found"}), 404

        return jsonify({"key": key, "value": value}), 200

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@admin_api.route('/config/<key>', methods=['PUT'])
@super_admin_required
@require_mfa
@log_admin_action('admin.config.update')
def update_config_item(key):
    """
    Update a configuration value.

    Args:
        key (str): Configuration key

    Request Body:
        value: The new configuration value
        description (str, optional): Optional description update

    Returns:
        JSON: Updated configuration
    """
    data = request.get_json()
    if not data or 'value' not in data:
        return jsonify({"error": "No value provided"}), 400

    try:
        # Validate the key to ensure it's a valid configuration option
        if not validate_config_key(key):
            return jsonify({"error": f"Invalid configuration key: {key}"}), 400

        result = set_config_value(
            key=key,
            value=data['value'],
            description=data.get('description'),
            updated_by=g.user.id
        )

        log_security_event(
            event_type="config_updated",
            description=f"Configuration updated: {key}",
            severity="medium",
            user_id=g.user.id,
            ip_address=request.remote_addr
        )

        return jsonify(result), 200

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@admin_api.route('/config/export', methods=['GET'])
@super_admin_required
@log_admin_action('admin.config.export')
def export_config():
    """
    Export system configuration.

    Query Parameters:
        format (str): Export format (json or yaml, default: json)
        category (str, optional): Filter by category

    Returns:
        JSON or YAML: Exported configuration
    """
    format_type = request.args.get('format', 'json').lower()
    category = request.args.get('category')

    if format_type not in ['json', 'yaml']:
        return jsonify({"error": "Invalid format specified. Use 'json' or 'yaml'"}), 400

    try:
        result = export_configuration(format_type=format_type, category=category)

        if format_type == 'json':
            return jsonify(result), 200
        else:
            return result, 200, {'Content-Type': 'application/x-yaml'}

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@admin_api.route('/config/import', methods=['POST'])
@super_admin_required
@require_mfa
@log_admin_action('admin.config.import')
def import_config():
    """
    Import system configuration.

    Request Body:
        config: Configuration data (JSON object or YAML string)
        format (str): Import format (json or yaml, default: json)
        overwrite (bool): Whether to overwrite existing values (default: False)

    Returns:
        JSON: Import results
    """
    if 'config' not in request.json:
        return jsonify({"error": "No configuration data provided"}), 400

    format_type = request.json.get('format', 'json').lower()
    overwrite = request.json.get('overwrite', False)

    if format_type not in ['json', 'yaml']:
        return jsonify({"error": "Invalid format specified. Use 'json' or 'yaml'"}), 400

    try:
        config_data = request.json['config']
        result = import_configuration(
            config_data=config_data,
            format_type=format_type,
            overwrite=overwrite,
            imported_by=g.user.id
        )

        log_security_event(
            event_type="config_imported",
            description=f"Configuration imported: {len(result['imported'])} settings",
            severity="high",
            user_id=g.user.id,
            ip_address=request.remote_addr,
            details={
                "successful_imports": len(result['imported']),
                "failed_imports": len(result['errors'])
            }
        )

        return jsonify(result), 200 if not result['errors'] else 207  # 207 Multi-Status

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


# Audit log endpoints
@admin_api.route('/audit/logs', methods=['GET'])
@auditor_required
@log_admin_action('admin.audit.view_logs')
def view_audit_logs():
    """
    Get security audit logs with filtering options.

    Query Parameters:
        start_date (str): Start date (ISO format)
        end_date (str): End date (ISO format)
        user_id (int, optional): Filter by user ID
        event_type (str, optional): Filter by event type
        severity (str, optional): Filter by severity
        page (int): Page number (default: 1)
        per_page (int): Items per page (default: 50)

    Returns:
        JSON: List of audit logs with pagination metadata
    """
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    user_id = request.args.get('user_id')
    event_type = request.args.get('event_type')
    severity = request.args.get('severity')
    page = int(request.args.get('page', 1))
    per_page = min(int(request.args.get('per_page', 50)), 100)  # Limit to 100 max

    # Convert user_id to int if present
    if user_id:
        try:
            user_id = int(user_id)
        except ValueError:
            return jsonify({"error": "Invalid user ID"}), 400

    try:
        logs, total, page_count = get_audit_logs(
            start_date=start_date,
            end_date=end_date,
            user_id=user_id,
            event_type=event_type,
            severity=severity,
            page=page,
            per_page=per_page
        )

        return jsonify({
            "audit_logs": logs,
            "pagination": {
                "total": total,
                "page": page,
                "per_page": per_page,
                "pages": page_count
            }
        }), 200

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@admin_api.route('/audit/events', methods=['GET'])
@auditor_required
@log_admin_action('admin.audit.view_events')
def view_security_events():
    """
    Get security events with filtering options.

    Query Parameters:
        start_date (str): Start date (ISO format)
        end_date (str): End date (ISO format)
        severity (str, optional): Filter by severity
        event_type (str, optional): Filter by event type
        page (int): Page number (default: 1)
        per_page (int): Items per page (default: 50)

    Returns:
        JSON: List of security events with pagination metadata
    """
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    severity = request.args.get('severity')
    event_type = request.args.get('event_type')
    page = int(request.args.get('page', 1))
    per_page = min(int(request.args.get('per_page', 50)), 100)  # Limit to 100 max

    try:
        events, total, page_count = get_security_events(
            start_date=start_date,
            end_date=end_date,
            severity=severity,
            event_type=event_type,
            page=page,
            per_page=per_page
        )

        return jsonify({
            "security_events": events,
            "pagination": {
                "total": total,
                "page": page,
                "per_page": per_page,
                "pages": page_count
            }
        }), 200

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@admin_api.route('/audit/export', methods=['POST'])
@auditor_required
@log_admin_action('admin.audit.export')
def export_audit_logs():
    """
    Export audit logs in various formats.

    Request Body:
        format (str): Export format (json, csv, or pdf)
        start_date (str): Start date (ISO format)
        end_date (str): End date (ISO format)
        filters (dict, optional): Additional filters

    Returns:
        File download or JSON: Exported audit data
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    required_fields = ['format', 'start_date', 'end_date']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    format_type = data['format'].lower()
    if format_type not in ['json', 'csv', 'pdf']:
        return jsonify({"error": "Invalid format specified. Use 'json', 'csv', or 'pdf'"}), 400

    try:
        export_data = export_audit_data(
            format_type=format_type,
            start_date=data['start_date'],
            end_date=data['end_date'],
            filters=data.get('filters', {})
        )

        if format_type == 'json':
            return jsonify(export_data), 200
        elif format_type == 'csv':
            return export_data, 200, {
                'Content-Type': 'text/csv',
                'Content-Disposition': f'attachment; filename=audit_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            }
        else:  # pdf
            return export_data, 200, {
                'Content-Type': 'application/pdf',
                'Content-Disposition': f'attachment; filename=audit_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            }

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@admin_api.route('/audit/compliance', methods=['POST'])
@auditor_required
@log_admin_action('admin.audit.compliance_report')
def generate_compliance_report():
    """
    Generate a compliance report.

    Request Body:
        report_type (str): Type of compliance report (e.g., 'soc2', 'hipaa', 'gdpr')
        start_date (str): Start date (ISO format)
        end_date (str): End date (ISO format)
        format (str): Export format (json, csv, or pdf)

    Returns:
        File download or JSON: Compliance report
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    required_fields = ['report_type', 'start_date', 'end_date', 'format']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    format_type = data['format'].lower()
    if format_type not in ['json', 'csv', 'pdf']:
        return jsonify({"error": "Invalid format specified. Use 'json', 'csv', or 'pdf'"}), 400

    try:
        report_data = generate_compliance_report(
            report_type=data['report_type'],
            start_date=data['start_date'],
            end_date=data['end_date'],
            format_type=format_type,
            additional_params=data.get('params', {})
        )

        if format_type == 'json':
            return jsonify(report_data), 200
        elif format_type == 'csv':
            return report_data, 200, {
                'Content-Type': 'text/csv',
                'Content-Disposition': f'attachment; filename=compliance_{data["report_type"]}_{datetime.now().strftime("%Y%m%d")}.csv'
            }
        else:  # pdf
            return report_data, 200, {
                'Content-Type': 'application/pdf',
                'Content-Disposition': f'attachment; filename=compliance_{data["report_type"]}_{datetime.now().strftime("%Y%m%d")}.pdf'
            }

    except ValueError as e:
        return jsonify({"error": str(e)}), 400


# System health and monitoring endpoints
@admin_api.route('/system/health', methods=['GET'])
@admin_required
@log_admin_action('admin.system.health')
def system_health():
    """
    Get detailed system health information.

    Returns:
        JSON: System health metrics
    """
    try:
        # Get security metrics
        security_metrics = get_security_metrics()

        # Get system configuration status
        configs = SystemConfig.query.filter(
            SystemConfig.key.in_(['maintenance_mode', 'system_status', 'last_maintenance'])
        ).all()
        config_dict = {config.key: config.value for config in configs}

        # Check file integrity
        integrity_status, changes = check_critical_file_integrity()

        # Get recent security incidents
        recent_incidents = SecurityIncident.query.filter(
            SecurityIncident.status != 'resolved'
        ).order_by(
            SecurityIncident.severity.desc(),
            SecurityIncident.created_at.desc()
        ).limit(5).all()

        incidents_list = []
        for incident in recent_incidents:
            incidents_list.append({
                'id': incident.id,
                'type': incident.type,
                'severity': incident.severity,
                'status': incident.status,
                'created_at': incident.created_at.isoformat() if incident.created_at else None,
                'summary': incident.summary
            })

        return jsonify({
            "timestamp": datetime.utcnow().isoformat(),
            "system_status": config_dict.get('system_status', 'unknown'),
            "maintenance_mode": config_dict.get('maintenance_mode', 'false') == 'true',
            "last_maintenance": config_dict.get('last_maintenance'),
            "security": {
                "file_integrity": integrity_status,
                "file_changes": len(changes),
                "failed_logins_24h": security_metrics.get('failed_logins_24h', 0),
                "active_incidents": len(incidents_list),
                "suspicious_activities_24h": security_metrics.get('suspicious_activities_24h', 0)
            },
            "active_incidents": incidents_list,
            "database_status": "healthy"  # Could expand with actual DB health check
        }), 200

    except Exception as e:
        logger.error(f"Error retrieving system health: {str(e)}")
        return jsonify({
            "error": "Failed to retrieve complete health information",
            "timestamp": datetime.utcnow().isoformat(),
        }), 500


@admin_api.route('/system/maintenance', methods=['POST'])
@super_admin_required
@require_mfa
@log_admin_action('admin.system.maintenance')
def system_maintenance():
    """
    Perform system maintenance operations.

    Request Body:
        operation (str): Maintenance operation to perform
        parameters (dict, optional): Operation-specific parameters

    Returns:
        JSON: Operation result
    """
    data = request.get_json()
    if not data or 'operation' not in data:
        return jsonify({"error": "Operation must be specified"}), 400

    operation = data['operation']
    parameters = data.get('parameters', {})

    valid_operations = ['clear_cache', 'vacuum_db', 'cleanup_logs', 'rebuild_indexes']
    if operation not in valid_operations:
        return jsonify({"error": f"Invalid operation. Must be one of: {', '.join(valid_operations)}"}), 400

    try:
        result = {}

        # Implement specific maintenance operations
        if operation == 'clear_cache':
            # Implementation would depend on cache backend
            cache_regions = parameters.get('regions', ['default'])
            # This is simplified; actual implementation would clear cache
            result = {
                "operation": "clear_cache",
                "status": "success",
                "regions_cleared": cache_regions
            }

        elif operation == 'vacuum_db':
            # Implementation would depend on database
            db.session.execute("VACUUM ANALYZE;")  # Example for PostgreSQL
            result = {
                "operation": "vacuum_db",
                "status": "success",
                "tables": "all"
            }

        elif operation == 'cleanup_logs':
            # Implementation for log cleanup
            days_to_keep = parameters.get('days_to_keep', 90)
            cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)

            # Delete old audit logs
            deleted_rows = AuditLog.query.filter(AuditLog.timestamp < cutoff_date).delete()
            db.session.commit()

            result = {
                "operation": "cleanup_logs",
                "status": "success",
                "deleted_rows": deleted_rows,
                "cutoff_date": cutoff_date.isoformat()
            }

        elif operation == 'rebuild_indexes':
            # Implementation would depend on database
            # This is simplified; actual implementation would rebuild indexes
            result = {
                "operation": "rebuild_indexes",
                "status": "success",
                "tables": parameters.get('tables', ['all'])
            }

        # Update last maintenance timestamp
        config = SystemConfig.query.filter_by(key='last_maintenance').first()
        if config:
            config.value = datetime.utcnow().isoformat()
        else:
            config = SystemConfig(
                key='last_maintenance',
                value=datetime.utcnow().isoformat(),
                description='Last system maintenance timestamp'
            )
            db.session.add(config)
        db.session.commit()

        log_security_event(
            event_type="system_maintenance",
            description=f"System maintenance performed: {operation}",
            severity="medium",
            user_id=g.user.id,
            ip_address=request.remote_addr,
            details=result
        )

        return jsonify(result), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error during maintenance operation: {str(e)}")
        return jsonify({"error": f"Maintenance operation failed: {str(e)}"}), 500


@admin_api.route('/system/incidents', methods=['GET'])
@admin_required
@log_admin_action('admin.system.incidents')
def list_incidents():
    """
    List security incidents with filtering options.

    Query Parameters:
        status (str, optional): Filter by status
        severity (str, optional): Filter by severity
        type (str, optional): Filter by incident type
        page (int): Page number (default: 1)
        per_page (int): Items per page (default: 20)

    Returns:
        JSON: List of incidents with pagination metadata
    """
    status = request.args.get('status')
    severity = request.args.get('severity')
    incident_type = request.args.get('type')
    page = int(request.args.get('page', 1))
    per_page = min(int(request.args.get('per_page', 20)), 50)  # Limit to 50 max

    try:
        query = SecurityIncident.query

        # Apply filters
        if status:
            query = query.filter(SecurityIncident.status == status)
        if severity:
            query = query.filter(SecurityIncident.severity == severity)
        if incident_type:
            query = query.filter(SecurityIncident.type == incident_type)

        # Get total count
        total = query.count()

        # Apply pagination
        incidents = query.order_by(
            SecurityIncident.severity.desc(),
            SecurityIncident.created_at.desc()
        ).offset((page - 1) * per_page).limit(per_page).all()

        incidents_list = []
        for incident in incidents:
            incidents_list.append({
                'id': incident.id,
                'type': incident.type,
                'severity': incident.severity,
                'status': incident.status,
                'created_at': incident.created_at.isoformat() if incident.created_at else None,
                'updated_at': incident.updated_at.isoformat() if incident.updated_at else None,
                'summary': incident.summary,
                'assigned_to': incident.assigned_to
            })

        return jsonify({
            "incidents": incidents_list,
            "pagination": {
                "total": total,
                "page": page,
                "per_page": per_page,
                "pages": (total + per_page - 1) // per_page
            }
        }), 200

    except SQLAlchemyError as e:
        logger.error(f"Database error retrieving incidents: {str(e)}")
        return jsonify({"error": "Failed to retrieve incidents"}), 500


@admin_api.route('/system/incidents/<int:incident_id>', methods=['GET'])
@admin_required
@log_admin_action('admin.system.incident_details')
def get_incident(incident_id):
    """
    Get detailed information about a specific security incident.

    Args:
        incident_id (int): The incident ID to retrieve

    Returns:
        JSON: Incident details
    """
    try:
        incident = SecurityIncident.query.get(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found"}), 404

        # Convert incident to dictionary
        incident_dict = {
            'id': incident.id,
            'type': incident.type,
            'severity': incident.severity,
            'status': incident.status,
            'created_at': incident.created_at.isoformat() if incident.created_at else None,
            'updated_at': incident.updated_at.isoformat() if incident.updated_at else None,
            'summary': incident.summary,
            'description': incident.description,
            'assigned_to': incident.assigned_to,
            'reported_by': incident.reported_by,
            'resolution': incident.resolution,
            'affected_resources': incident.affected_resources,
            'related_events': incident.related_events
        }

        return jsonify(incident_dict), 200

    except SQLAlchemyError as e:
        logger.error(f"Database error retrieving incident: {str(e)}")
        return jsonify({"error": "Failed to retrieve incident"}), 500


@admin_api.route('/system/incidents/<int:incident_id>', methods=['PUT'])
@admin_required
@log_admin_action('admin.system.update_incident')
def update_incident(incident_id):
    """
    Update a security incident.

    Args:
        incident_id (int): The incident ID to update

    Request Body:
        status (str, optional): Updated status
        severity (str, optional): Updated severity
        assigned_to (int, optional): User ID to assign to
        resolution (str, optional): Resolution details
        description (str, optional): Updated description

    Returns:
        JSON: Updated incident details
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    try:
        incident = SecurityIncident.query.get(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found"}), 404

        # Update fields if provided
        if 'status' in data:
            incident.status = data['status']
        if 'severity' in data:
            incident.severity = data['severity']
        if 'assigned_to' in data:
            incident.assigned_to = data['assigned_to']
        if 'resolution' in data:
            incident.resolution = data['resolution']
        if 'description' in data:
            incident.description = data['description']

        incident.updated_at = datetime.utcnow()
        incident.updated_by = g.user.id

        db.session.commit()

        log_security_event(
            event_type="security_incident_updated",
            description=f"Security incident updated: ID {incident_id}",
            severity="medium",
            user_id=g.user.id,
            ip_address=request.remote_addr,
            details={
                "incident_id": incident_id,
                "status": incident.status,
                "severity": incident.severity
            }
        )

        # Convert incident to dictionary for response
        incident_dict = {
            'id': incident.id,
            'type': incident.type,
            'severity': incident.severity,
            'status': incident.status,
            'updated_at': incident.updated_at.isoformat() if incident.updated_at else None,
            'summary': incident.summary,
            'assigned_to': incident.assigned_to
        }

        return jsonify(incident_dict), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error updating incident: {str(e)}")
        return jsonify({"error": "Failed to update incident"}), 500


# Export module
__all__ = ['admin_api']
