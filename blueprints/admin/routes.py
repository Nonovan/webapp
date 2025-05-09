"""
Administrative routes for the Cloud Infrastructure Platform.

This module defines the web routes for the administrative interface, providing
secure access to system configuration, user management, security controls,
file integrity monitoring, and compliance reporting. All routes enforce strict
access controls including role requirements, MFA verification, CSRF protection,
and comprehensive audit logging.

Routes include:
- Dashboard and system overview
- User and permission management
- System configuration interfaces
- Security monitoring and incident response
- File integrity management
- Compliance reporting and audit log viewing

Security is enforced at multiple layers with strict input validation,
fine-grained permission checks, and defense-in-depth principles.
"""

import logging
import os
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union, Tuple

from flask import (
    render_template, redirect, url_for, flash, request,
    current_app, abort, jsonify, send_file, Response, g
)
from flask_wtf import CSRFProtect
from sqlalchemy import desc, func
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import Forbidden, NotFound, BadRequest
from werkzeug.utils import secure_filename

from . import admin_bp
from .decorators import admin_required, super_admin_required, auditor_required
from .forms import (
    UserCreateForm, UserEditForm, RoleCreateForm, RoleEditForm,
    SystemConfigForm, FileIntegrityForm, AuditLogSearchForm,
    IncidentManagementForm, ComplianceReportForm, SecurityReportForm
)
from .utils import (
    update_file_integrity_baseline, verify_file_integrity,
    restore_baseline_from_backup, check_baseline_status, log_admin_action
)
from extensions import db, cache, metrics, limiter
from models.auth import User, Role, Permission
from models.security import (
    AuditLog, SecurityIncident, SystemConfig, FileIntegrityBaseline
)
from models.compliance import ComplianceReport
from core.security import (
    log_security_event, check_critical_file_integrity,
    get_security_metrics, detect_suspicious_activity
)
from services.audit_service import audit_action, export_audit_data
from services.config_service import update_configuration, validate_config, export_configuration


# Initialize logger
logger = logging.getLogger(__name__)

# Configure CSRF protection
csrf = CSRFProtect()

# Define constants
ITEMS_PER_PAGE = 20
MAX_EXPORT_RECORDS = 10000
TEMP_FOLDER = '/tmp/admin_exports'
os.makedirs(TEMP_FOLDER, exist_ok=True)


# Dashboard routes

@admin_bp.route('/')
@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    """
    Admin dashboard showing system overview and recent activity.

    Displays key metrics, recent security events, system health status,
    and administrative access statistics. The dashboard aggregates information
    from various system components to provide a comprehensive overview.

    Returns:
        str: Rendered dashboard template
    """
    try:
        # Get security metrics
        security_metrics = get_security_metrics()

        # Get recent security events
        recent_events = AuditLog.query.filter(
            AuditLog.severity.in_(['high', 'critical'])
        ).order_by(desc(AuditLog.timestamp)).limit(5).all()

        # Get file integrity status
        try:
            integrity_status = check_critical_file_integrity()
        except Exception as e:
            logger.error(f"Error checking file integrity: {str(e)}")
            integrity_status = False

        # Get recent user activity
        recent_activity = AuditLog.query.filter(
            AuditLog.event_type.like('admin.%')
        ).order_by(desc(AuditLog.timestamp)).limit(10).all()

        # Get active incidents
        active_incidents = SecurityIncident.query.filter(
            SecurityIncident.status.in_(['open', 'investigating', 'mitigating'])
        ).order_by(desc(SecurityIncident.severity)).all()

        # Get system status from config
        system_status = SystemConfig.query.filter_by(
            key='system_status'
        ).first()

        # Track view metric
        metrics.info('admin_dashboard_views', 1)

        return render_template(
            'admin/dashboard.html',
            security_metrics=security_metrics,
            recent_events=recent_events,
            integrity_status=integrity_status,
            recent_activity=recent_activity,
            active_incidents=active_incidents,
            system_status=system_status.value if system_status else 'unknown',
            timestamp=datetime.utcnow().isoformat()
        )
    except Exception as e:
        logger.error(f"Error in admin dashboard: {str(e)}", exc_info=True)
        flash("An error occurred loading the dashboard. Please try again later.", "danger")
        return render_template('admin/dashboard.html', error=True)


# User management routes

@admin_bp.route('/users')
@admin_required
def user_list():
    """
    List and manage users with pagination and filtering.

    Allows administrators to view, search, and filter user accounts.
    The list is paginated and can be filtered by active status, role,
    and search terms.

    Returns:
        str: Rendered user list template
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', ITEMS_PER_PAGE, type=int)
        search = request.args.get('search', '')
        role_filter = request.args.get('role', '')
        status_filter = request.args.get('status', '')

        # Build query with filters
        query = User.query

        if search:
            query = query.filter(
                (User.username.ilike(f'%{search}%')) |
                (User.email.ilike(f'%{search}%'))
            )

        if role_filter:
            query = query.join(User.roles).filter(Role.name == role_filter)

        if status_filter == 'active':
            query = query.filter(User.active == True)
        elif status_filter == 'inactive':
            query = query.filter(User.active == False)

        # Get paginated results
        users = query.order_by(User.username).paginate(
            page=page, per_page=per_page, error_out=False
        )

        # Get all roles for the filter dropdown
        roles = Role.query.order_by(Role.name).all()

        # Log admin action
        log_admin_action(
            'admin.users.list_viewed',
            f"Admin {g.user.username} viewed user list",
            details={'page': page, 'search': search, 'role': role_filter, 'status': status_filter}
        )

        return render_template(
            'admin/users/list.html',
            users=users,
            roles=roles,
            search=search,
            role_filter=role_filter,
            status_filter=status_filter
        )
    except Exception as e:
        logger.error(f"Error in user list: {str(e)}", exc_info=True)
        flash("An error occurred while retrieving users.", "danger")
        return redirect(url_for('admin.dashboard'))


@admin_bp.route('/users/create', methods=['GET', 'POST'])
@admin_required
def user_create():
    """
    Create a new user account with proper validation.

    Allows administrators to create user accounts with specified roles
    and permissions. Includes comprehensive validation and security checks.

    Returns:
        str: Rendered user creation form or redirect on success
    """
    form = UserCreateForm()

    # Populate roles choices from the database
    form.roles.choices = [
        (r.id, r.name) for r in Role.query.order_by(Role.name).all()
    ]

    if form.validate_on_submit():
        try:
            # Create new user with sanitized data
            user = User(
                username=form.username.data,
                email=form.email.data,
                active=form.active.data
            )

            # Set initial password (will be hashed by model)
            user.set_password(form.password.data)

            # Set roles
            for role_id in form.roles.data:
                role = Role.query.get(role_id)
                if role:
                    user.roles.append(role)

            # Save to database
            db.session.add(user)
            db.session.commit()

            # Record audit entry
            audit_action(
                'user_created',
                f"Created user {user.username}",
                user_id=g.user.id,
                target_user_id=user.id,
                details={
                    'username': user.username,
                    'email': user.email,
                    'roles': [r.name for r in user.roles],
                    'active': user.active
                }
            )

            # Log security event
            log_security_event(
                event_type="user_created",
                description=f"User created: {user.username}",
                severity="medium",
                user_id=g.user.id,
                ip_address=request.remote_addr,
                details={
                    'username': user.username,
                    'roles': [r.name for r in user.roles],
                }
            )

            flash(f'User {user.username} has been created successfully', 'success')
            return redirect(url_for('admin.user_list'))

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error creating user: {str(e)}", exc_info=True)
            flash("A database error occurred. Please try again.", "danger")

        except Exception as e:
            logger.error(f"Error creating user: {str(e)}", exc_info=True)
            flash("An unexpected error occurred. Please try again.", "danger")

    return render_template('admin/users/create.html', form=form)


@admin_bp.route('/users/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def user_edit(user_id):
    """
    Edit an existing user's details and roles.

    Allows administrators to modify user account information, status,
    and role assignments. Employs proper authorization and validation checks.

    Args:
        user_id: ID of the user to edit

    Returns:
        str: Rendered user edit form or redirect on success
    """
    # Get user or return 404
    user = User.query.get_or_404(user_id)

    # Super admin restriction - regular admins can't edit super admins
    if user.has_role('super_admin') and not g.user.has_role('super_admin'):
        log_security_event(
            event_type="unauthorized_access_attempt",
            description=f"Admin {g.user.username} attempted to edit super admin {user.username}",
            severity="high",
            user_id=g.user.id
        )
        flash("You do not have permission to edit super admin users.", "danger")
        return redirect(url_for('admin.user_list'))

    # Create form and populate with user data
    form = UserEditForm(obj=user)
    form.roles.choices = [(r.id, r.name) for r in Role.query.order_by(Role.name).all()]

    # Set default selected roles
    if request.method == 'GET':
        form.roles.data = [r.id for r in user.roles]

    if form.validate_on_submit():
        try:
            # Track changes for audit log
            changes = {}

            # Update basic user information
            if user.username != form.username.data:
                changes['username'] = {'old': user.username, 'new': form.username.data}
                user.username = form.username.data

            if user.email != form.email.data:
                changes['email'] = {'old': user.email, 'new': form.email.data}
                user.email = form.email.data

            if user.active != form.active.data:
                changes['active'] = {'old': user.active, 'new': form.active.data}
                user.active = form.active.data

            # Update password if provided
            if form.password.data:
                user.set_password(form.password.data)
                changes['password'] = {'old': '[REDACTED]', 'new': '[REDACTED]'}

            # Update roles
            old_roles = {r.id: r.name for r in user.roles}
            new_roles = {r_id: Role.query.get(r_id).name for r_id in form.roles.data}

            if set(old_roles.keys()) != set(new_roles.keys()):
                changes['roles'] = {
                    'old': list(old_roles.values()),
                    'new': list(new_roles.values())
                }

                # Clear existing roles and add new ones
                user.roles = []
                for role_id in form.roles.data:
                    role = Role.query.get(role_id)
                    if role:
                        user.roles.append(role)

            # Save changes
            db.session.commit()

            # Record audit entry
            audit_action(
                'user_updated',
                f"Updated user {user.username}",
                user_id=g.user.id,
                target_user_id=user.id,
                details=changes
            )

            # Log security event for sensitive changes
            sensitive_changes = ['password', 'roles', 'active']
            if any(key in changes for key in sensitive_changes):
                log_security_event(
                    event_type="user_security_settings_updated",
                    description=f"Security settings updated for user {user.username}",
                    severity="medium",
                    user_id=g.user.id,
                    details={k: v for k, v in changes.items() if k in sensitive_changes}
                )

            flash(f'User {user.username} has been updated successfully', 'success')
            return redirect(url_for('admin.user_list'))

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error updating user: {str(e)}", exc_info=True)
            flash("A database error occurred. Please try again.", "danger")

        except Exception as e:
            logger.error(f"Error updating user: {str(e)}", exc_info=True)
            flash("An unexpected error occurred. Please try again.", "danger")

    return render_template('admin/users/edit.html', form=form, user=user)


@admin_bp.route('/users/<int:user_id>/permissions', methods=['GET', 'POST'])
@admin_required
def user_permissions(user_id):
    """
    Manage detailed permissions for a specific user.

    Provides granular control over user permissions beyond role-based access.
    Allows administrators to grant or revoke specific permissions.

    Args:
        user_id: ID of the user to manage permissions for

    Returns:
        str: Rendered permissions form or redirect on success
    """
    # Get user or return 404
    user = User.query.get_or_404(user_id)

    # Super admin restriction
    if user.has_role('super_admin') and not g.user.has_role('super_admin'):
        log_security_event(
            event_type="unauthorized_access_attempt",
            description=f"Admin {g.user.username} attempted to edit super admin permissions",
            severity="high",
            user_id=g.user.id
        )
        flash("You do not have permission to edit super admin permissions.", "danger")
        return redirect(url_for('admin.user_list'))

    if request.method == 'POST':
        try:
            # Track changes for audit
            old_permissions = set(user.get_all_permissions())

            # Process permission updates
            permission_updates = request.form.getlist('permissions')
            added_permissions = []
            removed_permissions = []

            # Get all available permissions
            all_permissions = Permission.query.all()

            # Clear direct permissions (role-based ones will remain)
            user.permissions = []

            # Add selected direct permissions
            for perm_id in permission_updates:
                try:
                    permission = Permission.query.get(int(perm_id))
                    if permission:
                        user.permissions.append(permission)
                        if permission.name not in old_permissions:
                            added_permissions.append(permission.name)
                except (ValueError, TypeError):
                    continue

            # Find removed permissions
            new_permissions = set(user.get_all_permissions())
            for perm in old_permissions:
                if perm not in new_permissions:
                    removed_permissions.append(perm)

            # Save changes
            db.session.commit()

            # Record audit entry
            audit_action(
                'user_permissions_updated',
                f"Updated permissions for user {user.username}",
                user_id=g.user.id,
                target_user_id=user.id,
                details={
                    'added_permissions': added_permissions,
                    'removed_permissions': removed_permissions
                }
            )

            # Log security event
            log_security_event(
                event_type="user_permissions_changed",
                description=f"Permissions changed for user {user.username}",
                severity="medium",
                user_id=g.user.id,
                details={
                    'added': added_permissions,
                    'removed': removed_permissions
                }
            )

            flash(f'Permissions for {user.username} have been updated', 'success')
            return redirect(url_for('admin.user_list'))

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error updating permissions: {str(e)}", exc_info=True)
            flash("A database error occurred. Please try again.", "danger")

        except Exception as e:
            logger.error(f"Error updating permissions: {str(e)}", exc_info=True)
            flash("An unexpected error occurred. Please try again.", "danger")

    # Get all permissions for the form
    all_permissions = Permission.query.order_by(Permission.name).all()

    # Group permissions by category
    permissions_by_category = {}
    for perm in all_permissions:
        category = perm.name.split(':')[0] if ':' in perm.name else 'general'
        if category not in permissions_by_category:
            permissions_by_category[category] = []
        permissions_by_category[category].append(perm)

    # Get current user permissions (both direct and role-based)
    user_permissions = set(user.get_all_permissions())

    return render_template(
        'admin/users/permissions.html',
        user=user,
        permissions_by_category=permissions_by_category,
        user_permissions=user_permissions
    )


# Role management routes

@admin_bp.route('/roles')
@admin_required
def role_list():
    """
    List and manage roles with pagination and filtering.

    Displays all available roles with their associated permissions.
    Includes search and filter functionality.

    Returns:
        str: Rendered role list template
    """
    try:
        roles = Role.query.order_by(Role.name).all()

        # Get user counts for each role
        role_user_counts = {}
        for role in roles:
            role_user_counts[role.id] = db.session.query(
                func.count(User.id)
            ).join(User.roles).filter(Role.id == role.id).scalar()

        # Log admin action
        log_admin_action(
            'admin.roles.list_viewed',
            f"Admin {g.user.username} viewed role list",
            details={}
        )

        return render_template(
            'admin/roles/list.html',
            roles=roles,
            role_user_counts=role_user_counts
        )
    except Exception as e:
        logger.error(f"Error in role list: {str(e)}", exc_info=True)
        flash("An error occurred while retrieving roles.", "danger")
        return redirect(url_for('admin.dashboard'))


@admin_bp.route('/roles/create', methods=['GET', 'POST'])
@admin_required
def role_create():
    """
    Create a new role with associated permissions.

    Allows administrators to define new roles with specific
    permissions for fine-grained access control.

    Returns:
        str: Rendered role creation form or redirect on success
    """
    form = RoleCreateForm()

    if form.validate_on_submit():
        try:
            # Create new role
            role = Role(
                name=form.name.data,
                description=form.description.data
            )

            # Add permissions
            permission_ids = request.form.getlist('permissions')
            for perm_id in permission_ids:
                try:
                    permission = Permission.query.get(int(perm_id))
                    if permission:
                        role.permissions.append(permission)
                except (ValueError, TypeError):
                    continue

            # Save to database
            db.session.add(role)
            db.session.commit()

            # Record audit entry
            audit_action(
                'role_created',
                f"Created role {role.name}",
                user_id=g.user.id,
                details={
                    'name': role.name,
                    'description': role.description,
                    'permissions': [p.name for p in role.permissions]
                }
            )

            flash(f'Role {role.name} has been created successfully', 'success')
            return redirect(url_for('admin.role_list'))

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error creating role: {str(e)}", exc_info=True)
            flash("A database error occurred. Please try again.", "danger")

        except Exception as e:
            logger.error(f"Error creating role: {str(e)}", exc_info=True)
            flash("An unexpected error occurred. Please try again.", "danger")

    # Get all permissions for the form
    all_permissions = Permission.query.order_by(Permission.name).all()

    # Group permissions by category
    permissions_by_category = {}
    for perm in all_permissions:
        category = perm.name.split(':')[0] if ':' in perm.name else 'general'
        if category not in permissions_by_category:
            permissions_by_category[category] = []
        permissions_by_category[category].append(perm)

    return render_template(
        'admin/roles/create.html',
        form=form,
        permissions_by_category=permissions_by_category
    )


@admin_bp.route('/roles/<int:role_id>', methods=['GET', 'POST'])
@admin_required
def role_edit(role_id):
    """
    Edit an existing role's details and permissions.

    Allows administrators to modify role information and
    associated permissions. Includes security restrictions
    for protected system roles.

    Args:
        role_id: ID of the role to edit

    Returns:
        str: Rendered role edit form or redirect on success
    """
    # Get role or return 404
    role = Role.query.get_or_404(role_id)

    # Protected role restriction - prevent editing system roles
    if role.name in ['super_admin', 'admin'] and not g.user.has_role('super_admin'):
        log_security_event(
            event_type="unauthorized_access_attempt",
            description=f"Admin {g.user.username} attempted to edit protected role {role.name}",
            severity="high",
            user_id=g.user.id
        )
        flash("You do not have permission to edit protected system roles.", "danger")
        return redirect(url_for('admin.role_list'))

    # Create form and populate with role data
    form = RoleEditForm(obj=role)

    if form.validate_on_submit():
        try:
            # Track changes for audit
            changes = {}

            # Update basic role information
            if role.name != form.name.data:
                changes['name'] = {'old': role.name, 'new': form.name.data}
                role.name = form.name.data

            if role.description != form.description.data:
                changes['description'] = {'old': role.description, 'new': form.description.data}
                role.description = form.description.data

            # Update permissions
            old_permissions = {p.id: p.name for p in role.permissions}

            # Process permission updates
            permission_ids = request.form.getlist('permissions')
            new_permissions = {}

            # Clear existing permissions
            role.permissions = []

            # Add selected permissions
            for perm_id in permission_ids:
                try:
                    permission = Permission.query.get(int(perm_id))
                    if permission:
                        role.permissions.append(permission)
                        new_permissions[permission.id] = permission.name
                except (ValueError, TypeError):
                    continue

            if set(old_permissions.keys()) != set(new_permissions.keys()):
                changes['permissions'] = {
                    'old': list(old_permissions.values()),
                    'new': list(new_permissions.values())
                }

            # Save changes
            db.session.commit()

            # Record audit entry
            audit_action(
                'role_updated',
                f"Updated role {role.name}",
                user_id=g.user.id,
                details=changes
            )

            flash(f'Role {role.name} has been updated successfully', 'success')
            return redirect(url_for('admin.role_list'))

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error updating role: {str(e)}", exc_info=True)
            flash("A database error occurred. Please try again.", "danger")

        except Exception as e:
            logger.error(f"Error updating role: {str(e)}", exc_info=True)
            flash("An unexpected error occurred. Please try again.", "danger")

    # Get all permissions for the form
    all_permissions = Permission.query.order_by(Permission.name).all()

    # Group permissions by category
    permissions_by_category = {}
    for perm in all_permissions:
        category = perm.name.split(':')[0] if ':' in perm.name else 'general'
        if category not in permissions_by_category:
            permissions_by_category[category] = []
        permissions_by_category[category].append(perm)

    # Get current role permissions
    role_permissions = {p.id for p in role.permissions}

    return render_template(
        'admin/roles/edit.html',
        form=form,
        role=role,
        permissions_by_category=permissions_by_category,
        role_permissions=role_permissions
    )


# System configuration routes

@admin_bp.route('/settings', methods=['GET', 'POST'])
@admin_required
def system_settings():
    """
    Manage system configuration settings.

    Provides interface to view and modify system-wide configuration
    settings with proper validation and security checks.

    Returns:
        str: Rendered settings form or redirect on success
    """
    # Create form and populate with current values
    form = SystemConfigForm()

    # Get all configuration settings
    config_settings = SystemConfig.query.all()

    # Create dictionary of config values
    config_dict = {cfg.key: cfg.value for cfg in config_settings}

    # On form submission
    if form.validate_on_submit():
        try:
            config_changes = {}

            # Process form fields
            for field in form:
                if field.name in ['csrf_token', 'submit', 'reason']:
                    continue

                # Get current value
                current_value = SystemConfig.get_value(field.name)

                # Check if changed
                if str(current_value) != str(field.data):
                    config_changes[field.name] = {
                        'old': current_value,
                        'new': field.data
                    }

            if config_changes:
                # Validate configuration for security implications
                validation_result = validate_config(config_changes)
                if not validation_result['valid']:
                    flash(f"Configuration error: {validation_result['message']}", 'danger')
                    return render_template(
                        'admin/system/settings.html',
                        form=form,
                        config_dict=config_dict
                    )

                # Apply the configuration changes
                for key, value in config_changes.items():
                    update_configuration(key, value['new'])

                # Record audit entry
                audit_action(
                    'system_config_updated',
                    f"Updated {len(config_changes)} system configuration settings",
                    user_id=g.user.id,
                    details={
                        'changes': config_changes,
                        'reason': form.reason.data
                    }
                )

                # Log security event
                log_security_event(
                    event_type="system_configuration_changed",
                    description=f"System configuration updated by {g.user.username}",
                    severity="medium" if len(config_changes) > 3 else "info",
                    user_id=g.user.id,
                    details={
                        'changes': config_changes.keys(),
                        'reason': form.reason.data
                    }
                )

                flash(f'System configuration has been updated ({len(config_changes)} changes)', 'success')
                return redirect(url_for('admin.system_settings'))
            else:
                flash('No configuration changes detected', 'info')

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error updating configuration: {str(e)}", exc_info=True)
            flash("A database error occurred. Please try again.", "danger")

        except Exception as e:
            logger.error(f"Error updating configuration: {str(e)}", exc_info=True)
            flash("An unexpected error occurred. Please try again.", "danger")

    # For GET requests, populate form with current values
    elif request.method == 'GET':
        for field in form:
            if field.name in ['csrf_token', 'submit', 'reason']:
                continue

            # Set form field value from config
            if field.name in config_dict:
                field.data = config_dict[field.name]

    # Log admin action for viewing settings
    if request.method == 'GET':
        log_admin_action(
            'admin.settings.viewed',
            f"Admin {g.user.username} viewed system settings",
            details={}
        )

    return render_template(
        'admin/system/settings.html',
        form=form,
        config_dict=config_dict
    )


@admin_bp.route('/config/export')
@super_admin_required
def export_config():
    """
    Export system configuration as JSON.

    Provides a downloadable export of all system configuration settings
    in JSON format. Restricted to super_admin users.

    Returns:
        Response: JSON file download response
    """
    try:
        # Export configuration to JSON
        config_data = export_configuration()

        # Create temporary file for download
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"system_config_export_{timestamp}.json"
        filepath = os.path.join(TEMP_FOLDER, filename)

        with open(filepath, 'w') as f:
            json.dump(config_data, f, indent=2)

        # Log the export action
        audit_action(
            'system_config_exported',
            f"Exported system configuration",
            user_id=g.user.id,
            details={'filename': filename}
        )

        # Set up file download
        response = send_file(
            filepath,
            mimetype='application/json',
            as_attachment=True,
            download_name=filename
        )

        # Delete file after response is generated (using Flask 2.0+ after_request)
        @response.call_on_close
        def cleanup():
            try:
                os.unlink(filepath)
            except Exception as e:
                logger.error(f"Error cleaning up export file: {str(e)}")

        return response

    except Exception as e:
        logger.error(f"Error exporting configuration: {str(e)}", exc_info=True)
        flash("An error occurred while exporting configuration. Please try again.", "danger")
        return redirect(url_for('admin.system_settings'))


@admin_bp.route('/config/import', methods=['GET', 'POST'])
@super_admin_required
def import_config():
    """
    Import system configuration from JSON.

    Allows uploading and importing of system configuration settings
    from a JSON file. Includes validation and security checks.

    Returns:
        str: Rendered import form or redirect on success
    """
    if request.method == 'POST':
        try:
            # Check if file was included
            if 'config_file' not in request.files:
                flash('No file selected', 'danger')
                return redirect(request.url)

            # Get file and check if it's valid
            file = request.files['config_file']
            if file.filename == '':
                flash('No file selected', 'danger')
                return redirect(request.url)

            if not file.filename.endswith('.json'):
                flash('Only JSON files are allowed', 'danger')
                return redirect(request.url)

            # Read and parse config file
            config_data = json.loads(file.read().decode('utf-8'))

            # Validate configuration structure
            if not isinstance(config_data, dict) or 'settings' not in config_data:
                flash('Invalid configuration file format', 'danger')
                return redirect(request.url)

            # Track import statistics
            imported = []
            errors = []

            # Import settings
            for key, value in config_data['settings'].items():
                try:
                    # Check if setting exists
                    config = SystemConfig.query.filter_by(key=key).first()

                    if config:
                        # Track old value
                        old_value = config.value

                        # Update existing setting
                        config.value = value
                        imported.append({
                            'key': key,
                            'old': old_value,
                            'new': value
                        })
                    else:
                        # Create new setting
                        config = SystemConfig(
                            key=key,
                            value=value,
                            description=f"Imported on {datetime.utcnow().isoformat()}"
                        )
                        db.session.add(config)
                        imported.append({
                            'key': key,
                            'old': None,
                            'new': value
                        })
                except Exception as e:
                    errors.append({
                        'key': key,
                        'error': str(e)
                    })

            # Save changes
            db.session.commit()

            # Log import action
            audit_action(
                'system_config_imported',
                f"Imported system configuration",
                user_id=g.user.id,
                details={
                    'imported': len(imported),
                    'errors': len(errors),
                    'source': file.filename
                }
            )

            # Log security event
            log_security_event(
                event_type="system_configuration_imported",
                description=f"System configuration imported by {g.user.username}",
                severity="high",
                user_id=g.user.id,
                details={
                    'imported': len(imported),
                    'errors': len(errors),
                    'source': file.filename
                }
            )

            flash(f'Configuration import complete: {len(imported)} settings imported, {len(errors)} errors', 'success')
            return redirect(url_for('admin.system_settings'))

        except json.JSONDecodeError:
            flash('Invalid JSON format in configuration file', 'danger')
            return redirect(request.url)

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error importing configuration: {str(e)}", exc_info=True)
            flash("A database error occurred. Please try again.", "danger")
            return redirect(request.url)

        except Exception as e:
            logger.error(f"Error importing configuration: {str(e)}", exc_info=True)
            flash("An unexpected error occurred. Please try again.", "danger")
            return redirect(request.url)

    # GET request - show upload form
    return render_template('admin/system/import_config.html')


# File integrity management routes

@admin_bp.route('/security/integrity')
@admin_required
def file_integrity():
    """
    File integrity monitoring dashboard.

    Displays the current status of file integrity monitoring,
    recent baseline updates, and detected violations.

    Returns:
        str: Rendered file integrity dashboard template
    """
    try:
        # Get baseline status
        baseline_status = check_baseline_status()

        # Get recent integrity violations
        violations_query = AuditLog.query.filter(
            AuditLog.event_type == 'file_integrity_violation'
        ).order_by(desc(AuditLog.timestamp)).limit(10)

        violations = violations_query.all()

        # Get recent baseline updates
        updates_query = AuditLog.query.filter(
            AuditLog.event_type.in_(['file_integrity_baseline_updated', 'file_integrity_baseline_restore'])
        ).order_by(desc(AuditLog.timestamp)).limit(5)

        updates = updates_query.all()

        # Create form for baseline updates
        form = FileIntegrityForm()

        # Log admin action
        log_admin_action(
            'admin.file_integrity.viewed',
            f"Admin {g.user.username} viewed file integrity dashboard",
            details={}
        )

        return render_template(
            'admin/security/file_integrity.html',
            baseline_status=baseline_status,
            violations=violations,
            updates=updates,
            form=form
        )
    except Exception as e:
        logger.error(f"Error in file integrity dashboard: {str(e)}", exc_info=True)
        flash("An error occurred while retrieving file integrity status.", "danger")
        return redirect(url_for('admin.dashboard'))


@admin_bp.route('/security/integrity/update', methods=['POST'])
@admin_required
def update_integrity_baseline():
    """
    Update file integrity baseline with validation.

    Processes user inputs to update the file integrity baseline
    with specified paths and patterns. Includes comprehensive
    validation and error handling.

    Returns:
        str: Redirect to file integrity dashboard with status message
    """
    form = FileIntegrityForm()

    if form.validate_on_submit():
        try:
            # Split and sanitize inputs
            paths = [p.strip() for p in form.paths.data.split('\n') if p.strip()]
            include_patterns = [p.strip() for p in form.include_patterns.data.split('\n') if p.strip()]
            exclude_patterns = [p.strip() for p in form.exclude_patterns.data.split('\n') if p.strip()]
            reason = form.reason.data

            # Update the baseline
            result = update_file_integrity_baseline(
                paths=paths,
                include_patterns=include_patterns,
                exclude_patterns=exclude_patterns,
                reason=reason
            )

            if result['success']:
                # Log detailed audit information
                audit_action(
                    'file_integrity_baseline_updated',
                    f"Updated file integrity baseline: {result['files_processed']} files processed",
                    user_id=g.user.id,
                    details={
                        'files_processed': result['files_processed'],
                        'files_added': result['files_added'],
                        'files_updated': result['files_updated'],
                        'files_removed': result['files_removed'],
                        'reason': reason,
                        'paths': paths,
                        'include_patterns': include_patterns,
                        'exclude_patterns': exclude_patterns
                    }
                )

                flash(f"File integrity baseline updated: {result['files_processed']} files processed, "
                      f"{result['files_added']} added, {result['files_updated']} updated, "
                      f"{result['files_removed']} removed", 'success')
            else:
                flash(f"Error updating file integrity baseline: {result['message']}", 'danger')

        except Exception as e:
            logger.error(f"Error updating integrity baseline: {str(e)}", exc_info=True)
            flash(f"Error updating integrity baseline: {str(e)}", 'danger')
    else:
        # Form validation failed
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {field}: {error}", 'danger')

    return redirect(url_for('admin.file_integrity'))


@admin_bp.route('/security/integrity/verify', methods=['POST'])
@admin_required
def verify_integrity():
    """
    Verify file integrity against baseline.

    Checks the integrity of specified files and paths against
    the stored baseline. Returns detailed violation information.

    Returns:
        Response: JSON response with verification results
    """
    try:
        data = request.json or {}
        paths = data.get('paths', [])
        include_patterns = data.get('include_patterns', [])
        exclude_patterns = data.get('exclude_patterns', [])

        # Verify integrity
        result = verify_file_integrity(
            paths=paths,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns
        )

        # Log result for auditing
        if not result['success'] or result.get('violations_count', 0) > 0:
            log_security_event(
                event_type='file_integrity_violation',
                description=f"File integrity verification found {result.get('violations_count', 0)} violations",
                severity='warning' if result.get('violations_count', 0) > 0 else 'info',
                user_id=g.user.id,
                details={
                    'violations_count': result.get('violations_count', 0),
                    'paths_checked': paths,
                    'execution_time': result.get('execution_time', 0)
                }
            )

            # Record audit action
            audit_action(
                'file_integrity_violations_detected',
                f"Detected {result.get('violations_count', 0)} file integrity violations",
                user_id=g.user.id,
                details={
                    'violations_count': result.get('violations_count', 0),
                    'paths_checked': paths,
                    'violations': result.get('violations', [])
                }
            )
        else:
            # Record audit action for clean verification
            audit_action(
                'file_integrity_verified',
                f"Verified file integrity with no violations",
                user_id=g.user.id,
                details={
                    'paths_checked': paths,
                    'execution_time': result.get('execution_time', 0)
                }
            )

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error verifying file integrity: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f"Error verifying integrity: {str(e)}",
            'violations_count': 0,
            'violations': [],
            'execution_time': 0
        }), 500


@admin_bp.route('/security/integrity/restore', methods=['POST'])
@admin_required
def restore_integrity_baseline():
    """
    Restore file integrity baseline from a backup.

    Restores the file integrity baseline from a specified backup file.
    Includes validation and security checks.

    Returns:
        str: Redirect to file integrity dashboard with status message
    """
    try:
        # Get backup ID
        backup_id = request.form.get('backup_id')
        if not backup_id:
            flash("No backup ID provided", 'danger')
            return redirect(url_for('admin.file_integrity'))

        # Validate backup ID for security
        if not _is_valid_backup_id(backup_id):
            log_security_event(
                event_type="invalid_backup_restore_attempt",
                description=f"Invalid backup ID in restore request: {backup_id}",
                severity="high",
                user_id=g.user.id
            )
            flash("Invalid backup ID format", 'danger')
            return redirect(url_for('admin.file_integrity'))

        # Restore from backup
        result = restore_baseline_from_backup(backup_id)

        if result['success']:
            # Log audit action
            audit_action(
                'file_integrity_baseline_restore',
                f"Restored file integrity baseline from backup: {backup_id}",
                user_id=g.user.id,
                details={
                    'backup_id': backup_id,
                    'entry_count': result.get('entry_count', 0)
                }
            )

            flash(f"Baseline restored successfully from backup: {backup_id}", 'success')
        else:
            flash(f"Failed to restore baseline: {result.get('message')}", 'danger')

    except Exception as e:
        logger.error(f"Error restoring baseline: {str(e)}", exc_info=True)
        flash(f"Error restoring baseline: {str(e)}", 'danger')

    return redirect(url_for('admin.file_integrity'))


@admin_bp.route('/security/integrity/status')
@admin_required
def get_integrity_status():
    """
    Get current file integrity status as JSON.

    Provides API access to current file integrity baseline status.
    Used by AJAX requests in the dashboard.

    Returns:
        Response: JSON response with baseline status details
    """
    try:
        # Get baseline status
        status = check_baseline_status()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting integrity status: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f"Error retrieving status: {str(e)}",
            'timestamp': datetime.utcnow().isoformat()
        }), 500


# Audit logs routes

@admin_bp.route('/audit-logs')
@auditor_required
def audit_logs():
    """
    View and search audit logs with filtering.

    Provides an interface to search and browse security audit logs
    with filtering by event type, user, severity, and date range.

    Returns:
        str: Rendered audit logs template
    """
    try:
        # Initialize search form
        form = AuditLogSearchForm(request.args)

        # Build query with filters
        query = AuditLog.query

        # Apply filters from form
        if form.event_type.data:
            query = query.filter(AuditLog.event_type.like(f"%{form.event_type.data}%"))

        if form.user_id.data:
            query = query.filter(AuditLog.user_id == form.user_id.data)

        if form.severity.data:
            query = query.filter(AuditLog.severity == form.severity.data)

        if form.start_date.data:
            query = query.filter(AuditLog.timestamp >= form.start_date.data)

        if form.end_date.data:
            # Add one day to include the entire end date
            end_date = form.end_date.data + timedelta(days=1)
            query = query.filter(AuditLog.timestamp <= end_date)

        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', ITEMS_PER_PAGE, type=int)

        # Execute query with pagination
        logs = query.order_by(desc(AuditLog.timestamp)).paginate(
            page=page, per_page=per_page, error_out=False
        )

        # Get event types for filter dropdown
        event_types = db.session.query(AuditLog.event_type).distinct().all()
        event_types = sorted([et[0] for et in event_types])

        # Get users for filter dropdown
        users = User.query.order_by(User.username).all()

        # Log admin action
        log_admin_action(
            'admin.audit_logs.viewed',
            f"Admin {g.user.username} viewed audit logs",
            details={k: v for k, v in request.args.items()}
        )

        return render_template(
            'admin/security/audit_logs.html',
            logs=logs,
            form=form,
            event_types=event_types,
            users=users
        )
    except Exception as e:
        logger.error(f"Error in audit logs: {str(e)}", exc_info=True)
        flash("An error occurred while retrieving audit logs.", "danger")
        return redirect(url_for('admin.dashboard'))


@admin_bp.route('/audit-logs/export', methods=['POST'])
@auditor_required
def export_audit_logs():
    """
    Export filtered audit logs to CSV.

    Generates a downloadable CSV file containing audit logs
    based on the specified filters.

    Returns:
        Response: CSV file download response
    """
    try:
        # Get export parameters from form
        form = AuditLogSearchForm()

        # Build query with filters
        query = AuditLog.query

        # Apply filters from form
        if form.event_type.data:
            query = query.filter(AuditLog.event_type.like(f"%{form.event_type.data}%"))

        if form.user_id.data:
            query = query.filter(AuditLog.user_id == form.user_id.data)

        if form.severity.data:
            query = query.filter(AuditLog.severity == form.severity.data)

        if form.start_date.data:
            query = query.filter(AuditLog.timestamp >= form.start_date.data)

        if form.end_date.data:
            # Add one day to include the entire end date
            end_date = form.end_date.data + timedelta(days=1)
            query = query.filter(AuditLog.timestamp <= end_date)

        # Limit export size for performance
        logs = query.order_by(desc(AuditLog.timestamp)).limit(MAX_EXPORT_RECORDS).all()

        # Generate export file
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"audit_logs_export_{timestamp}.csv"
        filepath = os.path.join(TEMP_FOLDER, filename)

        # Export data to CSV
        fieldnames = ['timestamp', 'event_type', 'description', 'user_id', 'ip_address', 'severity']

        with open(filepath, 'w', newline='') as f:
            import csv
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for log in logs:
                writer.writerow({
                    'timestamp': log.timestamp.isoformat() if log.timestamp else '',
                    'event_type': log.event_type,
                    'description': log.description,
                    'user_id': log.user_id,
                    'ip_address': log.ip_address,
                    'severity': log.severity
                })

        # Record audit entry
        audit_action(
            'audit_logs_exported',
            f"Exported {len(logs)} audit logs to CSV",
            user_id=g.user.id,
            details={k: v for k, v in request.form.items() if k != 'csrf_token'}
        )

        # Set up file download
        response = send_file(
            filepath,
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )

        # Delete file after response is generated
        @response.call_on_close
        def cleanup():
            try:
                os.unlink(filepath)
            except Exception as e:
                logger.error(f"Error cleaning up export file: {str(e)}")

        return response

    except Exception as e:
        logger.error(f"Error exporting audit logs: {str(e)}", exc_info=True)
        flash("An error occurred while exporting audit logs. Please try again.", "danger")
        return redirect(url_for('admin.audit_logs'))


# Security incident management routes

@admin_bp.route('/security/incidents')
@admin_required
def security_incidents():
    """
    Security incident tracking and management.

    Provides an interface to view and manage security incidents
    with filtering, sorting, and detailed status tracking.

    Returns:
        str: Rendered incidents template
    """
    try:
        # Get filters from request args
        status_filter = request.args.get('status', 'all')
        severity_filter = request.args.get('severity', 'all')
        time_period = request.args.get('period', '30d')

        # Build query with filters
        query = SecurityIncident.query

        # Apply status filter
        if status_filter != 'all':
            query = query.filter(SecurityIncident.status == status_filter)

        # Apply severity filter
        if severity_filter != 'all':
            query = query.filter(SecurityIncident.severity == severity_filter)

        # Apply time period filter
        if time_period != 'all':
            # Parse time period (e.g. '30d', '6m', '1y')
            unit = time_period[-1]
            try:
                value = int(time_period[:-1])
                now = datetime.utcnow()

                if unit == 'd':
                    cutoff = now - timedelta(days=value)
                elif unit == 'm':
                    cutoff = now - timedelta(days=value * 30)
                elif unit == 'y':
                    cutoff = now - timedelta(days=value * 365)
                else:
                    cutoff = now - timedelta(days=30)  # Default to 30 days

                query = query.filter(SecurityIncident.created_at >= cutoff)

            except (ValueError, TypeError):
                # Invalid format, don't apply filter
                pass

        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', ITEMS_PER_PAGE, type=int)

        # Execute query with pagination
        incidents = query.order_by(
            desc(SecurityIncident.severity),
            desc(SecurityIncident.created_at)
        ).paginate(page=page, per_page=per_page, error_out=False)

        # Get counts for dashboard
        status_counts = {}
        for status in ['open', 'investigating', 'mitigating', 'resolved', 'closed']:
            status_counts[status] = SecurityIncident.query.filter(
                SecurityIncident.status == status).count()

        severity_counts = {}
        for severity in ['critical', 'high', 'medium', 'low']:
            severity_counts[severity] = SecurityIncident.query.filter(
                SecurityIncident.severity == severity).count()

        # Log admin action
        log_admin_action(
            'admin.security_incidents.viewed',
            f"Admin {g.user.username} viewed security incidents",
            details={
                'status': status_filter,
                'severity': severity_filter,
                'period': time_period
            }
        )

        return render_template(
            'admin/security/incidents.html',
            incidents=incidents,
            status_filter=status_filter,
            severity_filter=severity_filter,
            time_period=time_period,
            status_counts=status_counts,
            severity_counts=severity_counts
        )
    except Exception as e:
        logger.error(f"Error in security incidents: {str(e)}", exc_info=True)
        flash("An error occurred while retrieving security incidents.", "danger")
        return redirect(url_for('admin.dashboard'))


@admin_bp.route('/security/incidents/<int:incident_id>')
@admin_required
def incident_details(incident_id):
    """
    View detailed information about a security incident.

    Displays comprehensive information about a specific security incident
    including timeline, responses, and affected components.

    Args:
        incident_id: ID of the incident to view

    Returns:
        str: Rendered incident details template
    """
    try:
        # Get incident or return 404
        incident = SecurityIncident.query.get_or_404(incident_id)

        # Get related audit logs
        related_logs = AuditLog.query.filter(
            AuditLog.details.contains(f'"{incident_id}"')
        ).order_by(desc(AuditLog.timestamp)).all()

        # Create form for updating the incident
        form = IncidentManagementForm(obj=incident)

        # Log admin action
        log_admin_action(
            'admin.security_incident.viewed',
            f"Admin {g.user.username} viewed security incident #{incident_id}",
            details={'incident_id': incident_id}
        )

        return render_template(
            'admin/security/incident_details.html',
            incident=incident,
            related_logs=related_logs,
            form=form
        )
    except Exception as e:
        logger.error(f"Error retrieving incident details: {str(e)}", exc_info=True)
        flash("An error occurred while retrieving incident details.", "danger")
        return redirect(url_for('admin.security_incidents'))


@admin_bp.route('/security/incidents/<int:incident_id>', methods=['POST'])
@admin_required
def update_incident(incident_id):
    """
    Update a security incident's status and details.

    Allows administrators to update the status, severity, and
    response details of a security incident.

    Args:
        incident_id: ID of the incident to update

    Returns:
        str: Redirect to incident details with status message
    """
    try:
        # Get incident or return 404
        incident = SecurityIncident.query.get_or_404(incident_id)

        # Create and validate form
        form = IncidentManagementForm()

        if form.validate_on_submit():
            # Track changes for audit log
            changes = {}

            # Update incident fields
            if incident.status != form.status.data:
                changes['status'] = {'old': incident.status, 'new': form.status.data}
                incident.status = form.status.data

            if incident.severity != form.severity.data:
                changes['severity'] = {'old': incident.severity, 'new': form.severity.data}
                incident.severity = form.severity.data

            if incident.assigned_to != form.assigned_to.data:
                changes['assigned_to'] = {'old': incident.assigned_to, 'new': form.assigned_to.data}
                incident.assigned_to = form.assigned_to.data

            if incident.resolution != form.resolution.data:
                changes['resolution'] = {'old': incident.resolution, 'new': form.resolution.data}
                incident.resolution = form.resolution.data

            # Update timestamps
            incident.updated_at = datetime.utcnow()
            incident.updated_by = g.user.id

            # If status changed to resolved or closed, set resolution date
            if form.status.data in ['resolved', 'closed'] and incident.resolved_at is None:
                incident.resolved_at = datetime.utcnow()

            # Save changes
            db.session.commit()

            # Record audit entry
            audit_action(
                'security_incident_updated',
                f"Updated security incident #{incident_id}",
                user_id=g.user.id,
                details={
                    'incident_id': incident_id,
                    'changes': changes
                }
            )

            # Log security event
            log_security_event(
                event_type="security_incident_status_changed",
                description=f"Security incident #{incident_id} status updated",
                severity="medium" if form.severity.data in ['critical', 'high'] else "info",
                user_id=g.user.id,
                details={
                    'incident_id': incident_id,
                    'status': form.status.data,
                    'severity': form.severity.data,
                }
            )

            flash(f"Incident #{incident_id} has been updated", "success")
            return redirect(url_for('admin.incident_details', incident_id=incident_id))
        else:
            # Form validation failed
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"Error in {field}: {error}", 'danger')

            return redirect(url_for('admin.incident_details', incident_id=incident_id))

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error updating incident: {str(e)}", exc_info=True)
        flash("A database error occurred. Please try again.", "danger")
        return redirect(url_for('admin.incident_details', incident_id=incident_id))

    except Exception as e:
        logger.error(f"Error updating incident: {str(e)}", exc_info=True)
        flash("An unexpected error occurred. Please try again.", "danger")
        return redirect(url_for('admin.incident_details', incident_id=incident_id))


@admin_bp.route('/security/incidents/create', methods=['GET', 'POST'])
@admin_required
def create_incident():
    """
    Create a new security incident.

    Allows administrators to create and document new security incidents
    with detailed information about the nature and severity.

    Returns:
        str: Rendered creation form or redirect on success
    """
    form = IncidentManagementForm()

    if form.validate_on_submit():
        try:
            # Create new incident
            incident = SecurityIncident(
                type=form.type.data,
                summary=form.summary.data,
                description=form.description.data,
                severity=form.severity.data,
                status=form.status.data,
                source=form.source.data,
                assigned_to=form.assigned_to.data,
                created_by=g.user.id,
                created_at=datetime.utcnow()
            )

            # Save to database
            db.session.add(incident)
            db.session.commit()

            # Record audit entry
            audit_action(
                'security_incident_created',
                f"Created security incident: {incident.summary}",
                user_id=g.user.id,
                details={
                    'incident_id': incident.id,
                    'type': incident.type,
                    'severity': incident.severity,
                    'status': incident.status,
                    'source': incident.source,
                    'assigned_to': incident.assigned_to
                }
            )

            # Log security event
            log_security_event(
                event_type="security_incident_created",
                description=f"Security incident created: {incident.summary}",
                severity=incident.severity,
                user_id=g.user.id,
                ip_address=request.remote_addr,
                details={
                    'incident_id': incident.id,
                    'type': incident.type,
                    'source': incident.source
                }
            )

            flash(f"Security incident #{incident.id} has been created", "success")
            return redirect(url_for('admin.incident_details', incident_id=incident.id))

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error creating incident: {str(e)}", exc_info=True)
            flash("A database error occurred. Please try again.", "danger")

        except Exception as e:
            logger.error(f"Error creating incident: {str(e)}", exc_info=True)
            flash("An unexpected error occurred. Please try again.", "danger")

    # Log admin action for viewing creation form
    if request.method == 'GET':
        log_admin_action(
            'admin.security_incident.create_form',
            f"Admin {g.user.username} accessed incident creation form",
            details={}
        )

    return render_template('admin/security/create_incident.html', form=form)


@admin_bp.route('/reports/compliance', methods=['GET', 'POST'])
@auditor_required
def compliance_reports():
    """
    Generate and view compliance reports.

    Provides an interface for generating, scheduling, and viewing
    compliance reports for regulatory requirements.

    Returns:
        str: Rendered compliance reports template
    """
    form = ComplianceReportForm()

    if form.validate_on_submit():
        try:
            # Generate compliance report
            report = ComplianceReport(
                name=form.name.data,
                report_type=form.report_type.data,
                period_start=form.period_start.data,
                period_end=form.period_end.data,
                status='generating',
                created_by=g.user.id,
                created_at=datetime.utcnow()
            )

            # Save to database
            db.session.add(report)
            db.session.commit()

            # Queue report generation task
            # (This would typically use a background job system like Celery)
            try:
                from services.compliance_service import generate_compliance_report
                generate_compliance_report(report.id)
            except ImportError:
                # Update report status if service isn't available
                report.status = 'failed'
                report.completion_notes = 'Compliance service unavailable'
                db.session.commit()
                flash("Compliance report service is not available", "danger")

            # Record audit entry
            audit_action(
                'compliance_report_requested',
                f"Requested compliance report: {report.name}",
                user_id=g.user.id,
                details={
                    'report_id': report.id,
                    'report_type': report.report_type,
                    'period': f"{report.period_start} to {report.period_end}"
                }
            )

            flash(f"Compliance report '{report.name}' has been queued for generation", "success")
            return redirect(url_for('admin.compliance_reports'))

        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating compliance report: {str(e)}", exc_info=True)
            flash(f"Error creating report: {str(e)}", "danger")

    # Get existing reports
    page = request.args.get('page', 1, type=int)
    reports = ComplianceReport.query.order_by(
        desc(ComplianceReport.created_at)
    ).paginate(page=page, per_page=ITEMS_PER_PAGE, error_out=False)

    # Log admin action for viewing reports
    if request.method == 'GET':
        log_admin_action(
            'admin.compliance_reports.viewed',
            f"Admin {g.user.username} viewed compliance reports",
            details={}
        )

    return render_template(
        'admin/reports/compliance.html',
        form=form,
        reports=reports
    )


@admin_bp.route('/reports/security', methods=['GET', 'POST'])
@admin_required
def security_reports():
    """
    Generate and view security reports.

    Provides interface for analyzing security metrics, incidents,
    and trends over specified time periods.

    Returns:
        str: Rendered security reports template
    """
    form = SecurityReportForm()

    if form.validate_on_submit():
        try:
            # Generate security metrics report
            report_type = form.report_type.data
            period_days = int(form.period_days.data)
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=period_days)

            # Get security metrics for the period
            metrics_data = _generate_security_metrics_report(
                start_date=start_date,
                end_date=end_date,
                report_type=report_type
            )

            # Record audit entry
            audit_action(
                'security_report_generated',
                f"Generated security report: {report_type}",
                user_id=g.user.id,
                details={
                    'report_type': report_type,
                    'period_days': period_days,
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat()
                }
            )

            # Return the report template with metrics data
            return render_template(
                'admin/reports/security_report.html',
                metrics=metrics_data,
                report_type=report_type,
                start_date=start_date,
                end_date=end_date
            )

        except Exception as e:
            logger.error(f"Error generating security report: {str(e)}", exc_info=True)
            flash(f"Error generating report: {str(e)}", "danger")

    # Log admin action for viewing reports form
    if request.method == 'GET':
        log_admin_action(
            'admin.security_reports.form_viewed',
            f"Admin {g.user.username} viewed security reports form",
            details={}
        )

    return render_template('admin/reports/security.html', form=form)


# --- Helper functions ---

def _is_valid_backup_id(backup_id: str) -> bool:
    """
    Validate backup ID to prevent directory traversal attacks.

    Args:
        backup_id: Backup ID to validate

    Returns:
        bool: True if backup ID is valid
    """
    # Check for valid backup ID format (e.g., baseline_backup_20230101_120000.json)
    import re
    pattern = r'^baseline_backup_\d{8}_\d{6}(_(pre_restore))?.json$'
    if not re.match(pattern, backup_id):
        return False

    # Ensure no path traversal characters
    if '..' in backup_id or '/' in backup_id or '\\' in backup_id:
        return False

    return True


def _generate_security_metrics_report(start_date: datetime, end_date: datetime, report_type: str) -> Dict[str, Any]:
    """
    Generate security metrics report for the specified period.

    Args:
        start_date: Start date for report period
        end_date: End date for report period
        report_type: Type of security report to generate

    Returns:
        Dict[str, Any]: Security metrics data for the report
    """
    metrics_data = {
        'period': {
            'start': start_date,
            'end': end_date,
            'days': (end_date - start_date).days
        },
        'generated_at': datetime.utcnow(),
        'report_type': report_type
    }

    # Query audit logs for the period
    logs_query = AuditLog.query.filter(
        AuditLog.timestamp.between(start_date, end_date)
    )

    # Get event counts by type
    event_counts = {}
    event_results = db.session.query(
        AuditLog.event_type, func.count(AuditLog.id)
    ).filter(
        AuditLog.timestamp.between(start_date, end_date)
    ).group_by(AuditLog.event_type).all()

    for event_type, count in event_results:
        event_counts[event_type] = count

    metrics_data['event_counts'] = event_counts

    # Get severity distribution
    severity_counts = {}
    severity_results = db.session.query(
        AuditLog.severity, func.count(AuditLog.id)
    ).filter(
        AuditLog.timestamp.between(start_date, end_date)
    ).group_by(AuditLog.severity).all()

    for severity, count in severity_results:
        severity_counts[severity] = count

    metrics_data['severity_counts'] = severity_counts

    # Get incident metrics if requested
    if report_type == 'incidents' or report_type == 'comprehensive':
        incidents_query = SecurityIncident.query.filter(
            SecurityIncident.created_at.between(start_date, end_date)
        )

        # Get total incidents
        metrics_data['incidents_total'] = incidents_query.count()

        # Get incidents by status
        status_counts = {}
        status_results = db.session.query(
            SecurityIncident.status, func.count(SecurityIncident.id)
        ).filter(
            SecurityIncident.created_at.between(start_date, end_date)
        ).group_by(SecurityIncident.status).all()

        for status, count in status_results:
            status_counts[status] = count

        metrics_data['incident_status_counts'] = status_counts

        # Get incidents by severity
        severity_counts = {}
        severity_results = db.session.query(
            SecurityIncident.severity, func.count(SecurityIncident.id)
        ).filter(
            SecurityIncident.created_at.between(start_date, end_date)
        ).group_by(SecurityIncident.severity).all()

        for severity, count in severity_results:
            severity_counts[severity] = count

        metrics_data['incident_severity_counts'] = severity_counts

        # Get resolution times
        resolved_incidents = SecurityIncident.query.filter(
            SecurityIncident.created_at.between(start_date, end_date),
            SecurityIncident.resolved_at.isnot(None)
        ).all()

        if resolved_incidents:
            resolution_times = []
            for incident in resolved_incidents:
                resolution_time = incident.resolved_at - incident.created_at
                resolution_times.append(resolution_time.total_seconds() / 3600)  # hours

            metrics_data['incident_resolution_times'] = {
                'mean': sum(resolution_times) / len(resolution_times) if resolution_times else 0,
                'max': max(resolution_times) if resolution_times else 0,
                'min': min(resolution_times) if resolution_times else 0
            }
        else:
            metrics_data['incident_resolution_times'] = {
                'mean': 0,
                'max': 0,
                'min': 0
            }

    # Get integrity metrics if requested
    if report_type == 'integrity' or report_type == 'comprehensive':
        # Get integrity violation counts
        violation_count = AuditLog.query.filter(
            AuditLog.event_type == 'file_integrity_violation',
            AuditLog.timestamp.between(start_date, end_date)
        ).count()

        metrics_data['integrity_violations'] = violation_count

        # Get baseline update counts
        baseline_updates = AuditLog.query.filter(
            AuditLog.event_type.in_(['file_integrity_baseline_updated', 'file_integrity_baseline_restore']),
            AuditLog.timestamp.between(start_date, end_date)
        ).count()

        metrics_data['baseline_updates'] = baseline_updates

    # Get login metrics if requested
    if report_type == 'access' or report_type == 'comprehensive':
        # Get failed login attempts
        failed_logins = AuditLog.query.filter(
            AuditLog.event_type == 'login_failed',
            AuditLog.timestamp.between(start_date, end_date)
        ).count()

        metrics_data['failed_logins'] = failed_logins

        # Get successful logins
        successful_logins = AuditLog.query.filter(
            AuditLog.event_type == 'login_success',
            AuditLog.timestamp.between(start_date, end_date)
        ).count()

        metrics_data['successful_logins'] = successful_logins

        # Get access denied counts
        access_denied = AuditLog.query.filter(
            AuditLog.event_type.in_(['permission_denied', 'access_denied']),
            AuditLog.timestamp.between(start_date, end_date)
        ).count()

        metrics_data['access_denied'] = access_denied

    return metrics_data
