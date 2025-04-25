from functools import wraps

# Flask imports
from flask import current_app, request, g, has_request_context, session, has_app_context
from flask_login import current_user

# Internal imports
from extensions import db, metrics
from .cs_audit import log_security_event
from .cs_constants import SECURITY_CONFIG
from models.audit_log import AuditLog


def require_permission(permission: str):
    """
    Decorator to ensure user has the required permission.

    This decorator checks that the current user has the specified permission
    before allowing access to the decorated function. If the user lacks the
    permission, a 403 Forbidden response is returned.

    Args:
        permission: The permission name required (format: 'resource:action')

    Returns:
        Decorator function that checks permission

    Example:
        @app.route('/admin/users')
        @require_permission('users:list')
        def list_users():
            return render_template('users.html')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                from flask import redirect, url_for, flash
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login', next=request.path))

            # Skip check if superuser or admin role, if such attributes exist
            if (hasattr(current_user, 'is_superuser') and current_user.is_superuser) or \
               (hasattr(current_user, 'role') and current_user.role == 'admin'):
                return f(*args, **kwargs)

            # Check permission
            if hasattr(current_user, 'has_permission') and current_user.has_permission(permission):
                # User has permission, proceed
                return f(*args, **kwargs)
            else:
                # Log the permission denial
                log_security_event(
                    event_type=AuditLog.EVENT_PERMISSION_DENIED,
                    description=f"Permission denied: {permission}",
                    severity='warning',
                    user_id=current_user.id if hasattr(current_user, 'id') else None,
                    details={
                        'permission': permission,
                        'endpoint': request.endpoint,
                        'path': request.path
                    }
                )

                # Track metric
                metrics.increment('security.permission_denied')

                # Return 403 Forbidden
                from flask import abort
                return abort(403, description=f"You don't have the required permission: {permission}")

        return decorated_function
    return decorator

def require_mfa(f):
    """
    Decorator to ensure user has completed Multi-Factor Authentication.

    This decorator checks that the current user has completed MFA verification
    before allowing access to the decorated function. If MFA is not verified,
    the user is redirected to the MFA verification page.

    Args:
        f: The function to decorate

    Returns:
        Decorated function that checks MFA verification

    Example:
        @app.route('/sensitive-data')
        @login_required
        @require_mfa
        def view_sensitive_data():
            return render_template('sensitive_data.html')
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            from flask import redirect, url_for
            return redirect(url_for('auth.login'))

        # Check if MFA is required for this user
        mfa_required = True
        if has_app_context():
            # Check if MFA is globally disabled
            mfa_enabled = current_app.config.get('MFA_ENABLED', True)
            if not mfa_enabled:
                return f(*args, **kwargs)

            # Check if user is exempt from MFA
            if hasattr(current_user, 'mfa_exempt') and current_user.mfa_exempt:
                return f(*args, **kwargs)

        # Check if MFA is verified in the session
        mfa_verified = session.get('mfa_verified', False)
        if not mfa_verified:
            from flask import redirect, url_for, flash
            flash('Please complete two-factor authentication to access this page.', 'warning')

            # Log the MFA requirement
            log_security_event(
                event_type='mfa_required',
                description='MFA verification required for sensitive action',
                severity='info',
                user_id=current_user.id if hasattr(current_user, 'id') else None,
                details={'endpoint': request.endpoint, 'path': request.path}
            )

            # Track metric
            metrics.increment('security.mfa_redirects')

            # Redirect to MFA verification with return URL
            return redirect(url_for('auth.verify_mfa', next=request.path))

        return f(*args, **kwargs)

    return decorated_function

def can_access_ui_element(element_id: str, required_permission: str = None):
    """
    Decorator factory to control access to UI elements based on permissions.

    This decorator manages UI element visibility based on user permissions without
    raising errors. It allows for progressive UI enhancement where elements are
    conditionally shown based on the user's access rights.

    Args:
        element_id: The UI element identifier that will be used in templates
        required_permission: The permission name required to see the element
                            (format: 'resource:action')

    Returns:
        Callable: A decorator that controls UI element access

    Example:
        @app.route('/dashboard')
        @can_access_ui_element('admin_panel', 'admin:access')
        def dashboard():
            return render_template('dashboard.html')
    """
    def decorator(view_func):
        @wraps(view_func)
        def decorated_function(*args, **kwargs):
            # Initialize ui_permissions dict if it doesn't exist
            kwargs['ui_permissions'] = kwargs.get('ui_permissions', {})

            # Default to showing the element
            has_access = True

            # Check permission if one is required
            if required_permission:
                # Guard against current_user not being authenticated
                if not hasattr(current_user, 'has_permission'):
                    has_access = False
                # Handle case where current_user isn't properly initialized
                elif getattr(current_user, 'is_authenticated', False) is False:
                    has_access = False
                # Check the actual permission
                elif not current_user.has_permission(required_permission):
                    has_access = False

            # Store the result in the ui_permissions dict
            kwargs['ui_permissions'][element_id] = has_access

            # Add element_id to a list of checked elements for debugging
            if 'checked_elements' not in kwargs:
                kwargs['checked_elements'] = []
            kwargs['checked_elements'].append(element_id)

            return view_func(*args, **kwargs)
        return decorated_function
    return decorator
