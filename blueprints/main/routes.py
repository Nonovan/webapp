"""
Main routes module for myproject.

This module defines the primary routes for the application's user interface,
including the home page, about page, cloud services dashboard, ICS application
interface, and user profile pages. These routes provide the core functionality
of the application for end users.

Each route implements appropriate:
- Authentication and authorization checks
- Rate limiting to prevent abuse
- Caching for performance optimization
- Error handling for a smooth user experience
- Metrics collection for monitoring

The routes are organized by functional area and include both page rendering
for browser clients and API endpoints for AJAX and mobile integration.
"""

from datetime import datetime
from typing import Union, Dict, Any, List

from flask import render_template, current_app, request, abort, jsonify, g, redirect, url_for
from jinja2 import TemplateNotFound
from sqlalchemy.exc import SQLAlchemyError

from extensions import limiter, cache, metrics, db
from auth.decorators import login_required, require_role
from core.security import get_security_metrics, log_security_event
from monitoring.metrics import SystemMetrics, DatabaseMetrics, EnvironmentalData

from . import main_bp

@main_bp.before_request
def log_request() -> None:
    """
    Log and track incoming requests to main routes.

    This function runs before each request to the main blueprint. It logs
    request details for audit purposes and increments request count metrics.

    Returns:
        None: This function logs information as a side effect
    """
    request_id = request.headers.get('X-Request-ID', 'unknown')
    current_app.logger.info(f"Request {request_id}: {request.method} {request.path}")
    metrics.info('request_count_total', 1)

@main_bp.route('/')
@limiter.limit("60/minute")
@cache.cached(timeout=300)
def home() -> Union[str, tuple]:
    """
    Render the application home page.

    This route displays the main landing page of the application with
    feature highlights and summary information. It's rate-limited and
    cached to handle high traffic efficiently.

    Returns:
        Union[str, tuple]: Rendered template on success, or error response on failure

    Example URL:
        GET /
    """
    try:
        metrics.info('page_views_total', 1, labels={'page': 'home'})
        return render_template('main/home.html')
    except (TemplateNotFound, RuntimeError) as e:
        current_app.logger.error(f"Home page error: {e}")
        metrics.info('error_count_total', 1, labels={'page': 'home'})
        abort(500)
        return jsonify({'error': 'Internal server error'}), 500  # Fallback return value

@main_bp.route('/about')
@limiter.limit("30/minute")
@cache.cached(timeout=3600)
def about() -> Union[str, tuple]:
    """
    Render the about page.

    This route displays information about the application, company,
    and services provided. It's cached longer than most pages since
    the content changes infrequently.

    Returns:
        Union[str, tuple]: Rendered template on success, or error response on failure

    Example URL:
        GET /about
    """
    try:
        metrics.info('page_views_total', 1, labels={'page': 'about'})
        return render_template('main/about.html')
    except (TemplateNotFound, RuntimeError) as e:
        current_app.logger.error(f"About page error: {e}")
        metrics.info('error_count_total', 1, labels={'page': 'about'})
        abort(500)
        return jsonify({'error': 'Internal server error'}), 500

@main_bp.route('/contact')
@limiter.limit("10/minute")
@cache.cached(timeout=1800)  # 30 minutes cache
def contact() -> Union[str, tuple]:
    """
    Render the contact page.

    This route displays the contact information and contact form.
    It's cached for a medium duration and includes rate limiting
    to prevent form abuse.

    Returns:
        Union[str, tuple]: Rendered template on success, or error response on failure

    Example URL:
        GET /contact
    """
    try:
        metrics.info('page_views_total', 1, labels={'page': 'contact'})
        return render_template('main/contact.html')
    except (TemplateNotFound, RuntimeError) as e:
        current_app.logger.error(f"Contact page error: {e}")
        metrics.info('error_count_total', 1, labels={'page': 'contact'})
        abort(500)
        return jsonify({'error': 'Internal server error'}), 500

@main_bp.route('/cloud')
@login_required
@require_role('admin')
@limiter.limit("30/minute")
@cache.cached(timeout=60)
def cloud() -> Union[str, tuple]:
    """
    Render the cloud services dashboard.

    This route displays the cloud services management dashboard with
    real-time system metrics, user activity, and system alerts. It requires
    admin role and is cached for a short period due to its dynamic nature.

    Returns:
        Union[str, tuple]: Rendered dashboard template on success, or error response on failure

    Example URL:
        GET /cloud
    """
    try:
        start_time = datetime.utcnow()

        # Collect metrics
        system_metrics = SystemMetrics.get_system_metrics()
        db_metrics = DatabaseMetrics.get_db_metrics()
        env_metrics = EnvironmentalData.get_env_metrics()

        # Log access
        current_app.logger.info(
            "Cloud dashboard accessed",
            extra={
                'user_id': g.user.id,
                'ip': request.remote_addr
            }
        )

        # Record admin access in audit log
        record_admin_access(request.remote_addr, g.user.id)

        # Track view
        metrics.info('cloud_dashboard_views_total', 1, labels={'user': str(g.user.id)})

        # Render template
        response = render_template(
            'main/cloud.html',
            metrics={
                'system': system_metrics,
                'database': db_metrics,
                'environment': env_metrics,
                'load_time': datetime.utcnow() - start_time
            }
        )

        # Track performance
        metrics.info(
            'cloud_dashboard_load_time',
            (datetime.utcnow() - start_time).total_seconds(),
            labels={'user': str(g.user.id)}
        )

        return response

    except (KeyError, ValueError, RuntimeError) as e:
        current_app.logger.error(f"Cloud dashboard error: {str(e)}")
        metrics.info('error_count_total', 1, labels={'page': 'cloud'})
        return jsonify({'error': 'Internal server error'}), 500

@main_bp.route('/dashboard')
@login_required
@limiter.limit("60/minute")
@cache.cached(timeout=60)
def dashboard() -> Union[str, tuple]:
    """
    Render the user dashboard.

    This route displays the main user dashboard with personalized
    information and quick access to key functions. It requires authentication
    and is cached briefly due to personalized content.

    Returns:
        Union[str, tuple]: Rendered dashboard template on success, or error response on failure

    Example URL:
        GET /dashboard
    """
    try:
        # Get user-specific data
        user_data = {
            'id': g.user.id,
            'username': g.user.username,
            'role': g.user.role,
            'last_login': g.user.last_login.isoformat() if g.user.last_login else None
        }

        # Get recent activity
        from models.user_activity import UserActivity
        recent_activity = UserActivity.query.filter_by(user_id=g.user.id) \
            .order_by(UserActivity.timestamp.desc()) \
            .limit(5) \
            .all()

        # Track view
        metrics.info('dashboard_views_total', 1, labels={'user': str(g.user.id)})

        return render_template(
            'main/dashboard.html',
            user=user_data,
            activity=recent_activity,
            security_events=get_recent_security_events(3)
        )
    except (TemplateNotFound, RuntimeError, SQLAlchemyError) as e:
        current_app.logger.error(f"Dashboard error: {str(e)}")
        metrics.info('error_count_total', 1, labels={'page': 'dashboard'})
        return jsonify({'error': 'Internal server error'}), 500

@main_bp.route('/profile')
@login_required
@limiter.limit("30/minute")
def profile() -> Union[str, tuple]:
    """
    Render the user profile page.

    This route displays the current user's profile information with
    account settings and activity history. It requires authentication.

    Returns:
        Union[str, tuple]: Rendered profile template on success, or error response on failure

    Example URL:
        GET /profile
    """
    try:
        # Get user activity
        from models.user_activity import UserActivity
        user_activity = UserActivity.query.filter_by(user_id=g.user.id) \
            .order_by(UserActivity.timestamp.desc()) \
            .limit(10) \
            .all()

        # Get security alerts for user
        from models.security_alert import SecurityAlert
        security_alerts = SecurityAlert.query.filter_by(user_id=g.user.id) \
            .order_by(SecurityAlert.created_at.desc()) \
            .limit(5) \
            .all()

        metrics.info('page_views_total', 1, labels={'page': 'profile'})

        return render_template(
            'main/profile.html',
            user=g.user,
            activity=user_activity,
            alerts=security_alerts
        )
    except (TemplateNotFound, RuntimeError, SQLAlchemyError) as e:
        current_app.logger.error(f"Profile error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@main_bp.route('/admin')
@login_required
@require_role('admin')
@limiter.limit("30/minute")
@cache.cached(timeout=60)
def admin() -> Union[str, tuple]:
    """
    Render the admin panel.

    This route displays the administrative control panel with system
    configuration, user management, and monitoring tools. It requires
    admin role and is cached briefly to reduce server load.

    Returns:
        Union[str, tuple]: Rendered admin template on success, or error response on failure

    Example URL:
        GET /admin
    """
    try:
        # Record admin access in audit log
        record_admin_access(request.remote_addr, g.user.id)

        # Track view
        metrics.info('admin_panel_views_total', 1, labels={'user': str(g.user.id)})

        return render_template(
            'main/admin.html',
            system_metrics=SystemMetrics.get_system_metrics(),
            db_metrics=DatabaseMetrics.get_db_metrics(),
            security_metrics=get_security_metrics(),
            timestamp=datetime.utcnow().isoformat()
        )
    except (TemplateNotFound, RuntimeError, SQLAlchemyError) as e:
        current_app.logger.error(f"Admin panel error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@main_bp.route('/ics')
@login_required
@require_role('operator')
@limiter.limit("30/minute")
@cache.cached(timeout=60)
def ics() -> Union[str, tuple]:
    """
    Render the ICS (Industrial Control System) application interface.

    This route displays the industrial control system interface with
    operational controls and real-time monitoring. It requires operator
    role and is cached briefly due to its semi-dynamic nature.

    Returns:
        Union[str, tuple]: Rendered ICS template on success, or error response on failure

    Example URL:
        GET /ics
    """
    try:
        system_metrics = SystemMetrics.get_system_metrics()
        security_status = get_security_metrics()

        metrics.info('ics_views_total', 1, labels={'user': str(g.user.id)})

        # Log ICS access
        log_security_event(
            event_type='ics_access',
            description=f"ICS application accessed by {g.user.username}",
            user_id=g.user.id,
            ip_address=request.remote_addr,
            severity='info'
        )

        return render_template(
            'main/ics.html',
            cpu_usage=system_metrics['cpu_usage'],
            memory_usage=system_metrics['memory_usage'],
            uptime=datetime.utcnow() - current_app.uptime,
            security_status=security_status.get('status', 'unknown')
        )
    except (KeyError, RuntimeError, TypeError) as e:
        current_app.logger.error(f"ICS application error: {e}")
        metrics.info('error_count_total', 1, labels={'page': 'ics'})
        abort(500)
        return jsonify({'error': 'Internal server error'}), 500

@main_bp.route('/ics/environmental')
@login_required
@require_role('operator')
@limiter.limit("30/minute")
@cache.cached(timeout=60)
def environmental_data() -> Union[str, tuple]:
    """
    Render environmental data for ICS systems.

    This route displays real-time environmental metrics from ICS sensors
    including temperature and humidity readings. It requires operator role
    and is cached briefly to balance freshness with server load.

    Returns:
        Union[str, tuple]: Rendered environmental data template, possibly with status code

    Example URL:
        GET /ics/environmental
    """
    try:
        start_time = datetime.utcnow()

        data = db.session.query(EnvironmentalData) \
            .order_by(EnvironmentalData.created_at.desc()) \
            .first()

        # Track request
        metrics.info('ics_environmental_requests_total', 1,
                   labels={'user': str(g.user.id)})

        if data:
            # Log successful data retrieval
            current_app.logger.info(
                "Environmental data retrieved",
                extra={
                    'user_id': g.user.id,
                    'timestamp': data.timestamp
                }
            )

            return render_template(
                "monitoring/environmental_data.html",
                temperature=data.temperature,
                humidity=data.humidity,
                timestamp=data.timestamp,
                load_time=datetime.utcnow() - start_time
            )

        # Handle no data case
        metrics.info('ics_environmental_no_data_total', 1)
        return render_template(
            "monitoring/environmental_data.html",
            error="No environmental data available"
        ), 404

    except (KeyError, RuntimeError, SQLAlchemyError) as e:
        # Log error and track metric
        current_app.logger.error(
            f"Environmental data error: {str(e)}",
            extra={'user_id': g.user.id}
        )
        metrics.info('ics_environmental_errors_total', 1)

        return render_template(
            "monitoring/environmental_data.html",
            error="Error retrieving environmental data"
        ), 500

@main_bp.route('/privacy')
@limiter.limit("30/minute")
@cache.cached(timeout=86400)  # 24 hour cache
def privacy() -> str:
    """
    Render the privacy policy page.

    This route displays the application's privacy policy.
    It's cached for a long duration since it changes infrequently.

    Returns:
        str: Rendered privacy policy template

    Example URL:
        GET /privacy
    """
    metrics.info('page_views_total', 1, labels={'page': 'privacy'})
    return render_template('main/privacy.html')

@main_bp.route('/terms')
@limiter.limit("30/minute")
@cache.cached(timeout=86400)  # 24 hour cache
def terms() -> str:
    """
    Render the terms of service page.

    This route displays the application's terms of service.
    It's cached for a long duration since it changes infrequently.

    Returns:
        str: Rendered terms of service template

    Example URL:
        GET /terms
    """
    metrics.info('page_views_total', 1, labels={'page': 'terms'})
    return render_template('main/terms.html')

@main_bp.route('/security')
@limiter.limit("30/minute")
@cache.cached(timeout=43200)  # 12 hour cache
def security() -> str:
    """
    Render the security information page.

    This route displays information about the application's security practices,
    compliance certifications, and security features.

    Returns:
        str: Rendered security information template

    Example URL:
        GET /security
    """
    metrics.info('page_views_total', 1, labels={'page': 'security'})
    return render_template('main/security.html')

@main_bp.route('/newsletter/subscribe', methods=['POST'])
@limiter.limit("5/minute")
def newsletter_subscribe() -> Union[str, tuple]:
    """
    Handle newsletter subscription requests.

    This endpoint processes newsletter subscription form submissions.
    It validates the email address and forwards the request to the newsletter service.

    Returns:
        Union[str, tuple]: Response with result message

    Example URL:
        POST /newsletter/subscribe
    """
    try:
        email = request.form.get('email')

        if not email:
            return jsonify({'error': 'Email address is required'}), 400

        # Validate email address format - basic check
        if '@' not in email or '.' not in email:
            return jsonify({'error': 'Invalid email address format'}), 400

        # Forward to newsletter API
        from services.newsletter_service import NewsletterService
        success = NewsletterService.subscribe(email, source='website_form')

        if success:
            metrics.info('newsletter_subscriptions_total', 1)
            return jsonify({'success': True, 'message': 'Subscription successful'})
        else:
            return jsonify({'error': 'Subscription failed'}), 500

    except Exception as e:
        current_app.logger.error(f"Newsletter subscription error: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

# ----- Helper Functions -----

def check_security_status() -> Dict[str, Any]:
    """
    Perform comprehensive security status check.

    Returns:
        Dict[str, Any]: Security status information
    """
    return get_security_metrics()

import warnings

def check_critical_file_integrity() -> bool:
    """
    DEPRECATED: Use core.security_utils.check_critical_file_integrity instead
    """
    warnings.warn(
        "This function is deprecated. Use core.security_utils.check_critical_file_integrity instead",
        DeprecationWarning,
        stacklevel=2
    )
    from core.security_utils import check_critical_file_integrity as core_check_integrity
    return core_check_integrity()

def get_recent_security_events(limit: int = 5) -> List[Dict[str, Any]]:
    """
    Get the most recent security events from the audit log.

    Args:
        limit: Maximum number of events to return

    Returns:
        List[Dict[str, Any]]: List of recent security events
    """
    from models.audit_log import AuditLog

    events = AuditLog.query.filter(
        AuditLog.event_type.in_([
            'login_failed', 'login_success', 'password_reset',
            'permission_denied', 'security_breach_attempt'
        ])
    ).order_by(
        AuditLog.created_at.desc()
    ).limit(limit).all()

    return [event.to_dict() for event in events]

def record_admin_access(ip_address: str, user_id: int) -> None:
    """
    Record access to administrative metrics in the audit log.

    Args:
        ip_address: IP address of the requesting user
        user_id: ID of the user accessing admin metrics
    """
    from models.audit_log import AuditLog

    log = AuditLog(
        event_type='admin_metrics_access',
        user_id=user_id,
        ip_address=ip_address,
        details=f"Admin metrics accessed from {ip_address}",
        severity='info'
    )
    db.session.add(log)
    db.session.commit()
