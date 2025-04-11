from datetime import datetime
from typing import Union
from flask import render_template, current_app, request, abort, jsonify, g
from jinja2 import TemplateNotFound
from auth.utils import login_required, require_role
from monitoring.metrics import SystemMetrics, DatabaseMetrics, EnvironmentalData
from extensions import limiter, cache, metrics, db
from . import main_bp

@main_bp.before_request
def log_request() -> None:
    """Log and track incoming requests."""
    request_id = request.headers.get('X-Request-ID', 'unknown')
    current_app.logger.info(f"Request {request_id}: {request.method} {request.path}")
    metrics.info('request_count_total', 1)

@main_bp.route('/')
@limiter.limit("60/minute")
@cache.cached(timeout=300)
def home() -> Union[str, tuple]:
    """Home page route."""
    try:
        metrics.info('page_views_total', 1, labels={'page': 'home'})
        return render_template('main/home.html')  # Ensure a valid return value
    except (TemplateNotFound, RuntimeError) as e:  # Replace with specific exceptions
        current_app.logger.error(f"Home page error: {e}")
        metrics.info('error_count_total', 1, labels={'page': 'home'})
        abort(500)
        return jsonify({'error': 'Internal server error'}), 500  # Fallback return value

@main_bp.route('/about')
@limiter.limit("30/minute")
@cache.cached(timeout=3600)
def about() -> Union[str, tuple]:
    """About page route."""
    try:
        metrics.info('page_views_total', 1, labels={'page': 'about'})
        return render_template('main/about.html')
    except (TemplateNotFound, RuntimeError) as e:  # Replace with specific exceptions
        current_app.logger.error(f"About page error: {e}")
        metrics.info('error_count_total', 1, labels={'page': 'about'})
        abort(500)
        return jsonify({'error': 'Internal server error'}), 500  # Fallback return value

@main_bp.route('/cloud')
@login_required
@require_role('admin')
@limiter.limit("30/minute")
@cache.cached(timeout=60)
def cloud() -> Union[str, tuple]:
    """Cloud services dashboard route."""
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

    except (KeyError, ValueError, RuntimeError) as e:  # Replace with specific exceptions
        current_app.logger.error(f"Cloud dashboard error: {str(e)}")
        metrics.info('error_count_total', 1, labels={'page': 'cloud'})
        return jsonify({'error': 'Internal server error'}), 500

@main_bp.route('/profile')
@login_required
@limiter.limit("30/minute")
def profile() -> Union[str, tuple[dict, int]]:
    """User profile route."""
    try:
        return render_template('main/profile.html')
    except (TemplateNotFound, RuntimeError) as e:
        current_app.logger.error(f"Profile error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@main_bp.route('/admin')
@login_required
@require_role('admin')
@limiter.limit("30/minute")
@cache.cached(timeout=60)
def admin() -> Union[str, tuple[dict, int]]:
    """Admin panel route."""
    try:
        return render_template('main/admin.html',
            system_metrics=SystemMetrics.get_system_metrics(),
            db_metrics=DatabaseMetrics.get_db_metrics(),
            timestamp=datetime.utcnow().isoformat()
        )
    except (TemplateNotFound, RuntimeError) as e:
        current_app.logger.error(f"Admin panel error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@main_bp.route('/ics')
@login_required
@require_role('operator')
@limiter.limit("30/minute")
@cache.cached(timeout=60)
def ics():
    """ICS application route."""
    try:
        system_metrics = SystemMetrics.get_system_metrics()
        return render_template('main/ics.html',
            cpu_usage=system_metrics['cpu_usage'],
            memory_usage=system_metrics['memory_usage'],
            uptime=datetime.utcnow() - current_app.uptime
        )
    except (KeyError, RuntimeError) as e:  # Replace with specific exceptions
        current_app.logger.error(f"ICS application error: {e}")
        abort(500)

@main_bp.route('/ics/environmental')
@login_required
@require_role('operator')
@limiter.limit("30/minute")
@cache.cached(timeout=60)
def environmental_data() -> Union[str, tuple]:
    """Get latest environmental data for ICS systems."""
    try:
        start_time = datetime.utcnow()

        data = db.session.query(EnvironmentalData) \
            .order_by(EnvironmentalData.timestamp.desc()) \
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

    except (KeyError, RuntimeError) as e:  # Replace with specific exceptions
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
