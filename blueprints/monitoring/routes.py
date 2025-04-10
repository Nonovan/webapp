from datetime import datetime
from flask import Blueprint, jsonify, current_app
from auth.utils import login_required, require_role
from extensions import db, limiter, cache
from .metrics import SystemMetrics, DatabaseMetrics, ApplicationMetrics

monitoring_bp = Blueprint('monitoring', __name__, url_prefix='/monitoring')

@monitoring_bp.route('/health')
@limiter.limit("60/minute")
@cache.cached(timeout=30)
def health():
    """Health check endpoint."""
    try:
        return {
            'status': 'healthy',
            'version': current_app.config.get('VERSION', '1.0.0'),
            'database': db.engine.execute('SELECT 1').scalar() == 1,
            'uptime': str(datetime.utcnow() - current_app.uptime),
            'timestamp': datetime.utcnow().isoformat()
        }
    except (db.exc.SQLAlchemyError, AttributeError) as e:
        current_app.logger.error(f'Health check failed: {e}')
        return {'status': 'unhealthy', 'error': str(e)}, 500

@monitoring_bp.route('/metrics')
@login_required
@require_role('admin')
@limiter.limit("30/minute")
@cache.cached(timeout=60)
def metrics():
    """System metrics endpoint."""
    try:
        return jsonify({
            'system': SystemMetrics.get_system_metrics(),
            'database': DatabaseMetrics.get_db_metrics(),
            'application': ApplicationMetrics.get_app_metrics(),
            'timestamp': datetime.utcnow().isoformat()
        })
    except (SystemMetrics.MetricsError, DatabaseMetrics.MetricsError, ApplicationMetrics.MetricsError) as e:
        current_app.logger.error(f'Metrics collection failed: {e}')
        return {'error': str(e)}, 500

@monitoring_bp.route('/db/status')
@login_required
@require_role('admin')
@limiter.limit("30/minute")
@cache.cached(timeout=60)
def db_status():
    """Database status endpoint."""
    try:
        db_metrics = DatabaseMetrics.get_db_metrics()
        db_metrics['timestamp'] = datetime.utcnow().isoformat()
        return db_metrics
    except db.exc.SQLAlchemyError as e:
        current_app.logger.error(f'Database status check failed: {e}')
        return {'error': str(e)}, 500
