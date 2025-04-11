from datetime import datetime
from flask import Blueprint, current_app, request, session, g
from extensions import metrics, db

auth_bp = Blueprint(
    'auth',
    __name__,
    url_prefix='/auth',
    template_folder='templates'
)

@auth_bp.before_request
def before_request() -> None:
    """Setup request context and tracking."""
    g.start_time = datetime.utcnow()
    metrics.info('auth_requests_total', 1, labels={
        'method': request.method,
        'endpoint': request.endpoint,
        'user_id': session.get('user_id', 'anonymous')
    })

@auth_bp.app_errorhandler(401)
def unauthorized_error(_error) -> tuple[dict[str, str], int]:
    """Handle unauthorized access attempts."""
    current_app.logger.warning(
        'Unauthorized access',
        extra={
            'url': request.url,
            'ip': request.remote_addr,
            'user_id': session.get('user_id')
        }
    )
    metrics.info('auth_unauthorized_total', 1)
    return {'error': 'Unauthorized access'}, 401

@auth_bp.app_errorhandler(403)
def forbidden_error(_error) -> tuple[dict[str, str], int]:
    """Handle forbidden access attempts."""
    current_app.logger.warning(
        'Forbidden access',
        extra={
            'url': request.url,
            'ip': request.remote_addr,
            'user_id': session.get('user_id')
        }
    )
    metrics.info('auth_forbidden_total', 1)
    return {'error': 'Forbidden access'}, 403

@auth_bp.teardown_request
def teardown_request(exc) -> None:
    """Cleanup after request and record error metrics if an exception occurred."""
    if exc:
        db.session.rollback()
        metrics.info('auth_errors_total', 1, labels={
            'type': exc.__class__.__name__
        })
    db.session.remove()

    # Calculate request duration if start time was recorded
    if hasattr(g, 'start_time'):
        duration = (datetime.utcnow() - g.start_time).total_seconds()
        metrics.info('auth_request_duration_seconds', duration, labels={
            'endpoint': request.endpoint
        })
