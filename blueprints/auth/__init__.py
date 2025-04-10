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
    metrics.increment('auth_requests_total', {
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
    metrics.increment('auth_unauthorized_total')
    return {'error': 'Unauthorized access'}, 401

@auth_bp.app_errorhandler(403)
def forbidden_error() -> tuple[dict[str, str], int]:
    """Handle forbidden access attempts."""
    current_app.logger.warning(
        'Forbidden access',
        extra={
            'url': request.url,
            'ip': request.remote_addr,
            'user_id': session.get('user_id')
        }
    )
    metrics.increment('auth_forbidden_total')
    return {'error': 'Forbidden access'}, 403

@auth_bp.teardown_request
def teardown_request(exc) -> None:
    """Cleanup after request."""
    if exc:
        db.session.rollback()
        metrics.increment('auth_errors_total', {
            'type': exc.__class__.__name__
        })
    db.session.remove()
