import uuid
from flask import Blueprint, g, request, session
from extensions import metrics, db
from .routes import *
from .errors import init_error_handlers

main_bp = Blueprint(
    'main',
    __name__,
    template_folder='templates',
    static_folder='static'
)

@main_bp.before_request
def before_request():
    """Track request metrics and validate access."""
    g.start_time = datetime.utcnow()
    g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
    
    metrics.increment('main_requests_total', {
        'method': request.method,
        'endpoint': request.endpoint,
        'user_id': session.get('user_id', 'anonymous')
    })

@main_bp.after_request
def after_request(response):
    """Add response metrics and headers."""
    if hasattr(g, 'start_time'):
        duration = (datetime.utcnow() - g.start_time).total_seconds()
        metrics.timing('main_response_time', duration, {
            'endpoint': request.endpoint,
            'status': response.status_code
        })

    # Add security headers
    response.headers['X-Request-ID'] = g.request_id
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response

@main_bp.teardown_request
def teardown_request(exc):
    """Cleanup after request."""
    if exc is not None:
        db.session.rollback()
        metrics.increment('main_errors_total', {
            'type': exc.__class__.__name__,
            'endpoint': request.endpoint
        })
    db.session.remove()

# Initialize error handlers
init_error_handlers(main_bp)
