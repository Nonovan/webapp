from datetime import datetime
import gzip
import uuid
from flask import Blueprint, g, request, session, Response, current_app
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
def after_request(response: Response) -> Response:
    """Add response metrics and headers."""
    if hasattr(g, 'start_time'):
        duration = (datetime.utcnow() - g.start_time).total_seconds()
        metrics.timing('main_response_time', duration, {
            'endpoint': request.endpoint,
            'status': response.status_code
        })

        # Add security headers
        response.headers.update({
            'X-Request-ID': g.request_id,
            'X-Response-Time': f'{duration:.3f}s',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'"
        })

        # Compress large responses
        if (response.content_length is not None and 
            response.content_length > 1024 and
            'gzip' in request.headers.get('Accept-Encoding', '')):
            response.data = gzip.compress(response.data)
            response.headers['Content-Encoding'] = 'gzip'

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
        current_app.logger.error(f"Request error: {exc}")
    db.session.remove()

# Initialize error handlers
init_error_handlers(main_bp)
