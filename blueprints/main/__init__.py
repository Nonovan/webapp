from datetime import datetime
import gzip
import uuid
from flask import Blueprint, g, request, session, Response, current_app
from extensions import metrics, db
from .errors import init_error_handlers

main_bp = Blueprint(
    'main',
    __name__,
    template_folder='templates',
    static_folder='static'
)

@main_bp.before_request
def before_request() -> None:
    """Track request metrics and validate access."""
    g.start_time = datetime.utcnow()
    g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))

    # Using the correct method from PrometheusMetrics
    metrics.info('main_requests_total', 1, labels={
        'method': request.method,
        'endpoint': request.endpoint,
        'user_id': session.get('user_id', 'anonymous')
    })

@main_bp.after_request
def after_request(response: Response) -> Response:
    """Add response metrics and headers."""
    if hasattr(g, 'start_time'):
        duration = (datetime.utcnow() - g.start_time).total_seconds()
        # Use info method instead of timing for PrometheusMetrics
        metrics.info('main_response_time', duration, labels={
            'endpoint': request.endpoint,
            'status': response.status_code
        })

        # Add security headers one by one instead of using update
        response.headers['X-Request-ID'] = g.request_id
        response.headers['X-Response-Time'] = f'{duration:.3f}s'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'"

        # Compress large responses
        if (response.content_length is not None and
            response.content_length > 1024 and
            'gzip' in request.headers.get('Accept-Encoding', '')):
            response.data = gzip.compress(response.data)
            response.headers['Content-Encoding'] = 'gzip'

    return response

@main_bp.teardown_request
def teardown_request(exc) -> None:
    """Cleanup after request."""
    if exc is not None:
        db.session.rollback()
        metrics.info('main_errors_total', 1, labels={
            'type': exc.__class__.__name__,
            'endpoint': request.endpoint
        })
        current_app.logger.error(f"Request error: {exc}")
    db.session.remove()

# Initialize error handlers
init_error_handlers(main_bp)
