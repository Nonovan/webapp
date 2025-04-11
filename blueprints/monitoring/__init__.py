from datetime import datetime
import uuid
from typing import Dict
from flask import Blueprint, g, request, current_app, Response
from extensions import metrics

monitoring_bp = Blueprint(
    'monitoring',
    __name__,
    url_prefix='/monitoring',
    template_folder='templates'
)

@monitoring_bp.before_request
def before_request() -> None:
    """Setup request context and tracking."""
    g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
    g.start_time = datetime.utcnow()

    metrics.info('monitoring_requests_total', 1, labels={
        'method': request.method,
        'path': request.path
    })

    current_app.logger.info(
        f'Request {g.request_id}: {request.method} {request.path}',
        extra={'request_id': g.request_id}
    )

@monitoring_bp.after_request
def after_request(response: Response) -> Response:
    """Add response headers and metrics."""
    if not hasattr(g, 'start_time'):
        g.start_time = datetime.utcnow()
        g.request_id = getattr(g, 'request_id', str(uuid.uuid4()))
        current_app.logger.warning(
            f'Missing request context for {g.request_id}. Adding fallback.',
            extra={'request_id': g.request_id}
        )

    elapsed = datetime.utcnow() - g.start_time

    # Use set() method for individual headers instead of update()
    response.headers.set('X-Request-ID', g.request_id)
    response.headers.set('X-Response-Time', f'{elapsed.total_seconds():.3f}s')
    response.headers.set('X-Content-Type-Options', 'nosniff')
    response.headers.set('X-Frame-Options', 'DENY')
    response.headers.set('X-XSS-Protection', '1; mode=block')

    # Use info() method instead of timing() which is not available in PrometheusMetrics
    metrics.info('monitoring_response_time', elapsed.total_seconds(), labels={
        'path': request.path,
        'status': response.status_code
    })

    # Log additional diagnostic information for non-200 responses
    if response.status_code >= 400:
        current_app.logger.warning(
            f'Error response {g.request_id}: {response.status_code} ({elapsed.total_seconds():.3f}s)',
            extra={'request_id': g.request_id, 'status_code': response.status_code}
        )
    else:
        current_app.logger.info(
            f'Response {g.request_id}: {response.status_code} ({elapsed.total_seconds():.3f}s)',
            extra={'request_id': g.request_id}
        )

    return response

@monitoring_bp.errorhandler(429)
def ratelimit_handler() -> tuple[Dict[str, str], int]:
    """Handle rate limit errors."""
    current_app.logger.warning(
        f'Rate limit exceeded: {request.url}',
        extra={'request_id': g.get('request_id')}
    )
    metrics.info('monitoring_ratelimit_total', 1, labels={
        'path': request.path,
        'method': request.method
    })
    return {'error': 'Rate limit exceeded'}, 429

@monitoring_bp.errorhandler(500)
def internal_error(e: Exception) -> tuple[Dict[str, str], int]:
    """Handle internal server errors."""
    current_app.logger.error(
        f'Server Error: {e}',
        extra={'request_id': g.get('request_id')}
    )
    metrics.info('monitoring_error_total', 1, labels={
        'path': request.path,
        'method': request.method
    })
    return {'error': 'Internal server error'}, 500
