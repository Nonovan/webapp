from datetime import datetime
import uuid
from typing import Dict, Any
from flask import Blueprint, g, request, current_app, Response
from extensions import metrics
from . import routes

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
    
    metrics.increment('monitoring_requests_total', {
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
    if hasattr(g, 'start_time'):
        elapsed = datetime.utcnow() - g.start_time
        
        response.headers.update({
            'X-Request-ID': g.request_id,
            'X-Response-Time': f'{elapsed.total_seconds():.3f}s',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block'
        })
        
        metrics.timing('monitoring_response_time', elapsed.total_seconds(), {
            'path': request.path,
            'status': response.status_code
        })
        
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
    metrics.increment('monitoring_ratelimit_total')
    return {'error': 'Rate limit exceeded'}, 429

@monitoring_bp.errorhandler(500)
def internal_error(e: Exception) -> tuple[Dict[str, str], int]:
    """Handle internal server errors."""
    current_app.logger.error(
        f'Server Error: {e}',
        extra={'request_id': g.get('request_id')}
    )
    metrics.increment('monitoring_error_total')
    return {'error': 'Internal server error'}, 500
