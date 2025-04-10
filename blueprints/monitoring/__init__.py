from datetime import datetime
import uuid
from flask import Blueprint, g, request, current_app
from . import routes

monitoring_bp = Blueprint(
    'monitoring',
    __name__,
    url_prefix='/monitoring',
    template_folder='templates'
)

@monitoring_bp.before_request
def before_request():
    g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
    g.start_time = datetime.utcnow()
    current_app.logger.info(f'Request {g.request_id}: {request.method} {request.path}')

@monitoring_bp.after_request
def after_request(response):
    if hasattr(g, 'start_time'):
        elapsed = datetime.utcnow() - g.start_time
        response.headers.update({
            'X-Request-ID': g.request_id,
            'X-Response-Time': f'{elapsed.total_seconds():.3f}s',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block'
        })
        current_app.logger.info(f'Response {g.request_id}: {response.status_code} ({elapsed.total_seconds():.3f}s)')
    return response

@monitoring_bp.app_errorhandler(429)
def ratelimit_handler(e):
    current_app.logger.warning(f'Rate limit exceeded: {request.url}')
    return {'error': 'Rate limit exceeded'}, 429

@monitoring_bp.app_errorhandler(500)
def internal_error(e):
    current_app.logger.error(f'Server Error: {e}')
    return {'error': 'Internal server error'}, 500

