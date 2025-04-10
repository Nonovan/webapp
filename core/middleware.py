from datetime import datetime
import gzip
import uuid
from flask import g, request, current_app, abort

def setup_security_headers(response):
    """Centralized security header configuration."""
    response.headers.update({
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-same-origin',
        'Permissions-Policy': 'geolocation=(), camera=()',
        'Access-Control-Allow-Origin': current_app.config.get('ALLOWED_ORIGINS', '*'),
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    })
    return response

def setup_request_context():
    """Centralized request context setup."""
    g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
    g.start_time = datetime.utcnow()
    g.api_version = request.headers.get('X-API-Version', 'v1')

    # Validate API version
    if not g.api_version in current_app.config['API_VERSIONS']:
        abort(400, 'Invalid API version')

    current_app.logger.info(f'Request {g.request_id}: {request.method} {request.path}')

def setup_response_context(response):
    """Centralized response context setup."""
    if hasattr(g, 'start_time'):
        elapsed = datetime.utcnow() - g.start_time
        response.headers.update({
            'X-Request-ID': g.request_id,
            'X-Response-Time': f'{elapsed.total_seconds():.3f}s',
            'X-API-Version': g.api_version
        })

        # Compression for large responses
        if (response.content_length and response.content_length > 1024
            and 'gzip' in request.headers.get('Accept-Encoding', '')):
            response.data = gzip.compress(response.data)
            response.headers['Content-Encoding'] = 'gzip'

        current_app.logger.info(
            f'Response {g.request_id}: {response.status_code} ({elapsed.total_seconds():.3f}s)'
        )
    return response
