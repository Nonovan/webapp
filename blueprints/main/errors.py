from flask import render_template, request, jsonify, current_app, session, g
from extensions import db, metrics
from . import main_bp

def log_error(error, level='error', context=None):
    log_message = f'Error {error.code}: {request.url} - {error}'
    if context:
        log_message += f' | Context: {context}'
    getattr(current_app.logger, level)(log_message)
    metrics.increment(f'error_{error.code}')

@main_bp.app_errorhandler(400)
def bad_request_error(error):
    log_error(error, 'warning')
    if request.is_json:
        return jsonify(error="Bad request", details=str(error)), 400
    return render_template('errors/400.html', error=error), 400

@main_bp.app_errorhandler(401)
def unauthorized_error(error):
    log_error(error, 'warning')
    if request.is_json:
        return jsonify(error="Unauthorized"), 401
    return render_template('errors/401.html'), 401

@main_bp.app_errorhandler(404)
def not_found_error(error):
    log_error(error, 'warning')
    if request.is_json:
        return jsonify(error="Not found"), 404
    return render_template('errors/404.html'), 404

@main_bp.app_errorhandler(403)
def forbidden_error(error):
    log_error(error, 'warning')
    if request.is_json:
        return jsonify(error="Forbidden"), 403
    return render_template('errors/403.html'), 403

@main_bp.app_errorhandler(422)
def validation_error(error):
    log_error(error, 'warning')
    if request.is_json:
        return jsonify(error="Validation error", details=error.description), 422
    return render_template('errors/422.html', error=error), 422

@main_bp.app_errorhandler(500)
def internal_error(error):
    log_error(error)
    db.session.rollback()
    if request.is_json:
        return jsonify(error="Internal server error"), 500
    return render_template('errors/500.html'), 500

@main_bp.app_errorhandler(429)
def ratelimit_error(error):
    log_error(error, 'warning')
    if request.is_json:
        return jsonify(error="Too many requests"), 429
    return render_template('errors/429.html'), 429

@main_bp.app_errorhandler(503)
def service_unavailable_error(error):
    log_error(error)
    if request.is_json:
        return jsonify(error="Service unavailable"), 503
    return render_template('errors/503.html'), 503

@main_bp.app_errorhandler(502)
def bad_gateway_error(error):
    log_error(error)
    if request.is_json:
        return jsonify(error="Bad gateway"), 502
    return render_template('errors/502.html'), 502

@main_bp.app_errorhandler(504)
def gateway_timeout_error(error):
    log_error(error)
    if request.is_json:
        return jsonify(error="Gateway timeout"), 504
    return render_template('errors/504.html'), 504

@main_bp.app_errorhandler(402)
def payment_required_error(error):
    log_error(error, 'warning')
    if request.is_json:
        return jsonify(error="Payment required"), 402
    return render_template('errors/402.html'), 402

def init_error_handlers(app):
    """Initialize error handlers and monitoring."""
    metrics.register_default(
        metrics.counter(
            'flask_error_total',
            'Total number of HTTP errors',
            labels={
                'code': lambda: request.view_args.get('code'),
                'path': lambda: request.path,
                'method': lambda: request.method,
                'user_id': lambda: session.get('user_id', 'anonymous')
            }
        )
    )
    
    metrics.register_default(
        metrics.histogram(
            'flask_error_response_time_seconds',
            'Error response time in seconds',
            labels={
                'code': lambda: request.view_args.get('code'),
                'path': lambda: request.path
            }
        )
    )

def handle_database_error(error):
    """Handle database connection/timeout errors."""
    log_error(error, level='error', context={
        'transaction_id': g.get('transaction_id'),
        'query': getattr(error, 'statement', None)
    })
    db.session.rollback()
    
    if request.is_json:
        return jsonify({
            'error': 'Database error',
            'code': 503,
            'retry_after': 30
        }), 503
    return render_template('errors/db_error.html', retry=30), 503

def handle_network_error(error):
    """Handle network timeouts and connection errors."""
    log_error(error, level='error', context={
        'remote_addr': request.remote_addr,
        'endpoint': request.endpoint
    })
    
    if request.is_json:
        return jsonify({
            'error': 'Network error',
            'code': 504,
            'retry_after': 60
        }), 504
    return render_template('errors/network_error.html', retry=60), 504
