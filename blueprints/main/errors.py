from flask import Blueprint, request, jsonify, g, session, render_template, current_app
from extensions import db, metrics

def log_error(error, level='error', context=None) -> None:
    """
    Log an error to the application logger and record it in metrics.

    Args:
        error: The error object containing code and message
        level: Log level to use (default: 'error')
        context: Optional context information to include in log
    """
    log_message = f'Error {error.code}: {request.url} - {error}'
    if context:
        log_message += f' | Context: {context}'
    getattr(current_app.logger, level)(log_message)

    # Using the correct metrics API method (info) instead of increment
    metrics.info(f'error_{error.code}', 1)

def init_error_handlers(blueprint: Blueprint) -> Blueprint:
    """Initialize error handlers and monitoring."""

    # Register error metrics
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

    @blueprint.errorhandler(400)
    def bad_request_error(error) -> tuple:
        log_error(error, 'warning')
        if request.is_json:
            return jsonify(error="Bad request"), 400
        return render_template('errors/400.html'), 400

    @blueprint.errorhandler(401)
    def unauthorized_error(error) -> tuple:
        log_error(error, 'warning')
        if request.is_json:
            return jsonify(error="Unauthorized"), 401
        return render_template('errors/401.html'), 401

    @blueprint.errorhandler(403)
    def forbidden_error(error) -> tuple:
        log_error(error, 'warning')
        if request.is_json:
            return jsonify(error="Forbidden"), 403
        return render_template('errors/403.html'), 403

    @blueprint.errorhandler(404)
    def not_found_error(error) -> tuple:
        log_error(error, 'warning')
        if request.is_json:
            return jsonify(error="Not found"), 404
        return render_template('errors/404.html'), 404

    @blueprint.errorhandler(500)
    def internal_error(error) -> tuple:
        log_error(error, 'error')
        db.session.rollback()
        if request.is_json:
            return jsonify(error="Internal server error"), 500
        return render_template('errors/500.html'), 500

    @blueprint.errorhandler(503)
    def service_unavailable_error(error) -> tuple:
        log_error(error, 'error')
        if request.is_json:
            return jsonify(error="Service unavailable"), 503
        return render_template('errors/503.html'), 503

    return blueprint

def handle_database_error(error) -> tuple:
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

def handle_network_error(error) -> tuple:
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
