"""
Flask extensions for Cloud Infrastructure Platform.

This module initializes and configures all Flask extensions used by the application.
It provides a centralized way to manage extension dependencies and configuration.
"""

import redis
import logging
from typing import Dict, Any, Optional, Callable, Union
from prometheus_flask_exporter import PrometheusMetrics
from flask import request, g, current_app, session, Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache
from flask_session import Session
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_cors import CORS
from flask_migrate import Migrate
from flask_socketio import SocketIO

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
csrf = CSRFProtect()
cache = Cache()
session_extension = Session()  # Renamed to avoid conflict with flask.session
mail = Mail()
cors = CORS()
talisman = Talisman()
socketio = SocketIO()  # Initialize SocketIO extension

# Security extensions
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Monitoring extensions
metrics = PrometheusMetrics()

# Redis client for various uses (cache, pub/sub, session storage)
_redis_client = None

def get_redis_client() -> Optional[redis.Redis]:
    """Get the Redis client instance."""
    global _redis_client
    return _redis_client

def set_redis_client(client: redis.Redis) -> None:
    """Set the Redis client instance."""
    global _redis_client
    _redis_client = client

# Import internal modules after initializing objects to avoid circular imports
from .metrics import request_counter, endpoint_counter, error_counter, security_event_counter, auth_counter, ics_gauge, request_latency, db_query_counter

# Create gauge for cloud resources
cloud_resource_gauge = metrics.gauge(
    'cloud_resources',
    'Cloud resources by provider and type',
    labels={
        'provider': lambda: g.get('cloud_provider', 'unknown'),
        'type': lambda: g.get('resource_type', 'unknown'),
        'region': lambda: g.get('cloud_region', 'unknown')
    },
    registry=metrics.registry
)  # Gauge for cloud resources

# Import SocketIO extension implementation
from .socketio import socketio_connection_count, socketio_message_counter, socketio_error_counter, socketio_latency, emit_with_metrics

def init_extensions(app: Flask) -> None:
    """
    Initialize all Flask extensions with the application.

    This function configures each extension with appropriate settings
    based on the application configuration.

    Args:
        app: The Flask application instance
    """
    # Database
    db.init_app(app)
    migrate.init_app(app, db)

    # Security
    jwt.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    cors.init_app(app)

    # Configure Redis for various services if available
    if app.config.get('REDIS_URL'):
        client = redis.from_url(
            app.config['REDIS_URL'],
            decode_responses=True  # Store as strings not bytes
        )
        set_redis_client(client)
    else:
        # Fallback to simple memory cache
        app.logger.warning("Redis URL not configured, using in-memory cache")
        cache.init_app(app, config={'CACHE_TYPE': 'SimpleCache'})

    # Configure cache with Redis if available
    cache_config = {
        'CACHE_TYPE': 'RedisCache',
        'CACHE_DEFAULT_TIMEOUT': app.config.get('CACHE_DEFAULT_TIMEOUT', 300)
    }

    if app.config.get('REDIS_URL') and 'CACHE_REDIS_URL' not in cache_config:
        cache_config['CACHE_REDIS_URL'] = app.config.get('REDIS_URL')

    cache.init_app(app, config=cache_config)
    session_extension.init_app(app)
    mail.init_app(app)

    # Configure metrics with additional settings if provided
    if app.config.get('METRICS_AUTH_ENABLED'):
        metrics.configure_with_auth(
            username=app.config.get('METRICS_USERNAME'),
            password=app.config.get('METRICS_PASSWORD')
        )

    # Only enable Talisman in production or if explicitly configured
    if app.config.get('SECURITY_HEADERS_ENABLED', False) or app.config.get('ENV') == 'production':
        csp = app.config.get('CONTENT_SECURITY_POLICY')
        talisman.init_app(
            app,
            content_security_policy=csp,
            content_security_policy_nonce_in=['script-src'] if csp else None,
            force_https=app.config.get('FORCE_HTTPS', True),
            session_cookie_secure=app.config.get('SESSION_COOKIE_SECURE', True),
            session_cookie_http_only=app.config.get('SESSION_COOKIE_HTTPONLY', True),
            strict_transport_security=app.config.get('STRICT_TRANSPORT_SECURITY', True),
            strict_transport_security_preload=app.config.get('HSTS_PRELOAD', False),
            referrer_policy=app.config.get('REFERRER_POLICY', 'strict-origin-when-cross-origin')
        )

    # Register metrics blueprints if applicable
    if app.config.get('METRICS_REGISTER_VIEWS', True):
        metrics.register_endpoint(
            path=app.config.get('METRICS_ENDPOINT_PATH', '/metrics')
        )

    # Initialize SocketIO extension
    from .socketio import init_app as init_socketio
    init_socketio(app)

    # Register JWT handlers
    register_jwt_handlers(app)

# Register JWT token handlers for security
def register_jwt_handlers(app: Flask) -> None:
    """Register handlers for JWT authentication events."""
    # Implementation of JWT handlers...
    pass

# List of all extensions for import in other modules
__all__ = [
    'db',
    'migrate',
    'jwt',
    'csrf',
    'limiter',
    'cors',
    'cache',
    'mail',
    'session_extension',  # Updated name to avoid conflict
    'talisman',
    'socketio',  # Added SocketIO to exports
    'metrics',
    'request_counter',
    'endpoint_counter',
    'error_counter',
    'security_event_counter',
    'auth_counter',
    'ics_gauge',
    'request_latency',
    'db_query_counter',
    'cloud_resource_gauge',
    'socketio_connection_count',  # Added SocketIO metrics
    'socketio_message_counter',
    'socketio_error_counter',
    'socketio_latency',
    'emit_with_metrics',  # Added helper function
    'get_redis_client',
    'init_extensions'
]
