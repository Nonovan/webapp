"""
Flask extensions for the Cloud Infrastructure Platform.

This module initializes and configures all Flask extensions used in the application,
ensuring they're properly set up and available throughout the system.
"""

import redis
import logging
import os
import time
from typing import Dict, Any, Optional, Callable, Union
from flask import request, g, current_app, session, Flask, Response
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
from flask_socketio import SocketIO, emit
from prometheus_client import Counter, Histogram, Gauge, Info, generate_latest, CONTENT_TYPE_LATEST
import geoip2.database
from functools import wraps

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

# Redis client for various uses (cache, pub/sub, session storage)
redis_client = None

# Initialize GeoIP reader
geoip = None

# Metrics tracking
metrics = None
db_query_counter = None
cloud_resource_gauge = None
socketio_connection_count = None
socketio_message_counter = None
socketio_error_counter = None
socketio_latency = None


def get_redis_client() -> Optional[redis.Redis]:
    """Get the Redis client instance."""
    return redis_client


def init_metrics(app: Flask) -> None:
    """
    Initialize metrics collection.

    Args:
        app: Flask application
    """
    global db_query_counter, cloud_resource_gauge, socketio_connection_count
    global socketio_message_counter, socketio_error_counter, socketio_latency, metrics

    # Create metrics namespace
    metrics_prefix = app.config.get('METRICS_PREFIX', 'cloud_platform')

    # Database metrics
    db_query_counter = Counter(
        f'{metrics_prefix}_db_queries_total',
        'Total number of database queries',
        ['operation', 'model', 'status']
    )

    # Cloud resource metrics
    cloud_resource_gauge = Gauge(
        f'{metrics_prefix}_cloud_resources',
        'Number of cloud resources',
        ['type', 'region', 'status']
    )

    # SocketIO metrics
    socketio_connection_count = Gauge(
        f'{metrics_prefix}_socketio_connections',
        'Number of active SocketIO connections'
    )

    socketio_message_counter = Counter(
        f'{metrics_prefix}_socketio_messages_total',
        'Total number of SocketIO messages',
        ['event', 'direction']
    )

    socketio_error_counter = Counter(
        f'{metrics_prefix}_socketio_errors_total',
        'Total number of SocketIO errors',
        ['type']
    )

    socketio_latency = Histogram(
        f'{metrics_prefix}_socketio_latency_seconds',
        'SocketIO message processing latency',
        ['event']
    )

    # Export the metrics object
    metrics = {
        'counter': Counter,
        'gauge': Gauge,
        'histogram': Histogram,
        'info': Info,
        'increment': lambda name, labels=None: Counter(f'{metrics_prefix}_{name}', f'{name} metric').inc()
    }


def init_redis(app: Flask) -> None:
    """
    Initialize Redis connection.

    Args:
        app: Flask application
    """
    global redis_client

    redis_url = app.config.get('REDIS_URL')
    if not redis_url:
        app.logger.warning("Redis URL not configured. Rate limiting and session features will be limited.")
        return

    try:
        redis_client = redis.from_url(
            redis_url,
            decode_responses=True,
            socket_timeout=app.config.get('REDIS_TIMEOUT', 5),
            socket_connect_timeout=app.config.get('REDIS_CONNECT_TIMEOUT', 5)
        )
        # Test the connection
        redis_client.ping()
        app.logger.info("Redis connection established successfully")
    except redis.RedisError as e:
        app.logger.error(f"Failed to connect to Redis: {e}")
        redis_client = None


def init_geoip(app: Flask) -> None:
    """
    Initialize GeoIP database reader.

    Args:
        app: Flask application
    """
    global geoip

    geoip_path = app.config.get('GEOIP_DB_PATH')
    if not geoip_path or not os.path.exists(geoip_path):
        app.logger.warning("GeoIP database not found. Geolocation features will be disabled.")
        return

    try:
        geoip = {
            'reader': geoip2.database.Reader(geoip_path),
            'get_location': lambda ip: _get_location_from_ip(ip)
        }
        app.geoip_reader = geoip['reader']
        app.logger.info("GeoIP database loaded successfully")
    except Exception as e:
        app.logger.error(f"Failed to initialize GeoIP: {e}")
        geoip = None


def _get_location_from_ip(ip: str) -> Optional[Dict[str, Any]]:
    """
    Get location information from an IP address.

    Args:
        ip: IP address to geolocate

    Returns:
        Dictionary with location information or None if not found
    """
    if not geoip or not geoip.get('reader'):
        return None

    try:
        response = geoip['reader'].city(ip)
        return {
            'city': response.city.name,
            'country': response.country.iso_code,
            'country_name': response.country.name,
            'latitude': response.location.latitude,
            'longitude': response.location.longitude
        }
    except Exception:
        return None


def emit_with_metrics(event, data=None, **kwargs):
    """
    Emit a SocketIO event with metrics tracking.

    Args:
        event: Event name
        data: Data to send
        **kwargs: Additional arguments to pass to emit
    """
    start_time = time.time()
    emit(event, data, **kwargs)

    # Track metrics
    socketio_message_counter.labels(event=event, direction='out').inc()
    socketio_latency.labels(event=event).observe(time.time() - start_time)


def init_extensions(app: Flask) -> None:
    """
    Initialize all Flask extensions with the app.

    Args:
        app: Flask application
    """
    # Initialize SQLAlchemy
    db.init_app(app)
    migrate.init_app(app, db)

    # Initialize JWT
    jwt.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    cors.init_app(app)

    # Initialize Redis
    init_redis(app)

    # Initialize GeoIP
    init_geoip(app)

    # Initialize metrics if enabled
    if app.config.get('METRICS_ENABLED', False):
        init_metrics(app)

        # Register metrics endpoint if configured
        if app.config.get('METRICS_REGISTER_VIEWS', True):
            metrics_endpoint = app.config.get('METRICS_ENDPOINT_PATH', '/metrics')

            # Authentication decorator for metrics endpoint
            def metrics_auth_required(f):
                @wraps(f)
                def decorated_function(*args, **kwargs):
                    if not app.config.get('METRICS_AUTH_ENABLED', False):
                        return f(*args, **kwargs)

                    auth = request.authorization
                    if not auth or auth.username != app.config.get('METRICS_USERNAME', 'prometheus') or \
                       auth.password != app.config.get('METRICS_PASSWORD', 'secret'):
                        return Response('Unauthorized', 401, {'WWW-Authenticate': 'Basic realm="Metrics"'})

                    return f(*args, **kwargs)
                return decorated_function

            @app.route(metrics_endpoint)
            @metrics_auth_required
            def metrics_view():
                return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

            app.logger.info(f"Metrics endpoint registered at {metrics_endpoint}")

    # Set up exception tracking
    @app.errorhandler(Exception)
    def track_exceptions(error):
        if hasattr(metrics, 'counter'):
            metrics['counter'](
                f'exceptions_total',
                'Total number of exceptions',
                ['type']
            ).labels(type=error.__class__.__name__).inc()

        # Re-raise the exception to be handled by Flask
        raise error

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
    'jwt',
    'redis_client',
    'geoip',
    'metrics',
    'db_query_counter',
    'cloud_resource_gauge',
    'socketio_connection_count',
    'socketio_message_counter',
    'socketio_error_counter',
    'socketio_latency',
    'emit_with_metrics',
    'get_redis_client',
    'init_extensions'
]
