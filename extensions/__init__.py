"""
Flask extensions for Cloud Infrastructure Platform.

This module initializes and configures all Flask extensions used by the application.
It provides a centralized way to manage extension dependencies and configuration.
"""

from typing import Dict, Any, Optional, Callable
from flask import request, g, current_app, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache
from flask_session import Session
from flask_mail import Mail
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from prometheus_flask_exporter import PrometheusMetrics
import redis

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
csrf = CSRFProtect()
cache = Cache()
session = Session()
mail = Mail()
cors = CORS()
talisman = Talisman()

# Security extensions
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)  # Rate limiting to prevent abuse

# Cache configuration
CACHE_CONFIG: Dict[str, Any] = {
    'CACHE_TYPE': 'redis',
    'CACHE_DEFAULT_TIMEOUT': 300,
    'CACHE_KEY_PREFIX': 'myapp_'
}

# Metrics configuration
metrics = PrometheusMetrics.for_app_factory(
    app_name='myapp',
    path='/metrics',
    group_by=['endpoint', 'http_status'],
    defaults_prefix='myapp',
    default_labels={'environment': lambda: current_app.config.get('ENVIRONMENT', 'production')}
)  # Prometheus metrics for application monitoring

# Initialize counters
request_counter = metrics.counter(
    'http_requests_total',
    'Total HTTP request count',
    labels={
        'method': lambda: request.method,
        'endpoint': lambda: request.endpoint,
        'user_role': lambda: session.get('role', 'anonymous') if hasattr(session, 'get') else 'unknown',
        'is_authenticated': lambda: 'user_id' in session if hasattr(session, '__contains__') else False
    }
)  # Counter for overall HTTP requests

endpoint_counter = metrics.counter(
    'http_requests_by_endpoint_total',
    'Total HTTP requests by endpoint path',
    labels={
        'method': lambda: request.method,
        'path': lambda: request.path,
        'endpoint': lambda: request.endpoint
    }
)  # Counter for requests by specific endpoint

error_counter = metrics.counter(
    'http_errors_total',
    'Total HTTP errors by status code',
    labels={
        'method': lambda: request.method,
        'status': lambda error: getattr(error, 'code', 500),
        'path': lambda: request.path
    }
)  # Counter for HTTP errors

# Security metrics
security_event_counter = metrics.counter(
    'security_events_total',
    'Total security events by type and severity',
    labels={
        'event_type': lambda: g.get('security_event_type', 'unknown'),
        'severity': lambda: g.get('security_event_severity', 'info'),
        'authenticated': lambda: 'user_id' in session if hasattr(session, '__contains__') else False
    }
)  # Counter for security events

auth_counter = metrics.counter(
    'auth_attempts_total',
    'Authentication attempts (success/failure)',
    labels={
        'result': lambda: g.get('auth_result', 'unknown'),
        'method': lambda: g.get('auth_method', 'unknown')
    }
)  # Counter for authentication attempts

# ICS system metrics
ics_gauge = metrics.gauge(
    'ics_system_parameters',
    'Current ICS system parameter values',
    labels={
        'parameter': lambda: g.get('ics_parameter', 'unknown'),
        'unit': lambda: g.get('ics_unit', 'unknown'),
        'zone': lambda: g.get('ics_zone', 'main')
    },
    registry=metrics.registry
)  # Gauge for ICS system parameters

# Performance metrics
request_latency = metrics.histogram(
    'request_latency_seconds',
    'Request latency in seconds',
    labels={
        'endpoint': lambda: request.endpoint,
        'method': lambda: request.method
    },
    buckets=(0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0)
)  # Histogram for request latency

# Database metrics
db_query_counter = metrics.counter(
    'database_queries_total',
    'Total database queries executed',
    labels={
        'operation': lambda: g.get('db_operation', 'unknown'),
        'model': lambda: g.get('db_model', 'unknown'),
        'status': lambda: g.get('db_status', 'success')
    }
)  # Counter for database queries

# Cloud resources metrics
cloud_resource_gauge = metrics.gauge(
    'cloud_resources_count',
    'Count of active cloud resources by provider and type',
    labels={
        'provider': lambda: g.get('cloud_provider', 'unknown'),
        'resource_type': lambda: g.get('resource_type', 'unknown'),
        'region': lambda: g.get('cloud_region', 'unknown')
    },
    registry=metrics.registry
)  # Gauge for cloud resources


def get_redis_client() -> Optional[redis.Redis]:
    """
    Get a Redis client instance based on application configuration.

    Returns:
        Optional[redis.Redis]: Redis client or None if configuration is missing
    """
    try:
        if current_app.config.get('REDIS_URL'):
            return redis.from_url(current_app.config.get('REDIS_URL'))
        elif all(current_app.config.get(k) for k in ['REDIS_HOST', 'REDIS_PORT']):
            return redis.Redis(
                host=current_app.config.get('REDIS_HOST'),
                port=current_app.config.get('REDIS_PORT'),
                db=current_app.config.get('REDIS_DB', 0),
                password=current_app.config.get('REDIS_PASSWORD'),
                ssl=current_app.config.get('REDIS_SSL', False),
                decode_responses=False
            )
        return None
    except (redis.RedisError, Exception) as e:
        current_app.logger.error(f"Redis connection error: {e}")
        return None


def init_extensions(app) -> None:
    """
    Initialize all Flask extensions with the app.

    Args:
        app: Flask application instance
    """
    # Database and ORM
    db.init_app(app)
    migrate.init_app(app, db)

    # Security-related extensions
    jwt.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    cors.init_app(
        app,
        resources=app.config.get('CORS_RESOURCES', {}),
        origins=app.config.get('CORS_ORIGINS', '*')
    )

    # Session, caching and email
    cache.init_app(app, config=app.config.get('CACHE_CONFIG', CACHE_CONFIG))
    session.init_app(app)
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
    'session',
    'talisman',
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
    'get_redis_client',
    'init_extensions'
]
