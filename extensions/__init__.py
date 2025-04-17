"""
Flask extensions module for the myproject application.

This module initializes and configures all Flask extensions used throughout the application,
establishing the core infrastructure components needed for the application to function.
It includes:
- Database connections and migrations (SQLAlchemy, Alembic)
- Security features (CSRF protection, rate limiting, CORS)
- Caching infrastructure (Redis)
- Email and session handling
- Metrics collection and reporting (Prometheus)

All extensions are instantiated here but configured and initialized during application
factory setup. This separation allows for proper context binding and testing isolation.
"""

from typing import Dict, Any
from flask import request, g, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache
from flask_session import Session
from flask_mail import Mail
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from prometheus_flask_exporter import PrometheusMetrics


# Database extensions
db = SQLAlchemy()  # SQLAlchemy database ORM instance
migrate = Migrate()  # Flask-Migrate for database migrations

# Security extensions
csrf = CSRFProtect()  # CSRF protection for forms
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)  # Rate limiting to prevent abuse
cors = CORS()  # Cross-Origin Resource Sharing support

# Cache configuration
CACHE_CONFIG: Dict[str, Any] = {
    'CACHE_TYPE': 'redis',
    'CACHE_DEFAULT_TIMEOUT': 300,
    'CACHE_KEY_PREFIX': 'myapp_'
}
cache = Cache(config=CACHE_CONFIG)  # Application cache using Redis

# Email and session
mail = Mail()  # Email sending capabilities
session = Session()  # Server-side session management

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
        'user_role': lambda: session.get('role', 'anonymous'),
        'is_authenticated': lambda: 'user_id' in session
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
        'authenticated': lambda: 'user_id' in session
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

__all__ = [
    'db',
    'migrate',
    'csrf',
    'limiter',
    'cors',
    'cache',
    'mail',
    'session',
    'metrics',
    'request_counter',
    'endpoint_counter',
    'error_counter',
    'security_event_counter',
    'auth_counter',
    'ics_gauge',
    'request_latency',
    'db_query_counter',
    'cloud_resource_gauge'
]
