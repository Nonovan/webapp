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
from flask import request
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
    group_by=['endpoint', 'http_status']
)  # Prometheus metrics for application monitoring

# Initialize counters
request_counter = metrics.counter(
    'http_requests_total',
    'Total HTTP request count',
    labels={
        'method': lambda: request.method,
        'endpoint': lambda: request.endpoint
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
        'status': lambda error: getattr(error, 'code', 500)
    }
)  # Counter for HTTP errors

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
    'error_counter'
]
