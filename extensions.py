"""
Flask extensions initialization module for myproject.

This module initializes and configures Flask extensions used throughout the application.
It maintains these extensions as module-level variables to avoid circular imports and
to provide a central point for extension instance management.

Extensions are initialized but not bound to the application here - the actual binding
happens during application creation in the application factory. This separation allows
for proper testing setup, flexible configuration, and avoids circular imports.

Extensions included:
- Database ORM via SQLAlchemy
- Database migrations via Flask-Migrate
- Security features (CSRF, CORS, rate limiting)
- Caching via Redis
- Session handling
- Metrics collection via Prometheus
"""

# Core extensions needed
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache
from flask_session import Session
from prometheus_flask_exporter import PrometheusMetrics
from flask_cors import CORS

# Database - Required for models
db = SQLAlchemy()
"""
SQLAlchemy ORM integration for Flask.

This extension provides a Flask-integrated SQLAlchemy instance for defining models
and interacting with the database. It manages database connections, session handling,
and model registration.

Examples:
    Define a model:
    ```
    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True)
    ```

    Query the database:
    ```
    user = User.query.filter_by(username='admin').first()
    ```
"""

migrate = Migrate()
"""
Database migration support via Alembic.

This extension integrates Alembic with Flask to provide database migration
capabilities, enabling schema changes to be tracked, versioned, and applied
consistently across different environments.

Examples:
    Generate a migration after model changes:
    ```
    flask db migrate -m "Add user table"
    ```

    Apply pending migrations:
    ```
    flask db upgrade
    ```
"""

# Security - Required for protection
csrf = CSRFProtect()
"""
Cross-Site Request Forgery protection.

This extension adds CSRF protection to all forms and POST requests, mitigating
against CSRF attacks by requiring a secure token with form submissions.

Examples:
    Generate a CSRF token in a form:
    ```
    <form method="post">
        {{ csrf_token() }}
        ...
    </form>
    ```

    Skip CSRF protection for specific views:
    ```
    @csrf.exempt
    def my_view():
        ...
    ```
"""

cors = CORS()
"""
Cross-Origin Resource Sharing support.

This extension handles CORS headers for the application, allowing controlled
cross-origin requests based on application configuration.

Examples:
    Setting CORS parameters during initialization:
    ```
    cors.init_app(app, resources={r"/api/*": {"origins": "*"}})
    ```
"""

# Performance - Required for scaling
cache = Cache(config={
    'CACHE_TYPE': 'redis',
    'CACHE_DEFAULT_TIMEOUT': 300
})
"""
Application caching via Redis.

This extension provides caching capabilities to improve performance by storing
the results of expensive operations for a configurable period of time.

Examples:
    Caching a view:
    ```
    @cache.cached(timeout=50)
    def cached_view():
        ...
    ```

    Caching an arbitrary function:
    ```
    @cache.memoize(300)
    def expensive_calculation(param1, param2):
        ...
    ```
"""

# Session handling - Required for auth
session = Session()
"""
Server-side session management.

This extension provides server-side session storage with Redis, improving security
and scalability compared to client-side sessions.

Examples:
    Storing values in the session:
    ```
    session['user_id'] = user.id
    ```

    Checking for values in the session:
    ```
    if 'user_id' in session:
        ...
    ```
"""

# Monitoring - Required for ops
metrics = PrometheusMetrics.for_app_factory()
"""
Prometheus metrics collection and exposition.

This extension adds Prometheus metrics collection for monitoring request counts,
response times, error rates, and custom application metrics.

Examples:
    Registering custom metrics:
    ```
    gauge = metrics.gauge('in_progress', 'Number of requests in progress')
    ```

    Recording metrics values:
    ```
    metrics.info('requests_by_path', 1, labels={'path': request.path})
    ```
"""

__all__ = ['db', 'migrate', 'csrf', 'cache', 'session', 'metrics', 'cors']
