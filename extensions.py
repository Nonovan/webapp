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
- Token blacklisting
- Security monitoring
- File integrity monitoring via Circuit Breaker pattern
- Geo-location services
"""

# Core extensions needed
from flask import request, g, session, current_app, has_request_context
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache
from flask_session import Session
from prometheus_flask_exporter import PrometheusMetrics
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager, get_jwt
import redis
import logging
import os
import json
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Callable, List, Union, Set, Tuple

# Initialize logger
logger = logging.getLogger(__name__)

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

# Rate limiting - Protection against abuse
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    strategy="fixed-window"
)
"""
Rate limiting for API endpoints.

This extension provides protection against abuse and DoS attacks by limiting
the number of requests clients can make in a specified time period.

Examples:
    Apply rate limits to a specific route:
    ```
    @app.route('/api/resource')
    @limiter.limit("10 per minute")
    def limited_resource():
        ...
    ```

    Customize the rate limit key:
    ```
    @limiter.limit("10 per minute", key_func=lambda: request.headers.get('X-API-Key'))
    def api_endpoint():
        ...
    ```
"""

# Performance - Required for scaling
cache = Cache()
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
session_extension = Session()
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

# JWT handling - Required for API auth
jwt = JWTManager()
"""
JSON Web Token management.

This extension handles the creation, validation, and refreshing of JWTs for
API authentication, allowing stateless authentication for API clients.

Examples:
    Creating a JWT:
    ```
    access_token = create_access_token(identity=user.id)
    ```

    Accessing the JWT identity:
    ```
    @jwt_required()
    def protected_route():
        current_user_id = get_jwt_identity()
    ```
"""

# Private module-level variable
_redis_client = None

def get_redis_client():
    """
    Get the application's Redis client instance.

    Returns:
        Redis client or None if not initialized
    """
    return _redis_client

def set_redis_client(client):
    """
    Set the application's Redis client instance.

    Args:
        client: Redis client instance
    """
    global _redis_client
    _redis_client = client

# GeoIP support - for location-based features
_geoip_instance = None

def get_geoip():
    """
    Get the application's GeoIP instance.

    Returns:
        GeoIP instance or None if not initialized
    """
    return _geoip_instance

# Circuit Breaker pattern - for reliable external service calls
class CircuitBreakerState:
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operations - requests pass through
    OPEN = "open"      # Circuit is open - requests are blocked
    HALF_OPEN = "half_open"  # Testing the waters - limited requests allowed

class CircuitOpenError(Exception):
    """Exception raised when a circuit is open."""
    def __init__(self, circuit_name, message="Circuit is open"):
        self.circuit_name = circuit_name
        self.message = f"{message} ({circuit_name})"
        super().__init__(self.message)

# Circuit breaker registry
_circuit_breakers = {}

def create_circuit_breaker(
    name: str,
    failure_threshold: int = 5,
    reset_timeout: float = 60.0,
    half_open_after: float = 30.0,
    excluded_exceptions: tuple = ()
) -> None:
    """
    Create and register a new circuit breaker.

    Args:
        name: Unique name for the circuit breaker
        failure_threshold: Number of failures before opening circuit
        reset_timeout: Time in seconds before resetting failure count
        half_open_after: Time in seconds before trying half-open state
        excluded_exceptions: Exception types that don't count as failures
    """
    _circuit_breakers[name] = {
        'state': CircuitBreakerState.CLOSED,
        'failure_count': 0,
        'last_failure_time': 0,
        'last_state_change': time.time(),
        'failure_threshold': failure_threshold,
        'reset_timeout': reset_timeout,
        'half_open_after': half_open_after,
        'excluded_exceptions': excluded_exceptions
    }
    logger.debug(f"Created circuit breaker: {name}")

def circuit_breaker(name: str, failure_threshold: int = None, reset_timeout: float = None,
                   half_open_after: float = None, excluded_exceptions: tuple = None):
    """
    Circuit breaker decorator for functions that call external services.

    Args:
        name: Name of the circuit breaker to use
        failure_threshold: Number of failures before circuit opens
        reset_timeout: Time in seconds before resetting failure count
        half_open_after: Time in seconds before trying half-open state
        excluded_exceptions: Exceptions that don't count as failures

    Returns:
        Decorated function with circuit breaker protection
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Create circuit breaker if it doesn't exist
            if name not in _circuit_breakers:
                create_circuit_breaker(
                    name=name,
                    failure_threshold=failure_threshold or 5,
                    reset_timeout=reset_timeout or 60.0,
                    half_open_after=half_open_after or 30.0,
                    excluded_exceptions=excluded_exceptions or ()
                )

            # Get circuit breaker
            circuit = _circuit_breakers[name]
            now = time.time()

            # Reset failure count if enough time has passed
            if (circuit['state'] == CircuitBreakerState.CLOSED and
                circuit['failure_count'] > 0 and
                now - circuit['last_failure_time'] > circuit['reset_timeout']):
                circuit['failure_count'] = 0

            # Try to move from OPEN to HALF_OPEN if enough time has passed
            if (circuit['state'] == CircuitBreakerState.OPEN and
                now - circuit['last_state_change'] > circuit['half_open_after']):
                circuit['state'] = CircuitBreakerState.HALF_OPEN
                circuit['last_state_change'] = now
                logger.info(f"Circuit {name} moving to half-open state")

            # Check circuit state
            if circuit['state'] == CircuitBreakerState.OPEN:
                # Increment metrics if available
                if metrics and hasattr(metrics, 'counter'):
                    metrics.counter('circuit_breaker_blocks_total', 1, {'circuit': name})

                raise CircuitOpenError(circuit_name=name)

            # Allow request if CLOSED or testing in HALF_OPEN
            try:
                result = func(*args, **kwargs)

                # Successful request in HALF_OPEN moves back to CLOSED
                if circuit['state'] == CircuitBreakerState.HALF_OPEN:
                    circuit['state'] = CircuitBreakerState.CLOSED
                    circuit['failure_count'] = 0
                    circuit['last_state_change'] = now
                    logger.info(f"Circuit {name} back to closed state")

                    # Update metrics if available
                    if metrics and hasattr(metrics, 'gauge'):
                        metrics.gauge('circuit_breaker_state', 0, {'circuit': name})

                return result

            except Exception as e:
                # Skip excluded exceptions
                if isinstance(e, circuit['excluded_exceptions']):
                    raise

                # Increment failure count
                circuit['failure_count'] += 1
                circuit['last_failure_time'] = now

                # Log failure
                logger.warning(f"Circuit {name} registered failure ({circuit['failure_count']}/{circuit['failure_threshold']}): {str(e)}")

                # Update metrics if available
                if metrics and hasattr(metrics, 'counter'):
                    metrics.counter('circuit_breaker_failures_total', 1, {'circuit': name})

                # Check if threshold exceeded
                if circuit['failure_count'] >= circuit['failure_threshold']:
                    if circuit['state'] != CircuitBreakerState.OPEN:
                        circuit['state'] = CircuitBreakerState.OPEN
                        circuit['last_state_change'] = now
                        logger.error(f"Circuit {name} tripped open after {circuit['failure_count']} failures")

                        # Update metrics if available
                        if metrics and hasattr(metrics, 'gauge'):
                            metrics.gauge('circuit_breaker_state', 2, {'circuit': name})  # 2 = OPEN

                        # Track security event if we have access to the app context
                        if has_request_context() and hasattr(g, 'get'):
                            g.security_event_type = 'circuit_breaker_trip'
                            g.security_event_severity = 'warning'

                # Re-raise the exception
                raise
        return wrapper
    return decorator

def reset_circuit(name: str) -> bool:
    """
    Reset a circuit breaker to closed state.

    Args:
        name: Circuit name to reset

    Returns:
        True if reset was successful, False if circuit not found
    """
    if name not in _circuit_breakers:
        return False

    circuit = _circuit_breakers[name]
    circuit['state'] = CircuitBreakerState.CLOSED
    circuit['failure_count'] = 0
    circuit['last_state_change'] = time.time()
    logger.info(f"Circuit {name} manually reset to closed state")

    # Update metrics if available
    if metrics and hasattr(metrics, 'gauge'):
        metrics.gauge('circuit_breaker_state', 0, {'circuit': name})

    return True

def reset_all_circuits() -> int:
    """
    Reset all circuit breakers to closed state.

    Returns:
        Number of circuits reset
    """
    reset_count = 0
    for name in _circuit_breakers:
        reset_circuit(name)
        reset_count += 1
    return reset_count

def get_all_circuits() -> Dict[str, Dict[str, Any]]:
    """
    Get the state of all circuit breakers.

    Returns:
        Dictionary of circuit breakers with their current state
    """
    return {k: v.copy() for k, v in _circuit_breakers.items()}

# Rate limiting constants
FIXED_WINDOW = "fixed-window"
SLIDING_WINDOW = "moving-window"
TOKEN_BUCKET = "token-bucket"

# Rate limiters registry
_rate_limiters = {}

class RateLimitExceededError(Exception):
    """Exception raised when rate limit is exceeded."""
    def __init__(self, key, limit):
        self.key = key
        self.limit = limit
        self.message = f"Rate limit exceeded for {key}: {limit}"
        super().__init__(self.message)

def get_user_id() -> str:
    """Get current user ID for rate limiting."""
    user_id = None
    if has_request_context():
        if hasattr(g, 'get') and g.get('user_id'):
            user_id = g.get('user_id')
        elif hasattr(session, 'get') and session.get('user_id'):
            user_id = session.get('user_id')
    return str(user_id or 'anonymous')

def get_ip_address() -> str:
    """Get client IP address for rate limiting."""
    if not has_request_context():
        return 'unknown'

    # Try to get real IP behind proxies
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or 'unknown'

def get_api_key() -> str:
    """Get API key from request for rate limiting."""
    if not has_request_context():
        return 'none'

    # Check for API key in header or query param
    return (request.headers.get('X-API-Key') or
            request.args.get('api_key') or
            'none')

def get_combined_key() -> str:
    """Get combined user+IP key for rate limiting."""
    user_id = get_user_id()
    ip = get_ip_address()
    return f"{user_id}:{ip}"

def create_limiter(key: str, limit: str, window: str = FIXED_WINDOW,
                   key_func: Callable = None) -> None:
    """
    Create and register a new rate limiter.

    Args:
        key: Unique name for the rate limiter
        limit: Rate limit string (e.g. "10 per minute")
        window: Rate limit algorithm to use
        key_func: Function to extract the limiting key
    """
    if key_func is None:
        key_func = get_combined_key

    _rate_limiters[key] = {
        'limit': limit,
        'window': window,
        'key_func': key_func,
        'counters': {},
        'last_reset': time.time()
    }
    logger.debug(f"Created rate limiter: {key}")

def rate_limit(key: str, limit: str = None, window: str = None,
              key_func: Callable = None):
    """
    Rate limiter decorator for API endpoints.

    Args:
        key: Rate limiter name
        limit: Rate limit string (e.g. "10 per minute")
        window: Rate limit algorithm
        key_func: Function to extract limiting key

    Returns:
        Decorated function with rate limiting
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Create rate limiter if it doesn't exist
            if key not in _rate_limiters:
                create_limiter(
                    key=key,
                    limit=limit or "100 per minute",
                    window=window or FIXED_WINDOW,
                    key_func=key_func or get_combined_key
                )

            # Get rate limiter config
            limiter_config = _rate_limiters[key]

            # Get limiting key
            limit_key = limiter_config['key_func']()

            # Update rate limiter state
            if limit_key not in limiter_config['counters']:
                limiter_config['counters'][limit_key] = {
                    'count': 0,
                    'first_request': time.time(),
                    'last_request': time.time()
                }

            # Get counter
            counter = limiter_config['counters'][limit_key]
            counter['last_request'] = time.time()

            # Parse limit
            limit_parts = limiter_config['limit'].split()
            max_requests = int(limit_parts[0])

            # Calculate window in seconds
            time_unit = limit_parts[2] if len(limit_parts) >= 3 else "minute"
            window_seconds = {
                'second': 1,
                'seconds': 1,
                'minute': 60,
                'minutes': 60,
                'hour': 3600,
                'hours': 3600,
                'day': 86400,
                'days': 86400
            }.get(time_unit, 60)

            # Check if window has expired
            elapsed = time.time() - counter['first_request']
            if elapsed > window_seconds:
                # Reset counter for new window
                counter['count'] = 0
                counter['first_request'] = time.time()

            # Increment counter
            counter['count'] += 1

            # Check limit
            if counter['count'] > max_requests:
                # Log rate limit exceeded
                logger.warning(f"Rate limit exceeded for {key}:{limit_key}: {counter['count']} requests")

                # Update metrics if available
                if metrics and hasattr(metrics, 'counter'):
                    metrics.counter('rate_limit_exceeded_total', 1, {
                        'limiter': key,
                        'limit': limiter_config['limit']
                    })

                # Track as security event
                if has_request_context() and hasattr(g, 'get'):
                    g.security_event_type = 'rate_limit_exceeded'
                    g.security_event_severity = 'warning'

                raise RateLimitExceededError(key=limit_key, limit=limiter_config['limit'])

            # Execute the decorated function
            return func(*args, **kwargs)

        return wrapper

    return decorator

# File integrity monitoring constants
_FILE_HASH_ALGORITHMS = {
    'md5': 'md5',
    'sha1': 'sha1',
    'sha256': 'sha256',
    'sha512': 'sha512'
}

_FILE_INTEGRITY_STATUS = {}
_FILE_INTEGRITY_BASELINES = {}

# Initialize metrics counters
request_counter = metrics.counter(
    'http_requests_total',
    'Total HTTP request count',
    labels={
        'method': lambda: request.method,
        'endpoint': lambda: request.endpoint
    }
)

endpoint_counter = metrics.counter(
    'http_requests_by_endpoint_total',
    'Total HTTP requests by endpoint path',
    labels={
        'method': lambda: request.method,
        'path': lambda: request.path,
        'endpoint': lambda: request.endpoint
    }
)

error_counter = metrics.counter(
    'http_errors_total',
    'Total HTTP errors by status code',
    labels={
        'method': lambda: request.method,
        'status': lambda error: getattr(error, 'code', 500)
    }
)

security_event_counter = metrics.counter(
    'security_events_total',
    'Total security events by type',
    labels={
        'event_type': lambda: g.get('security_event_type', 'unknown'),
        'severity': lambda: g.get('security_event_severity', 'info')
    }
)

auth_attempt_counter = metrics.counter(
    'authentication_attempts_total',
    'Authentication attempt counts',
    labels={
        'success': lambda: g.get('auth_success', False),
        'method': lambda: g.get('auth_method', 'unknown')
    }
)

session_activity_gauge = metrics.gauge(
    'active_sessions',
    'Number of active sessions by type',
    labels={
        'type': lambda: g.get('session_type', 'user')
    }
)

# File integrity metrics
file_integrity_gauge = metrics.gauge(
    'file_integrity_status',
    'File integrity status',
    labels={
        'status': lambda: g.get('file_integrity_status', 'unknown'),
        'environment': lambda: current_app.config.get('ENVIRONMENT', 'unknown') if has_request_context() else 'unknown'
    }
)

file_integrity_violations = metrics.counter(
    'file_integrity_violations_total',
    'Total file integrity violations',
    labels={
        'severity': lambda: g.get('violation_severity', 'unknown'),
        'path_pattern': lambda: g.get('violation_pattern', 'unknown')
    }
)

file_baseline_updates = metrics.counter(
    'file_baseline_updates_total',
    'Total file baseline updates',
    labels={
        'status': lambda: g.get('baseline_update_status', 'unknown'),
        'environment': lambda: current_app.config.get('ENVIRONMENT', 'unknown') if has_request_context() else 'unknown'
    }
)

def init_extensions(app):
    """
    Initialize all extensions with the Flask app.

    This function binds all extension instances to the Flask application,
    configuring them based on the app's config. This function centralizes
    the extension initialization to ensure proper setup order and error handling.

    Args:
        app: Flask application instance
    """
    # Initialize database
    db.init_app(app)
    migrate.init_app(app, db)

    # Initialize security extensions
    csrf.init_app(app)
    cors.init_app(app)
    limiter.init_app(app)

    # Initialize cache & Redis client
    if app.config.get('REDIS_URL'):
        # Use same Redis connection for both when possible
        cache_config = {
            'CACHE_TYPE': 'redis',
            'CACHE_REDIS_URL': app.config['REDIS_URL'],
            'CACHE_DEFAULT_TIMEOUT': app.config.get('CACHE_DEFAULT_TIMEOUT', 300),
            'CACHE_KEY_PREFIX': app.config.get('CACHE_KEY_PREFIX', 'myapp_')
        }
        cache.init_app(app, config=cache_config)

        # Initialize Redis client
        client = redis.from_url(
            app.config['REDIS_URL'],
            decode_responses=True  # Store as strings not bytes
        )
        set_redis_client(client)
    else:
        # Fallback to simple memory cache
        app.logger.warning("Redis URL not configured, using in-memory cache")
        cache.init_app(app, config={'CACHE_TYPE': 'SimpleCache'})

    # Configure server-side sessions
    session_extension.init_app(app)

    # Initialize JWT
    jwt.init_app(app)

    # Set up JWT token blacklisting if Redis is available
    redis_client = get_redis_client()
    if redis_client and app.config.get('JWT_BLACKLIST_ENABLED', False):
        @jwt.token_in_blocklist_loader
        def check_if_token_is_revoked(_jwt_header, jwt_payload):
            """
            Check if the provided JWT token has been revoked.

            This function is called by the JWT manager for every protected endpoint
            to verify that the token hasn't been blacklisted. It uses Redis to store
            blacklisted tokens for efficient lookup.

            Args:
                jwt_header: JWT header data
                jwt_payload: JWT payload containing claims

            Returns:
                bool: True if token is blacklisted, False otherwise
            """
            jti = jwt_payload['jti']
            token_in_redis = redis_client.get(f"blacklist:{jti}")
            return token_in_redis is not None

    # Initialize metrics
    metrics.init_app(app)

    # Initialize custom security metrics
    if app.config.get('METRICS_ENABLED', True):
        # Register custom metrics collectors
        @app.before_request
        def track_request_metrics():
            """
            Track request metrics for each incoming request.

            This function increments various Prometheus counters for HTTP request tracking
            and monitors active user sessions. It runs before each request is processed.
            """
            # Basic request tracking
            request_counter.inc()
            endpoint_counter.inc()

            # Track active session count
            if hasattr(session, 'get') and session.get('user_id'):
                session_activity_gauge.labels(type='user').inc()
                g.session_started = True

        @app.teardown_appcontext
        def track_session_end(_=None):
            """
            Update metrics when a request context ends.

            This function decrements active session counters when a request completes,
            ensuring accurate tracking of concurrent active sessions.

            Args:
                _: Exception that occurred during request handling (not used)
            """
            # Decrement active session count
            if hasattr(g, 'session_started') and g.session_started:
                session_activity_gauge.labels(type='user').dec()

        @app.errorhandler(Exception)
        def track_exceptions(error):
            """
            Track exceptions in Prometheus metrics.

            This handler ensures that all exceptions are counted in the error metrics,
            categorized by their HTTP status code when available.

            Args:
                error: The exception that occurred

            Returns:
                tuple: Error response and status code from the original error handler
            """
            error_counter.labels(status=getattr(error, 'code', 500)).inc()

            # Pass to next error handler
            if hasattr(app, '_find_error_handler'):
                handler = app.handle_user_exception(error)
                if handler is not None:
                    return handler(error)

            # Re-raise if no other handler is found
            raise error

        @jwt.expired_token_loader
        def handle_expired_token():
            """
            Handle expired JWT tokens.

            Track expired tokens in metrics and return a standardized response
            when a JWT token has expired.

            Args:
                jwt_header: JWT header data
                jwt_payload: JWT payload containing claims

            Returns:
                tuple: JSON response and 401 status code
            """
            # Track expired tokens
            g.security_event_type = 'token_expired'
            g.security_event_severity = 'warning'
            security_event_counter.inc()

            return {'msg': 'Token has expired'}, 401

        @jwt.invalid_token_loader
        def handle_invalid_token(error_string):
            """
            Handle invalid JWT tokens.

            Track invalid token attempts in metrics and return a standardized response
            when a JWT token is invalid.

            Args:
                error_string: Description of the error

            Returns:
                tuple: JSON response and 401 status code
            """
            # Track invalid tokens
            g.security_event_type = 'token_invalid'
            g.security_event_severity = 'warning'
            security_event_counter.inc()

            return {'msg': 'Invalid token', 'details': error_string}, 401

        @jwt.unauthorized_loader
        def handle_unauthorized_request(error_string):
            """
            Handle requests missing required JWT tokens.

            Track unauthorized requests in metrics and return a standardized response
            when a JWT token is required but missing.

            Args:
                error_string: Description of the error

            Returns:
                tuple: JSON response and 401 status code
            """
            # Track unauthorized requests
            g.security_event_type = 'unauthorized_request'
            g.security_event_severity = 'warning'
            security_event_counter.inc()

            return {'msg': 'Authorization required', 'details': error_string}, 401

    # Initialize GeoIP
    try:
        import geoip2.database
        geoip_db_path = app.config.get('GEOIP_DB_PATH')
        if geoip_db_path and os.path.exists(geoip_db_path):
            global _geoip_instance
            _geoip_instance = geoip2.database.Reader(geoip_db_path)
            app.logger.info("GeoIP database initialized")
        else:
            app.logger.warning("GeoIP database not found")
    except ImportError:
        app.logger.warning("GeoIP module not available")
    except Exception as e:
        app.logger.error(f"Error initializing GeoIP: {e}")

    # Initialize circuit breakers from config
    if app.config.get('CIRCUIT_BREAKERS'):
        failure_threshold = app.config.get('CIRCUIT_BREAKER_FAILURE_THRESHOLD', 5)
        reset_timeout = app.config.get('CIRCUIT_BREAKER_RESET_TIMEOUT', 60.0)
        half_open_after = app.config.get('CIRCUIT_BREAKER_HALF_OPEN_AFTER', 30.0)

        for name, config in app.config.get('CIRCUIT_BREAKERS').items():
            create_circuit_breaker(
                name=name,
                failure_threshold=config.get('failure_threshold', failure_threshold),
                reset_timeout=config.get('reset_timeout', reset_timeout),
                half_open_after=config.get('half_open_after', half_open_after),
                excluded_exceptions=config.get('excluded_exceptions', ())
            )

    # Register CircuitOpenError handler
    @app.errorhandler(CircuitOpenError)
    def handle_circuit_open_error(error):
        """Handle circuit breaker open errors."""
        try:
            from core.security import log_security_event
            log_security_event(
                event_type='circuit_breaker_tripped',
                description=f"Circuit breaker tripped: {error.circuit_name}",
                severity='warning'
            )
        except ImportError:
            pass  # Core security module not available

        return {
            'error': 'service_unavailable',
            'message': f"Service temporarily unavailable: {error.circuit_name}",
            'retry_after': 30  # Suggest retry after half-open timeout
        }, 503

    # Register RateLimitExceededError handler
    @app.errorhandler(RateLimitExceededError)
    def handle_rate_limit_error(error):
        """Handle rate limit exceeded errors."""
        try:
            from core.security import log_security_event
            log_security_event(
                event_type='rate_limit_exceeded',
                description=f"Rate limit exceeded: {error.key} ({error.limit})",
                severity='warning'
            )
        except ImportError:
            pass  # Core security module not available

        return {
            'error': 'rate_limit_exceeded',
            'message': f"Rate limit exceeded: {error.limit}",
            'retry_after': 60  # Suggest retry after a minute
        }, 429

    # Add CLI commands for circuit breaker management
    if hasattr(app, 'cli'):
        import click

        @app.cli.group('circuit')
        def circuit_cli():
            """Circuit breaker management commands."""
            pass

        @circuit_cli.command('list')
        def list_circuits():
            """List all circuit breakers and their status."""
            circuits = get_all_circuits()
            if not circuits:
                click.echo("No circuit breakers defined")
                return

            # Display circuit status
            click.echo("Circuit Breaker Status:")
            for name, config in circuits.items():
                state = config['state']
                failures = config['failure_count']
                threshold = config['failure_threshold']
                click.echo(f"  {name}: {state} ({failures}/{threshold} failures)")

        @circuit_cli.command('reset')
        @click.argument('name')
        def reset_circuit_cmd(name):
            """Reset a specific circuit breaker to closed state."""
            if reset_circuit(name):
                click.echo(f"Circuit {name} reset successfully")
            else:
                click.echo(f"Circuit {name} not found")
                return 1

        @circuit_cli.command('reset-all')
        def reset_all_cmd():
            """Reset all circuit breakers to closed state."""
            count = reset_all_circuits()
            click.echo(f"Reset {count} circuit breakers")

    # Add CLI commands for file integrity monitoring
    if hasattr(app, 'cli') and app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', False):
        import click

        @app.cli.group('integrity')
        def integrity_cli():
            """File integrity monitoring commands."""
            pass

        @integrity_cli.command('check')
        @click.option('--path', '-p', multiple=True, help="Specific paths to check")
        @click.option('--verbose', '-v', is_flag=True, help="Show detailed output")
        def check_integrity_cmd(path, verbose):
            """Check file integrity against baseline."""
            try:
                from services import check_integrity

                paths = list(path) if path else None
                status, changes = check_integrity(paths)

                if status:
                    click.echo("File integrity check passed!")
                else:
                    click.echo(f"File integrity check FAILED: {len(changes)} changes detected")

                    # Show changes in verbose mode
                    if verbose and changes:
                        for change in changes:
                            path = change.get('path', 'unknown')
                            status = change.get('status', 'unknown')
                            severity = change.get('severity', 'unknown')
                            click.echo(f"  • {path}: {status} (severity: {severity})")

            except ImportError:
                click.echo("File integrity checking not available - missing required modules")
                return 1

        @integrity_cli.command('update-baseline')
        @click.option('--path', '-p', multiple=True, help="Specific paths to update")
        @click.option('--remove-missing', is_flag=True, help="Remove missing files from baseline")
        def update_baseline_cmd(path, remove_missing):
            """Update the file integrity baseline."""
            try:
                from services import update_security_baseline

                paths = list(path) if path else None
                success, message = update_security_baseline(
                    paths_to_update=paths,
                    remove_missing=remove_missing
                )

                if success:
                    click.echo(f"Baseline updated successfully: {message}")
                else:
                    click.echo(f"Baseline update failed: {message}")
                    return 1

            except ImportError:
                click.echo("Baseline update not available - missing required modules")
                return 1

    # Initialize file integrity circuit breaker
    if app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', False):
        create_circuit_breaker(
            name='file_integrity_monitoring',
            failure_threshold=app.config.get('FILE_INTEGRITY_FAILURE_THRESHOLD', 3),
            reset_timeout=app.config.get('FILE_INTEGRITY_RESET_TIMEOUT', 1800.0),  # 30 minutes
            half_open_after=app.config.get('FILE_INTEGRITY_HALF_OPEN_AFTER', 600.0)  # 10 minutes
        )

    # Log successful initialization
    app.logger.info("Extensions initialized successfully")

# Exports - functions and classes to be imported from the module
__all__ = [
    # Core extensions
    'db',
    'migrate',
    'csrf',
    'cors',
    'cache',
    'limiter',
    'session_extension',
    'metrics',
    'jwt',

    # Initialization functions
    'init_extensions',
    'get_redis_client',

    # Metrics collectors
    'request_counter',
    'endpoint_counter',
    'error_counter',
    'security_event_counter',
    'auth_attempt_counter',
    'session_activity_gauge',
    'file_integrity_gauge',
    'file_integrity_violations',
    'file_baseline_updates',

    # Circuit breaker
    'circuit_breaker',
    'CircuitBreakerState',
    'CircuitOpenError',
    'create_circuit_breaker',
    'reset_circuit',
    'reset_all_circuits',
    'get_all_circuits',

    # Rate limiting
    'rate_limit',
    'RateLimitExceededError',
    'create_limiter',
    'get_user_id',
    'get_ip_address',
    'get_api_key',
    'get_combined_key',
    'FIXED_WINDOW',
    'SLIDING_WINDOW',
    'TOKEN_BUCKET',

    # GeoIP
    'get_geoip'
]
