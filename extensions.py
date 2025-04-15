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
"""

# Core extensions needed
from flask import request, g, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache
from flask_session import Session
from prometheus_flask_exporter import PrometheusMetrics
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager
import redis

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

# Token blacklist and redis client
class RedisClientManager:
    """
    Manages the Redis client instance.
    
    This class provides a centralized way to manage the application's Redis client,
    using a class-level singleton pattern to ensure there's only one client
    instance throughout the application's lifecycle.
    
    The Redis client is used for:
    - Token blacklisting in JWT authentication
    - Distributed rate limiting
    - Session storage
    - Cache backends
    """
    _redis_client = None

    @classmethod
    def get_client(cls):
        """
        Retrieve the Redis client instance.
        
        Returns:
            Redis client instance or None if not initialized
            
        Example:
            ```
            client = RedisClientManager.get_client()
            if client:
                client.set("key", "value")
            ```
        """
        return cls._redis_client

    @classmethod
    def set_client(cls, client):
        """
        Set the Redis client instance.
        
        This method should be called during application initialization
        to configure the shared Redis client.
        
        Args:
            client: Redis client instance
            
        Example:
            ```
            redis_client = redis.from_url(app.config['REDIS_URL'])
            RedisClientManager.set_client(redis_client)
            ```
        """
        cls._redis_client = client

# Update references to use RedisClientManager
def get_redis_client():
    """
    Retrieve the application's Redis client.
    
    This function provides a convenient way to access the shared Redis client
    from anywhere in the application without directly accessing the
    RedisClientManager class.
    
    Returns:
        Redis client instance or None if not initialized
        
    Example:
        ```python
        from extensions import get_redis_client
        
        def blacklist_token(token_jti, expires_in):
            client = get_redis_client()
            if client:
                client.setex(f"blacklist:{token_jti}", expires_in, "1")
        ```
    """
    return RedisClientManager.get_client()

def set_redis_client(client):
    """
    Set the application's shared Redis client.
    
    This function provides a convenient way to configure the shared Redis client
    without directly accessing the RedisClientManager class.
    
    Args:
        client: Redis client instance to be used throughout the application
        
    Example:
        ```python
        from extensions import set_redis_client
        import redis
        
        def configure_redis(app):
            if app.config.get('REDIS_URL'):
                client = redis.from_url(
                    app.config['REDIS_URL'],
                    decode_responses=True
                )
                set_redis_client(client)
        ```
    """
    RedisClientManager.set_client(client)

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
        redis_client_instance = redis.from_url(
            app.config['REDIS_URL'],
            decode_responses=True  # Store as strings not bytes
        )
        set_redis_client(redis_client_instance)
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