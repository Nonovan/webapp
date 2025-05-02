"""
Circuit breaker and rate limiting extension for the Cloud Infrastructure Platform.

This module provides integrated circuit breaker and rate limiting functionality
that can be applied to any Flask route or function. The circuit breaker prevents
cascading failures by fast-failing requests to services that are experiencing
issues, while rate limiting prevents abuse and ensures fair resource usage.

Features:
- Circuit Breaker:
  - Configurable failure thresholds and recovery timeouts
  - Half-open state testing for graceful recovery
  - Integration with the application metrics system
  - Distributed circuit state with Redis support
  - Admin endpoints for monitoring and management
  - Decorator-based usage for easy integration

- Rate Limiting:
  - Multiple rate limiting strategies (fixed-window, sliding-window, token-bucket)
  - Redis-based storage for distributed environments
  - Memory fallback when Redis is unavailable
  - Automatic rate limit headers in responses
  - Decorators for easy application to routes
  - Comprehensive metrics for monitoring
"""

import time
import logging
import threading
from typing import Dict, Any, Optional, Callable, List, Set, Tuple, Union, TypeVar, cast, Type
from functools import wraps
from datetime import datetime, timedelta
from enum import Enum

from flask import Flask, Blueprint, jsonify, request, current_app, g, has_request_context, has_app_context
from werkzeug.local import LocalProxy

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Import the actual implementations from the models package
try:
    from models.security.circuit_breaker import (
        CircuitBreaker, CircuitBreakerState, CircuitOpenError,
        RateLimiter as CoreRateLimiter, RateLimitExceededError
    )
except ImportError:
    # Fallback implementation if the models package is not available
    # This should not happen in normal operation but prevents import errors
    # during initialization
    logger = logging.getLogger(__name__)
    logger.error("Failed to import circuit breaker classes from models.security.circuit_breaker")

    class CircuitBreakerState(Enum):
        """Circuit breaker state enum."""
        CLOSED = 'closed'  # Circuit is closed, requests flow normally
        OPEN = 'open'      # Circuit is open, requests are blocked
        HALF_OPEN = 'half-open'  # Circuit is testing if service is healthy again

    class CircuitBreaker:
        """Fallback implementation of CircuitBreaker."""
        _registry = {}

        def __init__(self, *args, **kwargs):
            self.name = kwargs.get('name', 'default')
            self._state = CircuitBreakerState.CLOSED
            CircuitBreaker._registry[self.name] = self

        def __call__(self, func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper

        @classmethod
        def get_all_circuit_states(cls):
            """Get states of all registered circuit breakers."""
            return {name: {'state': 'closed'} for name, cb in cls._registry.items()}

        @classmethod
        def get_circuit_breaker(cls, name):
            """Get a circuit breaker by name."""
            return cls._registry.get(name)

        @classmethod
        def reset_all_circuits(cls):
            """Reset all circuit breakers."""
            return 0

        def reset(self):
            """Reset circuit state to closed."""
            pass

    class CircuitOpenError(Exception):
        """Exception raised when a request is rejected due to an open circuit."""
        pass

    class CoreRateLimiter:
        """Fallback implementation of RateLimiter."""
        STRATEGY_FIXED_WINDOW = 'fixed-window'
        STRATEGY_SLIDING_WINDOW = 'sliding-window'
        STRATEGY_TOKEN_BUCKET = 'token-bucket'

        def __init__(self, *args, **kwargs):
            pass

        def __call__(self, func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper

        def _get_rate_key(self):
            return "default"

        def check_rate_limit(self, key):
            return True, 0, int(time.time()) + 60

    class RateLimitExceededError(Exception):
        """Exception raised when a rate limit is exceeded."""
        pass

# Configure module logger
logger = logging.getLogger(__name__)

# Initialize the Flask-Limiter extension
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    strategy="fixed-window"
)

# Extract core strategies for use in configuration
FIXED_WINDOW = CoreRateLimiter.STRATEGY_FIXED_WINDOW
SLIDING_WINDOW = CoreRateLimiter.STRATEGY_SLIDING_WINDOW
TOKEN_BUCKET = CoreRateLimiter.STRATEGY_TOKEN_BUCKET

# Dictionary of active rate limiters
_limiters: Dict[str, CoreRateLimiter] = {}

# Registry of named circuit breakers
_circuit_breakers: Dict[str, CircuitBreaker] = {}

# Type variable for generic decorators
F = TypeVar('F', bound=Callable[..., Any])

# Blueprint for admin endpoints
circuit_breaker_bp = Blueprint('circuit_breaker', __name__)


#------------------------------------------------------------------------------
# Circuit Breaker Implementation
#------------------------------------------------------------------------------

def create_circuit_breaker(
    name: str,
    failure_threshold: int = 5,
    reset_timeout: float = 60.0,
    half_open_after: float = 30.0,
    excluded_exceptions: Tuple[Type[Exception], ...] = ()
) -> CircuitBreaker:
    """
    Create a new circuit breaker with the given configuration.

    Args:
        name: Name of this circuit breaker for identification
        failure_threshold: Number of failures before opening circuit
        reset_timeout: Seconds before resetting failure count
        half_open_after: Seconds before trying a test request
        excluded_exceptions: Exception types that don't count as failures

    Returns:
        CircuitBreaker: The created circuit breaker instance

    Example:
        >>> api_circuit = create_circuit_breaker('api.external', failure_threshold=3)
        >>> @api_circuit
        >>> def call_external_api(params):
        ...     # Function that might fail
    """
    if name in _circuit_breakers:
        # Return existing circuit breaker if one with this name exists
        return _circuit_breakers[name]

    circuit_breaker = CircuitBreaker(
        name=name,
        failure_threshold=failure_threshold,
        reset_timeout=reset_timeout,
        half_open_after=half_open_after,
        excluded_exceptions=excluded_exceptions
    )

    # Register in local registry for this extension
    _circuit_breakers[name] = circuit_breaker

    # Return the circuit breaker
    return circuit_breaker


def circuit_breaker(
    name_or_func: Union[str, Callable],
    failure_threshold: int = 5,
    reset_timeout: float = 60.0,
    half_open_after: float = 30.0,
    excluded_exceptions: Tuple[Type[Exception], ...] = ()
) -> Union[CircuitBreaker, Callable]:
    """
    Decorator to apply circuit breaking to a function.

    Can be used in two ways:
    1. With parameters: @circuit_breaker(name="my_circuit", failure_threshold=3)
    2. Without parameters: @circuit_breaker

    Args:
        name_or_func: Either the function to decorate or the circuit name
        failure_threshold: Number of failures before opening circuit
        reset_timeout: Seconds before resetting failure count
        half_open_after: Seconds before trying a test request
        excluded_exceptions: Exception types that don't count as failures

    Returns:
        Decorated function or decorator function

    Example:
        >>> @circuit_breaker("pdf_generator", failure_threshold=3)
        >>> def generate_pdf(data):
        ...     # Function that might fail
    """
    # Check if this is the direct decorator case (@circuit_breaker)
    if callable(name_or_func) and not isinstance(name_or_func, str):
        # Generate name from the function
        name = f"func.{name_or_func.__module__}.{name_or_func.__name__}"
        # Create and apply circuit breaker
        cb = create_circuit_breaker(name, failure_threshold, reset_timeout,
                                   half_open_after, excluded_exceptions)
        return cb(name_or_func)

    # This is the parameterized decorator case (@circuit_breaker(...))
    def decorator(func: F) -> F:
        name = name_or_func if isinstance(name_or_func, str) else f"func.{func.__module__}.{func.__name__}"
        # Create and apply circuit breaker
        cb = create_circuit_breaker(name, failure_threshold, reset_timeout,
                                   half_open_after, excluded_exceptions)
        return cb(func)

    return decorator


def get_circuit_breaker(name: str) -> Optional[CircuitBreaker]:
    """
    Get a circuit breaker by name.

    Args:
        name: The name of the circuit breaker to retrieve

    Returns:
        CircuitBreaker instance or None if not found
    """
    # Check local registry first
    if name in _circuit_breakers:
        return _circuit_breakers[name]

    # Then check the CircuitBreaker class registry
    return CircuitBreaker.get_circuit_breaker(name)


def reset_circuit(name: str) -> bool:
    """
    Reset a specific circuit breaker to closed state.

    Args:
        name: Name of the circuit breaker to reset

    Returns:
        bool: True if the circuit was found and reset, False otherwise
    """
    circuit = get_circuit_breaker(name)
    if circuit:
        circuit.reset()
        return True
    return False


def reset_all_circuits() -> int:
    """
    Reset all circuit breakers to closed state.

    Returns:
        int: Number of circuits reset
    """
    return CircuitBreaker.reset_all_circuits()


def get_all_circuits() -> Dict[str, Dict[str, Any]]:
    """
    Get the state of all registered circuit breakers.

    Returns:
        Dict: Dictionary with circuit states indexed by name
    """
    return CircuitBreaker.get_all_circuit_states()


# Admin API endpoints
@circuit_breaker_bp.route('/api/admin/circuit-breakers', methods=['GET'])
def list_circuit_breakers():
    """API endpoint to list all circuit breakers and their states."""
    if has_app_context():
        # Check if this is an API request that should return JSON
        if (request.accept_mimetypes.best == 'application/json' or
            request.args.get('format') == 'json'):
            return jsonify({
                'success': True,
                'data': get_all_circuits()
            })

    # Default response
    return get_all_circuits()


@circuit_breaker_bp.route('/api/admin/circuit-breakers/<name>/reset', methods=['POST'])
def reset_circuit_breaker(name: str):
    """API endpoint to reset a specific circuit breaker."""
    success = reset_circuit(name)

    if has_app_context():
        return jsonify({
            'success': success,
            'message': f"Circuit breaker '{name}' {'reset successfully' if success else 'not found'}"
        })

    return success


@circuit_breaker_bp.route('/api/admin/circuit-breakers/reset-all', methods=['POST'])
def reset_all_circuit_breakers():
    """API endpoint to reset all circuit breakers."""
    count = reset_all_circuits()

    if has_app_context():
        return jsonify({
            'success': True,
            'message': f"Reset {count} circuit breakers"
        })

    return count


#------------------------------------------------------------------------------
# Rate Limiting Implementation
#------------------------------------------------------------------------------

def create_limiter(
    name: str,
    limit: int = 100,
    window: int = 60,
    strategy: str = FIXED_WINDOW,
    key_function: Optional[Callable] = None
) -> CoreRateLimiter:
    """
    Create and register a new rate limiter.

    Args:
        name: Unique name for this rate limiter
        limit: Maximum number of requests in the time window
        window: Time window in seconds
        strategy: Rate limiting strategy (fixed-window, sliding-window, token-bucket)
        key_function: Custom function to generate rate limit keys

    Returns:
        CoreRateLimiter: Configured rate limiter instance

    Example:
        >>> api_limiter = create_limiter('api', limit=60, window=60)
        >>> admin_limiter = create_limiter(
        ...     'admin',
        ...     limit=30,
        ...     window=60,
        ...     key_function=lambda: f"{request.remote_addr}:{g.user_id}"
        ... )
    """
    if name in _limiters:
        logger.warning(f"Rate limiter '{name}' already exists, returning existing instance")
        return _limiters[name]

    limiter = CoreRateLimiter(name, limit, window, strategy, key_function)
    _limiters[name] = limiter

    logger.debug(f"Created rate limiter '{name}' with limit={limit}/{window}s, strategy={strategy}")
    return limiter


def rate_limit(
    name_or_limiter: Union[str, CoreRateLimiter],
    limit: Optional[int] = None,
    window: Optional[int] = None,
    key_function: Optional[Callable] = None,
    strategy: Optional[str] = None
):
    """
    Apply rate limiting to a function.

    This decorator uses either a named rate limiter or creates a new one
    with the specified parameters.

    Args:
        name_or_limiter: Either a limiter name or a CoreRateLimiter instance
        limit: Maximum number of requests in the time window (if creating new)
        window: Time window in seconds (if creating new)
        key_function: Custom function to generate rate limit keys (if creating new)
        strategy: Rate limiting strategy (if creating new)

    Returns:
        Callable: Decorated function with rate limiting

    Example:
        >>> @rate_limit('api_get_user', limit=30, window=60)
        >>> def get_user(user_id):
        ...     # Rate limited function
        ...     return User.query.get(user_id)

        >>> # Using an existing limiter
        >>> api_limiter = create_limiter('api', limit=60, window=60)
        >>> @rate_limit(api_limiter)
        >>> def api_function():
        ...     # Rate limited by existing limiter
        ...     pass
    """
    # Get or create the limiter
    if isinstance(name_or_limiter, str):
        if name_or_limiter in _limiters:
            limiter_instance = _limiters[name_or_limiter]
        else:
            if limit is None:
                limit = 100  # Default limit
            if window is None:
                window = 60  # Default window
            if strategy is None:
                strategy = FIXED_WINDOW  # Default strategy

            limiter_instance = create_limiter(
                name_or_limiter,
                limit=limit,
                window=window,
                strategy=strategy,
                key_function=key_function
            )
    else:
        limiter_instance = name_or_limiter

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get rate limit key
            key = limiter_instance._get_rate_key()

            # Check rate limit
            allowed, current, reset_time = limiter_instance.check_rate_limit(key)

            if not allowed:
                # Log and track rate limit hit
                logger.warning(f"Rate limit exceeded: {limiter_instance.name} - {current}/{limiter_instance.limit}")

                # Try to add rate limit headers
                if has_request_context():
                    headers = {
                        'X-RateLimit-Limit': str(limiter_instance.limit),
                        'X-RateLimit-Remaining': '0',
                        'X-RateLimit-Reset': str(reset_time),
                        'Retry-After': str(reset_time - int(time.time()))
                    }

                    # Store headers to be added to response
                    if not hasattr(g, 'rate_limit_headers'):
                        g.rate_limit_headers = {}
                    g.rate_limit_headers.update(headers)

                # Raise 429 Too Many Requests error
                from flask import abort
                abort(429, description=f"Rate limit exceeded: {current}/{limiter_instance.limit}")

            # Track allowed request in metrics
            if has_app_context():
                try:
                    from extensions.metrics import metrics
                    if metrics:
                        metrics.counter(
                            'rate_limit_requests_total',
                            1,
                            labels={
                                'limiter': limiter_instance.name,
                                'allowed': 'true'
                            }
                        )
                except (ImportError, AttributeError):
                    pass

            # Add rate limit headers to response
            if has_request_context():
                remaining = limiter_instance.limit - current - 1
                headers = {
                    'X-RateLimit-Limit': str(limiter_instance.limit),
                    'X-RateLimit-Remaining': str(remaining),
                    'X-RateLimit-Reset': str(reset_time)
                }

                # Store headers to be added to response
                if not hasattr(g, 'rate_limit_headers'):
                    g.rate_limit_headers = {}
                g.rate_limit_headers.update(headers)

            # Call the wrapped function
            return func(*args, **kwargs)

        return wrapper

    return decorator


# Custom key functions for different rate limiting scenarios
def get_user_id() -> str:
    """
    Get current user ID for rate limiting.

    Returns:
        str: User ID if authenticated, IP address otherwise
    """
    if has_request_context() and hasattr(g, 'user_id') and g.user_id:
        return f"user:{g.user_id}"
    return f"ip:{request.remote_addr}"


def get_ip_address() -> str:
    """
    Get client IP address for rate limiting.

    Returns:
        str: Client IP address with special handling for proxies
    """
    if has_request_context():
        # Try to get real IP if behind proxy
        if request.headers.get('X-Forwarded-For'):
            ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        else:
            ip = request.remote_addr or 'unknown'
        return f"ip:{ip}"
    return "ip:unknown"


def get_api_key() -> str:
    """
    Get API key for rate limiting.

    Returns:
        str: API key if provided, IP address otherwise
    """
    if has_request_context():
        # Try different header conventions for API key
        api_key = (
            request.headers.get('X-API-Key') or
            request.headers.get('Authorization') or
            request.args.get('api_key')
        )

        if api_key:
            if api_key.startswith('Bearer '):
                api_key = api_key[7:]  # Remove 'Bearer ' prefix
            return f"key:{api_key}"

    return get_ip_address()


def get_combined_key() -> str:
    """
    Get combined key using both user ID and IP address.

    Returns:
        str: Combined key for rate limiting
    """
    ip = get_ip_address().split(':')[1]
    if has_request_context() and hasattr(g, 'user_id') and g.user_id:
        return f"combined:{ip}:{g.user_id}"
    return f"ip:{ip}"


#------------------------------------------------------------------------------
# Flask Extension Initialization
#------------------------------------------------------------------------------

def init_app(app: Flask) -> None:
    """
    Initialize circuit breaker and rate limiting extensions with Flask application.

    Args:
        app: Flask application instance
    """
    # Initialize Flask-Limiter
    limiter.init_app(app)

    # Register after request handler to add rate limit headers
    @app.after_request
    def add_rate_limit_headers(response):
        """Add rate limit headers to response if set."""
        if hasattr(g, 'rate_limit_headers'):
            for key, value in g.rate_limit_headers.items():
                response.headers.add(key, value)
        return response

    # Apply rate limiter configuration from app config
    if app.config.get('RATELIMIT_STORAGE_URL'):
        limiter.storage_uri = app.config.get('RATELIMIT_STORAGE_URL')

    limiter.strategy = app.config.get('RATELIMIT_STRATEGY', 'fixed-window')
    limiter.enabled = app.config.get('RATELIMIT_ENABLED', True)
    limiter.header_enabled = app.config.get('RATELIMIT_HEADERS_ENABLED', True)

    # Register error handler for rate limit exceeded
    @app.errorhandler(429)
    def handle_rate_limit_error(error):
        """Handle rate limit exceeded errors."""
        # Log security event
        from core.security import log_security_event

        log_security_event(
            event_type='rate_limit_exceeded',
            description=f"Rate limit exceeded: {request.endpoint}",
            severity='warning',
            ip_address=request.remote_addr,
            details={
                'endpoint': request.endpoint or 'unknown',
                'path': request.path,
                'method': request.method,
                'description': str(error.description)
            }
        )

        # Update metrics if available
        try:
            from extensions.metrics import metrics
            if metrics:
                metrics.counter(
                    'rate_limit_exceeded_total',
                    1,
                    labels={
                        'endpoint': request.endpoint or 'unknown',
                        'path': request.path,
                        'method': request.method
                    }
                )
        except (ImportError, AttributeError):
            pass

        # Return standardized error response
        from flask import jsonify

        retry_after = None
        if hasattr(error, 'retry_after'):
            retry_after = error.retry_after
        elif hasattr(g, 'rate_limit_headers') and 'Retry-After' in g.rate_limit_headers:
            retry_after = g.rate_limit_headers['Retry-After']

        response = jsonify({
            'error': 'too_many_requests',
            'message': str(error.description),
            'retry_after': retry_after
        })

        response.status_code = 429
        if retry_after:
            response.headers.add('Retry-After', str(retry_after))

        return response

    # Register admin blueprint for circuit breaker if enabled
    if app.config.get('CIRCUIT_BREAKER_ADMIN_ENABLED', False):
        app.register_blueprint(circuit_breaker_bp)

    # Add error handler for CircuitOpenError
    @app.errorhandler(CircuitOpenError)
    def handle_circuit_open_error(error):
        """Handle circuit open errors."""
        # Log security event
        try:
            from core.security import log_security_event
            log_security_event(
                event_type='circuit_breaker_trip',
                description=f"Circuit breaker tripped: {getattr(error, 'circuit_name', 'unknown')}",
                severity='warning',
                ip_address=request.remote_addr if has_request_context() else None,
                details={
                    'circuit_name': getattr(error, 'circuit_name', 'unknown'),
                    'endpoint': request.endpoint if has_request_context() else None,
                    'path': request.path if has_request_context() else None,
                    'error': str(error)
                }
            )
        except ImportError:
            pass

        # Update metrics if available
        try:
            from extensions.metrics import metrics
            if metrics:
                metrics.counter(
                    'circuit_breaker_trips_total',
                    1,
                    labels={
                        'circuit': getattr(error, 'circuit_name', 'unknown')
                    }
                )
        except (ImportError, AttributeError):
            pass

        # Return standardized error response
        response = jsonify({
            'error': 'service_unavailable',
            'message': str(error),
            'status_code': 503
        })
        response.status_code = 503
        response.headers.add('Retry-After', '60')  # Suggest retry after 1 minute
        return response

    # Configure circuit breakers from app config
    default_failure_threshold = app.config.get('CIRCUIT_BREAKER_FAILURE_THRESHOLD', 5)
    default_reset_timeout = app.config.get('CIRCUIT_BREAKER_RESET_TIMEOUT', 60.0)
    default_half_open_after = app.config.get('CIRCUIT_BREAKER_HALF_OPEN_AFTER', 30.0)

    # Create preconfigured circuit breakers from config
    preconfigured = app.config.get('CIRCUIT_BREAKERS', {})
    for name, config in preconfigured.items():
        create_circuit_breaker(
            name=name,
            failure_threshold=config.get('failure_threshold', default_failure_threshold),
            reset_timeout=config.get('reset_timeout', default_reset_timeout),
            half_open_after=config.get('half_open_after', default_half_open_after),
            excluded_exceptions=config.get('excluded_exceptions', ())
        )

    # Add Flask CLI commands for circuit breaker management
    if hasattr(app, 'cli'):
        import click

        @app.cli.group('circuit-breaker')
        def circuit_breaker_cli():
            """Circuit breaker management commands."""
            pass

        @circuit_breaker_cli.command('list')
        def list_circuits():
            """List all circuit breakers and their states."""
            circuits = get_all_circuits()

            # Format output as table
            click.echo("Circuit Breakers:")
            click.echo("=" * 80)
            click.echo(f"{'Name':<30} {'State':<10} {'Failures':<10} {'Time Since Failure':<20}")
            click.echo("-" * 80)

            for name, data in circuits.items():
                time_since = data.get('seconds_since_last_failure', float('inf'))
                if time_since == float('inf'):
                    time_since_str = "N/A"
                else:
                    time_since_str = f"{time_since:.1f}s"

                click.echo(
                    f"{name:<30} {data.get('state', 'unknown'):<10} "
                    f"{data.get('failures', 0):<10} {time_since_str:<20}"
                )

        @circuit_breaker_cli.command('reset')
        @click.argument('name')
        def reset_circuit_cmd(name):
            """Reset a specific circuit breaker."""
            success = reset_circuit(name)
            if success:
                click.echo(f"Circuit breaker '{name}' reset successfully")
            else:
                click.echo(f"Circuit breaker '{name}' not found")

        @circuit_breaker_cli.command('reset-all')
        def reset_all_circuits_cmd():
            """Reset all circuit breakers."""
            count = reset_all_circuits()
            click.echo(f"Reset {count} circuit breakers")

    # Log initialization
    app.logger.info("Circuit breaker and rate limiting extensions initialized")


# Compatibility with direct import mode
# This allows using the circuit_breaker decorator directly
circuit_breaker_decorator = circuit_breaker


# Export public API
__all__ = [
    # Circuit breaker exports
    'CircuitBreaker',
    'CircuitBreakerState',
    'CircuitOpenError',
    'circuit_breaker',
    'circuit_breaker_decorator',
    'create_circuit_breaker',
    'get_circuit_breaker',
    'reset_circuit',
    'reset_all_circuits',
    'get_all_circuits',

    # Rate limiter exports
    'limiter',
    'RateLimitExceededError',
    'create_limiter',
    'rate_limit',
    'get_user_id',
    'get_ip_address',
    'get_api_key',
    'get_combined_key',
    'FIXED_WINDOW',
    'SLIDING_WINDOW',
    'TOKEN_BUCKET',

    # Common
    'init_app',
]
