"""
Rate limiting extension for the Cloud Infrastructure Platform.

This module provides a centralized rate limiting implementation that can be applied
to any Flask route or function to prevent abuse and ensure fair resource usage.
It supports multiple rate limiting strategies, distributed rate limiting with Redis,
and automatic header application.

Features:
- Multiple rate limiting strategies (fixed-window, sliding-window, token-bucket)
- Redis-based storage for distributed environments
- Memory fallback when Redis is unavailable
- Automatic rate limit headers in responses
- Decorators for easy application to routes
- Comprehensive metrics for monitoring
"""

import time
import logging
from typing import Dict, Any, Optional, Callable, Union, Tuple, List
from functools import wraps

from flask import request, has_request_context, g, current_app, has_app_context
from werkzeug.local import LocalProxy

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from models.security.circuit_breaker import RateLimiter as CoreRateLimiter
from models.security.circuit_breaker import RateLimitExceededError

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


# Initialize module with the application
def init_app(app):
    """
    Initialize rate limiting extension with Flask application.

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

    # Apply configuration from app config
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
            'error': 'Too many requests',
            'message': str(error.description),
            'retry_after': retry_after
        })

        response.status_code = 429
        if retry_after:
            response.headers.add('Retry-After', str(retry_after))

        return response

    app.logger.info("Rate limiter initialized")
