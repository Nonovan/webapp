"""
Circuit breaker extension for the Cloud Infrastructure Platform.

This extension provides a circuit breaker pattern implementation that prevents
cascading failures by fast-failing requests to services that are experiencing
issues. It offers both global circuit breaker management and decorators for
protecting specific functions.

Features:
- Configurable failure thresholds and recovery timeouts
- Half-open state testing for graceful recovery
- Integration with the application metrics system
- Distributed circuit state with Redis support
- Admin endpoints for monitoring and management
- Decorator-based usage for easy integration
"""

import time
import logging
import threading
from typing import Dict, Any, Optional, Callable, List, Set, Tuple, Union, TypeVar, cast, Type
from functools import wraps
from datetime import datetime, timedelta
from enum import Enum

from flask import Flask, Blueprint, jsonify, request, current_app, g, has_request_context, has_app_context

# Import the actual CircuitBreaker implementation from the models package
try:
    from models.security.circuit_breaker import (
        CircuitBreaker, CircuitBreakerState, CircuitOpenError,
        RateLimiter, RateLimitExceededError
    )
except ImportError:
    # Fallback implementation if the models package is not available
    # This should not happen in normal operation but prevents import errors
    # during initialization
    logger = logging.getLogger(__name__)
    logger.error("Failed to import CircuitBreaker from models.security.circuit_breaker")

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

    class CircuitOpenError(Exception):
        """Exception raised when a request is rejected due to an open circuit."""
        pass

    class RateLimiter:
        """Fallback implementation of RateLimiter."""
        def __init__(self, *args, **kwargs):
            pass

        def __call__(self, func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper

    class RateLimitExceededError(Exception):
        """Exception raised when a rate limit is exceeded."""
        pass

# Registry of named circuit breakers
_circuit_breakers: Dict[str, CircuitBreaker] = {}

# Type variable for generic decorators
F = TypeVar('F', bound=Callable[..., Any])

# Blueprint for admin endpoints
circuit_breaker_bp = Blueprint('circuit_breaker', __name__)

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

# Flask extension initialization
def init_app(app: Flask) -> None:
    """
    Initialize the circuit breaker extension with a Flask application.

    Args:
        app: Flask application instance
    """
    # Register admin blueprint if enabled
    if app.config.get('CIRCUIT_BREAKER_ADMIN_ENABLED', False):
        app.register_blueprint(circuit_breaker_bp)

    # Add error handler for CircuitOpenError
    @app.errorhandler(CircuitOpenError)
    def handle_circuit_open_error(error):
        """Handle circuit open errors."""
        response = jsonify({
            'error': 'service_unavailable',
            'message': str(error),
            'status_code': 503
        })
        response.status_code = 503
        return response

    # Configure from app config
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

    # Add Flask CLI commands
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
    app.logger.info("Circuit breaker extension initialized")

# Compatibility with direct import mode
# This allows using the circuit_breaker decorator directly
circuit_breaker_decorator = circuit_breaker

# Export public API
__all__ = [
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
    'RateLimiter',
    'RateLimitExceededError',
    'init_app',
]
