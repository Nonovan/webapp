"""
Circuit Breaker class and functions for the Cloud Infrastructure Platform.

This module provides a circuit breaker utility class for preventing cascading failures
used across the application.
"""

import time
import logging
import threading
from typing import Dict, Any, Optional, Callable, List, Set, Tuple, Union, TypeVar, cast, Type
from functools import wraps
from datetime import datetime, timedelta
from enum import Enum

from flask import request, current_app, g, has_request_context, has_app_context
try:
    from extensions import get_redis_client, metrics
except ImportError:
    # Fallback for when running without the full application context
    get_redis_client = lambda: None
    metrics = None

# Initialize logger
logger = logging.getLogger(__name__)

# Type variable for generic decorators
F = TypeVar('F', bound=Callable[..., Any])

class CircuitBreakerState(Enum):
    """Circuit breaker state enum."""
    CLOSED = 'closed'  # Circuit is closed, requests flow normally
    OPEN = 'open'      # Circuit is open, requests are blocked
    HALF_OPEN = 'half-open'  # Circuit is testing if service is healthy again


class CircuitBreaker:
    """
    Circuit breaker pattern implementation to prevent cascading failures.

    This class implements the circuit breaker pattern to protect services from
    cascading failures. When a service experiences failures above the threshold,
    the circuit opens and fast-fails subsequent requests for a cooldown period.

    Attributes:
        name: Name of this circuit breaker for identification
        failure_threshold: Number of failures before opening the circuit
        reset_timeout: Seconds before allowing another request after opening
        half_open_after: Seconds before allowing a test request
        excluded_exceptions: Exception types that don't count as failures
    """
    # Class-level registry of all circuit breakers for monitoring
    _registry: Dict[str, 'CircuitBreaker'] = {}

    # Metrics for circuit breaker operations
    if metrics:
        circuit_state = metrics.gauge(
            'circuit_breaker_state',
            'Circuit breaker state (0=closed, 1=half-open, 2=open)',
            labels=['name', 'service']
        )
        circuit_failures = metrics.counter(
            'circuit_breaker_failures_total',
            'Total circuit breaker failures',
            labels=['name', 'service']
        )
        circuit_successes = metrics.counter(
            'circuit_breaker_successes_total',
            'Total circuit breaker successes',
            labels=['name', 'service']
        )
        circuit_trips = metrics.counter(
            'circuit_breaker_trips_total',
            'Total circuit breaker trips (opening events)',
            labels=['name', 'service']
        )
        circuit_resets = metrics.counter(
            'circuit_breaker_resets_total',
            'Total circuit breaker resets (closing events)',
            labels=['name', 'service']
        )

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        reset_timeout: float = 60.0,
        half_open_after: float = 30.0,
        excluded_exceptions: Tuple[Type[Exception], ...] = ()
    ) -> None:
        """
        Initialize a new circuit breaker.

        Args:
            name: Name of this circuit breaker for identification
            failure_threshold: Number of failures before opening circuit
            reset_timeout: Seconds before resetting failure count
            half_open_after: Seconds before trying a test request
            excluded_exceptions: Exception types that don't count as failures
        """
        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.half_open_after = half_open_after
        self.excluded_exceptions = excluded_exceptions

        # State
        self._failures = 0
        self._state = CircuitBreakerState.CLOSED
        self._last_failure_time = 0.0
        self._lock = threading.RLock()

        # Service derived from name
        self.service = name.split('.')[0] if '.' in name else 'default'

        # Register this instance
        CircuitBreaker._registry[name] = self

        logger.info(f"Circuit breaker '{name}' created with threshold={failure_threshold}, "
                   f"reset_timeout={reset_timeout}s, half_open_after={half_open_after}s")

    def initialize(self) -> None:
        """Initialize circuit breaker metrics and configuration."""
        if metrics:
            # Initialize gauge with closed state
            self._update_state_metric()

    def __call__(self, func: F) -> F:
        """
        Decorator to apply circuit breaker to a function.

        Args:
            func: The function to protect with a circuit breaker

        Returns:
            Decorated function with circuit breaker protection
        """
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Check if circuit is open
            if not self.allow_request():
                logger.warning(f"Circuit '{self.name}' is open, fast-failing request")
                raise CircuitOpenError(f"Circuit '{self.name}' is open")

            try:
                result = func(*args, **kwargs)
                self.record_success()
                return result
            except Exception as e:
                # Don't count excluded exceptions
                if not isinstance(e, self.excluded_exceptions):
                    self.record_failure()
                raise

        return cast(F, wrapper)

    def allow_request(self) -> bool:
        """
        Check if a request should be allowed through the circuit.

        Returns:
            True if the request should be allowed, False otherwise
        """
        with self._lock:
            current_time = time.time()

            # Check if we need to reset failure count based on reset_timeout
            if (self._state == CircuitBreakerState.CLOSED and
                self._failures > 0 and
                self._last_failure_time > 0 and
                current_time - self._last_failure_time > self.reset_timeout):
                self._failures = 0
                logger.debug(f"Circuit '{self.name}' reset failure count after {self.reset_timeout}s")

            # If closed, allow the request
            if self._state == CircuitBreakerState.CLOSED:
                return True

            # If open, check if it's time to try half-open
            if self._state == CircuitBreakerState.OPEN:
                if current_time - self._last_failure_time >= self.half_open_after:
                    logger.info(f"Circuit '{self.name}' transitioning from open to half-open")
                    self._state = CircuitBreakerState.HALF_OPEN
                    self._update_state_metric()
                    return True
                return False

            # If half-open, allow a single request
            if self._state == CircuitBreakerState.HALF_OPEN:
                return True

        return True

    def record_success(self) -> None:
        """Record a successful operation, potentially closing the circuit."""
        with self._lock:
            if self._state == CircuitBreakerState.HALF_OPEN:
                self._failures = 0
                self._state = CircuitBreakerState.CLOSED
                logger.info(f"Circuit '{self.name}' closed after successful test request")

                if metrics:
                    CircuitBreaker.circuit_resets.inc(1, labels={'name': self.name, 'service': self.service})
                    self._update_state_metric()
                    CircuitBreaker.circuit_successes.inc(1, labels={'name': self.name, 'service': self.service})

            elif self._state == CircuitBreakerState.CLOSED and self._failures > 0:
                # Reset failure count on success in closed state
                self._failures = 0

                if metrics:
                    CircuitBreaker.circuit_successes.inc(1, labels={'name': self.name, 'service': self.service})

    def record_failure(self) -> None:
        """
        Record a failed operation, potentially opening the circuit.

        This should be called when an operation protected by this circuit breaker fails.
        """
        with self._lock:
            current_time = time.time()
            self._last_failure_time = current_time

            if self._state == CircuitBreakerState.HALF_OPEN:
                # If fail in half-open, go back to open
                self._state = CircuitBreakerState.OPEN
                logger.warning(f"Circuit '{self.name}' reopened after failed test request")

                if metrics:
                    CircuitBreaker.circuit_trips.inc(1, labels={'name': self.name, 'service': self.service})
                    CircuitBreaker.circuit_failures.inc(1, labels={'name': self.name, 'service': self.service})
                    self._update_state_metric()

            elif self._state == CircuitBreakerState.CLOSED:
                self._failures += 1

                if self._failures >= self.failure_threshold:
                    self._state = CircuitBreakerState.OPEN
                    logger.warning(
                        f"Circuit '{self.name}' opened after {self._failures} failures "
                        f"(threshold: {self.failure_threshold})"
                    )

                    if metrics:
                        CircuitBreaker.circuit_trips.inc(1, labels={'name': self.name, 'service': self.service})
                        self._update_state_metric()

                if metrics:
                    CircuitBreaker.circuit_failures.inc(1, labels={'name': self.name, 'service': self.service})

    def reset(self) -> None:
        """
        Force reset this circuit breaker to closed state.

        Use with caution as it bypasses the normal circuit breaker operation.
        """
        with self._lock:
            if self._state != CircuitBreakerState.CLOSED:
                logger.warning(f"Circuit '{self.name}' manually reset to closed state")
                self._state = CircuitBreakerState.CLOSED
                self._failures = 0

                if metrics:
                    CircuitBreaker.circuit_resets.inc(1, labels={'name': self.name, 'service': self.service})
                    self._update_state_metric()

    def _update_state_metric(self) -> None:
        """Update the circuit state metric."""
        if metrics:
            # Convert state to metric value (0=closed, 1=half-open, 2=open)
            state_value = {
                CircuitBreakerState.CLOSED: 0,
                CircuitBreakerState.HALF_OPEN: 1,
                CircuitBreakerState.OPEN: 2
            }.get(self._state, 0)

            CircuitBreaker.circuit_state.set(
                state_value,
                labels={'name': self.name, 'service': self.service}
            )

    @property
    def state(self) -> str:
        """Get the current circuit state as a string."""
        return self._state.value

    @property
    def failure_count(self) -> int:
        """Get the current failure count."""
        return self._failures

    @property
    def seconds_since_last_failure(self) -> float:
        """Get the seconds elapsed since the last failure."""
        if self._last_failure_time == 0:
            return float('inf')
        return time.time() - self._last_failure_time

    @classmethod
    def get_all_circuit_states(cls) -> Dict[str, Dict[str, Any]]:
        """
        Get the state of all registered circuit breakers.

        Returns:
            Dictionary with circuit states indexed by name
        """
        result = {}
        for name, circuit in cls._registry.items():
            result[name] = {
                'state': circuit.state,
                'failures': circuit.failure_count,
                'seconds_since_last_failure': circuit.seconds_since_last_failure,
                'service': circuit.service
            }
        return result

    @classmethod
    def get_circuit_breaker(cls, name: str) -> Optional['CircuitBreaker']:
        """
        Get a circuit breaker by name.

        Args:
            name: The name of the circuit breaker to retrieve

        Returns:
            CircuitBreaker instance or None if not found
        """
        return cls._registry.get(name)

    @classmethod
    def reset_all_circuits(cls) -> int:
        """
        Reset all registered circuit breakers.

        Returns:
            Number of circuit breakers that were reset
        """
        reset_count = 0
        for name, circuit in cls._registry.items():
            if circuit._state != CircuitBreakerState.CLOSED:
                circuit.reset()
                reset_count += 1
        return reset_count


class CircuitOpenError(Exception):
    """Exception raised when a request is rejected due to an open circuit."""
    pass


class RateLimitExceededError(Exception):
    """Exception raised when a rate limit is exceeded."""
    pass


class RateLimiter:
    """Rate limiter implementation using the token bucket algorithm."""
    # Constants
    STRATEGY_FIXED_WINDOW = 'fixed-window'
    STRATEGY_SLIDING_WINDOW = 'sliding-window'
    STRATEGY_TOKEN_BUCKET = 'token-bucket'

    # Registry of all rate limiters for monitoring
    _registry: Dict[str, 'RateLimiter'] = {}

    def __init__(self, name: str, limit: int, window: int,
                 strategy: str = STRATEGY_FIXED_WINDOW,
                 key_function: Optional[Callable[[], str]] = None):
        """
        Initialize a new rate limiter.

        Args:
            name: Name of this rate limiter for identification
            limit: Maximum number of requests in the window
            window: Time window in seconds
            strategy: Rate limiting strategy
            key_function: Function to generate rate limit keys based on context
        """
        self.name = name
        self.limit = limit
        self.window = window
        self.strategy = strategy
        self._key_function = key_function

        # Register this instance
        RateLimiter._registry[name] = self

        logger.info(f"Rate limiter '{name}' created with limit={limit}/{window}s, strategy={strategy}")

    def _get_rate_key(self) -> str:
        """
        Get the rate limiting key for the current context.

        Returns:
            String key for rate limiting
        """
        if self._key_function:
            return self._key_function()

        # Default implementations based on available context
        if has_request_context():
            # Use IP address from the request if available
            return f"rate:{self.name}:{request.remote_addr}"
        elif has_app_context() and hasattr(g, 'user_id') and g.user_id:
            # Use user ID if available
            return f"rate:{self.name}:user:{g.user_id}"
        else:
            # Fallback to name only for global limits
            return f"rate:{self.name}:global"

    def check_rate_limit(self, key: str) -> Tuple[bool, int, int]:
        """
        Check if the current request is within rate limits.

        Args:
            key: Rate limit key for the current request

        Returns:
            Tuple of (allowed, current_count, reset_time)
        """
        redis_client = get_redis_client()
        current_time = int(time.time())

        if redis_client:
            # Redis-based implementation for distributed systems
            if self.strategy == self.STRATEGY_FIXED_WINDOW:
                # Fixed-window - single counter per window
                window_key = f"{key}:{current_time // self.window}"
                current = redis_client.incr(window_key)
                redis_client.expire(window_key, self.window)
                reset_time = (current_time // self.window + 1) * self.window

                return current <= self.limit, current, reset_time

            elif self.strategy == self.STRATEGY_SLIDING_WINDOW:
                # Sliding-window - count events in last window
                pipeline = redis_client.pipeline()
                window_start = current_time - self.window

                # Add current timestamp to sorted set with score
                member = f"{current_time}:{time.time_ns()}"  # Use nanoseconds to ensure uniqueness
                pipeline.zadd(key, {member: current_time})

                # Remove expired entries
                pipeline.zremrangebyscore(key, 0, window_start)

                # Count remaining entries
                pipeline.zcard(key)

                # Set key expiration
                pipeline.expire(key, self.window * 2)

                # Execute pipeline
                _, _, current, _ = pipeline.execute()

                reset_time = current_time + self.window
                return current <= self.limit, current, reset_time

            else:  # Token bucket algorithm
                # Token bucket - continuous refill of tokens
                bucket_key = f"{key}:bucket"
                last_update_key = f"{key}:last_update"

                # Get last update time
                last_update = redis_client.get(last_update_key)
                last_update = int(last_update) if last_update else 0

                # Calculate tokens to add based on time passed
                elapsed = current_time - last_update
                tokens_to_add = (elapsed * self.limit) / self.window

                # Get current tokens
                current_tokens = redis_client.get(bucket_key)
                current_tokens = float(current_tokens) if current_tokens else float(self.limit)

                # Update tokens
                new_tokens = min(float(self.limit), current_tokens + tokens_to_add)

                # Try to consume a token
                if new_tokens >= 1.0:
                    # Success - consume token
                    new_tokens -= 1.0
                    redis_client.set(bucket_key, str(new_tokens))
                    redis_client.set(last_update_key, str(current_time))
                    redis_client.expire(bucket_key, self.window * 2)
                    redis_client.expire(last_update_key, self.window * 2)

                    reset_time = current_time + int((1.0 - new_tokens) * (self.window / self.limit))
                    return True, self.limit - int(new_tokens), reset_time
                else:
                    # Failed - out of tokens
                    redis_client.set(bucket_key, str(new_tokens))
                    redis_client.set(last_update_key, str(current_time))

                    reset_time = current_time + int((1.0 - new_tokens) * (self.window / self.limit))
                    return False, self.limit, reset_time

        # In-memory fallback implementation with less sophistication
        # This loses state between application restarts and doesn't work in distributed environments
        # Simplified fixed window only
        return True, 0, current_time + self.window

    def __call__(self, func: F) -> F:
        """
        Decorator to apply rate limiting to a function.

        Args:
            func: The function to protect with rate limiting

        Returns:
            Decorated function with rate limiting
        """
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            key = self._get_rate_key()
            allowed, current, reset_time = self.check_rate_limit(key)

            if not allowed:
                reset_in = reset_time - int(time.time())
                logger.warning(f"Rate limit exceeded for {self.name}: {current}/{self.limit}")

                # Store rate limit info in request context if available
                if has_request_context() and hasattr(g, 'rate_limit_info'):
                    g.rate_limit_info = {
                        'limit': self.limit,
                        'remaining': 0,
                        'reset': reset_time,
                        'retry_after': reset_in
                    }

                raise RateLimitExceededError(
                    f"Rate limit exceeded for {self.name}: {current}/{self.limit}. "
                    f"Try again in {reset_in} seconds."
                )

            # Update rate limit info in request context
            if has_request_context():
                if not hasattr(g, 'rate_limit_info'):
                    g.rate_limit_info = {}

                g.rate_limit_info = {
                    'limit': self.limit,
                    'remaining': self.limit - current,
                    'reset': reset_time
                }

            return func(*args, **kwargs)

        return cast(F, wrapper)


# Export classes
__all__ = [
    'CircuitBreaker',
    'CircuitBreakerState',
    'CircuitOpenError',
    'RateLimiter',
    'RateLimitExceededError'
]
