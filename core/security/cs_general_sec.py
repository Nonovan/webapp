"""
Security utility classes and functions for the Cloud Infrastructure Platform.

This module provides general security utility classes including circuit breakers
for preventing cascading failures, rate limiters for resource protection, and
other security-related utilities used across the application.
"""

import time
import logging
import threading
from typing import Dict, Any, Optional, Callable, List, Set, Tuple, Union
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
        excluded_exceptions: Tuple[Exception, ...] = ()
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

    def __call__(self, func):
        """
        Decorator to apply circuit breaker to a function.

        Args:
            func: The function to protect with a circuit breaker

        Returns:
            Decorated function with circuit breaker protection
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
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

        return wrapper

    def allow_request(self) -> bool:
        """
        Check if a request should be allowed through the circuit.

        Returns:
            True if the request should be allowed, False otherwise
        """
        with self._lock:
            current_time = time.time()

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
                    CircuitBreaker.circuit_resets.inc(1, {'name': self.name, 'service': self.service})
                    self._update_state_metric()
                    CircuitBreaker.circuit_successes.inc(1, {'name': self.name, 'service': self.service})

            elif self._state == CircuitBreakerState.CLOSED and self._failures > 0:
                # Reset failure count on success in closed state
                self._failures = 0

                if metrics:
                    CircuitBreaker.circuit_successes.inc(1, {'name': self.name, 'service': self.service})

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
                    CircuitBreaker.circuit_trips.inc(1, {'name': self.name, 'service': self.service})
                    CircuitBreaker.circuit_failures.inc(1, {'name': self.name, 'service': self.service})
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
                        CircuitBreaker.circuit_trips.inc(1, {'name': self.name, 'service': self.service})
                        self._update_state_metric()

                if metrics:
                    CircuitBreaker.circuit_failures.inc(1, {'name': self.name, 'service': self.service})

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
                    CircuitBreaker.circuit_resets.inc(1, {'name': self.name, 'service': self.service})
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


class CircuitOpenError(Exception):
    """Exception raised when a request is rejected due to an open circuit."""
    pass


class RateLimiter:
    """
    Rate limiter implementation with multiple strategies.

    This class implements various rate limiting strategies for protecting
    resources from excessive use. It supports fixed window, sliding window,
    and token bucket algorithms.

    Attributes:
        name: Name of this rate limiter for identification
        limit: Maximum number of requests within the time window
        window: Time window in seconds
        strategy: Rate limiting strategy to use
        key_function: Custom function to generate rate limit keys
    """

    # Rate limiting strategies
    STRATEGY_FIXED_WINDOW = 'fixed-window'
    STRATEGY_SLIDING_WINDOW = 'sliding-window'
    STRATEGY_TOKEN_BUCKET = 'token-bucket'

    # Valid strategies
    VALID_STRATEGIES = [
        STRATEGY_FIXED_WINDOW,
        STRATEGY_SLIDING_WINDOW,
        STRATEGY_TOKEN_BUCKET
    ]

    # Class-level registry of all rate limiters
    _registry: Dict[str, 'RateLimiter'] = {}

    # Metrics for rate limiting
    if metrics:
        rate_limit_hits = metrics.counter(
            'rate_limit_hits_total',
            'Rate limit hits (throttled requests)',
            labels=['name', 'strategy']
        )
        rate_limit_allowed = metrics.counter(
            'rate_limit_allowed_total',
            'Rate limit allowed requests',
            labels=['name', 'strategy']
        )
        rate_current_usage = metrics.gauge(
            'rate_limit_current_usage',
            'Current usage level (requests in window)',
            labels=['name', 'strategy']
        )
        rate_limit_capacity = metrics.gauge(
            'rate_limit_capacity',
            'Rate limit capacity (maximum requests allowed)',
            labels=['name', 'strategy']
        )

    def __init__(
        self,
        name: str,
        limit: int = 100,
        window: int = 60,
        strategy: str = STRATEGY_FIXED_WINDOW,
        key_function: Optional[Callable] = None
    ) -> None:
        """
        Initialize a new rate limiter.

        Args:
            name: Name of this rate limiter
            limit: Maximum number of requests in the time window
            window: Time window in seconds
            strategy: Rate limiting strategy (fixed-window, sliding-window, token-bucket)
            key_function: Custom function to generate rate limit keys

        Raises:
            ValueError: If an invalid strategy is specified
        """
        self.name = name
        self.limit = limit
        self.window = window

        if strategy not in self.VALID_STRATEGIES:
            raise ValueError(f"Invalid rate limiting strategy: {strategy}")
        self.strategy = strategy

        self.key_function = key_function
        self._lock = threading.RLock()

        # Local memory storage for cases where Redis is unavailable
        self._memory_store = {}

        # Register this instance
        RateLimiter._registry[name] = self

        logger.info(f"Rate limiter '{name}' created with limit={limit}/{window}s, "
                   f"strategy={strategy}")

        # Set up metrics
        if metrics:
            RateLimiter.rate_limit_capacity.set(
                limit,
                labels={'name': name, 'strategy': strategy}
            )

    def initialize(self) -> None:
        """Initialize rate limiter metrics and configuration."""
        pass

    def __call__(self, func):
        """
        Decorator to apply rate limiting to a function.

        Args:
            func: The function to protect with rate limiting

        Returns:
            Decorated function with rate limiting applied
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get rate limit key
            key = self._get_rate_key()

            # Check rate limit
            allowed, current, reset_time = self.check_rate_limit(key)

            if not allowed:
                # Log and track rate limit hit
                logger.warning(f"Rate limit exceeded for '{self.name}': {current}/{self.limit}")

                if metrics:
                    RateLimiter.rate_limit_hits.inc(
                        1,
                        labels={'name': self.name, 'strategy': self.strategy}
                    )

                # Add rate limit headers to response if available
                self._add_rate_limit_headers(reset_time)

                # Raise exception
                raise RateLimitExceededError(
                    f"Rate limit exceeded: {current}/{self.limit}. "
                    f"Retry after {reset_time - int(time.time())} seconds."
                )

            # Track allowed request
            if metrics:
                RateLimiter.rate_limit_allowed.inc(
                    1,
                    labels={'name': self.name, 'strategy': self.strategy}
                )

            # Add rate limit headers to response if available
            self._add_rate_limit_headers(reset_time, remaining=self.limit - current - 1)

            # Execute the function
            return func(*args, **kwargs)

        return wrapper

    def _get_rate_key(self) -> str:
        """
        Generate a rate limiting key based on the context.

        Returns:
            String key for rate limiting
        """
        if self.key_function:
            return self.key_function()

        # Default: use IP address and limiter name if in request context
        if has_request_context():
            return f"ratelimit:{self.name}:{request.remote_addr}"

        # Fallback to name only
        return f"ratelimit:{self.name}:global"

    def check_rate_limit(self, key: str) -> Tuple[bool, int, int]:
        """
        Check if the request is allowed based on rate limits.

        Args:
            key: Rate limit key

        Returns:
            Tuple of (allowed, current_count, reset_time)
        """
        # Get Redis client
        redis = get_redis_client()

        # Use appropriate strategy
        if self.strategy == self.STRATEGY_FIXED_WINDOW:
            return self._check_fixed_window(key, redis)
        elif self.strategy == self.STRATEGY_SLIDING_WINDOW:
            return self._check_sliding_window(key, redis)
        elif self.strategy == self.STRATEGY_TOKEN_BUCKET:
            return self._check_token_bucket(key, redis)

        # Default fallback
        return self._check_fixed_window(key, redis)

    def _check_fixed_window(
        self, key: str, redis
    ) -> Tuple[bool, int, int]:
        """
        Implement fixed window rate limiting.

        Args:
            key: Rate limit key
            redis: Redis client or None

        Returns:
            Tuple of (allowed, current_count, reset_time)
        """
        current_time = int(time.time())
        window_key = f"{key}:{current_time // self.window}"
        reset_time = (current_time // self.window + 1) * self.window

        if redis:
            try:
                # Get current count
                current = redis.get(window_key)
                current = int(current) if current is not None else 0

                # Check if limit exceeded
                if current >= self.limit:
                    return False, current, reset_time

                # Increment with pipeline for atomicity
                pipe = redis.pipeline()
                pipe.incr(window_key)
                pipe.expire(window_key, self.window)
                result = pipe.execute()

                # Update current count
                current = result[0] if result else current + 1

            except Exception as e:
                logger.error(f"Redis error in rate limiter: {str(e)}")
                # Fall back to in-memory rate limiting
                return self._memory_fixed_window(window_key, reset_time)

        else:
            # Use in-memory rate limiting if Redis is not available
            return self._memory_fixed_window(window_key, reset_time)

        # Update metrics
        if metrics:
            RateLimiter.rate_current_usage.set(
                current,
                labels={'name': self.name, 'strategy': self.strategy}
            )

        return current < self.limit, current, reset_time

    def _memory_fixed_window(
        self, window_key: str, reset_time: int
    ) -> Tuple[bool, int, int]:
        """
        In-memory implementation of fixed window rate limiting.

        Args:
            window_key: Time-based window key
            reset_time: Time when the current window expires

        Returns:
            Tuple of (allowed, current_count, reset_time)
        """
        with self._lock:
            # Clean expired entries
            current_time = int(time.time())
            self._memory_store = {k: v for k, v in self._memory_store.items()
                                if v[1] > current_time}

            # Get current count
            current, _ = self._memory_store.get(window_key, (0, reset_time))

            # Check if limit exceeded
            if current >= self.limit:
                return False, current, reset_time

            # Increment count
            self._memory_store[window_key] = (current + 1, reset_time)
            current += 1

        # Update metrics
        if metrics:
            RateLimiter.rate_current_usage.set(
                current,
                labels={'name': self.name, 'strategy': self.strategy}
            )

        return current < self.limit, current, reset_time

    def _check_sliding_window(
        self, key: str, redis
    ) -> Tuple[bool, int, int]:
        """
        Implement sliding window rate limiting.

        Args:
            key: Rate limit key
            redis: Redis client or None

        Returns:
            Tuple of (allowed, current_count, reset_time)
        """
        current_time = int(time.time())
        min_time = current_time - self.window
        reset_time = current_time + self.window

        if redis:
            try:
                # Use sorted sets with score = timestamp
                # 1. Remove old entries
                redis.zremrangebyscore(key, 0, min_time)

                # 2. Count remaining entries
                current = redis.zcard(key)

                # 3. Check limit
                if current >= self.limit:
                    # Get time of oldest entry for accurate reset time
                    oldest = redis.zrange(key, 0, 0, withscores=True)
                    if oldest:
                        reset_time = int(oldest[0][1]) + self.window
                    return False, current, reset_time

                # 4. Add new entry
                redis.zadd(key, {str(current_time): current_time})
                redis.expire(key, self.window)
                current += 1

            except Exception as e:
                logger.error(f"Redis error in rate limiter: {str(e)}")
                # Fall back to in-memory rate limiting
                return self._memory_sliding_window(key, min_time, reset_time)

        else:
            # Use in-memory rate limiting if Redis is not available
            return self._memory_sliding_window(key, min_time, reset_time)

        # Update metrics
        if metrics:
            RateLimiter.rate_current_usage.set(
                current,
                labels={'name': self.name, 'strategy': self.strategy}
            )

        return current < self.limit, current, reset_time

    def _memory_sliding_window(
        self, key: str, min_time: int, reset_time: int
    ) -> Tuple[bool, int, int]:
        """
        In-memory implementation of sliding window rate limiting.

        Args:
            key: Rate limit key
            min_time: Minimum timestamp to consider
            reset_time: Time when the current window expires

        Returns:
            Tuple of (allowed, current_count, reset_time)
        """
        current_time = int(time.time())

        with self._lock:
            # Initialize or get existing timeseries
            if key not in self._memory_store:
                self._memory_store[key] = []

            # Remove old entries
            timeseries = [t for t in self._memory_store[key] if t > min_time]
            self._memory_store[key] = timeseries

            # Check limit
            current = len(timeseries)
            if current >= self.limit:
                if timeseries:
                    reset_time = timeseries[0] + self.window
                return False, current, reset_time

            # Add new entry
            timeseries.append(current_time)
            self._memory_store[key] = timeseries
            current += 1

        # Update metrics
        if metrics:
            RateLimiter.rate_current_usage.set(
                current,
                labels={'name': self.name, 'strategy': self.strategy}
            )

        return current < self.limit, current, reset_time

    def _check_token_bucket(
        self, key: str, redis
    ) -> Tuple[bool, int, int]:
        """
        Implement token bucket rate limiting.

        Args:
            key: Rate limit key
            redis: Redis client or None

        Returns:
            Tuple of (allowed, current_count, reset_time)
        """
        bucket_key = f"{key}:bucket"
        last_update_key = f"{key}:last_update"

        current_time = time.time()
        tokens_per_second = self.limit / self.window
        reset_time = int(current_time + 1/tokens_per_second)

        if redis:
            try:
                # Get current tokens and last update time
                pipe = redis.pipeline()
                pipe.get(bucket_key)
                pipe.get(last_update_key)
                results = pipe.execute()

                tokens = float(results[0]) if results[0] is not None else self.limit
                last_update = float(results[1]) if results[1] is not None else current_time

                # Calculate token refill
                time_passed = current_time - last_update
                new_tokens = min(self.limit, tokens + time_passed * tokens_per_second)

                # Try to consume a token
                if new_tokens < 1:
                    # Not enough tokens
                    time_to_refill = (1 - new_tokens) / tokens_per_second
                    reset_time = int(current_time + time_to_refill)
                    return False, int(self.limit - new_tokens), reset_time

                # Update bucket
                remaining_tokens = new_tokens - 1

                pipe = redis.pipeline()
                pipe.set(bucket_key, str(remaining_tokens))
                pipe.set(last_update_key, str(current_time))
                pipe.expire(bucket_key, self.window * 2)
                pipe.expire(last_update_key, self.window * 2)
                pipe.execute()

                current = int(self.limit - remaining_tokens)

            except Exception as e:
                logger.error(f"Redis error in rate limiter: {str(e)}")
                # Fall back to in-memory rate limiting
                return self._memory_token_bucket(bucket_key, last_update_key, tokens_per_second, reset_time)

        else:
            # Use in-memory rate limiting if Redis is not available
            return self._memory_token_bucket(bucket_key, last_update_key, tokens_per_second, reset_time)

        # Update metrics
        if metrics:
            RateLimiter.rate_current_usage.set(
                current,
                labels={'name': self.name, 'strategy': self.strategy}
            )

        return True, current, reset_time

    def _memory_token_bucket(
        self, bucket_key: str, last_update_key: str,
        tokens_per_second: float, reset_time: int
    ) -> Tuple[bool, int, int]:
        """
        In-memory implementation of token bucket rate limiting.

        Args:
            bucket_key: Key for token bucket
            last_update_key: Key for last update time
            tokens_per_second: Rate of token refill
            reset_time: Time when a token will be available

        Returns:
            Tuple of (allowed, current_count, reset_time)
        """
        current_time = time.time()

        with self._lock:
            # Get current tokens and last update time
            tokens = self._memory_store.get(bucket_key, self.limit)
            last_update = self._memory_store.get(last_update_key, current_time)

            # Calculate token refill
            time_passed = current_time - last_update
            new_tokens = min(self.limit, tokens + time_passed * tokens_per_second)

            # Try to consume a token
            if new_tokens < 1:
                # Not enough tokens
                time_to_refill = (1 - new_tokens) / tokens_per_second
                reset_time = int(current_time + time_to_refill)
                return False, int(self.limit - new_tokens), reset_time

            # Update bucket
            remaining_tokens = new_tokens - 1
            self._memory_store[bucket_key] = remaining_tokens
            self._memory_store[last_update_key] = current_time

            current = int(self.limit - remaining_tokens)

        # Update metrics
        if metrics:
            RateLimiter.rate_current_usage.set(
                current,
                labels={'name': self.name, 'strategy': self.strategy}
            )

        return True, current, reset_time

    def _add_rate_limit_headers(self, reset_time: int, remaining: int = 0) -> None:
        """
        Add rate limit headers to the response if in a Flask request context.

        Args:
            reset_time: Unix timestamp when the rate limit resets
            remaining: Number of requests remaining in the current window
        """
        if has_request_context() and hasattr(g, 'add_response_headers'):
            # Add standard rate limit headers
            headers = {
                'X-RateLimit-Limit': str(self.limit),
                'X-RateLimit-Remaining': str(remaining),
                'X-RateLimit-Reset': str(reset_time)
            }

            # If it's a 429 response, add Retry-After header
            if remaining == 0:
                headers['Retry-After'] = str(reset_time - int(time.time()))

            g.add_response_headers(headers)

    @classmethod
    def get_all_rate_limiters(cls) -> Dict[str, Dict[str, Any]]:
        """
        Get the state of all registered rate limiters.

        Returns:
            Dictionary with rate limiter states indexed by name
        """
        result = {}
        for name, limiter in cls._registry.items():
            result[name] = {
                'limit': limiter.limit,
                'window': limiter.window,
                'strategy': limiter.strategy
            }
        return result


class RateLimitExceededError(Exception):
    """Exception raised when a request exceeds the rate limit."""
    pass


# Export classes
__all__ = [
    'CircuitBreaker',
    'CircuitBreakerState',
    'CircuitOpenError',
    'RateLimiter',
    'RateLimitExceededError'
]
