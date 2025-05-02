"""
Circuit Breaker class and functions for the Cloud Infrastructure Platform.

This module provides a circuit breaker utility class for preventing cascading failures
used across the application.
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


# Export classes
__all__ = [
    'CircuitBreaker',
    'CircuitBreakerState',
    'CircuitOpenError',
]
