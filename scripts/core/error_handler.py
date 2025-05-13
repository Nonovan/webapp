#!/usr/bin/env python3
# filepath: scripts/core/error_handler.py
"""
Standardized Error Handling for Cloud Infrastructure Platform.

This module provides a comprehensive error handling framework with standardized error
reporting, categorization, and correlation. It ensures consistent error management
across all platform components and facilitates troubleshooting through detailed
error information and integration with monitoring systems.

Key features:
- Structured error reporting and classification
- Error correlation through request IDs
- Integration with logging and monitoring
- Customizable error recovery strategies
- Circuit breaker pattern implementation
- Error metrics collection
- Notification system integration
- Error aggregation and deduplication
"""

import os
import sys
import uuid
import time
import logging
import traceback
import json
import socket
import inspect
import threading
from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional, Union, List, Tuple, Callable, TypeVar, Type, cast

# Try to import internal modules
try:
    from scripts.core.logger import Logger
    from scripts.core.notification import NotificationService, PRIORITY_HIGH, PRIORITY_CRITICAL
    INTERNAL_MODULES_AVAILABLE = True
except ImportError:
    INTERNAL_MODULES_AVAILABLE = False

# Set up basic logging if Logger is not available
if INTERNAL_MODULES_AVAILABLE:
    logger = Logger.get_logger(__name__)
else:
    logging.basicConfig(
        format='[%(asctime)s] %(levelname)s in %(name)s: %(message)s',
        level=logging.INFO
    )
    logger = logging.getLogger(__name__)

# Type variable for generic function decorator
F = TypeVar('F', bound=Callable[..., Any])

# Constants
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 1.0  # seconds
DEFAULT_BACKOFF_MULTIPLIER = 2.0
DEFAULT_MAX_JITTER = 0.25  # 25% jitter
DEFAULT_CIRCUIT_TIMEOUT = 60.0  # seconds
DEFAULT_CIRCUIT_HALF_OPEN_TIMEOUT = 30.0  # seconds
DEFAULT_CIRCUIT_FAILURE_THRESHOLD = 5
DEFAULT_TIMEOUT = 30.0  # seconds

# Error categories for classification
class ErrorCategory(Enum):
    """Categories for error classification."""
    CONFIGURATION = "configuration"
    NETWORK = "network"
    RESOURCE = "resource"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    TIMEOUT = "timeout"
    SERVICE = "service"
    DATABASE = "database"
    SECURITY = "security"
    API = "api"
    CLIENT = "client"
    SYSTEM = "system"
    DEPENDENCY = "dependency"
    UNEXPECTED = "unexpected"
    UNKNOWN = "unknown"

# Error severity levels
class ErrorSeverity(Enum):
    """Severity levels for errors."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

# Exit codes for CLI applications
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_CONFIG_ERROR = 2
EXIT_VALIDATION_ERROR = 3
EXIT_AUTHENTICATION_ERROR = 4
EXIT_AUTHORIZATION_ERROR = 5
EXIT_NETWORK_ERROR = 6
EXIT_TIMEOUT_ERROR = 7
EXIT_SERVICE_ERROR = 8
EXIT_RESOURCE_ERROR = 9
EXIT_DEPENDENCY_ERROR = 10
EXIT_NOT_IMPLEMENTED = 11
EXIT_SECURITY_ERROR = 12
EXIT_USER_ABORT = 130  # Standard for SIGINT

# Exception class definitions
class ApplicationError(Exception):
    """Base exception class for application errors."""

    def __init__(self, message: str, category: ErrorCategory = ErrorCategory.UNKNOWN,
                 severity: ErrorSeverity = ErrorSeverity.ERROR, details: Optional[Dict[str, Any]] = None):
        """
        Initialize application error.

        Args:
            message: Error message
            category: Error category
            severity: Error severity
            details: Additional error details
        """
        super().__init__(message)
        self.message = message
        self.category = category
        self.severity = severity
        self.details = details or {}
        self.timestamp = datetime.now().isoformat()
        self.error_id = str(uuid.uuid4())

    def __str__(self) -> str:
        """String representation of the error."""
        return f"{self.category.value.upper()}: {self.message}"

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert error to dictionary representation.

        Returns:
            Dictionary containing error details
        """
        return {
            "error_id": self.error_id,
            "message": self.message,
            "category": self.category.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp,
            "details": self.details
        }

class ConfigurationError(ApplicationError):
    """Error related to configuration issues."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message,
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            details=details
        )

class ValidationError(ApplicationError):
    """Error related to input validation."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message,
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.WARNING,
            details=details
        )

class AuthenticationError(ApplicationError):
    """Error related to authentication issues."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message,
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            details=details
        )

class AuthorizationError(ApplicationError):
    """Error related to authorization issues."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message,
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            details=details
        )

class ResourceError(ApplicationError):
    """Error related to resource management."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message,
            category=ErrorCategory.RESOURCE,
            severity=ErrorSeverity.ERROR,
            details=details
        )

class NetworkError(ApplicationError):
    """Error related to network operations."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message,
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.ERROR,
            details=details
        )

class TimeoutError(ApplicationError):
    """Error related to timeout issues."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message,
            category=ErrorCategory.TIMEOUT,
            severity=ErrorSeverity.WARNING,
            details=details
        )

class ServiceError(ApplicationError):
    """Error related to service operations."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message,
            category=ErrorCategory.SERVICE,
            severity=ErrorSeverity.ERROR,
            details=details
        )

class DatabaseError(ApplicationError):
    """Error related to database operations."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message,
            category=ErrorCategory.DATABASE,
            severity=ErrorSeverity.ERROR,
            details=details
        )

class SecurityError(ApplicationError):
    """Error related to security issues."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message,
            category=ErrorCategory.SECURITY,
            severity=ErrorSeverity.CRITICAL,
            details=details
        )

class CircuitOpenError(ApplicationError):
    """Error raised when a circuit breaker is open."""

    def __init__(self, service_name: str, timeout: float, details: Optional[Dict[str, Any]] = None):
        message = f"Circuit breaker open for service: {service_name}. Retry after {timeout}s"
        super().__init__(
            message,
            category=ErrorCategory.SERVICE,
            severity=ErrorSeverity.WARNING,
            details=details or {}
        )
        self.service_name = service_name
        self.timeout = timeout
        self.details["service_name"] = service_name
        self.details["timeout"] = timeout

# Circuit breaker implementation
class CircuitBreaker:
    """Implementation of the circuit breaker pattern."""

    # Store circuit breakers by name for reuse
    _circuit_breakers = {}
    _lock = threading.RLock()

    # Circuit breaker states
    class State(Enum):
        """Circuit breaker states."""
        CLOSED = "closed"  # Normal operation
        OPEN = "open"      # Failing, not allowing calls
        HALF_OPEN = "half_open"  # Testing if service is back

    def __init__(
        self,
        name: str,
        failure_threshold: int = DEFAULT_CIRCUIT_FAILURE_THRESHOLD,
        reset_timeout: float = DEFAULT_CIRCUIT_TIMEOUT,
        half_open_timeout: float = DEFAULT_CIRCUIT_HALF_OPEN_TIMEOUT
    ):
        """
        Initialize circuit breaker.

        Args:
            name: Unique name for this circuit
            failure_threshold: Number of consecutive failures before tripping
            reset_timeout: Seconds to wait before attempting reset
            half_open_timeout: Seconds to wait in half-open before fully closing
        """
        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.half_open_timeout = half_open_timeout

        # State information
        self.state = self.State.CLOSED
        self.failures = 0
        self.last_failure_time = 0
        self.last_success_time = 0
        self.opened_at = 0
        self.half_opened_at = 0

    @classmethod
    def get(cls, name: str, **kwargs) -> 'CircuitBreaker':
        """
        Get (or create) a circuit breaker by name.

        Args:
            name: Circuit breaker name
            **kwargs: Arguments for creation if needed

        Returns:
            CircuitBreaker instance
        """
        with cls._lock:
            if name not in cls._circuit_breakers:
                cls._circuit_breakers[name] = CircuitBreaker(name, **kwargs)
            return cls._circuit_breakers[name]

    @classmethod
    def reset_all(cls) -> None:
        """Reset all circuit breakers to closed state."""
        with cls._lock:
            for circuit in cls._circuit_breakers.values():
                circuit.reset()

    def reset(self) -> None:
        """Reset circuit breaker to closed state."""
        with self._lock:
            self.state = self.State.CLOSED
            self.failures = 0
            self.last_failure_time = 0
            self.opened_at = 0
            self.half_opened_at = 0

    def record_success(self) -> None:
        """Record successful operation, potentially closing circuit."""
        with self._lock:
            self.last_success_time = time.time()

            if self.state == self.State.HALF_OPEN:
                # If we've been in half-open state for enough time with success,
                # fully close the circuit
                if time.time() - self.half_opened_at >= self.half_open_timeout:
                    logger.info(f"Circuit '{self.name}' closing after success in half-open state")
                    self.state = self.State.CLOSED
                    self.failures = 0
                    self.opened_at = 0
                    self.half_opened_at = 0
            elif self.state == self.State.CLOSED:
                # Reset failure count on success in closed state
                self.failures = 0

    def record_failure(self) -> None:
        """Record failure, potentially opening circuit."""
        with self._lock:
            self.failures += 1
            self.last_failure_time = time.time()

            if self.state == self.State.CLOSED and self.failures >= self.failure_threshold:
                logger.warning(
                    f"Circuit '{self.name}' opening after {self.failures} consecutive failures"
                )
                self.state = self.State.OPEN
                self.opened_at = time.time()
            elif self.state == self.State.HALF_OPEN:
                # Any failure in half-open returns to open state
                logger.warning(f"Circuit '{self.name}' returning to open state after failure in half-open")
                self.state = self.State.OPEN
                self.opened_at = time.time()
                self.half_opened_at = 0

    def allow_request(self) -> bool:
        """
        Check if a request should be allowed through the circuit.

        Returns:
            True if request is allowed, False otherwise
        """
        with self._lock:
            now = time.time()

            if self.state == self.State.CLOSED:
                return True
            elif self.state == self.State.OPEN:
                # Check if we've waited long enough to try again
                if now - self.opened_at >= self.reset_timeout:
                    logger.info(f"Circuit '{self.name}' transitioning from open to half-open")
                    self.state = self.State.HALF_OPEN
                    self.half_opened_at = now
                    return True
                return False
            elif self.state == self.State.HALF_OPEN:
                # In half-open, we allow limited traffic through
                # We'll allow just one request at a time
                return True

            # Default to safety - shouldn't get here
            return False

    def __enter__(self):
        """Context manager entry."""
        if not self.allow_request():
            remaining = self.reset_timeout - (time.time() - self.opened_at)
            remaining = max(0, remaining)
            raise CircuitOpenError(self.name, remaining)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if exc_val is not None:
            self.record_failure()
        else:
            self.record_success()
        return False  # Don't suppress exceptions

# Main error handler class
class ErrorHandler:
    """
    Main error handler for standardized error processing.
    Provides methods for handling errors, implementing retry logic,
    and integrating with notification systems.
    """

    def __init__(
        self,
        correlation_id: Optional[str] = None,
        service_name: Optional[str] = None,
        context: Optional[str] = None,
        log_level: ErrorSeverity = ErrorSeverity.ERROR,
        notify_critical: bool = True,
        collect_metrics: bool = True
    ):
        """
        Initialize error handler.

        Args:
            correlation_id: ID for correlating related errors
            service_name: Service or module name
            context: Context information
            log_level: Default log level for errors
            notify_critical: Whether to send notifications for critical errors
            collect_metrics: Whether to collect error metrics
        """
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.service_name = service_name or self._get_caller_module()
        self.context = context
        self.log_level = log_level
        self.notify_critical = notify_critical
        self.collect_metrics = collect_metrics

        # Initialize notification service if available
        self.notifier = None
        if INTERNAL_MODULES_AVAILABLE and self.notify_critical:
            try:
                self.notifier = NotificationService()
            except Exception as e:
                logger.warning(f"Failed to initialize notification service: {e}")

    def handle_error(
        self,
        error: Exception,
        message: Optional[str] = None,
        severity: Optional[ErrorSeverity] = None,
        category: Optional[ErrorCategory] = None,
        context: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        notify: bool = False,
        exit_code: Optional[int] = None,
        reraise: bool = True,
        retry: bool = False,
        retry_count: int = 0,
        critical: bool = False
    ) -> Dict[str, Any]:
        """
        Handle an exception with standardized processing.

        Args:
            error: The exception to handle
            message: Custom error message
            severity: Error severity level
            category: Error category
            context: Error context
            details: Additional error details
            notify: Whether to send notification
            exit_code: Exit code to use if exiting
            reraise: Whether to re-raise the exception
            retry: Whether to retry the operation
            retry_count: Current retry count
            critical: Whether to treat as critical regardless of severity

        Returns:
            Dictionary with error details

        Raises:
            Exception: Re-raises the original exception if reraise=True
        """
        # Extract or create error details
        error_details = self._extract_error_details(
            error, message, severity, category, context, details, retry_count
        )

        # Override critical flag if specified
        if critical:
            error_details["severity"] = ErrorSeverity.CRITICAL.value

        # Log the error
        self._log_error(error_details, error)

        # Send notification if needed
        if self._should_notify(error_details, notify):
            self._send_notification(error_details)

        # Update metrics if enabled
        if self.collect_metrics:
            self._update_metrics(error_details)

        # Exit if exit code provided
        if exit_code is not None:
            sys.exit(exit_code)

        # Re-raise if requested
        if reraise:
            raise error

        return error_details

    def retry(
        self,
        func: Callable,
        args: tuple = (),
        kwargs: Optional[Dict[str, Any]] = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_delay: float = DEFAULT_RETRY_DELAY,
        backoff_multiplier: float = DEFAULT_BACKOFF_MULTIPLIER,
        jitter: bool = True,
        retry_exceptions: Tuple[Type[Exception], ...] = (Exception,),
        exclude_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
        on_retry: Optional[Callable[[Exception, int], None]] = None
    ) -> Any:
        """
        Retry a function with exponential backoff.

        Args:
            func: Function to execute
            args: Function positional arguments
            kwargs: Function keyword arguments
            max_retries: Maximum number of retries
            retry_delay: Initial retry delay in seconds
            backoff_multiplier: Multiplier for exponential backoff
            jitter: Whether to add jitter to delay
            retry_exceptions: Exceptions that trigger retries
            exclude_exceptions: Exceptions that should not be retried
            on_retry: Callback function executed on retry

        Returns:
            Result of the function call

        Raises:
            Exception: The last exception if all retries fail
        """
        kwargs = kwargs or {}
        exclude_exceptions = exclude_exceptions or ()

        last_exception = None
        for attempt in range(max_retries + 1):  # +1 for the initial attempt
            try:
                return func(*args, **kwargs)
            except retry_exceptions as e:
                # Skip retry if exception is in excluded list
                if isinstance(e, exclude_exceptions):
                    raise

                last_exception = e
                if attempt >= max_retries:
                    # We've used all retries
                    break

                # Calculate delay with exponential backoff
                delay = retry_delay * (backoff_multiplier ** attempt)

                # Add jitter if requested (±25%)
                if jitter:
                    import random
                    delay = delay * (1 + random.uniform(-DEFAULT_MAX_JITTER, DEFAULT_MAX_JITTER))

                # Log the retry
                logger.warning(
                    f"Retry {attempt + 1}/{max_retries} after error: {str(e)}. "
                    f"Retrying in {delay:.2f}s"
                )

                # Execute retry callback if provided
                if on_retry:
                    on_retry(e, attempt)

                # Wait before retrying
                time.sleep(delay)

        # If we get here, all retries failed
        if last_exception:
            error_details = self._extract_error_details(
                last_exception,
                message=f"Operation failed after {max_retries} retries",
                severity=ErrorSeverity.ERROR,
                retry_count=max_retries
            )
            self._log_error(error_details, last_exception)
            raise last_exception

        # Should never reach here, but just in case
        raise RuntimeError("Unexpected error in retry logic")

    def with_circuit_breaker(
        self,
        circuit_name: str,
        func: Callable,
        args: tuple = (),
        kwargs: Optional[Dict[str, Any]] = None,
        failure_threshold: int = DEFAULT_CIRCUIT_FAILURE_THRESHOLD,
        reset_timeout: float = DEFAULT_CIRCUIT_TIMEOUT,
        half_open_timeout: float = DEFAULT_CIRCUIT_HALF_OPEN_TIMEOUT
    ) -> Any:
        """
        Execute a function with circuit breaker protection.

        Args:
            circuit_name: Name of the circuit breaker
            func: Function to execute
            args: Function positional arguments
            kwargs: Function keyword arguments
            failure_threshold: Number of failures before opening circuit
            reset_timeout: Seconds to wait before attempting reset
            half_open_timeout: Seconds to wait in half-open state

        Returns:
            Result of the function call

        Raises:
            CircuitOpenError: When circuit is open
            Exception: Any exception raised by the function
        """
        kwargs = kwargs or {}

        # Get or create circuit breaker
        circuit = CircuitBreaker.get(
            circuit_name,
            failure_threshold=failure_threshold,
            reset_timeout=reset_timeout,
            half_open_timeout=half_open_timeout
        )

        # Use context manager to properly track success/failure
        with circuit:
            return func(*args, **kwargs)

    def with_timeout(
        self,
        func: Callable,
        args: tuple = (),
        kwargs: Optional[Dict[str, Any]] = None,
        timeout: float = DEFAULT_TIMEOUT
    ) -> Any:
        """
        Execute a function with timeout.

        Args:
            func: Function to execute
            args: Function positional arguments
            kwargs: Function keyword arguments
            timeout: Timeout in seconds

        Returns:
            Result of the function call

        Raises:
            TimeoutError: When function execution exceeds timeout
            Exception: Any exception raised by the function
        """
        kwargs = kwargs or {}

        # Import threading modules only when needed
        import threading
        import ctypes

        # Result container
        result = {"value": None, "exception": None}

        # Worker thread function
        def worker():
            try:
                result["value"] = func(*args, **kwargs)
            except Exception as e:
                result["exception"] = e

        # Start worker thread
        thread = threading.Thread(target=worker)
        thread.daemon = True
        thread.start()

        # Wait for thread to complete or timeout
        thread.join(timeout)

        # Check if thread is still alive (meaning we timed out)
        if thread.is_alive():
            # Create custom timeout error
            error = TimeoutError(f"Operation timed out after {timeout} seconds")
            error_details = self._extract_error_details(
                error,
                severity=ErrorSeverity.WARNING,
                category=ErrorCategory.TIMEOUT,
                details={"timeout_seconds": timeout}
            )
            self._log_error(error_details, error)

            raise error

        # If there was an exception in the thread, raise it
        if result["exception"]:
            raise result["exception"]

        return result["value"]

    def safe_execute(
        self,
        func: Callable,
        args: tuple = (),
        kwargs: Optional[Dict[str, Any]] = None,
        fallback: Any = None,
        error_message: Optional[str] = None,
        log_errors: bool = True
    ) -> Any:
        """
        Execute a function safely, returning fallback value on error.

        Args:
            func: Function to execute
            args: Function positional arguments
            kwargs: Function keyword arguments
            fallback: Value to return on error
            error_message: Custom error message
            log_errors: Whether to log errors

        Returns:
            Result of function call or fallback value
        """
        kwargs = kwargs or {}

        try:
            return func(*args, **kwargs)
        except Exception as e:
            if log_errors:
                error_details = self._extract_error_details(
                    e,
                    message=error_message or f"Error executing {func.__name__}",
                    severity=ErrorSeverity.WARNING
                )
                self._log_error(error_details, e)
            return fallback

    def _extract_error_details(
        self,
        error: Exception,
        message: Optional[str] = None,
        severity: Optional[ErrorSeverity] = None,
        category: Optional[ErrorCategory] = None,
        context: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        retry_count: int = 0
    ) -> Dict[str, Any]:
        """
        Extract or create error details from an exception.

        Args:
            error: The exception
            message: Custom error message
            severity: Error severity
            category: Error category
            context: Error context
            details: Additional error details
            retry_count: Current retry count

        Returns:
            Dictionary with error details
        """
        error_details = {}

        # If it's our application error, use its details
        if isinstance(error, ApplicationError):
            error_details = error.to_dict()
        else:
            # Determine category and severity based on error type
            if category is None:
                category = self._categorize_error(error)

            if severity is None:
                severity = self._determine_severity(error, category)

            # Create error details
            error_id = str(uuid.uuid4())
            error_details = {
                "error_id": error_id,
                "message": message or str(error),
                "category": category.value,
                "severity": severity.value,
                "timestamp": datetime.now().isoformat(),
                "exception_type": error.__class__.__name__,
                "details": {}
            }

        # Add common information
        error_details["correlation_id"] = self.correlation_id
        error_details["service_name"] = self.service_name

        # Update context
        if context or self.context:
            error_details["context"] = context or self.context

        # Update details
        if details:
            if "details" not in error_details:
                error_details["details"] = {}
            error_details["details"].update(details)

        # Add stack information
        stack = self._get_stack_info()
        if stack:
            error_details["stack"] = stack

        # Add system information
        system_info = self._get_system_info()
        if system_info:
            error_details["system"] = system_info

        # Add retry information if applicable
        if retry_count > 0:
            error_details["retry_count"] = retry_count

        return error_details

    def _log_error(self, error_details: Dict[str, Any], error: Exception) -> None:
        """
        Log error with appropriate level and details.

        Args:
            error_details: Error details dictionary
            error: The original exception
        """
        # Determine log level
        severity = error_details.get("severity", ErrorSeverity.ERROR.value)
        if isinstance(severity, ErrorSeverity):
            severity = severity.value

        # Map severity to log level
        log_level_map = {
            ErrorSeverity.DEBUG.value: logging.DEBUG,
            ErrorSeverity.INFO.value: logging.INFO,
            ErrorSeverity.WARNING.value: logging.WARNING,
            ErrorSeverity.ERROR.value: logging.ERROR,
            ErrorSeverity.CRITICAL.value: logging.CRITICAL
        }
        log_level = log_level_map.get(severity, logging.ERROR)

        # Format message
        message = error_details.get("message", str(error))
        category = error_details.get("category", ErrorCategory.UNKNOWN.value)
        error_id = error_details.get("error_id", "unknown")
        correlation_id = error_details.get("correlation_id", self.correlation_id)

        log_message = f"[{error_id}] {category.upper()}: {message}"
        if correlation_id:
            log_message = f"[CID:{correlation_id}] {log_message}"

        # Log the error
        if log_level >= logging.ERROR:
            # Include traceback for errors and critical issues
            logger.log(log_level, log_message, exc_info=error)
        else:
            # Just log message for warnings and below
            logger.log(log_level, log_message)

    def _should_notify(self, error_details: Dict[str, Any], force_notify: bool) -> bool:
        """
        Determine if notification should be sent for this error.

        Args:
            error_details: Error details
            force_notify: Whether to force notification

        Returns:
            True if notification should be sent
        """
        # If notifier not available, can't notify
        if not self.notifier:
            return False

        # Explicit request to notify
        if force_notify:
            return True

        # Notify for critical errors if enabled
        severity = error_details.get("severity", "")
        if self.notify_critical and severity == ErrorSeverity.CRITICAL.value:
            return True

        return False

    def _send_notification(self, error_details: Dict[str, Any]) -> None:
        """
        Send notification for error.

        Args:
            error_details: Error details
        """
        if not self.notifier:
            return

        try:
            # Prepare notification
            severity = error_details.get("severity", "")
            priority = PRIORITY_CRITICAL if severity == ErrorSeverity.CRITICAL.value else PRIORITY_HIGH

            # Format message
            category = error_details.get("category", "unknown").upper()
            message = error_details.get("message", "Unknown error")
            error_id = error_details.get("error_id", "unknown")
            service = error_details.get("service_name", self.service_name or "unknown")

            subject = f"{category} ERROR in {service}: {message}"

            # Sanitize details for notification
            notification_details = {
                "error_id": error_id,
                "correlation_id": error_details.get("correlation_id", self.correlation_id),
                "category": error_details.get("category", "unknown"),
                "service": service,
                "timestamp": error_details.get("timestamp", datetime.now().isoformat())
            }

            if "context" in error_details:
                notification_details["context"] = error_details["context"]

            if "exception_type" in error_details:
                notification_details["exception_type"] = error_details["exception_type"]

            # Send notification using appropriate template or direct message
            channels = ["email", "slack"] if severity == ErrorSeverity.CRITICAL.value else ["slack"]

            self.notifier.send(
                message=f"{subject}\n\nDetails: {json.dumps(notification_details, indent=2)}",
                subject=subject,
                priority=priority,
                channels=channels,
                async_send=True
            )

        except Exception as e:
            logger.warning(f"Failed to send error notification: {e}")

    def _update_metrics(self, error_details: Dict[str, Any]) -> None:
        """
        Update error metrics.

        Args:
            error_details: Error details
        """
        # This would integrate with your metrics system
        # For now, we'll just add a stub implementation
        try:
            category = error_details.get("category", "unknown")
            severity = error_details.get("severity", "unknown")
            service = error_details.get("service_name", self.service_name or "unknown")

            # This is where you'd increment your metrics counters, for example:
            # metrics.increment(f"errors.{service}.{category}.{severity}", 1)
            pass

        except Exception as e:
            logger.debug(f"Failed to update error metrics: {e}")

    def _categorize_error(self, error: Exception) -> ErrorCategory:
        """
        Categorize an exception based on its type.

        Args:
            error: The exception to categorize

        Returns:
            Error category
        """
        error_type = type(error)
        error_name = error_type.__name__.lower()

        # Network errors
        if any(name in error_name for name in ["connection", "network", "socket", "timeout", "http"]):
            return ErrorCategory.NETWORK

        # Authentication errors
        if any(name in error_name for name in ["auth", "login", "credential", "password"]):
            return ErrorCategory.AUTHENTICATION

        # Permission/authorization errors
        if any(name in error_name for name in ["permission", "access", "forbidden", "unauthorized"]):
            return ErrorCategory.AUTHORIZATION

        # Validation errors
        if any(name in error_name for name in ["validation", "invalid", "schema", "format"]):
            return ErrorCategory.VALIDATION

        # Configuration errors
        if any(name in error_name for name in ["config", "setting", "parameter"]):
            return ErrorCategory.CONFIGURATION

        # Resource errors
        if any(name in error_name for name in ["resource", "notfound", "exists", "full", "empty"]):
            return ErrorCategory.RESOURCE

        # Timeout errors
        if "timeout" in error_name:
            return ErrorCategory.TIMEOUT

        # Database errors
        if any(name in error_name for name in ["database", "db", "sql", "query", "transaction"]):
            return ErrorCategory.DATABASE

        # Security errors
        if any(name in error_name for name in ["security", "crypto", "hash", "cipher", "secure"]):
            return ErrorCategory.SECURITY

        # Fall back to unknown
        return ErrorCategory.UNKNOWN

    def _determine_severity(self, error: Exception, category: ErrorCategory) -> ErrorSeverity:
        """
        Determine severity based on exception and category.

        Args:
            error: The exception
            category: Error category

        Returns:
            Error severity
        """
        # Security issues are always critical
        if category == ErrorCategory.SECURITY:
            return ErrorSeverity.CRITICAL

        # Authentication and authorization failures are errors
        if category in [ErrorCategory.AUTHENTICATION, ErrorCategory.AUTHORIZATION]:
            return ErrorSeverity.ERROR

        # Validation issues are warnings
        if category == ErrorCategory.VALIDATION:
            return ErrorSeverity.WARNING

        # Network errors severity depends on the specific exception
        if category == ErrorCategory.NETWORK:
            if any(name in type(error).__name__.lower() for name in ["timeout", "connectionrefused"]):
                return ErrorSeverity.WARNING
            return ErrorSeverity.ERROR

        # Configuration issues are errors
        if category == ErrorCategory.CONFIGURATION:
            return ErrorSeverity.ERROR

        # Database issues are errors
        if category == ErrorCategory.DATABASE:
            return ErrorSeverity.ERROR

        # Resource errors depend on context - not found often just a warning
        if category == ErrorCategory.RESOURCE:
            if "notfound" in type(error).__name__.lower():
                return ErrorSeverity.WARNING
            return ErrorSeverity.ERROR

        # Default to ERROR
        return ErrorSeverity.ERROR

    def _get_stack_info(self) -> Dict[str, Any]:
        """
        Get information about the current call stack.

        Returns:
            Dictionary with stack information
        """
        try:
            stack_info = {}

            # Get current frame
            frame = sys._getframe(2)  # Skip this method and handle_error

            # Extract basic frame info
            stack_info["file"] = frame.f_code.co_filename
            stack_info["function"] = frame.f_code.co_name
            stack_info["line"] = frame.f_lineno

            # Get file name without path
            stack_info["file_name"] = os.path.basename(stack_info["file"])

            return stack_info

        except Exception:
            return {}

    def _get_system_info(self) -> Dict[str, Any]:
        """
        Get basic system information.

        Returns:
            Dictionary with system information
        """
        try:
            system_info = {
                "hostname": socket.gethostname(),
                "pid": os.getpid()
            }

            # Add environment name if available
            env_var_names = ["ENVIRONMENT", "ENV", "APP_ENV", "FLASK_ENV"]
            for var in env_var_names:
                if var in os.environ:
                    system_info["environment"] = os.environ[var]
                    break

            return system_info

        except Exception:
            return {}

    def _get_caller_module(self) -> str:
        """
        Get the name of the calling module.

        Returns:
            Module name or 'unknown'
        """
        try:
            frame = sys._getframe(2)  # Skip this method and constructor
            module = inspect.getmodule(frame)
            if module:
                return module.__name__
            return "unknown"
        except Exception:
            return "unknown"

# Function decorators
def retry(
    max_retries: int = DEFAULT_MAX_RETRIES,
    retry_delay: float = DEFAULT_RETRY_DELAY,
    backoff_multiplier: float = DEFAULT_BACKOFF_MULTIPLIER,
    jitter: bool = True,
    retry_exceptions: Tuple[Type[Exception], ...] = (Exception,),
    exclude_exceptions: Optional[Tuple[Type[Exception], ...]] = None
) -> Callable[[F], F]:
    """
    Decorator for retry logic.

    Args:
        max_retries: Maximum number of retries
        retry_delay: Initial retry delay in seconds
        backoff_multiplier: Multiplier for exponential backoff
        jitter: Whether to add jitter to delay
        retry_exceptions: Exceptions that trigger retries
        exclude_exceptions: Exceptions that should not be retried

    Returns:
        Decorated function
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            handler = ErrorHandler()
            return handler.retry(
                func=func,
                args=args,
                kwargs=kwargs,
                max_retries=max_retries,
                retry_delay=retry_delay,
                backoff_multiplier=backoff_multiplier,
                jitter=jitter,
                retry_exceptions=retry_exceptions,
                exclude_exceptions=exclude_exceptions
            )
        return cast(F, wrapper)
    return decorator

def circuit_breaker(
    circuit_name: Optional[str] = None,
    failure_threshold: int = DEFAULT_CIRCUIT_FAILURE_THRESHOLD,
    reset_timeout: float = DEFAULT_CIRCUIT_TIMEOUT,
    half_open_timeout: float = DEFAULT_CIRCUIT_HALF_OPEN_TIMEOUT
) -> Callable[[F], F]:
    """
    Decorator for circuit breaker pattern.

    Args:
        circuit_name: Name of circuit breaker
        failure_threshold: Number of failures before opening
        reset_timeout: Seconds to wait before attempting reset
        half_open_timeout: Seconds to wait in half-open state

    Returns:
        Decorated function
    """
    def decorator(func: F) -> F:
        # Use function name as circuit name if not provided
        nonlocal circuit_name
        if circuit_name is None:
            circuit_name = f"{func.__module__}.{func.__name__}"

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            handler = ErrorHandler()
            return handler.with_circuit_breaker(
                circuit_name=circuit_name,
                func=func,
                args=args,
                kwargs=kwargs,
                failure_threshold=failure_threshold,
                reset_timeout=reset_timeout,
                half_open_timeout=half_open_timeout
            )
        return cast(F, wrapper)
    return decorator

def timeout(timeout_seconds: float = DEFAULT_TIMEOUT) -> Callable[[F], F]:
    """
    Decorator for function timeout.

    Args:
        timeout_seconds: Timeout in seconds

    Returns:
        Decorated function
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            handler = ErrorHandler()
            return handler.with_timeout(
                func=func,
                args=args,
                kwargs=kwargs,
                timeout=timeout_seconds
            )
        return cast(F, wrapper)
    return decorator

def safe_execution(
    fallback: Any = None,
    error_message: Optional[str] = None,
    log_errors: bool = True
) -> Callable[[F], F]:
    """
    Decorator for safe execution with fallback.

    Args:
        fallback: Value to return on error
        error_message: Custom error message
        log_errors: Whether to log errors

    Returns:
        Decorated function
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            handler = ErrorHandler()
            return handler.safe_execute(
                func=func,
                args=args,
                kwargs=kwargs,
                fallback=fallback,
                error_message=error_message,
                log_errors=log_errors
            )
        return cast(F, wrapper)
    return decorator

# Utility functions
def categorize_error(error: Exception) -> Dict[str, str]:
    """
    Categorize an error for external use.

    Args:
        error: Exception to categorize

    Returns:
        Dictionary with error category and severity
    """
    handler = ErrorHandler()
    category = handler._categorize_error(error)
    severity = handler._determine_severity(error, category)

    return {
        "category": category.value,
        "severity": severity.value
    }

def get_error_details(
    error: Exception,
    message: Optional[str] = None,
    correlation_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get detailed error information for an exception.

    Args:
        error: The exception
        message: Custom error message
        correlation_id: Correlation ID

    Returns:
        Dictionary with error details
    """
    handler = ErrorHandler(correlation_id=correlation_id)
    return handler._extract_error_details(error, message=message)

def format_error_for_cli(error: Exception, include_traceback: bool = False) -> str:
    """
    Format an error for CLI display.

    Args:
        error: The exception to format
        include_traceback: Whether to include traceback

    Returns:
        Formatted error string
    """
    handler = ErrorHandler()
    details = handler._extract_error_details(error)

    # Basic formatting
    severity = details.get("severity", "error").upper()
    category = details.get("category", "unknown").upper()
    message = details.get("message", str(error))

    formatted = f"{severity} [{category}]: {message}"

    # Add traceback if requested
    if include_traceback:
        tb_str = "".join(traceback.format_exception(type(error), error, error.__traceback__))
        formatted += f"\n\nStacktrace:\n{tb_str}"

    return formatted

def format_error_for_json(error: Exception) -> Dict[str, Any]:
    """
    Format an error for JSON response.

    Args:
        error: The exception to format

    Returns:
        Dictionary with formatted error details
    """
    handler = ErrorHandler()
    details = handler._extract_error_details(error)

    # Create API-friendly format
    return {
        "error": {
            "type": details.get("category", "unknown"),
            "message": details.get("message", str(error)),
            "code": details.get("error_id", "unknown"),
            "severity": details.get("severity", "error")
        }
    }

def exit_with_error(
    error: Union[Exception, str],
    exit_code: int = EXIT_ERROR,
    correlation_id: Optional[str] = None
) -> None:
    """
    Log an error and exit with specified code.

    Args:
        error: Exception or error message
        exit_code: Exit code to use
        correlation_id: Optional correlation ID
    """
    handler = ErrorHandler(correlation_id=correlation_id)

    if isinstance(error, str):
        # Create application error from message
        error = ApplicationError(error, ErrorCategory.UNKNOWN, ErrorSeverity.ERROR)

    details = handler._extract_error_details(error)
    handler._log_error(details, error if isinstance(error, Exception) else RuntimeError(error))

    sys.exit(exit_code)

def map_exception_to_exit_code(error: Exception) -> int:
    """
    Map an exception to an appropriate exit code.

    Args:
        error: Exception to map

    Returns:
        Exit code
    """
    if isinstance(error, ConfigurationError):
        return EXIT_CONFIG_ERROR
    elif isinstance(error, ValidationError):
        return EXIT_VALIDATION_ERROR
    elif isinstance(error, AuthenticationError):
        return EXIT_AUTHENTICATION_ERROR
    elif isinstance(error, AuthorizationError):
        return EXIT_AUTHORIZATION_ERROR
    elif isinstance(error, NetworkError):
        return EXIT_NETWORK_ERROR
    elif isinstance(error, TimeoutError):
        return EXIT_TIMEOUT_ERROR
    elif isinstance(error, ServiceError):
        return EXIT_SERVICE_ERROR
    elif isinstance(error, ResourceError):
        return EXIT_RESOURCE_ERROR
    elif isinstance(error, SecurityError):
        return EXIT_SECURITY_ERROR
    elif isinstance(error, NotImplementedError):
        return EXIT_NOT_IMPLEMENTED
    else:
        return EXIT_ERROR

# Module-level functions for direct use
def handle_error(
    error: Exception,
    message: Optional[str] = None,
    correlation_id: Optional[str] = None,
    context: Optional[str] = None,
    service_name: Optional[str] = None,
    notify: bool = False,
    exit_on_error: bool = False,
    reraise: bool = True
) -> Dict[str, Any]:
    """
    Handle an error with default error handler.

    Args:
        error: Exception to handle
        message: Custom error message
        correlation_id: Correlation ID
        context: Error context
        service_name: Service name
        notify: Whether to send notification
        exit_on_error: Whether to exit on error
        reraise: Whether to re-raise exception

    Returns:
        Dictionary with error details
    """
    handler = ErrorHandler(
        correlation_id=correlation_id,
        service_name=service_name,
        context=context
    )

    exit_code = map_exception_to_exit_code(error) if exit_on_error else None

    return handler.handle_error(
        error=error,
        message=message,
        notify=notify,
        exit_code=exit_code,
        reraise=reraise and not exit_on_error
    )

# CLI helper function
def handle_cli_error(
    error: Exception,
    message: Optional[str] = None,
    exit_code: Optional[int] = None,
    show_traceback: bool = False
) -> None:
    """
    Handle error in CLI application with proper formatting and exit code.

    Args:
        error: Exception to handle
        message: Custom error message
        exit_code: Exit code to use
        show_traceback: Whether to show traceback
    """
    if not exit_code:
        exit_code = map_exception_to_exit_code(error)

    # Get error details
    handler = ErrorHandler()
    details = handler._extract_error_details(error, message=message)

    # Log the error
    handler._log_error(details, error)

    # Print error message for CLI
    severity = details.get("severity", "error").upper()
    category = details.get("category", "unknown").upper()
    message = details.get("message", str(error))

    print(f"ERROR [{category}]: {message}", file=sys.stderr)

    # Show traceback if requested
    if show_traceback:
        print("\nTraceback:", file=sys.stderr)
        traceback.print_exception(type(error), error, error.__traceback__, file=sys.stderr)

    sys.exit(exit_code)

# If run directly, perform simple test
if __name__ == "__main__":
    # Simple test of error handler functionality
    handler = ErrorHandler(service_name="error_handler_test")

    print("Testing error handler functionality...")

    # Test circuit breaker
    circuit = CircuitBreaker.get("test_circuit")
    print(f"Circuit state: {circuit.state}")

    # Test retry decorator
    @retry(max_retries=3)
    def test_retry_function(fail=True):
        if fail:
            raise ValueError("Test error for retry")
        return "Success"

    # Test timeout decorator
    @timeout(2.0)
    def test_timeout_function(sleep_time):
        time.sleep(sleep_time)
        return "Done sleeping"

    # Test safe execution
    @safe_execution(fallback="Fallback value")
    def test_safe_function(fail=True):
        if fail:
            raise ValueError("Test error for safe execution")
        return "Success"

    # Run tests
    try:
        print("\nTesting retry (should fail after 3 attempts):")
        try:
            test_retry_function()
        except Exception as e:
            print(f"  Got expected error: {e}")

        print("\nTesting timeout (should succeed):")
        result = test_timeout_function(1.0)
        print(f"  Result: {result}")

        print("\nTesting timeout (should fail):")
        try:
            test_timeout_function(3.0)
        except TimeoutError as e:
            print(f"  Got expected timeout: {e}")

        print("\nTesting safe execution (should use fallback):")
        result = test_safe_function()
        print(f"  Result: {result}")

        print("\nTesting safe execution (should succeed):")
        result = test_safe_function(fail=False)
        print(f"  Result: {result}")

        print("\nTesting error category detection:")
        errors = [
            ValueError("Invalid value"),
            ConnectionError("Failed to connect"),
            PermissionError("Access denied"),
            TimeoutError("Operation timed out"),
            FileNotFoundError("Resource not found")
        ]

        for error in errors:
            cat_info = categorize_error(error)
            print(f"  {error.__class__.__name__}: {cat_info}")

        print("\nTesting application-specific errors:")
        try:
            raise ConfigurationError("Missing required configuration")
        except ApplicationError as e:
            handler.handle_error(e)

        print("\nTests completed.")
    except Exception as e:
        print(f"Unexpected error during tests: {e}")
        traceback.print_exc()
