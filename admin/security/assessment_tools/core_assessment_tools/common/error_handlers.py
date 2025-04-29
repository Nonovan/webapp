"""
Error handling utilities for security assessment tools.

This module provides standardized error handling functionality for security assessment tools,
including error processing, recovery mechanisms, retry logic, and error reporting. It ensures
consistent behavior across different assessment tools when encountering errors.
"""

import functools
import inspect
import logging
import os
import sys
import time
import traceback
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type, TypeVar, Union, cast

from .assessment_logging import get_assessment_logger
from .assessment_base import (
    AssessmentException,
    AssessmentInitializationError,
    AssessmentExecutionError,
    AssessmentConfigurationError
)

# Initialize module logger
logger = get_assessment_logger("error_handlers")

# Type variable for decorator return type preservation
F = TypeVar('F', bound=Callable[..., Any])


class ErrorSeverity(Enum):
    """Severity levels for errors and exceptions."""

    CRITICAL = "critical"  # Errors that require immediate attention, may impact security
    ERROR = "error"        # Standard errors that prevent normal operation
    WARNING = "warning"    # Issues that don't prevent operation but may indicate problems
    INFO = "info"          # Informational issues


class ErrorHandlingStrategy(Enum):
    """Strategies for handling errors."""

    FAIL_FAST = "fail_fast"           # Immediately fail on first error
    CONTINUE = "continue"             # Continue despite errors
    RETRY = "retry"                   # Retry the operation on failure
    GRACEFUL_DEGRADATION = "degrade"  # Continue with reduced functionality


class ExponentialBackoff:
    """
    Implements exponential backoff strategy for retries.

    Provides increasing delay times between retry attempts with configurable
    base delay, maximum delay, and jitter.
    """

    def __init__(
        self,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_retries: int = 5,
        backoff_factor: float = 2.0,
        jitter: bool = True
    ):
        """
        Initialize exponential backoff parameters.

        Args:
            base_delay: Initial delay in seconds
            max_delay: Maximum delay in seconds
            max_retries: Maximum number of retry attempts
            backoff_factor: Multiplier for each subsequent delay
            jitter: Whether to add randomness to delay times
        """
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.jitter = jitter
        self._attempts = 0

    def reset(self) -> None:
        """Reset the retry counter."""
        self._attempts = 0

    def next_delay(self) -> Optional[float]:
        """
        Calculate the next delay time.

        Returns:
            Next delay time in seconds, or None if max retries exceeded
        """
        if self._attempts >= self.max_retries:
            return None

        # Calculate exponential delay
        delay = min(
            self.base_delay * (self.backoff_factor ** self._attempts),
            self.max_delay
        )

        # Add jitter if enabled (±20%)
        if self.jitter:
            import random
            jitter_factor = 0.8 + (random.random() * 0.4)  # 0.8-1.2
            delay *= jitter_factor

        self._attempts += 1
        return delay

    @property
    def attempts(self) -> int:
        """Get the current number of attempts."""
        return self._attempts


def handle_assessment_error(
    error: Exception,
    context: str = "",
    assessment_id: Optional[str] = None,
    severity: ErrorSeverity = ErrorSeverity.ERROR,
    log_exception: bool = True,
    notify: bool = False,
    exit_on_error: bool = False,
    exit_code: int = 1
) -> Dict[str, Any]:
    """
    Handle an exception raised during assessment execution.

    This function provides standardized error handling for assessment tools,
    including proper logging, optional notification, and conditionally exiting
    the program.

    Args:
        error: The exception to handle
        context: Description of the context where the error occurred
        assessment_id: Optional ID of the assessment
        severity: Severity level of the error
        log_exception: Whether to include exception traceback in logs
        notify: Whether to trigger error notifications
        exit_on_error: Whether to exit the program after handling
        exit_code: Exit code to use if exiting

    Returns:
        Dictionary with error details
    """
    error_type = error.__class__.__name__
    error_message = str(error)
    error_context = context or "unspecified context"

    # Prepare the error details
    error_details = {
        "error_type": error_type,
        "message": error_message,
        "context": error_context,
        "severity": severity.value,
        "assessment_id": assessment_id,
        "timestamp": time.time()
    }

    # Format for logging
    log_message = f"{error_type} in {error_context}: {error_message}"
    if assessment_id:
        log_message = f"[Assessment {assessment_id}] {log_message}"

    # Log based on severity
    if severity == ErrorSeverity.CRITICAL:
        logger.critical(log_message, exc_info=log_exception)
    elif severity == ErrorSeverity.ERROR:
        logger.error(log_message, exc_info=log_exception)
    elif severity == ErrorSeverity.WARNING:
        logger.warning(log_message, exc_info=log_exception)
    else:
        logger.info(log_message, exc_info=log_exception)

    # Send notifications if requested
    if notify:
        try:
            _send_error_notification(error_details)
        except Exception as notification_error:
            logger.error(
                f"Failed to send error notification: {notification_error}",
                exc_info=True
            )

    # Exit if requested
    if exit_on_error:
        sys.exit(exit_code)

    return error_details


def retry_operation(
    func: Optional[Callable] = None,
    *,
    max_attempts: int = 3,
    retry_exceptions: Tuple[Type[Exception], ...] = (Exception,),
    exclude_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    backoff_factor: float = 2.0,
    jitter: bool = True,
    on_retry: Optional[Callable[[Exception, int], None]] = None
) -> Callable:
    """
    Decorator for retrying operations that may fail with transient errors.

    Args:
        func: Function to decorate
        max_attempts: Maximum number of retry attempts
        retry_exceptions: Tuple of exception types to retry
        exclude_exceptions: Tuple of exception types to not retry even if within retry_exceptions
        base_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
        backoff_factor: Multiplier for each subsequent delay
        jitter: Whether to add randomness to delay times
        on_retry: Optional callback function called before each retry

    Returns:
        Decorated function
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            backoff = ExponentialBackoff(
                base_delay=base_delay,
                max_delay=max_delay,
                max_retries=max_attempts - 1,
                backoff_factor=backoff_factor,
                jitter=jitter
            )

            attempt = 1
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    # Don't retry if the exception is excluded
                    if exclude_exceptions and isinstance(e, exclude_exceptions):
                        raise

                    # Only retry specific exceptions
                    if not isinstance(e, retry_exceptions):
                        raise

                    # Check if retries are exhausted
                    delay = backoff.next_delay()
                    if delay is None:
                        logger.error(
                            f"Operation failed after {max_attempts} attempts: {e}",
                            exc_info=True
                        )
                        raise

                    # Log retry attempt
                    logger.warning(
                        f"Retry attempt {attempt}/{max_attempts} after error: {e}. "
                        f"Retrying in {delay:.2f} seconds."
                    )

                    # Call the retry callback if provided
                    if on_retry:
                        try:
                            on_retry(e, attempt)
                        except Exception as callback_error:
                            logger.warning(
                                f"Error in retry callback: {callback_error}"
                            )

                    # Wait before retrying
                    time.sleep(delay)
                    attempt += 1

        return cast(F, wrapper)

    if func is None:
        return decorator
    return decorator(func)


def safe_execute(
    func: Callable,
    *args: Any,
    error_message: str = "Operation failed",
    fallback_result: Any = None,
    log_level: ErrorSeverity = ErrorSeverity.ERROR,
    **kwargs: Any
) -> Any:
    """
    Execute a function safely, handling exceptions.

    This function provides a way to execute operations that might fail,
    with standardized error handling and optional fallback results.

    Args:
        func: Function to execute
        *args: Positional arguments for the function
        error_message: Message to log if the operation fails
        fallback_result: Value to return if the operation fails
        log_level: Severity level for logging errors
        **kwargs: Keyword arguments for the function

    Returns:
        Function result or fallback value
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        if log_level == ErrorSeverity.CRITICAL:
            logger.critical(f"{error_message}: {e}", exc_info=True)
        elif log_level == ErrorSeverity.ERROR:
            logger.error(f"{error_message}: {e}", exc_info=True)
        elif log_level == ErrorSeverity.WARNING:
            logger.warning(f"{error_message}: {e}", exc_info=True)
        else:
            logger.info(f"{error_message}: {e}", exc_info=True)

        return fallback_result


def validate_assessment_preconditions(
    *required_conditions: Tuple[bool, str]
) -> None:
    """
    Validate required conditions before assessment execution.

    This function checks that all required conditions are met before
    starting an assessment, raising appropriate exceptions if not.

    Args:
        *required_conditions: Tuple pairs of condition and error message

    Raises:
        AssessmentInitializationError: If any condition is not met
    """
    for condition, error_message in required_conditions:
        if not condition:
            raise AssessmentInitializationError(error_message)


def handle_specific_exceptions(
    exception_handlers: Dict[Type[Exception], Callable[[Exception], Any]],
    default_handler: Optional[Callable[[Exception], Any]] = None
) -> Callable:
    """
    Decorator for handling specific types of exceptions with custom handlers.

    Args:
        exception_handlers: Mapping of exception types to handler functions
        default_handler: Optional default handler for unspecified exceptions

    Returns:
        Decorated function
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                for exception_type, handler in exception_handlers.items():
                    if isinstance(e, exception_type):
                        return handler(e)

                # Use default handler if provided, otherwise re-raise
                if default_handler is not None:
                    return default_handler(e)
                raise

        return cast(F, wrapper)

    return decorator


def circuit_breaker(
    failure_threshold: int = 5,
    reset_timeout: float = 60.0,
    half_open_after: float = 30.0,
    excluded_exceptions: Tuple[Type[Exception], ...] = ()
) -> Callable:
    """
    Decorator implementing the circuit breaker pattern.

    Prevents calling a failing service repeatedly, allowing it time to recover.

    Args:
        failure_threshold: Number of failures before opening the circuit
        reset_timeout: Seconds after which to reset failure count
        half_open_after: Seconds after which to try a single request
        excluded_exceptions: Exceptions that don't count towards failures

    Returns:
        Decorated function
    """
    def decorator(func: F) -> F:
        # Per-function state (shared across instances)
        state = {
            "failures": 0,
            "circuit_open": False,
            "last_failure_time": 0.0,
            "last_check_time": 0.0
        }

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            current_time = time.time()

            # Check if circuit should reset due to time elapsed
            if state["circuit_open"]:
                time_since_failure = current_time - state["last_failure_time"]

                # Allow a test request if in half-open state
                if time_since_failure >= half_open_after:
                    state["last_check_time"] = current_time
                    logger.info(f"Circuit half-open for {func.__name__}, allowing test request")
                # Otherwise fail fast
                else:
                    logger.warning(
                        f"Circuit open for {func.__name__}, fast failing "
                        f"(retry in {half_open_after - time_since_failure:.1f}s)"
                    )
                    raise AssessmentExecutionError(
                        f"Service unavailable due to circuit breaker for {func.__name__}"
                    )

            try:
                result = func(*args, **kwargs)

                # Reset circuit on success
                if state["circuit_open"] or state["failures"] > 0:
                    logger.info(f"Circuit reset for {func.__name__}, operation successful")
                    state["circuit_open"] = False
                    state["failures"] = 0

                return result

            except Exception as e:
                # Don't count excluded exceptions
                if isinstance(e, excluded_exceptions):
                    raise

                # Record failure
                state["failures"] += 1
                state["last_failure_time"] = current_time

                # Open circuit if threshold reached
                if state["failures"] >= failure_threshold:
                    state["circuit_open"] = True
                    logger.warning(
                        f"Circuit opened for {func.__name__} after {failure_threshold} failures"
                    )

                # Re-raise the original exception
                raise

        return cast(F, wrapper)

    return decorator


def capture_assessment_exceptions(func: F) -> F:
    """
    Decorator for capturing and transforming exceptions into AssessmentExceptions.

    Args:
        func: Function to decorate

    Returns:
        Decorated function
    """
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except AssessmentException:
            # Already an assessment exception, re-raise
            raise
        except ValueError as e:
            # Configuration or parameter errors
            raise AssessmentConfigurationError(str(e))
        except (ConnectionError, TimeoutError) as e:
            # Network or connectivity problems
            raise AssessmentExecutionError(f"Connection error: {str(e)}")
        except PermissionError as e:
            # Permission problems
            raise AssessmentExecutionError(f"Permission denied: {str(e)}")
        except FileNotFoundError as e:
            # Missing files or resources
            raise AssessmentConfigurationError(f"Resource not found: {str(e)}")
        except Exception as e:
            # Generic cases
            raise AssessmentExecutionError(
                f"Unhandled exception ({e.__class__.__name__}): {str(e)}"
            ) from e

    return cast(F, wrapper)


def with_timeout(timeout: float) -> Callable:
    """
    Decorator for adding timeout to a function.

    Args:
        timeout: Timeout in seconds

    Returns:
        Decorated function
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            import signal

            def timeout_handler(signum: int, frame: Any) -> None:
                raise TimeoutError(f"Function {func.__name__} timed out after {timeout} seconds")

            # Set the timeout handler
            original_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(int(timeout))

            try:
                return func(*args, **kwargs)
            finally:
                # Reset alarm and restore original handler
                signal.alarm(0)
                signal.signal(signal.SIGALRM, original_handler)

        return cast(F, wrapper)

    return decorator


def error_chain_formatter(exc_info: Optional[Tuple] = None) -> str:
    """
    Format an exception chain with cause information.

    Args:
        exc_info: Optional exception info tuple (type, value, traceback)

    Returns:
        Formatted error chain as string
    """
    if exc_info is None:
        exc_info = sys.exc_info()

    if not exc_info or not exc_info[0]:
        return "No exception information available"

    error_type, error_value, tb = exc_info

    # Format the initial error and traceback
    error_chain = [
        f"Exception: {error_type.__name__}: {error_value}",
        "Traceback:",
        "".join(traceback.format_tb(tb)).strip()
    ]

    # Add any chained exceptions (Python 3 exception chaining with __cause__)
    current_exc = error_value
    while current_exc.__cause__:
        current_exc = current_exc.__cause__
        error_chain.append(f"Caused by: {current_exc.__class__.__name__}: {current_exc}")

    return "\n".join(error_chain)


def collect_error_details(
    error: Exception,
    context: str = "",
    include_traceback: bool = True,
    include_system_info: bool = False
) -> Dict[str, Any]:
    """
    Collect detailed information about an error.

    Args:
        error: Exception to analyze
        context: Context where the error occurred
        include_traceback: Whether to include traceback information
        include_system_info: Whether to include system information

    Returns:
        Dictionary with error details
    """
    details = {
        "error_type": error.__class__.__name__,
        "message": str(error),
        "context": context or "unspecified",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    # Add traceback if requested
    if include_traceback:
        details["traceback"] = "".join(
            traceback.format_exception(
                type(error), error, error.__traceback__
            )
        )

    # Add system info if requested
    if include_system_info:
        import platform
        details["system_info"] = {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "interpreter": sys.executable,
            "pid": os.getpid(),
            "cwd": os.getcwd()
        }

    # Add any additional error attributes
    details["attributes"] = {}
    for attr in dir(error):
        if not attr.startswith("_") and attr not in ["args", "with_traceback"]:
            try:
                value = getattr(error, attr)
                if not callable(value):
                    details["attributes"][attr] = str(value)
            except Exception:
                pass

    return details


def get_stack_info(skip_frames: int = 0) -> Dict[str, Any]:
    """
    Get information about the current call stack.

    Args:
        skip_frames: Number of frames to skip (to exclude utility functions)

    Returns:
        Dictionary with stack information
    """
    stack_info: Dict[str, Any] = {
        "frames": [],
        "caller": None
    }

    try:
        # Get the call stack
        stack = inspect.stack()

        # Skip this function and any requested frames
        frames = stack[skip_frames + 1:]

        for frame_info in frames:
            frame = {
                "filename": frame_info.filename,
                "function": frame_info.function,
                "lineno": frame_info.lineno
            }
            stack_info["frames"].append(frame)

        # Get the immediate caller
        if len(frames) > 0:
            caller = frames[0]
            stack_info["caller"] = {
                "filename": caller.filename,
                "function": caller.function,
                "lineno": caller.lineno,
                "code_context": caller.code_context[0].strip() if caller.code_context else None
            }
    except Exception as e:
        logger.debug(f"Error getting stack info: {e}")

    return stack_info


def _send_error_notification(error_details: Dict[str, Any]) -> None:
    """
    Send notification for critical errors.

    Args:
        error_details: Dictionary with error information

    Note:
        This is a placeholder implementation. In a production environment,
        this would integrate with notification systems like email, Slack, etc.
    """
    # This is a stub implementation - in a real system, this would:
    # 1. Check configuration for notification settings
    # 2. Format the error message appropriately for the notification channel
    # 3. Send the notification via the appropriate service (email, Slack, etc.)

    logger.info(
        f"Would send notification for error: "
        f"{error_details['error_type']}: {error_details['message']}"
    )

    # Examples of potential implementations:
    # 1. Email notification:
    # send_email(
    #     to="security-alerts@example.com",
    #     subject=f"Assessment Error: {error_details['error_type']}",
    #     body=format_error_for_email(error_details)
    # )

    # 2. Slack/Teams notification:
    # post_to_slack(
    #     webhook_url=config.get("slack_webhook_url"),
    #     channel="#security-alerts",
    #     message=format_error_for_slack(error_details)
    # )

    # 3. Incident management system:
    # create_incident(
    #     title=f"Assessment Error: {error_details['error_type']}",
    #     description=error_details['message'],
    #     severity=map_severity(error_details['severity']),
    #     source="security_assessment_tools"
    # )
    pass
