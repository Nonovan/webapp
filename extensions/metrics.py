"""
Metrics module for Cloud Infrastructure Platform.

This module defines custom metrics and integrates monitoring for the application.
It provides centralized metrics collection, Prometheus integration, and utilities
for tracking various application performance indicators.

Features:
- Counter, gauge, histogram, and summary metrics
- Request latency and throughput tracking
- Database performance monitoring
- Cloud resource usage tracking
- Security event monitoring
- System health metrics
"""

import time
from typing import Any, Callable, Dict, List, Optional, TypeVar, cast

from flask import Flask, current_app, g, request, session
from prometheus_client import Counter, Gauge, Histogram, Summary, CollectorRegistry
from flask_prometheus_metrics import PrometheusMetrics
from flask_socketio import emit

# Type variable for generic function wrapping
F = TypeVar('F', bound=Callable[..., Any])

# Custom registry for isolation and testing
registry = CollectorRegistry()

# Define custom metrics with proper naming conventions
REQUEST_COUNT = Counter(
    'app_http_requests_total',
    'Total number of HTTP requests',
    ['method', 'endpoint', 'http_status'],
    registry=registry
)

REQUEST_LATENCY = Histogram(
    'app_http_request_latency_seconds',
    'Histogram of HTTP request latency in seconds',
    ['method', 'endpoint'],
    buckets=(0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0),
    registry=registry
)

DB_QUERY_LATENCY = Summary(
    'app_db_query_latency_seconds',
    'Summary of database query latency in seconds',
    ['query_type', 'model', 'status'],
    registry=registry
)

CLOUD_RESOURCE_USAGE = Gauge(
    'app_cloud_resource_usage',
    'Gauge for tracking cloud resource usage',
    ['resource_type', 'provider', 'region'],
    registry=registry
)

API_REQUEST_COUNT = Counter(
    'app_api_requests_total',
    'Total number of API endpoint requests',
    ['endpoint', 'method', 'authenticated'],
    registry=registry
)

SECURITY_EVENT_COUNT = Counter(
    'app_security_events_total',
    'Total number of security events',
    ['event_type', 'severity'],
    registry=registry
)

ERROR_COUNT = Counter(
    'app_errors_total',
    'Total number of application errors',
    ['module', 'error_type', 'is_handled'],
    registry=registry
)

ACTIVE_USERS_GAUGE = Gauge(
    'app_active_users_count',
    'Gauge for active users',
    ['user_type'],
    registry=registry
)

TASK_EXECUTION_TIME = Summary(
    'app_task_execution_seconds',
    'Summary of background task execution time in seconds',
    ['task_name', 'status'],
    registry=registry
)

# Socket.IO specific metrics
socketio_connection_count = Gauge(
    'websocket_connections_active',
    'Current number of active WebSocket connections',
    ['channel', 'role'],
    multiprocess_mode='livesum',
    registry=registry
)

socketio_message_counter = Counter(
    'websocket_messages_total',
    'Total WebSocket messages',
    ['event_type', 'channel', 'direction'],
    multiprocess_mode='livesum',
    registry=registry
)

socketio_error_counter = Counter(
    'websocket_errors_total',
    'Total WebSocket errors',
    ['error_type', 'channel'],
    multiprocess_mode='livesum',
    registry=registry
)

socketio_latency = Histogram(
    'websocket_message_latency_seconds',
    'WebSocket message processing latency in seconds',
    ['event_type'],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
    registry=registry
)

# Define functions to create custom metrics
def counter(name: str, description: str, labels: Dict[str, Callable] = None,
            registry: CollectorRegistry = registry) -> Counter:
    """
    Create a Counter metric with proper prefix.

    Args:
        name: Name of the metric
        description: Description of the metric
        labels: Dictionary of label names and callables that return label values
        registry: Prometheus registry to use

    Returns:
        Counter: A properly configured counter metric
    """
    if not name.startswith('app_'):
        name = f"app_{name}"
    return Counter(name, description, list(labels.keys()) if labels else [], registry=registry)


def gauge(name: str, description: str, labels: Dict[str, Callable] = None,
          registry: CollectorRegistry = registry) -> Gauge:
    """
    Create a Gauge metric with proper prefix.

    Args:
        name: Name of the metric
        description: Description of the metric
        labels: Dictionary of label names and callables that return label values
        registry: Prometheus registry to use

    Returns:
        Gauge: A properly configured gauge metric
    """
    if not name.startswith('app_'):
        name = f"app_{name}"
    return Gauge(name, description, list(labels.keys()) if labels else [], registry=registry)


def histogram(name: str, description: str, labels: Dict[str, Callable] = None,
              buckets: tuple = None, registry: CollectorRegistry = registry) -> Histogram:
    """
    Create a Histogram metric with proper prefix.

    Args:
        name: Name of the metric
        description: Description of the metric
        labels: Dictionary of label names and callables that return label values
        buckets: Custom histogram buckets
        registry: Prometheus registry to use

    Returns:
        Histogram: A properly configured histogram metric
    """
    if not name.startswith('app_'):
        name = f"app_{name}"

    default_buckets = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
    buckets = buckets or default_buckets

    return Histogram(name, description, list(labels.keys()) if labels else [], buckets=buckets, registry=registry)


def summary(name: str, description: str, labels: Dict[str, Callable] = None,
            registry: CollectorRegistry = registry) -> Summary:
    """
    Create a Summary metric with proper prefix.

    Args:
        name: Name of the metric
        description: Description of the metric
        labels: Dictionary of label names and callables that return label values
        registry: Prometheus registry to use

    Returns:
        Summary: A properly configured summary metric
    """
    if not name.startswith('app_'):
        name = f"app_{name}"
    return Summary(name, description, list(labels.keys()) if labels else [], registry=registry)


# Flask middleware functions
def start_request_timer() -> None:
    """Start the request timer for latency tracking."""
    g.start_time = time.time()


def record_request_metrics(response: Any) -> Any:
    """
    Record request metrics after each request.

    Args:
        response: Flask response object

    Returns:
        response: Unmodified Flask response object
    """
    try:
        # Check if timer was started
        if hasattr(g, 'start_time'):
            latency = time.time() - g.start_time

            # Record metrics only if we have a valid endpoint
            if hasattr(request, 'endpoint') and request.endpoint:
                endpoint = request.endpoint
            else:
                endpoint = request.path

            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=endpoint,
                http_status=response.status_code
            ).inc()

            REQUEST_LATENCY.labels(
                method=request.method,
                endpoint=endpoint
            ).observe(latency)

            # Track API requests separately if applicable
            if request.path.startswith('/api/'):
                API_REQUEST_COUNT.labels(
                    endpoint=request.path,
                    method=request.method,
                    authenticated=hasattr(g, 'user_id') and g.user_id is not None
                ).inc()
    except Exception as e:
        # Never fail the request because of metrics collection
        if current_app and current_app.logger:
            current_app.logger.error(f"Error recording metrics: {e}")

    return response


# Database performance monitoring
def track_db_query(query_type: str, func: F, model_name: str = "unknown", *args: Any, **kwargs: Any) -> Any:
    """
    Track database query performance.

    Args:
        query_type: Type of query (select, insert, update, delete)
        func: Function that executes the query
        model_name: Name of the model being queried
        *args: Arguments to pass to the function
        **kwargs: Keyword arguments to pass to the function

    Returns:
        Any: Result of the function call
    """
    start_time = time.time()
    status = "success"

    try:
        result = func(*args, **kwargs)
        return result
    except Exception as e:
        status = "error"
        raise
    finally:
        latency = time.time() - start_time
        DB_QUERY_LATENCY.labels(
            query_type=query_type,
            model=model_name,
            status=status
        ).observe(latency)


# Cloud resource tracking
def update_cloud_resource_usage(resource_type: str, provider: str, usage: float, region: str = "global") -> None:
    """
    Update the cloud resource usage metric.

    Args:
        resource_type: Type of the resource (e.g., CPU, Memory)
        provider: Cloud provider (e.g., AWS, Azure, GCP)
        usage: Current usage value
        region: Cloud region
    """
    CLOUD_RESOURCE_USAGE.labels(
        resource_type=resource_type,
        provider=provider,
        region=region
    ).set(usage)


# Task execution monitoring
def monitor_task_execution(task_name: str) -> Callable[[F], F]:
    """
    Decorator for monitoring task execution time.

    Args:
        task_name: Name of the task for metrics labeling

    Returns:
        Callable: Decorated function
    """
    def decorator(func: F) -> F:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.time()
            status = "success"

            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                status = "error"
                raise
            finally:
                execution_time = time.time() - start_time
                TASK_EXECUTION_TIME.labels(
                    task_name=task_name,
                    status=status
                ).observe(execution_time)

        return cast(F, wrapper)
    return decorator


# Security event tracking
def track_security_event(event_type: str, severity: str = "info") -> None:
    """
    Record a security event for monitoring.

    Args:
        event_type: Type of security event (e.g., login_failed, access_denied)
        severity: Severity level (info, warning, error, critical)
    """
    SECURITY_EVENT_COUNT.labels(
        event_type=event_type,
        severity=severity
    ).inc()


# User tracking
def update_active_users(count: int, user_type: str = "regular") -> None:
    """
    Update the active users gauge.

    Args:
        count: Number of active users
        user_type: Type of user (regular, admin, api)
    """
    ACTIVE_USERS_GAUGE.labels(user_type=user_type).set(count)


# Error tracking
def track_error(module: str, error_type: str, is_handled: bool = True) -> None:
    """
    Track application errors by module and type.

    Args:
        module: Module where the error occurred
        error_type: Type of error
        is_handled: Whether the error was handled gracefully
    """
    ERROR_COUNT.labels(
        module=module,
        error_type=error_type,
        is_handled="true" if is_handled else "false"
    ).inc()


# WebSocket metrics tracking helpers
def emit_with_metrics(event: str, data: Any = None, namespace: str = None, to: str = None, room: str = None) -> None:
    """
    Emit a socket.io event with metrics tracking.

    Args:
        event: Event name
        data: Data to emit
        namespace: Socket.io namespace
        to: Specific recipient
        room: Room to broadcast to
    """
    # Record metrics before emission
    socketio_message_counter.labels(
        event_type=event,
        channel=room or 'global',
        direction='outgoing'
    ).inc()

    start_time = time.time()

    # Emit event
    emit(event, data, namespace=namespace, to=to, room=room)

    # Record latency
    latency = time.time() - start_time
    socketio_latency.labels(event_type=event).observe(latency)


# Global metrics instance
metrics = PrometheusMetrics.for_app_factory(
    app_name='cloud_platform',
    path='/metrics',
    defaults_prefix='cloud_platform',
    default_labels={
        'environment': lambda: current_app.config.get('ENVIRONMENT', 'production') if current_app else 'unknown'
    }
)

# Expose specific database metrics
db_query_counter = metrics.counter(
    'database_queries_total',
    'Total database queries executed',
    labels={
        'operation': lambda: g.get('db_operation', 'unknown'),
        'model': lambda: g.get('db_model', 'unknown'),
        'status': lambda: g.get('db_status', 'success')
    }
)

# Expose cloud resource gauge
cloud_resource_gauge = metrics.gauge(
    'cloud_resources',
    'Count of cloud resources',
    labels={
        'provider': lambda: g.get('cloud_provider', 'unknown'),
        'resource_type': lambda: g.get('resource_type', 'instance'),
        'region': lambda: g.get('cloud_region', 'unknown'),
        'status': lambda: g.get('resource_status', 'running')
    }
)


def init_metrics(app: Flask) -> None:
    """
    Initialize metrics for the Flask application.

    Args:
        app: Flask application instance
    """
    # Register middleware for all requests
    app.before_request(start_request_timer)
    app.after_request(record_request_metrics)

    # Store reference to registry in app for easier access
    app.extensions['prometheus_metrics'] = {
        'registry': registry,
        'REQUEST_COUNT': REQUEST_COUNT,
        'REQUEST_LATENCY': REQUEST_LATENCY,
        'DB_QUERY_LATENCY': DB_QUERY_LATENCY,
        'CLOUD_RESOURCE_USAGE': CLOUD_RESOURCE_USAGE,
        'API_REQUEST_COUNT': API_REQUEST_COUNT,
        'SECURITY_EVENT_COUNT': SECURITY_EVENT_COUNT,
        'ERROR_COUNT': ERROR_COUNT
    }

    # Expose helper methods on the app
    app.track_db_query = track_db_query
    app.update_cloud_resource_usage = update_cloud_resource_usage
    app.track_security_event = track_security_event
    app.track_error = track_error
    app.monitor_task = monitor_task_execution
    app.emit_with_metrics = emit_with_metrics

    # Initialize the Prometheus metrics
    metrics.init_app(app)
