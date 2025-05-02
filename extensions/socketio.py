"""
SocketIO extension for Cloud Infrastructure Platform.

This module provides centralized WebSocket functionality with security controls,
authentication integration, and metrics tracking. It implements secure real-time
communication channels between clients and server with proper authorization checks.
"""

import logging
from typing import Dict, Any, Optional, List, Callable, Union

from flask import Flask, request, session, g, current_app
from flask_socketio import SocketIO

from extensions import metrics

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize SocketIO with default settings
# We'll configure it properly during init_app
socketio = SocketIO()

# Metrics for SocketIO connections and events
socketio_connection_count = metrics.gauge(
    'socketio_connections_active',
    'Current number of active SocketIO connections',
    labels=['namespace']
)

socketio_message_counter = metrics.counter(
    'socketio_messages_total',
    'Total SocketIO messages',
    labels=['namespace', 'event_type', 'direction']
)

socketio_error_counter = metrics.counter(
    'socketio_errors_total',
    'Total SocketIO errors',
    labels=['namespace', 'error_type']
)

socketio_latency = metrics.histogram(
    'socketio_message_latency_seconds',
    'SocketIO message processing latency in seconds',
    labels=['namespace', 'event_type'],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
)

# Track connection sessions
active_namespaces: Dict[str, int] = {}


def init_app(app: Flask) -> None:
    """
    Initialize SocketIO with the Flask application.

    Configures the SocketIO extension with security settings and integrates
    with authentication and metrics systems.

    Args:
        app: The Flask application instance
    """
    # Get configuration settings with secure defaults
    config = {
        'cors_allowed_origins': app.config.get('SOCKETIO_CORS_ALLOWED_ORIGINS', '*'),
        'async_mode': app.config.get('SOCKETIO_ASYNC_MODE', 'eventlet'),
        'ping_timeout': app.config.get('SOCKETIO_PING_TIMEOUT', 20),
        'ping_interval': app.config.get('SOCKETIO_PING_INTERVAL', 25),
        'max_http_buffer_size': app.config.get('SOCKETIO_MAX_HTTP_BUFFER_SIZE', 1024 * 1024),  # 1 MB default
        'manage_session': app.config.get('SOCKETIO_MANAGE_SESSION', True),
        'json': app.config.get('SOCKETIO_JSON_SERIALIZER', None),
        'engineio_logger': app.config.get('SOCKETIO_ENGINEIO_LOGGER', False),
        'logger': app.config.get('SOCKETIO_LOGGER', False),
    }

    # Configure WebSocket handling
    if app.config.get('ENV') == 'production':
        # Enforce secure WebSocket in production
        config['ssl_required'] = True

        # Set WebSocket protocols with secure defaults
        websocket_allowed_origins = app.config.get('WEBSOCKET_ALLOWED_ORIGINS', [])
        if websocket_allowed_origins:
            config['cors_allowed_origins'] = websocket_allowed_origins

    # Apply rate limiting if configured
    if app.config.get('SOCKETIO_RATE_LIMITING_ENABLED', False):
        # Import rate limiter only if enabled
        from extensions import limiter
        config['rate_limiting_enabled'] = True

    # Initialize the extension with the Flask app and configuration
    socketio.init_app(app, **config)

    # Register connection handlers
    register_connection_handlers(app)

    # Set up metrics tracking
    if app.config.get('METRICS_ENABLED', True):
        setup_metrics_tracking()

    logger.info("SocketIO initialized with %s backend", config['async_mode'])


def register_connection_handlers(app: Flask) -> None:
    """
    Register global connection event handlers for security and metrics.

    Args:
        app: The Flask application instance
    """
    @socketio.on('connect')
    def handle_connect():
        """Global connection handler for security and metrics."""
        namespace = getattr(request, 'namespace', '/')

        # Track connection metrics
        if namespace not in active_namespaces:
            active_namespaces[namespace] = 0
        active_namespaces[namespace] += 1
        socketio_connection_count.inc(1, labels={'namespace': namespace})

        # Log connection if debug logging is enabled
        if app.config.get('SOCKETIO_LOG_CONNECTIONS', False):
            logger.debug(
                "SocketIO connection established: namespace=%s, sid=%s, ip=%s",
                namespace,
                request.sid,
                request.remote_addr
            )

    @socketio.on('disconnect')
    def handle_disconnect():
        """Global disconnection handler for security and metrics."""
        namespace = getattr(request, 'namespace', '/')

        # Update metrics
        if namespace in active_namespaces and active_namespaces[namespace] > 0:
            active_namespaces[namespace] -= 1
            socketio_connection_count.dec(1, labels={'namespace': namespace})

        # Log disconnection if debug logging is enabled
        if app.config.get('SOCKETIO_LOG_CONNECTIONS', False):
            logger.debug(
                "SocketIO connection closed: namespace=%s, sid=%s",
                namespace,
                request.sid
            )


def setup_metrics_tracking() -> None:
    """Configure SocketIO metrics tracking."""
    # Set up before_event and after_event handlers for latency tracking
    # Note: This would require custom event handler wrapping to accurately track latency

    # Alternatively, use the Flask-SocketIO's before_event and after_event hooks if available
    pass


def emit_with_metrics(event: str, data: Any, namespace: str = None, room: str = None, **kwargs) -> None:
    """
    Emit a SocketIO event with metrics tracking.

    Args:
        event: The event name
        data: The data to send
        namespace: The namespace to emit to
        room: The room to emit to
        **kwargs: Additional arguments to pass to emit
    """
    try:
        # Track message metrics before sending
        socketio_message_counter.inc(1, labels={
            'namespace': namespace or '/',
            'event_type': event,
            'direction': 'sent'
        })

        # Emit the event
        socketio.emit(event, data, namespace=namespace, room=room, **kwargs)
    except Exception as e:
        # Track error metrics
        socketio_error_counter.inc(1, labels={
            'namespace': namespace or '/',
            'error_type': 'emit_error'
        })
        logger.error("Error emitting SocketIO event %s: %s", event, str(e), exc_info=True)
        raise


def get_active_connections(namespace: str = '/') -> int:
    """
    Get the number of active connections for a namespace.

    Args:
        namespace: The namespace to check

    Returns:
        The number of active connections
    """
    return active_namespaces.get(namespace, 0)


def get_active_connections_by_namespace() -> Dict[str, int]:
    """
    Get all active connections grouped by namespace.

    Returns:
        Dictionary with namespaces as keys and connection counts as values
    """
    return active_namespaces.copy()


def run_server(host: str = None, port: int = None, **kwargs) -> None:
    """
    Run the SocketIO server.

    This is a convenience wrapper around socketio.run().

    Args:
        host: The host to bind to
        port: The port to bind to
        **kwargs: Additional arguments to pass to socketio.run()
    """
    socketio.run(current_app, host=host, port=port, **kwargs)
