"""
SocketIO extension for the Cloud Infrastructure Platform.

This module provides real-time communication capabilities for the application.
"""

import logging
from typing import Dict, Any

from flask import Flask, request, current_app
from flask_socketio import SocketIO
import time
from extensions import metrics

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize SocketIO
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


def init_socketio(app: Flask) -> None:
    """
    Initialize SocketIO with the Flask app.

    Args:
        app: Flask application
    """
    socketio_config = {
        'cors_allowed_origins': app.config.get('SOCKETIO_CORS_ALLOWED_ORIGINS', '*'),
        'async_mode': app.config.get('SOCKETIO_ASYNC_MODE', 'eventlet'),
    }

    # Use Redis as message queue if available
    if app.config.get('SOCKETIO_MESSAGE_QUEUE') or app.config.get('REDIS_URL'):
        socketio_config['message_queue'] = (
            app.config.get('SOCKETIO_MESSAGE_QUEUE') or
            app.config.get('REDIS_URL')
        )

    # Initialize SocketIO
    socketio.init_app(app, **socketio_config)

    # Set up event handlers with metrics tracking
    @socketio.on('connect')
    def handle_connect():
        socketio_connection_count.inc()

    @socketio.on('disconnect')
    def handle_disconnect():
        socketio_connection_count.dec()

    @socketio.on_error()
    def handle_error(e):
        error_type = e.__class__.__name__
        socketio_error_counter.labels(type=error_type).inc()

        # Log the error
        app.logger.error(f"SocketIO error: {str(e)}")

    app.logger.info("SocketIO initialized successfully")


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
