"""
Administrative WebSocket API for the Cloud Infrastructure Platform.

This module initializes WebSocket endpoints that provide secure real-time
communication for system administrators, including system health monitoring,
security event notifications, audit log streaming, and interactive
administrative commands.

The module enforces strict authentication and authorization with comprehensive
audit logging, following the same security patterns as the REST API.
"""

import logging
from typing import Dict, Any, Optional
from flask import Flask

from extensions import socketio
from .routes import init_app as init_routes
from .metrics import emit_metrics, get_metrics_summary

# Initialize module logger
logger = logging.getLogger(__name__)

# Module version for tracking in security audit logs
__version__ = '0.1.1'

# Track initialization state
_initialized = False

def init_app(app: Flask) -> bool:
    """
    Initialize the Administrative WebSocket API with the Flask application.

    This function registers WebSocket event handlers, configures metrics collection,
    and sets up security controls for admin WebSocket connections.

    Args:
        app: Flask application instance

    Returns:
        bool: True if initialization was successful, False otherwise
    """
    global _initialized

    if _initialized:
        logger.debug("Admin WebSocket API already initialized, skipping")
        return True

    try:
        # Register WebSocket routes with SocketIO instance
        init_routes(socketio)

        # Configure periodic metrics emission if enabled
        if app.config.get('ADMIN_WS_METRICS_ENABLED', True):
            metrics_interval = app.config.get('ADMIN_WS_METRICS_INTERVAL', 30)
            channels = app.config.get('ADMIN_WS_METRICS_CHANNELS', ['admin:metrics'])

            @socketio.on_namespace('/admin')
            def emit_periodic_metrics():
                """Schedule periodic metrics emission to metrics channels."""
                for channel in channels:
                    emit_metrics(target_channel=channel)

            # Register metrics task
            if hasattr(socketio, 'start_background_task'):
                socketio.start_background_task(
                    name='admin_ws_metrics',
                    target=emit_periodic_metrics,
                    interval=metrics_interval
                )

        # Register lifecycle events
        logger.info("Admin WebSocket API initialized successfully")
        _initialized = True
        return True

    except Exception as e:
        logger.error(f"Failed to initialize Admin WebSocket API: {str(e)}", exc_info=True)
        return False

# Export publicly accessible components
__all__ = [
    'init_app',
    'get_metrics_summary',
    '__version__'
]
