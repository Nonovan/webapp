"""
WebSocket API for the Cloud Infrastructure Platform.

This module provides real-time communication capabilities through WebSocket
connections, enabling bidirectional communication between clients and the server
for features such as live updates, notifications, and real-time data streaming.

Key features:
- Secure connection establishment with token-based authentication
- Channel-based subscription model for targeted event delivery
- Standardized message format and validation
- Comprehensive error handling and logging
- Metrics collection for performance monitoring
- Rate limiting and circuit breaking for stability

This package follows the same security standards as the REST API, including
strict authentication, input validation, and permission checking.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from flask import Blueprint, current_app, Flask

# Create blueprint for WebSocket API routes
websocket_bp = Blueprint('websocket_api', __name__, url_prefix='/api/websocket')

# Initialize module logger
logger = logging.getLogger(__name__)

# Module version for tracking
__version__ = '0.1.0'

# Track initialization state
_initialized = False

# Import components after blueprint creation to avoid circular imports
# These will be imported when needed in init_app
from .routes import init_app as init_routes
from .auth import authenticate_connection, validate_channel_permission
from .channels import get_available_channels, validate_channel
from .events import dispatch_event, register_event_handlers, get_event_types
from .metrics import emit_metrics, track_connection, track_disconnection, track_message

def init_app(app: Flask) -> bool:
    """
    Initialize the WebSocket API with the Flask application.

    This function:
    - Registers the WebSocket blueprint with the application
    - Initializes WebSocket routes and event handlers
    - Sets up security controls and metrics collection
    - Configures rate limits and connection monitoring

    Args:
        app: Flask application instance

    Returns:
        bool: True if initialization was successful, False otherwise
    """
    global _initialized

    if _initialized:
        logger.debug("WebSocket API already initialized, skipping")
        return True

    try:
        logger.info("Initializing WebSocket API components")

        # Register blueprint with application
        if not app.blueprints.get('websocket_api'):
            app.register_blueprint(websocket_bp)
            logger.debug("WebSocket API blueprint registered")

        # Configure rate limiting if available
        if hasattr(app, 'extensions') and 'limiter' in app.extensions:
            limiter = app.extensions['limiter']
            auth_limit = app.config.get('WEBSOCKET_AUTH_RATE_LIMIT', '30/minute')
            conn_limit = app.config.get('WEBSOCKET_CONNECTION_RATE_LIMIT', '60/minute')
            status_limit = app.config.get('WEBSOCKET_STATUS_RATE_LIMIT', '120/minute')

            try:
                # Apply rate limits to WebSocket endpoints
                limiter.limit(auth_limit, key_func=lambda: f"ws-auth:{request.remote_addr}")(websocket_bp)
                limiter.limit(conn_limit, key_func=lambda: f"ws-conn:{request.remote_addr}")(websocket_bp)
                limiter.limit(status_limit)(websocket_bp)
                logger.debug("WebSocket API rate limits configured")
            except Exception as e:
                logger.warning(f"Failed to apply WebSocket API rate limits: {e}")

        # Initialize WebSocket routes with the SocketIO instance
        from extensions import socketio
        init_routes(socketio)

        # Set up metrics if available
        try:
            from .metrics import initialize_metrics
            initialize_metrics()
            logger.debug("WebSocket metrics initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize WebSocket metrics: {e}")

        # Register event handlers
        register_event_handlers()

        # Set up periodic tasks
        if hasattr(app, 'config') and app.config.get('WEBSOCKET_ENABLE_METRICS_EMISSION', True):
            try:
                metrics_interval = app.config.get('WEBSOCKET_METRICS_INTERVAL', 60)
                metrics_channel = app.config.get('WEBSOCKET_METRICS_CHANNEL', 'metrics')

                @socketio.on_namespace('/ws')
                def setup_metrics_task():
                    if not hasattr(current_app, 'websocket_metrics_task'):
                        def emit_metrics_task():
                            try:
                                emit_metrics(target_channel=metrics_channel)
                            except Exception as e:
                                logger.error(f"Error in metrics emission task: {str(e)}", exc_info=True)

                        current_app.websocket_metrics_task = socketio.start_background_task(
                            emit_metrics_task,
                            interval=metrics_interval
                        )
                        logger.debug(f"WebSocket metrics emission task initialized (interval: {metrics_interval}s)")
            except Exception as e:
                logger.warning(f"Failed to configure WebSocket metrics emission: {e}")

        # Set up WebSocket security monitoring
        try:
            from core.security import log_security_event
            log_security_event(
                event_type="websocket_api_initialized",
                description="WebSocket API components initialized",
                severity="info",
                details={
                    "version": __version__,
                    "features": [
                        "authentication",
                        "channel_subscriptions",
                        "event_dispatching",
                        "metrics_collection"
                    ]
                }
            )
        except Exception as e:
            logger.warning(f"Could not log WebSocket API initialization event: {e}")

        _initialized = True
        logger.info("WebSocket API initialization complete")
        return True

    except Exception as e:
        logger.error(f"Failed to initialize WebSocket API: {str(e)}", exc_info=True)
        return False

# Export public components
__all__ = [
    # Core components
    'websocket_bp',
    'init_app',
    '__version__',

    # Authentication functionality
    'authenticate_connection',
    'validate_channel_permission',

    # Channel management
    'get_available_channels',
    'validate_channel',

    # Event handling
    'dispatch_event',
    'register_event_handlers',
    'get_event_types',

    # Metrics collection
    'track_connection',
    'track_disconnection',
    'track_message',
    'emit_metrics'
]
