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
- File integrity event notifications
- Graceful recovery from service interruptions
- Efficient resource cleanup

This package follows the same security standards as the REST API, including
strict authentication, input validation, and permission checking.
"""

import logging
import os
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Callable
from flask import Blueprint, current_app, Flask, request

# Create blueprint for WebSocket API routes
websocket_bp = Blueprint('websocket_api', __name__, url_prefix='/api/websocket')

# Initialize module logger
logger = logging.getLogger(__name__)

# Module version for tracking
__version__ = '0.1.1'

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
    - Configures file integrity monitoring events
    - Sets up periodic tasks for metrics and cleanup

    Args:
        app: Flask application instance

    Returns:
        bool: True if initialization was successful, False otherwise
    """
    global _initialized

    if _initialized:
        logger.debug("WebSocket API already initialized, skipping")
        return True

    start_time = time.time()
    components_initialized = []

    try:
        logger.info("Initializing WebSocket API components")

        # Register blueprint with application
        if not app.blueprints.get('websocket_api'):
            app.register_blueprint(websocket_bp)
            logger.debug("WebSocket API blueprint registered")
            components_initialized.append("blueprint")

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
                components_initialized.append("rate_limiting")
            except Exception as e:
                logger.warning(f"Failed to apply WebSocket API rate limits: {e}", exc_info=True)

        # Initialize WebSocket routes with the SocketIO instance
        try:
            from extensions import socketio
            init_routes(socketio)
            logger.debug("WebSocket routes initialized")
            components_initialized.append("routes")
        except ImportError as e:
            logger.error(f"Failed to import SocketIO extension: {e}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"Failed to initialize WebSocket routes: {e}", exc_info=True)
            return False

        # Set up metrics if available
        try:
            from .metrics import initialize_metrics
            initialize_metrics()
            logger.debug("WebSocket metrics initialized")
            components_initialized.append("metrics")
        except Exception as e:
            logger.warning(f"Failed to initialize WebSocket metrics: {e}")

        # Register event handlers
        try:
            register_event_handlers()
            logger.debug("WebSocket event handlers registered")
            components_initialized.append("event_handlers")
        except Exception as e:
            logger.error(f"Failed to register WebSocket event handlers: {e}", exc_info=True)
            return False

        # Set up periodic tasks
        if hasattr(app, 'config') and app.config.get('WEBSOCKET_ENABLE_METRICS_EMISSION', True):
            try:
                metrics_interval = app.config.get('WEBSOCKET_METRICS_INTERVAL', 60)
                metrics_channel = app.config.get('WEBSOCKET_METRICS_CHANNEL', 'metrics')

                @socketio.on_namespace('/ws')
                def setup_metrics_task():
                    if not hasattr(current_app, 'websocket_metrics_task'):
                        def emit_metrics_task():
                            while not current_app.config.get('WEBSOCKET_SHUTTING_DOWN', False):
                                try:
                                    emit_metrics(target_channel=metrics_channel)
                                except Exception as e:
                                    logger.error(f"Error in metrics emission task: {str(e)}", exc_info=True)
                                socketio.sleep(metrics_interval)

                        current_app.websocket_metrics_task = socketio.start_background_task(emit_metrics_task)
                        logger.debug(f"WebSocket metrics emission task initialized (interval: {metrics_interval}s)")
                components_initialized.append("metrics_task")
            except Exception as e:
                logger.warning(f"Failed to configure WebSocket metrics emission: {e}")

        # Set up connection cleanup task
        try:
            cleanup_interval = app.config.get('WEBSOCKET_CLEANUP_INTERVAL', 300)  # 5 minutes

            @socketio.on_namespace('/ws')
            def setup_cleanup_task():
                if not hasattr(current_app, 'websocket_cleanup_task'):
                    def cleanup_task():
                        while not current_app.config.get('WEBSOCKET_SHUTTING_DOWN', False):
                            try:
                                from .routes import clean_inactive_connections
                                cleaned = clean_inactive_connections()
                                if cleaned > 0:
                                    logger.info(f"Cleaned {cleaned} inactive WebSocket connections")
                            except Exception as e:
                                logger.error(f"Error in WebSocket cleanup task: {str(e)}", exc_info=True)
                            socketio.sleep(cleanup_interval)

                    current_app.websocket_cleanup_task = socketio.start_background_task(cleanup_task)
                    logger.debug(f"WebSocket connection cleanup task initialized (interval: {cleanup_interval}s)")
            components_initialized.append("cleanup_task")
        except Exception as e:
            logger.warning(f"Failed to configure WebSocket cleanup task: {e}")

        # Set up file integrity event integration
        file_integrity_available = False
        if app.config.get('WEBSOCKET_ENABLE_FILE_INTEGRITY_EVENTS', True):
            try:
                from .events import broadcast_file_integrity_event, register_event_handler

                # Register callback to broadcast file integrity events to WebSocket clients
                register_event_handler(broadcast_file_integrity_event)
                logger.debug("File integrity event handler registered for WebSocket broadcasting")
                components_initialized.append("file_integrity")
                file_integrity_available = True
            except ImportError:
                logger.info("File integrity module not available, skipping event registration")
            except Exception as e:
                logger.warning(f"Failed to register file integrity event handler: {e}")

        # Set up WebSocket security monitoring
        try:
            from core.security import log_security_event
            log_security_event(
                event_type="websocket_api_initialized",
                description="WebSocket API components initialized",
                severity="info",
                details={
                    "version": __version__,
                    "initialization_time_ms": round((time.time() - start_time) * 1000),
                    "components": components_initialized,
                    "features": [
                        "authentication",
                        "channel_subscriptions",
                        "event_dispatching",
                        "file_integrity_events" if file_integrity_available else "file_integrity_events_disabled",
                        "metrics_collection",
                        "connection_cleanup"
                    ]
                }
            )
            components_initialized.append("security_logging")
        except Exception as e:
            logger.warning(f"Could not log WebSocket API initialization event: {e}")

        # Register shutdown handler to gracefully terminate background tasks
        @app.teardown_appcontext
        def shutdown_websocket_tasks(_):
            if hasattr(current_app, 'websocket_metrics_task') or hasattr(current_app, 'websocket_cleanup_task'):
                current_app.config['WEBSOCKET_SHUTTING_DOWN'] = True
                logger.debug("WebSocket background tasks marked for shutdown")

        _initialized = True
        logger.info(f"WebSocket API initialization complete ({', '.join(components_initialized)})")
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
