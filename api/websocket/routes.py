"""
WebSocket routes implementation for the Cloud Infrastructure Platform.

This module defines the WebSocket endpoint handlers and message routing for
real-time communication between clients and the server. It includes connection
management, authentication verification, channel subscriptions, and message
dispatching to appropriate handlers.

Key features:
- Secure connection establishment with token-based authentication
- Channel subscription and permission verification
- Event broadcasting to subscribed clients
- Comprehensive error handling and logging
- Performance monitoring and metrics collection
"""

import json
import logging
import time
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Dict, Any, Optional, List, Union, Callable, Tuple

from flask import Blueprint, current_app, g, request, session
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect, ConnectionRefusedError

from extensions import socketio, db, metrics
from core.security import log_security_event, require_permission
from core.security.cs_general_sec import CircuitBreaker, RateLimiter
from models.auth.user import User
from models.auth.user_session import UserSession

from .auth import (
    authenticate_connection,
    verify_token,
    validate_channel_permission,
    refresh_token
)
from .schemas import (
    validate_message,
    SubscriptionSchema,
    MessageSchema,
    AuthenticationSchema
)
from .events import dispatch_event, get_event_types
from .channels import get_available_channels, validate_channel, get_channel_info

# Initialize module logger
logger = logging.getLogger(__name__)

# Configure WebSocket metrics
ws_connection_count = metrics.gauge(
    'websocket_connections_active',
    'Current number of active WebSocket connections',
    labels=['channel', 'role']
)

ws_message_counter = metrics.counter(
    'websocket_messages_total',
    'Total WebSocket messages',
    labels=['event_type', 'channel', 'direction']
)

ws_error_counter = metrics.counter(
    'websocket_errors_total',
    'Total WebSocket errors',
    labels=['error_type']
)

ws_latency = metrics.histogram(
    'websocket_message_latency_seconds',
    'WebSocket message processing latency in seconds',
    labels=['event_type'],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
)

# Circuit breaker for external service calls
channel_circuit = CircuitBreaker(name="channel_service", failure_threshold=3,
                               reset_timeout=300, half_open_after=60)

# Maximum number of concurrent connections per user
MAX_CONNECTIONS_PER_USER = 10

# Active connections tracking
active_connections = {}

# Message rate limiter
message_limiter = RateLimiter(rate=60, interval=60)  # 60 messages per minute

@socketio.on('connect', namespace='/ws')
def handle_connect():
    """
    Handle new WebSocket connection requests.

    Performs authentication, validates the request, and manages connection tracking.
    Connections are rejected if authentication fails or user exceeds connection limit.
    """
    start_time = time.time()
    connection_id = request.sid

    try:
        # Authenticate the connection
        auth_result = authenticate_connection(request)
        if not auth_result['success']:
            log_security_event(
                event_type='websocket_auth_failure',
                description=f"WebSocket authentication failure: {auth_result['message']}",
                severity='medium',
                user_id=auth_result.get('user_id'),
                ip_address=request.remote_addr,
            )
            ws_error_counter.inc(1, labels={'error_type': 'authentication_failure'})
            raise ConnectionRefusedError(auth_result['message'])

        # Store user information in session
        user = auth_result['user']
        g.user = user
        g.user_id = user.id
        g.connection_id = connection_id

        # Check if user has too many connections
        user_connections = [cid for cid, data in active_connections.items()
                          if data.get('user_id') == user.id]

        if len(user_connections) >= MAX_CONNECTIONS_PER_USER:
            log_security_event(
                event_type='websocket_connection_limit',
                description=f"WebSocket connection limit exceeded for user: {user.username}",
                severity='medium',
                user_id=user.id,
                ip_address=request.remote_addr,
            )
            ws_error_counter.inc(1, labels={'error_type': 'connection_limit_exceeded'})
            raise ConnectionRefusedError("Connection limit exceeded")

        # Track the connection
        active_connections[connection_id] = {
            'user_id': user.id,
            'username': user.username,
            'role': user.role,
            'connected_at': datetime.now(timezone.utc),
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'channels': [],
            'last_activity': datetime.now(timezone.utc)
        }

        # Update metrics
        ws_connection_count.inc(1, labels={
            'channel': 'none',
            'role': user.role
        })

        # Log successful connection
        log_security_event(
            event_type='websocket_connected',
            description=f"WebSocket connection established for user: {user.username}",
            severity='info',
            user_id=user.id,
            ip_address=request.remote_addr,
        )

        # Send welcome message with system information
        emit('system_info', {
            'type': 'connection.established',
            'data': {
                'connection_id': connection_id,
                'server_time': datetime.now(timezone.utc).isoformat(),
                'user': user.username,
                'role': user.role,
                'version': current_app.config.get('VERSION', 'unknown'),
                'environment': current_app.config.get('ENVIRONMENT', 'production'),
                'session_expires_at': (datetime.now(timezone.utc) +
                                    timedelta(minutes=current_app.config.get('WS_SESSION_MINUTES', 60))).isoformat()
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        })

        # Log performance metric
        connection_time = time.time() - start_time
        logger.debug(f"WebSocket connection established in {connection_time:.4f}s")

    except ConnectionRefusedError as e:
        # Let the exception propagate to reject the connection
        logger.warning(f"WebSocket connection rejected: {str(e)}")
        raise

    except Exception as e:
        # Handle unexpected errors
        logger.error(f"Error in WebSocket connection handler: {str(e)}", exc_info=True)
        ws_error_counter.inc(1, labels={'error_type': 'connection_error'})
        raise ConnectionRefusedError("Internal server error occurred")

@socketio.on('disconnect', namespace='/ws')
def handle_disconnect():
    """
    Handle WebSocket disconnection.

    Cleans up resources, updates metrics, and logs the disconnection event.
    """
    connection_id = request.sid

    if connection_id in active_connections:
        connection_data = active_connections[connection_id]
        user_id = connection_data.get('user_id')

        # Clean up channel subscriptions
        for channel in connection_data.get('channels', []):
            leave_room(channel)
            ws_connection_count.dec(1, labels={
                'channel': channel,
                'role': connection_data.get('role', 'unknown')
            })

        # Log disconnection
        if user_id:
            log_security_event(
                event_type='websocket_disconnected',
                description=f"WebSocket connection closed for user: {connection_data.get('username', 'unknown')}",
                severity='info',
                user_id=user_id,
                ip_address=connection_data.get('ip_address'),
            )

        # Remove from tracking
        del active_connections[connection_id]

@socketio.on('channel.subscribe', namespace='/ws')
def handle_subscribe(message):
    """
    Handle channel subscription requests.

    Validates permissions for the requested channel and manages subscription tracking.
    """
    start_time = time.time()
    connection_id = request.sid

    if connection_id not in active_connections:
        emit('error', {
            'type': 'error',
            'data': {
                'code': 'authentication_error',
                'message': 'Not authenticated'
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        })
        return

    try:
        # Validate message format
        validation_result = validate_message(message, SubscriptionSchema)
        if not validation_result['valid']:
            emit('error', {
                'type': 'error',
                'data': {
                    'code': 'validation_error',
                    'message': 'Invalid subscription request',
                    'details': validation_result['errors']
                },
                'meta': {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'request_id': message.get('request_id')
                }
            })
            ws_error_counter.inc(1, labels={'error_type': 'validation_error'})
            return

        # Extract data
        channel = message.get('data', {}).get('channel')
        filters = message.get('data', {}).get('filters', {})
        options = message.get('data', {}).get('options', {})
        request_id = message.get('request_id')

        # Validate channel format
        channel_validation = validate_channel(channel)
        if not channel_validation['valid']:
            emit('error', {
                'type': 'error',
                'data': {
                    'code': 'channel_error',
                    'message': channel_validation['message']
                },
                'meta': {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'request_id': request_id
                }
            })
            ws_error_counter.inc(1, labels={'error_type': 'invalid_channel'})
            return

        # Check permissions
        connection_data = active_connections[connection_id]
        user_id = connection_data['user_id']

        if not validate_channel_permission(channel, user_id):
            emit('error', {
                'type': 'error',
                'data': {
                    'code': 'authorization_error',
                    'message': f"Insufficient permissions for channel {channel}"
                },
                'meta': {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'request_id': request_id
                }
            })

            log_security_event(
                event_type='websocket_permission_denied',
                description=f"WebSocket channel access denied: {channel}",
                severity='medium',
                user_id=user_id,
                ip_address=connection_data.get('ip_address'),
                details={
                    'channel': channel
                }
            )

            ws_error_counter.inc(1, labels={'error_type': 'permission_denied'})
            return

        # Add to the channel
        join_room(channel)

        # Update connection tracking
        if channel not in connection_data['channels']:
            connection_data['channels'].append(channel)
            connection_data['last_activity'] = datetime.now(timezone.utc)

            # Update metrics
            ws_connection_count.inc(1, labels={
                'channel': channel,
                'role': connection_data.get('role', 'unknown')
            })

        # Send confirmation
        emit('channel.subscribe.success', {
            'type': 'channel.subscribe.success',
            'data': {
                'channel': channel,
                'filters': filters,
                'options': options
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_id': request_id
            }
        })

        # Log the subscription
        log_security_event(
            event_type='websocket_subscription',
            description=f"WebSocket channel subscription: {channel}",
            severity='info',
            user_id=user_id,
            ip_address=connection_data.get('ip_address'),
            details={
                'channel': channel,
                'filters': filters
            }
        )

        # Track message metrics
        ws_message_counter.inc(1, labels={
            'event_type': 'channel.subscribe',
            'channel': channel,
            'direction': 'received'
        })

        # Track latency
        subscription_time = time.time() - start_time
        ws_latency.observe(subscription_time, labels={'event_type': 'channel.subscribe'})

    except Exception as e:
        logger.error(f"Error in WebSocket subscribe handler: {str(e)}", exc_info=True)
        ws_error_counter.inc(1, labels={'error_type': 'subscription_error'})
        emit('error', {
            'type': 'error',
            'data': {
                'code': 'system_error',
                'message': 'Internal server error occurred'
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_id': message.get('request_id')
            }
        })

@socketio.on('channel.unsubscribe', namespace='/ws')
def handle_unsubscribe(message):
    """
    Handle channel unsubscription requests.

    Removes client from the specified channel and updates tracking.
    """
    connection_id = request.sid

    if connection_id not in active_connections:
        emit('error', {
            'type': 'error',
            'data': {
                'code': 'authentication_error',
                'message': 'Not authenticated'
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        })
        return

    try:
        # Get channel from message
        channel = message.get('data', {}).get('channel')
        request_id = message.get('request_id')

        if not channel:
            emit('error', {
                'type': 'error',
                'data': {
                    'code': 'validation_error',
                    'message': 'Channel is required'
                },
                'meta': {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'request_id': request_id
                }
            })
            return

        # Get connection data
        connection_data = active_connections[connection_id]
        user_id = connection_data['user_id']

        # Remove from the channel
        leave_room(channel)

        # Update connection tracking
        if channel in connection_data['channels']:
            connection_data['channels'].remove(channel)
            connection_data['last_activity'] = datetime.now(timezone.utc)

            # Update metrics
            ws_connection_count.dec(1, labels={
                'channel': channel,
                'role': connection_data.get('role', 'unknown')
            })

        # Send confirmation
        emit('channel.unsubscribe.success', {
            'type': 'channel.unsubscribe.success',
            'data': {
                'channel': channel
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_id': request_id
            }
        })

        # Track message metrics
        ws_message_counter.inc(1, labels={
            'event_type': 'channel.unsubscribe',
            'channel': channel,
            'direction': 'received'
        })

    except Exception as e:
        logger.error(f"Error in WebSocket unsubscribe handler: {str(e)}", exc_info=True)
        ws_error_counter.inc(1, labels={'error_type': 'unsubscription_error'})
        emit('error', {
            'type': 'error',
            'data': {
                'code': 'system_error',
                'message': 'Internal server error occurred'
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_id': message.get('request_id')
            }
        })

@socketio.on('auth.refresh', namespace='/ws')
def handle_token_refresh(message):
    """
    Handle authentication token refresh requests.

    Validates the current token and issues a new one if valid.
    """
    connection_id = request.sid

    if connection_id not in active_connections:
        emit('error', {
            'type': 'error',
            'data': {
                'code': 'authentication_error',
                'message': 'Not authenticated'
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        })
        return

    try:
        # Get connection data
        connection_data = active_connections[connection_id]
        user_id = connection_data['user_id']

        # Refresh the token
        refresh_result = refresh_token(user_id)

        if refresh_result['success']:
            # Send the new token
            emit('auth.refresh.success', {
                'type': 'auth.refresh.success',
                'data': {
                    'token': refresh_result['token'],
                    'expires_at': refresh_result['expires_at'].isoformat()
                },
                'meta': {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'request_id': message.get('request_id')
                }
            })

            # Update last activity
            connection_data['last_activity'] = datetime.now(timezone.utc)

            # Track message metrics
            ws_message_counter.inc(1, labels={
                'event_type': 'auth.refresh',
                'channel': 'control',
                'direction': 'received'
            })
        else:
            # Token refresh failed
            emit('error', {
                'type': 'error',
                'data': {
                    'code': 'authentication_error',
                    'message': refresh_result['message']
                },
                'meta': {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'request_id': message.get('request_id')
                }
            })

            # Log the failure
            log_security_event(
                event_type='websocket_token_refresh_failed',
                description=f"WebSocket token refresh failed: {refresh_result['message']}",
                severity='medium',
                user_id=user_id,
                ip_address=connection_data.get('ip_address')
            )

            ws_error_counter.inc(1, labels={'error_type': 'token_refresh_error'})

    except Exception as e:
        logger.error(f"Error in WebSocket token refresh handler: {str(e)}", exc_info=True)
        ws_error_counter.inc(1, labels={'error_type': 'token_refresh_error'})
        emit('error', {
            'type': 'error',
            'data': {
                'code': 'system_error',
                'message': 'Internal server error occurred'
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_id': message.get('request_id')
            }
        })

@socketio.on('ping', namespace='/ws')
def handle_ping(message):
    """
    Handle ping messages from clients to maintain connection.

    Updates the last activity timestamp and responds with a pong message.
    """
    connection_id = request.sid

    if connection_id in active_connections:
        # Update last activity
        active_connections[connection_id]['last_activity'] = datetime.now(timezone.utc)
        client_timestamp = message.get('data', {}).get('timestamp')

        # Send pong response
        emit('pong', {
            'type': 'pong',
            'data': {
                'server_time': datetime.now(timezone.utc).isoformat(),
                'client_time': client_timestamp,
                'latency_ms': None  # Client can calculate this
            }
        })

        # Track message metrics
        ws_message_counter.inc(1, labels={
            'event_type': 'ping',
            'channel': 'control',
            'direction': 'received'
        })

@socketio.on('message', namespace='/ws')
def handle_message(message):
    """
    Handle generic messages sent via the WebSocket.

    Validates message structure and routes to appropriate handlers.
    """
    connection_id = request.sid

    if connection_id not in active_connections:
        emit('error', {
            'type': 'error',
            'data': {
                'code': 'authentication_error',
                'message': 'Not authenticated'
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        })
        return

    try:
        # Apply rate limiting
        user_id = active_connections[connection_id]['user_id']
        if not message_limiter.check_rate(user_id):
            emit('error', {
                'type': 'error',
                'data': {
                    'code': 'rate_limit_exceeded',
                    'message': 'Message rate limit exceeded'
                },
                'meta': {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'request_id': message.get('request_id')
                }
            })
            ws_error_counter.inc(1, labels={'error_type': 'rate_limit_exceeded'})
            return

        # Validate basic message structure
        validation_result = validate_message(message, MessageSchema)
        if not validation_result['valid']:
            emit('error', {
                'type': 'error',
                'data': {
                    'code': 'validation_error',
                    'message': 'Invalid message format',
                    'details': validation_result['errors']
                },
                'meta': {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'request_id': message.get('request_id')
                }
            })
            return

        # Update last activity
        connection_data = active_connections[connection_id]
        connection_data['last_activity'] = datetime.now(timezone.utc)

        # Extract message type and route accordingly
        event_type = message.get('type')

        # Route to appropriate handler based on event type
        if event_type == 'channel.subscribe':
            handle_subscribe(message)
        elif event_type == 'channel.unsubscribe':
            handle_unsubscribe(message)
        elif event_type == 'auth.refresh':
            handle_token_refresh(message)
        elif event_type == 'ping':
            handle_ping(message)
        elif event_type.startswith('custom.'):
            # Custom message handling through event dispatcher
            dispatch_result = dispatch_event(event_type, message, active_connections[connection_id])

            if not dispatch_result['success']:
                emit('error', {
                    'type': 'error',
                    'data': {
                        'code': 'event_error',
                        'message': dispatch_result['message']
                    },
                    'meta': {
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'request_id': message.get('request_id')
                    }
                })
        else:
            # Unknown message type
            emit('error', {
                'type': 'error',
                'data': {
                    'code': 'unknown_message_type',
                    'message': f"Unknown message type: {event_type}"
                },
                'meta': {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'request_id': message.get('request_id')
                }
            })

            # Track unknown message type
            ws_error_counter.inc(1, labels={'error_type': 'unknown_message_type'})

    except Exception as e:
        logger.error(f"Error in WebSocket message handler: {str(e)}", exc_info=True)
        ws_error_counter.inc(1, labels={'error_type': 'message_error'})
        emit('error', {
            'type': 'error',
            'data': {
                'code': 'system_error',
                'message': 'Internal server error occurred'
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_id': message.get('request_id')
            }
        })

def broadcast_to_channel(channel: str, event_type: str, data: Dict[str, Any], exclude_sid: Optional[str] = None) -> int:
    """
    Broadcast an event to all clients subscribed to a channel.

    Args:
        channel: The channel to broadcast to
        event_type: The type of event to broadcast
        data: The event data
        exclude_sid: Optional connection ID to exclude from the broadcast

    Returns:
        int: Number of clients the message was sent to
    """
    try:
        message = {
            'type': event_type,
            'data': data,
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'channel': channel
            }
        }

        socketio.emit(event_type, message, room=channel, namespace='/ws', skip_sid=exclude_sid)

        # Track message metrics
        ws_message_counter.inc(1, labels={
            'event_type': event_type,
            'channel': channel,
            'direction': 'sent'
        })

        # Determine number of recipients (connections subscribed to this channel)
        recipients = sum(1 for conn in active_connections.values() if channel in conn.get('channels', []))

        return recipients

    except Exception as e:
        logger.error(f"Error broadcasting to channel {channel}: {str(e)}", exc_info=True)
        ws_error_counter.inc(1, labels={'error_type': 'broadcast_error'})
        return 0

def get_connection_status() -> Dict[str, Any]:
    """
    Get current WebSocket connection statistics.

    Returns:
        Dict containing connection statistics
    """
    now = datetime.now(timezone.utc)
    stats = {
        'total_connections': len(active_connections),
        'active_channels': {},
        'connections_by_role': {},
        'timestamp': now.isoformat()
    }

    # Count channels
    channel_counts = {}
    for connection in active_connections.values():
        for channel in connection.get('channels', []):
            channel_counts[channel] = channel_counts.get(channel, 0) + 1

    stats['active_channels'] = channel_counts

    # Count by role
    role_counts = {}
    for connection in active_connections.values():
        role = connection.get('role', 'unknown')
        role_counts[role] = role_counts.get(role, 0) + 1

    stats['connections_by_role'] = role_counts

    return stats

def clean_inactive_connections() -> int:
    """
    Clean up inactive connections that haven't sent messages recently.

    Returns:
        int: Number of connections cleaned up
    """
    now = datetime.now(timezone.utc)
    timeout = current_app.config.get('WEBSOCKET_IDLE_TIMEOUT', 300)  # Default 5 minutes

    expired_connections = []
    for connection_id, data in active_connections.items():
        last_activity = data.get('last_activity', data.get('connected_at'))
        if (now - last_activity).total_seconds() > timeout:
            expired_connections.append(connection_id)

    # Disconnect expired connections
    for connection_id in expired_connections:
        try:
            socketio.disconnect(connection_id, namespace='/ws')
        except Exception as e:
            logger.warning(f"Error disconnecting inactive connection {connection_id}: {str(e)}")

    return len(expired_connections)

def init_app(socketio_instance):
    """
    Initialize the WebSocket routes with the SocketIO instance.

    Args:
        socketio_instance: The Flask-SocketIO instance to register handlers with
    """
    # Initialize event handlers
    from .events import register_event_handlers
    register_event_handlers()

    # Set up periodic tasks
    @socketio_instance.on_namespace('/ws')
    def setup_periodic_tasks():
        # Set up task to clean inactive connections
        if not hasattr(current_app, 'websocket_cleanup_task'):
            def cleanup_task():
                try:
                    cleaned = clean_inactive_connections()
                    if cleaned > 0:
                        logger.info(f"Cleaned {cleaned} inactive WebSocket connections")
                except Exception as e:
                    logger.error(f"Error in WebSocket cleanup task: {str(e)}", exc_info=True)

            current_app.websocket_cleanup_task = socketio_instance.start_background_task(cleanup_task)

    logger.info("WebSocket routes initialized")
    return True
