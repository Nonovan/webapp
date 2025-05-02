"""
Administrative WebSocket routes for the Cloud Infrastructure Platform.

This module implements WebSocket endpoints for real-time administrative operations,
including system health monitoring, security event notifications, and interactive
administrative commands. All connections enforce strict authentication and
authorization with comprehensive audit logging.

Key features:
- Channel-based subscription model for targeted data streams
- Real-time system metrics and status updates
- Live audit log and security event monitoring
- Administrative command processing with approval workflow
- Comprehensive security and permission enforcement
"""

import json
import logging
import time
import psutil
import os
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Dict, Any, Optional, List, Union, Callable, Tuple

from flask import Blueprint, current_app, g, request, session
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect, ConnectionRefusedError

from extensions import socketio, db, metrics
from core.security import log_security_event, require_permission
from core.security.cs_general_sec import CircuitBreaker, RateLimiter
from models.security.audit_log import AuditLog
from models.auth.user import User
from models.auth.user_session import UserSession

from .auth import (
    authenticate_connection,
    validate_admin_access,
    verify_channel_permission,
    require_approval_for_command
)
from .schemas import (
    validate_message,
    SubscriptionSchema,
    CommandSchema,
    MessageSchema
)

# Initialize logger
logger = logging.getLogger(__name__)

# Configure admin WebSocket metrics
ws_connection_count = metrics.gauge(
    'admin_ws_connections_active',
    'Current number of active admin WebSocket connections',
    labels=['channel', 'role']
)

ws_message_counter = metrics.counter(
    'admin_ws_messages_total',
    'Total admin WebSocket messages',
    labels=['event_type', 'channel', 'direction']
)

ws_command_counter = metrics.counter(
    'admin_ws_commands_total',
    'Total admin commands executed via WebSocket',
    labels=['command', 'status']
)

ws_error_counter = metrics.counter(
    'admin_ws_errors_total',
    'Total admin WebSocket errors',
    labels=['error_type']
)

ws_latency = metrics.histogram(
    'admin_ws_message_latency_seconds',
    'Admin WebSocket message processing latency in seconds',
    labels=['event_type'],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
)

# Metrics retention configuration with sensible defaults
METRICS_RETENTION = {
    'high_frequency': 86400,     # 1 day for high-frequency metrics
    'medium_frequency': 604800,  # 1 week for medium-frequency metrics
    'low_frequency': 2592000     # 30 days for low-frequency metrics
}

# Circuit breaker instances for external services
session_circuit = CircuitBreaker(name="user_sessions", failure_threshold=3,
                                reset_timeout=300, half_open_after=60)
config_circuit = CircuitBreaker(name="config", failure_threshold=3,
                              reset_timeout=300, half_open_after=60)
integrity_circuit = CircuitBreaker(name="file_integrity", failure_threshold=3,
                                 reset_timeout=300, half_open_after=60)

# Channel definitions with required permissions
ADMIN_CHANNELS = {
    'admin:system': 'admin:system:view',
    'admin:audit': 'audit:logs:view',
    'admin:security': 'security:events:view',
    'admin:users': 'admin:users:view',
    'admin:maintenance': 'admin:system:maintenance',
    'admin:metrics': 'admin:metrics:view',
    'admin:interactive': 'admin:system:command',
    'admin:config': 'admin:config:view',
    'admin:file_integrity': 'security:integrity:view'
}

# Maximum number of concurrent connections per user
MAX_CONNECTIONS_PER_USER = 5

# Active connections tracking
active_connections = {}

@socketio.on('connect', namespace='/admin')
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
                event_type='admin_websocket_auth_failure',
                description=f"Admin WebSocket authentication failure: {auth_result['message']}",
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
                event_type='admin_websocket_connection_limit',
                description=f"Admin WebSocket connection limit exceeded for user: {user.username}",
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
            event_type='admin_websocket_connected',
            description=f"Admin WebSocket connection established for user: {user.username}",
            severity='info',
            user_id=user.id,
            ip_address=request.remote_addr,
        )

        # Send welcome message with system information
        emit('system_info', {
            'event_type': 'connection.established',
            'data': {
                'connection_id': connection_id,
                'server_time': datetime.now(timezone.utc).isoformat(),
                'user': user.username,
                'role': user.role,
                'version': current_app.config.get('VERSION', 'unknown'),
                'environment': current_app.config.get('ENVIRONMENT', 'production'),
                'session_expires_at': (datetime.now(timezone.utc) +
                                       timedelta(minutes=current_app.config.get('ADMIN_WS_SESSION_MINUTES', 15))).isoformat()
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        })

        # Log performance metric
        connection_time = time.time() - start_time
        logger.debug(f"Admin WebSocket connection established in {connection_time:.4f}s")

    except ConnectionRefusedError as e:
        # Let the exception propagate to reject the connection
        logger.warning(f"Admin WebSocket connection rejected: {str(e)}")
        raise

    except Exception as e:
        # Handle unexpected errors
        logger.error(f"Error in admin WebSocket connection handler: {str(e)}", exc_info=True)
        ws_error_counter.inc(1, labels={'error_type': 'connection_error'})
        raise ConnectionRefusedError("Internal server error occurred")

@socketio.on('disconnect', namespace='/admin')
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
                event_type='admin_websocket_disconnected',
                description=f"Admin WebSocket connection closed for user: {connection_data.get('username', 'unknown')}",
                severity='info',
                user_id=user_id,
                ip_address=connection_data.get('ip_address'),
            )

        # Remove from tracking
        del active_connections[connection_id]

@socketio.on('subscribe', namespace='/admin')
def handle_subscribe(message):
    """
    Handle channel subscription requests.

    Validates permissions for the requested channel and manages subscription tracking.
    """
    start_time = time.time()
    connection_id = request.sid

    if connection_id not in active_connections:
        emit('error', {
            'event_type': 'error',
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
                'event_type': 'error',
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
        channel = message.get('channel')
        filters = message.get('data', {}).get('filters', {})
        options = message.get('data', {}).get('options', {})
        request_id = message.get('request_id')

        # Check if this is a valid channel
        if channel not in ADMIN_CHANNELS:
            emit('error', {
                'event_type': 'error',
                'data': {
                    'code': 'channel_error',
                    'message': f"Channel not found: {channel}"
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
        required_permission = ADMIN_CHANNELS[channel]

        if not verify_channel_permission(user_id, required_permission):
            emit('error', {
                'event_type': 'error',
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
                event_type='admin_websocket_permission_denied',
                description=f"WebSocket channel access denied: {channel}",
                severity='medium',
                user_id=user_id,
                ip_address=connection_data.get('ip_address'),
                details={
                    'channel': channel,
                    'required_permission': required_permission
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
        emit('subscription_confirmation', {
            'event_type': 'subscription.confirmed',
            'channel': channel,
            'data': {
                'status': 'subscribed',
                'filters': filters,
                'options': options,
                'subscription_id': f"{connection_id}_{channel}"
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_id': request_id
            }
        })

        # Log the subscription
        log_security_event(
            event_type='admin_websocket_subscription',
            description=f"Admin WebSocket channel subscription: {channel}",
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
            'event_type': 'subscribe',
            'channel': channel,
            'direction': 'received'
        })

        # Track latency
        subscription_time = time.time() - start_time
        ws_latency.observe(subscription_time, labels={'event_type': 'subscribe'})

    except Exception as e:
        logger.error(f"Error in admin WebSocket subscribe handler: {str(e)}", exc_info=True)
        ws_error_counter.inc(1, labels={'error_type': 'subscription_error'})
        emit('error', {
            'event_type': 'error',
            'data': {
                'code': 'system_error',
                'message': 'Internal server error occurred'
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_id': message.get('request_id')
            }
        })

@socketio.on('unsubscribe', namespace='/admin')
def handle_unsubscribe(message):
    """
    Handle channel unsubscription requests.

    Removes the client from the specified channel and updates tracking.
    """
    connection_id = request.sid

    if connection_id not in active_connections:
        emit('error', {
            'event_type': 'error',
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
        channel = message.get('channel')
        request_id = message.get('request_id')
        connection_data = active_connections[connection_id]

        # Validate channel
        if not channel:
            emit('error', {
                'event_type': 'error',
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
        emit('unsubscription_confirmation', {
            'event_type': 'unsubscription.confirmed',
            'channel': channel,
            'data': {
                'status': 'unsubscribed'
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_id': request_id
            }
        })

        # Track message metrics
        ws_message_counter.inc(1, labels={
            'event_type': 'unsubscribe',
            'channel': channel,
            'direction': 'received'
        })

    except Exception as e:
        logger.error(f"Error in admin WebSocket unsubscribe handler: {str(e)}", exc_info=True)
        ws_error_counter.inc(1, labels={'error_type': 'unsubscription_error'})
        emit('error', {
            'event_type': 'error',
            'data': {
                'code': 'system_error',
                'message': 'Internal server error occurred'
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_id': message.get('request_id')
            }
        })

@socketio.on('command', namespace='/admin')
def handle_command(message):
    """
    Handle administrative command execution.

    Validates the command, checks permissions, and enforces approval workflow for sensitive operations.
    """
    start_time = time.time()
    connection_id = request.sid

    if connection_id not in active_connections:
        emit('error', {
            'event_type': 'error',
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
        validation_result = validate_message(message, CommandSchema)
        if not validation_result['valid']:
            emit('error', {
                'event_type': 'error',
                'data': {
                    'code': 'validation_error',
                    'message': 'Invalid command format',
                    'details': validation_result['errors']
                },
                'meta': {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'request_id': message.get('request_id')
                }
            })
            ws_error_counter.inc(1, labels={'error_type': 'validation_error'})
            return

        # Extract command data
        operation = message.get('data', {}).get('operation')
        parameters = message.get('data', {}).get('parameters', {})
        justification = message.get('data', {}).get('justification')
        ticket_id = message.get('data', {}).get('ticket_id')
        request_id = message.get('request_id')

        # Get connection data
        connection_data = active_connections[connection_id]
        user_id = connection_data['user_id']
        username = connection_data['username']
        role = connection_data['role']

        # Check if this is a high-risk command requiring approval
        approval_result = require_approval_for_command(
            operation=operation,
            user_id=user_id,
            role=role
        )

        if approval_result['requires_approval'] and not approval_result['is_approved']:
            # Request is pending approval - notify and exit
            emit('command_response', {
                'event_type': 'command.pending_approval',
                'data': {
                    'operation': operation,
                    'status': 'pending_approval',
                    'approval_id': approval_result['approval_id'],
                    'expires_at': approval_result['expires_at'].isoformat() if approval_result['expires_at'] else None,
                    'message': 'Command requires approval from a security administrator'
                },
                'meta': {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'request_id': request_id
                }
            })

            # Log the approval request
            log_security_event(
                event_type='admin_command_approval_requested',
                description=f"Admin command requires approval: {operation}",
                severity='medium',
                user_id=user_id,
                ip_address=connection_data.get('ip_address'),
                details={
                    'operation': operation,
                    'approval_id': approval_result['approval_id'],
                    'justification': justification,
                    'ticket_id': ticket_id
                }
            )

            ws_command_counter.inc(1, labels={
                'command': operation,
                'status': 'pending_approval'
            })

            return

        # Execute the command
        execution_result = execute_admin_command(
            operation=operation,
            parameters=parameters,
            user_id=user_id,
            connection_data=connection_data
        )

        # Send the response
        emit('command_response', {
            'event_type': 'command.response',
            'data': {
                'operation': operation,
                'status': execution_result['status'],
                'result': execution_result['result'],
                'execution_time': execution_result['execution_time']
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_id': request_id
            }
        })

        # Log the command execution
        log_security_event(
            event_type='admin_command_executed',
            description=f"Admin command executed: {operation}",
            severity='medium',
            user_id=user_id,
            ip_address=connection_data.get('ip_address'),
            details={
                'operation': operation,
                'status': execution_result['status'],
                'execution_time': execution_result['execution_time'],
                'justification': justification,
                'ticket_id': ticket_id
            }
        )

        # Update metrics
        ws_command_counter.inc(1, labels={
            'command': operation,
            'status': execution_result['status']
        })

        # Track message metrics
        ws_message_counter.inc(1, labels={
            'event_type': 'command',
            'channel': 'admin:interactive',
            'direction': 'received'
        })

        # Track latency
        command_time = time.time() - start_time
        ws_latency.observe(command_time, labels={'event_type': 'command'})

    except Exception as e:
        logger.error(f"Error in admin WebSocket command handler: {str(e)}", exc_info=True)
        ws_error_counter.inc(1, labels={'error_type': 'command_error'})
        emit('error', {
            'event_type': 'error',
            'data': {
                'code': 'system_error',
                'message': 'Internal server error occurred during command execution'
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_id': message.get('request_id')
            }
        })

@socketio.on('ping', namespace='/admin')
def handle_ping(message):
    """
    Handle ping messages from clients to maintain connection.

    Updates the last activity timestamp and responds with a pong message.
    """
    connection_id = request.sid

    if connection_id in active_connections:
        # Update last activity
        active_connections[connection_id]['last_activity'] = datetime.now(timezone.utc)
        client_timestamp = message.get('timestamp', None)

        # Send pong response
        emit('pong', {
            'event_type': 'pong',
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

@socketio.on('message', namespace='/admin')
def handle_message(message):
    """
    Handle generic messages sent via the WebSocket.

    Validates message structure and routes to appropriate handlers.
    """
    connection_id = request.sid

    if connection_id not in active_connections:
        emit('error', {
            'event_type': 'error',
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
        # Validate basic message structure
        validation_result = validate_message(message, MessageSchema)
        if not validation_result['valid']:
            emit('error', {
                'event_type': 'error',
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
        event_type = message.get('event_type')

        if event_type == 'subscribe':
            handle_subscribe(message)
        elif event_type == 'unsubscribe':
            handle_unsubscribe(message)
        elif event_type == 'command':
            handle_command(message)
        elif event_type == 'ping':
            handle_ping(message)
        else:
            # Unknown message type
            emit('error', {
                'event_type': 'error',
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
        logger.error(f"Error in admin WebSocket message handler: {str(e)}", exc_info=True)
        ws_error_counter.inc(1, labels={'error_type': 'message_error'})
        emit('error', {
            'event_type': 'error',
            'data': {
                'code': 'system_error',
                'message': 'Internal server error occurred'
            },
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_id': message.get('request_id')
            }
        })

def broadcast_system_health(health_data):
    """
    Broadcast system health updates to all clients subscribed to the system channel.

    Args:
        health_data: Dictionary containing system health metrics
    """
    try:
        socketio.emit('system_health', {
            'event_type': 'system.health.update',
            'channel': 'admin:system',
            'data': health_data,
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        }, namespace='/admin', room='admin:system')

        # Track message metrics
        ws_message_counter.inc(1, labels={
            'event_type': 'system.health.update',
            'channel': 'admin:system',
            'direction': 'sent'
        })

    except Exception as e:
        logger.error(f"Error broadcasting system health: {str(e)}", exc_info=True)
        ws_error_counter.inc(1, labels={'error_type': 'broadcast_error'})

def broadcast_security_event(event_data):
    """
    Broadcast security events to all clients subscribed to the security channel.

    Args:
        event_data: Dictionary containing security event details
    """
    try:
        socketio.emit('security_event', {
            'event_type': 'security.event',
            'channel': 'admin:security',
            'data': event_data,
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        }, namespace='/admin', room='admin:security')

        # Track message metrics
        ws_message_counter.inc(1, labels={
            'event_type': 'security.event',
            'channel': 'admin:security',
            'direction': 'sent'
        })

    except Exception as e:
        logger.error(f"Error broadcasting security event: {str(e)}", exc_info=True)
        ws_error_counter.inc(1, labels={'error_type': 'broadcast_error'})

def broadcast_audit_log(log_entry):
    """
    Broadcast audit log entries to all clients subscribed to the audit channel.

    Args:
        log_entry: Dictionary containing audit log data
    """
    try:
        socketio.emit('audit_log', {
            'event_type': 'audit.log.entry',
            'channel': 'admin:audit',
            'data': log_entry,
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        }, namespace='/admin', room='admin:audit')

        # Track message metrics
        ws_message_counter.inc(1, labels={
            'event_type': 'audit.log.entry',
            'channel': 'admin:audit',
            'direction': 'sent'
        })

    except Exception as e:
        logger.error(f"Error broadcasting audit log: {str(e)}", exc_info=True)
        ws_error_counter.inc(1, labels={'error_type': 'broadcast_error'})

def execute_admin_command(operation: str, parameters: Dict[str, Any],
                         user_id: int, connection_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute an administrative command.

    Args:
        operation: The operation to perform
        parameters: Parameters for the operation
        user_id: ID of the user executing the command
        connection_data: Data about the connection

    Returns:
        Dict containing execution results
    """
    start_time = time.time()
    result = {}
    status = 'failed'

    try:
        # Execute the command based on operation type
        if operation == 'system.status':
            # Get system status information
            result = {
                'system_status': 'healthy',
                'uptime': get_system_uptime(),
                'load': get_system_load(),
                'memory_usage': get_memory_usage(),
                'disk_usage': get_disk_usage(),
                'active_sessions': get_active_session_count(),
                'pending_tasks': get_pending_task_count()
            }
            status = 'success'

        elif operation == 'cache.clear':
            # Clear application cache
            cache_name = parameters.get('cache_name', 'default')
            if cache_name == 'all':
                result = {'cleared_caches': clear_all_caches()}
            else:
                result = {'cleared': clear_specific_cache(cache_name)}
            status = 'success'

        elif operation == 'config.get':
            # Get configuration values
            config_key = parameters.get('key')
            if config_key:
                result = {'config': get_config_value(config_key, user_id)}
            else:
                result = {'error': 'Missing configuration key'}
                status = 'failed'

        elif operation == 'file_integrity.check':
            # Run file integrity check
            result = perform_file_integrity_check(parameters.get('paths'))
            status = 'success'

        elif operation == 'maintenance.status':
            # Get maintenance status
            result = get_maintenance_status()

            def get_maintenance_status() -> Dict[str, Any]:
                """
                Retrieve the current maintenance status of the system.

                Returns:
                    A dictionary containing maintenance status details.
                """
                try:
                    # Example implementation, replace with actual logic
                    return {
                        'status': 'active',  # or 'inactive'
                        'scheduled_start': datetime.now(timezone.utc).isoformat(),
                        'scheduled_end': (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
                        'message': 'System maintenance is currently active.'
                    }
                except Exception as e:
                    logger.error(f"Error retrieving maintenance status: {str(e)}", exc_info=True)
                    return {'error': 'Unable to retrieve maintenance status'}
            status = 'success'

        elif operation == 'user.sessions':
            # Get active user sessions
            username = parameters.get('username')
            limit = parameters.get('limit', 100)
            result = get_user_sessions(username, limit)
            status = 'success'

        else:
            result = {'error': f"Unknown operation: {operation}"}
            status = 'failed'

    except Exception as e:
        logger.error(f"Error executing admin command '{operation}': {str(e)}", exc_info=True)
        result = {'error': f"Command execution failed: {str(e)}"}
        status = 'error'

    # Calculate execution time
    execution_time = time.time() - start_time

    return {
        'status': status,
        'result': result,
        'execution_time': round(execution_time, 3)
    }

# Helper functions for command execution
def get_system_uptime() -> str:
    """Get system uptime as a formatted string."""
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])

        days, remainder = divmod(uptime_seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)

        return f"{int(days)}d {int(hours)}h {int(minutes)}m {int(seconds)}s"
    except Exception as e:
        logger.warning(f"Error getting system uptime: {str(e)}")
        return "Unknown"

def get_system_load() -> List[float]:
    """Get system load averages."""
    try:
        import os
        return [round(x, 2) for x in os.getloadavg()]
    except Exception as e:
        logger.warning(f"Error getting system load: {str(e)}")
        return [-1, -1, -1]  # Error indicator

def get_memory_usage() -> Dict[str, Any]:
    """Get memory usage information."""
    try:
        memory = psutil.virtual_memory()
        return {
            'total_mb': round(memory.total / (1024 * 1024), 1),
            'used_mb': round(memory.used / (1024 * 1024), 1),
            'percent': memory.percent
        }
    except Exception as e:
        logger.warning(f"Error getting memory usage: {str(e)}")
        return {'error': 'Unable to retrieve memory information'}

def get_disk_usage() -> Dict[str, Any]:
    """Get disk usage information."""
    try:
        disk = psutil.disk_usage('/')
        return {
            'total_gb': round(disk.total / (1024 * 1024 * 1024), 1),
            'used_gb': round(disk.used / (1024 * 1024 * 1024), 1),
            'percent': disk.percent
        }
    except Exception as e:
        logger.warning(f"Error getting disk usage: {str(e)}")
        return {'error': 'Unable to retrieve disk information'}

def get_active_session_count() -> int:
    """Get count of active user sessions."""
    try:
        return UserSession.query.filter_by(is_active=True).count()
    except Exception as e:
        logger.warning(f"Error getting active session count: {str(e)}")
        return -1  # Error indicator

def get_pending_task_count() -> int:
    """Get count of pending background tasks."""
    try:
        # This would need to be implemented based on your task queue
        # Assuming a function exists to check the queue
        from services.tasks import get_pending_count
        return get_pending_count()
    except Exception as e:
        logger.warning(f"Error getting pending task count: {str(e)}")
        return -1  # Error indicator

def clear_all_caches() -> List[str]:
    """Clear all application caches."""
    caches_cleared = []
    try:
        # Main application cache
        from extensions import cache
        cache.clear()
        caches_cleared.append("application")

        # Any additional caches would be cleared here

        return caches_cleared
    except Exception as e:
        logger.error(f"Error clearing all caches: {str(e)}", exc_info=True)
        raise

def clear_specific_cache(cache_name: str) -> bool:
    """Clear a specific application cache."""
    try:
        if cache_name == "application":
            from extensions import cache
            cache.clear()
            return True
        else:
            # Additional cache types would be handled here
            logger.warning(f"Unknown cache name: {cache_name}")
            return False
    except Exception as e:
        logger.error(f"Error clearing cache {cache_name}: {str(e)}", exc_info=True)
        raise

@config_circuit
def get_config_value(key: str, user_id: int) -> Any:
    """Get a configuration value with circuit breaker protection."""
    try:
        from models.security import SystemConfig

        # Check if user has permission to read this config key
        # This would be implemented based on your permission system

        config = SystemConfig.query.filter_by(key=key).first()
        if config:
            # Record successful call for circuit breaker
            config_circuit.record_success()
            return {
                'key': config.key,
                'value': config.value,
                'description': config.description,
                'last_updated': config.updated_at.isoformat() if hasattr(config, 'updated_at') else None
            }
        else:
            return {'error': f"Configuration key not found: {key}"}

    except Exception as e:
        logger.error(f"Error retrieving config value: {str(e)}", exc_info=True)
        config_circuit.record_failure()
        raise

@integrity_circuit
def perform_file_integrity_check(paths=None) -> Dict[str, Any]:
    """Run file integrity check with circuit breaker protection."""
    try:
        from core.security import check_file_integrity

        result = check_file_integrity(paths=paths, full_details=True)
        integrity_circuit.record_success()
        return result

    except Exception as e:
        logger.error(f"Error performing file integrity check: {str(e)}", exc_info=True)
        integrity_circuit.record_failure()
        raise

@session_circuit
def get_user_sessions(username=None, limit=100) -> Dict[str, Any]:
    """
    Get active user sessions with detailed information.

    Args:
        username: Optional username to filter sessions
        limit: Maximum number of sessions to return (default: 100)

    Returns:
        Dict containing session count and detailed session information

    Raises:
        SQLAlchemyError: If database query fails
        ValueError: If invalid parameters provided
    """
    try:
        # Parameter validation
        if limit <= 0 or limit > 1000:
            raise ValueError("Limit must be between 1 and 1000")

        # Build the base query
        query = UserSession.query.filter_by(is_active=True)

        # Apply username filter if provided
        if username:
            user = User.query.filter_by(username=username).first()
            if user:
                query = query.filter_by(user_id=user.id)
            else:
                # Return empty result if username doesn't exist
                return {
                    'count': 0,
                    'sessions': [],
                    'message': f"No user found with username: {username}"
                }

        # Get the sessions with proper ordering
        sessions = query.order_by(UserSession.last_active.desc()).limit(limit).all()

        # Format session data with comprehensive details
        session_data = []
        for session in sessions:
            # Get user details with fallback for integrity
            user = User.query.get(session.user_id) if hasattr(session, 'user_id') else None

            # Build detailed session information
            session_info = {
                'id': session.id,
                'user_id': session.user_id,
                'username': user.username if user else 'unknown',
                'session_id': session.session_id,
                'ip_address': session.ip_address,
                'user_agent': session.user_agent,
                'created_at': session.created_at.isoformat() if hasattr(session, 'created_at') else None,
                'last_active': session.last_active.isoformat() if hasattr(session, 'last_active') else None,
                'expires_at': session.expires_at.isoformat() if hasattr(session, 'expires_at') else None,
                'is_suspicious': session.is_suspicious if hasattr(session, 'is_suspicious') else False,
                'client_type': session.client_type if hasattr(session, 'client_type') else 'unknown',
                'access_level': session.access_level if hasattr(session, 'access_level') else 'standard'
            }

            # Include geographic location if available
            if hasattr(session, 'last_location') and session.last_location:
                session_info['location'] = session.last_location

            session_data.append(session_info)

        # Return well-structured response
        return {
            'count': len(sessions),
            'total_active_count': UserSession.get_active_sessions_count(),
            'sessions': session_data
        }

    except ValueError as e:
        # Handle validation errors
        logger.warning(f"Invalid parameters for get_user_sessions: {str(e)}")
        session_circuit.record_failure()
        raise

    except Exception as e:
        # Log detailed error and record circuit breaker failure
        logger.error(f"Error getting user sessions: {str(e)}", exc_info=True)
        session_circuit.record_failure()

        # Re-raise for consistent error handling at higher level
        raise

def configure_metrics_retention():
    """Configure retention policy for WebSocket metrics."""
    try:
        # Apply retention policy to counters
        metrics.configure_retention(ws_message_counter, METRICS_RETENTION['high_frequency'])
        metrics.configure_retention(ws_command_counter, METRICS_RETENTION['medium_frequency'])
        metrics.configure_retention(ws_error_counter, METRICS_RETENTION['medium_frequency'])

        # Apply retention policy to gauges
        metrics.configure_retention(ws_connection_count, METRICS_RETENTION['low_frequency'])

        # Apply retention policy to histograms
        metrics.configure_retention(ws_latency, METRICS_RETENTION['medium_frequency'])

        logger.info("WebSocket metrics retention configured")

    except Exception as e:
        logger.error(f"Failed to configure metrics retention: {str(e)}", exc_info=True)

def init_app(socketio_instance):
    """
    Initialize the WebSocket routes with the SocketIO instance.

    Args:
        socketio_instance: The Flask-SocketIO instance to register handlers with
    """
    # Configure metrics retention
    configure_metrics_retention()

    # Initialize circuit breakers
    session_circuit.initialize()
    config_circuit.initialize()
    integrity_circuit.initialize()

    # Register event handlers with socketio
    # This function would be called from the main application factory
    logger.info("Admin WebSocket routes initialized")

    # Return success status
    return True
