"""
Event handling and dispatch for WebSocket connections.

This module defines the event types and handlers for the WebSocket API,
providing a consistent way to process and dispatch different message types.
It handles event registration, validation, and routing to appropriate
handler functions based on message type.

Key features:
- Event handler registration system
- Message validation and sanitization
- Standard event response formatting
- Permission-based access control for events
- Metrics tracking and performance monitoring
"""

import logging
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Dict, Any, Optional, List, Callable, Tuple, Union

from flask import current_app, g
from flask_socketio import emit

from extensions import metrics
from core.security import log_security_event, require_permission
from .channels import validate_channel
from models.auth.user import User

# Initialize module logger
logger = logging.getLogger(__name__)

# Store registered event handlers
_event_handlers = {}

# Event metrics
event_counter = metrics.counter(
    'websocket_event_handlers_total',
    'WebSocket event handler invocations',
    labels=['event_type', 'status']
)

event_latency = metrics.histogram(
    'websocket_event_processing_seconds',
    'WebSocket event processing time in seconds',
    labels=['event_type'],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
)

# Standard event types
EVENT_TYPE_RESOURCE_UPDATED = "resource.updated"
EVENT_TYPE_RESOURCE_CREATED = "resource.created"
EVENT_TYPE_RESOURCE_DELETED = "resource.deleted"
EVENT_TYPE_RESOURCE_STATE_CHANGED = "resource.state_changed"
EVENT_TYPE_ALERT_TRIGGERED = "alert.triggered"
EVENT_TYPE_ALERT_UPDATED = "alert.updated"
EVENT_TYPE_ALERT_RESOLVED = "alert.resolved"
EVENT_TYPE_NOTIFICATION = "notification"
EVENT_TYPE_METRICS_UPDATE = "metrics.update"
EVENT_TYPE_SYSTEM_STATUS = "system.status"
EVENT_TYPE_SECURITY_EVENT = "security.event"


def register_event_handler(event_type: str, permission: Optional[str] = None):
    """
    Decorator to register an event handler function for a specific event type.

    Args:
        event_type: The event type this handler will process
        permission: Optional permission required to execute this handler

    Returns:
        Decorator function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(message: Dict[str, Any], connection_data: Dict[str, Any]) -> Dict[str, Any]:
            start_time = time.time()
            user_id = connection_data.get('user_id')

            # Check permission if required
            if permission and not _check_permission(user_id, permission):
                event_counter.inc(1, labels={'event_type': event_type, 'status': 'denied'})
                return {
                    'success': False,
                    'message': f"Permission denied: {permission} required"
                }

            try:
                # Call the handler function
                result = func(message, connection_data)
                event_counter.inc(1, labels={'event_type': event_type, 'status': 'success'})

                # Track latency
                processing_time = time.time() - start_time
                event_latency.observe(processing_time, labels={'event_type': event_type})

                return result
            except Exception as e:
                logger.error(f"Error in event handler for {event_type}: {str(e)}", exc_info=True)
                event_counter.inc(1, labels={'event_type': event_type, 'status': 'error'})

                # Log security event for errors in sensitive handlers
                if event_type.startswith(("security.", "admin.", "custom.")):
                    log_security_event(
                        event_type="websocket_event_error",
                        description=f"Error handling WebSocket event: {event_type}",
                        severity='error',
                        user_id=user_id,
                        ip_address=connection_data.get('ip_address'),
                        details={
                            'event_type': event_type,
                            'error': str(e)
                        }
                    )

                return {
                    'success': False,
                    'message': "An error occurred processing the event"
                }

        # Store the handler in the registry
        _event_handlers[event_type] = wrapper
        logger.debug(f"Registered event handler for: {event_type}")
        return wrapper

    return decorator


def dispatch_event(event_type: str, message: Dict[str, Any],
                   connection_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Dispatch an event to its registered handler.

    Args:
        event_type: Type of event to dispatch
        message: Event message data
        connection_data: Connection context data

    Returns:
        Dict containing dispatch result
    """
    # Validate event type format for security
    if not _validate_event_type(event_type):
        return {
            'success': False,
            'message': f"Invalid event type format: {event_type}"
        }

    # Check if we have a handler for this event type
    if event_type not in _event_handlers:
        logger.warning(f"No handler registered for event type: {event_type}")
        return {
            'success': False,
            'message': f"Unsupported event type: {event_type}"
        }

    # Dispatch to the appropriate handler
    handler = _event_handlers[event_type]
    return handler(message, connection_data)


def get_event_types() -> List[Dict[str, Any]]:
    """
    Get list of registered event types with metadata.

    Returns:
        List of event types with descriptions and permission requirements
    """
    event_types = []

    for event_type in _event_handlers.keys():
        # Create event type metadata
        event_info = {
            'event_type': event_type,
            'description': _get_event_description(event_type),
            'category': _get_event_category(event_type),
            'requires_permission': _get_event_permission(event_type)
        }
        event_types.append(event_info)

    # Sort by category and then type for consistency
    return sorted(event_types, key=lambda x: (x['category'], x['event_type']))


def broadcast_event(channel: str, event_type: str, data: Dict[str, Any],
                   source_connection_id: Optional[str] = None) -> int:
    """
    Broadcast an event to a channel.

    Args:
        channel: Channel to broadcast to
        event_type: Type of event being broadcast
        data: Event payload data
        source_connection_id: Connection ID to exclude from broadcast

    Returns:
        Number of recipients
    """
    from .routes import broadcast_to_channel

    # Add standard metadata
    if 'timestamp' not in data:
        data['timestamp'] = datetime.now(timezone.utc).isoformat()

    # Broadcast the event
    recipients = broadcast_to_channel(
        channel=channel,
        event_type=event_type,
        data=data,
        exclude_sid=source_connection_id
    )

    return recipients


def send_direct_event(connection_id: str, event_type: str, data: Dict[str, Any]) -> bool:
    """
    Send an event directly to a specific connection.

    Args:
        connection_id: Connection ID to send to
        event_type: Type of event being sent
        data: Event payload data

    Returns:
        True if successful, False otherwise
    """
    try:
        # Add standard metadata
        if 'timestamp' not in data:
            data['timestamp'] = datetime.now(timezone.utc).isoformat()

        # Format the event message
        message = {
            'type': event_type,
            'data': data,
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        }

        # Send the event to the specific client
        emit(event_type, message, room=connection_id, namespace='/ws')

        # Track metrics
        metrics.counter(
            'websocket_direct_messages_total',
            'Direct WebSocket messages sent',
            labels={'event_type': event_type}
        ).inc()

        return True

    except Exception as e:
        logger.error(f"Error sending direct event: {str(e)}", exc_info=True)
        return False


def broadcast_file_integrity_event(event_data: Dict[str, Any]) -> int:
    """
    Broadcast file integrity events to subscribed clients.

    This function is designed to be registered as a callback for the file integrity
    monitoring system. When file integrity violations or baseline updates are detected,
    this function forwards those events to all clients subscribed to the file_integrity
    channel.

    Args:
        event_data: Dictionary containing file integrity event details

    Returns:
        int: Number of clients the message was sent to
    """
    try:
        # Extract event properties
        event_type = event_data.get('event_type', 'security.file_integrity.violation')
        severity = event_data.get('severity', 'info')

        # Add standard metadata if not present
        if 'timestamp' not in event_data:
            event_data['timestamp'] = datetime.now(timezone.utc).isoformat()

        if 'event_id' not in event_data and 'id' in event_data:
            event_data['event_id'] = event_data['id']
        elif 'event_id' not in event_data:
            event_data['event_id'] = f"fim-{int(time.time())}"

        # Format the event according to WebSocket API standards
        formatted_data = {
            'severity': severity,
            'event_id': event_data.get('event_id'),
            'timestamp': event_data.get('timestamp')
        }

        # Add specific data depending on event type
        if event_type == 'baseline_updated' or event_type == 'security.file_integrity.baseline_updated':
            # For baseline updates
            formatted_data['changes'] = {
                'added': event_data.get('added', 0),
                'updated': event_data.get('updated', 0),
                'removed': event_data.get('removed', 0)
            }

            if 'initiated_by' in event_data:
                formatted_data['initiated_by'] = event_data['initiated_by']

            if 'reason' in event_data:
                formatted_data['reason'] = event_data['reason']

            event_type = 'security.file_integrity.baseline_updated'

        else:
            # For integrity violations
            violations = []

            # Extract violations from event_data
            if 'violations' in event_data:
                violations = event_data['violations']
            elif 'changes' in event_data:
                # Convert changes format to violations format
                for change in event_data.get('changes', []):
                    violation = {
                        'path': change.get('path', ''),
                        'type': change.get('status', 'modified'),
                        'details': {
                            'severity': change.get('severity', 'medium'),
                            'old_hash': change.get('old_hash', ''),
                            'new_hash': change.get('new_hash', '')
                        }
                    }
                    violations.append(violation)

            formatted_data['violations'] = violations
            event_type = 'security.file_integrity.violation'

        # Log the broadcasting of the event
        logger.info(f"Broadcasting file integrity event: {event_type} with {len(formatted_data.get('violations', []))} violations"
                    if 'violations' in formatted_data else
                    f"Broadcasting baseline update with {sum(formatted_data['changes'].values())} changes")

        # Broadcast to the file_integrity channel
        return broadcast_event('file_integrity', event_type, formatted_data)

    except Exception as e:
        logger.error(f"Error broadcasting file integrity event: {str(e)}", exc_info=True)
        metrics.counter(
            'websocket_file_integrity_errors_total',
            'Total WebSocket file integrity broadcast errors'
        ).inc()
        return 0


def register_event_handlers():
    """
    Register all event handlers for the websocket API.

    This function should be called during application initialization.
    """
    logger.info("Registering WebSocket event handlers")

    # Register system event handlers
    _register_system_event_handlers()

    # Register resource event handlers
    _register_resource_event_handlers()

    # Register alert event handlers
    _register_alert_event_handlers()

    # Register file integrity event handlers
    _register_file_integrity_event_handlers()

    # Register custom event handlers
    _register_custom_event_handlers()

    logger.info(f"Registered {len(_event_handlers)} WebSocket event handlers")


# --- Private Helper Functions ---

def _check_permission(user_id: Optional[int], permission: str) -> bool:
    """Check if a user has the required permission."""
    if not user_id or not permission:
        return False

    try:
        from core.security.cs_authorization import verify_permission
        return verify_permission(user_id, permission)
    except Exception as e:
        logger.error(f"Error checking permission: {str(e)}")
        return False


def _validate_event_type(event_type: str) -> bool:
    """Validate event type format for security."""
    if not event_type or not isinstance(event_type, str):
        return False

    # Event types must follow namespace.action pattern except for special system types
    valid_patterns = [
        r'^resource\.[a-z_]+$',
        r'^alert\.[a-z_]+$',
        r'^system\.[a-z_]+$',
        r'^metrics\.[a-z_]+$',
        r'^security\.[a-z_]+$',
        r'^notification$',
        r'^custom\.[a-z_]+$'
    ]

    for pattern in valid_patterns:
        if re.match(pattern, event_type):
            return True

    return False


def _get_event_description(event_type: str) -> str:
    """Get a human-readable description of an event type."""
    descriptions = {
        EVENT_TYPE_RESOURCE_UPDATED: "Resource information updated",
        EVENT_TYPE_RESOURCE_CREATED: "New resource created",
        EVENT_TYPE_RESOURCE_DELETED: "Resource has been deleted",
        EVENT_TYPE_RESOURCE_STATE_CHANGED: "Resource state has changed",
        EVENT_TYPE_ALERT_TRIGGERED: "New alert triggered",
        EVENT_TYPE_ALERT_UPDATED: "Alert information updated",
        EVENT_TYPE_ALERT_RESOLVED: "Alert has been resolved",
        EVENT_TYPE_NOTIFICATION: "User notification",
        EVENT_TYPE_METRICS_UPDATE: "Metrics data update",
        EVENT_TYPE_SYSTEM_STATUS: "System status update",
        EVENT_TYPE_SECURITY_EVENT: "Security-related event"
    }

    # Return description if found, otherwise generate a generic one
    return descriptions.get(event_type, f"Event: {event_type}")


def _get_event_category(event_type: str) -> str:
    """Get the category for an event type."""
    if event_type.startswith('resource.'):
        return 'resources'
    elif event_type.startswith('alert.'):
        return 'alerts'
    elif event_type.startswith('system.'):
        return 'system'
    elif event_type.startswith('metrics.'):
        return 'metrics'
    elif event_type.startswith('security.'):
        return 'security'
    elif event_type.startswith('custom.'):
        return 'custom'
    else:
        return 'other'


def _get_event_permission(event_type: str) -> Optional[str]:
    """Get the permission requirement for an event type."""
    # For custom handlers that have been registered with permissions
    handlers = list(filter(
        lambda h: h[0] == event_type,
        [(k, v.__wrapped__ if hasattr(v, '__wrapped__') else None)
         for k, v in _event_handlers.items()]
    ))

    if handlers:
        handler = handlers[0][1]
        if hasattr(handler, '__permission'):
            return handler.__permission

    # Default permissions based on event type
    if event_type.startswith('resource.'):
        return 'resources:view'
    elif event_type.startswith('alert.'):
        return 'alerts:view'
    elif event_type.startswith('security.'):
        return 'security:view'
    elif event_type.startswith('system.') or event_type.startswith('metrics.'):
        return 'system:view'

    return None


# --- System Event Handler Registration ---

def _register_system_event_handlers():
    """Register handlers for system events."""

    @register_event_handler('system.ping')
    def handle_ping(message: Dict[str, Any], connection_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ping messages to keep connection alive."""
        client_timestamp = message.get('data', {}).get('timestamp')

        # Send pong response
        emit('pong', {
            'type': 'pong',
            'data': {
                'server_time': datetime.now(timezone.utc).isoformat(),
                'client_time': client_timestamp
            }
        })

        return {'success': True}


    @register_event_handler('system.status.request', permission='system:view')
    def handle_status_request(message: Dict[str, Any], connection_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle system status request."""
        # Implement based on your system status check logic
        try:
            # Get basic system status
            status_info = {
                'status': 'healthy',
                'version': current_app.config.get('VERSION', 'unknown'),
                'environment': current_app.config.get('ENVIRONMENT', 'production'),
                'server_time': datetime.now(timezone.utc).isoformat()
            }

            # Send status response
            emit('system.status', {
                'type': 'system.status',
                'data': status_info
            })

            return {'success': True}

        except Exception as e:
            logger.error(f"Error getting system status: {str(e)}", exc_info=True)
            return {'success': False, 'message': "Failed to get system status"}


# --- Resource Event Handler Registration ---

def _register_resource_event_handlers():
    """Register handlers for resource-related events."""

    @register_event_handler('resource.subscribe', permission='resources:view')
    def handle_resource_subscribe(message: Dict[str, Any], connection_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle resource subscription request."""
        resource_id = message.get('data', {}).get('resource_id')
        resource_type = message.get('data', {}).get('resource_type')

        if not resource_id:
            return {'success': False, 'message': "Resource ID is required"}

        # Validate that user has permission to view this resource
        user_id = connection_data.get('user_id')

        # Subscribe to resource channel
        channel = f"resource:{resource_type or 'general'}:{resource_id}"

        # Validate channel format
        channel_validation = validate_channel(channel)
        if not channel_validation['valid']:
            return {'success': False, 'message': channel_validation['message']}

        # This would typically involve channel subscription logic
        from .routes import handle_subscribe

        # Create a subscribe message
        subscribe_message = {
            'type': 'channel.subscribe',
            'data': {
                'channel': channel
            },
            'request_id': message.get('request_id')
        }

        # Use the existing channel subscription logic
        handle_subscribe(subscribe_message)

        return {'success': True}


# --- Alert Event Handler Registration ---

def _register_alert_event_handlers():
    """Register handlers for alert-related events."""

    @register_event_handler('alert.subscribe', permission='alerts:view')
    def handle_alert_subscribe(message: Dict[str, Any], connection_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle alert subscription request."""
        alert_category = message.get('data', {}).get('category')

        # Subscribe to alert channel
        channel = f"alerts:{alert_category or 'all'}"

        # Validate channel format
        channel_validation = validate_channel(channel)
        if not channel_validation['valid']:
            return {'success': False, 'message': channel_validation['message']}

        # Create a subscribe message
        subscribe_message = {
            'type': 'channel.subscribe',
            'data': {
                'channel': channel
            },
            'request_id': message.get('request_id')
        }

        # Use the existing channel subscription logic
        from .routes import handle_subscribe
        handle_subscribe(subscribe_message)

        return {'success': True}


# --- File Integrity Event Handler Registration ---

def _register_file_integrity_event_handlers():
    """Register handlers for file integrity related events."""

    @register_event_handler('security.file_integrity.request', permission='security:integrity:read')
    def handle_file_integrity_request(message: Dict[str, Any], connection_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle request for current file integrity status."""
        try:
            # Check if the file_integrity module is available
            from core.security.cs_file_integrity import get_last_integrity_status

            # Get the current integrity status
            integrity_status = get_last_integrity_status()

            if not integrity_status:
                integrity_status = {
                    'status': 'unknown',
                    'last_check': datetime.now(timezone.utc).isoformat(),
                    'violations': []
                }

            # Send response with current status
            emit('security.file_integrity.status', {
                'type': 'security.file_integrity.status',
                'data': integrity_status,
                'meta': {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'request_id': message.get('request_id')
                }
            })

            return {'success': True}

        except ImportError:
            logger.warning("File integrity module not available")
            return {'success': False, 'message': "File integrity monitoring not available"}
        except Exception as e:
            logger.error(f"Error handling file integrity request: {str(e)}", exc_info=True)
            return {'success': False, 'message': "Failed to get file integrity status"}


    @register_event_handler('security.file_integrity.subscribe', permission='security:integrity:view')
    def handle_file_integrity_subscribe(message: Dict[str, Any], connection_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle subscription to file integrity events."""
        # Create filters for subscription
        filters = message.get('data', {}).get('filters', {})

        # Create subscribe message for the channel
        subscribe_message = {
            'type': 'channel.subscribe',
            'data': {
                'channel': 'file_integrity',
                'filters': filters
            },
            'request_id': message.get('request_id')
        }

        # Use existing channel subscription mechanism
        from .routes import handle_subscribe
        handle_subscribe(subscribe_message)

        # Also send the current status immediately after subscribing
        handle_file_integrity_request(message, connection_data)

        return {'success': True}


# --- Custom Event Handler Registration ---

def _register_custom_event_handlers():
    """Register custom event handlers."""

    @register_event_handler('custom.echo')
    def handle_echo(message: Dict[str, Any], connection_data: Dict[str, Any]) -> Dict[str, Any]:
        """Simple echo handler for testing."""
        echo_data = message.get('data', {})

        # Send echo response with the same data
        emit('custom.echo.response', {
            'type': 'custom.echo.response',
            'data': echo_data,
            'meta': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_id': message.get('request_id')
            }
        })

        return {'success': True}


# --- Initialize Module ---
import re  # Import here to avoid circular imports
