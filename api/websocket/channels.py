"""
Channel management for WebSocket connections in the Cloud Infrastructure Platform.

This module provides functionality for WebSocket channel management, including
validation of channel names, permission checking for channel subscriptions,
and information retrieval about available channels. It ensures consistent
channel naming and access control across the WebSocket API.

Key features:
- Channel name format validation
- Available channel listing with filtering options
- Channel information retrieval
- Permission checking for secure channel access
"""

import logging
import re
from typing import Dict, Any, List, Optional, Set, Union
from datetime import datetime, timezone

from flask import current_app, g

from core.security import require_permission, log_security_event
from models.auth.user import User

# Initialize module logger
logger = logging.getLogger(__name__)

# Channel type constants
CHANNEL_TYPE_USER = 'user'           # User-specific events (user:123)
CHANNEL_TYPE_RESOURCE = 'resource'   # Resource updates (resource:servers:456)
CHANNEL_TYPE_ALERT = 'alerts'        # Alert notifications (alerts:security)
CHANNEL_TYPE_METRIC = 'metrics'      # Metrics updates (metrics)
CHANNEL_TYPE_SYSTEM = 'system'       # System-wide events (system)
CHANNEL_TYPE_STATUS = 'status'       # Status updates (status:cloud)
CHANNEL_TYPE_CUSTOM = 'custom'       # Custom event streams (custom:name)

# Available channel patterns with descriptions
CHANNEL_PATTERNS = {
    r'^user:[0-9]+$': 'User-specific events',
    r'^resource:[a-zA-Z0-9_\-]+:[0-9]+$': 'Resource-specific updates',
    r'^resource:[a-zA-Z0-9_\-]+$': 'Resource type events',
    r'^alerts:[a-zA-Z0-9_\-]+$': 'Alert notifications by category',
    r'^metrics$': 'System metrics stream',
    r'^metrics:[a-zA-Z0-9_\-]+$': 'Component-specific metrics',
    r'^system$': 'System-wide notifications',
    r'^status:[a-zA-Z0-9_\-]+$': 'Status updates by component',
    r'^custom:[a-zA-Z0-9_\-]+$': 'Custom event streams'
}

# Valid characters for channel names
VALID_CHANNEL_CHARS = re.compile(r'^[a-zA-Z0-9_\-:]+$')

# Maximum channel name length
MAX_CHANNEL_NAME_LENGTH = 100


def validate_channel(channel: str) -> Dict[str, Any]:
    """
    Validate a channel name to ensure it follows required format.

    Args:
        channel: Channel name to validate

    Returns:
        Dict containing validation result and message if invalid
    """
    # Basic checks
    if not channel:
        return {'valid': False, 'message': 'Channel name is required'}

    if not isinstance(channel, str):
        return {'valid': False, 'message': 'Channel name must be a string'}

    # Length check
    if len(channel) > MAX_CHANNEL_NAME_LENGTH:
        return {'valid': False, 'message': f'Channel name exceeds maximum length of {MAX_CHANNEL_NAME_LENGTH}'}

    # Character validation
    if not VALID_CHANNEL_CHARS.match(channel):
        return {'valid': False, 'message': 'Channel name contains invalid characters'}

    # Special characters check
    if channel.startswith(':') or channel.endswith(':') or '::' in channel:
        return {'valid': False, 'message': 'Invalid channel format: improper use of colon separator'}

    # Pattern matching
    pattern_matched = False
    for pattern in CHANNEL_PATTERNS.keys():
        if re.match(pattern, channel):
            pattern_matched = True
            break

    if not pattern_matched:
        return {
            'valid': False,
            'message': 'Channel does not match any supported format. ' +
                      'Examples: user:123, resource:servers:456, alerts:security'
        }

    # Success case
    return {'valid': True}


def get_available_channels(user_id: Optional[int] = None,
                          filter_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Get list of available channels, optionally filtered by type or user permission.

    Args:
        user_id: Optional user ID to filter channels by permission
        filter_type: Optional channel type filter

    Returns:
        List of channel definitions with metadata
    """
    # Get all standard channels
    standard_channels = [
        {
            'name': 'system',
            'type': CHANNEL_TYPE_SYSTEM,
            'description': 'System-wide notifications',
            'requires_permission': 'system:view'
        },
        {
            'name': 'metrics',
            'type': CHANNEL_TYPE_METRIC,
            'description': 'System metrics stream',
            'requires_permission': 'metrics:view'
        },
        {
            'name': 'alerts:security',
            'type': CHANNEL_TYPE_ALERT,
            'description': 'Security alert notifications',
            'requires_permission': 'alerts:security:view'
        },
        {
            'name': 'alerts:performance',
            'type': CHANNEL_TYPE_ALERT,
            'description': 'Performance alert notifications',
            'requires_permission': 'alerts:performance:view'
        },
        {
            'name': 'alerts:system',
            'type': CHANNEL_TYPE_ALERT,
            'description': 'System alert notifications',
            'requires_permission': 'alerts:system:view'
        },
        {
            'name': 'status:cloud',
            'type': CHANNEL_TYPE_STATUS,
            'description': 'Cloud infrastructure status updates',
            'requires_permission': 'status:view'
        },
        {
            'name': 'status:network',
            'type': CHANNEL_TYPE_STATUS,
            'description': 'Network status updates',
            'requires_permission': 'status:view'
        }
    ]

    # Get dynamic channels if possible
    try:
        from models.auth.user import User

        # Add user-specific channel
        if user_id:
            user_channel = {
                'name': f'user:{user_id}',
                'type': CHANNEL_TYPE_USER,
                'description': 'Your user-specific events',
                'requires_permission': None  # Own user channel doesn't require special permission
            }
            standard_channels.append(user_channel)

        # Add resource-type channels based on permissions
        if user_id:
            from core.security.cs_authorization import get_user_permissions

            # Check for resource view permissions
            user_perms = get_user_permissions(user_id)
            resource_types = []

            for perm in user_perms:
                if perm.endswith(':view') and not perm.startswith(('system:', 'admin:', 'metrics:')):
                    resource_type = perm.split(':')[0]
                    if resource_type not in ('status', 'alerts') and resource_type not in resource_types:
                        resource_types.append(resource_type)

            # Add resource channels
            for resource_type in resource_types:
                resource_channel = {
                    'name': f'resource:{resource_type}',
                    'type': CHANNEL_TYPE_RESOURCE,
                    'description': f'{resource_type.capitalize()} resource events',
                    'requires_permission': f'{resource_type}:view'
                }
                standard_channels.append(resource_channel)

    except Exception as e:
        logger.warning(f"Error generating dynamic channels: {str(e)}")

    # Filter channels if requested
    result = []
    for channel in standard_channels:
        # Apply type filter if provided
        if filter_type and channel['type'] != filter_type:
            continue

        # Apply permission filter if user_id provided
        if user_id and channel['requires_permission']:
            try:
                from core.security.cs_authorization import verify_permission
                has_permission = verify_permission(user_id, channel['requires_permission'])
                if not has_permission:
                    continue
            except Exception as e:
                logger.warning(f"Error checking permission for channel {channel['name']}: {str(e)}")
                continue

        # Add metadata
        channel_info = {
            **channel,
            'pattern': next((p for p in CHANNEL_PATTERNS.keys() if re.match(p, channel['name'])), None)
        }

        result.append(channel_info)

    return result


def get_channel_info(channel: str) -> Dict[str, Any]:
    """
    Get detailed information about a specific channel.

    Args:
        channel: Channel name to get information for

    Returns:
        Dict with channel details or error information
    """
    # Validate channel first
    validation = validate_channel(channel)
    if not validation['valid']:
        return {
            'exists': False,
            'error': validation['message'],
            'channel': channel
        }

    # Determine channel type and info based on pattern matching
    channel_type = None
    description = None
    permission = None

    # Try to match with standard channels
    for std_channel in get_available_channels():
        if std_channel['name'] == channel:
            return {
                'exists': True,
                'channel': channel,
                'type': std_channel['type'],
                'description': std_channel['description'],
                'requires_permission': std_channel['requires_permission']
            }

    # Handle common patterns for dynamic channels
    if channel.startswith('user:'):
        parts = channel.split(':')
        if len(parts) == 2 and parts[1].isdigit():
            user_id = int(parts[1])
            return {
                'exists': True,
                'channel': channel,
                'type': CHANNEL_TYPE_USER,
                'description': f'User-specific events for user ID {user_id}',
                'requires_permission': None,  # Will be checked separately for user ownership
                'resource_id': user_id
            }

    elif channel.startswith('resource:'):
        parts = channel.split(':')
        if len(parts) >= 2:
            resource_type = parts[1]
            resource_id = parts[2] if len(parts) > 2 and parts[2].isdigit() else None

            result = {
                'exists': True,
                'channel': channel,
                'type': CHANNEL_TYPE_RESOURCE,
                'description': f'{resource_type.capitalize()} resource events',
                'requires_permission': f'{resource_type}:view',
                'resource_type': resource_type
            }

            if resource_id:
                result['resource_id'] = int(resource_id)

            return result

    elif channel.startswith('alerts:'):
        parts = channel.split(':')
        if len(parts) == 2:
            alert_type = parts[1]
            return {
                'exists': True,
                'channel': channel,
                'type': CHANNEL_TYPE_ALERT,
                'description': f'{alert_type.capitalize()} alert notifications',
                'requires_permission': f'alerts:{alert_type}:view',
                'alert_type': alert_type
            }

    elif channel.startswith('status:'):
        parts = channel.split(':')
        if len(parts) == 2:
            status_type = parts[1]
            return {
                'exists': True,
                'channel': channel,
                'type': CHANNEL_TYPE_STATUS,
                'description': f'{status_type.capitalize()} status updates',
                'requires_permission': 'status:view',
                'status_type': status_type
            }

    elif channel.startswith('custom:'):
        parts = channel.split(':')
        if len(parts) == 2:
            custom_type = parts[1]
            return {
                'exists': True,
                'channel': channel,
                'type': CHANNEL_TYPE_CUSTOM,
                'description': f'Custom event stream: {custom_type}',
                'requires_permission': 'events:subscribe',
                'custom_type': custom_type
            }

    # Fall back to generic info
    for pattern, desc in CHANNEL_PATTERNS.items():
        if re.match(pattern, channel):
            return {
                'exists': True,
                'channel': channel,
                'type': channel.split(':')[0] if ':' in channel else channel,
                'description': desc,
                'requires_permission': None  # Permission check will be done separately
            }

    # Should not reach here if validation passed, but just in case
    return {
        'exists': False,
        'error': 'Unknown channel format',
        'channel': channel
    }
