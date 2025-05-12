"""
Schema definitions for WebSocket messages in the Cloud Infrastructure Platform.

This module provides validation schemas for messages exchanged via WebSocket
connections, ensuring data integrity, security, and consistent structure.
These schemas validate all incoming messages before they're processed by
handlers to prevent invalid operations and potential security issues.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from marshmallow import (
    Schema, fields, validate, validates, validates_schema,
    ValidationError, pre_load, post_load, EXCLUDE
)

# Constants for validation
MAX_CHANNEL_LENGTH = 100
MAX_MESSAGE_SIZE = 512 * 1024  # 512 KB limit for entire message
MAX_DATA_SIZE = 100 * 1024     # 100 KB limit for data payload
MAX_FILTER_SIZE = 50 * 1024    # 50 KB limit for filter parameters
MAX_EVENT_DEPTH = 5            # Maximum nesting depth for events
MAX_ARRAY_ITEMS = 1000         # Maximum number of items in array fields

# Valid event types that clients can subscribe to
VALID_EVENT_TYPES = [
    # Resource events
    'resource.created', 'resource.updated', 'resource.deleted',
    'resource.started', 'resource.stopped', 'resource.error',
    # Alert events
    'alert.triggered', 'alert.acknowledged', 'alert.resolved', 'alert.escalated',
    # Security events
    'security.incident', 'security.scan_completed', 'security.vulnerability',
    'security.file_integrity', 'security.file_integrity.violation',
    'security.file_integrity.baseline_updated',
    # System events
    'system.notification', 'system.status', 'system.maintenance',
    # ICS events
    'ics.reading', 'ics.state_change', 'ics.alarm'
]

# Channel patterns that can be subscribed to
VALID_CHANNEL_PATTERNS = [
    r'^user:[a-zA-Z0-9_\-]+$',                   # User-specific events
    r'^resource:[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+$', # Resource-specific events
    r'^resource:[a-zA-Z0-9_\-]+$',               # Resource type events
    r'^alerts:[a-zA-Z0-9_\-]+$',                 # Alert category events
    r'^metrics$',                                # System metrics stream
    r'^system$',                                 # System-wide notifications
    r'^status:[a-zA-Z0-9_\-]+$',                 # Component status
    r'^security:[a-zA-Z0-9_\-]+$',               # Security events
    r'^file_integrity$',                         # File integrity events
]


class BaseSchema(Schema):
    """
    Base schema with common configuration for all WebSocket messages.

    This base schema enforces:
    - Field ordering for consistent output
    - Strict field validation to prevent extra fields
    - Type validation for common fields
    - Security-focused validation patterns
    """

    class Meta:
        """Schema metadata."""
        # Ensure consistent field ordering in serialized output
        ordered = True
        # Exclude unknown fields for security
        unknown = EXCLUDE

    @pre_load
    def sanitize_input(self, data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        Pre-process incoming data to prevent security issues.

        This method performs basic sanitization of input data to prevent
        potential security issues like nested object attacks.

        Args:
            data: The incoming message data

        Returns:
            Dict: The sanitized data
        """
        # Check for oversized input to prevent DoS
        import json
        try:
            message_size = len(json.dumps(data))
            if message_size > MAX_MESSAGE_SIZE:
                raise ValidationError(f"Message size exceeds limit ({message_size} > {MAX_MESSAGE_SIZE} bytes)")
        except (TypeError, OverflowError):
            raise ValidationError("Message contains invalid data types")

        # Check for excessive nesting to prevent DoS
        self._check_nesting_depth(data)

        return data

    def _check_nesting_depth(self, obj: Any, current_depth: int = 0, max_depth: int = MAX_EVENT_DEPTH) -> None:
        """
        Check the nesting depth of a complex object to prevent DoS attacks.

        Args:
            obj: The object to check
            current_depth: Current nesting level
            max_depth: Maximum allowed nesting level

        Raises:
            ValidationError: If maximum nesting depth is exceeded
        """
        if current_depth > max_depth:
            raise ValidationError("Maximum nesting depth exceeded")

        if isinstance(obj, dict):
            if len(obj) > MAX_ARRAY_ITEMS:
                raise ValidationError(f"Dictionary contains too many items (limit: {MAX_ARRAY_ITEMS})")

            for key, value in obj.items():
                if not isinstance(key, str):
                    raise ValidationError("Dictionary keys must be strings")

                # Check key length to prevent DoS
                if len(key) > 255:
                    raise ValidationError(f"Dictionary key exceeds maximum length: {key[:50]}...")

                self._check_nesting_depth(value, current_depth + 1, max_depth)

        elif isinstance(obj, (list, tuple)):
            if len(obj) > MAX_ARRAY_ITEMS:
                raise ValidationError(f"Array contains too many items (limit: {MAX_ARRAY_ITEMS})")

            for item in obj:
                self._check_nesting_depth(item, current_depth + 1, max_depth)


class MessageSchema(BaseSchema):
    """
    Basic message schema for validating generic messages.

    This schema serves as a general-purpose validator to ensure
    all WebSocket messages meet minimal requirements.
    """

    type = fields.String(
        required=True,
        validate=validate.Length(min=1, max=50)
    )

    # Optional request ID for correlation
    request_id = fields.String(
        missing=lambda: f"req-{datetime.now(timezone.utc).timestamp()}"
    )

    # Optional data payload
    data = fields.Dict(missing=dict)

    @validates('type')
    def validate_type(self, value: str) -> None:
        """
        Validate message type format for security.

        Ensures the message type follows the required pattern to prevent
        injection attacks and maintain consistent naming.

        Args:
            value: The message type value to validate

        Raises:
            ValidationError: If validation fails
        """
        if not re.match(r'^[a-zA-Z0-9_]+(\.)[a-zA-Z0-9_]+$', value) and value not in ['ping']:
            raise ValidationError(
                "Message type must follow the pattern 'namespace.action' using only "
                "letters, numbers and underscores, or be one of the reserved types"
            )

    @validates('data')
    def validate_data_size(self, value: Dict[str, Any]) -> None:
        """
        Ensure data doesn't exceed size limits to prevent DoS attacks.

        Args:
            value: The data payload to validate

        Raises:
            ValidationError: If the data size exceeds the limit
        """
        import json
        try:
            data_size = len(json.dumps(value))
            if data_size > MAX_DATA_SIZE:
                raise ValidationError(f"Message data exceeds size limit ({data_size} > {MAX_DATA_SIZE} bytes)")
        except (TypeError, OverflowError):
            raise ValidationError("Message data contains invalid data types")


class SubscriptionSchema(MessageSchema):
    """
    Schema for validating channel subscription requests.

    Validates that subscription requests include valid:
    - Message type (channel.subscribe)
    - Channel name
    - Optional filters
    - Optional subscription options
    """

    type = fields.String(
        required=True,
        validate=validate.Equal('channel.subscribe')
    )

    data = fields.Dict(required=True)

    @validates('data')
    def validate_subscription_data(self, value: Dict[str, Any]) -> None:
        """
        Validate subscription data structure.

        Ensures the subscription data contains required fields and
        follows the expected structure and size limits.

        Args:
            value: The subscription data to validate

        Raises:
            ValidationError: If validation fails
        """
        # Validate required channel field
        if 'channel' not in value:
            raise ValidationError("Channel is required")

        # Validate channel format
        channel = value.get('channel', '')
        if not isinstance(channel, str):
            raise ValidationError("Channel must be a string")

        if len(channel) < 3 or len(channel) > MAX_CHANNEL_LENGTH:
            raise ValidationError(f"Channel name must be between 3 and {MAX_CHANNEL_LENGTH} characters")

        if not re.match(r'^[a-zA-Z0-9_\-:]+$', channel):
            raise ValidationError("Channel name contains invalid characters")

        # Validate that channel follows a known pattern
        if not any(re.match(pattern, channel) for pattern in VALID_CHANNEL_PATTERNS):
            raise ValidationError("Invalid channel pattern")

        # Validate filters if present
        if 'filters' in value and not isinstance(value['filters'], dict):
            raise ValidationError("'filters' must be an object")

        # Validate options if present
        if 'options' in value and not isinstance(value['options'], dict):
            raise ValidationError("'options' must be an object")

        # Check filter size
        if 'filters' in value:
            import json
            try:
                filters_size = len(json.dumps(value['filters']))
                if filters_size > MAX_FILTER_SIZE:
                    raise ValidationError(f"Filters exceed size limit ({filters_size} > {MAX_FILTER_SIZE} bytes)")
            except (TypeError, OverflowError):
                raise ValidationError("Filters contain invalid data types")

        # Validate specific filter fields if present
        if 'filters' in value and isinstance(value['filters'], dict):
            filters = value['filters']

            # Validate date range if present
            if 'date_range' in filters:
                date_range = filters['date_range']
                if not isinstance(date_range, dict):
                    raise ValidationError("'date_range' must be an object")

                if 'start' in date_range and not isinstance(date_range['start'], str):
                    raise ValidationError("'date_range.start' must be a string")

                if 'end' in date_range and not isinstance(date_range['end'], str):
                    raise ValidationError("'date_range.end' must be a string")

                # Validate date format if provided
                if 'start' in date_range:
                    try:
                        datetime.fromisoformat(date_range['start'].replace('Z', '+00:00'))
                    except ValueError:
                        raise ValidationError("Invalid date format for 'date_range.start'")

                if 'end' in date_range:
                    try:
                        datetime.fromisoformat(date_range['end'].replace('Z', '+00:00'))
                    except ValueError:
                        raise ValidationError("Invalid date format for 'date_range.end'")

            # Validate event types if present
            if 'event_types' in filters:
                event_types = filters['event_types']
                if not isinstance(event_types, list):
                    raise ValidationError("'event_types' must be an array")

                if not event_types:
                    raise ValidationError("'event_types' cannot be empty")

                if len(event_types) > 20:  # Limit number of event types
                    raise ValidationError("Too many event types specified (max: 20)")

                for event_type in event_types:
                    if not isinstance(event_type, str):
                        raise ValidationError("Each event type must be a string")

                    if len(event_type) > 50:
                        raise ValidationError(f"Event type name too long: {event_type[:30]}...")

                    # Check if event type is supported
                    if event_type not in VALID_EVENT_TYPES and not event_type.startswith('custom.'):
                        raise ValidationError(f"Unsupported event type: {event_type}")

            # Validate severity filter if present
            if 'severity' in filters:
                severity = filters['severity']
                if not isinstance(severity, list):
                    raise ValidationError("'severity' must be an array")

                valid_severities = ['critical', 'high', 'medium', 'low', 'info']
                for sev in severity:
                    if not isinstance(sev, str) or sev not in valid_severities:
                        raise ValidationError(f"Invalid severity value: {sev}")

            # Validate file_integrity-specific filters
            if 'file_integrity' in filters:
                file_integrity = filters['file_integrity']
                if not isinstance(file_integrity, dict):
                    raise ValidationError("'file_integrity' must be an object")

                # Validate file_integrity filter fields
                for field in file_integrity:
                    if field not in ['status', 'paths', 'severity', 'change_types']:
                        raise ValidationError(f"Unknown file_integrity filter field: {field}")

                # Validate status
                if 'status' in file_integrity:
                    status = file_integrity['status']
                    if not isinstance(status, list):
                        raise ValidationError("'file_integrity.status' must be an array")

                    valid_statuses = ['modified', 'added', 'deleted', 'permission_changed']
                    for s in status:
                        if not isinstance(s, str) or s not in valid_statuses:
                            raise ValidationError(f"Invalid status value: {s}")

                # Validate paths
                if 'paths' in file_integrity:
                    paths = file_integrity['paths']
                    if not isinstance(paths, list):
                        raise ValidationError("'file_integrity.paths' must be an array")

                    for path in paths:
                        if not isinstance(path, str):
                            raise ValidationError("Each path must be a string")

                        if len(path) > 256:  # Limit path length
                            raise ValidationError(f"Path too long: {path[:50]}...")

                # Validate change_types
                if 'change_types' in file_integrity:
                    change_types = file_integrity['change_types']
                    if not isinstance(change_types, list):
                        raise ValidationError("'file_integrity.change_types' must be an array")

                    valid_change_types = ['content', 'permission', 'ownership', 'timestamp']
                    for ct in change_types:
                        if not isinstance(ct, str) or ct not in valid_change_types:
                            raise ValidationError(f"Invalid change_type value: {ct}")


class UnsubscriptionSchema(MessageSchema):
    """
    Schema for validating channel unsubscription requests.

    Validates that unsubscription requests include:
    - Message type (channel.unsubscribe)
    - Channel name to unsubscribe from
    """

    type = fields.String(
        required=True,
        validate=validate.Equal('channel.unsubscribe')
    )

    data = fields.Dict(required=True)

    @validates('data')
    def validate_unsubscription_data(self, value: Dict[str, Any]) -> None:
        """
        Validate unsubscription data structure.

        Ensures the unsubscription data contains the required channel field
        and follows the expected format.

        Args:
            value: The unsubscription data to validate

        Raises:
            ValidationError: If validation fails
        """
        # Validate required channel field
        if 'channel' not in value:
            raise ValidationError("Channel is required")

        # Validate channel format
        channel = value.get('channel', '')
        if not isinstance(channel, str):
            raise ValidationError("Channel must be a string")

        if len(channel) < 3 or len(channel) > MAX_CHANNEL_LENGTH:
            raise ValidationError(f"Channel name must be between 3 and {MAX_CHANNEL_LENGTH} characters")

        if not re.match(r'^[a-zA-Z0-9_\-:]+$', channel):
            raise ValidationError("Channel name contains invalid characters")


class AuthenticationSchema(MessageSchema):
    """
    Schema for validating authentication messages.

    Validates that authentication requests include:
    - Message type (auth.refresh)
    - Optional data for authentication parameters
    """

    type = fields.String(
        required=True,
        validate=validate.Equal('auth.refresh')
    )

    data = fields.Dict(missing=dict)

    @validates('data')
    def validate_authentication_data(self, value: Dict[str, Any]) -> None:
        """
        Validate authentication data structure.

        Ensures the authentication data follows the expected format.

        Args:
            value: The authentication data to validate

        Raises:
            ValidationError: If validation fails
        """
        # Token validation would happen at the handler level since it's not in the message


class PingSchema(MessageSchema):
    """
    Schema for validating ping messages used for connection heartbeats.

    Ensures ping messages have proper structure for maintaining connections.
    """

    type = fields.String(
        required=True,
        validate=validate.Equal('ping')
    )

    data = fields.Dict(missing=dict)


class FileIntegrityEventSchema(MessageSchema):
    """
    Schema for validating file integrity event messages.

    Used for messages related to file integrity monitoring events including:
    - Integrity violations
    - Baseline updates
    - Security alerts related to file changes

    This schema ensures proper structure and content validation for file
    integrity events that require special handling.
    """

    type = fields.String(
        required=True,
        validate=validate.OneOf([
            'security.file_integrity.violation',
            'security.file_integrity.baseline_updated'
        ])
    )

    data = fields.Dict(required=True)

    @validates('data')
    def validate_file_integrity_data(self, value: Dict[str, Any]) -> None:
        """
        Validate file integrity event data structure.

        Ensures that data for file integrity events contains the required fields
        and follows the expected structure based on the event type.

        Args:
            value: The event data to validate

        Raises:
            ValidationError: If validation fails
        """
        required_fields = ['event_id', 'timestamp', 'severity']
        for field in required_fields:
            if field not in value:
                raise ValidationError(f"Required field missing: {field}")

        # Validate event_id format
        event_id = value.get('event_id', '')
        if not isinstance(event_id, str):
            raise ValidationError("event_id must be a string")

        if not re.match(r'^[a-zA-Z0-9_\-]+$', event_id):
            raise ValidationError("event_id contains invalid characters")

        # Validate timestamp
        timestamp = value.get('timestamp', '')
        if not isinstance(timestamp, str):
            raise ValidationError("timestamp must be a string")

        try:
            datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        except ValueError:
            raise ValidationError("Invalid timestamp format")

        # Validate severity
        severity = value.get('severity', '')
        if not isinstance(severity, str):
            raise ValidationError("severity must be a string")

        valid_severities = ['critical', 'high', 'medium', 'low', 'info']
        if severity not in valid_severities:
            raise ValidationError(f"Invalid severity: {severity}")

        # Event type specific validation
        event_type = self.context.get('type', '')

        if event_type == 'security.file_integrity.violation':
            if 'violations' not in value:
                raise ValidationError("violations field is required")

            violations = value['violations']
            if not isinstance(violations, list):
                raise ValidationError("violations must be an array")

            if len(violations) == 0:
                raise ValidationError("violations cannot be empty")

            if len(violations) > 100:
                raise ValidationError("Too many violations (max: 100)")

            for violation in violations:
                if not isinstance(violation, dict):
                    raise ValidationError("Each violation must be an object")

                required_violation_fields = ['path', 'type', 'details']
                for field in required_violation_fields:
                    if field not in violation:
                        raise ValidationError(f"Violation missing required field: {field}")

                # Validate path
                path = violation.get('path', '')
                if not isinstance(path, str):
                    raise ValidationError("path must be a string")

                # Validate type
                vtype = violation.get('type', '')
                if not isinstance(vtype, str):
                    raise ValidationError("type must be a string")

                valid_types = ['modified', 'added', 'deleted', 'permission_changed']
                if vtype not in valid_types:
                    raise ValidationError(f"Invalid violation type: {vtype}")

        elif event_type == 'security.file_integrity.baseline_updated':
            if 'changes' not in value:
                raise ValidationError("changes field is required")

            changes = value['changes']
            if not isinstance(changes, dict):
                raise ValidationError("changes must be an object")

            for change_type, count in changes.items():
                valid_change_types = ['added', 'updated', 'removed']
                if change_type not in valid_change_types:
                    raise ValidationError(f"Invalid change type: {change_type}")

                if not isinstance(count, int) or count < 0:
                    raise ValidationError(f"Invalid count for {change_type}")

            if 'initiated_by' in value:
                initiated_by = value['initiated_by']
                if not isinstance(initiated_by, str):
                    raise ValidationError("initiated_by must be a string")

            if 'reason' in value:
                reason = value['reason']
                if not isinstance(reason, str):
                    raise ValidationError("reason must be a string")

                if len(reason) > 1000:
                    raise ValidationError("reason is too long (max: 1000 characters)")


def validate_message(message: Dict[str, Any], schema_class: Schema = MessageSchema) -> Dict[str, Any]:
    """
    Validate a WebSocket message against the specified schema.

    This function serves as a central validation point for all WebSocket messages,
    providing consistent error handling and logging.

    Args:
        message: The message to validate
        schema_class: The schema class to use for validation (default: MessageSchema)

    Returns:
        Dict containing validation result with fields:
            - valid: Boolean indicating if validation passed
            - errors: Error messages if validation failed
            - data: Validated and processed data if successful
    """
    if not isinstance(message, dict):
        return {
            'valid': False,
            'errors': {'_schema': ['Message must be a JSON object']}
        }

    # Basic size validation to prevent DoS
    import json
    try:
        message_size = len(json.dumps(message))
        if message_size > MAX_MESSAGE_SIZE:
            return {
                'valid': False,
                'errors': {'_schema': [f'Message size exceeds limit ({message_size} > {MAX_MESSAGE_SIZE} bytes)']}
            }
    except (TypeError, OverflowError):
        return {
            'valid': False,
            'errors': {'_schema': ['Message contains invalid data types']}
        }

    try:
        # Create schema instance
        schema = schema_class()

        # For file integrity events, provide event type in context
        if schema_class == FileIntegrityEventSchema and 'type' in message:
            schema.context['type'] = message['type']

        # Validate and deserialize
        validated_data = schema.load(message)

        return {
            'valid': True,
            'data': validated_data
        }

    except ValidationError as err:
        # Return validation errors
        return {
            'valid': False,
            'errors': err.messages
        }
    except Exception as err:
        # Return unexpected errors
        return {
            'valid': False,
            'errors': {'_schema': [f'Validation error: {str(err)}']}
        }


# Create schema instances for direct use in routes
subscription_schema = SubscriptionSchema()
unsubscription_schema = UnsubscriptionSchema()
authentication_schema = AuthenticationSchema()
ping_schema = PingSchema()
message_schema = MessageSchema()
file_integrity_event_schema = FileIntegrityEventSchema()
