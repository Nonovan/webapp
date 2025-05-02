"""
Schema definitions for WebSocket messages in the Administrative WebSocket API.

This module provides validation schemas for messages exchanged via WebSocket
connections, ensuring data integrity, security, and consistent structure.
These schemas validate all incoming messages before they're processed by
handlers to prevent invalid operations and potential security issues.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union

from marshmallow import Schema, fields, validate, validates, validates_schema, ValidationError

# Constants for validation
MAX_CHANNEL_LENGTH = 100
MAX_OPERATION_LENGTH = 100
MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB limit for entire message
MAX_JUSTIFICATION_LENGTH = 1000
MAX_PARAMETERS_SIZE = 100 * 1024  # 100 KB limit for parameters


class BaseSchema(Schema):
    """
    Base schema with common configuration for all WebSocket messages.

    This base schema enforces:
    - Field ordering for consistent output
    - Strict field validation to prevent extra fields
    - Event type is always present
    - Request ID for tracking and correlation
    """

    class Meta:
        """Schema metadata."""
        # Ensure consistent field ordering in serialized output
        ordered = True
        # Strict validation - don't allow unknown fields
        unknown = 'raise'

    # Fields common to all messages
    event_type = fields.String(required=True)
    request_id = fields.String(missing=lambda: f"req-{datetime.now(timezone.utc).timestamp()}")


class MessageSchema(BaseSchema):
    """
    Basic message schema for validating generic messages.

    This schema serves as a general-purpose validator to ensure
    all messages meet minimal requirements.
    """

    event_type = fields.String(
        required=True,
        validate=validate.OneOf(['subscribe', 'unsubscribe', 'command', 'ping'])
    )

    # Optional data payload
    data = fields.Dict(missing=dict)

    @validates('data')
    def validate_data_size(self, value):
        """Ensure data doesn't exceed size limits (prevents DoS attacks)."""
        import json
        data_size = len(json.dumps(value))
        if data_size > MAX_MESSAGE_SIZE:
            raise ValidationError(f"Message data exceeds size limit ({data_size} > {MAX_MESSAGE_SIZE} bytes)")


class SubscriptionSchema(BaseSchema):
    """
    Schema for validating channel subscription requests.

    Validates that subscription requests include valid:
    - Channel name
    - Optional filters
    - Optional subscription options
    """

    event_type = fields.String(
        required=True,
        validate=validate.Equal('subscribe')
    )

    channel = fields.String(
        required=True,
        validate=[
            validate.Length(min=3, max=MAX_CHANNEL_LENGTH),
            validate.Regexp(r'^[a-zA-Z0-9_\-:]+$', error="Channel name contains invalid characters")
        ]
    )

    data = fields.Dict(missing=dict)

    @validates('data')
    def validate_subscription_data(self, value):
        """Validate subscription data structure."""
        # Validate filters if present
        if 'filters' in value and not isinstance(value['filters'], dict):
            raise ValidationError("'filters' must be an object")

        # Validate options if present
        if 'options' in value and not isinstance(value['options'], dict):
            raise ValidationError("'options' must be an object")

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

            # Validate severity list if present
            if 'severity' in filters and not isinstance(filters['severity'], list):
                raise ValidationError("'severity' must be a list")

            # Validate components list if present
            if 'components' in filters and not isinstance(filters['components'], list):
                raise ValidationError("'components' must be a list")


class UnsubscriptionSchema(BaseSchema):
    """
    Schema for validating channel unsubscription requests.

    Validates that unsubscription requests include a valid channel name.
    """

    event_type = fields.String(
        required=True,
        validate=validate.Equal('unsubscribe')
    )

    channel = fields.String(
        required=True,
        validate=[
            validate.Length(min=3, max=MAX_CHANNEL_LENGTH),
            validate.Regexp(r'^[a-zA-Z0-9_\-:]+$', error="Channel name contains invalid characters")
        ]
    )


class CommandSchema(BaseSchema):
    """
    Schema for validating administrative commands.

    Enforces strict validation of command operations including:
    - Valid operation names
    - Properly structured parameters
    - Required justification for sensitive operations
    - Optional ticket ID for change tracking
    """

    event_type = fields.String(
        required=True,
        validate=validate.Equal('command')
    )

    data = fields.Dict(required=True)

    @validates('data')
    def validate_command_data(self, value):
        """Validate command structure and parameters."""
        # Validate operation presence and format
        if 'operation' not in value:
            raise ValidationError("'operation' is required for command messages")

        operation = value['operation']
        if not isinstance(operation, str):
            raise ValidationError("'operation' must be a string")

        if len(operation) > MAX_OPERATION_LENGTH:
            raise ValidationError(f"'operation' name is too long (max {MAX_OPERATION_LENGTH} characters)")

        # Validate operation format (namespace.action)
        if not re.match(r'^[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+$', operation):
            raise ValidationError(
                "'operation' must follow format 'namespace.action' using only letters, numbers, and underscores"
            )

        # Validate parameters if present
        if 'parameters' in value:
            if not isinstance(value['parameters'], dict):
                raise ValidationError("'parameters' must be an object")

            # Check parameters size to prevent DoS
            import json
            params_size = len(json.dumps(value['parameters']))
            if params_size > MAX_PARAMETERS_SIZE:
                raise ValidationError(
                    f"Command parameters exceed size limit ({params_size} > {MAX_PARAMETERS_SIZE} bytes)"
                )

        # Validate justification for sensitive operations
        high_risk_operations = {
            'system.shutdown', 'system.restart', 'cache.clear', 'database.vacuum',
            'file_integrity.update_baseline', 'security.reset_mfa', 'maintenance.start',
            'maintenance.end', 'config.update', 'user.delete', 'user.lock'
        }

        if operation in high_risk_operations:
            if 'justification' not in value or not value['justification']:
                raise ValidationError(f"Justification is required for operation '{operation}'")

            if not isinstance(value['justification'], str):
                raise ValidationError("'justification' must be a string")

            if len(value['justification']) < 10:
                raise ValidationError("'justification' must be at least 10 characters")

            if len(value['justification']) > MAX_JUSTIFICATION_LENGTH:
                raise ValidationError(
                    f"'justification' is too long (max {MAX_JUSTIFICATION_LENGTH} characters)"
                )

        # Validate ticket ID format if present
        if 'ticket_id' in value and value['ticket_id']:
            if not isinstance(value['ticket_id'], str):
                raise ValidationError("'ticket_id' must be a string")

            # Match common ticket ID formats: INC-12345, REQ-2023-1234, CHG0012345
            if not re.match(r'^(INC|REQ|CHG)[\-0-9]{5,12}$', value['ticket_id']):
                raise ValidationError("'ticket_id' has invalid format")


class PingSchema(BaseSchema):
    """
    Schema for validating ping messages used for connection heartbeats.

    Ensures ping messages have proper structure for maintaining connections.
    """

    event_type = fields.String(
        required=True,
        validate=validate.Equal('ping')
    )

    timestamp = fields.String(missing=lambda: datetime.now(timezone.utc).isoformat())


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
command_schema = CommandSchema()
ping_schema = PingSchema()
message_schema = MessageSchema()
