"""
Schema definitions for the Alerts API.

This module defines Marshmallow schemas for data validation, serialization, and
deserialization of alert-related data. These schemas ensure that data sent to
and from the API is properly validated and follows the expected structure.

The schemas implement:
- Input validation with custom validators
- Output formatting for consistent API responses
- Nested schemas for complex data structures
- Field-level validation with custom error messages
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Union
from marshmallow import Schema, fields, validate, validates, ValidationError, post_load, INCLUDE, validates_schema
from core.utils.validation import validate_resource_id, validate_service_name, validate_region


class BaseSchema(Schema):
    """Base schema with common configuration."""

    class Meta:
        """Schema metadata."""
        # Include unknown fields during deserialization but don't include them in the output
        unknown = INCLUDE
        # Order output fields for consistent responses
        ordered = True


class AlertCreateSchema(BaseSchema):
    """Schema for creating a new alert."""

    alert_type = fields.String(
        required=True,
        validate=validate.OneOf(
            ['high_cpu', 'high_memory', 'high_disk', 'low_disk', 'service_down',
             'security_vulnerability', 'cost_increase', 'availability',
             'performance', 'compliance', 'system']
        ),
        error_messages={"required": "Alert type is required"}
    )
    resource_id = fields.String(
        allow_none=True,
        validate=validate_resource_id
    )
    service_name = fields.String(
        required=True,
        validate=[validate.Length(min=2, max=64), validate_service_name],
        error_messages={"required": "Service name is required"}
    )
    severity = fields.String(
        required=True,
        validate=validate.OneOf(['critical', 'high', 'warning', 'info']),
        error_messages={"required": "Alert severity is required"}
    )
    message = fields.String(
        required=True,
        validate=validate.Length(min=5, max=500),
        error_messages={"required": "Alert message is required"}
    )
    details = fields.Dict(
        keys=fields.String(),
        values=fields.Raw(),
        missing=dict
    )
    environment = fields.String(
        required=True,
        validate=validate.OneOf(['production', 'staging', 'development', 'dr-recovery']),
        error_messages={"required": "Environment is required"}
    )
    region = fields.String(
        allow_none=True,
        validate=validate_region
    )
    status = fields.String(
        validate=validate.OneOf(['active', 'acknowledged', 'resolved']),
        missing='active'
    )
    created_at = fields.DateTime(missing=lambda: datetime.utcnow())

    @validates('details')
    def validate_details(self, value: Dict[str, Any]) -> None:
        """Validate that details dictionary isn't too large or complex."""
        # Convert to JSON and check size
        import json
        try:
            json_data = json.dumps(value)
            if len(json_data) > 10000:  # 10KB limit
                raise ValidationError("Details object too large (max 10KB)")
        except (TypeError, OverflowError):
            raise ValidationError("Invalid details structure")

        # Check nesting level (prevent DoS via deeply nested objects)
        self._check_nesting_depth(value)

    def _check_nesting_depth(self, obj: Any, current_depth: int = 0, max_depth: int = 5) -> None:
        """Check for excessive nesting in dictionaries/lists."""
        if current_depth > max_depth:
            raise ValidationError("Details structure too deeply nested")

        if isinstance(obj, dict):
            for key, value in obj.items():
                if not isinstance(key, str):
                    raise ValidationError("Dictionary keys must be strings")
                self._check_nesting_depth(value, current_depth + 1, max_depth)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                self._check_nesting_depth(item, current_depth + 1, max_depth)


class AlertUpdateSchema(BaseSchema):
    """Schema for updating an existing alert."""

    status = fields.String(
        validate=validate.OneOf(['active', 'acknowledged', 'resolved'])
    )
    severity = fields.String(
        validate=validate.OneOf(['critical', 'high', 'warning', 'info'])
    )
    message = fields.String(
        validate=validate.Length(min=5, max=500)
    )
    details = fields.Dict(
        keys=fields.String(),
        values=fields.Raw()
    )

    @validates_schema
    def validate_has_data(self, data: Dict[str, Any], **kwargs) -> None:
        """Ensure at least one field is provided for update."""
        if not data:
            raise ValidationError("At least one field must be provided for update")

    @validates('details')
    def validate_details(self, value: Dict[str, Any]) -> None:
        """Validate details structure and size."""
        # Reuse validation logic from AlertCreateSchema
        AlertCreateSchema().validate_details(value)


class AlertAcknowledgeSchema(BaseSchema):
    """Schema for acknowledging an alert."""

    acknowledged_by = fields.String(
        validate=validate.Length(min=1, max=100)
    )
    comment = fields.String(
        validate=validate.Length(max=500),
        missing=""
    )


class AlertResolveSchema(BaseSchema):
    """Schema for resolving an alert."""

    resolved_by = fields.String(
        validate=validate.Length(min=1, max=100)
    )
    resolution = fields.String(
        validate=validate.Length(min=5, max=1000),
        required=True,
        error_messages={"required": "Resolution details are required"}
    )
    resolution_type = fields.String(
        validate=validate.OneOf([
            'fixed', 'false_positive', 'expected_behavior', 'other'
        ]),
        missing='fixed'
    )


class AlertFilterSchema(BaseSchema):
    """Schema for filtering alerts."""

    status = fields.String(
        validate=validate.OneOf(['active', 'acknowledged', 'resolved', 'all'])
    )
    severity = fields.String(
        validate=validate.OneOf(['critical', 'high', 'warning', 'info', 'all'])
    )
    service_name = fields.String(
        validate=validate.Length(max=64)
    )
    resource_id = fields.String()
    environment = fields.String(
        validate=validate.OneOf(['production', 'staging', 'development', 'dr-recovery', 'all'])
    )
    region = fields.String()
    start_date = fields.DateTime()
    end_date = fields.DateTime()

    @validates_schema
    def validate_date_range(self, data: Dict[str, Any], **kwargs) -> None:
        """Validate that end_date is after start_date if both are provided."""
        if 'start_date' in data and 'end_date' in data:
            if data['start_date'] > data['end_date']:
                raise ValidationError("End date must be after start date")


class AlertStatisticsSchema(BaseSchema):
    """Schema for alert statistics requests."""

    period = fields.String(
        validate=validate.OneOf(['1d', '7d', '30d', '90d', 'all']),
        missing='7d'
    )
    environment = fields.String(
        validate=validate.OneOf(['production', 'staging', 'development', 'dr-recovery', 'all']),
        missing='all'
    )

    @post_load
    def process_period(self, data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """Convert period string to actual date range."""
        period = data.pop('period')

        if period == 'all':
            # Don't set date limits
            return data

        end_date = datetime.utcnow()

        if period == '1d':
            start_date = end_date - timedelta(days=1)
        elif period == '7d':
            start_date = end_date - timedelta(days=7)
        elif period == '30d':
            start_date = end_date - timedelta(days=30)
        elif period == '90d':
            start_date = end_date - timedelta(days=90)

        data['start_date'] = start_date
        data['end_date'] = end_date
        data['days'] = int(period[:-1])  # Store the number of days

        return data


class PaginationSchema(BaseSchema):
    """Schema for pagination parameters."""

    page = fields.Integer(
        validate=validate.Range(min=1),
        missing=1
    )
    per_page = fields.Integer(
        validate=validate.Range(min=1, max=100),
        missing=20
    )
    sort_by = fields.String(
        validate=validate.OneOf(['created_at', 'severity', 'status', 'service_name']),
        missing='created_at'
    )
    sort_dir = fields.String(
        validate=validate.OneOf(['asc', 'desc']),
        missing='desc'
    )


class AlertDetailSchema(BaseSchema):
    """Schema for detailed alert representation."""

    id = fields.Integer(dump_only=True)
    alert_type = fields.String(dump_only=True)
    resource_id = fields.String(dump_only=True, allow_none=True)
    service_name = fields.String(dump_only=True)
    severity = fields.String(dump_only=True)
    message = fields.String(dump_only=True)
    details = fields.Dict(dump_only=True)
    status = fields.String(dump_only=True)
    created_at = fields.DateTime(dump_only=True)
    environment = fields.String(dump_only=True)
    region = fields.String(dump_only=True, allow_none=True)
    acknowledged_by = fields.String(dump_only=True, allow_none=True)
    acknowledged_at = fields.DateTime(dump_only=True, allow_none=True)
    acknowledgement_note = fields.String(dump_only=True, allow_none=True)
    resolved_by = fields.String(dump_only=True, allow_none=True)
    resolved_at = fields.DateTime(dump_only=True, allow_none=True)
    resolution_note = fields.String(dump_only=True, allow_none=True)
    resolution_type = fields.String(dump_only=True, allow_none=True)


class AlertListItemSchema(BaseSchema):
    """Schema for alert list representation (simplified)."""

    id = fields.Integer(dump_only=True)
    alert_type = fields.String(dump_only=True)
    severity = fields.String(dump_only=True)
    message = fields.String(dump_only=True)
    status = fields.String(dump_only=True)
    created_at = fields.DateTime(dump_only=True)
    service_name = fields.String(dump_only=True)
    environment = fields.String(dump_only=True)


# Create schema instances for direct use in routes.py
alert_schema = AlertDetailSchema()
alerts_schema = AlertListItemSchema(many=True)
alert_create_schema = AlertCreateSchema()
alert_update_schema = AlertUpdateSchema()
alert_acknowledge_schema = AlertAcknowledgeSchema()
alert_resolve_schema = AlertResolveSchema()
alert_filter_schema = AlertFilterSchema()
alert_statistics_schema = AlertStatisticsSchema()
pagination_schema = PaginationSchema()
