"""
Schema definitions for the Administrative API.

This module defines Marshmallow schemas for data validation, serialization, and
deserialization in the administrative API. These schemas ensure that data sent to
and from the API endpoints is properly validated and follows the expected structure,
implementing security controls to prevent injection attacks and DoS attempts.
"""

import re
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union, Set

from marshmallow import (
    Schema, fields, validate, validates, validates_schema,
    ValidationError, pre_load, post_load, EXCLUDE, INCLUDE
)

from admin.security.forensics.utils import validate_port_number
from core.security.cs_authentication import is_valid_username, validate_password_strength

# Initialize module logger
import logging
logger = logging.getLogger(__name__)


class BaseSchema(Schema):
    """
    Base schema with common configuration for all admin schemas.

    This schema provides foundational behaviors for admin API schemas:
    - Excludes unknown fields to prevent data injection attacks
    - Implements sanitization hooks for input data
    - Provides common utility methods for validation
    """
    class Meta:
        """Schema metadata."""
        # Exclude unknown fields for security
        unknown = EXCLUDE
        # Ensure consistent field ordering in serialized output
        ordered = True

    @pre_load
    def sanitize_input(self, data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        Pre-process and sanitize input data before validation.

        Args:
            data: The input data dictionary

        Returns:
            Sanitized input data
        """
        # Strip whitespace from string fields to prevent whitespace-based attacks
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = value.strip()
            else:
                sanitized[key] = value
        return sanitized

    def _check_nesting_depth(self, obj: Any, current_depth: int = 0, max_depth: int = 5) -> None:
        """
        Check object nesting depth to prevent DoS attacks.

        Args:
            obj: Object to check for nesting
            current_depth: Current nesting depth
            max_depth: Maximum allowed nesting depth

        Raises:
            ValidationError: If nesting exceeds maximum depth
        """
        if current_depth > max_depth:
            raise ValidationError("Object exceeds maximum allowed nesting depth")

        if isinstance(obj, dict):
            for val in obj.values():
                self._check_nesting_depth(val, current_depth + 1, max_depth)
        elif isinstance(obj, list):
            for item in obj:
                self._check_nesting_depth(item, current_depth + 1, max_depth)


class PaginationSchema(BaseSchema):
    """Schema for pagination parameters."""

    page = fields.Integer(
        validate=validate.Range(min=1, max=10000),
        missing=1
    )
    per_page = fields.Integer(
        validate=validate.Range(min=1, max=100),
        missing=20
    )
    sort_by = fields.String(missing="created_at")
    sort_direction = fields.String(
        validate=validate.OneOf(['asc', 'desc']),
        missing='desc'
    )

    @validates('sort_by')
    def validate_sort_field(self, value: str) -> None:
        """
        Validate sort field against allowed columns.

        Args:
            value: Field name to sort by

        Raises:
            ValidationError: If field is not allowed for sorting
        """
        # Define allowed sort fields - adjust based on your models
        allowed_sort_fields = {
            'id', 'username', 'email', 'created_at', 'updated_at',
            'last_login', 'role', 'status', 'name', 'title',
            'severity', 'category', 'type', 'environment'
        }

        if value not in allowed_sort_fields:
            raise ValidationError(f"Cannot sort by '{value}'. Allowed fields: {', '.join(sorted(allowed_sort_fields))}")


class DateRangeSchema(BaseSchema):
    """Schema for date range filtering."""

    start_date = fields.DateTime()
    end_date = fields.DateTime()

    @validates_schema
    def validate_date_range(self, data: Dict[str, Any], **kwargs) -> None:
        """
        Validate that start date is before end date.

        Args:
            data: The input data dictionary

        Raises:
            ValidationError: If start_date is after end_date or dates are too far in past/future
        """
        start_date = data.get('start_date')
        end_date = data.get('end_date')

        if start_date and end_date:
            if start_date > end_date:
                raise ValidationError("Start date must be before end date", "start_date")

        # Ensure dates are not too far in the past or future
        now = datetime.now(timezone.utc)
        max_past = now - timedelta(days=365*5)  # 5 years in the past
        max_future = now + timedelta(days=365)  # 1 year in the future

        if start_date and start_date < max_past:
            raise ValidationError("Start date cannot be more than 5 years in the past", "start_date")

        if end_date and end_date > max_future:
            raise ValidationError("End date cannot be more than 1 year in the future", "end_date")


# --- User Management Schemas ---

class UserCreateSchema(BaseSchema):
    """Schema for creating a new user."""

    username = fields.String(
        required=True,
        validate=[validate.Length(min=3, max=64)]
    )
    email = fields.Email(required=True)
    password = fields.String(
        required=True,
        validate=validate.Length(min=12, max=128)
    )
    first_name = fields.String(
        validate=validate.Length(max=64),
        missing=None
    )
    last_name = fields.String(
        validate=validate.Length(max=64),
        missing=None
    )
    role_id = fields.Integer(missing=None)
    is_active = fields.Boolean(missing=True)

    @validates('username')
    def validate_username(self, value: str) -> None:
        """
        Validate username format.

        Args:
            value: Username to validate

        Raises:
            ValidationError: If username format is invalid
        """
        if not is_valid_username(value):
            raise ValidationError(
                "Username must contain only letters, numbers, dots, hyphens, and underscores"
            )

    @validates('password')
    def validate_password(self, value: str) -> None:
        """
        Validate password strength.

        Args:
            value: Password to validate

        Raises:
            ValidationError: If password doesn't meet strength requirements
        """
        if not validate_password_strength(value):
            raise ValidationError(
                "Password must contain at least one uppercase letter, "
                "one lowercase letter, one number, and one special character"
            )


class UserUpdateSchema(BaseSchema):
    """Schema for updating an existing user."""

    email = fields.Email()
    first_name = fields.String(validate=validate.Length(max=64))
    last_name = fields.String(validate=validate.Length(max=64))
    is_active = fields.Boolean()


class UserRoleUpdateSchema(BaseSchema):
    """Schema for updating a user's role."""

    role_id = fields.Integer(required=True)
    reason = fields.String(
        required=True,
        validate=validate.Length(min=5, max=500)
    )


class PasswordResetSchema(BaseSchema):
    """Schema for resetting a user's password."""

    password = fields.String(
        required=True,
        validate=validate.Length(min=12, max=128)
    )
    force_change = fields.Boolean(missing=True)
    notify_user = fields.Boolean(missing=True)

    @validates('password')
    def validate_password(self, value: str) -> None:
        """
        Validate password strength.

        Args:
            value: Password to validate

        Raises:
            ValidationError: If password doesn't meet strength requirements
        """
        if not validate_password_strength(value):
            raise ValidationError(
                "Password must contain at least one uppercase letter, "
                "one lowercase letter, one number, and one special character"
            )


# --- System Configuration Schemas ---

class ConfigValueUpdateSchema(BaseSchema):
    """Schema for updating a configuration value."""

    value = fields.Raw(required=True)
    description = fields.String(validate=validate.Length(max=255))
    category = fields.String(validate=validate.Length(max=64))
    reason = fields.String(
        required=True,
        validate=validate.Length(min=5, max=500)
    )

    @validates('value')
    def validate_value_size(self, value: Any) -> None:
        """
        Validate that the value isn't too large.

        Args:
            value: Configuration value to validate

        Raises:
            ValidationError: If value is too large
        """
        # Convert to JSON string to check size
        import json
        try:
            json_str = json.dumps(value)
            if len(json_str) > 100000:  # 100KB limit
                raise ValidationError("Configuration value exceeds maximum allowed size")
        except (TypeError, OverflowError):
            raise ValidationError("Configuration value must be JSON serializable")


class ConfigFilterSchema(BaseSchema):
    """Schema for filtering configuration values."""

    category = fields.String()
    key = fields.String()
    search = fields.String()


class ConfigImportSchema(BaseSchema):
    """Schema for importing configuration values."""

    configs = fields.List(fields.Dict(), required=True)
    overwrite_existing = fields.Boolean(missing=False)
    validate_only = fields.Boolean(missing=False)
    reason = fields.String(
        required=True,
        validate=validate.Length(min=5, max=500)
    )

    @validates('configs')
    def validate_configs(self, value: List[Dict[str, Any]]) -> None:
        """
        Validate the configs list to prevent oversized imports.

        Args:
            value: List of configuration items

        Raises:
            ValidationError: If the import is too large or malformed
        """
        if len(value) > 1000:  # Limit to 1000 config items per import
            raise ValidationError("Config import exceeds maximum allowed size")

        for i, config in enumerate(value):
            # Validate required fields
            if 'key' not in config:
                raise ValidationError(f"Missing 'key' in config at index {i}")
            if 'value' not in config:
                raise ValidationError(f"Missing 'value' in config at index {i}")

            # Validate key format
            if not isinstance(config['key'], str):
                raise ValidationError(f"Key must be a string in config at index {i}")
            if len(config['key']) > 128:
                raise ValidationError(f"Key too long in config at index {i}")

            # Check for serialization issues
            try:
                import json
                json_str = json.dumps(config['value'])
                if len(json_str) > 100000:  # 100KB limit per value
                    raise ValidationError(f"Config value too large at index {i}")
            except (TypeError, OverflowError):
                raise ValidationError(f"Config value must be JSON serializable at index {i}")


# --- Audit and Reporting Schemas ---

class AuditFilterSchema(BaseSchema):
    """Schema for filtering audit logs."""

    start_date = fields.DateTime()
    end_date = fields.DateTime()
    user_id = fields.Integer()
    event_type = fields.String()
    severity = fields.String(
        validate=validate.OneOf(['critical', 'high', 'medium', 'low', 'info'])
    )
    category = fields.String()
    resource_type = fields.String()
    resource_id = fields.String()
    ip_address = fields.String()
    contains = fields.String()

    @validates_schema
    def validate_date_range(self, data: Dict[str, Any], **kwargs) -> None:
        """
        Validate that start date is before end date.

        Args:
            data: The input data dictionary

        Raises:
            ValidationError: If start_date is after end_date
        """
        start_date = data.get('start_date')
        end_date = data.get('end_date')

        if start_date and end_date and start_date > end_date:
            raise ValidationError("Start date must be before end date", "start_date")


class AuditExportSchema(BaseSchema):
    """Schema for exporting audit logs."""

    format = fields.String(
        required=True,
        validate=validate.OneOf(['json', 'csv', 'pdf'])
    )
    start_date = fields.DateTime(required=True)
    end_date = fields.DateTime(required=True)
    filters = fields.Dict(missing={})
    include_details = fields.Boolean(missing=True)
    max_records = fields.Integer(
        missing=10000,
        validate=validate.Range(min=1, max=50000)
    )

    @validates_schema
    def validate_date_range(self, data: Dict[str, Any], **kwargs) -> None:
        """
        Validate date range and limit.

        Args:
            data: The input data dictionary

        Raises:
            ValidationError: If date range is invalid or too large
        """
        start_date = data['start_date']
        end_date = data['end_date']

        if start_date > end_date:
            raise ValidationError("Start date must be before end date", "start_date")

        # Limit date range to prevent excessive exports
        if (end_date - start_date).days > 90:
            raise ValidationError("Date range cannot exceed 90 days", "end_date")

    @validates('filters')
    def validate_filters(self, value: Dict[str, Any]) -> None:
        """
        Validate filter structure.

        Args:
            value: Filters dictionary

        Raises:
            ValidationError: If filters are invalid
        """
        allowed_filter_keys = {
            'user_id', 'event_type', 'severity', 'category',
            'resource_type', 'resource_id', 'ip_address', 'contains'
        }

        for key in value:
            if key not in allowed_filter_keys:
                raise ValidationError(f"Unknown filter key: '{key}'")


class ComplianceReportSchema(BaseSchema):
    """Schema for generating compliance reports."""

    report_type = fields.String(
        required=True,
        validate=validate.OneOf([
            'pci-dss', 'hipaa', 'gdpr', 'iso27001',
            'soc2', 'nist', 'custom'
        ])
    )
    format = fields.String(
        required=True,
        validate=validate.OneOf(['json', 'csv', 'pdf'])
    )
    start_date = fields.DateTime(required=True)
    end_date = fields.DateTime(required=True)
    sections = fields.List(
        fields.String(),
        missing=None
    )
    include_evidence = fields.Boolean(missing=True)
    include_remediation = fields.Boolean(missing=True)
    include_exceptions = fields.Boolean(missing=True)

    @validates_schema
    def validate_date_range(self, data: Dict[str, Any], **kwargs) -> None:
        """
        Validate date range for the report.

        Args:
            data: The input data dictionary

        Raises:
            ValidationError: If date range is invalid
        """
        start_date = data['start_date']
        end_date = data['end_date']

        if start_date > end_date:
            raise ValidationError("Start date must be before end date", "start_date")

        # Compliance reports are typically quarterly or annual,
        # so we allow up to 1 year of data
        if (end_date - start_date).days > 366:
            raise ValidationError("Date range cannot exceed 1 year", "end_date")


# --- System Management Schemas ---

class SystemMaintenanceSchema(BaseSchema):
    """Schema for system maintenance operations."""

    operation = fields.String(
        required=True,
        validate=validate.OneOf([
            'clear_cache', 'vacuum_db', 'cleanup_logs',
            'rebuild_indexes', 'rotate_keys', 'system_scan'
        ])
    )
    parameters = fields.Dict(missing={})
    reason = fields.String(
        required=True,
        validate=validate.Length(min=5, max=500)
    )
    scheduled_time = fields.DateTime(missing=None)
    notify_users = fields.Boolean(missing=False)

    @validates('parameters')
    def validate_parameters(self, value: Dict[str, Any]) -> None:
        """
        Validate operation parameters.

        Args:
            value: Operation parameters

        Raises:
            ValidationError: If parameters are invalid or potentially dangerous
        """
        # Check for oversized parameters
        import json
        try:
            json_str = json.dumps(value)
            if len(json_str) > 10000:  # 10KB limit
                raise ValidationError("Parameters exceed maximum allowed size")
        except (TypeError, OverflowError):
            raise ValidationError("Parameters must be JSON serializable")

        # Check for potentially dangerous strings in parameters
        dangerous_patterns = [
            'exec', 'eval', 'system', 'popen', 'subprocess',
            'os.', 'import', 'open(', '__', 'child_process'
        ]

        serialized = str(value).lower()
        for pattern in dangerous_patterns:
            if pattern in serialized:
                raise ValidationError(f"Potentially unsafe pattern '{pattern}' in parameters")

        # Validate parameters based on operation
        if 'operation' in self.context:
            operation = self.context['operation']

            if operation == 'cleanup_logs':
                if 'days_to_keep' in value:
                    try:
                        days = int(value['days_to_keep'])
                        if days < 30:
                            raise ValidationError("Cannot retain logs for less than 30 days")
                        if days > 3650:  # 10 years
                            raise ValidationError("Log retention cannot exceed 10 years")
                    except (ValueError, TypeError):
                        raise ValidationError("days_to_keep must be a valid integer")

            elif operation == 'rebuild_indexes':
                if 'tables' in value and value['tables'] != ['all']:
                    if not isinstance(value['tables'], list):
                        raise ValidationError("tables must be a list or 'all'")

                    # Validate table names if provided
                    allowed_tables = {
                        'audit_logs', 'users', 'cloud_resources', 'security_incidents',
                        'user_sessions', 'user_activities', 'system_configs',
                        'file_uploads', 'ics_readings', 'alerts'
                    }

                    for table in value['tables']:
                        if not isinstance(table, str):
                            raise ValidationError("table names must be strings")
                        if table not in allowed_tables:
                            raise ValidationError(f"Unknown table: '{table}'")


class SystemHealthFilterSchema(BaseSchema):
    """Schema for filtering system health data."""

    components = fields.List(
        fields.String(
            validate=validate.OneOf([
                'cpu', 'memory', 'disk', 'network', 'database',
                'cache', 'api', 'worker', 'security'
            ])
        ),
        missing=None
    )
    interval = fields.String(
        validate=validate.OneOf(['1h', '6h', '24h', '7d', '30d']),
        missing='24h'
    )
    include_details = fields.Boolean(missing=False)


# --- Export schema instances ---

# Create schema instances for direct use in routes.py
user_create_schema = UserCreateSchema()
user_update_schema = UserUpdateSchema()
user_role_update_schema = UserRoleUpdateSchema()
password_reset_schema = PasswordResetSchema()

config_value_update_schema = ConfigValueUpdateSchema()
config_filter_schema = ConfigFilterSchema()
config_import_schema = ConfigImportSchema()

audit_filter_schema = AuditFilterSchema()
audit_export_schema = AuditExportSchema()
compliance_report_schema = ComplianceReportSchema()

system_maintenance_schema = SystemMaintenanceSchema()
system_health_filter_schema = SystemHealthFilterSchema()
pagination_schema = PaginationSchema()
