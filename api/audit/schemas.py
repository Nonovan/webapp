"""
Validation schemas for Audit API.

This module defines JSON schema and validation rules for the Audit API endpoints,
implementing careful validation of user input, proper error handling, and consistent
data formatting for responses.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Union
from marshmallow import Schema, fields, validate, validates, validates_schema, ValidationError, EXCLUDE

# --- Base Schema ---

class BaseSchema(Schema):
    """Base schema with common configuration for all schemas."""

    class Meta:
        # Exclude unknown fields by default for security
        unknown = EXCLUDE
        # Ensure consistent field ordering in output
        ordered = True

# --- Audit Log Schemas ---

class AuditLogSchema(BaseSchema):
    """Schema for individual audit log serialization."""

    id = fields.Integer(dump_only=True)
    event_type = fields.String(dump_only=True)
    description = fields.String(dump_only=True)
    user_id = fields.Integer(dump_only=True, allow_none=True)
    ip_address = fields.String(dump_only=True, allow_none=True)
    user_agent = fields.String(dump_only=True, allow_none=True)
    severity = fields.String(dump_only=True)
    category = fields.String(dump_only=True, allow_none=True)
    details = fields.Dict(dump_only=True, allow_none=True)
    object_type = fields.String(dump_only=True, allow_none=True)
    object_id = fields.Integer(dump_only=True, allow_none=True)
    related_type = fields.String(dump_only=True, allow_none=True)
    related_id = fields.Integer(dump_only=True, allow_none=True)
    created_at = fields.DateTime(dump_only=True)

    # Optional enriched fields that may be added during processing
    username = fields.String(dump_only=True)

# --- Filter Schemas ---

class AuditFilterSchema(BaseSchema):
    """Schema for validating audit log filter parameters."""

    start_date = fields.DateTime()
    end_date = fields.DateTime()
    user_id = fields.Integer()
    username = fields.String(validate=validate.Length(min=1, max=100))
    event_type = fields.String(validate=validate.Length(min=1, max=100))
    severity = fields.String(validate=validate.OneOf(['critical', 'high', 'warning', 'info']))
    category = fields.String(validate=validate.Length(min=1, max=50))
    object_type = fields.String(validate=validate.Length(min=1, max=100))
    object_id = fields.String(validate=validate.Length(min=1, max=100))
    ip_address = fields.String(validate=validate.Length(min=1, max=45))
    contains = fields.String(validate=validate.Length(min=1, max=255))

    @validates_schema
    def validate_date_range(self, data, **kwargs):
        """Validate that start_date is before end_date if both are provided."""
        start_date = data.get('start_date')
        end_date = data.get('end_date')

        if start_date and end_date and start_date > end_date:
            raise ValidationError("start_date must be before end_date")

        # Check for excessive date ranges
        if start_date and end_date:
            max_range_days = 366  # Limit to 1 year by default
            if (end_date - start_date).days > max_range_days:
                raise ValidationError(f"Date range exceeds maximum allowed ({max_range_days} days)")

# --- Export Schema ---

class ExportSchema(BaseSchema):
    """Schema for validating audit log export requests."""

    format = fields.String(required=True, validate=validate.OneOf(['json', 'csv', 'pdf']))
    start_date = fields.String()
    end_date = fields.String()
    filters = fields.Dict()

    @validates('filters')
    def validate_filters(self, value):
        """Validate filter structure if provided."""
        # Skip if empty
        if not value:
            return

        # Validate that filters use known keys
        allowed_keys = {
            'user_id', 'username', 'event_type', 'severity',
            'category', 'object_type', 'object_id', 'ip_address', 'contains'
        }

        for key in value:
            if key not in allowed_keys:
                raise ValidationError(f"Unknown filter key: {key}")

    @validates_schema
    def validate_date_format(self, data, **kwargs):
        """Validate date string format if provided."""
        for date_field in ['start_date', 'end_date']:
            if date_field in data and data[date_field]:
                try:
                    # Attempt to parse the date
                    date_str = data[date_field]
                    datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                except ValueError:
                    raise ValidationError(f"Invalid date format for {date_field}. Use ISO 8601 format.")

# --- Compliance Report Schema ---

class ComplianceReportSchema(BaseSchema):
    """Schema for validating compliance report generation requests."""

    report_type = fields.String(required=True, validate=validate.Length(min=1, max=50))
    format = fields.String(required=True, validate=validate.OneOf(['json', 'csv', 'pdf']))
    start_date = fields.String()
    end_date = fields.String()
    include_sections = fields.List(fields.String(), validate=validate.Length(max=100))

    @validates('report_type')
    def validate_report_type(self, value):
        """Validate report type is lowercase and hyphenated."""
        if not value.islower() or ' ' in value:
            raise ValidationError("report_type should be lowercase and hyphenated, e.g., 'pci-dss'")

    @validates_schema
    def validate_date_format(self, data, **kwargs):
        """Validate date string format if provided."""
        for date_field in ['start_date', 'end_date']:
            if date_field in data and data[date_field]:
                try:
                    # Attempt to parse the date
                    date_str = data[date_field]
                    datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                except ValueError:
                    raise ValidationError(f"Invalid date format for {date_field}. Use ISO 8601 format.")

# --- Security Report Schema ---

class SecurityReportSchema(BaseSchema):
    """Schema for validating security report generation requests."""

    report_type = fields.String(required=True, validate=validate.OneOf([
        'general', 'access_control', 'authentication', 'data_access',
        'system_events', 'authorization', 'security_incidents'
    ]))
    format = fields.String(required=True, validate=validate.OneOf(['json', 'csv', 'pdf']))
    start_date = fields.String()
    end_date = fields.String()
    focus_areas = fields.List(fields.String(), validate=validate.Length(max=20))

    @validates_schema
    def validate_date_format(self, data, **kwargs):
        """Validate date string format if provided."""
        for date_field in ['start_date', 'end_date']:
            if date_field in data and data[date_field]:
                try:
                    # Attempt to parse the date
                    date_str = data[date_field]
                    datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                except ValueError:
                    raise ValidationError(f"Invalid date format for {date_field}. Use ISO 8601 format.")

# --- Advanced Search Schema ---

class AdvancedSearchSchema(BaseSchema):
    """Schema for validating advanced search requests."""

    query = fields.Dict(required=True)
    page = fields.Integer(missing=1, validate=validate.Range(min=1, max=1000))
    per_page = fields.Integer(missing=50, validate=validate.Range(min=1, max=100))

    @validates('query')
    def validate_query_structure(self, value):
        """Validate the advanced search query structure."""
        # Ensure the query isn't empty
        if not value:
            raise ValidationError("Search query cannot be empty")

        # Validate known query parameters
        if 'time_range' in value:
            time_range = value['time_range']
            if not isinstance(time_range, dict):
                raise ValidationError("time_range must be an object")

            if 'start' in time_range:
                try:
                    datetime.fromisoformat(time_range['start'].replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    raise ValidationError("Invalid start date format in time_range")

            if 'end' in time_range:
                try:
                    datetime.fromisoformat(time_range['end'].replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    raise ValidationError("Invalid end date format in time_range")

# --- Event Correlation Schema ---

class EventCorrelationSchema(BaseSchema):
    """Schema for validating event correlation requests."""

    event_id = fields.Integer(required=True, validate=validate.Range(min=1))
    time_window = fields.Integer(missing=30, validate=validate.Range(min=1, max=1440))  # max 24 hours
    related_types = fields.List(fields.String(), validate=validate.Length(max=20))

# --- Dashboard Schema ---

class DashboardSchema(BaseSchema):
    """Schema for validating dashboard requests."""

    period = fields.String(missing='7d', validate=validate.OneOf(['24h', '7d', '30d', '90d', '365d']))

# --- Create Schema Instances ---

# Individual audit log schema
audit_log_schema = AuditLogSchema()
# Schema for a list of audit logs
audit_logs_schema = AuditLogSchema(many=True)
# Schema for filtering audit logs
audit_filter_schema = AuditFilterSchema()
# Schema for exporting audit logs
export_schema = ExportSchema()
# Schema for generating compliance reports
compliance_report_schema = ComplianceReportSchema()
# Schema for generating security reports
security_report_schema = SecurityReportSchema()
# Schema for advanced search
advanced_search_schema = AdvancedSearchSchema()
# Schema for event correlation
event_correlation_schema = EventCorrelationSchema()
# Schema for dashboard data
dashboard_schema = DashboardSchema()
