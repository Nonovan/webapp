"""
Core schema definitions for data validation across the application.

This module provides base schema classes and utilities for consistent data
validation throughout the Cloud Infrastructure Platform. It implements common
validation patterns, custom field types, and security-focused validation rules.
"""

import logging
import re
import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union, Tuple

from marshmallow import (
    Schema, fields, validate, validates, validates_schema,
    ValidationError, pre_load, post_load, EXCLUDE
)

# Initialize module logger
logger = logging.getLogger(__name__)

# --- Base Schema Classes ---

class BaseSchema(Schema):
    """
    Base schema with common settings and security-focused validation patterns.

    This schema provides foundational behaviors for all schemas in the system:
    - Excludes unknown fields to prevent data injection attacks
    - Implements sanitization hooks for input data
    - Provides common utility methods for validation
    """
    class Meta:
        # Default behavior: exclude unknown fields for security
        unknown = EXCLUDE
        # Ensure ordered output for consistent API responses
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

    def validate_string_security(self, value: str, field_name: str) -> None:
        """
        Validate a string field for common security issues.

        Args:
            value: String value to validate
            field_name: Name of the field for error messages

        Raises:
            ValidationError: If the string contains potentially malicious content
        """
        if not value:
            return

        # Check for potential XSS or injection patterns
        dangerous_patterns = [
            r'<script', r'javascript:', r'onerror=', r'onclick=',
            r'eval\(', r'document\.', r'window\.', r'\balert\(',
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValidationError(f"Value contains potentially unsafe content", field_name)


class PaginationSchema(BaseSchema):
    """
    Schema for standardized pagination parameters.

    This schema handles pagination parameters consistently across all API endpoints
    that return collections, with secure defaults and validation.
    """
    page = fields.Int(missing=1, validate=validate.Range(min=1, max=10000))
    per_page = fields.Int(missing=20, validate=validate.Range(min=1, max=100))
    sort_by = fields.Str(missing='created_at')
    sort_direction = fields.Str(
        missing='desc',
        validate=validate.OneOf(['asc', 'desc'])
    )

    @validates('sort_by')
    def validate_sort_field(self, value: str) -> None:
        """
        Validate sort field to prevent SQL injection via sorting parameters.

        Args:
            value: Sort field name

        Raises:
            ValidationError: If the field contains SQL injection attempts
        """
        # Only allow alphanumeric characters and underscores
        if not re.match(r'^[a-zA-Z0-9_]+$', value):
            raise ValidationError("Sort field can only contain alphanumeric characters and underscores")

        # Additional security check - prevent common SQL injection patterns
        dangerous_sort_patterns = [
            'delete', 'insert', 'update', 'drop', 'select', 'union', '--'
        ]

        if any(pattern in value.lower() for pattern in dangerous_sort_patterns):
            raise ValidationError("Invalid sort field")


class DateRangeSchema(BaseSchema):
    """Schema mixin for date range filtering."""
    start_date = fields.DateTime()
    end_date = fields.DateTime()

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

        # Ensure dates are not too far in the past or future
        now = datetime.now(timezone.utc)
        max_future = datetime(now.year + 10, now.month, now.day, tzinfo=timezone.utc)

        if end_date and end_date > max_future:
            raise ValidationError("End date cannot be more than 10 years in the future", "end_date")


# --- Custom Field Types ---

class SanitizedString(fields.String):
    """String field that sanitizes input to prevent XSS and injection attacks."""

    def _deserialize(self, value: Any, attr: str, data: Dict[str, Any], **kwargs) -> str:
        """
        Deserialize and sanitize string input.

        Args:
            value: Input value
            attr: Field name
            data: Full input data

        Returns:
            Sanitized string value
        """
        result = super()._deserialize(value, attr, data, **kwargs)
        if result:
            # Basic sanitization
            result = result.strip()

            # Replace potentially dangerous characters
            dangerous_chars = {
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#x27;',
                '/': '&#x2F;'
            }

            for char, replacement in dangerous_chars.items():
                result = result.replace(char, replacement)

        return result


class IPAddressField(fields.String):
    """Field for validating IP addresses."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize with IP version validation."""
        self.ip_version = kwargs.pop('ip_version', None)  # 4, 6, or None for both
        super().__init__(*args, **kwargs)

    def _deserialize(self, value: Any, attr: str, data: Dict[str, Any], **kwargs) -> str:
        """
        Deserialize and validate IP address.

        Args:
            value: Input value
            attr: Field name
            data: Full input data

        Returns:
            Validated IP address string

        Raises:
            ValidationError: If input is not a valid IP address
        """
        if value is None:
            return None

        result = super()._deserialize(value, attr, data, **kwargs)

        try:
            ip = ipaddress.ip_address(result)

            if self.ip_version == 4 and not isinstance(ip, ipaddress.IPv4Address):
                raise ValidationError("Not a valid IPv4 address")
            elif self.ip_version == 6 and not isinstance(ip, ipaddress.IPv6Address):
                raise ValidationError("Not a valid IPv6 address")

        except ValueError:
            raise ValidationError("Not a valid IP address")

        return result


class CVEField(fields.String):
    """Field for validating CVE IDs with proper format."""

    def _deserialize(self, value: Any, attr: str, data: Dict[str, Any], **kwargs) -> str:
        """
        Deserialize and validate CVE ID format.

        Args:
            value: Input value
            attr: Field name
            data: Full input data

        Returns:
            Validated CVE ID string

        Raises:
            ValidationError: If input is not a valid CVE ID format
        """
        result = super()._deserialize(value, attr, data, **kwargs)

        # Validate CVE format (CVE-YEAR-DIGITS where YEAR is 4 digits and DIGITS is 4+ digits)
        if not re.match(r'^CVE-\d{4}-\d{4,}$', result):
            raise ValidationError("Not a valid CVE ID format (should be CVE-YYYY-NNNNN...)")

        return result


# --- Security-Related Schemas ---

class SecurityEventSchema(BaseSchema):
    """Schema for security events in the system."""

    event_type = fields.String(required=True)
    severity = fields.String(
        required=True,
        validate=validate.OneOf(['critical', 'high', 'medium', 'low', 'info'])
    )
    source = fields.String(required=True)
    description = fields.String(required=True)
    details = fields.Dict(missing={})
    ip_address = IPAddressField()
    user_agent = fields.String()
    user_id = fields.Integer(allow_none=True)
    resource_id = fields.String(allow_none=True)
    resource_type = fields.String(allow_none=True)
    timestamp = fields.DateTime(missing=lambda: datetime.now(timezone.utc))

    @validates('details')
    def validate_details(self, value: Dict[str, Any]) -> None:
        """
        Validate the details dictionary to prevent oversized objects.

        Args:
            value: Details dictionary to validate

        Raises:
            ValidationError: If the details are too large or complex
        """
        # Prevent DoS by limiting the size of the details object
        serialized = str(value)
        if len(serialized) > 10000:  # Limit to 10KB
            raise ValidationError("Security event details exceed maximum allowed size")

        # Limit nesting depth to prevent complex objects that could cause
        # performance issues when processing
        self._check_nesting_depth(value)

    def _check_nesting_depth(self, obj: Any, current_depth: int = 0, max_depth: int = 5) -> None:
        """
        Check the nesting depth of an object to prevent DoS attacks.

        Args:
            obj: Object to check
            current_depth: Current nesting depth
            max_depth: Maximum allowed nesting depth

        Raises:
            ValidationError: If the nesting depth exceeds the maximum
        """
        if current_depth > max_depth:
            raise ValidationError("Security event details exceed maximum allowed nesting depth")

        if isinstance(obj, dict):
            for val in obj.values():
                self._check_nesting_depth(val, current_depth + 1, max_depth)
        elif isinstance(obj, list):
            for item in obj:
                self._check_nesting_depth(item, current_depth + 1, max_depth)


class SecurityConfigSchema(BaseSchema):
    """Schema for security configuration validation."""

    file_integrity_enabled = fields.Boolean(required=True)
    file_hash_algorithm = fields.String(
        validate=validate.OneOf(['sha256', 'sha512']),
        missing='sha256'
    )
    audit_log_retention_days = fields.Integer(
        validate=validate.Range(min=30, max=3650),  # 30 days to 10 years
        missing=90
    )
    session_timeout_minutes = fields.Integer(
        validate=validate.Range(min=5, max=1440),  # 5 minutes to 24 hours
        missing=60
    )
    password_expiry_days = fields.Integer(
        validate=validate.Range(min=0, max=365),  # 0 = never expire
        missing=90
    )
    max_failed_logins = fields.Integer(
        validate=validate.Range(min=3, max=10),
        missing=5
    )
    mfa_required = fields.Boolean(missing=True)
    api_rate_limit = fields.String(missing="100 per minute")
    sensitive_data_encryption = fields.Boolean(missing=True)

    @validates('api_rate_limit')
    def validate_rate_limit(self, value: str) -> None:
        """
        Validate rate limit format.

        Args:
            value: Rate limit string to validate

        Raises:
            ValidationError: If the rate limit format is invalid
        """
        if not re.match(r'^\d+ per (second|minute|hour|day)$', value):
            raise ValidationError("Rate limit must be in format 'N per [second|minute|hour|day]'")


# Export schema instances for direct use
security_event_schema = SecurityEventSchema()
security_config_schema = SecurityConfigSchema()
pagination_schema = PaginationSchema()

logger.debug("Core schemas initialized")
