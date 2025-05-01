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


class FileIntegrityBaselineSchema(BaseSchema):
    """Schema for file integrity baseline operations."""

    path = fields.String(required=True)
    current_hash = fields.String(required=True)
    expected_hash = fields.String(allow_none=True)
    status = fields.String(
        validate=validate.OneOf(['intact', 'modified', 'missing', 'error']),
        required=True
    )
    severity = fields.String(
        validate=validate.OneOf(['critical', 'high', 'medium', 'low', 'info']),
        missing='medium'
    )
    timestamp = fields.DateTime(missing=lambda: datetime.now(timezone.utc))

    @validates('path')
    def validate_path(self, value: str) -> None:
        """
        Validate file path to prevent path traversal attempts.

        Args:
            value: File path to validate

        Raises:
            ValidationError: If path contains suspicious patterns
        """
        # Check for path traversal attempts
        if '..' in value or value.startswith('/') or '~' in value:
            raise ValidationError("Path contains potentially unsafe patterns")

        # Check path length to prevent DoS
        if len(value) > 512:
            raise ValidationError("Path exceeds maximum allowed length")


class BaselineUpdateSchema(BaseSchema):
    """Schema for baseline update operations."""

    changes = fields.List(fields.Nested(FileIntegrityBaselineSchema), required=True)
    remove_missing = fields.Boolean(missing=False)
    auto_update_limit = fields.Integer(
        validate=validate.Range(min=1, max=100),
        missing=10
    )

    @validates('changes')
    def validate_changes(self, value: List[Dict[str, Any]]) -> None:
        """
        Validate the changes list to prevent oversized updates.

        Args:
            value: List of file changes

        Raises:
            ValidationError: If the changes list is too large
        """
        if len(value) > 1000:  # Reasonable upper limit
            raise ValidationError("Changes list exceeds maximum allowed size")


# Define scan schemas after the FileIntegrityBaselineSchema class
class ScanFilterSchema(BaseSchema):
    """Schema for filtering security scans."""

    scan_type = fields.String(
        validate=validate.OneOf(['vulnerability', 'compliance', 'configuration',
                                 'web_application', 'network', 'container',
                                 'code', 'security_posture', 'penetration', 'iam']),
        missing=None
    )
    status = fields.String(
        validate=validate.OneOf(['pending', 'scheduled', 'in_progress', 'completed',
                                 'failed', 'canceled', 'error']),
        missing=None
    )
    target_id = fields.String(missing=None)
    profile = fields.String(missing=None)
    priority = fields.String(
        validate=validate.OneOf(['critical', 'high', 'medium', 'low']),
        missing=None
    )
    created_after = fields.DateTime(missing=None)
    created_before = fields.DateTime(missing=None)
    completed_after = fields.DateTime(missing=None)
    completed_before = fields.DateTime(missing=None)
    created_by_id = fields.Integer(missing=None)

    @validates_schema
    def validate_date_ranges(self, data, **kwargs):
        """Validate date ranges are logically correct."""
        # Validate created date range
        if data.get('created_after') and data.get('created_before'):
            if data['created_after'] > data['created_before']:
                raise ValidationError("created_after must be before created_before")

        # Validate completed date range
        if data.get('completed_after') and data.get('completed_before'):
            if data['completed_after'] > data['completed_before']:
                raise ValidationError("completed_after must be before completed_before")


class ScanCreateSchema(BaseSchema):
    """Schema for creating security scans."""

    scan_type = fields.String(
        required=True,
        validate=validate.OneOf(['vulnerability', 'compliance', 'configuration',
                                 'web_application', 'network', 'container',
                                 'code', 'security_posture', 'penetration', 'iam'])
    )
    profile = fields.String(validate=validate.Length(min=1, max=100))
    targets = fields.List(fields.Dict(), required=True, validate=validate.Length(min=1))
    options = fields.Dict(missing={})
    scheduled_for = fields.DateTime()
    priority = fields.String(
        validate=validate.OneOf(['critical', 'high', 'medium', 'low']),
        missing='medium'
    )
    notes = fields.String(validate=validate.Length(max=1000))

    @validates('targets')
    def validate_targets(self, targets):
        """Validate scan targets are properly structured."""
        if not isinstance(targets, list) or len(targets) == 0:
            raise ValidationError("At least one target must be specified")

        for target in targets:
            if not isinstance(target, dict):
                raise ValidationError("Each target must be a dictionary")

            if 'target_id' not in target:
                raise ValidationError("Each target must contain a target_id")

            if target.get('target_type') not in ('host', 'network', 'container', 'cloud_resource',
                                              'application', 'repository', None):
                raise ValidationError("Invalid target_type")

    @validates('options')
    def validate_options(self, options):
        """Validate scan options for security and integrity."""
        # Check for oversized options object
        serialized = str(options)
        if len(serialized) > 10000:  # Limit to 10KB
            raise ValidationError("Scan options exceed maximum allowed size")

        # Check for potentially dangerous options
        dangerous_keys = ['exec', 'script', 'command', 'shell', 'bypass']
        if any(key in str(options).lower() for key in dangerous_keys):
            raise ValidationError("Options contain potentially unsafe patterns")


class ScanUpdateSchema(BaseSchema):
    """Schema for updating security scans."""

    status = fields.String(
        validate=validate.OneOf(['canceled', 'scheduled', 'pending'])
    )
    scheduled_for = fields.DateTime()
    notes = fields.String(validate=validate.Length(max=1000))
    priority = fields.String(
        validate=validate.OneOf(['critical', 'high', 'medium', 'low'])
    )
    options = fields.Dict()

    @validates('options')
    def validate_options(self, options):
        """Validate scan options for security and integrity."""
        # Check for oversized options object
        serialized = str(options)
        if len(serialized) > 10000:  # Limit to 10KB
            raise ValidationError("Scan options exceed maximum allowed size")


class ScanResultSchema(BaseSchema):
    """Schema for updating security scan results."""

    status = fields.String(
        required=True,
        validate=validate.OneOf(['in_progress', 'completed', 'failed', 'error'])
    )
    findings_count = fields.Integer(missing=0, validate=validate.Range(min=0))
    critical_count = fields.Integer(missing=0, validate=validate.Range(min=0))
    high_count = fields.Integer(missing=0, validate=validate.Range(min=0))
    medium_count = fields.Integer(missing=0, validate=validate.Range(min=0))
    low_count = fields.Integer(missing=0, validate=validate.Range(min=0))
    info_count = fields.Integer(missing=0, validate=validate.Range(min=0))
    findings_summary = fields.Dict(missing={})
    error_message = fields.String()
    performance_metrics = fields.Dict(missing={})
    end_time = fields.DateTime()
    duration_seconds = fields.Float(validate=validate.Range(min=0))

    @validates('findings_summary')
    def validate_findings_summary(self, value):
        """Validate findings summary for size and structure."""
        # Prevent DoS with large objects
        serialized = str(value)
        if len(serialized) > 50000:  # Limit to 50KB
            raise ValidationError("Findings summary exceeds maximum allowed size")


class FindingSchema(BaseSchema):
    """Schema for individual security scan findings."""

    title = fields.String(required=True, validate=validate.Length(min=5, max=200))
    description = fields.String(required=True)
    scan_id = fields.Integer(required=True)
    severity = fields.String(
        required=True,
        validate=validate.OneOf(['critical', 'high', 'medium', 'low', 'info'])
    )
    finding_type = fields.String(required=True)
    target_id = fields.String(required=True)
    status = fields.String(
        missing='open',
        validate=validate.OneOf(['open', 'in_progress', 'resolved', 'false_positive', 'risk_accepted'])
    )
    details = fields.Dict(missing={})
    affected_resources = fields.List(fields.Dict(), missing=[])
    remediation_steps = fields.String()
    cvss_score = fields.Float(validate=validate.Range(min=0, max=10))
    cvss_vector = fields.String()
    references = fields.List(fields.String(), missing=[])

    @validates('details')
    def validate_details(self, value):
        """Validate details dictionary to prevent DoS."""
        serialized = str(value)
        if len(serialized) > 20000:  # Limit to 20KB
            raise ValidationError("Finding details exceed maximum allowed size")

        # Check nesting depth to prevent complex objects
        self._check_nesting_depth(value)

    def _check_nesting_depth(self, obj, current_depth=0, max_depth=5):
        """Check object nesting depth to prevent DoS attacks."""
        if current_depth > max_depth:
            raise ValidationError("Finding details exceed maximum allowed nesting depth")

        if isinstance(obj, dict):
            for val in obj.values():
                self._check_nesting_depth(val, current_depth + 1, max_depth)
        elif isinstance(obj, list):
            for item in obj:
                self._check_nesting_depth(item, current_depth + 1, max_depth)


# --- Vulnerability Schemas ---

class VulnerabilitySchema(BaseSchema):
    """Schema for vulnerability serialization."""

    id = fields.Integer(dump_only=True)
    title = fields.String(required=True, validate=validate.Length(min=5, max=200))
    description = fields.String(required=True)
    cve_id = fields.String(validate=validate.Length(max=20))
    cvss_score = fields.Float(validate=validate.Range(min=0, max=10))
    cvss_vector = fields.String(validate=validate.Length(max=100))
    severity = fields.String(
        validate=validate.OneOf(['critical', 'high', 'medium', 'low', 'info']),
        missing='medium'
    )
    status = fields.String(
        validate=validate.OneOf(['open', 'in_progress', 'resolved', 'verified',
                                'closed', 'duplicate', 'false_positive',
                                'risk_accepted', 'wont_fix']),
        missing='open'
    )
    affected_resources = fields.List(fields.Dict(), missing=[])
    remediation_steps = fields.String()
    exploit_available = fields.Boolean(missing=False)
    exploited_in_wild = fields.Boolean(missing=False)
    vulnerability_type = fields.String(
        validate=validate.OneOf(['code', 'configuration', 'infrastructure',
                                'network', 'platform', 'software',
                                'third_party', 'web_application', 'other'])
    )
    asset_criticality = fields.String(
        validate=validate.OneOf(['critical', 'high', 'medium', 'low']),
        missing='medium'
    )
    remediation_deadline = fields.DateTime()
    discovered_at = fields.DateTime()
    resolved_at = fields.DateTime(dump_only=True)
    verified_at = fields.DateTime(dump_only=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)
    reported_by_id = fields.Integer(allow_none=True)
    assigned_to_id = fields.Integer(allow_none=True)
    verified_by_id = fields.Integer(allow_none=True)
    resolution_summary = fields.String()
    risk_score = fields.Float(dump_only=True)
    detection_source = fields.String()
    tags = fields.List(fields.String(), missing=[])
    external_references = fields.List(fields.Dict(), missing=[])

    @validates('cvss_vector')
    def validate_cvss_vector(self, value):
        """Validate CVSS vector format."""
        if value:
            # Simplified CVSS v3 vector validation
            cvss_v3_pattern = r'^CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]'
            # Simplified CVSS v2 vector validation
            cvss_v2_pattern = r'^(AV:[LAN]/AC:[LMH]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC])'

            if not (re.match(cvss_v3_pattern, value) or re.match(cvss_v2_pattern, value)):
                raise ValidationError("Invalid CVSS vector format")


class VulnerabilityCreateSchema(VulnerabilitySchema):
    """Schema for creating vulnerabilities."""

    @validates('affected_resources')
    def validate_affected_resources(self, resources):
        """Validate affected resources format."""
        if not isinstance(resources, list):
            raise ValidationError("Affected resources must be a list")

        for resource in resources:
            if not isinstance(resource, dict):
                raise ValidationError("Each resource must be a dictionary")

            if 'type' not in resource or 'id' not in resource:
                raise ValidationError("Each resource must have 'type' and 'id' fields")

    @validates_schema
    def validate_cvss_and_severity(self, data, **kwargs):
        """Ensure CVSS score and severity are consistent if both provided."""
        if 'cvss_score' in data and 'severity' in data:
            expected_severity = None

            if data['cvss_score'] >= 9.0:
                expected_severity = 'critical'
            elif data['cvss_score'] >= 7.0:
                expected_severity = 'high'
            elif data['cvss_score'] >= 4.0:
                expected_severity = 'medium'
            elif data['cvss_score'] > 0.0:
                expected_severity = 'low'
            else:
                expected_severity = 'info'

            if data['severity'] != expected_severity:
                logger.warning(f"Provided severity '{data['severity']}' doesn't match expected '{expected_severity}' for CVSS score {data['cvss_score']}")


class VulnerabilityUpdateSchema(BaseSchema):
    """Schema for updating vulnerabilities."""

    title = fields.String(validate=validate.Length(min=5, max=200))
    description = fields.String()
    cvss_score = fields.Float(validate=validate.Range(min=0, max=10))
    cvss_vector = fields.String(validate=validate.Length(max=100))
    severity = fields.String(validate=validate.OneOf(['critical', 'high', 'medium', 'low', 'info']))
    status = fields.String(
        validate=validate.OneOf(['open', 'in_progress', 'resolved', 'verified',
                                'closed', 'duplicate', 'false_positive',
                                'risk_accepted', 'wont_fix'])
    )
    affected_resources = fields.List(fields.Dict())
    remediation_steps = fields.String()
    exploit_available = fields.Boolean()
    exploited_in_wild = fields.Boolean()
    vulnerability_type = fields.String(
        validate=validate.OneOf(['code', 'configuration', 'infrastructure',
                                'network', 'platform', 'software',
                                'third_party', 'web_application', 'other'])
    )
    asset_criticality = fields.String(validate=validate.OneOf(['critical', 'high', 'medium', 'low']))
    remediation_deadline = fields.DateTime()
    assigned_to_id = fields.Integer(allow_none=True)
    resolution_summary = fields.String()
    tags = fields.List(fields.String())
    external_references = fields.List(fields.Dict())

    @validates('cvss_vector')
    def validate_cvss_vector(self, value):
        """Validate CVSS vector format."""
        if value:
            # Simplified CVSS v3 vector validation
            cvss_v3_pattern = r'^CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]'
            # Simplified CVSS v2 vector validation
            cvss_v2_pattern = r'^(AV:[LAN]/AC:[LMH]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC])'

            if not (re.match(cvss_v3_pattern, value) or re.match(cvss_v2_pattern, value)):
                raise ValidationError("Invalid CVSS vector format")

    @validates('affected_resources')
    def validate_affected_resources(self, resources):
        """Validate affected resources format."""
        if not isinstance(resources, list):
            raise ValidationError("Affected resources must be a list")

        for resource in resources:
            if not isinstance(resource, dict):
                raise ValidationError("Each resource must be a dictionary")

            if 'type' not in resource or 'id' not in resource:
                raise ValidationError("Each resource must have 'type' and 'id' fields")


class VulnerabilityFilterSchema(BaseSchema):
    """Schema for filtering vulnerabilities."""

    # Pagination parameters
    page = fields.Integer(missing=1, validate=validate.Range(min=1, max=1000))
    per_page = fields.Integer(missing=20, validate=validate.Range(min=1, max=100))
    sort_by = fields.String(missing='created_at')
    sort_direction = fields.String(
        missing='desc',
        validate=validate.OneOf(['asc', 'desc'])
    )

    # Filter parameters
    severity = fields.String(validate=validate.OneOf(['critical', 'high', 'medium', 'low', 'info']))
    status = fields.String(validate=validate.OneOf(
        ['open', 'in_progress', 'resolved', 'verified', 'closed',
         'duplicate', 'false_positive', 'risk_accepted', 'wont_fix']
    ))
    vulnerability_type = fields.String()
    cve_id = fields.String()
    reported_by_id = fields.Integer()
    assigned_to_id = fields.Integer()
    asset_criticality = fields.String(validate=validate.OneOf(['critical', 'high', 'medium', 'low']))
    exploit_available = fields.Boolean()
    exploited_in_wild = fields.Boolean()
    search = fields.String()
    tags = fields.List(fields.String())
    resource_type = fields.String()
    resource_id = fields.String()
    discovery_start_date = fields.DateTime()
    discovery_end_date = fields.DateTime()
    is_overdue = fields.Boolean()

    @validates('sort_by')
    def validate_sort_field(self, value):
        """Validate sort field is a valid vulnerability field."""
        valid_sort_fields = [
            'id', 'created_at', 'updated_at', 'discovered_at', 'resolved_at',
            'severity', 'cvss_score', 'remediation_deadline', 'risk_score',
            'status', 'title'
        ]

        if value not in valid_sort_fields:
            raise ValidationError(f"Invalid sort field. Valid options: {', '.join(valid_sort_fields)}")

    @validates_schema
    def validate_date_ranges(self, data, **kwargs):
        """Validate date ranges are logically correct."""
        if data.get('discovery_start_date') and data.get('discovery_end_date'):
            if data['discovery_start_date'] > data['discovery_end_date']:
                raise ValidationError("discovery_start_date must be before discovery_end_date")


class VulnerabilityBulkUpdateSchema(BaseSchema):
    """Schema for bulk vulnerability updates."""

    ids = fields.List(fields.Integer(), required=True, validate=validate.Length(min=1, max=1000))
    data = fields.Dict(required=True)

    @validates('data')
    def validate_update_data(self, value):
        """Validate bulk update data."""
        if not value:
            raise ValidationError("Update data cannot be empty")

        valid_fields = {
            'severity', 'status', 'vulnerability_type', 'asset_criticality',
            'remediation_deadline', 'assigned_to_id', 'exploited_in_wild',
            'exploit_available', 'resolution_summary'
        }

        invalid_fields = set(value.keys()) - valid_fields
        if invalid_fields:
            raise ValidationError(f"Invalid update fields: {', '.join(invalid_fields)}")

        # Validate specific field values
        if 'severity' in value:
            if value['severity'] not in ['critical', 'high', 'medium', 'low', 'info']:
                raise ValidationError("Invalid severity value")

        if 'status' in value:
            valid_statuses = ['open', 'in_progress', 'resolved', 'verified', 'closed',
                             'duplicate', 'false_positive', 'risk_accepted', 'wont_fix']
            if value['status'] not in valid_statuses:
                raise ValidationError(f"Invalid status value. Must be one of: {', '.join(valid_statuses)}")

        if 'vulnerability_type' in value:
            valid_types = ['code', 'configuration', 'infrastructure', 'network',
                          'platform', 'software', 'third_party', 'web_application', 'other']
            if value['vulnerability_type'] not in valid_types:
                raise ValidationError(f"Invalid vulnerability type. Must be one of: {', '.join(valid_types)}")


# --- Threat Intelligence Schemas ---

class ThreatIndicatorSchema(BaseSchema):
    """Schema for threat indicator (IOC) serialization."""

    id = fields.Integer(dump_only=True)
    indicator_type = fields.String(
        required=True,
        validate=validate.OneOf([
            'ip', 'domain', 'url', 'file_hash', 'email', 'user_agent',
            'file_path', 'registry_key', 'mutex', 'process_name', 'other'
        ])
    )
    value = fields.String(required=True, validate=validate.Length(min=2, max=500))
    description = fields.String(validate=validate.Length(max=1000))
    source = fields.String(validate=validate.Length(max=100))
    severity = fields.String(
        validate=validate.OneOf(['critical', 'high', 'medium', 'low', 'info']),
        missing='medium'
    )
    confidence = fields.Integer(
        validate=validate.Range(min=0, max=100),
        missing=50
    )
    tags = fields.List(fields.String(), missing=[])
    first_seen = fields.DateTime(missing=lambda: datetime.now(timezone.utc))
    last_seen = fields.DateTime(dump_only=True)
    is_active = fields.Boolean(missing=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)

    @validates('value')
    def validate_indicator_value(self, value):
        """Validate the indicator value based on its type."""
        indicator_type = self.context.get('indicator_type')

        # If we don't have the indicator_type in context yet, try to get it from the data
        if not indicator_type and 'indicator_type' in self.context.get('data', {}):
            indicator_type = self.context['data']['indicator_type']

        # If we still don't have indicator_type, we can't validate type-specific formats
        if not indicator_type:
            return value

        # Validate based on indicator type
        if indicator_type == 'ip':
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise ValidationError("Not a valid IP address")

        elif indicator_type == 'domain':
            # Simple domain validation
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$', value):
                raise ValidationError("Not a valid domain name")

        elif indicator_type == 'url':
            # URL validation
            if not re.match(r'^(https?|ftp)://', value):
                raise ValidationError("URL must start with http://, https://, or ftp://")

        elif indicator_type == 'file_hash':
            # MD5, SHA1, SHA256 validation
            hash_patterns = {
                'md5': r'^[a-fA-F0-9]{32}$',
                'sha1': r'^[a-fA-F0-9]{40}$',
                'sha256': r'^[a-fA-F0-9]{64}$'
            }

            if not any(re.match(pattern, value) for pattern in hash_patterns.values()):
                raise ValidationError("Not a valid MD5, SHA1, or SHA256 hash")

        elif indicator_type == 'email':
            # Email validation
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
                raise ValidationError("Not a valid email address")

        # For other types, we just accept the string value as-is

        return value


class ThreatIndicatorCreateSchema(ThreatIndicatorSchema):
    """Schema for creating threat indicators."""

    @validates_schema
    def validate_indicator_content(self, data, **kwargs):
        """Perform cross-field validation for indicator content."""
        # Add the indicator_type to context for value validation
        self.context['indicator_type'] = data.get('indicator_type')
        self.context['data'] = data


class ThreatIndicatorUpdateSchema(BaseSchema):
    """Schema for updating threat indicators."""

    description = fields.String(validate=validate.Length(max=1000))
    source = fields.String(validate=validate.Length(max=100))
    severity = fields.String(validate=validate.OneOf(['critical', 'high', 'medium', 'low', 'info']))
    confidence = fields.Integer(validate=validate.Range(min=0, max=100))
    tags = fields.List(fields.String())
    first_seen = fields.DateTime()
    is_active = fields.Boolean()

    # Note: Value and indicator_type cannot be updated


class ThreatIndicatorFilterSchema(BaseSchema):
    """Schema for filtering threat indicators."""

    page = fields.Integer(missing=1, validate=validate.Range(min=1, max=1000))
    per_page = fields.Integer(missing=20, validate=validate.Range(min=1, max=100))
    sort_by = fields.String(missing='created_at')
    sort_direction = fields.String(
        missing='desc',
        validate=validate.OneOf(['asc', 'desc'])
    )

    indicator_type = fields.String(validate=validate.OneOf([
        'ip', 'domain', 'url', 'file_hash', 'email', 'user_agent',
        'file_path', 'registry_key', 'mutex', 'process_name', 'other'
    ]))
    severity = fields.String(validate=validate.OneOf(['critical', 'high', 'medium', 'low', 'info']))
    is_active = fields.Boolean()
    source = fields.String()
    confidence_min = fields.Integer(validate=validate.Range(min=0, max=100))
    confidence_max = fields.Integer(validate=validate.Range(min=0, max=100))
    search = fields.String(validate=validate.Length(max=100))
    tags = fields.List(fields.String())
    created_after = fields.DateTime()
    created_before = fields.DateTime()

    @validates('sort_by')
    def validate_sort_field(self, value):
        """Validate sort field is a valid field."""
        valid_sort_fields = [
            'id', 'indicator_type', 'value', 'severity', 'confidence',
            'source', 'created_at', 'updated_at', 'is_active'
        ]

        if value not in valid_sort_fields:
            raise ValidationError(f"Invalid sort field. Valid options: {', '.join(valid_sort_fields)}")

    @validates_schema
    def validate_date_ranges(self, data, **kwargs):
        """Validate date ranges are logically correct."""
        if data.get('created_after') and data.get('created_before'):
            if data['created_after'] > data['created_before']:
                raise ValidationError("created_after must be before created_before")

        if data.get('confidence_min') and data.get('confidence_max'):
            if data['confidence_min'] > data['confidence_max']:
                raise ValidationError("confidence_min must be less than or equal to confidence_max")


class ThreatDetectionFilterSchema(BaseSchema):
    """Schema for filtering threat detection events."""

    page = fields.Integer(missing=1, validate=validate.Range(min=1, max=1000))
    per_page = fields.Integer(missing=20, validate=validate.Range(min=1, max=100))
    event_type = fields.String(validate=validate.OneOf([
        'ioc_match', 'file_integrity_violation', 'suspicious_activity', 'all'
    ]))
    severity = fields.String(validate=validate.OneOf(['critical', 'high', 'medium', 'low', 'info']))
    start_date = fields.DateTime()
    end_date = fields.DateTime()
    source_ip = fields.String()
    action_taken = fields.String()
    indicator_id = fields.Integer()

    @validates_schema
    def validate_date_ranges(self, data, **kwargs):
        """Validate date ranges are logically correct."""
        if data.get('start_date') and data.get('end_date'):
            if data['start_date'] > data['end_date']:
                raise ValidationError("start_date must be before end_date")


# --- Security Incident Schemas ---

class IncidentSchema(BaseSchema):
    """Schema for security incident serialization."""

    id = fields.Integer(dump_only=True)
    title = fields.String(required=True, validate=validate.Length(min=5, max=200))
    description = fields.String(required=True)
    incident_type = fields.String(required=True)
    severity = fields.String(
        validate=validate.OneOf(['critical', 'high', 'medium', 'low']),
        missing='medium'
    )
    status = fields.String(
        validate=validate.OneOf(['open', 'investigating', 'contained', 'eradicated',
                               'recovering', 'resolved', 'closed', 'merged']),
        missing='open'
    )
    phase = fields.String(
        validate=validate.OneOf(['identification', 'containment', 'eradication',
                               'recovery', 'lessons_learned']),
        missing='identification'
    )
    details = fields.Dict(missing={})
    user_id = fields.Integer(allow_none=True)
    assigned_to = fields.Integer(allow_none=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)
    resolved_at = fields.DateTime(allow_none=True, dump_only=True)
    notes = fields.List(fields.Dict(), dump_only=True)
    affected_resources = fields.List(fields.Dict(), missing=[])
    related_incidents = fields.List(fields.Integer(), missing=[])
    tags = fields.List(fields.String(), missing=[])

    @validates('details')
    def validate_details(self, value):
        """Validate details dictionary to prevent DoS."""
        serialized = str(value)
        if len(serialized) > 20000:  # Limit to 20KB
            raise ValidationError("Incident details exceed maximum allowed size")

        # Check nesting depth to prevent complex objects
        self._check_nesting_depth(value)

    def _check_nesting_depth(self, obj, current_depth=0, max_depth=5):
        """Check object nesting depth to prevent DoS attacks."""
        if current_depth > max_depth:
            raise ValidationError("Incident details exceed maximum allowed nesting depth")

        if isinstance(obj, dict):
            for val in obj.values():
                self._check_nesting_depth(val, current_depth + 1, max_depth)
        elif isinstance(obj, list):
            for item in obj:
                self._check_nesting_depth(item, current_depth + 1, max_depth)


class IncidentCreateSchema(IncidentSchema):
    """Schema for creating security incidents."""

    status = fields.String(dump_only=True)  # Status is set by the system on creation
    phase = fields.String(dump_only=True)   # Phase is set by the system on creation
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)

    @validates('affected_resources')
    def validate_affected_resources(self, resources):
        """Validate affected resources format."""
        if not isinstance(resources, list):
            raise ValidationError("Affected resources must be a list")

        for resource in resources:
            if not isinstance(resource, dict):
                raise ValidationError("Each resource must be a dictionary")

            if 'type' not in resource or 'id' not in resource:
                raise ValidationError("Each resource must have 'type' and 'id' fields")


class IncidentUpdateSchema(BaseSchema):
    """Schema for updating security incidents."""

    title = fields.String(validate=validate.Length(min=5, max=200))
    description = fields.String()
    incident_type = fields.String()
    severity = fields.String(validate=validate.OneOf(['critical', 'high', 'medium', 'low']))
    details = fields.Dict()
    affected_resources = fields.List(fields.Dict())
    tags = fields.List(fields.String())

    @validates('details')
    def validate_details(self, value):
        """Validate details dictionary to prevent DoS."""
        serialized = str(value)
        if len(serialized) > 20000:  # Limit to 20KB
            raise ValidationError("Incident details exceed maximum allowed size")

        # Check nesting depth to prevent complex objects
        self._check_nesting_depth(value)

    def _check_nesting_depth(self, obj, current_depth=0, max_depth=5):
        """Check object nesting depth to prevent DoS attacks."""
        if current_depth > max_depth:
            raise ValidationError("Incident details exceed maximum allowed nesting depth")

        if isinstance(obj, dict):
            for val in obj.values():
                self._check_nesting_depth(val, current_depth + 1, max_depth)
        elif isinstance(obj, list):
            for item in obj:
                self._check_nesting_depth(item, current_depth + 1, max_depth)

    @validates('affected_resources')
    def validate_affected_resources(self, resources):
        """Validate affected resources format."""
        if not isinstance(resources, list):
            raise ValidationError("Affected resources must be a list")

        for resource in resources:
            if not isinstance(resource, dict):
                raise ValidationError("Each resource must be a dictionary")

            if 'type' not in resource or 'id' not in resource:
                raise ValidationError("Each resource must have 'type' and 'id' fields")


class IncidentFilterSchema(BaseSchema):
    """Schema for filtering security incidents."""

    page = fields.Integer(missing=1, validate=validate.Range(min=1, max=1000))
    per_page = fields.Integer(missing=20, validate=validate.Range(min=1, max=100))
    sort_by = fields.String(missing='created_at')
    sort_direction = fields.String(
        missing='desc',
        validate=validate.OneOf(['asc', 'desc'])
    )
    severity = fields.String(validate=validate.OneOf(['critical', 'high', 'medium', 'low']))
    status = fields.String(validate=validate.OneOf(
        ['open', 'investigating', 'contained', 'eradicated', 'recovering', 'resolved', 'closed', 'merged']
    ))
    phase = fields.String(validate=validate.OneOf(
        ['identification', 'containment', 'eradication', 'recovery', 'lessons_learned']
    ))
    incident_type = fields.String()
    assigned_to = fields.Integer()
    created_after = fields.DateTime()
    created_before = fields.DateTime()
    resolved_after = fields.DateTime()
    resolved_before = fields.DateTime()
    tag = fields.String()

    @validates('sort_by')
    def validate_sort_field(self, value):
        """Validate sort field is a valid incident field."""
        valid_sort_fields = [
            'id', 'created_at', 'updated_at', 'severity', 'status',
            'phase', 'title', 'resolved_at'
        ]

        if value not in valid_sort_fields:
            raise ValidationError(f"Invalid sort field. Valid options: {', '.join(valid_sort_fields)}")

    @validates_schema
    def validate_date_ranges(self, data, **kwargs):
        """Validate date ranges are logically correct."""
        if data.get('created_after') and data.get('created_before'):
            if data['created_after'] > data['created_before']:
                raise ValidationError("created_after must be before created_before")

        if data.get('resolved_after') and data.get('resolved_before'):
            if data['resolved_after'] > data['resolved_before']:
                raise ValidationError("resolved_after must be before resolved_before")


class IncidentNoteSchema(BaseSchema):
    """Schema for adding notes to incidents."""

    note = fields.String(required=True, validate=validate.Length(min=1, max=5000))


class IncidentStatusChangeSchema(BaseSchema):
    """Schema for changing incident status."""

    status = fields.String(
        required=True,
        validate=validate.OneOf(['open', 'investigating', 'contained', 'eradicated',
                               'recovering', 'resolved', 'closed', 'merged'])
    )
    reason = fields.String(required=True, validate=validate.Length(min=5, max=1000))


class IncidentPhaseChangeSchema(BaseSchema):
    """Schema for changing incident phase."""

    phase = fields.String(
        required=True,
        validate=validate.OneOf(['identification', 'containment', 'eradication',
                               'recovery', 'lessons_learned'])
    )
    reason = fields.String(required=True, validate=validate.Length(min=5, max=1000))


class IncidentMetricsSchema(BaseSchema):
    """Schema for incident metrics requests."""

    start_date = fields.DateTime()
    end_date = fields.DateTime()
    group_by = fields.String(validate=validate.OneOf(
        ['day', 'week', 'month', 'severity', 'status', 'type']
    ))

    @validates_schema
    def validate_date_range(self, data, **kwargs):
        """Validate date range is logically correct."""
        if data.get('start_date') and data.get('end_date'):
            if data['start_date'] > data['end_date']:
                raise ValidationError("start_date must be before end_date")


# Create schema instances for direct use in routes
incident_schema = IncidentSchema()
incidents_schema = IncidentSchema(many=True)
incident_create_schema = IncidentCreateSchema()
incident_update_schema = IncidentUpdateSchema()
incident_filter_schema = IncidentFilterSchema()
incident_note_schema = IncidentNoteSchema()
incident_status_change_schema = IncidentStatusChangeSchema()
incident_phase_change_schema = IncidentPhaseChangeSchema()
incident_metrics_schema = IncidentMetricsSchema()

# Create schema instances for direct use in API routes
threat_indicator_schema = ThreatIndicatorSchema()
threat_indicators_schema = ThreatIndicatorSchema(many=True)
threat_indicator_create_schema = ThreatIndicatorCreateSchema()
threat_indicator_update_schema = ThreatIndicatorUpdateSchema()
threat_indicator_filter_schema = ThreatIndicatorFilterSchema()
threat_detection_filter_schema = ThreatDetectionFilterSchema()

# Create schema instances for direct use
vulnerability_schema = VulnerabilitySchema()
vulnerabilities_schema = VulnerabilitySchema(many=True)
vulnerability_create_schema = VulnerabilityCreateSchema()
vulnerability_update_schema = VulnerabilityUpdateSchema()
vulnerability_filter_schema = VulnerabilityFilterSchema()
vulnerability_bulk_update_schema = VulnerabilityBulkUpdateSchema()

# Create and export schema instances
scan_filter_schema = ScanFilterSchema()
scan_create_schema = ScanCreateSchema()
scan_update_schema = ScanUpdateSchema()
scan_result_schema = ScanResultSchema()
scan_finding_schema = FindingSchema()

# Create combined schemas for collections
scan_schema = BaseSchema()  # For single scan serialization
scans_schema = BaseSchema()  # For multiple scans serialization
scan_findings_schema = BaseSchema()  # For multiple findings serialization

# Export schema instances for direct use
security_event_schema = SecurityEventSchema()
security_config_schema = SecurityConfigSchema()
pagination_schema = PaginationSchema()
file_integrity_schema = FileIntegrityBaselineSchema()
baseline_update_schema = BaselineUpdateSchema()

logger.debug("Core schemas initialized")
