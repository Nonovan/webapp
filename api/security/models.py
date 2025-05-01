"""
Security API models for Cloud Infrastructure Platform.

This module defines data transfer objects, request/response schemas, and utility
models used by the security API endpoints. These models facilitate proper request
validation, response formatting, and data transformation between the API layer
and database models.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, TypedDict
from enum import Enum
from marshmallow import Schema, fields, validate, validates, ValidationError, post_load

from models.security import (
    SecurityIncident,
    SecurityBaseline,
    SecurityScan,
    Vulnerability,
    AuditLog,
    SystemConfig
)


class SecuritySeverity(Enum):
    """Standard severity levels for security-related items."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityStatus(Enum):
    """Standard status values for security items."""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    DECLINED = "declined"


class ScanType(Enum):
    """Supported security scan types."""
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    CONFIGURATION = "configuration"
    WEB_APPLICATION = "web_application"
    NETWORK = "network"
    CONTAINER = "container"
    CODE = "code"
    SECURITY_POSTURE = "security_posture"
    PENETRATION = "penetration"
    IAM = "iam"


class SecurityFilters(TypedDict, total=False):
    """Type definition for security API filter parameters."""
    severity: Optional[List[str]]
    status: Optional[List[str]]
    date_from: Optional[str]
    date_to: Optional[str]
    assigned_to: Optional[int]
    source: Optional[str]
    target_id: Optional[str]
    tags: Optional[List[str]]
    search: Optional[str]
    resource_type: Optional[str]


# Base schema with common fields and functionality
class BaseSecuritySchema(Schema):
    """Base schema for all security API schemas."""

    class Meta:
        """Schema metadata."""
        ordered = True

    id = fields.Integer(dump_only=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)

    @staticmethod
    def normalize_severity(severity: str) -> str:
        """Normalize severity value to standard format."""
        severity = severity.lower().strip()

        # Map similar terms to standard values
        if severity in ('critical', 'crit', 'fatal', 'emergency'):
            return SecuritySeverity.CRITICAL.value
        elif severity in ('high', 'important', 'major'):
            return SecuritySeverity.HIGH.value
        elif severity in ('medium', 'moderate', 'warning'):
            return SecuritySeverity.MEDIUM.value
        elif severity in ('low', 'minor'):
            return SecuritySeverity.LOW.value
        elif severity in ('info', 'information', 'informational'):
            return SecuritySeverity.INFO.value
        else:
            return SecuritySeverity.MEDIUM.value  # Default to medium if unknown


# Security Incident Schemas
class IncidentCreateSchema(BaseSecuritySchema):
    """Schema for creating security incidents."""

    title = fields.String(required=True, validate=validate.Length(min=5, max=200))
    description = fields.String(required=True, validate=validate.Length(min=10))
    incident_type = fields.String(required=True)
    severity = fields.String(required=True, validate=validate.OneOf([s.value for s in SecuritySeverity]))
    details = fields.Dict(missing=dict)
    ip_address = fields.String(validate=validate.Length(max=45))
    source = fields.String()
    affected_resources = fields.List(fields.Dict())
    tags = fields.List(fields.String())

    @validates('severity')
    def validate_severity(self, severity):
        """Validate and normalize severity."""
        return self.normalize_severity(severity)

    @post_load
    def create_incident(self, data, **kwargs):
        """Convert validated data to SecurityIncident model instance."""
        return SecurityIncident(**data)


class IncidentUpdateSchema(BaseSecuritySchema):
    """Schema for updating security incidents."""

    title = fields.String(validate=validate.Length(min=5, max=200))
    description = fields.String(validate=validate.Length(min=10))
    severity = fields.String(validate=validate.OneOf([s.value for s in SecuritySeverity]))
    status = fields.String(validate=validate.OneOf([s.value for s in SecurityStatus]))
    details = fields.Dict()
    tags = fields.List(fields.String())

    @validates('severity')
    def validate_severity(self, severity):
        """Validate and normalize severity."""
        return self.normalize_severity(severity)


class IncidentCommentSchema(BaseSecuritySchema):
    """Schema for adding comments to security incidents."""

    comment = fields.String(required=True, validate=validate.Length(min=1, max=5000))
    visibility = fields.String(missing="internal", validate=validate.OneOf(["internal", "public"]))


class IncidentAssignmentSchema(BaseSecuritySchema):
    """Schema for assigning security incidents."""

    assignee_id = fields.Integer(required=True)
    note = fields.String(validate=validate.Length(max=500))


class IncidentEscalationSchema(BaseSecuritySchema):
    """Schema for escalating security incidents."""

    new_severity = fields.String(required=True, validate=validate.OneOf([s.value for s in SecuritySeverity]))
    reason = fields.String(required=True, validate=validate.Length(min=10))
    notify_users = fields.List(fields.Integer(), missing=[])

    @validates('new_severity')
    def validate_severity(self, severity):
        """Validate and normalize severity."""
        return self.normalize_severity(severity)


# Security Scan Schemas
class ScanCreateSchema(BaseSecuritySchema):
    """Schema for creating security scans."""

    scan_type = fields.String(required=True, validate=validate.OneOf([s.value for s in ScanType]))
    profile = fields.String(validate=validate.Length(max=100))
    targets = fields.List(fields.Dict(), required=True, validate=validate.Length(min=1))
    options = fields.Dict(missing=dict)
    scheduled_for = fields.DateTime()
    notes = fields.String(validate=validate.Length(max=1000))

    @post_load
    def create_scan(self, data, **kwargs):
        """Convert validated data to SecurityScan model instance."""
        return SecurityScan(**data)


class ScanResultSchema(BaseSecuritySchema):
    """Schema for updating security scan results."""

    status = fields.String(required=True)
    findings_count = fields.Integer(missing=0)
    critical_count = fields.Integer(missing=0)
    high_count = fields.Integer(missing=0)
    medium_count = fields.Integer(missing=0)
    low_count = fields.Integer(missing=0)
    info_count = fields.Integer(missing=0)
    findings_summary = fields.Dict()
    error_message = fields.String()
    end_time = fields.DateTime()


class ScanFindingSchema(BaseSecuritySchema):
    """Schema for individual security scan findings."""

    title = fields.String(required=True, validate=validate.Length(min=5, max=200))
    description = fields.String(required=True)
    severity = fields.String(required=True, validate=validate.OneOf([s.value for s in SecuritySeverity]))
    target_id = fields.String(required=True)
    details = fields.Dict(missing=dict)
    status = fields.String(missing="open")
    affected_resources = fields.List(fields.Dict())
    remediation_steps = fields.String()
    cvss_score = fields.Float()
    cvss_vector = fields.String()

    @validates('severity')
    def validate_severity(self, severity):
        """Validate and normalize severity."""
        return self.normalize_severity(severity)


# Vulnerability Management Schemas
class VulnerabilityCreateSchema(BaseSecuritySchema):
    """Schema for creating vulnerabilities."""

    title = fields.String(required=True, validate=validate.Length(min=5, max=200))
    description = fields.String(required=True, validate=validate.Length(min=10))
    vulnerability_type = fields.String(required=True)
    severity = fields.String(required=True, validate=validate.OneOf([s.value for s in SecuritySeverity]))
    cvss_score = fields.Float(validate=validate.Range(min=0, max=10))
    cvss_vector = fields.String()
    affected_resources = fields.List(fields.Dict(), required=True)
    remediation_steps = fields.String()
    reference_urls = fields.List(fields.String())
    tags = fields.List(fields.String())

    @validates('severity')
    def validate_severity(self, severity):
        """Validate and normalize severity."""
        return self.normalize_severity(severity)

    @validates('cvss_vector')
    def validate_cvss_vector(self, vector):
        """Validate CVSS vector string format."""
        if vector and not vector.startswith(("CVSS:3", "CVSS:2")):
            raise ValidationError("CVSS vector must start with CVSS:3 or CVSS:2")
        return vector

    @post_load
    def create_vulnerability(self, data, **kwargs):
        """Convert validated data to Vulnerability model instance."""
        return Vulnerability(**data)


class VulnerabilityUpdateSchema(BaseSecuritySchema):
    """Schema for updating vulnerabilities."""

    title = fields.String(validate=validate.Length(min=5, max=200))
    description = fields.String(validate=validate.Length(min=10))
    severity = fields.String(validate=validate.OneOf([s.value for s in SecuritySeverity]))
    status = fields.String(validate=validate.OneOf([s.value for s in SecurityStatus]))
    remediation_steps = fields.String()
    remediation_deadline = fields.DateTime()
    assigned_to = fields.Integer()
    tags = fields.List(fields.String())

    @validates('severity')
    def validate_severity(self, severity):
        """Validate and normalize severity."""
        return self.normalize_severity(severity)


# Security Baseline Schemas
class BaselineControlSchema(Schema):
    """Schema for security baseline controls."""

    control_id = fields.String(required=True)
    title = fields.String(required=True)
    description = fields.String(required=True)
    implementation = fields.String()
    verification = fields.String()
    remediation = fields.String()
    impact = fields.String(missing="Low")
    severity = fields.String(required=True, validate=validate.OneOf([s.value for s in SecuritySeverity]))


class BaselineCreateSchema(BaseSecuritySchema):
    """Schema for creating security baselines."""

    name = fields.String(required=True, validate=validate.Length(min=3, max=128))
    description = fields.String(validate=validate.Length(max=255))
    system_type = fields.String(required=True)
    version = fields.String(required=True, validate=validate.Length(min=1, max=32))
    framework = fields.String(validate=validate.Length(max=32))
    is_public = fields.Boolean(missing=False)
    security_controls = fields.Dict()
    metadata = fields.Dict(missing=dict)

    @post_load
    def create_baseline(self, data, **kwargs):
        """Convert validated data to SecurityBaseline model instance."""
        return SecurityBaseline(**data)


# File Integrity Schemas
class FileIntegrityCheckSchema(Schema):
    """Schema for file integrity check results."""

    path = fields.String(required=True)
    status = fields.String(required=True)
    last_checked = fields.DateTime()
    last_modified = fields.DateTime()
    expected_hash = fields.String()
    actual_hash = fields.String()
    file_permissions = fields.String()
    details = fields.Dict()


class FileBaselineUpdateSchema(Schema):
    """Schema for updating file integrity baseline."""

    paths = fields.List(fields.String(), missing=[])
    auto_update_limit = fields.Integer(missing=10)
    remove_missing = fields.Boolean(missing=False)


# Utility class for security data transformation
class SecurityDataTransformer:
    """Utility class for transforming security data between API and database models."""

    @staticmethod
    def format_incident_response(incident: SecurityIncident) -> Dict[str, Any]:
        """Format a security incident for API response."""
        incident_dict = incident.to_dict()

        # Add calculated fields
        if incident.created_at and incident.status not in (SecurityStatus.RESOLVED.value, SecurityStatus.CLOSED.value):
            incident_dict['age_hours'] = round((datetime.utcnow() - incident.created_at).total_seconds() / 3600, 1)

        # Add SLA information
        if incident.severity == SecuritySeverity.CRITICAL.value:
            sla_hours = 1
        elif incident.severity == SecuritySeverity.HIGH.value:
            sla_hours = 4
        elif incident.severity == SecuritySeverity.MEDIUM.value:
            sla_hours = 24
        else:
            sla_hours = 72

        if incident.created_at:
            incident_dict['sla_deadline'] = incident.created_at + timedelta(hours=sla_hours)
            incident_dict['sla_breached'] = datetime.utcnow() > incident_dict['sla_deadline']

        return incident_dict

    @staticmethod
    def format_vulnerability_response(vulnerability: Vulnerability) -> Dict[str, Any]:
        """Format a vulnerability for API response."""
        vuln_dict = vulnerability.to_dict()

        # Add calculated fields
        if vulnerability.remediation_deadline:
            vuln_dict['days_to_deadline'] = (vulnerability.remediation_deadline - datetime.utcnow()).days
            vuln_dict['overdue'] = vuln_dict['days_to_deadline'] < 0

        # Calculate risk score (CVSS score with additional context factors)
        if vulnerability.cvss_score:
            # Start with base CVSS score
            risk_score = vulnerability.cvss_score * 10  # Scale to 0-100

            # Adjust for other risk factors
            if vulnerability.is_exploitable:
                risk_score += 15
            if vulnerability.has_public_exploit:
                risk_score += 20
            if vulnerability.is_being_exploited:
                risk_score += 30

            vuln_dict['risk_score'] = min(100, risk_score)  # Cap at 100

        return vuln_dict

    @staticmethod
    def format_scan_response(scan: SecurityScan) -> Dict[str, Any]:
        """Format a security scan for API response."""
        scan_dict = scan.to_dict()

        # Add scan health information
        if scan.status == SecurityScan.STATUS_IN_PROGRESS:
            if scan.start_time:
                duration_hours = (datetime.utcnow() - scan.start_time).total_seconds() / 3600
                scan_dict['duration_hours'] = round(duration_hours, 2)

                # Flag potentially stuck scans
                if duration_hours > 8:  # Scans running longer than 8 hours
                    scan_dict['potentially_stuck'] = True

        # Add findings distribution if available
        if scan.findings_count > 0:
            total = max(1, scan.findings_count)  # Prevent division by zero
            scan_dict['findings_distribution'] = {
                "critical_percent": round(scan.critical_count * 100 / total, 1),
                "high_percent": round(scan.high_count * 100 / total, 1),
                "medium_percent": round(scan.medium_count * 100 / total, 1),
                "low_percent": round(scan.low_count * 100 / total, 1),
                "info_percent": round(scan.info_count * 100 / total, 1)
            }

        return scan_dict


# Initialize schemas for direct use in views
incident_create_schema = IncidentCreateSchema()
incident_update_schema = IncidentUpdateSchema()
incident_comment_schema = IncidentCommentSchema()
incident_assignment_schema = IncidentAssignmentSchema()
incident_escalation_schema = IncidentEscalationSchema()

scan_create_schema = ScanCreateSchema()
scan_result_schema = ScanResultSchema()
scan_finding_schema = ScanFindingSchema()

vulnerability_create_schema = VulnerabilityCreateSchema()
vulnerability_update_schema = VulnerabilityUpdateSchema()

baseline_create_schema = BaselineCreateSchema()
baseline_control_schema = BaselineControlSchema()

file_integrity_check_schema = FileIntegrityCheckSchema()
file_baseline_update_schema = FileBaselineUpdateSchema()
