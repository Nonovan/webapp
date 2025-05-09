"""
Administrative forms for the Cloud Infrastructure Platform.

This module defines the form classes used throughout the administrative
interface for user management, system configuration, security controls,
and compliance reporting. Each form includes proper validation and
security protections.

Forms include:
- User management forms (creation and editing)
- Role management forms (creation and editing)
- System configuration forms
- File integrity management forms
- Security incident management forms
- Audit log search forms
- Compliance and security reporting forms
"""

import os
from datetime import datetime, date, timedelta
from typing import List, Optional, Dict, Any, Union

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import (
    StringField, PasswordField, BooleanField, TextAreaField, SelectField,
    SelectMultipleField, IntegerField, DateField, HiddenField, SubmitField,
    ValidationError
)
from wtforms.validators import (
    DataRequired, Email, Length, EqualTo, Optional as OptionalValidator,
    Regexp, URL, ValidationError, InputRequired, NumberRange
)

from models.auth import User, Role, Permission
from models.security import SecurityIncident
from core.security.cs_validation import validate_password_complexity


class UserCreateForm(FlaskForm):
    """Form for creating a new user account."""
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=64),
        Regexp(r'^[a-zA-Z0-9_.-]+$', message="Username must contain only letters, numbers, dots, underscores, or hyphens")
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message="Not a valid email address"),
        Length(max=120)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    active = BooleanField('Active', default=True)
    roles = SelectMultipleField('Roles', coerce=int)

    # Custom validation for password complexity
    def validate_password(self, field):
        if not validate_password_complexity(field.data):
            raise ValidationError('Password does not meet complexity requirements')


class UserEditForm(FlaskForm):
    """Form for editing an existing user."""
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=64),
        Regexp(r'^[a-zA-Z0-9_.-]+$', message="Username must contain only letters, numbers, dots, underscores, or hyphens")
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message="Not a valid email address"),
        Length(max=120)
    ])
    password = PasswordField('New Password (leave blank to keep current)', validators=[
        OptionalValidator(),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        EqualTo('password', message='Passwords must match')
    ])
    active = BooleanField('Active')
    roles = SelectMultipleField('Roles', coerce=int)

    # Custom validation for password complexity
    def validate_password(self, field):
        if field.data and not validate_password_complexity(field.data):
            raise ValidationError('Password does not meet complexity requirements')


class RoleCreateForm(FlaskForm):
    """Form for creating a new role."""
    name = StringField('Role Name', validators=[
        DataRequired(),
        Length(min=3, max=64),
        Regexp(r'^[a-zA-Z0-9_]+$', message="Role name must contain only letters, numbers, and underscores")
    ])
    description = TextAreaField('Description', validators=[
        DataRequired(),
        Length(max=255)
    ])


class RoleEditForm(FlaskForm):
    """Form for editing an existing role."""
    name = StringField('Role Name', validators=[
        DataRequired(),
        Length(min=3, max=64),
        Regexp(r'^[a-zA-Z0-9_]+$', message="Role name must contain only letters, numbers, and underscores")
    ])
    description = TextAreaField('Description', validators=[
        DataRequired(),
        Length(max=255)
    ])


class SystemConfigForm(FlaskForm):
    """Form for managing system configuration settings."""
    # Core settings
    system_name = StringField('System Name', validators=[
        DataRequired(),
        Length(max=100)
    ])
    system_url = StringField('System URL', validators=[
        DataRequired(),
        URL(message="Must be a valid URL")
    ])
    admin_email = StringField('Administrator Email', validators=[
        DataRequired(),
        Email(message="Not a valid email address")
    ])

    # Security settings
    enable_mfa = BooleanField('Enable Multi-Factor Authentication', default=True)
    password_expiry_days = IntegerField('Password Expiry (days)', validators=[
        NumberRange(min=0, max=365)
    ])
    session_timeout_minutes = IntegerField('Session Timeout (minutes)', validators=[
        NumberRange(min=1, max=1440)
    ])
    admin_session_timeout = IntegerField('Admin Session Timeout (minutes)', validators=[
        NumberRange(min=1, max=180)
    ])
    login_attempts = IntegerField('Maximum Login Attempts', validators=[
        NumberRange(min=1, max=10)
    ])

    # File integrity settings
    file_integrity_check_frequency = IntegerField('File Integrity Check Frequency (minutes)', validators=[
        NumberRange(min=5, max=1440)
    ])

    # Notification settings
    alert_email = StringField('Security Alert Email', validators=[
        DataRequired(),
        Email(message="Not a valid email address")
    ])

    # Audit settings
    audit_retention_days = IntegerField('Audit Log Retention (days)', validators=[
        NumberRange(min=30, max=3650)
    ])

    # Reason field for tracking changes
    reason = TextAreaField('Reason for Change', validators=[
        DataRequired(),
        Length(max=500)
    ])

    submit = SubmitField('Update Configuration')


class FileIntegrityForm(FlaskForm):
    """Form for file integrity baseline management."""
    paths = TextAreaField('Paths to Monitor', validators=[
        DataRequired(),
        Length(max=2000)
    ])
    include_patterns = TextAreaField('Include Patterns (one per line)', validators=[
        OptionalValidator(),
        Length(max=500)
    ])
    exclude_patterns = TextAreaField('Exclude Patterns (one per line)', validators=[
        OptionalValidator(),
        Length(max=500)
    ])
    reason = TextAreaField('Reason for Update', validators=[
        DataRequired(),
        Length(max=500)
    ])

    submit = SubmitField('Update Baseline')


class AuditLogSearchForm(FlaskForm):
    """Form for searching audit logs with filters."""
    event_type = StringField('Event Type', validators=[OptionalValidator()])
    user_id = StringField('User ID', validators=[OptionalValidator()])
    severity = SelectField('Severity', choices=[
        ('', 'All'),
        ('debug', 'Debug'),
        ('info', 'Info'),
        ('notice', 'Notice'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('critical', 'Critical')
    ], validators=[OptionalValidator()])
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[OptionalValidator()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[OptionalValidator()])

    submit = SubmitField('Search Logs')


class IncidentManagementForm(FlaskForm):
    """Form for managing security incidents."""
    type = SelectField('Incident Type', choices=[
        ('malware', 'Malware Detection'),
        ('unauthorized_access', 'Unauthorized Access'),
        ('data_breach', 'Data Breach'),
        ('policy_violation', 'Policy Violation'),
        ('denial_of_service', 'Denial of Service'),
        ('insider_threat', 'Insider Threat'),
        ('phishing', 'Phishing Attack'),
        ('physical_security', 'Physical Security'),
        ('other', 'Other')
    ], validators=[DataRequired()])

    summary = StringField('Summary', validators=[
        DataRequired(),
        Length(min=5, max=100)
    ])

    description = TextAreaField('Description', validators=[
        DataRequired(),
        Length(min=10, max=5000)
    ])

    severity = SelectField('Severity', choices=[
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low')
    ], validators=[DataRequired()])

    status = SelectField('Status', choices=[
        ('open', 'Open'),
        ('investigating', 'Investigating'),
        ('mitigating', 'Mitigating'),
        ('resolved', 'Resolved'),
        ('closed', 'Closed')
    ], validators=[DataRequired()])

    source = StringField('Incident Source', validators=[
        DataRequired(),
        Length(max=100)
    ])

    assigned_to = StringField('Assigned To', validators=[
        OptionalValidator(),
        Length(max=100)
    ])

    resolution = TextAreaField('Resolution Notes', validators=[
        OptionalValidator(),
        Length(max=5000)
    ])

    submit = SubmitField('Save Incident')


class ComplianceReportForm(FlaskForm):
    """Form for generating compliance reports."""
    name = StringField('Report Name', validators=[
        DataRequired(),
        Length(min=5, max=100)
    ])

    report_type = SelectField('Report Type', choices=[
        ('gdpr', 'GDPR Compliance'),
        ('hipaa', 'HIPAA Compliance'),
        ('pci', 'PCI DSS Compliance'),
        ('sox', 'Sarbanes-Oxley (SOX)'),
        ('iso27001', 'ISO 27001'),
        ('nist', 'NIST Cybersecurity Framework'),
        ('custom', 'Custom Compliance Report')
    ], validators=[DataRequired()])

    period_start = DateField('Period Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    period_end = DateField('Period End Date', format='%Y-%m-%d', validators=[DataRequired()])

    description = TextAreaField('Report Description', validators=[
        OptionalValidator(),
        Length(max=500)
    ])

    # Custom validation to ensure end date is after start date
    def validate_period_end(self, field):
        if field.data < self.period_start.data:
            raise ValidationError('End date must be after start date')

    submit = SubmitField('Generate Report')


class SecurityReportForm(FlaskForm):
    """Form for generating security reports."""
    report_type = SelectField('Report Type', choices=[
        ('comprehensive', 'Comprehensive Security Report'),
        ('incidents', 'Security Incidents Report'),
        ('access', 'Access Control Report'),
        ('integrity', 'File Integrity Report')
    ], validators=[DataRequired()])

    period_days = SelectField('Time Period', choices=[
        ('7', 'Last 7 Days'),
        ('30', 'Last 30 Days'),
        ('90', 'Last 90 Days'),
        ('180', 'Last 6 Months'),
        ('365', 'Last Year')
    ], validators=[DataRequired()])

    submit = SubmitField('Generate Report')
