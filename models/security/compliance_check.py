"""
Compliance check framework for the Cloud Infrastructure Platform.

This module provides models and functionality for defining, executing, and tracking
compliance checks against various security standards and frameworks. It integrates
with the platform's audit logging, file integrity monitoring, and security baseline systems.
"""

import os
import json
import re
from typing import Dict, List, Optional, Union, Any, Tuple
from datetime import datetime, timezone
from enum import Enum
from sqlalchemy.exc import SQLAlchemyError

from flask import current_app, has_request_context, g, has_app_context
from sqlalchemy.orm import validates
from sqlalchemy.ext.associationproxy import association_proxy

from models.base import BaseModel, db, AuditableMixin
from core.security.cs_audit import log_security_event, log_model_event


class ComplianceSeverity(str, Enum):
    """Severity levels for compliance findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceStatus(str, Enum):
    """Status values for compliance checks."""
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"


class ComplianceFramework(BaseModel):
    """Model representing a compliance framework or standard."""

    __tablename__ = 'compliance_frameworks'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    version = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=True)
    source_url = db.Column(db.String(255), nullable=True)
    documentation_url = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Relationships
    controls = db.relationship('ComplianceControl', back_populates='framework',
                              cascade='all, delete-orphan')

    def __init__(self, name: str, version: str, description: Optional[str] = None,
                 source_url: Optional[str] = None, documentation_url: Optional[str] = None):
        self.name = name
        self.version = version
        self.description = description
        self.source_url = source_url
        self.documentation_url = documentation_url

    def to_dict(self) -> Dict[str, Any]:
        """Convert framework to dictionary representation."""
        return {
            'id': self.id,
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'source_url': self.source_url,
            'documentation_url': self.documentation_url,
            'is_active': self.is_active,
            'control_count': len(self.controls) if self.controls else 0
        }


class ComplianceControl(BaseModel):
    """Model representing a specific control within a compliance framework."""

    __tablename__ = 'compliance_controls'

    id = db.Column(db.Integer, primary_key=True)
    framework_id = db.Column(db.Integer, db.ForeignKey('compliance_frameworks.id',
                                                    ondelete='CASCADE'), nullable=False)
    control_id = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), nullable=False)
    implementation_details = db.Column(db.Text, nullable=True)
    verification_method = db.Column(db.String(100), nullable=True)

    # Relationships
    framework = db.relationship('ComplianceFramework', back_populates='controls')
    checks = db.relationship('ComplianceCheck', back_populates='control',
                           cascade='all, delete-orphan')

    __table_args__ = (
        db.UniqueConstraint('framework_id', 'control_id', name='uix_control_framework'),
    )

    def __init__(self, framework_id: int, control_id: str, category: str, title: str,
                 severity: str, description: Optional[str] = None,
                 implementation_details: Optional[str] = None,
                 verification_method: Optional[str] = None):
        self.framework_id = framework_id
        self.control_id = control_id
        self.category = category
        self.title = title
        self.description = description
        self.severity = severity
        self.implementation_details = implementation_details
        self.verification_method = verification_method

    @validates('severity')
    def validate_severity(self, key: str, severity: str) -> str:
        """Validate the severity level."""
        try:
            return ComplianceSeverity(severity.lower()).value
        except ValueError:
            return ComplianceSeverity.MEDIUM.value

    def to_dict(self) -> Dict[str, Any]:
        """Convert control to dictionary representation."""
        return {
            'id': self.id,
            'framework_id': self.framework_id,
            'control_id': self.control_id,
            'category': self.category,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'implementation_details': self.implementation_details,
            'verification_method': self.verification_method,
            'framework_name': self.framework.name if self.framework else None
        }


class ComplianceCheck(BaseModel, AuditableMixin):
    """Model representing a specific compliance check implementation and its results."""

    __tablename__ = 'compliance_checks'

    # Security critical fields for enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['status', 'parameters', 'check_type']

    id = db.Column(db.Integer, primary_key=True)
    control_id = db.Column(db.Integer, db.ForeignKey('compliance_controls.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    check_type = db.Column(db.String(50), nullable=False) # 'config', 'api', 'file', etc.
    parameters = db.Column(db.JSON, nullable=True)
    enabled = db.Column(db.Boolean, default=True, nullable=False)

    # Check execution results
    status = db.Column(db.String(20), nullable=True)
    last_run_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_run_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    result_details = db.Column(db.JSON, nullable=True)

    # Relationships
    control = db.relationship('ComplianceControl', back_populates='checks')
    results = db.relationship('ComplianceResult', back_populates='check',
                            cascade='all, delete-orphan', order_by='ComplianceResult.created_at.desc()')

    # Constants
    CHECK_TYPE_CONFIG = "config"
    CHECK_TYPE_API = "api"
    CHECK_TYPE_FILE = "file"
    CHECK_TYPE_DATABASE = "database"
    CHECK_TYPE_SYSTEM = "system"
    CHECK_TYPE_PROCESS = "process"
    CHECK_TYPE_NETWORK = "network"
    CHECK_TYPE_CUSTOM = "custom"

    VALID_CHECK_TYPES = [
        CHECK_TYPE_CONFIG, CHECK_TYPE_API, CHECK_TYPE_FILE, CHECK_TYPE_DATABASE,
        CHECK_TYPE_SYSTEM, CHECK_TYPE_PROCESS, CHECK_TYPE_NETWORK, CHECK_TYPE_CUSTOM
    ]

    def __init__(self, control_id: int, name: str, check_type: str,
                 description: Optional[str] = None, parameters: Optional[Dict[str, Any]] = None,
                 enabled: bool = True):
        self.control_id = control_id
        self.name = name
        self.description = description
        self.check_type = check_type
        self.parameters = parameters or {}
        self.enabled = enabled

    @validates('check_type')
    def validate_check_type(self, key: str, check_type: str) -> str:
        """Validate the check type."""
        if check_type not in self.VALID_CHECK_TYPES:
            raise ValueError(f"Invalid check type: {check_type}. Must be one of: {', '.join(self.VALID_CHECK_TYPES)}")
        return check_type

    @validates('status')
    def validate_status(self, key: str, status: Optional[str]) -> Optional[str]:
        """Validate the status value."""
        if status is None:
            return None

        try:
            return ComplianceStatus(status.lower()).value
        except ValueError:
            return ComplianceStatus.ERROR.value

    def execute(self, user_id: Optional[int] = None) -> Tuple[str, Dict[str, Any]]:
        """
        Execute the compliance check.

        Args:
            user_id: Optional ID of user running the check

        Returns:
            Tuple of status string and result details dict
        """
        now = datetime.now(timezone.utc)
        self.last_run_at = now
        self.last_run_by = user_id

        try:
            # Execute appropriate check based on check_type
            if self.check_type == self.CHECK_TYPE_CONFIG:
                status, details = self._check_config()
            elif self.check_type == self.CHECK_TYPE_FILE:
                status, details = self._check_file()
            elif self.check_type == self.CHECK_TYPE_API:
                status, details = self._check_api()
            else:
                # For other check types, use custom handler if registered
                handler = self._get_check_handler()
                if handler:
                    status, details = handler(self.parameters)
                else:
                    status = ComplianceStatus.ERROR.value
                    details = {"error": f"No handler registered for check type: {self.check_type}"}

            # Update check status
            self.status = status
            self.result_details = details

            # Create result record
            result = ComplianceResult(
                check_id=self.id,
                status=status,
                details=details,
                executed_by=user_id
            )

            # Save changes
            db.session.add(result)
            db.session.add(self)
            db.session.commit()

            # Log security event for failed compliance checks
            if status == ComplianceStatus.FAILED.value:
                control = self.control
                framework = control.framework if control else None

                log_security_event(
                    event_type='compliance_check_failed',
                    description=f"Compliance check failed: {self.name}",
                    severity='warning',
                    user_id=user_id,
                    details={
                        'check_id': self.id,
                        'check_name': self.name,
                        'control_id': control.control_id if control else None,
                        'framework': framework.name if framework else None,
                        'failure_details': details
                    }
                )

            return status, details

        except Exception as e:
            error_details = {"error": str(e), "type": type(e).__name__}
            self.status = ComplianceStatus.ERROR.value
            self.result_details = error_details

            # Create error result
            result = ComplianceResult(
                check_id=self.id,
                status=ComplianceStatus.ERROR.value,
                details=error_details,
                executed_by=user_id
            )

            db.session.add(result)
            db.session.add(self)
            db.session.commit()

            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error executing compliance check {self.id}: {str(e)}")

            return ComplianceStatus.ERROR.value, error_details

    def _check_config(self) -> Tuple[str, Dict[str, Any]]:
        """Execute configuration-based compliance check."""
        if not self.parameters:
            return ComplianceStatus.ERROR.value, {"error": "No parameters specified for config check"}

        try:
            config_path = self.parameters.get('config_path')
            key = self.parameters.get('key')
            check_type = self.parameters.get('check_type', 'key_value')
            expected = self.parameters.get('expected')

            if not all([config_path, key, expected]):
                return ComplianceStatus.ERROR.value, {
                    "error": "Missing required parameters",
                    "required": ["config_path", "key", "expected"]
                }

            # Get base config directory from app config or use default
            config_dir = current_app.config.get('CONFIG_DIR', '/etc/cloud-platform')
            full_path = os.path.join(config_dir, config_path)

            if not os.path.exists(full_path):
                return ComplianceStatus.FAILED.value, {
                    "message": f"Configuration file not found: {config_path}",
                    "path": full_path
                }

            # Read config file
            with open(full_path, 'r') as f:
                content = f.read()

            # Extract value for key
            match = re.search(rf'^{key}\s*=\s*(.+?)$', content, re.MULTILINE)
            if not match:
                return ComplianceStatus.FAILED.value, {
                    "message": f"Key '{key}' not found in configuration file",
                    "config_file": config_path
                }

            actual_value = match.group(1).strip()

            # Apply check based on check_type
            result_details = {
                "config_file": config_path,
                "key": key,
                "actual_value": actual_value,
                "expected_value": expected,
                "check_type": check_type
            }

            if check_type == 'key_value':
                # Direct value comparison
                if str(actual_value) == str(expected):
                    return ComplianceStatus.PASSED.value, result_details
                return ComplianceStatus.FAILED.value, result_details

            elif check_type == 'key_value_min':
                # Minimum value comparison
                try:
                    if float(actual_value) >= float(expected):
                        return ComplianceStatus.PASSED.value, result_details
                    return ComplianceStatus.FAILED.value, result_details
                except ValueError:
                    return ComplianceStatus.ERROR.value, {
                        **result_details,
                        "error": "Non-numeric value found for comparison"
                    }

            elif check_type == 'key_value_max':
                # Maximum value comparison
                try:
                    if float(actual_value) <= float(expected):
                        return ComplianceStatus.PASSED.value, result_details
                    return ComplianceStatus.FAILED.value, result_details
                except ValueError:
                    return ComplianceStatus.ERROR.value, {
                        **result_details,
                        "error": "Non-numeric value found for comparison"
                    }

            elif check_type == 'key_value_not':
                # Ensure value is not equal to expected
                if str(actual_value) != str(expected):
                    return ComplianceStatus.PASSED.value, result_details
                return ComplianceStatus.FAILED.value, result_details

            else:
                return ComplianceStatus.ERROR.value, {
                    **result_details,
                    "error": f"Unknown check type: {check_type}"
                }

        except Exception as e:
            return ComplianceStatus.ERROR.value, {"error": str(e)}

    def _check_file(self) -> Tuple[str, Dict[str, Any]]:
        """Execute file-based compliance check."""
        if not self.parameters:
            return ComplianceStatus.ERROR.value, {"error": "No parameters specified for file check"}

        try:
            file_path = self.parameters.get('file_path')
            check_type = self.parameters.get('check_type', 'existence')

            if not file_path:
                return ComplianceStatus.ERROR.value, {
                    "error": "Missing required parameter: file_path"
                }

            # Get base directory from app config or use default
            base_dir = current_app.config.get('APP_ROOT', '/')
            if not os.path.isabs(file_path):
                full_path = os.path.join(base_dir, file_path)
            else:
                full_path = file_path

            result_details = {
                "file_path": file_path,
                "full_path": full_path,
                "check_type": check_type
            }

            # Check file existence
            if check_type == 'existence':
                exists = os.path.exists(full_path)
                result_details["exists"] = exists
                if self.parameters.get('should_exist', True):
                    return (ComplianceStatus.PASSED.value if exists else ComplianceStatus.FAILED.value,
                            result_details)
                else:
                    return (ComplianceStatus.PASSED.value if not exists else ComplianceStatus.FAILED.value,
                            result_details)

            # File must exist for other checks
            if not os.path.exists(full_path):
                result_details["exists"] = False
                return ComplianceStatus.FAILED.value, result_details

            # Check file permissions
            if check_type == 'permissions':
                expected_perms = self.parameters.get('permissions')
                if not expected_perms:
                    return ComplianceStatus.ERROR.value, {
                        **result_details,
                        "error": "Missing required parameter: permissions"
                    }

                actual_perms = oct(os.stat(full_path).st_mode & 0o777)[2:]  # Get only permission bits
                result_details["actual_permissions"] = actual_perms
                result_details["expected_permissions"] = expected_perms

                if expected_perms == actual_perms:
                    return ComplianceStatus.PASSED.value, result_details
                return ComplianceStatus.FAILED.value, result_details

            # Check file integrity/hash
            elif check_type == 'integrity':
                expected_hash = self.parameters.get('hash')
                hash_algorithm = self.parameters.get('algorithm', 'sha256')

                if not expected_hash:
                    return ComplianceStatus.ERROR.value, {
                        **result_details,
                        "error": "Missing required parameter: hash"
                    }

                # Import appropriate hash function
                import hashlib
                hash_func = getattr(hashlib, hash_algorithm, None)
                if not hash_func:
                    return ComplianceStatus.ERROR.value, {
                        **result_details,
                        "error": f"Unsupported hash algorithm: {hash_algorithm}"
                    }

                # Calculate file hash
                with open(full_path, 'rb') as f:
                    file_hash = hash_func(f.read()).hexdigest()

                result_details["actual_hash"] = file_hash
                result_details["expected_hash"] = expected_hash
                result_details["algorithm"] = hash_algorithm

                if file_hash == expected_hash:
                    return ComplianceStatus.PASSED.value, result_details
                return ComplianceStatus.FAILED.value, result_details

            # Check file content
            elif check_type == 'content':
                pattern = self.parameters.get('pattern')
                if not pattern:
                    return ComplianceStatus.ERROR.value, {
                        **result_details,
                        "error": "Missing required parameter: pattern"
                    }

                with open(full_path, 'r') as f:
                    content = f.read()

                match = re.search(pattern, content)
                result_details["pattern"] = pattern
                result_details["pattern_found"] = bool(match)

                should_match = self.parameters.get('should_match', True)
                if bool(match) == should_match:
                    return ComplianceStatus.PASSED.value, result_details
                return ComplianceStatus.FAILED.value, result_details

            else:
                return ComplianceStatus.ERROR.value, {
                    **result_details,
                    "error": f"Unknown check type: {check_type}"
                }

        except Exception as e:
            return ComplianceStatus.ERROR.value, {"error": str(e)}

    def _check_api(self) -> Tuple[str, Dict[str, Any]]:
        """Execute API-based compliance check."""
        if not self.parameters:
            return ComplianceStatus.ERROR.value, {"error": "No parameters specified for API check"}

        try:
            endpoint = self.parameters.get('endpoint')
            method = self.parameters.get('method', 'GET').upper()
            expected_status = self.parameters.get('expected_status', 200)
            validation_key = self.parameters.get('validation_key')
            expected_value = self.parameters.get('expected_value')

            if not endpoint:
                return ComplianceStatus.ERROR.value, {
                    "error": "Missing required parameter: endpoint"
                }

            # Prepare request
            import requests
            headers = self.parameters.get('headers', {})
            params = self.parameters.get('params', {})
            data = self.parameters.get('data')
            json_data = self.parameters.get('json')
            timeout = self.parameters.get('timeout', 30)

            # Execute request
            response = requests.request(
                method=method,
                url=endpoint,
                headers=headers,
                params=params,
                data=data,
                json=json_data,
                timeout=timeout
            )

            result_details = {
                "endpoint": endpoint,
                "method": method,
                "status_code": response.status_code,
                "expected_status": expected_status,
            }

            # First check status code
            if response.status_code != expected_status:
                result_details["message"] = f"Expected status code {expected_status}, got {response.status_code}"
                return ComplianceStatus.FAILED.value, result_details

            # If validation key is provided, check response content
            if validation_key:
                try:
                    response_json = response.json()
                except ValueError:
                    result_details["error"] = "Response is not valid JSON"
                    return ComplianceStatus.ERROR.value, result_details

                # Extract value using dot notation (e.g., "data.user.enabled")
                actual_value = response_json
                for key in validation_key.split('.'):
                    if isinstance(actual_value, dict) and key in actual_value:
                        actual_value = actual_value[key]
                    else:
                        result_details["error"] = f"Key '{validation_key}' not found in response"
                        result_details["response"] = response_json
                        return ComplianceStatus.FAILED.value, result_details

                result_details["validation_key"] = validation_key
                result_details["actual_value"] = actual_value
                result_details["expected_value"] = expected_value

                if str(actual_value) == str(expected_value):
                    return ComplianceStatus.PASSED.value, result_details
                else:
                    result_details["message"] = f"Expected '{expected_value}', got '{actual_value}'"
                    return ComplianceStatus.FAILED.value, result_details

            # If we reach here, the check passed based on status code
            return ComplianceStatus.PASSED.value, result_details

        except requests.RequestException as e:
            return ComplianceStatus.ERROR.value, {
                "error": f"API request failed: {str(e)}",
                "endpoint": self.parameters.get('endpoint')
            }
        except Exception as e:
            return ComplianceStatus.ERROR.value, {"error": str(e)}

    def _get_check_handler(self):
        """Get custom check handler if registered."""
        if not hasattr(current_app, 'compliance_check_handlers'):
            return None

        handlers = current_app.compliance_check_handlers
        return handlers.get(self.check_type)

    def to_dict(self) -> Dict[str, Any]:
        """Convert check to dictionary representation."""
        control = self.control
        framework = control.framework if control else None

        return {
            'id': self.id,
            'control_id': self.control_id,
            'name': self.name,
            'description': self.description,
            'check_type': self.check_type,
            'parameters': self.parameters,
            'enabled': self.enabled,
            'status': self.status,
            'last_run_at': self.last_run_at.isoformat() if self.last_run_at else None,
            'result_details': self.result_details,
            'control': {
                'id': control.id,
                'control_id': control.control_id,
                'title': control.title,
                'severity': control.severity
            } if control else None,
            'framework': {
                'id': framework.id,
                'name': framework.name,
                'version': framework.version
            } if framework else None
        }


class ComplianceResult(BaseModel):
    """Model for storing individual compliance check results."""

    __tablename__ = 'compliance_results'

    id = db.Column(db.Integer, primary_key=True)
    check_id = db.Column(db.Integer, db.ForeignKey('compliance_checks.id', ondelete='CASCADE'),
                        nullable=False)
    status = db.Column(db.String(20), nullable=False)
    details = db.Column(db.JSON, nullable=True)
    execution_time = db.Column(db.Float, nullable=True)  # Time in seconds
    executed_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                         nullable=False)

    # Relationships
    check = db.relationship('ComplianceCheck', back_populates='results')

    def __init__(self, check_id: int, status: str, details: Optional[Dict[str, Any]] = None,
                 executed_by: Optional[int] = None, execution_time: Optional[float] = None):
        self.check_id = check_id
        self.status = status
        self.details = details
        self.executed_by = executed_by
        self.execution_time = execution_time

    @validates('status')
    def validate_status(self, key: str, status: str) -> str:
        """Validate the status value."""
        try:
            return ComplianceStatus(status.lower()).value
        except ValueError:
            return ComplianceStatus.ERROR.value

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            'id': self.id,
            'check_id': self.check_id,
            'status': self.status,
            'details': self.details,
            'execution_time': self.execution_time,
            'executed_by': self.executed_by,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class ComplianceValidator:
    """
    Utility class for validating systems against compliance requirements.

    Runs a series of compliance checks based on specified frameworks and
    produces comprehensive validation reports.
    """

    def __init__(self, framework: Optional[str] = None,
                 categories: Optional[List[str]] = None,
                 environment: Optional[str] = None):
        self.framework = framework
        self.categories = categories
        self.environment = environment or self._get_current_environment()
        self.results = []

    def _get_current_environment(self) -> str:
        """Get the current environment from app config."""
        if has_app_context():
            return current_app.config.get('ENVIRONMENT', 'production').lower()
        return 'production'

    def validate(self, user_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Run validation against the selected framework or categories.

        Args:
            user_id: Optional ID of user running the validation

        Returns:
            Dict with validation summary and results
        """
        start_time = datetime.now(timezone.utc)

        # Get checks to execute based on criteria
        query = ComplianceCheck.query.filter(ComplianceCheck.enabled == True)

        if self.framework:
            query = query.join(ComplianceControl).join(ComplianceFramework).filter(
                ComplianceFramework.name == self.framework
            )

        if self.categories:
            query = query.join(ComplianceControl, aliased=True).filter(
                ComplianceControl.category.in_(self.categories)
            )

        checks = query.all()

        # Execute each check
        passed = 0
        failed = 0
        errors = 0
        skipped = 0

        for check in checks:
            status, details = check.execute(user_id)
            self.results.append({
                'check': check.to_dict(),
                'status': status,
                'details': details
            })

            # Count results by status
            if status == ComplianceStatus.PASSED.value:
                passed += 1
            elif status == ComplianceStatus.FAILED.value:
                failed += 1
            elif status == ComplianceStatus.ERROR.value:
                errors += 1
            elif status == ComplianceStatus.SKIPPED.value:
                skipped += 1

        # Generate summary
        end_time = datetime.now(timezone.utc)
        execution_time = (end_time - start_time).total_seconds()

        overall_status = ComplianceStatus.PASSED.value
        if failed > 0:
            overall_status = ComplianceStatus.FAILED.value
        elif errors > 0 and passed == 0:
            overall_status = ComplianceStatus.ERROR.value

        summary = {
            'framework': self.framework,
            'categories': self.categories,
            'environment': self.environment,
            'timestamp': end_time.isoformat(),
            'execution_time': execution_time,
            'total_checks': len(checks),
            'passed': passed,
            'failed': failed,
            'errors': errors,
            'skipped': skipped,
            'overall_status': overall_status
        }

        # Log validation event
        log_security_event(
            event_type='compliance_validation_completed',
            description=f"Compliance validation completed with status: {overall_status}",
            severity='info' if overall_status == ComplianceStatus.PASSED.value else 'warning',
            user_id=user_id,
            details={
                'framework': self.framework,
                'categories': self.categories,
                'environment': self.environment,
                'passed': passed,
                'failed': failed,
                'errors': errors
            }
        )

        return {
            'summary': summary,
            'results': self.results
        }

    def generate_report(self, format: str = 'json', output_file: Optional[str] = None) -> Union[str, Dict]:
        """
        Generate a compliance report in the specified format.

        Args:
            format: Report format ('json', 'html', 'text')
            output_file: Optional file path to save the report

        Returns:
            Report content as string or dict (for JSON)
        """
        if not self.results:
            raise ValueError("No validation results available. Run validate() first.")

        if format == 'json':
            report = self._generate_json_report()
        elif format == 'html':
            report = self._generate_html_report()
        elif format == 'text':
            report = self._generate_text_report()
        else:
            raise ValueError(f"Unsupported report format: {format}")

        # Save to file if specified
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    if format == 'json':
                        json.dump(report, f, indent=2)
                    else:
                        f.write(report)
            except IOError as e:
                if hasattr(current_app, 'logger'):
                    current_app.logger.error(f"Failed to write report to {output_file}: {e}")
                raise

        return report

    def _generate_json_report(self) -> Dict:
        """Generate a JSON report."""
        # Get the first result's summary
        if not self.results:
            return {"error": "No validation results available"}

        # Assuming summary info is available from the validation results
        first_result = self.results[0]
        summary = first_result.get('check', {}).get('framework', {})

        # Find the summary data
        for result in self.results:
            if 'summary' in result:
                summary = result['summary']
                break

        return {
            "compliance_report": {
                "metadata": {
                    "framework": self.framework,
                    "categories": self.categories,
                    "environment": self.environment,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "version": summary.get('version', '1.0')
                },
                "summary": {
                    "total_checks": len(self.results),
                    "passed": sum(1 for r in self.results if r.get('status') == ComplianceStatus.PASSED.value),
                    "failed": sum(1 for r in self.results if r.get('status') == ComplianceStatus.FAILED.value),
                    "errors": sum(1 for r in self.results if r.get('status') == ComplianceStatus.ERROR.value),
                    "skipped": sum(1 for r in self.results if r.get('status') == ComplianceStatus.SKIPPED.value),
                    "overall_status": ComplianceStatus.PASSED.value if not any(
                        r.get('status') == ComplianceStatus.FAILED.value for r in self.results
                    ) else ComplianceStatus.FAILED.value
                },
                "results": self.results
            }
        }

    def _generate_html_report(self) -> str:
        """Generate an HTML report."""
        # Get summary counts
        total_checks = len(self.results)
        passed = sum(1 for r in self.results if r.get('status') == ComplianceStatus.PASSED.value)
        failed = sum(1 for r in self.results if r.get('status') == ComplianceStatus.FAILED.value)
        errors = sum(1 for r in self.results if r.get('status') == ComplianceStatus.ERROR.value)
        skipped = sum(1 for r in self.results if r.get('status') == ComplianceStatus.SKIPPED.value)

        overall_status = ComplianceStatus.PASSED.value if not any(
            r.get('status') == ComplianceStatus.FAILED.value for r in self.results
        ) else ComplianceStatus.FAILED.value

        # Generate HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Validation Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; color: #333; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .summary {{ display: flex; justify-content: space-between; margin-bottom: 20px; }}
        .summary-box {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; }}
        .summary-critical {{ background-color: #ffeeee; }}
        .summary-high {{ background-color: #fff6ee; }}
        .summary-medium {{ background-color: #ffffee; }}
        .summary-low {{ background-color: #eeffee; }}
        .summary-info {{ background-color: #eeeeff; }}
        .summary-count {{ font-size: 24px; font-weight: bold; }}
        .dashboard {{ display: flex; flex-wrap: wrap; margin-bottom: 20px; }}
        .dashboard-item {{ flex: 1; min-width: 200px; margin: 10px; padding: 15px; border: 1px solid #ddd; }}
        .section {{ margin-bottom: 30px; }}
        .issue {{ margin: 10px 0; padding: 10px; border-left: 4px solid; }}
        .critical {{ border-color: #ff0000; background-color: #ffeeee; }}
        .high {{ border-color: #ff6600; background-color: #fff6ee; }}
        .medium {{ border-color: #ffcc00; background-color: #ffffee; }}
        .low {{ border-color: #99cc99; background-color: #f0fff0; }}
        .info {{ border-color: #6666cc; background-color: #eeeeff; }}
        .passed {{ color: #27ae60; }}
        .failed {{ color: #e74c3c; }}
        .error {{ color: #e67e22; }}
        .skipped {{ color: #7f8c8d; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .footer {{ text-align: center; margin-top: 40px; color: #7f8c8d; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Compliance Validation Report</h1>

        <div class="summary-box">
            <p><strong>Framework:</strong> {self.framework or "All Frameworks"}</p>
            <p><strong>Categories:</strong> {", ".join(self.categories) if self.categories else "All Categories"}</p>
            <p><strong>Environment:</strong> {self.environment}</p>
            <p><strong>Timestamp:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p><strong>Overall Status:</strong> <span class="{overall_status.lower()}">{overall_status.upper()}</span></p>
        </div>

        <div class="dashboard">
            <div class="dashboard-item">
                <h3>Total Checks</h3>
                <p class="summary-count">{total_checks}</p>
            </div>
            <div class="dashboard-item passed">
                <h3>Passed</h3>
                <p class="summary-count">{passed}</p>
            </div>
            <div class="dashboard-item failed">
                <h3>Failed</h3>
                <p class="summary-count">{failed}</p>
            </div>
            <div class="dashboard-item error">
                <h3>Errors</h3>
                <p class="summary-count">{errors}</p>
            </div>
            <div class="dashboard-item skipped">
                <h3>Skipped</h3>
                <p class="summary-count">{skipped}</p>
            </div>
        </div>

        <h2>Detailed Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Control ID</th>
                    <th>Check Name</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
"""

        # Add table rows for each result
        for result in self.results:
            check = result.get('check', {})
            control = check.get('control', {})
            status = result.get('status', '')
            details = result.get('details', {})
            details_str = str(details)

            html += f"""
                <tr class="{status.lower()}">
                    <td>{control.get('control_id', 'N/A')}</td>
                    <td>{check.get('name', 'Unknown')}</td>
                    <td class="{status.lower()}">{status.upper()}</td>
                    <td>{control.get('severity', 'medium')}</td>
                    <td><pre>{details_str}</pre></td>
                </tr>
"""

        # Close the HTML document
        html += """
            </tbody>
        </table>

        <div class="footer">
            <p>Generated by Cloud Infrastructure Platform Compliance Validator</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def _generate_text_report(self) -> str:
        """Generate a plain text report."""
        # Get summary counts
        total_checks = len(self.results)
        passed = sum(1 for r in self.results if r.get('status') == ComplianceStatus.PASSED.value)
        failed = sum(1 for r in self.results if r.get('status') == ComplianceStatus.FAILED.value)
        errors = sum(1 for r in self.results if r.get('status') == ComplianceStatus.ERROR.value)
        skipped = sum(1 for r in self.results if r.get('status') == ComplianceStatus.SKIPPED.value)

        overall_status = ComplianceStatus.PASSED.value if not any(
            r.get('status') == ComplianceStatus.FAILED.value for r in self.results
        ) else ComplianceStatus.FAILED.value

        # Generate text
        text = f"""
=================================================================
                COMPLIANCE VALIDATION REPORT
=================================================================

Framework:     {self.framework or "All Frameworks"}
Categories:    {", ".join(self.categories) if self.categories else "All Categories"}
Environment:   {self.environment}
Timestamp:     {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
Overall Status: {overall_status.upper()}

SUMMARY:
  Total Checks:  {total_checks}
  Passed:        {passed}
  Failed:        {failed}
  Errors:        {errors}
  Skipped:       {skipped}

DETAILED RESULTS:
"""

        # Add each result
        for i, result in enumerate(self.results, 1):
            check = result.get('check', {})
            control = check.get('control', {})
            framework = check.get('framework', {})
            status = result.get('status', '')
            details = result.get('details', {})

            text += f"""
-----------------------------------------------------------------
CHECK #{i}: {check.get('name', 'Unknown')}
-----------------------------------------------------------------
Control ID:     {control.get('control_id', 'N/A')}
Framework:      {framework.get('name', 'Unknown')} {framework.get('version', '')}
Category:       {control.get('category', 'N/A')}
Severity:       {control.get('severity', 'medium')}
Status:         {status.upper()}

Details:
{str(details)}
"""

        text += "\n=================================================================\n"
        return text


# Register signal handlers for audit logging
@db.event.listens_for(ComplianceCheck, 'after_insert')
def log_compliance_check_creation(mapper, connection, target):
    """Log compliance check creation."""
    log_model_event(
        model_name="ComplianceCheck",
        event_type="create",
        object_id=target.id,
        severity="info"
    )

@db.event.listens_for(ComplianceCheck, 'after_update')
def log_compliance_check_update(mapper, connection, target):
    """Log compliance check updates."""
    # Only log substantial changes
    if hasattr(target, '_sa_instance_state') and target._sa_instance_state.attrs:
        changes = {}
        for attr in target._sa_instance_state.attrs:
            if attr.key in ['parameters', 'enabled', 'check_type']:
                history = attr.history
                if history.has_changes():
                    changes[attr.key] = {
                        'old': history.deleted[0] if history.deleted else None,
                        'new': history.added[0] if history.added else None
                    }

        if changes:
            log_model_event(
                model_name="ComplianceCheck",
                event_type="update",
                object_id=target.id,
                details={'changes': changes},
                severity="info"
            )
