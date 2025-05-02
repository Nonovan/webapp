"""
Security Baseline model for Cloud Infrastructure Platform.

This module provides the SecurityBaseline model which represents security baseline
configurations used to define secure states for different system types. It enables
storing, validating, and comparing security controls against expected secure configurations.

Security baselines are used for security assessment, compliance verification, and drift detection
to ensure systems maintain their secure state over time.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Union, cast
from sqlalchemy.dialects.postgresql import JSONB
from flask import current_app
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.mutable import MutableDict

from extensions import db, cache
from models.base import BaseModel, AuditableMixin
from core.security.cs_audit import log_security_event


class SecurityBaseline(BaseModel, AuditableMixin):
    """
    Security baseline model representing expected secure configurations for system components.

    This model stores security controls, their expected values, validation methods, and remediation
    guidance. It's used for security compliance assessment, vulnerability management, and
    configuration drift detection.
    """

    # System type constants
    TYPE_SERVER = 'server'
    TYPE_APPLICATION = 'application'
    TYPE_DATABASE = 'database'
    TYPE_CONTAINER = 'container'
    TYPE_CLOUD_SERVICE = 'cloud_service'
    TYPE_NETWORK_DEVICE = 'network_device'
    TYPE_IDENTITY_SYSTEM = 'identity_system'

    # System types list for validation
    SYSTEM_TYPES = [
        TYPE_SERVER, TYPE_APPLICATION, TYPE_DATABASE, TYPE_CONTAINER,
        TYPE_CLOUD_SERVICE, TYPE_NETWORK_DEVICE, TYPE_IDENTITY_SYSTEM
    ]

    # Status constants
    STATUS_DRAFT = 'draft'
    STATUS_ACTIVE = 'active'
    STATUS_ARCHIVED = 'archived'
    STATUS_DEPRECATED = 'deprecated'

    # Valid status values
    STATUSES = [STATUS_DRAFT, STATUS_ACTIVE, STATUS_ARCHIVED, STATUS_DEPRECATED]

    # Framework constants
    FRAMEWORK_CIS = 'cis'
    FRAMEWORK_NIST = 'nist'
    FRAMEWORK_ISO27001 = 'iso27001'
    FRAMEWORK_PCI = 'pci'
    FRAMEWORK_HIPAA = 'hipaa'
    FRAMEWORK_SOC2 = 'soc2'
    FRAMEWORK_CUSTOM = 'custom'

    # Valid frameworks
    FRAMEWORKS = [
        FRAMEWORK_CIS, FRAMEWORK_NIST, FRAMEWORK_ISO27001,
        FRAMEWORK_PCI, FRAMEWORK_HIPAA, FRAMEWORK_SOC2, FRAMEWORK_CUSTOM
    ]

    # Severity levels
    SEVERITY_CRITICAL = 'critical'
    SEVERITY_HIGH = 'high'
    SEVERITY_MEDIUM = 'medium'
    SEVERITY_LOW = 'low'
    SEVERITY_INFO = 'info'

    # Valid severity levels
    SEVERITIES = [
        SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
    ]

    # Column definitions
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String(255))
    system_type = db.Column(db.String(64), nullable=False, index=True)
    version = db.Column(db.String(32), nullable=False)
    framework = db.Column(db.String(32), index=True)
    status = db.Column(db.String(32), default=STATUS_DRAFT, nullable=False, index=True)
    is_public = db.Column(db.Boolean, default=False, nullable=False)

    # JSON fields
    security_controls = db.Column(MutableDict.as_mutable(JSONB), default=dict)
    metadata = db.Column(MutableDict.as_mutable(JSONB), default=dict)

    # Timestamps
    published_at = db.Column(db.DateTime(timezone=True))

    # Relationships
    # - Could add relationships to assessments, evaluation results, etc.

    # Cache timeout in seconds (5 minutes)
    CACHE_TIMEOUT = 300

    def __init__(self, name: str, system_type: str, version: str, description: Optional[str] = None,
                framework: Optional[str] = None, is_public: bool = False,
                security_controls: Optional[Dict[str, Any]] = None,
                metadata: Optional[Dict[str, Any]] = None):
        """
        Initialize a SecurityBaseline object.

        Args:
            name: The name of the security baseline
            system_type: The type of system this baseline applies to
            version: Version number of the baseline
            description: Optional description of the baseline's purpose and coverage
            framework: Optional compliance framework this baseline is based on
            is_public: Whether this baseline is publicly available to all users
            security_controls: Optional dictionary of security controls and requirements
            metadata: Optional additional metadata for the baseline
        """
        if system_type not in self.SYSTEM_TYPES:
            raise ValueError(f"Invalid system type: {system_type}. Must be one of: {', '.join(self.SYSTEM_TYPES)}")

        if framework is not None and framework not in self.FRAMEWORKS:
            raise ValueError(f"Invalid framework: {framework}. Must be one of: {', '.join(self.FRAMEWORKS)}")

        super().__init__()
        self.name = name
        self.system_type = system_type
        self.version = version
        self.description = description
        self.framework = framework
        self.is_public = is_public
        self.security_controls = security_controls or {}
        self.metadata = metadata or {}

    def publish(self, user_id: int) -> bool:
        """
        Publish the security baseline, making it active.

        Args:
            user_id: ID of the user publishing the baseline

        Returns:
            bool: True if published successfully, False otherwise
        """
        try:
            if not self.security_controls or not isinstance(self.security_controls, dict):
                current_app.logger.error(f"Cannot publish baseline {self.id}: No security controls defined")
                return False

            # Validate controls before publishing
            control_errors = self.validate_controls()
            if control_errors:
                error_msg = f"Cannot publish baseline {self.id}: Invalid controls: {control_errors}"
                current_app.logger.error(error_msg)
                return False

            self.status = self.STATUS_ACTIVE
            self.published_at = datetime.now(timezone.utc)

            db.session.add(self)
            db.session.commit()

            # Log security event
            log_security_event(
                event_type='baseline_published',
                description=f"Security baseline published: {self.name} v{self.version}",
                user_id=user_id,
                severity="info",
                details={
                    "baseline_id": self.id,
                    "name": self.name,
                    "version": self.version,
                    "system_type": self.system_type
                }
            )

            # Clear cache
            self._clear_cache()
            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error publishing baseline {self.id}: {str(e)}")
            return False

    def archive(self, user_id: int, reason: Optional[str] = None) -> bool:
        """
        Archive the security baseline.

        Args:
            user_id: ID of the user archiving the baseline
            reason: Optional reason for archiving

        Returns:
            bool: True if archived successfully, False otherwise
        """
        try:
            if self.status == self.STATUS_ARCHIVED:
                return True  # Already archived

            self.status = self.STATUS_ARCHIVED

            # Store archiving reason in metadata
            if reason:
                self.metadata = self.metadata or {}
                self.metadata["archive_reason"] = reason
                self.metadata["archived_at"] = datetime.now(timezone.utc).isoformat()
                self.metadata["archived_by"] = user_id

            db.session.add(self)
            db.session.commit()

            # Log security event
            log_security_event(
                event_type='baseline_archived',
                description=f"Security baseline archived: {self.name} v{self.version}",
                user_id=user_id,
                severity="info",
                details={
                    "baseline_id": self.id,
                    "name": self.name,
                    "version": self.version,
                    "reason": reason
                }
            )

            # Clear cache
            self._clear_cache()
            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error archiving baseline {self.id}: {str(e)}")
            return False

    def validate_controls(self) -> List[str]:
        """
        Validate the security controls structure and content.

        Returns:
            List of error messages. Empty list if validation passes.
        """
        errors = []

        if not isinstance(self.security_controls, dict):
            return ["Security controls must be a dictionary"]

        # Validate structure: security_controls should be a dict of categories
        for category_name, category in self.security_controls.items():
            if not isinstance(category, dict):
                errors.append(f"Category '{category_name}' must be a dictionary")
                continue

            # Each category contains controls
            for control_name, control in category.items():
                if not isinstance(control, dict):
                    errors.append(f"Control '{category_name}.{control_name}' must be a dictionary")
                    continue

                # Required fields for controls
                if "severity" in control and control["severity"] not in self.SEVERITIES:
                    errors.append(f"Invalid severity in '{category_name}.{control_name}': {control['severity']}")

                # Validation command should be a string if provided
                if "validation" in control and not isinstance(control["validation"], str):
                    errors.append(f"Validation command in '{category_name}.{control_name}' must be a string")

        return errors

    def add_control(self, category: str, control_id: str, control_data: Dict[str, Any]) -> bool:
        """
        Add or update a security control in the baseline.

        Args:
            category: Control category name
            control_id: Unique identifier for the control
            control_data: Dictionary containing control details

        Returns:
            bool: True if successful, False if error occurred
        """
        try:
            if self.status != self.STATUS_DRAFT:
                current_app.logger.warning(f"Cannot add control to baseline {self.id}: Not in draft status")
                return False

            # Initialize the category if it doesn't exist
            if not self.security_controls:
                self.security_controls = {}

            if category not in self.security_controls:
                self.security_controls[category] = {}

            # Add/update the control
            self.security_controls[category][control_id] = control_data

            # Save changes
            db.session.add(self)
            db.session.commit()

            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error adding control to baseline {self.id}: {str(e)}")
            return False

    def remove_control(self, category: str, control_id: str) -> bool:
        """
        Remove a security control from the baseline.

        Args:
            category: Control category name
            control_id: Unique identifier for the control

        Returns:
            bool: True if successful, False if error occurred
        """
        try:
            if self.status != self.STATUS_DRAFT:
                current_app.logger.warning(f"Cannot remove control from baseline {self.id}: Not in draft status")
                return False

            if not self.security_controls or category not in self.security_controls:
                current_app.logger.warning(f"Category '{category}' not found in baseline {self.id}")
                return False

            if control_id not in self.security_controls[category]:
                current_app.logger.warning(f"Control '{control_id}' not found in category '{category}' in baseline {self.id}")
                return False

            # Remove the control
            del self.security_controls[category][control_id]

            # Remove the category if it's now empty
            if not self.security_controls[category]:
                del self.security_controls[category]

            # Save changes
            db.session.add(self)
            db.session.commit()

            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error removing control from baseline {self.id}: {str(e)}")
            return False

    def clone(self, new_name: str, new_version: str, user_id: int) -> 'SecurityBaseline':
        """
        Clone this baseline to create a new draft version.

        Args:
            new_name: Name for the new baseline
            new_version: Version for the new baseline
            user_id: ID of the user creating the clone

        Returns:
            SecurityBaseline: The newly created baseline

        Raises:
            SQLAlchemyError: If database error occurs
        """
        new_baseline = SecurityBaseline(
            name=new_name,
            system_type=self.system_type,
            version=new_version,
            description=f"Cloned from {self.name} v{self.version}",
            framework=self.framework,
            is_public=False,  # Default to private for the new clone
            security_controls=self.security_controls.copy() if self.security_controls else {},
            metadata={
                "cloned_from": self.id,
                "cloned_at": datetime.now(timezone.utc).isoformat(),
                "cloned_by": user_id
            }
        )

        db.session.add(new_baseline)
        db.session.commit()

        # Log security event
        log_security_event(
            event_type='baseline_cloned',
            description=f"Security baseline cloned: {new_baseline.name} v{new_baseline.version}",
            user_id=user_id,
            severity="info",
            details={
                "source_baseline_id": self.id,
                "source_name": self.name,
                "source_version": self.version,
                "new_baseline_id": new_baseline.id,
                "new_name": new_baseline.name,
                "new_version": new_baseline.version
            }
        )

        return new_baseline

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the baseline to a dictionary representation.

        Returns:
            Dictionary containing baseline data
        """
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'system_type': self.system_type,
            'version': self.version,
            'framework': self.framework,
            'status': self.status,
            'is_public': self.is_public,
            'security_controls': self.security_controls,
            'metadata': self.metadata,
            'published_at': self.published_at.isoformat() if self.published_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def get_control_count(self) -> Dict[str, int]:
        """
        Get count of controls by severity.

        Returns:
            Dictionary with counts per severity level
        """
        counts = {severity: 0 for severity in self.SEVERITIES}
        counts['total'] = 0

        if not self.security_controls:
            return counts

        for category in self.security_controls.values():
            for control in category.values():
                counts['total'] += 1
                severity = control.get('severity', self.SEVERITY_MEDIUM)
                if severity in counts:
                    counts[severity] += 1

        return counts

    def _clear_cache(self) -> None:
        """Clear cache entries related to this baseline."""
        cache_keys = [
            f'security_baseline_{self.id}',
            f'security_baseline_active_{self.system_type}'
        ]
        for key in cache_keys:
            cache.delete(key)

    @classmethod
    def get_active_baseline(cls, system_type: str) -> Optional['SecurityBaseline']:
        """
        Get the active security baseline for a specific system type.

        Args:
            system_type: Type of system to get baseline for

        Returns:
            SecurityBaseline or None if not found
        """
        cache_key = f'security_baseline_active_{system_type}'
        cached = cache.get(cache_key)

        if cached is not None:
            return cached

        baseline = cls.query.filter_by(
            system_type=system_type,
            status=cls.STATUS_ACTIVE
        ).order_by(cls.published_at.desc()).first()

        if baseline:
            cache.set(cache_key, baseline, timeout=cls.CACHE_TIMEOUT)

        return baseline

    @classmethod
    def get_control_from_baseline(cls, baseline_id: int, category: str,
                                 control_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific control from a baseline.

        Args:
            baseline_id: ID of the baseline
            category: Category name
            control_id: Control identifier

        Returns:
            Dictionary containing control data or None if not found
        """
        baseline = cls.query.get(baseline_id)
        if not baseline or not baseline.security_controls:
            return None

        try:
            return baseline.security_controls.get(category, {}).get(control_id)
        except (KeyError, AttributeError):
            return None

    @classmethod
    def import_from_json(cls, json_data: Dict[str, Any], user_id: int) -> Optional['SecurityBaseline']:
        """
        Import a security baseline from a JSON structure.

        Args:
            json_data: Dictionary containing baseline data
            user_id: ID of the user importing the baseline

        Returns:
            SecurityBaseline or None if error occurred

        Raises:
            ValueError: If JSON data is invalid
        """
        try:
            # Required fields
            required_fields = ['name', 'system_type', 'version', 'security_controls']
            for field in required_fields:
                if field not in json_data:
                    raise ValueError(f"Missing required field: {field}")

            # Validate system type
            if json_data['system_type'] not in cls.SYSTEM_TYPES:
                raise ValueError(f"Invalid system type: {json_data['system_type']}")

            # Create baseline instance
            baseline = cls(
                name=json_data['name'],
                system_type=json_data['system_type'],
                version=json_data['version'],
                description=json_data.get('description'),
                framework=json_data.get('framework'),
                is_public=json_data.get('is_public', False),
                security_controls=json_data['security_controls'],
                metadata=json_data.get('metadata', {})
            )

            # Add import metadata
            if not baseline.metadata:
                baseline.metadata = {}
            baseline.metadata['imported_at'] = datetime.now(timezone.utc).isoformat()
            baseline.metadata['imported_by'] = user_id

            # Validate controls
            errors = baseline.validate_controls()
            if errors:
                raise ValueError(f"Invalid controls in baseline: {', '.join(errors)}")

            # Save to database
            db.session.add(baseline)
            db.session.commit()

            # Log security event
            log_security_event(
                event_type='baseline_imported',
                description=f"Security baseline imported: {baseline.name} v{baseline.version}",
                user_id=user_id,
                severity="info",
                details={
                    "baseline_id": baseline.id,
                    "name": baseline.name,
                    "system_type": baseline.system_type
                }
            )

            return baseline

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Database error importing baseline: {str(e)}")
            raise ValueError(f"Database error importing baseline: {str(e)}")

    @classmethod
    def compare_baselines(cls, baseline_id_1: int, baseline_id_2: int) -> Dict[str, Any]:
        """
        Compare two security baselines.

        Args:
            baseline_id_1: ID of the first baseline
            baseline_id_2: ID of the second baseline

        Returns:
            Dictionary with comparison results
        """
        baseline1 = cls.query.get(baseline_id_1)
        baseline2 = cls.query.get(baseline_id_2)

        if not baseline1 or not baseline2:
            missing = []
            if not baseline1:
                missing.append(baseline_id_1)
            if not baseline2:
                missing.append(baseline_id_2)
            return {"error": f"Baseline(s) not found: {', '.join(map(str, missing))}"}

        # Initialize result structure
        result = {
            "baseline1": {
                "id": baseline1.id,
                "name": baseline1.name,
                "version": baseline1.version
            },
            "baseline2": {
                "id": baseline2.id,
                "name": baseline2.name,
                "version": baseline2.version
            },
            "added_controls": [],
            "removed_controls": [],
            "modified_controls": [],
            "unchanged_controls": []
        }

        # Get all control identifiers from both baselines
        controls1 = cls._get_all_control_identifiers(baseline1.security_controls)
        controls2 = cls._get_all_control_identifiers(baseline2.security_controls)

        # Find added controls (in baseline2 but not in baseline1)
        for control_id in controls2 - controls1:
            category, control_name = control_id.split(':', 1)
            control_data = baseline2.security_controls.get(category, {}).get(control_name)
            result["added_controls"].append({
                "id": control_id,
                "category": category,
                "control_name": control_name,
                "data": control_data
            })

        # Find removed controls (in baseline1 but not in baseline2)
        for control_id in controls1 - controls2:
            category, control_name = control_id.split(':', 1)
            control_data = baseline1.security_controls.get(category, {}).get(control_name)
            result["removed_controls"].append({
                "id": control_id,
                "category": category,
                "control_name": control_name,
                "data": control_data
            })

        # Find modified and unchanged controls
        for control_id in controls1 & controls2:
            category, control_name = control_id.split(':', 1)
            control_data1 = baseline1.security_controls.get(category, {}).get(control_name)
            control_data2 = baseline2.security_controls.get(category, {}).get(control_name)

            if control_data1 != control_data2:
                result["modified_controls"].append({
                    "id": control_id,
                    "category": category,
                    "control_name": control_name,
                    "before": control_data1,
                    "after": control_data2
                })
            else:
                result["unchanged_controls"].append({
                    "id": control_id,
                    "category": category,
                    "control_name": control_name,
                    "data": control_data1
                })

        # Add summary counts
        result["summary"] = {
            "added": len(result["added_controls"]),
            "removed": len(result["removed_controls"]),
            "modified": len(result["modified_controls"]),
            "unchanged": len(result["unchanged_controls"]),
            "total_controls1": len(controls1),
            "total_controls2": len(controls2)
        }

        return result

    @staticmethod
    def _get_all_control_identifiers(security_controls: Dict[str, Any]) -> Set[str]:
        """
        Get all control identifiers from a security controls dictionary.

        Args:
            security_controls: Dictionary of security controls

        Returns:
            Set of strings in format "category:control_name"
        """
        identifiers = set()
        if not security_controls:
            return identifiers

        for category, controls in security_controls.items():
            for control_name in controls.keys():
                identifiers.add(f"{category}:{control_name}")

        return identifiers

    def __repr__(self) -> str:
        """Return string representation of the baseline."""
        return f"<SecurityBaseline {self.id}: {self.name} v{self.version}, {self.status}>"
