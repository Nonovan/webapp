"""
Permission model for fine-grained authorization control.

This module defines the Permission model which represents individual permissions
that can be assigned to roles within the Cloud Infrastructure Platform's RBAC system.
Permissions represent specific actions that can be performed on resources, enabling
granular access control throughout the application.

The model supports resource-action based permission naming, hierarchical organization,
and comprehensive validation to ensure security constraints are maintained.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set, Union, cast
from sqlalchemy import and_, or_, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import relationship, validates
from flask import current_app

from extensions import db
from models.base import BaseModel, AuditableMixin
from core.security.cs_audit import log_security_event


class Permission(BaseModel, AuditableMixin):
    """
    Represents a single permission in the system's authorization model.

    Permissions define specific actions that can be performed on resources,
    following the pattern of 'resource:action' (e.g., 'users:create').
    These permissions are assigned to roles which in turn are assigned to users.

    Attributes:
        id: Primary key
        name: Unique permission identifier (format: 'resource:action')
        description: Human-readable description of the permission
        category: Grouping category for organization (e.g., 'user_management')
        is_active: Whether the permission is currently active
        is_system: Whether this is a system-defined permission that cannot be modified
        resource: The resource this permission applies to (extracted from name)
        action: The action this permission allows (extracted from name)
    """
    __tablename__ = 'permissions'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['name', 'is_active']

    # Enable access auditing for this model due to its sensitive nature
    AUDIT_ACCESS = True

    # Permission category constants
    CATEGORY_USER_MANAGEMENT = 'user_management'
    CATEGORY_ROLE_MANAGEMENT = 'role_management'
    CATEGORY_CLOUD_RESOURCES = 'cloud_resources'
    CATEGORY_MONITORING = 'monitoring'
    CATEGORY_SECURITY = 'security'
    CATEGORY_CONFIG = 'configuration'
    CATEGORY_REPORTING = 'reporting'
    CATEGORY_ICS = 'ics_management'
    CATEGORY_SYSTEM = 'system'
    CATEGORY_OTHER = 'other'

    CATEGORIES = [
        CATEGORY_USER_MANAGEMENT, CATEGORY_ROLE_MANAGEMENT,
        CATEGORY_CLOUD_RESOURCES, CATEGORY_MONITORING, CATEGORY_SECURITY,
        CATEGORY_CONFIG, CATEGORY_REPORTING, CATEGORY_ICS,
        CATEGORY_SYSTEM, CATEGORY_OTHER
    ]

    # Common action types for standardization
    ACTION_CREATE = 'create'
    ACTION_READ = 'read'
    ACTION_UPDATE = 'update'
    ACTION_DELETE = 'delete'
    ACTION_LIST = 'list'
    ACTION_MANAGE = 'manage'
    ACTION_EXECUTE = 'execute'
    ACTION_CONTROL = 'control'
    ACTION_APPROVE = 'approve'
    ACTION_REJECT = 'reject'
    ACTION_ASSIGN = 'assign'
    ACTION_REVOKE = 'revoke'
    ACTION_IMPORT = 'import'
    ACTION_EXPORT = 'export'
    ACTION_START = 'start'
    ACTION_STOP = 'stop'
    ACTION_RESTART = 'restart'

    # Core fields
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False, unique=True, index=True)
    description = db.Column(db.String(255), nullable=True)
    category = db.Column(db.String(50), nullable=False, default=CATEGORY_OTHER, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    is_system = db.Column(db.Boolean, default=False, nullable=False)

    # Timestamps (inherited from BaseModel via TimestampMixin)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True),
                         default=lambda: datetime.now(timezone.utc),
                         onupdate=lambda: datetime.now(timezone.utc),
                         nullable=False)

    # Relationships to roles are defined in Role model via the association table

    def __init__(self, name: str, description: Optional[str] = None,
                category: str = CATEGORY_OTHER, is_active: bool = True,
                is_system: bool = False) -> None:
        """
        Initialize a new permission.

        Args:
            name: Permission name in 'resource:action' format
            description: Human-readable description
            category: Category for organizing permissions
            is_active: Whether the permission is active
            is_system: Whether this is a system-defined permission
        """
        self.name = name
        self.description = description
        self.category = category
        self.is_active = is_active
        self.is_system = is_system

    @validates('name')
    def validate_name(self, key: str, name: str) -> str:
        """
        Validate the permission name.

        Ensures the name follows the 'resource:action' format and is unique.

        Args:
            key: Field name being validated
            name: Permission name to validate

        Returns:
            str: Validated permission name

        Raises:
            ValueError: If name is empty, invalid format, or already exists
        """
        if not name or not name.strip():
            raise ValueError("Permission name cannot be empty")

        # Check format (resource:action)
        cleaned_name = name.strip().lower()
        if ':' not in cleaned_name:
            raise ValueError("Permission name must be in 'resource:action' format")

        # Check length
        if len(cleaned_name) > 100:
            raise ValueError("Permission name cannot exceed 100 characters")

        # Validate resource and action names individually
        parts = cleaned_name.split(':', 1)
        if len(parts[0]) == 0:
            raise ValueError("Resource name cannot be empty")
        if len(parts) < 2 or len(parts[1]) == 0:
            raise ValueError("Action name cannot be empty")

        # Ensure resource name doesn't contain invalid characters
        if not all(c.isalnum() or c == '_' for c in parts[0]):
            raise ValueError("Resource name can only contain alphanumeric characters and underscores")

        # Ensure action name doesn't contain invalid characters
        if not all(c.isalnum() or c == '_' for c in parts[1]):
            raise ValueError("Action name can only contain alphanumeric characters and underscores")

        # Check for uniqueness (case insensitive)
        existing_permission = Permission.query.filter(
            and_(
                func.lower(Permission.name) == cleaned_name,
                Permission.id != getattr(self, 'id', None)
            )
        ).first()

        if existing_permission:
            raise ValueError(f"Permission name '{cleaned_name}' already exists")

        return cleaned_name

    @validates('category')
    def validate_category(self, key: str, category: str) -> str:
        """
        Validate the permission category.

        Args:
            key: Field name being validated
            category: Category to validate

        Returns:
            str: Validated category, defaults to CATEGORY_OTHER if invalid
        """
        if not category or category not in self.CATEGORIES:
            current_app.logger.warning(f"Invalid permission category: {category}, using default")
            return self.CATEGORY_OTHER
        return category

    @property
    def resource(self) -> str:
        """
        Get the resource part of the permission name.

        Returns:
            str: Resource name or empty string if invalid format
        """
        try:
            return self.name.split(':')[0]
        except (AttributeError, IndexError):
            return ""

    @property
    def action(self) -> str:
        """
        Get the action part of the permission name.

        Returns:
            str: Action name or empty string if invalid format
        """
        try:
            parts = self.name.split(':')
            return parts[1] if len(parts) > 1 else ""
        except (AttributeError, IndexError):
            return ""

    def set_active(self, active: bool) -> bool:
        """
        Set the active status of the permission.

        Args:
            active: The new active status

        Returns:
            bool: True if successful, False otherwise

        Raises:
            ValueError: If trying to deactivate a system permission
        """
        if self.is_system and not active:
            raise ValueError("Cannot deactivate system-defined permissions")

        # If status is already what we want, do nothing
        if self.is_active == active:
            return True

        try:
            self.is_active = active
            db.session.commit()

            # Log the change
            action = 'activate' if active else 'deactivate'
            self.log_change(['is_active'], f"Permission {action}d")

            # Log security event for permission status changes
            log_security_event(
                event_type=f"permission_{action}d",
                description=f"Permission '{self.name}' was {action}d",
                severity="warning",
                details={
                    "permission_id": self.id,
                    "permission_name": self.name,
                    "category": self.category
                }
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error {action}ing permission: {str(e)}")
            return False

    def update_description(self, description: str) -> bool:
        """
        Update the permission description.

        Args:
            description: New description text

        Returns:
            bool: True if successful, False otherwise

        Raises:
            ValueError: If trying to modify a system permission
        """
        if self.is_system:
            raise ValueError("Cannot modify system-defined permissions")

        try:
            self.description = description
            db.session.commit()

            # Log the change
            self.log_change(['description'], "Permission description updated")

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating permission description: {str(e)}")
            return False

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert permission to dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary containing permission data
        """
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'category': self.category,
            'resource': self.resource,
            'action': self.action,
            'is_active': self.is_active,
            'is_system': self.is_system,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def to_detailed_dict(self) -> Dict[str, Any]:
        """
        Convert permission to a detailed dictionary representation.

        Returns:
            Dict[str, Any]: Detailed dictionary containing permission data and related information
        """
        basic_dict = self.to_dict()

        # Add statistics about permission usage if possible
        try:
            from models.auth.role import Role

            # Get roles with this permission
            roles_with_permission = Role.query.join(Role.permissions).filter(
                Permission.id == self.id
            ).all()

            # Add usage information
            basic_dict['usage'] = {
                'roles_count': len(roles_with_permission),
                'roles': [r.name for r in roles_with_permission],
                'is_orphaned': len(roles_with_permission) == 0
            }

            # Add dynamic rules if any
            basic_dict['dynamic_rules'] = [
                {
                    'id': rule.id,
                    'attribute': rule.attribute_name,
                    'operator': rule.operator,
                    'value': rule.value
                }
                for rule in self.dynamic_rules
            ] if hasattr(self, 'dynamic_rules') else []

        except Exception as e:
            current_app.logger.warning(f"Could not get detailed permission information: {str(e)}")

        return basic_dict

    @classmethod
    def get_by_name(cls, name: str) -> Optional['Permission']:
        """
        Get a permission by its name (case-insensitive).

        Args:
            name: The permission name to search for

        Returns:
            Optional[Permission]: The permission if found, None otherwise
        """
        if not name:
            return None

        return cls.query.filter(func.lower(cls.name) == func.lower(name.strip())).first()

    @classmethod
    def get_by_resource(cls, resource: str, active_only: bool = True) -> List['Permission']:
        """
        Get all permissions for a specific resource.

        Args:
            resource: The resource name
            active_only: Whether to return only active permissions

        Returns:
            List[Permission]: List of permissions for the resource
        """
        if not resource:
            return []

        query = cls.query.filter(cls.name.startswith(f"{resource}:"))

        if active_only:
            query = query.filter_by(is_active=True)

        return query.order_by(cls.name).all()

    @classmethod
    def get_by_resource_action(cls, resource: str, action: str) -> Optional['Permission']:
        """
        Get a specific permission by resource and action.

        Args:
            resource: The resource name
            action: The action name

        Returns:
            Optional[Permission]: The permission if found, None otherwise
        """
        if not resource or not action:
            return None

        permission_name = f"{resource}:{action}"
        return cls.get_by_name(permission_name)

    @classmethod
    def get_by_category(cls, category: str, active_only: bool = True) -> List['Permission']:
        """
        Get all permissions in a specific category.

        Args:
            category: The category name
            active_only: Whether to return only active permissions

        Returns:
            List[Permission]: List of permissions in the category
        """
        if not category:
            return []

        query = cls.query.filter_by(category=category)

        if active_only:
            query = query.filter_by(is_active=True)

        return query.order_by(cls.name).all()

    @classmethod
    def search(cls, search_term: str, active_only: bool = True) -> List['Permission']:
        """
        Search for permissions by name or description.

        Args:
            search_term: The search term to find
            active_only: Whether to return only active permissions

        Returns:
            List[Permission]: List of matching permissions
        """
        if not search_term:
            return []

        search_pattern = f"%{search_term.lower()}%"
        query = cls.query.filter(
            or_(
                func.lower(cls.name).like(search_pattern),
                func.lower(cls.description).like(search_pattern)
            )
        )

        if active_only:
            query = query.filter_by(is_active=True)

        return query.order_by(cls.name).all()

    @classmethod
    def get_all_resources(cls, active_only: bool = True) -> List[str]:
        """
        Get a list of all resource names used in permissions.

        Args:
            active_only: Whether to consider only active permissions

        Returns:
            List[str]: List of unique resource names
        """
        query = """
            SELECT DISTINCT SUBSTRING_INDEX(name, ':', 1) as resource
            FROM permissions
        """

        if active_only:
            query += " WHERE is_active = TRUE"

        query += " ORDER BY resource"

        result = db.session.execute(query)
        return [row[0] for row in result]

    @classmethod
    def get_grouped_by_resource(cls, active_only: bool = True) -> Dict[str, List['Permission']]:
        """
        Group permissions by resource name.

        Args:
            active_only: Whether to include only active permissions

        Returns:
            Dict[str, List['Permission']]: Dictionary of resource names to permission lists
        """
        query = cls.query
        if active_only:
            query = query.filter_by(is_active=True)

        permissions = query.all()
        grouped = {}

        for perm in permissions:
            resource = perm.resource
            if resource not in grouped:
                grouped[resource] = []
            grouped[resource].append(perm)

        return grouped

    @classmethod
    def initialize_default_permissions(cls) -> None:
        """
        Initialize default system permissions if they don't exist.
        """
        default_permissions = [
            # User management permissions
            {
                'name': 'users:create',
                'description': 'Create new user accounts',
                'category': cls.CATEGORY_USER_MANAGEMENT,
                'is_system': True
            },
            {
                'name': 'users:read',
                'description': 'View user information',
                'category': cls.CATEGORY_USER_MANAGEMENT,
                'is_system': True
            },
            {
                'name': 'users:update',
                'description': 'Modify user accounts',
                'category': cls.CATEGORY_USER_MANAGEMENT,
                'is_system': True
            },
            {
                'name': 'users:delete',
                'description': 'Delete user accounts',
                'category': cls.CATEGORY_USER_MANAGEMENT,
                'is_system': True
            },

            # Role management permissions
            {
                'name': 'roles:create',
                'description': 'Create new roles',
                'category': cls.CATEGORY_ROLE_MANAGEMENT,
                'is_system': True
            },
            {
                'name': 'roles:read',
                'description': 'View role information',
                'category': cls.CATEGORY_ROLE_MANAGEMENT,
                'is_system': True
            },
            {
                'name': 'roles:update',
                'description': 'Modify roles',
                'category': cls.CATEGORY_ROLE_MANAGEMENT,
                'is_system': True
            },
            {
                'name': 'roles:delete',
                'description': 'Delete roles',
                'category': cls.CATEGORY_ROLE_MANAGEMENT,
                'is_system': True
            },

            # Permission management
            {
                'name': 'permissions:assign',
                'description': 'Assign permissions to roles',
                'category': cls.CATEGORY_ROLE_MANAGEMENT,
                'is_system': True
            },
            {
                'name': 'permissions:manage',
                'description': 'Create, update, delete permissions',
                'category': cls.CATEGORY_ROLE_MANAGEMENT,
                'is_system': True
            },

            # Cloud resource permissions
            {
                'name': 'cloud_resources:create',
                'description': 'Create cloud resources',
                'category': cls.CATEGORY_CLOUD_RESOURCES,
                'is_system': True
            },
            {
                'name': 'cloud_resources:read',
                'description': 'View cloud resources',
                'category': cls.CATEGORY_CLOUD_RESOURCES,
                'is_system': True
            },
            {
                'name': 'cloud_resources:update',
                'description': 'Modify cloud resources',
                'category': cls.CATEGORY_CLOUD_RESOURCES,
                'is_system': True
            },
            {
                'name': 'cloud_resources:delete',
                'description': 'Delete cloud resources',
                'category': cls.CATEGORY_CLOUD_RESOURCES,
                'is_system': True
            },
            {
                'name': 'cloud_resources:start',
                'description': 'Start cloud resources',
                'category': cls.CATEGORY_CLOUD_RESOURCES,
                'is_system': True
            },
            {
                'name': 'cloud_resources:stop',
                'description': 'Stop cloud resources',
                'category': cls.CATEGORY_CLOUD_RESOURCES,
                'is_system': True
            },

            # ICS permissions
            {
                'name': 'ics_devices:read',
                'description': 'View ICS device information',
                'category': cls.CATEGORY_ICS,
                'is_system': True
            },
            {
                'name': 'ics_devices:update',
                'description': 'Modify ICS device settings',
                'category': cls.CATEGORY_ICS,
                'is_system': True
            },
            {
                'name': 'ics_devices:control',
                'description': 'Send control commands to ICS devices',
                'category': cls.CATEGORY_ICS,
                'is_system': True
            },

            # Security permissions
            {
                'name': 'security_logs:read',
                'description': 'View security logs',
                'category': cls.CATEGORY_SECURITY,
                'is_system': True
            },
            {
                'name': 'security_incidents:manage',
                'description': 'Manage security incidents',
                'category': cls.CATEGORY_SECURITY,
                'is_system': True
            },

            # Configuration permissions
            {
                'name': 'system_config:read',
                'description': 'View system configuration',
                'category': cls.CATEGORY_CONFIG,
                'is_system': True
            },
            {
                'name': 'system_config:update',
                'description': 'Update system configuration',
                'category': cls.CATEGORY_CONFIG,
                'is_system': True
            },

            # Monitoring permissions
            {
                'name': 'monitoring:read',
                'description': 'View monitoring data',
                'category': cls.CATEGORY_MONITORING,
                'is_system': True
            },
            {
                'name': 'monitoring:manage',
                'description': 'Manage monitoring settings',
                'category': cls.CATEGORY_MONITORING,
                'is_system': True
            },

            # Reporting permissions
            {
                'name': 'reports:generate',
                'description': 'Generate system reports',
                'category': cls.CATEGORY_REPORTING,
                'is_system': True
            },
            {
                'name': 'reports:view',
                'description': 'View system reports',
                'category': cls.CATEGORY_REPORTING,
                'is_system': True
            }
        ]

        created_count = 0

        for perm_data in default_permissions:
            # Check if permission already exists
            existing_perm = cls.get_by_name(perm_data['name'])
            if not existing_perm:
                try:
                    new_perm = cls(**perm_data)
                    db.session.add(new_perm)
                    created_count += 1
                except Exception as e:
                    current_app.logger.error(f"Error creating default permission {perm_data['name']}: {str(e)}")

        if created_count > 0:
            try:
                db.session.commit()
                current_app.logger.info(f"Created {created_count} default permissions")

                # Log security event for new permission creation
                log_security_event(
                    event_type="default_permissions_created",
                    description=f"Created {created_count} default system permissions",
                    severity="info",
                    details={"count": created_count}
                )
            except SQLAlchemyError as e:
                db.session.rollback()
                current_app.logger.error(f"Error saving default permissions: {str(e)}")

    @classmethod
    def create_custom_permission(cls, name: str, description: str, category: str) -> Optional['Permission']:
        """
        Create a new custom permission.

        Args:
            name: Permission name in 'resource:action' format
            description: Human-readable description
            category: Category for organizing the permission

        Returns:
            Optional[Permission]: The created permission if successful, None otherwise
        """
        try:
            # Check if permission already exists
            existing = cls.get_by_name(name)
            if existing:
                current_app.logger.warning(f"Permission {name} already exists")
                return None

            permission = cls(
                name=name,
                description=description,
                category=category,
                is_active=True,
                is_system=False
            )

            db.session.add(permission)
            db.session.commit()

            # Log security event for new permission creation
            log_security_event(
                event_type="custom_permission_created",
                description=f"Created custom permission '{permission.name}'",
                severity="warning",
                details={
                    "permission_id": permission.id,
                    "permission_name": permission.name,
                    "category": permission.category
                }
            )

            return permission
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating custom permission {name}: {str(e)}")
            return None

    def __eq__(self, other: Any) -> bool:
        """Equal operator for comparing two Permission objects."""
        if not isinstance(other, Permission):
            return False
        return self.id == other.id and self.name == other.name

    def __hash__(self) -> int:
        """Generate a hash for a Permission object."""
        return hash((self.id, self.name))

    def __repr__(self) -> str:
        """String representation of the Permission object."""
        return f"<Permission {self.id}: {self.name}>"


class DynamicPermissionRule(BaseModel):
    """Represents a dynamic rule for permission checking."""
    __tablename__ = 'dynamic_permission_rules'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    permission_id = db.Column(db.Integer, db.ForeignKey('permissions.id', ondelete='CASCADE'))
    attribute_name = db.Column(db.String(100), nullable=False)
    operator = db.Column(db.String(20), nullable=False)  # eq, ne, gt, lt, contains, etc.
    value = db.Column(db.String(255), nullable=False)

    # Relationship to permission
    permission = relationship('Permission', backref='dynamic_rules')

    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True),
                         default=lambda: datetime.now(timezone.utc),
                         onupdate=lambda: datetime.now(timezone.utc),
                         nullable=False)

    def evaluate(self, context: Dict[str, Any]) -> bool:
        """
        Evaluate this rule against a context.

        Args:
            context: Dictionary containing contextual attributes to check against

        Returns:
            bool: True if the rule matches the context, False otherwise
        """
        if self.attribute_name not in context:
            return False

        attr_value = context[self.attribute_name]

        if self.operator == 'eq':
            return str(attr_value) == self.value
        elif self.operator == 'ne':
            return str(attr_value) != self.value
        elif self.operator == 'contains':
            return self.value in str(attr_value)
        elif self.operator == 'gt':
            try:
                return float(attr_value) > float(self.value)
            except (ValueError, TypeError):
                return False
        elif self.operator == 'lt':
            try:
                return float(attr_value) < float(self.value)
            except (ValueError, TypeError):
                return False
        elif self.operator == 'gte':
            try:
                return float(attr_value) >= float(self.value)
            except (ValueError, TypeError):
                return False
        elif self.operator == 'lte':
            try:
                return float(attr_value) <= float(self.value)
            except (ValueError, TypeError):
                return False
        elif self.operator == 'in':
            try:
                values = [v.strip() for v in self.value.split(',')]
                return str(attr_value) in values
            except Exception:
                return False
        elif self.operator == 'not_in':
            try:
                values = [v.strip() for v in self.value.split(',')]
                return str(attr_value) not in values
            except Exception:
                return False
        elif self.operator == 'starts_with':
            return str(attr_value).startswith(self.value)
        elif self.operator == 'ends_with':
            return str(attr_value).endswith(self.value)

        return False

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert rule to dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary containing rule data
        """
        return {
            'id': self.id,
            'permission_id': self.permission_id,
            'attribute_name': self.attribute_name,
            'operator': self.operator,
            'value': self.value,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self) -> str:
        """String representation of the DynamicPermissionRule object."""
        return f"<DynamicPermissionRule {self.id}: {self.attribute_name} {self.operator} {self.value}>"


class PermissionDelegation(BaseModel, AuditableMixin):
    """Represents a temporary delegation of permissions between users."""
    __tablename__ = 'permission_delegations'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    delegator_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
    delegate_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
    permission_id = db.Column(db.Integer, db.ForeignKey('permissions.id', ondelete='CASCADE'))
    reason = db.Column(db.String(255), nullable=True)
    valid_from = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    valid_until = db.Column(db.DateTime(timezone=True), nullable=False)
    is_active = db.Column(db.Boolean, default=True)

    # Relationships
    delegator = relationship('User', foreign_keys=[delegator_id])
    delegate = relationship('User', foreign_keys=[delegate_id])
    permission = relationship('Permission')

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['delegate_id', 'permission_id', 'valid_until', 'is_active']

    # Enable access auditing for this model due to its sensitive nature
    AUDIT_ACCESS = True

    @validates('valid_until')
    def validate_valid_until(self, key, valid_until):
        """
        Validate delegation expiration date.

        Args:
            key: Field name being validated
            valid_until: Expiration date to validate

        Returns:
            datetime: Validated expiration date

        Raises:
            ValueError: If expiration date is not in the future
        """
        if valid_until <= datetime.now(timezone.utc):
            raise ValueError("Delegation expiration must be in the future")

        # Maximum delegation period (e.g., 7 days)
        max_period = datetime.now(timezone.utc) + timedelta(days=7)
        if valid_until > max_period:
            return max_period

        return valid_until

    def revoke(self, revoked_by_id: int, reason: Optional[str] = None) -> bool:
        """
        Revoke this delegation before its expiration time.

        Args:
            revoked_by_id: ID of the user revoking the delegation
            reason: Optional reason for revocation

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_active:
            # Already revoked
            return True

        try:
            self.is_active = False
            db.session.commit()

            # Log the revocation
            revocation_details = {
                "revoked_by_id": revoked_by_id,
                "delegation_id": self.id,
                "permission": self.permission.name if self.permission else None,
                "delegate": self.delegate.email if self.delegate else None,
                "delegator": self.delegator.email if self.delegator else None
            }

            if reason:
                revocation_details["reason"] = reason

            # Record audit
            self.log_change(
                fields_changed=["is_active"],
                details=f"Permission delegation revoked: {self.permission.name if self.permission else 'unknown'}"
            )

            # Log security event
            log_security_event(
                event_type="permission_delegation_revoked",
                description=f"Permission delegation of '{self.permission.name if self.permission else 'unknown'}' was revoked",
                severity="info",
                details=revocation_details
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error revoking permission delegation: {str(e)}")
            return False

    def is_valid(self) -> bool:
        """
        Check if the delegation is currently valid.

        Returns:
            bool: True if delegation is active and within its validity period
        """
        now = datetime.now(timezone.utc)
        return (self.is_active and
                self.valid_from <= now <= self.valid_until)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert delegation to dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary containing delegation data
        """
        return {
            'id': self.id,
            'delegator_id': self.delegator_id,
            'delegate_id': self.delegate_id,
            'permission_id': self.permission_id,
            'permission_name': self.permission.name if self.permission else None,
            'reason': self.reason,
            'valid_from': self.valid_from.isoformat() if self.valid_from else None,
            'valid_until': self.valid_until.isoformat() if self.valid_until else None,
            'is_active': self.is_active,
            'is_valid': self.is_valid(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    @classmethod
    def create_delegation(cls, delegator_id: int, delegate_id: int,
                         permission_id: int, valid_until: datetime,
                         reason: Optional[str] = None) -> Optional['PermissionDelegation']:
        """
        Create a new permission delegation.

        Args:
            delegator_id: ID of the user delegating the permission
            delegate_id: ID of the user receiving the delegation
            permission_id: ID of the permission being delegated
            valid_until: When the delegation expires
            reason: Optional reason for the delegation

        Returns:
            Optional[PermissionDelegation]: The created delegation if successful, None otherwise
        """
        try:
            delegation = cls(
                delegator_id=delegator_id,
                delegate_id=delegate_id,
                permission_id=permission_id,
                valid_until=valid_until,
                reason=reason
            )

            db.session.add(delegation)
            db.session.commit()

            # Log security event
            from models.auth.permission import Permission
            permission = Permission.query.get(permission_id)
            permission_name = permission.name if permission else "unknown"

            log_security_event(
                event_type="permission_delegation_created",
                description=f"Permission '{permission_name}' delegated",
                severity="info",
                details={
                    "delegator_id": delegator_id,
                    "delegate_id": delegate_id,
                    "permission_id": permission_id,
                    "permission_name": permission_name,
                    "valid_until": valid_until.isoformat(),
                    "reason": reason
                }
            )

            return delegation
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating permission delegation: {str(e)}")
            return None

    @classmethod
    def get_active_for_user(cls, user_id: int) -> List['PermissionDelegation']:
        """
        Get all active delegations for a specific user.

        Args:
            user_id: ID of the user to get delegations for

        Returns:
            List[PermissionDelegation]: List of active delegations
        """
        now = datetime.now(timezone.utc)
        return cls.query.filter(
            cls.delegate_id == user_id,
            cls.is_active == True,
            cls.valid_from <= now,
            cls.valid_until >= now
        ).all()

    def __repr__(self) -> str:
        """String representation of the PermissionDelegation object."""
        return f"<PermissionDelegation {self.id}: {self.delegator_id} -> {self.delegate_id}>"
