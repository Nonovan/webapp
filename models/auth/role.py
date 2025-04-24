"""
Role model for authentication and authorization.

This module defines the Role model which represents user roles and permissions
in the Cloud Infrastructure Platform application. It provides the foundation for
role-based access control (RBAC) with hierarchical capabilities to support
complex authorization requirements.

Roles define sets of permissions that can be assigned to users, ensuring proper
access control across the application. The model supports role inheritance,
custom permission sets, and comprehensive access verification.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Union, cast
from sqlalchemy import and_, or_, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import relationship, validates
from flask import current_app

from extensions import db
from models.base import BaseModel, AuditableMixin
from core.security_utils import log_security_event
from models.auth.permission import Permission


# Association table for role-permission relationship
role_permissions = db.Table(
    'role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id', ondelete='CASCADE'), primary_key=True),
    db.Column('created_at', db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
)


class Role(BaseModel, AuditableMixin):
    """
    Represents a user role with associated permissions.

    This model defines roles that can be assigned to users, each containing
    a set of permissions that control access to various system features.
    Roles can inherit from other roles to support hierarchical access control.

    Attributes:
        id: Primary key
        name: Unique role name
        description: Role description
        is_active: Whether the role is currently active
        is_system: Whether this is a system-defined role that cannot be modified
        parent_id: Optional reference to a parent role for inheritance
        permissions: Many-to-many relationship with Permission model
        parent: Relationship to parent role
        children: Relationship to child roles
    """
    __tablename__ = 'roles'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['name', 'is_active', 'parent_id']

    # Enable access auditing for this model due to its sensitive nature
    AUDIT_ACCESS = True

    # Role constants
    ROLE_ADMIN = 'admin'
    ROLE_USER = 'user'
    ROLE_OPERATOR = 'operator'
    ROLE_AUDITOR = 'auditor'
    ROLE_GUEST = 'guest'

    # Permission requirements for role operations
    PERMISSION_CREATE_ROLE = 'roles:create'
    PERMISSION_READ_ROLE = 'roles:read'
    PERMISSION_UPDATE_ROLE = 'roles:update'
    PERMISSION_DELETE_ROLE = 'roles:delete'
    PERMISSION_ASSIGN_PERMISSIONS = 'permissions:assign'

    # Core fields
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), nullable=False, unique=True, index=True)
    description = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    is_system = db.Column(db.Boolean, default=False, nullable=False)

    # Self-referential relationship for role hierarchy
    parent_id = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete='SET NULL'), nullable=True, index=True)
    parent = relationship("Role", remote_side=[id], backref=db.backref("children", lazy="dynamic"))

    # Relationships
    permissions = relationship(
        "Permission",
        secondary=role_permissions,
        lazy="joined",
        backref=db.backref("roles", lazy="dynamic")
    )

    # User relationship is defined in the User model

    # Timestamps (inherited from BaseModel via TimestampMixin)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True),
                         default=lambda: datetime.now(timezone.utc),
                         onupdate=lambda: datetime.now(timezone.utc),
                         nullable=False)

    def __init__(self, name: str, description: Optional[str] = None,
                parent_id: Optional[int] = None,
                is_active: bool = True, is_system: bool = False) -> None:
        """
        Initialize a new role.

        Args:
            name: Role name (must be unique)
            description: Role description (optional)
            parent_id: ID of parent role for inheritance (optional)
            is_active: Whether the role is active
            is_system: Whether this is a system-defined role
        """
        self.name = name
        self.description = description
        self.parent_id = parent_id
        self.is_active = is_active
        self.is_system = is_system

    @validates('name')
    def validate_name(self, key: str, name: str) -> str:
        """
        Validate the role name.

        Args:
            key: Field name being validated
            name: Role name to validate

        Returns:
            str: Validated role name

        Raises:
            ValueError: If name is empty or invalid
        """
        if not name or not name.strip():
            raise ValueError("Role name cannot be empty")

        if len(name.strip()) > 50:
            raise ValueError("Role name cannot exceed 50 characters")

        # Check for uniqueness
        existing_role = Role.query.filter(
            and_(
                func.lower(Role.name) == func.lower(name.strip()),
                Role.id != getattr(self, 'id', None)
            )
        ).first()

        if existing_role:
            raise ValueError(f"Role name '{name}' already exists")

        # Check for reserved names if this is not a system role
        reserved_names = ['superadmin', 'super_admin', 'root', 'administrator', 'system']
        if not self.is_system and name.lower() in reserved_names:
            raise ValueError(f"Role name '{name}' is reserved for system use")

        return name.strip()

    @validates('parent_id')
    def validate_parent_id(self, key: str, parent_id: Optional[int]) -> Optional[int]:
        """
        Validate the parent role ID to prevent circular references.

        Args:
            key: Field name being validated
            parent_id: Parent role ID to validate

        Returns:
            Optional[int]: Validated parent role ID

        Raises:
            ValueError: If parent ID would create a circular reference
        """
        if parent_id is None:
            return None

        # Can't set parent to self
        if hasattr(self, 'id') and self.id is not None and parent_id == self.id:
            raise ValueError("A role cannot be its own parent")

        # Check for circular references
        if hasattr(self, 'id') and self.id is not None:
            parent_role = Role.query.get(parent_id)
            if parent_role:
                current_parent = parent_role
                while current_parent is not None:
                    if current_parent.parent_id == self.id:
                        raise ValueError("Circular reference detected in role hierarchy")
                    if current_parent.parent_id is None:
                        break
                    current_parent = current_parent.parent

        return parent_id

    def add_permission(self, permission: 'Permission') -> bool:
        """
        Add a permission to this role.

        Args:
            permission: The permission to add

        Returns:
            bool: True if successful, False otherwise

        Raises:
            ValueError: If trying to modify a system role
        """
        if self.is_system:
            raise ValueError("Cannot modify system-defined roles")

        if permission not in self.permissions:
            try:
                self.permissions.append(permission)
                db.session.commit()

                # Log the permission addition
                self._log_permission_change('add', permission)

                return True
            except SQLAlchemyError as e:
                db.session.rollback()
                current_app.logger.error(f"Error adding permission to role: {str(e)}")
                return False

        return False

    def add_permissions(self, permissions: List['Permission']) -> bool:
        """
        Add multiple permissions to this role.

        Args:
            permissions: List of permissions to add

        Returns:
            bool: True if successful, False otherwise

        Raises:
            ValueError: If trying to modify a system role
        """
        if self.is_system:
            raise ValueError("Cannot modify system-defined roles")

        if not permissions:
            return True

        try:
            added_count = 0
            for permission in permissions:
                if permission not in self.permissions:
                    self.permissions.append(permission)
                    added_count += 1

            if added_count > 0:
                db.session.commit()
                # Log the bulk permission addition
                self.log_change(
                    fields_changed=['permissions'],
                    details=f"Added {added_count} permissions to role"
                )
                return True
            return False
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error adding permissions to role: {str(e)}")
            return False

    def remove_permission(self, permission: 'Permission') -> bool:
        """
        Remove a permission from this role.

        Args:
            permission: The permission to remove

        Returns:
            bool: True if successful, False otherwise

        Raises:
            ValueError: If trying to modify a system role
        """
        if self.is_system:
            raise ValueError("Cannot modify system-defined roles")

        if permission in self.permissions:
            try:
                self.permissions.remove(permission)
                db.session.commit()

                # Log the permission removal
                self._log_permission_change('remove', permission)

                return True
            except SQLAlchemyError as e:
                db.session.rollback()
                current_app.logger.error(f"Error removing permission from role: {str(e)}")
                return False

        return False

    def has_permission(self, permission: 'Permission') -> bool:
        """
        Check if this role has a specific permission.

        Args:
            permission: The permission to check

        Returns:
            bool: True if the role has the permission, False otherwise
        """
        # Direct permission check
        if permission in self.permissions:
            return True

        # Check parent roles for inherited permissions (recursive)
        if self.parent_id and self.parent:
            return self.parent.has_permission(permission)

        return False

    def has_permission_by_name(self, permission_name: str) -> bool:
        """
        Check if this role has a permission by its name.

        Args:
            permission_name: Name of the permission to check

        Returns:
            bool: True if the role has the permission, False otherwise
        """
        # Import here to avoid circular imports
        from models.auth.permission import Permission

        # Direct permission check by name
        for perm in self.permissions:
            if perm.name == permission_name:
                return True

        # Check parent roles for inherited permissions
        if self.parent_id and self.parent:
            return self.parent.has_permission_by_name(permission_name)

        return False

    def get_all_permissions(self) -> Set['Permission']:
        """
        Get all permissions for this role, including inherited ones.

        Returns:
            Set[Permission]: Set of all permissions
        """
        all_permissions = set(self.permissions)

        # Add parent permissions if available
        if self.parent_id and self.parent:
            all_permissions.update(self.parent.get_all_permissions())

        return all_permissions

    def get_permission_names(self) -> List[str]:
        """
        Get names of all permissions for this role, including inherited ones.

        Returns:
            List[str]: List of permission names
        """
        all_permissions = self.get_all_permissions()
        return sorted([p.name for p in all_permissions])

    def set_active(self, active: bool) -> bool:
        """
        Set the active status of the role.

        Args:
            active: The new active status

        Returns:
            bool: True if successful, False otherwise

        Raises:
            ValueError: If trying to deactivate a system role
        """
        if self.is_system and not active:
            raise ValueError("Cannot deactivate system-defined roles")

        if self.is_active == active:
            return True  # No change needed

        try:
            old_status = "active" if self.is_active else "inactive"
            new_status = "active" if active else "inactive"

            self.is_active = active
            db.session.commit()

            # Log the change
            self.log_change(['is_active'], f"Role status changed from {old_status} to {new_status}")

            # Log security event for role deactivation (security sensitive)
            if not active:
                log_security_event(
                    event_type="role_deactivated",
                    description=f"Role '{self.name}' was deactivated",
                    severity="warning",
                    details={"role_id": self.id, "role_name": self.name}
                )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            action = 'activating' if active else 'deactivating'
            current_app.logger.error(f"Error {action} role: {str(e)}")
            return False

    def _log_permission_change(self, action: str, permission: 'Permission') -> None:
        """
        Log a permission change for auditing purposes.

        Args:
            action: The action performed (add/remove)
            permission: The permission that was changed
        """
        try:
            # Use the AuditableMixin's log_change method
            permission_name = getattr(permission, 'name', str(permission))
            self.log_change(
                fields_changed=['permissions'],
                details=f"{action.capitalize()}ed permission: {permission_name}"
            )

            # Log security event for permission changes
            log_security_event(
                event_type=f"role_permission_{action}ed",
                description=f"Permission '{permission_name}' {action}ed to/from role '{self.name}'",
                severity="warning",
                details={
                    "role_id": self.id,
                    "role_name": self.name,
                    "permission": permission_name,
                    "action": action
                }
            )
        except Exception as e:
            current_app.logger.error(f"Error logging permission change: {str(e)}")

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the role to a dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary representation of the role
        """
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'is_active': self.is_active,
            'is_system': self.is_system,
            'parent_id': self.parent_id,
            'parent_name': self.parent.name if self.parent else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'permissions': [p.name for p in self.permissions] if self.permissions else [],
            'all_permissions': self.get_permission_names()
        }

    def to_detailed_dict(self) -> Dict[str, Any]:
        """
        Convert the role to a dictionary with additional details.

        Returns:
            Dict[str, Any]: Detailed dictionary representation of the role
        """
        base_dict = self.to_dict()

        # Add permission details
        base_dict['permissions'] = [
            {
                'id': p.id,
                'name': p.name,
                'description': p.description
            }
            for p in self.permissions
        ] if self.permissions else []

        # Add inherited permissions separately
        if self.parent_id and self.parent:
            inherited_permissions = self.parent.get_all_permissions()
            base_dict['inherited_permissions'] = [
                {
                    'id': p.id,
                    'name': p.name,
                    'description': p.description,
                    'source_role': self._find_permission_source(p).name
                }
                for p in inherited_permissions
            ]

        # Add children information
        base_dict['children'] = [
            {
                'id': child.id,
                'name': child.name,
            }
            for child in self.children
        ] if self.children else []

        return base_dict

    def _find_permission_source(self, permission: 'Permission') -> 'Role':
        """
        Find the source role that directly contains a permission in the inheritance chain.

        Args:
            permission: The permission to find

        Returns:
            Role: The role that directly contains the permission
        """
        if permission in self.permissions:
            return self

        if self.parent:
            return self.parent._find_permission_source(permission)

        return self  # Fallback, shouldn't reach here if used correctly

    @classmethod
    def get_by_name(cls, name: str) -> Optional['Role']:
        """
        Get a role by its name (case-insensitive).

        Args:
            name: The role name to search for

        Returns:
            Optional[Role]: The role if found, None otherwise
        """
        if not name:
            return None

        return cls.query.filter(func.lower(cls.name) == func.lower(name.strip())).first()

    @classmethod
    def get_active_roles(cls) -> List['Role']:
        """
        Get all active roles.

        Returns:
            List[Role]: List of active roles
        """
        return cls.query.filter_by(is_active=True).order_by(cls.name).all()

    @classmethod
    def get_system_roles(cls) -> List['Role']:
        """
        Get all system-defined roles.

        Returns:
            List[Role]: List of system roles
        """
        return cls.query.filter_by(is_system=True).order_by(cls.name).all()

    @classmethod
    def get_roles_by_permission(cls, permission: 'Permission') -> List['Role']:
        """
        Get all roles that have a specific permission.

        Args:
            permission: The permission to search for

        Returns:
            List[Role]: List of roles with the permission
        """
        return permission.roles.filter_by(is_active=True).all()

    @classmethod
    def get_roles_by_permission_name(cls, permission_name: str) -> List['Role']:
        """
        Get all roles that have a specific permission by name.

        Args:
            permission_name: The permission name to search for

        Returns:
            List[Role]: List of roles with the permission
        """
        from models.auth.permission import Permission

        permission = Permission.get_by_name(permission_name)
        if not permission:
            return []

        return cls.get_roles_by_permission(permission)

    @classmethod
    def initialize_default_roles(cls) -> None:
        """
        Initialize default system roles if they don't exist.
        """
        default_roles = [
            {
                'name': cls.ROLE_ADMIN,
                'description': 'Administrative access',
                'is_system': True
            },
            {
                'name': cls.ROLE_USER,
                'description': 'Standard user access',
                'is_system': True
            },
            {
                'name': cls.ROLE_OPERATOR,
                'description': 'Operational tasks access',
                'is_system': True
            },
            {
                'name': cls.ROLE_AUDITOR,
                'description': 'Audit and compliance access',
                'is_system': True
            },
            {
                'name': cls.ROLE_GUEST,
                'description': 'Limited read-only access',
                'is_system': True
            }
        ]

        created_count = 0

        for role_data in default_roles:
            # Check if role already exists
            existing_role = cls.get_by_name(role_data['name'])
            if not existing_role:
                try:
                    new_role = cls(**role_data)
                    db.session.add(new_role)
                    created_count += 1
                except Exception as e:
                    current_app.logger.error(f"Error creating default role {role_data['name']}: {str(e)}")

        if created_count > 0:
            try:
                db.session.commit()
                current_app.logger.info(f"Created {created_count} default roles")
            except SQLAlchemyError as e:
                db.session.rollback()
                current_app.logger.error(f"Error saving default roles: {str(e)}")

    @classmethod
    def setup_admin_permissions(cls) -> bool:
        """
        Setup permissions for the admin role.

        This method ensures the admin role has all available permissions.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Import here to avoid circular imports
            from models.auth.permission import Permission

            # Get admin role
            admin_role = cls.get_by_name(cls.ROLE_ADMIN)
            if not admin_role:
                current_app.logger.error("Admin role not found when setting up permissions")
                return False

            # Get all active permissions
            all_permissions = Permission.query.filter_by(is_active=True).all()

            # Add all permissions to admin role
            added_count = 0
            for permission in all_permissions:
                if permission not in admin_role.permissions:
                    admin_role.permissions.append(permission)
                    added_count += 1

            if added_count > 0:
                db.session.commit()
                current_app.logger.info(f"Added {added_count} permissions to admin role")

                # Log security event for admin permission update
                log_security_event(
                    event_type="admin_permissions_updated",
                    description=f"Updated admin role with {added_count} permissions",
                    severity="info",
                    details={
                        "role_id": admin_role.id,
                        "role_name": admin_role.name,
                        "permissions_added": added_count
                    }
                )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error setting up admin permissions: {str(e)}")
            return False

    def __eq__(self, other: Any) -> bool:
        """
        Check if two roles are equal.

        Args:
            other: The other role to compare with

        Returns:
            bool: True if roles are equal, False otherwise
        """
        if not isinstance(other, Role):
            return False
        return self.id == other.id

    def __hash__(self) -> int:
        """
        Generate a hash for the role.

        Returns:
            int: Hash value based on the role ID
        """
        return hash(self.id)

    def __repr__(self) -> str:
        """String representation of the Role object."""
        return f"<Role {self.id}: {self.name}>"
