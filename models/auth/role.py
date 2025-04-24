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


# Association table for role-permission relationship with expiration
role_permissions = db.Table(
    'role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id', ondelete='CASCADE'), primary_key=True),
    db.Column('created_at', db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
    db.Column('expires_at', db.DateTime(timezone=True), nullable=True),
    db.Column('granted_by_id', db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
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
    ROLE_API = 'api'
    ROLE_SECURITY = 'security'
    ROLE_COMPLIANCE = 'compliance'
    ROLE_READONLY = 'readonly'

    # Permission requirements for role operations
    PERMISSION_CREATE_ROLE = 'roles:create'
    PERMISSION_READ_ROLE = 'roles:read'
    PERMISSION_UPDATE_ROLE = 'roles:update'
    PERMISSION_DELETE_ROLE = 'roles:delete'
    PERMISSION_ASSIGN_PERMISSIONS = 'permissions:assign'

    # Maximum role hierarchy depth to prevent performance issues
    MAX_HIERARCHY_DEPTH = 5

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

        name = name.strip()
        if len(name) > 50:
            raise ValueError("Role name cannot exceed 50 characters")

        # Ensure name follows proper format (alphanumeric with underscores)
        if not all(c.isalnum() or c == '_' for c in name):
            raise ValueError("Role name can only contain alphanumeric characters and underscores")

        # Check for uniqueness (case insensitive)
        existing_role = Role.query.filter(
            and_(
                func.lower(Role.name) == func.lower(name),
                Role.id != getattr(self, 'id', None)
            )
        ).first()

        if existing_role:
            raise ValueError(f"Role name '{name}' already exists")

        # Check for reserved names if this is not a system role
        reserved_names = ['superadmin', 'super_admin', 'root', 'administrator', 'system']
        if not self.is_system and name.lower() in reserved_names:
            raise ValueError(f"Role name '{name}' is reserved for system use")

        return name

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
            ValueError: If parent ID would create a circular reference or exceed maximum depth
        """
        if parent_id is None:
            return None

        # Can't set parent to self
        if hasattr(self, 'id') and self.id is not None and parent_id == self.id:
            raise ValueError("A role cannot be its own parent")

        # Check if parent role exists
        parent_role = Role.query.get(parent_id)
        if not parent_role:
            raise ValueError(f"Parent role with ID {parent_id} does not exist")

        # Check for circular references
        if hasattr(self, 'id') and self.id is not None:
            current_parent = parent_role
            depth = 0
            # Check for circular references and maximum hierarchy depth
            while current_parent is not None:
                depth += 1
                if depth > self.MAX_HIERARCHY_DEPTH:
                    raise ValueError(f"Role hierarchy exceeds maximum depth of {self.MAX_HIERARCHY_DEPTH}")

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
            ValueError: If trying to modify a system role or permission is not active
        """
        from models.auth.permission import Permission

        if self.is_system and not hasattr(permission, 'is_system'):
            raise ValueError("Cannot modify system-defined roles")

        # Verify the permission is active
        if not permission.is_active:
            raise ValueError("Cannot add inactive permission to role")

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

        return True  # Permission already exists in role

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
                # Skip inactive permissions
                if not permission.is_active:
                    continue

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

                # Log security event for bulk permission changes
                log_security_event(
                    event_type="role_permissions_added",
                    description=f"Added {added_count} permissions to role '{self.name}'",
                    severity="warning",
                    details={
                        "role_id": self.id,
                        "role_name": self.name,
                        "permissions_added": added_count
                    }
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

        return True  # Permission already not in role

    def has_permission_by_name(self, permission_name: str) -> bool:
        """
        Check if this role has a permission by its name.

        Args:
            permission_name: Name of the permission to check

        Returns:
            bool: True if the role has the permission, False otherwise
        """
        # Direct permission check by name
        for perm in self.permissions:
            if perm.name == permission_name and perm.is_active:
                return True

        # Check parent roles for inherited permissions
        if self.parent_id and self.parent:
            return self.parent.has_permission_by_name(permission_name)

        return False

    def has_permission(self, permission: 'Permission') -> bool:
        """
        Check if this role has a specific permission.

        Args:
            permission: The permission to check

        Returns:
            bool: True if the role has the permission, False otherwise
        """
        # Get the current time for expiration check
        now = datetime.now(timezone.utc)

        # Check direct permissions with expiration check
        for assoc in db.session.query(role_permissions).filter(
            role_permissions.c.role_id == self.id,
            role_permissions.c.permission_id == permission.id,
            or_(
                role_permissions.c.expires_at.is_(None),
                role_permissions.c.expires_at > now
            )
        ).all():
            return True

        # Check parent roles for inherited permissions (recursive)
        if self.parent_id and self.parent:
            return self.parent.has_permission(permission)

        return False

    def has_permission_with_context(self, permission_name: str, context: Dict[str, Any] = None) -> bool:
        """
        Check if role has a permission in a specific context.

        Args:
            permission_name: Name of the permission to check
            context: Contextual data for dynamic permission rules

        Returns:
            bool: True if role has permission in this context
        """
        from models.auth.permission import Permission

        # First check if role has the base permission
        if not self.has_permission_by_name(permission_name):
            return False

        if not context:
            return True

        # Get the permission object
        permission = Permission.get_by_name(permission_name)
        if not permission:
            return False

        # Evaluate dynamic rules if they exist
        if hasattr(permission, 'dynamic_rules'):
            for rule in permission.dynamic_rules:
                if not rule.evaluate(context):
                    return False

        return True

    def get_all_permissions(self, include_inactive: bool = False) -> Set['Permission']:
        """
        Get all permissions for this role, including inherited ones.

        Args:
            include_inactive: Whether to include inactive permissions

        Returns:
            Set[Permission]: Set of all permissions
        """
        # Get direct permissions
        if include_inactive:
            all_permissions = set(self.permissions)
        else:
            all_permissions = {p for p in self.permissions if p.is_active}

        # Add parent permissions if available
        if self.parent_id and self.parent:
            all_permissions.update(self.parent.get_all_permissions(include_inactive))

        return all_permissions

    def get_permission_names(self, include_inactive: bool = False) -> List[str]:
        """
        Get names of all permissions for this role, including inherited ones.

        Args:
            include_inactive: Whether to include inactive permissions

        Returns:
            List[str]: List of permission names
        """
        all_permissions = self.get_all_permissions(include_inactive)
        return sorted([p.name for p in all_permissions])

    def get_effective_permissions(self) -> Dict[str, Dict[str, Any]]:
        """
        Get a dictionary of effective permissions with their sources.

        Returns:
            Dict: Dictionary mapping permission names to their details and source roles
        """
        result = {}

        # Add direct permissions
        for perm in self.permissions:
            if perm.is_active:
                result[perm.name] = {
                    'id': perm.id,
                    'name': perm.name,
                    'description': perm.description,
                    'source_role': self.name,
                    'source_role_id': self.id,
                    'is_inherited': False
                }

        # Add inherited permissions
        if self.parent_id and self.parent:
            parent_permissions = self.parent.get_effective_permissions()

            # Add parent permissions that aren't overridden locally
            for perm_name, perm_details in parent_permissions.items():
                if perm_name not in result:
                    perm_details['is_inherited'] = True
                    result[perm_name] = perm_details

        return result

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

            # Check if this role is a parent of other roles before deactivating
            if not active and self.children.count() > 0:
                child_roles = [child.name for child in self.children]
                current_app.logger.warning(
                    f"Deactivating role {self.name} will affect child roles: {', '.join(child_roles)}"
                )

            self.is_active = active
            db.session.commit()

            # Log the change
            self.log_change(['is_active'], f"Role status changed from {old_status} to {new_status}")

            # Log security event for role deactivation (security sensitive)
            severity = "warning" if not active else "info"
            event_type = "role_deactivated" if not active else "role_activated"

            log_security_event(
                event_type=event_type,
                description=f"Role '{self.name}' was {new_status}",
                severity=severity,
                details={
                    "role_id": self.id,
                    "role_name": self.name,
                    "previous_status": old_status,
                    "new_status": new_status
                }
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            action = 'activating' if active else 'deactivating'
            current_app.logger.error(f"Error {action} role: {str(e)}")
            return False

    def update_description(self, description: str) -> bool:
        """
        Update the role description.

        Args:
            description: New role description

        Returns:
            bool: True if successful, False otherwise

        Raises:
            ValueError: If trying to modify a system role
        """
        if self.is_system:
            raise ValueError("Cannot modify system-defined roles")

        if self.description == description:
            return True  # No change needed

        try:
            self.description = description
            db.session.commit()

            # Log the change
            self.log_change(['description'], "Role description updated")
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating role description: {str(e)}")
            return False

    def set_parent(self, parent_id: Optional[int]) -> bool:
        """
        Update the parent role.

        Args:
            parent_id: ID of the new parent role, or None to remove parent

        Returns:
            bool: True if successful, False otherwise

        Raises:
            ValueError: If trying to modify a system role or creating circular reference
        """
        if self.is_system:
            raise ValueError("Cannot modify system-defined roles")

        if self.parent_id == parent_id:
            return True  # No change needed

        try:
            # Validate the new parent_id
            self.parent_id = self.validate_parent_id('parent_id', parent_id)
            db.session.commit()

            # Log the change
            if parent_id:
                parent_role = Role.query.get(parent_id)
                parent_name = parent_role.name if parent_role else "unknown"
                self.log_change(['parent_id'], f"Role parent updated to {parent_name}")

                # Log security event for role hierarchy changes
                log_security_event(
                    event_type="role_hierarchy_changed",
                    description=f"Role '{self.name}' now inherits from '{parent_name}'",
                    severity="info",
                    details={
                        "role_id": self.id,
                        "role_name": self.name,
                        "parent_id": parent_id,
                        "parent_name": parent_name
                    }
                )
            else:
                self.log_change(['parent_id'], "Role parent removed")

                # Log security event for role hierarchy removal
                log_security_event(
                    event_type="role_hierarchy_removed",
                    description=f"Role '{self.name}' no longer inherits from any parent",
                    severity="info",
                    details={
                        "role_id": self.id,
                        "role_name": self.name
                    }
                )

            return True
        except ValueError as e:
            # Re-raise ValueError for API to catch and display to user
            raise
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating role parent: {str(e)}")
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
    def search(cls, query: str, include_inactive: bool = False) -> List['Role']:
        """
        Search for roles by name or description.

        Args:
            query: Search term
            include_inactive: Whether to include inactive roles

        Returns:
            List[Role]: List of matching roles
        """
        if not query:
            return []

        search_query = cls.query

        if not include_inactive:
            search_query = search_query.filter_by(is_active=True)

        search_pattern = f"%{query.lower()}%"
        return search_query.filter(
            or_(
                func.lower(cls.name).like(search_pattern),
                func.lower(cls.description).like(search_pattern)
            )
        ).order_by(cls.name).all()

    @classmethod
    def initialize_default_roles(cls) -> None:
        """
        Initialize default system roles if they don't exist.
        """
        default_roles = [
            {
                'name': cls.ROLE_ADMIN,
                'description': 'Administrative access with all permissions',
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
                'description': 'Audit and compliance access (read-only)',
                'is_system': True
            },
            {
                'name': cls.ROLE_GUEST,
                'description': 'Limited read-only access',
                'is_system': True
            },
            {
                'name': cls.ROLE_API,
                'description': 'API access for service accounts',
                'is_system': True
            },
            {
                'name': cls.ROLE_SECURITY,
                'description': 'Security management access',
                'is_system': True
            },
            {
                'name': cls.ROLE_COMPLIANCE,
                'description': 'Compliance management access',
                'is_system': True
            },
            {
                'name': cls.ROLE_READONLY,
                'description': 'Read-only access across all resources',
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

                # Log security event for role creation
                log_security_event(
                    event_type="default_roles_created",
                    description=f"Created {created_count} default system roles",
                    severity="info",
                    details={"count": created_count}
                )
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

    @classmethod
    def get_hierarchy_tree(cls) -> Dict[str, Any]:
        """
        Generate a hierarchical tree representation of roles and their permissions.

        Returns:
            Dict[str, Any]: Dictionary representing the role hierarchy with inherited permissions
        """
        all_roles = cls.query.all()
        root_roles = [r for r in all_roles if r.parent_id is None]

        def build_subtree(role):
            return {
                'id': role.id,
                'name': role.name,
                'description': role.description,
                'is_system': role.is_system,
                'is_active': role.is_active,
                'direct_permissions': [p.name for p in role.permissions],
                'all_permissions': role.get_permission_names(),
                'children': [build_subtree(child) for child in role.children]
            }

        return [build_subtree(role) for role in root_roles]

    @classmethod
    def get_permission_audit_data(cls) -> Dict[str, Any]:
        """
        Generate comprehensive audit data for all permissions.

        Returns:
            Dict: Structured permission audit information
        """
        from models.auth import User, Permission

        # Get all permissions and roles
        all_permissions = Permission.query.all()
        all_roles = cls.query.all()

        result = {
            'permissions_count': len(all_permissions),
            'active_permissions': len([p for p in all_permissions if p.is_active]),
            'system_permissions': len([p for p in all_permissions if p.is_system]),
            'custom_permissions': len([p for p in all_permissions if not p.is_system]),
            'permissions_by_category': {},
            'permission_usage': {},
            'orphaned_permissions': [],
            'most_used_permissions': [],
            'least_used_permissions': []
        }

        # Count by category
        for perm in all_permissions:
            if perm.category not in result['permissions_by_category']:
                result['permissions_by_category'][perm.category] = 0
            result['permissions_by_category'][perm.category] += 1

        # Check permission usage
        for perm in all_permissions:
            roles_with_perm = perm.roles.all()
            users_with_perm_count = User.query.join(User.roles).join(Role.permissions).filter(
                Permission.id == perm.id
            ).distinct().count()

            result['permission_usage'][perm.name] = {
                'roles_count': len(roles_with_perm),
                'roles': [r.name for r in roles_with_perm],
                'users_count': users_with_perm_count,
                'is_active': perm.is_active,
                'is_system': perm.is_system,
                'category': perm.category
            }

            if not roles_with_perm:
                result['orphaned_permissions'].append(perm.name)

        # Sort by usage
        usage_data = [(name, data['users_count']) for name, data in result['permission_usage'].items()]
        usage_data.sort(key=lambda x: x[1], reverse=True)

        result['most_used_permissions'] = usage_data[:10]
        result['least_used_permissions'] = usage_data[-10:] if len(usage_data) >= 10 else usage_data

        return result

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
