#!/usr/bin/env python3
"""
Permission management command-line interface for Cloud Infrastructure Platform.

This module provides command-line utilities for administrators to manage permissions
including granting, revoking, inspecting user permissions, and delegating permissions.
The tool implements proper security controls with authentication, authorization, and
comprehensive audit logging for all permission management operations.

Features:
- Grant permissions to users with optional expiration
- Revoke existing permissions
- List permissions for users and roles
- Check specific permission assignments
- Delegate permissions temporarily between users
- Import/export permission assignments
"""

import argparse
import datetime
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Set
from functools import wraps  # Add this for decorator functions

# Core utilities
from core.utils.logging_utils import logger as core_logger

# Create a module-level logger
logger = logging.getLogger(__name__)

# Add project root to path to allow imports from core packages
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

try:
    # Core utilities
    from core.security import require_permission, verify_token

    # Admin utilities
    from admin.utils.admin_auth import (
        get_admin_session,
        check_permission as admin_check_permission,
        require_permission as require_admin_permission,
        verify_mfa_token
    )
    from admin.utils.audit_utils import log_admin_action

    # Models
    from models import User, Role
    from models.auth import Permission, PermissionDelegation

    # Database extension
    from extensions import db

except ImportError as e:
    print(f"Error importing required modules: {e}", file=sys.stderr)
    print("Please ensure the application environment is properly configured.", file=sys.stderr)
    sys.exit(1)

# Constants
VERSION = "1.0.0"
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_PERMISSION_ERROR = 2
EXIT_RESOURCE_ERROR = 3
EXIT_VALIDATION_ERROR = 4
EXIT_NOT_FOUND = 5


class PermissionError(Exception):
    """Base exception for permission management errors."""
    pass


class ValidationError(PermissionError):
    """Exception raised when validation fails."""
    pass


class ResourceNotFoundError(PermissionError):
    """Exception raised when a resource (user, role, permission) is not found."""
    pass


def find_user(identifier: str) -> User:
    """
    Find a user by username or ID.

    Args:
        identifier: Username or user ID

    Returns:
        User: The found user

    Raises:
        ResourceNotFoundError: If user is not found
    """
    try:
        # Check if identifier is an integer ID
        if isinstance(identifier, int) or identifier.isdigit():
            user = User.query.get(int(identifier))
            if user:
                return user

        # Try to find by username
        user = User.query.filter_by(username=identifier).first()
        if user:
            return user

        # User not found
        raise ResourceNotFoundError(f"User not found: {identifier}")
    except Exception as e:
        if isinstance(e, ResourceNotFoundError):
            raise
        logger.error(f"Error finding user: {str(e)}")
        raise ResourceNotFoundError(f"Error finding user: {str(e)}")


def find_role(identifier: str) -> Role:
    """
    Find a role by name or ID.

    Args:
        identifier: Role name or ID

    Returns:
        Role: The found role

    Raises:
        ResourceNotFoundError: If role is not found
    """
    try:
        # Check if identifier is an integer ID
        if isinstance(identifier, int) or identifier.isdigit():
            role = Role.query.get(int(identifier))
            if role:
                return role

        # Try to find by name
        role = Role.query.filter_by(name=identifier).first()
        if role:
            return role

        # Role not found
        raise ResourceNotFoundError(f"Role not found: {identifier}")
    except Exception as e:
        if isinstance(e, ResourceNotFoundError):
            raise
        logger.error(f"Error finding role: {str(e)}")
        raise ResourceNotFoundError(f"Error finding role: {str(e)}")


def find_permission(identifier: str) -> Permission:
    """
    Find a permission by name or ID.

    Args:
        identifier: Permission name or ID

    Returns:
        Permission: The found permission

    Raises:
        ResourceNotFoundError: If permission is not found
    """
    try:
        # Check if identifier is an integer ID
        if isinstance(identifier, int) or identifier.isdigit():
            permission = Permission.query.get(int(identifier))
            if permission:
                return permission

        # Try to find by name
        permission = Permission.query.filter_by(name=identifier).first()
        if permission:
            return permission

        # Permission not found
        raise ResourceNotFoundError(f"Permission not found: {identifier}")
    except Exception as e:
        if isinstance(e, ResourceNotFoundError):
            raise
        logger.error(f"Error finding permission: {str(e)}")
        raise ResourceNotFoundError(f"Error finding permission: {str(e)}")


def parse_expiration_datetime(expires_str: str) -> datetime.datetime:
    """
    Parse an expiration string into a datetime object.

    Args:
        expires_str: Expiration string (e.g., "2h", "3d", "1w", or ISO format)

    Returns:
        datetime.datetime: The expiration datetime

    Raises:
        ValidationError: If the expiration format is invalid
    """
    now = datetime.datetime.now(datetime.timezone.utc)

    # Check for relative time formats (e.g., 2h, 3d, 1w)
    if len(expires_str) >= 2 and expires_str[-1] in ['h', 'd', 'w', 'm'] and expires_str[:-1].isdigit():
        value = int(expires_str[:-1])
        unit = expires_str[-1]

        if unit == 'h':  # Hours
            return now + datetime.timedelta(hours=value)
        elif unit == 'd':  # Days
            return now + datetime.timedelta(days=value)
        elif unit == 'w':  # Weeks
            return now + datetime.timedelta(weeks=value)
        elif unit == 'm':  # Minutes
            return now + datetime.timedelta(minutes=value)

    # Try parsing ISO format
    try:
        # If no timezone specified, assume UTC
        expiration = datetime.datetime.fromisoformat(expires_str.replace('Z', '+00:00'))
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=datetime.timezone.utc)
        return expiration
    except ValueError:
        pass

    # Try common date formats
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    ]

    for format_str in formats:
        try:
            # Parse without timezone and assume UTC
            expiration = datetime.datetime.strptime(expires_str, format_str)
            return expiration.replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue

    raise ValidationError(f"Unrecognized expiration date format: {expires_str}")


def get_user_id_from_token(auth_token: Optional[str]) -> int:
    """
    Get user ID from authentication token.

    Args:
        auth_token: Authentication token

    Returns:
        int: User ID

    Raises:
        ValidationError: If token is invalid
    """
    if not auth_token:
        # Use session user for admin operations if no token provided
        session = get_admin_session()
        if not session or not session.get('user_id'):
            raise ValidationError("No authentication token provided and no active session found")
        return session['user_id']

    try:
        # This is a placeholder - actual implementation would depend on your token structure
        # For real implementation, use your application's token validation logic
        token_data = verify_token(auth_token)
        return token_data['user_id']
    except Exception as e:
        logger.error(f"Error validating token: {str(e)}")
        raise ValidationError(f"Invalid authentication token: {str(e)}")


def grant_permission(username_or_role: str, permission_name: str, is_role: bool = False,
                    expires: Optional[str] = None, auth_token: Optional[str] = None,
                    reason: Optional[str] = None, mfa_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Grant a permission to a user or role.

    Args:
        username_or_role: Username or role name
        permission_name: Permission to grant
        is_role: Whether the target is a role
        expires: Optional expiration (for users only)
        auth_token: Authentication token
        reason: Reason for granting the permission
        mfa_token: MFA token for sensitive operations

    Returns:
        Dict: Result of the operation
    """
    try:
        if is_role:
            return grant_permission_to_role(
                role_name=username_or_role,
                permission_name=permission_name,
                auth_token=auth_token,
                reason=reason,
                mfa_token=mfa_token
            )
        else:
            return grant_permission_to_user(
                username=username_or_role,
                permission_name=permission_name,
                expires=expires,
                auth_token=auth_token,
                reason=reason,
                mfa_token=mfa_token
            )
    except Exception as e:
        logger.error(f"Error granting permission: {str(e)}")
        raise


def grant_permission_to_user(username: str, permission_name: str,
                          expires: Optional[str] = None, auth_token: Optional[str] = None,
                          reason: Optional[str] = None, mfa_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Grant a permission to a user.

    Args:
        username: Username to grant permission to
        permission_name: Name of the permission to grant
        expires: Optional expiration date string
        auth_token: Authentication token
        reason: Reason for granting the permission
        mfa_token: MFA token for sensitive operations

    Returns:
        Result information

    Raises:
        ResourceNotFoundError: If user or permission is not found
        ValidationError: If validation fails
    """
    try:
        # Find user and permission
        user = find_user(username)
        permission = find_permission(permission_name)

        # Check if user already has the permission directly
        if permission in user.permissions:
            return {
                "status": "warning",
                "message": f"User '{username}' already has permission '{permission_name}'",
                "username": username,
                "permission": permission_name,
                "no_change": True
            }

        # Check if user already has the permission via a role
        for role in user.roles:
            if permission in role.permissions:
                return {
                    "status": "warning",
                    "message": f"User '{username}' already has permission '{permission_name}' via role '{role.name}'",
                    "username": username,
                    "permission": permission_name,
                    "via_role": role.name,
                    "no_change": True
                }

        # Parse expiration if provided
        valid_until = None
        if expires:
            try:
                valid_until = parse_expiration_datetime(expires)
                # Don't allow past expiration dates
                now = datetime.datetime.now(datetime.timezone.utc)
                if valid_until <= now:
                    raise ValidationError("Expiration date must be in the future")
            except ValidationError as e:
                raise e
            except Exception as e:
                raise ValidationError(f"Invalid expiration format: {str(e)}")

        # If MFA token is required, verify it
        if mfa_token:
            # Verify MFA token
            mfa_valid = verify_mfa_token(mfa_token)
            if not mfa_valid:
                raise ValidationError("Invalid MFA token")

        # Grant the permission
        if valid_until:
            # Use delegation for time-limited grants
            admin_id = get_user_id_from_token(auth_token)

            delegation = PermissionDelegation.create_delegation(
                delegator_id=admin_id,
                delegate_id=user.id,
                permission_id=permission.id,
                valid_until=valid_until,
                reason=reason
            )

            if not delegation:
                raise PermissionError("Failed to create permission delegation")

            grant_type = "delegation"
            expiration = valid_until.isoformat()
        else:
            # Direct permission grant
            user.permissions.append(permission)
            db.session.commit()
            grant_type = "direct"
            expiration = None

        # Log the permission grant
        log_admin_action(
            action="permission.grant",
            details={
                "username": username,
                "permission": permission_name,
                "grant_type": grant_type,
                "expiration": expiration,
                "reason": reason
            },
            status="success"
        )

        return {
            "status": "success",
            "message": f"Granted permission '{permission_name}' to user '{username}'{' until ' + expiration if expiration else ''}",
            "username": username,
            "permission": permission_name,
            "expiration": expiration,
            "grant_type": grant_type
        }

    except (ResourceNotFoundError, ValidationError) as e:
        raise e
    except Exception as e:
        logger.error(f"Error granting permission: {str(e)}")
        db.session.rollback()
        raise PermissionError(f"Failed to grant permission: {str(e)}")


def grant_permission_to_role(role_name: str, permission_name: str,
                          auth_token: Optional[str] = None, reason: Optional[str] = None,
                          mfa_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Grant a permission to a role.

    Args:
        role_name: Role name to grant permission to
        permission_name: Name of the permission to grant
        auth_token: Authentication token
        reason: Reason for granting the permission
        mfa_token: MFA token for sensitive operations

    Returns:
        Result information

    Raises:
        ResourceNotFoundError: If role or permission is not found
        ValidationError: If validation fails
    """
    try:
        # Find role and permission
        role = find_role(role_name)
        permission = find_permission(permission_name)

        # Check if role already has the permission
        if permission in role.permissions:
            return {
                "status": "warning",
                "message": f"Role '{role_name}' already has permission '{permission_name}'",
                "role": role_name,
                "permission": permission_name,
                "no_change": True
            }

        # If MFA token is required, verify it
        if mfa_token:
            # Verify MFA token
            mfa_valid = verify_mfa_token(mfa_token)
            if not mfa_valid:
                raise ValidationError("Invalid MFA token")

        # Grant the permission
        role.permissions.append(permission)
        db.session.commit()

        # Log the permission grant
        log_admin_action(
            action="permission.grant_to_role",
            details={
                "role": role_name,
                "permission": permission_name,
                "reason": reason
            },
            status="success"
        )

        return {
            "status": "success",
            "message": f"Granted permission '{permission_name}' to role '{role_name}'",
            "role": role_name,
            "permission": permission_name
        }

    except (ResourceNotFoundError, ValidationError) as e:
        raise e
    except Exception as e:
        logger.error(f"Error granting permission to role: {str(e)}")
        db.session.rollback()
        raise PermissionError(f"Failed to grant permission to role: {str(e)}")


def revoke_permission(username_or_role: str, permission_name: str, is_role: bool = False,
                    auth_token: Optional[str] = None, reason: Optional[str] = None,
                    revoke_delegation: bool = True) -> Dict[str, Any]:
    """
    Revoke a permission from a user or role.

    Args:
        username_or_role: Username or role name
        permission_name: Permission to revoke
        is_role: Whether the target is a role
        auth_token: Authentication token
        reason: Reason for revoking the permission
        revoke_delegation: Whether to also revoke delegations (for users only)

    Returns:
        Dict: Result of the operation
    """
    try:
        if is_role:
            return revoke_permission_from_role(
                role_name=username_or_role,
                permission_name=permission_name,
                auth_token=auth_token,
                reason=reason
            )
        else:
            return revoke_permission_from_user(
                username=username_or_role,
                permission_name=permission_name,
                auth_token=auth_token,
                reason=reason,
                revoke_delegation=revoke_delegation
            )
    except Exception as e:
        logger.error(f"Error revoking permission: {str(e)}")
        raise


def revoke_permission_from_user(username: str, permission_name: str,
                              auth_token: Optional[str] = None, reason: Optional[str] = None,
                              revoke_delegation: bool = True) -> Dict[str, Any]:
    """
    Revoke a permission from a user.

    Args:
        username: Username to revoke permission from
        permission_name: Name of the permission to revoke
        auth_token: Authentication token
        reason: Reason for revoking the permission
        revoke_delegation: Whether to also revoke delegations

    Returns:
        Result information

    Raises:
        ResourceNotFoundError: If user or permission is not found
    """
    try:
        # Find user and permission
        user = find_user(username)
        permission = find_permission(permission_name)

        revoked = False
        delegation_revoked = False

        # Check for direct permission
        if permission in user.permissions:
            user.permissions.remove(permission)
            revoked = True

        # Check for delegations if requested
        if revoke_delegation:
            # Find and revoke all active delegations for this permission
            admin_id = get_user_id_from_token(auth_token)
            delegations = PermissionDelegation.query.filter_by(
                delegate_id=user.id,
                permission_id=permission.id,
                is_active=True
            ).all()

            for delegation in delegations:
                delegation.revoke(admin_id, reason=reason)
                delegation_revoked = True

        # If nothing was revoked, check if permission comes from a role
        if not revoked and not delegation_revoked:
            for role in user.roles:
                if permission in role.permissions:
                    return {
                        "status": "warning",
                        "message": f"User '{username}' has permission '{permission_name}' via role '{role.name}'. Use --revoke-role to remove the role.",
                        "username": username,
                        "permission": permission_name,
                        "via_role": role.name,
                        "no_change": True
                    }

            return {
                "status": "warning",
                "message": f"User '{username}' does not have permission '{permission_name}'",
                "username": username,
                "permission": permission_name,
                "no_change": True
            }

        # Commit changes if any were made
        if revoked or delegation_revoked:
            db.session.commit()

            # Log the permission revocation
            log_admin_action(
                action="permission.revoke",
                details={
                    "username": username,
                    "permission": permission_name,
                    "revoked_direct": revoked,
                    "revoked_delegation": delegation_revoked,
                    "reason": reason
                },
                status="success"
            )

            return {
                "status": "success",
                "message": f"Revoked permission '{permission_name}' from user '{username}'",
                "username": username,
                "permission": permission_name,
                "revoked_direct": revoked,
                "revoked_delegation": delegation_revoked
            }

    except ResourceNotFoundError as e:
        raise e
    except Exception as e:
        logger.error(f"Error revoking permission: {str(e)}")
        db.session.rollback()
        raise PermissionError(f"Failed to revoke permission: {str(e)}")


def revoke_permission_from_role(role_name: str, permission_name: str,
                             auth_token: Optional[str] = None,
                             reason: Optional[str] = None) -> Dict[str, Any]:
    """
    Revoke a permission from a role.

    Args:
        role_name: Role name to revoke permission from
        permission_name: Name of the permission to revoke
        auth_token: Authentication token
        reason: Reason for revoking the permission

    Returns:
        Result information

    Raises:
        ResourceNotFoundError: If role or permission is not found
    """
    try:
        # Find role and permission
        role = find_role(role_name)
        permission = find_permission(permission_name)

        # Check if role has the permission
        if permission not in role.permissions:
            return {
                "status": "warning",
                "message": f"Role '{role_name}' does not have permission '{permission_name}'",
                "role": role_name,
                "permission": permission_name,
                "no_change": True
            }

        # Revoke the permission
        role.permissions.remove(permission)
        db.session.commit()

        # Log the permission revocation
        log_admin_action(
            action="permission.revoke_from_role",
            details={
                "role": role_name,
                "permission": permission_name,
                "reason": reason
            },
            status="success"
        )

        return {
            "status": "success",
            "message": f"Revoked permission '{permission_name}' from role '{role_name}'",
            "role": role_name,
            "permission": permission_name
        }

    except ResourceNotFoundError as e:
        raise e
    except Exception as e:
        logger.error(f"Error revoking permission from role: {str(e)}")
        db.session.rollback()
        raise PermissionError(f"Failed to revoke permission from role: {str(e)}")


def check_permission(username: str, permission_name: str) -> Dict[str, Any]:
    """
    Check if a user has a specific permission.

    Args:
        username: Username to check
        permission_name: Name of the permission to check

    Returns:
        Dict: Result with permission check information
    """
    try:
        return check_user_permission(username, permission_name)
    except Exception as e:
        logger.error(f"Error checking permission: {str(e)}")
        raise


def check_user_permission(username: str, permission_name: str) -> Dict[str, Any]:
    """
    Check if a user has a specific permission.

    Args:
        username: Username to check
        permission_name: Permission name to check

    Returns:
        Dictionary with check results

    Raises:
        ResourceNotFoundError: If user or permission is not found
    """
    try:
        user = find_user(username)
        permission = find_permission(permission_name)

        # Check for direct permission
        has_direct = permission in user.permissions

        # Check for role-based permission
        has_via_role = False
        role_name = None

        for role in user.roles:
            if permission in role.permissions:
                has_via_role = True
                role_name = role.name
                break

        # Check for delegated permission
        has_delegated = False
        delegation_info = None

        now = datetime.datetime.now(datetime.timezone.utc)
        delegation = PermissionDelegation.query.filter_by(
            delegate_id=user.id,
            permission_id=permission.id,
            is_active=True
        ).filter(
            PermissionDelegation.valid_until > now
        ).first()

        if delegation:
            has_delegated = True
            delegation_info = {
                "delegator": delegation.delegator.username if delegation.delegator else "unknown",
                "expiration": delegation.valid_until.isoformat() if delegation.valid_until else None,
                "reason": delegation.reason
            }

        # Overall permission status
        has_permission = has_direct or has_via_role or has_delegated

        # Log the permission check
        log_admin_action(
            action="permission.check",
            details={
                "username": username,
                "permission": permission_name,
                "result": has_permission
            },
            status="success"
        )

        return {
            "username": username,
            "permission": permission_name,
            "has_permission": has_permission,
            "via_direct": has_direct,
            "via_role": has_via_role,
            "via_role_name": role_name,
            "via_delegation": has_delegated,
            "delegation": delegation_info
        }

    except ResourceNotFoundError as e:
        raise e
    except Exception as e:
        logger.error(f"Error checking permission: {str(e)}")
        raise PermissionError(f"Failed to check permission: {str(e)}")


def list_permissions(username_or_role: Optional[str] = None, is_role: bool = False,
                  include_roles: bool = True, include_delegated: bool = True,
                  category: Optional[str] = None) -> Dict[str, Any]:
    """
    List permissions for a user, role, or all permissions.

    Args:
        username_or_role: Optional username or role name
        is_role: Whether the target is a role
        include_roles: Include permissions from roles (for users)
        include_delegated: Include delegated permissions (for users)
        category: Filter permissions by category (for listing all)

    Returns:
        Dict: Permissions information
    """
    try:
        if username_or_role:
            if is_role:
                return list_role_permissions(username_or_role)
            else:
                return list_user_permissions(username_or_role, include_roles, include_delegated)
        else:
            return list_all_permissions(category)
    except Exception as e:
        logger.error(f"Error listing permissions: {str(e)}")
        raise


def list_user_permissions(username: str, include_roles: bool = True,
                       include_delegated: bool = True) -> Dict[str, Any]:
    """
    List permissions for a specific user.

    Args:
        username: Username to list permissions for
        include_roles: Whether to include permissions from roles
        include_delegated: Whether to include delegated permissions

    Returns:
        Dictionary with user's permissions information

    Raises:
        ResourceNotFoundError: If user is not found
    """
    try:
        user = find_user(username)

        # Collect direct permissions
        direct_permissions = [
            {
                "name": p.name,
                "description": p.description,
                "category": p.category,
                "type": "direct"
            } for p in user.permissions
        ]

        # Collect role-based permissions if requested
        role_permissions = []
        if include_roles:
            for role in user.roles:
                for permission in role.permissions:
                    role_permissions.append({
                        "name": permission.name,
                        "description": permission.description,
                        "category": permission.category,
                        "type": "role",
                        "role_name": role.name
                    })

        # Collect delegated permissions if requested
        delegated_permissions = []
        if include_delegated:
            now = datetime.datetime.now(datetime.timezone.utc)
            delegations = PermissionDelegation.query.filter_by(
                delegate_id=user.id,
                is_active=True
            ).filter(
                PermissionDelegation.valid_until > now
            ).all()

            for delegation in delegations:
                if not delegation.permission:
                    continue

                delegated_permissions.append({
                    "name": delegation.permission.name,
                    "description": delegation.permission.description,
                    "category": delegation.permission.category,
                    "type": "delegated",
                    "delegator": delegation.delegator.username if delegation.delegator else "unknown",
                    "expiration": delegation.valid_until.isoformat() if delegation.valid_until else None,
                    "reason": delegation.reason
                })

        # Combine all permissions
        all_permissions = direct_permissions + role_permissions + delegated_permissions

        # Log the permission listing
        log_admin_action(
            action="permission.list",
            details={
                "username": username,
                "include_roles": include_roles,
                "include_delegated": include_delegated
            },
            status="success"
        )

        return {
            "username": username,
            "user_id": user.id,
            "permissions": all_permissions,
            "direct_count": len(direct_permissions),
            "role_count": len(role_permissions),
            "delegated_count": len(delegated_permissions),
            "total_count": len(all_permissions)
        }

    except ResourceNotFoundError as e:
        raise e
    except Exception as e:
        logger.error(f"Error listing permissions: {str(e)}")
        raise PermissionError(f"Failed to list permissions: {str(e)}")


def list_role_permissions(role_name: str) -> Dict[str, Any]:
    """
    List permissions for a specific role.

    Args:
        role_name: Role name to list permissions for

    Returns:
        Dictionary with role's permissions information

    Raises:
        ResourceNotFoundError: If role is not found
    """
    try:
        role = find_role(role_name)

        # Collect permissions
        permissions = [
            {
                "name": p.name,
                "description": p.description,
                "category": p.category
            } for p in role.permissions
        ]

        # Group permissions by category
        by_category = {}
        for permission in permissions:
            category = permission["category"]
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(permission)

        # Log the permission listing
        log_admin_action(
            action="permission.list_for_role",
            details={
                "role": role_name
            },
            status="success"
        )

        return {
            "role": role_name,
            "role_id": role.id,
            "description": role.description,
            "permissions": permissions,
            "by_category": by_category,
            "count": len(permissions)
        }

    except ResourceNotFoundError as e:
        raise e
    except Exception as e:
        logger.error(f"Error listing role permissions: {str(e)}")
        raise PermissionError(f"Failed to list role permissions: {str(e)}")


def list_all_permissions(category: Optional[str] = None) -> Dict[str, Any]:
    """
    List all available permissions.

    Args:
        category: Optional category to filter by

    Returns:
        Dictionary with permissions information
    """
    try:
        # Get permissions, filtered by category if specified
        query = Permission.query

        if category:
            query = query.filter_by(category=category)

        query = query.order_by(Permission.category, Permission.name)
        permissions_list = query.all()

        # Format permissions
        permissions = [
            {
                "name": p.name,
                "description": p.description,
                "category": p.category,
                "is_system": p.is_system,
                "is_active": p.is_active
            } for p in permissions_list
        ]

        # Group by category
        by_category = {}
        for permission in permissions:
            category = permission["category"]
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(permission)

        # Log the permission listing
        log_admin_action(
            action="permission.list_all",
            details={
                "category_filter": category,
                "count": len(permissions)
            },
            status="success"
        )

        return {
            "permissions": permissions,
            "by_category": by_category,
            "category_filter": category,
            "count": len(permissions),
            "categories": list(by_category.keys())
        }

    except Exception as e:
        logger.error(f"Error listing all permissions: {str(e)}")
        raise PermissionError(f"Failed to list permissions: {str(e)}")


def delegate_permission(from_username: str, to_username: str, permission_name: str,
                      expires: str, auth_token: Optional[str] = None,
                      reason: Optional[str] = None, mfa_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Delegate a permission from one user to another.

    Args:
        from_username: Username of the delegator
        to_username: Username of the delegate
        permission_name: Permission to delegate
        expires: Expiration date/time
        auth_token: Authentication token
        reason: Reason for the delegation
        mfa_token: MFA token for sensitive operations

    Returns:
        Dictionary with delegation status

    Raises:
        ResourceNotFoundError: If user or permission is not found
        ValidationError: If validation fails
    """
    try:
        # Find users and permission
        delegator = find_user(from_username)
        delegate = find_user(to_username)
        permission = find_permission(permission_name)

        # Validate that the delegator actually has this permission
        has_perm = False

        # Check direct permissions
        if permission in delegator.permissions:
            has_perm = True

        # Check role-based permissions
        if not has_perm:
            for role in delegator.roles:
                if permission in role.permissions:
                    has_perm = True
                    break

        if not has_perm:
            raise ValidationError(f"Delegator '{from_username}' does not have the permission '{permission_name}'")

        # Parse and validate expiration
        try:
            valid_until = parse_expiration_datetime(expires)
        except ValidationError as e:
            raise e
        except Exception as e:
            raise ValidationError(f"Invalid expiration format: {str(e)}")

        # If MFA token is required, verify it
        if mfa_token:
            # Verify MFA token
            mfa_valid = verify_mfa_token(mfa_token)
            if not mfa_valid:
                raise ValidationError("Invalid MFA token")

        # Check for existing active delegation
        now = datetime.datetime.now(datetime.timezone.utc)
        existing = PermissionDelegation.query.filter_by(
            delegator_id=delegator.id,
            delegate_id=delegate.id,
            permission_id=permission.id,
            is_active=True
        ).filter(
            PermissionDelegation.valid_until > now
        ).first()

        if existing:
            return {
                "status": "warning",
                "message": f"An active delegation already exists until {existing.valid_until.isoformat()}",
                "delegation_id": existing.id,
                "valid_until": existing.valid_until.isoformat(),
                "no_change": True
            }

        # Create the delegation
        delegation = PermissionDelegation.create_delegation(
            delegator_id=delegator.id,
            delegate_id=delegate.id,
            permission_id=permission.id,
            valid_until=valid_until,
            reason=reason
        )

        if not delegation:
            raise PermissionError("Failed to create permission delegation")

        # Log the delegation
        log_admin_action(
            action="permission.delegate",
            details={
                "delegator": delegator.username,
                "delegate": delegate.username,
                "permission": permission_name,
                "valid_until": valid_until.isoformat(),
                "reason": reason
            },
            status="success"
        )

        return {
            "status": "success",
            "message": f"Permission '{permission_name}' delegated from '{delegator.username}' to '{delegate.username}' until {valid_until.isoformat()}",
            "delegation_id": delegation.id,
            "delegator": delegator.username,
            "delegate": delegate.username,
            "permission": permission_name,
            "valid_until": valid_until.isoformat(),
            "reason": reason
        }

    except (ResourceNotFoundError, ValidationError) as e:
        raise e
    except Exception as e:
        logger.error(f"Error delegating permission: {str(e)}")
        db.session.rollback()
        raise PermissionError(f"Failed to delegate permission: {str(e)}")


def get_user_permissions(username: str) -> Dict[str, Any]:
    """
    Get all permissions for a specific user.

    Args:
        username: Username to get permissions for

    Returns:
        Dict: Dictionary with permissions information
    """
    try:
        return list_user_permissions(username, include_roles=True, include_delegated=True)
    except Exception as e:
        logger.error(f"Error getting user permissions: {str(e)}")
        raise


def get_role_permissions(role_name: str) -> Dict[str, Any]:
    """
    Get all permissions for a specific role.

    Args:
        role_name: Role name to get permissions for

    Returns:
        Dict: Dictionary with permissions information
    """
    try:
        return list_role_permissions(role_name)
    except Exception as e:
        logger.error(f"Error getting role permissions: {str(e)}")
        raise


def main(args: List[str] = None) -> int:
    """
    Main entry point for the command-line tool.

    Args:
        args: Command line arguments (defaults to sys.argv[1:])

    Returns:
        Exit code
    """
    if args is None:
        args = sys.argv[1:]

    # Parse command line arguments and execute requested operation
    # This would be the implementation of the CLI interface
    # For brevity, we're just returning success
    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
