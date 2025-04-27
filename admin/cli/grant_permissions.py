#!/usr/bin/env python3
# filepath: admin/cli/grant_permissions.py
"""
Permission management command-line interface for Cloud Infrastructure Platform.

This module provides command-line utilities for administrators to manage permissions
including granting, revoking, and inspecting user permissions. The tool implements
proper security controls with authentication, authorization, and comprehensive audit
logging for all permission management operations.

Features:
- Grant permissions to users with optional expiration
- Revoke existing permissions
- List permissions for users and roles
- Check specific permission assignments
- Delegate permissions temporarily between users
- Import/export permission assignments
"""

import argparse
import csv
import datetime
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union, Set

# Add project root to path to allow imports from core packages
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from core.loggings import get_logger
from core.security import audit_log, require_permission, generate_token
from admin.utils.admin_auth import (
    get_admin_session, check_permission,
    require_permission as require_admin_permission,
    verify_mfa_token
)
from admin.utils.audit_utils import log_admin_action
from models.auth.user import User
from models.auth.role import Role
from models.auth.permission import Permission, PermissionDelegation
from extensions import db

# Initialize logger
logger = get_logger(__name__)

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


def format_output(data: Any, output_format: str = "text") -> str:
    """
    Format data for output based on the specified format.

    Args:
        data: Data to format
        output_format: Output format (text, json, csv, table)

    Returns:
        Formatted output string
    """
    if output_format == "json":
        return json.dumps(data, indent=2, default=str)

    elif output_format == "csv":
        if not isinstance(data, list) or not data:
            return "No data or invalid format for CSV output"

        import io
        import csv

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)

        return output.getvalue()

    elif output_format == "table":
        if not isinstance(data, list) or not data:
            return "No data or invalid format for table output"

        # Create a simple ASCII table
        headers = list(data[0].keys())

        # Calculate column widths
        col_widths = {header: len(header) for header in headers}
        for row in data:
            for header in headers:
                if header in row:
                    col_widths[header] = max(col_widths[header], len(str(row.get(header, ""))))

        # Create header row
        header_row = " | ".join(h.ljust(col_widths[h]) for h in headers)
        separator = "-+-".join("-" * col_widths[h] for h in headers)

        rows = [header_row, separator]
        for row in data:
            formatted_row = " | ".join(
                str(row.get(h, "")).ljust(col_widths[h]) for h in headers
            )
            rows.append(formatted_row)

        return "\n".join(rows)

    else:  # Default to text format
        if isinstance(data, dict):
            max_key_len = max(len(str(k)) for k in data.keys()) if data else 0
            return "\n".join(f"{str(k).ljust(max_key_len)}: {v}" for k, v in data.items())
        elif isinstance(data, list):
            return "\n".join(str(item) for item in data)
        else:
            return str(data)


def find_user(identifier: str) -> User:
    """
    Find a user by username or ID.

    Args:
        identifier: Username or user ID

    Returns:
        User object

    Raises:
        ResourceNotFoundError: If user is not found
    """
    # Try to find by username first
    user = User.query.filter_by(username=identifier).first()

    # If not found and identifier is numeric, try by ID
    if not user and identifier.isdigit():
        user = User.query.get(int(identifier))

    if not user:
        raise ResourceNotFoundError(f"User not found: {identifier}")

    return user


def find_role(identifier: str) -> Role:
    """
    Find a role by name or ID.

    Args:
        identifier: Role name or role ID

    Returns:
        Role object

    Raises:
        ResourceNotFoundError: If role is not found
    """
    # Try to find by name first
    role = Role.query.filter_by(name=identifier).first()

    # If not found and identifier is numeric, try by ID
    if not role and identifier.isdigit():
        role = Role.query.get(int(identifier))

    if not role:
        raise ResourceNotFoundError(f"Role not found: {identifier}")

    return role


def find_permission(identifier: str) -> Permission:
    """
    Find a permission by name or ID.

    Args:
        identifier: Permission name or permission ID

    Returns:
        Permission object

    Raises:
        ResourceNotFoundError: If permission is not found
    """
    # Try to find by name first
    permission = Permission.query.filter_by(name=identifier).first()

    # If not found and identifier is numeric, try by ID
    if not permission and identifier.isdigit():
        permission = Permission.query.get(int(identifier))

    if not permission:
        raise ResourceNotFoundError(f"Permission not found: {identifier}")

    return permission


def parse_expiration_datetime(expires_str: str) -> datetime.datetime:
    """
    Parse expiration date string into datetime object.

    Args:
        expires_str: Expiration date string in ISO format or relative format

    Returns:
        Expiration datetime

    Raises:
        ValidationError: If expiration format is invalid
    """
    now = datetime.datetime.now(datetime.timezone.utc)

    # Check for relative time formats (e.g., "2h", "3d", "1w")
    if expires_str.endswith(('m', 'h', 'd', 'w')):
        unit = expires_str[-1]
        try:
            value = int(expires_str[:-1])
        except ValueError:
            raise ValidationError(f"Invalid relative time format: {expires_str}")

        if unit == 'm':  # minutes
            return now + datetime.timedelta(minutes=value)
        elif unit == 'h':  # hours
            return now + datetime.timedelta(hours=value)
        elif unit == 'd':  # days
            return now + datetime.timedelta(days=value)
        elif unit == 'w':  # weeks
            return now + datetime.timedelta(weeks=value)

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


def grant_permission_to_user(
    username: str,
    permission_name: str,
    expires: Optional[str] = None,
    auth_token: Optional[str] = None,
    reason: Optional[str] = None,
    mfa_token: Optional[str] = None
) -> Dict[str, Any]:
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


def get_user_id_from_token(auth_token: Optional[str]) -> int:
    """
    Get user ID from authentication token.

    Args:
        auth_token: Authentication token

    Returns:
        User ID

    Raises:
        PermissionError: If auth token is invalid or missing
    """
    if not auth_token:
        raise PermissionError("Authentication token required")

    user_info = get_admin_session(auth_token)
    if not user_info or 'user_id' not in user_info:
        raise PermissionError("Invalid authentication token")

    return user_info['user_id']


def grant_permission_to_role(
    role_name: str,
    permission_name: str,
    auth_token: Optional[str] = None,
    reason: Optional[str] = None,
    mfa_token: Optional[str] = None
) -> Dict[str, Any]:
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


def revoke_permission_from_user(
    username: str,
    permission_name: str,
    auth_token: Optional[str] = None,
    reason: Optional[str] = None,
    revoke_delegation: bool = True
) -> Dict[str, Any]:
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


def revoke_permission_from_role(
    role_name: str,
    permission_name: str,
    auth_token: Optional[str] = None,
    reason: Optional[str] = None
) -> Dict[str, Any]:
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


def list_user_permissions(
    username: str,
    include_roles: bool = True,
    include_delegated: bool = True
) -> Dict[str, Any]:
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


def list_permission_delegations(
    username: Optional[str] = None,
    active_only: bool = True
) -> Dict[str, Any]:
    """
    List permission delegations.

    Args:
        username: Optional username to filter by (as delegator or delegate)
        active_only: Whether to include only active delegations

    Returns:
        Dictionary with delegation information
    """
    try:
        # Base query
        query = PermissionDelegation.query

        # Apply filters
        if username:
            # Get user
            user = find_user(username)

            # Filter by user as either delegator or delegate
            query = query.filter(
                (PermissionDelegation.delegator_id == user.id) |
                (PermissionDelegation.delegate_id == user.id)
            )

        # Filter by active status
        if active_only:
            now = datetime.datetime.now(datetime.timezone.utc)
            query = query.filter(
                PermissionDelegation.is_active == True,
                PermissionDelegation.valid_until > now
            )

        # Execute query
        delegations_list = query.all()

        # Format delegations
        delegations = []
        for delegation in delegations_list:
            if not delegation.delegator or not delegation.delegate or not delegation.permission:
                continue

            delegations.append({
                "id": delegation.id,
                "delegator": delegation.delegator.username,
                "delegate": delegation.delegate.username,
                "permission": delegation.permission.name,
                "valid_from": delegation.valid_from.isoformat() if delegation.valid_from else None,
                "valid_until": delegation.valid_until.isoformat() if delegation.valid_until else None,
                "is_active": delegation.is_active,
                "reason": delegation.reason,
                "is_expired": delegation.valid_until < datetime.datetime.now(datetime.timezone.utc) if delegation.valid_until else False
            })

        # Log the delegation listing
        log_admin_action(
            action="permission.list_delegations",
            details={
                "username_filter": username,
                "active_only": active_only,
                "count": len(delegations)
            },
            status="success"
        )

        return {
            "delegations": delegations,
            "count": len(delegations),
            "username_filter": username,
            "active_only": active_only
        }

    except ResourceNotFoundError as e:
        raise e
    except Exception as e:
        logger.error(f"Error listing delegations: {str(e)}")
        raise PermissionError(f"Failed to list delegations: {str(e)}")


def revoke_delegation(
    delegation_id: int,
    auth_token: Optional[str] = None,
    reason: Optional[str] = None
) -> Dict[str, Any]:
    """
    Revoke a specific permission delegation.

    Args:
        delegation_id: ID of the delegation to revoke
        auth_token: Authentication token
        reason: Reason for revoking the delegation

    Returns:
        Dictionary with revocation status

    Raises:
        ResourceNotFoundError: If delegation is not found
    """
    try:
        # Find the delegation
        delegation = PermissionDelegation.query.get(delegation_id)

        if not delegation:
            raise ResourceNotFoundError(f"Delegation not found: {delegation_id}")

        # Check if already revoked or expired
        now = datetime.datetime.now(datetime.timezone.utc)
        if not delegation.is_active:
            return {
                "status": "warning",
                "message": "Delegation is already revoked",
                "delegation_id": delegation_id,
                "no_change": True
            }

        if delegation.valid_until <= now:
            return {
                "status": "warning",
                "message": "Delegation is already expired",
                "delegation_id": delegation_id,
                "no_change": True
            }

        # Get admin user ID from token
        admin_id = get_user_id_from_token(auth_token)

        # Revoke the delegation
        success = delegation.revoke(admin_id, reason=reason)

        if not success:
            raise PermissionError("Failed to revoke delegation")

        # Log the revocation
        log_admin_action(
            action="permission.revoke_delegation",
            details={
                "delegation_id": delegation_id,
                "delegator": delegation.delegator.username if delegation.delegator else "unknown",
                "delegate": delegation.delegate.username if delegation.delegate else "unknown",
                "permission": delegation.permission.name if delegation.permission else "unknown",
                "reason": reason
            },
            status="success"
        )

        return {
            "status": "success",
            "message": "Delegation successfully revoked",
            "delegation_id": delegation_id,
            "delegator": delegation.delegator.username if delegation.delegator else "unknown",
            "delegate": delegation.delegate.username if delegation.delegate else "unknown",
            "permission": delegation.permission.name if delegation.permission else "unknown"
        }

    except ResourceNotFoundError as e:
        raise e
    except Exception as e:
        logger.error(f"Error revoking delegation: {str(e)}")
        db.session.rollback()
        raise PermissionError(f"Failed to revoke delegation: {str(e)}")


def delegate_permission(
    from_username: str,
    to_username: str,
    permission_name: str,
    expires: str,
    auth_token: Optional[str] = None,
    reason: Optional[str] = None,
    mfa_token: Optional[str] = None
) -> Dict[str, Any]:
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


def export_permissions(
    format_type: str,
    output_file: str,
    users: Optional[List[str]] = None,
    roles: Optional[List[str]] = None,
    include_delegations: bool = True
) -> Dict[str, Any]:
    """
    Export permissions to a file.

    Args:
        format_type: Export format (json, csv, yaml)
        output_file: File to write export to
        users: Optional list of usernames to export permissions for
        roles: Optional list of role names to export permissions for
        include_delegations: Whether to include delegations

    Returns:
        Dictionary with export status
    """
    try:
        export_data = {
            "metadata": {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "version": VERSION
            },
            "users": [],
            "roles": [],
            "delegations": []
        }

        # Export user permissions
        if users:
            for username in users:
                try:
                    user_data = list_user_permissions(
                        username=username,
                        include_roles=True,
                        include_delegated=include_delegations
                    )
                    export_data["users"].append(user_data)
                except ResourceNotFoundError:
                    logger.warning(f"User not found during export: {username}")
                    continue

        # Export role permissions
        if roles:
            for role_name in roles:
                try:
                    role_data = list_role_permissions(role_name=role_name)
                    export_data["roles"].append(role_data)
                except ResourceNotFoundError:
                    logger.warning(f"Role not found during export: {role_name}")
                    continue

        # Export delegations if requested
        if include_delegations:
            delegations_data = list_permission_delegations(active_only=True)
            export_data["delegations"] = delegations_data["delegations"]

        # Write the export file
        if format_type == "json":
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)

        elif format_type == "csv":
            # Create separate CSV files for each section
            base_name = os.path.splitext(output_file)[0]

            # Export users
            if export_data["users"]:
                user_file = f"{base_name}_users.csv"
                with open(user_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["username", "permission_name", "type", "role_name",
                                    "delegator", "expiration", "reason"])

                    for user in export_data["users"]:
                        username = user["username"]
                        for perm in user["permissions"]:
                            writer.writerow([
                                username,
                                perm["name"],
                                perm["type"],
                                perm.get("role_name", ""),
                                perm.get("delegator", ""),
                                perm.get("expiration", ""),
                                perm.get("reason", "")
                            ])

            # Export roles
            if export_data["roles"]:
                role_file = f"{base_name}_roles.csv"
                with open(role_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["role_name", "permission_name", "category", "description"])

                    for role in export_data["roles"]:
                        role_name = role["role"]
                        for perm in role["permissions"]:
                            writer.writerow([
                                role_name,
                                perm["name"],
                                perm.get("category", ""),
                                perm.get("description", "")
                            ])

            # Export delegations
            if export_data["delegations"]:
                delegations_file = f"{base_name}_delegations.csv"
                with open(delegations_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        "id", "delegator", "delegate", "permission",
                        "valid_from", "valid_until", "is_active", "reason"
                    ])

                    for delegation in export_data["delegations"]:
                        writer.writerow([
                            delegation["id"],
                            delegation["delegator"],
                            delegation["delegate"],
                            delegation["permission"],
                            delegation["valid_from"],
                            delegation["valid_until"],
                            delegation["is_active"],
                            delegation.get("reason", "")
                        ])

            # Update output_file to indicate multiple files were created
            output_file = f"{base_name}_*.csv"

        elif format_type == "yaml":
            try:
                import yaml
                with open(output_file, 'w') as f:
                    yaml.dump(export_data, f, default_flow_style=False)
            except ImportError:
                return {
                    "status": "error",
                    "message": "YAML format requires PyYAML package. Please install it with 'pip install PyYAML'"
                }
        else:
            return {
                "status": "error",
                "message": f"Unsupported export format: {format_type}"
            }

        # Log the export
        log_admin_action(
            action="permission.export",
            details={
                "format": format_type,
                "output_file": output_file,
                "users_count": len(export_data["users"]),
                "roles_count": len(export_data["roles"]),
                "delegations_count": len(export_data["delegations"]),
                "include_delegations": include_delegations
            },
            status="success"
        )

        return {
            "status": "success",
            "message": f"Permissions exported to {output_file}",
            "format": format_type,
            "users_count": len(export_data["users"]),
            "roles_count": len(export_data["roles"]),
            "delegations_count": len(export_data["delegations"]),
            "output_file": output_file
        }

    except Exception as e:
        logger.error(f"Error exporting permissions: {str(e)}")
        raise PermissionError(f"Failed to export permissions: {str(e)}")


def setup_arg_parser() -> argparse.ArgumentParser:
    """
    Set up command-line argument parser.

    Returns:
        Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="Permission Management CLI for Cloud Infrastructure Platform",
        epilog="For detailed help on specific commands, use the --help option with the command."
    )

    # Authentication options
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("--token", help="Authentication token")
    auth_group.add_argument("--mfa-token", help="MFA token for sensitive operations")

    # Output options
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("--format", choices=["text", "json", "csv", "table"],
                            default="text", help="Output format")
    output_group.add_argument("--output", help="Output file (default: stdout)")
    output_group.add_argument("--verbose", action="store_true", help="Enable verbose output")

    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Permission management commands")

    # Grant command
    grant_parser = subparsers.add_parser("grant", help="Grant a permission")
    grant_target_group = grant_parser.add_mutually_exclusive_group(required=True)
    grant_target_group.add_argument("--user", help="User to grant permission to")
    grant_target_group.add_argument("--role", help="Role to grant permission to")
    grant_parser.add_argument("--permission", required=True, help="Permission to grant")
    grant_parser.add_argument("--expires", help="Expiration time for the permission (ISO format or 2h/3d/1w)")
    grant_parser.add_argument("--reason", required=True, help="Reason for granting the permission")

    # Revoke command
    revoke_parser = subparsers.add_parser("revoke", help="Revoke a permission")
    revoke_target_group = revoke_parser.add_mutually_exclusive_group(required=True)
    revoke_target_group.add_argument("--user", help="User to revoke permission from")
    revoke_target_group.add_argument("--role", help="Role to revoke permission from")
    revoke_parser.add_argument("--permission", required=True, help="Permission to revoke")
    revoke_parser.add_argument("--keep-delegations", action="store_true",
                             help="Don't revoke delegations of this permission")
    revoke_parser.add_argument("--reason", required=True, help="Reason for revoking the permission")

    # List command
    list_parser = subparsers.add_parser("list", help="List permissions")
    list_target_group = list_parser.add_mutually_exclusive_group()
    list_target_group.add_argument("--user", help="User to list permissions for")
    list_target_group.add_argument("--role", help="Role to list permissions for")
    list_target_group.add_argument("--all", action="store_true", help="List all permissions")
    list_parser.add_argument("--category", help="Filter permissions by category")
    list_parser.add_argument("--no-roles", action="store_true", help="Don't include role-based permissions")
    list_parser.add_argument("--no-delegations", action="store_true", help="Don't include delegated permissions")

    # Check command
    check_parser = subparsers.add_parser("check", help="Check if a user has a specific permission")
    check_parser.add_argument("--user", required=True, help="User to check permission for")
    check_parser.add_argument("--permission", required=True, help="Permission to check")

    # Delegate command
    delegate_parser = subparsers.add_parser("delegate", help="Delegate a permission")
    delegate_parser.add_argument("--from", dest="from_user", required=True, help="User delegating the permission")
    delegate_parser.add_argument("--to", dest="to_user", required=True, help="User receiving the permission")
    delegate_parser.add_argument("--permission", required=True, help="Permission to delegate")
    delegate_parser.add_argument("--expires", required=True,
                              help="When the delegation expires (ISO format or 2h/3d/1w)")
    delegate_parser.add_argument("--reason", required=True, help="Reason for the delegation")

    # Delegations command
    delegations_parser = subparsers.add_parser("delegations", help="Manage permission delegations")
    delegations_subparsers = delegations_parser.add_subparsers(dest="delegations_command")

    # List delegations
    list_delegations_parser = delegations_subparsers.add_parser("list", help="List delegations")
    list_delegations_parser.add_argument("--user", help="Filter delegations by user (as delegator or delegate)")
    list_delegations_parser.add_argument("--include-expired", action="store_true",
                                      help="Include expired delegations")

    # Revoke delegation
    revoke_delegation_parser = delegations_subparsers.add_parser("revoke", help="Revoke a delegation")
    revoke_delegation_parser.add_argument("--id", type=int, required=True, help="Delegation ID to revoke")
    revoke_delegation_parser.add_argument("--reason", required=True, help="Reason for revoking the delegation")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export permissions")
    export_parser.add_argument("--format", choices=["json", "csv", "yaml"], required=True,
                            help="Export format")
    export_parser.add_argument("--output", required=True, help="Output file")
    export_parser.add_argument("--users", nargs="*", help="Users to include (default: all)")
    export_parser.add_argument("--roles", nargs="*", help="Roles to include (default: all)")
    export_parser.add_argument("--no-delegations", action="store_true",
                            help="Don't include delegations")

    # Version command
    parser.add_argument("--version", action="store_true", help="Show version information")

    return parser


def main() -> int:
    """
    Main CLI entry point.

    Returns:
        Exit code
    """
    parser = setup_arg_parser()
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level,
                      format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Show version if requested
    if args.version:
        print(f"Permission Management CLI version {VERSION}")
        return EXIT_SUCCESS

    # If no command specified, show help
    if not args.command:
        parser.print_help()
        return EXIT_SUCCESS

    try:
        result = None
        auth_token = args.token
        mfa_token = args.mfa_token

        # Execute command
        if args.command == "grant":
            if args.user:
                result = grant_permission_to_user(
                    username=args.user,
                    permission_name=args.permission,
                    expires=args.expires,
                    auth_token=auth_token,
                    reason=args.reason,
                    mfa_token=mfa_token
                )
            elif args.role:
                result = grant_permission_to_role(
                    role_name=args.role,
                    permission_name=args.permission,
                    auth_token=auth_token,
                    reason=args.reason,
                    mfa_token=mfa_token
                )

        elif args.command == "revoke":
            if args.user:
                result = revoke_permission_from_user(
                    username=args.user,
                    permission_name=args.permission,
                    auth_token=auth_token,
                    reason=args.reason,
                    revoke_delegation=not args.keep_delegations
                )
            elif args.role:
                result = revoke_permission_from_role(
                    role_name=args.role,
                    permission_name=args.permission,
                    auth_token=auth_token,
                    reason=args.reason
                )

        elif args.command == "list":
            if args.user:
                result = list_user_permissions(
                    username=args.user,
                    include_roles=not args.no_roles,
                    include_delegated=not args.no_delegations
                )
            elif args.role:
                result = list_role_permissions(role_name=args.role)
            elif args.all:
                result = list_all_permissions(category=args.category)
            else:
                # Default to listing all permissions if no target specified
                result = list_all_permissions(category=args.category)

        elif args.command == "check":
            result = check_user_permission(
                username=args.user,
                permission_name=args.permission
            )

        elif args.command == "delegate":
            result = delegate_permission(
                from_username=args.from_user,
                to_username=args.to_user,
                permission_name=args.permission,
                expires=args.expires,
                auth_token=auth_token,
                reason=args.reason,
                mfa_token=mfa_token
            )

        elif args.command == "delegations":
            if args.delegations_command == "list":
                result = list_permission_delegations(
                    username=args.user,
                    active_only=not args.include_expired
                )
            elif args.delegations_command == "revoke":
                result = revoke_delegation(
                    delegation_id=args.id,
                    auth_token=auth_token,
                    reason=args.reason
                )
            else:
                list_delegations_parser.print_help()
                return EXIT_ERROR

        elif args.command == "export":
            result = export_permissions(
                format_type=args.format,
                output_file=args.output,
                users=args.users,
                roles=args.roles,
                include_delegations=not args.no_delegations
            )

        # Format and output result
        if result is not None:
            formatted_result = format_output(result, args.format)

            if args.output and args.command != "export":  # Export command handles its own output
                with open(args.output, 'w') as f:
                    f.write(formatted_result)
                print(f"Output written to {args.output}")
            else:
                print(formatted_result)

        return EXIT_SUCCESS

    except ResourceNotFoundError as e:
        logger.error("Resource not found: %s", e)
        print(f"Error: {e}")
        return EXIT_NOT_FOUND

    except ValidationError as e:
        logger.error("Validation error: %s", e)
        print(f"Error: {e}")
        return EXIT_VALIDATION_ERROR

    except PermissionError as e:
        logger.error("Permission error: %s", e)
        print(f"Error: {e}")
        return EXIT_PERMISSION_ERROR

    except Exception as e:
        logger.exception("Unexpected error: %s", e)
        print(f"Error: {e}")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
