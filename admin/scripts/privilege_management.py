#!/usr/bin/env python3
# filepath: /admin/scripts/privilege_management.py
"""
Privilege Management Script for Cloud Infrastructure Platform.

This script provides command-line utilities for administrators to manage permissions
including granting, revoking, and reviewing privileges across the platform. It implements
proper security controls with authentication, authorization, and comprehensive audit
logging for all privilege management operations.

Usage:
    python privilege_management.py [options] command [args]

Commands:
    grant       Grant permissions to users or roles
    revoke      Revoke permissions from users or roles
    list        List privileges for users or roles
    delegate    Delegate permissions between users temporarily
    check       Check if a user has specific permissions
    export      Export permission configuration

Examples:
    # Grant a permission to a user with expiration
    python privilege_management.py grant --user jsmith --permission "api:write" --expires "4h" --reason "Deployment support"

    # Review a user's permissions
    python privilege_management.py list --user jsmith --format json

    # Revoke a permission
    python privilege_management.py revoke --user jsmith --permission "config:write" --reason "No longer required"
"""

import argparse
import datetime
import json
import logging
import os
import sys
import time
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union

# Add project root to path to allow imports from core packages
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

# Import the relevant modules
try:
    from core.utils.logging_utils import logger as get_logger
    from core.security.cs_authentication import generate_secure_token
    from admin.utils.admin_auth import (
        get_admin_session, check_permission,
        require_permission as require_admin_permission,
        verify_mfa_token
    )
    from admin.utils.audit_utils import log_admin_action
    from models.auth.user import User
    from models.auth.role import Role
    from models.auth.permission import Permission
    from models.auth.permission_delegation import PermissionDelegation
    from models.security import AuditLog
    from extensions import db
except ImportError as e:
    print(f"Error importing required modules: {e}", file=sys.stderr)
    print("Please ensure you run this script from the project root directory", file=sys.stderr)
    sys.exit(1)

# Initialize logger
logger = get_logger(__name__)

# Constants
VERSION = "0.1.1"
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_PERMISSION_ERROR = 2
EXIT_RESOURCE_ERROR = 3
EXIT_VALIDATION_ERROR = 4
EXIT_NOT_FOUND = 5
EXIT_AUTHENTICATION_ERROR = 6

__all__ = [
    # Core functions
    "grant_permission",
    "revoke_permission",
    "list_permissions",
    "check_permission",
    "delegate_permission",
    "list_delegations",
    "revoke_delegation",
    "export_permissions",

    # Helper functions
    "format_output",
    "authenticate_user",
    "find_user",
    "find_role",
    "find_permission",

    # Exception classes
    "PrivilegeManagementError",
    "ValidationError",
    "ResourceNotFoundError",
    "AuthenticationError",

    # Main entry point
    "main"
]

class PrivilegeManagementError(Exception):
    """Base exception for privilege management errors."""
    pass

class ValidationError(PrivilegeManagementError):
    """Exception raised when validation fails."""
    pass

class ResourceNotFoundError(PrivilegeManagementError):
    """Exception raised when a resource (user, role, permission) is not found."""
    pass

class AuthenticationError(PrivilegeManagementError):
    """Exception raised when authentication fails."""
    pass

def parse_expiration_datetime(expires_str: str) -> datetime.datetime:
    """
    Parse an expiration string into a datetime object.
    Supports ISO format dates or relative formats like '2h', '3d', '1w'.

    Args:
        expires_str: Expiration string ('2h', '3d', '1w' or ISO format)

    Returns:
        datetime: Expiration datetime in UTC
    """
    now = datetime.datetime.now(datetime.timezone.utc)

    # Check if it's a relative format
    if expires_str.endswith(('h', 'd', 'w', 'm')):
        unit = expires_str[-1]
        try:
            amount = int(expires_str[:-1])
        except ValueError:
            raise ValidationError(f"Invalid expiration format: {expires_str}")

        if unit == 'h':
            return now + datetime.timedelta(hours=amount)
        elif unit == 'd':
            return now + datetime.timedelta(days=amount)
        elif unit == 'w':
            return now + datetime.timedelta(weeks=amount)
        elif unit == 'm':
            return now + datetime.timedelta(minutes=amount)

    # Otherwise, try parsing as ISO format
    try:
        expiry = datetime.datetime.fromisoformat(expires_str.replace('Z', '+00:00'))
        if expiry.tzinfo is None:
            # Add UTC timezone if not specified
            expiry = expiry.replace(tzinfo=datetime.timezone.utc)
        return expiry
    except ValueError:
        raise ValidationError(f"Invalid expiration format: {expires_str}. Use ISO format or relative format (e.g., '2h', '3d', '1w')")

def authenticate_user(username: str, password: str, mfa_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Authenticate a user and return a session token.

    Args:
        username: Username
        password: Password
        mfa_token: Optional MFA token

    Returns:
        dict: Authentication result with token
    """
    from admin.cli.security_admin import authenticate

    try:
        auth_result = authenticate(username, password, mfa_code=mfa_token)
        if not auth_result.get("success", False):
            raise AuthenticationError(f"Authentication failed: {auth_result.get('error', 'Unknown error')}")
        return auth_result
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise AuthenticationError(f"Authentication failed: {str(e)}")

def find_user(identifier: str) -> User:
    """
    Find a user by username or ID.

    Args:
        identifier: Username or user ID

    Returns:
        User: User object
    """
    try:
        # Try to find by ID if identifier is numeric
        if identifier.isdigit():
            user = User.query.get(int(identifier))
            if user:
                return user

        # Try to find by username
        user = User.query.filter_by(username=identifier).first()
        if not user:
            # Try to find by email
            user = User.query.filter_by(email=identifier).first()

        if not user:
            raise ResourceNotFoundError(f"User not found: {identifier}")

        return user
    except Exception as e:
        if isinstance(e, ResourceNotFoundError):
            raise
        logger.error(f"Error finding user: {e}")
        raise ResourceNotFoundError(f"Error finding user: {str(e)}")

def find_role(identifier: str) -> Role:
    """
    Find a role by name or ID.

    Args:
        identifier: Role name or ID

    Returns:
        Role: Role object
    """
    try:
        # Try to find by ID if identifier is numeric
        if identifier.isdigit():
            role = Role.query.get(int(identifier))
            if role:
                return role

        # Try to find by name
        role = Role.query.filter_by(name=identifier).first()
        if not role:
            raise ResourceNotFoundError(f"Role not found: {identifier}")

        return role
    except Exception as e:
        if isinstance(e, ResourceNotFoundError):
            raise
        logger.error(f"Error finding role: {e}")
        raise ResourceNotFoundError(f"Error finding role: {str(e)}")

def find_permission(identifier: str) -> Permission:
    """
    Find a permission by name or ID.

    Args:
        identifier: Permission name or ID

    Returns:
        Permission: Permission object
    """
    try:
        # Try to find by ID if identifier is numeric
        if identifier.isdigit():
            permission = Permission.query.get(int(identifier))
            if permission:
                return permission

        # Try to find by name
        permission = Permission.query.filter_by(name=identifier).first()
        if not permission:
            raise ResourceNotFoundError(f"Permission not found: {identifier}")

        return permission
    except Exception as e:
        if isinstance(e, ResourceNotFoundError):
            raise
        logger.error(f"Error finding permission: {e}")
        raise ResourceNotFoundError(f"Error finding permission: {str(e)}")

def grant_permission(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Grant a permission to a user or role.

    Args:
        args: Command line arguments

    Returns:
        dict: Result of the operation
    """
    if args.user and args.role:
        raise ValidationError("Specify either --user or --role, not both")

    if not (args.user or args.role):
        raise ValidationError("Must specify either --user or --role")

    try:
        from admin.cli.grant_permissions import (
            grant_permission_to_user,
            grant_permission_to_role
        )

        if args.user:
            result = grant_permission_to_user(
                username=args.user,
                permission_name=args.permission,
                expires=args.expires,
                auth_token=args.auth_token,
                reason=args.reason,
                mfa_token=args.mfa_token
            )
            return result
        else:
            result = grant_permission_to_role(
                role_name=args.role,
                permission_name=args.permission,
                auth_token=args.auth_token,
                reason=args.reason,
                mfa_token=args.mfa_token
            )
            return result
    except Exception as e:
        logger.error(f"Error granting permission: {e}")
        raise

def revoke_permission(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Revoke a permission from a user or role.

    Args:
        args: Command line arguments

    Returns:
        dict: Result of the operation
    """
    if args.user and args.role:
        raise ValidationError("Specify either --user or --role, not both")

    if not (args.user or args.role):
        raise ValidationError("Must specify either --user or --role")

    try:
        from admin.cli.grant_permissions import (
            revoke_permission_from_user,
            revoke_permission_from_role
        )

        if args.user:
            result = revoke_permission_from_user(
                username=args.user,
                permission_name=args.permission,
                auth_token=args.auth_token,
                reason=args.reason,
                revoke_delegation=not args.keep_delegations
            )
            return result
        else:
            result = revoke_permission_from_role(
                role_name=args.role,
                permission_name=args.permission,
                auth_token=args.auth_token,
                reason=args.reason
            )
            return result
    except Exception as e:
        logger.error(f"Error revoking permission: {e}")
        raise

def list_permissions(args: argparse.Namespace) -> Dict[str, Any]:
    """
    List permissions for a user, role, or all permissions.

    Args:
        args: Command line arguments

    Returns:
        dict: Result of the operation with permissions data
    """
    try:
        from admin.cli.grant_permissions import (
            list_user_permissions,
            list_role_permissions,
            list_all_permissions
        )

        if args.user:
            return list_user_permissions(
                username=args.user,
                include_roles=not args.no_roles,
                include_delegated=not args.no_delegations
            )
        elif args.role:
            return list_role_permissions(role_name=args.role)
        else:
            return list_all_permissions(category=args.category)
    except Exception as e:
        logger.error(f"Error listing permissions: {e}")
        raise

def check_permission(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Check if a user has a specific permission.

    Args:
        args: Command line arguments

    Returns:
        dict: Result of the check
    """
    try:
        from admin.cli.grant_permissions import check_user_permission

        return check_user_permission(
            username=args.user,
            permission_name=args.permission
        )
    except Exception as e:
        logger.error(f"Error checking permission: {e}")
        raise

def delegate_permission(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Delegate a permission from one user to another.

    Args:
        args: Command line arguments

    Returns:
        dict: Result of the delegation operation
    """
    try:
        from admin.cli.grant_permissions import delegate_permission as cli_delegate_permission

        return cli_delegate_permission(
            from_username=args.from_user,
            to_username=args.to_user,
            permission_name=args.permission,
            expires=args.expires,
            auth_token=args.auth_token,
            reason=args.reason,
            mfa_token=args.mfa_token
        )
    except Exception as e:
        logger.error(f"Error delegating permission: {e}")
        raise

def list_delegations(args: argparse.Namespace) -> Dict[str, Any]:
    """
    List permission delegations.

    Args:
        args: Command line arguments

    Returns:
        dict: Result with delegations information
    """
    try:
        from admin.cli.grant_permissions import list_permission_delegations

        return list_permission_delegations(
            username=args.user,
            active_only=not args.include_expired
        )
    except Exception as e:
        logger.error(f"Error listing delegations: {e}")
        raise

def revoke_delegation(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Revoke a permission delegation.

    Args:
        args: Command line arguments

    Returns:
        dict: Result of the operation
    """
    try:
        from admin.cli.grant_permissions import revoke_delegation as cli_revoke_delegation

        return cli_revoke_delegation(
            delegation_id=args.id,
            auth_token=args.auth_token,
            reason=args.reason
        )
    except Exception as e:
        logger.error(f"Error revoking delegation: {e}")
        raise

def export_permissions(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Export permissions configuration.

    Args:
        args: Command line arguments

    Returns:
        dict: Result of the export operation
    """
    try:
        from admin.cli.grant_permissions import export_permissions as cli_export_permissions

        return cli_export_permissions(
            format_type=args.format,
            output_file=args.output,
            users=args.users,
            roles=args.roles,
            include_delegations=not args.no_delegations
        )
    except Exception as e:
        logger.error(f"Error exporting permissions: {e}")
        raise

def format_output(data: Any, format_type: str = "text") -> str:
    """
    Format command output based on specified format.

    Args:
        data: Data to format
        format_type: Output format (text, json, yaml)

    Returns:
        str: Formatted output
    """
    if format_type == "json":
        return json.dumps(data, indent=2, default=str)
    elif format_type == "yaml":
        try:
            return yaml.dump(data, default_flow_style=False)
        except ImportError:
            logger.warning("PyYAML not installed. Falling back to JSON format.")
            return json.dumps(data, indent=2, default=str)
    else:
        # Default to text format
        if isinstance(data, dict):
            result = []
            for key, value in data.items():
                if isinstance(value, list):
                    result.append(f"{key}:")
                    for item in value:
                        if isinstance(item, dict):
                            for k, v in item.items():
                                result.append(f"  - {k}: {v}")
                        else:
                            result.append(f"  - {item}")
                else:
                    result.append(f"{key}: {value}")
            return "\n".join(result)
        elif isinstance(data, list):
            result = []
            for item in data:
                if isinstance(item, dict):
                    result.append("---")
                    for k, v in item.items():
                        result.append(f"{k}: {v}")
                else:
                    result.append(str(item))
            return "\n".join(result)
        else:
            return str(data)

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Privilege Management Script for Cloud Infrastructure Platform",
        epilog="Run with --help for more information on specific commands"
    )

    # Global options
    parser.add_argument("--version", action="store_true", help="Show version information")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--quiet", action="store_true", help="Suppress output except errors")
    parser.add_argument("--format", choices=["text", "json", "yaml"], default="text",
                      help="Output format (default: text)")
    parser.add_argument("--output", help="Output file path")

    # Authentication options
    auth_group = parser.add_argument_group("Authentication options")
    auth_group.add_argument("--username", help="Username for authentication")
    auth_group.add_argument("--password", help="Password for authentication")
    auth_group.add_argument("--mfa-token", help="MFA token for authentication")
    auth_group.add_argument("--auth-token", help="Use existing authentication token")

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Grant command
    grant_parser = subparsers.add_parser("grant", help="Grant a permission")
    grant_target = grant_parser.add_mutually_exclusive_group(required=True)
    grant_target.add_argument("--user", help="User to grant permission to")
    grant_target.add_argument("--role", help="Role to grant permission to")
    grant_parser.add_argument("--permission", required=True, help="Permission to grant")
    grant_parser.add_argument("--expires", help="Expiration time for the permission (ISO format or 2h/3d/1w)")
    grant_parser.add_argument("--reason", required=True, help="Reason for granting the permission")

    # Revoke command
    revoke_parser = subparsers.add_parser("revoke", help="Revoke a permission")
    revoke_target = revoke_parser.add_mutually_exclusive_group(required=True)
    revoke_target.add_argument("--user", help="User to revoke permission from")
    revoke_target.add_argument("--role", help="Role to revoke permission from")
    revoke_parser.add_argument("--permission", required=True, help="Permission to revoke")
    revoke_parser.add_argument("--keep-delegations", action="store_true",
                             help="Don't revoke delegations of this permission")
    revoke_parser.add_argument("--reason", required=True, help="Reason for revoking the permission")

    # List command
    list_parser = subparsers.add_parser("list", help="List permissions")
    list_target = list_parser.add_mutually_exclusive_group()
    list_target.add_argument("--user", help="User to list permissions for")
    list_target.add_argument("--role", help="Role to list permissions for")
    list_target.add_argument("--all", action="store_true", help="List all permissions")
    list_parser.add_argument("--category", help="Filter permissions by category")
    list_parser.add_argument("--no-roles", action="store_true",
                           help="Don't include role-based permissions when listing user permissions")
    list_parser.add_argument("--no-delegations", action="store_true",
                           help="Don't include delegated permissions when listing user permissions")

    # Check command
    check_parser = subparsers.add_parser("check", help="Check if a user has a specific permission")
    check_parser.add_argument("--user", required=True, help="User to check permission for")
    check_parser.add_argument("--permission", required=True, help="Permission to check")

    # Delegate command
    delegate_parser = subparsers.add_parser("delegate", help="Delegate a permission")
    delegate_parser.add_argument("--from", dest="from_user", required=True,
                               help="User delegating the permission")
    delegate_parser.add_argument("--to", dest="to_user", required=True,
                               help="User receiving the permission")
    delegate_parser.add_argument("--permission", required=True, help="Permission to delegate")
    delegate_parser.add_argument("--expires", required=True,
                               help="When the delegation expires (ISO format or 2h/3d/1w)")
    delegate_parser.add_argument("--reason", required=True, help="Reason for the delegation")

    # Delegations command
    delegations_parser = subparsers.add_parser("delegations", help="Manage permission delegations")
    delegations_subparsers = delegations_parser.add_subparsers(dest="delegations_command")

    # List delegations
    list_delegations_parser = delegations_subparsers.add_parser("list",
                                                              help="List delegations")
    list_delegations_parser.add_argument("--user", help="Filter delegations by user")
    list_delegations_parser.add_argument("--include-expired", action="store_true",
                                       help="Include expired delegations")

    # Revoke delegation
    revoke_delegation_parser = delegations_subparsers.add_parser("revoke",
                                                               help="Revoke a delegation")
    revoke_delegation_parser.add_argument("--id", type=int, required=True,
                                        help="Delegation ID to revoke")
    revoke_delegation_parser.add_argument("--reason", required=True,
                                        help="Reason for revoking the delegation")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export permissions")
    export_parser.add_argument("--format", choices=["json", "csv", "yaml"], required=True,
                             help="Export format")
    export_parser.add_argument("--output", required=True, help="Output file")
    export_parser.add_argument("--users", nargs="*", help="Users to include (default: all)")
    export_parser.add_argument("--roles", nargs="*", help="Roles to include (default: all)")
    export_parser.add_argument("--no-delegations", action="store_true",
                             help="Don't include delegations")

    return parser.parse_args()

def main() -> int:
    """Main entry point for the script."""
    args = parse_args()

    # Configure logging
    log_level = logging.INFO
    if args.verbose:
        log_level = logging.DEBUG
    elif args.quiet:
        log_level = logging.WARNING

    logging.basicConfig(level=log_level)

    # Show version and exit if requested
    if args.version:
        print(f"Privilege Management Script v{VERSION}")
        return EXIT_SUCCESS

    # Handle authentication
    auth_token = args.auth_token
    if not auth_token and (args.username and args.password):
        try:
            auth_result = authenticate_user(args.username, args.password, args.mfa_token)
            auth_token = auth_result.get("token")
            if not auth_token:
                print("Authentication failed: No token received")
                return EXIT_AUTHENTICATION_ERROR
        except AuthenticationError as e:
            print(f"Authentication failed: {e}")
            return EXIT_AUTHENTICATION_ERROR

    # Execute appropriate command
    try:
        if not args.command:
            print("No command specified. Use --help for usage information.")
            return EXIT_ERROR

        # Set auth token in args for commands that need it
        args.auth_token = auth_token

        if args.command == "grant":
            result = grant_permission(args)

        elif args.command == "revoke":
            result = revoke_permission(args)

        elif args.command == "list":
            result = list_permissions(args)

        elif args.command == "check":
            result = check_permission(args)

        elif args.command == "delegate":
            result = delegate_permission(args)

        elif args.command == "delegations":
            if args.delegations_command == "list":
                result = list_delegations(args)
            elif args.delegations_command == "revoke":
                result = revoke_delegation(args)
            else:
                print("Unknown delegations subcommand. Use --help for usage information.")
                return EXIT_ERROR

        elif args.command == "export":
            result = export_permissions(args)

        else:
            print(f"Unknown command: {args.command}")
            return EXIT_ERROR

        # Format and output the result
        formatted_output = format_output(result, args.format)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(formatted_output)
            if not args.quiet:
                print(f"Output written to {args.output}")
        else:
            print(formatted_output)

        return EXIT_SUCCESS

    except ResourceNotFoundError as e:
        logger.error(f"Resource not found: {e}")
        print(f"Error: {e}")
        return EXIT_NOT_FOUND

    except ValidationError as e:
        logger.error(f"Validation error: {e}")
        print(f"Error: {e}")
        return EXIT_VALIDATION_ERROR

    except PrivilegeManagementError as e:
        logger.error(f"Privilege management error: {e}")
        print(f"Error: {e}")
        return EXIT_ERROR

    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        print(f"Error: {e}")
        return EXIT_ERROR

if __name__ == "__main__":
    sys.exit(main())
