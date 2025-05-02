#!/usr/bin/env python3
# filepath: admin/cli/user_admin.py
"""
User administration command-line interface for Cloud Infrastructure Platform.

This module provides command-line utilities for administrators to manage user accounts
including creation, modification, deactivation, and credential management. It implements
proper security controls with authentication, authorization, and comprehensive audit
logging for all user management operations.

The CLI enables secure user administration from the command line which is particularly
useful for automated user management, bulk operations, and emergency access scenarios.
"""

import argparse
import csv
import datetime
import getpass
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union, Set

# Add project root to path to allow imports from core packages
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


from admin.utils.admin_auth import (
    get_admin_session, check_permission,
    require_permission as require_admin_permission,
    verify_mfa_token
)
from admin.utils.audit_utils import log_admin_action
from admin.utils.security_utils import generate_password
from core.security.cs_audit import log_security_event
from models.auth import User, Role
from models.auth.permission import Permission
from extensions import db

# Core utilities
from core.loggings import logger as core_logger

# Create a module-level logger
logger = logging.getLogger(__name__)

# Constants
VERSION = "1.0.0"
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_PERMISSION_ERROR = 2
EXIT_RESOURCE_ERROR = 3
EXIT_VALIDATION_ERROR = 4
EXIT_AUTHENTICATION_ERROR = 5

# User status options
USER_STATUSES = ["active", "inactive", "locked", "pending"]
USER_ROLES = ["user", "operator", "admin", "auditor"]

# Authentication status value for verbose output
AUTH_STATUS = {
    True: "Authenticated",
    False: "Authentication Required"
}


class UserAdminError(Exception):
    """Base exception for user administration errors."""
    pass


class UserValidationError(UserAdminError):
    """Exception raised when user data validation fails."""
    pass


class UserExistsError(UserAdminError):
    """Exception raised when attempting to create a user that already exists."""
    pass


class UserNotFoundError(UserAdminError):
    """Exception raised when a user cannot be found."""
    pass


def validate_email(email: str) -> bool:
    """
    Validate email format.

    Args:
        email: Email address to validate

    Returns:
        True if valid, False otherwise
    """
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_username(username: str) -> bool:
    """
    Validate username format.

    Args:
        username: Username to validate

    Returns:
        True if valid, False otherwise
    """
    import re
    # Allow alphanumeric, underscore, dash and dot
    pattern = r'^[a-zA-Z0-9._-]{3,64}$'
    return re.match(pattern, username) is not None


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
                    col_widths[header] = max(col_widths[header], len(str(row[header] or "")))

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
            max_key_len = max(len(str(k)) for k in data.keys())
            return "\n".join(f"{str(k).ljust(max_key_len)}: {v}" for k, v in data.items())
        elif isinstance(data, list):
            return "\n".join(str(item) for item in data)
        else:
            return str(data)


def create_user(
    username: str,
    email: str,
    password: Optional[str] = None,
    role: str = "user",
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    status: str = "active",
    require_mfa: bool = False,
    require_password_change: bool = True,
    auth_token: Optional[str] = None,
    reason: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a new user.

    Args:
        username: Username
        email: Email address
        password: Password (None to generate random password)
        role: User role
        first_name: First name
        last_name: Last name
        status: Account status
        require_mfa: Whether to require MFA
        require_password_change: Whether to require password change on first login
        auth_token: Authentication token
        reason: Reason for creation (for audit purposes)

    Returns:
        Dictionary with user information and status

    Raises:
        UserValidationError: If validation fails
        UserExistsError: If user already exists
    """
    # Validate inputs
    if not validate_username(username):
        raise UserValidationError(f"Invalid username format: {username}")

    if not validate_email(email):
        raise UserValidationError(f"Invalid email format: {email}")

    if role not in USER_ROLES:
        raise UserValidationError(f"Invalid role: {role}. Must be one of: {', '.join(USER_ROLES)}")

    if status not in USER_STATUSES:
        raise UserValidationError(f"Invalid status: {status}. Must be one of: {', '.join(USER_STATUSES)}")

    # Check if user already exists
    existing_user = User.query.filter(
        (User.username == username) | (User.email == email)
    ).first()

    if existing_user:
        if existing_user.username == username:
            raise UserExistsError(f"User with username '{username}' already exists")
        else:
            raise UserExistsError(f"User with email '{email}' already exists")

    try:
        # Get role object
        role_obj = Role.query.filter_by(name=role).first()
        if not role_obj:
            raise UserValidationError(f"Role '{role}' does not exist")

        # Generate random password if none provided
        if not password:
            password = generate_password()

        # Create user
        user = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            status=status,
            require_mfa=require_mfa,
            password_change_required=require_password_change,
            created_at=datetime.datetime.now(datetime.timezone.utc)
        )

        # Set password
        user.set_password(password)

        # Set role
        user.roles = [role_obj]

        # Save to database
        db.session.add(user)
        db.session.commit()

        # Log the action
        log_admin_action(
            action="user.create",
            details={
                "username": username,
                "email": email,
                "role": role,
                "status": status,
                "require_mfa": require_mfa,
                "password_change_required": require_password_change,
                "reason": reason
            },
            status="success"
        )

        # Create response object
        result = {
            "username": username,
            "email": email,
            "role": role,
            "status": status,
            "require_mfa": require_mfa,
            "password_change_required": require_password_change,
            "user_id": user.id,
            "created_at": user.created_at.isoformat(),
        }

        # Include password if it was generated
        if not password:
            result["generated_password"] = password
            logger.info("Generated password for new user %s", username)

        logger.info("Created user %s with role %s", username, role)
        return result

    except Exception as e:
        db.session.rollback()
        if not isinstance(e, UserAdminError):
            logger.exception("Failed to create user: %s", e)
            raise UserAdminError(f"Failed to create user: {str(e)}")
        raise


def get_user(
    username: str,
    include_sensitive: bool = False,
    auth_token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get user information.

    Args:
        username: Username to look up
        include_sensitive: Whether to include sensitive information
        auth_token: Authentication token

    Returns:
        User information dictionary

    Raises:
        UserNotFoundError: If user doesn't exist
    """
    user = User.query.filter_by(username=username).first()

    if not user:
        raise UserNotFoundError(f"User not found: {username}")

    # Get role names
    role_names = [role.name for role in user.roles] if user.roles else []

    # Include permission names if available
    permission_names = []
    for role in user.roles:
        if role.permissions:
            for perm in role.permissions:
                permission_names.append(perm.name)

    # Get last login timestamp
    last_login = None
    if hasattr(user, 'last_login'):
        last_login = user.last_login.isoformat() if user.last_login else None

    # Build result object
    result = {
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "status": user.status,
        "roles": role_names,
        "permissions": list(set(permission_names)),
        "require_mfa": user.require_mfa,
        "password_change_required": user.password_change_required,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": last_login
    }

    # Include updated_at if available
    if hasattr(user, 'updated_at') and user.updated_at:
        result["updated_at"] = user.updated_at.isoformat()

    # Optionally include sensitive data for admins
    if include_sensitive:
        result["id"] = user.id
        result["mfa_enabled"] = bool(user.mfa_secret) if hasattr(user, 'mfa_secret') else False
        result["login_attempts"] = user.login_attempts if hasattr(user, 'login_attempts') else None

    # Log request for user information
    log_admin_action(
        action="user.info",
        details={
            "username": username,
            "include_sensitive": include_sensitive
        },
        status="success"
    )

    logger.debug("Retrieved user info for %s", username)
    return result


def update_user(
    username: str,
    email: Optional[str] = None,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    role: Optional[str] = None,
    status: Optional[str] = None,
    require_mfa: Optional[bool] = None,
    require_password_change: Optional[bool] = None,
    auth_token: Optional[str] = None,
    reason: Optional[str] = None
) -> Dict[str, Any]:
    """
    Update user information.

    Args:
        username: Username to update
        email: New email address
        first_name: New first name
        last_name: New last name
        role: New role
        status: New account status
        require_mfa: Whether to require MFA
        require_password_change: Whether to require password change
        auth_token: Authentication token
        reason: Reason for update (for audit purposes)

    Returns:
        Updated user information dictionary

    Raises:
        UserNotFoundError: If user doesn't exist
        UserValidationError: If validation fails
    """
    # Validate inputs
    if email is not None and not validate_email(email):
        raise UserValidationError(f"Invalid email format: {email}")

    if role is not None and role not in USER_ROLES:
        raise UserValidationError(f"Invalid role: {role}. Must be one of: {', '.join(USER_ROLES)}")

    if status is not None and status not in USER_STATUSES:
        raise UserValidationError(f"Invalid status: {status}. Must be one of: {', '.join(USER_STATUSES)}")

    user = User.query.filter_by(username=username).first()

    if not user:
        raise UserNotFoundError(f"User not found: {username}")

    try:
        # Keep track of changes for audit log
        changes = {}

        if email is not None and email != user.email:
            # Check if email is already in use
            existing = User.query.filter_by(email=email).first()
            if existing and existing.id != user.id:
                raise UserValidationError(f"Email '{email}' is already in use")

            changes["email"] = {"old": user.email, "new": email}
            user.email = email

        if first_name is not None and first_name != user.first_name:
            changes["first_name"] = {"old": user.first_name, "new": first_name}
            user.first_name = first_name

        if last_name is not None and last_name != user.last_name:
            changes["last_name"] = {"old": user.last_name, "new": last_name}
            user.last_name = last_name

        if role is not None:
            current_role = user.roles[0].name if user.roles else None

            if role != current_role:
                # Get role object
                role_obj = Role.query.filter_by(name=role).first()
                if not role_obj:
                    raise UserValidationError(f"Role '{role}' does not exist")

                changes["role"] = {"old": current_role, "new": role}
                user.roles = [role_obj]

        if status is not None and status != user.status:
            changes["status"] = {"old": user.status, "new": status}
            user.status = status

        if require_mfa is not None and require_mfa != user.require_mfa:
            changes["require_mfa"] = {"old": user.require_mfa, "new": require_mfa}
            user.require_mfa = require_mfa

        if require_password_change is not None and require_password_change != user.password_change_required:
            changes["password_change_required"] = {"old": user.password_change_required, "new": require_password_change}
            user.password_change_required = require_password_change

        # Only update if there are changes
        if changes:
            user.updated_at = datetime.datetime.now(datetime.timezone.utc)
            db.session.commit()

            # Log the update
            log_admin_action(
                action="user.update",
                details={
                    "username": username,
                    "changes": changes,
                    "reason": reason
                },
                status="success"
            )

            logger.info("Updated user %s with changes: %s", username, changes)
        else:
            logger.info("No changes detected for user %s", username)

        # Return updated user information
        return get_user(username, auth_token=auth_token)

    except Exception as e:
        db.session.rollback()
        if not isinstance(e, UserAdminError):
            logger.exception("Failed to update user: %s", e)
            raise UserAdminError(f"Failed to update user: {str(e)}")
        raise


def reset_password(
    username: str,
    new_password: Optional[str] = None,
    temporary: bool = True,
    notify: bool = False,
    auth_token: Optional[str] = None,
    reason: Optional[str] = None
) -> Dict[str, Any]:
    """
    Reset user password.

    Args:
        username: Username of the user
        new_password: New password (None to generate random password)
        temporary: Whether the password is temporary (requires change)
        notify: Whether to send notification email
        auth_token: Authentication token
        reason: Reason for password reset (for audit purposes)

    Returns:
        Dictionary with reset information

    Raises:
        UserNotFoundError: If user doesn't exist
    """
    user = User.query.filter_by(username=username).first()

    if not user:
        raise UserNotFoundError(f"User not found: {username}")

    try:
        # Generate random password if none provided
        if not new_password:
            new_password = generate_password()

        # Update password
        user.set_password(new_password)

        # Update password change requirement
        user.password_change_required = temporary

        # Update last modified
        user.updated_at = datetime.datetime.now(datetime.timezone.utc)

        # Save changes
        db.session.commit()

        # Send notification email if requested
        if notify:
            try:
                from core.notification import send_email_notification

                send_email_notification(
                    recipient=user.email,
                    template="password_reset",
                    data={
                        "username": user.username,
                        "temporary_password": new_password if temporary else None,
                        "reset_link": None if temporary else "/reset-password"
                    }
                )
                notification_sent = True
                logger.info("Sent password reset notification to %s", username)
            except Exception as e:
                logger.error("Failed to send password reset notification: %s", e)
                notification_sent = False
        else:
            notification_sent = False

        # Log the password reset
        log_admin_action(
            action="user.password_reset",
            details={
                "username": username,
                "temporary": temporary,
                "notification_sent": notification_sent,
                "reason": reason
            },
            status="success"
        )

        # Build result
        result = {
            "username": username,
            "temporary": temporary,
            "notification_sent": notification_sent,
            "reset_time": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

        # Include password if it was generated
        if not new_password:
            result["password"] = new_password

        logger.info("Reset password for user %s", username)
        return result

    except Exception as e:
        db.session.rollback()
        if not isinstance(e, UserAdminError):
            logger.exception("Failed to reset password: %s", e)
            raise UserAdminError(f"Failed to reset password: {str(e)}")
        raise


def list_users(
    role: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    auth_token: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    List users with optional filtering.

    Args:
        role: Filter by role
        status: Filter by status
        search: Search term for username, email, or name
        limit: Maximum number of users to return
        offset: Pagination offset
        auth_token: Authentication token

    Returns:
        List of user dictionaries
    """
    # Build query
    query = User.query

    # Apply filters
    if role:
        # Join with roles and filter
        query = query.join(User.roles).filter(Role.name == role)

    if status:
        query = query.filter(User.status == status)

    if search:
        # Search in username, email, first_name, and last_name
        search_term = f"%{search}%"
        query = query.filter(
            User.username.ilike(search_term) |
            User.email.ilike(search_term) |
            User.first_name.ilike(search_term) |
            User.last_name.ilike(search_term)
        )

    # Apply pagination
    query = query.limit(limit).offset(offset)

    # Execute query
    users = query.all()

    # Format results
    results = []
    for user in users:
        # Get role names
        role_names = [role.name for role in user.roles] if user.roles else []

        # Get last login timestamp
        last_login = None
        if hasattr(user, 'last_login'):
            last_login = user.last_login.isoformat() if user.last_login else None

        # Create user entry
        user_entry = {
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "status": user.status,
            "roles": role_names,
            "require_mfa": user.require_mfa,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login": last_login
        }

        results.append(user_entry)

    # Log the action
    log_admin_action(
        action="user.list",
        details={
            "role_filter": role,
            "status_filter": status,
            "search": search,
            "limit": limit,
            "offset": offset,
            "results_count": len(results)
        },
        status="success"
    )

    logger.debug("Listed %d users with filters: role=%s, status=%s, search=%s",
                len(results), role, status, search)
    return results


def delete_user(
    username: str,
    permanent: bool = False,
    auth_token: Optional[str] = None,
    reason: Optional[str] = None
) -> Dict[str, Any]:
    """
    Delete a user.

    Args:
        username: Username to delete
        permanent: Whether to permanently delete (True) or soft delete (False)
        auth_token: Authentication token
        reason: Reason for deletion (for audit purposes)

    Returns:
        Dictionary with deletion status

    Raises:
        UserNotFoundError: If user doesn't exist
    """
    user = User.query.filter_by(username=username).first()

    if not user:
        raise UserNotFoundError(f"User not found: {username}")

    try:
        if permanent:
            # Permanent deletion
            db.session.delete(user)
            db.session.commit()

            logger.info("Permanently deleted user %s", username)
        else:
            # Soft deletion - just mark as inactive
            user.status = "inactive"
            user.updated_at = datetime.datetime.now(datetime.timezone.utc)
            db.session.commit()

            logger.info("Soft-deleted (deactivated) user %s", username)

        # Log the deletion
        log_admin_action(
            action="user.delete",
            details={
                "username": username,
                "permanent": permanent,
                "reason": reason
            },
            status="success"
        )

        result = {
            "username": username,
            "permanent": permanent,
            "status": "deleted" if permanent else "inactive",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

        return result

    except Exception as e:
        db.session.rollback()
        if not isinstance(e, UserAdminError):
            logger.exception("Failed to delete user: %s", e)
            raise UserAdminError(f"Failed to delete user: {str(e)}")
        raise


def lock_unlock_user(
    username: str,
    action: str,
    duration: Optional[int] = None,
    auth_token: Optional[str] = None,
    reason: Optional[str] = None
) -> Dict[str, Any]:
    """
    Lock or unlock a user account.

    Args:
        username: Username to lock/unlock
        action: Either "lock" or "unlock"
        duration: Lock duration in minutes (None for indefinite)
        auth_token: Authentication token
        reason: Reason for action (for audit purposes)

    Returns:
        Dictionary with lock/unlock status

    Raises:
        UserNotFoundError: If user doesn't exist
        ValueError: If action is invalid
    """
    if action not in ["lock", "unlock"]:
        raise ValueError(f"Invalid action: {action}. Must be 'lock' or 'unlock'")

    user = User.query.filter_by(username=username).first()

    if not user:
        raise UserNotFoundError(f"User not found: {username}")

    try:
        if action == "lock":
            # Lock account
            user.status = "locked"

            # Calculate unlock time if duration provided
            unlock_time = None
            if duration:
                unlock_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=duration)

            # Set unlock time if the model supports it
            if hasattr(user, 'lock_expiration'):
                user.lock_expiration = unlock_time

            logger.info("Locked user account %s", username)
        else:
            # Unlock account
            user.status = "active"

            # Clear unlock time if the model supports it
            if hasattr(user, 'lock_expiration'):
                user.lock_expiration = None

            # Reset failed login attempts if the model supports it
            if hasattr(user, 'login_attempts'):
                user.login_attempts = 0

            logger.info("Unlocked user account %s", username)

        # Update last modified timestamp
        user.updated_at = datetime.datetime.now(datetime.timezone.utc)
        db.session.commit()

        # Log the action
        log_admin_action(
            action=f"user.{action}",
            details={
                "username": username,
                "duration": duration,
                "reason": reason
            },
            status="success"
        )

        # Build result
        result = {
            "username": username,
            "status": user.status,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

        if action == "lock" and duration:
            unlock_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=duration)
            result["unlock_time"] = unlock_time.isoformat()

        return result

    except Exception as e:
        db.session.rollback()
        if not isinstance(e, (UserAdminError, ValueError)):
            logger.exception("Failed to %s user: %s", action, e)
            raise UserAdminError(f"Failed to {action} user: {str(e)}")
        raise


def manage_mfa(
    username: str,
    enable: bool,
    reset: bool = False,
    auth_token: Optional[str] = None,
    reason: Optional[str] = None
) -> Dict[str, Any]:
    """
    Manage MFA requirements and settings for a user.

    Args:
        username: Username to manage MFA for
        enable: Whether to enable MFA requirement
        reset: Whether to reset existing MFA configuration
        auth_token: Authentication token
        reason: Reason for change (for audit purposes)

    Returns:
        Dictionary with MFA status

    Raises:
        UserNotFoundError: If user doesn't exist
    """
    user = User.query.filter_by(username=username).first()

    if not user:
        raise UserNotFoundError(f"User not found: {username}")

    try:
        # Track changes for audit
        changes = {}

        # Update MFA requirement
        if user.require_mfa != enable:
            changes["require_mfa"] = {"old": user.require_mfa, "new": enable}
            user.require_mfa = enable

        # Reset MFA if requested
        if reset and hasattr(user, 'mfa_secret'):
            changes["mfa_reset"] = True
            user.mfa_secret = None

            # Also reset backup codes if they exist
            if hasattr(user, 'mfa_backup_codes'):
                user.mfa_backup_codes = None

        # Only update if there are changes
        if changes:
            user.updated_at = datetime.datetime.now(datetime.timezone.utc)
            db.session.commit()

            # Log the action
            log_admin_action(
                action="user.manage_mfa",
                details={
                    "username": username,
                    "changes": changes,
                    "reason": reason
                },
                status="success"
            )

            logger.info("Updated MFA settings for user %s: %s", username, changes)

        # Build result
        result = {
            "username": username,
            "require_mfa": user.require_mfa,
            "mfa_configured": bool(user.mfa_secret) if hasattr(user, 'mfa_secret') else False,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

        if reset and hasattr(user, 'mfa_secret'):
            result["mfa_reset"] = True

        return result

    except Exception as e:
        db.session.rollback()
        if not isinstance(e, UserAdminError):
            logger.exception("Failed to manage MFA: %s", e)
            raise UserAdminError(f"Failed to manage MFA: {str(e)}")
        raise


def bulk_import_users(
    users_data: List[Dict[str, Any]],
    update_existing: bool = False,
    auth_token: Optional[str] = None,
    reason: Optional[str] = None
) -> Dict[str, Any]:
    """
    Import multiple users from a data structure.

    Args:
        users_data: List of user dictionaries
        update_existing: Whether to update existing users
        auth_token: Authentication token
        reason: Reason for import (for audit purposes)

    Returns:
        Dictionary with import statistics

    Raises:
        UserAdminError: If import fails
    """
    stats = {
        "total": len(users_data),
        "created": 0,
        "updated": 0,
        "failed": 0,
        "skipped": 0,
        "errors": []
    }

    for user_data in users_data:
        username = user_data.get('username')
        email = user_data.get('email')

        if not username or not email:
            stats["failed"] += 1
            stats["errors"].append(f"Missing required fields (username/email) for entry: {user_data}")
            continue

        try:
            # Check if user exists
            existing_user = User.query.filter_by(username=username).first()

            if existing_user:
                if update_existing:
                    # Update existing user
                    update_user(
                        username=username,
                        email=user_data.get('email'),
                        first_name=user_data.get('first_name'),
                        last_name=user_data.get('last_name'),
                        role=user_data.get('role'),
                        status=user_data.get('status'),
                        require_mfa=user_data.get('require_mfa'),
                        require_password_change=user_data.get('require_password_change'),
                        auth_token=auth_token,
                        reason=reason
                    )

                    # Reset password if provided
                    if 'password' in user_data:
                        reset_password(
                            username=username,
                            new_password=user_data['password'],
                            temporary=user_data.get('password_change_required', True),
                            auth_token=auth_token,
                            reason=reason
                        )

                    stats["updated"] += 1
                else:
                    stats["skipped"] += 1
            else:
                # Create new user
                create_user(
                    username=username,
                    email=email,
                    password=user_data.get('password'),
                    role=user_data.get('role', 'user'),
                    first_name=user_data.get('first_name'),
                    last_name=user_data.get('last_name'),
                    status=user_data.get('status', 'active'),
                    require_mfa=user_data.get('require_mfa', False),
                    require_password_change=user_data.get('require_password_change', True),
                    auth_token=auth_token,
                    reason=reason
                )

                stats["created"] += 1

        except Exception as e:
            stats["failed"] += 1
            stats["errors"].append(f"Error processing user {username}: {str(e)}")

    # Log the bulk import
    log_admin_action(
        action="user.bulk_import",
        details={
            "total": stats["total"],
            "created": stats["created"],
            "updated": stats["updated"],
            "failed": stats["failed"],
            "skipped": stats["skipped"],
            "reason": reason
        },
        status="success" if stats["failed"] == 0 else "partial_success"
    )

    logger.info("Bulk imported %d users: %d created, %d updated, %d failed, %d skipped",
               stats["total"], stats["created"], stats["updated"],
               stats["failed"], stats["skipped"])

    return stats


def export_users(
    role: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    include_sensitive: bool = False,
    auth_token: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Export user data with optional filtering.

    Args:
        role: Filter by role
        status: Filter by status
        search: Search term for username, email, or name
        include_sensitive: Whether to include sensitive data
        auth_token: Authentication token

    Returns:
        List of user dictionaries
    """
    # List users with filters
    users = list_users(
        role=role,
        status=status,
        search=search,
        limit=10000,  # High limit for exports
        auth_token=auth_token
    )

    # If sensitive data is requested, enrich each user
    if include_sensitive:
        enriched_users = []
        for user_data in users:
            username = user_data["username"]
            try:
                # Get full user data including sensitive fields
                enriched_user = get_user(
                    username=username,
                    include_sensitive=True,
                    auth_token=auth_token
                )
                enriched_users.append(enriched_user)
            except Exception as e:
                logger.warning("Failed to enrich user %s: %s", username, e)
                # Fall back to basic user data
                enriched_users.append(user_data)

        users = enriched_users

    # Log the export
    log_admin_action(
        action="user.export",
        details={
            "role_filter": role,
            "status_filter": status,
            "search": search,
            "include_sensitive": include_sensitive,
            "count": len(users)
        },
        status="success"
    )

    logger.info("Exported %d users with filters: role=%s, status=%s, search=%s",
              len(users), role, status, search)

    return users


def setup_arg_parser() -> argparse.ArgumentParser:
    """
    Set up command-line argument parser.

    Returns:
        Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="User Administration CLI for Cloud Infrastructure Platform",
        epilog="For detailed help, see the documentation."
    )

    # Authentication options
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("--token", help="Authentication token")
    auth_group.add_argument("--mfa-token", help="MFA token for privileged operations")

    # Output options
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("--format", choices=["text", "json", "csv", "table"],
                           default="text", help="Output format")
    output_group.add_argument("--output", help="Output file (default: stdout)")
    output_group.add_argument("--verbose", action="store_true", help="Enable verbose output")

    # Command subparsers
    subparsers = parser.add_subparsers(dest="command", help="User administration commands")

    # Create user command
    create_parser = subparsers.add_parser("create", help="Create a new user")
    create_parser.add_argument("--username", required=True, help="Username")
    create_parser.add_argument("--email", required=True, help="Email address")
    create_parser.add_argument("--password", help="Password (will generate if not provided)")
    create_parser.add_argument("--role", choices=USER_ROLES, default="user", help="Role")
    create_parser.add_argument("--first-name", help="First name")
    create_parser.add_argument("--last-name", help="Last name")
    create_parser.add_argument("--status", choices=USER_STATUSES, default="active", help="Status")
    create_parser.add_argument("--require-mfa/--no-require-mfa", dest="require_mfa",
                           default=False, help="Require MFA")
    create_parser.add_argument("--require-password-change/--no-require-password-change",
                           dest="require_password_change", default=True,
                           help="Require password change on first login")
    create_parser.add_argument("--reason", help="Reason for creation (for audit purposes)")

    # User info command
    info_parser = subparsers.add_parser("info", help="Get user information")
    info_parser.add_argument("username", help="Username")
    info_parser.add_argument("--include-sensitive", action="store_true",
                          help="Include sensitive information (requires elevated permissions)")

    # List users command
    list_parser = subparsers.add_parser("list", help="List users")
    list_parser.add_argument("--role", choices=USER_ROLES, help="Filter by role")
    list_parser.add_argument("--status", choices=USER_STATUSES, help="Filter by status")
    list_parser.add_argument("--search", help="Search term (username, email, name)")
    list_parser.add_argument("--limit", type=int, default=100, help="Maximum number of results")
    list_parser.add_argument("--offset", type=int, default=0, help="Pagination offset")

    # Update user command
    update_parser = subparsers.add_parser("update", help="Update user information")
    update_parser.add_argument("username", help="Username")
    update_parser.add_argument("--email", help="New email address")
    update_parser.add_argument("--first-name", help="New first name")
    update_parser.add_argument("--last-name", help="New last name")
    update_parser.add_argument("--role", choices=USER_ROLES, help="New role")
    update_parser.add_argument("--status", choices=USER_STATUSES, help="New status")
    update_parser.add_argument("--require-mfa", type=bool, help="Require MFA")
    update_parser.add_argument("--require-password-change", type=bool,
                            help="Require password change")
    update_parser.add_argument("--reason", required=True,
                            help="Reason for update (for audit purposes)")

    # Reset password command
    reset_parser = subparsers.add_parser("reset-password", help="Reset user password")
    reset_parser.add_argument("username", help="Username")
    reset_parser.add_argument("--password", help="New password (will generate if not provided)")
    reset_parser.add_argument("--temporary/--permanent", dest="temporary", default=True,
                           help="Whether the password is temporary (requires change)")
    reset_parser.add_argument("--notify/--no-notify", dest="notify", default=False,
                           help="Send notification email")
    reset_parser.add_argument("--reason", required=True,
                           help="Reason for password reset (for audit purposes)")

    # Delete user command
    delete_parser = subparsers.add_parser("delete", help="Delete user")
    delete_parser.add_argument("username", help="Username")
    delete_parser.add_argument("--permanent/--soft-delete", dest="permanent", default=False,
                            help="Permanently delete instead of deactivating")
    delete_parser.add_argument("--reason", required=True,
                            help="Reason for deletion (for audit purposes)")

    # Lock/unlock commands
    lock_parser = subparsers.add_parser("lock", help="Lock user account")
    lock_parser.add_argument("username", help="Username")
    lock_parser.add_argument("--duration", type=int, help="Lock duration in minutes (None for indefinite)")
    lock_parser.add_argument("--reason", required=True,
                          help="Reason for locking (for audit purposes)")

    unlock_parser = subparsers.add_parser("unlock", help="Unlock user account")
    unlock_parser.add_argument("username", help="Username")
    unlock_parser.add_argument("--reason", required=True,
                            help="Reason for unlocking (for audit purposes)")

    # MFA management command
    mfa_parser = subparsers.add_parser("mfa", help="Manage MFA settings")
    mfa_parser.add_argument("username", help="Username")
    mfa_parser.add_argument("--enable/--disable", dest="enable", required=True,
                         help="Enable or disable MFA requirement")
    mfa_parser.add_argument("--reset/--no-reset", dest="reset", default=False,
                         help="Reset existing MFA configuration")
    mfa_parser.add_argument("--reason", required=True,
                         help="Reason for MFA change (for audit purposes)")

    # Bulk export command
    export_parser = subparsers.add_parser("export", help="Export user data")
    export_parser.add_argument("--role", choices=USER_ROLES, help="Filter by role")
    export_parser.add_argument("--status", choices=USER_STATUSES, help="Filter by status")
    export_parser.add_argument("--search", help="Search term (username, email, name)")
    export_parser.add_argument("--include-sensitive", action="store_true",
                            help="Include sensitive information (requires elevated permissions)")
    export_parser.add_argument("--output", required=True, help="Output file path")

    # Bulk import command
    import_parser = subparsers.add_parser("import", help="Import users from file")
    import_parser.add_argument("file", help="Import file path (CSV or JSON)")
    import_parser.add_argument("--format", choices=["csv", "json"], default="csv",
                            help="File format")
    import_parser.add_argument("--update-existing/--no-update-existing",
                            dest="update_existing", default=False,
                            help="Update existing users instead of skipping")
    import_parser.add_argument("--dry-run", action="store_true",
                            help="Preview changes without applying them")
    import_parser.add_argument("--reason", required=True,
                            help="Reason for import (for audit purposes)")

    # Add version command
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
        print(f"User Administration CLI version {VERSION}")
        return EXIT_SUCCESS

    if not args.command:
        parser.print_help()
        return EXIT_SUCCESS

    try:
        result = None

        # Check authentication if required
        auth_token = args.token

        # List of commands that don't require auth for execution
        # (they'll be handled by the core permission system)
        # This is just to avoid showing auth warnings in CLI for public info
        public_commands = ["list", "info"]

        if args.command not in public_commands and not auth_token:
            logger.warning("No authentication token provided. Some operations may fail.")

        # Execute appropriate command based on subparser
        if args.command == "create":
            result = create_user(
                username=args.username,
                email=args.email,
                password=args.password,
                role=args.role,
                first_name=args.first_name,
                last_name=args.last_name,
                status=args.status,
                require_mfa=args.require_mfa,
                require_password_change=args.require_password_change,
                auth_token=auth_token,
                reason=args.reason
            )

        elif args.command == "info":
            result = get_user(
                username=args.username,
                include_sensitive=args.include_sensitive,
                auth_token=auth_token
            )

        elif args.command == "list":
            result = list_users(
                role=args.role,
                status=args.status,
                search=args.search,
                limit=args.limit,
                offset=args.offset,
                auth_token=auth_token
            )

        elif args.command == "update":
            result = update_user(
                username=args.username,
                email=args.email,
                first_name=args.first_name,
                last_name=args.last_name,
                role=args.role,
                status=args.status,
                require_mfa=args.require_mfa,
                require_password_change=args.require_password_change,
                auth_token=auth_token,
                reason=args.reason
            )

        elif args.command == "reset-password":
            result = reset_password(
                username=args.username,
                new_password=args.password,
                temporary=args.temporary,
                notify=args.notify,
                auth_token=auth_token,
                reason=args.reason
            )

        elif args.command == "delete":
            result = delete_user(
                username=args.username,
                permanent=args.permanent,
                auth_token=auth_token,
                reason=args.reason
            )

        elif args.command == "lock":
            result = lock_unlock_user(
                username=args.username,
                action="lock",
                duration=args.duration,
                auth_token=auth_token,
                reason=args.reason
            )

        elif args.command == "unlock":
            result = lock_unlock_user(
                username=args.username,
                action="unlock",
                auth_token=auth_token,
                reason=args.reason
            )

        elif args.command == "mfa":
            result = manage_mfa(
                username=args.username,
                enable=args.enable,
                reset=args.reset,
                auth_token=auth_token,
                reason=args.reason
            )

        elif args.command == "export":
            # Export users
            users_data = export_users(
                role=args.role,
                status=args.status,
                search=args.search,
                include_sensitive=args.include_sensitive,
                auth_token=auth_token
            )

            # Format and write to file
            output_format = args.format
            if args.output.endswith('.json'):
                output_format = 'json'
            elif args.output.endswith('.csv'):
                output_format = 'csv'

            formatted_output = format_output(users_data, output_format)

            with open(args.output, 'w') as f:
                f.write(formatted_output)

            result = {
                "exported_users": len(users_data),
                "output_file": args.output,
                "format": output_format
            }

        elif args.command == "import":
            # Determine format from file extension if not specified
            file_format = args.format
            if not file_format:
                if args.file.endswith('.json'):
                    file_format = 'json'
                elif args.file.endswith('.csv'):
                    file_format = 'csv'
                else:
                    raise ValueError("Could not determine file format from extension. Please specify --format.")

            # Read import data
            users_data = []
            if file_format == 'json':
                with open(args.file, 'r') as f:
                    users_data = json.load(f)
            else:  # CSV
                with open(args.file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    users_data = list(reader)

                    # Convert boolean fields
                    for user in users_data:
                        for field in ['require_mfa', 'require_password_change']:
                            if field in user:
                                user[field] = user[field].lower() in ('true', 'yes', '1', 'y')

            # Run import or dry run
            if args.dry_run:
                # Just preview the data
                result = {
                    "dry_run": True,
                    "users_to_process": len(users_data),
                    "sample": users_data[:5] if len(users_data) > 5 else users_data
                }
            else:
                # Perform actual import
                result = bulk_import_users(
                    users_data=users_data,
                    update_existing=args.update_existing,
                    auth_token=auth_token,
                    reason=args.reason
                )

        # Format and output the result
        if result is not None:
            formatted_result = format_output(result, args.format)

            if args.output and args.command != "export":  # Export already handles output file
                with open(args.output, 'w') as f:
                    f.write(formatted_result)
                print(f"Results written to {args.output}")
            else:
                print(formatted_result)

        return EXIT_SUCCESS

    except UserValidationError as e:
        logger.error("Validation error: %s", e)
        print(f"Error: {e}")
        return EXIT_VALIDATION_ERROR

    except UserExistsError as e:
        logger.error("User exists error: %s", e)
        print(f"Error: {e}")
        return EXIT_RESOURCE_ERROR

    except UserNotFoundError as e:
        logger.error("User not found: %s", e)
        print(f"Error: {e}")
        return EXIT_RESOURCE_ERROR

    except ValueError as e:
        logger.error("Invalid value: %s", e)
        print(f"Error: {e}")
        return EXIT_VALIDATION_ERROR

    except PermissionError as e:
        logger.error("Permission denied: %s", e)
        print(f"Error: Access denied. {e}")
        return EXIT_PERMISSION_ERROR

    except Exception as e:
        logger.exception("Unhandled exception: %s", e)
        print(f"Error: {e}")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
