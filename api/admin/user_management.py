"""
User management functionality for the Administrative API.

This module provides functions for user account administration including creation,
modification, deletion, and credential management. It implements appropriate security
controls with proper validation, error handling, and comprehensive security logging
for audit purposes.

The functions here serve as the business logic layer for user operations exposed
through the REST API endpoints in routes.py, ensuring consistent security and
validation across all user management operations.
"""

import logging
import secrets
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple, Union

from flask import current_app, g
from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash

from extensions import db
from models.auth import Role, User
from models.auth.permission import Permission
from core.security import validate_password_strength, log_security_event
from services.notification_service import send_user_notification

# Initialize logger
logger = logging.getLogger(__name__)


def get_users(
    role: Optional[str] = None,
    active: Optional[bool] = None,
    search: Optional[str] = None,
    page: int = 1,
    per_page: int = 50
) -> Tuple[List[Dict[str, Any]], int, int]:
    """
    Get a list of users with filtering and pagination.

    Args:
        role: Filter by role name
        active: Filter by active status
        search: Search by username, email, or name
        page: Page number
        per_page: Items per page

    Returns:
        Tuple containing:
        - List of user dictionaries
        - Total count of matching users
        - Total number of pages
    """
    try:
        # Start with base query
        query = User.query

        # Apply filters
        if role:
            # Join with roles to filter by role name
            query = query.join(User.roles).filter(Role.name == role)

        if active is not None:
            query = query.filter(User.status == 'active' if active else User.status != 'active')

        if search:
            # Search in username, email, first_name, and last_name
            search_term = f"%{search}%"
            query = query.filter(or_(
                User.username.ilike(search_term),
                User.email.ilike(search_term),
                User.first_name.ilike(search_term),
                User.last_name.ilike(search_term)
            ))

        # Get total count before pagination
        total_count = query.count()

        # Calculate total pages
        total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1

        # Apply pagination and get users
        users = query.order_by(User.username).offset((page - 1) * per_page).limit(per_page).all()

        # Format users for response
        result = []
        for user in users:
            # Get roles and permissions
            roles = [role.name for role in user.roles]
            permissions = []

            # Get permissions directly assigned to user or through roles
            for role in user.roles:
                for permission in role.permissions:
                    if permission.name not in permissions:
                        permissions.append(permission.name)

            # Create user dictionary with essential information
            user_dict = {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name or "",
                "last_name": user.last_name or "",
                "status": user.status,
                "roles": roles,
                "permissions": permissions,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "last_login": user.last_login.isoformat() if user.last_login else None,
                "require_mfa": user.require_mfa if hasattr(user, 'require_mfa') else False,
                "mfa_enabled": bool(user.two_factor_enabled) if hasattr(user, 'two_factor_enabled') else False
            }
            result.append(user_dict)

        return result, total_count, total_pages

    except SQLAlchemyError as e:
        logger.error(f"Database error in get_users: {str(e)}")
        db.session.rollback()
        raise ValueError("A database error occurred while fetching users")


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """
    Get detailed information about a specific user by ID.

    Args:
        user_id: The user ID to retrieve

    Returns:
        User dictionary or None if not found
    """
    try:
        # Get the user
        user = User.query.get(user_id)
        if not user:
            return None

        # Get roles and permissions
        roles = [role.name for role in user.roles]
        permissions = []

        # Include permissions from roles
        for role in user.roles:
            for permission in role.permissions:
                if permission.name not in permissions:
                    permissions.append(permission.name)

        # Create detailed user dictionary
        user_dict = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name or "",
            "last_name": user.last_name or "",
            "status": user.status,
            "roles": roles,
            "permissions": permissions,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "updated_at": user.updated_at.isoformat() if user.updated_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "login_count": user.login_count if hasattr(user, 'login_count') else 0,
            "failed_login_count": user.failed_login_count if hasattr(user, 'failed_login_count') else 0,
            "require_mfa": user.require_mfa if hasattr(user, 'require_mfa') else False,
            "mfa_enabled": bool(user.two_factor_enabled) if hasattr(user, 'two_factor_enabled') else False,
            "password_change_required": user.password_change_required if hasattr(user, 'password_change_required') else False,
            "active_sessions": []
        }

        # Include active sessions if available
        if hasattr(user, 'sessions'):
            active_sessions = user.sessions.filter_by(is_active=True).all()
            user_dict["active_sessions"] = [
                {
                    "id": session.id,
                    "created_at": session.created_at.isoformat() if session.created_at else None,
                    "ip_address": session.ip_address,
                    "user_agent": session.user_agent,
                    "expires_at": session.expires_at.isoformat() if session.expires_at else None
                }
                for session in active_sessions
            ]

        return user_dict

    except SQLAlchemyError as e:
        logger.error(f"Database error in get_user_by_id: {str(e)}")
        db.session.rollback()
        raise ValueError("A database error occurred while fetching user details")


def create_user(
    username: str,
    email: str,
    password: str,
    role: str = 'user',
    first_name: str = '',
    last_name: str = '',
    active: bool = True,
    require_mfa: bool = False,
    password_change_required: bool = True,
    created_by: Optional[int] = None
) -> Dict[str, Any]:
    """
    Create a new user account.

    Args:
        username: Unique username
        email: User's email address
        password: Initial password
        role: Role name (default: 'user')
        first_name: User's first name
        last_name: User's last name
        active: Whether the account is active (default: True)
        require_mfa: Whether to require MFA setup (default: False)
        password_change_required: Whether to require password change on first login (default: True)
        created_by: ID of the admin creating the user (for audit)

    Returns:
        Created user dictionary

    Raises:
        ValueError: If validation fails or user already exists
    """
    # Input validation
    if not username or len(username) < 3:
        raise ValueError("Username must be at least 3 characters long")

    if not email or '@' not in email:
        raise ValueError("Valid email address is required")

    # Validate password strength
    if not validate_password_strength(password):
        raise ValueError("Password does not meet strength requirements")

    # Check if username or email already exists
    existing_user = User.query.filter(
        or_(User.username == username, User.email == email)
    ).first()

    if existing_user:
        if existing_user.username == username:
            raise ValueError(f"Username '{username}' already exists")
        else:
            raise ValueError(f"Email '{email}' already exists")

    try:
        # Get the role object
        role_obj = Role.query.filter_by(name=role).first()
        if not role_obj:
            raise ValueError(f"Role '{role}' not found")

        # Create the user object
        status = User.STATUS_ACTIVE if active else User.STATUS_INACTIVE

        new_user = User(
            username=username,
            email=email,
            status=status,
            first_name=first_name,
            last_name=last_name,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )

        # Set MFA and password attributes if available
        if hasattr(new_user, 'require_mfa'):
            new_user.require_mfa = require_mfa

        if hasattr(new_user, 'password_change_required'):
            new_user.password_change_required = password_change_required

        # Set password
        new_user.set_password(password)

        # Assign role
        new_user.roles = [role_obj]

        # Save to database
        db.session.add(new_user)
        db.session.commit()

        # Create user dictionary for response
        user_dict = {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "first_name": new_user.first_name or "",
            "last_name": new_user.last_name or "",
            "status": new_user.status,
            "roles": [role],
            "created_at": new_user.created_at.isoformat() if new_user.created_at else None,
        }

        # Send welcome notification if enabled
        try:
            send_user_notification(
                user_id=new_user.id,
                notification_type="account_created",
                data={
                    "username": username,
                    "temporary_password": password_change_required,
                    "require_mfa": require_mfa,
                    "created_by": created_by
                }
            )
        except Exception as e:
            logger.warning(f"Failed to send welcome notification: {str(e)}")

        logger.info(f"User '{username}' created by admin ID {created_by or 'system'}")
        return user_dict

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error in create_user: {str(e)}")
        raise ValueError("A database error occurred while creating user")


def update_user(
    user_id: int,
    email: Optional[str] = None,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    active: Optional[bool] = None,
    require_mfa: Optional[bool] = None,
    password_change_required: Optional[bool] = None,
    updated_by: Optional[int] = None
) -> Optional[Dict[str, Any]]:
    """
    Update a user's account details.

    Args:
        user_id: User ID to update
        email: New email address
        first_name: New first name
        last_name: New last name
        active: New active status
        require_mfa: Whether to require MFA
        password_change_required: Whether to require password change
        updated_by: ID of admin making the update (for audit)

    Returns:
        Updated user dictionary or None if user not found

    Raises:
        ValueError: If validation fails
    """
    try:
        # Get the user
        user = User.query.get(user_id)
        if not user:
            return None

        # Track changes for audit log
        changes = {}

        # Update email if provided and different
        if email is not None and email != user.email:
            # Check that the new email is not already in use
            existing = User.query.filter_by(email=email).first()
            if existing and existing.id != user_id:
                raise ValueError(f"Email '{email}' is already in use")

            changes["email"] = {"from": user.email, "to": email}
            user.email = email

        # Update first name if provided
        if first_name is not None and first_name != user.first_name:
            changes["first_name"] = {"from": user.first_name, "to": first_name}
            user.first_name = first_name

        # Update last name if provided
        if last_name is not None and last_name != user.last_name:
            changes["last_name"] = {"from": user.last_name, "to": last_name}
            user.last_name = last_name

        # Update active status if provided
        if active is not None:
            new_status = User.STATUS_ACTIVE if active else User.STATUS_INACTIVE
            if new_status != user.status:
                changes["status"] = {"from": user.status, "to": new_status}
                user.status = new_status

                # If deactivating, terminate all sessions
                if not active and hasattr(user, 'sessions'):
                    for session in user.sessions.all():
                        session.is_active = False
                        if hasattr(session, 'termination_reason'):
                            session.termination_reason = 'account_deactivated'

        # Update MFA requirement if provided and the attribute exists
        if require_mfa is not None and hasattr(user, 'require_mfa'):
            if require_mfa != user.require_mfa:
                changes["require_mfa"] = {"from": user.require_mfa, "to": require_mfa}
                user.require_mfa = require_mfa

        # Update password change requirement if provided and the attribute exists
        if password_change_required is not None and hasattr(user, 'password_change_required'):
            if password_change_required != user.password_change_required:
                changes["password_change_required"] = {
                    "from": user.password_change_required,
                    "to": password_change_required
                }
                user.password_change_required = password_change_required

        # Only update if there are changes
        if changes:
            user.updated_at = datetime.now(timezone.utc)
            db.session.commit()

            # Log the changes for audit
            log_security_event(
                event_type="user_updated",
                description=f"User '{user.username}' (ID: {user_id}) updated by admin",
                severity="info",
                user_id=updated_by,
                details={
                    "user_id": user_id,
                    "username": user.username,
                    "changes": changes
                }
            )

            logger.info(f"User '{user.username}' updated by admin ID {updated_by or 'system'}")

        # Return updated user details
        return get_user_by_id(user_id)

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error in update_user: {str(e)}")
        raise ValueError("A database error occurred while updating user")


def update_user_role(
    user_id: int,
    role: str,
    updated_by: Optional[int] = None
) -> Optional[Dict[str, Any]]:
    """
    Change a user's role.

    Args:
        user_id: User ID to update
        role: New role name
        updated_by: ID of admin making the update (for audit)

    Returns:
        Updated user dictionary or None if user not found

    Raises:
        ValueError: If validation fails or role not found
    """
    try:
        # Get the user
        user = User.query.get(user_id)
        if not user:
            return None

        # Get the role object
        role_obj = Role.query.filter_by(name=role).first()
        if not role_obj:
            raise ValueError(f"Role '{role}' not found")

        # Get current role for logging
        current_role = user.roles[0].name if user.roles else None

        # Don't update if already assigned
        if current_role == role:
            return get_user_by_id(user_id)

        # Update role
        user.roles = [role_obj]
        user.updated_at = datetime.now(timezone.utc)
        db.session.commit()

        # Log for audit
        log_security_event(
            event_type="user_role_changed",
            description=f"User '{user.username}' (ID: {user_id}) role changed from '{current_role}' to '{role}'",
            severity="medium",  # Role changes are security-sensitive
            user_id=updated_by,
            details={
                "user_id": user_id,
                "username": user.username,
                "previous_role": current_role,
                "new_role": role
            }
        )

        logger.info(f"User '{user.username}' role changed from '{current_role}' to '{role}' by admin ID {updated_by or 'system'}")

        # Return updated user details
        return get_user_by_id(user_id)

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error in update_user_role: {str(e)}")
        raise ValueError("A database error occurred while updating user role")


def reset_user_password(
    user_id: int,
    new_password: str,
    send_email: bool = True,
    reset_by: Optional[int] = None,
    force_change: bool = True
) -> bool:
    """
    Reset a user's password.

    Args:
        user_id: User ID to update
        new_password: New password
        send_email: Whether to send notification email
        reset_by: ID of admin performing the reset (for audit)
        force_change: Whether to force password change on next login

    Returns:
        True if successful, False otherwise

    Raises:
        ValueError: If validation fails
    """
    # Validate password strength
    if not validate_password_strength(new_password):
        raise ValueError("Password does not meet strength requirements")

    try:
        # Get the user
        user = User.query.get(user_id)
        if not user:
            return False

        # Update password
        user.set_password(new_password)

        # Update password change timestamp if available
        if hasattr(user, 'last_password_change'):
            user.last_password_change = datetime.now(timezone.utc)

        # Set password change required if applicable
        if force_change and hasattr(user, 'password_change_required'):
            user.password_change_required = True

        # Invalidate existing sessions if applicable
        if hasattr(user, 'sessions'):
            for session in user.sessions.all():
                session.is_active = False
                if hasattr(session, 'termination_reason'):
                    session.termination_reason = 'password_reset'

        user.updated_at = datetime.now(timezone.utc)
        db.session.commit()

        # Send notification if requested
        notification_sent = False
        if send_email:
            try:
                send_user_notification(
                    user_id=user_id,
                    notification_type="password_reset",
                    data={
                        "reset_by_admin": True,
                        "force_change": force_change,
                        "admin_id": reset_by
                    }
                )
                notification_sent = True
            except Exception as e:
                logger.warning(f"Failed to send password reset notification: {str(e)}")

        # Log for audit
        log_security_event(
            event_type="password_reset_by_admin",
            description=f"Password reset for user '{user.username}' (ID: {user_id}) by admin",
            severity="medium",  # Password resets are security-sensitive
            user_id=reset_by,
            details={
                "user_id": user_id,
                "username": user.username,
                "notification_sent": notification_sent,
                "force_change": force_change
            }
        )

        logger.info(f"Password reset for user '{user.username}' by admin ID {reset_by or 'system'}")
        return True

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error in reset_user_password: {str(e)}")
        raise ValueError("A database error occurred while resetting password")


def delete_user(user_id: int, deleted_by: Optional[int] = None) -> bool:
    """
    Delete a user account.

    Args:
        user_id: User ID to delete
        deleted_by: ID of admin performing the deletion (for audit)

    Returns:
        True if successful, False otherwise
    """
    try:
        # Get the user
        user = User.query.get(user_id)
        if not user:
            return False

        # Store user information for logging
        username = user.username
        email = user.email

        # Delete the user
        db.session.delete(user)
        db.session.commit()

        # Log for audit
        log_security_event(
            event_type="user_deleted",
            description=f"User '{username}' (ID: {user_id}) deleted by admin",
            severity="high",  # User deletions are high security impact
            user_id=deleted_by,
            details={
                "deleted_user_id": user_id,
                "username": username,
                "email": email
            }
        )

        logger.info(f"User '{username}' deleted by admin ID {deleted_by or 'system'}")
        return True

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error in delete_user: {str(e)}")
        raise ValueError("A database error occurred while deleting user")


def generate_random_password(length: int = 12) -> str:
    """
    Generate a secure random password.

    Args:
        length: Length of the password (default: 12)

    Returns:
        Randomly generated password
    """
    # Simple implementation - in production, consider using more sophisticated password generation
    return secrets.token_urlsafe(length)[:length]
