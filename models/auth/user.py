"""
User model module for authentication and authorization in the Cloud Infrastructure Platform.

This module defines the User model which serves as the foundation for the application's
authentication and authorization system. It provides robust functionality for:

- Secure password management with hashing and verification
- Role-based access control with permission inheritance
- JWT token generation and validation for API authentication
- Two-factor authentication support
- Account status management (pending, active, inactive, suspended)
- User profile information storage
- Login tracking and security monitoring
- Password reset capabilities
- Session management and tracking

The User model implements security best practices including proper password hashing,
token expiration, and protection against common authentication vulnerabilities.
It serves as the central component for user identity and access management throughout
the application.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Set, Union
import uuid
import jwt
from flask import current_app
from sqlalchemy import and_, or_, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db
from models.base import BaseModel, AuditableMixin
from core.security_utils import log_security_event

class User(BaseModel, AuditableMixin):
    """
    User model with authentication and authorization.

    This model represents users in the system and provides functionality for
    authentication, authorization, and user management. It supports role-based
    access control with permission inheritance.

    Attributes:
        id: Primary key
        username: Unique username for login
        password: Hashed password
        email: Unique email address
        status: Account status (pending, active, inactive, suspended)
        first_name: User's first name
        last_name: User's last name
        bio: User's biographical information
        avatar_url: URL to user's avatar image
        two_factor_enabled: Whether 2FA is enabled for this user
        two_factor_secret: Secret key for 2FA
        created_at: When the user account was created
        updated_at: When the user account was last updated
        last_login: When the user last logged in
        login_count: How many successful logins have occurred
        failed_login_count: How many consecutive failed login attempts
        last_failed_login: When the last failed login attempt occurred
        locked_until: Account lockout expiration time
    """
    __tablename__ = 'users'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['status', 'password', 'email', 'role_id', 'two_factor_enabled']

    # Enable access auditing for this model due to its sensitive nature
    AUDIT_ACCESS = True

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)

    # Role relationship for RBAC
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete='SET NULL'),
                       nullable=True, index=True)
    role = relationship('Role', backref=db.backref('users', lazy='dynamic'))

    # User status
    status = db.Column(db.String(20), default='pending', index=True)

    # Profile fields
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    bio = db.Column(db.Text)
    avatar_url = db.Column(db.String(255))

    # Security
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32))

    # Activity tracking
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True),
                         default=lambda: datetime.now(timezone.utc),
                         onupdate=lambda: datetime.now(timezone.utc),
                         nullable=False)
    last_login = db.Column(db.DateTime(timezone=True))
    login_count = db.Column(db.Integer, default=0)
    failed_login_count = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime(timezone=True))
    locked_until = db.Column(db.DateTime(timezone=True))

    # Additional security attributes
    last_password_change = db.Column(db.DateTime(timezone=True))
    password_reset_token = db.Column(db.String(100), unique=True, nullable=True)
    password_reset_expires = db.Column(db.DateTime(timezone=True), nullable=True)

    # Constants
    STATUS_PENDING = 'pending'
    STATUS_ACTIVE = 'active'
    STATUS_INACTIVE = 'inactive'
    STATUS_SUSPENDED = 'suspended'
    VALID_STATUSES = [STATUS_PENDING, STATUS_ACTIVE, STATUS_INACTIVE, STATUS_SUSPENDED]

    # Authorization level constants (for compatibility with legacy code)
    AUTH_LEVEL_USER = 'user'
    AUTH_LEVEL_ADMIN = 'admin'
    AUTH_LEVEL_OPERATOR = 'operator'

    def __init__(self, username: str, email: str, password: Optional[str] = None,
                 status: str = STATUS_PENDING, **kwargs) -> None:
        """
        Initialize a new user.

        Args:
            username: Unique username
            email: Email address
            password: Plain text password to hash, or None
            status: Initial account status
            **kwargs: Additional attributes to set
        """
        self.username = username
        self.email = email
        if password:
            self.set_password(password)
        self.status = status

        # Optional fields
        self.first_name = kwargs.get('first_name')
        self.last_name = kwargs.get('last_name')
        self.bio = kwargs.get('bio')
        self.avatar_url = kwargs.get('avatar_url')
        self.role_id = kwargs.get('role_id')

        # Set creation timestamp
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = self.created_at
        self.last_password_change = self.created_at

    def set_password(self, password: str) -> None:
        """
        Set password with validation and update last_password_change timestamp.

        Args:
            password: Plain text password to hash

        Raises:
            ValueError: If password doesn't meet criteria
        """
        # Basic password validation
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters")

        # Store the hashed password
        self.password = generate_password_hash(password)
        self.last_password_change = datetime.now(timezone.utc)

        # Log the password change event (but not the password itself)
        self.log_change(['password'], "Password changed")

    def check_password(self, password: str) -> bool:
        """
        Verify password.

        Args:
            password: Plain text password to check

        Returns:
            bool: True if password matches, False otherwise
        """
        return check_password_hash(self.password, password)

    def generate_token(self, expires_in: int = 3600) -> str:
        """
        Generate JWT token with expiry.

        Args:
            expires_in: Token expiration time in seconds (default: 1 hour)

        Returns:
            str: Encoded JWT token

        Raises:
            ValueError: If expires_in is invalid
            RuntimeError: If token generation fails
        """
        try:
            # Validate expiration time
            if expires_in < 1 or expires_in > 86400:  # Max 24 hours
                raise ValueError("Token expiration must be between 1 second and 24 hours")

            # Get permissions if we have a role
            permissions = []
            if self.role:
                permissions = self.role.get_permission_names()

            token = jwt.encode(
                {
                    'user_id': self.id,
                    'username': self.username,
                    'role_id': self.role_id,
                    'permissions': permissions,
                    'exp': datetime.utcnow() + timedelta(seconds=expires_in),
                    'iat': datetime.utcnow(),
                    'jti': str(uuid.uuid4())
                },
                current_app.config['SECRET_KEY'],
                algorithm='HS256'
            )

            current_app.logger.info(f"Generated token for user {self.id}")

            # Convert token to string if it's bytes
            if isinstance(token, bytes):
                token = token.decode('utf-8')

            return token

        except Exception as e:
            current_app.logger.error(f"Token generation failed: {e}")
            raise RuntimeError(f"Failed to generate token: {e}") from e

    @classmethod
    def verify_token(cls, token) -> Optional['User']:
        """
        Verify JWT token.

        Args:
            token: JWT token to verify

        Returns:
            Optional[User]: User if token is valid, None otherwise
        """
        try:
            data = jwt.decode(
                token,
                current_app.config['SECRET_KEY'],
                algorithms=['HS256']
            )
            return cls.query.get(data['user_id'])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
            current_app.logger.error(f"Token verification failed: {e}")
            return None

    def update_last_login(self) -> None:
        """
        Update login tracking and reset failed login counter.
        """
        self.last_login = datetime.now(timezone.utc)
        self.login_count += 1
        self.reset_failed_logins()

        try:
            db.session.commit()

            # Log successful login for security auditing
            log_security_event(
                event_type="user_login",
                description=f"User {self.username} logged in",
                severity="info",
                details={
                    "user_id": self.id,
                    "username": self.username,
                    "login_count": self.login_count
                }
            )

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating login tracking: {str(e)}")

    def record_failed_login(self) -> None:
        """
        Record a failed login attempt and apply lockout if needed.
        """
        self.failed_login_count += 1
        self.last_failed_login = datetime.now(timezone.utc)

        # Progressive lockout strategy
        if self.failed_login_count >= 10:
            # Extended lockout (1 hour) after 10 failed attempts
            self.locked_until = datetime.now(timezone.utc) + timedelta(hours=1)

            # Log security event for extended lockout
            log_security_event(
                event_type="account_locked",
                description=f"Extended account lockout for user {self.username}",
                severity="warning",
                details={
                    "user_id": self.id,
                    "username": self.username,
                    "failed_attempts": self.failed_login_count,
                    "lockout_duration": "1 hour"
                }
            )

        elif self.failed_login_count >= 5:
            # Medium lockout (15 minutes) after 5 failed attempts
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)

            # Log security event for medium lockout
            log_security_event(
                event_type="account_locked",
                description=f"Medium account lockout for user {self.username}",
                severity="info",
                details={
                    "user_id": self.id,
                    "username": self.username,
                    "failed_attempts": self.failed_login_count,
                    "lockout_duration": "15 minutes"
                }
            )

        elif self.failed_login_count >= 3:
            # Short lockout (5 minutes) after 3 failed attempts
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=5)

            # Log security event for short lockout
            log_security_event(
                event_type="account_locked",
                description=f"Short account lockout for user {self.username}",
                severity="info",
                details={
                    "user_id": self.id,
                    "username": self.username,
                    "failed_attempts": self.failed_login_count,
                    "lockout_duration": "5 minutes"
                }
            )

        try:
            db.session.add(self)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error recording failed login: {str(e)}")

    def reset_failed_logins(self) -> None:
        """
        Reset failed login count after successful authentication.
        """
        if self.failed_login_count > 0 or self.locked_until is not None:
            self.failed_login_count = 0
            self.locked_until = None

            try:
                db.session.add(self)
                db.session.commit()
            except SQLAlchemyError as e:
                db.session.rollback()
                current_app.logger.error(f"Error resetting failed logins: {str(e)}")

    def is_locked(self) -> bool:
        """
        Check if the account is currently locked out.

        Returns:
            bool: True if account is locked, False otherwise
        """
        if not self.locked_until:
            return False

        # Check if lockout period has expired
        if self.locked_until <= datetime.now(timezone.utc):
            # Auto-unlock if lockout period passed
            self.locked_until = None

            try:
                db.session.add(self)
                db.session.commit()
            except SQLAlchemyError:
                db.session.rollback()
                # Don't fail the lock check if we can't update the database

            return False

        return True

    def get_lockout_message(self) -> Optional[str]:
        """
        Get appropriate lockout message with remaining time.

        Returns:
            Optional[str]: Lockout message with remaining time, or None if not locked
        """
        if not self.locked_until:
            return None

        now = datetime.now(timezone.utc)
        if self.locked_until <= now:
            return None

        time_diff = self.locked_until - now
        minutes = int(time_diff.total_seconds() / 60)

        if minutes > 60:
            return f"Account locked for security. Try again in {minutes // 60} hours and {minutes % 60} minutes."
        elif minutes > 0:
            return f"Account locked for security. Try again in {minutes} minutes."
        else:
            return f"Account locked for security. Try again in {int(time_diff.total_seconds())} seconds."

    def assign_role(self, role: 'Role') -> bool:
        """
        Assign a role to this user.

        Args:
            role: Role to assign

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            old_role_id = self.role_id
            old_role_name = self.role.name if self.role else "none"

            self.role = role
            db.session.commit()

            # Log role change event
            self.log_change(['role_id'], f"Role changed from {old_role_name} to {role.name}")

            # Log security event for role change
            log_security_event(
                event_type="role_assigned",
                description=f"Role '{role.name}' assigned to user {self.username}",
                severity="warning",
                details={
                    "user_id": self.id,
                    "username": self.username,
                    "old_role_id": old_role_id,
                    "new_role_id": role.id,
                    "new_role_name": role.name
                }
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error assigning role to user: {str(e)}")
            return False

    def has_permission(self, permission_name: str) -> bool:
        """
        Check if user has a specific permission through their assigned role.

        Args:
            permission_name: Name of permission to check

        Returns:
            bool: True if user has the permission, False otherwise
        """
        # Admin users have all permissions
        if self.is_admin:
            return True

        # Must have a role to have permissions
        if not self.role:
            return False

        # Check permission through role
        return self.role.has_permission_by_name(permission_name)

    def has_permission_with_context(self, permission_name: str, context: Dict[str, Any] = None) -> bool:
        """
        Check if user has a context-specific permission through their assigned role.

        Args:
            permission_name: Name of permission to check
            context: Contextual data for evaluating dynamic permission rules

        Returns:
            bool: True if user has the permission in this context, False otherwise
        """
        # Admin users have all permissions
        if self.is_admin:
            return True

        # Must have a role to have permissions
        if not self.role:
            return False

        # Check permission with context through role
        return self.role.has_permission_with_context(permission_name, context)

    def get_all_permissions(self) -> List[str]:
        """
        Get all permission names available to this user.

        Returns:
            List[str]: List of permission names
        """
        if not self.role:
            return []

        return self.role.get_permission_names()

    def generate_password_reset_token(self, expires_in_hours: int = 24) -> str:
        """
        Generate a password reset token.

        Args:
            expires_in_hours: Hours until token expires (default 24)

        Returns:
            str: Password reset token
        """
        token = uuid.uuid4().hex
        self.password_reset_token = token
        self.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)

        try:
            db.session.add(self)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error generating password reset token: {str(e)}")
            raise RuntimeError("Failed to save password reset token") from e

        return token

    def verify_password_reset_token(self, token: str) -> bool:
        """
        Verify a password reset token.

        Args:
            token: Token to verify

        Returns:
            bool: True if token is valid, False otherwise
        """
        if not self.password_reset_token or not self.password_reset_expires:
            return False

        if self.password_reset_token != token:
            return False

        if self.password_reset_expires < datetime.now(timezone.utc):
            return False

        return True

    def clear_password_reset_token(self) -> None:
        """Clear password reset token."""
        self.password_reset_token = None
        self.password_reset_expires = None

        try:
            db.session.add(self)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error clearing password reset token: {str(e)}")

    def should_change_password(self, max_age_days: int = 90) -> bool:
        """
        Check if user should change their password based on age.

        Args:
            max_age_days: Maximum password age in days

        Returns:
            bool: True if password should be changed, False otherwise
        """
        if not self.last_password_change:
            return True

        password_age = datetime.now(timezone.utc) - self.last_password_change
        return password_age.days >= max_age_days

    def set_active(self) -> bool:
        """
        Set user status to active.

        Returns:
            bool: True if successful, False otherwise
        """
        return self.set_status(self.STATUS_ACTIVE)

    def set_inactive(self) -> bool:
        """
        Set user status to inactive.

        Returns:
            bool: True if successful, False otherwise
        """
        return self.set_status(self.STATUS_INACTIVE)

    def set_suspended(self) -> bool:
        """
        Set user status to suspended.

        Returns:
            bool: True if successful, False otherwise
        """
        return self.set_status(self.STATUS_SUSPENDED)

    def set_status(self, status: str) -> bool:
        """
        Set user status.

        Args:
            status: New status (must be one of VALID_STATUSES)

        Returns:
            bool: True if successful, False otherwise

        Raises:
            ValueError: If status is invalid
        """
        if status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}")

        if self.status == status:
            return True  # Status already set

        try:
            old_status = self.status
            self.status = status
            db.session.commit()

            # Log status change event
            self.log_change(['status'], f"Status changed from {old_status} to {status}")

            # Log security event for status changes
            severity = "info"
            if status == self.STATUS_SUSPENDED:
                severity = "warning"

            log_security_event(
                event_type="user_status_changed",
                description=f"User {self.username} status changed to {status}",
                severity=severity,
                details={
                    "user_id": self.id,
                    "username": self.username,
                    "old_status": old_status,
                    "new_status": status
                }
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error setting user status: {str(e)}")
            return False

    @property
    def is_active(self) -> bool:
        """Check if user is active."""
        return self.status == self.STATUS_ACTIVE

    @property
    def is_admin(self) -> bool:
        """Check if user is admin."""
        if not self.role:
            return False
        return self.role.name.lower() == 'admin'

    @property
    def display_name(self) -> str:
        """Get user's display name (first + last if available, otherwise username)."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.username

    @classmethod
    def get_by_username(cls, username: str) -> Optional['User']:
        """
        Find user by username (case-insensitive).

        Args:
            username: Username to search for

        Returns:
            Optional[User]: User if found, None otherwise
        """
        if not username:
            return None
        return cls.query.filter(func.lower(cls.username) == func.lower(username)).first()

    @classmethod
    def get_by_email(cls, email: str) -> Optional['User']:
        """
        Find user by email (case-insensitive).

        Args:
            email: Email to search for

        Returns:
            Optional[User]: User if found, None otherwise
        """
        if not email:
            return None
        return cls.query.filter(func.lower(cls.email) == func.lower(email)).first()

    @classmethod
    def search(cls, query: str, include_inactive: bool = False,
              limit: int = 20) -> List['User']:
        """
        Search for users by username, email, or name.

        Args:
            query: Search term
            include_inactive: Whether to include inactive/suspended users
            limit: Maximum number of results to return

        Returns:
            List[User]: List of matching users
        """
        if not query or len(query) < 3:
            return []

        search_query = cls.query

        if not include_inactive:
            search_query = search_query.filter(cls.status == cls.STATUS_ACTIVE)

        search_pattern = f"%{query.lower()}%"
        return search_query.filter(
            or_(
                func.lower(cls.username).like(search_pattern),
                func.lower(cls.email).like(search_pattern),
                func.lower(cls.first_name).like(search_pattern),
                func.lower(cls.last_name).like(search_pattern)
            )
        ).order_by(cls.username).limit(limit).all()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert user to dictionary representation for API responses.

        Returns:
            Dict[str, Any]: Dictionary representation of user
        """
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'status': self.status,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'display_name': self.display_name,
            'bio': self.bio,
            'avatar_url': self.avatar_url,
            'role': self.role.name if self.role else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'two_factor_enabled': self.two_factor_enabled,
            'is_admin': self.is_admin,
            'is_active': self.is_active
        }

    def to_detailed_dict(self) -> Dict[str, Any]:
        """
        Convert user to detailed dictionary representation for admin views.

        Returns:
            Dict[str, Any]: Dictionary representation of user with additional details
        """
        basic_dict = self.to_dict()

        # Add permissions if we have a role
        if self.role:
            basic_dict['permissions'] = self.role.get_permission_names()
            basic_dict['role_id'] = self.role.id

        # Add additional administrative details
        basic_dict['login_count'] = self.login_count
        basic_dict['failed_login_count'] = self.failed_login_count
        basic_dict['last_failed_login'] = (self.last_failed_login.isoformat()
                                         if self.last_failed_login else None)
        basic_dict['locked_until'] = (self.locked_until.isoformat()
                                    if self.locked_until else None)
        basic_dict['is_locked'] = self.is_locked()
        basic_dict['last_password_change'] = (self.last_password_change.isoformat()
                                            if self.last_password_change else None)
        basic_dict['password_age_days'] = ((datetime.now(timezone.utc) - self.last_password_change).days
                                         if self.last_password_change else None)
        basic_dict['should_change_password'] = self.should_change_password()

        return basic_dict

    def __repr__(self) -> str:
        """String representation of the User object."""
        return f"<User {self.id}: {self.username}>"
