"""
User model module for authentication and authorization in myproject.

This module defines the User model which serves as the foundation for the application's
authentication and authorization system. It provides robust functionality for:

- Secure password management with hashing and verification
- Role-based access control (user, admin, operator roles)
- JWT token generation and validation for API authentication
- Two-factor authentication support
- Account status management (pending, active, inactive, suspended)
- User profile information storage
- Login tracking and security monitoring
- Password reset capabilities

The User model implements security best practices including proper password hashing,
token expiration, and protection against common authentication vulnerabilities.
It serves as the central component for user identity and access management throughout
the application.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
import uuid
import jwt
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db

class User(db.Model):
    """User model with authentication and authorization."""
    __tablename__ = 'users'

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    # Role and status
    role = db.Column(db.String(20), default='user')
    status = db.Column(db.String(20), default='pending')

    # Profile fields
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    bio = db.Column(db.Text)
    avatar_url = db.Column(db.String(255))

    # Security
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32))

    # Activity tracking
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())
    last_login = db.Column(db.DateTime)
    login_count = db.Column(db.Integer, default=0)
    failed_login_count = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime(timezone=True))
    locked_until = db.Column(db.DateTime(timezone=True))

    # Constants
    STATUS_PENDING = 'pending'
    STATUS_ACTIVE = 'active'
    STATUS_INACTIVE = 'inactive'
    STATUS_SUSPENDED = 'suspended'
    VALID_ROLES = ['user', 'admin', 'operator']

    def set_password(self, password: str) -> None:
        """Set password with validation."""
        self.password = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify password."""
        return check_password_hash(self.password, password)

    def generate_token(self, expires_in: int = 3600) -> str:
        """Generate JWT token with expiry.

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

            token = jwt.encode(
                {
                    'user_id': self.id,
                    'role': self.role,
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
        """Verify JWT token."""
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
        """Update login tracking."""
        self.last_login = datetime.utcnow()
        self.login_count += 1
        db.session.commit()

    def record_failed_login(self) -> None:
        """Record a failed login attempt and apply lockout if needed."""
        self.failed_login_count += 1
        self.last_failed_login = datetime.now(timezone.utc)

        # Progressive lockout strategy
        if self.failed_login_count >= 10:
            # Extended lockout (1 hour) after 10 failed attempts
            self.locked_until = datetime.now(timezone.utc) + timedelta(hours=1)
        elif self.failed_login_count >= 5:
            # Medium lockout (15 minutes) after 5 failed attempts
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        elif self.failed_login_count >= 3:
            # Short lockout (5 minutes) after 3 failed attempts
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=5)

        db.session.add(self)

    def reset_failed_logins(self) -> None:
        """Reset failed login count after successful authentication."""
        self.failed_login_count = 0
        self.locked_until = None
        db.session.add(self)

    def is_locked(self) -> bool:
        """Check if the account is currently locked out."""
        if not self.locked_until:
            return False

        # Check if lockout period has expired
        if self.locked_until <= datetime.now(timezone.utc):
            # Auto-unlock if lockout period passed
            self.locked_until = None
            return False

        return True

    def get_lockout_message(self) -> Optional[str]:
        """Get appropriate lockout message with remaining time."""
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

    @property
    def is_admin(self) -> bool:
        """Check if user is admin."""
        return self.role == 'admin'

    def __repr__(self) -> str:
        return f'<User {self.username}>'
