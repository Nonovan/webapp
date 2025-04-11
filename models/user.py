from datetime import datetime, timedelta
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
    last_failed_login = db.Column(db.DateTime)

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
        """Record failed login attempt."""
        self.failed_login_count += 1
        self.last_failed_login = datetime.utcnow()
        db.session.commit()

    @property
    def is_admin(self) -> bool:
        """Check if user is admin."""
        return self.role == 'admin'

    def __repr__(self) -> str:
        return f'<User {self.username}>'
