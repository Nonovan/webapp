"""
OAuth provider model for the Cloud Infrastructure Platform.

This module manages external OAuth providers for single sign-on (SSO)
and federated identity management.
"""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from sqlalchemy.exc import SQLAlchemyError
from flask import current_app

from extensions import db
from models.base import BaseModel, AuditableMixin


class OAuthProvider(BaseModel, AuditableMixin):
    """
    OAuth provider configuration model.

    Stores configuration for external identity providers supporting OAuth/OIDC.
    """

    __tablename__ = 'oauth_providers'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['client_id', 'client_secret', 'is_enabled']

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    provider_type = db.Column(db.String(20), nullable=False)  # 'google', 'github', 'azure', etc.

    # Configuration settings
    client_id = db.Column(db.String(255), nullable=False)
    client_secret = db.Column(db.String(255), nullable=False)
    authorize_url = db.Column(db.String(512), nullable=True)
    token_url = db.Column(db.String(512), nullable=True)
    userinfo_url = db.Column(db.String(512), nullable=True)

    # Provider configuration
    scopes = db.Column(db.String(512), nullable=True)  # Comma-separated scopes
    is_enabled = db.Column(db.Boolean, default=True)
    config = db.Column(db.JSON, nullable=True)  # Additional provider-specific config

    # User mapping settings
    username_path = db.Column(db.String(100), nullable=True, default='email')  # JSON path to username field
    email_path = db.Column(db.String(100), nullable=True, default='email')  # JSON path to email field
    name_path = db.Column(db.String(100), nullable=True, default='name')  # JSON path to name field

    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                         onupdate=lambda: datetime.now(timezone.utc))

    # Relationship to user connections
    connections = db.relationship('OAuthConnection', back_populates='provider',
                              cascade='all, delete-orphan')

    def __init__(self, name: str, provider_type: str, client_id: str, client_secret: str,
                 authorize_url: Optional[str] = None, token_url: Optional[str] = None,
                 userinfo_url: Optional[str] = None, scopes: Optional[str] = None,
                 config: Optional[Dict] = None):
        """
        Initialize a new OAuth provider.

        Args:
            name: Display name for the provider
            provider_type: Type identifier (e.g., 'google', 'github')
            client_id: OAuth client ID
            client_secret: OAuth client secret
            authorize_url: Authorization endpoint URL (optional)
            token_url: Token endpoint URL (optional)
            userinfo_url: User info endpoint URL (optional)
            scopes: Comma-separated scopes to request (optional)
            config: Additional provider configuration (optional)
        """
        self.name = name
        self.provider_type = provider_type
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorize_url = authorize_url
        self.token_url = token_url
        self.userinfo_url = userinfo_url
        self.scopes = scopes
        self.config = config or {}

        # Set default endpoints based on provider_type if not specified
        if self.provider_type == 'google' and not all([authorize_url, token_url, userinfo_url]):
            self.authorize_url = self.authorize_url or 'https://accounts.google.com/o/oauth2/auth'
            self.token_url = self.token_url or 'https://oauth2.googleapis.com/token'
            self.userinfo_url = self.userinfo_url or 'https://openidconnect.googleapis.com/v1/userinfo'
            self.scopes = self.scopes or 'openid,email,profile'
        elif self.provider_type == 'github' and not all([authorize_url, token_url, userinfo_url]):
            self.authorize_url = self.authorize_url or 'https://github.com/login/oauth/authorize'
            self.token_url = self.token_url or 'https://github.com/login/oauth/access_token'
            self.userinfo_url = self.userinfo_url or 'https://api.github.com/user'
            self.scopes = self.scopes or 'read:user,user:email'

    def to_dict(self, include_secret: bool = False) -> Dict[str, Any]:
        """
        Convert provider to dictionary representation.

        Args:
            include_secret: Whether to include the client secret

        Returns:
            Dict: Provider data as dictionary
        """
        result = {
            'id': self.id,
            'name': self.name,
            'provider_type': self.provider_type,
            'client_id': self.client_id,
            'authorize_url': self.authorize_url,
            'token_url': self.token_url,
            'userinfo_url': self.userinfo_url,
            'scopes': self.scopes,
            'is_enabled': self.is_enabled,
            'username_path': self.username_path,
            'email_path': self.email_path,
            'name_path': self.name_path,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }

        if include_secret:
            result['client_secret'] = self.client_secret

        return result

    @classmethod
    def get_enabled_providers(cls) -> List['OAuthProvider']:
        """Get all enabled OAuth providers."""
        return cls.query.filter_by(is_enabled=True).all()

    @classmethod
    def get_by_type(cls, provider_type: str) -> Optional['OAuthProvider']:
        """Get provider by type."""
        return cls.query.filter_by(provider_type=provider_type, is_enabled=True).first()


class OAuthConnection(BaseModel):
    """
    OAuth connection between a user and an external identity provider.

    Stores user identities from external OAuth providers.
    """

    __tablename__ = 'oauth_connections'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                      nullable=False, index=True)
    provider_id = db.Column(db.Integer, db.ForeignKey('oauth_providers.id', ondelete='CASCADE'),
                         nullable=False)

    # External account information
    provider_user_id = db.Column(db.String(255), nullable=False)  # User ID at the provider
    provider_username = db.Column(db.String(255), nullable=True)  # Username at the provider
    provider_email = db.Column(db.String(255), nullable=True)  # Email at the provider

    # OAuth tokens
    access_token = db.Column(db.String(2048), nullable=True)
    refresh_token = db.Column(db.String(2048), nullable=True)
    token_expiry = db.Column(db.DateTime(timezone=True), nullable=True)

    # Other metadata
    profile_data = db.Column(db.JSON, nullable=True)  # Full profile data from provider
    last_used = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    user = db.relationship('User')
    provider = db.relationship('OAuthProvider', back_populates='connections')

    __table_args__ = (
        db.UniqueConstraint('provider_id', 'provider_user_id', name='uix_oauth_connection_provider_id'),
    )

    def __init__(self, user_id: int, provider_id: int, provider_user_id: str,
                 provider_username: Optional[str] = None, provider_email: Optional[str] = None,
                 access_token: Optional[str] = None, refresh_token: Optional[str] = None,
                 token_expiry: Optional[datetime] = None, profile_data: Optional[Dict] = None):
        """
        Initialize a new OAuth connection.

        Args:
            user_id: ID of the user
            provider_id: ID of the OAuth provider
            provider_user_id: User ID at the OAuth provider
            provider_username: Username at the provider (optional)
            provider_email: Email at the provider (optional)
            access_token: OAuth access token (optional)
            refresh_token: OAuth refresh token (optional)
            token_expiry: Token expiration timestamp (optional)
            profile_data: Full profile data from the provider (optional)
        """
        self.user_id = user_id
        self.provider_id = provider_id
        self.provider_user_id = provider_user_id
        self.provider_username = provider_username
        self.provider_email = provider_email
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_expiry = token_expiry
        self.profile_data = profile_data
        self.last_used = datetime.now(timezone.utc)

    def update_tokens(self, access_token: str, refresh_token: Optional[str] = None,
                     expiry: Optional[datetime] = None) -> None:
        """
        Update OAuth tokens for this connection.

        Args:
            access_token: New access token
            refresh_token: New refresh token (optional)
            expiry: New expiration timestamp (optional)
        """
        self.access_token = access_token
        if refresh_token:
            self.refresh_token = refresh_token
        if expiry:
            self.token_expiry = expiry

        self.last_used = datetime.now(timezone.utc)

        try:
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Failed to update OAuth tokens: {str(e)}")

    @classmethod
    def get_by_provider_user_id(cls, provider_id: int, provider_user_id: str) -> Optional['OAuthConnection']:
        """
        Find a connection by provider ID and provider-specific user ID.

        Args:
            provider_id: ID of the OAuth provider
            provider_user_id: User ID at the provider

        Returns:
            Optional[OAuthConnection]: Connection if found, None otherwise
        """
        return cls.query.filter_by(
            provider_id=provider_id,
            provider_user_id=provider_user_id
        ).first()

    @classmethod
    def get_by_user_id(cls, user_id: int) -> List['OAuthConnection']:
        """
        Find all OAuth connections for a specific user.

        Args:
            user_id: User ID to look up

        Returns:
            List[OAuthConnection]: List of all OAuth connections for the user
        """
        return cls.query.filter_by(user_id=user_id).all()

    @classmethod
    def get_by_user_and_provider(cls, user_id: int, provider_id: int) -> Optional['OAuthConnection']:
        """
        Find a connection by user ID and provider ID.

        Args:
            user_id: ID of the user
            provider_id: ID of the OAuth provider

        Returns:
            Optional[OAuthConnection]: Connection if found, None otherwise
        """
        return cls.query.filter_by(
            user_id=user_id,
            provider_id=provider_id
        ).first()

    def is_token_expired(self) -> bool:
        """
        Check if the OAuth access token has expired.

        Returns:
            bool: True if token is expired or expiry is unknown, False otherwise
        """
        if not self.token_expiry:
            return True

        now = datetime.now(timezone.utc)
        return now >= self.token_expiry

    def to_dict(self, include_tokens: bool = False) -> Dict[str, Any]:
        """
        Convert connection to dictionary representation.

        Args:
            include_tokens: Whether to include access and refresh tokens

        Returns:
            Dict: Connection data as dictionary
        """
        result = {
            'id': self.id,
            'user_id': self.user_id,
            'provider_id': self.provider_id,
            'provider_user_id': self.provider_user_id,
            'provider_username': self.provider_username,
            'provider_email': self.provider_email,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'token_expiry': self.token_expiry.isoformat() if self.token_expiry else None,
            'has_refresh_token': bool(self.refresh_token)
        }

        if include_tokens:
            result['access_token'] = self.access_token
            result['refresh_token'] = self.refresh_token

        return result
