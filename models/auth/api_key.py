"""
API key management model for the Cloud Infrastructure Platform.

This module provides models for creating, managing, and validating API keys
used for programmatic access to the application APIs.
"""

import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple, Union
from flask import current_app, request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func

from extensions import db, redis_client, metrics
from models.base import BaseModel, AuditableMixin
from core.security.cs_audit import log_security_event

class APIKey(BaseModel, AuditableMixin):
    """
    API key model for programmatic authentication.

    Note that API keys are stored using a secure hash, not in plaintext.
    The actual key is only shown once when created.
    """

    __tablename__ = 'api_keys'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['key_hash', 'is_active', 'scopes']

    # Status constants
    STATUS_ACTIVE = 'active'
    STATUS_EXPIRED = 'expired'
    STATUS_REVOKED = 'revoked'
    STATUS_SUSPENDED = 'suspended'

    # Rate limit constants
    RATE_LIMIT_WINDOW_SECONDS = 60
    DEFAULT_RATE_LIMIT = 100  # Requests per minute

    # Prefix for identifying API keys with version
    KEY_PREFIX = "cip-key-v1-"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                      nullable=False, index=True)
    key_hash = db.Column(db.String(128), nullable=False, unique=True, index=True)
    scopes = db.Column(db.JSON, nullable=False, default=list)  # List of permission scopes
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    status = db.Column(db.String(20), default=STATUS_ACTIVE, nullable=False, index=True)

    # Usage restrictions
    allowed_ips = db.Column(db.JSON, nullable=True)  # List of IPs or CIDR ranges
    allowed_referers = db.Column(db.JSON, nullable=True)  # List of allowed referer domains
    rate_limit = db.Column(db.Integer, default=DEFAULT_RATE_LIMIT)  # Requests per minute

    # Expiration
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Last usage and stats
    last_used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_ip = db.Column(db.String(45), nullable=True)  # Last IP that used this key
    usage_count = db.Column(db.Integer, default=0, nullable=False)

    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                         nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                         onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Relations
    user = db.relationship('User', backref=db.backref('api_keys', lazy='dynamic',
                                                    cascade='all, delete-orphan'))

    def __init__(self, name: str, user_id: int, scopes: List[str],
                expires_at: Optional[datetime] = None, allowed_ips: Optional[List[str]] = None,
                allowed_referers: Optional[List[str]] = None,
                rate_limit: int = DEFAULT_RATE_LIMIT):
        """Initialize a new API key, generating a secure random key."""
        self.name = name
        self.user_id = user_id
        self.scopes = scopes or []
        self.expires_at = expires_at
        self.allowed_ips = allowed_ips
        self.allowed_referers = allowed_referers
        self.rate_limit = rate_limit

        # The actual key (only available during creation)
        raw_key = self._generate_key()

        # Store only the hash
        self.key_hash = self._hash_key(raw_key)

        # Save the raw key to return it to the caller
        self._raw_key = raw_key

    def _generate_key(self) -> str:
        """Generate a secure random API key with prefix."""
        # 32 bytes = 256 bits of entropy, encoded as hex = 64 chars
        random_part = secrets.token_hex(32)
        return f"{self.KEY_PREFIX}{random_part}"

    @staticmethod
    def _hash_key(key: str) -> str:
        """Hash an API key for secure storage."""
        return hashlib.sha256(key.encode()).hexdigest()

    def verify_key(self, key: str) -> bool:
        """Verify if a provided key matches this API key."""
        return self.key_hash == self._hash_key(key)

    def get_raw_key(self) -> Optional[str]:
        """
        Get the raw API key. Only available immediately after creation.

        Returns:
            Optional[str]: The raw API key or None if not available
        """
        return getattr(self, '_raw_key', None)

    def is_expired(self) -> bool:
        """Check if the API key is expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) >= self.expires_at

    def is_valid(self) -> bool:
        """Check if the API key is valid (active and not expired)."""
        return self.is_active and self.status == self.STATUS_ACTIVE and not self.is_expired()

    def has_scope(self, scope: str) -> bool:
        """
        Check if the API key has a specific scope.

        Args:
            scope: Permission scope to check

        Returns:
            bool: True if the key has the scope
        """
        if not self.scopes:
            return False

        # Check for direct match
        if scope in self.scopes:
            return True

        # Check for wildcard scopes (e.g., "resource:*")
        parts = scope.split(':')
        if len(parts) == 2:
            resource, action = parts
            wildcard_scope = f"{resource}:*"
            return wildcard_scope in self.scopes

        return False

    def validate_request(self, request_ip: str,
                       referer: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Validate if a request can use this API key based on restrictions.

        Args:
            request_ip: IP address of the request
            referer: HTTP referer header (optional)

        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_reason)
        """
        # Check if key is active
        if not self.is_valid():
            if self.is_expired():
                return False, "API key has expired"
            elif self.status == self.STATUS_REVOKED:
                return False, "API key has been revoked"
            elif self.status == self.STATUS_SUSPENDED:
                return False, "API key is suspended"
            else:
                return False, "API key is not active"

        # Check IP restrictions if configured
        if self.allowed_ips and request_ip not in self.allowed_ips:
            # TODO: Implement proper CIDR range checking
            return False, "IP address not allowed for this API key"

        # Check referer restrictions if configured
        if self.allowed_referers and referer:
            referer_matched = False
            for allowed_referer in self.allowed_referers:
                if allowed_referer in referer:
                    referer_matched = True
                    break

            if not referer_matched:
                return False, "Referer not allowed for this API key"

        # Check rate limit
        is_rate_limited, ttl = self.is_rate_limited(request_ip)
        if is_rate_limited:
            return False, f"Rate limit exceeded, retry after {ttl} seconds"

        return True, None

    def record_usage(self, ip_address: Optional[str] = None) -> bool:
        """
        Record usage of this API key.

        Args:
            ip_address: IP address that used the key

        Returns:
            bool: True if the usage was recorded successfully
        """
        try:
            self.last_used_at = datetime.now(timezone.utc)
            self.usage_count += 1
            if ip_address:
                self.last_ip = ip_address

            db.session.add(self)
            db.session.commit()

            # Update rate limiter
            self._increment_rate_counter(ip_address)

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to record API key usage: {str(e)}")
            return False

    def is_rate_limited(self, ip_address: Optional[str] = None) -> Tuple[bool, int]:
        """
        Check if requests with this API key are currently rate limited.

        Args:
            ip_address: IP address to check (optional)

        Returns:
            Tuple[bool, int]: (is_limited, retry_after_seconds)
        """
        if not redis_client:
            return False, 0

        # Key for tracking requests
        rate_key = f"api:ratelimit:{self.id}"
        if ip_address:
            rate_key = f"{rate_key}:{ip_address}"

        # Get current count
        count = redis_client.get(rate_key)

        # If no count or below limit, not rate limited
        if not count or int(count) < self.rate_limit:
            return False, 0

        # Rate limited, calculate retry-after time
        ttl = redis_client.ttl(rate_key)
        return True, max(1, ttl)

    def _increment_rate_counter(self, ip_address: Optional[str] = None) -> None:
        """Increment rate limiting counter in Redis."""
        if not redis_client:
            return

        # Key for tracking requests
        rate_key = f"api:ratelimit:{self.id}"
        if ip_address:
            rate_key = f"{rate_key}:{ip_address}"

        # Increment counter
        count = redis_client.incr(rate_key)

        # Set expiry if first request in window
        if int(count) == 1:
            redis_client.expire(rate_key, self.RATE_LIMIT_WINDOW_SECONDS)

    def revoke(self) -> bool:
        """
        Revoke this API key permanently.

        Returns:
            bool: True if the key was revoked successfully
        """
        try:
            self.is_active = False
            self.status = self.STATUS_REVOKED
            self.revoked_at = datetime.now(timezone.utc)

            db.session.add(self)
            db.session.commit()

            # Log security event
            from core.security_utils import log_security_event
            log_security_event(
                'api_key_revoked',
                f"API key revoked: {self.name} (ID: {self.id})",
                user_id=self.user_id,
                severity="info"
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to revoke API key: {str(e)}")
            return False

    def suspend(self) -> bool:
        """
        Temporarily suspend this API key.

        Returns:
            bool: True if the key was suspended successfully
        """
        try:
            self.status = self.STATUS_SUSPENDED

            db.session.add(self)
            db.session.commit()

            # Log security event
            from core.security_utils import log_security_event
            log_security_event(
                'api_key_suspended',
                f"API key suspended: {self.name} (ID: {self.id})",
                user_id=self.user_id,
                severity="info"
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to suspend API key: {str(e)}")
            return False

    def activate(self) -> bool:
        """
        Activate a suspended API key.

        Returns:
            bool: True if the key was activated successfully
        """
        if self.status == self.STATUS_REVOKED:
            return False  # Can't activate a revoked key

        try:
            self.is_active = True
            self.status = self.STATUS_ACTIVE

            db.session.add(self)
            db.session.commit()

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to activate API key: {str(e)}")
            return False

    @classmethod
    def find_by_key(cls, api_key: str) -> Optional['APIKey']:
        """
        Find an API key by the raw key value.

        Args:
            api_key: The raw API key to look up

        Returns:
            Optional[APIKey]: The API key if found, None otherwise
        """
        if not api_key.startswith(cls.KEY_PREFIX):
            return None

        key_hash = cls._hash_key(api_key)
        return cls.query.filter_by(key_hash=key_hash).first()

    @classmethod
    def get_active_keys_for_user(cls, user_id: int) -> List['APIKey']:
        """Get all active API keys for a user."""
        return cls.query.filter_by(
            user_id=user_id,
            is_active=True,
            status=cls.STATUS_ACTIVE
        ).all()

    def to_dict(self, include_hash: bool = False) -> Dict[str, Any]:
        """
        Convert API key to dictionary representation.

        Args:
            include_hash: Whether to include the key hash (for admin purposes)

        Returns:
            Dict: API key data as dictionary
        """
        result = {
            'id': self.id,
            'name': self.name,
            'user_id': self.user_id,
            'scopes': self.scopes,
            'is_active': self.is_active,
            'status': self.status,
            'allowed_ips': self.allowed_ips,
            'allowed_referers': self.allowed_referers,
            'rate_limit': self.rate_limit,
            'usage_count': self.usage_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None,
            'last_ip': self.last_ip
        }

        if include_hash:
            result['key_hash'] = self.key_hash

        return result

    @classmethod
    def cleanup_expired(cls) -> Tuple[int, int]:
        """
        Update status for expired API keys.

        Returns:
            Tuple[int, int]: (total_updated, error_count)
        """
        try:
            now = datetime.now(timezone.utc)
            expired = cls.query.filter(
                cls.expires_at <= now,
                cls.status != cls.STATUS_EXPIRED,
                cls.status != cls.STATUS_REVOKED
            ).all()

            updated = 0
            errors = 0

            for key in expired:
                key.status = cls.STATUS_EXPIRED
                try:
                    db.session.add(key)
                    db.session.commit()
                    updated += 1
                except SQLAlchemyError:
                    db.session.rollback()
                    errors += 1

            return updated, errors

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to cleanup expired API keys: {str(e)}")
            return 0, 1
