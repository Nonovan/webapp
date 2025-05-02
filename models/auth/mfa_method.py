"""
Multi-Factor Authentication model for the Cloud Infrastructure Platform.

This module defines the MFA model which handles multiple authentication factors
including TOTP, and backup codes. It separates MFA data from
the User table for better security and more flexible authentication options.
"""
from datetime import datetime, timezone, timedelta
import base64
import hmac
import hashlib
import os
import json
import pyotp
from typing import List, Dict, Any, Optional, Tuple, Set, Union
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import relationship, validates

from extensions import db
from admin.utils import encrypt_data, decrypt_data
from core.security.cs_audit import log_security_event
from models.base import BaseModel, AuditableMixin

class MFAMethod(BaseModel, AuditableMixin):
    """Model for storing user multi-factor authentication methods."""

    __tablename__ = 'mfa_methods'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['is_active', 'verified', 'method_type', 'encrypted_secret']

    # Constants for method types
    TYPE_TOTP = 'totp'
    TYPE_BACKUP_CODES = 'backup_codes'
    TYPE_EMAIL = 'email'
    TYPE_SMS = 'sms'

    VALID_TYPES = [TYPE_TOTP, TYPE_BACKUP_CODES, TYPE_EMAIL, TYPE_SMS]

    # Primary key
    id = db.Column(db.Integer, primary_key=True)

    # Relationship to user
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                         nullable=False, index=True)

    # MFA properties
    method_type = db.Column(db.String(20), nullable=False)
    encrypted_secret = db.Column(db.Text, nullable=True)
    name = db.Column(db.String(64), nullable=True)  # User-defined name for this method
    is_primary = db.Column(db.Boolean, default=False)  # Whether this is the primary MFA method
    is_active = db.Column(db.Boolean, default=True)
    verified = db.Column(db.Boolean, default=False)

    # For backup codes
    backup_codes = db.Column(MutableDict.as_mutable(db.JSON), nullable=True)

    # Metadata
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True),
                           default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))
    last_used_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Relationships
    user = relationship('User', backref=db.backref('mfa_methods', lazy='dynamic', cascade='all, delete-orphan'))

    def __init__(self, user_id: int, method_type: str, **kwargs):
        if method_type not in self.VALID_TYPES:
            raise ValueError(f"Invalid MFA method type: {method_type}")

        self.user_id = user_id
        self.method_type = method_type

        # Set additional attributes passed as kwargs
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def set_secret(self, secret: str) -> None:
        """Encrypt and store the MFA secret."""
        self.encrypted_secret = encrypt_data(secret)

    def get_secret(self) -> str:
        """Decrypt and return the MFA secret."""
        if not self.encrypted_secret:
            return None
        return decrypt_data(self.encrypted_secret)

    def verify_totp(self, token: str) -> bool:
        """Verify a TOTP token."""
        if self.method_type != self.TYPE_TOTP or not self.is_active:
            return False

        # Get the secret
        secret = self.get_secret()
        if not secret:
            return False

        # Verify the token
        totp = pyotp.TOTP(secret)
        result = totp.verify(token)

        if result:
            self.last_used_at = datetime.now(timezone.utc)
            db.session.commit()

        return result

    def verify_backup_code(self, code: str) -> bool:
        """Verify and consume a backup code."""
        if self.method_type != self.TYPE_BACKUP_CODES or not self.is_active:
            return False

        codes_data = self.backup_codes or {}
        codes = codes_data.get('codes', [])

        # Check if the code exists and is unused
        for i, code_dict in enumerate(codes):
            if code_dict.get('code') == code and not code_dict.get('used'):
                # Mark code as used
                codes[i]['used'] = True
                codes[i]['used_at'] = datetime.now(timezone.utc).isoformat()
                self.backup_codes = {'codes': codes}
                self.last_used_at = datetime.now(timezone.utc)
                db.session.commit()

                # Log backup code usage
                log_security_event(
                    'mfa_backup_code_used',
                    f"Backup code used for user {self.user_id}",
                    user_id=self.user_id,
                    severity="warning"
                )

                return True

        return False

    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Generate a set of backup codes."""
        if self.method_type != self.TYPE_BACKUP_CODES:
            raise ValueError("This MFA method does not support backup codes")

        codes = []
        for _ in range(count):
            # Generate a 10-character alphanumeric code
            code = base64.b32encode(os.urandom(5)).decode('utf-8').replace('=', '').lower()
            codes.append({
                'code': code,
                'used': False,
                'created_at': datetime.now(timezone.utc).isoformat()
            })

        self.backup_codes = {'codes': codes}
        self.is_active = True
        self.verified = True

        return [code_dict['code'] for code_dict in codes]

    def setup_totp(self, name: str = None, issuer: str = "Cloud Infrastructure Platform") -> Dict[str, str]:
        """Set up a new TOTP method and return the secret and URI."""
        if self.method_type != self.TYPE_TOTP:
            raise ValueError("This MFA method is not TOTP")

        # Generate a new TOTP secret
        secret = pyotp.random_base32()
        self.set_secret(secret)

        # Set the name if provided
        if name:
            self.name = name

        # Get the provisioning URI
        username = self.user.username if hasattr(self.user, 'username') else f"user_{self.user_id}"
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(username, issuer_name=issuer)

        return {
            'secret': secret,
            'uri': uri,
            'issuer': issuer,
            'name': self.name or username
        }


    @validates('is_primary')
    def validate_is_primary(self, key, is_primary):
        """Ensure only one method is primary."""
        if is_primary:
            # If setting this method to primary, set all others to non-primary
            if self.id is not None:  # Only if the record exists
                MFAMethod.query.filter(
                    MFAMethod.user_id == self.user_id,
                    MFAMethod.id != self.id
                ).update({'is_primary': False})
        return is_primary

    @classmethod
    def get_active_methods_for_user(cls, user_id: int) -> List['MFAMethod']:
        """Get all active MFA methods for a user."""
        return cls.query.filter(
            cls.user_id == user_id,
            cls.is_active == True,
            cls.verified == True
        ).all()

    @classmethod
    def has_active_mfa(cls, user_id: int) -> bool:
        """Check if a user has any active MFA methods."""
        return cls.query.filter(
            cls.user_id == user_id,
            cls.is_active == True,
            cls.verified == True
        ).count() > 0
