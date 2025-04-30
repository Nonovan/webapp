"""
MFA backup codes model for the Cloud Infrastructure Platform.

This module provides backup authentication codes functionality when users
cannot access their primary MFA method.
"""

from datetime import datetime, timezone
from typing import List, Optional
import secrets
import hashlib

from extensions import db
from models.base import BaseModel


class MFABackupCode(BaseModel):
    """
    Model for storing MFA backup codes.

    Users can generate a set of one-time use backup codes to authenticate
    when they cannot access their primary MFA device.
    """

    __tablename__ = 'mfa_backup_codes'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    code_hash = db.Column(db.String(128), nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)

    def __init__(self, user_id: int, code: str):
        """
        Initialize a new backup code.

        Args:
            user_id: ID of the user this backup code belongs to
            code: Plain text backup code to hash and store
        """
        self.user_id = user_id
        self.code_hash = self._hash_code(code)
        self.used = False

    @staticmethod
    def _hash_code(code: str) -> str:
        """Create a secure hash of the backup code."""
        return hashlib.sha256(code.encode()).hexdigest()

    def verify(self, code: str) -> bool:
        """
        Verify if the provided code matches this backup code.

        Args:
            code: Plain text code to verify

        Returns:
            bool: True if the code matches and hasn't been used yet
        """
        if self.used:
            return False

        return self._hash_code(code) == self.code_hash

    def mark_used(self) -> None:
        """Mark this backup code as used."""
        self.used = True
        self.used_at = datetime.now(timezone.utc)

    @classmethod
    def generate_codes(cls, user_id: int, count: int = 10) -> List[str]:
        """
        Generate a set of backup codes for a user.

        Args:
            user_id: User ID to generate codes for
            count: Number of codes to generate (default: 10)

        Returns:
            List[str]: List of plaintext backup codes
        """
        # Delete any existing unused backup codes for the user
        cls.query.filter_by(user_id=user_id, used=False).delete()

        codes = []
        for _ in range(count):
            # Generate a random code (e.g., "1234-5678")
            code = f"{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}"
            codes.append(code)

            # Store the hashed version in the database
            db.session.add(cls(user_id=user_id, code=code))

        db.session.commit()
        return codes

    @classmethod
    def verify_code(cls, user_id: int, code: str) -> bool:
        """
        Verify a backup code for a user and mark it as used if valid.

        Args:
            user_id: User ID to check the code for
            code: Backup code to verify

        Returns:
            bool: True if the code was valid and has been consumed
        """
        backup_code = cls.query.filter_by(
            user_id=user_id,
            code_hash=cls._hash_code(code),
            used=False
        ).first()

        if backup_code:
            backup_code.mark_used()
            db.session.commit()
            return True

        return False

    @classmethod
    def get_unused_count(cls, user_id: int) -> int:
        """
        Get count of remaining unused backup codes for a user.

        Args:
            user_id: User ID to check

        Returns:
            int: Number of unused backup codes
        """
        return cls.query.filter_by(user_id=user_id, used=False).count()
