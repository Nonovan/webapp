"""
Time-Based One-Time Password (TOTP) implementation for Multi-Factor Authentication.

This module provides a dedicated model for managing TOTP-based authentication
following RFC 6238. It handles secret generation, QR code creation, and
code verification with appropriate security controls and audit logging.

The module works alongside other MFA components to provide a comprehensive
multi-factor authentication system for the Cloud Infrastructure Platform.
"""

import base64
import hashlib
import hmac
import logging
import os
import re
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Union, Any, cast

import pyotp
import qrcode
from io import BytesIO
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app, has_request_context, request, g
from werkzeug.security import constant_time_compare

from extensions import db
from models.base import BaseModel, AuditableMixin
from core.security.cs_audit import log_security_event


class MFATotp(BaseModel, AuditableMixin):
    """
    Model for TOTP-based multi-factor authentication.

    This model handles the storage and verification of TOTP secrets and
    provides methods for generating and validating one-time passwords.
    """
    __tablename__ = 'mfa_totp'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['secret', 'is_active', 'last_used_at']

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                       nullable=False, index=True)
    secret = db.Column(db.String(64), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Tracking fields
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                         nullable=False)
    last_used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    setup_completed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Configuration
    digits = db.Column(db.Integer, default=6, nullable=False)
    interval = db.Column(db.Integer, default=30, nullable=False)
    algorithm = db.Column(db.String(16), default='sha1', nullable=False)

    # Window size for verification (number of time steps to check on each side)
    window = db.Column(db.Integer, default=1, nullable=False)

    # Additional information
    device_name = db.Column(db.String(255), nullable=True)

    # Relationships
    user = db.relationship('User', backref=db.backref('totp_devices', lazy='dynamic'))

    # Constants for algorithms
    ALG_SHA1 = 'sha1'
    ALG_SHA256 = 'sha256'
    ALG_SHA512 = 'sha512'

    VALID_ALGORITHMS = [ALG_SHA1, ALG_SHA256, ALG_SHA512]
    DEFAULT_DIGITS = 6
    DEFAULT_INTERVAL = 30
    DEFAULT_ALGORITHM = ALG_SHA1
    DEFAULT_WINDOW = 1

    def __init__(self, user_id: int, secret: Optional[str] = None, digits: int = DEFAULT_DIGITS,
                interval: int = DEFAULT_INTERVAL, algorithm: str = DEFAULT_ALGORITHM,
                device_name: Optional[str] = None) -> None:
        """
        Initialize a new TOTP device.

        Args:
            user_id: The user ID this TOTP device belongs to
            secret: The TOTP secret (generated if None)
            digits: Number of digits in the TOTP code
            interval: Time interval in seconds for TOTP codes
            algorithm: Hash algorithm (sha1, sha256, sha512)
            device_name: Optional descriptive name for this TOTP device
        """
        self.user_id = user_id

        # Validate and set parameters
        if algorithm not in self.VALID_ALGORITHMS:
            raise ValueError(f"Invalid algorithm: {algorithm}. Must be one of: {', '.join(self.VALID_ALGORITHMS)}")

        if digits not in [6, 8]:
            raise ValueError("Digits must be either 6 or 8")

        if not (10 <= interval <= 120):
            raise ValueError("Interval must be between 10 and 120 seconds")

        # Generate a secure random secret if not provided
        if secret is None:
            secret = pyotp.random_base32()

        self.secret = secret
        self.digits = digits
        self.interval = interval
        self.algorithm = algorithm
        self.device_name = device_name

    def get_totp(self) -> pyotp.TOTP:
        """
        Get a TOTP object for code generation and verification.

        Returns:
            pyotp.TOTP: Configured TOTP object
        """
        return pyotp.TOTP(
            self.secret,
            digits=self.digits,
            interval=self.interval,
            digest=self._get_digest_method()
        )

    def _get_digest_method(self):
        """Get the appropriate hashlib digest method for the algorithm."""
        if self.algorithm == self.ALG_SHA1:
            return 'sha1'
        elif self.algorithm == self.ALG_SHA256:
            return 'sha256'
        elif self.algorithm == self.ALG_SHA512:
            return 'sha512'
        return 'sha1'  # Default

    def verify_code(self, code: str) -> bool:
        """
        Verify a TOTP code against this device.

        Args:
            code: The TOTP code to verify

        Returns:
            bool: True if code is valid, False otherwise
        """
        # Basic validation
        if not code or not re.match(r'^\d{' + str(self.digits) + '}$', code):
            return False

        # Skip verification if device is not active
        if not self.is_active:
            return False

        try:
            # Verify the code with configured window
            totp = self.get_totp()
            is_valid = totp.verify(code, valid_window=self.window)

            if is_valid:
                # Update last used timestamp
                self.last_used_at = datetime.now(timezone.utc)
                db.session.commit()

                # Log successful verification
                self._log_verification(True)

                return True
            else:
                # Log failed verification
                self._log_verification(False)
                return False

        except Exception as e:
            logger = current_app.logger if current_app else logging.getLogger(__name__)
            logger.error(f"TOTP verification error: {str(e)}")
            return False

    def generate_current_code(self) -> str:
        """
        Generate the current TOTP code.

        This should only be used for testing/debugging purposes.

        Returns:
            str: Current TOTP code
        """
        return self.get_totp().now()

    def get_provisioning_uri(self, username: str, issuer: Optional[str] = None) -> str:
        """
        Get the provisioning URI for QR code generation.

        Args:
            username: Username to include in the URI
            issuer: Name of the issuer (app name)

        Returns:
            str: Provisioning URI for QR code generation
        """
        issuer = issuer or (current_app.config.get('APP_NAME') if has_request_context() else "CloudPlatform")
        return self.get_totp().provisioning_uri(username, issuer_name=issuer)

    def generate_qr_code(self, username: str, issuer: Optional[str] = None) -> BytesIO:
        """
        Generate a QR code image for TOTP setup.

        Args:
            username: Username to include in the URI
            issuer: Name of the issuer (app name)

        Returns:
            BytesIO: QR code image data
        """
        uri = self.get_provisioning_uri(username, issuer)

        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to BytesIO
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)

        return img_io

    def complete_setup(self) -> bool:
        """
        Mark this TOTP device as fully set up.

        Returns:
            bool: True if successful
        """
        try:
            self.setup_completed_at = datetime.now(timezone.utc)
            db.session.commit()

            # Log completion of setup
            log_security_event(
                event_type="mfa_totp_setup_completed",
                description=f"TOTP setup completed for user {self.user_id}",
                severity="info",
                user_id=self.user_id,
                details={
                    "device_id": self.id,
                    "device_name": self.device_name
                }
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            logger = current_app.logger if current_app else logging.getLogger(__name__)
            logger.error(f"Error completing TOTP setup: {str(e)}")
            return False

    def deactivate(self) -> bool:
        """
        Deactivate this TOTP device.

        Returns:
            bool: True if successful
        """
        try:
            self.is_active = False
            db.session.commit()

            # Log deactivation
            log_security_event(
                event_type="mfa_totp_deactivated",
                description=f"TOTP device deactivated for user {self.user_id}",
                severity="warning",
                user_id=self.user_id,
                details={
                    "device_id": self.id,
                    "device_name": self.device_name
                }
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            logger = current_app.logger if current_app else logging.getLogger(__name__)
            logger.error(f"Error deactivating TOTP device: {str(e)}")
            return False

    def _log_verification(self, success: bool) -> None:
        """
        Log a verification attempt for security auditing.

        Args:
            success: Whether the verification was successful
        """
        try:
            # Try to use MFAVerification class if available
            from .mfa_verification import MFAVerification
            MFAVerification.log_verification(
                user_id=self.user_id,
                verification_type="totp",
                success=success,
                mfa_method_id=self.id,
                ip_address=request.remote_addr if has_request_context() else None,
                user_agent=request.user_agent.string if has_request_context() and hasattr(request, 'user_agent') else None
            )
        except ImportError:
            # Fall back to direct security event logging
            event_type = "mfa_totp_verification_success" if success else "mfa_totp_verification_failure"
            severity = "info" if success else "warning"

            log_security_event(
                event_type=event_type,
                description=f"TOTP verification {'succeeded' if success else 'failed'} for user {self.user_id}",
                severity=severity,
                user_id=self.user_id,
                ip_address=request.remote_addr if has_request_context() else None,
                details={
                    "device_id": self.id,
                    "device_name": self.device_name
                }
            )

    @classmethod
    def generate_secret(cls) -> str:
        """
        Generate a secure random TOTP secret.

        Returns:
            str: Base32 encoded secret
        """
        return pyotp.random_base32()

    @classmethod
    def get_active_for_user(cls, user_id: int) -> List["MFATotp"]:
        """
        Get all active TOTP devices for a user.

        Args:
            user_id: User ID

        Returns:
            List[MFATotp]: List of active TOTP devices
        """
        return cls.query.filter_by(user_id=user_id, is_active=True).all()

    @classmethod
    def has_active_device(cls, user_id: int) -> bool:
        """
        Check if user has any active TOTP device.

        Args:
            user_id: User ID

        Returns:
            bool: True if user has at least one active device
        """
        return cls.query.filter_by(user_id=user_id, is_active=True).count() > 0

    @classmethod
    def verify_code_for_user(cls, user_id: int, code: str) -> bool:
        """
        Verify a TOTP code for any of the user's active devices.

        Args:
            user_id: User ID
            code: TOTP code to verify

        Returns:
            bool: True if code is valid for any active device
        """
        devices = cls.get_active_for_user(user_id)

        for device in devices:
            if device.verify_code(code):
                return True

        return False
