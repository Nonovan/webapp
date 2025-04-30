"""
Permission delegation model for the Cloud Infrastructure Platform.

This module enables temporary delegation of specific permissions between users,
supporting emergency access and controlled permission escalation.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple, Union
from flask import current_app
from sqlalchemy.exc import SQLAlchemyError

from extensions import db
from models.base import BaseModel, AuditableMixin
from core.security_utils import log_security_event

class PermissionDelegation(BaseModel, AuditableMixin):
    """
    Model for tracking permission delegations between users.

    Allows temporary transfer of specific permissions between users with
    time constraints, approval workflow, and comprehensive audit trail.
    """

    __tablename__ = 'permission_delegations'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['permissions', 'status', 'is_active']

    # Status constants
    STATUS_PENDING = 'pending'    # Delegation has been requested but not approved
    STATUS_APPROVED = 'approved'  # Delegation has been approved and is active
    STATUS_EXPIRED = 'expired'    # Delegation has naturally expired
    STATUS_REVOKED = 'revoked'    # Delegation was explicitly revoked before expiry
    STATUS_REJECTED = 'rejected'  # Delegation request was rejected

    # Delegation types
    TYPE_STANDARD = 'standard'    # Standard planned delegation
    TYPE_EMERGENCY = 'emergency'  # Emergency delegation with expedited approval
    TYPE_SCHEDULED = 'scheduled'  # Scheduled delegation for future activation

    id = db.Column(db.Integer, primary_key=True)

    # Delegation parties
    delegator_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                           nullable=False, index=True)
    delegate_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                          nullable=False, index=True)
    approver_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'),
                          nullable=True)

    # Delegation details
    delegation_type = db.Column(db.String(20), default=TYPE_STANDARD, nullable=False)

    # Individual permissions or role IDs being delegated
    permissions = db.Column(db.JSON, nullable=False)  # List of permission names or IDs

    # Delegation constraints
    context_constraints = db.Column(db.JSON, nullable=True)  # Optional context restrictions
    reason = db.Column(db.Text, nullable=False)

    # Status tracking
    status = db.Column(db.String(20), default=STATUS_PENDING, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=False, nullable=False)

    # Time constraints
    start_time = db.Column(db.DateTime(timezone=True), nullable=False)
    end_time = db.Column(db.DateTime(timezone=True), nullable=False)

    # Approval tracking
    requested_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                           nullable=False)
    approved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    approval_notes = db.Column(db.Text, nullable=True)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    revocation_reason = db.Column(db.Text, nullable=True)

    # Relationships
    delegator = db.relationship('User', foreign_keys=[delegator_id],
                              backref=db.backref('outgoing_delegations', lazy='dynamic'))
    delegate = db.relationship('User', foreign_keys=[delegate_id],
                             backref=db.backref('incoming_delegations', lazy='dynamic'))
    approver = db.relationship('User', foreign_keys=[approver_id])

    def __init__(self, delegator_id: int, delegate_id: int, permissions: List[str],
               start_time: datetime, end_time: datetime, reason: str,
               delegation_type: str = TYPE_STANDARD,
               context_constraints: Optional[Dict[str, Any]] = None):
        """
        Initialize a new permission delegation.

        Args:
            delegator_id: ID of the user delegating permissions
            delegate_id: ID of the user receiving permissions
            permissions: List of permission names or IDs being delegated
            start_time: When the delegation becomes active
            end_time: When the delegation expires
            reason: Reason for the delegation
            delegation_type: Type of delegation (standard, emergency, scheduled)
            context_constraints: Optional context restrictions on the delegated permissions
        """
        self.delegator_id = delegator_id
        self.delegate_id = delegate_id
        self.permissions = permissions
        self.start_time = start_time
        self.end_time = end_time
        self.reason = reason
        self.delegation_type = delegation_type
        self.context_constraints = context_constraints

        # Set initial status based on delegation type
        if delegation_type == self.TYPE_EMERGENCY:
            # Emergency delegations are auto-approved
            self.status = self.STATUS_APPROVED
            self.is_active = True
            self.approved_at = datetime.now(timezone.utc)
            self.approver_id = delegator_id  # Self-approval for emergencies

        else:
            # Standard and scheduled delegations start as pending
            self.status = self.STATUS_PENDING
            self.is_active = False

    def approve(self, approver_id: int, notes: Optional[str] = None) -> bool:
        """
        Approve a pending delegation request.

        Args:
            approver_id: ID of the user approving the delegation
            notes: Optional approval notes

        Returns:
            bool: True if successful, False otherwise
        """
        if self.status != self.STATUS_PENDING:
            return False

        try:
            now = datetime.now(timezone.utc)
            self.status = self.STATUS_APPROVED
            self.approver_id = approver_id
            self.approved_at = now
            self.approval_notes = notes

            # Activate immediately if start time is in the past
            if self.start_time <= now:
                self.is_active = True

            db.session.add(self)
            db.session.commit()

            # Log security event
            log_security_event(
                'delegation_approved',
                f"Permission delegation approved: {self.delegator_id} → {self.delegate_id}",
                user_id=approver_id,
                severity="info",
                details={
                    "delegation_id": self.id,
                    "delegator_id": self.delegator_id,
                    "delegate_id": self.delegate_id,
                    "permissions": self.permissions,
                    "start_time": self.start_time.isoformat(),
                    "end_time": self.end_time.isoformat()
                }
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to approve delegation: {str(e)}")
            return False

    def reject(self, approver_id: int, reason: Optional[str] = None) -> bool:
        """
        Reject a pending delegation request.

        Args:
            approver_id: ID of the user rejecting the delegation
            reason: Optional rejection reason

        Returns:
            bool: True if successful, False otherwise
        """
        if self.status != self.STATUS_PENDING:
            return False

        try:
            self.status = self.STATUS_REJECTED
            self.approver_id = approver_id
            self.revoked_at = datetime.now(timezone.utc)
            self.revocation_reason = reason
            self.is_active = False

            db.session.add(self)
            db.session.commit()

            # Log security event
            log_security_event(
                'delegation_rejected',
                f"Permission delegation rejected: {self.delegator_id} → {self.delegate_id}",
                user_id=approver_id,
                severity="info",
                details={
                    "delegation_id": self.id,
                    "delegator_id": self.delegator_id,
                    "delegate_id": self.delegate_id,
                    "permissions": self.permissions,
                    "reason": reason
                }
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to reject delegation: {str(e)}")
            return False

    def revoke(self, revoker_id: int, reason: Optional[str] = None) -> bool:
        """
        Revoke an active delegation before its expiration.

        Args:
            revoker_id: ID of the user revoking the delegation
            reason: Optional reason for revocation

        Returns:
            bool: True if successful, False otherwise
        """
        if self.status not in [self.STATUS_APPROVED, self.STATUS_PENDING] or not self.is_active:
            return False

        try:
            now = datetime.now(timezone.utc)
            self.status = self.STATUS_REVOKED
            self.is_active = False
            self.revoked_at = now
            self.revocation_reason = reason

            db.session.add(self)
            db.session.commit()

            # Log security event
            log_security_event(
                'delegation_revoked',
                f"Permission delegation revoked: {self.delegator_id} → {self.delegate_id}",
                user_id=revoker_id,
                severity="info",
                details={
                    "delegation_id": self.id,
                    "delegator_id": self.delegator_id,
                    "delegate_id": self.delegate_id,
                    "permissions": self.permissions,
                    "reason": reason
                }
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to revoke delegation: {str(e)}")
            return False

    def is_valid(self) -> bool:
        """
        Check if the delegation is currently valid and active.

        Returns:
            bool: True if delegation is active and within validity period
        """
        now = datetime.now(timezone.utc)
        return (self.is_active and
                self.status == self.STATUS_APPROVED and
                self.start_time <= now <= self.end_time)

    @classmethod
    def get_active_for_user(cls, user_id: int) -> List['PermissionDelegation']:
        """
        Get all active delegations for a user.

        Args:
            user_id: ID of the user to get delegations for

        Returns:
            List[PermissionDelegation]: List of active delegations
        """
        now = datetime.now(timezone.utc)
        return cls.query.filter(
            cls.delegate_id == user_id,
            cls.status == cls.STATUS_APPROVED,
            cls.is_active == True,
            cls.start_time <= now,
            cls.end_time >= now
        ).all()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert delegation to dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary with delegation data
        """
        return {
            'id': self.id,
            'delegator_id': self.delegator_id,
            'delegator_name': self.delegator.username if self.delegator else None,
            'delegate_id': self.delegate_id,
            'delegate_name': self.delegate.username if self.delegate else None,
            'permissions': self.permissions,
            'context_constraints': self.context_constraints,
            'reason': self.reason,
            'status': self.status,
            'is_active': self.is_active,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'requested_at': self.requested_at.isoformat() if self.requested_at else None,
            'approved_at': self.approved_at.isoformat() if self.approved_at else None,
            'revoked_at': self.revoked_at.isoformat() if self.revoked_at else None,
            'is_valid': self.is_valid()
        }

    @classmethod
    def create_standard_delegation(cls, delegator_id: int, delegate_id: int,
                                    permissions: List[str], valid_days: int = 7,
                                    reason: str = None, context_constraints: Dict = None) -> 'PermissionDelegation':
        """
        Create a standard delegation request with default timeframe.

        Args:
            delegator_id: ID of user delegating permissions
            delegate_id: ID of user receiving permissions
            permissions: List of permission names or IDs to delegate
            valid_days: Number of days the delegation should be valid
            reason: Reason for the delegation
            context_constraints: Optional context restrictions

        Returns:
            PermissionDelegation: The created delegation request
        """
        now = datetime.now(timezone.utc)
        end_time = now + timedelta(days=valid_days)

        delegation = cls(
            delegator_id=delegator_id,
            delegate_id=delegate_id,
            permissions=permissions,
            start_time=now,
            end_time=end_time,
            reason=reason or "Standard permission delegation",
            delegation_type=cls.TYPE_STANDARD,
            context_constraints=context_constraints
        )

        try:
            db.session.add(delegation)
            db.session.commit()
            return delegation
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to create delegation: {str(e)}")
            raise

    @classmethod
    def create_emergency_delegation(cls, delegator_id: int, delegate_id: int,
                                    permissions: List[str], valid_hours: int = 24,
                                    reason: str = None) -> 'PermissionDelegation':
        """
        Create an emergency delegation that is automatically approved.

        Args:
            delegator_id: ID of user delegating permissions
            delegate_id: ID of user receiving permissions
            permissions: List of permission names or IDs to delegate
            valid_hours: Number of hours the delegation should be valid
            reason: Reason for the emergency delegation

        Returns:
            PermissionDelegation: The created emergency delegation
        """
        now = datetime.now(timezone.utc)
        end_time = now + timedelta(hours=valid_hours)

        delegation = cls(
            delegator_id=delegator_id,
            delegate_id=delegate_id,
            permissions=permissions,
            start_time=now,
            end_time=end_time,
            reason=reason or "Emergency permission delegation",
            delegation_type=cls.TYPE_EMERGENCY
        )

        try:
            db.session.add(delegation)
            db.session.commit()

            # Log security event for emergency delegation
            log_security_event(
                'emergency_delegation_created',
                f"Emergency permission delegation: {delegator_id} → {delegate_id}",
                user_id=delegator_id,
                severity="warning",  # Higher severity for emergency delegations
                details={
                    "delegation_id": delegation.id,
                    "permissions": permissions,
                    "valid_hours": valid_hours,
                    "reason": reason
                }
            )

            return delegation
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to create emergency delegation: {str(e)}")
            raise

    def __repr__(self) -> str:
        """String representation of the delegation."""
        return f"<PermissionDelegation {self.id}: {self.delegator_id} → {self.delegate_id}, status={self.status}>"
