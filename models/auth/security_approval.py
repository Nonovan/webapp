"""
Security approval model for command authorization workflows.

This module provides the data model for tracking approval requests and authorizations
for sensitive administrative operations. It supports multi-person approval workflows,
time-limited approvals, and comprehensive audit trails.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from sqlalchemy import Column, String, Boolean, Integer, DateTime, ForeignKey, Table
from sqlalchemy.orm import relationship

from extensions import db
from models.base import BaseModel, AuditableMixin
from core.security.cs_audit import log_security_event

# Association table for approvers
approval_approvers = Table(
    'security_approval_approvers',
    db.Model.metadata,
    Column('approval_id', String(36), ForeignKey('security_approvals.id', ondelete='CASCADE')),
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE')),
)


class SecurityApproval(BaseModel, AuditableMixin):
    """
    Represents a security approval request and its current status.

    Used for implementing multi-person approval workflows for sensitive operations
    like high-risk administrative commands, security control changes, and emergency access.

    Attributes:
        id: Unique identifier for the approval (UUID string)
        operation: Operation identifier requiring approval
        requester_id: ID of the user requesting approval
        approval_type: Type of approval request (e.g., 'admin_command')
        details: JSON data with additional details about the request
        is_approved: Whether the request has been approved
        is_active: Whether the approval request is still active
        approval_count: Number of approvals received
        required_approvals: Number of approvals required
        created_at: When the approval request was created
        updated_at: When the approval request was last updated
        expires_at: When the approval request expires
        context: JSON data with contextual information about the request
    """
    __tablename__ = 'security_approvals'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['is_approved', 'is_active']

    # Enable access auditing for this model due to its sensitive nature
    AUDIT_ACCESS = True

    # Approval types
    TYPE_ADMIN_COMMAND = 'admin_command'
    TYPE_SECURITY_CHANGE = 'security_change'
    TYPE_EMERGENCY_ACCESS = 'emergency_access'
    TYPE_CONFIG_CHANGE = 'config_change'

    # Status constants
    STATUS_PENDING = 'pending'
    STATUS_APPROVED = 'approved'
    STATUS_DENIED = 'denied'
    STATUS_EXPIRED = 'expired'
    STATUS_CANCELED = 'canceled'

    # Primary key - using string for UUID
    id = db.Column(db.String(36), primary_key=True)

    # Basic fields
    operation = db.Column(db.String(100), nullable=False, index=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                           nullable=False, index=True)
    approval_type = db.Column(db.String(50), nullable=False, index=True)
    details = db.Column(db.JSON, nullable=True)

    # Approval status
    is_approved = db.Column(db.Boolean, default=False, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    status = db.Column(db.String(20), default=STATUS_PENDING, nullable=False)
    approval_count = db.Column(db.Integer, default=0, nullable=False)
    required_approvals = db.Column(db.Integer, default=1, nullable=False)

    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                         nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True),
                         default=lambda: datetime.now(timezone.utc),
                         onupdate=lambda: datetime.now(timezone.utc),
                         nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    executed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Additional context
    context = db.Column(db.JSON, nullable=True)

    # Relationships
    requester = relationship('User', foreign_keys=[requester_id],
                           backref=db.backref('approval_requests', lazy='dynamic'))
    approvers = relationship('User', secondary=approval_approvers,
                           backref=db.backref('approvals', lazy='dynamic'))

    def __init__(self, id: str, operation: str, requester_id: int, approval_type: str,
                is_approved: bool = False, is_active: bool = True, created_at: datetime = None,
                expires_at: datetime = None, details: Dict = None, required_approvals: int = 1):
        """Initialize a new security approval request."""
        self.id = id
        self.operation = operation
        self.requester_id = requester_id
        self.approval_type = approval_type
        self.is_approved = is_approved
        self.is_active = is_active
        self.status = self.STATUS_PENDING
        self.approval_count = 0
        self.required_approvals = required_approvals
        self.details = details

        # Set timestamps
        current_time = datetime.now(timezone.utc)
        self.created_at = created_at or current_time
        self.updated_at = current_time
        self.expires_at = expires_at

    def add_approver(self, approver_id: int, notes: Optional[str] = None) -> bool:
        """
        Add an approver to this approval request.

        Args:
            approver_id: ID of the user approving the request
            notes: Optional notes accompanying the approval

        Returns:
            bool: True if the request is now fully approved, False otherwise
        """
        from models.auth.user import User

        try:
            approver = User.query.get(approver_id)
            if not approver:
                return False

            # Check if this user already approved
            if approver in self.approvers:
                return False

            # Add the approver
            self.approvers.append(approver)
            self.approval_count += 1

            # Add notes if provided
            if notes and self.details:
                if 'approval_notes' not in self.details:
                    self.details['approval_notes'] = []
                self.details['approval_notes'].append({
                    'approver_id': approver_id,
                    'approver_name': approver.username,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'notes': notes
                })

            # Check if we've reached the required number of approvals
            if self.approval_count >= self.required_approvals:
                self.is_approved = True
                self.status = self.STATUS_APPROVED
                self.updated_at = datetime.now(timezone.utc)

                # Log security event
                log_security_event(
                    event_type='approval_granted',
                    description=f"Approval granted for operation: {self.operation}",
                    severity='warning',
                    user_id=approver_id,
                    details={
                        'approval_id': self.id,
                        'operation': self.operation,
                        'approval_type': self.approval_type,
                        'requester_id': self.requester_id
                    }
                )

            db.session.add(self)
            db.session.commit()

            return self.is_approved

        except Exception as e:
            db.session.rollback()
            if hasattr(db, 'logger'):
                db.logger.error(f"Error adding approver: {str(e)}")
            return False

    def deny(self, denier_id: int, reason: Optional[str] = None) -> bool:
        """
        Deny an approval request.

        Args:
            denier_id: ID of the user denying the request
            reason: Reason for the denial

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.is_approved = False
            self.is_active = False
            self.status = self.STATUS_DENIED
            self.updated_at = datetime.now(timezone.utc)

            # Add denial reason to details
            if reason:
                self.details = self.details or {}
                self.details['denial_reason'] = reason
                self.details['denied_by'] = denier_id
                self.details['denied_at'] = datetime.now(timezone.utc).isoformat()

            db.session.add(self)
            db.session.commit()

            # Log security event
            log_security_event(
                event_type='approval_denied',
                description=f"Approval denied for operation: {self.operation}",
                severity='warning',
                user_id=denier_id,
                details={
                    'approval_id': self.id,
                    'operation': self.operation,
                    'approval_type': self.approval_type,
                    'requester_id': self.requester_id,
                    'reason': reason
                }
            )

            return True
        except Exception as e:
            db.session.rollback()
            if hasattr(db, 'logger'):
                db.logger.error(f"Error denying approval: {str(e)}")
            return False

    def execute(self) -> bool:
        """
        Mark an approved request as executed.

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_approved or not self.is_active:
            return False

        try:
            self.executed_at = datetime.now(timezone.utc)
            self.updated_at = self.executed_at

            db.session.add(self)
            db.session.commit()

            return True
        except Exception as e:
            db.session.rollback()
            if hasattr(db, 'logger'):
                db.logger.error(f"Error marking approval as executed: {str(e)}")
            return False

    def expire(self) -> bool:
        """
        Mark an approval request as expired.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.is_active = False
            self.status = self.STATUS_EXPIRED
            self.updated_at = datetime.now(timezone.utc)

            db.session.add(self)
            db.session.commit()

            # Log security event
            log_security_event(
                event_type='approval_expired',
                description=f"Approval request expired: {self.operation}",
                severity='info',
                details={
                    'approval_id': self.id,
                    'operation': self.operation,
                    'approval_type': self.approval_type,
                    'requester_id': self.requester_id
                }
            )

            return True
        except Exception as e:
            db.session.rollback()
            if hasattr(db, 'logger'):
                db.logger.error(f"Error expiring approval: {str(e)}")
            return False

    def cancel(self, user_id: int, reason: Optional[str] = None) -> bool:
        """
        Cancel an approval request.

        Args:
            user_id: ID of the user canceling the request
            reason: Optional reason for cancellation

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.is_active = False
            self.status = self.STATUS_CANCELED
            self.updated_at = datetime.now(timezone.utc)

            # Add cancellation reason to details
            if reason:
                self.details = self.details or {}
                self.details['cancellation_reason'] = reason
                self.details['canceled_by'] = user_id
                self.details['canceled_at'] = datetime.now(timezone.utc).isoformat()

            db.session.add(self)
            db.session.commit()

            # Log security event
            log_security_event(
                event_type='approval_canceled',
                description=f"Approval request canceled: {self.operation}",
                severity='info',
                user_id=user_id,
                details={
                    'approval_id': self.id,
                    'operation': self.operation,
                    'approval_type': self.approval_type,
                    'requester_id': self.requester_id,
                    'reason': reason
                }
            )

            return True
        except Exception as e:
            db.session.rollback()
            if hasattr(db, 'logger'):
                db.logger.error(f"Error canceling approval: {str(e)}")
            return False

    def is_expired(self) -> bool:
        """Check if the approval request has expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        """Convert the approval to a dictionary representation."""
        return {
            'id': self.id,
            'operation': self.operation,
            'requester_id': self.requester_id,
            'approval_type': self.approval_type,
            'is_approved': self.is_approved,
            'is_active': self.is_active,
            'status': self.status,
            'approval_count': self.approval_count,
            'required_approvals': self.required_approvals,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'executed_at': self.executed_at.isoformat() if self.executed_at else None,
            'details': self.details,
            'approvers': [approver.id for approver in self.approvers]
        }

    @classmethod
    def create_approval_request(
        cls,
        operation: str,
        requester_id: int,
        approval_type: str = TYPE_ADMIN_COMMAND,
        required_approvals: int = 1,
        expiry_minutes: int = 60,
        details: Dict = None
    ) -> Optional['SecurityApproval']:
        """
        Create a new security approval request.

        Args:
            operation: Operation identifier requiring approval
            requester_id: ID of the user requesting approval
            approval_type: Type of approval request
            required_approvals: Number of approvals required
            expiry_minutes: Minutes until the request expires
            details: Additional details about the request

        Returns:
            SecurityApproval object if created successfully, None otherwise
        """
        import uuid

        try:
            approval_id = str(uuid.uuid4())
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)

            approval = cls(
                id=approval_id,
                operation=operation,
                requester_id=requester_id,
                approval_type=approval_type,
                required_approvals=required_approvals,
                expires_at=expires_at,
                details=details
            )

            db.session.add(approval)
            db.session.commit()

            # Log security event
            log_security_event(
                event_type='approval_requested',
                description=f"Approval requested for operation: {operation}",
                severity='info',
                user_id=requester_id,
                details={
                    'approval_id': approval_id,
                    'operation': operation,
                    'approval_type': approval_type,
                    'expires_at': expires_at.isoformat(),
                    'required_approvals': required_approvals
                }
            )

            return approval
        except Exception as e:
            db.session.rollback()
            if hasattr(db, 'logger'):
                db.logger.error(f"Error creating approval request: {str(e)}")
            return None

    @classmethod
    def get_pending_approvals(cls, approval_type: Optional[str] = None) -> List['SecurityApproval']:
        """
        Get all pending approval requests.

        Args:
            approval_type: Optional type to filter by

        Returns:
            List of pending approval requests
        """
        query = cls.query.filter_by(is_active=True, is_approved=False)

        if approval_type:
            query = query.filter_by(approval_type=approval_type)

        return query.all()

    @classmethod
    def get_pending_approvals_for_user(cls, user_id: int, approval_type: Optional[str] = None) -> List['SecurityApproval']:
        """
        Get pending approval requests created by a specific user.

        Args:
            user_id: User ID to filter by
            approval_type: Optional type to filter by

        Returns:
            List of pending approval requests
        """
        query = cls.query.filter_by(requester_id=user_id, is_active=True)

        if approval_type:
            query = query.filter_by(approval_type=approval_type)

        return query.all()

    @classmethod
    def cleanup_expired_approvals(cls) -> int:
        """
        Mark all expired approval requests as expired.

        Returns:
            int: Number of approvals marked as expired
        """
        count = 0
        now = datetime.now(timezone.utc)

        try:
            # Find expired but still active approvals
            expired_approvals = cls.query.filter(
                cls.is_active == True,
                cls.expires_at < now
            ).all()

            for approval in expired_approvals:
                if approval.expire():
                    count += 1

            return count
        except Exception as e:
            db.session.rollback()
            if hasattr(db, 'logger'):
                db.logger.error(f"Error cleaning up expired approvals: {str(e)}")
            return 0

    def __repr__(self) -> str:
        """String representation of the approval."""
        return f"<SecurityApproval {self.id}: {self.operation} ({self.status})>"
