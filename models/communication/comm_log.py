"""
Communication logging model for the Cloud Infrastructure Platform.

This module defines the CommunicationLog model which records all sent communications
across different channels (email, SMS, push notifications, etc.) for the purposes of:
- Message delivery tracking and troubleshooting
- Communication audit trails and compliance
- User engagement analytics
- Rate limiting enforcement
- Content analysis and quality assurance

The model provides a centralized way to track and query communication history while
supporting data retention policies and privacy requirements.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Union, Tuple
from sqlalchemy import desc, func, and_, or_, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import relationship, validates
from flask import current_app, g, has_request_context, request

from extensions import db, cache, metrics
from models.base import BaseModel, AuditableMixin
from core.security.cs_authentication import log_security_event


class CommunicationLog(BaseModel, AuditableMixin):
    """
    Model for tracking and auditing all communications sent through the platform.

    This model stores records of all communications sent through various channels,
    capturing details about message content, delivery status, and recipient information.
    It serves as an audit log for communications and supports analytics on messaging patterns.

    Attributes:
        id: Primary key
        channel_type: Type of communication channel used (email, SMS, push, etc.)
        recipient_type: Type of recipient (user, subscriber, custom, etc.)
        recipient_id: ID of the recipient user/subscriber/entity if applicable
        recipient_address: Address used for delivery (email, phone, etc.)
        sender_id: ID of the user/system that initiated the communication
        message_type: Type of message (notification, newsletter, alert, etc.)
        subject: Subject or title of the communication
        content_snippet: Brief excerpt of message content for reference
        template_id: ID of the template used (if applicable)
        status: Current status of the communication (sent, delivered, failed, etc.)
        message_id: External message ID from provider (if available)
        sent_at: When the communication was sent
        delivered_at: When the communication was delivered (if tracked)
        failed_at: When the communication failed (if applicable)
        error_details: Error information if delivery failed
        metadata: Additional message metadata and tracking information
    """

    __tablename__ = 'communication_logs'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['recipient_address', 'content_snippet', 'metadata']

    # Flag to enable access logging for this model
    AUDIT_ACCESS = True

    # Channel type constants
    CHANNEL_EMAIL = 'email'
    CHANNEL_SMS = 'sms'
    CHANNEL_PUSH = 'push'
    CHANNEL_IN_APP = 'in_app'
    CHANNEL_WEBHOOK = 'webhook'
    CHANNEL_CHAT = 'chat'
    CHANNEL_VOICE = 'voice'
    CHANNEL_API = 'api'

    VALID_CHANNELS = [
        CHANNEL_EMAIL, CHANNEL_SMS, CHANNEL_PUSH, CHANNEL_IN_APP,
        CHANNEL_WEBHOOK, CHANNEL_CHAT, CHANNEL_VOICE, CHANNEL_API
    ]

    # Message type constants
    TYPE_NOTIFICATION = 'notification'
    TYPE_NEWSLETTER = 'newsletter'
    TYPE_ALERT = 'alert'
    TYPE_MARKETING = 'marketing'
    TYPE_TRANSACTIONAL = 'transactional'
    TYPE_VERIFICATION = 'verification'
    TYPE_SECURITY = 'security'
    TYPE_SYSTEM = 'system'
    TYPE_OTHER = 'other'

    VALID_MESSAGE_TYPES = [
        TYPE_NOTIFICATION, TYPE_NEWSLETTER, TYPE_ALERT, TYPE_MARKETING,
        TYPE_TRANSACTIONAL, TYPE_VERIFICATION, TYPE_SECURITY, TYPE_SYSTEM, TYPE_OTHER
    ]

    # Recipient type constants
    RECIPIENT_USER = 'user'
    RECIPIENT_SUBSCRIBER = 'subscriber'
    RECIPIENT_CONTACT = 'contact'
    RECIPIENT_GROUP = 'group'
    RECIPIENT_CUSTOM = 'custom'

    VALID_RECIPIENT_TYPES = [
        RECIPIENT_USER, RECIPIENT_SUBSCRIBER, RECIPIENT_CONTACT, RECIPIENT_GROUP, RECIPIENT_CUSTOM
    ]

    # Status constants
    STATUS_QUEUED = 'queued'
    STATUS_SENT = 'sent'
    STATUS_DELIVERED = 'delivered'
    STATUS_FAILED = 'failed'
    STATUS_OPENED = 'opened'
    STATUS_CLICKED = 'clicked'
    STATUS_BOUNCED = 'bounced'
    STATUS_REJECTED = 'rejected'
    STATUS_BLOCKED = 'blocked'

    VALID_STATUSES = [
        STATUS_QUEUED, STATUS_SENT, STATUS_DELIVERED, STATUS_FAILED,
        STATUS_OPENED, STATUS_CLICKED, STATUS_BOUNCED, STATUS_REJECTED, STATUS_BLOCKED
    ]

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    channel_type = db.Column(db.String(20), nullable=False, index=True)
    recipient_type = db.Column(db.String(20), nullable=False, index=True)
    recipient_id = db.Column(db.Integer, nullable=True, index=True)
    recipient_address = db.Column(db.String(255), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    message_type = db.Column(db.String(20), nullable=False, index=True)
    subject = db.Column(db.String(255), nullable=True)
    content_snippet = db.Column(db.Text, nullable=True)
    template_id = db.Column(db.Integer, nullable=True)

    # Tracking fields
    status = db.Column(db.String(20), nullable=False, default=STATUS_QUEUED, index=True)
    message_id = db.Column(db.String(255), nullable=True, unique=True)
    sent_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    delivered_at = db.Column(db.DateTime(timezone=True), nullable=True)
    failed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    error_details = db.Column(db.Text, nullable=True)

    # Additional metadata and analytics tracking
    metadata = db.Column(JSONB, nullable=True)

    # Relationships
    sender = relationship('User', foreign_keys=[sender_id], lazy='joined',
                         backref=db.backref('sent_communications', lazy='dynamic'))

    # Indexes for common queries
    __table_args__ = (
        Index('ix_comm_logs_recipient_sent_at', 'recipient_id', 'sent_at'),
        Index('ix_comm_logs_channel_status', 'channel_type', 'status'),
        Index('ix_comm_logs_message_type_sent_at', 'message_type', 'sent_at'),
    )

    def __init__(self, channel_type: str, recipient_type: str, recipient_address: str,
                 message_type: str, subject: Optional[str] = None,
                 content_snippet: Optional[str] = None, recipient_id: Optional[int] = None,
                 sender_id: Optional[int] = None, template_id: Optional[int] = None,
                 message_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None):
        """
        Initialize a new communication log entry.

        Args:
            channel_type: Type of communication channel used
            recipient_type: Type of the recipient
            recipient_address: Address the message was sent to
            message_type: Type of message that was sent
            subject: Subject or title of the message (optional)
            content_snippet: Brief excerpt of message content (optional)
            recipient_id: ID of the recipient if applicable (optional)
            sender_id: ID of the sender if applicable (optional)
            template_id: ID of the template used if applicable (optional)
            message_id: External provider's message ID (optional)
            metadata: Additional tracking data (optional)

        Raises:
            ValueError: If required parameters are invalid
        """
        if channel_type not in self.VALID_CHANNELS:
            raise ValueError(f"Invalid channel type: {channel_type}. "
                            f"Must be one of: {', '.join(self.VALID_CHANNELS)}")

        if recipient_type not in self.VALID_RECIPIENT_TYPES:
            raise ValueError(f"Invalid recipient type: {recipient_type}. "
                            f"Must be one of: {', '.join(self.VALID_RECIPIENT_TYPES)}")

        if message_type not in self.VALID_MESSAGE_TYPES:
            raise ValueError(f"Invalid message type: {message_type}. "
                            f"Must be one of: {', '.join(self.VALID_MESSAGE_TYPES)}")

        self.channel_type = channel_type
        self.recipient_type = recipient_type
        self.recipient_address = recipient_address
        self.recipient_id = recipient_id
        self.message_type = message_type
        self.subject = subject
        self.content_snippet = content_snippet
        self.sender_id = sender_id
        self.template_id = template_id
        self.message_id = message_id
        self.metadata = metadata or {}

        # Auto-detect sender_id if not provided
        if self.sender_id is None and has_request_context() and hasattr(g, 'user_id'):
            self.sender_id = g.user_id

        # For security messages, log a security event
        if message_type == self.TYPE_SECURITY:
            self._log_security_message()

    @validates('status')
    def validate_status(self, key: str, value: str) -> str:
        """
        Validate and handle status transitions.

        Args:
            key: Field name
            value: New status value

        Returns:
            str: Validated status value

        Raises:
            ValueError: If status is invalid
        """
        if value not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status: {value}. "
                           f"Must be one of: {', '.join(self.VALID_STATUSES)}")

        # Set timestamp based on status change
        now = datetime.now(timezone.utc)

        # Handle status-specific timestamps
        if value == self.STATUS_SENT and not self.sent_at:
            self.sent_at = now
        elif value == self.STATUS_DELIVERED and not self.delivered_at:
            self.delivered_at = now
        elif value in (self.STATUS_FAILED, self.STATUS_BOUNCED, self.STATUS_REJECTED) and not self.failed_at:
            self.failed_at = now

        # For security messages with important status changes, log security event
        current_status = getattr(self, 'status', None)
        if self.message_type == self.TYPE_SECURITY and current_status != value:
            self._log_status_change(current_status, value)

        return value

    def update_status(self, status: str, error_details: Optional[str] = None,
                     additional_metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update the communication status and related fields.

        Args:
            status: New status (must be one of VALID_STATUSES)
            error_details: Error information if status is 'failed'
            additional_metadata: Additional tracking data to append

        Returns:
            bool: True if the update was successful
        """
        try:
            # Validate status
            if status not in self.VALID_STATUSES:
                if current_app:
                    current_app.logger.warning(f"Invalid status update: {status}")
                return False

            # Update status (which automatically updates timestamps via validator)
            self.status = status

            # Set error details if provided
            if error_details:
                self.error_details = error_details

            # Update metadata if provided
            if additional_metadata:
                if not self.metadata:
                    self.metadata = {}
                self.metadata.update(additional_metadata)

            # Update the log entry
            db.session.add(self)
            db.session.commit()

            # Track metrics if available
            if hasattr(metrics, 'counter'):
                metrics.counter(
                    'communication_status_changes',
                    1,
                    labels={
                        'channel': self.channel_type,
                        'message_type': self.message_type,
                        'status': status
                    }
                )

            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Failed to update communication status: {str(e)}")
            return False

    def _log_security_message(self) -> None:
        """Log a security event when a security-related message is created."""
        try:
            log_security_event(
                event_type="security_communication_sent",
                description=f"Security communication sent via {self.channel_type}",
                severity="info",
                user_id=self.recipient_id,
                details={
                    'channel_type': self.channel_type,
                    'recipient_type': self.recipient_type,
                    'subject': self.subject,
                    'message_type': self.message_type
                }
            )
        except Exception as e:
            if current_app:
                current_app.logger.error(f"Failed to log security event for communication: {str(e)}")

    def _log_status_change(self, old_status: Optional[str], new_status: str) -> None:
        """Log status changes for security-related messages."""
        try:
            # Only log important status changes
            if new_status in (self.STATUS_FAILED, self.STATUS_BOUNCED, self.STATUS_REJECTED):
                severity = "warning"
            else:
                severity = "info"

            log_security_event(
                event_type="security_communication_status",
                description=f"Security communication status changed to {new_status}",
                severity=severity,
                user_id=self.recipient_id,
                details={
                    'channel_type': self.channel_type,
                    'recipient_type': self.recipient_type,
                    'old_status': old_status,
                    'new_status': new_status,
                    'subject': self.subject,
                    'error': self.error_details
                }
            )
        except Exception as e:
            if current_app:
                current_app.logger.error(f"Failed to log security status change: {str(e)}")

    @classmethod
    def log_communication(cls, channel_type: str, recipient_address: str,
                        message_type: str, **kwargs) -> Optional['CommunicationLog']:
        """
        Create and save a new communication log entry.

        Args:
            channel_type: Communication channel type
            recipient_address: Address the message was sent to
            message_type: Type of message sent
            **kwargs: Additional fields for the log entry

        Returns:
            Optional[CommunicationLog]: Created log entry or None if failed
        """
        try:
            # Set a default recipient type if not provided
            if 'recipient_type' not in kwargs:
                # Try to infer recipient type from address format
                if '@' in recipient_address:
                    recipient_type = cls.RECIPIENT_USER
                elif recipient_address.startswith('+') or recipient_address.isdigit():
                    recipient_type = cls.RECIPIENT_CONTACT
                else:
                    recipient_type = cls.RECIPIENT_CUSTOM
            else:
                recipient_type = kwargs.pop('recipient_type')

            # Create log entry
            log_entry = cls(
                channel_type=channel_type,
                recipient_type=recipient_type,
                recipient_address=recipient_address,
                message_type=message_type,
                **kwargs
            )

            db.session.add(log_entry)
            db.session.commit()

            # Record metrics
            if hasattr(metrics, 'counter'):
                metrics.counter(
                    'communications_sent',
                    1,
                    labels={
                        'channel': channel_type,
                        'message_type': message_type
                    }
                )

            return log_entry

        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Failed to create communication log: {str(e)}")
            return None
        except Exception as e:
            if current_app:
                current_app.logger.error(f"Unexpected error logging communication: {str(e)}")
            return None

    @classmethod
    def get_by_recipient(cls, recipient_id: int, recipient_type: str = RECIPIENT_USER,
                      limit: int = 100) -> List['CommunicationLog']:
        """
        Get communication logs for a specific recipient.

        Args:
            recipient_id: ID of the recipient
            recipient_type: Type of the recipient (default: user)
            limit: Maximum number of logs to return

        Returns:
            List[CommunicationLog]: List of communication logs
        """
        return cls.query.filter(
            cls.recipient_id == recipient_id,
            cls.recipient_type == recipient_type
        ).order_by(desc(cls.sent_at)).limit(limit).all()

    @classmethod
    def get_by_message_id(cls, message_id: str) -> Optional['CommunicationLog']:
        """
        Get communication log by external message ID.

        Args:
            message_id: External message ID

        Returns:
            Optional[CommunicationLog]: Communication log if found, None otherwise
        """
        return cls.query.filter(cls.message_id == message_id).first()

    @classmethod
    def get_failed_communications(cls, hours: int = 24) -> List['CommunicationLog']:
        """
        Get all failed communications within the specified time window.

        Args:
            hours: Time window in hours

        Returns:
            List[CommunicationLog]: List of failed communication logs
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return cls.query.filter(
            cls.status.in_([cls.STATUS_FAILED, cls.STATUS_BOUNCED, cls.STATUS_REJECTED]),
            cls.created_at >= cutoff
        ).order_by(desc(cls.created_at)).all()

    @classmethod
    def get_communication_stats(cls, days: int = 30) -> Dict[str, Any]:
        """
        Get communication statistics for the specified time period.

        Args:
            days: Number of days to include in statistics

        Returns:
            Dict[str, Any]: Dictionary of statistics
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        # Get total count
        total_count = cls.query.filter(cls.created_at >= cutoff).count()

        # Get counts by status
        status_counts = db.session.query(
            cls.status, func.count(cls.id)
        ).filter(
            cls.created_at >= cutoff
        ).group_by(cls.status).all()

        # Get counts by channel type
        channel_counts = db.session.query(
            cls.channel_type, func.count(cls.id)
        ).filter(
            cls.created_at >= cutoff
        ).group_by(cls.channel_type).all()

        # Get counts by message type
        message_type_counts = db.session.query(
            cls.message_type, func.count(cls.id)
        ).filter(
            cls.created_at >= cutoff
        ).group_by(cls.message_type).all()

        # Calculate error rate
        error_count = sum(count for status, count in status_counts
                        if status in (cls.STATUS_FAILED, cls.STATUS_BOUNCED, cls.STATUS_REJECTED))
        error_rate = (error_count / total_count) * 100 if total_count > 0 else 0

        # Format results
        return {
            'total': total_count,
            'error_rate': round(error_rate, 2),
            'by_status': {status: count for status, count in status_counts},
            'by_channel': {channel: count for channel, count in channel_counts},
            'by_message_type': {message_type: count for message_type, count in message_type_counts},
            'period_days': days
        }

    @classmethod
    def search(cls, query_params: Dict[str, Any],
             start_date: Optional[datetime] = None,
             end_date: Optional[datetime] = None,
             limit: int = 100) -> List['CommunicationLog']:
        """
        Search communication logs based on various filter criteria.

        Args:
            query_params: Dictionary of search parameters
            start_date: Start date for filtering by sent_at
            end_date: End date for filtering by sent_at
            limit: Maximum number of records to return

        Returns:
            List[CommunicationLog]: Filtered communication logs
        """
        filters = []

        if start_date:
            filters.append(cls.sent_at >= start_date)

        if end_date:
            filters.append(cls.sent_at <= end_date)

        # Process query parameters
        for key, value in query_params.items():
            if not hasattr(cls, key):
                continue

            if isinstance(value, list):
                filters.append(getattr(cls, key).in_(value))
            else:
                filters.append(getattr(cls, key) == value)

        # Apply filters and return results
        if filters:
            return cls.query.filter(and_(*filters)).order_by(
                desc(cls.sent_at)).limit(limit).all()
        else:
            return cls.query.order_by(desc(cls.sent_at)).limit(limit).all()

    @classmethod
    def cleanup_old_logs(cls, retention_days: int = 180) -> Tuple[bool, int]:
        """
        Delete communication logs older than the retention period.

        Args:
            retention_days: Number of days to retain logs

        Returns:
            Tuple[bool, int]: Success status and number of deleted logs
        """
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
            # Keep security message logs for longer (double the retention period)
            security_cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days * 2)

            # Delete non-security messages older than retention period
            deletion_query = cls.query.filter(
                cls.message_type != cls.TYPE_SECURITY,
                cls.created_at < cutoff
            )
            deletion_count = deletion_query.count()
            deletion_query.delete(synchronize_session=False)

            # Delete security messages older than extended retention period
            security_deletion_query = cls.query.filter(
                cls.message_type == cls.TYPE_SECURITY,
                cls.created_at < security_cutoff
            )
            security_deletion_count = security_deletion_query.count()
            security_deletion_query.delete(synchronize_session=False)

            # Commit changes
            db.session.commit()

            total_deleted = deletion_count + security_deletion_count

            # Log the cleanup operation
            if current_app:
                current_app.logger.info(
                    f"Cleaned up {total_deleted} communication logs "
                    f"({deletion_count} regular, {security_deletion_count} security)"
                )

            return True, total_deleted

        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Failed to clean up communication logs: {str(e)}")
            return False, 0

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the communication log to a dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary representation of the communication log
        """
        return {
            'id': self.id,
            'channel_type': self.channel_type,
            'recipient_type': self.recipient_type,
            'recipient_id': self.recipient_id,
            'recipient_address': self.recipient_address,
            'sender_id': self.sender_id,
            'message_type': self.message_type,
            'subject': self.subject,
            'content_snippet': self.content_snippet,
            'template_id': self.template_id,
            'status': self.status,
            'message_id': self.message_id,
            'sent_at': self.sent_at.isoformat() if self.sent_at else None,
            'delivered_at': self.delivered_at.isoformat() if self.delivered_at else None,
            'failed_at': self.failed_at.isoformat() if self.failed_at else None,
            'error_details': self.error_details,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self) -> str:
        """String representation of the communication log entry."""
        return (f"<CommunicationLog id={self.id}, channel={self.channel_type}, "
                f"type={self.message_type}, status={self.status}>")
