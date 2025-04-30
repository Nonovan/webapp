"""
Communication scheduler model for the Cloud Infrastructure Platform.

This module defines the CommunicationScheduler model which represents scheduled
communications such as newsletters, notifications, and automated messages.
It provides functionality for:
- Scheduling one-time and recurring messages
- Managing communication templates
- Tracking delivery status and history
- Handling different communication channels (email, SMS, in-app, etc.)
- Supporting timezone-aware scheduling
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Union, Set
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.postgresql import JSONB
from croniter import croniter
from flask import current_app

from extensions import db, cache, metrics
from models.base import BaseModel, AuditableMixin
from models.communication.comm_channel import CommunicationChannel


class CommunicationScheduler(BaseModel, AuditableMixin):
    """
    Model for scheduled communications and automated messaging.

    This model handles the scheduling of various types of communications
    including newsletters, notifications, and automated messages with support
    for one-time and recurring schedules.

    Attributes:
        id: Primary key
        name: Descriptive name for the scheduled communication
        channel_id: ID of the communication channel to use
        template_id: ID of the message template to use
        recipient_type: Type of recipients (user, group, segment, etc.)
        recipient_data: Information needed to determine recipients
        schedule_type: One-time or recurring
        schedule_data: Scheduling information (datetime or cron expression)
        status: Current status of the schedule
        context_data: Variables to use in message template
        last_run: When the schedule was last executed
        next_run: When the schedule is next due to run
        created_at: When the schedule was created
        updated_at: When the schedule was last updated
    """

    __tablename__ = 'communication_schedules'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['status', 'schedule_data', 'recipient_data', 'context_data']
    AUDIT_ACCESS = True

    # Schedule type constants
    TYPE_ONE_TIME = 'one_time'
    TYPE_RECURRING = 'recurring'

    VALID_SCHEDULE_TYPES = [
        TYPE_ONE_TIME,
        TYPE_RECURRING
    ]

    # Recipient type constants
    RECIPIENT_ALL_USERS = 'all_users'
    RECIPIENT_USER_GROUP = 'user_group'
    RECIPIENT_SEGMENT = 'segment'
    RECIPIENT_SUBSCRIPTION = 'subscription'
    RECIPIENT_INDIVIDUAL = 'individual'
    RECIPIENT_QUERY = 'query'

    VALID_RECIPIENT_TYPES = [
        RECIPIENT_ALL_USERS,
        RECIPIENT_USER_GROUP,
        RECIPIENT_SEGMENT,
        RECIPIENT_SUBSCRIPTION,
        RECIPIENT_INDIVIDUAL,
        RECIPIENT_QUERY
    ]

    # Status constants
    STATUS_ACTIVE = 'active'
    STATUS_PAUSED = 'paused'
    STATUS_COMPLETED = 'completed'
    STATUS_FAILED = 'failed'
    STATUS_DRAFT = 'draft'

    VALID_STATUSES = [
        STATUS_ACTIVE,
        STATUS_PAUSED,
        STATUS_COMPLETED,
        STATUS_FAILED,
        STATUS_DRAFT
    ]

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)

    # Communication settings
    channel_id = db.Column(db.Integer, db.ForeignKey('communication_channels.id', ondelete='RESTRICT'), nullable=False)
    template_id = db.Column(db.Integer, db.ForeignKey('message_templates.id', ondelete='RESTRICT'), nullable=True)
    subject = db.Column(db.String(255), nullable=True)
    message_body = db.Column(db.Text, nullable=True)

    # Recipient configuration
    recipient_type = db.Column(db.String(50), nullable=False)
    recipient_data = db.Column(JSONB, nullable=True)

    # Schedule configuration
    schedule_type = db.Column(db.String(20), nullable=False)
    schedule_data = db.Column(JSONB, nullable=False)
    timezone = db.Column(db.String(50), default='UTC', nullable=False)
    start_date = db.Column(db.DateTime(timezone=True), nullable=True)
    end_date = db.Column(db.DateTime(timezone=True), nullable=True)

    # Status and tracking
    status = db.Column(db.String(20), default=STATUS_DRAFT, nullable=False)
    last_run = db.Column(db.DateTime(timezone=True), nullable=True)
    next_run = db.Column(db.DateTime(timezone=True), nullable=True)
    run_count = db.Column(db.Integer, default=0, nullable=False)
    max_runs = db.Column(db.Integer, nullable=True)  # Optional limit

    # Content and rendering
    context_data = db.Column(JSONB, nullable=True)

    # Tracking and analytics
    success_count = db.Column(db.Integer, default=0, nullable=False)
    failure_count = db.Column(db.Integer, default=0, nullable=False)
    last_error = db.Column(db.Text, nullable=True)

    # Relationships
    channel = db.relationship('CommunicationChannel', foreign_keys=[channel_id])
    template = db.relationship('MessageTemplate', foreign_keys=[template_id])

    def __init__(self, name: str, channel_id: int, recipient_type: str,
                 schedule_type: str, schedule_data: Dict[str, Any],
                 template_id: Optional[int] = None,
                 subject: Optional[str] = None,
                 message_body: Optional[str] = None,
                 recipient_data: Optional[Dict[str, Any]] = None,
                 context_data: Optional[Dict[str, Any]] = None,
                 timezone: str = 'UTC',
                 status: str = STATUS_DRAFT,
                 start_date: Optional[datetime] = None,
                 end_date: Optional[datetime] = None,
                 max_runs: Optional[int] = None):
        """
        Initialize a new scheduled communication.

        Args:
            name: Descriptive name for this scheduled communication
            channel_id: ID of the communication channel to use
            recipient_type: Type of recipients (user, group, segment, etc.)
            schedule_type: One-time or recurring
            schedule_data: Dictionary with scheduling information
            template_id: Optional ID of message template to use
            subject: Optional subject line (can be from template)
            message_body: Optional message body (can be from template)
            recipient_data: Optional data defining recipients
            context_data: Optional variables for message template
            timezone: Timezone for schedule (default: UTC)
            status: Initial status (default: draft)
            start_date: Optional date when schedule becomes active
            end_date: Optional date when schedule expires
            max_runs: Optional maximum number of executions

        Raises:
            ValueError: If required parameters are invalid
        """
        self.name = name
        self.channel_id = channel_id

        # Validate recipient type
        if recipient_type not in self.VALID_RECIPIENT_TYPES:
            raise ValueError(f"Invalid recipient type: {recipient_type}. "
                           f"Must be one of: {', '.join(self.VALID_RECIPIENT_TYPES)}")
        self.recipient_type = recipient_type

        # Validate schedule type
        if schedule_type not in self.VALID_SCHEDULE_TYPES:
            raise ValueError(f"Invalid schedule type: {schedule_type}. "
                           f"Must be one of: {', '.join(self.VALID_SCHEDULE_TYPES)}")
        self.schedule_type = schedule_type

        # Validate schedule data based on type
        self._validate_schedule_data(schedule_type, schedule_data)
        self.schedule_data = schedule_data

        # Set optional fields
        self.template_id = template_id
        self.subject = subject
        self.message_body = message_body
        self.recipient_data = recipient_data or {}
        self.context_data = context_data or {}
        self.timezone = timezone
        self.start_date = start_date
        self.end_date = end_date
        self.max_runs = max_runs

        # Validate status
        if status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}. "
                           f"Must be one of: {', '.join(self.VALID_STATUSES)}")
        self.status = status

        # Calculate next run time
        if self.status == self.STATUS_ACTIVE:
            self._calculate_next_run()

    def _validate_schedule_data(self, schedule_type: str, schedule_data: Dict[str, Any]) -> None:
        """
        Validate schedule data based on schedule type.

        Args:
            schedule_type: Type of schedule (one_time or recurring)
            schedule_data: Dictionary with scheduling information

        Raises:
            ValueError: If schedule data is invalid
        """
        if schedule_type == self.TYPE_ONE_TIME:
            # One-time schedule requires a datetime
            if 'datetime' not in schedule_data:
                raise ValueError("One-time schedule requires 'datetime' field")

            # Validate datetime format (ISO format)
            try:
                datetime.fromisoformat(schedule_data['datetime'].replace('Z', '+00:00'))
            except (ValueError, TypeError):
                raise ValueError("Invalid datetime format in schedule_data. Use ISO format.")

        elif schedule_type == self.TYPE_RECURRING:
            # Recurring schedule requires a cron expression
            if 'cron' not in schedule_data:
                raise ValueError("Recurring schedule requires 'cron' expression")

            # Validate cron expression
            try:
                croniter(schedule_data['cron'], datetime.now(timezone.utc))
            except (ValueError, KeyError):
                raise ValueError("Invalid cron expression in schedule_data")

    def _calculate_next_run(self) -> None:
        """
        Calculate the next scheduled run time based on schedule type and data.

        Updates the next_run field with the calculated datetime.
        """
        now = datetime.now(timezone.utc)

        if self.schedule_type == self.TYPE_ONE_TIME:
            # Parse the datetime string from schedule_data
            run_time = datetime.fromisoformat(self.schedule_data['datetime'].replace('Z', '+00:00'))

            # If the time is in the past, don't set a next run
            if run_time <= now:
                if self.status == self.STATUS_ACTIVE:
                    self.status = self.STATUS_FAILED
                    self.last_error = "Scheduled time is in the past"
                self.next_run = None
            else:
                self.next_run = run_time

        elif self.schedule_type == self.TYPE_RECURRING:
            # Use croniter to calculate the next run based on cron expression
            base_time = self.last_run if self.last_run and self.last_run >= now else now
            cron = croniter(self.schedule_data['cron'], base_time)
            next_run = cron.get_next(datetime)

            # Check if beyond end date
            if self.end_date and next_run > self.end_date:
                self.next_run = None
                if self.status == self.STATUS_ACTIVE:
                    self.status = self.STATUS_COMPLETED
            else:
                self.next_run = next_run

    def activate(self) -> bool:
        """
        Activate this communication schedule.

        Returns:
            bool: True if activation was successful
        """
        try:
            # Don't activate if already completed or failed
            if self.status in (self.STATUS_COMPLETED, self.STATUS_FAILED):
                return False

            self.status = self.STATUS_ACTIVE
            self._calculate_next_run()

            # If no next run time could be calculated, mark as failed or completed
            if not self.next_run:
                if self.run_count > 0:
                    self.status = self.STATUS_COMPLETED
                else:
                    self.status = self.STATUS_FAILED
                    self.last_error = "Could not calculate a valid run time"

            db.session.commit()
            self._clear_cache()
            return self.status == self.STATUS_ACTIVE

        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Failed to activate communication schedule: {str(e)}")
            return False

    def pause(self) -> bool:
        """
        Pause this communication schedule.

        Returns:
            bool: True if pause was successful
        """
        try:
            if self.status not in (self.STATUS_ACTIVE, self.STATUS_DRAFT):
                return False

            self.status = self.STATUS_PAUSED
            db.session.commit()
            self._clear_cache()
            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Failed to pause communication schedule: {str(e)}")
            return False

    def complete(self) -> bool:
        """
        Mark this communication schedule as completed.

        Returns:
            bool: True if operation was successful
        """
        try:
            self.status = self.STATUS_COMPLETED
            self.next_run = None
            db.session.commit()
            self._clear_cache()
            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Failed to complete communication schedule: {str(e)}")
            return False

    def record_execution(self, success: bool = True, error: Optional[str] = None) -> bool:
        """
        Record a schedule execution.

        Args:
            success: Whether the execution was successful
            error: Optional error message if execution failed

        Returns:
            bool: True if recorded successfully
        """
        try:
            self.run_count += 1
            self.last_run = datetime.now(timezone.utc)

            if success:
                self.success_count += 1
            else:
                self.failure_count += 1
                self.last_error = error

            # Check if max runs reached
            if self.max_runs and self.run_count >= self.max_runs:
                self.status = self.STATUS_COMPLETED
                self.next_run = None
            else:
                # Calculate the next run time
                self._calculate_next_run()

            db.session.commit()
            self._clear_cache()

            # Track metrics
            if hasattr(metrics, 'counter'):
                try:
                    metrics.counter(
                        'scheduled_communications_executed',
                        1,
                        {
                            'success': str(success).lower(),
                            'channel_type': self.channel.channel_type if self.channel else 'unknown'
                        }
                    )
                except Exception as e:
                    if current_app:
                        current_app.logger.warning(f"Failed to record metrics: {str(e)}")

            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Failed to record execution: {str(e)}")
            return False

    def update_schedule(self, schedule_data: Dict[str, Any]) -> bool:
        """
        Update the schedule configuration.

        Args:
            schedule_data: New scheduling information

        Returns:
            bool: True if update was successful
        """
        try:
            # Validate new schedule data
            self._validate_schedule_data(self.schedule_type, schedule_data)

            # Update schedule data
            self.schedule_data = schedule_data

            # Recalculate next run if active
            if self.status == self.STATUS_ACTIVE:
                self._calculate_next_run()

            db.session.commit()
            self._clear_cache()
            return True

        except (ValueError, SQLAlchemyError) as e:
            db.session.rollback()
            error_msg = str(e)
            if current_app:
                current_app.logger.error(f"Failed to update schedule: {error_msg}")
            return False

    def _clear_cache(self) -> None:
        """Clear cached data for this schedule."""
        if hasattr(cache, 'delete'):
            try:
                cache.delete(f"comm_schedule:{self.id}")
                cache.delete("upcoming_schedules")
            except Exception as e:
                if current_app:
                    current_app.logger.warning(f"Failed to clear schedule cache: {str(e)}")

    @classmethod
    def get_due_schedules(cls) -> List['CommunicationScheduler']:
        """
        Get all communication schedules that are due to run.

        Returns:
            List[CommunicationScheduler]: List of schedules due to run
        """
        now = datetime.now(timezone.utc)

        return cls.query.filter(
            cls.status == cls.STATUS_ACTIVE,
            cls.next_run <= now
        ).order_by(cls.next_run).all()

    @classmethod
    def get_upcoming_schedules(cls, hours: int = 24) -> List['CommunicationScheduler']:
        """
        Get upcoming scheduled communications within a time window.

        Args:
            hours: Number of hours to look ahead

        Returns:
            List[CommunicationScheduler]: List of upcoming schedules
        """
        cache_key = "upcoming_schedules"
        if hasattr(cache, 'get'):
            cached_data = cache.get(cache_key)
            if cached_data:
                return cached_data

        now = datetime.now(timezone.utc)
        end_time = now + timedelta(hours=hours)

        schedules = cls.query.filter(
            cls.status == cls.STATUS_ACTIVE,
            cls.next_run.between(now, end_time)
        ).order_by(cls.next_run).all()

        if hasattr(cache, 'set'):
            cache.set(cache_key, schedules, timeout=300)  # Cache for 5 minutes

        return schedules

    @classmethod
    def create_one_time_schedule(cls, name: str, channel_id: int, recipient_type: str,
                               scheduled_time: datetime, **kwargs) -> 'CommunicationScheduler':
        """
        Create a one-time scheduled communication.

        Args:
            name: Name of the scheduled communication
            channel_id: ID of the communication channel to use
            recipient_type: Type of recipients
            scheduled_time: When to send the communication
            **kwargs: Additional parameters for the schedule

        Returns:
            CommunicationScheduler: The created schedule
        """
        # Ensure scheduled_time is timezone-aware
        if scheduled_time.tzinfo is None:
            scheduled_time = scheduled_time.replace(tzinfo=timezone.utc)

        # Format as ISO string for storage
        schedule_data = {
            'datetime': scheduled_time.isoformat()
        }

        return cls(
            name=name,
            channel_id=channel_id,
            recipient_type=recipient_type,
            schedule_type=cls.TYPE_ONE_TIME,
            schedule_data=schedule_data,
            **kwargs
        )

    @classmethod
    def create_recurring_schedule(cls, name: str, channel_id: int, recipient_type: str,
                                cron_expression: str, **kwargs) -> 'CommunicationScheduler':
        """
        Create a recurring scheduled communication using cron expression.

        Args:
            name: Name of the scheduled communication
            channel_id: ID of the communication channel to use
            recipient_type: Type of recipients
            cron_expression: Cron expression for the schedule
            **kwargs: Additional parameters for the schedule

        Returns:
            CommunicationScheduler: The created schedule
        """
        # Validate cron expression
        try:
            croniter(cron_expression, datetime.now(timezone.utc))
        except (ValueError, KeyError):
            raise ValueError("Invalid cron expression")

        schedule_data = {
            'cron': cron_expression
        }

        return cls(
            name=name,
            channel_id=channel_id,
            recipient_type=recipient_type,
            schedule_type=cls.TYPE_RECURRING,
            schedule_data=schedule_data,
            **kwargs
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the scheduler to a dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary representation
        """
        result = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'channel_id': self.channel_id,
            'template_id': self.template_id,
            'subject': self.subject,
            'recipient_type': self.recipient_type,
            'schedule_type': self.schedule_type,
            'schedule_data': self.schedule_data,
            'timezone': self.timezone,
            'status': self.status,
            'run_count': self.run_count,
            'max_runs': self.max_runs,
            'success_count': self.success_count,
            'failure_count': self.failure_count,
            'last_error': self.last_error,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'next_run': self.next_run.isoformat() if self.next_run else None,
            'start_date': self.start_date.isoformat() if self.start_date else None,
            'end_date': self.end_date.isoformat() if self.end_date else None
        }

        # Add channel information if available
        if self.channel:
            result['channel_name'] = self.channel.name
            result['channel_type'] = self.channel.channel_type

        # Add template information if available
        if self.template:
            result['template_name'] = self.template.name

        # Add recipient data (excluding sensitive information)
        if self.recipient_data:
            # Filter out potentially sensitive fields
            safe_recipient_data = {}
            for key, value in self.recipient_data.items():
                if key.lower() not in ('password', 'token', 'secret', 'key', 'credential'):
                    safe_recipient_data[key] = value
            result['recipient_data'] = safe_recipient_data

        # Add context data (excluding sensitive information)
        if self.context_data:
            # Filter out potentially sensitive fields
            safe_context_data = {}
            for key, value in self.context_data.items():
                if key.lower() not in ('password', 'token', 'secret', 'key', 'credential'):
                    safe_context_data[key] = value
            result['context_data'] = safe_context_data

        return result

    def __repr__(self) -> str:
        """String representation of the scheduled communication."""
        return f"<CommunicationScheduler id={self.id} name='{self.name}' type='{self.schedule_type}' status='{self.status}'>"
