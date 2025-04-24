"""
Industrial Control System (ICS) control log model.

This module defines the ICSControlLog model which records all control operations
performed on Industrial Control System devices. These logs are critical for
security auditing, compliance reporting, and incident investigation.

The model provides a comprehensive audit trail of who did what to which device,
when they did it, and what changes were made, supporting security monitoring
and forensic analysis requirements.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union, Tuple
from sqlalchemy import and_, or_, func, desc
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import relationship, validates
from flask import current_app, has_request_context, request, g

from extensions import db
from models.base import BaseModel
from core.security_utils import log_security_event


class ICSControlLog(BaseModel):
    """
    Represents a control operation performed on an ICS device.

    This model records all control actions taken on ICS devices, providing
    an audit trail for security monitoring and compliance requirements.

    Attributes:
        id: Primary key
        device_id: Foreign key to the associated ICS device
        user_id: Foreign key to the user who performed the action
        action: Type of action performed (update_status, update_settings, etc.)
        value: New value or setting applied
        previous_value: Previous value or setting (for change tracking)
        ip_address: IP address of the user who initiated the action
        created_at: When the control operation was performed
        device: Relationship to parent ICSDevice
        user: Relationship to User who performed the action
    """
    __tablename__ = 'ics_control_logs'

    # Action type constants
    ACTION_UPDATE_STATUS = 'update_status'
    ACTION_UPDATE_SETTINGS = 'update_settings'
    ACTION_RESTART = 'restart'
    ACTION_SHUTDOWN = 'shutdown'
    ACTION_FIRMWARE_UPDATE = 'firmware_update'
    ACTION_CONFIGURATION_CHANGE = 'configuration_change'
    ACTION_CALIBRATION = 'calibration'
    ACTION_MAINTENANCE = 'maintenance'
    ACTION_OTHER = 'other'

    ACTIONS = [
        ACTION_UPDATE_STATUS, ACTION_UPDATE_SETTINGS, ACTION_RESTART,
        ACTION_SHUTDOWN, ACTION_FIRMWARE_UPDATE, ACTION_CONFIGURATION_CHANGE,
        ACTION_CALIBRATION, ACTION_MAINTENANCE, ACTION_OTHER
    ]

    # Security-sensitive actions that should trigger additional logging
    SECURITY_SENSITIVE_ACTIONS = [
        ACTION_UPDATE_SETTINGS, ACTION_FIRMWARE_UPDATE, ACTION_CONFIGURATION_CHANGE,
        ACTION_RESTART, ACTION_SHUTDOWN
    ]

    # Core fields
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_id = db.Column(db.Integer, db.ForeignKey('ics_devices.id', ondelete='CASCADE'),
                          nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'),
                        nullable=True, index=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    value = db.Column(db.String(255), nullable=True)
    previous_value = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    created_at = db.Column(db.DateTime(timezone=True),
                          default=lambda: datetime.now(timezone.utc),
                          nullable=False, index=True)

    # Relationships
    device = relationship('ICSDevice', back_populates='control_logs')
    user = relationship('User', backref=db.backref('ics_control_logs', lazy='dynamic'))

    def __init__(self, device_id: int, action: str, value: Optional[str] = None,
                previous_value: Optional[str] = None, user_id: Optional[int] = None,
                ip_address: Optional[str] = None) -> None:
        """
        Initialize a new ICS control log entry.

        Args:
            device_id: ID of the device being controlled
            action: Type of action performed
            value: New value or settings applied (optional)
            previous_value: Prior value or settings (optional)
            user_id: ID of the user performing the action (optional)
            ip_address: IP address of the user (optional, auto-detected if not provided)
        """
        self.device_id = device_id
        self.action = action
        self.value = value
        self.previous_value = previous_value
        self.user_id = user_id

        # Auto-detect IP address from request if not provided
        if ip_address:
            self.ip_address = ip_address
        elif has_request_context():
            self.ip_address = request.remote_addr

    @validates('action')
    def validate_action(self, key: str, action: str) -> str:
        """
        Validate the action type.

        Args:
            key: Field name being validated
            action: Action type to validate

        Returns:
            str: Validated action type

        Raises:
            ValueError: If action type is invalid
        """
        if not action:
            current_app.logger.warning("Empty action provided, defaulting to 'other'")
            return self.ACTION_OTHER

        if action not in self.ACTIONS:
            current_app.logger.warning(f"Non-standard ICS control action: {action}")
            return self.ACTION_OTHER
        return action

    @validates('device_id')
    def validate_device_id(self, key: str, device_id: int) -> int:
        """
        Validate the device ID.

        Args:
            key: Field name being validated
            device_id: Device ID to validate

        Returns:
            int: Validated device ID

        Raises:
            ValueError: If device ID is invalid
        """
        if not device_id or device_id <= 0:
            raise ValueError("Device ID must be a positive integer")
        return device_id

    @classmethod
    def log_action(cls, device_id: int, action: str, value: Optional[str] = None,
                  previous_value: Optional[str] = None, user_id: Optional[int] = None,
                  ip_address: Optional[str] = None, commit: bool = True) -> Optional['ICSControlLog']:
        """
        Create and save a new control log entry.

        Args:
            device_id: ID of the device being controlled
            action: Type of action performed
            value: New value or settings applied (optional)
            previous_value: Prior value or settings (optional)
            user_id: ID of the user performing the action (optional)
            ip_address: IP address of the user (optional)
            commit: Whether to commit the transaction (default: True)

        Returns:
            Optional[ICSControlLog]: The created log entry, or None if creation failed
        """
        if not device_id or not action:
            current_app.logger.error("Cannot log action: Missing required parameters")
            return None

        try:
            # Auto-detect user ID if not provided
            if user_id is None and has_request_context() and hasattr(g, 'user') and g.user:
                user_id = g.user.id

            log_entry = cls(
                device_id=device_id,
                action=action,
                value=value,
                previous_value=previous_value,
                user_id=user_id,
                ip_address=ip_address
            )

            db.session.add(log_entry)

            if commit:
                db.session.commit()

                # Log security event for sensitive actions
                if action in cls.SECURITY_SENSITIVE_ACTIONS:
                    cls._log_security_event(
                        log_entry.id, device_id, action, value, previous_value, user_id, ip_address
                    )

            return log_entry

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to create ICS control log: {str(e)}")
            return None

    @staticmethod
    def _log_security_event(log_id: int, device_id: int, action: str,
                          value: Optional[str], previous_value: Optional[str],
                          user_id: Optional[int], ip_address: Optional[str]) -> None:
        """
        Log a security event for sensitive control actions.

        Args:
            log_id: ID of the control log entry
            device_id: ID of the device
            action: Action performed
            value: New value
            previous_value: Previous value
            user_id: User ID
            ip_address: IP address
        """
        try:
            # Determine severity based on action type
            severity = "warning"
            if action in [ICSControlLog.ACTION_RESTART, ICSControlLog.ACTION_SHUTDOWN,
                          ICSControlLog.ACTION_FIRMWARE_UPDATE]:
                severity = "critical"

            # Create event description
            description = f"ICS device control action: {action}"

            # Log the security event
            log_security_event(
                event_type="ics_control_action",
                description=description,
                severity=severity,
                user_id=user_id,
                details={
                    "log_id": log_id,
                    "device_id": device_id,
                    "action": action,
                    "value": value,
                    "previous_value": previous_value,
                    "ip_address": ip_address
                }
            )
        except Exception as e:
            current_app.logger.error(f"Failed to log security event for control action: {str(e)}")

    @classmethod
    def get_by_device(cls, device_id: int, limit: int = 100) -> List['ICSControlLog']:
        """
        Get control logs for a specific device.

        Args:
            device_id: ID of the device
            limit: Maximum number of logs to return

        Returns:
            List[ICSControlLog]: List of control logs
        """
        if not device_id:
            return []

        return cls.query.filter_by(device_id=device_id)\
                 .order_by(cls.created_at.desc())\
                 .limit(limit)\
                 .all()

    @classmethod
    def get_by_user(cls, user_id: int, limit: int = 100) -> List['ICSControlLog']:
        """
        Get control logs for actions performed by a specific user.

        Args:
            user_id: ID of the user
            limit: Maximum number of logs to return

        Returns:
            List[ICSControlLog]: List of control logs
        """
        if not user_id:
            return []

        return cls.query.filter_by(user_id=user_id)\
                 .order_by(cls.created_at.desc())\
                 .limit(limit)\
                 .all()

    @classmethod
    def get_by_action(cls, action: str, limit: int = 100) -> List['ICSControlLog']:
        """
        Get control logs for a specific action type.

        Args:
            action: Type of action
            limit: Maximum number of logs to return

        Returns:
            List[ICSControlLog]: List of control logs
        """
        if not action:
            return []

        return cls.query.filter_by(action=action)\
                 .order_by(cls.created_at.desc())\
                 .limit(limit)\
                 .all()

    @classmethod
    def get_sensitive_actions(cls, days: int = 7, limit: int = 100) -> List['ICSControlLog']:
        """
        Get recent security-sensitive control actions.

        Args:
            days: Number of days to look back
            limit: Maximum number of logs to return

        Returns:
            List[ICSControlLog]: List of sensitive control logs
        """
        start_date = datetime.now(timezone.utc) - timedelta(days=days)

        return cls.query.filter(
            cls.action.in_(cls.SECURITY_SENSITIVE_ACTIONS),
            cls.created_at >= start_date
        ).order_by(cls.created_at.desc()).limit(limit).all()

    @classmethod
    def search(cls, query_params: Dict[str, Any],
              start_date: Optional[datetime] = None,
              end_date: Optional[datetime] = None,
              limit: int = 100) -> List['ICSControlLog']:
        """
        Search control logs with multiple filter criteria.

        Args:
            query_params: Dictionary of filter parameters (device_id, user_id, action)
            start_date: Start of date range for filtering
            end_date: End of date range for filtering
            limit: Maximum number of logs to return

        Returns:
            List[ICSControlLog]: List of matching control logs
        """
        filters = []

        # Add filters based on provided parameters
        for key, value in query_params.items():
            if hasattr(cls, key) and value is not None:
                filters.append(getattr(cls, key) == value)

        # Add date range filters if provided
        if start_date:
            filters.append(cls.created_at >= start_date)
        if end_date:
            filters.append(cls.created_at <= end_date)

        # Return query results with filters applied
        if filters:
            return cls.query.filter(and_(*filters))\
                     .order_by(cls.created_at.desc())\
                     .limit(limit)\
                     .all()
        else:
            return cls.query.order_by(cls.created_at.desc())\
                     .limit(limit)\
                     .all()

    @classmethod
    def get_action_summary(cls, start_date: Optional[datetime] = None,
                         end_date: Optional[datetime] = None) -> List[Tuple[str, int]]:
        """
        Get summary of actions grouped by action type.

        Args:
            start_date: Start of date range for filtering
            end_date: End of date range for filtering

        Returns:
            List[Tuple[str, int]]: List of (action_type, count) tuples
        """
        query = db.session.query(cls.action, func.count(cls.id).label('count'))

        if start_date:
            query = query.filter(cls.created_at >= start_date)
        if end_date:
            query = query.filter(cls.created_at <= end_date)

        return query.group_by(cls.action).order_by(desc('count')).all()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert control log to dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary containing control log data
        """
        return {
            'id': self.id,
            'device_id': self.device_id,
            'user_id': self.user_id,
            'action': self.action,
            'value': self.value,
            'previous_value': self.previous_value,
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self) -> str:
        """String representation of the ICSControlLog object."""
        return f"<ICSControlLog {self.id}: {self.action} on device {self.device_id}>"
