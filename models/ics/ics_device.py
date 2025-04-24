"""
Industrial Control System (ICS) device model.

This module defines the ICSDevice model which represents physical or virtual
industrial control system devices that can be monitored and controlled through
the Cloud Infrastructure Platform.

The model includes comprehensive security features, audit logging capabilities,
and device management functionality to ensure secure and reliable industrial
control system operations.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union, cast
from sqlalchemy import and_, or_, func
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import relationship, validates
from flask import current_app

from extensions import db
from models.base import BaseModel, AuditableMixin
from core.security_utils import log_security_event


class ICSDevice(BaseModel, AuditableMixin):
    """
    Represents an Industrial Control System device.

    This model tracks ICS devices, their status, and configuration to support
    secure operational technology (OT) integrations with IT infrastructure.

    Attributes:
        id: Primary key
        name: Human-readable device name
        device_type: Type of device (sensor, controller, actuator, etc.)
        location: Physical location of device
        ip_address: Network address (if applicable)
        protocol: Communication protocol used by the device
        status: Current operational status
        last_communication: When the system last connected to the device
        metadata: Additional device information as JSON
        settings: Device configuration as JSON
        created_at: When the device record was created
        updated_at: When the device record was last updated
        readings: Relationship to ICSReading records for this device
        control_logs: Relationship to ICSControlLog records for this device
    """
    __tablename__ = 'ics_devices'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['ip_address', 'protocol', 'settings']

    # Enable access auditing for this model due to its sensitive nature
    AUDIT_ACCESS = True

    # Device type constants
    TYPE_SENSOR = 'sensor'
    TYPE_CONTROLLER = 'controller'
    TYPE_ACTUATOR = 'actuator'
    TYPE_HMI = 'hmi'  # Human-Machine Interface
    TYPE_PLC = 'plc'  # Programmable Logic Controller
    TYPE_RTU = 'rtu'  # Remote Terminal Unit
    TYPE_GATEWAY = 'gateway'
    TYPE_OTHER = 'other'

    DEVICE_TYPES = [
        TYPE_SENSOR, TYPE_CONTROLLER, TYPE_ACTUATOR, TYPE_HMI,
        TYPE_PLC, TYPE_RTU, TYPE_GATEWAY, TYPE_OTHER
    ]

    # Status constants
    STATUS_ONLINE = 'online'
    STATUS_OFFLINE = 'offline'
    STATUS_MAINTENANCE = 'maintenance'
    STATUS_ERROR = 'error'
    STATUS_UNKNOWN = 'unknown'

    STATUSES = [STATUS_ONLINE, STATUS_OFFLINE, STATUS_MAINTENANCE, STATUS_ERROR, STATUS_UNKNOWN]

    # Protocol constants
    PROTOCOL_MODBUS = 'modbus'
    PROTOCOL_BACNET = 'bacnet'
    PROTOCOL_OPCUA = 'opcua'
    PROTOCOL_MQTT = 'mqtt'
    PROTOCOL_HTTP = 'http'
    PROTOCOL_PROFINET = 'profinet'
    PROTOCOL_ETHERNET_IP = 'ethernet_ip'
    PROTOCOL_OTHER = 'other'

    PROTOCOLS = [
        PROTOCOL_MODBUS, PROTOCOL_BACNET, PROTOCOL_OPCUA, PROTOCOL_MQTT,
        PROTOCOL_HTTP, PROTOCOL_PROFINET, PROTOCOL_ETHERNET_IP, PROTOCOL_OTHER
    ]

    # Core fields
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(128), nullable=False, index=True)
    device_type = db.Column(db.String(64), nullable=False, index=True)
    location = db.Column(db.String(128), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    protocol = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(32), nullable=False, default=STATUS_UNKNOWN, index=True)
    last_communication = db.Column(db.DateTime(timezone=True), nullable=True)

    # JSON data fields
    metadata = db.Column(MutableDict.as_mutable(db.JSON), default=dict, nullable=True)
    settings = db.Column(MutableDict.as_mutable(db.JSON), default=dict, nullable=True)

    # Timestamps (inherited from BaseModel via TimestampMixin)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True),
                          default=lambda: datetime.now(timezone.utc),
                          onupdate=lambda: datetime.now(timezone.utc),
                          nullable=False)

    # Relationships
    readings = relationship('ICSReading', back_populates='device', cascade='all, delete-orphan')
    control_logs = relationship('ICSControlLog', back_populates='device', cascade='all, delete-orphan')

    def __init__(self, name: str, device_type: str, protocol: str,
                location: Optional[str] = None, ip_address: Optional[str] = None,
                status: str = STATUS_UNKNOWN, metadata: Optional[Dict[str, Any]] = None,
                settings: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize a new ICS device.

        Args:
            name: Human-readable device name
            device_type: Type of device (sensor, controller, etc.)
            protocol: Communication protocol
            location: Physical location (optional)
            ip_address: Network address (optional)
            status: Current status (default: 'unknown')
            metadata: Additional device information
            settings: Device configuration
        """
        self.name = name
        self.device_type = device_type
        self.protocol = protocol
        self.location = location
        self.ip_address = ip_address
        self.status = status
        self.metadata = metadata or {}
        self.settings = settings or {}

    @validates('name')
    def validate_name(self, key: str, name: str) -> str:
        """
        Validate device name.

        Args:
            key: Field name being validated
            name: Device name to validate

        Returns:
            str: Validated device name

        Raises:
            ValueError: If name is empty or invalid
        """
        if not name or not name.strip():
            raise ValueError("Device name cannot be empty")

        if len(name.strip()) > 128:
            raise ValueError("Device name cannot exceed 128 characters")

        return name.strip()

    @validates('device_type')
    def validate_device_type(self, key: str, device_type: str) -> str:
        """
        Validate device type.

        Args:
            key: Field name being validated
            device_type: Device type to validate

        Returns:
            str: Validated device type

        Raises:
            ValueError: If device type is not in allowed types
        """
        if device_type not in self.DEVICE_TYPES:
            raise ValueError(f"Invalid device type: {device_type}. Must be one of: {', '.join(self.DEVICE_TYPES)}")
        return device_type

    @validates('protocol')
    def validate_protocol(self, key: str, protocol: str) -> str:
        """
        Validate communication protocol.

        Args:
            key: Field name being validated
            protocol: Protocol to validate

        Returns:
            str: Validated protocol

        Raises:
            ValueError: If protocol is not in allowed protocols
        """
        if protocol not in self.PROTOCOLS:
            raise ValueError(f"Invalid protocol: {protocol}. Must be one of: {', '.join(self.PROTOCOLS)}")
        return protocol

    @validates('status')
    def validate_status(self, key: str, status: str) -> str:
        """
        Validate device status.

        Args:
            key: Field name being validated
            status: Status to validate

        Returns:
            str: Validated status

        Raises:
            ValueError: If status is not in allowed statuses
        """
        if status not in self.STATUSES:
            raise ValueError(f"Invalid device status: {status}. Must be one of: {', '.join(self.STATUSES)}")
        return status

    @validates('ip_address')
    def validate_ip_address(self, key: str, ip_address: Optional[str]) -> Optional[str]:
        """
        Validate IP address if provided.

        Args:
            key: Field name being validated
            ip_address: IP address to validate

        Returns:
            Optional[str]: Validated IP address or None

        Raises:
            ValueError: If IP address format is invalid
        """
        if ip_address is None:
            return None

        ip_address = ip_address.strip()
        if not ip_address:
            return None

        # Simple validation - more comprehensive validation could be added
        if len(ip_address) > 45:  # Support IPv6
            raise ValueError("IP address too long")

        # Basic format validation
        if '.' in ip_address:  # IPv4
            octets = ip_address.split('.')
            if len(octets) != 4:
                raise ValueError("Invalid IPv4 address format")
        elif ':' in ip_address:  # IPv6
            if ip_address.count(':') < 2:
                raise ValueError("Invalid IPv6 address format")
        else:
            raise ValueError("IP address must be in IPv4 or IPv6 format")

        return ip_address

    def update_status(self, new_status: str, log_entry: bool = True,
                     user_id: Optional[int] = None) -> bool:
        """
        Update the device status and optionally create a control log entry.

        Args:
            new_status: New status value
            log_entry: Whether to create a control log entry
            user_id: ID of the user making the change (for auditing)

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if new_status not in self.STATUSES:
                raise ValueError(f"Invalid status: {new_status}")

            old_status = self.status
            self.status = new_status
            self.updated_at = datetime.now(timezone.utc)

            if new_status == self.STATUS_ONLINE:
                self.last_communication = datetime.now(timezone.utc)

            db.session.add(self)

            # Create control log if requested
            if log_entry:
                from models.ics.ics_control_log import ICSControlLog

                log = ICSControlLog(
                    device_id=self.id,
                    user_id=user_id,
                    action=ICSControlLog.ACTION_UPDATE_STATUS,
                    value=new_status,
                    previous_value=old_status
                )
                db.session.add(log)

            db.session.commit()

            # Log security event
            if new_status != old_status:
                self._log_status_change(old_status, new_status, user_id)

            return True

        except (ValueError, SQLAlchemyError) as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating device status: {str(e)}")
            return False

    def update_settings(self, settings: Dict[str, Any],
                       user_id: Optional[int] = None) -> bool:
        """
        Update device settings and create a control log entry.

        Args:
            settings: New settings dictionary
            user_id: ID of the user making the change (for auditing)

        Returns:
            bool: True if successful, False otherwise
        """
        if not settings:
            current_app.logger.warning("Empty settings dictionary provided")
            return False

        try:
            # Store original settings for logging
            original_settings = self.settings.copy() if self.settings else {}

            # Update settings
            if not self.settings:
                self.settings = settings
            else:
                self.settings.update(settings)

            self.updated_at = datetime.now(timezone.utc)
            db.session.add(self)

            # Create control log
            from models.ics.ics_control_log import ICSControlLog

            log = ICSControlLog(
                device_id=self.id,
                user_id=user_id,
                action=ICSControlLog.ACTION_UPDATE_SETTINGS,
                value=str(settings),
                previous_value=str(original_settings)
            )
            db.session.add(log)

            db.session.commit()

            # Log security event for settings changes
            self._log_settings_change(original_settings, settings, user_id)

            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating device settings: {str(e)}")
            return False

    def record_communication(self) -> bool:
        """
        Update the last communication timestamp.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            current_time = datetime.now(timezone.utc)
            self.last_communication = current_time
            self.updated_at = current_time
            db.session.add(self)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error recording device communication: {str(e)}")
            return False

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert device to dictionary representation.

        Returns:
            Dict: Dictionary containing device data
        """
        result = {
            'id': self.id,
            'name': self.name,
            'device_type': self.device_type,
            'location': self.location,
            'protocol': self.protocol,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_communication': self.last_communication.isoformat() if self.last_communication else None,
            'metadata': self.metadata,
        }

        # Only include IP address and settings if user has permission
        # This could be enhanced with more granular permission checks
        if hasattr(self, '_include_sensitive_data') and self._include_sensitive_data:
            result['ip_address'] = self.ip_address
            result['settings'] = self.settings

        return result

    def _log_status_change(self, old_status: str, new_status: str,
                          user_id: Optional[int] = None) -> None:
        """
        Log a security event for status changes.

        Args:
            old_status: Previous device status
            new_status: New device status
            user_id: ID of the user making the change (for auditing)
        """
        try:
            severity = 'info'
            if new_status == self.STATUS_ERROR:
                severity = 'warning'
            elif old_status == self.STATUS_ERROR and new_status != self.STATUS_ERROR:
                severity = 'info'
            elif new_status == self.STATUS_OFFLINE and old_status == self.STATUS_ONLINE:
                severity = 'warning'

            log_security_event(
                event_type='ics_device_status_change',
                description=f"ICS device '{self.name}' status changed from {old_status} to {new_status}",
                severity=severity,
                user_id=user_id,
                details={
                    'device_id': self.id,
                    'device_name': self.name,
                    'device_type': self.device_type,
                    'old_status': old_status,
                    'new_status': new_status
                }
            )
        except Exception as e:
            current_app.logger.error(f"Failed to log status change: {str(e)}")

    def _log_settings_change(self, old_settings: Dict[str, Any],
                            new_settings: Dict[str, Any],
                            user_id: Optional[int] = None) -> None:
        """
        Log a security event for settings changes.

        Args:
            old_settings: Previous device settings
            new_settings: New device settings
            user_id: ID of the user making the change (for auditing)
        """
        try:
            # Identify changed keys
            changed_keys = []
            for key in new_settings:
                if key not in old_settings or old_settings[key] != new_settings[key]:
                    changed_keys.append(key)

            # Look for removed keys too
            for key in old_settings:
                if key not in new_settings and key not in changed_keys:
                    changed_keys.append(key)

            if not changed_keys:
                return

            log_security_event(
                event_type='ics_device_settings_change',
                description=f"ICS device '{self.name}' settings changed",
                severity='warning',  # Settings changes are security-sensitive
                user_id=user_id,
                details={
                    'device_id': self.id,
                    'device_name': self.name,
                    'device_type': self.device_type,
                    'changed_keys': changed_keys
                }
            )
        except Exception as e:
            current_app.logger.error(f"Failed to log settings change: {str(e)}")

    @classmethod
    def get_by_name(cls, name: str) -> Optional['ICSDevice']:
        """
        Get a device by its name.

        Args:
            name: Device name to search for

        Returns:
            Optional[ICSDevice]: The device if found, None otherwise
        """
        if not name:
            return None

        return cls.query.filter(func.lower(cls.name) == func.lower(name.strip())).first()

    @classmethod
    def get_by_status(cls, status: Union[str, List[str]]) -> List['ICSDevice']:
        """
        Get devices by status(es).

        Args:
            status: Single status or list of statuses to filter by

        Returns:
            List[ICSDevice]: List of devices matching the status(es)
        """
        if isinstance(status, str):
            return cls.query.filter(cls.status == status).order_by(cls.name).all()
        else:
            return cls.query.filter(cls.status.in_(status)).order_by(cls.name).all()

    @classmethod
    def get_by_type(cls, device_type: Union[str, List[str]]) -> List['ICSDevice']:
        """
        Get devices by type(s).

        Args:
            device_type: Single type or list of types to filter by

        Returns:
            List[ICSDevice]: List of devices matching the type(s)
        """
        if isinstance(device_type, str):
            return cls.query.filter(cls.device_type == device_type).order_by(cls.name).all()
        else:
            return cls.query.filter(cls.device_type.in_(device_type)).order_by(cls.name).all()

    @classmethod
    def get_inactive_devices(cls, hours: int = 24) -> List['ICSDevice']:
        """
        Get devices that haven't communicated recently.

        Args:
            hours: Number of hours to consider for inactivity threshold

        Returns:
            List[ICSDevice]: List of inactive devices
        """
        threshold = datetime.now(timezone.utc) - datetime.timedelta(hours=hours)
        return cls.query.filter(
            or_(
                cls.last_communication < threshold,
                cls.last_communication.is_(None)
            )
        ).order_by(cls.name).all()

    @classmethod
    def search(cls, query: str, limit: int = 20) -> List['ICSDevice']:
        """
        Search for devices by name or location.

        Args:
            query: Search term
            limit: Maximum results to return

        Returns:
            List[ICSDevice]: Matching devices
        """
        if not query:
            return []

        search_term = f"%{query.lower()}%"
        return cls.query.filter(
            or_(
                func.lower(cls.name).like(search_term),
                func.lower(cls.location).like(search_term)
            )
        ).order_by(cls.name).limit(limit).all()

    def __repr__(self) -> str:
        """String representation of the ICSDevice object."""
        return f"<ICSDevice {self.id}: {self.name} ({self.device_type})>"
