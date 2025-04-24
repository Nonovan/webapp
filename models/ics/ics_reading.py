"""
Industrial Control System (ICS) reading model.

This module defines the ICSReading model which represents sensor readings
and telemetry data collected from industrial control system devices.
These readings are critical for monitoring device performance, detecting
anomalies, and supporting operational decisions.

The model includes functionality for storing, validating, and analyzing
readings with features for anomaly detection and historical trending.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union, Tuple, cast
from sqlalchemy import and_, or_, func, desc, Float
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import relationship, validates
from flask import current_app

from extensions import db
from models.base import BaseModel
from core.security_utils import log_security_event


class ICSReading(BaseModel):
    """
    Represents a single reading from an ICS device sensor.

    This model stores individual data points collected from industrial control
    system devices, including metadata for analysis and anomaly detection.

    Attributes:
        id: Primary key
        device_id: Foreign key to the associated ICS device
        reading_type: Type of reading (temperature, pressure, etc.)
        value: Numerical value of the reading
        unit: Unit of measurement (C, bar, etc.)
        timestamp: When the reading was taken
        is_anomaly: Flag indicating if reading is outside expected range
        metadata: Additional reading information as JSON
        device: Relationship to parent ICSDevice
    """
    __tablename__ = 'ics_readings'

    # Reading type constants
    TYPE_TEMPERATURE = 'temperature'
    TYPE_PRESSURE = 'pressure'
    TYPE_HUMIDITY = 'humidity'
    TYPE_VOLTAGE = 'voltage'
    TYPE_CURRENT = 'current'
    TYPE_FLOW_RATE = 'flow_rate'
    TYPE_RPM = 'rpm'
    TYPE_POWER = 'power'
    TYPE_VIBRATION = 'vibration'
    TYPE_LEVEL = 'level'
    TYPE_PH = 'ph'
    TYPE_WEIGHT = 'weight'
    TYPE_POSITION = 'position'
    TYPE_RADIATION = 'radiation'
    TYPE_OTHER = 'other'

    READING_TYPES = [
        TYPE_TEMPERATURE, TYPE_PRESSURE, TYPE_HUMIDITY, TYPE_VOLTAGE,
        TYPE_CURRENT, TYPE_FLOW_RATE, TYPE_RPM, TYPE_POWER, TYPE_VIBRATION,
        TYPE_LEVEL, TYPE_PH, TYPE_WEIGHT, TYPE_POSITION, TYPE_RADIATION,
        TYPE_OTHER
    ]

    # Common units by reading type
    UNITS_BY_TYPE = {
        TYPE_TEMPERATURE: ['C', 'F', 'K'],
        TYPE_PRESSURE: ['bar', 'psi', 'kPa', 'MPa'],
        TYPE_HUMIDITY: ['%'],
        TYPE_VOLTAGE: ['V', 'mV', 'kV'],
        TYPE_CURRENT: ['A', 'mA'],
        TYPE_FLOW_RATE: ['L/min', 'm³/h', 'gpm'],
        TYPE_RPM: ['rpm'],
        TYPE_POWER: ['W', 'kW', 'MW'],
        TYPE_VIBRATION: ['mm/s', 'in/s', 'g'],
        TYPE_LEVEL: ['%', 'm', 'cm', 'mm', 'in'],
        TYPE_PH: ['pH'],
        TYPE_WEIGHT: ['kg', 'g', 'lb', 'ton'],
        TYPE_POSITION: ['°', 'rad', 'mm', 'cm', 'm'],
        TYPE_RADIATION: ['μSv/h', 'mSv/h', 'cpm'],
        TYPE_OTHER: []
    }

    # Core fields
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_id = db.Column(db.Integer, db.ForeignKey('ics_devices.id', ondelete='CASCADE'),
                          nullable=False, index=True)
    reading_type = db.Column(db.String(64), nullable=False, index=True)
    value = db.Column(db.Float, nullable=False)
    unit = db.Column(db.String(32), nullable=True)
    timestamp = db.Column(db.DateTime(timezone=True),
                         default=lambda: datetime.now(timezone.utc),
                         nullable=False, index=True)
    is_anomaly = db.Column(db.Boolean, default=False, nullable=False, index=True)
    metadata = db.Column(db.JSON, default=dict, nullable=True)

    # Relationship
    device = relationship('ICSDevice', back_populates='readings')

    def __init__(self, device_id: int, reading_type: str, value: float,
                unit: Optional[str] = None, timestamp: Optional[datetime] = None,
                is_anomaly: bool = False, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize a new ICS reading.

        Args:
            device_id: ID of the associated device
            reading_type: Type of reading (temperature, pressure, etc.)
            value: Numerical value of the reading
            unit: Unit of measurement (optional)
            timestamp: When the reading was taken (default: now)
            is_anomaly: Flag for anomalous readings (default: False)
            metadata: Additional reading information (optional)
        """
        self.device_id = device_id
        self.reading_type = reading_type
        self.value = value
        self.unit = unit
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.is_anomaly = is_anomaly
        self.metadata = metadata or {}

    @validates('reading_type')
    def validate_reading_type(self, key: str, reading_type: str) -> str:
        """
        Validate the reading type.

        Args:
            key: Field name being validated
            reading_type: Type of reading to validate

        Returns:
            str: Validated reading type, defaults to TYPE_OTHER if invalid
        """
        if not reading_type:
            current_app.logger.warning("Empty reading type provided, defaulting to 'other'")
            return self.TYPE_OTHER

        if reading_type not in self.READING_TYPES:
            current_app.logger.warning(f"Non-standard reading type: {reading_type}, defaulting to 'other'")
            return self.TYPE_OTHER

        return reading_type

    @validates('unit')
    def validate_unit(self, key: str, unit: Optional[str]) -> Optional[str]:
        """
        Validate the unit of measurement.

        Args:
            key: Field name being validated
            unit: Unit to validate

        Returns:
            Optional[str]: Validated unit
        """
        if unit is None:
            return None

        if not unit.strip():
            return None

        reading_type = getattr(self, 'reading_type', self.TYPE_OTHER)
        if reading_type in self.UNITS_BY_TYPE:
            standard_units = self.UNITS_BY_TYPE[reading_type]
            if standard_units and unit not in standard_units:
                current_app.logger.warning(f"Non-standard unit {unit} for {reading_type}")

        return unit.strip()

    @validates('value')
    def validate_value(self, key: str, value: float) -> float:
        """
        Validate the reading value.

        Args:
            key: Field name being validated
            value: Reading value to validate

        Returns:
            float: Validated value

        Raises:
            ValueError: If value is not a valid number
        """
        try:
            return float(value)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid reading value: {value}. Must be a valid number.")

    def detect_anomaly(self, threshold_config: Optional[Dict[str, Any]] = None) -> bool:
        """
        Detect if this reading is anomalous based on configured thresholds.

        Args:
            threshold_config: Configuration with thresholds for anomaly detection

        Returns:
            bool: True if anomalous, False otherwise
        """
        # Get threshold configuration, with defaults if not provided
        config = threshold_config or {}

        # Get device-specific thresholds from metadata
        if not config and self.device and hasattr(self.device, 'metadata'):
            device_metadata = getattr(self.device, 'metadata') or {}
            thresholds = device_metadata.get('thresholds', {})
            if thresholds and self.reading_type in thresholds:
                config = thresholds[self.reading_type]

        # If no configuration found, cannot detect anomaly
        if not config:
            return False

        # Get threshold values for this reading type
        min_threshold = config.get('min')
        max_threshold = config.get('max')

        # Check if reading is outside thresholds
        if (min_threshold is not None and self.value < min_threshold) or \
           (max_threshold is not None and self.value > max_threshold):
            return True

        return False

    def update_anomaly_status(self, threshold_config: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update the is_anomaly flag based on thresholds.

        Args:
            threshold_config: Configuration with thresholds

        Returns:
            bool: True if value was updated, False otherwise
        """
        new_status = self.detect_anomaly(threshold_config)
        if new_status != self.is_anomaly:
            self.is_anomaly = new_status

            try:
                db.session.add(self)
                db.session.commit()

                # Log anomaly for security monitoring if detected
                if new_status:
                    self._log_anomaly()

                return True

            except SQLAlchemyError as e:
                db.session.rollback()
                current_app.logger.error(f"Failed to update anomaly status: {str(e)}")
                return False

        return False

    def _log_anomaly(self) -> None:
        """
        Log anomalous reading to security monitoring system.
        """
        try:
            log_security_event(
                event_type='ics_reading_anomaly',
                description=f"Anomalous {self.reading_type} reading detected",
                severity='warning',
                details={
                    'reading_id': self.id,
                    'device_id': self.device_id,
                    'reading_type': self.reading_type,
                    'value': self.value,
                    'unit': self.unit,
                    'timestamp': self.timestamp.isoformat() if self.timestamp else None
                }
            )
        except Exception as e:
            current_app.logger.error(f"Failed to log anomaly: {str(e)}")

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert reading to dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary containing reading data
        """
        return {
            'id': self.id,
            'device_id': self.device_id,
            'reading_type': self.reading_type,
            'value': self.value,
            'unit': self.unit,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'is_anomaly': self.is_anomaly,
            'metadata': self.metadata
        }

    @classmethod
    def get_recent_by_device(cls, device_id: int, limit: int = 100) -> List['ICSReading']:
        """
        Get recent readings for a specific device.

        Args:
            device_id: ID of the device
            limit: Maximum number of readings to return

        Returns:
            List[ICSReading]: List of recent readings
        """
        if not device_id:
            return []

        return cls.query.filter_by(device_id=device_id)\
                 .order_by(cls.timestamp.desc())\
                 .limit(limit)\
                 .all()

    @classmethod
    def get_by_type(cls, device_id: int, reading_type: str,
                   limit: int = 100) -> List['ICSReading']:
        """
        Get readings of a specific type for a device.

        Args:
            device_id: ID of the device
            reading_type: Type of reading to retrieve
            limit: Maximum number of readings to return

        Returns:
            List[ICSReading]: List of readings
        """
        if not device_id or not reading_type:
            return []

        return cls.query.filter_by(device_id=device_id, reading_type=reading_type)\
                 .order_by(cls.timestamp.desc())\
                 .limit(limit)\
                 .all()

    @classmethod
    def get_by_time_range(cls, device_id: int, start_time: datetime,
                         end_time: Optional[datetime] = None,
                         reading_type: Optional[str] = None) -> List['ICSReading']:
        """
        Get readings for a device within a time range.

        Args:
            device_id: ID of the device
            start_time: Start of time range
            end_time: End of time range (default: now)
            reading_type: Optional reading type filter

        Returns:
            List[ICSReading]: List of readings
        """
        if not device_id or not start_time:
            return []

        if end_time is None:
            end_time = datetime.now(timezone.utc)

        query = cls.query.filter(
            cls.device_id == device_id,
            cls.timestamp >= start_time,
            cls.timestamp <= end_time
        )

        if reading_type:
            query = query.filter_by(reading_type=reading_type)

        return query.order_by(cls.timestamp).all()

    @classmethod
    def get_statistics(cls, device_id: int, reading_type: str,
                      start_time: Optional[datetime] = None,
                      end_time: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Calculate statistics for readings of a specific type.

        Args:
            device_id: ID of the device
            reading_type: Type of reading
            start_time: Start of time range (default: 24h ago)
            end_time: End of time range (default: now)

        Returns:
            Dict[str, Any]: Dictionary with statistics (min, max, avg, count)
        """
        if not device_id or not reading_type:
            return {
                'min': None,
                'max': None,
                'avg': None,
                'count': 0
            }

        if not start_time:
            start_time = datetime.now(timezone.utc) - timedelta(hours=24)

        if not end_time:
            end_time = datetime.now(timezone.utc)

        try:
            result = db.session.query(
                func.min(cls.value).label('min'),
                func.max(cls.value).label('max'),
                func.avg(cls.value).label('avg'),
                func.count(cls.id).label('count')
            ).filter(
                cls.device_id == device_id,
                cls.reading_type == reading_type,
                cls.timestamp >= start_time,
                cls.timestamp <= end_time
            ).first()

            if result:
                return {
                    'min': result.min,
                    'max': result.max,
                    'avg': float(result.avg) if result.avg is not None else None,
                    'count': result.count
                }
        except SQLAlchemyError as e:
            current_app.logger.error(f"Error retrieving statistics: {str(e)}")

        return {
            'min': None,
            'max': None,
            'avg': None,
            'count': 0
        }

    @classmethod
    def get_aggregated_by_hour(cls, device_id: int, reading_type: str,
                              days: int = 1) -> List[Dict[str, Any]]:
        """
        Get hourly aggregated readings.

        Args:
            device_id: ID of the device
            reading_type: Type of reading
            days: Number of days to include

        Returns:
            List[Dict[str, Any]]: List of hourly aggregated data points
        """
        if not device_id or not reading_type:
            return []

        if days <= 0:
            days = 1

        start_time = datetime.now(timezone.utc) - timedelta(days=days)

        try:
            # This query syntax may need to be adjusted based on your database backend
            results = db.session.query(
                func.date_trunc('hour', cls.timestamp).label('hour'),
                func.avg(cls.value).label('avg_value'),
                func.min(cls.value).label('min_value'),
                func.max(cls.value).label('max_value'),
                func.count(cls.id).label('reading_count')
            ).filter(
                cls.device_id == device_id,
                cls.reading_type == reading_type,
                cls.timestamp >= start_time
            ).group_by(
                func.date_trunc('hour', cls.timestamp)
            ).order_by(
                func.date_trunc('hour', cls.timestamp)
            ).all()

            return [
                {
                    'hour': result.hour.isoformat(),
                    'avg': float(result.avg_value) if result.avg_value else 0,
                    'min': result.min_value,
                    'max': result.max_value,
                    'count': result.reading_count
                } for result in results
            ]
        except SQLAlchemyError as e:
            current_app.logger.error(f"Error retrieving aggregated data: {str(e)}")
            return []

    @classmethod
    def get_anomalies_by_device(cls, device_id: int,
                              days: int = 1,
                              limit: int = 100) -> List['ICSReading']:
        """
        Get anomalous readings for a specific device.

        Args:
            device_id: ID of the device
            days: Number of days to include
            limit: Maximum number of readings to return

        Returns:
            List[ICSReading]: List of anomalous readings
        """
        if not device_id:
            return []

        if days <= 0:
            days = 1

        start_time = datetime.now(timezone.utc) - timedelta(days=days)

        return cls.query.filter(
            cls.device_id == device_id,
            cls.is_anomaly == True,
            cls.timestamp >= start_time
        ).order_by(cls.timestamp.desc()).limit(limit).all()

    def __repr__(self) -> str:
        """String representation of the ICSReading object."""
        return f"<ICSReading {self.id}: {self.reading_type} {self.value} {self.unit or ''} @ {self.timestamp}>"
