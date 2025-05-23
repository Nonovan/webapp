"""
Alert model for tracking and managing system alerts.

This module provides the Alert model which centralizes alert functionality across
the platform. It supports alert creation, acknowledgment, resolution, and integrates
with the notification system for delivering alerts through various channels.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Union
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy import desc, asc, and_, or_, func
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app

from extensions import db
from models.base import BaseModel
from core.security import log_security_event
from core.utils.validation import sanitize_html


class Alert(BaseModel):
    """
    Model for system alerts across the platform.

    This model represents alerts generated by various systems including monitoring,
    security, and infrastructure components. It tracks alert lifecycle from creation
    through acknowledgment to resolution.

    Attributes:
        id (int): Alert unique identifier
        alert_type (str): Type of alert (high_cpu, service_down, etc.)
        resource_id (str): ID of the affected resource, if any
        service_name (str): Name of the service generating the alert
        severity (str): Alert severity level (critical, high, warning, info)
        message (str): Human-readable alert message
        details (dict): Additional structured data about the alert
        status (str): Current alert status (active, acknowledged, resolved)
        created_at (datetime): When the alert was created
        environment (str): Environment where alert was generated (production, staging, etc.)
        region (str): Region where alert was generated
        acknowledged_by (str): User who acknowledged the alert
        acknowledged_at (datetime): When the alert was acknowledged
        acknowledgement_note (str): Note provided during acknowledgment
        resolved_by (str): User who resolved the alert
        resolved_at (datetime): When the alert was resolved
        resolution_note (str): Note provided during resolution
        resolution_type (str): Type of resolution (fixed, false_positive, etc.)
    """

    __tablename__ = 'alerts'

    # Alert severity levels
    SEVERITY_CRITICAL = 'critical'
    SEVERITY_HIGH = 'high'
    SEVERITY_WARNING = 'warning'
    SEVERITY_INFO = 'info'

    SEVERITIES = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_WARNING, SEVERITY_INFO]

    # Alert statuses
    STATUS_ACTIVE = 'active'
    STATUS_ACKNOWLEDGED = 'acknowledged'
    STATUS_RESOLVED = 'resolved'

    STATUSES = [STATUS_ACTIVE, STATUS_ACKNOWLEDGED, STATUS_RESOLVED]

    # Alert types
    TYPE_HIGH_CPU = 'high_cpu'
    TYPE_HIGH_MEMORY = 'high_memory'
    TYPE_HIGH_DISK = 'high_disk'
    TYPE_LOW_DISK = 'low_disk'
    TYPE_SERVICE_DOWN = 'service_down'
    TYPE_SECURITY_VULNERABILITY = 'security_vulnerability'
    TYPE_COST_INCREASE = 'cost_increase'
    TYPE_AVAILABILITY = 'availability'
    TYPE_PERFORMANCE = 'performance'
    TYPE_COMPLIANCE = 'compliance'
    TYPE_SYSTEM = 'system'

    ALERT_TYPES = [
        TYPE_HIGH_CPU, TYPE_HIGH_MEMORY, TYPE_HIGH_DISK, TYPE_LOW_DISK,
        TYPE_SERVICE_DOWN, TYPE_SECURITY_VULNERABILITY, TYPE_COST_INCREASE,
        TYPE_AVAILABILITY, TYPE_PERFORMANCE, TYPE_COMPLIANCE, TYPE_SYSTEM
    ]

    # Resolution types
    RESOLUTION_FIXED = 'fixed'
    RESOLUTION_FALSE_POSITIVE = 'false_positive'
    RESOLUTION_EXPECTED_BEHAVIOR = 'expected_behavior'
    RESOLUTION_OTHER = 'other'

    RESOLUTION_TYPES = [
        RESOLUTION_FIXED, RESOLUTION_FALSE_POSITIVE,
        RESOLUTION_EXPECTED_BEHAVIOR, RESOLUTION_OTHER
    ]

    # Table schema
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(64), nullable=False, index=True)
    resource_id = db.Column(db.String(128), nullable=True, index=True)
    service_name = db.Column(db.String(64), nullable=False, index=True)
    severity = db.Column(db.String(32), nullable=False, index=True)
    message = db.Column(db.String(500), nullable=False)
    details = db.Column(MutableDict.as_mutable(db.JSON), default=dict, nullable=False)
    status = db.Column(db.String(32), nullable=False, default=STATUS_ACTIVE, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    environment = db.Column(db.String(32), nullable=False, index=True)
    region = db.Column(db.String(64), nullable=True, index=True)
    acknowledged_by = db.Column(db.String(100), nullable=True)
    acknowledged_at = db.Column(db.DateTime(timezone=True), nullable=True)
    acknowledgement_note = db.Column(db.String(500), nullable=True)
    resolved_by = db.Column(db.String(100), nullable=True)
    resolved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    resolution_note = db.Column(db.String(1000), nullable=True)
    resolution_type = db.Column(db.String(32), nullable=True)

    def __init__(self, alert_type: str, service_name: str, severity: str, message: str,
                 environment: str, details: Optional[Dict[str, Any]] = None,
                 resource_id: Optional[str] = None, region: Optional[str] = None,
                 status: str = STATUS_ACTIVE, created_at: Optional[datetime] = None):
        """
        Initialize a new Alert instance.

        Args:
            alert_type: Type of alert
            service_name: Name of the service that generated the alert
            severity: Alert severity level
            message: Human-readable alert message
            environment: Environment where alert was generated
            details: Additional structured data about the alert (optional)
            resource_id: ID of the affected resource (optional)
            region: Region where alert was generated (optional)
            status: Initial alert status (default: 'active')
            created_at: When the alert was created (default: current time)

        Raises:
            ValueError: If severity or status is not one of the allowed values
        """
        if severity not in self.SEVERITIES:
            raise ValueError(f"Invalid severity level. Must be one of: {', '.join(self.SEVERITIES)}")

        if status not in self.STATUSES:
            raise ValueError(f"Invalid status. Must be one of: {', '.join(self.STATUSES)}")

        # Sanitize message to prevent XSS attacks
        sanitized_message = sanitize_html(message) if message else ""

        self.alert_type = alert_type
        self.service_name = service_name
        self.severity = severity
        self.message = sanitized_message
        self.environment = environment
        self.details = details or {}
        self.resource_id = resource_id
        self.region = region
        self.status = status
        self.created_at = created_at or datetime.now(timezone.utc)

    def acknowledge(self, user: str, note: Optional[str] = None) -> bool:
        """
        Acknowledge the alert.

        Args:
            user: User acknowledging the alert
            note: Optional acknowledgement note

        Returns:
            bool: True if acknowledgement was successful, False otherwise
        """
        try:
            if self.status == self.STATUS_ACTIVE:
                self.status = self.STATUS_ACKNOWLEDGED
                self.acknowledged_at = datetime.now(timezone.utc)
                self.acknowledged_by = user

                if note:
                    self.acknowledgement_note = sanitize_html(note)

                db.session.add(self)
                db.session.commit()

                # Log the security event
                try:
                    log_security_event(
                        event_type="alert_acknowledged",
                        description=f"Alert acknowledged: ID {self.id}",
                        severity=self.severity.lower(),
                        user_id=user,
                        details={
                            'alert_id': self.id,
                            'alert_type': self.alert_type,
                            'service': self.service_name
                        }
                    )
                except Exception as e:
                    current_app.logger.warning(f"Could not log security event: {str(e)}")

                return True
            else:
                current_app.logger.warning(f"Cannot acknowledge alert {self.id} with status {self.status}")
                return False

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to acknowledge alert: {str(e)}")
            return False

    def resolve(self, user: str, resolution_note: str, resolution_type: str = RESOLUTION_FIXED) -> bool:
        """
        Resolve the alert.

        Args:
            user: User resolving the alert
            resolution_note: Note explaining the resolution
            resolution_type: Type of resolution (default: 'fixed')

        Returns:
            bool: True if resolution was successful, False otherwise
        """
        try:
            if self.status in [self.STATUS_ACTIVE, self.STATUS_ACKNOWLEDGED]:
                self.status = self.STATUS_RESOLVED
                self.resolved_at = datetime.now(timezone.utc)
                self.resolved_by = user
                self.resolution_note = sanitize_html(resolution_note)

                if resolution_type in self.RESOLUTION_TYPES:
                    self.resolution_type = resolution_type
                else:
                    self.resolution_type = self.RESOLUTION_OTHER

                db.session.add(self)
                db.session.commit()

                # Log the security event
                try:
                    log_security_event(
                        event_type="alert_resolved",
                        description=f"Alert resolved: ID {self.id}",
                        severity=self.severity.lower(),
                        user_id=user,
                        details={
                            'alert_id': self.id,
                            'alert_type': self.alert_type,
                            'resolution_type': resolution_type,
                            'service': self.service_name
                        }
                    )
                except Exception as e:
                    current_app.logger.warning(f"Could not log security event: {str(e)}")

                return True
            else:
                current_app.logger.warning(f"Cannot resolve alert {self.id} with status {self.status}")
                return False

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to resolve alert: {str(e)}")
            return False

    def update_details(self, details_update: Dict[str, Any]) -> bool:
        """
        Update alert details.

        Args:
            details_update: Dictionary with fields to update

        Returns:
            bool: True if update was successful, False otherwise
        """
        try:
            if not details_update:
                return False

            current_details = self.details or {}
            current_details.update(details_update)
            self.details = current_details

            db.session.add(self)
            db.session.commit()
            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to update alert details: {str(e)}")
            return False

    def is_stale(self) -> bool:
        """
        Check if alert is stale and should be auto-acknowledged.

        Returns:
            bool: True if alert is stale, False otherwise
        """
        if self.status != self.STATUS_ACTIVE:
            return False

        auto_ack_hours = current_app.config.get('ALERT_AUTO_ACKNOWLEDGE_HOURS', {
            self.SEVERITY_INFO: 24,
            self.SEVERITY_WARNING: 48,
            self.SEVERITY_HIGH: 72,
            self.SEVERITY_CRITICAL: None  # Don't auto-acknowledge critical alerts
        })

        hours = auto_ack_hours.get(self.severity)
        if hours is None:
            return False

        age = datetime.now(timezone.utc) - self.created_at
        return age > timedelta(hours=hours)

    def get_time_since_created(self) -> timedelta:
        """
        Get time elapsed since alert was created.

        Returns:
            timedelta: Time since alert creation
        """
        return datetime.now(timezone.utc) - self.created_at

    def get_correlated_alerts(self) -> List[Dict[str, Any]]:
        """
        Get alerts correlated with this alert.

        Returns:
            List of dictionaries with correlated alert info
        """
        from models.alerts.alert_correlation import AlertCorrelation

        correlation_engine = AlertCorrelation()
        return correlation_engine.find_correlated_alerts(self.id)

    def is_correlated_to(self, other_alert_id: int) -> bool:
        """
        Check if this alert is correlated to another alert.

        Args:
            other_alert_id: ID of another alert

        Returns:
            True if alerts are correlated, False otherwise
        """
        try:
            # First check if correlation is already cached in details
            if self.details and 'correlated_alerts' in self.details:
                return other_alert_id in self.details['correlated_alerts']

            # Otherwise calculate correlation
            from models.alerts.alert_correlation import AlertCorrelation

            correlation_engine = AlertCorrelation()
            correlated = correlation_engine.find_correlated_alerts(self.id)
            return any(item['alert']['id'] == other_alert_id for item in correlated)

        except Exception as e:
            current_app.logger.error(f"Error checking alert correlation: {str(e)}")
            return False

    @classmethod
    def get_alert_groups(cls,
                        environment: Optional[str] = None,
                        max_alerts: int = 100) -> List[List[Dict[str, Any]]]:
        """
        Get alerts grouped by correlation.

        Args:
            environment: Optional environment filter
            max_alerts: Maximum number of alerts to retrieve

        Returns:
            List of alert groups, each group is a list of alert dictionaries
        """
        try:
            from models.alerts.alert_correlation import AlertCorrelation

            # Get active alerts
            query = cls.query.filter_by(status=cls.STATUS_ACTIVE)
            if environment:
                query = query.filter_by(environment=environment)

            # Order by severity and created time
            severity_ordering = db.case({
                cls.SEVERITY_CRITICAL: 1,
                cls.SEVERITY_HIGH: 2,
                cls.SEVERITY_WARNING: 3,
                cls.SEVERITY_INFO: 4
            }, value=cls.severity)

            alerts = query.order_by(severity_ordering, desc(cls.created_at)).limit(max_alerts).all()

            # Group alerts by similarity
            return AlertCorrelation.group_alerts_by_similarity(alerts)

        except Exception as e:
            current_app.logger.error(f"Error getting alert groups: {str(e)}")
            return []

    @classmethod
    def get_active_alerts(cls, environment: Optional[str] = None, severity: Optional[str] = None,
                        service_name: Optional[str] = None, limit: int = 100) -> List['Alert']:
        """
        Get active alerts with optional filtering.

        Args:
            environment: Filter by environment (optional)
            severity: Filter by severity (optional)
            service_name: Filter by service name (optional)
            limit: Maximum number of results to return

        Returns:
            List of Alert objects
        """
        query = cls.query.filter_by(status=cls.STATUS_ACTIVE)

        if environment:
            query = query.filter_by(environment=environment)

        if severity:
            if isinstance(severity, list):
                query = query.filter(cls.severity.in_(severity))
            else:
                query = query.filter_by(severity=severity)

        if service_name:
            query = query.filter_by(service_name=service_name)

        # Ensure limit is valid
        if not isinstance(limit, int) or limit <= 0:
            limit = 100

        # Order by severity (critical first) and then creation date
        severity_ordering = db.case({
            cls.SEVERITY_CRITICAL: 1,
            cls.SEVERITY_HIGH: 2,
            cls.SEVERITY_WARNING: 3,
            cls.SEVERITY_INFO: 4
        }, value=cls.severity)

        return query.order_by(severity_ordering, desc(cls.created_at)).limit(limit).all()

    @classmethod
    def get_alert_counts(cls, environment: Optional[str] = None,
                        days: int = 7) -> Dict[str, Any]:
        """
        Get alert counts by severity and status.

        Args:
            environment: Filter by environment (optional)
            days: Number of days to include

        Returns:
            Dictionary with alert counts
        """
        try:
            start_date = datetime.now(timezone.utc) - timedelta(days=days)
            query = cls.query.filter(cls.created_at >= start_date)

            if environment and environment != 'all':
                query = query.filter_by(environment=environment)

            result = {
                'total': 0,
                'by_severity': {
                    cls.SEVERITY_CRITICAL: 0,
                    cls.SEVERITY_HIGH: 0,
                    cls.SEVERITY_WARNING: 0,
                    cls.SEVERITY_INFO: 0
                },
                'by_status': {
                    cls.STATUS_ACTIVE: 0,
                    cls.STATUS_ACKNOWLEDGED: 0,
                    cls.STATUS_RESOLVED: 0
                },
                'by_service': {}
            }

            # Count by severity
            severity_counts = query.with_entities(
                cls.severity, func.count(cls.id)
            ).group_by(cls.severity).all()

            for severity, count in severity_counts:
                result['by_severity'][severity] = count
                result['total'] += count

            # Count by status
            status_counts = query.with_entities(
                cls.status, func.count(cls.id)
            ).group_by(cls.status).all()

            for status, count in status_counts:
                result['by_status'][status] = count

            # Count by service
            service_counts = query.with_entities(
                cls.service_name, func.count(cls.id)
            ).group_by(cls.service_name).all()

            for service, count in service_counts:
                result['by_service'][service] = count

            return result

        except SQLAlchemyError as e:
            current_app.logger.error(f"Error getting alert counts: {str(e)}")
            return {
                'total': 0,
                'by_severity': {},
                'by_status': {},
                'by_service': {},
                'error': str(e)
            }

    @classmethod
    def search_alerts(cls, search_term: Optional[str] = None,
                     status: Optional[Union[str, List[str]]] = None,
                     severity: Optional[Union[str, List[str]]] = None,
                     service_name: Optional[str] = None,
                     resource_id: Optional[str] = None,
                     environment: Optional[str] = None,
                     region: Optional[str] = None,
                     start_date: Optional[datetime] = None,
                     end_date: Optional[datetime] = None,
                     page: int = 1,
                     per_page: int = 20) -> Dict[str, Any]:
        """
        Search alerts with various filters and pagination.

        Args:
            search_term: Text search in message and details
            status: Filter by status
            severity: Filter by severity
            service_name: Filter by service name
            resource_id: Filter by resource ID
            environment: Filter by environment
            region: Filter by region
            start_date: Include alerts created on or after this date
            end_date: Include alerts created on or before this date
            page: Page number for pagination
            per_page: Number of results per page

        Returns:
            Dictionary with alerts and pagination info
        """
        try:
            query = cls.query

            # Apply text search if provided
            if search_term:
                search_term = f"%{search_term}%"
                query = query.filter(or_(
                    cls.message.ilike(search_term),
                    cls.service_name.ilike(search_term)
                ))

            # Filter by status
            if status:
                if isinstance(status, list):
                    query = query.filter(cls.status.in_(status))
                else:
                    query = query.filter_by(status=status)

            # Filter by severity
            if severity:
                if isinstance(severity, list):
                    query = query.filter(cls.severity.in_(severity))
                else:
                    query = query.filter_by(severity=severity)

            # Filter by service name
            if service_name:
                query = query.filter_by(service_name=service_name)

            # Filter by resource ID
            if resource_id:
                query = query.filter_by(resource_id=resource_id)

            # Filter by environment
            if environment:
                query = query.filter_by(environment=environment)

            # Filter by region
            if region:
                query = query.filter_by(region=region)

            # Filter by date range
            if start_date:
                query = query.filter(cls.created_at >= start_date)

            if end_date:
                query = query.filter(cls.created_at <= end_date)

            # Get total count before pagination
            total = query.count()

            # Validate pagination params
            if page < 1:
                page = 1

            if per_page < 1 or per_page > 100:
                per_page = 20

            # Apply pagination
            query = query.order_by(desc(cls.created_at))
            offset = (page - 1) * per_page
            alerts = query.offset(offset).limit(per_page).all()

            # Calculate pagination metadata
            total_pages = (total + per_page - 1) // per_page if per_page > 0 else 0

            return {
                'alerts': alerts,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'total_pages': total_pages,
                    'has_next': page < total_pages,
                    'has_prev': page > 1
                }
            }

        except SQLAlchemyError as e:
            current_app.logger.error(f"Error searching alerts: {str(e)}")
            return {
                'alerts': [],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': 0,
                    'total_pages': 0,
                    'has_next': False,
                    'has_prev': False
                },
                'error': str(e)
            }

    @classmethod
    def auto_acknowledge_stale_alerts(cls) -> int:
        """
        Find and auto-acknowledge stale alerts.

        Returns:
            Number of acknowledged alerts
        """
        try:
            # Get auto-acknowledgement hours
            auto_ack_hours = current_app.config.get('ALERT_AUTO_ACKNOWLEDGE_HOURS', {
                cls.SEVERITY_INFO: 24,
                cls.SEVERITY_WARNING: 48,
                cls.SEVERITY_HIGH: 72,
                cls.SEVERITY_CRITICAL: None  # Don't auto-acknowledge critical alerts
            })

            acknowledged_count = 0

            # Process each severity level
            for severity, hours in auto_ack_hours.items():
                if hours is None:
                    continue

                cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

                stale_alerts = cls.query.filter(
                    cls.status == cls.STATUS_ACTIVE,
                    cls.severity == severity,
                    cls.created_at < cutoff_time
                ).all()

                for alert in stale_alerts:
                    if alert.acknowledge(user="system", note="Auto-acknowledged due to age"):
                        acknowledged_count += 1

            return acknowledged_count

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error auto-acknowledging alerts: {str(e)}")
            return 0

    @classmethod
    def create_from_event(cls, event_data: Dict[str, Any]) -> Optional['Alert']:
        """
        Create an alert from an event dictionary.

        Args:
            event_data: Dictionary containing event data

        Returns:
            Created Alert or None if creation failed
        """
        try:
            required_fields = ['alert_type', 'service_name', 'severity', 'message', 'environment']
            for field in required_fields:
                if field not in event_data:
                    current_app.logger.error(f"Missing required field {field} for alert creation")
                    return None

            alert = cls(
                alert_type=event_data['alert_type'],
                service_name=event_data['service_name'],
                severity=event_data['severity'],
                message=event_data['message'],
                environment=event_data['environment'],
                details=event_data.get('details'),
                resource_id=event_data.get('resource_id'),
                region=event_data.get('region'),
                status=event_data.get('status', cls.STATUS_ACTIVE),
                created_at=event_data.get('created_at')
            )

            db.session.add(alert)
            db.session.commit()

            return alert

        except (ValueError, SQLAlchemyError) as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to create alert from event: {str(e)}")
            return None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert alert to dictionary for API responses.

        Returns:
            Dictionary representation of the alert
        """
        result = {
            'id': self.id,
            'alert_type': self.alert_type,
            'resource_id': self.resource_id,
            'service_name': self.service_name,
            'severity': self.severity,
            'message': self.message,
            'details': self.details,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'environment': self.environment,
            'region': self.region
        }

        # Add acknowledgement info if available
        if self.acknowledged_at:
            result.update({
                'acknowledged_by': self.acknowledged_by,
                'acknowledged_at': self.acknowledged_at.isoformat(),
                'acknowledgement_note': self.acknowledgement_note
            })

        # Add resolution info if available
        if self.resolved_at:
            result.update({
                'resolved_by': self.resolved_by,
                'resolved_at': self.resolved_at.isoformat(),
                'resolution_note': self.resolution_note,
                'resolution_type': self.resolution_type
            })

        return result

    def __repr__(self) -> str:
        """Return string representation of Alert object."""
        return f"<Alert id={self.id} type={self.alert_type} severity={self.severity} status={self.status}>"
