"""
Cloud alert model for cloud resource monitoring and notifications.

This module provides the CloudAlert model which tracks alerts and notifications
related to cloud infrastructure resources. It supports alerting on resource metrics,
status changes, and security events to enable proactive monitoring and incident response.
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Union
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy import desc, and_, or_
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app

from extensions import db, metrics
from models.base import BaseModel


class CloudAlert(BaseModel):
    """
    Model representing a cloud infrastructure alert.

    This model captures alert conditions, status, and related metadata for cloud
    infrastructure monitoring. Alerts can be generated from metrics, status changes,
    or security events and can trigger notifications to users.

    Attributes:
        id: Primary key
        title: Alert title
        description: Detailed description of the alert
        severity: Alert severity level (info, warning, error, critical)
        status: Current alert status (active, acknowledged, resolved)
        resource_id: Related cloud resource ID
        provider_id: Related cloud provider ID
        acknowledged_at: When the alert was acknowledged
        acknowledged_by_id: User ID who acknowledged the alert
        resolved_at: When the alert was resolved
        resolved_by_id: User ID who resolved the alert
        metrics: JSON data containing related metrics
        metadata: JSON data containing additional alert metadata
        source: Alert source system or component
        notification_sent: Whether notification has been sent
    """
    __tablename__ = 'cloud_alerts'

    # Alert severities
    SEVERITY_INFO = 'info'
    SEVERITY_WARNING = 'warning'
    SEVERITY_ERROR = 'error'
    SEVERITY_CRITICAL = 'critical'

    SEVERITIES = [SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_ERROR, SEVERITY_CRITICAL]

    # Alert statuses
    STATUS_ACTIVE = 'active'
    STATUS_ACKNOWLEDGED = 'acknowledged'
    STATUS_RESOLVED = 'resolved'

    STATUSES = [STATUS_ACTIVE, STATUS_ACKNOWLEDGED, STATUS_RESOLVED]

    # Alert types for common categorization
    TYPE_METRIC = 'metric_threshold'
    TYPE_SECURITY = 'security_vulnerability'
    TYPE_COST = 'cost_increase'
    TYPE_AVAILABILITY = 'availability'
    TYPE_PERFORMANCE = 'performance'
    TYPE_COMPLIANCE = 'compliance'
    TYPE_SYSTEM = 'system'

    ALERT_TYPES = [TYPE_METRIC, TYPE_SECURITY, TYPE_COST,
                  TYPE_AVAILABILITY, TYPE_PERFORMANCE,
                  TYPE_COMPLIANCE, TYPE_SYSTEM]

    # Table definition
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(32), nullable=False, default=SEVERITY_WARNING, index=True)
    status = db.Column(db.String(32), nullable=False, default=STATUS_ACTIVE, index=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('cloud_resources.id', ondelete='SET NULL'), nullable=True, index=True)
    provider_id = db.Column(db.Integer, db.ForeignKey('cloud_providers.id', ondelete='SET NULL'), nullable=True, index=True)
    acknowledged_at = db.Column(db.DateTime(timezone=True), nullable=True)
    acknowledged_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    resolved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    resolved_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    metrics = db.Column(MutableDict.as_mutable(db.JSON), default=dict, nullable=False)
    metadata = db.Column(MutableDict.as_mutable(db.JSON), default=dict, nullable=False)
    source = db.Column(db.String(64), nullable=False, default='monitoring')
    notification_sent = db.Column(db.Boolean, default=False, nullable=False)
    alert_type = db.Column(db.String(64), nullable=False, default=TYPE_SYSTEM, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True),
                          default=lambda: datetime.now(timezone.utc),
                          onupdate=lambda: datetime.now(timezone.utc),
                          nullable=False)

    # Relationships
    provider = db.relationship('CloudProvider', backref=db.backref('alerts', lazy='dynamic'))
    resource = db.relationship('CloudResource', backref=db.backref('alerts', lazy='dynamic'))
    acknowledged_by = db.relationship('User', foreign_keys=[acknowledged_by_id],
                                    backref=db.backref('acknowledged_alerts', lazy='dynamic'))
    resolved_by = db.relationship('User', foreign_keys=[resolved_by_id],
                                backref=db.backref('resolved_alerts', lazy='dynamic'))

    def __init__(self, title: str, description: str, severity: str = SEVERITY_WARNING,
                resource_id: Optional[int] = None, provider_id: Optional[int] = None,
                alert_metrics: Optional[Dict] = None, metadata: Optional[Dict] = None,
                source: str = 'monitoring', alert_type: str = TYPE_SYSTEM):
        """
        Initialize a CloudAlert instance.

        Args:
            title: Alert title
            description: Detailed alert description
            severity: Alert severity level (info, warning, error, critical)
            resource_id: Related cloud resource ID (optional)
            provider_id: Related cloud provider ID (optional)
            alert_metrics: Related metrics data
            metadata: Additional alert metadata
            source: Alert source (monitoring, system, user, etc.)
            alert_type: Type of the alert for categorization

        Raises:
            ValueError: If severity is not one of the allowed values
        """
        if severity not in self.SEVERITIES:
            raise ValueError(f"Invalid severity. Must be one of: {', '.join(self.SEVERITIES)}")

        if alert_type and alert_type not in self.ALERT_TYPES:
            current_app.logger.warning(f"Non-standard alert type: {alert_type}")

        self.title = title
        self.description = description
        self.severity = severity
        self.resource_id = resource_id
        self.provider_id = provider_id
        self.metrics = alert_metrics or {}
        self.metadata = metadata or {}
        self.source = source
        self.status = self.STATUS_ACTIVE
        self.alert_type = alert_type

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert alert to dictionary for API responses.

        Returns:
            Dict[str, Any]: Dictionary representation of the alert
        """
        resource_name = None
        provider_name = None

        if self.resource:
            resource_name = self.resource.name

        if self.provider:
            provider_name = self.provider.name

        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'resource_id': self.resource_id,
            'resource_name': resource_name,
            'provider_id': self.provider_id,
            'provider_name': provider_name,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'acknowledged_by_id': self.acknowledged_by_id,
            'acknowledged_by_name': self.acknowledged_by.name if self.acknowledged_by else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolved_by_id': self.resolved_by_id,
            'resolved_by_name': self.resolved_by.name if self.resolved_by else None,
            'metrics': self.metrics,
            'metadata': self.metadata,
            'source': self.source,
            'alert_type': self.alert_type,
            'notification_sent': self.notification_sent
        }

    def acknowledge(self, user_id: int) -> bool:
        """
        Acknowledge the alert.

        Args:
            user_id: ID of the user acknowledging the alert

        Returns:
            bool: True if acknowledgment was successful, False otherwise
        """
        try:
            if self.status == self.STATUS_ACTIVE:
                self.status = self.STATUS_ACKNOWLEDGED
                self.acknowledged_at = datetime.now(timezone.utc)
                self.acknowledged_by_id = user_id

                # Track metrics if available
                if metrics:
                    try:
                        metrics.counter('cloud_alerts_acknowledged_total', 1, {
                            'severity': self.severity,
                            'source': self.source,
                            'alert_type': self.alert_type
                        })
                    except Exception as e:
                        current_app.logger.warning(f"Failed to record metrics: {str(e)}")

                db.session.add(self)
                db.session.commit()

                # Create audit log entry
                try:
                    from models.audit_log import AuditLog
                    AuditLog.create(
                        event_type='alert_acknowledged',
                        user_id=user_id,
                        object_type='CloudAlert',
                        object_id=self.id,
                        description=f"Alert '{self.title}' acknowledged",
                        details={
                            'alert_id': self.id,
                            'severity': self.severity,
                            'resource_id': self.resource_id,
                            'provider_id': self.provider_id
                        }
                    )
                except (ImportError, AttributeError) as e:
                    current_app.logger.warning(f"Could not create audit log: {str(e)}")

                return True
            return False
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to acknowledge alert: {str(e)}")
            return False

    def resolve(self, user_id: int, resolution_note: Optional[str] = None) -> bool:
        """
        Resolve the alert.

        Args:
            user_id: ID of the user resolving the alert
            resolution_note: Optional note about how the alert was resolved

        Returns:
            bool: True if resolution was successful, False otherwise
        """
        try:
            if self.status != self.STATUS_RESOLVED:
                self.status = self.STATUS_RESOLVED
                self.resolved_at = datetime.now(timezone.utc)
                self.resolved_by_id = user_id

                if resolution_note:
                    if 'resolution_notes' not in self.metadata:
                        self.metadata['resolution_notes'] = []
                    self.metadata['resolution_notes'].append({
                        'note': resolution_note,
                        'user_id': user_id,
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    })

                # Track metrics if available
                if metrics:
                    try:
                        metrics.counter('cloud_alerts_resolved_total', 1, {
                            'severity': self.severity,
                            'source': self.source,
                            'alert_type': self.alert_type
                        })

                        # Track resolution time if we have both created_at and resolved_at
                        if self.created_at and self.resolved_at:
                            resolution_time = (self.resolved_at - self.created_at).total_seconds()
                            metrics.histogram('cloud_alerts_resolution_time_seconds', resolution_time, {
                                'severity': self.severity,
                                'alert_type': self.alert_type
                            })
                    except Exception as e:
                        current_app.logger.warning(f"Failed to record metrics: {str(e)}")

                db.session.add(self)
                db.session.commit()

                # Create audit log entry
                try:
                    from models.audit_log import AuditLog
                    AuditLog.create(
                        event_type='alert_resolved',
                        user_id=user_id,
                        object_type='CloudAlert',
                        object_id=self.id,
                        description=f"Alert '{self.title}' resolved",
                        details={
                            'alert_id': self.id,
                            'severity': self.severity,
                            'resource_id': self.resource_id,
                            'provider_id': self.provider_id,
                            'has_resolution_note': resolution_note is not None
                        }
                    )
                except (ImportError, AttributeError) as e:
                    current_app.logger.warning(f"Could not create audit log: {str(e)}")

                return True
            return False
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to resolve alert: {str(e)}")
            return False

    def send_notification(self) -> bool:
        """
        Send notification for this alert.

        Returns:
            bool: True if notification was sent successfully, False otherwise
        """
        if self.notification_sent:
            return True

        try:
            # Create notification
            from models.notification import Notification

            # Determine notification priority based on severity
            priority_map = {
                self.SEVERITY_INFO: 'low',
                self.SEVERITY_WARNING: 'medium',
                self.SEVERITY_ERROR: 'high',
                self.SEVERITY_CRITICAL: 'critical'  # Changed from 'urgent' to match with notification constants
            }
            priority = priority_map.get(self.severity, 'medium')

            # If there's a resource, notify its creator
            user_ids = []
            if self.resource_id:
                from models.cloud_resource import CloudResource
                resource = CloudResource.query.get(self.resource_id)
                if resource and resource.created_by_id:
                    user_ids.append(resource.created_by_id)

            # Also notify admins and security team for high severity alerts
            if self.severity in (self.SEVERITY_ERROR, self.SEVERITY_CRITICAL):
                from models.user import User
                admin_roles = ['admin']

                # Add security team for security alerts
                if self.alert_type == self.TYPE_SECURITY:
                    admin_roles.append('security_analyst')

                # Add finance team for cost alerts
                if self.alert_type == self.TYPE_COST:
                    admin_roles.append('finance_manager')

                # Query users with the required roles
                admin_users = User.query.filter(User.role.in_(admin_roles)).all()
                admin_ids = [u.id for u in admin_users]
                user_ids.extend(admin_ids)

            # Deduplicate user IDs
            user_ids = list(set(user_ids))

            # Track the notifications
            successful_notifications = 0

            # Send notification to each user
            for user_id in user_ids:
                notification = Notification.create_notification(
                    user_id=user_id,
                    title=f"Cloud Alert: {self.title}",
                    message=self.description,
                    notification_type=f"alert_{self.severity}",
                    priority=priority,
                    action_url=f"/cloud/alerts/{self.id}",
                    data={
                        'alert_id': self.id,
                        'alert_type': self.alert_type,
                        'severity': self.severity,
                        'resource_id': self.resource_id,
                        'provider_id': self.provider_id
                    }
                )

                if notification:
                    successful_notifications += 1

            # Mark as sent if we created at least one notification or there were no recipients
            if successful_notifications > 0 or len(user_ids) == 0:
                self.notification_sent = True
                db.session.add(self)
                db.session.commit()

                # Track metric
                if metrics:
                    try:
                        metrics.counter('cloud_alert_notifications_sent_total', successful_notifications, {
                            'severity': self.severity,
                            'alert_type': self.alert_type
                        })
                    except Exception as e:
                        current_app.logger.warning(f"Failed to record metrics: {str(e)}")

                return True
            return False

        except (SQLAlchemyError, KeyError, AttributeError, ImportError) as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to send alert notification: {str(e)}")
            return False

    def escalate(self) -> bool:
        """
        Escalate an unacknowledged alert to a higher severity level.

        Returns:
            bool: True if escalation was successful, False otherwise
        """
        if self.status != self.STATUS_ACTIVE:
            return False

        try:
            original_severity = self.severity

            # Determine new severity
            if self.severity == self.SEVERITY_INFO:
                self.severity = self.SEVERITY_WARNING
            elif self.severity == self.SEVERITY_WARNING:
                self.severity = self.SEVERITY_ERROR
            elif self.severity == self.SEVERITY_ERROR:
                self.severity = self.SEVERITY_CRITICAL
            else:
                # Already at max severity
                return False

            # Add escalation info to metadata
            if 'escalation_history' not in self.metadata:
                self.metadata['escalation_history'] = []

            self.metadata['escalation_history'].append({
                'from_severity': original_severity,
                'to_severity': self.severity,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'reason': 'auto_escalation'
            })

            # Update the alert
            db.session.add(self)
            db.session.commit()

            # Send new notification with escalated severity
            self.notification_sent = False
            self.send_notification()

            # Create audit log entry
            try:
                from models.audit_log import AuditLog
                AuditLog.create(
                    event_type='alert_escalated',
                    user_id=None,  # System-initiated
                    object_type='CloudAlert',
                    object_id=self.id,
                    description=f"Alert '{self.title}' escalated from {original_severity} to {self.severity}"
                )
            except (ImportError, AttributeError) as e:
                current_app.logger.warning(f"Could not create audit log: {str(e)}")

            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to escalate alert: {str(e)}")
            return False

    @classmethod
    def get_active_alerts(cls, resource_id: Optional[int] = None,
                        provider_id: Optional[int] = None,
                        severity: Optional[str] = None,
                        alert_type: Optional[str] = None,
                        limit: int = 100) -> List['CloudAlert']:
        """
        Get active alerts with optional filtering.

        Args:
            resource_id: Filter by specific resource ID
            provider_id: Filter by specific provider ID
            severity: Filter by alert severity
            alert_type: Filter by alert type
            limit: Maximum number of alerts to return

        Returns:
            List[CloudAlert]: List of active alerts
        """
        query = cls.query.filter(cls.status != cls.STATUS_RESOLVED)

        if resource_id is not None:
            query = query.filter_by(resource_id=resource_id)

        if provider_id is not None:
            query = query.filter_by(provider_id=provider_id)

        if severity is not None:
            if isinstance(severity, list):
                query = query.filter(cls.severity.in_(severity))
            else:
                query = query.filter_by(severity=severity)

        if alert_type is not None:
            if isinstance(alert_type, list):
                query = query.filter(cls.alert_type.in_(alert_type))
            else:
                query = query.filter_by(alert_type=alert_type)

        # Validate limit parameter
        if not isinstance(limit, int) or limit <= 0:
            limit = 100

        return query.order_by(
            # Order by severity (critical first), then by creation date
            desc(db.case({
                cls.SEVERITY_CRITICAL: 4,
                cls.SEVERITY_ERROR: 3,
                cls.SEVERITY_WARNING: 2,
                cls.SEVERITY_INFO: 1
            }, value=cls.severity)),
            desc(cls.created_at)
        ).limit(limit).all()

    @classmethod
    def get_alerts_summary(cls) -> Dict[str, Any]:
        """
        Get summary of alerts by status and severity.

        Returns:
            Dict[str, Any]: Dictionary with alert counts
        """
        try:
            result = {
                'total': 0,
                'active': 0,
                'acknowledged': 0,
                'resolved': 0,
                'by_severity': {
                    cls.SEVERITY_CRITICAL: 0,
                    cls.SEVERITY_ERROR: 0,
                    cls.SEVERITY_WARNING: 0,
                    cls.SEVERITY_INFO: 0
                },
                'by_type': {}
            }

            # Get total counts by status
            status_counts = db.session.query(
                cls.status, db.func.count(cls.id)
            ).group_by(cls.status).all()

            for status, count in status_counts:
                result[status] = count
                result['total'] += count

            # Get counts by severity for active and acknowledged alerts
            severity_counts = db.session.query(
                cls.severity, db.func.count(cls.id)
            ).filter(cls.status != cls.STATUS_RESOLVED).group_by(cls.severity).all()

            for severity, count in severity_counts:
                if severity in result['by_severity']:
                    result['by_severity'][severity] = count

            # Get counts by alert type for active and acknowledged alerts
            type_counts = db.session.query(
                cls.alert_type, db.func.count(cls.id)
            ).filter(cls.status != cls.STATUS_RESOLVED).group_by(cls.alert_type).all()

            for alert_type, count in type_counts:
                result['by_type'][alert_type] = count

            return result

        except SQLAlchemyError as e:
            current_app.logger.error(f"Error getting alerts summary: {str(e)}")
            return {
                'total': 0,
                'active': 0,
                'acknowledged': 0,
                'resolved': 0,
                'by_severity': {
                    cls.SEVERITY_CRITICAL: 0,
                    cls.SEVERITY_ERROR: 0,
                    cls.SEVERITY_WARNING: 0,
                    cls.SEVERITY_INFO: 0
                },
                'by_type': {},
                'error': str(e)
            }

    @classmethod
    def create_from_metric(cls, metric_name: str, value: float, threshold: float,
                         resource_id: int, provider_id: int,
                         severity: str = SEVERITY_WARNING) -> Optional['CloudAlert']:
        """
        Create an alert from a metric threshold violation.

        Args:
            metric_name: Name of the metric
            value: Current value of the metric
            threshold: Threshold value that was exceeded
            resource_id: ID of the related resource
            provider_id: ID of the cloud provider
            severity: Alert severity level

        Returns:
            Optional[CloudAlert]: Created alert or None if creation failed
        """
        try:
            from models.cloud_resource import CloudResource
            resource = CloudResource.query.get(resource_id)

            if not resource:
                current_app.logger.warning(f"Cannot create alert: resource {resource_id} not found")
                return None

            # Format the metric name for display
            display_metric_name = metric_name.replace('_', ' ').title()

            title = f"{display_metric_name} Alert"
            description = (f"{display_metric_name} alert for {resource.name}: "
                         f"Current value {value:.2f} exceeds threshold of {threshold:.2f}")

            alert = cls(
                title=title,
                description=description,
                severity=severity,
                resource_id=resource_id,
                provider_id=provider_id,
                alert_metrics={
                    'name': metric_name,
                    'value': float(value),
                    'threshold': float(threshold),
                    'units': resource.metadata.get('metric_units', {}).get(metric_name, ''),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                },
                source='metric_monitor',
                alert_type=cls.TYPE_METRIC
            )

            db.session.add(alert)
            db.session.commit()

            # Track metric if available
            if metrics:
                try:
                    metrics.counter('cloud_alerts_created_total', 1, {
                        'severity': severity,
                        'type': cls.TYPE_METRIC,
                        'metric_name': metric_name
                    })
                except Exception as e:
                    current_app.logger.warning(f"Failed to record metrics: {str(e)}")

            # Send notification asynchronously or via task queue in production
            alert.send_notification()

            return alert

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to create metric alert: {str(e)}")
            return None

    @classmethod
    def create(cls, resource_id: Optional[int] = None, provider_id: Optional[int] = None,
              alert_type: str = TYPE_SYSTEM, severity: str = SEVERITY_WARNING,
              message: str = '', details: Optional[Dict[str, Any]] = None) -> Optional['CloudAlert']:
        """
        Create a new alert with standardized formatting.

        Args:
            resource_id: ID of the related cloud resource
            provider_id: ID of the cloud provider
            alert_type: Type of alert being created
            severity: Severity level of the alert
            message: Alert message content
            details: Additional details about the alert

        Returns:
            Optional[CloudAlert]: Created alert or None if creation failed
        """
        try:
            # Default title based on alert type if not in details
            if not details:
                details = {}

            title_map = {
                cls.TYPE_METRIC: "Metric Alert",
                cls.TYPE_SECURITY: "Security Alert",
                cls.TYPE_COST: "Cost Alert",
                cls.TYPE_AVAILABILITY: "Availability Alert",
                cls.TYPE_PERFORMANCE: "Performance Alert",
                cls.TYPE_COMPLIANCE: "Compliance Alert",
                cls.TYPE_SYSTEM: "System Alert"
            }

            title = details.get('title', title_map.get(alert_type, "Cloud Alert"))

            # Get resource name if available
            resource_name = "Unknown"
            if resource_id:
                from models.cloud_resource import CloudResource
                resource = CloudResource.query.get(resource_id)
                if resource:
                    resource_name = resource.name

                    # If provider_id wasn't provided, get it from the resource
                    if provider_id is None:
                        provider_id = resource.provider_id

            # Create the alert
            alert = cls(
                title=title,
                description=message,
                severity=severity,
                resource_id=resource_id,
                provider_id=provider_id,
                metadata=details,
                source=details.get('source', 'system'),
                alert_type=alert_type
            )

            db.session.add(alert)
            db.session.commit()

            # Send notification
            alert.send_notification()

            return alert

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to create alert: {str(e)}")
            return None

    @classmethod
    def get_alerts_by_resource(cls, resource_id: int,
                             include_resolved: bool = False,
                             limit: int = 50) -> List['CloudAlert']:
        """
        Get alerts for a specific resource.

        Args:
            resource_id: ID of the resource to get alerts for
            include_resolved: Whether to include resolved alerts
            limit: Maximum number of alerts to return

        Returns:
            List[CloudAlert]: List of alerts for the resource
        """
        query = cls.query.filter_by(resource_id=resource_id)

        if not include_resolved:
            query = query.filter(cls.status != cls.STATUS_RESOLVED)

        return query.order_by(desc(cls.created_at)).limit(limit).all()

    @classmethod
    def search_alerts(cls, search_term: Optional[str] = None,
                    status: Optional[Union[str, List[str]]] = None,
                    severity: Optional[Union[str, List[str]]] = None,
                    alert_type: Optional[Union[str, List[str]]] = None,
                    resource_id: Optional[int] = None,
                    provider_id: Optional[int] = None,
                    start_date: Optional[datetime] = None,
                    end_date: Optional[datetime] = None,
                    page: int = 1,
                    per_page: int = 20) -> Dict[str, Any]:
        """
        Search for alerts with various filters.

        Args:
            search_term: Text to search for in title and description
            status: Filter by alert status or list of statuses
            severity: Filter by alert severity or list of severities
            alert_type: Filter by alert type or list of types
            resource_id: Filter by specific resource ID
            provider_id: Filter by specific provider ID
            start_date: Include alerts created on or after this date
            end_date: Include alerts created on or before this date
            page: Page number for pagination (1-indexed)
            per_page: Number of results per page

        Returns:
            Dict[str, Any]: Dictionary with alerts and pagination info
        """
        try:
            query = cls.query

            # Apply text search if provided
            if search_term:
                search_term = f"%{search_term}%"
                query = query.filter(or_(
                    cls.title.ilike(search_term),
                    cls.description.ilike(search_term)
                ))

            # Filter by status
            if status:
                if isinstance(status, list):
                    query = query.filter(cls.status.in_(status))
                else:
                    query = query.filter(cls.status == status)

            # Filter by severity
            if severity:
                if isinstance(severity, list):
                    query = query.filter(cls.severity.in_(severity))
                else:
                    query = query.filter(cls.severity == severity)

            # Filter by alert type
            if alert_type:
                if isinstance(alert_type, list):
                    query = query.filter(cls.alert_type.in_(alert_type))
                else:
                    query = query.filter(cls.alert_type == alert_type)

            # Filter by resource ID
            if resource_id:
                query = query.filter(cls.resource_id == resource_id)

            # Filter by provider ID
            if provider_id:
                query = query.filter(cls.provider_id == provider_id)

            # Filter by date range
            if start_date:
                query = query.filter(cls.created_at >= start_date)

            if end_date:
                query = query.filter(cls.created_at <= end_date)

            # Count total results before pagination
            total = query.count()

            # Validate pagination parameters
            if page < 1:
                page = 1

            if per_page < 1 or per_page > 100:
                per_page = 20

            # Apply pagination
            query = query.order_by(desc(cls.created_at))
            offset = (page - 1) * per_page
            alerts = query.offset(offset).limit(per_page).all()

            # Calculate pagination metadata
            total_pages = (total + per_page - 1) // per_page if per_page > 0 else 0  # Ceiling division

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

    def __repr__(self) -> str:
        """Return string representation of CloudAlert object."""
        return f"<CloudAlert id={self.id} title='{self.title}' severity={self.severity} status={self.status}>"
