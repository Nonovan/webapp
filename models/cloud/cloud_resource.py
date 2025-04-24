"""
Cloud resource model for tracking cloud infrastructure resources.

This module provides the CloudResource model for tracking and managing cloud infrastructure
resources across multiple providers. It supports resource lifecycle management,
metadata tracking, and security monitoring for cloud assets.
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Union, Tuple
import json
from sqlalchemy import text, func, and_, or_
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.exc import SQLAlchemyError

from extensions import db, metrics
from models.base import BaseModel, AuditableMixin


class CloudResource(BaseModel, AuditableMixin):
    """
    Model representing a cloud infrastructure resource.

    This model tracks cloud resources (VMs, databases, storage, etc.) across
    different cloud providers with their metadata, configuration, and status.
    It supports resource lifecycle management and security monitoring.

    Attributes:
        id: Primary key
        name: Resource name
        resource_id: Cloud provider's resource identifier
        provider_id: Foreign key to CloudProvider
        resource_type: Type of resource (VM, database, storage, etc.)
        region: Geographic region where resource is deployed
        status: Current resource status (running, stopped, error, etc.)
        is_active: Whether the resource is currently active
        created_by_id: User who created the resource
        metadata: JSON data containing resource-specific metadata
        config: JSON data containing resource configuration
        tags: JSON data containing resource tags/labels
        monthly_cost: Estimated monthly cost for the resource
    """
    __tablename__ = 'cloud_resources'

    # Status constants
    STATUS_PENDING = 'pending'
    STATUS_PROVISIONING = 'provisioning'
    STATUS_RUNNING = 'running'
    STATUS_STOPPED = 'stopped'
    STATUS_TERMINATED = 'terminated'
    STATUS_ERROR = 'error'
    STATUS_MAINTENANCE = 'maintenance'
    STATUS_UPDATING = 'updating'

    VALID_STATUSES = [
        STATUS_PENDING,
        STATUS_PROVISIONING,
        STATUS_RUNNING,
        STATUS_STOPPED,
        STATUS_TERMINATED,
        STATUS_ERROR,
        STATUS_MAINTENANCE,
        STATUS_UPDATING
    ]

    # Common resource types
    TYPE_VM = 'vm'
    TYPE_DATABASE = 'database'
    TYPE_STORAGE = 'storage'
    TYPE_NETWORK = 'network'
    TYPE_CONTAINER = 'container'
    TYPE_SERVERLESS = 'serverless'
    TYPE_LOADBALANCER = 'loadbalancer'

    # Cost alert thresholds (percentage above baseline)
    COST_ALERT_WARNING = 20   # 20% increase
    COST_ALERT_CRITICAL = 50  # 50% increase

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    resource_id = db.Column(db.String(128), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('cloud_providers.id'), nullable=False)
    resource_type = db.Column(db.String(64), nullable=False, index=True)
    region = db.Column(db.String(64), nullable=False, index=True)
    status = db.Column(db.String(32), nullable=False, default=STATUS_PENDING, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    # JSON data fields with default empty dictionaries
    metadata = db.Column(MutableDict.as_mutable(db.JSON), default=dict, nullable=False)
    config = db.Column(MutableDict.as_mutable(db.JSON), default=dict, nullable=False)
    tags = db.Column(MutableDict.as_mutable(db.JSON), default=dict, nullable=False)

    # Cost tracking
    monthly_cost = db.Column(db.Numeric(10, 2), nullable=True)
    last_cost_update = db.Column(db.DateTime(timezone=True), nullable=True)

    # Security and compliance fields
    security_status = db.Column(db.String(32), default='unknown')
    compliance_status = db.Column(db.JSON, default=dict)
    last_scan_date = db.Column(db.DateTime(timezone=True), nullable=True)

    # Relationships
    provider = db.relationship('CloudProvider', backref=db.backref('resources', lazy='dynamic'))
    created_by = db.relationship('User', backref=db.backref('cloud_resources', lazy='dynamic'))
    metrics = db.relationship(
        'CloudMetric',
        backref='resource',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    alerts = db.relationship(
        'CloudAlert',
        backref='resource',
        lazy='dynamic',
        primaryjoin="CloudAlert.resource_id == CloudResource.id",
        cascade='all, delete-orphan'
    )

    def __init__(
        self,
        name: str,
        resource_id: str,
        provider_id: int,
        resource_type: str,
        region: str,
        created_by_id: Optional[int] = None,
        status: str = STATUS_PENDING,
        metadata: Optional[Dict] = None,
        config: Optional[Dict] = None,
        tags: Optional[Dict] = None,
        monthly_cost: Optional[float] = None
    ):
        """
        Initialize a CloudResource instance.

        Args:
            name: Name of the resource
            resource_id: Provider-specific resource identifier
            provider_id: ID of the cloud provider
            resource_type: Type of resource (VM, database, etc.)
            region: Geographic region where resource is deployed
            created_by_id: ID of user who created the resource
            status: Current resource status
            metadata: Resource-specific metadata
            config: Resource configuration
            tags: Resource tags/labels
            monthly_cost: Estimated monthly cost
        """
        self.name = name
        self.resource_id = resource_id
        self.provider_id = provider_id
        self.resource_type = resource_type
        self.region = region
        self.created_by_id = created_by_id

        # Validate status
        if status not in self.VALID_STATUSES:
            status = self.STATUS_PENDING
        self.status = status

        # Set JSON fields with default values if None
        self.metadata = metadata or {}
        self.config = config or {}
        self.tags = tags or {}
        self.monthly_cost = monthly_cost

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert resource to dictionary for API responses.

        Returns:
            Dict[str, Any]: Dictionary representation of the resource
        """
        return {
            'id': self.id,
            'name': self.name,
            'resource_id': self.resource_id,
            'provider_id': self.provider_id,
            'provider_name': self.provider.name if self.provider else None,
            'resource_type': self.resource_type,
            'region': self.region,
            'status': self.status,
            'is_active': self.is_active,
            'created_by_id': self.created_by_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'metadata': self.metadata,
            'config': self.config,
            'tags': self.tags,
            'monthly_cost': float(self.monthly_cost) if self.monthly_cost else None,
            'security_status': self.security_status,
            'last_scan_date': self.last_scan_date.isoformat() if self.last_scan_date else None,
        }

    @classmethod
    def get_by_resource_id(cls, resource_id: str, provider_id: int) -> Optional['CloudResource']:
        """
        Get resource by provider-specific resource ID.

        Args:
            resource_id: Provider-specific resource identifier
            provider_id: ID of the cloud provider

        Returns:
            CloudResource: Instance or None if not found
        """
        return cls.query.filter_by(resource_id=resource_id, provider_id=provider_id).first()

    @classmethod
    def get_by_type(cls, resource_type: str, active_only: bool = True) -> List['CloudResource']:
        """
        Get resources by resource type.

        Args:
            resource_type: Type of resources to retrieve
            active_only: Whether to return only active resources

        Returns:
            List[CloudResource]: List of CloudResource instances
        """
        query = cls.query.filter_by(resource_type=resource_type)
        if active_only:
            query = query.filter_by(is_active=True)
        return query.all()

    @classmethod
    def get_by_region(cls, region: str, active_only: bool = True) -> List['CloudResource']:
        """
        Get resources by region.

        Args:
            region: Region identifier
            active_only: Whether to return only active resources

        Returns:
            List[CloudResource]: List of CloudResource instances
        """
        query = cls.query.filter_by(region=region)
        if active_only:
            query = query.filter_by(is_active=True)
        return query.all()

    @classmethod
    def get_by_tags(cls, tags: Dict[str, str], active_only: bool = True) -> List['CloudResource']:
        """
        Get resources by matching tags.

        Args:
            tags: Dictionary of tag key-value pairs to match
            active_only: Whether to return only active resources

        Returns:
            List[CloudResource]: List of CloudResource instances
        """
        try:
            # Use database dialect-specific JSON query method
            query = cls.query

            # Determine database dialect and execute appropriate query
            dialect = db.engine.dialect.name

            if dialect == 'postgresql':
                # For PostgreSQL with JSONB support
                from sqlalchemy.dialects.postgresql import JSONB
                from sqlalchemy import cast

                # Add conditions for each tag key-value pair
                for key, value in tags.items():
                    # Use ->> operator to get value as text from JSON
                    query = query.filter(cast(cls.tags, JSONB)[key].astext == value)

            elif dialect == 'mysql':
                # For MySQL JSON support
                for key, value in tags.items():
                    # Use JSON_EXTRACT with -> operator
                    json_path = f"$.{key}"
                    query = query.filter(text(f"JSON_UNQUOTE(JSON_EXTRACT(tags, '{json_path}')) = :value"))
                    query = query.params(value=value)

            else:
                # Generic fallback using string serialization and filtering
                # This is less efficient but works across databases
                resources = cls.query.all()
                result = []

                for resource in resources:
                    if all(resource.tags.get(k) == v for k, v in tags.items()):
                        result.append(resource)

                return [r for r in result if r.is_active or not active_only]

            # Apply active filter if needed
            if active_only:
                query = query.filter_by(is_active=True)

            return query.all()

        except (SQLAlchemyError, AttributeError, TypeError) as e:
            from flask import current_app
            current_app.logger.error(f"Error querying resources by tags: {e}", exc_info=True)
            return []

    def update_status(self, status: str, update_reason: Optional[str] = None,
                     user_id: Optional[int] = None) -> bool:
        """
        Update resource status and record the change.

        Args:
            status: New status to set
            update_reason: Optional reason for the status update
            user_id: ID of user making the change (if applicable)

        Returns:
            bool: True if update was successful, False otherwise
        """
        from flask import current_app, g

        # Validate status before attempting update
        if status not in self.VALID_STATUSES:
            current_app.logger.warning(f"Invalid status '{status}' attempted for resource {self.id}")
            return False

        # Only update if there's an actual change
        if self.status == status:
            return True

        try:
            old_status = self.status
            self.status = status
            self.updated_at = datetime.now(timezone.utc)

            # Get current user from context if not provided
            if user_id is None and hasattr(g, 'user_id'):
                user_id = g.get('user_id')

            # Record metrics for status changes
            if metrics:
                metrics.counter(
                    'cloud_resource_status_changes_total',
                    1,
                    {
                        'resource_type': self.resource_type,
                        'old_status': old_status,
                        'new_status': status,
                        'region': self.region
                    }
                )

            # Update status history in metadata
            if 'status_history' not in self.metadata:
                self.metadata['status_history'] = []

            self.metadata['status_history'].append({
                'from': old_status,
                'to': status,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'user_id': user_id,
                'reason': update_reason
            })

            # Update is_active flag based on status
            if status in [self.STATUS_TERMINATED, self.STATUS_ERROR]:
                self.is_active = False
            elif status == self.STATUS_RUNNING:
                self.is_active = True

            db.session.add(self)
            db.session.commit()

            # Record status change in audit log
            self._create_audit_log(
                event_type='resource_status_change',
                user_id=user_id,
                description=f"Status changed from {old_status} to {status}",
                details={
                    'old_status': old_status,
                    'new_status': status,
                    'reason': update_reason
                }
            )

            # For certain status changes, trigger notifications
            if (status in [self.STATUS_ERROR, self.STATUS_TERMINATED] or
                (old_status == self.STATUS_RUNNING and status == self.STATUS_STOPPED)):
                self._notify_status_change(old_status, status, update_reason)

            return True

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to update resource status: {e}", exc_info=True)

            # Record error metric
            if metrics:
                metrics.counter(
                    'cloud_resource_status_change_errors_total',
                    1,
                    {'resource_type': self.resource_type, 'error_type': e.__class__.__name__}
                )

            return False

    def _create_audit_log(self, event_type: str, user_id: Optional[int],
                         description: str, details: Dict[str, Any]) -> None:
        """
        Create an audit log entry for this resource.

        Args:
            event_type: Type of event to log
            user_id: ID of the user performing the action
            description: Description of the event
            details: Additional details about the event
        """
        try:
            from models.audit_log import AuditLog

            AuditLog.create(
                event_type=event_type,
                user_id=user_id,
                object_type='CloudResource',
                object_id=self.id,
                description=description,
                details=json.dumps(details)
            )
        except (ImportError, AttributeError) as e:
            from flask import current_app
            current_app.logger.error(f"Failed to create audit log: {e}")

    def _notify_status_change(self, old_status: str, new_status: str,
                             reason: Optional[str] = None) -> None:
        """
        Send notifications for important status changes.

        Args:
            old_status: Previous status
            new_status: New status
            reason: Optional reason for the change
        """
        try:
            # Only send notifications for significant changes and if we have a user
            if not self.created_by_id:
                return

            # Import here to avoid circular imports
            from models.notification import Notification

            title = f"Resource Status Change: {self.name}"

            # Create more specific messages based on the status transition
            if new_status == self.STATUS_ERROR:
                message = f"Your resource {self.name} encountered an error."
                priority = 'high'
            elif old_status == self.STATUS_RUNNING and new_status == self.STATUS_STOPPED:
                message = f"Your resource {self.name} has been stopped."
                priority = 'medium'
            elif new_status == self.STATUS_TERMINATED:
                message = f"Your resource {self.name} has been terminated."
                priority = 'high'
            else:
                message = f"Your resource {self.name} status changed from {old_status} to {new_status}."
                priority = 'low'

            if reason:
                message += f" Reason: {reason}"

            # Create the notification
            notification = Notification.create_notification(
                user_id=self.created_by_id,
                title=title,
                message=message,
                notification_type='resource_status',
                priority=priority,
                action_url=f"/cloud/resources/{self.id}"
            )

            if notification:
                from flask import current_app
                current_app.logger.info(f"Created resource status change notification {notification.id} for user {self.created_by_id}")

        except Exception as e:
            from flask import current_app
            current_app.logger.error(f"Failed to send status change notification: {e}", exc_info=True)

    def update_cost(self, new_cost: float) -> bool:
        """
        Update the monthly cost estimate for this resource.

        Args:
            new_cost: New monthly cost estimate

        Returns:
            bool: True if update was successful, False otherwise
        """
        from flask import current_app

        try:
            old_cost = float(self.monthly_cost) if self.monthly_cost else 0
            significant_change = False

            # Check if this is a significant cost change that should trigger an alert
            if old_cost > 0 and new_cost > old_cost:
                percent_increase = ((new_cost - old_cost) / old_cost) * 100
                if percent_increase >= self.COST_ALERT_CRITICAL:
                    significant_change = True
                    self._create_cost_alert(old_cost, new_cost, percent_increase, "critical")
                elif percent_increase >= self.COST_ALERT_WARNING:
                    significant_change = True
                    self._create_cost_alert(old_cost, new_cost, percent_increase, "warning")

            # Update cost and timestamp
            self.monthly_cost = new_cost
            self.last_cost_update = datetime.now(timezone.utc)

            # Add cost history entry to metadata
            if 'cost_history' not in self.metadata:
                self.metadata['cost_history'] = []

            self.metadata['cost_history'].append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'amount': new_cost,
                'significant_change': significant_change
            })

            # Trim history if it's getting too large (keep last 50 entries)
            if len(self.metadata['cost_history']) > 50:
                self.metadata['cost_history'] = self.metadata['cost_history'][-50:]

            db.session.add(self)
            db.session.commit()

            # Record cost change in audit log if significant
            if significant_change:
                self._create_audit_log(
                    event_type='resource_cost_change',
                    user_id=None,  # System-generated
                    description=f"Monthly cost changed from ${old_cost:.2f} to ${new_cost:.2f}",
                    details={
                        'old_cost': old_cost,
                        'new_cost': new_cost,
                        'percent_change': ((new_cost - old_cost) / old_cost) * 100 if old_cost > 0 else 0
                    }
                )

            return True

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to update resource cost: {e}", exc_info=True)
            return False

    def _create_cost_alert(self, old_cost: float, new_cost: float,
                          percent_increase: float, severity: str) -> None:
        """
        Create cost alert for significant cost increases.

        Args:
            old_cost: Previous cost
            new_cost: New cost
            percent_increase: Percentage increase
            severity: Alert severity (warning/critical)
        """
        try:
            from models.cloud_alert import CloudAlert

            CloudAlert.create(
                resource_id=self.id,
                alert_type='cost_increase',
                severity=severity,
                message=f"Cost increased by {percent_increase:.1f}% from ${old_cost:.2f} to ${new_cost:.2f}",
                details={
                    'old_cost': old_cost,
                    'new_cost': new_cost,
                    'percent_increase': percent_increase,
                    'resource_type': self.resource_type,
                    'region': self.region
                }
            )

            # Also create a notification for the resource owner
            if self.created_by_id:
                from models.notification import Notification

                title = f"Cost Alert: {self.name}"
                message = (f"The cost of your resource {self.name} has increased by {percent_increase:.1f}% " +
                          f"from ${old_cost:.2f} to ${new_cost:.2f}.")

                Notification.create_notification(
                    user_id=self.created_by_id,
                    title=title,
                    message=message,
                    notification_type='cost_alert',
                    priority='high' if severity == 'critical' else 'medium',
                    action_url=f"/cloud/resources/{self.id}"
                )

        except (ImportError, AttributeError) as e:
            from flask import current_app
            current_app.logger.error(f"Failed to create cost alert: {e}", exc_info=True)

    def update_security_status(self, security_status: str, scan_results: Dict[str, Any],
                              user_id: Optional[int] = None) -> bool:
        """
        Update security status and scan results.

        Args:
            security_status: New security status (secure, warning, vulnerable)
            scan_results: Security scan results
            user_id: ID of user updating security status

        Returns:
            bool: True if update was successful, False otherwise
        """
        from flask import current_app, g

        valid_statuses = ['secure', 'warning', 'vulnerable', 'unknown', 'scanning']

        if security_status not in valid_statuses:
            current_app.logger.warning(f"Invalid security status '{security_status}' for resource {self.id}")
            return False

        try:
            old_status = self.security_status
            self.security_status = security_status
            self.last_scan_date = datetime.now(timezone.utc)

            # Store scan results in metadata
            if 'security_scans' not in self.metadata:
                self.metadata['security_scans'] = []

            self.metadata['security_scans'].append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'status': security_status,
                'results': scan_results
            })

            # Get current user from context if not provided
            if user_id is None and hasattr(g, 'user_id'):
                user_id = g.get('user_id')

            # Trim security scans history if it's getting too large (keep last 20 entries)
            if len(self.metadata['security_scans']) > 20:
                self.metadata['security_scans'] = self.metadata['security_scans'][-20:]

            db.session.add(self)
            db.session.commit()

            # Record security status change in audit log
            self._create_audit_log(
                event_type='resource_security_scan',
                user_id=user_id,
                description=f"Security status updated from {old_status} to {security_status}",
                details={
                    'old_status': old_status,
                    'new_status': security_status,
                    'findings_count': len(scan_results.get('findings', [])) if isinstance(scan_results, dict) else 0
                }
            )

            # Create alert for vulnerable resources
            if security_status == 'vulnerable':
                self._create_security_alert(scan_results)

            return True

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to update security status: {e}", exc_info=True)
            return False

    def _create_security_alert(self, scan_results: Dict[str, Any]) -> None:
        """
        Create security alert for vulnerable resources.

        Args:
            scan_results: Security scan results
        """
        try:
            from models.cloud_alert import CloudAlert

            # Extract critical findings
            critical_findings = [f for f in scan_results.get('findings', [])
                               if f.get('severity') in ('high', 'critical')]

            findings_text = ", ".join([f.get('title', 'Unknown') for f in critical_findings[:3]])
            if len(critical_findings) > 3:
                findings_text += f" and {len(critical_findings) - 3} more"

            CloudAlert.create(
                resource_id=self.id,
                alert_type='security_vulnerability',
                severity='critical' if any(f.get('severity') == 'critical' for f in critical_findings) else 'high',
                message=f"Security vulnerabilities detected: {findings_text}",
                details={
                    'resource_type': self.resource_type,
                    'region': self.region,
                    'critical_findings_count': len(critical_findings),
                    'total_findings_count': len(scan_results.get('findings', [])),
                    'scan_id': scan_results.get('scan_id')
                }
            )

            # Also create a notification for the resource owner
            if self.created_by_id:
                from models.notification import Notification

                title = f"Security Alert: {self.name}"
                message = f"Security vulnerabilities detected in {self.name}: {findings_text}"

                Notification.create_notification(
                    user_id=self.created_by_id,
                    title=title,
                    message=message,
                    notification_type='security_alert',
                    priority='high',
                    action_url=f"/cloud/resources/{self.id}/security"
                )

        except (ImportError, AttributeError) as e:
            from flask import current_app
            current_app.logger.error(f"Failed to create security alert: {e}", exc_info=True)

    @classmethod
    def get_cost_summary_by_type(cls) -> Dict[str, float]:
        """
        Get total cost summary grouped by resource type.

        Returns:
            Dict[str, float]: Dictionary mapping resource types to total costs
        """
        try:
            result = {}
            query_result = db.session.query(
                cls.resource_type,
                func.sum(cls.monthly_cost)
            ).filter(
                cls.is_active == True,
                cls.monthly_cost.isnot(None)
            ).group_by(cls.resource_type).all()

            for resource_type, total in query_result:
                result[resource_type] = float(total)

            return result

        except SQLAlchemyError as e:
            from flask import current_app
            current_app.logger.error(f"Error getting cost summary: {e}", exc_info=True)
            return {}

    @classmethod
    def get_cost_summary_by_region(cls) -> Dict[str, float]:
        """
        Get total cost summary grouped by region.

        Returns:
            Dict[str, float]: Dictionary mapping regions to total costs
        """
        try:
            result = {}
            query_result = db.session.query(
                cls.region,
                func.sum(cls.monthly_cost)
            ).filter(
                cls.is_active == True,
                cls.monthly_cost.isnot(None)
            ).group_by(cls.region).all()

            for region, total in query_result:
                result[region] = float(total)

            return result

        except SQLAlchemyError as e:
            from flask import current_app
            current_app.logger.error(f"Error getting cost summary: {e}", exc_info=True)
            return {}

    @classmethod
    def get_resources_with_filters(cls,
                                 provider_id: Optional[int] = None,
                                 resource_type: Optional[str] = None,
                                 region: Optional[str] = None,
                                 status: Optional[str] = None,
                                 is_active: Optional[bool] = True,
                                 tags: Optional[Dict[str, str]] = None,
                                 search: Optional[str] = None,
                                 page: int = 1,
                                 per_page: int = 20) -> Tuple[List['CloudResource'], int]:
        """
        Get resources with filtering and pagination.

        Args:
            provider_id: Filter by provider ID
            resource_type: Filter by resource type
            region: Filter by region
            status: Filter by status
            is_active: Filter by active status
            tags: Filter by tags
            search: Search term for name and resource_id
            page: Page number (1-indexed)
            per_page: Number of items per page

        Returns:
            Tuple[List[CloudResource], int]: List of resources and total count
        """
        try:
            query = cls.query

            # Apply filters
            if provider_id is not None:
                query = query.filter(cls.provider_id == provider_id)

            if resource_type is not None:
                query = query.filter(cls.resource_type == resource_type)

            if region is not None:
                query = query.filter(cls.region == region)

            if status is not None:
                query = query.filter(cls.status == status)

            if is_active is not None:
                query = query.filter(cls.is_active == is_active)

            if search:
                search_term = f"%{search}%"
                query = query.filter(or_(
                    cls.name.ilike(search_term),
                    cls.resource_id.ilike(search_term)
                ))

            # Handle tag filtering
            if tags:
                # The specific implementation depends on the database dialect
                # This is a simplified approach
                for key, value in tags.items():
                    resources_with_tag = cls._filter_by_tag(key, value)
                    resource_ids = [r.id for r in resources_with_tag]
                    if resource_ids:
                        query = query.filter(cls.id.in_(resource_ids))
                    else:
                        # No resources match this tag, return empty result
                        return [], 0

            # Get total count before pagination
            total = query.count()

            # Apply pagination
            if page < 1:
                page = 1

            if per_page < 1:
                per_page = 20

            offset = (page - 1) * per_page
            query = query.order_by(cls.updated_at.desc())
            resources = query.offset(offset).limit(per_page).all()

            return resources, total

        except SQLAlchemyError as e:
            from flask import current_app
            current_app.logger.error(f"Error filtering resources: {e}", exc_info=True)
            return [], 0

    @classmethod
    def _filter_by_tag(cls, tag_key: str, tag_value: str) -> List['CloudResource']:
        """
        Helper method to filter resources by a specific tag.

        Args:
            tag_key: Tag key
            tag_value: Tag value

        Returns:
            List[CloudResource]: List of resources with the specified tag
        """
        try:
            # Handle different database dialects
            dialect = db.engine.dialect.name

            if dialect == 'postgresql':
                # PostgreSQL JSON filtering
                from sqlalchemy.dialects.postgresql import JSONB
                from sqlalchemy import cast
                return cls.query.filter(cast(cls.tags, JSONB)[tag_key].astext == tag_value).all()

            elif dialect == 'mysql':
                # MySQL JSON filtering
                json_path = f"$.{tag_key}"
                return cls.query.filter(text(f"JSON_UNQUOTE(JSON_EXTRACT(tags, '{json_path}')) = :value"))\
                        .params(value=tag_value).all()

            else:
                # Fallback method - get all and filter in Python
                result = []
                for resource in cls.query.all():
                    if resource.tags.get(tag_key) == tag_value:
                        result.append(resource)
                return result

        except Exception as e:
            from flask import current_app
            current_app.logger.error(f"Error filtering by tag: {e}", exc_info=True)
            return []

    def __repr__(self) -> str:
        """String representation of CloudResource object."""
        return f'<CloudResource id={self.id} name="{self.name}" type={self.resource_type} status={self.status}>'
