"""
Cloud resource model for tracking cloud infrastructure resources.

This module provides the CloudResource model for tracking and managing cloud infrastructure
resources across multiple providers. It supports resource lifecycle management, 
metadata tracking, and security monitoring for cloud assets.
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
import json
from sqlalchemy.ext.mutable import MutableDict

from extensions import db
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
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    resource_id = db.Column(db.String(128), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('cloud_providers.id'), nullable=False)
    resource_type = db.Column(db.String(64), nullable=False, index=True)
    region = db.Column(db.String(64), nullable=False, index=True)
    status = db.Column(db.String(32), nullable=False, default='pending', index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    metadata = db.Column(MutableDict.as_mutable(db.JSON), default=dict)
    config = db.Column(MutableDict.as_mutable(db.JSON), default=dict)
    tags = db.Column(MutableDict.as_mutable(db.JSON), default=dict)
    monthly_cost = db.Column(db.Numeric(10, 2), nullable=True)
    
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
        primaryjoin="CloudAlert.resource_id == CloudResource.id"
    )
    
    def __init__(
        self, 
        name: str, 
        resource_id: str, 
        provider_id: int, 
        resource_type: str,
        region: str, 
        created_by_id: Optional[int] = None, 
        status: str = 'pending',
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
        self.status = status
        self.metadata = metadata or {}
        self.config = config or {}
        self.tags = tags or {}
        self.monthly_cost = monthly_cost
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert resource to dictionary for API responses."""
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
        }
    
    @classmethod
    def get_by_resource_id(cls, resource_id: str, provider_id: int) -> Optional['CloudResource']:
        """
        Get resource by provider-specific resource ID.
        
        Args:
            resource_id: Provider-specific resource identifier
            provider_id: ID of the cloud provider
            
        Returns:
            CloudResource instance or None if not found
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
            List of CloudResource instances
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
            List of CloudResource instances
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
            List of CloudResource instances
        """
        # This implementation assumes PostgreSQL with JSONB support
        # For other databases, alternative approaches would be needed
        try:
            from sqlalchemy.dialects.postgresql import JSONB
            from sqlalchemy import cast
            
            query = cls.query
            
            # Add conditions for each tag key-value pair
            for key, value in tags.items():
                # Use ->> operator to get value as text from JSON
                query = query.filter(cast(cls.tags, JSONB)[key].astext == value)
            
            if active_only:
                query = query.filter_by(is_active=True)
                
            return query.all()
        except (KeyError, AttributeError, TypeError) as e:
            from flask import current_app
            current_app.logger.error(f"Error querying resources by tags: {e}")
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
        from extensions import metrics
        
        # Validate status before attempting update
        valid_statuses = ['pending', 'running', 'stopped', 'terminated', 'error', 'maintenance']
        if status not in valid_statuses:
            current_app.logger.warning(f"Invalid status '{status}' attempted for resource {self.id}")
            return False
        
        # Only update if there's an actual change
        if self.status == status:
            return True
            
        try:
            old_status = self.status
            self.status = status
            self.updated_at = datetime.utcnow()
            
            # Get current user from context if not provided
            if user_id is None and hasattr(g, 'user_id'):
                user_id = g.user_id
            
            # Record metrics for status changes
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
            
            # Update status history in metadata if it exists
            if 'status_history' not in self.metadata:
                self.metadata['status_history'] = []
                
            self.metadata['status_history'].append({
                'from': old_status,
                'to': status,
                'timestamp': datetime.utcnow().isoformat(),
                'user_id': user_id,
                'reason': update_reason
            })
            
            db.session.add(self)
            db.session.commit()
            
            # Record status change in audit log
            from models.audit_log import AuditLog
            audit_details = {
                'old_status': old_status,
                'new_status': status,
                'reason': update_reason
            }
            
            AuditLog.create(
                event_type='resource_status_change',
                user_id=user_id,
                object_type='CloudResource',
                object_id=self.id,
                description=f"Status changed from {old_status} to {status}",
                details=json.dumps(audit_details)
            )
            
            # For certain status changes, trigger notifications
            if status in ['error', 'terminated'] or old_status == 'running' and status == 'stopped':
                self._notify_status_change(old_status, status, update_reason)
            
            return True
            
        except (KeyError, AttributeError, TypeError) as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to update resource status: {e}", exc_info=True)
            
            # Record error metric
            metrics.counter(
                'cloud_resource_status_change_errors_total',
                1,
                {'resource_type': self.resource_type, 'error_type': e.__class__.__name__}
            )
            
            return False
            
    def _notify_status_change(self, old_status: str, new_status: str, 
                             reason: Optional[str] = None) -> None:
        """Send notifications for important status changes."""
        try:
            # Only send notifications for significant changes
            if not self.created_by_id:
                return
                
            from models.notification import Notification
            
            title = f"Resource Status Change: {self.name}"
            
            # Create more specific messages based on the status transition
            if new_status == 'error':
                message = f"Your resource {self.name} encountered an error."
                priority = 'high'
            elif old_status == 'running' and new_status == 'stopped':
                message = f"Your resource {self.name} has been stopped."
                priority = 'medium'
            elif new_status == 'terminated':
                message = f"Your resource {self.name} has been terminated."
                priority = 'high'
            else:
                message = f"Your resource {self.name} status changed from {old_status} to {new_status}."
                priority = 'low'
                
            if reason:
                message += f" Reason: {reason}"
                
            # Create the notification
            Notification.create(
                user_id=self.created_by_id,
                title=title,
                message=message,
                notification_type='resource_status',
                priority=priority,
                link=f"/cloud/resources/{self.id}"
            )
                
        except (KeyError, AttributeError, TypeError, RuntimeError) as e:
            from flask import current_app
            current_app.logger.error(f"Failed to send status change notification: {e}")
