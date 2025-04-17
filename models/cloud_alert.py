"""
Cloud alert model for cloud resource monitoring and notifications.

This module provides the CloudAlert model which tracks alerts and notifications
related to cloud infrastructure resources. It supports alerting on resource metrics,
status changes, and security events to enable proactive monitoring and incident response.
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy import desc
from flask import current_app

from extensions import db, metrics
from models.base import BaseModel


class CloudAlert(BaseModel):
    """
    Model representing a cloud infrastructure alert.
    
    This model captures alert conditions, status, and related metadata for cloud
    infrastructure monitoring. Alerts can be generated from metrics, status changes,
    or security events and can trigger notifications to users.
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
    metrics = db.Column(MutableDict.as_mutable(db.JSON), default=dict)
    metadata = db.Column(MutableDict.as_mutable(db.JSON), default=dict)
    source = db.Column(db.String(64), nullable=False, default='monitoring')
    notification_sent = db.Column(db.Boolean, default=False, nullable=False)
    
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
                source: str = 'monitoring'):
        """
        Initialize a CloudAlert instance.
        
        Args:
            title: Alert title
            description: Detailed alert description
            severity: Alert severity level (info, warning, error, critical)
            resource_id: Related cloud resource ID (optional)
            provider_id: Related cloud provider ID (optional)
            metrics: Related metrics data
            metadata: Additional alert metadata
            source: Alert source (monitoring, system, user, etc.)
            
        Raises:
            ValueError: If severity is not one of the allowed values
        """
        if severity not in self.SEVERITIES:
            raise ValueError(f"Invalid severity. Must be one of: {', '.join(self.SEVERITIES)}")
            
        self.title = title
        self.description = description
        self.severity = severity
        self.resource_id = resource_id
        self.provider_id = provider_id
        self.metrics = alert_metrics or {}
        self.metadata = metadata or {}
        self.source = source
        self.status = self.STATUS_ACTIVE
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert alert to dictionary for API responses.
        
        Returns:
            Dict[str, Any]: Dictionary representation of the alert
        """
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'resource_id': self.resource_id,
            'provider_id': self.provider_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'acknowledged_by_id': self.acknowledged_by_id,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolved_by_id': self.resolved_by_id,
            'metrics': self.metrics,
            'metadata': self.metadata,
            'source': self.source,
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
                self.acknowledged_at = datetime.utcnow()
                self.acknowledged_by_id = user_id
                
                # Track metrics
                metrics.counter('cloud_alerts_acknowledged_total', 1, {
                    'severity': self.severity,
                    'source': self.source
                })
                
                db.session.add(self)
                db.session.commit()
                
                # Create audit log entry
                from models.audit_log import AuditLog
                AuditLog.create(
                    event_type='alert_acknowledged',
                    user_id=user_id,
                    object_type='CloudAlert',
                    object_id=self.id,
                    description=f"Alert '{self.title}' acknowledged"
                )
                
                return True
            return False
        except (ValueError, AttributeError, KeyError) as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to acknowledge alert: {e}")
            return False
    
    def resolve(self, user_id: int, resolution_note: Optional[str] = None) -> bool:
        """Resolve the alert."""
        try:
            if self.status != self.STATUS_RESOLVED:
                self.status = self.STATUS_RESOLVED
                self.resolved_at = datetime.utcnow()
                self.resolved_by_id = user_id
                
                if resolution_note:
                    if 'resolution_notes' not in self.metadata:
                        self.metadata['resolution_notes'] = []
                    self.metadata['resolution_notes'].append({
                        'note': resolution_note,
                        'user_id': user_id,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                
                db.session.add(self)
                db.session.commit()
                
                # Create audit log entry
                from models.audit_log import AuditLog
                AuditLog.create(
                    event_type='alert_resolved',
                    user_id=user_id,
                    target_type='CloudAlert',
                    target_id=self.id,
                    description=f"Alert '{self.title}' resolved"
                )
                
                return True
        except ValueError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to resolve alert: {e}")
            return False
    
    def send_notification(self) -> bool:
        """Send notification for this alert."""
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
                self.SEVERITY_CRITICAL: 'urgent'
            }
            priority = priority_map.get(self.severity, 'medium')
            
            # If there's a resource, notify its creator
            user_ids = []
            if self.resource_id:
                from models.cloud_resource import CloudResource
                resource = CloudResource.query.get(self.resource_id)
                if resource and resource.created_by_id:
                    user_ids.append(resource.created_by_id)
            
            # Also notify admins for high severity alerts
            if self.severity in (self.SEVERITY_ERROR, self.SEVERITY_CRITICAL):
                from models.user import User
                admin_ids = [u.id for u in User.query.filter_by(role='admin').all()]
                user_ids.extend(admin_ids)
            
            # Deduplicate user IDs
            user_ids = list(set(user_ids))
            
            # Send notification to each user
            for user_id in user_ids:
                Notification.create(
                    user_id=user_id,
                    title=f"Cloud Alert: {self.title}",
                    message=self.description,
                    notification_type=self.severity,
                    priority=priority,
                    link=f"/cloud/alerts/{self.id}"
                )
            
            self.notification_sent = True
            db.session.add(self)
            db.session.commit()
            return True
            
        except (db.exc.SQLAlchemyError, KeyError, AttributeError) as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to send alert notification: {e}")
            return False
    
    @classmethod
    def get_active_alerts(cls, resource_id: Optional[int] = None, 
                         provider_id: Optional[int] = None,
                         severity: Optional[str] = None) -> List['CloudAlert']:
        """Get active alerts with optional filtering."""
        query = cls.query.filter(cls.status != cls.STATUS_RESOLVED)
        
        if resource_id is not None:
            query = query.filter_by(resource_id=resource_id)
            
        if provider_id is not None:
            query = query.filter_by(provider_id=provider_id)
            
        if severity is not None:
            query = query.filter_by(severity=severity)
        
        return query.order_by(
            # Order by severity (critical first), then by creation date
            desc(db.case({
                cls.SEVERITY_CRITICAL: 4,
                cls.SEVERITY_ERROR: 3,
                cls.SEVERITY_WARNING: 2,
                cls.SEVERITY_INFO: 1
            }, value=cls.severity)),
            desc(cls.created_at)
        ).all()
    
    @classmethod
    def create_from_metric(cls, metric_name: str, value: float, threshold: float,
                         resource_id: int, provider_id: int,
                         severity: str = SEVERITY_WARNING) -> Optional['CloudAlert']:
        """Create an alert from a metric threshold violation."""
        try:
            from models.cloud_resource import CloudResource
            resource = CloudResource.query.get(resource_id)
            
            if not resource:
                return None
                
            title = f"{metric_name.replace('_', ' ').title()} Alert"
            description = (f"{title} for {resource.name}: "
                         f"Current value {value:.2f} exceeds threshold of {threshold:.2f}")
            
            alert = cls(
                title=title,
                description=description,
                severity=severity,
                resource_id=resource_id,
                provider_id=provider_id,
                alert_metrics={  # Changed from 'metrics' to 'alert_metrics' to match the constructor parameter
                    'name': metric_name,
                    'value': float(value),
                    'threshold': float(threshold),
                    'timestamp': datetime.utcnow().isoformat()
                },
                source='metric_threshold'
            )
            
            db.session.add(alert)
            db.session.commit()
            
            # Send notification asynchronously or via task queue in production
            alert.send_notification()
            
            return alert
            
        except (db.exc.SQLAlchemyError, AttributeError, KeyError) as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to create metric alert: {e}")
            return None
