"""
Data models package for the myproject application.

This package defines the application's data model layer using SQLAlchemy ORM, providing
a clean, Pythonic interface to the underlying database. It includes:

- A base model implementation with common functionality for all models
- Mixin classes for shared behaviors like timestamp tracking
- Type definitions and annotations for static type checking
- Custom model exception types
- Helper methods for data serialization and validation

The models implement the Active Record pattern through SQLAlchemy, where each model
instance represents a row in the database and provides methods for CRUD operations.
This approach encapsulates database operations within the models themselves, promoting
code organization and reusability.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Type, Union, cast

from flask import current_app, g, request, has_request_context
from sqlalchemy import event
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.declarative import declared_attr

from extensions import db

# Import base classes first to avoid circular imports
from .base import BaseModel, TimestampMixin, AuditableMixin

# Import models by domain
# Auth models
from .auth.user import User
from .auth.role import Role
from .auth.permission import Permission
from .auth.user_session import UserSession
from .auth.user_activity import UserActivity

# Content models
from .content.post import Post
from .content.category import Category
from .content.tag import Tag

# Communication models
from .communication.newsletter import Subscriber, MailingList, SubscriberList
from .communication.notification import Notification
from .communication.webhook import WebhookSubscription, WebhookDelivery
from .communication.subscriber import SubscriberCategory

# Security models
from .security.security_incident import SecurityIncident
from .security.audit_log import AuditLog
from .security.system_config import SystemConfig

# Cloud models
from .cloud.cloud_provider import CloudProvider
from .cloud.cloud_resource import CloudResource
from .cloud.cloud_metric import CloudMetric
from .cloud.cloud_alert import CloudAlert

# Storage models
from .storage.file_upload import FileUpload

# ICS models
from .ics.ics_device import ICSDevice
from .ics.ics_reading import ICSReading
from .ics.ics_control_log import ICSControlLog

# Build the __all__ list for proper exports
__all__ = [
    # Core components
    'db', 'BaseModel', 'TimestampMixin', 'AuditableMixin',

    # Auth models
    'User', 'Role', 'Permission', 'UserSession', 'UserActivity',

    # Content models
    'Post', 'Category', 'Tag',

    # Communication models
    'Subscriber', 'MailingList', 'SubscriberList', 'Notification',
    'WebhookSubscription', 'WebhookDelivery', 'SubscriberCategory',

    # Security models
    'SecurityIncident', 'AuditLog', 'SystemConfig',

    # Cloud infrastructure models
    'CloudProvider', 'CloudResource', 'CloudMetric', 'CloudAlert',

    # Storage models
    'FileUpload',

    # ICS models
    'ICSDevice', 'ICSReading', 'ICSControlLog',
]

def _setup_audit_listeners():
    """
    Set up SQLAlchemy event listeners for security auditing.

    This function registers event listeners on security-sensitive models
    to automatically create audit log entries when records are created,
    updated, or deleted.
    """
    # Add models that need security audit logging
    models_to_audit = [
        User,
        Role,
        Permission,
        SecurityIncident,
        SystemConfig,
        CloudResource,
        CloudProvider,
        CloudMetric,
        CloudAlert,
        ICSDevice,
        WebhookSubscription,
        FileUpload,
        MailingList
    ]

    for model in models_to_audit:
        # Set up listeners for each audit event type
        event.listen(model, 'after_insert', _log_model_insert)
        event.listen(model, 'after_update', _log_model_update)
        event.listen(model, 'after_delete', _log_model_delete)

def _log_model_insert(_mapper, _connection, target):
    """
    Log when a model instance is created.

    Args:
        _mapper: SQLAlchemy mapper object (unused)
        _connection: SQLAlchemy connection object (unused)
        target: Model instance that was created
    """
    if not has_request_context():
        return

    try:
        # Get user information if available
        user_id = getattr(g, 'user_id', None)
        ip_address = request.remote_addr if request else None

        # Get serialized representation if available
        details = {}
        if hasattr(target, 'to_dict'):
            try:
                # Remove sensitive fields from logs
                details = _sanitize_log_data(target.to_dict())
            except Exception:
                # Fallback if to_dict fails
                details = {"id": getattr(target, 'id', None)}

        # Handle case where AuditLog might not be imported yet
        from .security.audit_log import AuditLog

        AuditLog.create(
            event_type=AuditLog.EVENT_OBJECT_CREATED,
            user_id=user_id,
            object_type=target.__class__.__name__,
            object_id=getattr(target, 'id', None),
            description=f"Created {target.__class__.__name__} with ID {getattr(target, 'id', 'unknown')}",
            ip_address=ip_address,
            details=details
        )
    except Exception as e:
        if current_app:
            current_app.logger.error(f"Failed to log model insert: {str(e)}")

def _log_model_update(_mapper, _connection, target):
    """
    Log when a model instance is updated.

    Args:
        _mapper: SQLAlchemy mapper object (unused)
        _connection: SQLAlchemy connection object (unused)
        target: Model instance that was updated
    """
    if not has_request_context():
        return

    try:
        # Get user information if available
        user_id = getattr(g, 'user_id', None)
        ip_address = request.remote_addr if request else None

        # Get changed attributes if history tracker is available
        details = {}
        if hasattr(target, 'get_changed_columns'):
            try:
                details["changed_columns"] = target.get_changed_columns()
            except Exception:
                pass

        # Check if target is an AuditableMixin and has security critical fields
        if hasattr(target, 'SECURITY_CRITICAL_FIELDS'):
            # Add to details if a security critical field was modified
            changed_fields = details.get("changed_columns", [])
            critical_changes = [f for f in changed_fields if f in target.SECURITY_CRITICAL_FIELDS]
            if critical_changes:
                details["security_critical"] = True
                details["critical_fields_changed"] = critical_changes

        # Handle case where AuditLog might not be imported yet
        from .security.audit_log import AuditLog

        # Determine severity based on criticality
        severity = AuditLog.SEVERITY_INFO
        if details.get("security_critical", False):
            severity = AuditLog.SEVERITY_WARNING

        AuditLog.create(
            event_type=AuditLog.EVENT_OBJECT_UPDATED,
            user_id=user_id,
            object_type=target.__class__.__name__,
            object_id=target.id,
            description=f"Updated {target.__class__.__name__} with ID {target.id}",
            ip_address=ip_address,
            details=details,
            severity=severity
        )
    except Exception as e:
        if current_app:
            current_app.logger.error(f"Failed to log model update: {str(e)}")

def _log_model_delete(_mapper, _connection, target):
    """
    Log when a model instance is deleted.

    Args:
        _mapper: SQLAlchemy mapper object (unused)
        _connection: SQLAlchemy connection object (unused)
        target: Model instance that was deleted
    """
    if not has_request_context():
        return

    try:
        # Get user information if available
        user_id = getattr(g, 'user_id', None)
        ip_address = request.remote_addr if request else None

        # Handle case where AuditLog might not be imported yet
        from .security.audit_log import AuditLog

        AuditLog.create(
            event_type=AuditLog.EVENT_OBJECT_DELETED,
            user_id=user_id,
            object_type=target.__class__.__name__,
            object_id=getattr(target, 'id', None),
            description=f"Deleted {target.__class__.__name__} with ID {getattr(target, 'id', 'unknown')}",
            ip_address=ip_address,
            severity=AuditLog.SEVERITY_WARNING  # Deletions get higher severity
        )
    except Exception as e:
        if current_app:
            current_app.logger.error(f"Failed to log model delete: {str(e)}")

def _sanitize_log_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove sensitive fields from data before logging.

    Args:
        data: Dictionary containing model data

    Returns:
        Dict: Sanitized data safe for logging
    """
    if not isinstance(data, dict):
        return {}

    # Fields that should never be logged
    sensitive_fields = {
        'password', 'password_hash', 'token', 'secret', 'key',
        'private_key', 'access_key', 'secret_key', 'api_key',
        'auth_token', 'confirmation_token', 'reset_token',
        'unsubscribe_token', 'salt', 'credentials', 'api_secret',
        'encryption_key', 'security_answer', 'verification_code'
    }

    # Create a copy to avoid modifying the original
    result = data.copy()

    # Remove sensitive fields
    for field in sensitive_fields:
        if field in result:
            result[field] = '[REDACTED]'

    # Check for nested dictionaries that might contain sensitive data
    for key, value in result.items():
        if isinstance(value, dict):
            result[key] = _sanitize_log_data(value)
        elif isinstance(value, list) and value and isinstance(value[0], dict):
            result[key] = [_sanitize_log_data(item) if isinstance(item, dict) else item for item in value]

    # Look for custom _redacted_fields attribute on model
    for field in data.get('_redacted_fields', []):
        if field in result:
            result[field] = '[REDACTED]'

    return result

# Initialize audit listeners
_setup_audit_listeners()
