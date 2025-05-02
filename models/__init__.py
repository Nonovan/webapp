"""
Data models package for the Cloud Infrastructure Platform.

This package defines the application's data model layer using SQLAlchemy ORM, providing
a clean, Pythonic interface to the underlying database. It includes:

- A base model implementation with common functionality for all models
- Mixin classes for shared behaviors like timestamp tracking
- Type definitions and annotations for static type checking
- Custom model exception types
- Helper methods for data serialization and validation
- Security-focused audit logging for sensitive operations

The models implement the Active Record pattern through SQLAlchemy, where each model
instance represents a row in the database and provides methods for CRUD operations.
This approach encapsulates database operations within the models themselves, promoting
code organization and reusability.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Type, Union, cast, Set, TypeVar

from flask import current_app, g, request, has_request_context
from sqlalchemy import event
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.declarative import declared_attr

from extensions import db, metrics

# Set up package logger
logger = logging.getLogger(__name__)

# Import base classes first to avoid circular imports
from .base import BaseModel, TimestampMixin, AuditableMixin

# Define a type variable for generic functions
T_Model = TypeVar('T_Model', bound=BaseModel)

# Export bulk operations directly from BaseModel
bulk_create = BaseModel.bulk_create
bulk_update = BaseModel.bulk_update
bulk_delete = BaseModel.bulk_delete
paginate = BaseModel.paginate
get_or_create = BaseModel.get_or_create

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
from .communication.comm_log import CommunicationLog
from .communication.comm_channel import CommunicationChannel
from .communication.comm_scheduler import CommunicationScheduler

# Security models
from .security.security_incident import SecurityIncident
from .security.audit_log import AuditLog
from .security.system_config import SystemConfig
from .security.login_attempt import LoginAttempt

# Cloud models
from .cloud.cloud_provider import CloudProvider
from .cloud.cloud_resource import CloudResource
from .cloud.cloud_metric import CloudMetric
from .cloud.cloud_alert import CloudAlert

# Storage models
from .storage.file_upload import FileUpload
from .storage.file_metadata import FileMetadata

# ICS models
from .ics.ics_device import ICSDevice
from .ics.ics_reading import ICSReading
from .ics.ics_control_log import ICSControlLog

# Alert models
from .alerts.alert import Alert
from .alerts.alert_correlation import AlertCorrelation
from .alerts.alert_notification import AlertNotification
from .alerts.alert_escalation import AlertEscalation
from .alerts.alert_suppression import AlertSuppression
from .alerts.alert_metrics import AlertMetrics

# Import threat intelligence conditionally
try:
    from .security.threat_intelligence import ThreatIndicator, ThreatFeed
    THREAT_INTELLIGENCE_AVAILABLE = True
except ImportError:
    THREAT_INTELLIGENCE_AVAILABLE = False

# Import security baseline conditionally
try:
    from .security.security_baseline import SecurityBaseline
    SECURITY_BASELINE_AVAILABLE = True
except ImportError:
    SECURITY_BASELINE_AVAILABLE = False

# Build the __all__ list for proper exports
__all__ = [
    # Core components
    'db', 'BaseModel', 'TimestampMixin', 'AuditableMixin',
    'bulk_update_models', 'bulk_create', 'bulk_update', 'bulk_delete', 'paginate', 'get_or_create',

    # Auth models
    'User', 'Role', 'Permission', 'UserSession', 'UserActivity',

    # Content models
    'Post', 'Category', 'Tag',

    # Communication models
    'Subscriber', 'MailingList', 'SubscriberList', 'Notification',
    'WebhookSubscription', 'WebhookDelivery', 'SubscriberCategory',
    'CommunicationLog', 'CommunicationChannel', 'CommunicationScheduler',

    # Security models
    'SecurityIncident', 'AuditLog', 'SystemConfig', 'LoginAttempt',

    # Cloud infrastructure models
    'CloudProvider', 'CloudResource', 'CloudMetric', 'CloudAlert',

    # Storage models
    'FileUpload', 'FileMetadata',

    # ICS models
    'ICSDevice', 'ICSReading', 'ICSControlLog',

    # Alert models
    'Alert', 'AlertCorrelation', 'AlertNotification', 'AlertEscalation', 'AlertSuppression', 'AlertMetrics',
]

# Add conditionally imported models to __all__
if THREAT_INTELLIGENCE_AVAILABLE:
    __all__.extend(['ThreatIndicator', 'ThreatFeed'])

if SECURITY_BASELINE_AVAILABLE:
    __all__.append('SecurityBaseline')

# Define constants for security-sensitive fields
# This centralized list makes it easier to maintain and update
SENSITIVE_FIELDS: Set[str] = {
    'password', 'password_hash', 'token', 'secret', 'key',
    'private_key', 'access_key', 'secret_key', 'api_key',
    'auth_token', 'confirmation_token', 'reset_token',
    'unsubscribe_token', 'salt', 'credentials', 'api_secret',
    'encryption_key', 'security_answer', 'verification_code',
    'passphrase', 'certificate_key', 'client_secret', 'mfa_secret',
    'cookie_value', 'csrf_token', 'session_key', 'oauth_token',
    'jwt_secret', 'otac', 'recovery_code', 'signature'
}

# Define pattern fragments that indicate sensitive data
SENSITIVE_PATTERNS: List[str] = [
    'password', 'token', 'secret', 'key', 'auth', 'credential',
    'apikey', 'api_key', 'private', 'salt', 'hash', 'cipher',
    'encrypt', 'access', 'verify', 'session', 'cookie', 'cert'
]

def _setup_audit_listeners() -> None:
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
        MailingList,
        LoginAttempt
    ]

    # Add conditionally imported models
    if THREAT_INTELLIGENCE_AVAILABLE:
        models_to_audit.extend([ThreatIndicator, ThreatFeed])

    if SECURITY_BASELINE_AVAILABLE:
        models_to_audit.append(SecurityBaseline)

    for model in models_to_audit:
        # Set up listeners for each audit event type
        event.listen(model, 'after_insert', _log_model_insert)
        event.listen(model, 'after_update', _log_model_update)
        event.listen(model, 'after_delete', _log_model_delete)

    logger.debug(f"Set up audit listeners for {len(models_to_audit)} models")

def _log_model_insert(_mapper, _connection, target) -> None:
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
            except Exception as e:
                # Fallback if to_dict fails, with better error handling
                if current_app:
                    current_app.logger.warning(f"Failed to convert model to dict: {str(e)}")
                details = {"id": getattr(target, 'id', None)}

        # Handle case where AuditLog might not be imported yet
        from .security.audit_log import AuditLog

        # Check for security-critical fields
        severity = AuditLog.SEVERITY_INFO
        if hasattr(target, 'SECURITY_CRITICAL_FIELDS') and len(getattr(target, 'SECURITY_CRITICAL_FIELDS', [])) > 0:
            severity = AuditLog.SEVERITY_WARNING
            details["contains_security_critical"] = True

        obj_id = getattr(target, 'id', None)
        obj_id_str = str(obj_id) if obj_id is not None else 'unknown'

        AuditLog.create(
            event_type=AuditLog.EVENT_OBJECT_CREATED,
            user_id=user_id,
            object_type=target.__class__.__name__,
            object_id=obj_id,
            description=f"Created {target.__class__.__name__} with ID {obj_id_str}",
            ip_address=ip_address,
            details=details,
            severity=severity
        )

        # Track model creation in metrics
        if hasattr(metrics, 'counter'):
            try:
                metrics.counter(
                    'model_operations_total',
                    labels={
                        'operation': 'create',
                        'model': target.__class__.__name__,
                        'security_level': severity
                    }
                ).inc()
            except Exception:
                pass

    except Exception as e:
        if current_app:
            current_app.logger.error(f"Failed to log model insert: {str(e)}")

def _log_model_update(_mapper, _connection, target) -> None:
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
            except Exception as e:
                if current_app:
                    current_app.logger.warning(f"Failed to get changed columns: {str(e)}")

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

        # Ensure target has an ID attribute before accessing it
        obj_id = getattr(target, 'id', None)
        if obj_id is None:
            if current_app:
                current_app.logger.warning(f"Cannot log update for {target.__class__.__name__} with no ID")
            return

        AuditLog.create(
            event_type=AuditLog.EVENT_OBJECT_UPDATED,
            user_id=user_id,
            object_type=target.__class__.__name__,
            object_id=obj_id,
            description=f"Updated {target.__class__.__name__} with ID {obj_id}",
            ip_address=ip_address,
            details=details,
            severity=severity
        )

        # Track model update in metrics
        if hasattr(metrics, 'counter'):
            try:
                metrics.counter(
                    'model_operations_total',
                    labels={
                        'operation': 'update',
                        'model': target.__class__.__name__,
                        'security_level': severity
                    }
                ).inc()

                # Track critical updates separately
                if details.get("security_critical", False):
                    metrics.counter(
                        'model_critical_updates_total',
                        labels={
                            'model': target.__class__.__name__
                        }
                    ).inc()
            except Exception:
                pass

    except Exception as e:
        if current_app:
            current_app.logger.error(f"Failed to log model update: {str(e)}")

def _log_model_delete(_mapper, _connection, target) -> None:
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

        # Get object ID safely
        obj_id = getattr(target, 'id', None)
        obj_id_str = str(obj_id) if obj_id is not None else 'unknown'

        # For deletions, we might want to capture more information about the deleted object
        details = {}
        if hasattr(target, 'to_dict'):
            try:
                # Include sanitized data about the deleted object
                details["deleted_object"] = _sanitize_log_data(target.to_dict())
            except Exception:
                # If to_dict fails, at least capture the ID
                details["deleted_object_id"] = obj_id

        # Determine severity based on model type
        severity = AuditLog.SEVERITY_WARNING  # Default severity for deletions

        # Higher severity for critical models
        critical_model_classes = [User, Role, Permission, SecurityIncident, SystemConfig]
        if any(isinstance(target, cls) for cls in critical_model_classes):
            severity = AuditLog.SEVERITY_ERROR

        AuditLog.create(
            event_type=AuditLog.EVENT_OBJECT_DELETED,
            user_id=user_id,
            object_type=target.__class__.__name__,
            object_id=obj_id,
            description=f"Deleted {target.__class__.__name__} with ID {obj_id_str}",
            ip_address=ip_address,
            severity=severity,
            details=details
        )

        # Track model deletion in metrics
        if hasattr(metrics, 'counter'):
            try:
                metrics.counter(
                    'model_operations_total',
                    labels={
                        'operation': 'delete',
                        'model': target.__class__.__name__,
                        'security_level': severity
                    }
                ).inc()
            except Exception:
                pass

    except Exception as e:
        if current_app:
            current_app.logger.error(f"Failed to log model delete: {str(e)}")

def _sanitize_log_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove sensitive fields from data before logging.

    This function implements multiple strategies to identify and redact sensitive information:
    1. Exact match with known sensitive field names
    2. Pattern matching for field names containing sensitive fragments
    3. Custom field redaction specified by the model

    Args:
        data: Dictionary containing model data

    Returns:
        Dict: Sanitized data safe for logging
    """
    if not isinstance(data, dict):
        return {}

    # Create a copy to avoid modifying the original
    result = data.copy()

    # Remove sensitive fields by exact match
    for field in SENSITIVE_FIELDS:
        if field in result:
            result[field] = '[REDACTED]'

    # Additional pattern-based check for sensitive data
    for key in list(result.keys()):
        key_lower = key.lower()
        # Check for pattern match with sensitive field fragments
        if any(pattern in key_lower for pattern in SENSITIVE_PATTERNS):
            result[key] = '[REDACTED]'

    # Check for nested dictionaries that might contain sensitive data
    for key, value in list(result.items()):
        if isinstance(value, dict):
            result[key] = _sanitize_log_data(value)
        elif isinstance(value, list):
            # Process each item in the list
            result[key] = _sanitize_list_items(value)
        elif isinstance(value, str) and _looks_like_token(value):
            # Redact strings that look like authorization tokens or longer hex values
            result[key] = '[POSSIBLE TOKEN REDACTED]'

    # Look for custom _redacted_fields attribute on model
    for field in data.get('_redacted_fields', []):
        if field in result:
            result[field] = '[REDACTED]'

    return result

def _sanitize_list_items(items: List[Any]) -> List[Any]:
    """
    Sanitize items in a list that might contain sensitive data.

    Args:
        items: List of items to sanitize

    Returns:
        List: Sanitized list
    """
    if not items:
        return []

    result = []
    for item in items:
        if isinstance(item, dict):
            result.append(_sanitize_log_data(item))
        elif isinstance(item, list):
            result.append(_sanitize_list_items(item))
        else:
            result.append(item)

    return result

def _looks_like_token(value: str) -> bool:
    """
    Check if a string value looks like it might be a token.

    This is a heuristic check that looks for characteristics common in tokens:
    - Length >= 32 characters
    - Alphanumeric with some special characters typical of base64 or hex encoding
    - Few or no spaces

    Args:
        value: String value to check

    Returns:
        bool: True if the string looks like a token
    """
    if not isinstance(value, str):
        return False

    # Skip short strings
    if len(value) < 32:
        return False

    # Skip strings with lots of spaces (likely not tokens)
    if value.count(' ') > 3:
        return False

    # Check for common token patterns
    import re
    # JWT pattern (header.payload.signature)
    if re.match(r'^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', value):
        return True

    # OAuth/Bearer token pattern (mostly base64 chars)
    if re.match(r'^[A-Za-z0-9+/=_-]{32,}$', value):
        return True

    # Long hex string (like API keys, nonces, etc.)
    if re.match(r'^[A-Fa-f0-9]{32,}$', value):
        return True

    return False

def bulk_update_models(model_class: Type[BaseModel], model_ids: List[int],
                      update_data: Dict[str, Any], commit: bool = True) -> Dict[str, Any]:
    """
    Update multiple model instances with the same attribute values.

    Args:
        model_class: The model class to update
        model_ids: List of model IDs to update
        update_data: Dictionary of attribute values to update
        commit: Whether to commit the transaction (default: True)

    Returns:
        Dict: Result information including count of updated records and any errors

    Example:
        result = bulk_update_models(Post, [1, 2, 3], {"status": "published", "published_at": datetime.now()})
    """
    if not issubclass(model_class, BaseModel):
        raise TypeError(f"model_class must be a subclass of BaseModel, got {model_class.__name__}")

    if not model_ids:
        return {"updated_count": 0, "error": None, "skipped": []}

    result = {
        "updated_count": 0,
        "error": None,
        "skipped": []
    }

    try:
        # Find all matching records
        records = model_class.query.filter(model_class.id.in_(model_ids)).all()
        found_ids = {record.id for record in records}

        # Track IDs that weren't found
        result["skipped"] = [id for id in model_ids if id not in found_ids]

        # Update each record
        for record in records:
            try:
                # Use the model's update method which includes proper audit logging
                record.update(commit=False, **update_data)
                result["updated_count"] += 1
            except Exception as e:
                result["skipped"].append(record.id)
                if current_app:
                    current_app.logger.warning(
                        f"Failed to update {model_class.__name__} with ID {record.id}: {str(e)}"
                    )

        # Commit all changes at once if requested
        if commit and result["updated_count"] > 0:
            db.session.commit()

            # Log bulk update as a separate audit event if we have request context
            if has_request_context():
                try:
                    from .security.audit_log import AuditLog

                    user_id = getattr(g, 'user_id', None)
                    ip_address = request.remote_addr if request else None

                    # Determine if any security-critical fields are being updated
                    security_critical = False
                    if hasattr(model_class, 'SECURITY_CRITICAL_FIELDS'):
                        security_critical = any(field in model_class.SECURITY_CRITICAL_FIELDS for field in update_data.keys())

                    severity = AuditLog.SEVERITY_WARNING if security_critical else AuditLog.SEVERITY_INFO

                    AuditLog.create(
                        event_type=AuditLog.EVENT_BULK_UPDATE,
                        user_id=user_id,
                        object_type=model_class.__name__,
                        description=f"Bulk updated {result['updated_count']} {model_class.__name__} records",
                        ip_address=ip_address,
                        details={
                            "updated_fields": list(update_data.keys()),
                            "updated_count": result["updated_count"],
                            "skipped_ids": result["skipped"],
                            "security_critical": security_critical
                        },
                        severity=severity
                    )

                    # Track bulk updates in metrics
                    if hasattr(metrics, 'counter'):
                        metrics.counter(
                            'model_bulk_operations_total',
                            labels={
                                'model': model_class.__name__,
                                'operation': 'update',
                                'security_level': severity
                            }
                        ).inc()

                except Exception as e:
                    if current_app:
                        current_app.logger.error(f"Failed to log bulk update: {str(e)}")

    except SQLAlchemyError as e:
        db.session.rollback()
        error_message = str(e)
        result["error"] = error_message
        if current_app:
            current_app.logger.error(f"Database error during bulk update of {model_class.__name__}: {error_message}")

    return result

# Initialize audit listeners
_setup_audit_listeners()

# Version information
__version__ = '0.1.1'

# Log initialization
logger.debug(f"Models package initialized, version {__version__}")
