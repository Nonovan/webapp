"""
Base model definitions for the myproject application.

This module provides the base model class and mixins that are used throughout
the application's data model layer. It establishes common functionality,
consistent patterns, and shared behaviors that all models can inherit.

Key components:
- BaseModel: Abstract base class with CRUD operations and serialization
- TimestampMixin: Adds automatic timestamp tracking for all models
- AuditableMixin: Adds auditing capabilities for security monitoring

These base classes implement the Active Record pattern through SQLAlchemy ORM,
promoting code reuse and ensuring consistent behavior across the data layer.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Type, TypeVar, Union, ClassVar
from flask import current_app, abort, g, has_request_context, request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.hybrid import hybrid_property
from extensions import db

# Define TypeVar with proper constraints for type hinting
T_Model = TypeVar('T_Model', bound='BaseModel')


class TimestampMixin:
    """
    Mixin class that adds created and updated timestamps to models.

    This mixin automatically adds created_at and updated_at timestamp columns
    to any model it's applied to. The timestamps are stored with timezone information
    and are automatically set when records are created or updated.

    The created_at timestamp is set once when the record is first created,
    while updated_at is automatically updated whenever the record is modified.

    Attributes:
        created_at: Datetime when the record was created
        updated_at: Datetime when the record was last updated

    Example:
        class MyModel(db.Model, TimestampMixin):
            # The model will automatically have created_at and updated_at fields
            id = db.Column(db.Integer, primary_key=True)
            name = db.Column(db.String(50))
    """

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )
    
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    
    @hybrid_property
    def age_hours(self) -> float:
        """Calculate age in hours from created_at to now."""
        if not self.created_at:
            return 0
        delta = datetime.now(timezone.utc) - self.created_at
        return delta.total_seconds() / 3600
    
    @hybrid_property
    def last_updated_hours(self) -> float:
        """Calculate hours since last update."""
        if not self.updated_at:
            return 0
        delta = datetime.now(timezone.utc) - self.updated_at
        return delta.total_seconds() / 3600


class AuditableMixin:
    """
    Mixin class that adds auditing capabilities to models.
    
    This mixin provides methods to track changes to model instances and log those
    changes to the audit log for security monitoring and compliance purposes.
    
    Methods:
        log_change: Record a change to the model in the audit log
        log_access: Record access to the model in the audit log
        log_critical_change: Record a security-critical change
    """
    
    # Define security-critical fields that should trigger enhanced logging
    SECURITY_CRITICAL_FIELDS: ClassVar[List[str]] = []
    
    def log_change(self, fields_changed: List[str], details: Optional[str] = None) -> bool:
        """
        Log a change to this model instance to the audit log.
        
        Args:
            fields_changed: List of field names that were changed
            details: Optional details about the change
            
        Returns:
            bool: True if the change was logged successfully
        """
        from core.security_utils import log_security_event
        
        try:
            # Determine if any security-critical fields were changed
            critical = any(field in self.SECURITY_CRITICAL_FIELDS for field in fields_changed)
            severity = 'warning' if critical else 'info'
            
            # Get model name for the event type
            model_name = self.__class__.__name__.lower()
            
            # Log the change
            user_id = g.get('user_id') if has_request_context() and hasattr(g, 'user_id') else None
            ip_address = request.remote_addr if has_request_context() else None
            
            event_details = f"Changed fields: {', '.join(fields_changed)}"
            if details:
                event_details += f" | {details}"
                
            log_security_event(
                event_type=f"{model_name}_modified",
                description=f"{model_name.capitalize()} ID {getattr(self, 'id', 'unknown')} modified",
                severity=severity,
                user_id=user_id,
                ip_address=ip_address,
                details=event_details
            )
            return True
        except (KeyError, AttributeError, RuntimeError) as e:
            if current_app:
                current_app.logger.error(f"Failed to log model change: {e}")
            return False
    
    def log_access(self, access_type: str = 'read') -> bool:
        """
        Log access to this model instance to the audit log.
        
        Args:
            access_type: Type of access (read, list, export, etc.)
            
        Returns:
            bool: True if the access was logged successfully
        """
        # Only log access to sensitive models to avoid log bloat
        if not getattr(self.__class__, 'AUDIT_ACCESS', False):
            return True
            
        from core.security_utils import log_security_event
        
        try:
            # Get model name for the event type
            model_name = self.__class__.__name__.lower()
            
            # Log the access
            user_id = g.get('user_id') if has_request_context() and hasattr(g, 'user_id') else None
            ip_address = request.remote_addr if has_request_context() else None
            
            log_security_event(
                event_type=f"{model_name}_{access_type}",
                description=f"{model_name.capitalize()} ID {getattr(self, 'id', 'unknown')} accessed",
                severity='info',
                user_id=user_id,
                ip_address=ip_address
            )
            return True
        except (KeyError, AttributeError, RuntimeError) as e:
            if current_app:
                current_app.logger.error(f"Failed to log model access: {e}")
            return False
    
    def log_critical_change(self, operation: str, reason: str) -> bool:
        """
        Log a security-critical change to this model instance.
        
        Args:
            operation: Description of the operation (e.g., "password_reset")
            reason: Reason for the critical change
            
        Returns:
            bool: True if the critical change was logged successfully
        """
        from core.security_utils import log_security_event
        
        try:
            # Get model name for the event type
            model_name = self.__class__.__name__.lower()
            
            # Log the critical change
            user_id = g.get('user_id') if has_request_context() and hasattr(g, 'user_id') else None
            ip_address = request.remote_addr if has_request_context() else None
            
            log_security_event(
                event_type=f"{model_name}_{operation}",
                description=f"Critical change to {model_name} ID {getattr(self, 'id', 'unknown')}",
                severity='warning',
                user_id=user_id,
                ip_address=ip_address,
                details=f"Operation: {operation}, Reason: {reason}"
            )
            return True
        except (KeyError, AttributeError, RuntimeError) as e:
            if current_app:
                current_app.logger.error(f"Failed to log critical change: {e}")
            return False


class BaseModel(db.Model, TimestampMixin):
    """
    Abstract base model that provides common functionality for all models.
    
    This class should be used as the base for all models in the application.
    It provides common CRUD operations, serialization, and utility methods.
    
    Attributes:
        __abstract__: SQLAlchemy flag marking this as an abstract class
        
    Class Methods:
        create: Create a new model instance
        get_by_id: Retrieve a model instance by its primary key
        get_or_404: Retrieve a model instance or abort with 404
        
    Instance Methods:
        update: Update instance with new attribute values
        delete: Delete this instance from the database
        to_dict: Convert instance to a dictionary for serialization
    """
    __abstract__ = True

    @classmethod
    def create(cls: Type[T_Model], **kwargs) -> T_Model:
        """
        Create a new instance of the model and save it to the database.
        
        Args:
            **kwargs: Attribute values to set on the new instance
            
        Returns:
            T_Model: The new model instance
            
        Raises:
            SQLAlchemyError: If database error occurs during creation
        """
        try:
            instance = cls(**kwargs)
            db.session.add(instance)
            db.session.commit()
            
            # Log creation if the model supports it
            if isinstance(instance, AuditableMixin):
                model_name = cls.__name__.lower()
                from core.security_utils import log_security_event
                
                user_id = g.get('user_id') if has_request_context() and hasattr(g, 'user_id') else None
                ip_address = request.remote_addr if has_request_context() else None
                
                log_security_event(
                    event_type=f"{model_name}_created",
                    description=f"New {model_name} created with ID {instance.id}",
                    severity='info',
                    user_id=user_id,
                    ip_address=ip_address
                )
                
            return instance  # type: ignore
        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Failed to create {cls.__name__}: {e}")
            raise

    @classmethod
    def get_by_id(cls: Type[T_Model], instance_id: Union[int, str]) -> Optional[T_Model]:
        """
        Retrieve an instance by its primary key.
        
        Args:
            id: Primary key value to look up
            
        Returns:
            Optional[T_Model]: Model instance if found, None otherwise
        """
        return cls.query.get(instance_id)

    @classmethod
    def get_or_404(cls: Type[T_Model], instance_id: Union[int, str], description: Optional[str] = None) -> T_Model:
        """
        Retrieve an instance by its primary key or abort with 404.
        
        Args:
            instance_id: Primary key value to look up
            description: Optional custom message for the 404 error
            
        Returns:
            T_Model: Model instance
            
        Raises:
            HTTPException: 404 error if instance not found
        """
        instance = cls.query.get(instance_id)
        if instance is None:
            abort(404, description=description or f"{cls.__name__} with ID {instance_id} not found")

        # Log access if the model supports it
        if isinstance(instance, AuditableMixin):
            instance.log_access()

        return instance  # type: ignore

    def update(self, **kwargs) -> bool:
        """
        Update the instance with new attribute values.
        
        Args:
            **kwargs: Attribute values to update
            
        Returns:
            bool: True if update was successful
            
        Raises:
            SQLAlchemyError: If database error occurs during update
        """
        try:
            # Keep track of changed fields for auditing
            fields_changed = []

            for key, value in kwargs.items():
                if hasattr(self, key) and getattr(self, key) != value:
                    fields_changed.append(key)
                    setattr(self, key, value)

            if not fields_changed:
                return True  # No changes made

            db.session.commit()

            # Log change if the model supports it
            if isinstance(self, AuditableMixin) and fields_changed:
                self.log_change(fields_changed)

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Failed to update {self.__class__.__name__}: {e}")
            raise

    def delete(self) -> bool:
        """
        Delete the instance from the database.
        
        Returns:
            bool: True if deletion was successful
            
        Raises:
            SQLAlchemyError: If database error occurs during deletion
        """
        try:
            # Log deletion if the model supports it
            if isinstance(self, AuditableMixin):
                model_name = self.__class__.__name__.lower()
                from core.security_utils import log_security_event

                user_id = g.get('user_id') if has_request_context() and hasattr(g, 'user_id') else None
                ip_address = request.remote_addr if has_request_context() else None

                log_security_event(
                    event_type=f"{model_name}_deleted",
                    description=f"{model_name.capitalize()} ID {getattr(self, 'id', 'unknown')} deleted",
                    severity='warning',
                    user_id=user_id,
                    ip_address=ip_address
                )

            db.session.delete(self)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Failed to delete {self.__class__.__name__}: {e}")
            raise

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the instance to a dictionary for serialization.
        
        This provides a default implementation that includes all columns.
        Subclasses should override this to customize the serialization.
        
        Returns:
            Dict[str, Any]: Dictionary representation of the instance
        """
        # Start with a dictionary of column attributes
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)

            # Handle datetime objects for JSON serialization
            if isinstance(value, datetime):
                value = value.isoformat()

            result[column.name] = value

        return result

    @classmethod
    def filter_by_date_range(cls, start_date: datetime, end_date: datetime, 
                          date_column: str = 'created_at') -> List['BaseModel']:
        """
        Get all instances within a given date range.
        
        Args:
            start_date: Start date for filtering
            end_date: End date for filtering
            date_column: Column name to filter on (default: created_at)
            
        Returns:
            List[T_Model]: List of matching instances
        """
        column = getattr(cls, date_column)
        return cls.query.filter(column >= start_date, column <= end_date).all()
