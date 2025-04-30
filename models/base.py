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
import logging
from typing import Dict, Any, Optional, List, Type, TypeVar, Union, ClassVar, cast, Tuple
from flask import current_app, abort, g, has_request_context, request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.inspection import inspect
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
            return 0.0
        delta = datetime.now(timezone.utc) - self.created_at
        return delta.total_seconds() / 3600

    @hybrid_property
    def last_updated_hours(self) -> float:
        """Calculate hours since last update."""
        if not self.updated_at:
            return 0.0
        delta = datetime.now(timezone.utc) - self.updated_at
        return delta.total_seconds() / 3600


class AuditableMixin:
    """
    Mixin class that adds auditing capabilities to models.

    This mixin provides methods to track changes to model instances and log those
    changes to the audit log for security monitoring and compliance purposes.

    Class Attributes:
        SECURITY_CRITICAL_FIELDS: List of field names that are considered security-critical
        AUDIT_ACCESS: Whether to audit access to this model (default: False)

    Methods:
        log_change: Record a change to the model in the audit log
        log_access: Record access to the model in the audit log
        log_critical_change: Record a security-critical change
    """

    # Define security-critical fields that should trigger enhanced logging
    SECURITY_CRITICAL_FIELDS: ClassVar[List[str]] = []

    # Flag to determine if access to this model should be audited
    AUDIT_ACCESS: ClassVar[bool] = False

    def log_change(self, fields_changed: List[str], details: Optional[str] = None) -> bool:
        """
        Log a change to this model instance to the audit log.

        Args:
            fields_changed: List of field names that were changed
            details: Optional details about the change

        Returns:
            bool: True if the change was logged successfully
        """
        try:
            from core.security_utils import log_security_event

            # Determine if any security-critical fields were changed
            critical = any(field in self.SECURITY_CRITICAL_FIELDS for field in fields_changed)
            severity = 'warning' if critical else 'info'

            # Get model name for the event type
            model_name = self.__class__.__name__.lower()
            instance_id = getattr(self, 'id', 'unknown')

            # Log the change
            user_id = g.get('user_id') if has_request_context() and hasattr(g, 'user_id') else None
            ip_address = request.remote_addr if has_request_context() else None

            event_details = f"Changed fields: {', '.join(fields_changed)}"
            if details:
                event_details += f" | {details}"

            log_security_event(
                event_type=f"{model_name}_modified",
                description=f"{model_name.capitalize()} ID {instance_id} modified",
                severity=severity,
                user_id=user_id,
                ip_address=ip_address,
                details=event_details
            )
            return True
        except (KeyError, AttributeError, RuntimeError, ImportError) as e:
            logger = current_app.logger if current_app else logging.getLogger(__name__)
            logger.error("Failed to log model change: %s", str(e))
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

        try:
            from core.security_utils import log_security_event

            # Get model name for the event type
            model_name = self.__class__.__name__.lower()
            instance_id = getattr(self, 'id', 'unknown')

            # Log the access
            user_id = g.get('user_id') if has_request_context() and hasattr(g, 'user_id') else None
            ip_address = request.remote_addr if has_request_context() else None

            log_security_event(
                event_type=f"{model_name}_{access_type}",
                description=f"{model_name.capitalize()} ID {instance_id} accessed",
                severity='info',
                user_id=user_id,
                ip_address=ip_address
            )
            return True
        except (KeyError, AttributeError, RuntimeError, ImportError) as e:
            logger = current_app.logger if current_app else logging.getLogger(__name__)
            logger.error("Failed to log model access: %s", str(e))
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
        try:
            from core.security_utils import log_security_event

            # Get model name for the event type
            model_name = self.__class__.__name__.lower()
            instance_id = getattr(self, 'id', 'unknown')

            # Log the critical change
            user_id = g.get('user_id') if has_request_context() and hasattr(g, 'user_id') else None
            ip_address = request.remote_addr if has_request_context() else None

            log_security_event(
                event_type=f"{model_name}_{operation}",
                description=f"Critical change to {model_name} ID {instance_id}",
                severity='warning',
                user_id=user_id,
                ip_address=ip_address,
                details=f"Operation: {operation}, Reason: {reason}"
            )
            return True
        except (KeyError, AttributeError, RuntimeError, ImportError) as e:
            logger = current_app.logger if current_app else logging.getLogger(__name__)
            logger.error("Failed to log critical change: %s", str(e))
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
        filter_by_date_range: Get instances within a date range

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
                try:
                    from core.security_utils import log_security_event

                    model_name = cls.__name__.lower()
                    instance_id = getattr(instance, 'id', 'unknown')

                    user_id = g.get('user_id') if has_request_context() and hasattr(g, 'user_id') else None
                    ip_address = request.remote_addr if has_request_context() else None

                    log_security_event(
                        event_type=f"{model_name}_created",
                        description=f"New {model_name} created with ID {instance_id}",
                        severity='info',
                        user_id=user_id,
                        ip_address=ip_address
                    )
                except (ImportError, AttributeError) as e:
                    logger = current_app.logger if current_app else logging.getLogger(__name__)
                    logger.error("Failed to log model creation: %s", str(e))

            return cast(T_Model, instance)
        except SQLAlchemyError as e:
            db.session.rollback()
            logger = current_app.logger if current_app else logging.getLogger(__name__)
            logger.error("Failed to create %s: %s", cls.__name__, str(e))
            raise

    @classmethod
    def get_by_id(cls: Type[T_Model], instance_id: Union[int, str]) -> Optional[T_Model]:
        """
        Retrieve an instance by its primary key.

        Args:
            instance_id: Primary key value to look up

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
        if isinstance(instance, AuditableMixin) and getattr(cls, 'AUDIT_ACCESS', False):
            instance.log_access()

        return cast(T_Model, instance)

    def update(self, commit: bool = True, **kwargs) -> bool:
        """
        Update the instance with new attribute values.

        Args:
            commit: Whether to commit the transaction immediately (default: True)
            **kwargs: Attribute values to update

        Returns:
            bool: True if update was successful, False otherwise

        Raises:
            SQLAlchemyError: If database error occurs during update
        """
        try:
            # Keep track of changed fields for auditing
            fields_changed = []
            old_values = {}

            for key, value in kwargs.items():
                if hasattr(self, key):
                    current_value = getattr(self, key)
                    # Only update if value has changed
                    if current_value != value:
                        fields_changed.append(key)
                        old_values[key] = current_value
                        setattr(self, key, value)
                else:
                    logger = current_app.logger if current_app else logging.getLogger(__name__)
                    logger.warning("Attempted to update non-existent attribute %s on %s",
                                  key, self.__class__.__name__)

            # If no changes made, return early
            if not fields_changed:
                return True

            if commit:
                db.session.commit()

            # Log change if the model supports it
            if isinstance(self, AuditableMixin) and fields_changed:
                changes_detail = ", ".join([f"{field}: {old_values[field]} → {getattr(self, field)}"
                                        for field in fields_changed[:5]])  # Limit detail to first 5 changes
                if len(fields_changed) > 5:
                    changes_detail += f" and {len(fields_changed) - 5} more fields"

                self.log_change(fields_changed, f"Updated fields: {changes_detail}")

            return True

        except SQLAlchemyError as e:
            if commit:
                db.session.rollback()
            logger = current_app.logger if current_app else logging.getLogger(__name__)
            logger.error("Failed to update %s: %s", self.__class__.__name__, str(e))
            return False

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
                try:
                    from core.security_utils import log_security_event

                    model_name = self.__class__.__name__.lower()
                    instance_id = getattr(self, 'id', 'unknown')

                    user_id = g.get('user_id') if has_request_context() and hasattr(g, 'user_id') else None
                    ip_address = request.remote_addr if has_request_context() else None

                    log_security_event(
                        event_type=f"{model_name}_deleted",
                        description=f"{model_name.capitalize()} ID {instance_id} deleted",
                        severity='warning',
                        user_id=user_id,
                        ip_address=ip_address
                    )
                except (ImportError, AttributeError) as e:
                    logger = current_app.logger if current_app else logging.getLogger(__name__)
                    logger.error("Failed to log model deletion: %s", str(e))

            db.session.delete(self)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            logger = current_app.logger if current_app else logging.getLogger(__name__)
            logger.error("Failed to delete %s: %s", self.__class__.__name__, str(e))
            raise

    def to_dict(self, include_relationships: bool = False, max_depth: int = 1) -> Dict[str, Any]:
        """
        Convert the instance to a dictionary for serialization.

        Args:
            include_relationships: Whether to include relationships in the output
            max_depth: Maximum depth for nested relationship serialization

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

        # Include relationships if requested and depth allows
        if include_relationships and max_depth > 0:
            for relationship in inspect(self.__class__).relationships:
                # Skip back-references to avoid circular references
                if relationship.back_populates or relationship.backref:
                    continue

                rel_obj = getattr(self, relationship.key)

                # Handle collections (one-to-many, many-to-many)
                if hasattr(rel_obj, '__iter__'):
                    result[relationship.key] = [
                        item.to_dict(include_relationships=True, max_depth=max_depth-1)
                        for item in rel_obj
                    ] if rel_obj else []
                # Handle scalar relationships (many-to-one, one-to-one)
                elif rel_obj is not None:
                    result[relationship.key] = rel_obj.to_dict(
                        include_relationships=True,
                        max_depth=max_depth-1
                    )
                else:
                    result[relationship.key] = None

        return result

    @classmethod
    def filter_by_date_range(cls: Type[T_Model], start_date: datetime, end_date: datetime,
                          date_column: str = 'created_at') -> List[T_Model]:
        """
        Get all instances within a given date range.

        Args:
            start_date: Start date for filtering
            end_date: End date for filtering
            date_column: Column name to filter on (default: created_at)

        Returns:
            List[T_Model]: List of matching instances

        Raises:
            AttributeError: If the specified date_column does not exist
        """
        if not hasattr(cls, date_column):
            raise AttributeError(f"{cls.__name__} has no attribute '{date_column}'")

        column = getattr(cls, date_column)
        return cast(List[T_Model], cls.query.filter(column >= start_date, column <= end_date).all())

    @classmethod
    def bulk_create(cls: Type[T_Model], items: List[Dict[str, Any]],
                   return_instances: bool = False,
                   commit: bool = True) -> Union[int, List[T_Model]]:
        """
        Create multiple model instances in bulk.

        Args:
            items: List of dictionaries containing attributes for each instance
            return_instances: Whether to return the created instances (default: False)
            commit: Whether to commit the transaction immediately (default: True)

        Returns:
            Union[int, List[T_Model]]: Count of created instances or list of instances

        Raises:
            SQLAlchemyError: If database error occurs during creation
        """
        try:
            instances = [cls(**item) for item in items]
            db.session.add_all(instances)

            if commit:
                db.session.commit()

                # Log bulk creation if the model supports it
                if instances and isinstance(instances[0], AuditableMixin):
                    try:
                        from core.security_utils import log_security_event

                        model_name = cls.__name__.lower()
                        user_id = g.get('user_id') if has_request_context() and hasattr(g, 'user_id') else None
                        ip_address = request.remote_addr if has_request_context() else None

                        log_security_event(
                            event_type=f"{model_name}_bulk_created",
                            description=f"Created {len(instances)} {model_name} records",
                            severity='info',
                            user_id=user_id,
                            ip_address=ip_address,
                            details={
                                "count": len(instances)
                            }
                        )
                    except (ImportError, AttributeError) as e:
                        logger = current_app.logger if current_app else logging.getLogger(__name__)
                        logger.error("Failed to log bulk creation: %s", str(e))

            if return_instances:
                return instances
            return len(instances)

        except SQLAlchemyError as e:
            if commit:
                db.session.rollback()
            logger = current_app.logger if current_app else logging.getLogger(__name__)
            logger.error("Failed to bulk create %s: %s", cls.__name__, str(e))
            raise

    @classmethod
    def bulk_update(cls: Type[T_Model], items: Dict[Union[int, str], Dict[str, Any]],
                   commit: bool = True) -> Dict[str, Any]:
        """
        Update multiple model instances in bulk.

        Args:
            items: Dictionary mapping primary keys to attribute dictionaries
            commit: Whether to commit the transaction immediately (default: True)

        Returns:
            Dict[str, Any]: Result statistics with updated_count, skipped_ids, etc.

        Raises:
            SQLAlchemyError: If database error occurs during update
        """
        result = {
            "updated_count": 0,
            "skipped_ids": [],
            "error": None
        }

        try:
            # Get all instances at once to reduce database roundtrips
            instance_ids = list(items.keys())
            instances = cls.query.filter(cls.id.in_(instance_ids)).all()
            found_instances = {instance.id: instance for instance in instances}

            # Track changed fields for audit logging
            all_changed_fields = set()

            # Update each instance with the provided attributes
            for instance_id, attributes in items.items():
                instance = found_instances.get(instance_id)
                if not instance:
                    result["skipped_ids"].append(instance_id)
                    continue

                # Track changes for this instance
                fields_changed = []
                old_values = {}

                for key, value in attributes.items():
                    if hasattr(instance, key):
                        current_value = getattr(instance, key)
                        # Only update if value has changed
                        if current_value != value:
                            fields_changed.append(key)
                            old_values[key] = current_value
                            setattr(instance, key, value)
                            all_changed_fields.add(key)

                # Count as updated only if changes were made
                if fields_changed:
                    result["updated_count"] += 1

                    # Log individual changes if the model supports it
                    if isinstance(instance, AuditableMixin) and fields_changed:
                        changes_detail = ", ".join([f"{field}: {old_values[field]} → {getattr(instance, field)}"
                                                for field in fields_changed[:5]])
                        if len(fields_changed) > 5:
                            changes_detail += f" and {len(fields_changed) - 5} more fields"

                        instance.log_change(fields_changed, f"Updated fields: {changes_detail}")

            # Commit all changes at once if requested
            if commit and result["updated_count"] > 0:
                db.session.commit()

                # Log bulk update if any instances were updated and they support auditing
                if instances and isinstance(instances[0], AuditableMixin):
                    try:
                        from core.security_utils import log_security_event

                        model_name = cls.__name__.lower()
                        user_id = g.get('user_id') if has_request_context() and hasattr(g, 'user_id') else None
                        ip_address = request.remote_addr if has_request_context() else None

                        log_security_event(
                            event_type=f"{model_name}_bulk_updated",
                            description=f"Updated {result['updated_count']} {model_name} records",
                            severity='info',
                            user_id=user_id,
                            ip_address=ip_address,
                            details={
                                "count": result["updated_count"],
                                "fields": list(all_changed_fields),
                                "skipped": result["skipped_ids"]
                            }
                        )
                    except (ImportError, AttributeError) as e:
                        logger = current_app.logger if current_app else logging.getLogger(__name__)
                        logger.error("Failed to log bulk update: %s", str(e))

            return result

        except SQLAlchemyError as e:
            if commit:
                db.session.rollback()
            error_message = str(e)
            result["error"] = error_message
            logger = current_app.logger if current_app else logging.getLogger(__name__)
            logger.error("Failed to bulk update %s: %s", cls.__name__, error_message)
            return result

    @classmethod
    def bulk_delete(cls: Type[T_Model], instance_ids: List[Union[int, str]],
                   commit: bool = True) -> Dict[str, Any]:
        """
        Delete multiple model instances in bulk.

        Args:
            instance_ids: List of primary keys to delete
            commit: Whether to commit the transaction immediately (default: True)

        Returns:
            Dict[str, Any]: Result statistics with deleted_count, skipped_ids, etc.

        Raises:
            SQLAlchemyError: If database error occurs during deletion
        """
        result = {
            "deleted_count": 0,
            "skipped_ids": [],
            "error": None
        }

        try:
            # Get instances for audit logging before deletion
            if hasattr(AuditableMixin, '__subclasses__') and cls in AuditableMixin.__subclasses__():
                # For auditable models, fetch instances first to log details
                instances = cls.query.filter(cls.id.in_(instance_ids)).all()
                found_ids = {instance.id for instance in instances}
                result["skipped_ids"] = [id for id in instance_ids if id not in found_ids]

                # Log deletions individually
                for instance in instances:
                    if isinstance(instance, AuditableMixin):
                        try:
                            from core.security_utils import log_security_event

                            model_name = cls.__name__.lower()
                            instance_id = getattr(instance, 'id', 'unknown')

                            user_id = g.get('user_id') if has_request_context() and hasattr(g, 'user_id') else None
                            ip_address = request.remote_addr if has_request_context() else None

                            log_security_event(
                                event_type=f"{model_name}_deleted",
                                description=f"{model_name.capitalize()} ID {instance_id} deleted",
                                severity='warning',
                                user_id=user_id,
                                ip_address=ip_address
                            )
                        except (ImportError, AttributeError) as e:
                            logger = current_app.logger if current_app else logging.getLogger(__name__)
                            logger.error("Failed to log model deletion: %s", str(e))

                # Perform the deletion
                delete_query = cls.__table__.delete().where(cls.id.in_(found_ids))
                result["deleted_count"] = db.session.execute(delete_query).rowcount
            else:
                # For non-auditable models, use the more efficient direct delete
                delete_query = cls.__table__.delete().where(cls.id.in_(instance_ids))
                result["deleted_count"] = db.session.execute(delete_query).rowcount

            if commit:
                db.session.commit()

                # Log bulk deletion
                try:
                    from core.security_utils import log_security_event

                    model_name = cls.__name__.lower()
                    user_id = g.get('user_id') if has_request_context() and hasattr(g, 'user_id') else None
                    ip_address = request.remote_addr if has_request_context() else None

                    log_security_event(
                        event_type=f"{model_name}_bulk_deleted",
                        description=f"Deleted {result['deleted_count']} {model_name} records",
                        severity='warning',
                        user_id=user_id,
                        ip_address=ip_address,
                        details={
                            "count": result["deleted_count"],
                            "skipped": result["skipped_ids"]
                        }
                    )
                except (ImportError, AttributeError) as e:
                    logger = current_app.logger if current_app else logging.getLogger(__name__)
                    logger.error("Failed to log bulk deletion: %s", str(e))

            return result

        except SQLAlchemyError as e:
            if commit:
                db.session.rollback()
            error_message = str(e)
            result["error"] = error_message
            logger = current_app.logger if current_app else logging.getLogger(__name__)
            logger.error("Failed to bulk delete %s: %s", cls.__name__, error_message)
            return result

    @classmethod
    def paginate(cls: Type[T_Model], page: int = 1, per_page: int = 20,
                filters: Optional[Dict[str, Any]] = None,
                order_by: Optional[str] = None,
                order_direction: str = 'asc') -> Dict[str, Any]:
        """
        Get a paginated list of instances with filtering and sorting.

        Args:
            page: Page number (1-indexed)
            per_page: Number of items per page
            filters: Dictionary of field-value pairs to filter by
            order_by: Field name to sort by
            order_direction: Sort direction ('asc' or 'desc')

        Returns:
            Dict[str, Any]: Paginated results with items and metadata

        Raises:
            AttributeError: If the specified order_by field doesn't exist
            ValueError: If invalid pagination parameters are provided
        """
        if page < 1:
            raise ValueError("Page number must be 1 or greater")
        if per_page < 1:
            raise ValueError("Items per page must be 1 or greater")

        # Enforce upper limit to prevent excessive queries
        per_page = min(per_page, 100)

        # Build the base query
        query = cls.query

        # Apply filters if provided
        if filters:
            for field, value in filters.items():
                if hasattr(cls, field):
                    query = query.filter(getattr(cls, field) == value)
                else:
                    logger = current_app.logger if current_app else logging.getLogger(__name__)
                    logger.warning("Ignoring filter on non-existent field %s on %s",
                                  field, cls.__name__)

        # Apply ordering if provided
        if order_by:
            if not hasattr(cls, order_by):
                raise AttributeError(f"{cls.__name__} has no attribute '{order_by}'")

            column = getattr(cls, order_by)
            if order_direction.lower() == 'desc':
                column = column.desc()
            query = query.order_by(column)

        # Get the total count of items matching the filters
        total_items = query.count()
        total_pages = (total_items + per_page - 1) // per_page

        # Get the items for the requested page
        offset = (page - 1) * per_page
        items = query.offset(offset).limit(per_page).all()

        # Return pagination metadata along with the items
        return {
            "items": items,
            "meta": {
                "page": page,
                "per_page": per_page,
                "total_items": total_items,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_prev": page > 1,
                "next_page": page + 1 if page < total_pages else None,
                "prev_page": page - 1 if page > 1 else None
            }
        }

    @classmethod
    def get_or_create(cls: Type[T_Model], defaults: Optional[Dict[str, Any]] = None,
                     commit: bool = True, **kwargs) -> Tuple[T_Model, bool]:
        """
        Get an instance matching the given criteria or create it if it doesn't exist.

        Args:
            defaults: Dictionary of default values for creating a new instance
            commit: Whether to commit the transaction immediately (default: True)
            **kwargs: Search criteria used both to find and create the instance

        Returns:
            Tuple[T_Model, bool]: The instance and a boolean indicating if it was created

        Raises:
            SQLAlchemyError: If database error occurs during creation
        """
        instance = cls.query.filter_by(**kwargs).first()
        created = False

        if instance is None:
            # Create new instance with the provided kwargs and defaults
            create_kwargs = dict(kwargs)
            if defaults:
                create_kwargs.update(defaults)

            instance = cls(**create_kwargs)
            db.session.add(instance)
            created = True

            if commit:
                db.session.commit()

                # Log creation if the model supports it
                if isinstance(instance, AuditableMixin):
                    try:
                        from core.security_utils import log_security_event

                        model_name = cls.__name__.lower()
                        instance_id = getattr(instance, 'id', 'unknown')

                        user_id = g.get('user_id') if has_request_context() and hasattr(g, 'user_id') else None
                        ip_address = request.remote_addr if has_request_context() else None

                        log_security_event(
                            event_type=f"{model_name}_created",
                            description=f"New {model_name} created with ID {instance_id}",
                            severity='info',
                            user_id=user_id,
                            ip_address=ip_address,
                            details={
                                "method": "get_or_create"
                            }
                        )
                    except (ImportError, AttributeError) as e:
                        logger = current_app.logger if current_app else logging.getLogger(__name__)
                        logger.error("Failed to log model creation: %s", str(e))

        return instance, created
