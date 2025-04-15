"""
Base model definitions for the myproject application.

This module provides the base model class and mixins that are used throughout
the application's data model layer. It establishes common functionality,
consistent patterns, and shared behaviors that all models can inherit.

Key components:
- BaseModel: Abstract base class with CRUD operations and serialization
- TimestampMixin: Adds automatic timestamp tracking for all models

These base classes implement the Active Record pattern through SQLAlchemy ORM,
promoting code reuse and ensuring consistent behavior across the data layer.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Type, TypeVar
from flask import current_app, abort
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.declarative import declared_attr
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

    @declared_attr
    def created_at(self):
        """
        Creation timestamp for the record.

        Automatically set when the record is first created.

        Returns:
            datetime: The creation timestamp with timezone
        """
        return db.Column(
            db.DateTime(timezone=True),
            nullable=False,
            default=lambda: datetime.now(timezone.utc)
        )

    @declared_attr
    def updated_at(self):
        """
        Last update timestamp for the record.

        Automatically updated whenever the record is modified.

        Returns:
            datetime: The last update timestamp with timezone
        """
        return db.Column(
            db.DateTime(timezone=True),
            nullable=False,
            default=lambda: datetime.now(timezone.utc),
            onupdate=lambda: datetime.now(timezone.utc)
        )


class BaseModel(db.Model, TimestampMixin):
    """
    Base model class with common functionality.

    This abstract base class provides common functionality for all models,
    including standard CRUD operations, serialization, and error handling.
    It integrates with SQLAlchemy's ORM system and adds additional convenience
    methods for common operations.

    All models in the application should inherit from this class to ensure
    consistent behavior and reduce code duplication. The class includes
    TimestampMixin for automatic timestamp tracking.

    Attributes:
        id: Integer primary key
        created_at: Datetime when the record was created (from TimestampMixin)
        updated_at: Datetime when the record was last updated (from TimestampMixin)

    Example:
        class User(BaseModel):
            username = db.Column(db.String(80), unique=True)

            # Inherits save(), delete(), to_dict(), etc.
    """
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True)

    def __init__(self, **kwargs):
        """
        Initialize the model with dynamic attributes.
        
        Args:
            **kwargs: Key-value pairs to set as attributes
        """
        # Don't pass __abstract__ to parent constructor
        kwargs.pop('__abstract__', None)
        super().__init__(**kwargs)

    def save(self) -> bool:
        """
        Save model instance with error handling.

        Adds the model instance to the session and commits the transaction,
        handling common database errors with appropriate logging.

        Returns:
            bool: True if the save was successful, False otherwise

        Example:
            user = User(username='johndoe')
            if user.save():
                # Successfully saved
            else:
                # Handle error
        """
        try:
            db.session.add(self)
            db.session.commit()
            current_app.logger.info(f"{self.__class__.__name__} {self.id} saved")
            return True
        except IntegrityError as e:
            db.session.rollback()
            current_app.logger.error(f"Save failed - integrity error: {str(e)}")
            return False
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Save failed - database error: {str(e)}")
            return False

    def delete(self) -> bool:
        """
        Delete model instance with error handling.

        Removes the model instance from the database, handling database errors
        with appropriate logging and transaction rollback.

        Returns:
            bool: True if the deletion was successful, False otherwise

        Example:
            user = User.query.get(1)
            if user.delete():
                # Successfully deleted
            else:
                # Handle error
        """
        try:
            db.session.delete(self)
            db.session.commit()
            current_app.logger.info(f"{self.__class__.__name__} {self.id} deleted")
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Delete failed: {str(e)}")
            return False

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert model to dictionary with relationships.

        Creates a dictionary representation of the model instance, including
        both column values and relationship data if available. This is useful
        for serialization to JSON for API responses.

        Relationship handling:
        - Scalar relationships (one-to-one): Calls to_dict() on related object
        - Collection relationships (one-to-many): Maps to_dict() over collection

        Returns:
            Dict[str, Any]: Dictionary representation of the model

        Example:
            user = User.query.get(1)
            user_dict = user.to_dict()
            # Convert to JSON: json.dumps(user_dict)
        """
        data = {}
        # Use introspection methods that are guaranteed to exist at runtime
        # instead of directly accessing private attributes
        for c in db.inspect(self).mapper.column_attrs:
            data[c.key] = getattr(self, c.key)

        # Handle relationships safely
        for rel_name, _ in db.inspect(self).mapper.relationships.items():
            if hasattr(self, rel_name):
                rel_data = getattr(self, rel_name)
                # Handle both collections and scalar relationships
                if rel_data is None:
                    data[rel_name] = None
                elif hasattr(rel_data, 'to_dict'):  # Single object
                    data[rel_name] = rel_data.to_dict()
                else:  # Collection of objects
                    data[rel_name] = [
                        item.to_dict() for item in rel_data
                        if hasattr(item, 'to_dict')
                    ]
        return data

    @classmethod
    def get_by_id(cls: Type[T_Model], record_id: int) -> Optional[T_Model]:
        """
        Get model instance by primary key.

        Retrieves a single model instance by its primary key ID,
        returning None if no matching record is found.

        Args:
            record_id: Primary key value to search for

        Returns:
            Optional[T_Model]: Model instance if found, None otherwise

        Example:
            user = User.get_by_id(1)
            if user:
                # User exists
            else:
                # User not found
        """
        try:
            return cls.query.get(record_id)
        except SQLAlchemyError as e:
            current_app.logger.error(f"Error retrieving {cls.__name__}: {str(e)}")
            return None

    @classmethod
    def list_all(cls: Type[T_Model], page: int = 1, per_page: int = 20) -> List[T_Model]:
        """
        Get all instances with pagination.

        Retrieves a paginated list of model instances, with configurable page
        size and number. This method is useful for listing views where only a
        subset of records should be returned at once.

        Args:
            page: The page number to retrieve (1-indexed)
            per_page: The number of records per page

        Returns:
            List[T_Model]: List of model instances for the specified page

        Example:
            # Get first page of users, 20 per page
            users = User.list_all()

            # Get second page of users, 50 per page
            users = User.list_all(page=2, per_page=50)
        """
        try:
            return cls.query.paginate(page=page, per_page=per_page, error_out=False).items
        except SQLAlchemyError as e:
            current_app.logger.error(f"Error listing {cls.__name__}: {str(e)}")
            return []

    @classmethod
    def get_or_404(cls: Type[T_Model], record_id: int) -> T_Model:
        """
        Get model instance or raise 404 error.

        Similar to get_by_id(), but raises a 404 error if the record is not found.
        This is useful in view functions to handle non-existent resources.

        Args:
            record_id: Primary key value to search for

        Returns:
            T_Model: Model instance if found

        Raises:
            HTTPException: 404 error if record not found

        Example:
            try:
                user = User.get_or_404(1)
                # User exists
            except HTTPException:
                # Handle not found case
        """
        record = cls.get_by_id(record_id)
        if record is None:
            abort(404, f"{cls.__name__} with id {record_id} not found")
        assert record is not None, f"{cls.__name__} with id {record_id} not found"
        return record

    def __repr__(self) -> str:
        """
        String representation.

        Provides a useful string representation of the model instance for
        debugging and logging purposes.

        Returns:
            str: String representation in the format '<ClassName ID>'

        Example:
            user = User.get_by_id(1)
            str(user)  # '<User 1>'
        """
        return f'<{self.__class__.__name__} {self.id}>'
