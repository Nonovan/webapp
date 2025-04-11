from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Type, TypeVar, TYPE_CHECKING
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.declarative import declared_attr

if TYPE_CHECKING:
    from .user import User

db = SQLAlchemy()

# Define TypeVar with proper constraints using PEP 8 naming
T_Model = TypeVar('T_Model', bound='BaseModel')

class TimestampMixin:
    """Mixin class that adds created and updated timestamps to models."""
    @declared_attr
    def created_at(self) -> datetime:
        """Creation timestamp for the record."""
        return db.Column(
            db.DateTime(timezone=True),
            nullable=False,
            default=lambda: datetime.now(timezone.utc)
        )

    @declared_attr
    def updated_at(self) -> datetime:
        """Last update timestamp for the record."""
        return db.Column(
            db.DateTime(timezone=True),
            nullable=False,
            default=lambda: datetime.now(timezone.utc),
            onupdate=lambda: datetime.now(timezone.utc)
        )

class BaseModel(db.Model, TimestampMixin):
    """Base model class with common functionality."""
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True)

    def save(self) -> bool:
        """Save model instance with error handling."""
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
        """Delete model instance with error handling."""
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
        """Convert model to dictionary with relationships."""
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
        """Get instance by ID with error handling."""
        try:
            return cls.query.get(record_id)
        except SQLAlchemyError as e:
            current_app.logger.error(f"Error fetching {cls.__name__} {record_id}: {str(e)}")
            return None

    @classmethod
    def list_all(cls: Type[T_Model], page: int = 1, per_page: int = 20) -> List[T_Model]:
        """Get all instances with pagination."""
        try:
            return cls.query.paginate(page=page, per_page=per_page, error_out=False).items
        except SQLAlchemyError as e:
            current_app.logger.error(f"Error listing {cls.__name__}: {str(e)}")
            return []

    @classmethod
    def get_or_404(cls: Type[T_Model], record_id: int) -> T_Model:
        """Get instance by ID or 404 with error handling."""
        try:
            return cls.query.get_or_404(record_id)
        except SQLAlchemyError as e:
            current_app.logger.error(f"Error fetching {cls.__name__} {record_id}: {str(e)}")
            raise

    def __repr__(self) -> str:
        """String representation."""
        return f'<{self.__class__.__name__} {self.id}>'

__all__ = ['db', 'User']
