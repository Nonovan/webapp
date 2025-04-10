from datetime import datetime
from typing import Dict, Any, Optional, List, Type
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from .user import User

db = SQLAlchemy()

class TimestampMixin:
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
        data = {c.name: getattr(self, c.name) for c in self.__table__.columns}
        # Add relationships if they exist
        for rel in self.__mapper__.relationships:
            if hasattr(self, rel.key):
                data[rel.key] = [item.to_dict() for item in getattr(self, rel.key)]
        return data

    @classmethod
    def get_by_id(cls: Type['BaseModel'], id: int) -> Optional['BaseModel']:
        """Get instance by ID with error handling."""
        try:
            return cls.query.get(id)
        except SQLAlchemyError as e:
            current_app.logger.error(f"Error fetching {cls.__name__} {id}: {str(e)}")
            return None

    @classmethod
    def list_all(cls: Type['BaseModel'], page: int = 1, per_page: int = 20) -> List['BaseModel']:
        """Get all instances with pagination."""
        try:
            return cls.query.paginate(page=page, per_page=per_page, error_out=False).items
        except SQLAlchemyError as e:
            current_app.logger.error(f"Error listing {cls.__name__}: {str(e)}")
            return []

    @classmethod
    def get_or_404(cls: Type['BaseModel'], id: int) -> 'BaseModel':
        """Get instance by ID or 404 with error handling."""
        try:
            return cls.query.get_or_404(id)
        except SQLAlchemyError as e:
            current_app.logger.error(f"Error fetching {cls.__name__} {id}: {str(e)}")
            raise

    def __repr__(self) -> str:
        """String representation."""
        return f'<{self.__class__.__name__} {self.id}>'

__all__ = ['db', 'User']
