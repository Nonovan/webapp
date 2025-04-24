"""
Tag model for flexible content classification.

This module defines the Tag model used for organizing and categorizing content
with a flexible tagging system. Tags provide a non-hierarchical way to classify
content items and enable efficient content discovery through tag-based filtering.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional, Set
from sqlalchemy import and_, or_, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import validates, relationship
from flask import current_app

from models.base import BaseModel
from extensions import db
from core.utils.string import slugify


class Tag(BaseModel):
    """
    Represents a content tag for flexible content classification.

    Tags provide a way to categorize content in a flat, non-hierarchical manner,
    allowing for flexible organization and improved content discovery.

    Attributes:
        id: Primary key
        name: Tag name (unique)
        slug: URL-friendly version of the name
        description: Optional description of the tag
        is_active: Whether the tag is currently active
        usage_count: Counter for tag usage frequency
        created_at: Timestamp when tag was created
        updated_at: Timestamp when tag was last updated
    """
    __tablename__ = 'tags'

    # Constants
    STATUS_ACTIVE = True
    STATUS_INACTIVE = False

    # Core fields
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), nullable=False, unique=True, index=True)
    slug = db.Column(db.String(60), nullable=False, unique=True, index=True)
    description = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)

    # Statistics
    usage_count = db.Column(db.Integer, default=0, nullable=False)

    # Relationships - these will be populated by the models that use tags
    # Using backref from other models like Post

    def __init__(self, name: str, slug: Optional[str] = None,
                 description: Optional[str] = None, is_active: bool = True) -> None:
        """
        Initialize a new Tag instance.

        Args:
            name: The tag name
            slug: URL-friendly identifier (auto-generated from name if not provided)
            description: Optional tag description
            is_active: Whether the tag is active
        """
        self.name = name.strip()
        self.slug = slug or self._generate_slug(name)
        self.description = description
        self.is_active = is_active

    def _generate_slug(self, name: str) -> str:
        """
        Generate a URL-friendly slug from the tag name.

        Args:
            name: The tag name to generate slug from

        Returns:
            str: A URL-friendly slug
        """
        base_slug = slugify(name, separator="-", lowercase=True)

        # Ensure the slug is unique
        slug = base_slug
        counter = 1

        while self._slug_exists(slug):
            slug = f"{base_slug}-{counter}"
            counter += 1

        return slug

    def _slug_exists(self, slug: str) -> bool:
        """
        Check if a slug already exists in the database.

        Args:
            slug: The slug to check

        Returns:
            bool: True if the slug exists, False otherwise
        """
        return db.session.query(db.exists().where(Tag.slug == slug)).scalar()

    @validates('name')
    def validate_name(self, key: str, name: str) -> str:
        """
        Validate the tag name.

        Args:
            key: Field name being validated
            name: Tag name to validate

        Returns:
            str: Validated name

        Raises:
            ValueError: If name is empty or too long
        """
        if not name or not name.strip():
            raise ValueError("Tag name cannot be empty")

        if len(name) > 50:
            raise ValueError("Tag name cannot exceed 50 characters")

        return name.strip()

    @validates('slug')
    def validate_slug(self, key: str, slug: str) -> str:
        """
        Validate the tag slug.

        Args:
            key: Field name being validated
            slug: Tag slug to validate

        Returns:
            str: Validated slug

        Raises:
            ValueError: If slug is empty or too long
        """
        if not slug:
            raise ValueError("Tag slug cannot be empty")

        if len(slug) > 60:
            raise ValueError("Tag slug cannot exceed 60 characters")

        return slug

    def update(self, name: Optional[str] = None, slug: Optional[str] = None,
               description: Optional[str] = None, is_active: Optional[bool] = None) -> bool:
        """
        Update tag attributes.

        Args:
            name: New tag name
            slug: New tag slug
            description: New description
            is_active: New active status

        Returns:
            bool: True if update was successful, False otherwise
        """
        try:
            changes_made = False

            if name is not None:
                name = name.strip()
                if not name:
                    raise ValueError("Tag name cannot be empty")

                if self.name != name:
                    self.name = name

                    # Update slug if not explicitly provided
                    if slug is None:
                        self.slug = self._generate_slug(name)

                    changes_made = True

            if slug is not None:
                slug = slug.strip()
                if not slug:
                    raise ValueError("Tag slug cannot be empty")

                if self.slug != slug:
                    self.slug = slug
                    changes_made = True

            if description is not None and self.description != description:
                self.description = description
                changes_made = True

            if is_active is not None and self.is_active != is_active:
                self.is_active = is_active
                changes_made = True

            if changes_made:
                db.session.commit()

            return changes_made

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating tag: {str(e)}")
            return False

    def activate(self) -> bool:
        """
        Activate this tag.

        Returns:
            bool: True if successful, False otherwise
        """
        return self.update(is_active=True)

    def deactivate(self) -> bool:
        """
        Deactivate this tag.

        Returns:
            bool: True if successful, False otherwise
        """
        return self.update(is_active=False)

    def increment_usage_count(self) -> bool:
        """
        Increment the usage count for this tag.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.usage_count += 1
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error incrementing tag usage count: {str(e)}")
            return False

    def reset_usage_count(self) -> bool:
        """
        Reset the usage count (typically called during system maintenance).

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Calculate actual count from relationships
            count = 0

            # Check for post-tag relationship
            if hasattr(self, 'posts'):
                count = self.posts.count()

            # Update the usage count
            self.usage_count = count
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error resetting tag usage count: {str(e)}")
            return False

    @classmethod
    def get_by_slug(cls, slug: str) -> Optional['Tag']:
        """
        Get a tag by its slug.

        Args:
            slug: The slug to search for

        Returns:
            Optional[Tag]: The tag if found, None otherwise
        """
        return cls.query.filter_by(slug=slug).first()

    @classmethod
    def get_by_name(cls, name: str) -> Optional['Tag']:
        """
        Get a tag by its name.

        Args:
            name: The name to search for

        Returns:
            Optional[Tag]: The tag if found, None otherwise
        """
        return cls.query.filter(func.lower(cls.name) == func.lower(name)).first()

    @classmethod
    def get_active(cls) -> List['Tag']:
        """
        Get all active tags.

        Returns:
            List[Tag]: List of active tags
        """
        return cls.query.filter_by(is_active=True).order_by(cls.name).all()

    @classmethod
    def search(cls, query: str, active_only: bool = True) -> List['Tag']:
        """
        Search tags by name or description.

        Args:
            query: Search query string
            active_only: Whether to include only active tags

        Returns:
            List[Tag]: List of tags matching the search criteria
        """
        search_query = query.strip()
        if not search_query:
            return []

        filters = [
            or_(
                cls.name.ilike(f'%{search_query}%'),
                cls.description.ilike(f'%{search_query}%')
            )
        ]

        if active_only:
            filters.append(cls.is_active == True)

        return cls.query.filter(*filters).order_by(cls.name).all()

    @classmethod
    def get_popular(cls, limit: int = 10, active_only: bool = True) -> List['Tag']:
        """
        Get the most popular tags based on usage count.

        Args:
            limit: Maximum number of tags to return
            active_only: Whether to include only active tags

        Returns:
            List[Tag]: List of popular tags
        """
        query = cls.query

        if active_only:
            query = query.filter_by(is_active=True)

        return query.order_by(cls.usage_count.desc()).limit(limit).all()

    @classmethod
    def get_or_create(cls, name: str, commit: bool = True) -> tuple['Tag', bool]:
        """
        Get an existing tag or create a new one if it doesn't exist.

        Args:
            name: The name of the tag to get or create
            commit: Whether to commit the transaction if a new tag is created

        Returns:
            Tuple[Tag, bool]: The tag object and a boolean indicating if it was created
        """
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Tag name cannot be empty")

        tag = cls.get_by_name(clean_name)

        if tag:
            return tag, False

        # Create new tag
        tag = cls(name=clean_name)
        db.session.add(tag)

        if commit:
            try:
                db.session.commit()
            except SQLAlchemyError as e:
                db.session.rollback()
                current_app.logger.error(f"Error creating tag: {str(e)}")
                # Check if it was a unique constraint violation (perhaps race condition)
                tag = cls.get_by_name(clean_name)
                if tag:
                    return tag, False
                raise

        return tag, True

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert tag to dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary containing tag data
        """
        return {
            'id': self.id,
            'name': self.name,
            'slug': self.slug,
            'description': self.description,
            'is_active': self.is_active,
            'usage_count': self.usage_count,
            'created_at': self.created_at.isoformat() if hasattr(self, 'created_at') and self.created_at else None,
            'updated_at': self.updated_at.isoformat() if hasattr(self, 'updated_at') and self.updated_at else None,
        }

    def __repr__(self) -> str:
        """String representation of the Tag object."""
        return f"<Tag {self.id}: {self.name}>"
