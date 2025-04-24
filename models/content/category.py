"""
Category model for content management system.

This module defines the Category model used for organizing different types of content
within the application. Categories provide a hierarchical structure for content
organization with support for nested categories and multiple content associations.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any, Set

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, func
from sqlalchemy.orm import relationship, validates
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app

from models.base import BaseModel
from core.database import db
from core.utils.string import slugify


class Category(BaseModel):
    """
    Represents a content category for organizing and grouping related content items.

    Categories can be hierarchical (with parent-child relationships) and are used
    to organize various content types like posts, pages, and other resources.

    Attributes:
        id: Primary key
        name: Category name (unique)
        slug: URL-friendly version of the name
        description: Optional description of the category
        parent_id: Foreign key to parent category (for hierarchical categories)
        is_active: Whether the category is currently active
        created_at: Timestamp when category was created
        updated_at: Timestamp when category was last updated
    """
    __tablename__ = 'categories'

    # Status constants
    STATUS_ACTIVE = True
    STATUS_INACTIVE = False

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True, index=True)
    slug = Column(String(100), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    parent_id = Column(Integer, ForeignKey('categories.id', ondelete='CASCADE'), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    parent = relationship("Category", remote_side=[id], backref="children")
    contents = relationship("Content", back_populates="category", cascade="all, delete-orphan")
    posts = relationship("Post", secondary="post_categories", back_populates="categories")

    def __init__(self, name: str, slug: Optional[str] = None, description: Optional[str] = None,
                 parent_id: Optional[int] = None, is_active: bool = True) -> None:
        """
        Initialize a new Category.

        Args:
            name: Category name
            slug: URL-friendly version of the name (generated from name if not provided)
            description: Optional description of the category
            parent_id: ID of the parent category (for hierarchical categories)
            is_active: Whether the category is active

        Raises:
            ValueError: If name is empty or None
        """
        if not name or not name.strip():
            raise ValueError("Category name cannot be empty")

        self.name = name.strip()
        self.slug = slug or self._generate_slug(name)
        self.description = description
        self.parent_id = parent_id
        self.is_active = is_active

    def _generate_slug(self, name: str) -> str:
        """
        Generate a URL-friendly slug from the category name.

        Args:
            name: The category name to convert to slug

        Returns:
            str: A URL-friendly slug
        """
        if not name:
            return ""

        # Use the dedicated slugify utility from core module
        base_slug = slugify(name)

        # Ensure uniqueness by appending a number if needed
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
            bool: True if slug exists, False otherwise
        """
        return db.session.query(Category.query.filter(
            Category.slug == slug,
            Category.id != getattr(self, 'id', None)
        ).exists()).scalar()

    @validates('parent_id')
    def validate_parent_id(self, key: str, parent_id: Optional[int]) -> Optional[int]:
        """
        Validate that parent_id doesn't create circular references.

        Args:
            key: Field name ('parent_id')
            parent_id: Parent category ID

        Returns:
            Optional[int]: Validated parent ID

        Raises:
            ValueError: If parent ID would create a circular reference
        """
        if parent_id is not None:
            if parent_id == getattr(self, 'id', None):
                raise ValueError("Category cannot be its own parent")

            # Check multi-level circular references
            if getattr(self, 'id', None) is not None:
                parent_chain: Set[int] = set()
                current_parent_id = parent_id

                while current_parent_id is not None:
                    if current_parent_id in parent_chain:
                        raise ValueError("Circular reference detected in category hierarchy")

                    parent_chain.add(current_parent_id)
                    parent = Category.query.get(current_parent_id)

                    if not parent:
                        break

                    current_parent_id = parent.parent_id

                    if current_parent_id == self.id:
                        raise ValueError("Circular reference detected in category hierarchy")

        return parent_id

    @classmethod
    def get_by_slug(cls, slug: str) -> Optional['Category']:
        """
        Find a category by its slug.

        Args:
            slug: The slug to search for

        Returns:
            Category object or None if not found
        """
        if not slug:
            return None

        return cls.query.filter_by(slug=slug).first()

    @classmethod
    def get_active(cls) -> List['Category']:
        """
        Get all active categories.

        Returns:
            List of active categories
        """
        return cls.query.filter_by(is_active=cls.STATUS_ACTIVE).order_by(cls.name).all()

    @classmethod
    def get_root_categories(cls) -> List['Category']:
        """
        Get all top-level categories (those with no parent).

        Returns:
            List of root categories
        """
        return cls.query.filter_by(parent_id=None).order_by(cls.name).all()

    @classmethod
    def get_active_root_categories(cls) -> List['Category']:
        """
        Get all active top-level categories.

        Returns:
            List of active root categories
        """
        return cls.query.filter_by(
            parent_id=None,
            is_active=cls.STATUS_ACTIVE
        ).order_by(cls.name).all()

    @classmethod
    def search(cls, query: str, active_only: bool = True) -> List['Category']:
        """
        Search for categories by name or description.

        Args:
            query: Search term
            active_only: Whether to only return active categories

        Returns:
            List of matching categories
        """
        if not query:
            return []

        search_query = cls.query.filter(
            db.or_(
                cls.name.ilike(f"%{query}%"),
                cls.description.ilike(f"%{query}%")
            )
        )

        if active_only:
            search_query = search_query.filter_by(is_active=cls.STATUS_ACTIVE)

        return search_query.order_by(cls.name).all()

    def get_hierarchy(self) -> List['Category']:
        """
        Get the full hierarchy path from root to this category.

        Returns:
            List of categories from root to this category
        """
        hierarchy = []
        current = self

        while current:
            hierarchy.append(current)
            current = current.parent

        # Reverse to get root -> child order
        hierarchy.reverse()
        return hierarchy

    def get_descendants(self, include_self: bool = False, active_only: bool = False) -> List['Category']:
        """
        Get all descendant categories (subcategories).

        Args:
            include_self: Whether to include this category in the result
            active_only: Whether to only include active categories

        Returns:
            List of descendant categories
        """
        descendants = []

        if include_self and (not active_only or bool(self.is_active)):
            descendants.append(self)

        if hasattr(self, 'children'):
            for child in self.children:
                if not active_only or child.is_active:
                    descendants.append(child)
                descendants.extend(child.get_descendants(False, active_only))

        return descendants

    def activate(self) -> bool:
        """
        Activate this category.

        Returns:
            bool: True if successful, False otherwise
        """
        return self.update(is_active=True)

    def deactivate(self) -> bool:
        """
        Deactivate this category.

        Returns:
            bool: True if successful, False otherwise
        """
        return self.update(is_active=False)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert category to dictionary representation.

        Returns:
            Dict containing category data
        """
        return {
            'id': self.id,
            'name': self.name,
            'slug': self.slug,
            'description': self.description,
            'parent_id': self.parent_id,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'has_children': len(self.children) > 0 if hasattr(self, 'children') else False,
            'parent_name': self.parent.name if self.parent else None
        }

    def update(self, name: Optional[str] = None, slug: Optional[str] = None,
              description: Optional[str] = None, parent_id: Optional[int] = None,
              is_active: Optional[bool] = None) -> bool:
        """
        Update category attributes.

        Args:
            name: New category name
            slug: New category slug
            description: New description
            parent_id: New parent category ID
            is_active: New active status

        Returns:
            bool: True if update was successful, False otherwise
        """
        try:
            if name is not None:
                name = name.strip()
                if not name:
                    raise ValueError("Category name cannot be empty")
                self.name = name
                # Update slug if not explicitly provided
                if slug is None:
                    self.slug = self._generate_slug(name)

            if slug is not None:
                slug = slug.strip()
                if not slug:
                    raise ValueError("Category slug cannot be empty")
                self.slug = slug

            if description is not None:
                self.description = description

            if parent_id is not None:
                # The validation decorator will handle circular references
                self.parent_id = parent_id

            if is_active is not None:
                self.is_active = is_active

            db.session.commit()
            return True
        except (SQLAlchemyError, ValueError) as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error updating category: {str(e)}")
            return False

    def __repr__(self) -> str:
        """
        String representation of the Category.

        Returns:
            str: String representation of the category
        """
        status = "active" if self.is_active else "inactive"
        return f"<Category(id={self.id}, name='{self.name}', {status})>"
