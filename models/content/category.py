"""
Category model for content management system.

This module defines the Category model used for organizing different types of content
within the application. Categories provide a hierarchical structure for content
organization with support for nested categories and multiple content associations.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any, Set, Tuple, Union

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, func, and_, or_
from sqlalchemy.orm import relationship, validates
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app, g

from .. import db, BaseModel
from core.utils.string import slugify
from core.security.cs_audit import log_model_event


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
        display_order: Order for displaying categories (lower numbers first)
        icon: Optional icon identifier or class (e.g., 'fa-folder')
        image_path: Optional path to category image
        visibility: Visibility level (public, restricted, private)
        required_permission: Optional permission required to access this category
        meta_title: SEO title override
        meta_description: SEO description
    """
    __tablename__ = 'categories'

    # Status constants
    STATUS_ACTIVE = True
    STATUS_INACTIVE = False

    # Visibility constants
    VISIBILITY_PUBLIC = 'public'      # Visible to all users
    VISIBILITY_RESTRICTED = 'restricted'  # Visible to authenticated users
    VISIBILITY_PRIVATE = 'private'    # Visible only to users with specific permissions

    VALID_VISIBILITIES = [VISIBILITY_PUBLIC, VISIBILITY_RESTRICTED, VISIBILITY_PRIVATE]

    # Security-critical fields that should trigger audit logging when changed
    SECURITY_CRITICAL_FIELDS = ['visibility', 'required_permission']

    # Core fields
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True, index=True)
    slug = Column(String(100), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    parent_id = Column(Integer, ForeignKey('categories.id', ondelete='CASCADE'), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False, index=True)

    # Presentation fields
    display_order = Column(Integer, default=0, nullable=False)
    icon = Column(String(50), nullable=True)
    image_path = Column(String(255), nullable=True)

    # Access control
    visibility = Column(String(20), default=VISIBILITY_PUBLIC, nullable=False)
    required_permission = Column(String(100), nullable=True)

    # SEO fields
    meta_title = Column(String(200), nullable=True)
    meta_description = Column(String(300), nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    parent = relationship("Category", remote_side=[id], backref=db.backref(
        "children",
        order_by=display_order,
        cascade="all, delete-orphan"
    ))
    contents = relationship("Content", back_populates="category", cascade="all, delete-orphan")
    posts = relationship("Post", secondary="post_categories", back_populates="categories")

    def __init__(self, name: str, slug: Optional[str] = None, description: Optional[str] = None,
                 parent_id: Optional[int] = None, is_active: bool = True,
                 display_order: int = 0, icon: Optional[str] = None,
                 image_path: Optional[str] = None, visibility: str = VISIBILITY_PUBLIC,
                 required_permission: Optional[str] = None,
                 meta_title: Optional[str] = None, meta_description: Optional[str] = None) -> None:
        """
        Initialize a new Category.

        Args:
            name: Category name
            slug: URL-friendly version of the name (generated from name if not provided)
            description: Optional description of the category
            parent_id: ID of the parent category (for hierarchical categories)
            is_active: Whether the category is active
            display_order: Ordering position for the category (lower numbers shown first)
            icon: Optional icon identifier or CSS class
            image_path: Optional path to category image
            visibility: Category visibility level (public, restricted, private)
            required_permission: Permission required to access this category
            meta_title: SEO title override
            meta_description: SEO description

        Raises:
            ValueError: If name is empty or None or if visibility value is invalid
        """
        if not name or not name.strip():
            raise ValueError("Category name cannot be empty")

        self.name = name.strip()
        self.slug = slug or self._generate_slug(name)
        self.description = description
        self.parent_id = parent_id
        self.is_active = is_active
        self.display_order = display_order
        self.icon = icon
        self.image_path = image_path

        if visibility not in self.VALID_VISIBILITIES:
            raise ValueError(f"Invalid visibility value: {visibility}")
        self.visibility = visibility

        self.required_permission = required_permission
        self.meta_title = meta_title
        self.meta_description = meta_description

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

    @validates('visibility')
    def validate_visibility(self, key: str, visibility: str) -> str:
        """
        Validate the visibility value.

        Args:
            key: Field name ('visibility')
            visibility: Visibility value to validate

        Returns:
            str: Validated visibility value

        Raises:
            ValueError: If visibility value is not valid
        """
        if visibility not in self.VALID_VISIBILITIES:
            raise ValueError(f"Invalid visibility value: {visibility}. Valid options: {', '.join(self.VALID_VISIBILITIES)}")
        return visibility

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
    def get_by_slugs(cls, slugs: List[str]) -> List['Category']:
        """
        Find multiple categories by their slugs.

        Args:
            slugs: List of slugs to search for

        Returns:
            List of Category objects
        """
        if not slugs:
            return []

        return cls.query.filter(cls.slug.in_(slugs)).all()

    @classmethod
    def get_active(cls) -> List['Category']:
        """
        Get all active categories.

        Returns:
            List of active categories
        """
        return cls.query.filter_by(is_active=cls.STATUS_ACTIVE).order_by(cls.display_order, cls.name).all()

    @classmethod
    def get_root_categories(cls) -> List['Category']:
        """
        Get all top-level categories (those with no parent).

        Returns:
            List of root categories
        """
        return cls.query.filter_by(parent_id=None).order_by(cls.display_order, cls.name).all()

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
        ).order_by(cls.display_order, cls.name).all()

    @classmethod
    def get_visible_categories(cls, user_id: Optional[int] = None,
                              check_permissions: bool = True) -> List['Category']:
        """
        Get categories visible to the current user based on visibility settings.

        Args:
            user_id: The user ID to check permissions for (None for anonymous)
            check_permissions: Whether to check required permissions

        Returns:
            List of visible categories
        """
        # Start with base query
        query = cls.query.filter_by(is_active=cls.STATUS_ACTIVE)

        if user_id is None:
            # Anonymous users can only see public categories
            query = query.filter(cls.visibility == cls.VISIBILITY_PUBLIC)
        else:
            # Authenticated users can see public and restricted categories
            query = query.filter(or_(
                cls.visibility.in_([cls.VISIBILITY_PUBLIC, cls.VISIBILITY_RESTRICTED]),
                # Include private categories if permissions should not be checked
                and_(cls.visibility == cls.VISIBILITY_PRIVATE, check_permissions == False)
            ))

            if check_permissions:
                # If we have permission checking enabled and user_id is provided,
                # we need to handle private categories that require specific permissions

                # This requires integration with the permission system
                # For now, we exclude private categories that require permissions
                # In a real implementation, you would check against the user's permissions
                query = query.filter(or_(
                    cls.visibility.in_([cls.VISIBILITY_PUBLIC, cls.VISIBILITY_RESTRICTED]),
                    and_(cls.visibility == cls.VISIBILITY_PRIVATE, cls.required_permission.is_(None))
                ))

        return query.order_by(cls.display_order, cls.name).all()

    @classmethod
    def search(cls, query: str, active_only: bool = True,
               visibility_filter: Optional[str] = None) -> List['Category']:
        """
        Search for categories by name or description.

        Args:
            query: Search term
            active_only: Whether to only return active categories
            visibility_filter: Optional filter for visibility level

        Returns:
            List of matching categories
        """
        if not query:
            return []

        search_query = cls.query.filter(
            db.or_(
                cls.name.ilike(f"%{query}%"),
                cls.description.ilike(f"%{query}%"),
                cls.meta_title.ilike(f"%{query}%"),
                cls.meta_description.ilike(f"%{query}%")
            )
        )

        if active_only:
            search_query = search_query.filter_by(is_active=cls.STATUS_ACTIVE)

        if visibility_filter and visibility_filter in cls.VALID_VISIBILITIES:
            search_query = search_query.filter_by(visibility=visibility_filter)

        return search_query.order_by(cls.display_order, cls.name).all()

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

    def get_absolute_url(self) -> str:
        """
        Get the absolute URL for this category.

        Returns:
            str: Absolute URL for this category
        """
        return f"/categories/{self.slug}"

    def get_breadcrumb_data(self) -> List[Dict[str, str]]:
        """
        Get breadcrumb data for this category including ancestors.

        Returns:
            List of dictionaries with name and url for each level
        """
        breadcrumbs = []
        for category in self.get_hierarchy():
            breadcrumbs.append({
                'name': category.name,
                'url': category.get_absolute_url()
            })
        return breadcrumbs

    def get_descendants(self, include_self: bool = False, active_only: bool = False,
                       max_depth: Optional[int] = None) -> List['Category']:
        """
        Get all descendant categories (subcategories).

        Args:
            include_self: Whether to include this category in the result
            active_only: Whether to only include active categories
            max_depth: Maximum depth to traverse (None for unlimited)

        Returns:
            List of descendant categories
        """
        descendants = []

        if include_self and (not active_only or bool(self.is_active)):
            descendants.append(self)

        if max_depth is not None and max_depth <= 0:
            return descendants

        next_depth = None if max_depth is None else max_depth - 1

        if hasattr(self, 'children'):
            for child in self.children:
                if not active_only or child.is_active:
                    descendants.append(child)
                if next_depth is None or next_depth > 0:
                    descendants.extend(child.get_descendants(False, active_only, next_depth))

        return descendants

    def get_siblings(self, include_self: bool = False, active_only: bool = False) -> List['Category']:
        """
        Get sibling categories (categories with the same parent).

        Args:
            include_self: Whether to include this category in the result
            active_only: Whether to only include active categories

        Returns:
            List of sibling categories
        """
        query = Category.query.filter_by(parent_id=self.parent_id)

        if not include_self:
            query = query.filter(Category.id != self.id)

        if active_only:
            query = query.filter_by(is_active=True)

        return query.order_by(Category.display_order, Category.name).all()

    def get_content_count(self) -> int:
        """
        Get the total number of content items in this category.

        Returns:
            int: Count of content items
        """
        content_count = 0

        # Count posts if the relationship exists
        if hasattr(self, 'posts'):
            content_count += self.posts.count()

        # Count direct contents if the relationship exists
        if hasattr(self, 'contents'):
            content_count += self.contents.count()

        return content_count

    def user_can_view(self, user_id: Optional[int] = None) -> bool:
        """
        Check if a user can view this category based on visibility settings.

        Args:
            user_id: User ID (None for anonymous users)

        Returns:
            bool: True if user can view this category, False otherwise
        """
        # Anonymous users can only access public categories
        if user_id is None:
            return self.visibility == self.VISIBILITY_PUBLIC

        # Authenticated users can access public and restricted categories
        if self.visibility in [self.VISIBILITY_PUBLIC, self.VISIBILITY_RESTRICTED]:
            return True

        # For private categories, check if user has required permission
        if self.visibility == self.VISIBILITY_PRIVATE:
            if not self.required_permission:
                # No permission required
                return True

            # In a real implementation, check user permissions here
            # For this example, we're returning False for simplicity
            return False

        return False

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

    def update_visibility(self, visibility: str, required_permission: Optional[str] = None) -> bool:
        """
        Update the visibility settings of this category.

        Args:
            visibility: New visibility setting
            required_permission: Permission required for private categories

        Returns:
            bool: True if successful, False otherwise
        """
        return self.update(visibility=visibility, required_permission=required_permission)

    def set_display_order(self, order: int) -> bool:
        """
        Set the display order for this category.

        Args:
            order: New display order value (lower numbers appear first)

        Returns:
            bool: True if successful, False otherwise
        """
        return self.update(display_order=order)

    def to_dict(self, include_hierarchy: bool = False, include_descendants: bool = False) -> Dict[str, Any]:
        """
        Convert category to dictionary representation.

        Args:
            include_hierarchy: Whether to include the full hierarchy path
            include_descendants: Whether to include descendants in the result

        Returns:
            Dict containing category data
        """
        result = {
            'id': self.id,
            'name': self.name,
            'slug': self.slug,
            'description': self.description,
            'parent_id': self.parent_id,
            'is_active': self.is_active,
            'display_order': self.display_order,
            'icon': self.icon,
            'image_path': self.image_path,
            'visibility': self.visibility,
            'required_permission': self.required_permission,
            'meta_title': self.meta_title,
            'meta_description': self.meta_description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'has_children': len(self.children) > 0 if hasattr(self, 'children') else False,
            'parent_name': self.parent.name if self.parent else None,
            'url': self.get_absolute_url(),
            'content_count': self.get_content_count()
        }

        if include_hierarchy:
            result['hierarchy'] = [
                {
                    'id': cat.id,
                    'name': cat.name,
                    'slug': cat.slug,
                    'url': cat.get_absolute_url()
                }
                for cat in self.get_hierarchy()
            ]

        if include_descendants and hasattr(self, 'children'):
            result['children'] = [
                child.to_dict(include_hierarchy=False, include_descendants=False)
                for child in self.children if child.is_active
            ]

        return result

    def update(self, name: Optional[str] = None, slug: Optional[str] = None,
              description: Optional[str] = None, parent_id: Optional[int] = None,
              is_active: Optional[bool] = None, display_order: Optional[int] = None,
              icon: Optional[str] = None, image_path: Optional[str] = None,
              visibility: Optional[str] = None, required_permission: Optional[str] = None,
              meta_title: Optional[str] = None, meta_description: Optional[str] = None) -> bool:
        """
        Update category attributes.

        Args:
            name: New category name
            slug: New category slug
            description: New description
            parent_id: New parent category ID
            is_active: New active status
            display_order: New display order value
            icon: New icon identifier or class
            image_path: New path to category image
            visibility: New visibility level
            required_permission: New required permission
            meta_title: New SEO title
            meta_description: New SEO description

        Returns:
            bool: True if update was successful, False otherwise
        """
        try:
            # Track changes for security audit logging
            changes = {}
            old_values = {}

            if name is not None:
                name = name.strip()
                if not name:
                    raise ValueError("Category name cannot be empty")

                if self.name != name:
                    old_values['name'] = self.name
                    self.name = name
                    changes['name'] = name

                    # Update slug if not explicitly provided
                    if slug is None:
                        old_slug = self.slug
                        new_slug = self._generate_slug(name)
                        self.slug = new_slug
                        old_values['slug'] = old_slug
                        changes['slug'] = new_slug

            if slug is not None:
                slug = slug.strip()
                if not slug:
                    raise ValueError("Category slug cannot be empty")

                if self.slug != slug:
                    old_values['slug'] = self.slug
                    self.slug = slug
                    changes['slug'] = slug

            if description is not None and description != self.description:
                old_values['description'] = self.description
                self.description = description
                changes['description'] = description

            if parent_id is not None and parent_id != self.parent_id:
                old_values['parent_id'] = self.parent_id
                # The validation decorator will handle circular references
                self.parent_id = parent_id
                changes['parent_id'] = parent_id

            if is_active is not None and is_active != self.is_active:
                old_values['is_active'] = self.is_active
                self.is_active = is_active
                changes['is_active'] = is_active

            if display_order is not None and display_order != self.display_order:
                old_values['display_order'] = self.display_order
                self.display_order = display_order
                changes['display_order'] = display_order

            if icon is not None and icon != self.icon:
                old_values['icon'] = self.icon
                self.icon = icon
                changes['icon'] = icon

            if image_path is not None and image_path != self.image_path:
                old_values['image_path'] = self.image_path
                self.image_path = image_path
                changes['image_path'] = image_path

            if visibility is not None and visibility != self.visibility:
                if visibility not in self.VALID_VISIBILITIES:
                    raise ValueError(f"Invalid visibility value: {visibility}")
                old_values['visibility'] = self.visibility
                self.visibility = visibility
                changes['visibility'] = visibility

            if required_permission is not None and required_permission != self.required_permission:
                old_values['required_permission'] = self.required_permission
                self.required_permission = required_permission
                changes['required_permission'] = required_permission

            if meta_title is not None and meta_title != self.meta_title:
                old_values['meta_title'] = self.meta_title
                self.meta_title = meta_title
                changes['meta_title'] = meta_title

            if meta_description is not None and meta_description != self.meta_description:
                old_values['meta_description'] = self.meta_description
                self.meta_description = meta_description
                changes['meta_description'] = meta_description

            # Only commit if changes were made
            if changes:
                db.session.commit()

                # Log changes for audit purposes, especially security-critical changes
                security_critical = False
                critical_changes = []

                for field in self.SECURITY_CRITICAL_FIELDS:
                    if field in changes:
                        security_critical = True
                        critical_changes.append(field)

                # Log the update event with appropriate severity
                user_id = getattr(g, 'user_id', None) if hasattr(g, 'user_id') else None

                log_model_event(
                    model_name="Category",
                    event_type="update",
                    object_id=self.id,
                    user_id=user_id,
                    details={
                        "changes": changes,
                        "old_values": old_values,
                        "security_critical": security_critical,
                        "critical_changes": critical_changes
                    },
                    severity="medium" if security_critical else "info"
                )

            return True

        except (SQLAlchemyError, ValueError) as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error updating category: {str(e)}")
            return False

    @classmethod
    def reorder_siblings(cls, category_orders: List[Tuple[int, int]]) -> bool:
        """
        Update the display order of multiple categories at once.

        Args:
            category_orders: List of tuples with (category_id, new_order)

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            for category_id, new_order in category_orders:
                category = cls.query.get(category_id)
                if category:
                    category.display_order = new_order

            db.session.commit()
            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error reordering categories: {str(e)}")
            return False

    def __repr__(self) -> str:
        """
        String representation of the Category.

        Returns:
            str: String representation of the category
        """
        status = "active" if self.is_active else "inactive"
        return f"<Category(id={self.id}, name='{self.name}', {status}, visibility='{self.visibility}')>"
