"""
Tag model for flexible content classification.

This module defines the Tag model used for organizing and categorizing content
with a flexible tagging system. Tags provide a non-hierarchical way to classify
content items and enable efficient content discovery through tag-based filtering.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional, Set, Tuple, Union
from sqlalchemy import and_, or_, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import validates, relationship
from flask import current_app, g, has_request_context

from .. import db, BaseModel
from core.utils.string import slugify
from core.security.cs_audit import log_model_event


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

    # Tag types for organizational purposes
    TYPE_GENERAL = 'general'    # General purpose tags
    TYPE_TOPIC = 'topic'        # Content topic
    TYPE_TECHNICAL = 'technical' # Technical category
    TYPE_AUDIENCE = 'audience'  # Target audience

    VALID_TYPES = [TYPE_GENERAL, TYPE_TOPIC, TYPE_TECHNICAL, TYPE_AUDIENCE]

    # Core fields
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), nullable=False, unique=True, index=True)
    slug = db.Column(db.String(60), nullable=False, unique=True, index=True)
    description = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    tag_type = db.Column(db.String(20), default=TYPE_GENERAL, nullable=False, index=True)
    color = db.Column(db.String(20), nullable=True)  # Optional color code for UI

    # Statistics
    usage_count = db.Column(db.Integer, default=0, nullable=False)

    # Metadata
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    featured = db.Column(db.Boolean, default=False, nullable=False, index=True)
    display_order = db.Column(db.Integer, default=0, nullable=False)

    # Relationships - these will be populated by the models that use tags
    # Using backref from other models like Post
    creator = relationship("User", foreign_keys=[created_by], backref="created_tags", lazy='joined')

    def __init__(self, name: str, slug: Optional[str] = None,
                 description: Optional[str] = None, is_active: bool = True,
                 tag_type: str = TYPE_GENERAL, color: Optional[str] = None) -> None:
        """
        Initialize a new Tag instance.

        Args:
            name: The tag name
            slug: URL-friendly identifier (auto-generated from name if not provided)
            description: Optional tag description
            is_active: Whether the tag is active
            tag_type: Type of tag (general, topic, technical, audience)
            color: Optional color code for UI representation
        """
        self.name = name.strip()
        self.slug = slug or self._generate_slug(name)
        self.description = description
        self.is_active = is_active

        if tag_type not in self.VALID_TYPES:
            tag_type = self.TYPE_GENERAL
        self.tag_type = tag_type
        self.color = color

        # Set creator if in request context
        if has_request_context() and hasattr(g, 'user_id'):
            self.created_by = g.user_id

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
        return db.session.query(db.exists().where(
            and_(Tag.slug == slug, Tag.id != getattr(self, 'id', None))
        )).scalar()

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

        # Check if slug format is valid (alphanumeric + dash)
        if not all(c.isalnum() or c == '-' for c in slug):
            raise ValueError("Tag slug can only contain letters, numbers, and hyphens")

        return slug

    @validates('tag_type')
    def validate_tag_type(self, key: str, tag_type: str) -> str:
        """
        Validate the tag type.

        Args:
            key: Field name being validated
            tag_type: Tag type to validate

        Returns:
            str: Validated tag type
        """
        if tag_type not in self.VALID_TYPES:
            return self.TYPE_GENERAL
        return tag_type

    @validates('color')
    def validate_color(self, key: str, color: Optional[str]) -> Optional[str]:
        """
        Validate the tag color.

        Args:
            key: Field name being validated
            color: Color code to validate

        Returns:
            Optional[str]: Validated color code or None
        """
        if color is None:
            return None

        # Accept hex color codes with or without leading #
        color = color.strip().lower()
        if color and not color.startswith('#'):
            color = f"#{color}"

        # Validate hex color format
        if not (len(color) == 7 and color[0] == '#' and all(c in '0123456789abcdef' for c in color[1:])):
            return None

        return color

    def update(self, name: Optional[str] = None, slug: Optional[str] = None,
               description: Optional[str] = None, is_active: Optional[bool] = None,
               tag_type: Optional[str] = None, color: Optional[str] = None,
               featured: Optional[bool] = None, display_order: Optional[int] = None) -> bool:
        """
        Update tag attributes.

        Args:
            name: New tag name
            slug: New tag slug
            description: New description
            is_active: New active status
            tag_type: New tag type
            color: New color code
            featured: New featured status
            display_order: New display order

        Returns:
            bool: True if update was successful, False otherwise
        """
        try:
            old_values = {}
            changes = {}

            if name is not None:
                name = name.strip()
                if not name:
                    raise ValueError("Tag name cannot be empty")

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
                    raise ValueError("Tag slug cannot be empty")

                if self.slug != slug:
                    old_values['slug'] = self.slug
                    self.slug = slug
                    changes['slug'] = slug

            if description is not None and self.description != description:
                old_values['description'] = self.description
                self.description = description
                changes['description'] = description

            if is_active is not None and self.is_active != is_active:
                old_values['is_active'] = self.is_active
                self.is_active = is_active
                changes['is_active'] = is_active

            if tag_type is not None and tag_type in self.VALID_TYPES and self.tag_type != tag_type:
                old_values['tag_type'] = self.tag_type
                self.tag_type = tag_type
                changes['tag_type'] = tag_type

            if color is not None and self.color != color:
                old_values['color'] = self.color
                # Use the validator to ensure color format is correct
                self.color = self.validate_color('color', color)
                changes['color'] = self.color

            if featured is not None and self.featured != featured:
                old_values['featured'] = self.featured
                self.featured = featured
                changes['featured'] = featured

            if display_order is not None and self.display_order != display_order:
                old_values['display_order'] = self.display_order
                self.display_order = display_order
                changes['display_order'] = display_order

            if changes:
                db.session.commit()

                # Log the update
                user_id = getattr(g, 'user_id', None) if has_request_context() and hasattr(g, 'user_id') else None
                log_model_event(
                    model_name="Tag",
                    event_type="update",
                    object_id=self.id,
                    user_id=user_id,
                    details={
                        "changes": changes,
                        "old_values": old_values
                    },
                    severity="info"
                )

                return True
            return False

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

    def set_featured(self, featured: bool = True) -> bool:
        """
        Set or unset this tag as featured.

        Args:
            featured: Whether this tag should be featured

        Returns:
            bool: True if successful, False otherwise
        """
        return self.update(featured=featured)

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

    def decrement_usage_count(self) -> bool:
        """
        Decrement the usage count for this tag.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if self.usage_count > 0:
                self.usage_count -= 1
                db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error decrementing tag usage count: {str(e)}")
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

    def get_related_tags(self, limit: int = 10) -> List['Tag']:
        """
        Get related tags based on shared content items.

        Args:
            limit: Maximum number of related tags to return

        Returns:
            List[Tag]: List of related tags
        """
        try:
            # This requires a proper many-to-many relationship set up
            if not hasattr(self, 'posts'):
                return []

            # Find posts that have this tag
            post_ids = [post.id for post in self.posts]
            if not post_ids:
                return []

            # Find other tags used in these posts
            from ..content import Tag
            # Use a subquery to get posts with this tag
            from sqlalchemy.sql import select, func

            # Get tag counts for posts that have this tag, excluding this tag itself
            tag_counts = db.session.query(
                Tag.id,
                func.count(Tag.id).label('count')
            ).join(
                db.Table('post_tags'),
                Tag.id == db.Table('post_tags').c.tag_id
            ).filter(
                db.Table('post_tags').c.post_id.in_(post_ids),
                Tag.id != self.id,
                Tag.is_active == True
            ).group_by(Tag.id).order_by(
                func.count(Tag.id).desc()
            ).limit(limit).all()

            # Get the actual tag objects
            if not tag_counts:
                return []

            tag_ids = [tag_id for tag_id, _ in tag_counts]
            related_tags = Tag.query.filter(Tag.id.in_(tag_ids)).all()

            # Sort them according to the counts
            tag_id_to_count = {tag_id: count for tag_id, count in tag_counts}
            related_tags.sort(key=lambda tag: tag_id_to_count.get(tag.id, 0), reverse=True)

            return related_tags

        except SQLAlchemyError as e:
            current_app.logger.error(f"Error finding related tags: {str(e)}")
            return []

    @classmethod
    def get_by_slug(cls, slug: str) -> Optional['Tag']:
        """
        Get a tag by its slug.

        Args:
            slug: The slug to search for

        Returns:
            Optional[Tag]: The tag if found, None otherwise
        """
        if not slug:
            return None
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
        if not name:
            return None
        clean_name = name.strip()
        return cls.query.filter(func.lower(cls.name) == func.lower(clean_name)).first()

    @classmethod
    def get_active(cls, tag_type: Optional[str] = None) -> List['Tag']:
        """
        Get all active tags.

        Args:
            tag_type: Optional tag type to filter by

        Returns:
            List[Tag]: List of active tags
        """
        query = cls.query.filter_by(is_active=True)

        if tag_type and tag_type in cls.VALID_TYPES:
            query = query.filter_by(tag_type=tag_type)

        return query.order_by(cls.display_order, cls.name).all()

    @classmethod
    def get_featured(cls, limit: int = 10) -> List['Tag']:
        """
        Get featured tags.

        Args:
            limit: Maximum number of featured tags to return

        Returns:
            List[Tag]: List of featured tags
        """
        return cls.query.filter_by(
            is_active=True, featured=True
        ).order_by(cls.display_order, cls.name).limit(limit).all()

    @classmethod
    def search(cls, query: str, active_only: bool = True, tag_type: Optional[str] = None) -> List['Tag']:
        """
        Search tags by name or description.

        Args:
            query: Search query string
            active_only: Whether to include only active tags
            tag_type: Optional tag type to filter by

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

        if tag_type and tag_type in cls.VALID_TYPES:
            filters.append(cls.tag_type == tag_type)

        return cls.query.filter(*filters).order_by(cls.name).all()

    @classmethod
    def get_popular(cls, limit: int = 10, active_only: bool = True, tag_type: Optional[str] = None) -> List['Tag']:
        """
        Get the most popular tags based on usage count.

        Args:
            limit: Maximum number of tags to return
            active_only: Whether to include only active tags
            tag_type: Optional tag type to filter by

        Returns:
            List[Tag]: List of popular tags
        """
        query = cls.query
        filters = []

        if active_only:
            filters.append(cls.is_active == True)

        if tag_type and tag_type in cls.VALID_TYPES:
            filters.append(cls.tag_type == tag_type)

        if filters:
            query = query.filter(*filters)

        return query.order_by(cls.usage_count.desc()).limit(limit).all()

    @classmethod
    def get_cloud_data(cls, limit: int = 50) -> List[Dict[str, Union[str, int]]]:
        """
        Get data for a tag cloud visualization.

        Args:
            limit: Maximum number of tags to include

        Returns:
            List[Dict[str, Union[str, int]]]: List of dictionaries with tag data
        """
        tags = cls.query.filter_by(is_active=True).order_by(
            cls.usage_count.desc()
        ).limit(limit).all()

        # Calculate weight between 1-10 based on usage count
        if tags:
            max_count = max(tag.usage_count for tag in tags)
            min_count = min(tag.usage_count for tag in tags)

            # Avoid division by zero
            count_range = max(1, max_count - min_count)

            result = []
            for tag in tags:
                # Calculate weight on a 1-10 scale
                if count_range == 1:
                    weight = 5  # Default middle weight if all tags have same count
                else:
                    weight = 1 + int(9 * (tag.usage_count - min_count) / count_range)

                result.append({
                    'id': tag.id,
                    'name': tag.name,
                    'slug': tag.slug,
                    'weight': weight,
                    'count': tag.usage_count,
                    'color': tag.color
                })

            return result
        return []

    @classmethod
    def get_or_create(cls, name: str, commit: bool = True) -> Tuple['Tag', bool]:
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

                # Log tag creation
                user_id = getattr(g, 'user_id', None) if has_request_context() and hasattr(g, 'user_id') else None
                log_model_event(
                    model_name="Tag",
                    event_type="create",
                    object_id=tag.id,
                    user_id=user_id,
                    details={"name": tag.name},
                    severity="info"
                )

            except SQLAlchemyError as e:
                db.session.rollback()
                current_app.logger.error(f"Error creating tag: {str(e)}")
                # Check if it was a unique constraint violation (perhaps race condition)
                tag = cls.get_by_name(clean_name)
                if tag:
                    return tag, False
                raise

        return tag, True

    @classmethod
    def merge_tags(cls, source_tag_ids: List[int], target_tag_id: int) -> bool:
        """
        Merge multiple tags into a single target tag.

        Args:
            source_tag_ids: List of tag IDs to merge from
            target_tag_id: ID of the tag to merge into

        Returns:
            bool: True if successful, False otherwise
        """
        if not source_tag_ids or target_tag_id is None:
            return False

        if target_tag_id in source_tag_ids:
            source_tag_ids.remove(target_tag_id)

        if not source_tag_ids:
            return False

        try:
            # Get the target tag
            target_tag = cls.query.get(target_tag_id)
            if not target_tag:
                return False

            # Process each source tag
            for source_id in source_tag_ids:
                if source_id == target_tag_id:
                    continue

                source_tag = cls.query.get(source_id)
                if not source_tag:
                    continue

                # Track total usage count
                target_tag.usage_count += source_tag.usage_count

                # For each post relationship, add to target if not already present
                if hasattr(source_tag, 'posts') and hasattr(target_tag, 'posts'):
                    for post in source_tag.posts:
                        if target_tag not in post.tags:
                            post.tags.append(target_tag)

                # Log the merge operation
                user_id = getattr(g, 'user_id', None) if has_request_context() and hasattr(g, 'user_id') else None
                log_model_event(
                    model_name="Tag",
                    event_type="merge",
                    object_id=target_tag_id,
                    user_id=user_id,
                    details={
                        "source_tag_id": source_id,
                        "source_tag_name": source_tag.name,
                        "target_tag_name": target_tag.name
                    },
                    severity="info"
                )

                # Delete the source tag
                db.session.delete(source_tag)

            db.session.commit()
            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error merging tags: {str(e)}")
            return False

    @classmethod
    def reindex_usage_counts(cls) -> int:
        """
        Recalculate usage counts for all tags.

        Returns:
            int: Number of tags updated
        """
        try:
            tags = cls.query.all()
            updated_count = 0

            for tag in tags:
                old_count = tag.usage_count

                # Calculate actual count from relationships
                count = 0

                # Check for post-tag relationship
                if hasattr(tag, 'posts'):
                    count = tag.posts.count()

                # Update if count has changed
                if old_count != count:
                    tag.usage_count = count
                    updated_count += 1

            db.session.commit()
            return updated_count

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error reindexing tag usage counts: {str(e)}")
            return 0

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert tag to dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary containing tag data
        """
        result = {
            'id': self.id,
            'name': self.name,
            'slug': self.slug,
            'description': self.description,
            'is_active': self.is_active,
            'tag_type': self.tag_type,
            'color': self.color,
            'usage_count': self.usage_count,
            'featured': self.featured,
            'display_order': self.display_order,
            'created_at': self.created_at.isoformat() if hasattr(self, 'created_at') and self.created_at else None,
            'updated_at': self.updated_at.isoformat() if hasattr(self, 'updated_at') and self.updated_at else None,
        }

        # Add creator info if available
        if self.created_by and hasattr(self, 'creator') and self.creator:
            result['creator'] = {
                'id': self.creator.id,
                'username': getattr(self.creator, 'username', None),
                'name': getattr(self.creator, 'name', None)
            }

        # Add URL
        result['url'] = f"/tags/{self.slug}"

        return result

    def delete(self) -> bool:
        """
        Delete this tag.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Log the deletion
            user_id = getattr(g, 'user_id', None) if has_request_context() and hasattr(g, 'user_id') else None
            tag_data = self.to_dict()

            # Delete the tag
            db.session.delete(self)
            db.session.commit()

            # Log after successful deletion
            log_model_event(
                model_name="Tag",
                event_type="delete",
                object_id=tag_data['id'],
                user_id=user_id,
                details={"tag_data": tag_data},
                severity="info"
            )

            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error deleting tag: {str(e)}")
            return False

    def __repr__(self) -> str:
        """String representation of the Tag object."""
        status = "active" if self.is_active else "inactive"
        return f"<Tag {self.id}: {self.name} ({status})>"
