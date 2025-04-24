"""
Post model module for content management in myproject.

This module defines the Post model which represents blog posts, articles,
announcements and other content items in the system. It provides functionality
for content creation, publication, and management with features including:

- Slug generation for SEO-friendly URLs
- Publication status tracking (draft, published, archived)
- View counting and analytics
- Post categorization and type management
- Content search capabilities
- User relationship mapping for authorship

The Post model extends the BaseModel to leverage common functionality like
timestamp tracking and CRUD operations while adding content-specific features.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import re
from slugify import slugify
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app

from .. import db, BaseModel


class Post(BaseModel):
    """
    Post model for blog/announcement system.

    Represents content items such as blog posts, articles, and announcements
    with support for drafts, publication, and content management.
    """
    __tablename__ = 'posts'

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    slug = db.Column(db.String(200), unique=True, index=True)
    excerpt = db.Column(db.Text)

    # Metadata
    status = db.Column(db.String(20), default='draft', index=True)
    post_type = db.Column(db.String(20), default='post', index=True)
    views = db.Column(db.Integer, default=0)
    featured = db.Column(db.Boolean, default=False, index=True)

    # SEO fields
    meta_title = db.Column(db.String(200))
    meta_description = db.Column(db.String(300))

    # Timestamps
    # created_at and updated_at inherited from BaseModel
    published_at = db.Column(db.DateTime, default=None, index=True)

    # Relationships
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    user = db.relationship('User', backref=db.backref('posts', lazy='dynamic', cascade='all, delete-orphan'))

    # Add categories and tags relationships if they exist
    categories = db.relationship('Category', secondary='post_categories',
                               backref=db.backref('posts', lazy='dynamic'),
                               lazy='joined') if 'Category' in globals() else None

    tags = db.relationship('Tag', secondary='post_tags',
                         backref=db.backref('posts', lazy='dynamic'),
                         lazy='joined') if 'Tag' in globals() else None

    # Status constants
    STATUS_DRAFT = 'draft'
    STATUS_PUBLISHED = 'published'
    STATUS_ARCHIVED = 'archived'

    # Post type constants
    TYPE_POST = 'post'
    TYPE_PAGE = 'page'
    TYPE_ANNOUNCEMENT = 'announcement'

    # Valid statuses for validation
    VALID_STATUSES = [STATUS_DRAFT, STATUS_PUBLISHED, STATUS_ARCHIVED]

    # Valid post types for validation
    VALID_POST_TYPES = [TYPE_POST, TYPE_PAGE, TYPE_ANNOUNCEMENT]

    def __init__(self, **kwargs) -> None:
        """
        Initialize a Post instance with keyword arguments.

        Args:
            **kwargs: Keyword arguments matching model attributes

        Note:
            Automatically generates a slug from the title if not provided
        """
        # Validate required fields
        if 'title' not in kwargs:
            raise ValueError("Post title is required")
        if 'content' not in kwargs:
            raise ValueError("Post content is required")

        # Validate status
        if 'status' in kwargs and kwargs['status'] not in self.VALID_STATUSES:
            raise ValueError(f"Invalid post status. Must be one of: {', '.join(self.VALID_STATUSES)}")

        # Validate post type
        if 'post_type' in kwargs and kwargs['post_type'] not in self.VALID_POST_TYPES:
            raise ValueError(f"Invalid post type. Must be one of: {', '.join(self.VALID_POST_TYPES)}")

        # Set published_at if status is published
        if kwargs.get('status') == self.STATUS_PUBLISHED and 'published_at' not in kwargs:
            kwargs['published_at'] = datetime.now(timezone.utc)

        # Generate excerpt if not provided
        if 'content' in kwargs and 'excerpt' not in kwargs:
            kwargs['excerpt'] = self._generate_excerpt(kwargs['content'])

        super(Post, self).__init__(**kwargs)

        # Generate slug if not provided
        if not self.slug and self.title:
            self.slug = self.generate_slug()

    def generate_slug(self) -> str:
        """
        Generate URL-friendly slug from title.

        Returns:
            str: A URL-friendly slug based on the post title
        """
        # Use python-slugify for better slug generation
        base_slug = slugify(self.title, separator="-", lowercase=True)

        # Ensure slug is unique
        slug = base_slug
        counter = 1

        while Post.query.filter_by(slug=slug).first() is not None:
            slug = f"{base_slug}-{counter}"
            counter += 1

        return slug

    def _generate_excerpt(self, content: str, max_length: int = 150) -> str:
        """
        Generate a short excerpt from the content.

        Args:
            content: The post content
            max_length: Maximum length of excerpt

        Returns:
            str: Truncated excerpt from content
        """
        # Strip HTML tags
        text = re.sub(r'<[^>]+>', '', content)

        # Remove extra whitespace
        text = ' '.join(text.split())

        # Truncate to max_length
        if len(text) <= max_length:
            return text

        # Find last space before max_length
        truncated = text[:max_length]
        last_space = truncated.rfind(' ')

        if last_space > 0:
            truncated = truncated[:last_space]

        return f"{truncated}..."

    def publish(self) -> bool:
        """
        Publish the post.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.status = self.STATUS_PUBLISHED
            self.published_at = datetime.now(timezone.utc)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error publishing post: {str(e)}")
            return False

    def archive(self) -> bool:
        """
        Archive the post.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.status = self.STATUS_ARCHIVED
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error archiving post: {str(e)}")
            return False

    def increment_views(self) -> bool:
        """
        Increment view count.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.views += 1
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error incrementing post views: {str(e)}")
            return False

    def update_content(self, title: Optional[str] = None, content: Optional[str] = None,
                      excerpt: Optional[str] = None) -> bool:
        """
        Update post content fields.

        Args:
            title: New title (optional)
            content: New content (optional)
            excerpt: New excerpt (optional)

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            changes_made = False

            if title and title != self.title:
                self.title = title
                # Update slug when title changes
                self.slug = self.generate_slug()
                changes_made = True

            if content and content != self.content:
                self.content = content
                changes_made = True

                # Regenerate excerpt if not provided
                if not excerpt:
                    self.excerpt = self._generate_excerpt(content)

            if excerpt:
                self.excerpt = excerpt
                changes_made = True

            if changes_made:
                db.session.commit()

            return changes_made
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error updating post content: {str(e)}")
            return False

    def set_featured(self, featured: bool = True) -> bool:
        """
        Set or unset post as featured.

        Args:
            featured: Whether to feature the post

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.featured = featured
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error setting post featured status: {str(e)}")
            return False

    @classmethod
    def get_published(cls, page: int = 1, per_page: int = 10) -> List['Post']:
        """
        Get published posts with pagination.

        Args:
            page: Page number (1-indexed)
            per_page: Number of posts per page

        Returns:
            List[Post]: List of published posts for the requested page
        """
        return cls.query.filter_by(status=cls.STATUS_PUBLISHED)\
                       .order_by(db.desc(cls.published_at))\
                       .paginate(page=page, per_page=per_page, error_out=False).items

    @classmethod
    def get_featured(cls) -> List['Post']:
        """
        Get featured published posts.

        Returns:
            List[Post]: List of featured published posts
        """
        return cls.query.filter_by(status=cls.STATUS_PUBLISHED, featured=True)\
                       .order_by(db.desc(cls.published_at)).all()

    @classmethod
    def search(cls, query: str, include_archived: bool = False) -> List['Post']:
        """
        Search posts by title or content.

        Args:
            query: Search query string
            include_archived: Whether to include archived posts

        Returns:
            List[Post]: List of posts matching the query
        """
        search_query = query.strip()
        if not search_query:
            return []

        # Only search published posts by default
        status_filter = [cls.STATUS_PUBLISHED]
        if include_archived:
            status_filter.append(cls.STATUS_ARCHIVED)

        return cls.query.filter(
            db.and_(
                cls.status.in_(status_filter),
                db.or_(
                    cls.title.ilike(f'%{search_query}%'),
                    cls.content.ilike(f'%{search_query}%'),
                    cls.excerpt.ilike(f'%{search_query}%')
                )
            )
        ).order_by(db.desc(cls.published_at)).all()

    @classmethod
    def get_by_slug(cls, slug: str) -> Optional['Post']:
        """
        Get a post by its slug.

        Args:
            slug: The post slug

        Returns:
            Optional[Post]: Post with the given slug or None if not found
        """
        return cls.query.filter_by(slug=slug).first()

    @classmethod
    def get_by_type(cls, post_type: str, page: int = 1, per_page: int = 10) -> List['Post']:
        """
        Get posts by type with pagination.

        Args:
            post_type: Type of posts to retrieve
            page: Page number (1-indexed)
            per_page: Number of posts per page

        Returns:
            List[Post]: List of posts of the specified type
        """
        if post_type not in cls.VALID_POST_TYPES:
            if hasattr(current_app, 'logger'):
                current_app.logger.warning(f"Invalid post type requested: {post_type}")
            return []

        return cls.query.filter_by(
            post_type=post_type,
            status=cls.STATUS_PUBLISHED
        ).order_by(
            db.desc(cls.published_at)
        ).paginate(
            page=page,
            per_page=per_page,
            error_out=False
        ).items

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert post to dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the post
        """
        # Format timestamps consistently
        def format_datetime(dt):
            if dt:
                if isinstance(dt, datetime):
                    return dt.isoformat()
                return str(dt)
            return None

        result = {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'excerpt': self.excerpt,
            'slug': self.slug,
            'status': self.status,
            'post_type': self.post_type,
            'views': self.views,
            'featured': self.featured,
            'created_at': format_datetime(getattr(self, 'created_at', None)),
            'updated_at': format_datetime(getattr(self, 'updated_at', None)),
            'published_at': format_datetime(self.published_at),
            'user_id': self.user_id,
        }

        # Include author details if relationship is loaded
        if self.user:
            result['author'] = {
                'id': self.user.id,
                'username': self.user.username,
                'name': getattr(self.user, 'name', None)
            }

        # Add SEO fields if they exist
        if self.meta_title:
            result['meta_title'] = self.meta_title
        if self.meta_description:
            result['meta_description'] = self.meta_description

        # Include categories if available
        if hasattr(self, 'categories') and self.categories is not None:
            result['categories'] = [
                {'id': cat.id, 'name': cat.name, 'slug': getattr(cat, 'slug', None)}
                for cat in self.categories
            ]

        # Include tags if available
        if hasattr(self, 'tags') and self.tags is not None:
            result['tags'] = [
                {'id': tag.id, 'name': tag.name}
                for tag in self.tags
            ]

        return result

    def __repr__(self) -> str:
        """
        String representation of the Post.

        Returns:
            str: String representation with title and status
        """
        return f'<Post {self.id}: {self.title} ({self.status})>'
