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
- Content revision history tracking
- Comment support with moderation
- Security audit integration

The Post model extends the BaseModel to leverage common functionality like
timestamp tracking and CRUD operations while adding content-specific features.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Union, Tuple
import re
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app, g
from sqlalchemy import desc, and_, or_, text, func
from sqlalchemy.orm import joinedload

from .. import db, BaseModel
from ..content import Category
from ..security import AuditLog
from core.security.cs_audit import log_model_event
from core.utils.string import slugify


class Post(BaseModel):
    """
    Post model for blog/announcement system.

    Represents content items such as blog posts, articles, and announcements
    with support for drafts, publication, and content management.
    """
    __tablename__ = 'posts'

    # Security-critical fields that should trigger audit logging when changed
    SECURITY_CRITICAL_FIELDS = ['status', 'visibility', 'access_level']

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
    keywords = db.Column(db.String(300))
    canonical_url = db.Column(db.String(500))

    # Access control
    visibility = db.Column(db.String(20), default='public', index=True)
    access_level = db.Column(db.String(20), default='all', index=True)
    required_permission = db.Column(db.String(100))

    # Content attributes
    allow_comments = db.Column(db.Boolean, default=True)
    comment_count = db.Column(db.Integer, default=0)
    reading_time = db.Column(db.Integer)  # Estimated reading time in minutes

    # Media fields
    featured_image_id = db.Column(db.Integer, db.ForeignKey('media.id', ondelete='SET NULL'), nullable=True)
    featured_image_alt = db.Column(db.String(255))
    featured_image_caption = db.Column(db.Text)

    # Timestamps
    # created_at and updated_at inherited from BaseModel
    published_at = db.Column(db.DateTime, default=None, index=True)
    last_commented_at = db.Column(db.DateTime, default=None)
    scheduled_at = db.Column(db.DateTime, default=None)

    # Relationships
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    user = db.relationship('User', backref=db.backref('posts', lazy='dynamic', cascade='all, delete-orphan'))
    featured_image = db.relationship('Media', foreign_keys=[featured_image_id],
                                    backref=db.backref('featured_in_posts', lazy='dynamic'))

    # Add categories and tags relationships if they exist
    categories = db.relationship('Category', secondary='post_categories',
                               backref=db.backref('posts', lazy='dynamic'),
                               lazy='joined') if 'Category' in globals() else None

    tags = db.relationship('Tag', secondary='post_tags',
                         backref=db.backref('posts', lazy='dynamic'),
                         lazy='joined') if 'Tag' in globals() else None

    comments = db.relationship('Comment', backref='post', lazy='dynamic',
                              cascade='all, delete-orphan',
                              order_by='Comment.created_at.desc()')

    revisions = db.relationship('ContentRevision',
                               foreign_keys='ContentRevision.content_id',
                               primaryjoin='and_(ContentRevision.content_id == Post.id, '
                                          'ContentRevision.content_type == "post")',
                               backref=db.backref('post'),
                               order_by='ContentRevision.created_at.desc()',
                               lazy='dynamic')

    # Status constants
    STATUS_DRAFT = 'draft'
    STATUS_PUBLISHED = 'published'
    STATUS_ARCHIVED = 'archived'
    STATUS_SCHEDULED = 'scheduled'
    STATUS_PENDING_REVIEW = 'pending_review'
    STATUS_REJECTED = 'rejected'

    # Post type constants
    TYPE_POST = 'post'
    TYPE_PAGE = 'page'
    TYPE_ANNOUNCEMENT = 'announcement'
    TYPE_NEWS = 'news'
    TYPE_EVENT = 'event'
    TYPE_RELEASE = 'release'

    # Visibility constants
    VISIBILITY_PUBLIC = 'public'     # Visible to everyone
    VISIBILITY_PRIVATE = 'private'   # Visible only to authorized users
    VISIBILITY_RESTRICTED = 'restricted'  # Visible only to specified roles
    VISIBILITY_INTERNAL = 'internal'  # Visible only to authenticated users

    # Valid statuses for validation
    VALID_STATUSES = [
        STATUS_DRAFT,
        STATUS_PUBLISHED,
        STATUS_ARCHIVED,
        STATUS_SCHEDULED,
        STATUS_PENDING_REVIEW,
        STATUS_REJECTED
    ]

    # Valid post types for validation
    VALID_POST_TYPES = [
        TYPE_POST,
        TYPE_PAGE,
        TYPE_ANNOUNCEMENT,
        TYPE_NEWS,
        TYPE_EVENT,
        TYPE_RELEASE
    ]

    # Valid visibility settings
    VALID_VISIBILITIES = [
        VISIBILITY_PUBLIC,
        VISIBILITY_PRIVATE,
        VISIBILITY_RESTRICTED,
        VISIBILITY_INTERNAL
    ]

    def __init__(self, **kwargs) -> None:
        """
        Initialize a Post instance with keyword arguments.

        Args:
            **kwargs: Keyword arguments matching model attributes

        Note:
            Automatically generates a slug from the title if not provided
            Calculates reading time based on content length

        Raises:
            ValueError: If required fields are missing or validation fails
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

        # Validate visibility
        if 'visibility' in kwargs and kwargs['visibility'] not in self.VALID_VISIBILITIES:
            raise ValueError(f"Invalid visibility. Must be one of: {', '.join(self.VALID_VISIBILITIES)}")

        # Set published_at if status is published
        if kwargs.get('status') == self.STATUS_PUBLISHED and 'published_at' not in kwargs:
            kwargs['published_at'] = datetime.now(timezone.utc)

        # Set scheduled_at if status is scheduled
        if kwargs.get('status') == self.STATUS_SCHEDULED and 'scheduled_at' not in kwargs:
            raise ValueError("Scheduled posts require a scheduled_at datetime")

        # Generate excerpt if not provided
        if 'content' in kwargs and 'excerpt' not in kwargs:
            kwargs['excerpt'] = self._generate_excerpt(kwargs['content'])

        # Calculate reading time
        if 'content' in kwargs and 'reading_time' not in kwargs:
            kwargs['reading_time'] = self._calculate_reading_time(kwargs['content'])

        super(Post, self).__init__(**kwargs)

        # Generate slug if not provided
        if not self.slug and self.title:
            self.slug = self.generate_slug()

    def generate_slug(self) -> str:
        """
        Generate URL-friendly slug from title.

        This method creates a unique, URL-friendly slug based on the post title,
        using the core slugify utility to ensure consistent slug formatting across
        the application. It automatically handles uniqueness by appending numbers
        to avoid duplicates.

        Returns:
            str: A URL-friendly slug based on the post title
        """
        if not self.title:
            return ""

        # Use default settings from core utility for consistency
        base_slug = slugify(
            self.title,
            separator="-",
            lowercase=True,
            strip_diacritics=True,
            allow_unicode=False
        )

        # Ensure slug is unique
        slug = base_slug
        counter = 1

        # Query to check uniqueness should exclude current post when updating
        query = Post.query.filter_by(slug=slug)
        if self.id:
            query = query.filter(Post.id != self.id)

        while query.first() is not None:
            slug = f"{base_slug}-{counter}"
            counter += 1
            query = Post.query.filter_by(slug=slug)
            if self.id:
                query = query.filter(Post.id != self.id)

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

    def _calculate_reading_time(self, content: str, words_per_minute: int = 200) -> int:
        """
        Calculate estimated reading time in minutes based on content length.

        Args:
            content: The post content
            words_per_minute: Average reading speed in words per minute

        Returns:
            int: Estimated reading time in minutes (minimum 1)
        """
        # Strip HTML tags
        text = re.sub(r'<[^>]+>', '', content)

        # Count words
        words = len(re.findall(r'\w+', text))

        # Calculate reading time (minimum 1 minute)
        reading_time = max(1, round(words / words_per_minute))

        return reading_time

    def publish(self) -> bool:
        """
        Publish the post.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Store previous status for logging
            previous_status = self.status

            # Update status and timestamps
            self.status = self.STATUS_PUBLISHED
            self.published_at = datetime.now(timezone.utc)

            # If scheduled, clear the scheduled_at field
            if self.scheduled_at:
                self.scheduled_at = None

            # Save changes
            db.session.commit()

            # Create revision
            self._create_revision("Post published")

            # Log the status change
            self._log_status_change(previous_status, self.STATUS_PUBLISHED)

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
            # Store previous status for logging
            previous_status = self.status

            # Update status
            self.status = self.STATUS_ARCHIVED

            # Save changes
            db.session.commit()

            # Create revision
            self._create_revision("Post archived")

            # Log the status change
            self._log_status_change(previous_status, self.STATUS_ARCHIVED)

            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error archiving post: {str(e)}")
            return False

    def schedule(self, publish_at: datetime) -> bool:
        """
        Schedule the post for future publication.

        Args:
            publish_at: Date and time when the post should be published

        Returns:
            bool: True if successful, False otherwise

        Raises:
            ValueError: If scheduled date is in the past
        """
        # Ensure publish_at is timezone-aware
        if publish_at.tzinfo is None:
            publish_at = publish_at.replace(tzinfo=timezone.utc)

        # Validate that publish_at is in the future
        if publish_at <= datetime.now(timezone.utc):
            raise ValueError("Scheduled publication date must be in the future")

        try:
            # Store previous status for logging
            previous_status = self.status

            # Update status and scheduled time
            self.status = self.STATUS_SCHEDULED
            self.scheduled_at = publish_at

            # Save changes
            db.session.commit()

            # Create revision
            self._create_revision(f"Post scheduled for {publish_at.isoformat()}")

            # Log the status change
            self._log_status_change(previous_status, self.STATUS_SCHEDULED)

            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error scheduling post: {str(e)}")
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
                      excerpt: Optional[str] = None, commit: bool = True,
                      revision_message: str = "Content updated") -> bool:
        """
        Update post content fields.

        Args:
            title: New title (optional)
            content: New content (optional)
            excerpt: New excerpt (optional)
            commit: Whether to commit the changes immediately
            revision_message: Message to include in revision history

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            changes_made = False
            old_content = None
            old_title = None

            if title and title != self.title:
                old_title = self.title
                self.title = title

                # Update slug when title changes
                old_slug = self.slug
                new_slug = self.generate_slug()
                self.slug = new_slug

                changes_made = True

            if content and content != self.content:
                old_content = self.content
                self.content = content
                changes_made = True

                # Recalculate reading time
                self.reading_time = self._calculate_reading_time(content)

                # Regenerate excerpt if not provided
                if not excerpt:
                    self.excerpt = self._generate_excerpt(content)

            if excerpt:
                self.excerpt = excerpt
                changes_made = True

            if changes_made and commit:
                db.session.commit()

                # Create revision
                self._create_revision(
                    revision_message,
                    {
                        'old_content': old_content,
                        'old_title': old_title
                    }
                )

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

            event_type = "feature" if featured else "unfeature"
            log_model_event(
                model_name="Post",
                event_type=event_type,
                object_id=self.id,
                user_id=getattr(g, 'user_id', None) if hasattr(g, 'user_id') else None,
                details={"featured": featured},
                severity="info"
            )

            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error setting post featured status: {str(e)}")
            return False

    def update_visibility(self, visibility: str, required_permission: Optional[str] = None) -> bool:
        """
        Update visibility settings for the post.

        Args:
            visibility: New visibility setting
            required_permission: Permission required for restricted/private content

        Returns:
            bool: True if successful, False otherwise

        Raises:
            ValueError: If visibility value is invalid
        """
        if visibility not in self.VALID_VISIBILITIES:
            raise ValueError(f"Invalid visibility value: {visibility}")

        try:
            changes = {}
            old_values = {}

            if visibility != self.visibility:
                old_values['visibility'] = self.visibility
                self.visibility = visibility
                changes['visibility'] = visibility

            if required_permission is not None and required_permission != self.required_permission:
                old_values['required_permission'] = self.required_permission
                self.required_permission = required_permission
                changes['required_permission'] = required_permission

            if changes:
                db.session.commit()

                # Log security-relevant change
                log_model_event(
                    model_name="Post",
                    event_type="update_visibility",
                    object_id=self.id,
                    user_id=getattr(g, 'user_id', None) if hasattr(g, 'user_id') else None,
                    details={
                        "changes": changes,
                        "old_values": old_values
                    },
                    severity="medium"  # Security-related change
                )

            return bool(changes)

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error updating post visibility: {str(e)}")
            return False

    def set_featured_image(self, media_id: int, alt_text: Optional[str] = None,
                          caption: Optional[str] = None) -> bool:
        """
        Set the featured image for the post.

        Args:
            media_id: ID of the media item to use as featured image
            alt_text: Alternative text for accessibility
            caption: Image caption

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.featured_image_id = media_id

            if alt_text is not None:
                self.featured_image_alt = alt_text

            if caption is not None:
                self.featured_image_caption = caption

            db.session.commit()
            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error setting featured image: {str(e)}")
            return False

    def update_seo_metadata(self, meta_title: Optional[str] = None,
                           meta_description: Optional[str] = None,
                           keywords: Optional[str] = None,
                           canonical_url: Optional[str] = None) -> bool:
        """
        Update SEO metadata for the post.

        Args:
            meta_title: SEO title override
            meta_description: SEO description
            keywords: Meta keywords
            canonical_url: Canonical URL for duplicate content

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            changes_made = False

            if meta_title is not None and meta_title != self.meta_title:
                self.meta_title = meta_title
                changes_made = True

            if meta_description is not None and meta_description != self.meta_description:
                self.meta_description = meta_description
                changes_made = True

            if keywords is not None and keywords != self.keywords:
                self.keywords = keywords
                changes_made = True

            if canonical_url is not None and canonical_url != self.canonical_url:
                self.canonical_url = canonical_url
                changes_made = True

            if changes_made:
                db.session.commit()

            return changes_made

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error updating SEO metadata: {str(e)}")
            return False

    def update_comment_settings(self, allow_comments: bool) -> bool:
        """
        Update comment settings for the post.

        Args:
            allow_comments: Whether to allow comments on this post

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if self.allow_comments != allow_comments:
                self.allow_comments = allow_comments
                db.session.commit()
                return True
            return False

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error updating comment settings: {str(e)}")
            return False

    def increment_comment_count(self) -> bool:
        """
        Increment the comment count and update last_commented_at timestamp.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.comment_count += 1
            self.last_commented_at = datetime.now(timezone.utc)
            db.session.commit()
            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error incrementing comment count: {str(e)}")
            return False

    def decrement_comment_count(self) -> bool:
        """
        Decrement the comment count.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if self.comment_count > 0:
                self.comment_count -= 1
                db.session.commit()
            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error decrementing comment count: {str(e)}")
            return False

    def add_category(self, category_id: int) -> bool:
        """
        Add post to a category.

        Args:
            category_id: ID of the category to add

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            from ..content import Category
            category = Category.query.get(category_id)

            if category is None:
                return False

            if category not in self.categories:
                self.categories.append(category)
                db.session.commit()

            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error adding category: {str(e)}")
            return False

    def remove_category(self, category_id: int) -> bool:
        """
        Remove post from a category.

        Args:
            category_id: ID of the category to remove

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            from ..content import Category
            category = Category.query.get(category_id)

            if category is None:
                return False

            if category in self.categories:
                self.categories.remove(category)
                db.session.commit()

            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error removing category: {str(e)}")
            return False

    def add_tag(self, tag_name: str) -> bool:
        """
        Add a tag to the post.

        Args:
            tag_name: Name of the tag to add

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            from ..content import Tag
            tag, created = Tag.get_or_create(tag_name)

            if tag not in self.tags:
                self.tags.append(tag)
                db.session.commit()

                # Increment tag usage count
                if not created:
                    tag.increment_usage_count()

            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error adding tag: {str(e)}")
            return False

    def remove_tag(self, tag_name: str) -> bool:
        """
        Remove a tag from the post.

        Args:
            tag_name: Name of the tag to remove

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            from ..content import Tag
            tag = Tag.get_by_name(tag_name)

            if tag is None:
                return False

            if tag in self.tags:
                self.tags.remove(tag)
                db.session.commit()

            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error removing tag: {str(e)}")
            return False

    def get_previous_post(self, same_category: bool = False) -> Optional['Post']:
        """
        Get the previous post based on publish date.

        Args:
            same_category: Whether to restrict to the same category

        Returns:
            Optional[Post]: The previous post or None if this is the first post
        """
        query = Post.query.filter(
            Post.status == self.STATUS_PUBLISHED,
            Post.published_at < self.published_at
        )

        if same_category and self.categories:
            # Get posts that share at least one category with this post
            category_ids = [cat.id for cat in self.categories]
            query = query.join(Post.categories).filter(
                Category.id.in_(category_ids)
            )

        return query.order_by(Post.published_at.desc()).first()

    def get_next_post(self, same_category: bool = False) -> Optional['Post']:
        """
        Get the next post based on publish date.

        Args:
            same_category: Whether to restrict to the same category

        Returns:
            Optional[Post]: The next post or None if this is the latest post
        """
        query = Post.query.filter(
            Post.status == self.STATUS_PUBLISHED,
            Post.published_at > self.published_at
        )

        if same_category and self.categories:
            # Get posts that share at least one category with this post
            category_ids = [cat.id for cat in self.categories]
            query = query.join(Post.categories).filter(
                Category.id.in_(category_ids)
            )

        return query.order_by(Post.published_at.asc()).first()

    def get_related_posts(self, limit: int = 5) -> List['Post']:
        """
        Get related posts based on categories and tags.

        Args:
            limit: Maximum number of related posts to return

        Returns:
            List[Post]: List of related posts
        """
        if not self.categories and not self.tags:
            return []

        # Initialize query for published posts excluding this post
        query = Post.query.filter(
            Post.status == self.STATUS_PUBLISHED,
            Post.id != self.id
        )

        # Build score using categorization data
        score_components = []

        if self.categories:
            # Add category scores
            category_ids = [cat.id for cat in self.categories]
            category_subquery = db.session.query(
                func.count().label('category_matches')
            ).select_from(
                db.Table('post_categories')
            ).filter(
                db.and_(
                    db.Table('post_categories').c.post_id == Post.id,
                    db.Table('post_categories').c.category_id.in_(category_ids)
                )
            ).scalar_subquery()

            score_components.append(category_subquery * 2)  # Categories weighted more

        if self.tags:
            # Add tag scores
            tag_ids = [tag.id for tag in self.tags]
            tag_subquery = db.session.query(
                func.count().label('tag_matches')
            ).select_from(
                db.Table('post_tags')
            ).filter(
                db.and_(
                    db.Table('post_tags').c.post_id == Post.id,
                    db.Table('post_tags').c.tag_id.in_(tag_ids)
                )
            ).scalar_subquery()

            score_components.append(tag_subquery)

        # Only include posts with at least one match
        if score_components:
            total_score = sum(score_components)
            # Order by score and then by publish date
            query = query.order_by(
                total_score.desc(),
                Post.published_at.desc()
            )

        # Limit results
        return query.limit(limit).all()

    def _create_revision(self, message: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Create a new revision record for this post.

        Args:
            message: Description of the changes
            metadata: Additional information about the revision

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            from ..content import ContentRevision

            user_id = getattr(g, 'user_id', None) if hasattr(g, 'user_id') else None

            revision = ContentRevision(
                content_type="post",
                content_id=self.id,
                title=self.title,
                content=self.content,
                user_id=user_id,
                message=message,
                metadata=metadata or {}
            )

            db.session.add(revision)
            db.session.commit()
            return True

        except (SQLAlchemyError, ImportError) as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error creating revision: {str(e)}")
            return False

    def _log_status_change(self, old_status: str, new_status: str) -> None:
        """
        Log a status change event for auditing purposes.

        Args:
            old_status: Previous status
            new_status: New status
        """
        user_id = getattr(g, 'user_id', None) if hasattr(g, 'user_id') else None

        log_model_event(
            model_name="Post",
            event_type="status_change",
            object_id=self.id,
            user_id=user_id,
            details={
                "old_status": old_status,
                "new_status": new_status
            },
            severity="info"
        )

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
    def get_featured(cls, limit: int = 5) -> List['Post']:
        """
        Get featured published posts.

        Args:
            limit: Maximum number of posts to return

        Returns:
            List[Post]: List of featured published posts
        """
        return cls.query.filter_by(status=cls.STATUS_PUBLISHED, featured=True)\
                       .order_by(db.desc(cls.published_at)).limit(limit).all()

    @classmethod
    def get_recent(cls, limit: int = 5, post_type: Optional[str] = None) -> List['Post']:
        """
        Get most recent published posts.

        Args:
            limit: Maximum number of posts to return
            post_type: Optionally filter by post type

        Returns:
            List[Post]: List of most recent published posts
        """
        query = cls.query.filter_by(status=cls.STATUS_PUBLISHED)

        if post_type and post_type in cls.VALID_POST_TYPES:
            query = query.filter_by(post_type=post_type)

        return query.order_by(db.desc(cls.published_at)).limit(limit).all()

    @classmethod
    def get_popular(cls, limit: int = 5) -> List['Post']:
        """
        Get most viewed published posts.

        Args:
            limit: Maximum number of posts to return

        Returns:
            List[Post]: List of most viewed published posts
        """
        return cls.query.filter_by(status=cls.STATUS_PUBLISHED)\
                       .order_by(db.desc(cls.views)).limit(limit).all()

    @classmethod
    def search(cls, query: str, include_archived: bool = False,
              category_id: Optional[int] = None,
              tag_name: Optional[str] = None,
              post_type: Optional[str] = None,
              page: int = 1, per_page: int = 10) -> Tuple[List['Post'], int]:
        """
        Search posts by title, content, or excerpt with filtering options.

        Args:
            query: Search query string
            include_archived: Whether to include archived posts
            category_id: Optional category ID to filter by
            tag_name: Optional tag name to filter by
            post_type: Optional post type to filter by
            page: Page number for pagination
            per_page: Results per page

        Returns:
            Tuple containing list of matching posts and total count
        """
        search_query = query.strip()

        # Start with a base query
        base_query = cls.query

        # Apply status filter
        status_filter = [cls.STATUS_PUBLISHED]
        if include_archived:
            status_filter.append(cls.STATUS_ARCHIVED)

        base_query = base_query.filter(cls.status.in_(status_filter))

        # Apply search query if provided
        if search_query:
            base_query = base_query.filter(
                db.or_(
                    cls.title.ilike(f'%{search_query}%'),
                    cls.content.ilike(f'%{search_query}%'),
                    cls.excerpt.ilike(f'%{search_query}%')
                )
            )

        # Apply category filter if provided
        if category_id is not None:
            base_query = base_query.join(cls.categories).filter(Category.id == category_id)

        # Apply tag filter if provided
        if tag_name is not None:
            from ..content import Tag
            tag = Tag.get_by_name(tag_name)
            if tag:
                base_query = base_query.join(cls.tags).filter(Tag.id == tag.id)

        # Apply post type filter if provided
        if post_type in cls.VALID_POST_TYPES:
            base_query = base_query.filter(cls.post_type == post_type)

        # Get total count before pagination
        total = base_query.count()

        # Apply pagination and ordering
        results = base_query.order_by(db.desc(cls.published_at))\
                           .offset((page - 1) * per_page)\
                           .limit(per_page)\
                           .all()

        return results, total

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

    @classmethod
    def get_scheduled_posts(cls) -> List['Post']:
        """
        Get posts scheduled for future publication.

        Returns:
            List[Post]: List of scheduled posts
        """
        return cls.query.filter_by(status=cls.STATUS_SCHEDULED)\
                       .filter(cls.scheduled_at > datetime.now(timezone.utc))\
                       .order_by(cls.scheduled_at.asc()).all()

    @classmethod
    def get_posts_by_category_slug(cls, category_slug: str, page: int = 1,
                                 per_page: int = 10) -> Tuple[List['Post'], int]:
        """
        Get posts belonging to a category identified by slug.

        Args:
            category_slug: Slug of the category
            page: Page number
            per_page: Posts per page

        Returns:
            Tuple containing list of posts and total count
        """
        from ..content import Category

        category = Category.get_by_slug(category_slug)
        if category is None:
            return [], 0

        query = cls.query.filter_by(status=cls.STATUS_PUBLISHED)\
                        .join(cls.categories)\
                        .filter(Category.id == category.id)\
                        .order_by(cls.published_at.desc())

        total = query.count()

        results = query.offset((page - 1) * per_page)\
                      .limit(per_page)\
                      .all()

        return results, total

    @classmethod
    def get_posts_by_tag_name(cls, tag_name: str, page: int = 1,
                            per_page: int = 10) -> Tuple[List['Post'], int]:
        """
        Get posts with a specific tag.

        Args:
            tag_name: Name of the tag
            page: Page number
            per_page: Posts per page

        Returns:
            Tuple containing list of posts and total count
        """
        from ..content import Tag

        tag = Tag.get_by_name(tag_name)
        if tag is None:
            return [], 0

        query = cls.query.filter_by(status=cls.STATUS_PUBLISHED)\
                        .join(cls.tags)\
                        .filter(Tag.id == tag.id)\
                        .order_by(cls.published_at.desc())

        total = query.count()

        results = query.offset((page - 1) * per_page)\
                      .limit(per_page)\
                      .all()

        return results, total

    @classmethod
    def get_archive_data(cls) -> Dict[str, Dict[str, int]]:
        """
        Get post counts grouped by year and month.

        Returns:
            Dict: Nested dictionary of post counts by year and month
        """
        # Query to count posts by year and month
        results = db.session.query(
            func.extract('year', cls.published_at).label('year'),
            func.extract('month', cls.published_at).label('month'),
            func.count().label('count')
        ).filter(
            cls.status == cls.STATUS_PUBLISHED,
            cls.published_at.isnot(None)
        ).group_by(
            'year', 'month'
        ).order_by(
            'year', 'month'
        ).all()

        # Format results into a nested dictionary
        archive = {}
        for year, month, count in results:
            year = int(year)
            month = int(month)

            if year not in archive:
                archive[year] = {}

            archive[year][month] = count

        return archive

    @classmethod
    def process_scheduled_posts(cls) -> int:
        """
        Process scheduled posts that should now be published.

        Returns:
            int: Number of posts published
        """
        now = datetime.now(timezone.utc)
        scheduled_posts = cls.query.filter(
            cls.status == cls.STATUS_SCHEDULED,
            cls.scheduled_at <= now
        ).all()

        published_count = 0
        for post in scheduled_posts:
            if post.publish():
                published_count += 1

        return published_count

    def to_dict(self, include_content: bool = True,
               include_related: bool = False,
               include_comments: bool = False) -> Dict[str, Any]:
        """
        Convert post to dictionary.

        Args:
            include_content: Whether to include the full content
            include_related: Whether to include related posts
            include_comments: Whether to include comments

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
            'slug': self.slug,
            'excerpt': self.excerpt,
            'status': self.status,
            'post_type': self.post_type,
            'views': self.views,
            'featured': self.featured,
            'visibility': self.visibility,
            'allow_comments': self.allow_comments,
            'comment_count': self.comment_count,
            'reading_time': self.reading_time,
            'created_at': format_datetime(getattr(self, 'created_at', None)),
            'updated_at': format_datetime(getattr(self, 'updated_at', None)),
            'published_at': format_datetime(self.published_at),
            'last_commented_at': format_datetime(self.last_commented_at),
            'scheduled_at': format_datetime(self.scheduled_at),
            'user_id': self.user_id,
        }

        # Include content if requested
        if include_content:
            result['content'] = self.content

        # Include author details if relationship is loaded
        if self.user:
            result['author'] = {
                'id': self.user.id,
                'username': self.user.username,
                'name': getattr(self.user, 'name', None)
            }

        # Add SEO fields
        if self.meta_title:
            result['meta_title'] = self.meta_title
        if self.meta_description:
            result['meta_description'] = self.meta_description
        if self.keywords:
            result['keywords'] = self.keywords
        if self.canonical_url:
            result['canonical_url'] = self.canonical_url

        # Include featured image if available
        if self.featured_image_id:
            result['featured_image'] = {
                'id': self.featured_image_id,
                'alt_text': self.featured_image_alt,
                'caption': self.featured_image_caption
            }
            if self.featured_image:
                result['featured_image']['url'] = getattr(self.featured_image, 'url', None)

        # Include categories if available
        if hasattr(self, 'categories') and self.categories is not None:
            result['categories'] = [
                {'id': cat.id, 'name': cat.name, 'slug': getattr(cat, 'slug', None)}
                for cat in self.categories
            ]

        # Include tags if available
        if hasattr(self, 'tags') and self.tags is not None:
            result['tags'] = [
                {'id': tag.id, 'name': tag.name, 'slug': getattr(tag, 'slug', None)}
                for tag in self.tags
            ]

        # Include comments if requested
        if include_comments and self.allow_comments:
            result['comments'] = [
                comment.to_dict() for comment in self.comments.filter_by(is_approved=True).limit(10)
            ]

        # Include related posts if requested
        if include_related:
            result['related_posts'] = [
                {
                    'id': post.id,
                    'title': post.title,
                    'slug': post.slug,
                    'excerpt': post.excerpt,
                    'published_at': format_datetime(post.published_at)
                }
                for post in self.get_related_posts(limit=3)
            ]

        return result

    def __repr__(self) -> str:
        """
        String representation of the Post.

        Returns:
            str: String representation with title and status
        """
        return f'<Post {self.id}: {self.title} ({self.status})>'
