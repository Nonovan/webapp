"""
Association model linking posts and media in the content management system.

This module defines the PostMedia model which represents the many-to-many
relationship between posts and media items, allowing media to be attached to
posts with additional context such as display order and caption.
"""

from typing import List, Dict, Any, Optional
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app

from .. import db, BaseModel

class PostMedia(BaseModel):
    """
    Association model for linking posts with media items.

    Provides additional context for media items attached to posts such as
    captions, display order, and positioning information.
    """
    __tablename__ = 'post_media'

    # Primary keys and foreign keys
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id', ondelete='CASCADE'), nullable=False, index=True)
    media_id = db.Column(db.Integer, db.ForeignKey('media.id', ondelete='CASCADE'), nullable=False, index=True)

    # Association metadata
    caption = db.Column(db.String(255), nullable=True)
    display_order = db.Column(db.Integer, default=0, nullable=False)
    is_featured = db.Column(db.Boolean, default=False, nullable=False)
    position = db.Column(db.String(50), default='inline', nullable=False)  # inline, header, gallery

    # Relationships
    post = db.relationship('Post', backref=db.backref('media_links', lazy='joined', cascade='all, delete-orphan'))
    media = db.relationship('Media', backref=db.backref('post_links', lazy='dynamic'))

    # Position constants
    POSITION_INLINE = 'inline'
    POSITION_HEADER = 'header'
    POSITION_GALLERY = 'gallery'
    POSITION_ATTACHMENT = 'attachment'

    VALID_POSITIONS = [POSITION_INLINE, POSITION_HEADER, POSITION_GALLERY, POSITION_ATTACHMENT]

    def __init__(self, post_id: int, media_id: int,
                 display_order: int = 0, caption: str = None,
                 is_featured: bool = False, position: str = 'inline'):
        self.post_id = post_id
        self.media_id = media_id
        self.display_order = display_order
        self.caption = caption
        self.is_featured = is_featured

        if position not in self.VALID_POSITIONS:
            position = self.POSITION_INLINE
        self.position = position

    def to_dict(self) -> Dict[str, Any]:
        """Convert post-media link to dictionary representation."""
        media_data = None
        if self.media:
            media_data = self.media.to_dict()

        return {
            'id': self.id,
            'post_id': self.post_id,
            'media_id': self.media_id,
            'caption': self.caption,
            'display_order': self.display_order,
            'is_featured': self.is_featured,
            'position': self.position,
            'media': media_data
        }

    @classmethod
    def get_post_media(cls, post_id: int, position: str = None) -> List['PostMedia']:
        """Get all media associated with a post, optionally filtered by position."""
        query = cls.query.filter_by(post_id=post_id)

        if position and position in cls.VALID_POSITIONS:
            query = query.filter_by(position=position)

        return query.order_by(cls.display_order).all()

    @classmethod
    def get_featured_media(cls, post_id: int) -> Optional['PostMedia']:
        """Get the featured media for a post, if any."""
        return cls.query.filter_by(post_id=post_id, is_featured=True).first()

    def __repr__(self) -> str:
        return f"<PostMedia {self.id}: Post {self.post_id} - Media {self.media_id}>"
