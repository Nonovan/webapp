"""
Media model for file attachments in the content management system.

This module defines the Media model which represents uploaded files such as images,
documents, videos, and other attachments that can be associated with content items.
It provides functionality for tracking media metadata, handling various file types,
and associating media with content items.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
import os
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app, g

from .. import db, BaseModel
from ..security.audit_log import AuditLog

class Media(BaseModel):
    """
    Media model for managing file attachments and uploads.

    Represents uploaded files and their metadata including images,
    documents, videos, and other media types that can be attached to
    content throughout the platform.
    """
    __tablename__ = 'media'

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    storage_path = db.Column(db.String(512), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)  # size in bytes
    mime_type = db.Column(db.String(128), nullable=False)
    title = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)
    alt_text = db.Column(db.String(255), nullable=True)  # for accessibility

    # Metadata
    upload_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    media_type = db.Column(db.String(50), nullable=False, index=True)  # image, document, video, etc.
    is_public = db.Column(db.Boolean, default=True, nullable=False)

    # Additional metadata stored as JSON
    metadata = db.Column(db.JSON, default=dict, nullable=False)  # dimensions, duration, etc.

    # Relationships
    user = db.relationship('User', backref=db.backref('uploads', lazy='dynamic'))

    # Media type constants
    TYPE_IMAGE = 'image'
    TYPE_DOCUMENT = 'document'
    TYPE_VIDEO = 'video'
    TYPE_AUDIO = 'audio'
    TYPE_OTHER = 'other'

    VALID_MEDIA_TYPES = [TYPE_IMAGE, TYPE_DOCUMENT, TYPE_VIDEO, TYPE_AUDIO, TYPE_OTHER]

    @hybrid_property
    def url(self) -> str:
        """Generate the URL for this media item."""
        if self.is_public:
            return f"/media/{self.storage_path}"
        return f"/media/private/{self.storage_path}"

    def __init__(self, filename: str, storage_path: str, file_size: int,
                 mime_type: str, uploaded_by: int, media_type: str = None,
                 title: str = None, description: str = None,
                 alt_text: str = None, is_public: bool = True,
                 metadata: Dict = None):
        self.filename = filename
        self.storage_path = storage_path
        self.file_size = file_size
        self.mime_type = mime_type
        self.uploaded_by = uploaded_by
        self.title = title
        self.description = description
        self.alt_text = alt_text
        self.is_public = is_public
        self.metadata = metadata or {}

        # Determine media type from mime_type if not provided
        if not media_type:
            if mime_type.startswith('image/'):
                media_type = self.TYPE_IMAGE
            elif mime_type.startswith('video/'):
                media_type = self.TYPE_VIDEO
            elif mime_type.startswith('audio/'):
                media_type = self.TYPE_AUDIO
            elif mime_type in ['application/pdf', 'application/msword',
                              'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                media_type = self.TYPE_DOCUMENT
            else:
                media_type = self.TYPE_OTHER

        if media_type not in self.VALID_MEDIA_TYPES:
            media_type = self.TYPE_OTHER

        self.media_type = media_type

    def to_dict(self) -> Dict[str, Any]:
        """Convert media to dictionary representation."""
        return {
            'id': self.id,
            'filename': self.filename,
            'url': self.url,
            'file_size': self.file_size,
            'mime_type': self.mime_type,
            'title': self.title,
            'description': self.description,
            'alt_text': self.alt_text,
            'upload_date': self.upload_date.isoformat() if self.upload_date else None,
            'uploaded_by': self.uploaded_by,
            'media_type': self.media_type,
            'is_public': self.is_public,
            'metadata': self.metadata
        }

    @classmethod
    def get_by_media_type(cls, media_type: str, page: int = 1,
                          per_page: int = 20) -> List['Media']:
        """Get media items by type with pagination."""
        if media_type not in cls.VALID_MEDIA_TYPES:
            return []

        return cls.query.filter_by(media_type=media_type)\
                       .order_by(cls.upload_date.desc())\
                       .paginate(page=page, per_page=per_page, error_out=False).items

    def delete(self) -> bool:
        """Delete media and associated file."""
        try:
            # Log the action
            AuditLog.create_log(
                event_type='media_deleted',
                user_id=getattr(g, 'user_id', None),
                resource_type='media',
                resource_id=self.id,
                description=f"Media deleted: {self.filename}",
                data={"filename": self.filename, "media_type": self.media_type}
            )

            # Delete the actual file
            file_path = os.path.join(
                current_app.config.get('MEDIA_STORAGE_PATH', 'uploads'),
                self.storage_path
            )
            if os.path.exists(file_path):
                os.remove(file_path)

            # Delete from database
            db.session.delete(self)
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error deleting media: {str(e)}")
            return False

    def __repr__(self) -> str:
        return f"<Media {self.id}: {self.filename}>"
