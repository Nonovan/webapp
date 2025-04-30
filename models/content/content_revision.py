"""
ContentRevision model for tracking content version history.

This module defines the ContentRevision model which stores historical versions
of content items, enabling version comparison, content restoration, and
comprehensive audit trails.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
import json
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app, g

from .. import db, BaseModel

class ContentRevision(BaseModel):
    """
    ContentRevision model for tracking content version history.

    Stores historical versions of content for audit trail, comparison,
    and restoration capabilities.
    """
    __tablename__ = 'content_revisions'

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    content_type = db.Column(db.String(50), nullable=False)  # 'post', 'page', etc.
    content_id = db.Column(db.Integer, nullable=False)
    revision_number = db.Column(db.Integer, nullable=False)
    content_data = db.Column(db.Text, nullable=False)  # JSON serialization of content
    change_summary = db.Column(db.String(255), nullable=True)  # Brief description of changes

    # Who made the revision
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    created_by = db.relationship('User', backref=db.backref('content_revisions', lazy='dynamic'))

    # Indexes for efficient lookups
    __table_args__ = (
        db.Index('idx_content_revision_lookup', content_type, content_id, revision_number),
    )

    def __init__(self, content_type: str, content_id: int, created_by_id: int,
                 content_data: dict, change_summary: Optional[str] = None):
        self.content_type = content_type
        self.content_id = content_id
        self.created_by_id = created_by_id

        # Convert dict to JSON string
        if isinstance(content_data, dict):
            self.content_data = json.dumps(content_data)
        else:
            self.content_data = content_data

        self.change_summary = change_summary

        # Set the revision number based on existing revisions
        previous_revision = ContentRevision.query.filter_by(
            content_type=content_type,
            content_id=content_id
        ).order_by(ContentRevision.revision_number.desc()).first()

        if previous_revision:
            self.revision_number = previous_revision.revision_number + 1
        else:
            self.revision_number = 1

    @hybrid_property
    def content(self) -> Dict[str, Any]:
        """Get content data as a Python dictionary."""
        if not self.content_data:
            return {}
        try:
            return json.loads(self.content_data)
        except Exception:
            current_app.logger.error(f"Error parsing revision content: {self.id}")
            return {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert revision to dictionary representation."""
        return {
            'id': self.id,
            'content_type': self.content_type,
            'content_id': self.content_id,
            'revision_number': self.revision_number,
            'content': self.content,
            'change_summary': self.change_summary,
            'created_by_id': self.created_by_id,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    @classmethod
    def get_revisions(cls, content_type: str, content_id: int,
                      limit: int = None) -> List['ContentRevision']:
        """Get revisions for a specific content item."""
        query = cls.query.filter_by(
            content_type=content_type,
            content_id=content_id
        ).order_by(cls.revision_number.desc())

        if limit:
            query = query.limit(limit)

        return query.all()

    @classmethod
    def get_revision(cls, content_type: str, content_id: int,
                     revision_number: int) -> Optional['ContentRevision']:
        """Get a specific revision."""
        return cls.query.filter_by(
            content_type=content_type,
            content_id=content_id,
            revision_number=revision_number
        ).first()

    @classmethod
    def get_latest_revision(cls, content_type: str, content_id: int) -> Optional['ContentRevision']:
        """Get the latest revision for a content item."""
        return cls.query.filter_by(
            content_type=content_type,
            content_id=content_id
        ).order_by(cls.revision_number.desc()).first()

    @classmethod
    def create_revision(cls, content_type: str, content_id: int,
                        content_data: dict, user_id: int,
                        change_summary: Optional[str] = None) -> Optional['ContentRevision']:
        """Create a new revision for a content item."""
        try:
            revision = cls(
                content_type=content_type,
                content_id=content_id,
                content_data=content_data,
                created_by_id=user_id,
                change_summary=change_summary
            )

            db.session.add(revision)
            db.session.commit()
            return revision
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating content revision: {str(e)}")
            return None

    def __repr__(self) -> str:
        return f"<ContentRevision {self.content_type}:{self.content_id} #{self.revision_number}>"
