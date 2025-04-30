"""
Comment model for content management system.

This module defines the Comment model which represents user-submitted comments
on content items such as posts. It provides functionality for nested comments
(replies), moderation status tracking, and user attribution.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import validates
from flask import current_app, g

from .. import db, BaseModel
from ..security.audit_log import AuditLog

class Comment(BaseModel):
    """
    Comment model for user-submitted feedback on content.

    Represents comments on posts with support for nested replies,
    moderation workflow, and user attribution.
    """
    __tablename__ = 'comments'

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    author_name = db.Column(db.String(100), nullable=True)  # For non-authenticated users
    author_email = db.Column(db.String(255), nullable=True)  # For non-authenticated users
    author_ip = db.Column(db.String(45), nullable=True)  # For tracking/moderation

    # Foreign keys
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('comments.id', ondelete='CASCADE'), nullable=True)

    # Moderation
    status = db.Column(db.String(20), default='pending', nullable=False)
    moderated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    moderated_at = db.Column(db.DateTime, nullable=True)
    moderation_reason = db.Column(db.String(255), nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    post = db.relationship('Post', backref=db.backref('comments', lazy='dynamic', cascade='all, delete-orphan'))
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('comments', lazy='dynamic'))
    moderator = db.relationship('User', foreign_keys=[moderated_by], backref=db.backref('moderated_comments', lazy='dynamic'))
    parent = db.relationship('Comment', remote_side=[id], backref=db.backref('replies', lazy='dynamic'))

    # Status constants
    STATUS_PENDING = 'pending'
    STATUS_APPROVED = 'approved'
    STATUS_REJECTED = 'rejected'
    STATUS_SPAM = 'spam'

    VALID_STATUSES = [STATUS_PENDING, STATUS_APPROVED, STATUS_REJECTED, STATUS_SPAM]

    def __init__(self, content: str, post_id: int, user_id: Optional[int] = None,
                 author_name: Optional[str] = None, author_email: Optional[str] = None,
                 author_ip: Optional[str] = None, parent_id: Optional[int] = None,
                 status: str = 'pending'):
        self.content = content
        self.post_id = post_id
        self.user_id = user_id
        self.author_name = author_name
        self.author_email = author_email
        self.author_ip = author_ip
        self.parent_id = parent_id

        if status not in self.VALID_STATUSES:
            status = self.STATUS_PENDING
        self.status = status

    @validates('status')
    def validate_status(self, key: str, status: str) -> str:
        """Validate the status field."""
        if status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {', '.join(self.VALID_STATUSES)}")
        return status

    def moderate(self, status: str, moderated_by: int, reason: Optional[str] = None) -> bool:
        """Moderate this comment by changing its status."""
        try:
            if status not in self.VALID_STATUSES:
                return False

            self.status = status
            self.moderated_by = moderated_by
            self.moderated_at = datetime.utcnow()
            self.moderation_reason = reason

            db.session.commit()

            # Log the moderation action
            AuditLog.create_log(
                event_type=f'comment_moderated_{status}',
                user_id=moderated_by,
                resource_type='comment',
                resource_id=self.id,
                description=f"Comment moderated: {status}",
                data={"post_id": self.post_id, "status": status, "reason": reason}
            )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error moderating comment: {str(e)}")
            return False

    def approve(self, moderated_by: int) -> bool:
        """Approve this comment."""
        return self.moderate(self.STATUS_APPROVED, moderated_by)

    def reject(self, moderated_by: int, reason: Optional[str] = None) -> bool:
        """Reject this comment."""
        return self.moderate(self.STATUS_REJECTED, moderated_by, reason)

    def mark_as_spam(self, moderated_by: int) -> bool:
        """Mark this comment as spam."""
        return self.moderate(self.STATUS_SPAM, moderated_by, "Spam")

    def to_dict(self, include_replies: bool = False) -> Dict[str, Any]:
        """Convert comment to dictionary representation."""
        result = {
            'id': self.id,
            'content': self.content,
            'post_id': self.post_id,
            'user_id': self.user_id,
            'author_name': self.author_name,
            'status': self.status,
            'parent_id': self.parent_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

        if include_replies and hasattr(self, 'replies'):
            result['replies'] = [reply.to_dict(include_replies=False) for reply in self.replies]

        return result

    @classmethod
    def get_approved_comments(cls, post_id: int, include_replies: bool = True) -> List['Comment']:
        """Get all approved comments for a post."""
        query = cls.query.filter_by(post_id=post_id, status=cls.STATUS_APPROVED)

        if not include_replies:
            query = query.filter(cls.parent_id.is_(None))

        return query.order_by(cls.created_at).all()

    @classmethod
    def get_comments_for_moderation(cls, page: int = 1, per_page: int = 20) -> tuple:
        """Get comments pending moderation."""
        pagination = cls.query.filter_by(status=cls.STATUS_PENDING)\
                        .order_by(cls.created_at.asc())\
                        .paginate(page=page, per_page=per_page, error_out=False)

        return pagination.items, pagination.total, pagination.pages

    def __repr__(self) -> str:
        return f"<Comment {self.id}: {self.status}>"
