from datetime import datetime
from typing import List
from . import db, BaseModel

class Post(BaseModel):
    """Post model for blog/announcement system."""
    __tablename__ = 'posts'

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    slug = db.Column(db.String(200), unique=True)

    # Metadata
    status = db.Column(db.String(20), default='draft')
    post_type = db.Column(db.String(20), default='post')
    views = db.Column(db.Integer, default=0)
    featured = db.Column(db.Boolean, default=False)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    published_at = db.Column(db.DateTime, default=None)

    # Relationships
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('posts', lazy=True))

    # Status constants
    STATUS_DRAFT = 'draft'
    STATUS_PUBLISHED = 'published'
    STATUS_ARCHIVED = 'archived'

    def __init__(self, **kwargs) -> None:
        super(Post, self).__init__(**kwargs)
        if not self.slug and self.title:
            self.slug = self.generate_slug()

    def generate_slug(self) -> str:
        """Generate URL-friendly slug from title."""
        return "-".join(
            word.lower() for word in self.title.replace("'", "").split()
        )

    def publish(self) -> None:
        """Publish the post."""
        self.status = self.STATUS_PUBLISHED
        self.published_at = datetime.utcnow()
        db.session.commit()

    def archive(self) -> None:
        """Archive the post."""
        self.status = self.STATUS_ARCHIVED
        db.session.commit()

    def increment_views(self) -> None:
        """Increment view count."""
        self.views += 1
        db.session.commit()

    @classmethod
    def get_published(cls) -> List['Post']:
        """Get all published posts."""
        return cls.query.filter_by(status=cls.STATUS_PUBLISHED)\
                       .order_by(db.desc(cls.published_at)).all()

    @classmethod
    def search(cls, query: str) -> List['Post']:
        """Search posts by title or content."""
        return cls.query.filter(
            db.or_(
                cls.title.ilike(f'%{query}%'),
                cls.content.ilike(f'%{query}%')
            )
        ).all()

    def to_dict(self) -> dict:
        """Convert post to dictionary."""
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'slug': self.slug,
            'status': self.status,
            'views': self.views,
            'featured': self.featured,
            'author': self.user.username,
            'created_at': self.created_at.isoformat(),
            'published_at': self.published_at.isoformat() if self.published_at else None
        }

    def __repr__(self) -> str:
        return f'<Post {self.title}>'
