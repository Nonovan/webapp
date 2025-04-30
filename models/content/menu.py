"""
Menu models for content navigation structure.

This module defines the Menu and MenuItem models which provide structured
navigation for content items, enabling customizable site navigation with
support for hierarchical menu structures.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import validates
from flask import current_app

from .. import db, BaseModel

class Menu(BaseModel):
    """
    Menu model for site navigation.

    Represents a named navigation menu that can contain multiple menu items
    in a hierarchical structure.
    """
    __tablename__ = 'menus'

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    items = db.relationship('MenuItem', backref='menu', lazy='joined',
                           cascade='all, delete-orphan',
                           primaryjoin="and_(Menu.id==MenuItem.menu_id, MenuItem.parent_id==None)")

    def __init__(self, name: str, slug: str, description: Optional[str] = None,
                 is_active: bool = True):
        self.name = name
        self.slug = slug
        self.description = description
        self.is_active = is_active

    def to_dict(self, include_items: bool = True) -> Dict[str, Any]:
        """Convert menu to dictionary representation."""
        result = {
            'id': self.id,
            'name': self.name,
            'slug': self.slug,
            'description': self.description,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

        if include_items and hasattr(self, 'items'):
            result['items'] = [item.to_dict(include_children=True) for item in self.items]

        return result

    @classmethod
    def get_by_slug(cls, slug: str) -> Optional['Menu']:
        """Get menu by slug."""
        return cls.query.filter_by(slug=slug).first()

    @classmethod
    def get_active(cls) -> List['Menu']:
        """Get all active menus."""
        return cls.query.filter_by(is_active=True).all()

    def __repr__(self) -> str:
        return f"<Menu {self.id}: {self.name}>"


class MenuItem(BaseModel):
    """
    MenuItem model for navigation items.

    Represents an individual item in a navigation menu, which can be
    linked to content or external URLs in a hierarchical structure.
    """
    __tablename__ = 'menu_items'

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    menu_id = db.Column(db.Integer, db.ForeignKey('menus.id', ondelete='CASCADE'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('menu_items.id', ondelete='CASCADE'), nullable=True)
    title = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(512), nullable=True)  # External URL

    # Link to internal content
    content_type = db.Column(db.String(50), nullable=True)  # 'post', 'category', etc.
    content_id = db.Column(db.Integer, nullable=True)

    # Metadata
    position = db.Column(db.Integer, default=0, nullable=False)
    target = db.Column(db.String(20), default='_self', nullable=False)  # '_blank', '_self'
    css_class = db.Column(db.String(100), nullable=True)
    icon = db.Column(db.String(50), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Relationships
    children = db.relationship('MenuItem', backref=db.backref('parent', remote_side=[id]),
                             lazy='joined', cascade='all, delete-orphan',
                             order_by='MenuItem.position')

    def __init__(self, menu_id: int, title: str, url: Optional[str] = None,
                 content_type: Optional[str] = None, content_id: Optional[int] = None,
                 parent_id: Optional[int] = None, position: int = 0,
                 target: str = '_self', css_class: Optional[str] = None,
                 icon: Optional[str] = None, is_active: bool = True):
        self.menu_id = menu_id
        self.title = title
        self.url = url
        self.content_type = content_type
        self.content_id = content_id
        self.parent_id = parent_id
        self.position = position
        self.target = target
        self.css_class = css_class
        self.icon = icon
        self.is_active = is_active

    @validates('parent_id')
    def validate_parent_id(self, key: str, parent_id: Optional[int]) -> Optional[int]:
        """Validate parent_id to prevent circular references."""
        if parent_id is not None:
            if parent_id == self.id:
                raise ValueError("MenuItem cannot be its own parent")

            # Prevent deep nesting - only allow 2 levels
            if self.parent_id is not None:
                parent = MenuItem.query.get(parent_id)
                if parent and parent.parent_id is not None:
                    raise ValueError("Menu items can only be nested 2 levels deep")

        return parent_id

    def to_dict(self, include_children: bool = True) -> Dict[str, Any]:
        """Convert menu item to dictionary representation."""
        result = {
            'id': self.id,
            'menu_id': self.menu_id,
            'parent_id': self.parent_id,
            'title': self.title,
            'url': self.url,
            'content_type': self.content_type,
            'content_id': self.content_id,
            'position': self.position,
            'target': self.target,
            'css_class': self.css_class,
            'icon': self.icon,
            'is_active': self.is_active
        }

        if include_children and hasattr(self, 'children'):
            result['children'] = [child.to_dict(include_children=True) for child in self.children]

        return result

    @classmethod
    def get_item_by_content(cls, content_type: str, content_id: int) -> List['MenuItem']:
        """Get menu items associated with specific content."""
        return cls.query.filter_by(content_type=content_type, content_id=content_id).all()

    def __repr__(self) -> str:
        return f"<MenuItem {self.id}: {self.title}>"
