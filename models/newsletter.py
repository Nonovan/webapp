# models/newsletter.py

from datetime import datetime
import uuid
from extensions import db

class Subscriber(db.Model):
    """Model for newsletter subscribers."""
    
    __tablename__ = 'newsletter_subscribers'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    subscribed_at = db.Column(db.DateTime, default=datetime.utcnow)
    confirmed = db.Column(db.Boolean, default=False)
    confirmed_at = db.Column(db.DateTime, nullable=True)
    confirmation_token = db.Column(db.String(64), default=lambda: str(uuid.uuid4()), unique=True)
    unsubscribe_token = db.Column(db.String(64), default=lambda: str(uuid.uuid4()), unique=True)
    
    def __repr__(self):
        return f"<Subscriber {self.email}>"