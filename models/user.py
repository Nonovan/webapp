from datetime import datetime, timedelta
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app
from . import db, BaseModel

class User(BaseModel):
    __tablename__ = 'users'
    
    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    
    # Role and status
    role = db.Column(db.String(20), default='user')
    status = db.Column(db.String(20), default='pending')
    
    # Profile fields
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    bio = db.Column(db.Text)
    avatar_url = db.Column(db.String(255))
    
    # Security
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32))
    
    # Activity tracking
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())
    last_login = db.Column(db.DateTime)
    login_count = db.Column(db.Integer, default=0)
    failed_login_count = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime)

    # Status constants
    STATUS_PENDING = 'pending'
    STATUS_ACTIVE = 'active'
    STATUS_INACTIVE = 'inactive'
    STATUS_SUSPENDED = 'suspended'

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def generate_token(self, expires_in=3600):
        """Generate JWT token."""
        return jwt.encode(
            {
                'user_id': self.id,
                'role': self.role,
                'exp': datetime.utcnow() + timedelta(seconds=expires_in)
            },
            current_app.config['SECRET_KEY'],
            algorithm='HS256'
        )

    @staticmethod
    def verify_token(token):
        """Verify JWT token."""
        try:
            data = jwt.decode(
                token,
                current_app.config['SECRET_KEY'],
                algorithms=['HS256']
            )
            return User.query.get(data['user_id'])
        except:
            return None

    def update_last_login(self):
        """Update login tracking."""
        self.last_login = datetime.utcnow()
        self.login_count += 1
        db.session.commit()

    def record_failed_login(self):
        """Record failed login attempt."""
        self.failed_login_count += 1
        self.last_failed_login = datetime.utcnow()
        db.session.commit()

    @property
    def is_admin(self):
        """Check if user is admin."""
        return self.role == 'admin'

    def __repr__(self):
        return f'<User {self.username}>'