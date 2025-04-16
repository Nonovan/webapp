"""
System configuration model for myproject.

This module provides the SystemConfig model which represents application
configuration settings stored in the database. It allows for dynamic
configuration changes without requiring application restarts and provides
an audit trail of configuration modifications.

Configuration settings are categorized, versioned, and include security
controls to prevent unauthorized changes to critical system parameters.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from extensions import db, cache
from models.base import BaseModel
from models.audit_log import AuditLog


class SystemConfig(BaseModel):
    """
    Database model for storing application configuration settings.
    
    This model represents a key-value store for application settings
    that can be modified at runtime. Each setting can have metadata
    including a description, security level, and validation rules.
    
    Attributes:
        id: Primary key
        key: Configuration key name (unique)
        value: Configuration value (stored as string)
        description: Human-readable description of the setting
        category: Category for grouping related settings
        security_level: Security restriction level (public, restricted, admin)
        is_encrypted: Whether the value should be stored encrypted
        validation_rules: JSON rules for validating value changes
        created_at: When the config was created (from BaseModel)
        updated_at: Last update timestamp (from BaseModel)
    """
    __tablename__ = 'system_configs'
    
    # Security levels
    SECURITY_PUBLIC = 'public'      # Readable by all authenticated users
    SECURITY_RESTRICTED = 'restricted'  # Restricted to specific roles
    SECURITY_ADMIN = 'admin'        # Admin only
    
    # Default categories
    CATEGORY_SECURITY = 'security'
    CATEGORY_PERFORMANCE = 'performance'
    CATEGORY_NOTIFICATION = 'notification'
    CATEGORY_APPEARANCE = 'appearance'
    CATEGORY_FEATURE_FLAG = 'feature_flag'
    
    # Column definitions
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True)
    description = db.Column(db.String(255), nullable=True)
    category = db.Column(db.String(50), nullable=False, default=CATEGORY_SECURITY)
    security_level = db.Column(db.String(20), nullable=False, default=SECURITY_RESTRICTED)
    is_encrypted = db.Column(db.Boolean, default=False)
    validation_rules = db.Column(db.JSON, nullable=True)
    
    def __init__(self, key: str, value: str, description: Optional[str] = None, 
                 category: str = CATEGORY_SECURITY, security_level: str = SECURITY_RESTRICTED,
                 is_encrypted: bool = False, validation_rules: Optional[Dict] = None):
        """
        Initialize a new SystemConfig entry.
        
        Args:
            key: Configuration key name
            value: Configuration value
            description: Human-readable description
            category: Category for grouping
            security_level: Security restriction level
            is_encrypted: Whether the value should be stored encrypted
            validation_rules: JSON rules for validating value changes
        """
        super().__init__()  # Call the base class __init__ method
        self.key = key
        self.value = self._encrypt_if_needed(value, is_encrypted)
        self.description = description
        self.category = category
        self.security_level = security_level
        self.is_encrypted = is_encrypted
        self.validation_rules = validation_rules or {}
    
    def _encrypt_if_needed(self, value: str, should_encrypt: bool) -> str:
        """Encrypt the value if needed."""
        if should_encrypt and value:
            from core.security_utils import encrypt_sensitive_data
            return encrypt_sensitive_data(value)
        return value
    
    def _decrypt_if_needed(self) -> str:
        """Decrypt the value if it's encrypted."""
        if self.is_encrypted and self.value:
            from core.security_utils import decrypt_sensitive_data
            return decrypt_sensitive_data(self.value)
        return self.value
    
    @property
    def decoded_value(self) -> Any:
        """Get the configuration value, decrypting if necessary."""
        raw_value = self._decrypt_if_needed()
        
        # Try to convert to appropriate type
        if raw_value is None:
            return None
        
        # Handle boolean values
        if raw_value.lower() in ('true', 'false'):
            return raw_value.lower() == 'true'
        
        # Handle numeric values
        try:
            if '.' in raw_value:
                return float(raw_value)
            return int(raw_value)
        except (ValueError, TypeError):
            pass
            
        return raw_value
    
    def update_value(self, new_value: str, user_id: Optional[int] = None) -> bool:
        """
        Update the configuration value with audit logging.
        
        Args:
            new_value: New configuration value
            user_id: ID of user making the change
            
        Returns:
            bool: True if update successful, False otherwise
        """
        # Handle encryption if needed
        self.value = self._encrypt_if_needed(new_value, self.is_encrypted)
        self.updated_at = datetime.utcnow()  # Ensure updated_at is a direct attribute or use a setter if defined
        
        try:
            db.session.commit()
            
            # Log the configuration change
            from core.security_utils import log_security_event
            log_security_event(
                event_type=AuditLog.EVENT_CONFIG_CHANGE,
                description=f"Configuration '{self.key}' updated",
                user_id=user_id,
                details=f"Category: {self.category}, Old value masked for security"
            )
            
            # Clear cache for this config
            self.clear_cache()
            
            return True
        except (db.exc.SQLAlchemyError, ValueError) as e:
            db.session.rollback()
            from flask import current_app
            current_app.logger.error(f"Failed to update config {self.key}: {e}")
            return False
    
    def clear_cache(self) -> None:
        """Clear any cached instances of this configuration."""
        cache_key = f"system_config_{self.key}"
        if hasattr(cache, 'delete'):
            cache.delete(cache_key)
    
    @classmethod
    def get_value(cls, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by key with caching.
        
        Args:
            key: Configuration key
            default: Default value if key doesn't exist
            
        Returns:
            The configuration value or default
        """
        cache_key = f"system_config_{key}"
        
        # Try to get from cache first
        cached_value = cache.get(cache_key)
        if cached_value is not None:
            return cached_value
        
        # Get from database
        config = cls.query.filter_by(key=key).first()
        if not config:
            return default
            
        value = config.decoded_value
        
        # Cache the result
        cache.set(cache_key, value, timeout=300)  # 5 minutes
        
        return value
    
    @classmethod
    def set_value(cls, key: str, value: str, user_id: Optional[int] = None, 
                  description: Optional[str] = None, category: Optional[str] = None) -> bool:
        """
        Set a configuration value, creating the entry if it doesn't exist.
        
        Args:
            key: Configuration key
            value: New value
            user_id: ID of user making the change
            description: Optional description for new entries
            category: Optional category for new entries
            
        Returns:
            bool: True if successful, False otherwise
        """
        config = cls.query.filter_by(key=key).first()
        
        if config:
            return config.update_value(value, user_id)
        else:
            # Create new config entry
            try:
                new_config = cls(
                    key=key,
                    value=value,
                    description=description,
                    category=category or cls.CATEGORY_SECURITY
                )
                db.session.add(new_config)
                db.session.commit()
                
                # Log the configuration creation
                from core.security_utils import log_security_event
                log_security_event(
                    event_type=AuditLog.EVENT_CONFIG_CHANGE,
                    description=f"Configuration '{key}' created",
                    user_id=user_id,
                    details=f"Category: {new_config.category}"
                )
                
                return True
            except (db.exc.SQLAlchemyError, ValueError) as e:
                db.session.rollback()
                from flask import current_app
                current_app.logger.error(f"Failed to create config {key}: {e}")
                return False
    
    @classmethod
    def get_by_category(cls, category: str) -> List['SystemConfig']:
        """Get all configuration settings in a specific category."""
        return cls.query.filter_by(category=category).all()
    
    @classmethod
    def initialize_defaults(cls) -> None:
        """
        Initialize default system configuration values.
        
        This method ensures critical system configurations exist
        with appropriate default values.
        """
        defaults = [
            # Security settings
            {
                'key': 'max_login_attempts',
                'value': '5',
                'description': 'Maximum failed login attempts before account lockout',
                'category': cls.CATEGORY_SECURITY
            },
            {
                'key': 'lockout_period_minutes',
                'value': '30',
                'description': 'Account lockout period in minutes',
                'category': cls.CATEGORY_SECURITY
            },
            {
                'key': 'session_timeout_minutes',
                'value': '30',
                'description': 'Session timeout in minutes',
                'category': cls.CATEGORY_SECURITY
            },
            {
                'key': 'password_min_length',
                'value': '12', 
                'description': 'Minimum password length',
                'category': cls.CATEGORY_SECURITY
            },
            # Feature flags
            {
                'key': 'maintenance_mode',
                'value': 'false',
                'description': 'Enable maintenance mode',
                'category': cls.CATEGORY_FEATURE_FLAG
            },
            {
                'key': 'enable_security_monitoring',
                'value': 'true',
                'description': 'Enable security monitoring features',
                'category': cls.CATEGORY_FEATURE_FLAG
            },
            # Notification settings
            {
                'key': 'notification_email',
                'value': 'admin@example.com',
                'description': 'Email address for system notifications',
                'category': cls.CATEGORY_NOTIFICATION
            }
        ]
        
        for config in defaults:
            # Only create if doesn't exist
            existing = cls.query.filter_by(key=config['key']).first()
            if not existing:
                new_config = cls(
                    key=config['key'],
                    value=config['value'],
                    description=config['description'],
                    category=config['category']
                )
                db.session.add(new_config)
        
        try:
            db.session.commit()
        except db.exc.SQLAlchemyError as e:
            db.session.rollback()
            from flask import current_app
            current_app.logger.error(f"Failed to initialize default configs: {e}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            'id': self.id,
            'key': self.key,
            'value': self.value if not self.is_encrypted else '[REDACTED]',
            'description': self.description,
            'category': self.category,
            'security_level': self.security_level,
            'is_encrypted': self.is_encrypted,
            'updated_at': self.updated_at.isoformat() if isinstance(self.updated_at, datetime) else None
        }