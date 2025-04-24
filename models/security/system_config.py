"""
System configuration model for myproject.

This module provides the SystemConfig model which represents application
configuration settings stored in the database. It allows for dynamic
configuration changes without requiring application restarts and provides
an audit trail of configuration modifications.

Configuration settings are categorized, versioned, and include security
controls to prevent unauthorized changes to critical system parameters.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union, cast
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app

from extensions import db, cache
from models.base import BaseModel
from models.audit_log import AuditLog
from core.security_utils import encrypt_sensitive_data, decrypt_sensitive_data, log_security_event


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

    SECURITY_LEVELS = [SECURITY_PUBLIC, SECURITY_RESTRICTED, SECURITY_ADMIN]

    # Default categories
    CATEGORY_SECURITY = 'security'
    CATEGORY_PERFORMANCE = 'performance'
    CATEGORY_NOTIFICATION = 'notification'
    CATEGORY_APPEARANCE = 'appearance'
    CATEGORY_FEATURE_FLAG = 'feature_flag'
    CATEGORY_INTEGRATION = 'integration'
    CATEGORY_GENERAL = 'general'

    CATEGORIES = [
        CATEGORY_SECURITY, CATEGORY_PERFORMANCE, CATEGORY_NOTIFICATION,
        CATEGORY_APPEARANCE, CATEGORY_FEATURE_FLAG, CATEGORY_INTEGRATION,
        CATEGORY_GENERAL
    ]

    # Cache timeout in seconds (5 minutes)
    CACHE_TIMEOUT = 300

    # Column definitions
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True)
    description = db.Column(db.String(255), nullable=True)
    category = db.Column(db.String(50), nullable=False, default=CATEGORY_SECURITY, index=True)
    security_level = db.Column(db.String(20), nullable=False, default=SECURITY_RESTRICTED)
    is_encrypted = db.Column(db.Boolean, default=False)
    validation_rules = db.Column(db.JSON, nullable=True)

    def __init__(self, key: str, value: str, description: Optional[str] = None,
                 category: str = CATEGORY_SECURITY, security_level: str = SECURITY_RESTRICTED,
                 is_encrypted: bool = False, validation_rules: Optional[Dict[str, Any]] = None):
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

        Raises:
            ValueError: If category or security_level is invalid
        """
        # Validate inputs
        if category not in self.CATEGORIES:
            raise ValueError(f"Invalid category: {category}. Must be one of: {', '.join(self.CATEGORIES)}")

        if security_level not in self.SECURITY_LEVELS:
            raise ValueError(f"Invalid security level: {security_level}. Must be one of: {', '.join(self.SECURITY_LEVELS)}")

        super().__init__()  # Call the base class __init__ method
        self.key = key
        self.value = self._encrypt_if_needed(value, is_encrypted)
        self.description = description
        self.category = category
        self.security_level = security_level
        self.is_encrypted = is_encrypted
        self.validation_rules = validation_rules or {}

    def _encrypt_if_needed(self, value: str, should_encrypt: bool) -> str:
        """
        Encrypt the value if needed.

        Args:
            value: The value to encrypt
            should_encrypt: Whether encryption should be applied

        Returns:
            str: Encrypted string if encrypted, original string otherwise
        """
        if should_encrypt and value:
            try:
                return encrypt_sensitive_data(value)
            except Exception as e:
                current_app.logger.error(f"Encryption failed for config key {self.key}: {str(e)}")
                # Return the original value if encryption fails
                # This prevents data loss but might expose sensitive data
                return value
        return value

    def _decrypt_if_needed(self) -> str:
        """
        Decrypt the value if it's encrypted.

        Returns:
            str: Decrypted string if encrypted, original string otherwise
        """
        if self.is_encrypted and self.value:
            try:
                return decrypt_sensitive_data(self.value)
            except Exception as e:
                current_app.logger.error(f"Decryption failed for config key {self.key}: {str(e)}")
                # Return a placeholder to avoid exposing potentially corrupt encrypted data
                return "[DECRYPTION_ERROR]"
        return self.value

    @property
    def decoded_value(self) -> Any:
        """
        Get the configuration value, decrypting if necessary and converting to appropriate type.

        Returns:
            Any: Type-converted value (bool, int, float, or str)
        """
        raw_value = self._decrypt_if_needed()

        # Try to convert to appropriate type
        if raw_value is None or raw_value == "[DECRYPTION_ERROR]":
            return raw_value

        # Handle boolean values
        if isinstance(raw_value, str) and raw_value.lower() in ('true', 'false'):
            return raw_value.lower() == 'true'

        # Handle numeric values
        try:
            if isinstance(raw_value, str):
                if '.' in raw_value:
                    return float(raw_value)
                return int(raw_value)
        except (ValueError, TypeError):
            pass

        return raw_value

    def validate_value(self, new_value: str) -> tuple[bool, str]:
        """
        Validate a new value against validation rules if they exist.

        Args:
            new_value: The new value to validate

        Returns:
            tuple: (is_valid, error_message)
        """
        if not self.validation_rules:
            return True, ""

        # Apply validation rules
        try:
            rules = self.validation_rules

            # Type validation
            if 'type' in rules:
                if rules['type'] == 'number':
                    try:
                        float(new_value)
                    except ValueError:
                        return False, "Value must be a number"

                elif rules['type'] == 'integer':
                    try:
                        int(new_value)
                    except ValueError:
                        return False, "Value must be an integer"

                elif rules['type'] == 'boolean':
                    if new_value.lower() not in ('true', 'false'):
                        return False, "Value must be 'true' or 'false'"

            # Range validation for numbers
            if ('min' in rules or 'max' in rules) and rules.get('type', '') in ('number', 'integer'):
                try:
                    num_value = float(new_value)
                    if 'min' in rules and num_value < float(rules['min']):
                        return False, f"Value cannot be less than {rules['min']}"
                    if 'max' in rules and num_value > float(rules['max']):
                        return False, f"Value cannot be greater than {rules['max']}"
                except ValueError:
                    pass  # Already checked in type validation

            # String length validation
            if 'minLength' in rules or 'maxLength' in rules:
                if 'minLength' in rules and len(new_value) < int(rules['minLength']):
                    return False, f"Value must be at least {rules['minLength']} characters"
                if 'maxLength' in rules and len(new_value) > int(rules['maxLength']):
                    return False, f"Value cannot exceed {rules['maxLength']} characters"

            # Pattern validation
            if 'pattern' in rules:
                import re
                pattern = rules['pattern']
                if not re.match(pattern, new_value):
                    return False, f"Value does not match required pattern: {pattern}"

            # Enum validation
            if 'enum' in rules and new_value not in rules['enum']:
                return False, f"Value must be one of: {', '.join(rules['enum'])}"

            return True, ""

        except Exception as e:
            current_app.logger.error(f"Validation error for {self.key}: {e}")
            return False, f"Validation error: {str(e)}"

    def update_value(self, new_value: str, user_id: Optional[int] = None) -> bool:
        """
        Update the configuration value with audit logging.

        Args:
            new_value: New configuration value
            user_id: ID of user making the change

        Returns:
            bool: True if update successful, False otherwise
        """
        # Validate the new value if rules exist
        is_valid, error_message = self.validate_value(new_value)
        if not is_valid:
            current_app.logger.error(f"Validation failed for {self.key}: {error_message}")
            return False

        # Store original value for audit log (without exposing encrypted values)
        original_value = self.value if not self.is_encrypted else "[REDACTED]"

        # Handle encryption if needed
        self.value = self._encrypt_if_needed(new_value, self.is_encrypted)
        self.updated_at = datetime.now(timezone.utc)

        try:
            db.session.commit()

            # Log the configuration change
            log_security_event(
                event_type=AuditLog.EVENT_CONFIG_CHANGE,
                description=f"Configuration '{self.key}' updated",
                user_id=user_id,
                details={
                    "category": self.category,
                    "previous_value": original_value,
                    "security_level": self.security_level
                }
            )

            # Clear cache for this config
            self.clear_cache()

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Database error updating config {self.key}: {e}")
            return False
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Unexpected error updating config {self.key}: {e}")
            return False

    def clear_cache(self) -> None:
        """
        Clear any cached instances of this configuration.

        Note:
            This should be called whenever a configuration is updated
            to ensure cached values are refreshed.
        """
        cache_key = f"system_config_{self.key}"
        if hasattr(cache, 'delete'):
            try:
                cache.delete(cache_key)
            except Exception as e:
                current_app.logger.warning(f"Failed to clear cache for {self.key}: {e}")

    @classmethod
    def get_value(cls, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by key with caching.

        Args:
            key: Configuration key
            default: Default value if key doesn't exist

        Returns:
            Any: The configuration value or default
        """
        cache_key = f"system_config_{key}"

        # Try to get from cache first
        try:
            cached_value = cache.get(cache_key)
            if cached_value is not None:
                return cached_value
        except Exception as e:
            current_app.logger.warning(f"Cache retrieval error for {key}: {e}")

        # Get from database
        try:
            config = cls.query.filter_by(key=key).first()
            if not config:
                return default

            value = config.decoded_value

            # Cache the result
            try:
                cache.set(cache_key, value, timeout=cls.CACHE_TIMEOUT)
            except Exception as e:
                current_app.logger.warning(f"Cache storage error for {key}: {e}")

            return value
        except Exception as e:
            current_app.logger.error(f"Error retrieving config {key}: {e}")
            return default

    @classmethod
    def set_value(cls, key: str, value: str, user_id: Optional[int] = None,
                  description: Optional[str] = None, category: Optional[str] = None,
                  is_encrypted: bool = False) -> bool:
        """
        Set a configuration value, creating the entry if it doesn't exist.

        Args:
            key: Configuration key
            value: New value
            user_id: ID of user making the change
            description: Optional description for new entries
            category: Optional category for new entries
            is_encrypted: Whether the value should be stored encrypted (for new entries only)

        Returns:
            bool: True if successful, False otherwise
        """
        if not key or not isinstance(key, str):
            current_app.logger.error(f"Invalid key: {key}")
            return False

        try:
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
                        category=category or cls.CATEGORY_GENERAL,
                        is_encrypted=is_encrypted
                    )
                    db.session.add(new_config)
                    db.session.commit()

                    # Log the configuration creation
                    log_security_event(
                        event_type=AuditLog.EVENT_CONFIG_CHANGE,
                        description=f"Configuration '{key}' created",
                        user_id=user_id,
                        details={
                            "category": new_config.category,
                            "is_encrypted": is_encrypted,
                            "security_level": new_config.security_level
                        }
                    )

                    return True
                except SQLAlchemyError as e:
                    db.session.rollback()
                    current_app.logger.error(f"Database error creating config {key}: {e}")
                    return False
                except ValueError as e:
                    db.session.rollback()
                    current_app.logger.error(f"Validation error creating config {key}: {e}")
                    return False
        except Exception as e:
            current_app.logger.error(f"Unexpected error in set_value for {key}: {e}")
            return False

    @classmethod
    def get_by_category(cls, category: str) -> List['SystemConfig']:
        """
        Get all configuration settings in a specific category.

        Args:
            category: Category to filter by

        Returns:
            List[SystemConfig]: List of configurations in the category
        """
        if category not in cls.CATEGORIES:
            current_app.logger.warning(f"Invalid category requested: {category}")
            return []

        return cls.query.filter_by(category=category).all()

    @classmethod
    def search(cls, query: str, categories: Optional[List[str]] = None,
               security_level: Optional[str] = None) -> List['SystemConfig']:
        """
        Search for configuration settings by key or description.

        Args:
            query: Search term
            categories: Optional list of categories to filter by
            security_level: Optional security level to filter by

        Returns:
            List[SystemConfig]: List of matching configurations
        """
        search_query = cls.query

        # Add text search criteria
        if query:
            search_term = f"%{query}%"
            search_query = search_query.filter(
                db.or_(
                    cls.key.ilike(search_term),
                    cls.description.ilike(search_term)
                )
            )

        # Filter by categories if specified
        if categories:
            valid_categories = [c for c in categories if c in cls.CATEGORIES]
            if valid_categories:
                search_query = search_query.filter(cls.category.in_(valid_categories))

        # Filter by security level if specified
        if security_level and security_level in cls.SECURITY_LEVELS:
            search_query = search_query.filter_by(security_level=security_level)

        return search_query.order_by(cls.category, cls.key).all()

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
                'category': cls.CATEGORY_SECURITY,
                'validation_rules': {'type': 'integer', 'min': 1, 'max': 10}
            },
            {
                'key': 'lockout_period_minutes',
                'value': '30',
                'description': 'Account lockout period in minutes',
                'category': cls.CATEGORY_SECURITY,
                'validation_rules': {'type': 'integer', 'min': 5, 'max': 1440}
            },
            {
                'key': 'session_timeout_minutes',
                'value': '30',
                'description': 'Session timeout in minutes',
                'category': cls.CATEGORY_SECURITY,
                'validation_rules': {'type': 'integer', 'min': 5, 'max': 1440}
            },
            {
                'key': 'password_min_length',
                'value': '12',
                'description': 'Minimum password length',
                'category': cls.CATEGORY_SECURITY,
                'validation_rules': {'type': 'integer', 'min': 8, 'max': 128}
            },
            {
                'key': 'require_mfa',
                'value': 'false',
                'description': 'Require multi-factor authentication for all users',
                'category': cls.CATEGORY_SECURITY,
                'validation_rules': {'type': 'boolean'}
            },
            {
                'key': 'password_expiry_days',
                'value': '90',
                'description': 'Days before password expires and must be changed',
                'category': cls.CATEGORY_SECURITY,
                'validation_rules': {'type': 'integer', 'min': 0, 'max': 365}
            },
            # Feature flags
            {
                'key': 'maintenance_mode',
                'value': 'false',
                'description': 'Enable maintenance mode',
                'category': cls.CATEGORY_FEATURE_FLAG,
                'validation_rules': {'type': 'boolean'}
            },
            {
                'key': 'enable_security_monitoring',
                'value': 'true',
                'description': 'Enable security monitoring features',
                'category': cls.CATEGORY_FEATURE_FLAG,
                'validation_rules': {'type': 'boolean'}
            },
            {
                'key': 'enable_notifications',
                'value': 'true',
                'description': 'Enable system notifications',
                'category': cls.CATEGORY_FEATURE_FLAG,
                'validation_rules': {'type': 'boolean'}
            },
            # Notification settings
            {
                'key': 'notification_email',
                'value': 'admin@example.com',
                'description': 'Email address for system notifications',
                'category': cls.CATEGORY_NOTIFICATION,
                'validation_rules': {
                    'type': 'string',
                    'pattern': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                }
            },
            {
                'key': 'alert_notification_level',
                'value': 'warning',
                'description': 'Minimum severity level for alert notifications',
                'category': cls.CATEGORY_NOTIFICATION,
                'validation_rules': {
                    'enum': ['info', 'warning', 'error', 'critical']
                }
            },
            # Performance settings
            {
                'key': 'cache_timeout',
                'value': '300',
                'description': 'Default cache timeout in seconds',
                'category': cls.CATEGORY_PERFORMANCE,
                'validation_rules': {'type': 'integer', 'min': 0, 'max': 86400}
            },
            {
                'key': 'query_timeout',
                'value': '30',
                'description': 'Database query timeout in seconds',
                'category': cls.CATEGORY_PERFORMANCE,
                'validation_rules': {'type': 'integer', 'min': 1, 'max': 300}
            },
            # Appearance settings
            {
                'key': 'theme',
                'value': 'default',
                'description': 'UI theme',
                'category': cls.CATEGORY_APPEARANCE,
                'validation_rules': {
                    'enum': ['default', 'dark', 'light', 'high-contrast']
                }
            }
        ]

        validation_errors = []
        created_count = 0

        for config in defaults:
            # Only create if doesn't exist
            existing = cls.query.filter_by(key=config['key']).first()
            if not existing:
                try:
                    new_config = cls(
                        key=config['key'],
                        value=config['value'],
                        description=config['description'],
                        category=config['category'],
                        validation_rules=config.get('validation_rules')
                    )
                    db.session.add(new_config)
                    created_count += 1
                except ValueError as e:
                    validation_errors.append(f"{config['key']}: {str(e)}")
                    continue

        if validation_errors:
            current_app.logger.warning(
                f"Some default configs had validation errors: {', '.join(validation_errors)}"
            )

        if created_count > 0:
            try:
                db.session.commit()
                current_app.logger.info(f"Initialized {created_count} default system configurations")
            except SQLAlchemyError as e:
                db.session.rollback()
                current_app.logger.error(f"Failed to initialize default configs: {e}")

    @classmethod
    def get_boolean(cls, key: str, default: bool = False) -> bool:
        """
        Get a boolean configuration value.

        Args:
            key: Configuration key
            default: Default value if key doesn't exist or isn't a boolean

        Returns:
            bool: The boolean value or default
        """
        value = cls.get_value(key, default)

        # Handle string conversion if needed
        if isinstance(value, str):
            return value.lower() == 'true'

        # Return boolean value if it is one, otherwise default
        return bool(value) if isinstance(value, bool) else default

    @classmethod
    def get_int(cls, key: str, default: int = 0) -> int:
        """
        Get an integer configuration value.

        Args:
            key: Configuration key
            default: Default value if key doesn't exist or isn't an integer

        Returns:
            int: The integer value or default
        """
        value = cls.get_value(key, default)

        try:
            if isinstance(value, str):
                return int(value)
            return int(value) if isinstance(value, (int, float)) else default
        except (ValueError, TypeError):
            return default

    @classmethod
    def get_float(cls, key: str, default: float = 0.0) -> float:
        """
        Get a float configuration value.

        Args:
            key: Configuration key
            default: Default value if key doesn't exist or isn't a float

        Returns:
            float: The float value or default
        """
        value = cls.get_value(key, default)

        try:
            if isinstance(value, str):
                return float(value)
            return float(value) if isinstance(value, (int, float)) else default
        except (ValueError, TypeError):
            return default

    @classmethod
    def clear_all_cache(cls) -> None:
        """
        Clear all SystemConfig cache entries.

        This is useful when making bulk changes or when cache keys
        might be unknown.
        """
        if not hasattr(cache, 'delete'):
            return

        try:
            # Get all config keys from the database
            keys = db.session.query(cls.key).all()

            # Clear each key from cache
            for (key,) in keys:
                cache_key = f"system_config_{key}"
                cache.delete(cache_key)

            current_app.logger.info(f"Cleared cache for {len(keys)} system configurations")
        except Exception as e:
            current_app.logger.error(f"Failed to clear all system config cache: {e}")

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for API responses.

        Returns:
            Dict[str, Any]: Dictionary representation with sensitive data redacted
        """
        return {
            'id': self.id,
            'key': self.key,
            'value': self.value if not self.is_encrypted else '[REDACTED]',
            'description': self.description,
            'category': self.category,
            'security_level': self.security_level,
            'is_encrypted': self.is_encrypted,
            'has_validation_rules': bool(self.validation_rules),
            'created_at': self.created_at.isoformat() if isinstance(self.created_at, datetime) else None,
            'updated_at': self.updated_at.isoformat() if isinstance(self.updated_at, datetime) else None
        }

    def __repr__(self) -> str:
        """String representation of the SystemConfig."""
        return f"<SystemConfig {self.key} ({self.category})>"
