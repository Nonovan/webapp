"""
Communication channel model for the Cloud Infrastructure Platform.

This module defines the CommunicationChannel model which represents available
communication methods (email, SMS, in-app, etc.) and their configurations.
It provides a centralized way to manage:
- Channel availability and configuration
- Delivery preferences and throttling rules
- Security controls and authentication settings
- Analytics and delivery metrics
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Union, Tuple, Set
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func
from flask import current_app

from extensions import db, metrics, cache
from models.base import BaseModel, AuditableMixin


class CommunicationChannel(BaseModel, AuditableMixin):
    """
    Model representing a communication channel for notifications and messages.

    This model stores configuration for various communication channels like
    email, SMS, in-app notifications, webhooks, and more. It provides methods
    for checking channel status, configuration, and delivery capabilities.

    Attributes:
        id: Primary key
        name: Unique name of the channel
        channel_type: Type of channel (email, sms, in_app, etc.)
        is_active: Whether the channel is currently active
        config: JSON data with channel configuration
        provider: Service provider for this channel
        rate_limit: Maximum messages per minute
        security_level: Security level required for this channel
        created_at: When the channel was created
        updated_at: When the channel was last updated
        last_tested: When the channel was last tested
        test_status: Status of the last connection test
    """

    __tablename__ = 'communication_channels'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['config', 'security_level', 'is_active']

    # Channel type constants
    TYPE_EMAIL = 'email'
    TYPE_SMS = 'sms'
    TYPE_IN_APP = 'in_app'
    TYPE_PUSH = 'push'
    TYPE_WEBHOOK = 'webhook'
    TYPE_CHAT = 'chat'
    TYPE_VOICE = 'voice'
    TYPE_WEBSOCKET = 'websocket'
    TYPE_API = 'api'

    VALID_TYPES = [
        TYPE_EMAIL, TYPE_SMS, TYPE_IN_APP, TYPE_PUSH, TYPE_WEBHOOK,
        TYPE_CHAT, TYPE_VOICE, TYPE_WEBSOCKET, TYPE_API
    ]

    # Provider constants
    PROVIDER_INTERNAL = 'internal'
    PROVIDER_SENDGRID = 'sendgrid'
    PROVIDER_MAILGUN = 'mailgun'
    PROVIDER_AWS_SES = 'aws_ses'
    PROVIDER_TWILIO = 'twilio'
    PROVIDER_NEXMO = 'nexmo'
    PROVIDER_FCM = 'firebase_cloud_messaging'
    PROVIDER_SLACK = 'slack'
    PROVIDER_TEAMS = 'teams'
    PROVIDER_CUSTOM = 'custom'

    # Test status constants
    TEST_STATUS_PASSED = 'passed'
    TEST_STATUS_FAILED = 'failed'
    TEST_STATUS_PENDING = 'pending'
    TEST_STATUS_UNKNOWN = 'unknown'

    # Security level constants
    SECURITY_LEVEL_LOW = 'low'           # Non-sensitive notifications
    SECURITY_LEVEL_MEDIUM = 'medium'     # General notifications
    SECURITY_LEVEL_HIGH = 'high'         # User-specific notifications
    SECURITY_LEVEL_CRITICAL = 'critical' # Security-critical notifications

    VALID_SECURITY_LEVELS = [
        SECURITY_LEVEL_LOW,
        SECURITY_LEVEL_MEDIUM,
        SECURITY_LEVEL_HIGH,
        SECURITY_LEVEL_CRITICAL
    ]

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    channel_type = db.Column(db.String(20), nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    provider = db.Column(db.String(50), nullable=False)

    # Configuration
    config = db.Column(db.JSON, nullable=True)
    rate_limit = db.Column(db.Integer, default=60)  # Messages per minute
    security_level = db.Column(db.String(20), default=SECURITY_LEVEL_MEDIUM, nullable=False)

    # Status tracking
    last_tested = db.Column(db.DateTime(timezone=True), nullable=True)
    test_status = db.Column(db.String(20), default=TEST_STATUS_UNKNOWN)

    # Analytics
    success_count = db.Column(db.Integer, default=0, nullable=False)
    failure_count = db.Column(db.Integer, default=0, nullable=False)
    last_success = db.Column(db.DateTime(timezone=True), nullable=True)
    last_failure = db.Column(db.DateTime(timezone=True), nullable=True)

    def __init__(self, name: str, channel_type: str, provider: str,
                 config: Optional[Dict[str, Any]] = None,
                 rate_limit: int = 60,
                 security_level: str = SECURITY_LEVEL_MEDIUM,
                 is_active: bool = True):
        """
        Initialize a new communication channel.

        Args:
            name: Unique channel name
            channel_type: Type of channel (email, sms, etc.)
            provider: Service provider for this channel
            config: Configuration data as JSON
            rate_limit: Maximum messages per minute
            security_level: Security level for this channel
            is_active: Whether this channel is active

        Raises:
            ValueError: If channel_type or security_level is invalid
        """
        if channel_type not in self.VALID_TYPES:
            raise ValueError(f"Invalid channel type: {channel_type}. "
                            f"Must be one of: {', '.join(self.VALID_TYPES)}")

        if security_level not in self.VALID_SECURITY_LEVELS:
            raise ValueError(f"Invalid security level: {security_level}. "
                            f"Must be one of: {', '.join(self.VALID_SECURITY_LEVELS)}")

        self.name = name
        self.channel_type = channel_type
        self.provider = provider
        self.config = config or {}
        self.rate_limit = rate_limit
        self.security_level = security_level
        self.is_active = is_active

    def update_config(self, config: Dict[str, Any], user_id: Optional[int] = None) -> bool:
        """
        Update channel configuration with new settings.

        Args:
            config: New configuration dictionary
            user_id: ID of user making the change

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Store old config for audit logging
            old_config = self.config.copy() if self.config else {}

            # Update config
            self.config = config
            self.updated_at = datetime.now(timezone.utc)
            db.session.add(self)
            db.session.commit()

            # Clear cache
            self._clear_cache()

            # Log critical changes
            if user_id and hasattr(self, 'log_change'):
                self.log_change(['config'], f"Configuration updated by user {user_id}")

            # Track metrics
            if hasattr(metrics, 'counter'):
                metrics.counter('channel_config_updated', 1, {'type': self.channel_type})

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Failed to update channel config: {str(e)}")
            return False

    def set_active(self, is_active: bool = True, user_id: Optional[int] = None) -> bool:
        """
        Enable or disable this communication channel.

        Args:
            is_active: Whether channel should be active
            user_id: ID of user making the change

        Returns:
            bool: True if successful, False otherwise
        """
        if self.is_active == is_active:
            return True  # No change needed

        try:
            old_status = self.is_active
            self.is_active = is_active
            self.updated_at = datetime.now(timezone.utc)
            db.session.add(self)
            db.session.commit()

            # Clear cache
            self._clear_cache()

            # Log the change
            if user_id and hasattr(self, 'log_change'):
                new_status = "active" if is_active else "inactive"
                self.log_change(['is_active'], f"Channel set to {new_status} by user {user_id}")

            # Track metrics
            if hasattr(metrics, 'counter'):
                action = 'enabled' if is_active else 'disabled'
                metrics.counter(f'channel_{action}', 1, {'type': self.channel_type})

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Failed to update channel status: {str(e)}")
            return False

    def test_connection(self) -> bool:
        """
        Test the channel connection to verify it's properly configured.

        Returns:
            bool: True if test passed, False otherwise
        """
        try:
            # Implementation would depend on channel type
            # This is a placeholder - a real implementation would:
            # 1. Connect to the actual service (e.g., send a test email)
            # 2. Handle errors appropriately
            # 3. Update test status and timestamp

            # Simulate a test based on channel type
            test_passed = True  # In real implementation, this would be the result

            # Update test status
            self.last_tested = datetime.now(timezone.utc)
            self.test_status = self.TEST_STATUS_PASSED if test_passed else self.TEST_STATUS_FAILED
            db.session.add(self)
            db.session.commit()

            # Track metrics
            if hasattr(metrics, 'counter'):
                outcome = 'success' if test_passed else 'failure'
                metrics.counter(f'channel_test_{outcome}', 1, {'type': self.channel_type})

            return test_passed
        except Exception as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Channel test failed for {self.name}: {str(e)}")

            # Update test status to failed
            try:
                self.last_tested = datetime.now(timezone.utc)
                self.test_status = self.TEST_STATUS_FAILED
                db.session.add(self)
                db.session.commit()
            except SQLAlchemyError:
                db.session.rollback()

            return False

    def record_delivery_success(self) -> bool:
        """
        Record a successful message delivery through this channel.

        Returns:
            bool: True if recorded successfully
        """
        try:
            self.success_count += 1
            self.last_success = datetime.now(timezone.utc)
            db.session.add(self)
            db.session.commit()
            return True
        except SQLAlchemyError:
            db.session.rollback()
            return False

    def record_delivery_failure(self) -> bool:
        """
        Record a failed message delivery through this channel.

        Returns:
            bool: True if recorded successfully
        """
        try:
            self.failure_count += 1
            self.last_failure = datetime.now(timezone.utc)
            db.session.add(self)
            db.session.commit()
            return True
        except SQLAlchemyError:
            db.session.rollback()
            return False

    def get_success_rate(self) -> float:
        """
        Calculate the success rate for this channel.

        Returns:
            float: Percentage of successful deliveries (0-100)
        """
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.0
        return (self.success_count / total) * 100

    def get_required_config_keys(self) -> Set[str]:
        """
        Get required configuration keys based on channel type and provider.

        Returns:
            Set[str]: Set of required config keys
        """
        # Define required config keys for each channel type and provider
        required_keys = {
            self.TYPE_EMAIL: {
                self.PROVIDER_SENDGRID: {'api_key', 'from_email', 'from_name'},
                self.PROVIDER_MAILGUN: {'api_key', 'domain', 'from_email'},
                self.PROVIDER_AWS_SES: {'access_key', 'secret_key', 'region', 'from_email'},
                self.PROVIDER_INTERNAL: {'smtp_host', 'smtp_port', 'username', 'password', 'from_email'}
            },
            self.TYPE_SMS: {
                self.PROVIDER_TWILIO: {'account_sid', 'auth_token', 'from_number'},
                self.PROVIDER_NEXMO: {'api_key', 'api_secret', 'from_number'}
            },
            self.TYPE_WEBHOOK: {'endpoint_url', 'secret_key'},
            self.TYPE_PUSH: {
                self.PROVIDER_FCM: {'server_key', 'sender_id'}
            }
        }

        # Get provider-specific keys, falling back to empty set
        provider_keys = required_keys.get(self.channel_type, {}).get(self.provider, set())

        # Get general keys for this channel type, falling back to empty set
        type_keys = required_keys.get(self.channel_type, {}).get('*', set())

        # Combine both sets
        return provider_keys.union(type_keys)

    def validate_config(self) -> Tuple[bool, List[str]]:
        """
        Validate current configuration against required keys.

        Returns:
            Tuple[bool, List[str]]: Success status and list of missing keys
        """
        if not self.config:
            required_keys = self.get_required_config_keys()
            return False, list(required_keys)

        required_keys = self.get_required_config_keys()
        missing_keys = [key for key in required_keys if key not in self.config]

        return len(missing_keys) == 0, missing_keys

    def _clear_cache(self) -> None:
        """Clear cached data for this channel."""
        if hasattr(cache, 'delete'):
            try:
                cache.delete(f"channel:{self.id}")
                cache.delete(f"channel_name:{self.name}")
                cache.delete("active_channels")
            except Exception as e:
                if current_app:
                    current_app.logger.warning(f"Failed to clear channel cache: {str(e)}")

    @classmethod
    def get_active_channels(cls, channel_type: Optional[str] = None) -> List['CommunicationChannel']:
        """
        Get all active communication channels, optionally filtered by type.

        Args:
            channel_type: Optional channel type filter

        Returns:
            List[CommunicationChannel]: List of active channels
        """
        query = cls.query.filter(cls.is_active.is_(True))

        if channel_type:
            query = query.filter(cls.channel_type == channel_type)

        return query.all()

    @classmethod
    def get_by_name(cls, name: str) -> Optional['CommunicationChannel']:
        """
        Get a channel by its unique name.

        Args:
            name: Channel name

        Returns:
            Optional[CommunicationChannel]: Channel if found, None otherwise
        """
        cache_key = f"channel_name:{name}"

        if hasattr(cache, 'get'):
            channel_id = cache.get(cache_key)
            if channel_id:
                return cls.query.get(channel_id)

        channel = cls.query.filter(cls.name == name).first()

        if channel and hasattr(cache, 'set'):
            cache.set(cache_key, channel.id, timeout=300)  # Cache for 5 minutes

        return channel

    @classmethod
    def get_delivery_stats(cls) -> Dict[str, Dict[str, Any]]:
        """
        Get delivery statistics for all channel types.

        Returns:
            Dict[str, Dict[str, Any]]: Statistics by channel type
        """
        stats = {}

        # Get aggregated stats by channel type
        results = db.session.query(
            cls.channel_type,
            func.sum(cls.success_count).label('successes'),
            func.sum(cls.failure_count).label('failures')
        ).group_by(cls.channel_type).all()

        # Process results
        for channel_type, successes, failures in results:
            total = successes + failures
            success_rate = (successes / total) * 100 if total > 0 else 0

            stats[channel_type] = {
                'successes': successes,
                'failures': failures,
                'total': total,
                'success_rate': success_rate
            }

        return stats

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert channel to dictionary for API responses.

        Returns:
            Dict[str, Any]: Dictionary representation of channel
        """
        is_valid, missing_keys = self.validate_config()

        result = {
            'id': self.id,
            'name': self.name,
            'channel_type': self.channel_type,
            'provider': self.provider,
            'is_active': self.is_active,
            'security_level': self.security_level,
            'rate_limit': self.rate_limit,
            'test_status': self.test_status,
            'success_count': self.success_count,
            'failure_count': self.failure_count,
            'success_rate': self.get_success_rate(),
            'config_valid': is_valid,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_tested': self.last_tested.isoformat() if self.last_tested else None,
            'last_success': self.last_success.isoformat() if self.last_success else None,
            'last_failure': self.last_failure.isoformat() if self.last_failure else None,
        }

        # Include safe config properties (without credentials)
        if self.config:
            safe_config = {}
            for key, value in self.config.items():
                # Skip sensitive keys
                if key in ('api_key', 'password', 'auth_token', 'secret_key', 'access_key', 'secret'):
                    safe_config[key] = '********'  # Mask sensitive values
                else:
                    safe_config[key] = value

            result['config'] = safe_config
        else:
            result['config'] = {}

        # Include config validation details if invalid
        if not is_valid:
            result['missing_config_keys'] = missing_keys

        return result

    def __repr__(self) -> str:
        """String representation of the channel."""
        status = "active" if self.is_active else "inactive"
        return f"<CommunicationChannel {self.name} ({self.channel_type}/{self.provider}) - {status}>"
