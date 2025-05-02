"""
Login attempt tracking model for the Cloud Infrastructure Platform.

This module tracks login attempts, supports IP and account-based rate limiting,
and implements sophisticated brute force detection with progressive lockout
strategies.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple, Union, List
from flask import current_app
import json
import ipaddress
from user_agents import parse
from geoip2.errors import AddressNotFoundError
from sqlalchemy.exc import SQLAlchemyError

from extensions import db, redis_client, geoip
from core.security.cs_audit import log_security_event
from models.base import BaseModel

class LoginAttempt(BaseModel):
    """Model for tracking login attempts and implementing brute force protection."""

    __tablename__ = 'login_attempts'

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=True, index=True)  # May be null for loginless auth methods
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    ip_address = db.Column(db.String(45), nullable=True, index=True)  # IPv6 compatible
    user_agent = db.Column(db.String(255), nullable=True)
    success = db.Column(db.Boolean, nullable=False, default=False, index=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                          nullable=False, index=True)

    # Additional security metadata
    geo_location = db.Column(db.String(255), nullable=True)
    device_info = db.Column(db.JSON, nullable=True)  # Store device fingerprint, os, browser, etc.
    auth_method = db.Column(db.String(20), nullable=True)  # 'password', 'sso', 'api_key', etc.
    failure_reason = db.Column(db.String(64), nullable=True)  # Why the login failed
    request_id = db.Column(db.String(64), nullable=True)  # Link to request logs
    risk_score = db.Column(db.Float, nullable=True)  # Calculated risk score

    # Redis key prefixes for rate limiting
    USERNAME_ATTEMPT_PREFIX = "login:attempts:username:"
    USERNAME_LOCKOUT_PREFIX = "login:lockout:username:"
    IP_ATTEMPT_PREFIX = "login:attempts:ip:"
    IP_LOCKOUT_PREFIX = "login:lockout:ip:"

    # Default configuration values (can be overridden in application config)
    DEFAULT_USERNAME_MAX_ATTEMPTS = 5
    DEFAULT_IP_MAX_ATTEMPTS = 10
    DEFAULT_LOCKOUT_MINUTES = 15
    DEFAULT_IP_LOCKOUT_MINUTES = 30
    DEFAULT_ATTEMPT_WINDOW_HOURS = 24

    # Progressive lockout timeouts (in minutes) for repeated failures
    PROGRESSIVE_LOCKOUT_MINUTES = [5, 15, 30, 60, 240, 1440]  # 5min, 15min, 30min, 1hr, 4hr, 24hr

    def __init__(self, username: Optional[str] = None, ip_address: Optional[str] = None,
                 user_agent: Optional[str] = None, user_id: Optional[int] = None,
                 success: bool = False, **kwargs):
        """Initialize a new login attempt record."""
        self.username = username
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.user_id = user_id
        self.success = success

        # Process user agent to extract device info
        if user_agent:
            try:
                ua_object = parse(user_agent)
                self.device_info = {
                    'browser': ua_object.browser.family,
                    'browser_version': ua_object.browser.version_string,
                    'os': ua_object.os.family,
                    'os_version': ua_object.os.version_string,
                    'device': ua_object.device.family,
                    'is_mobile': ua_object.is_mobile,
                    'is_tablet': ua_object.is_tablet,
                    'is_bot': ua_object.is_bot
                }
            except:
                # Handle parsing errors gracefully
                self.device_info = {'raw': user_agent[:255] if user_agent else None}

        # Try to determine geo_location from IP
        if ip_address and hasattr(current_app, 'geoip_reader'):
            try:
                location = current_app.geoip_reader.city(ip_address)
                if location:
                    self.geo_location = f"{location.city.name}, {location.country.iso_code}" if location.city.name else location.country.name
            except (AddressNotFoundError, Exception):
                # Handle private IPs, etc.
                pass

        # Set additional attributes from kwargs
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    @classmethod
    def log_attempt(cls, username: Optional[str] = None, ip_address: Optional[str] = None,
                   user_agent: Optional[str] = None, user_id: Optional[int] = None,
                   success: bool = False, failure_reason: Optional[str] = None,
                   **kwargs) -> 'LoginAttempt':
        """Log a login attempt and update rate limiting counters."""
        attempt = cls(
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            user_id=user_id,
            success=success,
            failure_reason=failure_reason,
            **kwargs
        )

        # Save the attempt
        db.session.add(attempt)
        db.session.commit()

        # If this was a failure, update rate limiting counters
        if not success and redis_client:
            now = datetime.now(timezone.utc)
            expiry = int(timedelta(hours=cls.DEFAULT_ATTEMPT_WINDOW_HOURS).total_seconds())

            # Update username-based counter
            if username:
                username_key = f"{cls.USERNAME_ATTEMPT_PREFIX}{username.lower()}"
                redis_client.incr(username_key)
                redis_client.expire(username_key, expiry)

            # Update IP-based counter
            if ip_address:
                ip_key = f"{cls.IP_ATTEMPT_PREFIX}{ip_address}"
                redis_client.incr(ip_key)
                redis_client.expire(ip_key, expiry)

            # Log security event for repeated failures
            if username:
                attempts = redis_client.get(username_key)
                if attempts:
                    attempts = int(attempts)
                    if attempts >= cls.DEFAULT_USERNAME_MAX_ATTEMPTS:
                        # Log enhanced security event for potential brute force
                        log_security_event(
                            'repeated_login_failures',
                            f"Multiple login failures for username: {username}",
                            username=username,
                            attempts=attempts,
                            ip_address=ip_address,
                            severity="warning"
                        )

                        # Apply progressive lockout if configured
                        lockout_index = min(attempts // cls.DEFAULT_USERNAME_MAX_ATTEMPTS - 1,
                                           len(cls.PROGRESSIVE_LOCKOUT_MINUTES) - 1)
                        if lockout_index >= 0:
                            lockout_mins = cls.PROGRESSIVE_LOCKOUT_MINUTES[lockout_index]
                            username_lockout_key = f"{cls.USERNAME_LOCKOUT_PREFIX}{username.lower()}"
                            redis_client.set(
                                username_lockout_key,
                                int(now.timestamp()),
                                ex=int(timedelta(minutes=lockout_mins).total_seconds())
                            )

        return attempt

    @classmethod
    def is_account_locked(cls, username: str) -> Tuple[bool, Optional[datetime]]:
        """Check if an account is locked due to too many failed attempts."""
        if not redis_client:
            return False, None

        username_lockout_key = f"{cls.USERNAME_LOCKOUT_PREFIX}{username.lower()}"
        lockout_time = redis_client.get(username_lockout_key)

        if lockout_time:
            # Get the TTL to determine unlock time
            ttl = redis_client.ttl(username_lockout_key)
            if ttl > 0:
                unlock_time = datetime.now(timezone.utc) + timedelta(seconds=ttl)
                return True, unlock_time

        return False, None

    @classmethod
    def is_ip_blocked(cls, ip_address: str) -> Tuple[bool, Optional[datetime]]:
        """Check if an IP is blocked due to too many failed attempts."""
        if not redis_client:
            return False, None

        ip_lockout_key = f"{cls.IP_LOCKOUT_PREFIX}{ip_address}"
        lockout_time = redis_client.get(ip_lockout_key)

        if lockout_time:
            # Get the TTL to determine unlock time
            ttl = redis_client.ttl(ip_lockout_key)
            if ttl > 0:
                unlock_time = datetime.now(timezone.utc) + timedelta(seconds=ttl)
                return True, unlock_time

        return False, None

    @classmethod
    def get_attempt_stats(cls, username: Optional[str] = None,
                         ip_address: Optional[str] = None,
                         hours: int = 24) -> Dict[str, Any]:
        """
        Get statistics about login attempts for a username or IP address.

        Args:
            username: Filter by username (optional)
            ip_address: Filter by IP address (optional)
            hours: How many hours back to analyze

        Returns:
            Dict: Statistics about login attempts
        """
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            result = {
                'total_attempts': 0,
                'failed_attempts': 0,
                'successful_attempts': 0,
                'unique_ip_addresses': set(),
                'unique_usernames': set(),
                'last_attempt_time': None,
                'last_successful_attempt': None,
                'last_failed_attempt': None
            }

            # Build query based on filters
            query = cls.query.filter(cls.timestamp >= cutoff)

            if username:
                query = query.filter(cls.username == username.lower())

            if ip_address:
                query = query.filter(cls.ip_address == ip_address)

            # Execute query and build stats
            attempts = query.order_by(cls.timestamp.desc()).all()

            for attempt in attempts:
                result['total_attempts'] += 1

                if attempt.success:
                    result['successful_attempts'] += 1
                    if not result['last_successful_attempt']:
                        result['last_successful_attempt'] = attempt.timestamp
                else:
                    result['failed_attempts'] += 1
                    if not result['last_failed_attempt']:
                        result['last_failed_attempt'] = attempt.timestamp

                if attempt.ip_address:
                    result['unique_ip_addresses'].add(attempt.ip_address)

                if attempt.username:
                    result['unique_usernames'].add(attempt.username)

                if not result['last_attempt_time']:
                    result['last_attempt_time'] = attempt.timestamp

            # Convert sets to counts for serialization
            result['unique_ip_count'] = len(result['unique_ip_addresses'])
            result['unique_username_count'] = len(result['unique_usernames'])
            result['unique_ip_addresses'] = list(result['unique_ip_addresses'])
            result['unique_usernames'] = list(result['unique_usernames'])

            # Add rate limiting information
            if username:
                result['is_account_locked'], unlock_time = cls.is_account_locked(username)
                if unlock_time:
                    result['account_unlock_time'] = unlock_time.isoformat()
                result['remaining_attempts'] = cls.DEFAULT_USERNAME_MAX_ATTEMPTS - result['failed_attempts']
                result['remaining_attempts'] = max(0, result['remaining_attempts'])

            if ip_address:
                result['is_ip_blocked'], unlock_time = cls.is_ip_blocked(ip_address)
                if unlock_time:
                    result['ip_unlock_time'] = unlock_time.isoformat()

            return result

        except SQLAlchemyError as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Database error getting attempt stats: {str(e)}")
            return {
                'error': 'Database error fetching login statistics',
                'total_attempts': 0,
                'failed_attempts': 0,
                'successful_attempts': 0
            }

    @classmethod
    def clear_old_attempts(cls, days: int = 90) -> int:
        """
        Delete old login attempts from the database.

        Args:
            days: Remove records older than this many days

        Returns:
            int: Number of records deleted
        """
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            count = cls.query.filter(cls.timestamp < cutoff).delete(synchronize_session=False)
            db.session.commit()

            return count
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error clearing old login attempts: {str(e)}")
            return 0
