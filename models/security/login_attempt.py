"""
Login attempt tracking model for brute force protection.

This module provides functionality for tracking failed login attempts
and implementing progressive lockout policies to prevent brute force attacks.
It supports both username-based and IP-based rate limiting with configurable
thresholds and lockout durations.

Features:
- Records login attempts with timestamps
- Implements progressive lockout policies
- Provides rate limiting by username and IP address
- Supports customizable thresholds and timeouts
- Integrates with security monitoring and metrics
"""

import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Union, Any
from flask import current_app, request
from redis import Redis
from sqlalchemy.exc import SQLAlchemyError

from models.base import BaseModel
from models.security.audit_log import AuditLog
from extensions import db, metrics, cache


class LoginAttempt(BaseModel):
    """
    Model for tracking login attempts to prevent brute force attacks.

    This model stores information about login attempts, including the username,
    IP address, success status, and timestamp. It's used to implement
    rate limiting and account lockout mechanisms.

    Attributes:
        id: Primary key ID for the login attempt
        username: Username that was used in the login attempt
        email: Email that was used in the login attempt (if applicable)
        ip_address: Source IP address of the login attempt
        user_agent: User agent string from the request
        success: Whether the login attempt was successful
        timestamp: When the login attempt occurred
        geo_location: Geographic location inferred from IP (when available)
    """

    __tablename__ = 'login_attempts'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=True, index=True)
    email = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True, index=True)
    user_agent = db.Column(db.String(255), nullable=True)
    success = db.Column(db.Boolean, nullable=False, default=False, index=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                          nullable=False, index=True)
    geo_location = db.Column(db.String(255), nullable=True)

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

    def __init__(self, username: Optional[str] = None, email: Optional[str] = None,
                 ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                 success: bool = False, geo_location: Optional[str] = None) -> None:
        """
        Initialize a new login attempt record.

        Args:
            username: Username used in the login attempt
            email: Email used in the login attempt
            ip_address: Source IP address
            user_agent: User agent string
            success: Whether the login attempt was successful
            geo_location: Geographic location inferred from IP
        """
        super().__init__()
        self.username = username
        self.email = email
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.success = success
        self.geo_location = geo_location

    @classmethod
    def record_attempt(cls, username: str, ip_address: Optional[str] = None,
                       success: bool = False, user_agent: Optional[str] = None,
                       email: Optional[str] = None) -> bool:
        """
        Record a login attempt in both database and Redis (for rate limiting).

        Args:
            username: Username used in login attempt
            ip_address: Source IP address
            success: Whether the attempt was successful
            user_agent: User agent string from request
            email: Email used in login attempt (if different from username)

        Returns:
            bool: True if recorded successfully, False otherwise
        """
        try:
            # Normalize inputs
            username = username.lower() if username else None
            email = email.lower() if email else None
            if not user_agent and request:
                user_agent = request.user_agent.string if hasattr(request, 'user_agent') else None

            # Create and store database record
            attempt = cls(
                username=username,
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=success
            )

            # Try to add geo-location if available
            if hasattr(current_app, 'geo_locator') and ip_address:
                try:
                    location = current_app.geo_locator.get_location(ip_address)
                    if location:
                        attempt.geo_location = location
                except Exception as e:
                    if current_app:
                        current_app.logger.debug(f"Geolocation failed: {str(e)}")

            db.session.add(attempt)
            db.session.commit()

            # Track metrics
            if hasattr(metrics, 'info'):
                metrics.info('security_login_attempts_total', 1, labels={
                    "success": str(success).lower(),
                    "has_username": "true" if username else "false",
                    "has_ip": "true" if ip_address else "false"
                })

            # If failed attempt, update Redis for rate limiting
            if not success:
                cls._increment_attempt_counter(username, ip_address)

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Failed to record login attempt: {str(e)}")
            return False
        except Exception as e:
            if current_app:
                current_app.logger.error(f"Unexpected error recording login attempt: {str(e)}")
            return False

    @classmethod
    def is_username_locked(cls, username: str) -> bool:
        """
        Check if a username is currently locked out due to too many failed attempts.

        Args:
            username: Username to check

        Returns:
            bool: True if the username is locked out, False otherwise
        """
        if not username:
            return False

        redis_client = cls._get_redis_client()
        if not redis_client:
            return False

        lockout_key = f"{cls.USERNAME_LOCKOUT_PREFIX}{username.lower()}"
        return bool(redis_client.exists(lockout_key))

    @classmethod
    def is_ip_rate_limited(cls, ip_address: Optional[str]) -> bool:
        """
        Check if an IP address is rate limited due to too many failed attempts.

        Args:
            ip_address: IP address to check

        Returns:
            bool: True if the IP is rate limited, False otherwise
        """
        if not ip_address:
            return False

        redis_client = cls._get_redis_client()
        if not redis_client:
            return False

        lockout_key = f"{cls.IP_LOCKOUT_PREFIX}{ip_address}"
        return bool(redis_client.exists(lockout_key))

    @classmethod
    def get_remaining_attempts(cls, username: str) -> int:
        """
        Get the number of login attempts remaining before lockout.

        Args:
            username: Username to check

        Returns:
            int: Number of attempts remaining before lockout
        """
        if not username:
            return cls.DEFAULT_USERNAME_MAX_ATTEMPTS

        redis_client = cls._get_redis_client()
        if not redis_client:
            return cls.DEFAULT_USERNAME_MAX_ATTEMPTS

        attempt_key = f"{cls.USERNAME_ATTEMPT_PREFIX}{username.lower()}"
        attempts = redis_client.get(attempt_key)

        if not attempts:
            return cls.DEFAULT_USERNAME_MAX_ATTEMPTS

        max_attempts = current_app.config.get('MAX_LOGIN_ATTEMPTS', cls.DEFAULT_USERNAME_MAX_ATTEMPTS)
        return max(0, max_attempts - int(attempts))

    @classmethod
    def get_lockout_expiration(cls, username: str) -> Optional[datetime]:
        """
        Get the expiration time for a username lockout.

        Args:
            username: Username to check

        Returns:
            Optional[datetime]: Expiration time of lockout or None if not locked
        """
        if not username or not cls.is_username_locked(username):
            return None

        redis_client = cls._get_redis_client()
        if not redis_client:
            return None

        lockout_key = f"{cls.USERNAME_LOCKOUT_PREFIX}{username.lower()}"
        ttl = redis_client.ttl(lockout_key)

        if ttl <= 0:
            return None

        return datetime.now(timezone.utc) + timedelta(seconds=ttl)

    @classmethod
    def reset_attempts(cls, username: str, ip_address: Optional[str] = None) -> None:
        """
        Reset failed login attempt counters for a username and/or IP.

        This is typically called after a successful login.

        Args:
            username: Username to reset
            ip_address: IP address to reset (optional)
        """
        redis_client = cls._get_redis_client()
        if not redis_client:
            return

        # Reset username attempt counter and lockout
        if username:
            username = username.lower()
            attempt_key = f"{cls.USERNAME_ATTEMPT_PREFIX}{username}"
            lockout_key = f"{cls.USERNAME_LOCKOUT_PREFIX}{username}"
            redis_client.delete(attempt_key, lockout_key)

        # Reset IP attempt counter and lockout
        if ip_address:
            attempt_key = f"{cls.IP_ATTEMPT_PREFIX}{ip_address}"
            lockout_key = f"{cls.IP_LOCKOUT_PREFIX}{ip_address}"
            redis_client.delete(attempt_key, lockout_key)

    @classmethod
    def unlock_account(cls, username: str) -> bool:
        """
        Administratively unlock a locked account.

        Args:
            username: Username to unlock

        Returns:
            bool: True if unlocked, False otherwise
        """
        if not username:
            return False

        redis_client = cls._get_redis_client()
        if not redis_client:
            return False

        username = username.lower()
        attempt_key = f"{cls.USERNAME_ATTEMPT_PREFIX}{username}"
        lockout_key = f"{cls.USERNAME_LOCKOUT_PREFIX}{username}"

        # Delete both attempt counter and lockout flag
        redis_client.delete(attempt_key, lockout_key)

        # Log security event
        from core.security import log_security_event
        log_security_event(
            event_type=AuditLog.EVENT_ACCOUNT_UNLOCKED,
            description=f"Account {username} manually unlocked",
            severity="info",
            details={"username": username, "administrative_action": True}
        )

        return True

    @classmethod
    def get_suspicious_ips(cls, hours: int = 24, min_attempts: int = 5) -> List[Dict[str, Any]]:
        """
        Get a list of suspicious IPs based on failed login patterns.

        Args:
            hours: How many hours back to analyze
            min_attempts: Minimum number of failed attempts to be considered suspicious

        Returns:
            List[Dict[str, Any]]: List of suspicious IP info with counts and usernames
        """
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

            # Query for IPs with multiple failed logins
            ip_results = db.session.query(
                cls.ip_address,
                db.func.count(cls.id).label('attempt_count')
            ).filter(
                cls.timestamp >= cutoff,
                cls.success == False,
                cls.ip_address != None
            ).group_by(
                cls.ip_address
            ).having(
                db.func.count(cls.id) >= min_attempts
            ).all()

            suspicious_ips = []

            for ip, count in ip_results:
                # Get unique usernames targeted by this IP
                username_query = db.session.query(cls.username).filter(
                    cls.ip_address == ip,
                    cls.success == False,
                    cls.timestamp >= cutoff,
                    cls.username != None
                ).distinct().all()

                unique_usernames = [u[0] for u in username_query]

                # Get success count if any
                success_count = db.session.query(db.func.count(cls.id)).filter(
                    cls.ip_address == ip,
                    cls.success == True,
                    cls.timestamp >= cutoff
                ).scalar()

                geo_location = None
                latest_attempt = db.session.query(cls).filter(
                    cls.ip_address == ip,
                    cls.timestamp >= cutoff
                ).order_by(cls.timestamp.desc()).first()

                if latest_attempt and latest_attempt.geo_location:
                    geo_location = latest_attempt.geo_location

                suspicious_ips.append({
                    'ip_address': ip,
                    'failed_count': count,
                    'success_count': success_count or 0,
                    'unique_usernames': unique_usernames,
                    'unique_username_count': len(unique_usernames),
                    'geo_location': geo_location,
                    'is_locked': cls.is_ip_rate_limited(ip)
                })

            return sorted(suspicious_ips, key=lambda x: x['failed_count'], reverse=True)

        except SQLAlchemyError as e:
            if current_app:
                current_app.logger.error(f"Database error getting suspicious IPs: {str(e)}")
            return []
        except Exception as e:
            if current_app:
                current_app.logger.error(f"Unexpected error getting suspicious IPs: {str(e)}")
            return []

    @classmethod
    def get_recent_attempts(cls, username: Optional[str] = None,
                           ip_address: Optional[str] = None,
                           hours: int = 24, limit: int = 100) -> List['LoginAttempt']:
        """
        Get recent login attempts for a username or IP address.

        Args:
            username: Filter by username (optional)
            ip_address: Filter by IP address (optional)
            hours: How many hours back to retrieve
            limit: Maximum number of results to return

        Returns:
            List[LoginAttempt]: List of recent login attempts
        """
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            query = cls.query.filter(cls.timestamp >= cutoff)

            if username:
                query = query.filter(cls.username == username.lower())

            if ip_address:
                query = query.filter(cls.ip_address == ip_address)

            return query.order_by(cls.timestamp.desc()).limit(limit).all()

        except SQLAlchemyError as e:
            if current_app:
                current_app.logger.error(f"Database error getting recent attempts: {str(e)}")
            return []

    @classmethod
    def prune_old_records(cls, days: int = 90) -> int:
        """
        Remove old login attempt records from the database.

        Args:
            days: Age in days of records to remove

        Returns:
            int: Number of records deleted
        """
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            result = cls.query.filter(cls.timestamp < cutoff).delete(synchronize_session=False)
            db.session.commit()
            return result
        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Error pruning login attempts: {str(e)}")
            return 0

    # Private methods

    @classmethod
    def _increment_attempt_counter(cls, username: Optional[str], ip_address: Optional[str]) -> None:
        """
        Increment failed login attempt counters and apply lockouts if needed.

        Args:
            username: Username to increment counter for
            ip_address: IP address to increment counter for
        """
        redis_client = cls._get_redis_client()
        if not redis_client:
            return

        # Update username-based counters and lockouts
        if username:
            username = username.lower()
            attempt_key = f"{cls.USERNAME_ATTEMPT_PREFIX}{username}"
            lockout_key = f"{cls.USERNAME_LOCKOUT_PREFIX}{username}"

            # If not already locked out
            if not redis_client.exists(lockout_key):
                # Increment and get the updated count
                attempts = redis_client.incr(attempt_key)

                # Set expiration if first attempt
                if int(attempts) == 1:
                    redis_client.expire(attempt_key, 24 * 60 * 60)  # 24 hours

                # Apply progressive lockout based on attempt count
                username_max_attempts = current_app.config.get(
                    'MAX_LOGIN_ATTEMPTS',
                    cls.DEFAULT_USERNAME_MAX_ATTEMPTS
                )

                if int(attempts) >= username_max_attempts:
                    # Determine lockout duration based on number of previous lockouts
                    previous_lockouts = redis_client.get(f"login:previous_lockouts:{username}") or 0
                    previous_lockouts = int(previous_lockouts)

                    # Progressive lockout: 15min, 30min, 1h, 2h, 4h, 8h, 24h (max)
                    lockout_minutes = min(
                        cls.DEFAULT_LOCKOUT_MINUTES * (2 ** previous_lockouts),
                        24 * 60  # Max 24 hours
                    )

                    # Apply lockout
                    redis_client.setex(
                        lockout_key,
                        int(lockout_minutes * 60),
                        1
                    )

                    # Reset attempt counter
                    redis_client.delete(attempt_key)

                    # Increment previous lockout counter with 30 day expiry
                    redis_client.incr(f"login:previous_lockouts:{username}")
                    redis_client.expire(f"login:previous_lockouts:{username}", 30 * 24 * 60 * 60)

                    # Log security event
                    from core.security import log_security_event
                    log_security_event(
                        event_type=AuditLog.EVENT_ACCOUNT_LOCKOUT,
                        description=f"Account {username} locked due to failed login attempts",
                        severity="warning",
                        details={
                            "username": username,
                            "attempts": attempts,
                            "lockout_minutes": lockout_minutes,
                            "previous_lockouts": previous_lockouts
                        }
                    )

                    # Track metrics
                    if hasattr(metrics, 'info'):
                        metrics.info('security_account_lockouts_total', 1, labels={
                            "username": username,
                            "duration_minutes": str(lockout_minutes)
                        })

        # Update IP-based counters and lockouts
        if ip_address:
            attempt_key = f"{cls.IP_ATTEMPT_PREFIX}{ip_address}"
            lockout_key = f"{cls.IP_LOCKOUT_PREFIX}{ip_address}"

            # If not already locked out
            if not redis_client.exists(lockout_key):
                # Increment and get the updated count
                attempts = redis_client.incr(attempt_key)

                # Set expiration if first attempt
                if int(attempts) == 1:
                    redis_client.expire(attempt_key, 24 * 60 * 60)  # 24 hours

                # Apply IP lockout if threshold exceeded
                ip_max_attempts = current_app.config.get(
                    'IP_MAX_LOGIN_ATTEMPTS',
                    cls.DEFAULT_IP_MAX_ATTEMPTS
                )

                if int(attempts) >= ip_max_attempts:
                    # Apply IP lockout
                    ip_lockout_minutes = current_app.config.get(
                        'IP_LOCKOUT_MINUTES',
                        cls.DEFAULT_IP_LOCKOUT_MINUTES
                    )

                    redis_client.setex(
                        lockout_key,
                        int(ip_lockout_minutes * 60),
                        1
                    )

                    # Reset attempt counter
                    redis_client.delete(attempt_key)

                    # Log security event
                    from core.security import log_security_event
                    log_security_event(
                        event_type=AuditLog.EVENT_RATE_LIMIT,
                        description=f"IP {ip_address} rate limited due to failed login attempts",
                        severity="warning",
                        ip_address=ip_address,
                        details={
                            "attempts": attempts,
                            "lockout_minutes": ip_lockout_minutes
                        }
                    )

                    # Track metrics
                    if hasattr(metrics, 'info'):
                        metrics.info('security_ip_lockouts_total', 1, labels={
                            "ip_address": ip_address,
                            "duration_minutes": str(ip_lockout_minutes)
                        })

    @staticmethod
    def _get_redis_client() -> Optional[Redis]:
        """
        Get the Redis client from Flask app extensions.

        Returns:
            Optional[Redis]: Redis client or None if not available
        """
        # Try to get Redis from extensions
        if hasattr(current_app, 'extensions') and 'redis' in current_app.extensions:
            return current_app.extensions['redis']

        # Fallback to cache if it's a Redis cache
        if cache and hasattr(cache, 'cache') and hasattr(cache.cache, '_client'):
            return cache.cache._client

        # Log warning but don't fail
        if current_app:
            current_app.logger.warning(
                "Redis client not available for login attempt tracking. "
                "Brute-force protection functionality will be limited."
            )

        return None
