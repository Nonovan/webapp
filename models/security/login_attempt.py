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
- Detects suspicious login patterns and anomalies
- Tracks device fingerprints for enhanced fraud detection
"""

import time
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Union, Any, Set
from flask import current_app, request, g, has_request_context
from redis import Redis
from sqlalchemy.exc import SQLAlchemyError
from user_agents import parse

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
        device_fingerprint: Device fingerprinting information for fraud detection
        risk_score: Calculated risk score for this login attempt
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
    device_fingerprint = db.Column(db.JSON, nullable=True)  # Store device identification data
    risk_score = db.Column(db.Float, nullable=True)  # Risk score from 0 (low) to 100 (high)
    login_method = db.Column(db.String(20), nullable=True)  # 'password', 'sso', 'mfa', etc.
    failure_reason = db.Column(db.String(64), nullable=True)  # Reason for failure if failed
    user_id = db.Column(db.Integer, nullable=True, index=True)  # User ID if resolved
    request_id = db.Column(db.String(36), nullable=True)  # Request ID for correlation with logs

    # Redis key prefixes for rate limiting
    USERNAME_ATTEMPT_PREFIX = "login:attempts:username:"
    USERNAME_LOCKOUT_PREFIX = "login:lockout:username:"
    IP_ATTEMPT_PREFIX = "login:attempts:ip:"
    IP_LOCKOUT_PREFIX = "login:lockout:ip:"
    DEVICE_ATTEMPT_PREFIX = "login:attempts:device:"

    # Suspicious activity keys
    SUSPICIOUS_IP_PREFIX = "suspicious:ip:"
    SUSPICIOUS_DEVICE_PREFIX = "suspicious:device:"
    SUSPICIOUS_USERNAME_PREFIX = "suspicious:username:"

    # Default configuration values (can be overridden in application config)
    DEFAULT_USERNAME_MAX_ATTEMPTS = 5
    DEFAULT_IP_MAX_ATTEMPTS = 10
    DEFAULT_LOCKOUT_MINUTES = 15
    DEFAULT_IP_LOCKOUT_MINUTES = 30
    DEFAULT_ATTEMPT_WINDOW_HOURS = 24

    # Progressive lockout timeouts in minutes
    PROGRESSIVE_LOCKOUTS = [15, 30, 60, 120, 240, 480, 1440]  # 15min to 24h

    def __init__(self, username: Optional[str] = None, email: Optional[str] = None,
                 ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                 success: bool = False, geo_location: Optional[str] = None,
                 user_id: Optional[int] = None, login_method: Optional[str] = None,
                 failure_reason: Optional[str] = None) -> None:
        """
        Initialize a new login attempt record.

        Args:
            username: Username used in the login attempt
            email: Email used in the login attempt
            ip_address: Source IP address
            user_agent: User agent string
            success: Whether the login attempt was successful
            geo_location: Geographic location inferred from IP
            user_id: ID of the user (if identified)
            login_method: Authentication method used
            failure_reason: Reason for failure if unsuccessful
        """
        super().__init__()
        self.username = username
        self.email = email
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.success = success
        self.geo_location = geo_location
        self.user_id = user_id
        self.login_method = login_method
        self.failure_reason = failure_reason

        # Generate request ID for correlation with logs
        if has_request_context() and hasattr(g, 'request_id'):
            self.request_id = g.request_id

        # Extract device fingerprint from user agent
        if user_agent:
            self._extract_device_fingerprint(user_agent)

        # Calculate initial risk score
        self.risk_score = self._calculate_risk_score()

    def _extract_device_fingerprint(self, user_agent_str: str) -> None:
        """
        Extract device fingerprinting information from user agent.

        Args:
            user_agent_str: The user agent string to parse
        """
        try:
            ua_object = parse(user_agent_str)
            self.device_fingerprint = {
                'browser': ua_object.browser.family,
                'browser_version': ua_object.browser.version_string,
                'os': ua_object.os.family,
                'os_version': ua_object.os.version_string,
                'device': ua_object.device.family,
                'is_mobile': ua_object.is_mobile,
                'is_tablet': ua_object.is_tablet,
                'is_pc': not (ua_object.is_mobile or ua_object.is_tablet),
                'is_bot': ua_object.is_bot,
                'raw': user_agent_str[:255]  # Truncate for storage
            }
        except Exception as e:
            if current_app:
                current_app.logger.debug(f"Error parsing user agent: {str(e)}")
            self.device_fingerprint = {'raw': user_agent_str[:255]}

    def _calculate_risk_score(self) -> float:
        """
        Calculate risk score based on login factors.

        Returns:
            float: Risk score from 0 (low) to 100 (high)
        """
        score = 0.0

        # Base score depends on success/failure
        if not self.success:
            score += 25.0

            # Additional score based on failure reason
            if self.failure_reason:
                if 'password' in self.failure_reason.lower():
                    score += 10.0
                if 'locked' in self.failure_reason.lower():
                    score += 15.0
                if 'mfa' in self.failure_reason.lower():
                    score += 20.0

        # Check suspicious IP if available
        if self.ip_address:
            try:
                # Score for private IPs
                ip_obj = ipaddress.ip_address(self.ip_address)
                if ip_obj.is_private:
                    score -= 5.0

                # Check if IP is suspicious
                redis_client = self._get_redis_client()
                if redis_client:
                    ip_key = f"{self.SUSPICIOUS_IP_PREFIX}{self.ip_address}"
                    if redis_client.exists(ip_key):
                        score += 25.0
            except:
                pass

        # Check if user agent indicates a bot
        if self.device_fingerprint and self.device_fingerprint.get('is_bot'):
            score += 15.0

        return min(max(score, 0.0), 100.0)  # Clamp between 0 and 100

    @classmethod
    def record_attempt(cls, username: str, ip_address: Optional[str] = None,
                       success: bool = False, user_agent: Optional[str] = None,
                       email: Optional[str] = None, user_id: Optional[int] = None,
                       login_method: Optional[str] = None,
                       failure_reason: Optional[str] = None) -> bool:
        """
        Record a login attempt in both database and Redis (for rate limiting).

        Args:
            username: Username used in login attempt
            ip_address: Source IP address
            success: Whether the attempt was successful
            user_agent: User agent string from request
            email: Email used in login attempt (if different from username)
            user_id: ID of the user (if identified)
            login_method: Authentication method used
            failure_reason: Reason for failure if unsuccessful

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
                success=success,
                user_id=user_id,
                login_method=login_method,
                failure_reason=failure_reason
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
                    "has_ip": "true" if ip_address else "false",
                    "method": login_method or "unknown"
                })

            # If failed attempt, update Redis for rate limiting
            if not success:
                cls._increment_attempt_counter(username, ip_address, attempt.device_fingerprint)

                # Check for velocity attacks (sudden spike in attempts)
                cls._check_velocity_attack(username, ip_address)

            # Check for anomalies after successful login
            if success and user_id:
                anomalies = cls._detect_login_anomalies(user_id, ip_address, attempt.device_fingerprint)
                if anomalies:
                    # Log anomalies and update risk score
                    from core.security import log_security_event
                    log_security_event(
                        event_type=AuditLog.EVENT_LOGIN_ANOMALY,
                        description=f"Login anomalies detected for user {user_id}",
                        severity="warning",
                        user_id=user_id,
                        ip_address=ip_address,
                        details={
                            "anomalies": anomalies,
                            "username": username,
                            "login_method": login_method
                        }
                    )

                    # Update metrics
                    metrics.info('security_login_anomalies_total', 1, labels={
                        "anomaly_type": ",".join(a["type"] for a in anomalies),
                        "username_present": "true" if username else "false"
                    })

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
    def unlock_account(cls, username: str, admin_user_id: Optional[int] = None) -> bool:
        """
        Administratively unlock a locked account.

        Args:
            username: Username to unlock
            admin_user_id: ID of admin performing the unlock

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
            user_id=admin_user_id,
            details={
                "username": username,
                "administrative_action": True,
                "admin_user_id": admin_user_id
            }
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

                # Calculate a threat score
                threat_score = cls._calculate_ip_threat_score(
                    count, success_count or 0, len(unique_usernames)
                )

                suspicious_ips.append({
                    'ip_address': ip,
                    'failed_count': count,
                    'success_count': success_count or 0,
                    'unique_usernames': unique_usernames,
                    'unique_username_count': len(unique_usernames),
                    'geo_location': geo_location,
                    'is_locked': cls.is_ip_rate_limited(ip),
                    'threat_score': threat_score,
                    'latest_attempt': latest_attempt.timestamp.isoformat() if latest_attempt else None,
                    'recommendation': cls._get_ip_recommendation(threat_score)
                })

            return sorted(suspicious_ips, key=lambda x: x['threat_score'], reverse=True)

        except SQLAlchemyError as e:
            if current_app:
                current_app.logger.error(f"Database error getting suspicious IPs: {str(e)}")
            return []
        except Exception as e:
            if current_app:
                current_app.logger.error(f"Unexpected error getting suspicious IPs: {str(e)}")
            return []

    @classmethod
    def _calculate_ip_threat_score(cls, failed_attempts: int,
                                 successful_attempts: int,
                                 unique_username_count: int) -> int:
        """
        Calculate a threat score for an IP address based on login patterns.

        Args:
            failed_attempts: Number of failed login attempts
            successful_attempts: Number of successful login attempts
            unique_username_count: Number of unique usernames attempted

        Returns:
            int: Threat score from 0-100
        """
        # Base score based on failed login count
        base_score = min(failed_attempts * 2, 50)

        # Increase score if targeting multiple usernames
        username_factor = min(unique_username_count * 10, 30)

        # Reduce score if there are successful logins (legitimate IP)
        success_factor = -min(successful_attempts * 2, 20)

        # High ratio of failures to success is suspicious
        if successful_attempts > 0:
            ratio_factor = min((failed_attempts / successful_attempts) * 5, 20)
        else:
            ratio_factor = 20  # No successful logins is suspicious

        score = base_score + username_factor + success_factor + ratio_factor
        return int(max(min(score, 100), 0))  # Clamp between 0-100

    @classmethod
    def _get_ip_recommendation(cls, threat_score: int) -> str:
        """Get recommendation based on IP threat score."""
        if threat_score >= 80:
            return "Block IP address immediately"
        elif threat_score >= 60:
            return "Implement additional verification for this IP"
        elif threat_score >= 40:
            return "Monitor activity from this IP"
        else:
            return "No immediate action needed"

    @classmethod
    def get_recent_attempts(cls, username: Optional[str] = None,
                           ip_address: Optional[str] = None,
                           user_id: Optional[int] = None,
                           hours: int = 24, limit: int = 100) -> List['LoginAttempt']:
        """
        Get recent login attempts for a username, IP address, or user ID.

        Args:
            username: Filter by username (optional)
            ip_address: Filter by IP address (optional)
            user_id: Filter by user ID (optional)
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

            if user_id:
                query = query.filter(cls.user_id == user_id)

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

    @classmethod
    def get_account_activity_summary(cls, username: str, days: int = 30) -> Dict[str, Any]:
        """
        Get a summary of login activity for an account.

        Args:
            username: The username to analyze
            days: Number of days to analyze

        Returns:
            Dict containing login activity summary
        """
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            username = username.lower() if username else None

            # Base query for this username
            query = cls.query.filter(
                cls.username == username,
                cls.timestamp >= cutoff
            )

            # Get total attempts
            total_attempts = query.count()

            # Get success rate
            successful = query.filter(cls.success == True).count()
            failed = total_attempts - successful
            success_rate = (successful / total_attempts) * 100 if total_attempts > 0 else 0

            # Get unique IPs
            unique_ips_query = db.session.query(
                cls.ip_address,
                db.func.count(cls.id).label('count')
            ).filter(
                cls.username == username,
                cls.timestamp >= cutoff,
                cls.ip_address != None
            ).group_by(cls.ip_address).all()

            unique_ips = [{'ip': ip, 'count': count} for ip, count in unique_ips_query]

            # Get latest successful login
            latest_success = query.filter(cls.success == True).order_by(
                cls.timestamp.desc()).first()

            # Get devices used
            devices_query = db.session.query(
                cls.device_fingerprint['browser'].label('browser'),
                cls.device_fingerprint['os'].label('os'),
                db.func.count(cls.id).label('count')
            ).filter(
                cls.username == username,
                cls.timestamp >= cutoff,
                cls.device_fingerprint != None
            ).group_by('browser', 'os').all()

            devices = [{'browser': browser, 'os': os, 'count': count}
                      for browser, os, count in devices_query]

            return {
                'username': username,
                'period_days': days,
                'total_attempts': total_attempts,
                'successful_attempts': successful,
                'failed_attempts': failed,
                'success_rate': round(success_rate, 2),
                'unique_ip_count': len(unique_ips),
                'unique_ips': unique_ips[:10],  # Limit to top 10
                'device_count': len(devices),
                'devices': devices[:10],  # Limit to top 10
                'latest_success': latest_success.timestamp.isoformat() if latest_success else None,
                'anomalies': cls._get_account_anomalies(username, cutoff)
            }

        except SQLAlchemyError as e:
            if current_app:
                current_app.logger.error(f"Database error getting account summary: {str(e)}")
            return {'error': 'Database error retrieving account activity'}
        except Exception as e:
            if current_app:
                current_app.logger.error(f"Error getting account summary: {str(e)}")
            return {'error': 'Error retrieving account activity'}

    @classmethod
    def _get_account_anomalies(cls, username: str, cutoff: datetime) -> List[Dict[str, Any]]:
        """Get account anomalies for given username."""
        anomalies = []

        try:
            # Check for multiple failed logins followed by success
            attempts = cls.query.filter(
                cls.username == username,
                cls.timestamp >= cutoff
            ).order_by(cls.timestamp).all()

            # Track consecutive failures
            consecutive_failures = 0
            for i, attempt in enumerate(attempts):
                if not attempt.success:
                    consecutive_failures += 1
                else:
                    # If we had 3+ consecutive failures and then success,
                    # that's potentially suspicious
                    if consecutive_failures >= 3 and i > 0:
                        anomalies.append({
                            'type': 'brute_force_success',
                            'timestamp': attempt.timestamp.isoformat(),
                            'ip_address': attempt.ip_address,
                            'consecutive_failures': consecutive_failures
                        })
                    consecutive_failures = 0

            # Look for logins from unusual locations
            geo_locations = db.session.query(
                cls.geo_location,
                db.func.count(cls.id).label('count')
            ).filter(
                cls.username == username,
                cls.timestamp >= cutoff,
                cls.success == True,
                cls.geo_location != None
            ).group_by(cls.geo_location).order_by(
                db.func.count(cls.id).desc()
            ).all()

            # If user has common locations but also logged in from rare locations
            if len(geo_locations) >= 2:
                common_locations = {loc for loc, count in geo_locations if count >= 3}
                rare_locations = [(loc, when) for loc, when in db.session.query(
                    cls.geo_location, cls.timestamp
                ).filter(
                    cls.username == username,
                    cls.timestamp >= cutoff,
                    cls.success == True,
                    cls.geo_location.notin_(common_locations)
                ).all()]

                for location, timestamp in rare_locations:
                    anomalies.append({
                        'type': 'unusual_location',
                        'location': location,
                        'timestamp': timestamp.isoformat()
                    })

            # Check for multiple countries in short time period
            successful_logins = cls.query.filter(
                cls.username == username,
                cls.timestamp >= cutoff,
                cls.success == True,
                cls.geo_location != None
            ).order_by(cls.timestamp).all()

            # Check for rapid location changes
            for i in range(1, len(successful_logins)):
                prev = successful_logins[i-1]
                curr = successful_logins[i]
                time_diff = (curr.timestamp - prev.timestamp).total_seconds()

                # Only check if different locations
                if prev.geo_location != curr.geo_location:
                    # If less than 6 hours between logins from different locations
                    if time_diff < 21600:  # 6 hours in seconds
                        anomalies.append({
                            'type': 'impossible_travel',
                            'from_location': prev.geo_location,
                            'to_location': curr.geo_location,
                            'timestamp': curr.timestamp.isoformat(),
                            'hours_between': round(time_diff / 3600, 2)
                        })

            return anomalies

        except Exception as e:
            if current_app:
                current_app.logger.error(f"Error detecting account anomalies: {str(e)}")
            return []

    @classmethod
    def _check_velocity_attack(cls, username: Optional[str],
                             ip_address: Optional[str]) -> None:
        """
        Check for velocity attacks (rapid succession of login attempts).

        Args:
            username: Username being attempted
            ip_address: Source IP address
        """
        if not username and not ip_address:
            return

        try:
            # Count attempts in last 5 minutes
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)

            # Build query based on available data
            query = cls.query.filter(cls.timestamp >= cutoff)

            if username:
                query = query.filter(cls.username == username.lower())

            if ip_address:
                query = query.filter(cls.ip_address == ip_address)

            # Get count of attempts
            attempt_count = query.count()

            # If we have a high velocity of attempts, mark as suspicious
            if attempt_count >= 10:  # 10+ attempts in 5 minutes is suspicious
                from core.security import log_security_event

                # Mark IP as suspicious in Redis
                if ip_address:
                    redis_client = cls._get_redis_client()
                    if redis_client:
                        redis_client.setex(
                            f"{cls.SUSPICIOUS_IP_PREFIX}{ip_address}",
                            24 * 60 * 60,  # 24 hour TTL
                            attempt_count
                        )

                # Log the security event
                log_security_event(
                    event_type=AuditLog.EVENT_API_ABUSE,
                    description=f"Velocity attack detected: {attempt_count} attempts in 5 minutes",
                    severity="warning",
                    ip_address=ip_address,
                    details={
                        "username": username,
                        "ip_address": ip_address,
                        "attempt_count": attempt_count,
                        "window_minutes": 5
                    }
                )

                # Track metrics
                if hasattr(metrics, 'info'):
                    metrics.info('security_velocity_attack_total', 1, labels={
                        "username_present": "true" if username else "false",
                        "ip_present": "true" if ip_address else "false",
                        "attempt_count": str(attempt_count)
                    })

        except Exception as e:
            if current_app:
                current_app.logger.error(f"Error checking velocity attack: {str(e)}")

    @classmethod
    def _detect_login_anomalies(cls, user_id: int, ip_address: Optional[str],
                              device_info: Optional[Dict]) -> List[Dict[str, Any]]:
        """
        Detect anomalies for a successful login.

        Args:
            user_id: ID of the user who logged in
            ip_address: Source IP address
            device_info: Device fingerprint information

        Returns:
            List of detected anomalies
        """
        anomalies = []

        try:
            # Get recent successful logins for this user
            cutoff = datetime.now(timezone.utc) - timedelta(days=30)
            recent_logins = cls.query.filter(
                cls.user_id == user_id,
                cls.success == True,
                cls.timestamp >= cutoff
            ).order_by(cls.timestamp.desc()).limit(10).all()

            if not recent_logins or len(recent_logins) <= 1:
                return []  # Not enough history

            # Check if this is first login from this IP
            if ip_address:
                ip_logins = cls.query.filter(
                    cls.user_id == user_id,
                    cls.success == True,
                    cls.ip_address == ip_address,
                    cls.timestamp >= cutoff
                ).count()

                if ip_logins <= 1:  # First or second time from this IP
                    # Check if user has common IPs
                    common_ips_count = db.session.query(
                        cls.ip_address,
                        db.func.count(cls.id).label('count')
                    ).filter(
                        cls.user_id == user_id,
                        cls.success == True,
                        cls.timestamp >= cutoff
                    ).group_by(cls.ip_address).having(
                        db.func.count(cls.id) >= 3  # Used 3+ times
                    ).count()

                    # If user has established patterns but this is a new IP
                    if common_ips_count >= 1:
                        anomalies.append({
                            "type": "new_ip_address",
                            "ip_address": ip_address,
                            "severity": "medium"
                        })

            # Check for different device fingerprint
            if device_info:
                # Get most common browser and OS
                browser = device_info.get('browser')
                os = device_info.get('os')
                is_mobile = device_info.get('is_mobile', False)

                if browser and os:
                    # Check if this browser+OS combo has been used before
                    device_logins = cls.query.filter(
                        cls.user_id == user_id,
                        cls.success == True,
                        cls.timestamp >= cutoff,
                        cls.device_fingerprint['browser'].astext == browser,
                        cls.device_fingerprint['os'].astext == os
                    ).count()

                    if device_logins <= 1:  # First or second time from this device
                        anomalies.append({
                            "type": "new_device",
                            "browser": browser,
                            "os": os,
                            "is_mobile": is_mobile,
                            "severity": "low"
                        })

            # Check for time-based anomalies (if user typically logs in during certain hours)
            if len(recent_logins) >= 5:
                # Calculate user's typical login hour range
                login_hours = [login.timestamp.hour for login in recent_logins]
                min_hour, max_hour = min(login_hours), max(login_hours)

                # Get current hour
                current_hour = datetime.now(timezone.utc).hour

                # If login time is outside typical pattern with a buffer of 2 hours
                if current_hour < min_hour - 2 or current_hour > max_hour + 2:
                    # Only flag if the user has a consistent pattern
                    if max_hour - min_hour <= 12:  # User has 12-hour or less login window
                        anomalies.append({
                            "type": "unusual_login_time",
                            "typical_range": f"{min_hour}-{max_hour}",
                            "current_hour": current_hour,
                            "severity": "low"
                        })

            return anomalies

        except Exception as e:
            if current_app:
                current_app.logger.error(f"Error detecting login anomalies: {str(e)}")
            return []

    # Private methods

    @classmethod
    def _increment_attempt_counter(cls, username: Optional[str],
                                  ip_address: Optional[str],
                                  device_info: Optional[Dict] = None) -> None:
        """
        Increment failed login attempt counters and apply lockouts if needed.

        Args:
            username: Username to increment counter for
            ip_address: IP address to increment counter for
            device_info: Device fingerprint information
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
                    # Get previous lockout count
                    previous_lockouts_key = f"login:previous_lockouts:{username}"
                    previous_lockouts = int(redis_client.get(previous_lockouts_key) or 0)

                    # Calculate lockout duration based on previous lockouts
                    lockout_index = min(previous_lockouts, len(cls.PROGRESSIVE_LOCKOUTS) - 1)
                    lockout_minutes = cls.PROGRESSIVE_LOCKOUTS[lockout_index]

                    # Apply lockout
                    redis_client.setex(
                        lockout_key,
                        int(lockout_minutes * 60),
                        1
                    )

                    # Reset attempt counter
                    redis_client.delete(attempt_key)

                    # Increment previous lockout counter with 30 day expiry
                    redis_client.incr(previous_lockouts_key)
                    redis_client.expire(previous_lockouts_key, 30 * 24 * 60 * 60)

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
                            "previous_lockouts": previous_lockouts,
                            "ip_address": ip_address
                        }
                    )

                    # Track metrics
                    if hasattr(metrics, 'info'):
                        metrics.info('security_account_lockouts_total', 1, labels={
                            "username": username,
                            "duration_minutes": str(lockout_minutes),
                            "previous_lockouts": str(previous_lockouts)
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
                            "lockout_minutes": ip_lockout_minutes,
                            "username": username
                        }
                    )

                    # Track metrics
                    if hasattr(metrics, 'info'):
                        metrics.info('security_ip_lockouts_total', 1, labels={
                            "ip_address": ip_address,
                            "duration_minutes": str(ip_lockout_minutes)
                        })

        # Track suspicious activity using device fingerprint
        if device_info and redis_client:
            # Create a simplified device fingerprint string
            device_key = None
            try:
                browser = device_info.get('browser', 'unknown')
                os = device_info.get('os', 'unknown')
                device = device_info.get('device', 'unknown')
                device_key = f"{browser}|{os}|{device}".lower()

                if device_key:
                    # Increment device attempt counter
                    device_attempt_key = f"{cls.DEVICE_ATTEMPT_PREFIX}{device_key}"
                    device_attempts = redis_client.incr(device_attempt_key)
                    redis_client.expire(device_attempt_key, 24 * 60 * 60)  # 24 hour TTL

                    # Mark device as suspicious if it attempts many accounts
                    if username:
                        device_username_set = f"{cls.DEVICE_ATTEMPT_PREFIX}{device_key}:usernames"
                        redis_client.sadd(device_username_set, username)
                        redis_client.expire(device_username_set, 24 * 60 * 60)  # 24 hour TTL

                        # Check if device is trying many different accounts
                        unique_username_attempts = redis_client.scard(device_username_set)
                        if unique_username_attempts >= 5:  # 5+ different accounts is suspicious
                            redis_client.setex(
                                f"{cls.SUSPICIOUS_DEVICE_PREFIX}{device_key}",
                                7 * 24 * 60 * 60,  # 7 day TTL
                                unique_username_attempts
                            )
            except Exception as e:
                if current_app:
                    current_app.logger.debug(f"Error tracking device fingerprint: {str(e)}")

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

    @classmethod
    def get_threat_intelligence(cls, days: int = 7) -> Dict[str, Any]:
        """
        Generate threat intelligence report based on login attempt patterns.

        Args:
            days: Number of days to analyze

        Returns:
            Dict containing threat intelligence report
        """
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)

            # Overall statistics
            total_attempts = cls.query.filter(cls.timestamp >= cutoff).count()
            failed_attempts = cls.query.filter(
                cls.timestamp >= cutoff,
                cls.success == False
            ).count()

            # Top targeted usernames (potential brute force targets)
            top_usernames = db.session.query(
                cls.username,
                db.func.count(cls.id).label('attempt_count')
            ).filter(
                cls.timestamp >= cutoff,
                cls.success == False,
                cls.username != None
            ).group_by(cls.username).order_by(
                db.func.count(cls.id).desc()
            ).limit(10).all()

            # Get suspicious IPs
            suspicious_ips = cls.get_suspicious_ips(hours=days * 24, min_attempts=10)

            # Get success rate by country
            country_stats = db.session.query(
                db.func.regexp_replace(cls.geo_location, ', .*$', '').label('country'),
                db.func.sum(db.case([(cls.success == True, 1)], else_=0)).label('success_count'),
                db.func.count(cls.id).label('total_count')
            ).filter(
                cls.timestamp >= cutoff,
                cls.geo_location != None
            ).group_by('country').having(
                db.func.count(cls.id) > 5  # At least 5 attempts
            ).all()

            country_data = []
            for country, success, total in country_stats:
                if country:  # Skip if country is None
                    success_rate = (success / total) * 100 if total > 0 else 0
                    country_data.append({
                        'country': country,
                        'success_count': success,
                        'total_count': total,
                        'success_rate': round(success_rate, 2)
                    })

            # Sort by success rate (lowest first, as low success rates are suspicious)
            country_data.sort(key=lambda x: x['success_rate'])

            # Detect patterns of distributed attacks (many IPs targeting few accounts)
            distributed_attacks = []
            for username, _ in top_usernames[:5]:  # Check top 5 targeted accounts
                ip_count = db.session.query(db.func.count(db.func.distinct(cls.ip_address))).filter(
                    cls.timestamp >= cutoff,
                    cls.username == username,
                    cls.success == False,
                    cls.ip_address != None
                ).scalar()

                # If many IPs targeting same account, potential distributed attack
                if ip_count > 10:
                    distributed_attacks.append({
                        'username': username,
                        'unique_ip_count': ip_count,
                        'detection_time': datetime.now(timezone.utc).isoformat()
                    })

            # Return complete report
            return {
                'report_date': datetime.now(timezone.utc).isoformat(),
                'period_days': days,
                'total_login_attempts': total_attempts,
                'failed_attempts': failed_attempts,
                'success_rate': round(((total_attempts - failed_attempts) / total_attempts) * 100, 2) if total_attempts > 0 else 0,
                'top_targeted_accounts': [
                    {'username': username, 'attempts': count}
                    for username, count in top_usernames
                ],
                'suspicious_ips': suspicious_ips[:10],  # Top 10 suspicious IPs
                'country_statistics': country_data[:10],  # Top 10 countries
                'distributed_attacks': distributed_attacks,
                'recommendations': cls._generate_security_recommendations(
                    total_attempts, failed_attempts, len(suspicious_ips), len(distributed_attacks)
                )
            }

        except Exception as e:
            if current_app:
                current_app.logger.error(f"Error generating threat intelligence: {str(e)}")
            return {
                'error': 'Failed to generate threat intelligence report',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

    @classmethod
    def _generate_security_recommendations(cls, total_attempts: int,
                                         failed_attempts: int,
                                         suspicious_ip_count: int,
                                         distributed_attack_count: int) -> List[str]:
        """Generate security recommendations based on login patterns."""
        recommendations = []

        # Basic recommendations
        recommendations.append("Implement CAPTCHA for login forms to prevent automated attacks")

        # Failure rate-based recommendations
        if total_attempts > 0:
            failure_rate = (failed_attempts / total_attempts) * 100
            if failure_rate > 70:
                recommendations.append("High login failure rate detected - Consider strengthening password requirements")
                recommendations.append("Enable account lockout notifications to alert users of suspicious activity")

        # Suspicious IP recommendations
        if suspicious_ip_count > 10:
            recommendations.append("Consider implementing IP-based geofencing for sensitive accounts")
            recommendations.append("Enable IP reputation checking for login attempts")

        # Distributed attack recommendations
        if distributed_attack_count > 0:
            recommendations.append("Implement multi-factor authentication for all user accounts")
            recommendations.append("Consider implementing rate-limiting by IP blocks or ASNs")
            recommendations.append("Implement login anomaly detection with real-time alerts")

        return recommendations
