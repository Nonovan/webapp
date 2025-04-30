"""
Security monitoring functionality for the Cloud Infrastructure Platform.

This module provides security monitoring capabilities including suspicious IP detection,
login failure tracking, session monitoring, and security event analytics. These
functions support real-time security detection and response.
"""

import os
import json
import ipaddress
import requests
import functools
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple, Union, Set, TypeVar, cast

# SQLAlchemy imports
from sqlalchemy import func, desc, or_, and_, literal
from sqlalchemy.exc import SQLAlchemyError

# Flask imports
from flask import current_app, request, g, has_request_context, session, has_app_context

# Internal imports
from extensions import db, metrics
from extensions import get_redis_client
from .cs_audit import log_security_event, log_error, log_warning, log_info, log_debug
from .cs_authentication import is_valid_ip
from .cs_constants import SECURITY_CONFIG
from .cs_file_integrity import get_last_integrity_status
from models.security import AuditLog


def get_suspicious_ips(hours: int = 24, min_attempts: int = 5) -> List[Dict[str, Any]]:
    """
    Get list of suspicious IPs with their activity counts.

    Analyzes failed login attempts and security events to identify potentially
    malicious IP addresses that may be attempting to breach the system.

    Args:
        hours: Number of hours to look back for failed login attempts
        min_attempts: Minimum number of failed attempts to consider an IP suspicious

    Returns:
        List[Dict[str, Any]]: List of suspicious IPs with their failed login counts
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    cache_key = f"suspicious_ips:{hours}:{min_attempts}"

    # Try to get cached results first
    cached_data = _get_from_cache(cache_key)
    if cached_data:
        return cached_data

    try:
        # Subquery to count failed login attempts by IP
        failed_login_counts = db.session.query(
            AuditLog.ip_address,
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
            AuditLog.created_at >= cutoff,
            AuditLog.ip_address.isnot(None)
        ).group_by(AuditLog.ip_address).subquery()

        # Get IPs with more than min_attempts failed attempts
        suspicious = db.session.query(
            failed_login_counts.c.ip_address,
            failed_login_counts.c.count
        ).filter(failed_login_counts.c.count >= min_attempts).all()

        # Add additional fields for enriched data
        result = []
        for ip, count in suspicious:
            ip_data = {'ip': ip, 'count': count}

            # Add geolocation data if available
            ip_data['geolocation'] = _get_ip_geolocation(ip)

            # Add most recent failed attempt timestamp
            latest_attempt = db.session.query(func.max(AuditLog.created_at)).filter(
                AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
                AuditLog.ip_address == ip
            ).scalar()

            if latest_attempt:
                ip_data['latest_attempt'] = latest_attempt.isoformat()

            # Check if IP is currently blocked
            ip_data['is_blocked'] = check_ip_blocked(ip)

            # Add targeted usernames (from login attempts)
            targeted_usernames = _get_targeted_usernames(ip, cutoff)
            if targeted_usernames:
                ip_data['targeted_users'] = targeted_usernames

            # Add additional security events from this IP
            security_events = _get_security_events_for_ip(ip, cutoff)
            if security_events:
                ip_data['security_events'] = security_events

            # Add threat score based on various factors
            ip_data['threat_score'] = _calculate_threat_score(ip, count, security_events)

            result.append(ip_data)

        # Cache the results for 5 minutes
        _set_in_cache(cache_key, result, 300)

        # Track metrics
        metrics.gauge('security.suspicious_ips', len(result))

        # Track high threat IPs
        high_threat_count = sum(1 for ip_data in result if ip_data.get('threat_score', 0) >= 75)
        metrics.gauge('security.high_threat_ips', high_threat_count)

        return result
    except SQLAlchemyError as e:
        log_error(f"Database error in get_suspicious_ips: {e}")
        return []


def get_failed_login_count(hours: int = 24) -> int:
    """
    Get count of failed logins in the past hours.

    Args:
        hours: Number of hours to look back

    Returns:
        int: Count of failed login events
    """
    cache_key = f"failed_login_count:{hours}"

    # Try to get cached count first
    cached_count = _get_from_cache(cache_key, as_int=True)
    if cached_count is not None:
        return cached_count

    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Query database for count
        count = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
            AuditLog.created_at >= cutoff
        ).scalar() or 0

        # Cache the result for 5 minutes
        _set_in_cache(cache_key, count, 300)

        # Track metric
        metrics.gauge('security.failed_logins', count)

        return count
    except SQLAlchemyError as e:
        log_error(f"Database error in get_failed_login_count: {e}")
        return 0


def get_account_lockout_count(hours: int = 24) -> int:
    """
    Get count of account lockouts in the past hours.

    Args:
        hours: Number of hours to look back

    Returns:
        int: Count of account lockout events
    """
    cache_key = f"account_lockout_count:{hours}"

    # Try to get cached count first
    cached_count = _get_from_cache(cache_key, as_int=True)
    if cached_count is not None:
        return cached_count

    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Query database for count
        count = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.event_type == AuditLog.EVENT_ACCOUNT_LOCKOUT,
            AuditLog.created_at >= cutoff
        ).scalar() or 0

        # Cache the result for 5 minutes
        _set_in_cache(cache_key, count, 300)

        # Track metric
        metrics.gauge('security.account_lockouts', count)

        return count
    except SQLAlchemyError as e:
        log_error(f"Database error in get_account_lockout_count: {e}")
        return 0


def get_security_event_distribution(hours: int = 24) -> Dict[str, int]:
    """
    Get distribution of security events by type.

    Analyzes and categorizes security events to provide visibility into the
    security posture and help identify trends or anomalies.

    Args:
        hours: Number of hours to look back

    Returns:
        Dict[str, int]: Mapping of event types to their counts
    """
    cache_key = f"security_event_distribution:{hours}"

    # Try to get cached results first
    cached_data = _get_from_cache(cache_key)
    if cached_data:
        return cached_data

    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Query database for event types and counts
        events = db.session.query(
            AuditLog.event_type,
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.created_at >= cutoff
        ).group_by(AuditLog.event_type).all()

        # Convert to dictionary
        result = {event_type: count for event_type, count in events}

        # Cache the results for 5 minutes
        _set_in_cache(cache_key, result, 300)

        # Track top event types as metrics
        for event_type, count in result.items():
            # Only track specific important event types to avoid metric explosion
            if any(key in event_type for key in ['login', 'security', 'permission', 'breach', 'attack']):
                metrics.gauge(f'security.event.{event_type}', count)

        return result
    except SQLAlchemyError as e:
        log_error(f"Database error in get_security_event_distribution: {e}")
        return {}


def get_active_session_count() -> int:
    """
    Get count of active user sessions.

    This function queries Redis to count active user sessions, providing
    visibility into current system usage and potential session anomalies.

    Returns:
        int: Count of active sessions
    """
    try:
        # Use Redis client from extensions
        redis_client = get_redis_client()
        if not redis_client:
            log_warning("Redis unavailable for session count")
            return 0

        # Get session keys with cursor for large datasets
        cursor = '0'
        session_keys = set()

        while True:
            cursor, keys = redis_client.scan(
                cursor=cursor,
                match='session:*',
                count=1000
            )

            if keys:
                session_keys.update(keys)

            # Check if we've finished scanning
            if cursor == '0' or cursor == b'0' or cursor == 0:
                break

        # Track metric
        count = len(session_keys)
        metrics.gauge('security.active_sessions', count)

        return count
    except Exception as e:
        log_error(f"Error in get_active_session_count: {e}")
        return 0


def get_suspicious_sessions() -> List[Dict[str, Any]]:
    """
    Get list of suspicious user sessions with anomaly details.

    This function identifies active sessions with suspicious activity patterns
    such as abnormal locations, failed MFA attempts, or unusual navigation.

    Returns:
        List[Dict[str, Any]]: List of suspicious sessions with anomaly details
    """
    try:
        # Use database query to find sessions with anomalies
        if not _should_check_db_session():
            return []

        # Query for suspicious sessions in database
        from models.auth.user_session import UserSession

        suspicious_sessions = UserSession.query.filter(
            UserSession.is_active == True,
            UserSession.is_suspicious == True
        ).order_by(UserSession.last_active.desc()).limit(50).all()

        result = []
        for session in suspicious_sessions:
            # Create result entry
            session_data = {
                'session_id': session.session_id,
                'user_id': session.user_id,
                'ip_address': session.ip_address,
                'user_agent': session.user_agent,
                'created_at': session.created_at.isoformat() if session.created_at else None,
                'last_active': session.last_active.isoformat() if session.last_active else None,
                'anomaly': session.last_anomaly,
                'location': session.last_location
            }

            # Add anomaly history if available
            if hasattr(session, 'anomaly_history') and session.anomaly_history:
                session_data['anomaly_history'] = session.anomaly_history

            result.append(session_data)

        # Track metric
        metrics.gauge('security.suspicious_sessions', len(result))

        return result
    except Exception as e:
        log_error(f"Error getting suspicious sessions: {e}")
        return []


def is_suspicious_ip(ip_address: Optional[str], threshold: int = 5) -> bool:
    """
    Determine if an IP address is suspicious based on login failure history and blocklists.

    This function checks if an IP address should be considered suspicious by:
    1. Checking against known suspicious IP cache
    2. Looking up failed login attempts from this IP
    3. Checking against external IP reputation services
    4. Checking against known malicious IP ranges

    Args:
        ip_address: The IP address to check
        threshold: Minimum number of failed attempts to consider an IP suspicious

    Returns:
        bool: True if the IP is suspicious, False otherwise
    """
    if not ip_address:
        return False

    try:
        # Check if the IP is already blocked
        if check_ip_blocked(ip_address):
            return True

        # Check against known malicious networks
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            malicious_networks = SECURITY_CONFIG.get('KNOWN_MALICIOUS_NETWORKS', [])

            for network_str in malicious_networks:
                try:
                    network = ipaddress.ip_network(network_str, strict=False)
                    if ip_obj in network:
                        log_warning(f"IP {ip_address} found in known malicious network {network_str}")
                        metrics.increment('security.malicious_network_access')
                        return True
                except ValueError:
                    # Skip invalid network definitions
                    continue
        except ValueError:
            # Invalid IP address format
            log_warning(f"Invalid IP address format: {ip_address}")
            return False

        # Check Redis cache first for known suspicious IPs (faster)
        redis_client = get_redis_client()
        if redis_client:
            cached_result = redis_client.get(f"suspicious_ip:{ip_address}")
            if cached_result:
                is_suspicious = cached_result.decode('utf-8', errors='ignore') == "True"
                if is_suspicious:
                    metrics.increment('security.suspicious_ip_cache_hit')
                return is_suspicious

        # Check for failed login attempts in audit log
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        failed_count = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
            AuditLog.ip_address == ip_address,
            AuditLog.created_at >= cutoff
        ).scalar() or 0

        if failed_count >= threshold:
            # Cache the result for 1 hour
            if redis_client:
                redis_client.setex(f"suspicious_ip:{ip_address}", 3600, "True")
            metrics.increment('security.suspicious_ip_detected')
            return True

        # Check for other security breach attempts
        breach_attempts = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.event_type.in_([
                AuditLog.EVENT_SECURITY_BREACH_ATTEMPT,
                AuditLog.EVENT_PERMISSION_DENIED,
                AuditLog.EVENT_RATE_LIMIT_EXCEEDED,
                AuditLog.EVENT_FILE_INTEGRITY  # Added for file integrity violations
            ]),
            AuditLog.ip_address == ip_address,
            AuditLog.created_at >= cutoff
        ).scalar() or 0

        if breach_attempts > 0:
            # Cache the result for 1 hour
            if redis_client:
                redis_client.setex(f"suspicious_ip:{ip_address}", 3600, "True")
            metrics.increment('security.breach_attempt_detected')
            return True

        # Check against external IP reputation service if configured
        if has_app_context() and current_app.config.get('IP_REPUTATION_CHECK_ENABLED'):
            result = _check_ip_reputation(ip_address)
            if result and result.get('threat_score', 0) > 50:  # Threshold for reputation scoring
                # Cache the result for 6 hours
                if redis_client:
                    redis_client.setex(f"suspicious_ip:{ip_address}", 21600, "True")
                metrics.increment('security.ip_reputation_detected')
                return True

        # Cache negative result for 30 minutes
        if redis_client:
            redis_client.setex(f"suspicious_ip:{ip_address}", 1800, "False")

    except SQLAlchemyError as e:
        log_error(f"Database error when checking suspicious IP {ip_address}: {e}")
        return False

    return False


def block_ip(ip_address: str, duration: int = 3600, reason: str = "security_policy") -> bool:
    """
    Block an IP address for a specified duration.

    Args:
        ip_address: IP address to block
        duration: Block duration in seconds (default: 1 hour)
        reason: Reason for the block

    Returns:
        bool: True if successfully blocked, False otherwise
    """
    if not ip_address:
        return False

    try:
        if not is_valid_ip(ip_address):
            log_error(f"Invalid IP address format: {ip_address}")
            return False

        redis_client = get_redis_client()
        if not redis_client:
            log_warning(f"Redis unavailable, unable to block IP: {ip_address}")
            return False

        # Store block information
        block_data = {
            'blocked_at': datetime.now(timezone.utc).isoformat(),
            'reason': reason,
            'duration': duration,
            'expiry': (datetime.now(timezone.utc) + timedelta(seconds=duration)).isoformat()
        }

        # Get geolocation data for the IP
        geolocation = _get_ip_geolocation(ip_address)
        if geolocation:
            block_data['geolocation'] = geolocation

        # Set with expiry
        redis_client.setex(
            f"blocked_ip:{ip_address}",
            duration,
            json.dumps(block_data)
        )

        # Log the event with appropriate severity
        log_warning(f"Blocked IP {ip_address} for {duration} seconds. Reason: {reason}")

        # Record security event
        try:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_COUNTERMEASURE,
                description=f"Blocked IP address: {ip_address}",
                severity='warning',
                ip_address=ip_address,
                details={
                    'duration': f"{duration} seconds",
                    'reason': reason,
                    'expiry': block_data['expiry'],
                    'geolocation': geolocation
                }
            )
        except Exception as e:
            # Don't let audit logging errors prevent IP blocking
            log_error(f"Error logging IP block event: {e}")

        # Track metric
        metrics.increment('security.ip_blocked')

        return True
    except Exception as e:
        log_error(f"Failed to block IP {ip_address}: {e}")
        return False


def check_ip_blocked(ip_address: str) -> bool:
    """
    Check if an IP address is currently blocked.

    Args:
        ip_address: IP address to check

    Returns:
        bool: True if IP is blocked, False otherwise
    """
    if not ip_address:
        return False

    try:
        redis_client = get_redis_client()
        if not redis_client:
            log_warning("Redis unavailable, cannot check if IP is blocked")
            return False

        # Check if key exists
        return redis_client.exists(f"blocked_ip:{ip_address}") > 0
    except Exception as e:
        log_error(f"Error checking if IP {ip_address} is blocked: {e}")
        return False


def get_ip_block_info(ip_address: str) -> Optional[Dict[str, Any]]:
    """
    Get information about an IP block if it exists.

    Args:
        ip_address: IP address to check

    Returns:
        Optional[Dict[str, Any]]: Block information or None if not blocked
    """
    if not ip_address:
        return None

    try:
        redis_client = get_redis_client()
        if not redis_client:
            log_warning("Redis unavailable, cannot get IP block info")
            return None

        # Get the block data
        block_data = redis_client.get(f"blocked_ip:{ip_address}")
        if not block_data:
            return None

        try:
            # Parse and return the block info
            result = json.loads(block_data)

            # Calculate remaining time
            if 'expiry' in result:
                try:
                    expiry = datetime.fromisoformat(result['expiry'])
                    now = datetime.now(timezone.utc)
                    remaining_seconds = max(0, int((expiry - now).total_seconds()))
                    result['remaining_seconds'] = remaining_seconds
                except (ValueError, TypeError):
                    pass

            return result
        except json.JSONDecodeError as e:
            log_error(f"Error decoding block info for IP {ip_address}: {e}")
            return None

    except Exception as e:
        log_error(f"Error getting block info for IP {ip_address}: {e}")
        return None


def unblock_ip(ip_address: str) -> bool:
    """
    Remove a block on an IP address.

    Args:
        ip_address: IP address to unblock

    Returns:
        bool: True if successfully unblocked or wasn't blocked, False on error
    """
    if not ip_address:
        return False

    try:
        redis_client = get_redis_client()
        if not redis_client:
            log_warning(f"Redis unavailable, unable to unblock IP: {ip_address}")
            return False

        # Get block info before removing (for audit)
        block_info = get_ip_block_info(ip_address)

        # Remove the block
        removed = redis_client.delete(f"blocked_ip:{ip_address}")

        # Clear suspicious IP cache to allow re-evaluation
        redis_client.delete(f"suspicious_ip:{ip_address}")

        # Only log if something was actually removed
        if removed:
            # Log the event
            log_info(f"Unblocked IP: {ip_address}")

            # Record security event
            try:
                log_security_event(
                    event_type=AuditLog.EVENT_SECURITY_COUNTERMEASURE,
                    description=f"Unblocked IP address: {ip_address}",
                    severity='info',
                    ip_address=ip_address,
                    details=block_info
                )
            except Exception as e:
                # Don't let audit logging errors prevent reporting success
                log_error(f"Error logging IP unblock event: {e}")

            # Track metric
            metrics.increment('security.ip_unblocked')

        return True
    except Exception as e:
        log_error(f"Failed to unblock IP {ip_address}: {e}")
        return False


def get_blocked_ips() -> Set[str]:
    """
    Get set of currently blocked IP addresses.

    Returns:
        Set[str]: Set of blocked IP addresses
    """
    blocked_ips = set()

    try:
        redis_client = get_redis_client()
        if not redis_client:
            log_warning("Redis unavailable for retrieving blocked IPs")
            return blocked_ips

        # Get all keys matching blocked IP pattern with cursor for large datasets
        cursor = '0'
        while True:
            cursor, keys = redis_client.scan(
                cursor=cursor,
                match="blocked_ip:*",
                count=1000
            )

            # Extract IP addresses from keys
            for key in keys:
                try:
                    # Handle bytes vs string keys
                    if isinstance(key, bytes):
                        key_str = key.decode('utf-8')
                    else:
                        key_str = str(key)

                    # Extract IP from key format "blocked_ip:{ip_address}"
                    ip = key_str.split(':', 1)[1]
                    blocked_ips.add(ip)
                except (IndexError, UnicodeDecodeError) as e:
                    log_warning(f"Error extracting IP from key {key}: {e}")

            # Check if we've finished scanning
            if cursor == '0' or cursor == b'0' or cursor == 0:
                break

        # Track metric
        metrics.gauge('security.blocked_ips', len(blocked_ips))

        return blocked_ips
    except Exception as e:
        log_error(f"Error retrieving blocked IPs: {e}")
        return blocked_ips


def analyze_location_change(prev_location: str, current_location: str, last_active: Optional[datetime] = None) -> bool:
    """
    Analyze if a location change is suspiciously rapid.

    This function calculates whether a user's location has changed implausibly fast
    between two sessions or requests, which could indicate session hijacking.

    Args:
        prev_location: Previous location string
        current_location: Current location string
        last_active: Timestamp of last activity from previous location

    Returns:
        bool: True if the location change is suspicious
    """
    if not prev_location or not current_location or prev_location == current_location:
        return False

    try:
        # Basic location parsing - expects format like "City, Country"
        prev_parts = prev_location.split(',')
        current_parts = current_location.split(',')

        if len(prev_parts) < 1 or len(current_parts) < 1:
            return False

        # Check if country changed
        prev_country = prev_parts[-1].strip()
        current_country = current_parts[-1].strip()

        # Only suspicious if country changed
        if prev_country == current_country:
            return False

        # If we have timing information, check if the change happened too quickly
        if last_active:
            now = datetime.now(timezone.utc)
            hours_since_last_active = (now - last_active).total_seconds() / 3600

            # If location changed countries in less than 2 hours, consider suspicious
            if hours_since_last_active < 2:
                log_warning(f"Suspicious location change: {prev_location} → {current_location} in {hours_since_last_active:.1f} hours")
                metrics.increment('security.suspicious_location_change')
                return True

        # Without timing information, just log the country change
        log_info(f"Location change detected: {prev_location} → {current_location}")

        return False
    except Exception as e:
        log_error(f"Error analyzing location change: {e}")
        return False


def detect_permission_issues() -> List[Dict[str, Any]]:
    """
    Detect filesystem permission issues in critical directories.

    This function checks for insecure permissions on critical files and
    directories that could lead to security vulnerabilities.

    Returns:
        List[Dict[str, Any]]: List of permission issues found
    """
    issues = []

    try:
        if not has_app_context():
            return []

        # Get critical paths from application configuration
        app_root = current_app.root_path
        critical_dirs = current_app.config.get('CRITICAL_DIRECTORIES', [
            os.path.join(app_root, 'config'),
            os.path.join(app_root, 'instance'),
            os.path.join(app_root, 'core'),
            os.path.join(app_root, 'logs')
        ])

        for directory in critical_dirs:
            if not os.path.exists(directory):
                continue

            dir_stat = os.stat(directory)
            # Check directory permissions (world-writable directories are dangerous)
            if dir_stat.st_mode & 0o002:  # World writable
                issues.append({
                    'path': directory,
                    'issue': 'world_writable_directory',
                    'severity': 'high',
                    'description': f"Directory {directory} is world-writable (mode {oct(dir_stat.st_mode & 0o777)})"
                })

            # Check owner/group permissions for sensitive directories
            try:
                import pwd
                import grp
                owner = pwd.getpwuid(dir_stat.st_uid).pw_name
                group = grp.getgrgid(dir_stat.st_gid).gr_name

                # Check if owned by unexpected user
                expected_owner = current_app.config.get('EXPECTED_OWNER', 'www-data')
                if owner != expected_owner and directory.endswith(('config', 'instance')):
                    issues.append({
                        'path': directory,
                        'issue': 'unexpected_owner',
                        'severity': 'medium',
                        'description': f"Directory {directory} is owned by {owner} (expected {expected_owner})"
                    })
            except (ImportError, KeyError) as e:
                # Skip this check if we can't get user/group info
                log_debug(f"Unable to verify ownership for {directory}: {e}")

            # Check individual files in sensitive directories
            if directory.endswith(('config', 'instance')) and os.path.isdir(directory):
                for root, _, files in os.walk(directory):
                    for file in files:
                        if file.endswith(('.py', '.ini', '.conf', '.json', '.key', '.pem')):
                            file_path = os.path.join(root, file)
                            try:
                                file_stat = os.stat(file_path)
                                # Check if file is world-readable or world-writable
                                if file_stat.st_mode & 0o006:  # World readable/writable
                                    issues.append({
                                        'path': file_path,
                                        'issue': 'unsafe_file_permissions',
                                        'severity': 'high',
                                        'description': f"File {file_path} has unsafe permissions (mode {oct(file_stat.st_mode & 0o777)})"
                                    })
                            except (OSError, IOError) as e:
                                log_warning(f"Error checking permissions for {file_path}: {e}")

        # Log issues found
        if issues:
            log_warning(f"Found {len(issues)} permission issues")

            # Record security event
            try:
                log_security_event(
                    event_type=AuditLog.EVENT_SECURITY_ISSUE,
                    description=f"Detected {len(issues)} permission issues",
                    severity='warning',
                    details={'issues': issues}
                )
            except Exception as e:
                log_error(f"Failed to record permission issues: {e}")

            # Track metric
            metrics.gauge('security.permission_issues', len(issues))

        return issues
    except Exception as e:
        log_error(f"Error detecting permission issues: {e}")
        return []


def get_security_anomalies(hours: int = 24) -> List[Dict[str, Any]]:
    """
    Detect security anomalies based on recent events.

    This function analyzes security events to identify unusual patterns
    that might indicate security threats or compromises.

    Args:
        hours: Number of hours to analyze

    Returns:
        List[Dict[str, Any]]: List of detected anomalies
    """
    anomalies = []
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Check for account lockouts
        lockout_counts = db.session.query(
            AuditLog.details['username'].label('username'),
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.event_type == AuditLog.EVENT_ACCOUNT_LOCKOUT,
            AuditLog.created_at >= cutoff
        ).group_by('username').having(
            func.count(AuditLog.id) > 1
        ).all()

        for username, count in lockout_counts:
            anomalies.append({
                'type': 'multiple_account_lockouts',
                'severity': 'high',
                'details': {
                    'username': username,
                    'count': count
                },
                'description': f"Account {username} has been locked {count} times in the past {hours} hours"
            })

        # Check for permission denied events
        permission_denied_count = db.session.query(
            AuditLog.user_id,
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.event_type == AuditLog.EVENT_PERMISSION_DENIED,
            AuditLog.created_at >= cutoff
        ).group_by(AuditLog.user_id).having(
            func.count(AuditLog.id) > 5
        ).all()

        for user_id, count in permission_denied_count:
            anomalies.append({
                'type': 'excessive_permission_denied',
                'severity': 'medium',
                'details': {
                    'user_id': user_id,
                    'count': count
                },
                'description': f"User ID {user_id} has had {count} permission denied events in the past {hours} hours"
            })

        # Check for file integrity violations
        integrity_status = get_last_integrity_status()
        if integrity_status and integrity_status.get('has_violations', False):
            violations = integrity_status.get('violations', [])
            critical_count = sum(1 for v in violations if v.get('severity') in ('high', 'critical'))

            if critical_count > 0:
                anomalies.append({
                    'type': 'file_integrity_violations',
                    'severity': 'critical',
                    'details': {
                        'total_violations': len(violations),
                        'critical_violations': critical_count,
                        'violations': violations[:5]  # Include up to 5 violations
                    },
                    'description': f"Found {len(violations)} file integrity violations, including {critical_count} critical violations"
                })

        # Check for unusual API access patterns (high volume in short time)
        api_access_counts = db.session.query(
            AuditLog.ip_address,
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.created_at >= datetime.now(timezone.utc) - timedelta(minutes=10),  # Last 10 minutes
            AuditLog.request_data.like('%/api/%')
        ).group_by(AuditLog.ip_address).having(
            func.count(AuditLog.id) > 200  # Threshold for unusual API access
        ).all()

        for ip, count in api_access_counts:
            anomalies.append({
                'type': 'unusual_api_activity',
                'severity': 'medium',
                'details': {
                    'ip_address': ip,
                    'count': count,
                    'timeframe': '10 minutes'
                },
                'description': f"Unusually high API activity from IP {ip}: {count} requests in 10 minutes"
            })

        # Other anomalies can be added here

        # Record metrics for detected anomalies
        if anomalies:
            metrics.gauge('security.anomalies_detected', len(anomalies))

            # Group by severity for specific metrics
            high_severity = sum(1 for a in anomalies if a.get('severity') == 'high')
            critical_severity = sum(1 for a in anomalies if a.get('severity') == 'critical')
            metrics.gauge('security.high_severity_anomalies', high_severity)
            metrics.gauge('security.critical_severity_anomalies', critical_severity)

            # Log security event for critical anomalies
            if critical_severity > 0:
                critical_anomalies = [a for a in anomalies if a.get('severity') == 'critical']
                try:
                    log_security_event(
                        event_type=AuditLog.EVENT_SECURITY_ANOMALY,
                        description=f"Detected {critical_severity} critical security anomalies",
                        severity='critical',
                        details={
                            'anomalies': [a['description'] for a in critical_anomalies]
                        }
                    )
                except Exception as e:
                    log_error(f"Failed to log critical anomalies: {e}")

        return anomalies
    except Exception as e:
        log_error(f"Error detecting security anomalies: {e}")
        return []


def detect_suspicious_activity(hours: int = 24) -> Dict[str, Any]:
    """
    Detect suspicious activities across the system for security scanning.

    This function integrates multiple security detection mechanisms to provide
    a comprehensive view of potential security incidents across the platform.
    It's designed to work with the security scanning pipeline in app.py.

    Args:
        hours: Number of hours to analyze

    Returns:
        Dict[str, Any]: Dictionary containing categorized suspicious activities
    """
    try:
        result = {
            'suspicious_ips': [],
            'anomalies': [],
            'integrity_violations': [],
            'suspicious_sessions': [],
            'permission_issues': [],
            'blocked_ips': []
        }

        # Get suspicious IPs with their details
        suspicious_ips = get_suspicious_ips(hours=hours)
        if suspicious_ips:
            # Filter to include only relevant information
            result['suspicious_ips'] = [{
                'ip': ip.get('ip'),
                'threat_score': ip.get('threat_score', 0),
                'count': ip.get('count', 0),
                'location': ip.get('geolocation', {}).get('location'),
                'is_blocked': ip.get('is_blocked', False),
                'targeted_users': ip.get('targeted_users', []),
                'latest_attempt': ip.get('latest_attempt')
            } for ip in suspicious_ips]

        # Get security anomalies
        anomalies = get_security_anomalies(hours=hours)
        if anomalies:
            result['anomalies'] = anomalies

        # Get file integrity status
        integrity_status = get_last_integrity_status()
        if integrity_status and integrity_status.get('has_violations'):
            result['integrity_violations'] = integrity_status.get('violations', [])

        # Get suspicious sessions
        suspicious_sessions = get_suspicious_sessions()
        if suspicious_sessions:
            result['suspicious_sessions'] = suspicious_sessions

        # Get permission issues
        permission_issues = detect_permission_issues()
        if permission_issues:
            result['permission_issues'] = permission_issues

        # Get blocked IPs
        blocked_ips = list(get_blocked_ips())
        if blocked_ips:
            result['blocked_ips'] = blocked_ips

        # Calculate overall threat score (0-100)
        threat_score = _calculate_overall_threat_score(result)
        result['threat_score'] = threat_score

        # Track metrics
        metrics.gauge('security.suspicious_activity_score', threat_score)

        # Log high threat situations
        if threat_score >= 75:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_THREAT_DETECTED,
                description=f"High threat level detected (score: {threat_score}/100)",
                severity='high',
                details={
                    'suspicious_ip_count': len(result['suspicious_ips']),
                    'anomaly_count': len(result['anomalies']),
                    'integrity_violation_count': len(result['integrity_violations']),
                    'suspicious_session_count': len(result['suspicious_sessions'])
                }
            )

        return result
    except Exception as e:
        log_error(f"Error detecting suspicious activity: {e}")
        return {
            'error': str(e),
            'threat_score': 0
        }


def _calculate_overall_threat_score(data: Dict[str, Any]) -> int:
    """
    Calculate an overall threat score based on detected suspicious activities.

    Args:
        data: Dictionary of suspicious activity data

    Returns:
        int: Overall threat score from 0-100
    """
    score = 0

    # Suspicious IPs contribute up to 25 points
    suspicious_ips = data.get('suspicious_ips', [])
    if suspicious_ips:
        # Count high threat IPs (threat score >= 75)
        high_threat_count = sum(1 for ip in suspicious_ips if ip.get('threat_score', 0) >= 75)

        if high_threat_count >= 3:
            score += 25
        elif high_threat_count >= 1:
            score += 15
        elif len(suspicious_ips) >= 5:
            score += 10
        elif len(suspicious_ips) > 0:
            score += 5

    # Security anomalies contribute up to 30 points
    anomalies = data.get('anomalies', [])
    if anomalies:
        # Count critical and high severity anomalies
        critical_count = sum(1 for a in anomalies if a.get('severity') == 'critical')
        high_count = sum(1 for a in anomalies if a.get('severity') == 'high')

        if critical_count >= 1:
            score += 30
        elif high_count >= 2:
            score += 20
        elif high_count >= 1:
            score += 15
        elif len(anomalies) > 0:
            score += 10

    # File integrity violations contribute up to 25 points
    violations = data.get('integrity_violations', [])
    if violations:
        # Count critical and high severity violations
        critical_count = sum(1 for v in violations if v.get('severity') in ('critical', 'high'))

        if critical_count >= 1:
            score += 25
        elif len(violations) >= 3:
            score += 15
        elif len(violations) > 0:
            score += 10

    # Suspicious sessions contribute up to 10 points
    suspicious_sessions = data.get('suspicious_sessions', [])
    if len(suspicious_sessions) >= 3:
        score += 10
    elif len(suspicious_sessions) > 0:
        score += 5

    # Permission issues contribute up to 10 points
    permission_issues = data.get('permission_issues', [])
    if len(permission_issues) >= 3:
        score += 10
    elif len(permission_issues) > 0:
        score += 5

    # Cap at 100
    return min(100, score)


# Helper functions

def _get_from_cache(key: str, as_int: bool = False) -> Any:
    """
    Get data from Redis cache.

    Args:
        key: Cache key
        as_int: Whether to convert result to int

    Returns:
        Any: Cached data or None if not found
    """
    try:
        redis_client = get_redis_client()
        if not redis_client:
            return None

        cached_data = redis_client.get(key)
        if not cached_data:
            return None

        if as_int:
            try:
                return int(cached_data)
            except (ValueError, TypeError):
                return None
        else:
            try:
                return json.loads(cached_data)
            except json.JSONDecodeError as e:
                log_error(f"Failed to load cached data for {key}: {e}")
                return None
    except Exception as e:
        log_error(f"Cache retrieval error for {key}: {e}")
        return None


def _set_in_cache(key: str, data: Any, ttl: int) -> bool:
    """
    Set data in Redis cache.

    Args:
        key: Cache key
        data: Data to cache
        ttl: Time-to-live in seconds

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        redis_client = get_redis_client()
        if not redis_client:
            return False

        if isinstance(data, (int, float, bool)):
            redis_client.setex(key, ttl, str(data))
        else:
            try:
                json_data = json.dumps(data)
                redis_client.setex(key, ttl, json_data)
            except (TypeError, ValueError) as e:
                log_error(f"Failed to serialize data for cache key {key}: {e}")
                return False
        return True
    except Exception as e:
        log_error(f"Cache storage error for {key}: {e}")
        return False


def _get_targeted_usernames(ip_address: str, cutoff: datetime) -> List[str]:
    """
    Get usernames targeted in failed login attempts.

    Args:
        ip_address: IP address to check
        cutoff: Cutoff datetime for events

    Returns:
        List[str]: List of usernames
    """
    try:
        # Query for failed login attempts details
        records = db.session.query(AuditLog.details).filter(
            AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
            AuditLog.ip_address == ip_address,
            AuditLog.created_at >= cutoff
        ).limit(10).all()

        # Extract usernames from details
        usernames = []
        for record in records:
            details = record[0]
            if isinstance(details, dict) and 'username' in details:
                username = details['username']
                if username and username not in usernames:
                    usernames.append(username)
            elif isinstance(details, str) and 'username' in details.lower():
                try:
                    details_dict = json.loads(details)
                    if 'username' in details_dict:
                        username = details_dict['username']
                        if username and username not in usernames:
                            usernames.append(username)
                except json.JSONDecodeError:
                    pass

        return usernames
    except Exception as e:
        log_error(f"Error getting targeted usernames for IP {ip_address}: {e}")
        return []


def _get_security_events_for_ip(ip_address: str, cutoff: datetime) -> Dict[str, int]:
    """
    Get security events by type for an IP address.

    Args:
        ip_address: IP address to check
        cutoff: Cutoff datetime for events

    Returns:
        Dict[str, int]: Map of event types to counts
    """
    try:
        # Query for security events by type
        events = db.session.query(
            AuditLog.event_type,
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.ip_address == ip_address,
            AuditLog.created_at >= cutoff
        ).group_by(AuditLog.event_type).all()

        return {event_type: count for event_type, count in events}
    except Exception as e:
        log_error(f"Error getting security events for IP {ip_address}: {e}")
        return {}


def _check_ip_reputation(ip_address: str) -> Optional[Dict[str, Any]]:
    """
    Check IP reputation using external service.

    Args:
        ip_address: IP address to check

    Returns:
        Optional[Dict[str, Any]]: Dictionary with reputation data or None if not available
    """
    if not has_app_context():
        return None

    # Try to get from cache first
    cache_key = f"ip_reputation:{ip_address}"
    cached_data = _get_from_cache(cache_key)
    if cached_data:
        return cached_data

    try:
        # Use configured IP reputation service
        ip_reputation_api = current_app.config.get('IP_REPUTATION_API', 'ipinfo')
        api_key = current_app.config.get('IP_REPUTATION_API_KEY', '')

        if ip_reputation_api == 'abuseipdb':
            headers = {
                'Key': api_key,
                'Accept': 'application/json',
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90
            }
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params=params,
                timeout=3
            )

            if response.status_code == 200:
                data = response.json().get('data', {})

                # Add a calculated threat score
                abuse_score = data.get('abuseConfidenceScore', 0)
                data['threat_score'] = abuse_score

                # Cache for 6 hours
                _set_in_cache(cache_key, data, 21600)
                return data

        elif ip_reputation_api == 'ipinfo':
            token = f"?token={api_key}" if api_key else ""
            response = requests.get(
                f"https://ipinfo.io/{ip_address}/json{token}",
                timeout=3
            )

            if response.status_code == 200:
                data = response.json()

                # Add default threat score
                data['threat_score'] = 0

                # Check abuse flags
                if 'abuse' in data:
                    abuse_data = data['abuse']
                    if abuse_data.get('blocklisted', False):
                        data['threat_score'] = 80

                # Cache for 6 hours
                _set_in_cache(cache_key, data, 21600)
                return data

        return None
    except Exception as e:
        log_error(f"Error checking IP reputation for {ip_address}: {e}")
        return None


def _get_ip_geolocation(ip_address: str) -> Dict[str, Any]:
    """
    Get geolocation information for an IP address.

    Args:
        ip_address: IP address to look up

    Returns:
        Dict[str, Any]: Dictionary with geolocation data or empty dict if not available
    """
    if not ip_address:
        return {}

    # Validate IP format before making external requests
    if not is_valid_ip(ip_address):
        log_warning(f"Invalid IP format for geolocation lookup: {ip_address}")
        return {}

    # Check cache first
    cache_key = f"ip_geolocation:{ip_address}"
    cached_data = _get_from_cache(cache_key)
    if cached_data:
        return cached_data

    # Only perform lookup if configuration allows
    if not has_app_context() or not current_app.config.get('GEOLOCATION_ENABLED', False):
        return {}

    # Implement rate limiting protection
    redis_client = get_redis_client()
    if redis_client:
        rate_limit_key = "geolocation_api_calls"
        rate_window = 60  # 1 minute
        rate_limit = current_app.config.get('GEOLOCATION_RATE_LIMIT', 60)  # Default: 60 calls per minute

        # Check if we're over the rate limit
        current_count = redis_client.get(rate_limit_key)
        if current_count and int(current_count) >= rate_limit:
            log_warning(f"Geolocation API rate limit reached ({rate_limit}/{rate_window}s)")
            return {}

        # Increment counter
        pipe = redis_client.pipeline()
        pipe.incr(rate_limit_key)
        pipe.expire(rate_limit_key, rate_window)
        pipe.execute()

    try:
        # Use configured geolocation service
        geolocation_api = current_app.config.get('GEOLOCATION_API', 'ipapi')

        if geolocation_api == 'ipapi':
            # Prefer HTTPS if configured/available
            use_https = current_app.config.get('GEOLOCATION_USE_HTTPS', False)
            protocol = "https" if use_https else "http"
            api_key = current_app.config.get('IPAPI_KEY', '')

            # Add API key if available (for pro accounts that support HTTPS)
            params = {'fields': 'country,countryCode,region,regionName,city,isp,org,as'}
            if api_key:
                params['key'] = api_key

            response = requests.get(
                f"{protocol}://ip-api.com/json/{ip_address}",
                params=params,
                timeout=3  # Increased timeout for reliability
            )

            if response.status_code == 200:
                data = response.json()

                # Format location string for easier use
                if 'city' in data and 'country' in data:
                    data['location'] = f"{data['city']}, {data['country']}"

                # Cache for 24 hours
                _set_in_cache(cache_key, data, 86400)
                return data

        elif geolocation_api == 'ipinfo':
            # Support for ipinfo.io service
            api_key = current_app.config.get('IPINFO_API_KEY', '')
            token_param = f"?token={api_key}" if api_key else ""

            response = requests.get(
                f"https://ipinfo.io/{ip_address}/json{token_param}",
                timeout=3
            )

            if response.status_code == 200:
                data = response.json()

                # Format location string for easier use
                if 'city' in data and 'country' in data:
                    data['location'] = f"{data['city']}, {data['country']}"

                # Cache for 24 hours
                _set_in_cache(cache_key, data, 86400)
                return data

        return {}  # Default empty response

    except requests.exceptions.Timeout:
        log_warning(f"Timeout retrieving geolocation for IP {ip_address}")
        return {}
    except requests.exceptions.ConnectionError:
        log_error(f"Connection error retrieving geolocation for IP {ip_address}")
        return {}
    except requests.exceptions.RequestException as e:
        log_error(f"Request error retrieving geolocation for IP {ip_address}: {e}")
        return {}
    except json.JSONDecodeError:
        log_error(f"Invalid JSON response from geolocation API for IP {ip_address}")
        return {}
    except Exception as e:
        log_error(f"Error getting geolocation for IP {ip_address}: {e}")
        return {}


def _calculate_threat_score(ip_address: str, failed_login_count: int, security_events: Dict[str, int]) -> int:
    """
    Calculate a threat score for an IP address based on various factors.

    Args:
        ip_address: The IP address to analyze
        failed_login_count: Number of failed login attempts
        security_events: Dictionary of security events by type

    Returns:
        int: Threat score from 0-100 where higher is more suspicious
    """
    try:
        score = 0

        # Failed logins contribute to score (max 30 points)
        if failed_login_count >= 20:
            score += 30
        elif failed_login_count >= 10:
            score += 20
        elif failed_login_count >= 5:
            score += 10

        # Security events contribute to score (max 40 points)
        breach_events = sum(count for event_type, count in security_events.items()
                           if any(x in event_type for x in ['breach', 'attack', 'violation', 'tamper']))

        if breach_events >= 5:
            score += 40
        elif breach_events >= 2:
            score += 30
        elif breach_events >= 1:
            score += 20

        # Permission denied events are concerning (max 20 points)
        permission_denied = security_events.get('permission_denied', 0)
        if permission_denied >= 10:
            score += 20
        elif permission_denied >= 5:
            score += 15
        elif permission_denied >= 1:
            score += 10

        # Rate limit exceeded events suggest automated tools (max 10 points)
        rate_limit_events = security_events.get('rate_limit_exceeded', 0)
        if rate_limit_events >= 3:
            score += 10
        elif rate_limit_events >= 1:
            score += 5

        # Check if IP is in a blacklist (not implemented here)
        # This would add another 20 points

        # Cap score at 100
        return min(100, score)
    except Exception as e:
        log_error(f"Error calculating threat score for IP {ip_address}: {e}")
        return 0


def _should_check_db_session() -> bool:
    """
    Check if we should use database for session info.

    Returns:
        bool: True if database should be checked for session details
    """
    if has_app_context():
        return current_app.config.get('USE_DB_SESSIONS', True)
    else:
        from .cs_constants import SECURITY_CONFIG
        return SECURITY_CONFIG.get('USE_DB_SESSIONS', True)


def cache_ttl(ttl: int):
    """
    Decorator that caches function results with a TTL.

    Args:
        ttl: Cache TTL in seconds

    Returns:
        Decorator function
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Generate a cache key based on function name and arguments
            cache_key = f"{func.__name__}:{str(args)}:{str(kwargs)}".replace(' ', '')

            # Try to get from cache
            cached_result = _get_from_cache(cache_key)
            if cached_result is not None:
                return cached_result

            # Not in cache, call the function
            result = func(*args, **kwargs)

            # Store in cache
            _set_in_cache(cache_key, result, ttl)

            return result
        return wrapper
    return decorator


@cache_ttl(3600)
def get_threat_summary() -> Dict[str, Any]:
    """
    Get summary of current security threats.

    This generates an overview of the system's current security status
    including suspicious IPs, failed authentication attempts, and more.

    Returns:
        Dict[str, Any]: Summary of security threat information
    """
    try:
        # Collect threat metrics
        hours = 24  # Last 24 hours
        suspicious_ips = get_suspicious_ips(hours=hours)

        # Basic summary info
        summary = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'suspicious_ip_count': len(suspicious_ips),
            'failed_logins_24h': get_failed_login_count(hours=hours),
            'account_lockouts_24h': get_account_lockout_count(hours=hours),
            'blocked_ip_count': len(get_blocked_ips())
        }

        # Get high threat IPs (threshold 75+)
        high_threat_ips = [ip for ip in suspicious_ips if ip.get('threat_score', 0) >= 75]
        if high_threat_ips:
            summary['high_threat_ips'] = high_threat_ips[:5]  # Top 5

        # Get security anomalies
        anomalies = get_security_anomalies(hours=hours)
        if anomalies:
            summary['anomalies'] = anomalies[:5]  # Top 5

        # Add file integrity status
        integrity_status = get_last_integrity_status()
        if integrity_status:
            summary['file_integrity'] = {
                'status': 'compromised' if integrity_status.get('has_violations') else 'ok',
                'last_check': integrity_status.get('last_check')
            }

        # Add suspicious sessions info
        suspicious_sessions = get_suspicious_sessions()
        if suspicious_sessions:
            summary['suspicious_sessions'] = len(suspicious_sessions)

        # Calculate overall threat level
        threat_level = 'low'
        if (len(high_threat_ips) > 0 or
            summary.get('failed_logins_24h', 0) > 50 or
            len(anomalies) > 0 or
            integrity_status.get('has_violations')):
            threat_level = 'medium'

        if (len(high_threat_ips) > 2 or
            any(a.get('severity') == 'critical' for a in anomalies) or
            integrity_status.get('has_violations') and
            any(v.get('severity') == 'critical' for v in integrity_status.get('violations', []))):
            threat_level = 'high'

        summary['threat_level'] = threat_level

        return summary
    except Exception as e:
        log_error(f"Error generating threat summary: {e}")
        return {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': 'Failed to generate threat summary',
            'threat_level': 'unknown'
        }
