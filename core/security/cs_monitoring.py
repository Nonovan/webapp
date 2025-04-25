"""
Security monitoring functionality for the Cloud Infrastructure Platform.

This module provides security monitoring capabilities including suspicious IP detection,
login failure tracking, session monitoring, and security event analytics. These
functions support real-time security detection and response.
"""

import os
import json
import requests
import functools
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from typing import List, Dict, Any, Optional, Tuple, Union, Set, TypeVar, cast

# SQLAlchemy imports
from sqlalchemy import func, desc, or_, and_
from sqlalchemy.exc import SQLAlchemyError

# Flask imports
from flask import current_app, request, g, has_request_context, session, has_app_context

# Internal imports
from extensions import db, metrics
from extensions import get_redis_client
from .cs_audit import log_security_event
from .cs_authentication import is_valid_ip
from .cs_constants import SECURITY_CONFIG
from core.utils import log_error, log_warning, log_info, log_debug
from models.audit_log import AuditLog


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

            result.append(ip_data)

        # Cache the results for 5 minutes
        _set_in_cache(cache_key, result, 300)

        # Track metrics
        metrics.gauge('security.suspicious_ips', len(result))

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
            AuditLog.created_at >= cutoff,
            AuditLog.event_type.startswith('security_')
        ).group_by(AuditLog.event_type).all()

        # Convert to dictionary
        result = {event_type: count for event_type, count in events}

        # Cache the results for 5 minutes
        _set_in_cache(cache_key, result, 300)

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
            ip_obj = ip_address(ip_address)
            malicious_networks = SECURITY_CONFIG.get('KNOWN_MALICIOUS_NETWORKS', [])

            for network_str in malicious_networks:
                try:
                    if ip_obj in ip_network(network_str):
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
                is_suspicious = cached_result.decode() == "True"
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
                AuditLog.EVENT_RATE_LIMIT_EXCEEDED
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
                    'expiry': block_data['expiry']
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

        # Parse and return the block info
        return json.loads(block_data)
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

                    # Extract IP from key
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

        # Other anomalies can be added here

        # Record metrics for detected anomalies
        if anomalies:
            metrics.gauge('security.anomalies_detected', len(anomalies))

            # Group by severity for specific metrics
            high_severity = sum(1 for a in anomalies if a.get('severity') == 'high')
            metrics.gauge('security.high_severity_anomalies', high_severity)

        return anomalies
    except Exception as e:
        log_error(f"Error detecting security anomalies: {e}")
        return []


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
            except Exception as e:
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
                redis_client.setex(key, ttl, json.dumps(data))
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
            AuditLog.created_at >= cutoff,
            AuditLog.event_type.like('security_%')
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

    # Check cache first
    cache_key = f"ip_geolocation:{ip_address}"
    cached_data = _get_from_cache(cache_key)
    if cached_data:
        return cached_data

    try:
        # Only perform lookup if configuration allows
        if not has_app_context() or not current_app.config.get('GEOLOCATION_ENABLED', False):
            return {}

        # Use configured geolocation service
        geolocation_api = current_app.config.get('GEOLOCATION_API', 'ipapi')

        if geolocation_api == 'ipapi':
            # Use free ip-api.com service
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}",
                params={'fields': 'country,countryCode,region,regionName,city,isp,org,as'},
                timeout=2  # Short timeout to avoid blocking
            )

            if response.status_code == 200:
                data = response.json()
                # Cache for 24 hours
                _set_in_cache(cache_key, data, 86400)
                return data

        return {}  # Default empty response
    except Exception as e:
        log_error(f"Error getting geolocation for IP {ip_address}: {e}")
        return {}


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
