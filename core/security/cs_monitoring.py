
import os
import requests
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
from core.utils import log_error, log_warning, log_info
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

    try:
        pass  # Add the intended logic here
    except Exception as e:
        log_error(f"An error occurred: {e}")
        # Use cached results if available
        redis_client = get_redis_client()
        cache_key = f"suspicious_ips:{hours}:{min_attempts}"

        if redis_client:
            cached_data = redis_client.get(cache_key)
            if cached_data:
                try:
                    import json
                    return json.loads(cached_data)
                except Exception as e:
                    log_error(f"Failed to load cached suspicious IPs: {e}")

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

            # Add targeted usernames
            targeted_users = db.session.query(AuditLog.details).filter(
                AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
                AuditLog.ip_address == ip,
                AuditLog.created_at >= cutoff
            ).limit(5).all()

            user_details = []
            for detail in targeted_users:
                if detail and detail[0]:
                    user_details.append(detail[0])

            ip_data['targeted_users'] = user_details
            result.append(ip_data)

        # Cache the results for 5 minutes
        if redis_client:
            try:
                import json
                redis_client.setex(cache_key, 300, json.dumps(result))
            except Exception as e:
                log_error(f"Failed to cache suspicious IPs: {e}")

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
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Use cached results if available
        redis_client = get_redis_client()
        cache_key = f"failed_login_count:{hours}"

        if redis_client:
            cached_count = redis_client.get(cache_key)
            if cached_count:
                try:
                    return int(cached_count)
                except (ValueError, TypeError):
                    pass

        # Query database for count
        count = db.session.query(AuditLog).filter(
            AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
            AuditLog.created_at >= cutoff
        ).count()

        # Cache the result for 5 minutes
        if redis_client:
            redis_client.setex(cache_key, 300, str(count))

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
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Use cached results if available
        redis_client = get_redis_client()
        cache_key = f"account_lockout_count:{hours}"

        if redis_client:
            cached_count = redis_client.get(cache_key)
            if cached_count:
                try:
                    return int(cached_count)
                except (ValueError, TypeError):
                    pass

        # Query database for count
        count = db.session.query(AuditLog).filter(
            AuditLog.event_type == AuditLog.EVENT_ACCOUNT_LOCKOUT,
            AuditLog.created_at >= cutoff
        ).count()

        # Cache the result for 5 minutes
        if redis_client:
            redis_client.setex(cache_key, 300, str(count))

        # Track metric
        metrics.gauge('security.account_lockouts', count)

        return count
    except SQLAlchemyError as e:
        log_error(f"Database error in get_account_lockout_count: {e}")
        return 0


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

            if cursor == b'0' or cursor == 0:
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
            for network_str in SECURITY_CONFIG.get('KNOWN_MALICIOUS_NETWORKS', []):
                if ip_obj in ip_network(network_str):
                    log_warning(f"IP {ip_address} found in known malicious network {network_str}")
                    # Track metric
                    metrics.increment('security.malicious_network_access')
                    return True
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
                    # Track metric on cache hit for suspicious IP
                    metrics.increment('security.suspicious_ip_cache_hit')
                return is_suspicious

        # Check for failed login attempts in audit log
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        failed_count = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
            AuditLog.ip_address == ip_address,
            AuditLog.created_at >= cutoff
        ).scalar()

        if failed_count >= threshold:
            # Cache the result for 1 hour
            if redis_client:
                redis_client.setex(f"suspicious_ip:{ip_address}", 3600, "True")

            # Track metric
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
        ).scalar()

        if breach_attempts > 0:
            # Cache the result for 1 hour
            if redis_client:
                redis_client.setex(f"suspicious_ip:{ip_address}", 3600, "True")

            # Track metric
            metrics.increment('security.breach_attempt_detected')
            return True

    except SQLAlchemyError as e:
        log_error(f"Database error when checking suspicious IP: {ip_address}: {e}")
        return False

    # Check against external IP reputation service if configured
    if has_app_context() and current_app.config.get('IP_REPUTATION_CHECK_ENABLED'):
        result = _check_ip_reputation(ip_address)
        if result:
            # Cache the result for 6 hours
            if redis_client:
                redis_client.setex(f"suspicious_ip:{ip_address}", 21600, "True")

            # Track metric
            metrics.increment('security.ip_reputation_detected')
            return True

    # Cache negative result for 30 minutes
    if redis_client:
        redis_client.setex(f"suspicious_ip:{ip_address}", 1800, "False")

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
    try:
        if not ip_address or not is_valid_ip(ip_address):
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

        # Convert to string for storage
        import json
        block_str = json.dumps(block_data)

        # Set with expiry
        redis_client.setex(
            f"blocked_ip:{ip_address}",
            duration,
            block_str
        )

        # Log the event with appropriate severity
        log_warning(f"Blocked IP {ip_address} for {duration} seconds. Reason: {reason}")

        # Record security event
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_COUNTERMEASURE,
            description=f"Blocked IP address: {ip_address}",
            severity='warning',
            ip_address=ip_address,
            details=f"Duration: {duration} seconds, Reason: {reason}"
        )

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
    try:
        if not ip_address:
            return False

        redis_client = get_redis_client()
        if not redis_client:
            log_warning("Redis unavailable, cannot check if IP is blocked")
            return False

        # Check if key exists
        return redis_client.exists(f"blocked_ip:{ip_address}") > 0
    except Exception as e:
        log_error(f"Error checking if IP {ip_address} is blocked: {e}")
        return False


def unblock_ip(ip_address: str) -> bool:
    """
    Remove a block on an IP address.

    Args:
        ip_address: IP address to unblock

    Returns:
        bool: True if successfully unblocked or wasn't blocked, False on error
    """
    try:
        if not ip_address:
            return False

        redis_client = get_redis_client()
        if not redis_client:
            log_warning(f"Redis unavailable, unable to unblock IP: {ip_address}")
            return False

        # Remove the block
        redis_client.delete(f"blocked_ip:{ip_address}")

        # Log the event
        log_info(f"Unblocked IP: {ip_address}")

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
                ip = key.decode('utf-8').split(':', 1)[1]
                blocked_ips.add(ip)

            if cursor == '0' or cursor == b'0' or cursor == 0:
                break

        # Track metric
        metrics.gauge('security.blocked_ips', len(blocked_ips))

        return blocked_ips
    except Exception as e:
        log_error(f"Error retrieving blocked IPs: {e}")
        if not ip_address or not is_valid_ip(ip_address):
            log_error(f"Invalid IP address format: {ip_address}")
            return False


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
    redis_client = get_redis_client()
    cache_key = f"ip_geolocation:{ip_address}"

    if redis_client:
        cached_data = redis_client.get(cache_key)
        if cached_data:
            try:
                import json
                return json.loads(cached_data)
            except Exception as e:
                log_error(f"Failed to parse cached geolocation data: {e}")

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
                if redis_client and data.get('country'):
                    redis_client.setex(cache_key, 86400, response.text)
                return data

        return {}  # Default empty response

    except Exception as e:
        log_error(f"Error getting geolocation for IP {ip_address}: {e}")
        return {}


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
        critical_dirs = [
            os.path.join(app_root, 'config'),
            os.path.join(app_root, 'instance'),
            os.path.join(app_root, 'core'),
            os.path.join(app_root, 'logs')
        ]

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
            except (ImportError, KeyError):
                # Skip this check if we can't get user/group info
                pass

        return issues
    except Exception as e:
        log_error(f"Error detecting permission issues: {e}")
        return []

def _check_ip_reputation(ip_address: str) -> Optional[Dict[str, Any]]:
    """
    Check IP reputation using external service.

    Args:
        ip_address: IP address to check

    Returns:
        Optional[Dict[str, Any]]: Dictionary with reputation data or None if not available
    """
    try:
        # Use configured IP reputation service
        ip_reputation_api = current_app.config.get('IP_REPUTATION_API', 'ipinfo')

        if ip_reputation_api == 'ipinfo':
            response = requests.get(
                f"https://ipinfo.io/{ip_address}/json",
                timeout=2  # Short timeout to avoid blocking
            )

            if response.status_code == 200:
                return response.json()

        return None  # Default empty response

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
    redis_client = get_redis_client()
    cache_key = f"ip_geolocation:{ip_address}"

    if redis_client:
        cached_data = redis_client.get(cache_key)
        if cached_data:
            try:
                import json
                return json.loads(cached_data)
            except Exception as e:
                log_error(f"Failed to parse cached geolocation data: {e}")

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
                if redis_client and data.get('country'):
                    redis_client.setex(cache_key, 86400, response.text)
                return data

        return {}  # Default empty response

    except Exception as e:
        log_error(f"Error getting geolocation for IP {ip_address}: {e}")
        return {}

