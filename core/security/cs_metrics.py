
import time
import requests
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple, Union, Set, TypeVar, cast

# Flask imports
from flask import current_app, request, g, has_request_context, session, has_app_context

# Internal imports
from models.security_incident import SecurityIncident
from extensions import db, metrics
from extensions import get_redis_client
from core.utils import log_error
from .cs_file_integrity import check_config_integrity, check_critical_file_integrity
from .cs_monitoring import (
    get_suspicious_ips, get_failed_login_count, get_account_lockout_count,
    get_active_session_count, get_blocked_ips
)

# Type definitions
SecurityMetrics = Dict[str, Any]


def get_security_metrics(hours: int = 24) -> SecurityMetrics:
    """
    Collect comprehensive security metrics.

    This function compiles a complete picture of the system's security status
    by gathering metrics about failed logins, suspicious IPs, account lockouts,
    session counts, and file integrity information.

    Args:
        hours: Number of hours to look back for metrics

    Returns:
        Dict[str, Any]: Dictionary of security metrics containing:
            - failed_logins_24h: Count of failed login attempts
            - account_lockouts_24h: Count of account lockouts
            - active_sessions: Number of active user sessions
            - suspicious_ips: List of suspicious IP addresses with details
            - config_integrity: Boolean indicating if configuration files are unmodified
            - file_integrity: Boolean indicating if critical files are unmodified
            - incidents_active: Count of active security incidents
            - permission_issues: Count of permission-related issues
            - risk_score: Calculated security risk score (1-10)
            - timestamp: Unix timestamp when metrics were collected
            - period_hours: Number of hours metrics cover
    """
    try:
        # Cache key for Redis
        cache_key = f"security_metrics:{hours}"
        redis_client = get_redis_client()

        # Check cache first
        if redis_client:
            cached_data = redis_client.get(cache_key)
            if cached_data:
                try:
                    import json
                    return json.loads(cached_data)
                except Exception as e:
                    log_error(f"Failed to parse cached security metrics: {e}")

        # Start with basic metrics
        security_data: SecurityMetrics = {
            'failed_logins_24h': get_failed_login_count(hours=hours),
            'account_lockouts_24h': get_account_lockout_count(hours=hours),
            'active_sessions': get_active_session_count(),
            'suspicious_ips': get_suspicious_ips(hours=hours),
            'config_integrity': True,
            'file_integrity': True,
            'incidents_active': 0,
            'permission_issues': 0,
            'last_checked': datetime.now(timezone.utc).isoformat(),
            'timestamp': int(time.time()),
            'period_hours': hours
        }

        # Only check integrity in application context
        if has_app_context():
            security_data['config_integrity'] = check_config_integrity()
            integrity_result, changes = check_critical_file_integrity()
            security_data['file_integrity'] = integrity_result
            security_data['integrity_changes'] = changes

            try:
                # Count active security incidents
                security_data['incidents_active'] = SecurityIncident.query.filter(
                    SecurityIncident.status.in_(['open', 'investigating'])
                ).count()

                # Get permission issues
                from core.utils import detect_permission_issues
                permission_issues = detect_permission_issues()
                security_data['permission_issues'] = len(permission_issues)
                security_data['permission_details'] = permission_issues[:10]  # First 10 issues

                # Blocked IPs
                blocked_ips = list(get_blocked_ips())
                security_data['blocked_ips_count'] = len(blocked_ips)
                security_data['blocked_ips'] = blocked_ips[:20]  # Limit to first 20 for performance
            except Exception as e:
                log_error(f"Error collecting additional security metrics: {e}")

        # Calculate risk score and include security recommendations
        security_data['risk_score'] = calculate_risk_score(security_data)
        security_data['security_recommendations'] = generate_security_recommendations(security_data)

        # Cache the metrics for 5 minutes
        if redis_client:
            try:
                import json
                redis_client.setex(cache_key, 300, json.dumps(security_data))
            except Exception as e:
                log_error(f"Failed to cache security metrics: {e}")

        # Track metrics for monitoring
        metrics.gauge('security.risk_score', security_data['risk_score'])
        metrics.gauge('security.suspicious_ips', len(security_data.get('suspicious_ips', [])))

        return security_data
    except Exception as e:
        log_error(f"Error collecting security metrics: {e}")
        # Return minimal data on error to ensure API doesn't break
        return {
            'failed_logins_24h': 0,
            'suspicious_ips': [],
            'risk_score': 5,  # Medium risk when metrics can't be collected
            'last_checked': datetime.now(timezone.utc).isoformat(),
            'error': str(e),
            'timestamp': int(time.time()),
            'period_hours': hours
        }


def calculate_risk_score(metrics_data: SecurityMetrics) -> int:
    """
    Calculate a security risk score based on security metrics.

    This function analyzes various security indicators to produce a risk score
    from 1 (lowest risk) to 10 (highest risk).

    Args:
        metrics_data: Dictionary of security metrics

    Returns:
        int: Risk score from 1-10 (10 being highest risk)
    """
    # Start with a baseline risk of 1
    risk_score = 1

    # Failed logins increase risk
    failed_logins = metrics_data.get('failed_logins_24h', 0)
    if failed_logins > 100:
        risk_score += 3
    elif failed_logins > 50:
        risk_score += 2
    elif failed_logins > 20:
        risk_score += 1

    # Account lockouts are a stronger risk indicator
    lockouts = metrics_data.get('account_lockouts_24h', 0)
    if lockouts > 10:
        risk_score += 3
    elif lockouts > 5:
        risk_score += 2
    elif lockouts > 0:
        risk_score += 1

    # Suspicious IPs indicate potential attacks
    suspicious_ips_count = len(metrics_data.get('suspicious_ips', []))
    if suspicious_ips_count > 10:
        risk_score += 2
    elif suspicious_ips_count > 0:
        risk_score += 1

    # File integrity issues are critical
    if not metrics_data.get('file_integrity', True):
        risk_score += 3

    # Configuration integrity issues are critical
    if not metrics_data.get('config_integrity', True):
        risk_score += 3

    # Active security incidents
    incidents = metrics_data.get('incidents_active', 0)
    if incidents > 0:
        risk_score += min(3, incidents)  # Add up to 3 points

    # Permission issues could indicate misconfiguration or tampering
    permission_issues = metrics_data.get('permission_issues', 0)
    if permission_issues > 10:
        risk_score += 2
    elif permission_issues > 0:
        risk_score += 1

    # Cap the risk score at 10
    return min(10, risk_score)


def generate_security_recommendations(metrics_data: SecurityMetrics) -> List[Dict[str, str]]:
    """
    Generate security recommendations based on security metrics.

    This function analyzes security metrics and provides actionable
    recommendations for improving security posture.

    Args:
        metrics_data: Dictionary of security metrics

    Returns:
        List[Dict[str, str]]: List of recommendations with title and description
    """
    recommendations = []

    # Check failed logins
    failed_logins = metrics_data.get('failed_logins_24h', 0)
    if failed_logins > 20:
        recommendations.append({
            'priority': 'high' if failed_logins > 50 else 'medium',
            'title': 'High number of failed login attempts',
            'description': f'There have been {failed_logins} failed login attempts in the past 24 hours. Consider implementing additional authentication protections.'
        })

    # Check account lockouts
    lockouts = metrics_data.get('account_lockouts_24h', 0)
    if lockouts > 5:
        recommendations.append({
            'priority': 'high',
            'title': 'Unusual number of account lockouts',
            'description': f'There have been {lockouts} account lockouts in the past 24 hours, which may indicate a brute force attack.'
        })

    # Check file integrity
    if not metrics_data.get('file_integrity', True):
        integrity_changes = metrics_data.get('integrity_changes', [])
        critical_changes = sum(1 for change in integrity_changes if change.get('severity') in ('high', 'critical'))

        recommendations.append({
            'priority': 'critical',
            'title': 'File integrity violation detected',
            'description': f'There are {len(integrity_changes)} file integrity issues detected, including {critical_changes} critical changes. Review the changes immediately.'
        })

    # Check configuration integrity
    if not metrics_data.get('config_integrity', True):
        recommendations.append({
            'priority': 'critical',
            'title': 'Configuration integrity violation',
            'description': 'Configuration file changes detected. This could indicate unauthorized modifications to system configuration.'
        })

    # Check for suspicious IPs
    suspicious_ips = metrics_data.get('suspicious_ips', [])
    if suspicious_ips:
        recommendations.append({
            'priority': 'high' if len(suspicious_ips) > 5 else 'medium',
            'title': 'Suspicious IP addresses detected',
            'description': f'{len(suspicious_ips)} suspicious IP addresses have been identified. Consider implementing IP blocking or rate limiting.'
        })

    # Check for active incidents
    incidents = metrics_data.get('incidents_active', 0)
    if incidents > 0:
        recommendations.append({
            'priority': 'high',
            'title': 'Unresolved security incidents',
            'description': f'There are {incidents} active security incidents that require attention.'
        })

    # Add default recommendation if nothing else is found
    if not recommendations:
        recommendations.append({
            'priority': 'low',
            'title': 'Regular security review',
            'description': 'No immediate security issues detected. Continue with regular security monitoring and reviews.'
        })

    return recommendations


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
