"""
Security metrics collection and analysis for the Cloud Infrastructure Platform.

This module provides functionality for collecting, analyzing, and reporting security
metrics across the platform. It gathers data about system security status, calculates
risk scores, and generates actionable security recommendations.
"""

import json
import time
import requests
from datetime import datetime, timedelta, timezone
from sqlalchemy.sql import func
from typing import List, Dict, Any, Optional, Tuple, Union, Set, TypeVar, cast

# Flask imports
from flask import current_app, request, g, has_request_context, session, has_app_context, Flask

# Internal imports
from models.security import SecurityIncident
from extensions import db, metrics
from extensions import get_redis_client
from .cs_constants import SECURITY_CONFIG
from .cs_file_integrity import check_config_integrity, check_critical_file_integrity
from .cs_audit import log_security_event, log_error, log_warning, log_info, log_debug
from .cs_monitoring import (
    get_suspicious_ips, get_failed_login_count, get_account_lockout_count,
    get_active_session_count, get_blocked_ips, get_security_anomalies,
    get_security_event_distribution, detect_permission_issues
)

# Type definitions
SecurityMetrics = Dict[str, Any]
SecurityRecommendation = Dict[str, str]


def setup_security_metrics(app: Flask) -> bool:
    """
    Initialize security metrics collection for the Flask application.

    This function sets up security-related metrics collectors including risk scores,
    suspicious activity tracking, and integrity monitoring.

    Args:
        app: Flask application instance

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Register metrics
        with app.app_context():
            # Risk score gauge
            metrics.gauge(
                'security.risk_score_gauge',
                'Current security risk score (1-10)',
                labels={
                    'environment': lambda: app.config.get('ENVIRONMENT', 'production')
                }
            )

            # Security events counter
            metrics.counter(
                'security.events_total',
                'Total security events by type and severity',
                labels={
                    'event_type': lambda: g.get('security_event_type', 'unknown'),
                    'severity': lambda: g.get('security_event_severity', 'info')
                }
            )

            # File integrity metrics
            metrics.gauge(
                'security.file_integrity_status',
                'File integrity check status (1=ok, 0=violation)',
                labels={
                    'check_type': lambda: g.get('integrity_check_type', 'critical')
                }
            )

            # Suspicious IP tracking
            metrics.gauge(
                'security.suspicious_ips_count',
                'Number of suspicious IP addresses detected',
                labels={
                    'time_window': lambda: g.get('time_window', '24h')
                }
            )

            # Schedule daily risk score updates if using APScheduler
            if 'scheduler' in app.extensions:
                scheduler = app.extensions['scheduler']
                scheduler.add_job(
                    'update_daily_risk_score',
                    update_daily_risk_score,
                    trigger='cron',
                    hour=0,
                    minute=5,  # Run at 00:05 every day
                    id='daily_risk_score_update'
                )
                log_info("Scheduled daily risk score update job")

            # Log setup completion
            log_info("Security metrics setup completed successfully")
            metrics.increment('security.metrics_initialized')
            return True

    except Exception as e:
        log_error(f"Failed to set up security metrics: {e}")
        return False


def setup_auth_metrics(app: Flask) -> bool:
    """
    Initialize authentication metrics collection for the Flask application.

    This function sets up authentication-related metrics collectors including
    login attempts, MFA usage, and session tracking.

    Args:
        app: Flask application instance

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Register metrics
        with app.app_context():
            # Authentication attempt counter
            metrics.counter(
                'auth.attempts_total',
                'Authentication attempts (success/failure)',
                labels={
                    'result': lambda: g.get('auth_result', 'unknown'),
                    'method': lambda: g.get('auth_method', 'password')
                }
            )

            # Login failure counter
            metrics.counter(
                'auth.failures_total',
                'Failed login attempts by reason',
                labels={
                    'reason': lambda: g.get('auth_failure_reason', 'invalid_credentials'),
                    'with_valid_username': lambda: g.get('valid_username', False)
                }
            )

            # MFA usage metrics
            metrics.counter(
                'auth.mfa_attempts_total',
                'Multi-factor authentication attempts',
                labels={
                    'method': lambda: g.get('mfa_method', 'unknown'),
                    'success': lambda: g.get('mfa_success', False)
                }
            )

            # Session metrics
            metrics.gauge(
                'auth.active_sessions',
                'Number of active user sessions',
                labels={
                    'session_type': lambda: g.get('session_type', 'standard')
                }
            )

            # Account lockout tracking
            metrics.counter(
                'auth.account_lockouts',
                'Account lockout events',
                labels={
                    'reason': lambda: g.get('lockout_reason', 'failed_attempts')
                }
            )

            # Hook into request cycle for auth metrics
            @app.before_request
            def track_session_metrics():
                if has_request_context() and hasattr(session, '__contains__') and 'user_id' in session:
                    metrics.increment('auth.authenticated_requests')

            log_info("Authentication metrics setup completed successfully")
            metrics.increment('auth.metrics_initialized')
            return True

    except Exception as e:
        log_error(f"Failed to set up authentication metrics: {e}")
        return False

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
        cached_data = _get_cached_metrics(redis_client, cache_key)
        if cached_data:
            return cached_data

        # Start with basic metrics
        security_data: SecurityMetrics = {
            'failed_logins_24h': get_failed_login_count(hours=hours),
            'account_lockouts_24h': get_account_lockout_count(hours=hours),
            'active_sessions': get_active_session_count(),
            'suspicious_ips': get_suspicious_ips(hours=hours),
            'config_integrity': True,
            'file_integrity': True,
            'security_events': get_security_event_distribution(hours=hours),
            'incidents_active': 0,
            'permission_issues': 0,
            'last_checked': datetime.now(timezone.utc).isoformat(),
            'timestamp': int(time.time()),
            'period_hours': hours
        }

        # Collect advanced metrics when in application context
        if has_app_context():
            _collect_advanced_metrics(security_data, hours)

        # Calculate risk score and include security recommendations
        security_data['risk_score'] = calculate_risk_score(security_data)
        security_data['security_recommendations'] = generate_security_recommendations(security_data)

        # Track metrics for monitoring
        _track_security_metrics(security_data)

        # Cache the metrics for 5 minutes
        _cache_security_metrics(redis_client, cache_key, security_data)

        return security_data
    except Exception as e:
        log_error(f"Error collecting security metrics: {e}")
        # Return minimal data on error to ensure API doesn't break
        return _generate_fallback_metrics(hours, e)


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

    # Security anomalies
    security_anomalies = len(metrics_data.get('security_anomalies', []))
    if security_anomalies > 0:
        risk_score += min(3, security_anomalies)  # Add up to 3 points

    # High severity events
    high_severity_events = metrics_data.get('high_severity_events', 0)
    if high_severity_events > 5:
        risk_score += 2
    elif high_severity_events > 0:
        risk_score += 1

    # Cap the risk score at 10
    return min(10, risk_score)


def generate_security_recommendations(metrics_data: SecurityMetrics) -> List[SecurityRecommendation]:
    """
    Generate security recommendations based on security metrics.

    This function analyzes security metrics and provides actionable
    recommendations for improving security posture.

    Args:
        metrics_data: Dictionary of security metrics

    Returns:
        List[Dict[str, str]]: List of recommendations with title, priority and description
    """
    recommendations = []

    # Check failed logins
    failed_logins = metrics_data.get('failed_logins_24h', 0)
    if failed_logins > 20:
        recommendations.append({
            'priority': 'high' if failed_logins > 50 else 'medium',
            'title': 'High number of failed login attempts',
            'description': f'There have been {failed_logins} failed login attempts in the past 24 hours. Consider implementing additional authentication protections such as rate limiting, multi-factor authentication, or temporary IP blocks.'
        })

    # Check account lockouts
    lockouts = metrics_data.get('account_lockouts_24h', 0)
    if lockouts > 5:
        recommendations.append({
            'priority': 'high',
            'title': 'Unusual number of account lockouts',
            'description': f'There have been {lockouts} account lockouts in the past 24 hours, which may indicate a brute force attack or password spray. Consider reviewing authentication logs and implementing additional protections.'
        })

    # Check file integrity
    if not metrics_data.get('file_integrity', True):
        integrity_changes = metrics_data.get('integrity_changes', [])
        critical_changes = sum(1 for change in integrity_changes if change.get('severity') in ('high', 'critical'))

        recommendations.append({
            'priority': 'critical',
            'title': 'File integrity violation detected',
            'description': f'There are {len(integrity_changes)} file integrity issues detected, including {critical_changes} critical changes. Review the changes immediately as they could indicate a security breach.'
        })

    # Check configuration integrity
    if not metrics_data.get('config_integrity', True):
        recommendations.append({
            'priority': 'critical',
            'title': 'Configuration integrity violation',
            'description': 'Configuration file changes detected. This could indicate unauthorized modifications to system configuration. Review your configuration files and deploy from a trusted backup if necessary.'
        })

    # Check for suspicious IPs
    suspicious_ips = metrics_data.get('suspicious_ips', [])
    if suspicious_ips:
        blocked_ips_count = metrics_data.get('blocked_ips_count', 0)
        recommendations.append({
            'priority': 'high' if len(suspicious_ips) > 5 else 'medium',
            'title': 'Suspicious IP addresses detected',
            'description': f'{len(suspicious_ips)} suspicious IP addresses have been identified with {blocked_ips_count} currently blocked. Consider implementing additional IP blocking or rate limiting for the remaining suspicious IPs.'
        })

    # Check for active incidents
    incidents = metrics_data.get('incidents_active', 0)
    if incidents > 0:
        recommendations.append({
            'priority': 'high',
            'title': 'Unresolved security incidents',
            'description': f'There are {incidents} active security incidents that require attention. Review and resolve these incidents to improve security posture.'
        })

    # Check for security anomalies
    anomalies = metrics_data.get('security_anomalies', [])
    if anomalies:
        high_severity_anomalies = sum(1 for a in anomalies if a.get('severity') == 'high')
        if high_severity_anomalies > 0:
            recommendations.append({
                'priority': 'high',
                'title': 'High severity security anomalies detected',
                'description': f'{high_severity_anomalies} high severity security anomalies detected that require immediate investigation.'
            })

    # Check permission issues
    permission_issues = metrics_data.get('permission_issues', 0)
    if permission_issues > 5:
        recommendations.append({
            'priority': 'medium',
            'title': 'File permission issues detected',
            'description': f'{permission_issues} file permission issues detected that could create security vulnerabilities. Review and fix file permissions to follow principle of least privilege.'
        })

    # Check session counts if they seem abnormal
    active_sessions = metrics_data.get('active_sessions', 0)
    if active_sessions > SECURITY_CONFIG.get('SESSION_THRESHOLD_WARNING', 1000):
        recommendations.append({
            'priority': 'medium',
            'title': 'Unusually high number of active sessions',
            'description': f'There are currently {active_sessions} active sessions, which is above the normal threshold. This could indicate session management issues or unauthorized access.'
        })

    # Add default recommendation if nothing else is found
    if not recommendations:
        recommendations.append({
            'priority': 'low',
            'title': 'Regular security review',
            'description': 'No immediate security issues detected. Continue with regular security monitoring and reviews.'
        })

    return recommendations


def get_risk_trend(days: int = 7) -> Dict[str, Any]:
    """
    Get security risk score trend over time.

    This function retrieves historical risk scores to show how the security
    posture has changed over time.

    Args:
        days: Number of days to look back for trend data

    Returns:
        Dict[str, Any]: Dictionary containing risk trend data
    """
    try:
        redis_client = get_redis_client()
        if not redis_client:
            return {'error': 'Redis unavailable', 'data': []}

        # Cache key for trend
        cache_key = f"security:risk_trend:{days}"
        cached_data = redis_client.get(cache_key)
        if cached_data:
            try:
                return json.loads(cached_data)
            except Exception as e:
                log_error(f"Failed to parse cached risk trend data: {e}")

        # Get historical risk scores from metrics storage
        risk_data = []
        current_time = datetime.now(timezone.utc)

        # Get data for each day
        for day in range(days):
            day_date = current_time - timedelta(days=day)
            day_key = day_date.strftime('%Y-%m-%d')

            # Try to get from Redis first
            score_key = f"security:daily_risk:{day_key}"
            raw_score = redis_client.get(score_key)

            if raw_score:
                try:
                    score = int(raw_score)
                    risk_data.append({
                        'date': day_key,
                        'score': score
                    })
                    continue
                except (ValueError, TypeError):
                    pass

            # If we don't have data for this day, try to estimate from historical events
            if has_app_context() and day < 90:  # Only try for recent history (90 days)
                try:
                    score = _estimate_historical_risk_score(day_date)
                    risk_data.append({
                        'date': day_key,
                        'score': score
                    })
                except Exception as e:
                    log_error(f"Failed to estimate historical risk for {day_key}: {e}")
                    # Use the previous day's score or default to 1
                    prev_score = risk_data[-1]['score'] if risk_data else 1
                    risk_data.append({
                        'date': day_key,
                        'score': prev_score
                    })

        # Sort by date (oldest first)
        risk_data.sort(key=lambda x: x['date'])

        result = {
            'start_date': risk_data[0]['date'] if risk_data else None,
            'end_date': risk_data[-1]['date'] if risk_data else None,
            'data': risk_data,
            'trend': _calculate_trend(risk_data) if risk_data else 'stable'
        }

        # Cache the results for 1 hour
        if redis_client:
            try:
                redis_client.setex(cache_key, 3600, json.dumps(result))
            except Exception as e:
                log_error(f"Failed to cache risk trend data: {e}")

        return result
    except Exception as e:
        log_error(f"Error retrieving risk trend: {e}")
        return {
            'error': str(e),
            'data': []
        }


def get_threat_intelligence_summary() -> Dict[str, Any]:
    """
    Get threat intelligence summary based on internal and external data.

    This function combines internal security metrics with external threat
    intelligence data to provide a comprehensive threat summary.

    Returns:
        Dict[str, Any]: Dictionary containing threat intelligence summary
    """
    try:
        # Get basic security metrics
        metrics_data = get_security_metrics(hours=24)
        risk_score = metrics_data.get('risk_score', 5)

        # Initialize threat summary
        threat_summary = {
            'overall_threat_level': _risk_to_threat_level(risk_score),
            'risk_score': risk_score,
            'timestamp': int(time.time()),
            'suspicious_ips_count': len(metrics_data.get('suspicious_ips', [])),
            'blocked_ips_count': metrics_data.get('blocked_ips_count', 0),
            'integrity_issues': not metrics_data.get('file_integrity', True) or not metrics_data.get('config_integrity', True),
            'active_incidents': metrics_data.get('incidents_active', 0),
            'indicators': []
        }

        # Add threat indicators
        if has_app_context():
            _add_threat_indicators(threat_summary)

        # Get geolocation data for suspicious IPs
        suspicious_ips = metrics_data.get('suspicious_ips', [])
        countries = {}
        for ip_data in suspicious_ips:
            geo = ip_data.get('geolocation', {})
            country = geo.get('country', 'Unknown')
            if country in countries:
                countries[country] += 1
            else:
                countries[country] = 1

        # Add top countries
        threat_summary['top_source_countries'] = [
            {'country': country, 'count': count}
            for country, count in sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5]
        ]

        # Add trend
        trend_data = get_risk_trend(days=7)
        threat_summary['trend'] = trend_data.get('trend', 'stable')

        return threat_summary
    except Exception as e:
        log_error(f"Error generating threat intelligence summary: {e}")
        return {
            'error': str(e),
            'overall_threat_level': 'medium',
            'timestamp': int(time.time())
        }


def update_daily_risk_score() -> bool:
    """
    Update the daily risk score in Redis.

    This function should be called once daily to maintain historical risk data.

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        redis_client = get_redis_client()
        if not redis_client:
            log_error("Redis unavailable for updating daily risk score")
            return False

        # Get today's metrics
        metrics_data = get_security_metrics(hours=24)
        risk_score = metrics_data.get('risk_score', 5)

        # Store in Redis with today's date as key
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        key = f"security:daily_risk:{today}"

        # Store risk score (TTL of 90 days)
        redis_client.setex(key, 90 * 24 * 3600, risk_score)

        # Log the daily update
        log_info(f"Updated daily risk score: {risk_score} for {today}")

        # Log security event for significant risk scores
        if risk_score >= 8:
            try:
                log_security_event(
                    event_type="high_risk_score",
                    description=f"Critical security risk score: {risk_score}/10",
                    severity="error",
                    details={
                        'risk_score': risk_score,
                        'failed_logins': metrics_data.get('failed_logins_24h', 0),
                        'suspicious_ips_count': len(metrics_data.get('suspicious_ips', [])),
                        'integrity_issues': not metrics_data.get('file_integrity', True)
                            or not metrics_data.get('config_integrity', True)
                    }
                )
            except Exception as e:
                log_error(f"Failed to log security event for high risk score: {e}")

        return True
    except Exception as e:
        log_error(f"Error updating daily risk score: {e}")
        return False


def get_ip_geolocation(ip_address: str) -> Dict[str, Any]:
    """
    Get geolocation information for an IP address.

    Args:
        ip_address: IP address to look up

    Returns:
        Dict[str, Any]: Dictionary with geolocation data or empty dict if not available
    """
    # Validate input first
    if not ip_address:
        return {}

    try:
        # Preferred approach: Use the existing implementation from cs_monitoring
        # This reduces code duplication and ensures consistent behavior
        from .cs_monitoring import _get_ip_geolocation
        return _get_ip_geolocation(ip_address)
    except ImportError:
        # Only log once per application run to avoid log spam
        if not hasattr(get_ip_geolocation, '_import_error_logged'):
            log_error("Failed to import _get_ip_geolocation from cs_monitoring")
            get_ip_geolocation._import_error_logged = True

        # Input validation (basic check before making external API calls)
        try:
            from .cs_authentication import is_valid_ip
            if not is_valid_ip(ip_address):
                log_warning(f"Invalid IP address format: {ip_address}")
                metrics.increment('security.geolocation.invalid_ip')
                return {}
        except ImportError:
            # Fallback validation if cs_authentication is not available
            import re
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
            if not re.match(ip_pattern, ip_address):
                log_warning(f"Invalid IP address format: {ip_address}")
                metrics.increment('security.geolocation.invalid_ip')
                return {}

        # Check cache first (with metrics tracking)
        redis_client = get_redis_client()
        cache_key = f"ip_geolocation:{ip_address}"

        if redis_client:
            cached_data = redis_client.get(cache_key)
            if cached_data:
                try:
                    metrics.increment('security.geolocation.cache_hit')
                    return json.loads(cached_data)
                except json.JSONDecodeError:
                    log_error(f"Failed to parse cached geolocation data for IP: {ip_address}")
                    metrics.increment('security.geolocation.cache_error')

        # Track request for metrics
        metrics.increment('security.geolocation.request')

        try:
            # Only perform lookup if configuration allows
            if not has_app_context() or not current_app.config.get('GEOLOCATION_ENABLED', False):
                return {}

            # Use configured geolocation service
            geolocation_api = current_app.config.get('GEOLOCATION_API', 'ipapi')

            # Implement rate limiting protection
            rate_limit_key = "geolocation_api_calls"
            rate_window = 60  # 1 minute
            rate_limit = current_app.config.get('GEOLOCATION_RATE_LIMIT', 60)  # Default: 60 calls per minute

            if redis_client:
                # Check if we're over the rate limit
                current_count = redis_client.get(rate_limit_key)
                if current_count and int(current_count) >= rate_limit:
                    log_warning(f"Geolocation API rate limit reached ({rate_limit}/{rate_window}s)")
                    metrics.increment('security.geolocation.rate_limited')
                    return {}

                # Increment counter
                pipe = redis_client.pipeline()
                pipe.incr(rate_limit_key)
                pipe.expire(rate_limit_key, rate_window)
                pipe.execute()

            if geolocation_api == 'ipapi':
                # Use secure HTTPS endpoint if available, falling back to HTTP only if necessary
                # Note: ip-api.com requires a paid account for HTTPS
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

                    # Add formatted location string for consistency with cs_monitoring
                    if 'city' in data and 'country' in data:
                        data['location'] = f"{data['city']}, {data['country']}"

                    # Cache for 24 hours if we have valid data
                    if redis_client and data.get('country'):
                        redis_client.setex(cache_key, 86400, json.dumps(data))
                        metrics.increment('security.geolocation.cache_write')

                    metrics.increment('security.geolocation.success')
                    return data
                else:
                    log_warning(f"Geolocation API returned status {response.status_code} for IP {ip_address}")
                    metrics.increment('security.geolocation.api_error')

            elif geolocation_api == 'ipinfo':
                api_key = current_app.config.get('IPINFO_API_KEY', '')
                token_param = f"?token={api_key}" if api_key else ""

                response = requests.get(
                    f"https://ipinfo.io/{ip_address}/json{token_param}",
                    timeout=3
                )

                if response.status_code == 200:
                    data = response.json()

                    # Add formatted location string for consistency
                    if 'city' in data and 'country' in data:
                        data['location'] = f"{data['city']}, {data['country']}"

                    # Cache for 24 hours if we have valid data
                    if redis_client and data.get('country'):
                        redis_client.setex(cache_key, 86400, json.dumps(data))
                        metrics.increment('security.geolocation.cache_write')

                    metrics.increment('security.geolocation.success')
                    return data
                else:
                    log_warning(f"Geolocation API returned status {response.status_code} for IP {ip_address}")
                    metrics.increment('security.geolocation.api_error')

            return {}  # Default empty response

        except requests.exceptions.Timeout:
            log_warning(f"Timeout retrieving geolocation for IP {ip_address}")
            metrics.increment('security.geolocation.timeout')
            return {}
        except requests.exceptions.ConnectionError:
            log_error(f"Connection error retrieving geolocation for IP {ip_address}")
            metrics.increment('security.geolocation.connection_error')
            return {}
        except requests.exceptions.RequestException as e:
            log_error(f"Request error retrieving geolocation for IP {ip_address}: {e}")
            metrics.increment('security.geolocation.request_error')
            return {}
        except json.JSONDecodeError:
            log_error(f"Invalid JSON response from geolocation API for IP {ip_address}")
            metrics.increment('security.geolocation.json_error')
            return {}
        except Exception as e:
            log_error(f"Error getting geolocation for IP {ip_address}: {e}")
            metrics.increment('security.geolocation.error')
            return {}


# Helper functions

def _get_cached_metrics(redis_client, cache_key: str) -> Optional[SecurityMetrics]:
    """Get security metrics from cache if available."""
    if not redis_client:
        return None

    cached_data = redis_client.get(cache_key)
    if cached_data:
        try:
            return json.loads(cached_data)
        except Exception as e:
            log_error(f"Failed to parse cached security metrics: {e}")
    return None


def _collect_advanced_metrics(security_data: SecurityMetrics, hours: int) -> None:
    """Collect advanced security metrics when in application context."""
    try:
        # File integrity checks
        security_data['config_integrity'] = check_config_integrity()
        integrity_result, changes = check_critical_file_integrity()
        security_data['file_integrity'] = integrity_result
        security_data['integrity_changes'] = changes

        # Count active security incidents
        security_data['incidents_active'] = SecurityIncident.query.filter(
            SecurityIncident.status.in_(['open', 'investigating'])
        ).count()

        # Get permission issues
        permission_issues = detect_permission_issues()
        security_data['permission_issues'] = len(permission_issues)
        security_data['permission_details'] = permission_issues[:10]  # First 10 issues

        # Blocked IPs
        blocked_ips = list(get_blocked_ips())
        security_data['blocked_ips_count'] = len(blocked_ips)
        security_data['blocked_ips'] = blocked_ips[:20]  # Limit to first 20 for performance

        # Security anomalies
        security_anomalies = get_security_anomalies(hours=hours)
        security_data['security_anomalies'] = security_anomalies
        security_data['high_severity_anomalies'] = sum(1 for a in security_anomalies if a.get('severity') == 'high')

        # Count high severity events
        security_events = security_data.get('security_events', {})
        high_severity_events = 0
        for event_type, count in security_events.items():
            if any(pattern in event_type for pattern in ('breach', 'attack', 'critical', 'tamper')):
                high_severity_events += count
        security_data['high_severity_events'] = high_severity_events
    except Exception as e:
        log_error(f"Error collecting advanced security metrics: {e}")


def _track_security_metrics(security_data: SecurityMetrics) -> None:
    """Report collected metrics to monitoring system."""
    metrics.gauge('security.risk_score', security_data['risk_score'])
    metrics.gauge('security.suspicious_ips', len(security_data.get('suspicious_ips', [])))
    metrics.gauge('security.failed_logins', security_data.get('failed_logins_24h', 0))
    metrics.gauge('security.account_lockouts', security_data.get('account_lockouts_24h', 0))

    # Track additional metrics if available
    if 'incidents_active' in security_data:
        metrics.gauge('security.active_incidents', security_data['incidents_active'])

    if 'permission_issues' in security_data:
        metrics.gauge('security.permission_issues', security_data['permission_issues'])

    if 'blocked_ips_count' in security_data:
        metrics.gauge('security.blocked_ips', security_data['blocked_ips_count'])

    if 'high_severity_anomalies' in security_data:
        metrics.gauge('security.high_severity_anomalies', security_data['high_severity_anomalies'])

    # Track file integrity status
    metrics.gauge('security.file_integrity_violations',
        0 if security_data.get('file_integrity', True) else 1)


def _cache_security_metrics(redis_client, cache_key: str, security_data: SecurityMetrics) -> None:
    """Cache security metrics in Redis."""
    if not redis_client:
        return

    try:
        redis_client.setex(cache_key, 300, json.dumps(security_data))
    except Exception as e:
        log_error(f"Failed to cache security metrics: {e}")


def _generate_fallback_metrics(hours: int, error: Exception) -> SecurityMetrics:
    """Generate fallback metrics when collection fails."""
    return {
        'failed_logins_24h': 0,
        'suspicious_ips': [],
        'risk_score': 5,  # Medium risk when metrics can't be collected
        'last_checked': datetime.now(timezone.utc).isoformat(),
        'error': str(error),
        'timestamp': int(time.time()),
        'period_hours': hours,
        'security_recommendations': [{
            'priority': 'medium',
            'title': 'Security metrics collection failed',
            'description': 'Unable to collect complete security metrics. This could indicate system issues that require investigation.'
        }]
    }


def _estimate_historical_risk_score(target_date: datetime) -> int:
    """Estimate historical risk score for a given date based on audit logs."""
    try:
        # Get end of the target day
        end_date = datetime(
            target_date.year, target_date.month, target_date.day, 23, 59, 59,
            tzinfo=timezone.utc
        )

        # Get start of the target day
        start_date = datetime(
            target_date.year, target_date.month, target_date.day, 0, 0, 0,
            tzinfo=timezone.utc
        )

        # Query database for security events on that day
        from models.audit_log import AuditLog

        # Count different types of events
        failed_logins = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
            AuditLog.created_at >= start_date,
            AuditLog.created_at <= end_date
        ).scalar() or 0

        account_lockouts = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.event_type == AuditLog.EVENT_ACCOUNT_LOCKOUT,
            AuditLog.created_at >= start_date,
            AuditLog.created_at <= end_date
        ).scalar() or 0

        permission_denied = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.event_type == AuditLog.EVENT_PERMISSION_DENIED,
            AuditLog.created_at >= start_date,
            AuditLog.created_at <= end_date
        ).scalar() or 0

        critical_events = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.severity.in_(['error', 'critical']),
            AuditLog.created_at >= start_date,
            AuditLog.created_at <= end_date
        ).scalar() or 0

        # Get a list of distinct IPs with failed logins
        distinct_ips = db.session.query(AuditLog.ip_address).filter(
            AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
            AuditLog.created_at >= start_date,
            AuditLog.created_at <= end_date,
            AuditLog.ip_address.isnot(None)
        ).distinct().count()

        # Calculate an estimated risk score based on these metrics
        risk = 1  # Start with baseline

        # Failed logins increase risk
        if failed_logins > 100:
            risk += 3
        elif failed_logins > 50:
            risk += 2
        elif failed_logins > 20:
            risk += 1

        # Account lockouts are a stronger risk indicator
        if account_lockouts > 10:
            risk += 3
        elif account_lockouts > 5:
            risk += 2
        elif account_lockouts > 0:
            risk += 1

        # Distinct IPs with failed logins
        if distinct_ips > 10:
            risk += 2
        elif distinct_ips > 0:
            risk += 1

        # Permission denied events
        if permission_denied > 20:
            risk += 2
        elif permission_denied > 5:
            risk += 1

        # Critical security events
        if critical_events > 0:
            risk += min(critical_events, 3)  # Add up to 3 points

        # Cap the risk score at 10
        return min(10, risk)
    except Exception as e:
        log_error(f"Error estimating historical risk score: {e}")
        return 1  # Default to low risk on error


def _calculate_trend(risk_data: List[Dict[str, Any]]) -> str:
    """Calculate the risk trend based on historical data."""
    if not risk_data or len(risk_data) < 2:
        return 'stable'

    # Get first and last scores
    first_score = risk_data[0]['score']
    last_score = risk_data[-1]['score']

    # Calculate the difference
    diff = last_score - first_score

    if diff > 2:
        return 'increasing_rapidly'
    elif diff > 0:
        return 'increasing'
    elif diff < -2:
        return 'decreasing_rapidly'
    elif diff < 0:
        return 'decreasing'
    else:
        return 'stable'


def _risk_to_threat_level(risk_score: int) -> str:
    """Convert numeric risk score to threat level string."""
    if risk_score >= 8:
        return 'critical'
    elif risk_score >= 6:
        return 'high'
    elif risk_score >= 4:
        return 'medium'
    elif risk_score >= 2:
        return 'low'
    else:
        return 'minimal'


def _add_threat_indicators(threat_summary: Dict[str, Any]) -> None:
    """Add threat indicators to the threat summary."""
    # Add indicators based on metrics
    if threat_summary.get('risk_score', 0) >= 7:
        threat_summary['indicators'].append({
            'name': 'Elevated Risk Score',
            'description': f"Risk score of {threat_summary['risk_score']}/10 indicates potential security threats",
            'severity': 'high'
        })

    if threat_summary.get('integrity_issues', False):
        threat_summary['indicators'].append({
            'name': 'System Integrity Issues',
            'description': "Critical file or configuration integrity issues detected",
            'severity': 'critical'
        })

    if threat_summary.get('suspicious_ips_count', 0) > 10:
        threat_summary['indicators'].append({
            'name': 'Multiple Suspicious IPs',
            'description': f"High number of suspicious IPs detected ({threat_summary['suspicious_ips_count']})",
            'severity': 'high'
        })

    # Check for external threat intelligence indicators
    try:
        if has_app_context():
            threat_feed_enabled = current_app.config.get('THREAT_INTELLIGENCE_ENABLED', False)
            if threat_feed_enabled:
                # Get latest external threat intel if configured
                feed_url = current_app.config.get('THREAT_INTELLIGENCE_FEED')
                if feed_url:
                    # This would normally call an external threat feed
                    # Implementing a placeholder with minimal impact
                    threat_summary['external_threat_level'] = 'medium'
                    threat_summary['external_indicators'] = []
    except Exception as e:
        log_error(f"Error adding external threat indicators: {e}")
