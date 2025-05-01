"""
Security monitoring routes for the application.

This module provides endpoints for monitoring system security, detecting anomalies,
and managing security incidents. It implements comprehensive security monitoring
features including login anomaly detection, session monitoring, and automated
incident response.

All endpoints return JSON responses with appropriate HTTP status codes and follow
REST best practices. Most endpoints require administrative privileges.

Routes:
    /monitoring/status: Get current security status summary
    /monitoring/anomalies: Detect security anomalies
    /monitoring/metrics: View security metrics
    /monitoring/incidents: Manage security incidents
    /monitoring/forensics: Access forensic data
"""

import logging
import os
import json
import time
import ipaddress
import psutil
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List, Union
from functools import wraps
from sqlalchemy import desc, func, or_, and_
from sqlalchemy.exc import SQLAlchemyError
from flask import Blueprint, request, jsonify, session, current_app, Response, g
from flask_wtf.csrf import CSRFProtect
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from extensions import db, cache, limiter
from models import AuditLog, Notification, SecurityIncident, User
from services.email_service import send_email
from core.security import (
    check_for_anomalies,
    log_security_event,
    validate_admin_access,
    get_security_metrics,
    analyze_login_patterns,
    is_ip_suspicious
)

# Create blueprint
security_monitor_bp = Blueprint('security_monitor', __name__, url_prefix='/monitoring')

# Set up CSRF protection
csrf = CSRFProtect()

# Define Prometheus metrics
ANOMALY_DETECTIONS = Counter('security_anomalies_detected_total',
                           'Total number of security anomalies detected',
                           ['anomaly_type', 'severity'])
INCIDENT_COUNTER = Counter('security_incidents_total',
                         'Total number of security incidents',
                         ['threat_level'])
REQUEST_LATENCY = Histogram('monitoring_request_latency_seconds',
                          'Monitoring endpoint latency in seconds',
                          ['endpoint'])

# --- Authentication and Authorization Decorators ---

def admin_required(f):
    """Decorator to require admin role for access."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in and has admin role
        if not g.get('user') or g.user.role != 'admin':
            log_security_event(
                'permission_denied',
                f"Non-admin user attempted to access {request.path}",
                severity='warning',
                user_id=g.get('user_id') if hasattr(g, 'user_id') else None,
                ip_address=request.remote_addr
            )
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

def measure_latency(f):
    """Decorator to measure endpoint latency."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = datetime.utcnow()
        response = f(*args, **kwargs)
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()
        endpoint = request.endpoint or 'unknown'
        REQUEST_LATENCY.labels(endpoint=endpoint).observe(duration)
        return response
    return decorated_function

# --- Helper Functions ---

def format_response(data: Any, status: int = 200) -> Tuple[Response, int]:
    """Format standardized API response."""
    if isinstance(data, dict) and 'error' in data and status == 200:
        status = 400  # Default to 400 for error responses

    return jsonify(data), status

# --- Security Monitoring Endpoints ---

@security_monitor_bp.after_request
def apply_security_headers(response):
    """Apply security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

@security_monitor_bp.route('/health')
@measure_latency
def health_check():
    """
    Simple health check endpoint for infrastructure monitoring.

    This endpoint returns a 200 OK response if the application is running
    and can connect to its database, indicating that the service is healthy.

    Returns:
        tuple: JSON response with health status and HTTP status code
    """
    try:
        # Check database connection
        db_healthy = False
        try:
            db.session.execute("SELECT 1").scalar()
            db_healthy = True
        except SQLAlchemyError as e:
            current_app.logger.warning(f"Database health check failed: {e}")
            db_healthy = False

        # Check cache connection
        cache_healthy = False
        try:
            test_key = f"health_check_{datetime.utcnow().timestamp()}"
            cache.set(test_key, 'ok', timeout=10)
            cache_healthy = cache.get(test_key) == 'ok'
            cache.delete(test_key)  # Clean up after check
        except Exception as e:
            current_app.logger.warning(f"Cache health check failed: {e}")
            cache_healthy = False

        # Optional: check file system access
        fs_healthy = True
        try:
            temp_dir = current_app.config.get('TEMP_FOLDER', '/tmp')
            test_file = os.path.join(temp_dir, f"health_check_{int(time.time())}.txt")
            with open(test_file, "w") as f:
                f.write("health check")
            os.remove(test_file)
        except IOError as e:
            current_app.logger.warning(f"Filesystem health check failed: {e}")
            fs_healthy = False

        # Determine overall health status
        health_status = {
            'status': 'healthy' if (db_healthy and cache_healthy and fs_healthy) else 'degraded',
            'timestamp': datetime.utcnow().isoformat(),
            'components': {
                'database': 'healthy' if db_healthy else 'unhealthy',
                'cache': 'healthy' if cache_healthy else 'unhealthy',
                'filesystem': 'healthy' if fs_healthy else 'unhealthy',
                'app': 'healthy'
            }
        }

        # Add version information
        health_status['version'] = current_app.config.get('VERSION', 'unknown')

        status_code = 200 if health_status['status'] == 'healthy' else 503
        return jsonify(health_status), status_code

    except (SQLAlchemyError, OSError) as e:
        current_app.logger.error(f"Health check error: {e}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500

@security_monitor_bp.route('/status')
@limiter.limit("10/minute")
@admin_required
@measure_latency
def security_status():
    """
    Get current security status summary.

    This endpoint provides an overview of the system's security status,
    including recent failed login attempts, active sessions, suspicious IPs,
    and configuration integrity.

    Returns:
        tuple: JSON response with security metrics and an overall risk score
    """
    try:
        security_data = check_security_status()
        log_security_event(
            event_type='security_status_check',
            description='Security status checked by admin',
            user_id=g.get('user_id'),
            ip_address=request.remote_addr
        )
        return format_response(security_data)
    except (SQLAlchemyError, OSError) as e:
        log_security_event(
            event_type='security_status_error',
            description=f"Error checking security status: {str(e)}",
            severity='error',
            user_id=g.get('user_id'),
            ip_address=request.remote_addr
        )
        return format_response({'error': str(e)}, 500)

@security_monitor_bp.route('/anomalies', methods=['GET'])
@limiter.limit('10/hour')
@admin_required
def detect_system_anomalies():
    """
    Detect security anomalies across the system.

    This endpoint performs a comprehensive security scan to detect anomalies
    in login patterns, session activity, API usage, database access, and
    file system activity that may indicate security breaches.

    Returns:
        tuple: JSON response with detected anomalies across various categories
    """
    try:
        # Check cache first to avoid frequent expensive scans
        cached_result = cache.get('last_anomaly_scan')
        if cached_result and not request.args.get('force'):
            return format_response(cached_result)

        # Get baseline security metrics first
        security_metrics = get_security_metrics(hours=24)

        # Collect detailed anomalies across different areas
        anomalies = {
            'login_anomalies': detect_login_anomalies(
                suspicious_ips=security_metrics.get('suspicious_ips', [])
            ),
            'session_anomalies': detect_session_anomalies(),
            'api_anomalies': detect_api_anomalies(),
            'database_anomalies': detect_database_anomalies(),
            'file_access_anomalies': detect_file_access_anomalies(
                config_integrity=security_metrics.get('config_integrity', True),
                file_integrity=security_metrics.get('file_integrity', True)
            )
        }

        # Add relevant security metrics to anomaly report
        anomalies['security_metrics'] = {
            'failed_logins_24h': security_metrics.get('failed_logins_24h', 0),
            'account_lockouts_24h': security_metrics.get('account_lockouts_24h', 0),
            'active_sessions': security_metrics.get('active_sessions', 0),
            'incidents_active': security_metrics.get('incidents_active', 0)
        }

        # Calculate threat level - use baseline risk score as a factor
        baseline_risk = security_metrics.get('risk_score', 1)
        threat_level = calculate_threat_level(anomalies, baseline_risk)

        anomalies['threat_level'] = {'value': threat_level}
        anomalies['timestamp'] = {'value': datetime.utcnow().isoformat()}

        # Track metrics for each anomaly type
        for anomaly_type, data in anomalies.items():
            if anomaly_type not in ('threat_level', 'timestamp', 'security_metrics'):
                count = sum(len(category) for category in data.values()
                            if isinstance(category, list))
                if count > 0:
                    severity = _determine_severity(threat_level)
                    ANOMALY_DETECTIONS.labels(
                        anomaly_type=anomaly_type,
                        severity=severity
                    ).inc(count)

        # If threat level is high, trigger incident response
        if threat_level >= 7:
            incident_id = trigger_incident_response(anomalies)
            if incident_id:
                anomalies['incident_id'] = {'value': incident_id}

        # Cache the results briefly to avoid repeated expensive scans
        cache.set('last_anomaly_scan', anomalies, timeout=300)  # 5 minutes

        # Log the event
        log_security_event(
            event_type='anomaly_detection',
            description=f"Security anomaly scan completed. Threat level: {threat_level}/10",
            user_id=g.get('user_id'),
            ip_address=request.remote_addr
        )

        return format_response(anomalies)

    except Exception as e:
        current_app.logger.exception("Error in anomaly detection")
        log_security_event(
            event_type='anomaly_detection_error',
            description=f"Error detecting anomalies: {str(e)}",
            severity='error',
            user_id=g.get('user_id'),
            ip_address=request.remote_addr
        )
        return format_response({'error': str(e)}, 500)

def _determine_severity(threat_level: int) -> str:
    """
    Determine severity level based on threat level.

    Args:
        threat_level: Numeric threat level value

    Returns:
        str: Severity level (critical, high, medium, low)
    """
    if threat_level >= 8:
        return 'critical'
    elif threat_level >= 5:
        return 'high'
    elif threat_level >= 3:
        return 'medium'
    else:
        return 'low'

@security_monitor_bp.route('/metrics')
@limiter.limit("10/minute")
@admin_required
def prometheus_metrics():
    """
    Expose Prometheus metrics for monitoring.

    This endpoint returns metrics in the Prometheus text format,
    which can be scraped by a Prometheus server for monitoring and alerting.

    Returns:
        Response: Prometheus-formatted metrics
    """
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

@security_monitor_bp.route('/incidents')
@limiter.limit("20/minute")
@admin_required
@measure_latency
def list_incidents():
    """
    List security incidents with optional filtering.

    This endpoint returns a list of security incidents, with optional filtering
    by status, threat level, and time range. Results are paginated.

    Returns:
        tuple: JSON response with paginated security incidents
    """
    try:
        # Parse query parameters
        status = request.args.get('status')
        min_threat = request.args.get('min_threat', type=int)
        max_threat = request.args.get('max_threat', type=int)
        days = request.args.get('days', 30, type=int)
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        # Build query
        query = SecurityIncident.query

        if status:
            query = query.filter(SecurityIncident.status == status)

        if min_threat is not None:
            query = query.filter(SecurityIncident.threat_level >= min_threat)

        if max_threat is not None:
            query = query.filter(SecurityIncident.threat_level <= max_threat)

        if days:
            cutoff = datetime.utcnow() - timedelta(days=days)
            query = query.filter(SecurityIncident.detected_at >= cutoff)

        # Execute query with pagination
        pagination = query.order_by(desc(SecurityIncident.detected_at)).paginate(
            page=page, per_page=per_page, error_out=False)

        # Format results
        incidents = [incident.to_dict() for incident in pagination.items]

        result = {
            'incidents': incidents,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page,
            'per_page': per_page
        }

        return format_response(result)

    except (SQLAlchemyError, ValueError, OSError) as e:
        log_security_event(
            event_type='list_incidents_error',
            description=f"Error listing security incidents: {str(e)}",
            severity='error',
            user_id=g.get('user_id'),
            ip_address=request.remote_addr
        )
        return format_response({'error': str(e)}, 500)

@security_monitor_bp.route('/incidents/<int:incident_id>')
@limiter.limit("30/minute")
@admin_required
def get_incident(incident_id):
    """
    Get detailed information about a security incident.

    This endpoint returns detailed information about a specific security incident,
    including its threat level, status, and details about the detected anomalies.

    Args:
        incident_id: ID of the security incident

    Returns:
        tuple: JSON response with incident details
    """
    try:
        incident = SecurityIncident.query.get_or_404(incident_id)
        return format_response(incident.to_dict())
    except (SQLAlchemyError, ValueError, OSError) as e:
        log_security_event(
            event_type='get_incident_error',
            description=f"Error retrieving incident {incident_id}: {str(e)}",
            severity='error',
            user_id=g.get('user_id'),
            ip_address=request.remote_addr
        )
        return format_response({'error': str(e)}, 500)

@security_monitor_bp.route('/incidents/<int:incident_id>', methods=['PUT'])
@csrf.exempt  # For API usage
@limiter.limit("10/minute")
@admin_required
def update_incident(incident_id):
    """
    Update a security incident.

    This endpoint allows updating the status, resolution, and notes for a security incident.
    Only admin users can update incidents.

    Args:
        incident_id: ID of the security incident

    Returns:
        tuple: JSON response with updated incident details
    """
    try:
        incident = SecurityIncident.query.get_or_404(incident_id)
        data = request.get_json()

        if not data:
            return format_response({'error': 'No update data provided'}, 400)

        if 'status' in data:
            incident.status = data['status']

        if 'resolution' in data:
            incident.resolution = data['resolution']

        if 'notes' in data:
            incident.notes = data['notes']

        if 'assigned_to' in data:
            incident.assigned_to = data['assigned_to']

        # Update the modified timestamp
        incident.updated_at = datetime.utcnow()

        db.session.commit()

        log_security_event(
            event_type='incident_updated',
            description=f"Security incident {incident_id} updated",
            user_id=g.get('user_id'),
            ip_address=request.remote_addr
        )

        return format_response(incident.to_dict())

    except (SQLAlchemyError, ValueError, OSError) as e:
        db.session.rollback()
        log_security_event(
            event_type='update_incident_error',
            description=f"Error updating incident {incident_id}: {str(e)}",
            severity='error',
            user_id=g.get('user_id'),
            ip_address=request.remote_addr
        )
        return format_response({'error': str(e)}, 500)

@security_monitor_bp.route('/forensics/<int:incident_id>')
@limiter.limit("5/minute")
@admin_required
def get_forensic_data(incident_id):
    """
    Get forensic data collected for a security incident.

    This endpoint returns the forensic data collected during incident response,
    which may include process information, network connections, and system resources.

    Args:
        incident_id: ID of the security incident

    Returns:
        tuple: JSON response with forensic data or error
    """
    try:
        # Determine path to forensic data
        forensic_dir = current_app.config.get('FORENSIC_DATA_DIR', 'forensic_data')

        # List all forensic files for this incident
        if not os.path.exists(forensic_dir):
            return format_response({'error': 'No forensic data found'}, 404)

        forensic_files = []
        for filename in os.listdir(forensic_dir):
            if filename.startswith(f'incident_{incident_id}_'):
                forensic_files.append(filename)

        if not forensic_files:
            return format_response({'error': 'No forensic data found for this incident'}, 404)

        # Get the latest forensic file
        latest_file = sorted(forensic_files)[-1]
        file_path = os.path.join(forensic_dir, latest_file)

        # Validate file path to prevent directory traversal
        if not os.path.abspath(file_path).startswith(os.path.abspath(forensic_dir)):
            current_app.logger.error(f"Invalid file path detected: {file_path}")
            return format_response({'error': 'Invalid file path'}, 400)

        # Read the forensic data
        with open(file_path, 'r', encoding='utf-8') as f:
            forensic_data = json.load(f)

        return format_response({
            'incident_id': incident_id,
            'forensic_file': latest_file,
            'data': forensic_data
        })

    except (OSError, ValueError, SQLAlchemyError) as e:
        log_security_event(
            event_type='get_forensic_error',
            description=f"Error retrieving forensic data for incident {incident_id}: {str(e)}",
            severity='error',
            user_id=g.get('user_id'),
            ip_address=request.remote_addr
        )
        return format_response({'error': str(e)}, 500)

# --- Core Security Monitoring Functions ---

def check_security_status() -> Dict[str, Any]:
    """
    Perform comprehensive security status check.

    Returns:
        Dict[str, Any]: Dictionary with security metrics and status
    """
    return get_security_metrics()

def check_critical_file_integrity() -> bool:
    """
    Verify integrity of critical application files.

    Uses the established file integrity checking functions from core.utils
    for consistency and to leverage the security monitoring system.

    Returns:
        bool: True if all files match their reference hashes, False otherwise
    """
    from core.utils import detect_file_changes

    # Get expected hashes from application configuration
    expected_hashes = current_app.config.get('CRITICAL_FILE_HASHES', {})
    if not expected_hashes:
        current_app.logger.warning("No reference hashes found for critical files")
        return False

    # Use the more comprehensive detection function
    app_root = os.path.dirname(os.path.abspath(current_app.root_path))
    changes = detect_file_changes(app_root, expected_hashes)

    if changes:
        # Log each detected change
        for change in changes:
            path = change.get('path', 'unknown')
            status = change.get('status', 'unknown')
            severity = change.get('severity', 'medium')

            current_app.logger.warning(f"File integrity violation: {path} ({status})")

            # Record security event for high severity changes
            if severity in ('high', 'critical'):
                try:
                    log_security_event(
                        event_type=AuditLog.EVENT_FILE_INTEGRITY,
                        description=f"Critical file modified: {path}",
                        severity='error'
                    )
                except Exception as e:
                    current_app.logger.error(f"Failed to record file integrity event: {e}")

        return False

    return True

def detect_anomalies() -> bool:
    """
    Detect system anomalies that might indicate a security breach.

    Performs quick checks to identify unusual patterns or activities:
    - Suspicious login patterns (multiple failed attempts)
    - Unusual API access patterns
    - Unexpected process activities
    - Configuration file changes

    Returns:
        bool: True if anomalies detected, False otherwise
    """
    try:
        # Check for multiple failed logins from same IP
        from core.security_utils import get_suspicious_ips
        suspicious_ips = get_suspicious_ips(hours=24, min_attempts=5)

        if suspicious_ips and len(suspicious_ips) > 0:
            return True

        # Check for unusual API access patterns
        api_requests = AuditLog.query.filter(
            AuditLog.event_type == AuditLog.EVENT_API_ACCESS,
            AuditLog.created_at >= datetime.utcnow() - timedelta(minutes=5)
        ).count()

        if api_requests > 100:  # Unusual API traffic
            return True

        # Check for critical file modifications
        config_modified = False
        config_files = ['config.py', '.env', 'app.py']

        for file in config_files:
            if os.path.exists(file):
                mod_time = os.path.getmtime(file)
                if datetime.fromtimestamp(mod_time) > datetime.utcnow() - timedelta(minutes=30):
                    config_modified = True
                    break

        if config_modified:
            return True

        # All checks passed
        return False
    except Exception as e:
        current_app.logger.error(f"Error detecting anomalies: {e}")
        return False

def detect_login_anomalies(suspicious_ips=None) -> Dict[str, List[Dict[str, Any]]]:
    """
    Detect suspicious login patterns and authentication anomalies.

    This function analyzes recent login activity to identify patterns that may
    indicate security breaches such as:
    - Unusual login times or locations
    - Multiple failed login attempts from the same IP
    - Successful logins following failed attempts
    - Logins from unusual geographic locations
    - Logins with unusual user-agent strings

    Args:
        suspicious_ips: Optional pre-fetched list of suspicious IPs

    Returns:
        Dict[str, List[Dict[str, Any]]]: Dictionary containing login anomalies
    """
    result = {
        'failed_attempts': [],
        'unusual_locations': [],
        'suspicious_ips': [],
        'unusual_times': []
    }

    try:
        # Use provided suspicious IPs if available, otherwise fetch them
        if suspicious_ips is None:
            from core.security_utils import get_suspicious_ips
            suspicious_ip_data = get_suspicious_ips(hours=24, min_attempts=5)
        else:
            suspicious_ip_data = suspicious_ips

        # Format suspicious IPs data
        for ip_data in suspicious_ip_data:
            ip = ip_data.get('ip')
            if not ip:
                continue

            count = ip_data.get('count', 0)

            latest_attempt = AuditLog.query.filter(
                AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
                AuditLog.ip_address == ip
            ).order_by(desc(AuditLog.created_at)).first()

            result['suspicious_ips'].append({
                'ip_address': ip,
                'failed_attempts': count,
                'last_attempt': latest_attempt.created_at.isoformat() if latest_attempt else None
            })

        # Get successful logins that happened outside normal hours (9am-5pm)
        unusual_time_logins = AuditLog.query.filter(
            AuditLog.event_type == AuditLog.EVENT_LOGIN_SUCCESS,
            AuditLog.created_at >= datetime.utcnow() - timedelta(hours=24),
            ~and_(
                func.extract('hour', AuditLog.created_at) >= 9,
                func.extract('hour', AuditLog.created_at) < 17
            )
        ).order_by(desc(AuditLog.created_at)).limit(10).all()

        for login in unusual_time_logins:
            result['unusual_times'].append({
                'user_id': login.user_id,
                'timestamp': login.created_at.isoformat(),
                'ip_address': login.ip_address,
                'user_agent': login.user_agent
            })
    except Exception as e:
        current_app.logger.error(f"Error detecting login anomalies: {e}")

    # Return compiled results
    return result

def detect_session_anomalies() -> Dict[str, List[Dict[str, Any]]]:
    """
    Detect unusual session activity and potential session hijacking.

    This function examines session data to identify anomalies that may
    indicate session hijacking or token theft, including:
    - Rapid changes in user-agent or IP within the same session
    - Multiple simultaneous active sessions for the same user
    - Session durations outside typical usage patterns
    - Unusual navigation patterns within a session

    Returns:
        Dict[str, List[Dict[str, Any]]]: Dictionary containing session anomalies
    """
    result = {
        'ip_changes': [],
        'agent_changes': [],
        'concurrent_sessions': [],
        'unusual_duration': []
    }

    try:
        # Find users with multiple active sessions
        active_users = db.session.query(
            AuditLog.user_id,
            func.count(AuditLog.id).label('session_count')
        ).filter(
            AuditLog.event_type == AuditLog.EVENT_SESSION_START,
            AuditLog.created_at >= datetime.utcnow() - timedelta(days=1),
            # No matching session_end event
            ~AuditLog.id.in_(
                db.session.query(AuditLog.id).filter(
                    AuditLog.event_type == AuditLog.EVENT_SESSION_END
                )
            )
        ).group_by(AuditLog.user_id).having(
            func.count(AuditLog.id) > 2  # More than 2 active sessions
        ).all()

        for user_id, count in active_users:
            result['concurrent_sessions'].append({
                'user_id': user_id,
                'session_count': count
            })

        # Find sessions where IP address changed
        sessions = AuditLog.query.filter(
            AuditLog.event_type.in_([AuditLog.EVENT_SESSION_START, AuditLog.EVENT_API_ACCESS]),
            AuditLog.created_at >= datetime.utcnow() - timedelta(days=1),
            AuditLog.ip_address != None  # Ensure IP address is not null
        ).order_by(
            AuditLog.user_id,
            AuditLog.created_at
        ).all()

        # Process sessions to detect IP changes
        user_sessions = {}
        for user_session in sessions:
            if not user_session.user_id:
                continue

            if user_session.user_id not in user_sessions:
                user_sessions[user_session.user_id] = {'ips': [], 'agents': []}

            if user_session.ip_address and user_session.ip_address not in user_sessions[user_session.user_id]['ips']:
                user_sessions[user_session.user_id]['ips'].append(user_session.ip_address)

            if user_session.user_agent and user_session.user_agent not in user_sessions[user_session.user_id]['agents']:
                user_sessions[user_session.user_id]['agents'].append(user_session.user_agent)

        # Flag users with multiple IPs or user agents
        for user_id, data in user_sessions.items():
            if len(data['ips']) > 2:
                result['ip_changes'].append({
                    'user_id': user_id,
                    'ip_addresses': data['ips']
                })

            if len(data['agents']) > 2:
                result['agent_changes'].append({
                    'user_id': user_id,
                    'user_agents': data['agents']
                })
    except Exception as e:
        current_app.logger.error(f"Error detecting session anomalies: {e}")

    return result

def detect_api_anomalies() -> Dict[str, List[Dict[str, Any]]]:
    """
    Detect suspicious API usage patterns and potential API abuse.

    This function analyzes API request patterns to identify potential
    security issues such as:
    - Unusual API request volume
    - Suspicious request patterns or sequences
    - Access attempts to unauthorized endpoints
    - API requests with malformed data
    - Endpoints experiencing unusually high error rates

    Returns:
        Dict[str, List[Dict[str, Any]]]: Dictionary containing API usage anomalies
    """
    result = {
        'high_volume': [],
        'error_rates': [],
        'unauthorized_attempts': [],
        'suspicious_patterns': []
    }

    try:
        # Check for high volume API requests
        endpoint_stats = db.session.query(
            func.label('endpoint', AuditLog.details),
            func.count(AuditLog.id).label('request_count')
        ).filter(
            AuditLog.event_type == AuditLog.EVENT_API_ACCESS,
            AuditLog.created_at >= datetime.utcnow() - timedelta(hours=1)
        ).group_by(
            AuditLog.details
        ).all()

        # Define threshold for unusual volume
        avg_count = sum([stat[1] for stat in endpoint_stats]) / len(endpoint_stats) if endpoint_stats else 0
        threshold = max(avg_count * 2, 100)  # Double average or at least 100

        # Find endpoints with unusual request volume
        for endpoint, count in endpoint_stats:
            if count > threshold:
                result['high_volume'].append({
                    'endpoint': endpoint,
                    'request_count': count,
                    'threshold': threshold
                })

        # Check for unauthorized access attempts
        unauthorized = AuditLog.query.filter(
            AuditLog.event_type == AuditLog.EVENT_PERMISSION_DENIED,
            AuditLog.created_at >= datetime.utcnow() - timedelta(hours=6)
        ).order_by(
            desc(AuditLog.created_at)
        ).limit(20).all()

        for attempt in unauthorized:
            result['unauthorized_attempts'].append({
                'user_id': attempt.user_id,
                'ip_address': attempt.ip_address,
                'endpoint': attempt.details,
                'timestamp': attempt.created_at.isoformat()
            })

        # Calculate error rates for endpoints
        error_rates = db.session.query(
            func.label('endpoint', AuditLog.details),
            func.sum(func.case((AuditLog.severity == AuditLog.SEVERITY_ERROR, 1), else_=0)).label('errors'),
            func.count(AuditLog.id).label('total_requests')
        ).filter(
            AuditLog.event_type == AuditLog.EVENT_API_ACCESS,
            AuditLog.created_at >= datetime.utcnow() - timedelta(hours=1)
        ).group_by(
            AuditLog.details
        ).having(
            func.count(AuditLog.id) > 10  # Only consider endpoints with sufficient traffic
        ).all()

        # Flag endpoints with high error rates
        for endpoint, errors, total in error_rates:
            error_rate = (errors / total) * 100
            if error_rate > 10:  # More than 10% error rate
                result['error_rates'].append({
                    'endpoint': endpoint,
                    'error_rate': error_rate,
                    'total_requests': total
                })
    except Exception as e:
        current_app.logger.error(f"Error detecting API anomalies: {e}")

    return result

def detect_database_anomalies() -> Dict[str, List[Dict[str, Any]]]:
    """
    Detect unusual database access patterns and potential data exfiltration.

    This function examines database activity to identify anomalous patterns
    that may indicate security breaches. It checks for:
    - Unusual access hours
    - Large result set queries
    - Access to sensitive tables
    - Abnormal modification patterns
    - Suspicious query patterns

    Returns:
        Dict[str, List[Dict[str, Any]]]: Dictionary containing database anomalies
    """
    result = {
        'large_queries': [],
        'sensitive_tables': [],
        'modification_patterns': [],
        'unusual_queries': [],
        'brute_force_attempts': []
    }

    try:
        # Define business hours (UTC time)
        business_hours_start = 9
        business_hours_end = 17

        # Check for database access outside normal hours
        off_hours_queries = AuditLog.query.filter(
            AuditLog.event_type == 'database_access',
            AuditLog.created_at >= datetime.utcnow() - timedelta(days=1),
            ~and_(
                func.extract('hour', AuditLog.created_at) >= business_hours_start,
                func.extract('hour', AuditLog.created_at) < business_hours_end
            )
        ).order_by(
            desc(AuditLog.created_at)
        ).limit(10).all()

        for query in off_hours_queries:
            try:
                details = json.loads(query.details) if isinstance(query.details, str) else query.details
                result['unusual_queries'].append({
                    'user_id': query.user_id,
                    'query_type': details.get('query_type', 'unknown'),
                    'timestamp': query.created_at.isoformat(),
                    'ip_address': query.ip_address,
                    'tables': details.get('tables', []),
                    'severity': 'medium'
                })
            except (json.JSONDecodeError, AttributeError):
                continue

        # Check for large result set queries (potential data exfiltration)
        large_queries = AuditLog.query.filter(
            AuditLog.event_type == 'database_access',
            AuditLog.created_at >= datetime.utcnow() - timedelta(days=1)
        ).order_by(
            desc(AuditLog.created_at)
        ).limit(100).all()

        for query in large_queries:
            try:
                details = json.loads(query.details) if isinstance(query.details, str) else query.details
                rows_returned = details.get('rows_returned', 0)
                if rows_returned > 1000:  # Threshold for large result sets
                    result['large_queries'].append({
                        'user_id': query.user_id,
                        'query_type': details.get('query_type', 'unknown'),
                        'timestamp': query.created_at.isoformat(),
                        'rows_returned': rows_returned,
                        'tables': details.get('tables', []),
                        'query_duration': details.get('duration_ms', 0),
                        'severity': 'high' if rows_returned > 10000 else 'medium'
                    })
            except (json.JSONDecodeError, AttributeError):
                continue

        # Check for access to sensitive tables
        sensitive_table_list = ['users', 'security_incidents', 'audit_logs', 'ics_devices', 'ics_readings']
        sensitive_access = AuditLog.query.filter(
            AuditLog.event_type == 'database_access',
            AuditLog.created_at >= datetime.utcnow() - timedelta(days=1)
        ).order_by(
            desc(AuditLog.created_at)
        ).limit(50).all()

        for access in sensitive_access:
            try:
                details = json.loads(access.details) if isinstance(access.details, str) else access.details
                tables = details.get('tables', [])

                sensitive_tables = [table for table in tables if table in sensitive_table_list]
                if sensitive_tables:
                    result['sensitive_tables'].append({
                        'user_id': access.user_id,
                        'timestamp': access.created_at.isoformat(),
                        'ip_address': access.ip_address,
                        'tables': sensitive_tables,
                        'query_type': details.get('query_type', 'unknown'),
                        'severity': 'high'
                    })
            except (json.JSONDecodeError, AttributeError):
                continue

        # Check for brute force login attempts
        brute_force_attempts = db.session.query(
            AuditLog.ip_address,
            func.count(AuditLog.id).label('attempt_count')
        ).filter(
            AuditLog.event_type == 'login_failed',
            AuditLog.created_at >= datetime.utcnow() - timedelta(minutes=30),
            AuditLog.ip_address != None
        ).group_by(
            AuditLog.ip_address
        ).having(
            func.count(AuditLog.id) > 5  # Threshold for brute force detection
        ).all()

        for ip_address, attempt_count in brute_force_attempts:
            result['brute_force_attempts'].append({
                'ip_address': ip_address,
                'attempt_count': attempt_count,
                'timestamp': datetime.utcnow().isoformat(),
                'severity': 'critical' if attempt_count > 20 else 'high'
            })
    except Exception as e:
        current_app.logger.error(f"Error detecting database anomalies: {e}")

    return result

def detect_file_access_anomalies(config_integrity=True, file_integrity=True) -> Dict[str, List[Dict[str, Any]]]:
    """
    Detect unusual file access patterns and potential unauthorized access.

    This function analyzes file access patterns to identify potential
    security issues.

    Args:
        config_integrity: Whether configuration integrity check passed
        file_integrity: Whether critical file integrity check passed

    Returns:
        Dict[str, List[Dict[str, Any]]]: Dictionary containing file access anomalies
    """
    result = {
        'sensitive_files': [],
        'suspicious_modifications': [],
        'unusual_access_times': [],
        'bulk_operations': []
    }

    try:
        # Check for access to sensitive files
        sensitive_paths = ['config', 'env', '.secret', 'credentials', 'password']
        sensitive_file_access = AuditLog.query.filter(
            AuditLog.event_type == AuditLog.EVENT_FILE_ACCESS,
            AuditLog.created_at >= datetime.utcnow() - timedelta(days=1),
            # Check if any sensitive path is mentioned in the details
            or_(*[AuditLog.details.ilike(f'%{path}%') for path in sensitive_paths])
        ).order_by(
            desc(AuditLog.created_at)
        ).limit(10).all()

        for access in sensitive_file_access:
            result['sensitive_files'].append({
                'user_id': access.user_id,
                'file_path': access.details,
                'timestamp': access.created_at.isoformat()
            })

        # Check for unusual file modifications
        file_modifications = AuditLog.query.filter(
            AuditLog.event_type == AuditLog.EVENT_FILE_MODIFIED,
            AuditLog.created_at >= datetime.utcnow() - timedelta(hours=24)
        ).order_by(
            desc(AuditLog.created_at)
        ).all()

        # Group file modifications by user
        user_modifications = {}
        for mod in file_modifications:
            user_id = mod.user_id or 'unknown'
            if user_id not in user_modifications:
                user_modifications[user_id] = []
            user_modifications[user_id].append({
                'file_path': mod.details,
                'timestamp': mod.created_at.isoformat()
            })

        # Check for users with many modifications
        for user_id, mods in user_modifications.items():
            if len(mods) > 10:  # More than 10 modifications in 24 hours
                result['bulk_operations'].append({
                    'user_id': user_id,
                    'modification_count': len(mods),
                    'time_period': '24 hours'
                })

        # Check for file access outside normal hours
        off_hours_access = AuditLog.query.filter(
            AuditLog.event_type.in_([AuditLog.EVENT_FILE_ACCESS, AuditLog.EVENT_FILE_MODIFIED]),
            AuditLog.created_at >= datetime.utcnow() - timedelta(days=1),
            ~and_(
                func.extract('hour', AuditLog.created_at) >= 9,
                func.extract('hour', AuditLog.created_at) < 17
            )
        ).order_by(
            desc(AuditLog.created_at)
        ).limit(10).all()

        for access in off_hours_access:
            result['unusual_access_times'].append({
                'user_id': access.user_id,
                'file_path': access.details,
                'timestamp': access.created_at.isoformat(),
                'action': access.event_type
            })

        # Add integrity check results
        if not config_integrity:
            result['suspicious_modifications'].append({
                'severity': 'critical',
                'description': 'Configuration file integrity check failed',
                'timestamp': datetime.utcnow().isoformat()
            })

        if not file_integrity:
            result['suspicious_modifications'].append({
                'severity': 'critical',
                'description': 'Critical file integrity check failed',
                'timestamp': datetime.utcnow().isoformat()
            })
    except Exception as e:
        current_app.logger.error(f"Error detecting file access anomalies: {e}")

    return result

def trigger_incident_response(breach_data: Dict[str, Any]) -> Optional[int]:
    """
    Trigger incident response procedures for high-threat security incidents.

    This function implements the incident response workflow when serious security
    threats are detected, including:
    - Creating a security incident record in the database
    - Notifying the security team via multiple channels
    - Logging detailed information about the threat
    - Initiating automated countermeasures if configured
    - Collecting forensic data for later analysis

    Args:
        breach_data: Dictionary containing detected anomalies and threat information

    Returns:
        Optional[int]: ID of the created security incident, or None if creation failed
    """
    try:
        # Calculate threat level if not already provided
        if 'threat_level' not in breach_data:
            breach_data['threat_level'] = calculate_threat_level(breach_data)

        # Log critical security event
        current_app.logger.critical(
            "CRITICAL SECURITY THREAT DETECTED - Initiating incident response",
            extra={'breach_data': breach_data}
        )

        # Create descriptive title based on primary threat
        title = "Security Incident Detected"
        if breach_data.get('login_anomalies', {}).get('suspicious_ips'):
            title = "Multiple Failed Login Attempts Detected"
        elif breach_data.get('database_anomalies', {}).get('sensitive_tables'):
            title = "Unusual Access to Sensitive Database Tables"
        elif breach_data.get('file_access_anomalies', {}).get('sensitive_files'):
            title = "Suspicious Access to Sensitive Files"
        elif breach_data.get('api_anomalies', {}).get('unauthorized_attempts'):
            title = "Unauthorized API Access Attempts"

        # Record incident in database
        incident = SecurityIncident(
            title=title,
            threat_level=breach_data.get('threat_level', 0),
            incident_type=breach_data.get('incident_type', 'unknown'),
            description=breach_data.get('description', 'No description provided'),
            details=json.dumps(breach_data, default=str),
            status='open',
            detected_at=datetime.utcnow(),
            source=breach_data.get('source', 'system')
        )
        db.session.add(incident)
        db.session.commit()

        # Create audit log entry for the incident
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_BREACH_ATTEMPT,
            description=f"Security incident detected: {title}",
            severity='critical'
        )

        # Track incident metrics
        INCIDENT_COUNTER.labels(threat_level=str(breach_data['threat_level'])).inc()

        # Notify security team via email
        security_emails = current_app.config.get('SECURITY_TEAM_EMAILS', [])
        if security_emails:
            send_email(
                to=security_emails,
                subject=f"SECURITY ALERT: {title} - Threat Level {breach_data['threat_level']}/10",
                text_content=(
                    f"Critical security incident detected at {datetime.utcnow().isoformat()}\n\n"
                    f"Incident ID: {incident.id}\n"
                    f"Title: {title}\n"
                    f"Threat Level: {breach_data['threat_level']}/10\n\n"
                    f"Details: {json.dumps(breach_data, default=str, indent=2)}"
                )
            )

        # Notify administrators through in-app notifications
        notify_administrators(
            f"SECURITY ALERT: {title} - Threat Level {breach_data['threat_level']}/10"
        )

        # Collect forensic data if threat level is high
        if breach_data['threat_level'] >= 8:
            collect_forensic_data(incident.id)

        # Initiate automated countermeasures for critical threats
        if breach_data['threat_level'] >= 9:
            initiate_countermeasures(breach_data)

        return incident.id

    except (OSError, ValueError, SQLAlchemyError) as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to create security incident: {e}")
        # Even if DB storage fails, still try to notify admins
        notify_administrators(
            f"CRITICAL SECURITY ALERT: {title if 'title' in locals() else 'Security Incident'} - "
            f"Threat Level {breach_data.get('threat_level', '?')}/10 "
            f"(Failed to record in database: {e})"
        )
        return None

def collect_forensic_data(incident_id: int) -> bool:
    """
    Collect forensic data for a security incident.

    This function gathers additional system and application data that might
    be useful for investigating the security incident.

    Args:
        incident_id: ID of the security incident

    Returns:
        bool: True if data collection succeeded, False otherwise
    """
    try:
        forensic_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'incident_id': incident_id,
            'processes': [],
            'connections': [],
            'system_resources': {},
            'recent_logs': []
        }

        # Collect process information
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time']):
                try:
                    forensic_data['processes'].append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except (ImportError, AttributeError):
            current_app.logger.warning("psutil not available for process collection")

        # Collect network connections
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                try:
                    forensic_data['connections'].append({
                        'fd': conn.fd,
                        'family': conn.family,
                        'type': conn.type,
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    })
                except (AttributeError, TypeError):
                    pass
        except (ImportError, AttributeError):
            current_app.logger.warning("psutil not available for connection collection")

        # Collect system resources
        try:
            forensic_data['system_resources'] = {
                'cpu': psutil.cpu_percent(interval=1, percpu=True),
                'memory': dict(psutil.virtual_memory()._asdict()),
                'disk': {
                    '/': dict(psutil.disk_usage('/')._asdict())
                }
            }
        except (ImportError, AttributeError):
            current_app.logger.warning("psutil not available for resource collection")

        # Collect recent logs from database
        recent_logs = AuditLog.query.filter(
            AuditLog.created_at >= datetime.utcnow() - timedelta(hours=1)
        ).order_by(desc(AuditLog.created_at)).limit(100).all()

        forensic_data['recent_logs'] = [log.to_dict() for log in recent_logs]

        # Save forensic data
        forensic_dir = current_app.config.get('FORENSIC_DATA_DIR', 'forensic_data')
        os.makedirs(forensic_dir, exist_ok=True)

        filename = f"incident_{incident_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(forensic_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(forensic_data, f, default=str, indent=2)

        current_app.logger.info(f"Forensic data collected for incident {incident_id} and saved to {filepath}")

        # Create audit log entry for forensic data collection
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_COUNTERMEASURE,
            description=f"Collected forensic data for incident {incident_id}",
            severity='info'
        )

        return True
    except (OSError, ValueError, SQLAlchemyError) as e:
        current_app.logger.error(f"Failed to collect forensic data: {e}")
        return False

def notify_administrators(message: str) -> None:
    """
    Send security breach notification to administrators.

    This function sends notifications to system administrators through
    multiple channels (in-app notifications and email for critical issues).

    Args:
        message: Message to send to administrators
    """
    try:
        # Get admin users
        admins = User.query.filter_by(role='admin').all()

        # Send in-app notification
        for admin in admins:
            # Add notification to database
            notification = Notification(
                user_id=admin.id,
                message=message,
                notification_type='security_alert',
                priority='high'
            )
            db.session.add(notification)

        db.session.commit()

        # Consider sending email for critical issues
        if 'breach' in message.lower() or 'critical' in message.lower():
            for admin in admins:
                if admin.email:
                    send_email(
                        to=admin.email,
                        subject=f"SECURITY ALERT: {message[:50]}...",
                        text_content=f"Security alert detected at {datetime.utcnow().isoformat()}\n\n{message}"
                    )
    except (ValueError, SQLAlchemyError, OSError) as e:
        current_app.logger.error(f"Failed to notify administrators: {e}")

def initiate_countermeasures(breach_data: Dict[str, Any]) -> None:
    """
    Initiate automated countermeasures for critical security threats.

    This function takes defensive actions based on the type of security
    threat detected.

    Args:
        breach_data: Dictionary containing detected anomalies and threat information
    """
    try:
        # Block suspicious IPs
        if breach_data.get('login_anomalies', {}).get('suspicious_ips'):
            suspicious_ips = [
                item.get('ip_address')
                for item in breach_data['login_anomalies']['suspicious_ips']
                if item.get('ip_address')
            ]

            for ip in suspicious_ips:
                # Validate IP address before blocking
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    current_app.logger.warning(f"Invalid IP address detected: {ip}")
                    continue

                # Implement IP blocking (depends on infrastructure)
                current_app.logger.info(f"Blocking suspicious IP: {ip}")

                # Log the countermeasure
                log_security_event(
                    event_type=AuditLog.EVENT_SECURITY_COUNTERMEASURE,
                    description=f"Blocked suspicious IP {ip}",
                    ip_address=ip,
                    severity='warning'
                )

        # Invalidate suspicious sessions
        if breach_data.get('session_anomalies', {}).get('ip_changes'):
            for session_data in breach_data['session_anomalies']['ip_changes']:
                user_id = session_data.get('user_id')
                if not user_id:
                    continue

                current_app.logger.info(f"Invalidating sessions for user {user_id}")

                # Implementation depends on session backend
                if hasattr(current_app.session_interface, 'invalidate_user_sessions'):
                    current_app.session_interface.invalidate_user_sessions(user_id)

                # Log the countermeasure
                log_security_event(
                    event_type=AuditLog.EVENT_SECURITY_COUNTERMEASURE,
                    description=f"Invalidated sessions for user {user_id} due to suspicious activity",
                    user_id=user_id,
                    severity='warning'
                )

        # Lock accounts with suspicious activity
        if breach_data.get('database_anomalies', {}).get('sensitive_tables'):
            for access in breach_data['database_anomalies']['sensitive_tables']:
                if access.get('user_id'):
                    user_id = access['user_id']
                    current_app.logger.info(f"Temporarily locking user account {user_id}")

                    # Lock the user account
                    user = User.query.get(user_id)
                    if user:
                        user.account_locked = True
                        user.lock_reason = "Suspicious database access detected"
                        db.session.add(user)
                        db.session.commit()

                    # Log the countermeasure
                    log_security_event(
                        event_type=AuditLog.EVENT_SECURITY_COUNTERMEASURE,
                        description=f"Locked account for user {user_id} due to suspicious database access",
                        user_id=user_id,
                        severity='warning'
                    )

    except (ValueError, SQLAlchemyError, OSError) as e:
        current_app.logger.error(f"Error initiating countermeasures: {e}")

# --- Helper functions for security metrics ---

def get_failed_login_count(hours: int = 24) -> int:
    """
    Get count of failed logins in the past hours.

    Args:
        hours: Number of hours to look back

    Returns:
        int: Count of failed logins
    """
    try:
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return AuditLog.query.filter(
            AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
            AuditLog.created_at >= cutoff
        ).count()
    except Exception as e:
        current_app.logger.error(f"Error getting failed login count: {e}")
        return 0

def get_account_lockout_count(hours: int = 24) -> int:
    """
    Get count of account lockouts in the past hours.

    Args:
        hours: Number of hours to look back

    Returns:
        int: Count of account lockouts
    """
    try:
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return AuditLog.query.filter(
            AuditLog.event_type == AuditLog.EVENT_ACCOUNT_LOCKOUT,
            AuditLog.created_at >= cutoff
        ).count()
    except Exception as e:
        current_app.logger.error(f"Error getting account lockout count: {e}")
        return 0

def get_active_session_count() -> int:
    """
    Get count of active user sessions.

    Returns:
        int: Count of active sessions
    """
    try:
        # This would depend on how you're storing sessions
        if hasattr(cache, 'config') and cache.config.get('CACHE_TYPE') == 'redis':
            import redis
            r = redis.from_url(cache.config.get('CACHE_REDIS_URL'))
            return len([k for k in r.scan_iter(match='session:*') or []])
        else:
            # Fallback to database tracking for sessions
            return AuditLog.query.filter(
                AuditLog.event_type == AuditLog.EVENT_SESSION_START,
                AuditLog.created_at >= datetime.utcnow() - timedelta(days=1),
                ~AuditLog.id.in_(
                    db.session.query(AuditLog.id).filter(
                        AuditLog.event_type == AuditLog.EVENT_SESSION_END
                    )
                )
            ).count()
    except Exception as e:
        current_app.logger.error(f"Error getting active session count: {e}")
        return 0

def calculate_threat_level(security_data: Dict[str, Any], baseline_risk: int = 1) -> int:
    """
    Calculate security risk score based on collected security data.

    This function analyzes various security metrics to determine an overall
    risk score for the system on a scale of 1-10 (10 being highest risk).

    Args:
        security_data: Dictionary containing security metrics
        baseline_risk: Starting risk score (1-10)

    Returns:
        int: Risk score on a scale of 1-10
    """
    try:
        score = baseline_risk  # Start with baseline risk

        # Extract metrics from security data
        login_anomalies = security_data.get('login_anomalies', {})
        api_anomalies = security_data.get('api_anomalies', {})
        db_anomalies = security_data.get('database_anomalies', {})
        file_anomalies = security_data.get('file_access_anomalies', {})
        security_metrics = security_data.get('security_metrics', {})

        # Risk factors from login anomalies
        if len(login_anomalies.get('suspicious_ips', [])) > 10:
            score += 3
        elif len(login_anomalies.get('suspicious_ips', [])) > 5:
            score += 2
        elif len(login_anomalies.get('suspicious_ips', [])) > 0:
            score += 1

        if len(login_anomalies.get('unusual_times', [])) > 5:
            score += 2
        elif len(login_anomalies.get('unusual_times', [])) > 0:
            score += 1

        # Risk factors from session anomalies
        if len(security_data.get('session_anomalies', {}).get('ip_changes', [])) > 0:
            score += 2  # IP changing in same session is highly suspicious

        if len(security_data.get('session_anomalies', {}).get('concurrent_sessions', [])) > 3:
            score += 2
        elif len(security_data.get('session_anomalies', {}).get('concurrent_sessions', [])) > 0:
            score += 1

        # Risk factors from API anomalies
        if len(api_anomalies.get('unauthorized_attempts', [])) > 10:
            score += 3
        elif len(api_anomalies.get('unauthorized_attempts', [])) > 0:
            score += 1

        if len(api_anomalies.get('high_volume', [])) > 5:
            score += 2
        elif len(api_anomalies.get('high_volume', [])) > 0:
            score += 1

        # Risk factors from database anomalies
        if len(db_anomalies.get('sensitive_tables', [])) > 0:
            score += 3  # Access to sensitive tables is particularly serious

        if len(db_anomalies.get('large_queries', [])) > 5:
            score += 2
        elif len(db_anomalies.get('large_queries', [])) > 0:
            score += 1

        if len(db_anomalies.get('brute_force_attempts', [])) > 0:
            score += 3  # Database brute force is critical

        # Risk factors from file access anomalies
        if len(file_anomalies.get('sensitive_files', [])) > 3:
            score += 2
        elif len(file_anomalies.get('sensitive_files', [])) > 0:
            score += 1

        if len(file_anomalies.get('suspicious_modifications', [])) > 0:
            severity_count = sum(1 for mod in file_anomalies.get('suspicious_modifications', [])
                                if mod.get('severity') == 'critical')
            if severity_count > 0:
                score += 3  # Critical severity file modifications
            else:
                score += 2  # Other suspicious file modifications

        # Risk factors from security metrics
        failed_logins_24h = security_metrics.get('failed_logins_24h', 0)
        if failed_logins_24h > 100:
            score += 3
        elif failed_logins_24h > 50:
            score += 2
        elif failed_logins_24h > 20:
            score += 1

        account_lockouts_24h = security_metrics.get('account_lockouts_24h', 0)
        if account_lockouts_24h > 5:
            score += 2
        elif account_lockouts_24h > 0:
            score += 1

        # Check file and configuration integrity
        if not security_data.get('file_access_anomalies', {}).get('config_integrity', True):
            score += 3  # Configuration integrity failure is serious

        if not security_data.get('file_access_anomalies', {}).get('file_integrity', True):
            score += 2  # Critical file integrity failure

        # Check for active incidents
        if security_metrics.get('incidents_active', 0) > 0:
            score += min(security_metrics.get('incidents_active', 0), 3)  # Add up to 3 points for active incidents

        # Additional checks for suspicious IPs from security metrics
        suspicious_ips = []
        if security_data.get('security_metrics', {}).get('suspicious_ips'):
            suspicious_ips = security_data['security_metrics']['suspicious_ips']

        if len(suspicious_ips) > 10:
            score += 2
        elif len(suspicious_ips) > 0:
            score += 1

        # Cap the risk score at 10
        return min(score, 10)

    except Exception as e:
        current_app.logger.error(f"Error calculating threat level: {e}")
        # Return default risk score on error
        return max(baseline_risk, 1)  # Ensure at least 1

def determine_response_actions(threat_level: int, anomalies: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Determine appropriate response actions based on threat level and anomalies.

    This function analyzes the threat level and specific anomalies to recommend
    appropriate security responses, prioritized by importance.

    Args:
        threat_level: Numeric threat level (1-10)
        anomalies: Dictionary containing detected anomalies

    Returns:
        List[Dict[str, str]]: List of recommended actions with priority and description
    """
    actions = []

    # Base actions on threat level severity
    if threat_level >= 8:  # Critical
        actions.append({
            'priority': 'critical',
            'action': 'initiate_incident_response',
            'description': 'Initiate full incident response protocol',
            'automated': True
        })
        actions.append({
            'priority': 'critical',
            'action': 'notify_security_team',
            'description': 'Notify security team immediately',
            'automated': True
        })

    elif threat_level >= 5:  # High
        actions.append({
            'priority': 'high',
            'action': 'escalate_to_security',
            'description': 'Escalate to security team for investigation',
            'automated': True
        })

    elif threat_level >= 3:  # Medium
        actions.append({
            'priority': 'medium',
            'action': 'monitor_closely',
            'description': 'Monitor system closely for further anomalies',
            'automated': False
        })

    # Add specific actions based on anomaly types
    if len(anomalies.get('login_anomalies', {}).get('suspicious_ips', [])) > 0:
        actions.append({
            'priority': 'high' if threat_level >= 7 else 'medium',
            'action': 'block_suspicious_ips',
            'description': 'Block suspicious IP addresses',
            'automated': threat_level >= 7  # Automate only for high threats
        })

    if len(anomalies.get('session_anomalies', {}).get('ip_changes', [])) > 0:
        actions.append({
            'priority': 'high',
            'action': 'invalidate_suspicious_sessions',
            'description': 'Invalidate sessions with suspicious IP changes',
            'automated': threat_level >= 5
        })

    if len(anomalies.get('database_anomalies', {}).get('sensitive_tables', [])) > 0:
        actions.append({
            'priority': 'high',
            'action': 'review_sensitive_data_access',
            'description': 'Review all access to sensitive database tables',
            'automated': False
        })

    if not anomalies.get('file_access_anomalies', {}).get('config_integrity', True):
        actions.append({
            'priority': 'critical',
            'action': 'restore_configuration',
            'description': 'Restore configuration files from verified backup',
            'automated': False  # Requires human review
        })

    if len(anomalies.get('database_anomalies', {}).get('brute_force_attempts', [])) > 0:
        actions.append({
            'priority': 'critical',
            'action': 'lock_affected_accounts',
            'description': 'Lock accounts targeted by brute force attempts',
            'automated': True
        })

    # Sort actions by priority (critical, high, medium, low)
    priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    actions.sort(key=lambda x: priority_order.get(x['priority'], 4))

    return actions


def log_threat_assessment(security_data: Dict[str, Any], threat_level: int,
                          user_id: Optional[str] = None) -> None:
    """
    Log comprehensive threat assessment for auditing and analysis.

    This function creates detailed audit log entries for security threat
    assessments, providing a historical record of security incidents and
    the algorithm's decision process.

    Args:
        security_data: Dictionary containing detected anomalies and metrics
        threat_level: Calculated threat level (1-10)
        user_id: Optional user ID who triggered the assessment
    """
    severity = _determine_severity(threat_level)

    # Create summary of key threats for logging
    threat_summary = []

    # Check login anomalies
    login_anomalies = security_data.get('login_anomalies', {})
    if len(login_anomalies.get('suspicious_ips', [])) > 0:
        threat_summary.append(f"{len(login_anomalies['suspicious_ips'])} suspicious IPs")

    # Check session anomalies
    session_anomalies = security_data.get('session_anomalies', {})
    if len(session_anomalies.get('ip_changes', [])) > 0:
        threat_summary.append(f"{len(session_anomalies['ip_changes'])} session IP changes")
    if len(session_anomalies.get('concurrent_sessions', [])) > 0:
        threat_summary.append(f"{len(session_anomalies['concurrent_sessions'])} concurrent sessions")

    # Check database anomalies
    db_anomalies = security_data.get('database_anomalies', {})
    if len(db_anomalies.get('sensitive_tables', [])) > 0:
        threat_summary.append(f"{len(db_anomalies['sensitive_tables'])} sensitive table accesses")
    if len(db_anomalies.get('brute_force_attempts', [])) > 0:
        threat_summary.append(f"{len(db_anomalies['brute_force_attempts'])} brute force attempts")

    # Check file anomalies
    file_anomalies = security_data.get('file_access_anomalies', {})
    if len(file_anomalies.get('sensitive_files', [])) > 0:
        threat_summary.append(f"{len(file_anomalies['sensitive_files'])} sensitive file accesses")
    if not file_anomalies.get('config_integrity', True):
        threat_summary.append("configuration integrity failure")

    # Build the summary message
    summary_text = ", ".join(threat_summary) if threat_summary else "no specific threats"
    log_message = f"Security threat assessment: level {threat_level}/10 ({severity}) - {summary_text}"

    # Log the threat assessment
    log_security_event(
        event_type="threat_assessment",
        description=log_message,
        severity=severity,
        user_id=user_id,
        ip_address=request.remote_addr if request else None,
        details={
            'threat_level': threat_level,
            'assessment_time': datetime.utcnow().isoformat(),
            'security_data': security_data
        }
    )

    # Also log to application logger
    current_app.logger.warning(log_message)


def get_threat_level_description(threat_level: int) -> Dict[str, str]:
    """
    Convert numeric threat level to human-readable description with recommendations.

    This function provides a standardized way to describe threat levels
    with consistent terminology and recommended actions.

    Args:
        threat_level: Numeric threat level (1-10)

    Returns:
        Dict[str, str]: Dictionary with severity, description, and recommended action
    """
    if threat_level >= 9:
        return {
            'severity': 'critical',
            'description': 'Critical security threat requiring immediate action',
            'recommended_action': 'Initiate full incident response protocol and notify security team immediately',
            'monitoring_level': 'continuous',
            'response_time': 'immediate',
            'ttl': '1 hour'
        }
    elif threat_level >= 7:
        return {
            'severity': 'high',
            'description': 'High security threat requiring prompt investigation',
            'recommended_action': 'Escalate to security team and investigate suspicious activities',
            'monitoring_level': 'heightened',
            'response_time': 'within 2 hours',
            'ttl': '4 hours'
        }
    elif threat_level >= 5:
        return {
            'severity': 'medium',
            'description': 'Elevated security risk requiring attention',
            'recommended_action': 'Review detected anomalies and increase monitoring',
            'monitoring_level': 'increased',
            'response_time': 'within 8 hours',
            'ttl': '12 hours'
        }
    elif threat_level >= 3:
        return {
            'severity': 'low',
            'description': 'Minor security anomalies detected',
            'recommended_action': 'Monitor system activity and verify alerts',
            'monitoring_level': 'normal',
            'response_time': 'within 24 hours',
            'ttl': '24 hours'
        }
    else:
        return {
            'severity': 'informational',
            'description': 'No significant security concerns detected',
            'recommended_action': 'Continue normal monitoring procedures',
            'monitoring_level': 'baseline',
            'response_time': 'routine',
            'ttl': '48 hours'
        }
