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
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List
from functools import wraps
from sqlalchemy import desc, func, or_, and_
from sqlalchemy.exc import SQLAlchemyError
from flask import Blueprint, request, jsonify, session, current_app, Response, g
from flask_wtf.csrf import CSRFProtect
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from extensions import db, cache, limiter
from models.security_incident import SecurityIncident
from models.audit_log import AuditLog
from models.user import User  # Added for user account locking
from core.security_utils import (
    get_security_metrics, 
    calculate_threat_level, 
    log_security_event,
     check_critical_file_integrity
)

# Configure monitoring blueprint
monitoring_bp = Blueprint('monitoring', __name__, url_prefix='/monitoring')

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

@monitoring_bp.after_request
def apply_security_headers(response):
    """Apply security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

@monitoring_bp.route('/health')
@measure_latency
def health_check():
    """
    Simple health check endpoint for infrastructure monitoring.
    
    This endpoint returns a 200 OK response if the application is running
    and can connect to its database, indicating that the service is healthy.
    """
    try:
        # Check database connection
        db_healthy = False
        try:
            try:
                db.session.execute("SELECT 1")
                db_healthy = True
            except SQLAlchemyError:
                db_healthy = False
        except SQLAlchemyError:
            db_healthy = False
        
        # Check cache connection
        cache_healthy = cache.get('health_check') is not None
        
        health_status = {
            'status': 'healthy' if db_healthy and cache_healthy else 'degraded',
            'timestamp': datetime.utcnow().isoformat(),
            'components': {
                'database': 'healthy' if db_healthy else 'unhealthy',
                'cache': 'healthy' if cache_healthy else 'unhealthy',
                'app': 'healthy'
            }
        }
        
        status_code = 200 if health_status['status'] == 'healthy' else 503
        return jsonify(health_status), status_code
    except (SQLAlchemyError, OSError) as e:
        current_app.logger.error(f"Health check error: {e}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500

@monitoring_bp.route('/status')
@limiter.limit("10/minute")
@admin_required
@measure_latency
def security_status():
    """
    Get current security status summary.
    
    This endpoint provides an overview of the system's security status,
    including recent failed login attempts, active sessions, suspicious IPs,
    and configuration integrity.
    
    Returns a JSON object with security metrics and an overall risk score.
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

@monitoring_bp.route('/anomalies', methods=['GET'])
@limiter.limit('10/hour')
@admin_required
def detect_anomalies():
    """
    Detect security anomalies across the system.
    
    This endpoint performs a comprehensive security scan to detect anomalies
    in login patterns, session activity, API usage, database access, and
    file system activity that may indicate security breaches.
    
    Returns:
        Response: JSON response with detected anomalies across various categories
    """
    try:
        # Check cache first to avoid frequent expensive scans
        cached_result = cache.get('last_anomaly_scan')
        if cached_result and not request.args.get('force'):
            return format_response(cached_result)
        
        # Get baseline security metrics first
        security_metrics = get_security_metrics(hours=24)
        
        # Collect detailed anomalies across different areas
        # (Use security_metrics data where possible to avoid duplicate queries)
        anomalies = {
            'login_anomalies': detect_login_anomalies(
                suspicious_ips=security_metrics['suspicious_ips']
            ),
            'session_anomalies': detect_session_anomalies(),
            'api_anomalies': detect_api_anomalies(),
            'database_anomalies': detect_database_anomalies(),
            'file_access_anomalies': detect_file_access_anomalies(
                config_integrity=security_metrics['config_integrity'],
                file_integrity=security_metrics['file_integrity']
            )
        }
        
        # Add relevant security metrics to anomaly report
        anomalies['security_metrics'] = {
            'failed_logins_24h': security_metrics['failed_logins_24h'],
            'account_lockouts_24h': security_metrics['account_lockouts_24h'],
            'active_sessions': security_metrics['active_sessions'],
            'incidents_active': security_metrics['incidents_active']
        }
        
        # Calculate threat level - use baseline risk score as a factor
        baseline_risk = security_metrics['risk_score']
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


def _determine_severity(threat_level):
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
        pass
        return 'low'

@monitoring_bp.route('/metrics')
@limiter.limit("10/minute")
@admin_required
def prometheus_metrics():
    """
    Expose Prometheus metrics for monitoring.
    
    This endpoint returns metrics in the Prometheus text format,
    which can be scraped by a Prometheus server for monitoring and alerting.
    """
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

@monitoring_bp.route('/incidents')
@limiter.limit("20/minute")
@admin_required
@measure_latency
def list_incidents():
    """
    List security incidents with optional filtering.
    
    This endpoint returns a list of security incidents, with optional filtering
    by status, threat level, and time range. Results are paginated.
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

@monitoring_bp.route('/incidents/<int:incident_id>')
@limiter.limit("30/minute")
@admin_required
def get_incident(incident_id):
    """
    Get detailed information about a security incident.
    
    This endpoint returns detailed information about a specific security incident,
    including its threat level, status, and details about the detected anomalies.
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

@monitoring_bp.route('/incidents/<int:incident_id>', methods=['PUT'])
@csrf.exempt  # For API usage
@limiter.limit("10/minute")
@admin_required
def update_incident(incident_id):
    """
    Update a security incident.

    This endpoint allows updating the status, resolution, and notes for a security incident.
    Only admin users can update incidents.
    """
    try:
        incident = SecurityIncident.query.get_or_404(incident_id)
        data = request.get_json()

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

@monitoring_bp.route('/forensics/<int:incident_id>')
@limiter.limit("5/minute")
@admin_required
def get_forensic_data(incident_id):
    """
    Get forensic data collected for a security incident.
    
    This endpoint returns the forensic data collected during incident response,
    which may include process information, network connections, and system resources.
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
                    from core.security_utils import log_security_event

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
        
        if len(suspicious_ips) > 0:
            return True
            
        # Check for unusual API access patterns
        api_requests = AuditLog.query.filter(
            AuditLog.event_type == AuditLog.EVENT_API_ACCESS,
            AuditLog.created_at >= func.now() - timedelta(minutes=5)
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

def detect_login_anomalies(suspicious_ips=None):
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
        Dict[str, Any]: Dictionary containing login anomalies
    """
    result = {
        'failed_attempts': [],
        'unusual_locations': [],
        'suspicious_ips': [],
        'unusual_times': []
    }
    
    # Use provided suspicious IPs if available, otherwise fetch them
    if suspicious_ips is None:
        from core.security_utils import get_suspicious_ips
        suspicious_ip_data = get_suspicious_ips(hours=24, min_attempts=5)
    else:
        suspicious_ip_data = suspicious_ips
    
    # Format suspicious IPs data
    for ip_data in suspicious_ip_data:
        ip = ip_data.get('ip')
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
    
    # Return compiled results
    return result

def detect_session_anomalies() -> Dict[str, Any]:
    """
    Detect unusual session activity and potential session hijacking.
    
    This function examines session data to identify anomalies that may
    indicate session hijacking or token theft, including:
    - Rapid changes in user-agent or IP within the same session
    - Multiple simultaneous active sessions for the same user
    - Session durations outside typical usage patterns
    - Unusual navigation patterns within a session
    
    Returns:
        Dict[str, Any]: Dictionary containing session anomalies
    """
    result = {
        'ip_changes': [],
        'agent_changes': [],
        'concurrent_sessions': [],
        'unusual_duration': []
    }
    
    # Find users with multiple active sessions
    active_users = db.session.query(
        AuditLog.user_id,
        func.count(AuditLog.id).label('session_count')
    ).filter(
        AuditLog.event_type == AuditLog.EVENT_SESSION_START,
        AuditLog.created_at >= func.now() - timedelta(days=1),
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
        AuditLog.ip_address is not None
    ).order_by(
        AuditLog.user_id,
        AuditLog.created_at
    ).all()
    
    # Process sessions to detect IP changes
    user_sessions = {}
    for user_session in sessions:
        if user_session.user_id not in user_sessions:
            user_sessions[user_session.user_id] = {'ips': [], 'agents': []}
        
        if user_session.ip_address not in user_sessions[user_session.user_id]['ips']:
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
    
    return result

def detect_api_anomalies() -> Dict[str, Any]:
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
        Dict[str, Any]: Dictionary containing API usage anomalies
    """
    result = {
        'high_volume': [],
        'error_rates': [],
        'unauthorized_attempts': [],
        'suspicious_patterns': []
    }
    
    # Check for high volume API requests
    endpoint_stats = db.session.query(
        func.label('endpoint', AuditLog.details),
        func.count(AuditLog.id).label('request_count')
    ).filter(
        AuditLog.event_type == AuditLog.EVENT_API_ACCESS,
        AuditLog.created_at >= func.now() - timedelta(hours=1)
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
    
    return result

def detect_database_anomalies() -> Dict[str, Any]:
    """
    Detect unusual database access patterns and potential data exfiltration.
    
    This function examines database activity to identify anomalous patterns
    that may indicate security breaches.
    
    Returns:
        Dict[str, Any]: Dictionary containing database anomalies
    """
    result = {
        'large_queries': [],
        'sensitive_tables': [],
        'modification_patterns': [],
        'unusual_queries': []
    }
    
    # Check for database access outside normal hours
    off_hours_queries = AuditLog.query.filter(
        AuditLog.event_type == 'database_access',
        AuditLog.created_at >= datetime.utcnow() - timedelta(days=1),
        ~and_(
            func.extract('hour', AuditLog.created_at) >= 9,
            func.extract('hour', AuditLog.created_at) < 17
        )
    ).order_by(
        desc(AuditLog.created_at)
    ).limit(10).all()
    
    for query in off_hours_queries:
        result['unusual_queries'].append({
            'user_id': query.user_id,
            'query_type': query.details,
            'timestamp': query.created_at.isoformat()
        })
    
    # Check for access to sensitive tables
    sensitive_tables = ['users', 'security_incidents', 'audit_logs', 'notifications']
    sensitive_accesses = AuditLog.query.filter(
        AuditLog.event_type == 'database_access',
        AuditLog.created_at >= datetime.utcnow() - timedelta(days=1),
        # Check if any sensitive table is mentioned in the details
        or_(*[AuditLog.details.op('ilike')(f'%{table}%') for table in sensitive_tables])
    ).order_by(
        desc(AuditLog.created_at)
    ).limit(10).all()
    
    for access in sensitive_accesses:
        result['sensitive_tables'].append({
            'user_id': access.user_id,
            'query_details': access.details,
            'timestamp': access.created_at.isoformat()
        })
    
    # Check for unusual data modification patterns
    modification_patterns = db.session.query(
        AuditLog.user_id,
        func.count(AuditLog.id).label('delete_count')
    ).filter(
        AuditLog.event_type == 'database_access',
        AuditLog.details.op('ilike')('%DELETE%'),
        AuditLog.created_at >= datetime.utcnow() - timedelta(hours=1)
    ).group_by(
        AuditLog.user_id
    ).having(
        func.count(AuditLog.id) > 5  # More than 5 deletes in an hour
    ).all()
    
    for user_id, count in modification_patterns:
        result['modification_patterns'].append({
            'user_id': user_id,
            'delete_operations': count,
            'time_period': '1 hour'
        })
    
    return result

def detect_file_access_anomalies() -> Dict[str, Any]:
    """
    Detect unusual file access patterns and potential unauthorized access.
    
    This function analyzes file access patterns to identify potential
    security issues.
    
    Returns:
        Dict[str, Any]: Dictionary containing file access anomalies
    """
    result = {
        'sensitive_files': [],
        'suspicious_modifications': [],
        'unusual_access_times': [],
        'bulk_operations': []
    }
    
    # Check for access to sensitive files
    sensitive_paths = ['config', 'env', '.secret', 'credentials', 'password']
    sensitive_file_access = AuditLog.query.filter(
        AuditLog.event_type == AuditLog.EVENT_FILE_ACCESS,
        AuditLog.created_at >= datetime.utcnow() - timedelta(days=1),
        # Check if any sensitive path is mentioned in the details
        or_(*[AuditLog.details.op('ilike')(f'%{path}%') for path in sensitive_paths])
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
    
    return result

from core.security_utils import calculate_threat_level

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
            threat_level=breach_data['threat_level'],
            details=str(breach_data),
            status='open',
            detected_at=datetime.utcnow(),
            source='system'
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
        db.session.rollback()  # Ensure database consistency
        db.session.rollback()  # Ensure database consistency
        current_app.logger.error(f"Failed to create security incident: {e}")
        # Even if DB storage fails, still try to notify admins
        notify_administrators(
            f"CRITICAL SECURITY ALERT: {title} - Threat Level {breach_data['threat_level']}/10 (Failed to record in database: {e})"
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
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time']):
            try:
                forensic_data['processes'].append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Collect network connections
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
        
        # Collect system resources
        forensic_data['system_resources'] = {
            'cpu': psutil.cpu_percent(interval=1, percpu=True),
            'memory': dict(psutil.virtual_memory()._asdict()),
            'disk': {
                '/': dict(psutil.disk_usage('/')._asdict())
            }
        }
        
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
                
            for ip in suspicious_ips:
                # Validate IP address before blocking
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    current_app.logger.warning(f"Invalid IP address detected: {ip}")
                    continue
                
                # Implement IP blocking (depends on infrastructure)
                current_app.logger.info(f"Blocking suspicious IP: {ip}")
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
                user_id = session_data['user_id']
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
    """Get count of failed logins in the past hours."""
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    return AuditLog.query.filter(
        AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
        AuditLog.created_at >= cutoff
    ).count()

def get_account_lockout_count(hours: int = 24) -> int:
    """Get count of account lockouts in the past hours."""
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    return AuditLog.query.filter(
        AuditLog.event_type == AuditLog.EVENT_ACCOUNT_LOCKOUT,
        AuditLog.created_at >= cutoff
    ).count()

def get_active_session_count() -> int:
    """Get count of active user sessions."""
    # This would depend on how you're storing sessions
    if cache.config.get('CACHE_TYPE') == 'redis':
        import redis
        r = redis.from_url(cache.config.get('CACHE_REDIS_URL'))
        return len([k for k in r.keys('session:*') or []])
    else:
        # Placeholder for other session storage mechanisms
        return AuditLog.query.filter(
            AuditLog.event_type == AuditLog.EVENT_SESSION_START,
            AuditLog.created_at >= datetime.utcnow() - timedelta(days=1),
            ~AuditLog.id.in_(
                db.session.query(AuditLog.id).filter(
                    AuditLog.event_type == AuditLog.EVENT_SESSION_END
                )
            )
        ).count()

def calculate_risk_score(security_data: Dict[str, Any]) -> int:
    """
    Calculate security risk score based on collected security data.
    
    This function analyzes various security metrics to determine an overall
    risk score for the system on a scale of 1-10 (10 being highest risk).
    It considers factors like failed login attempts, account lockouts,
    suspicious IP addresses, and file integrity violations.
    
    Args:
        security_data: Dictionary containing security metrics including:
            - failed_logins_24h: Number of failed logins in past 24 hours
            - account_lockouts_24h: Number of account lockouts in past 24 hours
            - suspicious_ips: List of suspicious IP addresses
            - config_integrity: Boolean indicating config file integrity status
            - file_integrity: Boolean indicating critical file integrity status
        
    Returns:
        int: Risk score on a scale of 1-10
    """
    score = 1  # Start with minimum risk
    
    # Risk factors and their corresponding score increments
    risk_factors = [
        # Failed login thresholds
        (security_data['failed_logins_24h'] > 100, 3),
        (security_data['failed_logins_24h'] > 50, 2),
        (security_data['failed_logins_24h'] > 20, 1),
        
        # Account lockouts
        (security_data['account_lockouts_24h'] > 5, 2),
        (security_data['account_lockouts_24h'] > 0, 1),
        
        # Suspicious IPs
        (len(security_data['suspicious_ips']) > 10, 3),
        (len(security_data['suspicious_ips']) > 0, 1),
        
        # File integrity
        (not security_data.get('config_integrity', True), 3),
        (not security_data.get('file_integrity', True), 2)
    ]
    
    # Apply each risk factor
    for condition, increment in risk_factors:
        if condition:
            score += increment
            
    # Cap at maximum risk of 10
    return min(score, 10)
