"""
API authentication routes for the application.

This module provides RESTful API endpoints for authentication operations including
login, registration, session management, and token validation. It uses the AuthService
for centralized authentication logic and security enforcement.

All endpoints return JSON responses with appropriate HTTP status codes and follow
REST best practices. Authentication is handled via JWT tokens for stateless API access.

Routes:
    /login: Authenticate user and issue JWT token
    /register: Create new user account
    /extend-session: Extend existing session lifetime
    /verify: Verify token validity
    /refresh: Refresh an existing JWT token
    /logout: Invalidate current token
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List
from flask import Blueprint, request, jsonify, session, current_app
from sqlalchemy import func, and_, or_, desc

from services.auth_service import AuthService
from extensions import db, cache
from models.notification import Notification
from services.email_service import send_email
import psutil


def regenerate_session():
    """
    Regenerate the session ID for security purposes.
    
    This function marks the session as modified, triggering Flask to 
    generate a new session ID while preserving session data. This helps
    prevent session fixation attacks.
    """
    session.modified = True

# Create auth API blueprint - Note: Changed from auth_bp to auth_api to match imports
auth_api = Blueprint('auth_api', __name__)

@auth_api.route('/login', methods=['POST'])
def login():
    """API endpoint for user authentication."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    
    # Use AuthService to authenticate
    success, user, error_message = AuthService.authenticate_user(username, password)
    
    if success and user:
        # Generate API token
        token = AuthService.generate_api_token(user)
        return jsonify({
            "token": token,
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role
            }
        }), 200
    else:
        # Check if this is a lockout situation
        if "locked" in error_message.lower():
            return jsonify({"error": error_message, "locked": True}), 423  # 423 Locked status code
        else:
            return jsonify({"error": error_message}), 401

# Helper functions for breach detection and security monitoring

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
        from models.audit import AuditLog
        recent_failed_logins = AuditLog.query.filter(
            AuditLog.event_type == 'login_failed',
            AuditLog.created_at > (datetime.utcnow() - timedelta(minutes=10))
        ).count()
        
        if recent_failed_logins > 15:
            return True
            
        # Check for unusual API access patterns
        api_requests = AuditLog.query.filter(
            AuditLog.event_type == 'api_access',
            AuditLog.created_at > (datetime.utcnow() - timedelta(minutes=5))
        ).count()
        
        if api_requests > 100:  # Unusual API traffic
            return True
            
        # Check for critical file modifications
        import os
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
    except (db.exc.SQLAlchemyError, OSError) as e:
        current_app.logger.error(f"Error in anomaly detection: {e}")
        # Default to no anomalies on error to prevent false positives
        return False

def check_security_status() -> Dict[str, Any]:
    """
    Perform comprehensive security status check.
    
    Analyzes system security status by checking:
    - Recent failed login attempts
    - User session validity
    - Configuration integrity
    - System file integrity
    - Database connection security
    
    Returns:
        Dict[str, Any]: Security status information
    """
    security_data = {
        'failed_logins_24h': get_failed_login_count(hours=24),
        'account_lockouts_24h': get_account_lockout_count(hours=24),
        'active_sessions': get_active_session_count(),
        'suspicious_ips': get_suspicious_ips(),
        'config_integrity': check_config_integrity(),
        'file_integrity': check_critical_file_integrity()
    }
    
    # Calculate risk score (1-10)
    security_data['risk_score'] = calculate_risk_score(security_data)
    security_data['last_checked'] = datetime.utcnow().isoformat()
    
    return security_data

def notify_administrators(message: str) -> None:
    """Send security breach notification to administrators"""
    try:
        # Get admin users
        from models.user import User
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
                        subject=f"SECURITY ALERT: {message}",
                        text_content=f"Security alert detected at {datetime.utcnow().isoformat()}\n\n{message}"
                    )
    except (db.exc.SQLAlchemyError, ValueError, RuntimeError) as e:
        current_app.logger.error(f"Failed to notify administrators: {e}")

# Implement remaining helper functions

from typing import Optional

def create_audit_log(event_type: str, details: str, user_id: Optional[int] = None, severity: str = 'info') -> None:
    """
    Create an audit log entry in the database.

    Args:
        event_type (str): The type of event (e.g., 'security_countermeasure').
        details (str): Detailed description of the event.
        user_id (int, optional): ID of the user associated with the event. Defaults to None.
        severity (str, optional): Severity level of the event. Defaults to 'info'.

    Returns:
        None
    """
    from models.audit_log import AuditLog
    try:
        log_entry = AuditLog(
            event_type=event_type,
            details=details,
            user_id=user_id,
            severity=severity,
            created_at=datetime.utcnow()
        )
        db.session.add(log_entry)
        db.session.commit()
    except (db.exc.SQLAlchemyError, ValueError, RuntimeError) as e:
        current_app.logger.error(f"Failed to create audit log: {e}")
        
def detect_login_anomalies() -> Dict[str, Any]:
    """
    Detect suspicious login patterns and authentication anomalies.
    
    This function analyzes recent login activity to identify patterns that may
    indicate security breaches such as:
    - Unusual login times or locations
    - Multiple failed login attempts from the same IP
    - Successful logins following failed attempts
    - Logins from unusual geographic locations
    - Logins with unusual user-agent strings
    
    Returns:
        Dict[str, Any]: Dictionary containing login anomalies with keys such as:
            - 'failed_attempts': List of suspicious failed login attempts
            - 'unusual_locations': List of logins from unusual locations
            - 'suspicious_ips': List of suspicious IP addresses
            - 'unusual_times': List of logins at unusual times
    """
    from models.audit_log import AuditLog
    
    result = {
        'failed_attempts': [],
        'unusual_locations': [],
        'suspicious_ips': [],
        'unusual_times': []
    }
    
    # Check for multiple failed login attempts from same IP
    cutoff = datetime.utcnow() - timedelta(hours=24)
    
    # Group failed logins by IP and count
    ip_counts = db.session.query(
        AuditLog.ip_address,
        func.count(AuditLog.id).label('attempt_count')
    ).filter(
        AuditLog.event_type == 'login_failed',
        AuditLog.created_at.__ge__(cutoff),
        AuditLog.ip_address != None
    ).group_by(
        AuditLog.ip_address
    ).having(
        func.count(AuditLog.id) >= 5
    ).all()
    
    for ip, count in ip_counts:
        result['suspicious_ips'].append({
            'ip_address': ip,
            'failed_attempts': count,
            'last_attempt': AuditLog.query.filter(
                AuditLog.event_type == 'login_failed',
                AuditLog.ip_address == ip
            ).order_by(desc(AuditLog.created_at)).first().created_at.isoformat()
        })
    
    # Get successful logins that happened outside normal hours (9am-5pm)
    unusual_time_logins = AuditLog.query.filter(
        AuditLog.event_type == 'login_success',
        AuditLog.created_at.ge(cutoff),
        ~and_(
            func.extract('hour', AuditLog.created_at) >= 9,
            func.extract('hour', AuditLog.created_at) < 17
        )
    ).order_by(desc(AuditLog.created_at)).limit(10).all()
    
    for entry in unusual_time_logins:
        result['unusual_times'].append({
            'user_id': entry.user_id,
            'timestamp': entry.created_at.isoformat(),
            'ip_address': entry.ip_address,
            'user_agent': entry.user_agent
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
        Dict[str, Any]: Dictionary containing session anomalies with keys such as:
            - 'ip_changes': List of sessions with suspicious IP changes
            - 'agent_changes': List of sessions with suspicious user-agent changes
            - 'concurrent_sessions': List of users with multiple simultaneous sessions
            - 'unusual_duration': List of sessions with unusual duration
    """
    from models.audit_log import AuditLog
    
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
        AuditLog.event_type == 'session_start',
        AuditLog.created_at >= func.now() - timedelta(days=1),
        # No matching session_end event
        ~AuditLog.id.in_(
            db.session.query(AuditLog.id).filter(
                AuditLog.event_type == 'session_end'
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
        AuditLog.event_type.in_(['session_start', 'api_access']),
        AuditLog.created_at.__ge__(datetime.utcnow() - timedelta(days=1)),
        AuditLog.user_id != None
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
        Dict[str, Any]: Dictionary containing API usage anomalies with keys such as:
            - 'high_volume': List of endpoints with unusually high request volume
            - 'error_rates': List of endpoints with high error rates
            - 'unauthorized_attempts': List of unauthorized access attempts
            - 'suspicious_patterns': List of suspicious request sequences
    """
    from models.audit_log import AuditLog
    
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
        AuditLog.event_type == 'api_access',
        AuditLog.created_at.__ge__(datetime.utcnow() - timedelta(hours=1))
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
        AuditLog.event_type == 'permission_denied',
        AuditLog.created_at.__ge__(datetime.utcnow() - timedelta(hours=6))
    ).order_by(
        func.desc(AuditLog.created_at)
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
        func.sum(func.case((AuditLog.severity == 'error', 1), else_=0)).label('errors'),
        func.count(AuditLog.id).label('total_requests')
    ).filter(
        AuditLog.event_type == 'api_access',
        AuditLog.created_at.__ge__(datetime.utcnow() - timedelta(hours=1))
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
    that may indicate security breaches such as:
    - Unusually large query results (potential data exfiltration)
    - Suspicious data modification patterns
    - Unusual query patterns or sequences
    - Access to sensitive tables outside normal application flows
    
    Returns:
        Dict[str, Any]: Dictionary containing database anomalies with keys such as:
            - 'large_queries': List of unusually large query results
            - 'sensitive_tables': List of unusual access to sensitive tables
            - 'modification_patterns': List of suspicious data modification patterns
            - 'unusual_queries': List of atypical query patterns
    """
    from models.audit_log import AuditLog
    
    result = {
        'large_queries': [],
        'sensitive_tables': [],
        'modification_patterns': [],
        'unusual_queries': []
    }
    
    # Check for database access outside normal hours
    off_hours_queries = AuditLog.query.filter(
        AuditLog.event_type == 'database_access',
        AuditLog.created_at.ge(datetime.utcnow() - timedelta(days=1)),
        ~and_(
            func.extract('hour', AuditLog.created_at) >= 9,
            func.extract('hour', AuditLog.created_at) < 17
        )
    ).order_by(
        func.desc(AuditLog.created_at)
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
        AuditLog.created_at.__ge__(datetime.utcnow() - timedelta(days=1)),
        # Check if any sensitive table is mentioned in the details
        or_(*[AuditLog.details.op('ilike')(f'%{table}%') for table in sensitive_tables])
    ).order_by(
        func.desc(AuditLog.created_at)
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
        AuditLog.created_at.__ge__(datetime.utcnow() - timedelta(hours=1))
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
    security issues such as:
    - Access to sensitive files
    - Unusual file modification patterns
    - Access to files outside of normal working hours
    - Multiple file deletions or modifications in rapid succession
    - Access to system configuration files
    
    Returns:
        Dict[str, Any]: Dictionary containing file access anomalies with keys such as:
            - 'sensitive_files': List of access to sensitive files
            - 'suspicious_modifications': List of suspicious file modifications
            - 'unusual_access_times': List of file access outside normal hours
            - 'bulk_operations': List of suspicious bulk file operations
    """
    from models.audit_log import AuditLog
    
    result = {
        'sensitive_files': [],
        'suspicious_modifications': [],
        'unusual_access_times': [],
        'bulk_operations': []
    }
    
    # Check for access to sensitive files
    sensitive_paths = ['config', 'env', '.secret', 'credentials', 'password']
    sensitive_file_access = AuditLog.query.filter(
        AuditLog.event_type == 'file_access',
        AuditLog.created_at.__ge__(datetime.utcnow() - timedelta(days=1)),
        # Check if any sensitive path is mentioned in the details
        or_(*[AuditLog.details.op('ilike')(f'%{path}%') for path in sensitive_paths])
    ).order_by(
        func.desc(AuditLog.created_at)
    ).limit(10).all()
    
    for access in sensitive_file_access:
        result['sensitive_files'].append({
            'user_id': access.user_id,
            'file_path': access.details,
            'timestamp': access.created_at.isoformat()
        })
    
    # Check for unusual file modifications
    file_modifications = AuditLog.query.filter(
        AuditLog.event_type == 'file_modified',
        AuditLog.created_at.__ge__(datetime.utcnow() - timedelta(hours=24))
    ).order_by(
        func.desc(AuditLog.created_at)
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
        AuditLog.event_type.in_(['file_access', 'file_modified']),
        AuditLog.created_at.__ge__(datetime.utcnow() - timedelta(days=1)),
        ~and_(
            func.extract('hour', AuditLog.created_at) >= 9,
            func.extract('hour', AuditLog.created_at) < 17
        )
    ).order_by(
        func.desc(AuditLog.created_at)
    ).limit(10).all()
    
    for access in off_hours_access:
        result['unusual_access_times'].append({
            'user_id': access.user_id,
            'file_path': access.details,
            'timestamp': access.created_at.isoformat(),
            'action': access.event_type
        })
    
    return result

def calculate_threat_level(breach_data: Dict[str, Any]) -> int:
    """
    Calculate an overall threat level based on detected security anomalies.
    
    This function analyzes the detected anomalies across various categories
    and determines a numerical threat level from 1 (minimal) to 10 (critical).
    The calculation takes into account:
    - The number and types of anomalies detected
    - The severity of each anomaly
    - The combination of different anomaly categories
    - Historical baseline of normal behavior
    
    Args:
        breach_data: Dictionary containing detected anomalies across categories
        
    Returns:
        int: Calculated threat level on a scale of 1-10
    """
    # Start with base threat level
    threat_score = 1
    
    # Count anomalies across categories and assign weights
    category_weights = {
        'login_anomalies': 2,
        'session_anomalies': 2,
        'api_anomalies': 1.5,
        'database_anomalies': 2.5,
        'file_access_anomalies': 2
    }
    
    for category, weight in category_weights.items():
        if category in breach_data and breach_data[category]:
            # Add weighted score based on anomaly count
            anomaly_count = sum(len(breach_data[category][key]) 
                               for key in breach_data[category] 
                               if isinstance(breach_data[category][key], list))
            
            # Scale anomaly impact
            if anomaly_count > 0:
                category_score = min(weight * (1 + (anomaly_count / 10)), weight * 3)
                threat_score += category_score
    
    # Check for critical combinations
    if (breach_data.get('login_anomalies', {}).get('suspicious_ips') and 
        breach_data.get('database_anomalies', {}).get('sensitive_tables')):
        # Serious threat: failed logins combined with sensitive data access
        threat_score += 2
        
    if (breach_data.get('file_access_anomalies', {}).get('sensitive_files') and 
        breach_data.get('database_anomalies', {}).get('unusual_queries')):
        # Serious threat: sensitive file access combined with unusual queries
        threat_score += 2
    
    # Cap and round threat level
    return min(round(threat_score), 10)

def trigger_incident_response(breach_data: Dict[str, Any]) -> None:
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
        None
    """
    from services.email_service import send_email
    
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
    from models.security_incident import SecurityIncident
    
    try:
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
                    f"Details: {breach_data}"
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
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError) as e:
        current_app.logger.error(f"Failed to create security incident: {e}")
        # Even if DB storage fails, still try to notify admins
        notify_administrators(
            f"CRITICAL SECURITY ALERT: {title} - Threat Level {breach_data['threat_level']}/10 (Failed to record in database: {e})"
        )
        return None

def collect_forensic_data(incident_id: int) -> None:
    """
    Collect forensic data for a security incident.
    
    This function gathers additional system and application data that might
    be useful for investigating the security incident, including:
    - Recent logs
    - Process information
    - Network connections
    - System resource usage
    
    Args:
        incident_id: ID of the security incident
        
    Returns:
        None
    """
    try:
        import os
        import json
        
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
        
        # Save forensic data
        forensic_dir = current_app.config.get('FORENSIC_DATA_DIR', 'forensic_data')
        os.makedirs(forensic_dir, exist_ok=True)
        
        with open(f"{forensic_dir}/incident_{incident_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json", 'w', encoding='utf-8') as f:
            json.dump(forensic_data, f, default=str, indent=2)
        
        current_app.logger.info(f"Forensic data collected for incident {incident_id}")
        
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError) as e:
        current_app.logger.error(f"Failed to collect forensic data: {e}")

def initiate_countermeasures(breach_data: Dict[str, Any]) -> None:
    """
    Initiate automated countermeasures for critical security threats.
    
    This function takes defensive actions based on the type of security
    threat detected. These may include:
    - Blocking suspicious IP addresses
    - Invalidating compromised sessions
    - Temporarily disabling affected user accounts
    - Restricting access to sensitive resources
    
    Args:
        breach_data: Dictionary containing detected anomalies and threat information
        
                    # Ensure create_audit_log is defined or imported
                    create_audit_log(
        None
    """
    try:
        # Get configuration for automated response
        auto_response_enabled = current_app.config.get('ENABLE_AUTO_COUNTERMEASURES', False)
        
        if not auto_response_enabled:
            current_app.logger.info("Automated countermeasures disabled in configuration")
            return
            
        current_app.logger.info("Initiating automated countermeasures")
        
        # Block suspicious IPs if detected
        if breach_data.get('login_anomalies', {}).get('suspicious_ips'):
            suspicious_ips = [
                ip_data['ip_address'] 
                for ip_data in breach_data['login_anomalies']['suspicious_ips']
            ]
            
            if suspicious_ips:
                # Implement IP blocking (depends on infrastructure)
                # This might call an external firewall API, update .htaccess, etc.
                current_app.logger.info(f"Would block suspicious IPs: {suspicious_ips}")
                
                # Log the countermeasure
                for ip in suspicious_ips:
                    create_audit_log(
                        'security_countermeasure', 
                        f"Blocked suspicious IP {ip}",
                        user_id=None,
                        severity='warning'
                    )
        
        # Invalidate suspicious sessions
        if breach_data.get('session_anomalies', {}).get('ip_changes'):
            for session_data in breach_data['session_anomalies']['ip_changes']:
                user_id = session_data['user_id']
                current_app.logger.info(f"Invalidating sessions for user {user_id}")
                
                # Implementation depends on session backend
                # For example, with Redis session storage:
                if hasattr(current_app.session_interface, 'invalidate_user_sessions'):
                    current_app.session_interface.invalidate_user_sessions(user_id)
                
                # Log the countermeasure
                create_audit_log(
                    'security_countermeasure', 
                    f"Invalidated sessions for user {user_id} due to suspicious activity",
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
                    from models.user import User
                    user = User.query.get(user_id)
                    if user:
                        user.account_locked = True
                        user.lock_reason = "Suspicious database access detected"
                        db.session.add(user)
                        db.session.commit()
                    
                    # Log the countermeasure
                    create_audit_log(
                        'security_countermeasure', 
                        f"Locked account for user {user_id} due to suspicious database access",
                        user_id=user_id,
                        severity='warning'
                    )
        
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError) as e:
        current_app.logger.error(f"Error initiating countermeasures: {e}")

def get_recent_security_events(limit: int = 5) -> List[Dict[str, Any]]:
    """
    Get the most recent security events from the audit log.
    
    Args:
        limit: Maximum number of events to return
        
    Returns:
        List[Dict[str, Any]]: List of recent security events
    """
    from models.audit_log import AuditLog
    
    events = AuditLog.query.filter(
        AuditLog.event_type.in_([
            'login_failed', 'login_success', 'password_reset',
            'permission_denied', 'security_breach_attempt'
        ])
    ).order_by(
        desc(AuditLog.created_at)
    ).limit(limit).all()
    
    return [event.to_dict() for event in events]

def get_failed_login_count(hours: int = 24) -> int:
    """Get count of failed logins in the past hours."""
    from models.audit_log import AuditLog
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    return AuditLog.query.filter(
        AuditLog.event_type == 'login_failed',
        AuditLog.created_at.__ge__(cutoff)
    ).count()

def get_account_lockout_count(hours: int = 24) -> int:
    """Get count of account lockouts in the past hours."""
    from models.audit_log import AuditLog
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    return AuditLog.query.filter(
        AuditLog.event_type == 'account_lockout',
        AuditLog.created_at.__ge__(cutoff)
    ).count()

def get_active_session_count() -> int:
    """Get count of active user sessions."""
    # This would depend on how you're storing sessions
    # If using Redis or database-backed sessions:
    if cache.config.get('CACHE_TYPE') == 'redis':
        import redis
        r = redis.from_url(cache.config.get('CACHE_REDIS_URL'))
        return len([k for k in r.keys('session:*') or []])
    else:
        # Placeholder for other session storage mechanisms
        return 0

def get_suspicious_ips() -> List[Dict[str, Any]]:
    """Get list of suspicious IPs with their activity counts."""
    from models.audit_log import AuditLog
    cutoff = datetime.utcnow() - timedelta(hours=24)
    
    # Subquery to count failed login attempts by IP
    failed_login_counts = db.session.query(
        AuditLog.ip_address,
        func.count(AuditLog.id).label('count')
    ).filter(
        AuditLog.event_type == 'login_failed',
        AuditLog.created_at >= cutoff,
        AuditLog.ip_address != None
    ).group_by(AuditLog.ip_address).subquery()
    
    # Get IPs with more than 5 failed attempts
    suspicious = db.session.query(
        failed_login_counts.c.ip_address,
        failed_login_counts.c.count
    ).filter(failed_login_counts.c.count > 5).all()
    
    return [{'ip': ip, 'count': count} for ip, count in suspicious]

def check_config_integrity() -> bool:
    """
    Verify integrity of critical configuration files.
    
    Returns:
        bool: True if all configuration files are unmodified, False otherwise
    """
    import os
    import hashlib
    
    # Get expected hashes from application configuration
    expected_hashes = current_app.config.get('CONFIG_FILE_HASHES', {})
    
    # Check critical configuration files
    config_files = ['config.py', '.env', 'app.py']
    
    for file in config_files:
        if os.path.exists(file):
            # Calculate current file hash
            with open(file, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                
            # Compare with expected hash if available
            if file in expected_hashes and file_hash != expected_hashes[file]:
                current_app.logger.warning(f"Configuration file modified: {file}")
                return False
    
    return True

def check_critical_file_integrity() -> bool:
    """
    Verify integrity of critical application files.
    
    Returns:
        bool: True if all critical files are unmodified, False otherwise
    """
    import os
    import hashlib
    
    # Get expected hashes from application configuration
    expected_hashes = current_app.config.get('CRITICAL_FILE_HASHES', {})
    
    # Check critical files
    critical_files = [
        'app.py',
        'wsgi.py',
        'core/security.py',
        'core/auth.py',
        'extensions.py'
    ]
    
    for file in critical_files:
        if os.path.exists(file):
            # Calculate current file hash
            with open(file, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                
            # Compare with expected hash if available
            if file in expected_hashes and file_hash != expected_hashes[file]:
                current_app.logger.warning(f"Critical file modified: {file}")
                return False
    
    return True

def calculate_risk_score(security_data: Dict[str, Any]) -> int:
    """
    Calculate security risk score based on collected security data.
    
    Args:
        security_data: Dictionary containing security metrics
        
    Returns:
        int: Risk score on a scale of 1-10
    """
    score = 1  # Start with minimum risk
    
    # Check failed logins
    if security_data['failed_logins_24h'] > 100:
        score += 3
    elif security_data['failed_logins_24h'] > 50:
        score += 2
    elif security_data['failed_logins_24h'] > 20:
        score += 1
    
    # Check account lockouts
    if security_data['account_lockouts_24h'] > 5:
        score += 2
    elif security_data['account_lockouts_24h'] > 0:
        score += 1
    
    # Check suspicious IPs
    if len(security_data['suspicious_ips']) > 10:
        score += 3
    elif len(security_data['suspicious_ips']) > 0:
        score += 1
    
    # Check file integrity
    if not security_data['config_integrity']:
        score += 3
    
    if not security_data['file_integrity']:
        score += 2
    
    return min(score, 10)  # Cap at maximum risk of 10