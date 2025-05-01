"""
Audit Log Analysis Module

This module provides functions for analyzing audit logs, identifying patterns,
detecting security anomalies, and correlating related events. It implements
advanced search capabilities and event correlation algorithms to help security
teams investigate incidents and identify potential threats.
"""

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Tuple, Optional, Set, Union
from sqlalchemy import and_, or_, not_, desc, func, cast, String, Integer, Boolean
from sqlalchemy.sql.expression import text
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app, g, has_request_context

from extensions import db, cache
from models.security.audit_log import AuditLog
from models.auth.user import User
from core.security import log_security_event

# Initialize logger
logger = logging.getLogger(__name__)


def analyze_security_events(
    search_criteria: Dict[str, Any],
    page: int = 1,
    per_page: int = 50
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Perform advanced analysis and search on audit logs using complex criteria.

    This function supports complex search patterns, including nested conditions,
    temporal patterns, and multi-field correlations. It's designed for security
    investigation use cases.

    Args:
        search_criteria: Dictionary containing complex search parameters
        page: Page number for pagination (starting at 1)
        per_page: Number of results per page

    Returns:
        Tuple containing list of matched events and total count

    Example:
        results, count = analyze_security_events({
            'time_range': {'start': '2023-01-01T00:00:00Z', 'end': '2023-01-31T23:59:59Z'},
            'any_of': [
                {'event_type': 'login_failed', 'attempts_threshold': 3},
                {'severity': 'critical'}
            ],
            'user_id': 42,
            'pattern': 'password reset'
        })
    """
    try:
        query = AuditLog.query

        # Apply time range filter if provided
        if 'time_range' in search_criteria:
            time_range = search_criteria['time_range']
            start_time = None
            end_time = None

            if 'start' in time_range:
                try:
                    start_time = _parse_datetime(time_range['start'])
                    query = query.filter(AuditLog.created_at >= start_time)
                except ValueError as e:
                    logger.warning(f"Invalid start datetime format: {e}")

            if 'end' in time_range:
                try:
                    end_time = _parse_datetime(time_range['end'])
                    query = query.filter(AuditLog.created_at <= end_time)
                except ValueError as e:
                    logger.warning(f"Invalid end datetime format: {e}")

        # Apply basic filters
        basic_filters = ['event_type', 'severity', 'category', 'user_id',
                          'ip_address', 'object_type', 'object_id']

        for filter_name in basic_filters:
            if filter_name in search_criteria:
                filter_value = search_criteria[filter_name]

                # Handle list values (IN operator)
                if isinstance(filter_value, list):
                    query = query.filter(getattr(AuditLog, filter_name).in_(filter_value))
                else:
                    query = query.filter(getattr(AuditLog, filter_name) == filter_value)

        # Apply username filter if provided (requires join)
        if 'username' in search_criteria:
            username = search_criteria['username']
            query = query.join(User, AuditLog.user_id == User.id).filter(User.username == username)

        # Apply text search if provided
        if 'pattern' in search_criteria:
            pattern = f"%{search_criteria['pattern']}%"
            query = query.filter(
                or_(
                    AuditLog.description.ilike(pattern),
                    cast(AuditLog.details, String).ilike(pattern)
                )
            )

        # Apply logical OR conditions if provided
        if 'any_of' in search_criteria and isinstance(search_criteria['any_of'], list):
            or_conditions = []

            for condition in search_criteria['any_of']:
                and_conditions = []

                for field, value in condition.items():
                    # Skip special parameters
                    if field in ['attempts_threshold', 'time_window']:
                        continue

                    if isinstance(value, list):
                        and_conditions.append(getattr(AuditLog, field).in_(value))
                    else:
                        and_conditions.append(getattr(AuditLog, field) == value)

                if and_conditions:
                    or_conditions.append(and_(*and_conditions))

            if or_conditions:
                query = query.filter(or_(*or_conditions))

        # Apply logical AND conditions if provided
        if 'all_of' in search_criteria and isinstance(search_criteria['all_of'], list):
            for condition in search_criteria['all_of']:
                and_conditions = []

                for field, value in condition.items():
                    if isinstance(value, list):
                        and_conditions.append(getattr(AuditLog, field).in_(value))
                    else:
                        and_conditions.append(getattr(AuditLog, field) == value)

                if and_conditions:
                    query = query.filter(and_(*and_conditions))

        # Apply logical NOT conditions if provided
        if 'none_of' in search_criteria and isinstance(search_criteria['none_of'], list):
            for condition in search_criteria['none_of']:
                for field, value in condition.items():
                    if isinstance(value, list):
                        query = query.filter(not_(getattr(AuditLog, field).in_(value)))
                    else:
                        query = query.filter(getattr(AuditLog, field) != value)

        # Apply sequential event conditions (e.g., multiple failed logins)
        if 'sequential_events' in search_criteria:
            seq_params = search_criteria['sequential_events']
            if 'event_type' in seq_params:
                event_type = seq_params['event_type']
                threshold = int(seq_params.get('threshold', 3))
                window_minutes = int(seq_params.get('window_minutes', 30))

                # Get user/IP combinations with multiple occurrences of the specified event
                subquery = db.session.query(
                    AuditLog.user_id,
                    AuditLog.ip_address,
                    func.count(AuditLog.id).label('event_count')
                ).filter(
                    AuditLog.event_type == event_type,
                    AuditLog.created_at >= (datetime.now(timezone.utc) - timedelta(minutes=window_minutes))
                ).group_by(
                    AuditLog.user_id,
                    AuditLog.ip_address
                ).having(
                    func.count(AuditLog.id) >= threshold
                ).subquery()

                # Filter main query to only include logs for these user/IP combinations
                query = query.join(
                    subquery,
                    and_(
                        AuditLog.user_id == subquery.c.user_id,
                        AuditLog.ip_address == subquery.c.ip_address
                    )
                )

        # Calculate total count before applying pagination
        total_count = query.count()

        # Apply sorting (default to newest first)
        sort_field = search_criteria.get('sort_by', 'created_at')
        sort_dir = search_criteria.get('sort_dir', 'desc')

        if sort_field not in ['id', 'created_at', 'event_type', 'severity', 'category']:
            sort_field = 'created_at'

        if sort_dir.lower() == 'asc':
            query = query.order_by(getattr(AuditLog, sort_field).asc())
        else:
            query = query.order_by(getattr(AuditLog, sort_field).desc())

        # Apply pagination
        query = query.offset((page - 1) * per_page).limit(per_page)

        # Execute query and format results
        logs = query.all()
        results = []

        for log in logs:
            log_dict = {
                'id': log.id,
                'created_at': log.created_at.isoformat() if log.created_at else None,
                'event_type': log.event_type,
                'description': log.description,
                'user_id': log.user_id,
                'ip_address': log.ip_address,
                'severity': log.severity,
                'category': log.category,
                'details': log.details,
                'object_type': log.object_type,
                'object_id': log.object_id
            }

            # Add username if available
            if log.user_id:
                user = User.query.get(log.user_id)
                if user:
                    log_dict['username'] = user.username

            results.append(log_dict)

        return results, total_count

    except SQLAlchemyError as e:
        logger.error(f"Database error during security event analysis: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error analyzing security events: {str(e)}", exc_info=True)
        raise ValueError(f"Failed to analyze security events: {str(e)}")


def correlate_events(
    event_id: int,
    time_window_minutes: int = 30,
    related_types: Optional[List[str]] = None
) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Find and correlate audit log events related to a central event.

    This function finds temporal and contextual relationships between events,
    identifying potential security incidents or related activities around a
    specific audit event.

    Args:
        event_id: ID of the central event to correlate from
        time_window_minutes: Time window in minutes (before and after event)
        related_types: Optional list of event types to include in correlation

    Returns:
        Tuple containing:
            - Central event details
            - List of correlated events
            - List of relationship descriptions

    Example:
        central, related, relationships = correlate_events(
            event_id=12345,
            time_window_minutes=15,
            related_types=['login_failed', 'permission_denied']
        )
    """
    try:
        # Fetch the central event
        central_event = AuditLog.query.get(event_id)
        if not central_event:
            logger.warning(f"No audit event found with ID {event_id}")
            return None, [], []

        # Extract key attributes for correlation
        central_time = central_event.created_at
        central_user_id = central_event.user_id
        central_ip = central_event.ip_address
        central_category = central_event.category
        central_object_type = central_event.object_type
        central_object_id = central_event.object_id

        # Calculate time window boundaries
        start_time = central_time - timedelta(minutes=time_window_minutes)
        end_time = central_time + timedelta(minutes=time_window_minutes)

        # Build base query for correlated events
        query = AuditLog.query.filter(
            AuditLog.id != event_id,
            AuditLog.created_at.between(start_time, end_time)
        )

        # Filter by event types if specified
        if related_types and len(related_types) > 0:
            query = query.filter(AuditLog.event_type.in_(related_types))

        # Create a union of all potential relationship criteria
        relationships_criteria = []

        # Add user-based relationships
        if central_user_id:
            relationships_criteria.append(AuditLog.user_id == central_user_id)

        # Add IP-based relationships
        if central_ip:
            relationships_criteria.append(AuditLog.ip_address == central_ip)

        # Add object-based relationships
        if central_object_type and central_object_id:
            relationships_criteria.append(and_(
                AuditLog.object_type == central_object_type,
                AuditLog.object_id == central_object_id
            ))

        # Add category-based relationships for security events
        if central_category:
            relationships_criteria.append(AuditLog.category == central_category)

        # Apply the relationship criteria if any exist
        if relationships_criteria:
            query = query.filter(or_(*relationships_criteria))

        # Execute query and retrieve correlated events
        correlated_events = query.order_by(AuditLog.created_at).all()

        # Format central event data
        central_event_data = {
            'id': central_event.id,
            'created_at': central_event.created_at.isoformat() if central_event.created_at else None,
            'event_type': central_event.event_type,
            'description': central_event.description,
            'user_id': central_event.user_id,
            'ip_address': central_event.ip_address,
            'severity': central_event.severity,
            'category': central_event.category,
            'details': central_event.details,
            'object_type': central_event.object_type,
            'object_id': central_event.object_id
        }

        # If user exists, add username
        if central_event.user_id:
            user = User.query.get(central_event.user_id)
            if user:
                central_event_data['username'] = user.username

        # Process correlated events and determine relationships
        correlated_events_data = []
        relationships = []

        for event in correlated_events:
            # Create event data dictionary
            event_data = {
                'id': event.id,
                'created_at': event.created_at.isoformat() if event.created_at else None,
                'event_type': event.event_type,
                'description': event.description,
                'user_id': event.user_id,
                'ip_address': event.ip_address,
                'severity': event.severity,
                'category': event.category,
                'details': event.details,
                'object_type': event.object_type,
                'object_id': event.object_id,
                'time_delta_seconds': int((event.created_at - central_time).total_seconds())
            }

            # If user exists, add username
            if event.user_id:
                user = User.query.get(event.user_id)
                if user:
                    event_data['username'] = user.username

            # Determine relationships
            relationship_types = []

            # Check for user-based relationship
            if central_user_id and event.user_id and central_user_id == event.user_id:
                relationship_types.append("same_user")

            # Check for IP-based relationship
            if central_ip and event.ip_address and central_ip == event.ip_address:
                relationship_types.append("same_ip")

            # Check for object-based relationship
            if (central_object_type and central_object_id and
                event.object_type and event.object_id and
                central_object_type == event.object_type and
                central_object_id == event.object_id):
                relationship_types.append("same_object")

            # Check for category-based relationship
            if central_category and event.category and central_category == event.category:
                relationship_types.append("same_category")

            # Check for temporal sequence (within 5 seconds before/after)
            time_diff = abs((event.created_at - central_time).total_seconds())
            if time_diff <= 5:
                relationship_types.append("temporal_sequence")

            # Add to relationship data
            if relationship_types:
                relationships.append({
                    'source_id': central_event.id,
                    'target_id': event.id,
                    'types': relationship_types,
                    'strength': len(relationship_types),
                    'time_delta_seconds': int((event.created_at - central_time).total_seconds())
                })

            # Add to correlated events list
            correlated_events_data.append(event_data)

        # Sort relationships by strength (descending)
        relationships.sort(key=lambda x: x['strength'], reverse=True)

        # Log the correlation activity
        log_security_event(
            event_type="audit_event_correlation",
            description=f"Correlation analysis performed for event ID {event_id}",
            severity="info",
            user_id=g.get('user_id') if has_request_context() else None,
            details={
                'central_event_id': event_id,
                'time_window_minutes': time_window_minutes,
                'related_types': related_types,
                'correlated_events_count': len(correlated_events_data),
                'relationship_count': len(relationships)
            }
        )

        return central_event_data, correlated_events_data, relationships

    except SQLAlchemyError as e:
        logger.error(f"Database error during event correlation: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error correlating events: {str(e)}", exc_info=True)
        raise ValueError(f"Failed to correlate events: {str(e)}")


def analyze_user_behavior(
    user_id: int,
    days: int = 30
) -> Dict[str, Any]:
    """
    Analyze user behavior patterns from audit logs.

    Identifies patterns, anomalies, and trends in user activity based on
    historical audit data. Useful for user behavior analytics and identifying
    potentially suspicious activities.

    Args:
        user_id: User ID to analyze
        days: Number of days of history to analyze

    Returns:
        Dictionary containing behavior analysis results
    """
    try:
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)

        # Get all user events in the time period
        events = AuditLog.query.filter(
            AuditLog.user_id == user_id,
            AuditLog.created_at.between(start_date, end_date)
        ).order_by(AuditLog.created_at).all()

        if not events:
            return {
                "user_id": user_id,
                "analysis_period_days": days,
                "total_events": 0,
                "status": "no_data"
            }

        # Get username
        user = User.query.get(user_id)
        username = user.username if user else f"User #{user_id}"

        # Calculate activity metrics
        total_events = len(events)
        event_types = {}
        ip_addresses = set()
        severities = {}
        categories = {}

        # Time-based analysis
        hour_activity = [0] * 24  # Activity by hour of day
        weekday_activity = [0] * 7  # Activity by day of week
        daily_activity = {}  # Activity by date

        # Extract data
        for event in events:
            # Count event types
            event_type = event.event_type
            event_types[event_type] = event_types.get(event_type, 0) + 1

            # Collect IP addresses
            if event.ip_address:
                ip_addresses.add(event.ip_address)

            # Count severities
            severity = event.severity
            severities[severity] = severities.get(severity, 0) + 1

            # Count categories
            category = event.category or "uncategorized"
            categories[category] = categories.get(category, 0) + 1

            # Time-based counters
            if event.created_at:
                # Hour of day (0-23)
                hour_activity[event.created_at.hour] += 1

                # Day of week (0=Monday, 6=Sunday)
                weekday_activity[event.created_at.weekday()] += 1

                # Activity by date
                date_str = event.created_at.strftime('%Y-%m-%d')
                daily_activity[date_str] = daily_activity.get(date_str, 0) + 1

        # Identify top event types
        top_event_types = sorted(
            [(event_type, count) for event_type, count in event_types.items()],
            key=lambda x: x[1],
            reverse=True
        )[:5]

        # Detect unusual hour activity
        avg_hour_activity = sum(hour_activity) / 24
        unusual_hours = []

        for hour, count in enumerate(hour_activity):
            if count > 0:
                # Flag significant activity during unusual hours (10pm-5am)
                if (hour >= 22 or hour <= 5) and count > avg_hour_activity:
                    unusual_hours.append({
                        "hour": hour,
                        "count": count,
                        "deviation": count / avg_hour_activity if avg_hour_activity > 0 else float('inf')
                    })

        # Check for multiple IP addresses
        multiple_ips = len(ip_addresses) > 1

        # Prepare response
        result = {
            "user_id": user_id,
            "username": username,
            "analysis_period_days": days,
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "total_events": total_events,
            "average_daily_events": total_events / days if days > 0 else 0,
            "unique_ip_count": len(ip_addresses),
            "ip_addresses": list(ip_addresses),
            "event_type_breakdown": event_types,
            "top_event_types": [{"event_type": et, "count": count} for et, count in top_event_types],
            "severity_breakdown": severities,
            "category_breakdown": categories,
            "time_patterns": {
                "hour_activity": hour_activity,
                "weekday_activity": weekday_activity,
                "unusual_hours": unusual_hours
            },
            "daily_activity": [
                {"date": date, "count": count}
                for date, count in sorted(daily_activity.items())
            ],
            "multiple_ips_detected": multiple_ips
        }

        return result

    except SQLAlchemyError as e:
        logger.error(f"Database error during user behavior analysis: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error analyzing user behavior: {str(e)}", exc_info=True)
        raise ValueError(f"Failed to analyze user behavior: {str(e)}")


def detect_anomalies(
    timeframe_hours: int = 24,
    sensitivity: str = 'medium'
) -> List[Dict[str, Any]]:
    """
    Detect potential security anomalies in audit logs.

    Analyzes patterns in audit logs to identify potential security anomalies
    such as brute force attempts, unusual access patterns, or privilege escalation.

    Args:
        timeframe_hours: Time window in hours for analysis
        sensitivity: Sensitivity level ('low', 'medium', 'high')

    Returns:
        List of detected anomalies with details
    """
    try:
        # Define thresholds based on sensitivity
        thresholds = {
            'low': {
                'failed_logins': 10,
                'permission_denied': 8,
                'critical_events': 3,
                'admin_actions': 15,
                'unusual_hour_factor': 3
            },
            'medium': {
                'failed_logins': 5,
                'permission_denied': 5,
                'critical_events': 2,
                'admin_actions': 10,
                'unusual_hour_factor': 2
            },
            'high': {
                'failed_logins': 3,
                'permission_denied': 3,
                'critical_events': 1,
                'admin_actions': 5,
                'unusual_hour_factor': 1.5
            }
        }

        # Use medium sensitivity if invalid value provided
        if sensitivity not in thresholds:
            sensitivity = 'medium'

        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=timeframe_hours)
        anomalies = []

        # 1. Check for multiple failed logins
        failed_login_subq = db.session.query(
            AuditLog.user_id,
            AuditLog.ip_address,
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
            AuditLog.created_at >= cutoff_time
        ).group_by(
            AuditLog.user_id,
            AuditLog.ip_address
        ).subquery()

        login_anomalies = db.session.query(
            failed_login_subq,
            User.username
        ).outerjoin(
            User,
            User.id == failed_login_subq.c.user_id
        ).filter(
            failed_login_subq.c.count >= thresholds[sensitivity]['failed_logins']
        ).all()

        for anomaly in login_anomalies:
            user_id = anomaly.user_id
            username = anomaly.username or f"User #{user_id}" if user_id else "Unknown User"
            ip_address = anomaly.ip_address or "Unknown IP"
            count = anomaly.count

            anomalies.append({
                'type': 'multiple_failed_logins',
                'severity': 'high' if count >= thresholds['low']['failed_logins'] else 'medium',
                'source': 'audit_log_analysis',
                'description': f"Multiple failed login attempts detected ({count} attempts)",
                'details': {
                    'user_id': user_id,
                    'username': username,
                    'ip_address': ip_address,
                    'count': count,
                    'threshold': thresholds[sensitivity]['failed_logins']
                }
            })

        # 2. Check for permission denied events
        perm_denied_subq = db.session.query(
            AuditLog.user_id,
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.event_type == AuditLog.EVENT_PERMISSION_DENIED,
            AuditLog.created_at >= cutoff_time
        ).group_by(
            AuditLog.user_id
        ).subquery()

        perm_anomalies = db.session.query(
            perm_denied_subq,
            User.username
        ).outerjoin(
            User,
            User.id == perm_denied_subq.c.user_id
        ).filter(
            perm_denied_subq.c.count >= thresholds[sensitivity]['permission_denied']
        ).all()

        for anomaly in perm_anomalies:
            user_id = anomaly.user_id
            username = anomaly.username or f"User #{user_id}" if user_id else "Unknown User"
            count = anomaly.count

            anomalies.append({
                'type': 'multiple_permission_denied',
                'severity': 'medium' if count >= thresholds['low']['permission_denied'] else 'low',
                'source': 'audit_log_analysis',
                'description': f"Multiple permission denied events detected ({count} events)",
                'details': {
                    'user_id': user_id,
                    'username': username,
                    'count': count,
                    'threshold': thresholds[sensitivity]['permission_denied']
                }
            })

        # 3. Check for critical severity events
        critical_events = db.session.query(
            AuditLog
        ).filter(
            AuditLog.severity == 'critical',
            AuditLog.created_at >= cutoff_time
        ).order_by(
            AuditLog.created_at.desc()
        ).all()

        if len(critical_events) >= thresholds[sensitivity]['critical_events']:
            anomalies.append({
                'type': 'multiple_critical_events',
                'severity': 'high',
                'source': 'audit_log_analysis',
                'description': f"Multiple critical events detected ({len(critical_events)} events)",
                'details': {
                    'event_count': len(critical_events),
                    'threshold': thresholds[sensitivity]['critical_events'],
                    'events': [
                        {
                            'id': event.id,
                            'timestamp': event.created_at.isoformat(),
                            'event_type': event.event_type,
                            'description': event.description
                        }
                        for event in critical_events[:5]  # Include first 5 events
                    ]
                }
            })

        # 4. Check for unusual hour activity
        hour_counts = db.session.query(
            func.extract('hour', AuditLog.created_at).label('hour'),
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.created_at >= cutoff_time
        ).group_by(
            'hour'
        ).all()

        # Calculate average hourly activity
        total_count = sum(h.count for h in hour_counts)
        hours_with_activity = len(hour_counts)
        avg_count = total_count / max(24, hours_with_activity)

        # Check for unusual activity during night hours (11pm-5am)
        for hour_data in hour_counts:
            hour = int(hour_data.hour)
            count = hour_data.count

            # Check if this is a night hour with unusual activity level
            if (hour >= 23 or hour <= 5) and count > avg_count * thresholds[sensitivity]['unusual_hour_factor']:
                anomalies.append({
                    'type': 'unusual_hour_activity',
                    'severity': 'medium',
                    'source': 'audit_log_analysis',
                    'description': f"Unusual activity detected during non-business hours ({count} events at {hour}:00)",
                    'details': {
                        'hour': hour,
                        'event_count': count,
                        'average_count': avg_count,
                        'deviation_factor': count / avg_count
                    }
                })

        # Record anomaly detection in audit log
        if anomalies:
            log_security_event(
                event_type="security_anomalies_detected",
                description=f"Detected {len(anomalies)} security anomalies in audit logs",
                severity="warning" if any(a['severity'] == 'high' for a in anomalies) else "info",
                details={
                    'anomaly_count': len(anomalies),
                    'timeframe_hours': timeframe_hours,
                    'sensitivity': sensitivity,
                    'anomaly_types': [a['type'] for a in anomalies]
                }
            )

        return anomalies

    except SQLAlchemyError as e:
        logger.error(f"Database error during anomaly detection: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error detecting anomalies: {str(e)}", exc_info=True)
        raise ValueError(f"Failed to detect anomalies: {str(e)}")


# --- Helper Functions ---

def _parse_datetime(date_str: str) -> datetime:
    """
    Parse a string into a datetime with timezone.

    Handles multiple ISO 8601 formats and ensures UTC timezone.

    Args:
        date_str: ISO format datetime string

    Returns:
        datetime: Parsed datetime with UTC timezone

    Raises:
        ValueError: If string can't be parsed as a valid datetime
    """
    try:
        # Try direct ISO parsing first
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except ValueError:
        # Try other common formats
        formats = [
            '%Y-%m-%dT%H:%M:%S.%f%z',  # ISO with microseconds and timezone
            '%Y-%m-%dT%H:%M:%S%z',     # ISO with timezone
            '%Y-%m-%dT%H:%M:%S',       # ISO without timezone
            '%Y-%m-%d %H:%M:%S',       # Common format without T
            '%Y-%m-%d',                # Just the date
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                break
            except ValueError:
                continue
        else:
            raise ValueError(f"Unable to parse datetime: {date_str}")

    # Ensure timezone is set
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt
