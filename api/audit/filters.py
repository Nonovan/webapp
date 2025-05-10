"""
Audit Log Filtering Module

This module provides functions for building, filtering, and parsing audit log queries.
It supports complex filtering operations on audit logs with proper validation and
sanitization of filter parameters.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple, List, Union
import re

from sqlalchemy import or_, and_
from flask import current_app, g
from models.security import AuditLog
from models.auth.user import User


def build_audit_query(filter_data: Dict[str, Any]):
    """
    Build a SQLAlchemy query for audit logs based on filter parameters.

    This function constructs a query with multiple filter conditions based on
    the provided parameters, including date ranges, user details, event types,
    severity levels, categories, and more.

    Args:
        filter_data (Dict[str, Any]): Dictionary containing filter parameters.
            Supported filters:
                - start_date (str): ISO format datetime start boundary
                - end_date (str): ISO format datetime end boundary
                - user_id (int): Filter by specific user ID
                - username (str): Filter by username
                - event_type (str): Filter by specific event type
                - severity (str): Filter by severity level
                - category (str): Filter by event category
                - object_type (str): Filter by object type
                - object_id (str): Filter by object ID
                - ip_address (str): Filter by IP address
                - contains (str): Search in description and details

    Returns:
        SQLAlchemy Query: Query object with all applied filters

    Example:
        query = build_audit_query({
            'start_date': '2023-01-01T00:00:00Z',
            'end_date': '2023-01-31T23:59:59Z',
            'severity': 'critical',
            'contains': 'authentication'
        })
        audit_logs = query.all()
    """
    query = AuditLog.query

    # Parse and apply start/end date filters
    start_date, end_date = parse_time_range(filter_data.get('start_date'), filter_data.get('end_date'))
    if start_date:
        query = query.filter(AuditLog.created_at >= start_date)
    if end_date:
        query = query.filter(AuditLog.created_at <= end_date)

    # Filter by user ID
    if filter_data.get('user_id'):
        try:
            user_id = int(filter_data['user_id'])
            query = query.filter(AuditLog.user_id == user_id)
        except (ValueError, TypeError):
            current_app.logger.warning(f"Invalid user_id filter value: {filter_data['user_id']}")

    # Filter by username (requires join with User table)
    if filter_data.get('username'):
        username = filter_data['username']
        user = User.query.filter_by(username=username).first()
        if user:
            query = query.filter(AuditLog.user_id == user.id)
        else:
            # If username doesn't exist, return empty result set
            # (instead of all results, which would be misleading)
            query = query.filter(AuditLog.id < 0)

    # Filter by event type
    if filter_data.get('event_type'):
        query = query.filter(AuditLog.event_type == filter_data['event_type'])

    # Filter by severity
    if filter_data.get('severity'):
        # Support comma-separated list of severities
        if ',' in filter_data['severity']:
            severities = [s.strip() for s in filter_data['severity'].split(',')]
            query = query.filter(AuditLog.severity.in_(severities))
        else:
            query = query.filter(AuditLog.severity == filter_data['severity'])

    # Filter by category
    if filter_data.get('category'):
        query = query.filter(AuditLog.category == filter_data['category'])

    # Filter by object type
    if filter_data.get('object_type'):
        query = query.filter(AuditLog.object_type == filter_data['object_type'])

    # Filter by object ID
    if filter_data.get('object_id'):
        query = query.filter(AuditLog.object_id == filter_data['object_id'])

    # Filter by IP address
    if filter_data.get('ip_address'):
        query = query.filter(AuditLog.ip_address == filter_data['ip_address'])

    # Filter by text search (in description or details)
    if filter_data.get('contains'):
        search_term = f"%{filter_data['contains']}%"
        # Search in both description and JSON details
        query = query.filter(
            or_(
                AuditLog.description.ilike(search_term),
                AuditLog.details.cast(AuditLog.TextType).ilike(search_term)
            )
        )

    # Security filter: non-admins can only see non-sensitive logs unless they have specific roles
    if not g.get('has_admin_role', False) and not g.get('has_auditor_role', False):
        # Filter out sensitive security logs for regular users
        query = query.filter(
            or_(
                AuditLog.severity.in_(['info', 'warning']),
                AuditLog.category.notin_(['security', 'auth']),
                AuditLog.user_id == g.get('user_id')  # Users can see their own logs
            )
        )

    return query


def parse_time_range(start_date_str: Optional[str],
                     end_date_str: Optional[str],
                     default_range_days: int = 30) -> Tuple[Optional[datetime], Optional[datetime]]:
    """
    Parse and validate time range from string inputs.

    Takes ISO format datetime strings and converts them to datetime objects.
    If only one boundary is provided, the other is inferred based on defaults.
    If neither is provided, defaults to the last 'default_range_days' days.

    Args:
        start_date_str (str, optional): ISO format start datetime
        end_date_str (str, optional): ISO format end datetime
        default_range_days (int): Default number of days for the range if not specified

    Returns:
        Tuple[Optional[datetime], Optional[datetime]]: Validated start and end datetimes

    Raises:
        ValueError: If date strings are invalid or if end date is before start date
    """
    start_date = None
    end_date = None

    # Parse end date if provided
    if end_date_str:
        try:
            end_date = _parse_datetime(end_date_str)
        except ValueError as e:
            raise ValueError(f"Invalid end_date format: {str(e)}")
    else:
        end_date = datetime.now(timezone.utc)

    # Parse start date if provided
    if start_date_str:
        try:
            start_date = _parse_datetime(start_date_str)
        except ValueError as e:
            raise ValueError(f"Invalid start_date format: {str(e)}")
    else:
        # Default to N days before end_date
        start_date = end_date - timedelta(days=default_range_days)

    # Ensure start date is before end date
    if start_date and end_date and start_date > end_date:
        raise ValueError("start_date must be before end_date")

    # Apply maximum range limit to prevent excessive queries
    max_range = current_app.config.get('AUDIT_MAX_DATE_RANGE_DAYS', 366)
    if (end_date - start_date).days > max_range:
        raise ValueError(f"Date range exceeds maximum allowed ({max_range} days)")

    return start_date, end_date


def _parse_datetime(date_str: str) -> datetime:
    """
    Parse a string into a datetime with timezone.

    Handles multiple ISO 8601 formats and ensures UTC timezone.

    Args:
        date_str (str): ISO format datetime string

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


def parse_filters_from_query_string(query_params: Dict[str, str]) -> Dict[str, Any]:
    """
    Parse and normalize filter parameters from query string.

    Takes raw query parameters and converts them to the correct types
    for the build_audit_query function.

    Args:
        query_params (Dict[str, str]): Raw query parameters

    Returns:
        Dict[str, Any]: Normalized filter parameters
    """
    filters = {}

    # Process datetime filters
    for date_field in ['start_date', 'end_date']:
        if date_field in query_params and query_params[date_field]:
            filters[date_field] = query_params[date_field]

    # Process ID filters (convert to integers)
    for id_field in ['user_id', 'object_id']:
        if id_field in query_params and query_params[id_field]:
            try:
                filters[id_field] = int(query_params[id_field])
            except ValueError:
                current_app.logger.warning(f"Invalid {id_field} value: {query_params[id_field]}")

    # Process string filters
    for str_field in ['username', 'event_type', 'severity', 'category',
                      'object_type', 'ip_address', 'contains']:
        if str_field in query_params and query_params[str_field]:
            filters[str_field] = query_params[str_field]

    return filters
