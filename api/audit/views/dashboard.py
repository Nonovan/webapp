"""
Audit Dashboard Data Aggregation and Visualization

This module provides functions for aggregating audit data into dashboard-ready
formats, generating visualizations, and preparing trend analyses. It transforms
raw audit log entries into structured summaries suitable for presentation in
administrative dashboards and reports.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Tuple, Union
import json

from flask import current_app
from sqlalchemy import func, distinct, desc, and_, or_, case
from sqlalchemy.sql.expression import text

from extensions import db, cache
from models.security import AuditLog
from models.auth.user import User
from core.security.cs_audit import get_critical_event_categories
from core.security.cs_utils import format_time_period, parse_time_period

# Initialize logger
logger = logging.getLogger(__name__)

# Cache settings
DASHBOARD_CACHE_PREFIX = 'audit_dashboard:'
DEFAULT_CACHE_TTL = 900  # 15 minutes


def get_dashboard_data(period: str = '7d') -> Dict[str, Any]:
    """
    Generate complete dashboard data for the given time period.

    Args:
        period: Time period string (e.g., '24h', '7d', '30d')

    Returns:
        Dict containing aggregated dashboard data
    """
    # Check cache first for expensive calculations
    cache_key = f"{DASHBOARD_CACHE_PREFIX}{period}"
    cached_data = cache.get(cache_key)

    if cached_data:
        logger.debug(f"Returning cached dashboard data for period: {period}")
        return cached_data

    try:
        # Parse time range
        end_date = datetime.now(timezone.utc)
        delta = parse_time_period(period)
        start_date = end_date - delta

        # Generate all dashboard components
        event_summary = get_event_summary(start_date, end_date)
        severity_distribution = get_severity_distribution(start_date, end_date)
        top_events = get_top_events(start_date, end_date)
        user_activity = get_user_activity(start_date, end_date)
        trend_data = generate_trend_data(period)
        security_metrics = get_security_metrics(start_date, end_date)

        # Combine all data
        dashboard_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "period": period,
            "time_range": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "formatted": format_time_period(period)
            },
            "summary": event_summary,
            "severity_distribution": severity_distribution,
            "top_events": top_events,
            "user_activity": user_activity,
            "trends": trend_data,
            "security_metrics": security_metrics
        }

        # Cache the result
        cache_ttl = current_app.config.get('AUDIT_DASHBOARD_DATA_TTL', DEFAULT_CACHE_TTL)
        cache.set(cache_key, dashboard_data, timeout=cache_ttl)

        return dashboard_data

    except Exception as e:
        logger.error(f"Error generating dashboard data: {str(e)}", exc_info=True)
        # Return minimal fallback data on failure
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "period": period,
            "error": "Failed to generate complete dashboard data",
            "summary": {"total_events": 0, "error_status": True}
        }


def get_event_summary(start_date: datetime, end_date: datetime) -> Dict[str, Any]:
    """
    Generate summary statistics for audit events in the given time range.

    Args:
        start_date: Start of time range
        end_date: End of time range

    Returns:
        Dict with summary statistics
    """
    try:
        # Get total event count
        total_count = db.session.query(func.count(AuditLog.id))\
            .filter(AuditLog.created_at.between(start_date, end_date))\
            .scalar() or 0

        # Get counts by severity
        severity_stats = db.session.query(
            AuditLog.severity,
            func.count(AuditLog.id)
        ).filter(
            AuditLog.created_at.between(start_date, end_date)
        ).group_by(AuditLog.severity).all()

        severity_counts = {
            "critical": 0,
            "error": 0,
            "warning": 0,
            "info": 0
        }

        for severity, count in severity_stats:
            if severity in severity_counts:
                severity_counts[severity] = count

        # Get counts by category
        category_stats = db.session.query(
            AuditLog.category,
            func.count(AuditLog.id)
        ).filter(
            AuditLog.created_at.between(start_date, end_date)
        ).group_by(AuditLog.category).all()

        category_counts = {}
        for category, count in category_stats:
            if category:  # Skip None categories
                category_counts[category] = count

        # Calculate average events per day
        days_diff = (end_date - start_date).total_seconds() / 86400
        daily_average = int(total_count / days_diff) if days_diff > 0 else 0

        # Calculate change from previous period
        previous_start = start_date - (end_date - start_date)
        previous_count = db.session.query(func.count(AuditLog.id))\
            .filter(AuditLog.created_at.between(previous_start, start_date))\
            .scalar() or 0

        if previous_count > 0:
            percent_change = ((total_count - previous_count) / previous_count) * 100
        else:
            percent_change = 0 if total_count == 0 else 100

        return {
            "total_events": total_count,
            "by_severity": severity_counts,
            "by_category": category_counts,
            "daily_average": daily_average,
            "previous_period_change": round(percent_change, 1),
            "unique_users": get_unique_user_count(start_date, end_date),
        }

    except Exception as e:
        logger.error(f"Error generating event summary: {str(e)}", exc_info=True)
        return {
            "total_events": 0,
            "by_severity": {"critical": 0, "error": 0, "warning": 0, "info": 0},
            "by_category": {},
            "daily_average": 0,
            "previous_period_change": 0,
            "unique_users": 0,
            "error_status": True
        }


def get_severity_distribution(start_date: datetime, end_date: datetime) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get distribution of event severities by category.

    Args:
        start_date: Start of time range
        end_date: End of time range

    Returns:
        Dict with severity distribution data
    """
    try:
        # Get all categories with their severity distributions
        query_result = db.session.query(
            AuditLog.category,
            AuditLog.severity,
            func.count(AuditLog.id)
        ).filter(
            AuditLog.created_at.between(start_date, end_date),
            AuditLog.category.isnot(None)  # Exclude null categories
        ).group_by(
            AuditLog.category,
            AuditLog.severity
        ).all()

        # Organize data by category
        categories = {}
        for category, severity, count in query_result:
            if category not in categories:
                categories[category] = {
                    "critical": 0,
                    "error": 0,
                    "warning": 0,
                    "info": 0
                }

            if severity in categories[category]:
                categories[category][severity] = count

        # Transform into list format for easier frontend consumption
        result = []
        for category, severities in categories.items():
            result.append({
                "category": category,
                "counts": severities,
                "total": sum(severities.values())
            })

        # Sort by total count descending
        result.sort(key=lambda x: x["total"], reverse=True)

        # Limit to top categories
        top_limit = current_app.config.get('AUDIT_DASHBOARD_CATEGORY_LIMIT', 10)
        if top_limit and len(result) > top_limit:
            result = result[:top_limit]
            has_more = True
        else:
            has_more = False

        return {
            "categories": result,
            "has_more": has_more
        }

    except Exception as e:
        logger.error(f"Error generating severity distribution: {str(e)}", exc_info=True)
        return {"categories": [], "has_more": False, "error_status": True}


def get_top_events(start_date: datetime, end_date: datetime, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Get the most frequent event types in the given time range.

    Args:
        start_date: Start of time range
        end_date: End of time range
        limit: Maximum number of events to return

    Returns:
        List of top events with counts
    """
    try:
        # Query for top events
        top_events_query = db.session.query(
            AuditLog.event_type,
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.created_at.between(start_date, end_date)
        ).group_by(
            AuditLog.event_type
        ).order_by(
            text('count DESC')
        ).limit(limit).all()

        # Format results
        result = []
        for event_type, count in top_events_query:
            # Get example description for this event type
            example = db.session.query(AuditLog.description)\
                .filter(AuditLog.event_type == event_type)\
                .order_by(AuditLog.created_at.desc())\
                .first()

            example_desc = example[0] if example else None

            result.append({
                "event_type": event_type,
                "count": count,
                "example_description": example_desc
            })

        return result

    except Exception as e:
        logger.error(f"Error getting top events: {str(e)}", exc_info=True)
        return []


def get_user_activity(start_date: datetime, end_date: datetime, limit: int = 5) -> List[Dict[str, Any]]:
    """
    Get the most active users in the given time range.

    Args:
        start_date: Start of time range
        end_date: End of time range
        limit: Maximum number of users to return

    Returns:
        List of most active users with their activity counts
    """
    try:
        # Query for most active users
        user_activity = db.session.query(
            AuditLog.user_id,
            func.count(AuditLog.id).label('event_count')
        ).filter(
            AuditLog.created_at.between(start_date, end_date),
            AuditLog.user_id.isnot(None)
        ).group_by(
            AuditLog.user_id
        ).order_by(
            text('event_count DESC')
        ).limit(limit).all()

        # Format results and add usernames
        result = []
        for user_id, count in user_activity:
            user = User.query.get(user_id)
            username = user.username if user else f"Unknown ({user_id})"

            # Get the count of different event types for this user
            distinct_events = db.session.query(func.count(distinct(AuditLog.event_type)))\
                .filter(
                    AuditLog.created_at.between(start_date, end_date),
                    AuditLog.user_id == user_id
                ).scalar() or 0

            # Get the most recent activity
            latest_activity = db.session.query(AuditLog)\
                .filter(AuditLog.user_id == user_id)\
                .order_by(AuditLog.created_at.desc())\
                .first()

            latest_time = latest_activity.created_at if latest_activity else None

            result.append({
                "user_id": user_id,
                "username": username,
                "event_count": count,
                "distinct_event_types": distinct_events,
                "latest_activity": latest_time.isoformat() if latest_time else None
            })

        return result

    except Exception as e:
        logger.error(f"Error getting user activity: {str(e)}", exc_info=True)
        return []


def generate_trend_data(period: str, interval: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate time series data for trending visualizations.

    Args:
        period: Time period string (e.g., '24h', '7d', '30d')
        interval: Optional override for interval granularity

    Returns:
        Dict containing trend data suitable for visualization
    """
    try:
        # Determine time range
        end_date = datetime.now(timezone.utc)
        delta = parse_time_period(period)
        start_date = end_date - delta

        # Determine appropriate interval based on period if not specified
        if not interval:
            if period == '24h':
                interval = 'hour'
                points = 24
            elif period == '7d':
                interval = 'day'
                points = 7
            elif period == '30d':
                interval = 'day'
                points = 30
            else:
                # Default to daily data points for longer periods
                interval = 'day'
                points = int(delta.total_seconds() / 86400)  # Convert to days

        # Initialize trend data structure
        trend_data = {
            "labels": [],
            "datasets": {
                "total": [],
                "critical": [],
                "error": [],
                "warning": [],
                "info": []
            },
            "interval": interval
        }

        # Generate labels based on interval
        if interval == 'hour':
            for i in range(points):
                point_time = end_date - timedelta(hours=points-i-1)
                trend_data["labels"].append(point_time.strftime("%H:%M"))

            # Get hourly data for each severity
            for severity in ["critical", "error", "warning", "info"]:
                hourly_data = get_hourly_data(start_date, end_date, severity)
                trend_data["datasets"][severity] = hourly_data

            # Calculate total hourly data
            hourly_totals = get_hourly_data(start_date, end_date)
            trend_data["datasets"]["total"] = hourly_totals

        else:  # daily interval
            for i in range(points):
                point_date = end_date - timedelta(days=points-i-1)
                trend_data["labels"].append(point_date.strftime("%Y-%m-%d"))

            # Get daily data for each severity
            for severity in ["critical", "error", "warning", "info"]:
                daily_data = get_daily_data(start_date, end_date, severity)
                trend_data["datasets"][severity] = daily_data

            # Calculate total daily data
            daily_totals = get_daily_data(start_date, end_date)
            trend_data["datasets"]["total"] = daily_totals

        return trend_data

    except Exception as e:
        logger.error(f"Error generating trend data: {str(e)}", exc_info=True)
        return {
            "labels": [],
            "datasets": {"total": [], "critical": [], "error": [], "warning": [], "info": []},
            "interval": interval or "day",
            "error_status": True
        }


def get_hourly_data(start_date: datetime, end_date: datetime, severity: Optional[str] = None) -> List[int]:
    """
    Get hourly event counts for the given time range.

    Args:
        start_date: Start of time range
        end_date: End of time range
        severity: Optional severity filter

    Returns:
        List of hourly event counts
    """
    try:
        # Calculate number of hours
        hours_diff = int((end_date - start_date).total_seconds() / 3600)
        if hours_diff <= 0:
            return []

        # Initialize result array
        result = [0] * hours_diff

        # Build query with optional severity filter
        query = db.session.query(
            func.date_trunc('hour', AuditLog.created_at).label('hour'),
            func.count(AuditLog.id)
        ).filter(
            AuditLog.created_at.between(start_date, end_date)
        )

        if severity:
            query = query.filter(AuditLog.severity == severity)

        # Execute query
        hourly_counts = query.group_by('hour').all()

        # Map results to the correct positions in the result array
        for hour_bucket, count in hourly_counts:
            hour = hour_bucket.replace(tzinfo=timezone.utc)
            hours_ago = int((end_date - hour).total_seconds() / 3600)
            if 0 <= hours_ago < hours_diff:
                result[hours_diff - 1 - hours_ago] = count

        return result

    except Exception as e:
        logger.error(f"Error getting hourly data: {str(e)}", exc_info=True)
        return []


def get_daily_data(start_date: datetime, end_date: datetime, severity: Optional[str] = None) -> List[int]:
    """
    Get daily event counts for the given time range.

    Args:
        start_date: Start of time range
        end_date: End of time range
        severity: Optional severity filter

    Returns:
        List of daily event counts
    """
    try:
        # Calculate number of days
        days_diff = int((end_date - start_date).total_seconds() / 86400)
        if days_diff <= 0:
            return []

        # Initialize result array
        result = [0] * days_diff

        # Build query with optional severity filter
        query = db.session.query(
            func.date_trunc('day', AuditLog.created_at).label('day'),
            func.count(AuditLog.id)
        ).filter(
            AuditLog.created_at.between(start_date, end_date)
        )

        if severity:
            query = query.filter(AuditLog.severity == severity)

        # Execute query
        daily_counts = query.group_by('day').all()

        # Map results to the correct positions in the result array
        for day_bucket, count in daily_counts:
            day = day_bucket.replace(tzinfo=timezone.utc)
            days_ago = int((end_date - day).total_seconds() / 86400)
            if 0 <= days_ago < days_diff:
                result[days_diff - 1 - days_ago] = count

        return result

    except Exception as e:
        logger.error(f"Error getting daily data: {str(e)}", exc_info=True)
        return []


def get_security_metrics(start_date: datetime, end_date: datetime) -> Dict[str, Any]:
    """
    Calculate security-specific metrics from audit logs.

    Args:
        start_date: Start of time range
        end_date: End of time range

    Returns:
        Dict with security metrics
    """
    try:
        # Get critical event categories from configuration
        critical_categories = get_critical_event_categories()

        # Count failed login attempts
        failed_logins = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.created_at.between(start_date, end_date),
            AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED
        ).scalar() or 0

        # Count permission changes
        permission_changes = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.created_at.between(start_date, end_date),
            or_(
                AuditLog.event_type == AuditLog.EVENT_PERMISSION_GRANTED,
                AuditLog.event_type == AuditLog.EVENT_PERMISSION_REVOKED,
                AuditLog.event_type == AuditLog.EVENT_ROLE_ASSIGNED,
                AuditLog.event_type == AuditLog.EVENT_ROLE_REMOVED
            )
        ).scalar() or 0

        # Count configuration changes
        config_changes = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.created_at.between(start_date, end_date),
            AuditLog.event_type == AuditLog.EVENT_CONFIG_CHANGE
        ).scalar() or 0

        # Count critical events
        critical_events = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.created_at.between(start_date, end_date),
            AuditLog.category.in_(critical_categories),
            AuditLog.severity.in_(['critical', 'error'])
        ).scalar() or 0

        # Calculate security score (basic algorithm)
        # This is a simplified example - production would use a more sophisticated algorithm
        base_score = 100

        # Deductions based on various factors (simplified)
        failed_login_impact = min(30, failed_logins / 10)
        critical_event_impact = min(40, critical_events * 5)

        security_score = max(0, base_score - failed_login_impact - critical_event_impact)
        security_score = round(security_score)

        return {
            "failed_logins": failed_logins,
            "permission_changes": permission_changes,
            "config_changes": config_changes,
            "critical_events": critical_events,
            "security_score": security_score,
            "security_rating": get_security_rating(security_score)
        }

    except Exception as e:
        logger.error(f"Error calculating security metrics: {str(e)}", exc_info=True)
        return {
            "failed_logins": 0,
            "permission_changes": 0,
            "config_changes": 0,
            "critical_events": 0,
            "security_score": 0,
            "security_rating": "unknown",
            "error_status": True
        }


def get_unique_user_count(start_date: datetime, end_date: datetime) -> int:
    """
    Get count of unique users who generated audit events in the given time range.

    Args:
        start_date: Start of time range
        end_date: End of time range

    Returns:
        Count of unique users
    """
    try:
        return db.session.query(func.count(distinct(AuditLog.user_id)))\
            .filter(
                AuditLog.created_at.between(start_date, end_date),
                AuditLog.user_id.isnot(None)
            ).scalar() or 0

    except Exception as e:
        logger.error(f"Error getting unique user count: {str(e)}", exc_info=True)
        return 0


def get_security_rating(score: int) -> str:
    """
    Convert numeric security score to rating.

    Args:
        score: Security score (0-100)

    Returns:
        String rating (excellent, good, fair, poor, critical)
    """
    if score >= 90:
        return "excellent"
    elif score >= 75:
        return "good"
    elif score >= 60:
        return "fair"
    elif score >= 40:
        return "poor"
    else:
        return "critical"


def clear_dashboard_cache() -> bool:
    """
    Clear all cached dashboard data.

    Returns:
        Boolean indicating success
    """
    try:
        # Use pattern delete to clear all dashboard cache keys
        cache.delete_many(cache.keys(f"{DASHBOARD_CACHE_PREFIX}*"))
        logger.info("Dashboard cache cleared successfully")
        return True
    except Exception as e:
        logger.error(f"Error clearing dashboard cache: {str(e)}", exc_info=True)
        return False
