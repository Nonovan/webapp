"""
Audit Reports Generation

This module provides functions for generating various types of reports from audit logs.
It handles data formatting, aggregation, and presentation in different output formats
such as JSON, CSV, and PDF.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Union, Tuple
import json
import os
import tempfile
from io import StringIO, BytesIO

from flask import current_app, Response, send_file
from sqlalchemy import func, distinct, desc, and_, or_
from sqlalchemy.sql.expression import text

from extensions import db, cache
from models.security import AuditLog
from models.auth.user import User
from core.security.cs_audit import get_critical_event_categories
from core.security.cs_utils import format_time_period, parse_time_period

# Initialize logger
logger = logging.getLogger(__name__)

# Constants
DEFAULT_CACHE_TTL = 900  # 15 minutes
REPORT_FORMATS = ["json", "csv", "pdf", "html"]
SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]


def generate_security_report(
    report_type: str = "general",
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    format_type: str = "pdf",
    severity: Optional[List[str]] = None,
    focus_areas: Optional[List[str]] = None
) -> Union[Dict[str, Any], str, bytes, Response]:
    """
    Generate a security report focusing on security-relevant events.

    Args:
        report_type: Type of security report (e.g., 'general', 'access_control', 'authentication')
        start_date: Start of time range for the report
        end_date: End of time range for the report
        format_type: Output format (json, csv, pdf, html)
        severity: Filter by severity levels
        focus_areas: Specific security areas to focus on

    Returns:
        Report data in the requested format
    """
    try:
        if not start_date:
            start_date = datetime.now(timezone.utc) - timedelta(days=30)
        if not end_date:
            end_date = datetime.now(timezone.utc)

        if format_type not in REPORT_FORMATS:
            raise ValueError(f"Unsupported format: {format_type}")

        # Filter severity if provided
        if severity:
            for level in severity:
                if level not in SEVERITY_LEVELS:
                    raise ValueError(f"Invalid severity level: {level}")
        else:
            severity = SEVERITY_LEVELS

        # Get critical event categories
        critical_categories = get_critical_event_categories()

        # Define report structure
        report = {
            "title": f"Security {report_type.capitalize()} Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "description": f"From {start_date.strftime('%Y-%m-%d %H:%M:%S')} to {end_date.strftime('%Y-%m-%d %H:%M:%S')}"
            },
            "summary": {},
            "details": {},
            "recommendations": []
        }

        # Build query based on report type and focus areas
        base_query = db.session.query(AuditLog).filter(
            AuditLog.created_at.between(start_date, end_date),
            AuditLog.severity.in_(severity)
        )

        # Apply report type specific filters
        if report_type == "authentication":
            events = [
                AuditLog.EVENT_LOGIN_SUCCESS, AuditLog.EVENT_LOGIN_FAILED,
                AuditLog.EVENT_LOGOUT, AuditLog.EVENT_PASSWORD_CHANGED,
                AuditLog.EVENT_MFA_ENABLED, AuditLog.EVENT_MFA_DISABLED
            ]
            base_query = base_query.filter(AuditLog.event_type.in_(events))

        elif report_type == "access_control":
            events = [
                AuditLog.EVENT_PERMISSION_DENIED, AuditLog.EVENT_ROLE_ASSIGNED,
                AuditLog.EVENT_ROLE_REMOVED, AuditLog.EVENT_PERMISSION_GRANTED,
                AuditLog.EVENT_PERMISSION_REVOKED
            ]
            base_query = base_query.filter(AuditLog.event_type.in_(events))

        elif report_type == "data_access":
            base_query = base_query.filter(
                or_(
                    AuditLog.event_type == AuditLog.EVENT_FILE_DOWNLOAD,
                    AuditLog.event_type == AuditLog.EVENT_FILE_UPLOAD,
                    AuditLog.event_type == AuditLog.EVENT_OBJECT_CREATED,
                    AuditLog.event_type == AuditLog.EVENT_OBJECT_UPDATED,
                    AuditLog.event_type == AuditLog.EVENT_OBJECT_DELETED,
                    AuditLog.category == "data"
                )
            )

        # Apply focus areas if provided
        if focus_areas:
            focus_conditions = []
            for area in focus_areas:
                if area == "admin":
                    focus_conditions.append(AuditLog.category == "admin")
                elif area == "security":
                    focus_conditions.append(AuditLog.category == "security")
                elif area == "critical":
                    focus_conditions.append(AuditLog.category.in_(critical_categories))

            if focus_conditions:
                base_query = base_query.filter(or_(*focus_conditions))

        # Get count by severity
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

        # Get events by type
        event_stats = db.session.query(
            AuditLog.event_type,
            func.count(AuditLog.id)
        ).filter(
            AuditLog.created_at.between(start_date, end_date)
        ).group_by(AuditLog.event_type).all()

        event_counts = {}
        for event_type, count in event_stats:
            event_counts[event_type] = count

        # Get top users
        top_users = db.session.query(
            AuditLog.user_id,
            func.count(AuditLog.id).label('event_count')
        ).filter(
            AuditLog.created_at.between(start_date, end_date),
            AuditLog.user_id.isnot(None)
        ).group_by(AuditLog.user_id).order_by(
            desc('event_count')
        ).limit(10).all()

        user_activity = []
        for user_id, count in top_users:
            user = User.query.get(user_id)
            username = user.username if user else f"User #{user_id}"
            user_activity.append({
                "user_id": user_id,
                "username": username,
                "event_count": count
            })

        # Get timeline data (daily counts)
        days_diff = (end_date - start_date).days + 1
        timeline_data = []

        for i in range(days_diff):
            day_date = start_date + timedelta(days=i)
            next_day = day_date + timedelta(days=1)

            day_count = db.session.query(func.count(AuditLog.id)).filter(
                AuditLog.created_at >= day_date,
                AuditLog.created_at < next_day
            ).scalar() or 0

            timeline_data.append({
                "date": day_date.strftime("%Y-%m-%d"),
                "count": day_count
            })

        # Add data to report
        report["summary"] = {
            "total_events": sum(severity_counts.values()),
            "by_severity": severity_counts,
            "by_event_type": event_counts
        }

        report["details"] = {
            "top_users": user_activity,
            "timeline": timeline_data
        }

        # Add recommendations based on findings
        if severity_counts.get("critical", 0) > 0:
            report["recommendations"].append(
                "Critical security events detected. Immediate investigation recommended."
            )

        if event_counts.get(AuditLog.EVENT_LOGIN_FAILED, 0) > 10:
            report["recommendations"].append(
                "High number of failed login attempts detected. Review authentication security."
            )

        if event_counts.get(AuditLog.EVENT_PERMISSION_DENIED, 0) > 5:
            report["recommendations"].append(
                "Multiple permission denied events detected. Review access control policies."
            )

        # Return report in requested format
        if format_type == "json":
            return report
        elif format_type == "csv":
            return _generate_csv_report(report)
        elif format_type == "pdf":
            return _generate_pdf_report(report)
        elif format_type == "html":
            return _generate_html_report(report)
        else:
            return report

    except Exception as e:
        logger.error(f"Error generating security report: {str(e)}", exc_info=True)
        raise


def generate_audit_summary(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    include_details: bool = False
) -> Dict[str, Any]:
    """
    Generate a summary of audit activity for a specified time period.

    Args:
        start_date: Start of time range
        end_date: End of time range
        include_details: Whether to include detailed event information

    Returns:
        Dictionary with audit summary data
    """
    try:
        if not start_date:
            start_date = datetime.now(timezone.utc) - timedelta(days=7)
        if not end_date:
            end_date = datetime.now(timezone.utc)

        # Get total count
        total_count = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.created_at.between(start_date, end_date)
        ).scalar() or 0

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

        # Get unique users
        unique_users = db.session.query(func.count(distinct(AuditLog.user_id))).filter(
            AuditLog.created_at.between(start_date, end_date),
            AuditLog.user_id.isnot(None)
        ).scalar() or 0

        # Create summary
        summary = {
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "days": (end_date - start_date).days
            },
            "total_events": total_count,
            "by_severity": severity_counts,
            "by_category": category_counts,
            "unique_users": unique_users,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

        # Add detail data if requested
        if include_details:
            # Add most recent critical/error events
            critical_events = db.session.query(AuditLog).filter(
                AuditLog.created_at.between(start_date, end_date),
                AuditLog.severity.in_(["critical", "error"])
            ).order_by(AuditLog.created_at.desc()).limit(10).all()

            summary["critical_events"] = [{
                "id": event.id,
                "timestamp": event.created_at.isoformat() if event.created_at else None,
                "event_type": event.event_type,
                "severity": event.severity,
                "description": event.description,
                "user_id": event.user_id
            } for event in critical_events]

            # Add daily activity trend
            days_diff = (end_date - start_date).days + 1
            daily_trend = []

            for i in range(days_diff):
                day_date = start_date + timedelta(days=i)
                next_day = day_date + timedelta(days=1)

                day_count = db.session.query(func.count(AuditLog.id)).filter(
                    AuditLog.created_at >= day_date,
                    AuditLog.created_at < next_day
                ).scalar() or 0

                daily_trend.append({
                    "date": day_date.strftime("%Y-%m-%d"),
                    "count": day_count
                })

            summary["daily_trend"] = daily_trend

        return summary

    except Exception as e:
        logger.error(f"Error generating audit summary: {str(e)}", exc_info=True)
        return {
            "error": "Failed to generate audit summary",
            "start_date": start_date.isoformat() if start_date else None,
            "end_date": end_date.isoformat() if end_date else None
        }


def generate_activity_report(
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    format_type: str = "json"
) -> Union[Dict[str, Any], str, bytes, Response]:
    """
    Generate a user activity report for a specific user.

    Args:
        user_id: ID of the user to report on
        username: Username to report on (alternative to user_id)
        start_date: Start of time range
        end_date: End of time range
        format_type: Output format (json, csv, pdf, html)

    Returns:
        Report data in the requested format
    """
    try:
        if not start_date:
            start_date = datetime.now(timezone.utc) - timedelta(days=30)
        if not end_date:
            end_date = datetime.now(timezone.utc)

        if format_type not in REPORT_FORMATS:
            raise ValueError(f"Unsupported format: {format_type}")

        # Find user if username provided
        if username and not user_id:
            user = User.query.filter_by(username=username).first()
            if user:
                user_id = user.id
            else:
                raise ValueError(f"User not found with username: {username}")

        # Confirm we have a user_id
        if not user_id:
            raise ValueError("Either user_id or username must be provided")

        # Get user information
        user = User.query.get(user_id)
        if not user:
            raise ValueError(f"User not found with ID: {user_id}")

        # Build report structure
        report = {
            "title": f"User Activity Report for {user.username}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "description": f"From {start_date.strftime('%Y-%m-%d %H:%M:%S')} to {end_date.strftime('%Y-%m-%d %H:%M:%S')}"
            },
            "user": {
                "id": user_id,
                "username": user.username,
                "email": getattr(user, 'email', None)
            },
            "summary": {},
            "activities": {}
        }

        # Get total event count
        total_count = db.session.query(func.count(AuditLog.id)).filter(
            AuditLog.user_id == user_id,
            AuditLog.created_at.between(start_date, end_date)
        ).scalar() or 0

        # Get counts by event type
        event_stats = db.session.query(
            AuditLog.event_type,
            func.count(AuditLog.id)
        ).filter(
            AuditLog.user_id == user_id,
            AuditLog.created_at.between(start_date, end_date)
        ).group_by(AuditLog.event_type).all()

        event_counts = {}
        for event_type, count in event_stats:
            event_counts[event_type] = count

        # Get counts by severity
        severity_stats = db.session.query(
            AuditLog.severity,
            func.count(AuditLog.id)
        ).filter(
            AuditLog.user_id == user_id,
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

        # Get login/logout activity
        login_events = AuditLog.query.filter(
            AuditLog.user_id == user_id,
            AuditLog.created_at.between(start_date, end_date),
            AuditLog.event_type.in_([AuditLog.EVENT_LOGIN_SUCCESS, AuditLog.EVENT_LOGOUT])
        ).order_by(AuditLog.created_at).all()

        login_activity = [{
            "timestamp": event.created_at.isoformat() if event.created_at else None,
            "event_type": event.event_type,
            "ip_address": event.ip_address,
            "user_agent": event.user_agent
        } for event in login_events]

        # Get daily activity
        days_diff = (end_date - start_date).days + 1
        daily_activity = []

        for i in range(days_diff):
            day_date = start_date + timedelta(days=i)
            next_day = day_date + timedelta(days=1)

            day_count = db.session.query(func.count(AuditLog.id)).filter(
                AuditLog.user_id == user_id,
                AuditLog.created_at >= day_date,
                AuditLog.created_at < next_day
            ).scalar() or 0

            daily_activity.append({
                "date": day_date.strftime("%Y-%m-%d"),
                "count": day_count
            })

        # Get most recent activities
        recent_activities = AuditLog.query.filter(
            AuditLog.user_id == user_id,
            AuditLog.created_at.between(start_date, end_date)
        ).order_by(AuditLog.created_at.desc()).limit(50).all()

        recent_activity_list = [{
            "id": activity.id,
            "timestamp": activity.created_at.isoformat() if activity.created_at else None,
            "event_type": activity.event_type,
            "severity": activity.severity,
            "description": activity.description,
            "ip_address": activity.ip_address,
            "category": activity.category
        } for activity in recent_activities]

        # Add data to report
        report["summary"] = {
            "total_events": total_count,
            "by_event_type": event_counts,
            "by_severity": severity_counts
        }

        report["activities"] = {
            "logins": login_activity,
            "daily": daily_activity,
            "recent": recent_activity_list
        }

        # Return report in requested format
        if format_type == "json":
            return report
        elif format_type == "csv":
            return _generate_csv_report(report)
        elif format_type == "pdf":
            return _generate_pdf_report(report)
        elif format_type == "html":
            return _generate_html_report(report)
        else:
            return report

    except Exception as e:
        logger.error(f"Error generating user activity report: {str(e)}", exc_info=True)
        raise


def format_report_data(logs: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Format audit log data for reporting, ensuring consistent presentation.

    Args:
        logs: List of audit log dictionaries

    Returns:
        Tuple containing formatted log list and ordered headers
    """
    try:
        # Extract all possible keys from all logs
        all_keys = set()
        for log in logs:
            all_keys.update(log.keys())

        # Format each log consistently
        formatted_logs = []
        for log in logs:
            formatted_log = {}

            # Format timestamp if present
            if 'created_at' in log and log['created_at']:
                if isinstance(log['created_at'], str):
                    formatted_log['created_at'] = log['created_at']
                else:
                    formatted_log['created_at'] = log['created_at'].isoformat()

            # Format details if present as JSON
            if 'details' in log and log['details']:
                if isinstance(log['details'], str):
                    try:
                        formatted_log['details'] = json.loads(log['details'])
                    except json.JSONDecodeError:
                        formatted_log['details'] = log['details']
                else:
                    formatted_log['details'] = log['details']

            # Copy all other fields
            for key in all_keys:
                if key not in formatted_log and key in log:
                    formatted_log[key] = log[key]

            formatted_logs.append(formatted_log)

        # Define a consistent header order
        ordered_keys = sorted(list(all_keys), key=lambda x: (
            0 if x == 'id' else
            1 if x == 'created_at' else
            2 if x == 'event_type' else
            3 if x == 'severity' else
            4 if x == 'category' else
            5 if x == 'user_id' else
            6 if x == 'username' else
            7 if x == 'ip_address' else
            8 if x == 'description' else
            9 if x == 'details' else
            10  # Put others at the end
        ))

        return formatted_logs, ordered_keys

    except Exception as e:
        logger.error(f"Error formatting report data: {str(e)}", exc_info=True)
        return logs, list(set().union(*(log.keys() for log in logs)))


# --- Helper Functions for Report Generation ---

def _generate_csv_report(report_data: Dict[str, Any]) -> Response:
    """Generate a CSV formatted report."""
    try:
        csv_output = StringIO()

        # If this is an activity report
        if "activities" in report_data and "recent" in report_data["activities"]:
            # Get recent activities and format them
            recent_activities = report_data["activities"]["recent"]
            if recent_activities:
                # Generate headers
                headers = list(recent_activities[0].keys())
                csv_output.write(",".join(headers) + "\n")

                # Write rows
                for activity in recent_activities:
                    row = [str(activity.get(h, "")) for h in headers]
                    # Escape commas in fields
                    row = [f'"{field}"' if "," in field else field for field in row]
                    csv_output.write(",".join(row) + "\n")
        else:
            # Generic report format - create a flattened representation
            csv_output.write("Section,Key,Value\n")

            # Write metadata
            csv_output.write(f"Report,Title,\"{report_data.get('title', '')}\"\n")
            csv_output.write(f"Report,Generated,\"{report_data.get('generated_at', '')}\"\n")

            # Write period information
            period = report_data.get("period", {})
            csv_output.write(f"Period,Start,\"{period.get('start', '')}\"\n")
            csv_output.write(f"Period,End,\"{period.get('end', '')}\"\n")

            # Write summary information
            summary = report_data.get("summary", {})
            for key, value in summary.items():
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        csv_output.write(f"Summary,{key}.{sub_key},\"{sub_value}\"\n")
                else:
                    csv_output.write(f"Summary,{key},\"{value}\"\n")

        # Create response with CSV data
        csv_data = csv_output.getvalue()
        csv_output.close()

        # Return as a response that will be treated as a file download
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-disposition": f"attachment; filename=report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
        )

    except Exception as e:
        logger.error(f"Error generating CSV report: {str(e)}", exc_info=True)
        raise


def _generate_pdf_report(report_data: Dict[str, Any]) -> Response:
    """Generate a PDF formatted report."""
    try:
        # First generate an HTML version of the report
        html_content = _generate_html_report(report_data, as_string=True)

        # Check if WeasyPrint is available (should be imported at module level in production)
        try:
            from weasyprint import HTML
            pdf_content = HTML(string=html_content).write_pdf()

            # Return as a response that will be treated as a file download
            return Response(
                pdf_content,
                mimetype="application/pdf",
                headers={"Content-disposition": f"attachment; filename=report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"}
            )
        except ImportError:
            # If WeasyPrint is not available, create a simple PDF with a warning
            logger.warning("WeasyPrint not available. Using simple PDF generation.")

            # In a real implementation, we'd want to use another PDF library as fallback
            # For this example, we'll return a simple text file with a warning
            return Response(
                "PDF generation requires WeasyPrint. Please install it or request a different format.",
                mimetype="text/plain",
                headers={"Content-disposition": f"attachment; filename=report_error_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"}
            )

    except Exception as e:
        logger.error(f"Error generating PDF report: {str(e)}", exc_info=True)
        raise


def _generate_html_report(report_data: Dict[str, Any], as_string: bool = False) -> Union[Response, str]:
    """
    Generate an HTML formatted report.

    Args:
        report_data: The report data to format
        as_string: If True, return the HTML as a string instead of a Response

    Returns:
        Either a Response object or an HTML string
    """
    try:
        # Basic HTML template
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_data.get('title', 'Audit Report')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; }}
        h1, h2, h3, h4 {{ color: #2c3e50; }}
        h1 {{ border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .dashboard {{ display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 20px; }}
        .dashboard-item {{ flex: 1; min-width: 200px; background-color: #f8f9fa; padding: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .dashboard-item h3 {{ margin-top: 0; }}
        .summary-count {{ font-size: 24px; font-weight: bold; }}
        .critical {{ color: #e74c3c; }}
        .error {{ color: #e67e22; }}
        .warning {{ color: #f39c12; }}
        .info {{ color: #3498db; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .chart-container {{ width: 100%; height: 300px; margin-bottom: 20px; }}
        .footer {{ margin-top: 40px; color: #7f8c8d; font-size: 12px; text-align: center; }}
        @media print {{
            body {{ font-size: 12px; }}
            .dashboard-item {{ break-inside: avoid; }}
            table {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{report_data.get('title', 'Audit Report')}</h1>

        <div class="metadata">
            <p><strong>Generated:</strong> {report_data.get('generated_at', '')}</p>
            <p><strong>Period:</strong> {report_data.get('period', {}).get('description', '')}</p>
        </div>
"""

        # Add summary section
        summary = report_data.get('summary', {})
        if summary:
            html += f"""
        <h2>Summary</h2>
        <div class="dashboard">
            <div class="dashboard-item">
                <h3>Total Events</h3>
                <p class="summary-count">{summary.get('total_events', 0)}</p>
            </div>
"""

            # Add severity counts if present
            severity_counts = summary.get('by_severity', {})
            if severity_counts:
                for severity, count in severity_counts.items():
                    html += f"""
            <div class="dashboard-item">
                <h3>{severity.capitalize()}</h3>
                <p class="summary-count {severity}">{count}</p>
            </div>
"""

        # Add user section for activity reports
        if "user" in report_data:
            user = report_data.get("user", {})
            html += f"""
        <h2>User Information</h2>
        <div class="dashboard">
            <div class="dashboard-item">
                <h3>Username</h3>
                <p class="summary-count">{user.get('username', '')}</p>
            </div>
            <div class="dashboard-item">
                <h3>User ID</h3>
                <p class="summary-count">{user.get('id', '')}</p>
            </div>
            <div class="dashboard-item">
                <h3>Email</h3>
                <p class="summary-count">{user.get('email', '')}</p>
            </div>
        </div>
"""

        # Add activities if present (for activity reports)
        if "activities" in report_data:
            activities = report_data.get("activities", {})

            # Add daily activity chart
            daily_activity = activities.get("daily", [])
            if daily_activity:
                dates = [item.get("date", "") for item in daily_activity]
                counts = [item.get("count", 0) for item in daily_activity]

                html += f"""
        <h2>Daily Activity</h2>
        <div class="chart-container">
            <canvas id="dailyActivityChart"></canvas>
        </div>
        <script>
            // Data for the chart - will be filled in with JavaScript after load
            const dailyDates = {dates};
            const dailyCounts = {counts};
        </script>
"""

            # Add recent activities table
            recent_activities = activities.get("recent", [])
            if recent_activities:
                html += """
        <h2>Recent Activities</h2>
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Event Type</th>
                        <th>Severity</th>
                        <th>Description</th>
                        <th>IP Address</th>
                    </tr>
                </thead>
                <tbody>
"""

                for activity in recent_activities:
                    html += f"""
                    <tr>
                        <td>{activity.get('timestamp', '')}</td>
                        <td>{activity.get('event_type', '')}</td>
                        <td class="{activity.get('severity', '')}">{activity.get('severity', '')}</td>
                        <td>{activity.get('description', '')}</td>
                        <td>{activity.get('ip_address', '')}</td>
                    </tr>
"""

                html += """
                </tbody>
            </table>
        </div>
"""

        # Add recommendations if present
        recommendations = report_data.get("recommendations", [])
        if recommendations:
            html += """
        <h2>Recommendations</h2>
        <ul>
"""

            for recommendation in recommendations:
                html += f"            <li>{recommendation}</li>\n"

            html += "        </ul>\n"

        # Add footer and close HTML
        html += f"""
        <div class="footer">
            <p>Report generated by Audit System on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        // Load charts if canvas elements exist
        document.addEventListener('DOMContentLoaded', function() {{
            if(document.getElementById('dailyActivityChart')) {{
                const ctx = document.getElementById('dailyActivityChart').getContext('2d');
                new Chart(ctx, {{
                    type: 'line',
                    data: {{
                        labels: dailyDates,
                        datasets: [{{
                            label: 'Activity Count',
                            data: dailyCounts,
                            backgroundColor: 'rgba(54, 162, 235, 0.2)',
                            borderColor: 'rgba(54, 162, 235, 1)',
                            borderWidth: 1,
                            tension: 0.1
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        scales: {{
                            y: {{
                                beginAtZero: true,
                                ticks: {{
                                    precision: 0
                                }}
                            }}
                        }}
                    }}
                }});
            }}
        }});
    </script>
</body>
</html>
"""

        if as_string:
            return html
        else:
            # Return as a response
            return Response(
                html,
                mimetype="text/html",
                headers={"Content-disposition": f"attachment; filename=report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"}
            )

    except Exception as e:
        logger.error(f"Error generating HTML report: {str(e)}", exc_info=True)
        raise
