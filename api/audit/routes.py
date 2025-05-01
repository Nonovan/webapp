"""
Audit API routes for the Cloud Infrastructure Platform.

This module implements RESTful endpoints for accessing, querying, and analyzing
audit logs, providing functionality for compliance reporting, security monitoring,
and administrative oversight. All endpoints enforce strict access control and
implement comprehensive logging of access patterns.

The API supports:
- Filtering logs by various criteria
- Exporting logs in multiple formats
- Generating compliance reports
- Analyzing security events and trends
- Dashboard data aggregation
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Tuple, Union
import json
import logging

from flask import Blueprint, request, jsonify, current_app, Response, g, abort, send_file
from sqlalchemy import desc, func, or_, and_
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import NotFound, Forbidden, BadRequest

from extensions import db, limiter, cache, metrics
from models.security.audit_log import AuditLog
from models.auth.user import User
from core.security import require_permission, log_security_event
from .schemas import (
    audit_log_schema,
    audit_logs_schema,
    audit_filter_schema,
    export_schema,
    compliance_report_schema
)
from .filters import build_audit_query, parse_time_range
from .exporters import export_audit_data
from .analyzers import analyze_security_events, correlate_events
from .views.compliance import generate_compliance_report
from .views.dashboard import get_dashboard_data
from .views.reports import generate_security_report

# Initialize logger
logger = logging.getLogger(__name__)

# Create blueprint
audit_bp = Blueprint('audit', __name__, url_prefix='/audit')

# Apply rate limits with overrides from config
DEFAULT_LIMIT = current_app.config.get('RATELIMIT_AUDIT_DEFAULT', "60 per minute") if hasattr(current_app, 'config') else "60 per minute"
EXPORT_LIMIT = current_app.config.get('RATELIMIT_AUDIT_EXPORT', "10 per hour") if hasattr(current_app, 'config') else "10 per hour"
REPORT_LIMIT = current_app.config.get('RATELIMIT_AUDIT_REPORTS', "20 per hour") if hasattr(current_app, 'config') else "20 per hour"

# Configure audit metrics
audit_request_count = metrics.counter(
    'audit_api_requests_total',
    'Total number of Audit API requests',
    labels=['endpoint', 'status']
)

audit_export_size = metrics.histogram(
    'audit_export_size_bytes',
    'Size of exported audit data in bytes',
    labels=['format'],
    buckets=(10_000, 100_000, 1_000_000, 10_000_000, 100_000_000)
)

audit_latency = metrics.histogram(
    'audit_api_latency_seconds',
    'Audit API request latency in seconds',
    labels=['endpoint'],
    buckets=(0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 10)
)

# Error handler for the audit API
def handle_api_error(e: Exception, status_code: int = 500) -> Tuple[Response, int]:
    """Common error handler for audit API endpoints."""
    logger.error(f"Audit API error: {str(e)}", exc_info=True)

    # Log security event for critical errors
    if status_code >= 500:
        log_security_event(
            event_type="audit_api_error",
            description=f"Audit API error: {str(e)}",
            severity="error",
            user_id=g.get('user_id'),
            ip_address=request.remote_addr,
            details={"endpoint": request.path, "method": request.method}
        )

    error_message = str(e) if not isinstance(e, SQLAlchemyError) else "Database error"
    return jsonify({"error": error_message}), status_code

@audit_bp.errorhandler(SQLAlchemyError)
def handle_db_error(e):
    return handle_api_error(e, 500)

@audit_bp.errorhandler(Forbidden)
def handle_forbidden(e):
    return handle_api_error(e, 403)

@audit_bp.errorhandler(BadRequest)
def handle_bad_request(e):
    return handle_api_error(e, 400)

@audit_bp.errorhandler(NotFound)
def handle_not_found(e):
    return handle_api_error(e, 404)

@audit_bp.errorhandler(Exception)
def handle_exception(e):
    return handle_api_error(e, 500)

# --- Audit Log Access Endpoints ---

@audit_bp.route('/logs', methods=['GET'])
@require_permission('audit:logs:read')
@limiter.limit(DEFAULT_LIMIT)
def get_audit_logs():
    """
    Query audit logs with flexible filtering options.

    Query Parameters:
        start_date (str): ISO format datetime
        end_date (str): ISO format datetime
        user_id (int): Filter by user ID
        username (str): Filter by username
        event_type (str): Filter by event type
        severity (str): Filter by severity level
        category (str): Filter by event category
        object_type (str): Filter by affected object type
        object_id (str): Filter by affected object ID
        ip_address (str): Filter by originating IP address
        contains (str): Search in description and details
        page (int): Page number (default: 1)
        per_page (int): Results per page (default: 50, max: 100)
        sort_by (str): Field to sort by (default: created_at)
        sort_dir (str): Sort direction (asc/desc, default: desc)

    Returns:
        JSON: Filtered audit logs with pagination metadata
    """
    try:
        # Parse and validate query parameters
        filter_data = {
            'start_date': request.args.get('start_date'),
            'end_date': request.args.get('end_date'),
            'user_id': request.args.get('user_id'),
            'username': request.args.get('username'),
            'event_type': request.args.get('event_type'),
            'severity': request.args.get('severity'),
            'category': request.args.get('category'),
            'object_type': request.args.get('object_type'),
            'object_id': request.args.get('object_id'),
            'ip_address': request.args.get('ip_address'),
            'contains': request.args.get('contains')
        }

        # Validate filter parameters that are present
        non_empty_filters = {k: v for k, v in filter_data.items() if v is not None}
        if non_empty_filters:
            errors = audit_filter_schema.validate(non_empty_filters)
            if errors:
                return jsonify({"error": "Invalid filter parameters", "details": errors}), 400

        # Pagination parameters with defaults and limits
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(int(request.args.get('per_page', 50)), 100)  # Limit to 100 max

        # Sorting parameters
        sort_by = request.args.get('sort_by', 'created_at')
        sort_dir = request.args.get('sort_dir', 'desc').lower()

        # Validate sort parameters
        if sort_by not in ['id', 'created_at', 'event_type', 'severity', 'category', 'user_id']:
            sort_by = 'created_at'
        if sort_dir not in ['asc', 'desc']:
            sort_dir = 'desc'

        # Build the query with filters
        query = build_audit_query(filter_data)

        # Count total before pagination for metadata
        total_count = query.count()
        total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1

        # Apply sorting
        if sort_dir == 'asc':
            query = query.order_by(getattr(AuditLog, sort_by).asc())
        else:
            query = query.order_by(getattr(AuditLog, sort_by).desc())

        # Apply pagination
        query = query.offset((page - 1) * per_page).limit(per_page)

        # Execute query
        logs = query.all()

        # Track metrics
        log_count = len(logs)
        metrics.gauge('audit_query_result_count', log_count, labels={'endpoint': '/logs'})
        audit_request_count.inc(1, labels={'endpoint': '/logs', 'status': '200'})

        # Format logs using schema
        result = audit_logs_schema.dump(logs)

        # Include pagination metadata in the response
        return jsonify({
            "data": result,
            "meta": {
                "page": page,
                "per_page": per_page,
                "total_pages": total_pages,
                "total_items": total_count
            }
        }), 200

    except ValueError as e:
        audit_request_count.inc(1, labels={'endpoint': '/logs', 'status': '400'})
        return jsonify({"error": str(e)}), 400
    except SQLAlchemyError as e:
        audit_request_count.inc(1, labels={'endpoint': '/logs', 'status': '500'})
        logger.error(f"Database error retrieving audit logs: {str(e)}")
        return jsonify({"error": "Database error occurred"}), 500
    except Exception as e:
        audit_request_count.inc(1, labels={'endpoint': '/logs', 'status': '500'})
        logger.error(f"Unexpected error in get_audit_logs: {str(e)}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500

@audit_bp.route('/logs/<int:log_id>', methods=['GET'])
@require_permission('audit:logs:read')
@limiter.limit(DEFAULT_LIMIT)
def get_audit_log(log_id: int):
    """
    Get detailed information about a specific audit log entry.

    Args:
        log_id (int): ID of the audit log to retrieve

    Returns:
        JSON: Detailed audit log entry
    """
    try:
        log = AuditLog.query.get(log_id)
        if not log:
            audit_request_count.inc(1, labels={'endpoint': '/logs/id', 'status': '404'})
            return jsonify({"error": "Audit log not found"}), 404

        # Security check: Only admins and auditors can see sensitive entries
        if log.severity in ['critical', 'high'] and not g.get('has_admin_role', False):
            if not g.get('has_auditor_role', False):
                audit_request_count.inc(1, labels={'endpoint': '/logs/id', 'status': '403'})
                return jsonify({"error": "Insufficient permissions to access this audit log"}), 403

        result = audit_log_schema.dump(log)

        # Add user information if available
        if log.user_id:
            user = User.query.get(log.user_id)
            if user:
                result['username'] = user.username

        audit_request_count.inc(1, labels={'endpoint': '/logs/id', 'status': '200'})
        return jsonify(result), 200

    except SQLAlchemyError as e:
        audit_request_count.inc(1, labels={'endpoint': '/logs/id', 'status': '500'})
        logger.error(f"Database error retrieving audit log: {str(e)}")
        return jsonify({"error": "Database error occurred"}), 500
    except Exception as e:
        audit_request_count.inc(1, labels={'endpoint': '/logs/id', 'status': '500'})
        logger.error(f"Unexpected error in get_audit_log: {str(e)}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500

@audit_bp.route('/export', methods=['POST'])
@require_permission('audit:export')
@limiter.limit(EXPORT_LIMIT)
def export_logs():
    """
    Export audit logs in various formats.

    Request Body (JSON):
        format (str): Export format (json, csv, pdf)
        start_date (str): ISO format datetime
        end_date (str): ISO format datetime
        filters (dict, optional): Additional filters to apply

    Returns:
        File download or JSON: Exported audit data in the requested format
    """
    try:
        # Get and validate request data
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Validate with schema
        errors = export_schema.validate(data)
        if errors:
            return jsonify({"error": "Invalid request parameters", "details": errors}), 400

        format_type = data['format'].lower()
        if format_type not in ['json', 'csv', 'pdf']:
            return jsonify({"error": "Unsupported format. Use 'json', 'csv', or 'pdf'"}), 400

        # Check export size limits
        result_limit = current_app.config.get('AUDIT_EXPORT_LIMIT', 50000)

        # Parse time range
        start_date, end_date = parse_time_range(data.get('start_date'), data.get('end_date'))

        # Get filters
        filters = data.get('filters', {})

        # Check if this might be a large export
        count_query = build_audit_query({
            'start_date': start_date.isoformat() if start_date else None,
            'end_date': end_date.isoformat() if end_date else None,
            **filters
        })
        estimated_count = count_query.count()

        if estimated_count > result_limit:
            return jsonify({
                "error": "Export size exceeds limit",
                "details": {
                    "estimated_count": estimated_count,
                    "limit": result_limit
                }
            }), 400

        # Log the export request
        log_security_event(
            event_type="audit_export",
            description=f"Audit log export initiated in {format_type} format",
            severity="info",
            user_id=g.get('user_id'),
            ip_address=request.remote_addr,
            details={
                "format": format_type,
                "estimated_count": estimated_count,
                "filters": filters,
                "start_date": start_date.isoformat() if start_date else None,
                "end_date": end_date.isoformat() if end_date else None
            }
        )

        # Generate export
        export_result = export_audit_data(
            format_type=format_type,
            start_date=start_date,
            end_date=end_date,
            filters=filters
        )

        # Track metrics for the export
        if hasattr(export_result, 'content_length'):
            audit_export_size.observe(export_result.content_length, labels={'format': format_type})

        audit_request_count.inc(1, labels={'endpoint': '/export', 'status': '200'})

        # Return appropriate response based on format
        if format_type == 'json':
            # For JSON, we return directly as JSON response
            if isinstance(export_result, dict):
                return jsonify(export_result), 200
            # Otherwise assume it's already a Response
            return export_result

        # For CSV and PDF, return as file download
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if format_type == 'csv':
            content_type = 'text/csv'
            filename = f"audit_export_{timestamp}.csv"
        else:  # PDF
            content_type = 'application/pdf'
            filename = f"audit_export_{timestamp}.pdf"

        # Handle case where export_result is a file path
        if isinstance(export_result, str) and (export_result.startswith('/') or export_result.startswith('./')):
            return send_file(export_result,
                           mimetype=content_type,
                           download_name=filename,
                           as_attachment=True)

        # Otherwise assume it's a Response or has the right headers already
        return export_result

    except ValueError as e:
        audit_request_count.inc(1, labels={'endpoint': '/export', 'status': '400'})
        return jsonify({"error": str(e)}), 400
    except SQLAlchemyError as e:
        audit_request_count.inc(1, labels={'endpoint': '/export', 'status': '500'})
        logger.error(f"Database error during audit export: {str(e)}")
        return jsonify({"error": "Database error occurred during export"}), 500
    except Exception as e:
        audit_request_count.inc(1, labels={'endpoint': '/export', 'status': '500'})
        logger.error(f"Error during audit export: {str(e)}", exc_info=True)
        return jsonify({"error": f"Export failed: {str(e)}"}), 500

# --- Compliance and Reporting Endpoints ---

@audit_bp.route('/reports/compliance', methods=['POST'])
@require_permission('audit:reports:generate')
@limiter.limit(REPORT_LIMIT)
def create_compliance_report():
    """
    Generate a compliance report for a specific standard.

    Request Body (JSON):
        report_type (str): Compliance standard (e.g., 'pci-dss', 'hipaa', 'gdpr')
        start_date (str): ISO format datetime
        end_date (str): ISO format datetime
        format (str): Output format (json, csv, pdf)
        include_sections (list, optional): Specific sections to include

    Returns:
        File download or JSON: Compliance report in the requested format
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Validate with schema
        errors = compliance_report_schema.validate(data)
        if errors:
            return jsonify({"error": "Invalid report parameters", "details": errors}), 400

        # Check if report type is supported
        report_type = data['report_type'].lower()
        supported_frameworks = current_app.config.get('COMPLIANCE_FRAMEWORKS', {}).keys()
        if report_type not in supported_frameworks:
            return jsonify({
                "error": "Unsupported compliance framework",
                "supported": list(supported_frameworks)
            }), 400

        format_type = data['format'].lower()
        if format_type not in ['json', 'csv', 'pdf']:
            return jsonify({"error": "Unsupported format. Use 'json', 'csv', or 'pdf'"}), 400

        # Parse time range
        start_date, end_date = parse_time_range(data.get('start_date'), data.get('end_date'))

        # Optional sections to include
        include_sections = data.get('include_sections', [])

        # Log the report generation request
        log_security_event(
            event_type="compliance_report_generated",
            description=f"Compliance report generation initiated: {report_type}",
            severity="info",
            user_id=g.get('user_id'),
            ip_address=request.remote_addr,
            details={
                "report_type": report_type,
                "format": format_type,
                "start_date": start_date.isoformat() if start_date else None,
                "end_date": end_date.isoformat() if end_date else None,
                "include_sections": include_sections
            }
        )

        # Generate compliance report
        report_result = generate_compliance_report(
            report_type=report_type,
            start_date=start_date,
            end_date=end_date,
            format_type=format_type,
            sections=include_sections
        )

        audit_request_count.inc(1, labels={'endpoint': '/reports/compliance', 'status': '200'})

        # Handle report result based on format
        timestamp = datetime.now().strftime("%Y%m%d")

        if format_type == 'json':
            if isinstance(report_result, dict):
                return jsonify(report_result), 200
            # Otherwise assume it's already a Response
            return report_result

        # For CSV and PDF, return as file download
        if format_type == 'csv':
            content_type = 'text/csv'
            filename = f"compliance_{report_type}_{timestamp}.csv"
        else:  # PDF
            content_type = 'application/pdf'
            filename = f"compliance_{report_type}_{timestamp}.pdf"

        # Handle case where report_result is a file path
        if isinstance(report_result, str) and (report_result.startswith('/') or report_result.startswith('./')):
            return send_file(report_result,
                           mimetype=content_type,
                           download_name=filename,
                           as_attachment=True)

        # Otherwise assume it's a Response or has the right headers already
        return report_result

    except ValueError as e:
        audit_request_count.inc(1, labels={'endpoint': '/reports/compliance', 'status': '400'})
        return jsonify({"error": str(e)}), 400
    except SQLAlchemyError as e:
        audit_request_count.inc(1, labels={'endpoint': '/reports/compliance', 'status': '500'})
        logger.error(f"Database error during compliance report generation: {str(e)}")
        return jsonify({"error": "Database error occurred"}), 500
    except Exception as e:
        audit_request_count.inc(1, labels={'endpoint': '/reports/compliance', 'status': '500'})
        logger.error(f"Error generating compliance report: {str(e)}", exc_info=True)
        return jsonify({"error": f"Report generation failed: {str(e)}"}), 500

@audit_bp.route('/reports/security', methods=['POST'])
@require_permission('audit:reports:security')
@limiter.limit(REPORT_LIMIT)
def create_security_report():
    """
    Generate a security report focusing on security-relevant events.

    Request Body (JSON):
        report_type (str): Report type (e.g., 'access_control', 'authentication', 'data_access')
        start_date (str): ISO format datetime
        end_date (str): ISO format datetime
        format (str): Output format (json, csv, pdf)
        focus_areas (list, optional): Specific security areas to focus on

    Returns:
        File download or JSON: Security report in the requested format
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Extract parameters
        report_type = data.get('report_type', 'general').lower()
        format_type = data.get('format', 'pdf').lower()
        focus_areas = data.get('focus_areas', [])

        # Parse time range
        start_date, end_date = parse_time_range(data.get('start_date'), data.get('end_date'))

        # Generate security report
        report_result = generate_security_report(
            report_type=report_type,
            start_date=start_date,
            end_date=end_date,
            format_type=format_type,
            focus_areas=focus_areas
        )

        audit_request_count.inc(1, labels={'endpoint': '/reports/security', 'status': '200'})

        # Handle report result based on format
        timestamp = datetime.now().strftime("%Y%m%d")

        if format_type == 'json':
            if isinstance(report_result, dict):
                return jsonify(report_result), 200
            # Otherwise assume it's already a Response
            return report_result

        # For CSV and PDF, return as file download
        if format_type == 'csv':
            content_type = 'text/csv'
            filename = f"security_report_{report_type}_{timestamp}.csv"
        else:  # PDF
            content_type = 'application/pdf'
            filename = f"security_report_{report_type}_{timestamp}.pdf"

        # Handle case where report_result is a file path
        if isinstance(report_result, str) and (report_result.startswith('/') or report_result.startswith('./')):
            return send_file(report_result,
                           mimetype=content_type,
                           download_name=filename,
                           as_attachment=True)

        # Otherwise assume it's a Response or has the right headers already
        return report_result

    except ValueError as e:
        audit_request_count.inc(1, labels={'endpoint': '/reports/security', 'status': '400'})
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        audit_request_count.inc(1, labels={'endpoint': '/reports/security', 'status': '500'})
        logger.error(f"Error generating security report: {str(e)}", exc_info=True)
        return jsonify({"error": f"Report generation failed: {str(e)}"}), 500

# --- Analysis and Statistics Endpoints ---

@audit_bp.route('/statistics', methods=['GET'])
@require_permission('audit:statistics:view')
@limiter.limit(DEFAULT_LIMIT)
def get_statistics():
    """
    Get statistics and trends from the audit logs.

    Query Parameters:
        period (str): Time period to analyze (e.g., '24h', '7d', '30d')
        category (str, optional): Filter by event category

    Returns:
        JSON: Audit log statistics and trend data
    """
    try:
        # Parse time period
        period = request.args.get('period', '7d')
        category = request.args.get('category')

        # Convert period string to timedelta
        period_map = {
            '24h': timedelta(hours=24),
            '7d': timedelta(days=7),
            '30d': timedelta(days=30),
            '90d': timedelta(days=90),
            '365d': timedelta(days=365)
        }

        if period not in period_map:
            return jsonify({"error": "Invalid period. Use '24h', '7d', '30d', '90d', or '365d'"}), 400

        delta = period_map[period]
        end_date = datetime.now(timezone.utc)
        start_date = end_date - delta

        # Check cache first for expensive calculations
        cache_key = f"audit_statistics:{period}:{category or 'all'}"
        cached_data = cache.get(cache_key)

        if cached_data:
            audit_request_count.inc(1, labels={'endpoint': '/statistics', 'status': '200'})
            return jsonify(cached_data), 200

        # Build base query
        query = AuditLog.query.filter(AuditLog.created_at.between(start_date, end_date))

        if category:
            query = query.filter(AuditLog.category == category)

        # Get total count
        total_events = query.count()

        # Get counts by severity
        severity_stats = db.session.query(
            AuditLog.severity,
            func.count(AuditLog.id)
        ).filter(
            AuditLog.created_at.between(start_date, end_date)
        )

        if category:
            severity_stats = severity_stats.filter(AuditLog.category == category)

        severity_stats = severity_stats.group_by(AuditLog.severity).all()

        by_severity = {severity: count for severity, count in severity_stats}

        # Get counts by category
        category_stats = db.session.query(
            AuditLog.category,
            func.count(AuditLog.id)
        ).filter(
            AuditLog.created_at.between(start_date, end_date)
        )

        if category:
            category_stats = category_stats.filter(AuditLog.category == category)

        category_stats = category_stats.group_by(AuditLog.category).all()

        by_category = {cat: count for cat, count in category_stats}

        # Generate time series data based on period
        if period == '24h':
            # Hourly data points for 24 hours
            interval = 'hour'
            points = 24
        elif period == '7d':
            # Daily data points for 7 days
            interval = 'day'
            points = 7
        else:
            # Daily data points for longer periods
            interval = 'day'
            points = int(delta.total_seconds() / (24 * 3600))

        # Generate time series for different severities
        trend_data = {}
        for severity in ['critical', 'error', 'warning', 'info']:
            trend_data[severity] = [0] * points

            # Get time series data
            if interval == 'hour':
                # Group by hour for 24h period
                time_series = db.session.query(
                    func.date_trunc('hour', AuditLog.created_at).label('hour'),
                    func.count(AuditLog.id)
                ).filter(
                    AuditLog.created_at.between(start_date, end_date),
                    AuditLog.severity == severity
                )

                if category:
                    time_series = time_series.filter(AuditLog.category == category)

                time_series = time_series.group_by('hour').all()

                # Map to hour positions in array (0 = oldest, 23 = newest)
                for hour_bucket, count in time_series:
                    hour = hour_bucket.replace(tzinfo=timezone.utc)
                    hours_ago = int((end_date - hour).total_seconds() / 3600)
                    if 0 <= hours_ago < points:
                        trend_data[severity][points - 1 - hours_ago] = count

            else:  # Daily aggregation
                # Group by day for longer periods
                time_series = db.session.query(
                    func.date_trunc('day', AuditLog.created_at).label('day'),
                    func.count(AuditLog.id)
                ).filter(
                    AuditLog.created_at.between(start_date, end_date),
                    AuditLog.severity == severity
                )

                if category:
                    time_series = time_series.filter(AuditLog.category == category)

                time_series = time_series.group_by('day').all()

                # Map to day positions in array (0 = oldest, n-1 = newest)
                for day_bucket, count in time_series:
                    day = day_bucket.replace(tzinfo=timezone.utc)
                    days_ago = int((end_date - day).total_seconds() / (24 * 3600))
                    if 0 <= days_ago < points:
                        trend_data[severity][points - 1 - days_ago] = count

        # Assemble the result
        result = {
            "total_events": total_events,
            "by_severity": by_severity,
            "by_category": by_category,
            "trend": trend_data,
            "period": period
        }

        # Cache the result
        cache_ttl = current_app.config.get('AUDIT_DASHBOARD_DATA_TTL', 3600)  # Default 1 hour
        cache.set(cache_key, result, timeout=cache_ttl)

        audit_request_count.inc(1, labels={'endpoint': '/statistics', 'status': '200'})
        return jsonify(result), 200

    except SQLAlchemyError as e:
        audit_request_count.inc(1, labels={'endpoint': '/statistics', 'status': '500'})
        logger.error(f"Database error retrieving audit statistics: {str(e)}")
        return jsonify({"error": "Database error occurred"}), 500
    except Exception as e:
        audit_request_count.inc(1, labels={'endpoint': '/statistics', 'status': '500'})
        logger.error(f"Error retrieving audit statistics: {str(e)}", exc_info=True)
        return jsonify({"error": f"Failed to retrieve statistics: {str(e)}"}), 500

@audit_bp.route('/search/advanced', methods=['POST'])
@require_permission('audit:search:advanced')
@limiter.limit(DEFAULT_LIMIT)
def advanced_search():
    """
    Perform advanced search on audit logs with complex criteria.

    Request Body (JSON):
        query (dict): Complex search criteria
        page (int): Page number
        per_page (int): Results per page

    Returns:
        JSON: Search results with pagination metadata
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No search criteria provided"}), 400

        # Extract search criteria and pagination
        search_criteria = data.get('query', {})
        page = max(1, data.get('page', 1))
        per_page = min(data.get('per_page', 50), 100)  # Limit to 100 max

        # Execute advanced search
        results, total_count = analyze_security_events(search_criteria, page, per_page)

        audit_request_count.inc(1, labels={'endpoint': '/search/advanced', 'status': '200'})
        return jsonify({
            "data": results,
            "meta": {
                "page": page,
                "per_page": per_page,
                "total_pages": (total_count + per_page - 1) // per_page if total_count > 0 else 1,
                "total_items": total_count
            }
        }), 200

    except ValueError as e:
        audit_request_count.inc(1, labels={'endpoint': '/search/advanced', 'status': '400'})
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        audit_request_count.inc(1, labels={'endpoint': '/search/advanced', 'status': '500'})
        logger.error(f"Error during advanced search: {str(e)}", exc_info=True)
        return jsonify({"error": f"Search failed: {str(e)}"}), 500

@audit_bp.route('/events/correlate', methods=['POST'])
@require_permission('audit:events:correlate')
@limiter.limit(DEFAULT_LIMIT)
def correlate_security_events():
    """
    Find correlations between security events based on provided parameters.

    Request Body (JSON):
        event_id (int): Central event ID to correlate from
        time_window (int): Time window in minutes (before and after event)
        related_types (list, optional): Event types to include in correlation

    Returns:
        JSON: Correlated events and relationship information
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No correlation parameters provided"}), 400

        # Extract parameters
        event_id = data.get('event_id')
        time_window = data.get('time_window', 30)  # Default 30 minutes
        related_types = data.get('related_types', [])

        if not event_id:
            return jsonify({"error": "event_id is required"}), 400

        # Find correlations
        central_event, correlated_events, relationships = correlate_events(
            event_id=event_id,
            time_window_minutes=time_window,
            related_types=related_types
        )

        if not central_event:
            audit_request_count.inc(1, labels={'endpoint': '/events/correlate', 'status': '404'})
            return jsonify({"error": "Event not found"}), 404

        # Format response
        result = {
            "central_event": central_event,
            "correlated_events": correlated_events,
            "relationships": relationships,
            "correlation_params": {
                "time_window": time_window,
                "related_types": related_types
            }
        }

        audit_request_count.inc(1, labels={'endpoint': '/events/correlate', 'status': '200'})
        return jsonify(result), 200

    except ValueError as e:
        audit_request_count.inc(1, labels={'endpoint': '/events/correlate', 'status': '400'})
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        audit_request_count.inc(1, labels={'endpoint': '/events/correlate', 'status': '500'})
        logger.error(f"Error correlating security events: {str(e)}", exc_info=True)
        return jsonify({"error": f"Correlation failed: {str(e)}"}), 500

@audit_bp.route('/dashboard', methods=['GET'])
@require_permission('audit:dashboard:view')
@limiter.limit(DEFAULT_LIMIT)
@cache.cached(timeout=900)  # Cache for 15 minutes
def get_audit_dashboard():
    """
    Get dashboard data for audit activity visualization.

    Query Parameters:
        period (str): Time period for dashboard data (e.g., '24h', '7d', '30d')

    Returns:
        JSON: Dashboard data including summaries, trends, and key metrics
    """
    try:
        # Parse parameters
        period = request.args.get('period', '7d')

        # Generate dashboard data
        dashboard_data = get_dashboard_data(period)

        audit_request_count.inc(1, labels={'endpoint': '/dashboard', 'status': '200'})
        return jsonify(dashboard_data), 200

    except ValueError as e:
        audit_request_count.inc(1, labels={'endpoint': '/dashboard', 'status': '400'})
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        audit_request_count.inc(1, labels={'endpoint': '/dashboard', 'status': '500'})
        logger.error(f"Error generating audit dashboard data: {str(e)}", exc_info=True)
        return jsonify({"error": f"Failed to generate dashboard data: {str(e)}"}), 500

# --- Module initialization ---

# Register audit metrics
def register_audit_metrics():
    """Register custom metrics for the audit module."""
    metrics.gauge(
        'audit_log_count',
        'Total number of audit log entries',
        multiprocess_mode='livesum'
    )

    metrics.gauge(
        'audit_critical_events_24h',
        'Number of critical audit events in the last 24 hours',
        multiprocess_mode='livesum'
    )

    metrics.gauge(
        'audit_query_result_count',
        'Count of results from audit queries',
        labels=['endpoint'],
        multiprocess_mode='livesum'
    )
